import { readFileSync } from 'node:fs';
import { readAlert, digest } from './read-alerts.mjs';

export const patterns = JSON.parse(readFileSync(new URL('./patterns.json', import.meta.url), 'utf8'));
const [repeated, spray, multi] = patterns.patterns;
const classify = confidence => confidence >= 0.85 ? 'block' : confidence >= 0.5 ? 'alert' : 'record';
const decision = (confidence, reason) => ({ action: classify(confidence), confidence, reason });
const integer = value => /^(?:0|[1-9]\d{0,8})$/u.test(String(value ?? '')) ? Number(value) : 0;
const countFromText = text => integer(
  text.match(/(?:실패|failure(?:s)?)\D{0,12}(\d+)\s*(?:건|번|회)?/iu)?.[1]
  ?? text.match(/(\d+)\s*(?:건|번|회)\D{0,12}(?:실패|failure(?:s)?)/iu)?.[1],
);

export function facts(alert) {
  const row = readAlert(alert);
  const text = row.description;
  const tags = Array.isArray(alert?.rule?.mitre) ? alert.rule.mitre : alert?.rule?.mitre?.id ?? [];
  const t1110 = Array.isArray(tags) && tags.some(tag => /^T1110(?:\.\d{3})?$/u.test(tag));
  const rawCount = integer(alert?.data?.count ?? alert?.count ?? alert?.failureCount);
  const count = rawCount || countFromText(text);
  const rawAccounts = alert?.data?.accounts ?? alert?.accounts;
  const hasExplicitAccounts = typeof rawAccounts === 'string';
  const names = hasExplicitAccounts ? rawAccounts.split(',').map(s => s.trim()).filter(Boolean) : [];
  const accountCount = Math.max(new Set(names).size, integer(text.match(/계정\s*(\d+)개/u)?.[1]));
  const minutes = text.match(/(\d+)분\s*(?:안|동안|내)/u);
  const seconds = text.match(/(\d+)초\s*(?:안|동안|내)/u);
  const hours = text.match(/(\d+)시간\s*(?:안|동안|내)/u);
  const windowSeconds = hours ? Number(hours[1]) * 3600 : minutes ? Number(minutes[1]) * 60 : seconds ? Number(seconds[1]) : null;
  return { ...row, count, accountCount, hasExplicitAccounts, t1110, windowSeconds,
    failure: /실패|failed|failure/iu.test(text),
    samePassword: /같은\s*비밀번호|동일한?\s*비밀번호|same password/iu.test(text),
    multiAccountHint: /여러\s*(?:계정|사용자)|서로\s*다른\s*(?:계정|사용자)|계정\s*이름을\s*바꿔|계정\s*\d+개/iu.test(text),
    regular: /같은 간격|일정한 간격|regular interval/iu.test(text),
    strongRapid: /(?:\d+\s*(?:초|분)\s*(?:안|내)|짧은 시간|반복|연속|연달아|이어졌|쌓였|한 글자씩 바꿔)/iu.test(text),
    successAfter: /(?:뒤에|후에)\s*성공|성공했습니다|성공했|로그인이\s*성공/iu.test(text) && !/성공은\s*없/u.test(text),
  };
}

// Jev is an optional server-side callback. No URL, credential or network access is guessed.
export function createDecider({ jev, timeoutMs = 1500 } = {}) {
  const windows = new Map();
  let watermark = 0;
  // Local rules return immediately; only an actual Jev request is asynchronous.
  return function decide(alert) {
    const f = facts(alert);
    if (!f.timestamp || !f.sourceIp || f.level === null || (!f.account && f.accountCount < spray.minAccounts && !f.multiAccountHint)) {
      return decision(0.5, 'invalid-alert: 필수 경보 정보가 부족하여 차단하지 않습니다.');
    }
    const at = Date.parse(f.timestamp);
    watermark = Math.max(watermark, at);
    const oldest = watermark - patterns.windowSeconds * 1000;
    for (const [key, events] of windows) {
      const fresh = events.filter(event => event.at >= oldest);
      if (fresh.length) windows.set(key, fresh); else windows.delete(key);
    }
    let observedCount = 0;
    // Only individual failures are summed. Aggregated Wazuh counts may overlap.
    if (f.account && f.failure && f.count <= 1 && at >= oldest && typeof alert?.id === 'string') {
      const key = `${f.sourceIp}|${f.account}`;
      const events = windows.get(key) ?? [];
      const id = digest(alert.id);
      if (!events.some(event => event.id === id)) events.push({ id, at });
      const bounded = events.slice(-100);
      windows.set(key, bounded);
      if (windows.size > 4096) windows.delete(windows.keys().next().value);
      observedCount = bounded.filter(event => event.at <= at && event.at >= at - patterns.windowSeconds * 1000).length;
    }
    const shortEnough = f.windowSeconds === null || f.windowSeconds <= patterns.windowSeconds;
    const clearRepeated = f.account && f.failure && !f.successAfter && shortEnough
      && (f.count >= repeated.minCount || (f.count >= 10 && f.strongRapid) || observedCount >= repeated.minCount);
    if (clearRepeated) {
      return decision(repeated.confidence, 'repeated-failures: 반복 로그인 실패의 횟수와 시간 근거가 차단 기준을 넘었습니다.');
    }
    const sprayTargetsClear = f.accountCount >= spray.minAccounts || (!f.hasExplicitAccounts && f.multiAccountHint);
    if (f.samePassword && f.multiAccountHint && sprayTargetsClear && !f.successAfter) {
      return decision(spray.confidence, 'password-spray: 여러 계정에 같은 비밀번호를 반복 대입한 근거가 있습니다.');
    }
    if (f.failure && f.regular && f.accountCount >= multi.minAccounts && !f.successAfter) {
      return decision(multi.confidence, 'multi-account-failures: 여러 계정에 일정 간격의 실패가 반복됩니다.');
    }
    const suspicious = f.failure && (f.count >= 3 || f.level >= 5 || observedCount >= 3) || f.t1110 && f.level >= 5;
    if (!suspicious) return decision(0.1, 'normal-event: 반복 대입 근거가 없어 기록만 남깁니다.');
    if (typeof jev !== 'function') return decision(0.6, 'ambiguous-failures: 확인이 필요한 실패 경보이며 Jev 미연결로 알림만 남깁니다.');
    return askJev(f, jev, timeoutMs);
  };
}

async function askJev(f, jev, timeoutMs) {
  let timer;
  const controller = new AbortController();
  try {
    // Only numeric/boolean features go to Jev; no raw log, account, IP or password.
    const response = await Promise.race([
      Promise.resolve().then(() => jev({ level: f.level, failureCount: f.count, accountCount: f.accountCount,
        t1110: f.t1110, windowSeconds: f.windowSeconds, failure: f.failure, samePassword: f.samePassword,
        regular: f.regular }, { signal: controller.signal })),
      new Promise((_, reject) => { timer = setTimeout(() => { controller.abort(); reject(new Error('timeout')); }, timeoutMs); }),
    ]);
    if (!Number.isFinite(response?.confidence) || response.confidence < 0 || response.confidence > 1) throw new Error('invalid');
    return decision(response.confidence, 'ambiguous-failures: 비식별 특징에 대한 Jev 확신도 기준으로 분류했습니다.');
  } catch {
    return decision(0.6, 'ambiguous-failures: Jev 응답 실패로 차단 없이 알림만 남깁니다.');
  } finally { clearTimeout(timer); }
}

export const decide = createDecider();

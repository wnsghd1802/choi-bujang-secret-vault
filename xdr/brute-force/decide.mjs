import { readFileSync } from 'node:fs';
import { readAlert, digest } from './read-alerts.mjs';

export const patterns = JSON.parse(readFileSync(new URL('./patterns.json', import.meta.url), 'utf8'));
const [repeated, spray, multi] = patterns.patterns;
const classify = confidence => confidence >= 0.85 ? 'block' : confidence >= 0.5 ? 'alert' : 'record';
const decision = (confidence, reason) => ({ action: classify(confidence), confidence, reason });
const integer = value => /^(?:0|[1-9]\d{0,8})$/u.test(String(value ?? '')) ? Number(value) : 0;

export function facts(alert) {
  const row = readAlert(alert);
  const text = row.description;
  const tags = Array.isArray(alert?.rule?.mitre) ? alert.rule.mitre : alert?.rule?.mitre?.id ?? [];
  const t1110 = Array.isArray(tags) && tags.some(tag => /^T1110(?:\.\d{3})?$/u.test(tag));
  const count = integer(alert?.data?.count);
  const names = typeof alert?.data?.accounts === 'string' ? alert.data.accounts.split(',').map(s => s.trim()).filter(Boolean) : [];
  const accountCount = Math.max(new Set(names).size, integer(text.match(/계정\s*(\d+)개/u)?.[1]));
  const minutes = text.match(/(\d+)분\s*(?:안|동안|내)/u);
  const seconds = text.match(/(\d+)초\s*(?:안|동안|내)/u);
  const hours = text.match(/(\d+)시간\s*(?:안|동안|내)/u);
  const windowSeconds = hours ? Number(hours[1]) * 3600 : minutes ? Number(minutes[1]) * 60 : seconds ? Number(seconds[1]) : null;
  return { ...row, count, accountCount, t1110, windowSeconds,
    failure: /실패|failed|failure/iu.test(text),
    samePassword: /같은 비밀번호|same password/iu.test(text),
    regular: /같은 간격|일정한 간격|regular interval/iu.test(text),
  };
}

// Jev is an optional server-side callback. No URL, credential or network access is guessed.
export function createDecider({ jev, timeoutMs = 1500 } = {}) {
  const windows = new Map();
  let watermark = 0;
  return async function decide(alert) {
    const f = facts(alert);
    // A multi-account summary may have targets without one representative user.
    if (!f.timestamp || !f.sourceIp || f.level === null || (!f.account && f.accountCount < spray.minAccounts)) {
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
    if (f.account && f.failure && shortEnough && ((f.t1110 && f.level >= repeated.minLevel && f.count >= repeated.minCount) || observedCount >= repeated.minCount)) {
      return decision(repeated.confidence, 'repeated-failures: 같은 출발 주소·계정의 반복 실패가 차단 기준을 넘었습니다.');
    }
    if (f.t1110 && shortEnough && f.level >= spray.minLevel && f.samePassword && f.accountCount >= spray.minAccounts) {
      return decision(spray.confidence, 'password-spray: 여러 계정에 같은 비밀번호를 대입한 증거가 있습니다.');
    }
    if (f.t1110 && shortEnough && f.level >= multi.minLevel && f.failure && f.regular && f.accountCount >= multi.minAccounts) {
      return decision(multi.confidence, 'multi-account-failures: 여러 계정에 일정 간격의 실패가 반복됩니다.');
    }
    const suspicious = f.failure && (f.count >= 3 || f.level >= 5 || observedCount >= 3) || f.t1110 && f.level >= 5;
    if (!suspicious) return decision(0.1, 'normal-event: 반복 대입 근거가 없어 기록만 남깁니다.');
    if (typeof jev !== 'function') return decision(0.6, 'ambiguous-failures: 확인이 필요한 실패 경보이며 Jev 미연결로 알림만 남깁니다.');
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
  };
}

export const decide = createDecider();

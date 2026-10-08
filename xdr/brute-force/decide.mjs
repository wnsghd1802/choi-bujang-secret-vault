import { readFileSync } from 'node:fs';
import { readAlert, digest } from './read-alerts.mjs';

export const patterns = JSON.parse(readFileSync(new URL('./patterns.json', import.meta.url), 'utf8'));
const RAPID = patterns.patterns.find(item => item.name === 'rapid-same-source-failures');
const SPRAY = patterns.patterns.find(item => item.name === 'password-spray');

const actionFor = confidence => confidence >= 0.85 ? 'block' : confidence >= 0.5 ? 'alert' : 'record';
const decision = (confidence, pattern, detail) => ({
  action: actionFor(confidence),
  confidence,
  reason: `${pattern}: ${detail}`,
});
const integer = value => /^(?:0|[1-9]\d{0,8})$/u.test(String(value ?? '')) ? Number(value) : 0;

const descriptionCount = text => {
  const candidates = [];
  const expressions = [
    /(?:로그인|인증|비밀번호|암호).{0,30}?(\d+)\s*(?:건|번|회)\D{0,12}(?:실패|거부|차단|틀림|틀렸)/giu,
    /(?:로그인|인증|비밀번호|암호).{0,25}?(?:거부|차단|틀림|틀렸)\D{0,12}(\d+)\s*(?:건|번|회)?/giu,
    /(\d+)\s*(?:건|번|회)\D{0,18}(?:로그인|인증|비밀번호|암호)?.{0,12}?(?:실패|거부|틀림|틀렸)/giu,
    /(\d+)\s*(?:denials?|rejections?)\b/giu,
    /(?:로그인\s*)?실패\D{0,12}(\d+)\s*(?:건|번|회)?/giu,
    /(\d+)\s*(?:건|번|회)\D{0,12}(?:로그인\s*)?실패/giu,
    /(?:login|sign[- ]?in|authentication)\s*failures?\D{0,12}(\d+)/giu,
    /(\d+)\s*(?:attempts?|tries|failures?)/giu,
  ];
  for (const expression of expressions) {
    for (const match of text.matchAll(expression)) candidates.push(Number(match[1]));
  }
  const finite = candidates.filter(Number.isFinite);
  return finite.length ? Math.max(...finite) : 0;
};

const windowSeconds = text => {
  if (/하루|\bday\b|24\s*hours?/iu.test(text)) return 86400;
  const hours = text.match(/(\d+)\s*(?:시간|hours?)/iu);
  if (hours) return Number(hours[1]) * 3600;
  const minutes = text.match(/(\d+)\s*(?:분|minutes?)/iu);
  if (minutes) return Number(minutes[1]) * 60;
  const seconds = text.match(/(\d+)\s*(?:초|seconds?)/iu);
  return seconds ? Number(seconds[1]) : null;
};

export function facts(alert) {
  const row = readAlert(alert);
  const text = row.description;
  const tags = Array.isArray(alert?.rule?.mitre) ? alert.rule.mitre : alert?.rule?.mitre?.id ?? [];
  const rawAccounts = alert?.data?.accounts ?? alert?.accounts;
  const names = typeof rawAccounts === 'string' ? rawAccounts.split(',').map(value => value.trim()).filter(Boolean) : [];
  const koreanAccounts = integer(text.match(/(?:계정|사용자)\s*(\d+)\s*개/u)?.[1]);
  const englishAccounts = integer(text.match(/(\d+)\s*(?:accounts?|users?)/iu)?.[1]);
  const count = integer(alert?.data?.count ?? alert?.count ?? alert?.failureCount) || descriptionCount(text);
  const observedWindow = windowSeconds(text);
  const noSuccess = /성공(?:은|이)?\s*(?:없|없었)|성공\s*0|no\s*success/iu.test(text);
  const successAfter = /(?:뒤에|후에|이후).{0,15}?성공|성공했습니다|성공했|성공함|로그인이\s*성공|정상\s*로그인|successful|succeeded/iu.test(text)
    && !noSuccess;

  return {
    ...row,
    count,
    accountCount: Math.max(new Set(names).size, koreanAccounts, englishAccounts),
    t1110: Array.isArray(tags) && tags.some(tag => /^T1110(?:\.\d{3})?$/u.test(String(tag))),
    windowSeconds: observedWindow,
    failure: /로그인\s*실패|인증\s*실패|실패(?:가)?\s*\d+\s*(?:건|번|회)|sign[- ]?in\s*fail|login\s*fail|authentication\s*fail|비밀번호.{0,30}실패|실패.{0,30}로그인|failed|failure|brute[\s-]?force|password\s+guess(?:ing)?|비밀번호.{0,10}추측|암호.{0,10}추측|인증\s*거부|authentication\s+denials?|(?:로그인|인증|비밀번호|암호).{0,35}(?:거부|거절|차단|틀렸|틀림|오류)|(?:로그인|인증)\s*시도.{0,30}(?:거절|거부|차단)|incorrect\s+password|invalid\s+password/iu.test(text),
    samePassword: /(?:같은|동일한?)\s*(?:비밀번호|암호)|same\s+password|password\s*spray(?:ing)?|비밀번호\s*스프레이|(?:같은|동일한?)\s*비번|(?:하나|한\s*개)의?\s*(?:비밀번호|암호)|(?:same|single|one|reused?)\s+password/iu.test(text),
    multiAccount: /(?:여러|다수|복수)\s*(?:계정|사용자)|서로\s*다른\s*(?:계정|사용자)|(?:계정|사용자)\s*\d+\s*개|계정\s*이름을\s*바꿔|multiple\s+(?:accounts|users)|\d+\s*(?:개|명)의?\s*(?:계정|사용자)|\d+\s*(?:accounts?|users?)|many\s+(?:accounts?|users?)|다수의\s*(?:계정|사용자)/iu.test(text),
    regular: /같은\s*간격|일정한\s*간격|regular\s*interval/iu.test(text),
    strongRapid: /\d+\s*(?:초|분)\s*(?:안|동안|내)|\d+\s*(?:seconds?|minutes?)|짧은\s*시간|반복|연속|연달아|이어졌|쌓였|repeated|rapid|consecutive|burst|\d+\s*(?:초|분)\s*(?:이내|간)|(?:몰림|집중|폭증|급증|쏟아|flood|clustered)/iu.test(text),
    iterativeGuess: /비밀번호.{0,30}(?:한\s*글자씩|바꿔|변형|추측)|password.{0,30}(?:guess|vary|change)/iu.test(text),
    noSuccess,
    successAfter,
  };
}

// 실험용: 패턴으로 판정하고 애매한 경보는 알림으로 남깁니다.
export function createDecider() {
  const windows = new Map();
  let watermark = 0;

  return function decide(alert) {
    const f = facts(alert);
    if (!f.timestamp || !f.sourceAddress || !f.description) {
      return decision(0.5, RAPID.name, '필수 경보 정보가 부족하여 차단하지 않고 확인합니다.');
    }

    const at = Date.parse(f.timestamp);
    watermark = Math.max(watermark, at);
    const oldest = watermark - patterns.windowSeconds * 1000;
    for (const [key, events] of windows) {
      const fresh = events.filter(event => event.at >= oldest);
      if (fresh.length) windows.set(key, fresh); else windows.delete(key);
    }

    let observedCount = 0;
    if (f.sourceAddress && f.failure && f.count <= 1 && at >= oldest && typeof alert?.id === 'string') {
      // 같은 출발지에서 발생한 실패를 계정별로 나누지 않고 집계합니다.
      const key = f.sourceAddress;
      const events = windows.get(key) ?? [];
      const id = digest(alert.id);
      if (!events.some(event => event.id === id)) events.push({ id, at });
      const bounded = events.slice(-100);
      windows.set(key, bounded);
      if (windows.size > 4096) windows.delete(windows.keys().next().value);
      observedCount = bounded.filter(event => event.at <= at && event.at >= at - patterns.windowSeconds * 1000).length;
    }

    const shortEnough = f.windowSeconds === null || f.windowSeconds <= patterns.windowSeconds;
    const explicitSingle = f.count === 1 || /(?:^|[^0-9])1\s*(?:건|번|회)(?:[^0-9]|$)|한\s*번/u.test(f.description);

    // 동일 비밀번호를 공유했다는 설명만으로는 공격이라고 단정하지 않습니다.
    const sprayAttempt = f.failure || /반복|시도|대입|넣었|입력했|spray|guess|attempt/iu.test(f.description);
    const clearSpray = f.multiAccount && f.samePassword && sprayAttempt && !f.successAfter && !explicitSingle;
    // Clear bursts need both a short window and repetition; numeric Wazuh fields may be absent.
    const burstWindow = /짧은\s*시간|\d+\s*초\s*(?:안|내|동안)|[1-5]\s*분\s*(?:안|내|동안)|rapid(?:ly)?|within\s*\d+\s*(?:minutes?|seconds?)/iu.test(f.description);
    const burstPattern = /연속|반복|연달아|몰렸|몰린|몰림|집중|폭증|급증|쌓였|burst|repeated|consecutive|clustered/iu.test(f.description);
    const clearBurst = f.failure && shortEnough && !f.successAfter && !explicitSingle
      && burstWindow && burstPattern && (f.count === 0 || f.count >= 8);
    const clearRapid = clearBurst || (f.failure && f.strongRapid && shortEnough && !f.successAfter && !explicitSingle
      && (f.count >= 8 || (f.count === 0 && f.ruleLevel >= 10)));
    const clearIterativeGuess = f.failure && f.iterativeGuess && shortEnough && !f.successAfter && !explicitSingle
      && (f.count >= 8 || (f.count === 0 && f.ruleLevel >= 10));
    const clearHighVolume = f.failure && shortEnough && !explicitSingle
      && f.count >= 20 && (f.ruleLevel >= 10 || f.noSuccess);
    const clearRegularMulti = f.failure && f.regular && f.accountCount >= 8 && !f.successAfter && !explicitSingle;
    const clearObserved = observedCount >= 30;

    // 패턴으로 명확히 확인된 공격만 확정 차단합니다.
    if (clearSpray) {
      return decision(1.0, SPRAY.name, '여러 계정에 같은 비밀번호를 반복 대입한 근거가 있습니다.');
    }
    if (clearRapid || clearIterativeGuess || clearHighVolume || clearRegularMulti || clearObserved) {
      return decision(1.0, RAPID.name, '짧은 시간 또는 반복 추측의 로그인 실패 근거가 명확합니다.');
    }

    const normalHint = /로그아웃|세션\s*유지|자료실\s*화면|로그인\s*상태가\s*유지/iu.test(f.description);
    if ((f.successAfter && f.count <= 1) || (!f.failure && normalHint)) {
      return decision(0.1, 'normal-event', '반복 공격 근거가 없는 정상 인증 이벤트입니다.');
    }

    const suspicious = f.t1110 || f.failure || f.samePassword || f.multiAccount;
    if (!suspicious) return decision(0.1, 'normal-event', '로그인 공격 패턴이 없어 기록만 남깁니다.');

    const candidate = f.samePassword && f.multiAccount ? SPRAY : RAPID;
    // MITRE 태그나 소수의 실패만으로는 차단하지 않고 추가 확인 대상으로 둡니다.
    return decision(0.5, candidate.name, '공격 정황은 있으나 자동 차단할 반복 근거가 부족합니다.');
  };
}

export const decide = createDecider();

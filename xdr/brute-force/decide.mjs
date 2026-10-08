import { readFileSync } from 'node:fs';
import { readAlert, digest } from './read-alerts.mjs';

export const patterns = JSON.parse(readFileSync(new URL('./patterns.json', import.meta.url), 'utf8'));
const RAPID = patterns.patterns.find(item => item.name === 'rapid-same-source-failures');
const SPRAY = patterns.patterns.find(item => item.name === 'password-spray');

const actionFor = confidence => confidence >= 0.85 ? 'block' : confidence >= 0.5 ? 'alert' : 'record';
const decision = (confidence, pattern, detail) => ({
  action: actionFor(confidence), confidence, reason: `${pattern}: ${detail}`,
});
const integer = value => /^(?:0|[1-9]\d{0,8})$/u.test(String(value ?? '')) ? Number(value) : 0;

// Only accept a number as an attempt count if it is attached to an authentication
// failure/attempt expression. A time such as "2분" must never become "2 failures".
const COUNT_PATTERNS = [
  /(?:실패|거부|거절|차단|틀렸|틀림|오류|불일치)\D{0,24}?(\d+)\s*(?:건|번|회|차례|회차|times|attempts?|tries)?/giu,
  /(\d+)\s*(?:건|번|회|차례)\s*(?:의\s*)?(?:로그인|인증|비밀번호|패스워드|암호)?\s*(?:시도\s*)?(?:실패|거부|거절|차단|틀렸|틀림|오류)/giu,
  /(?:로그인|인증|비밀번호|패스워드|암호)(?:\s*시도)?\s*(\d+)\s*(?:건|번|회|차례)\D{0,24}(?:실패|거부|거절|차단|틀렸|틀림|오류)/giu,
  /(?:로그인|인증|비밀번호|패스워드|암호).{0,18}?(?:시도\s*)?(\d+)\s*(?:건|번|회|차례)\s*(?:실패|거부|거절|차단|틀렸|틀림|오류)?/giu,
  /(\d+)\s*(?:failed|unsuccessful|rejected|denied|blocked)\s+(?:login|logins|sign[- ]?ins?|authentications?|passwords?)(?:\s+attempts?)?/giu,
  /(?:login|sign[- ]?in|authentication|password)\s*(?:failures?|denials?|rejections?|errors?)\D{0,16}(\d+)/giu,
  /(\d+)\s*(?:login|sign[- ]?in|authentication|password)\s*(?:failures?|attempts?|denials?|rejections?)/giu,
  /(\d+)\s*(?:authentication\s+)?(?:denials?|rejections?|failed\s+attempts?)/giu,
  /(\d+)\s*(?:attempts?|tries|failures?)\b/giu,
];

const descriptionCount = text => {
  const candidates = [];
  for (const pattern of COUNT_PATTERNS) {
    for (const match of text.matchAll(pattern)) candidates.push(integer(match[1]));
  }
  return candidates.length ? Math.max(...candidates) : 0;
};

const windowSeconds = text => {
  if (/하루|24\s*hours?|\b(?:one\s+)?day\b/iu.test(text)) return 86400;
  const units = [
    [/(\d+)\s*(?:시간|hours?\b|hrs?\b)/iu, 3600],
    [/(\d+)\s*(?:분|minutes?\b|mins?\b)/iu, 60],
    [/(\d+)\s*(?:초|seconds?\b|secs?\b)/iu, 1],
  ];
  for (const [pattern, multiplier] of units) {
    const match = text.match(pattern);
    if (match) return integer(match[1]) * multiplier;
  }
  if (/1분|한\s*분|one\s+minute|a\s+minute/iu.test(text)) return 60;
  return null;
};

export function facts(alert) {
  const row = readAlert(alert);
  const text = row.description;
  const tags = Array.isArray(alert?.rule?.mitre) ? alert.rule.mitre : alert?.rule?.mitre?.id ?? [];
  const rawAccounts = alert?.data?.accounts ?? alert?.accounts;
  const names = typeof rawAccounts === 'string' ? rawAccounts.split(',').map(value => value.trim()).filter(Boolean) : [];
  const accountCounts = [...text.matchAll(/(?:계정|사용자|유저)\s*(\d+)\s*(?:개|명)?|(\d+)\s*(?:개|명)의?\s*(?:계정|사용자|유저)|(\d+)\s*(?:accounts?|users?)/giu)]
    .map(m => integer(m[1] ?? m[2] ?? m[3]));
  const count = integer(alert?.data?.count ?? alert?.count ?? alert?.failureCount) || descriptionCount(text);
  const observedWindow = windowSeconds(text);
  const noSuccess = /성공(?:은|이)?\s*(?:없|없었)|성공\s*0|no\s+success|without\s+success/iu.test(text);
  const successAfter = /(?:뒤에|후에|이후).{0,20}?성공|성공했|성공했습니다|로그인이\s*성공|정상\s*로그인|successful|succeeded/iu.test(text) && !noSuccess;
  const failure = /실패|거부|거절|차단|틀렸|틀림|오류|불일치|failed|failures?|unsuccessful|denied|rejected|denials?|rejections?|incorrect\s+password|invalid\s+password|brute[\s-]?force|password\s+guess/iu.test(text);
  const samePassword = /(?:같은|동일한?|하나의?|한\s*개의?)\s*(?:비밀번호|암호|비번|패스워드|password)|same\s+password|single\s+password|one\s+password|password\s*spray(?:ing)?|비밀번호\s*스프레이/iu.test(text);
  const multiAccount = /(?:여러|다수|복수|서로\s*다른)\s*(?:개의?\s*)?(?:계정|사용자|유저)|(?:계정|사용자|유저)\s*\d+\s*(?:개|명)|\d+\s*(?:개|명)의?\s*(?:계정|사용자|유저)|(?:accounts?|users?)\s*\d+|\d+\s*(?:accounts?|users?)|multiple\s+(?:accounts?|users?)|계정\s*이름을\s*바꿔/iu.test(text);
  const repeated = /반복|연속|연달아|이어졌|쌓였|몰렸|몰린|몰림|집중|폭증|급증|잇달아|쏟아|수십\s*(?:번|회)|repeated|repeatedly|rapid|consecutive|burst|clustered|flood|many\s+times/iu.test(text);
  const iterativeGuess = /비밀번호.{0,30}(?:한\s*글자씩|바꿔|변형|추측)|패스워드.{0,30}(?:바꿔|추측)|password.{0,30}(?:guess|vary|change)|brute[\s-]?force/iu.test(text);
  const passwordSetting = /(?:비밀번호|비번|패스워드|password).{0,20}(?:설정|변경|재설정|reset|set)|(?:설정|변경|재설정).{0,18}(?:비밀번호|비번|패스워드|password)/iu.test(text);
  return {
    ...row, count, accountCount: Math.max(new Set(names).size, ...accountCounts, 0),
    t1110: Array.isArray(tags) && tags.some(tag => /^T1110(?:\.\d{3})?$/u.test(String(tag))),
    windowSeconds: observedWindow, failure, samePassword, multiAccount, repeated,
    iterativeGuess, noSuccess, successAfter, passwordSetting,
    sprayAttempt: /(?:로그인|인증|비밀번호|비번|암호|패스워드|password|login|auth).{0,40}(?:시도|대입|입력|넣었|넣었습니다|추측|guess|attempt|tried|trying)|(?:시도|대입|입력|넣었|넣었습니다|추측|attempt|tries).{0,32}(?:로그인|인증|비밀번호|비번|암호|패스워드|password|login|auth)|password\s*spray(?:ing)?|비밀번호\s*스프레이/iu.test(text),
  };
}

// Fully local, explainable decisions based on observed behavior.
export function createDecider() {
  const windows = new Map();
  let watermark = 0;

  return function decide(alert) {
    const f = facts(alert);
    if (!f.timestamp || !f.sourceAddress || !f.description) {
      return decision(0.5, RAPID.name, '검증된 시각·출발 주소·설명이 부족하여 자동 차단할 수 없습니다.');
    }

    const at = Date.parse(f.timestamp);
    watermark = Math.max(watermark, at);
    const oldest = watermark - patterns.windowSeconds * 1000;
    for (const [key, events] of windows) {
      const fresh = events.filter(event => event.at >= oldest);
      if (fresh.length) windows.set(key, fresh); else windows.delete(key);
    }

    // Count distinct alert IDs from one source, across accounts. Retransmissions
    // must not increase the count, and old events do not extend the window.
    let observedCount = 0;
    if (f.failure && f.count <= 1 && at >= oldest && typeof alert?.id === 'string') {
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
    const timedBurst = f.windowSeconds !== null && f.windowSeconds <= patterns.windowSeconds;
    const explicitSingle = f.count === 1 || /(?:^|[^0-9])1\s*(?:건|번|회|차례)(?:[^0-9]|$)|한\s*번/u.test(f.description);
    const irregular = /(?:간격|주기).{0,14}(?:고르지|불규칙)|irregular|not\s+regular/iu.test(f.description);
    const rapidText = /짧은\s*시간|단시간|순식간|\d+\s*(?:초|분)\s*(?:안|내|이내|동안|간|사이)|within\s*\d+\s*(?:seconds?|minutes?)|in\s*\d+\s*(?:seconds?|minutes?)|rapid|burst|몰림|폭증|급증/iu.test(f.description);
    const deliberateSpray = f.samePassword && f.multiAccount && (f.sprayAttempt || f.failure && f.repeated) && !f.passwordSetting
      && (f.repeated || f.accountCount >= 3 || /spray/iu.test(f.description));
    const clearSpray = deliberateSpray && (!f.successAfter || f.count >= 8) && !explicitSingle;
    const highVolume = f.failure && f.count >= 20 && shortEnough;
    // A sustained, high-rate attack can exceed the normal five-minute window.
    // Do not treat sporadic failures spread over hours as the same evidence.
    const sustainedHighRate = f.failure && f.windowSeconds !== null
      && f.windowSeconds > patterns.windowSeconds && f.windowSeconds <= 3600
      && f.count >= 30 && f.count / f.windowSeconds >= 3 / 60;
    const timedFailures = f.failure && f.count >= 8 && timedBurst;
    const rapidFailures = f.failure && f.count >= 8 && f.repeated && !irregular && shortEnough;
    const strongUncounted = f.failure && !explicitSingle && f.count === 0 && !f.successAfter
      && shortEnough && ((rapidText && f.repeated) || (f.iterativeGuess && f.repeated));
    const iterativeFailures = f.failure && f.iterativeGuess && f.count >= 8 && shortEnough;
    const regularMulti = f.failure && f.accountCount >= 8
      && /같은\s*간격|일정한\s*간격|regular\s*interval/iu.test(f.description) && !irregular;
    const clearObserved = observedCount >= 30;

    if (clearSpray) {
      return decision(1.0, SPRAY.name, '여러 계정에 동일한 비밀번호를 반복 대입한 행동 근거가 있습니다.');
    }
    // A later successful login does NOT erase a clear high-volume attack.
    if (highVolume || sustainedHighRate || timedFailures || rapidFailures || strongUncounted || iterativeFailures || regularMulti || clearObserved) {
      return decision(1.0, RAPID.name, '다량·단시간·반복적인 인증 실패 또는 추측의 근거가 있습니다.');
    }

    const normalHint = /로그아웃|세션\s*유지|자료실\s*화면|로그인\s*상태가\s*유지/iu.test(f.description);
    if ((!f.failure && (normalHint || f.successAfter || /(?:로그인|인증|비밀번호)\s*(?:성공|완료)|logged\s+in|login\s+successful/iu.test(f.description)))
        || (f.successAfter && f.count <= 1)) {
      return decision(0.1, 'normal-event', '대량 또는 반복된 공격 근거가 없는 정상 인증 이벤트입니다.');
    }

    if (f.passwordSetting && !f.failure && !f.sprayAttempt) {
      return decision(0.1, 'normal-event', '비밀번호 설정에 관한 사실만 있고 공격 시도 근거가 없습니다.');
    }

    const suspicious = f.t1110 || f.failure || f.samePassword && f.multiAccount || f.sprayAttempt && f.repeated;
    if (!suspicious) return decision(0.1, 'normal-event', '공격 행동 근거가 없어 기록만 남깁니다.');
    return decision(0.5, f.samePassword && f.multiAccount ? SPRAY.name : RAPID.name,
      '공격 정황은 있으나 확정 차단할 반복·횟수·시간 근거가 부족합니다.');
  };
}

export const decide = createDecider();

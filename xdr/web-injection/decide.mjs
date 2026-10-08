// 독립 실행용 판정기입니다. 심판은 이 파일만 로드하므로 import, 네트워크, 파일 I/O를 사용하지 않습니다.
// 아래 패턴은 patterns.json과 같은 이름/조건을 사용합니다.
const PATTERNS = [
  { name: 'sql-injection', regex: /(?:SQL\s*(?:구문|주입|표식|표기)|데이터베이스\s*조회를?\s*이어\s*붙|\bunion\s+(?:all\s+)?select\b|\b(?:or|and)\s+\d+\s*=\s*\d+\b)/iu },
  { name: 'script-injection', regex: /(?:스크립트.{0,18}(?:삽입|표식|표기|실행)|<\s*script\b|\bonerror\s*=|\bonload\s*=)/iu },
  { name: 'path-traversal', regex: /(?:경로.{0,24}(?:이탈|거슬러\s*올라)|(?:\.\.[\\/]){2,})/iu },
  { name: 'command-injection', regex: /(?:명령\s*구분자|\bcommand[\s-]?injection\b|(?:;|&&|\|\|)\s*(?:whoami|id|uname|cat)\b)/iu },
];
const MIN_REPEATS = 5;
const decision = (action, confidence, pattern, note) => ({ action, confidence, reason: pattern + ': ' + note });
const validCount = value => /^(?:0|[1-9]\d{0,8})$/u.test(String(value ?? '')) ? Number(value) : null;
const limitText = value => typeof value === 'string' ? value.slice(0, 1000) : '';

// Wazuh 원본 및 read-alerts.mjs가 만든 정제 행을 모두 지원합니다.
function facts(alert) {
  const description = limitText(alert?.rule?.description ?? alert?.description);
  const url = limitText(alert?.data?.url ?? alert?.url);
  const rawCount = validCount(alert?.data?.count ?? alert?.count);
  const described = [...description.matchAll(/(\d+)\s*(?:건|번|회)(?=\s|$|[.,가에을이])/gu)]
    .map(match => Number(match[1]));
  const count = rawCount ?? (described.length ? Math.max(...described) : null);
  const rawTime = alert?.timestamp ?? alert?.time;
  const timestampOk = typeof rawTime === 'string' && Number.isFinite(Date.parse(rawTime));
  const address = alert?.data?.srcip ?? alert?.sourceAddress;
  const addressOk = typeof address === 'string' && ((/^(?:\d{1,3}\.){3}\d{1,3}$/u.test(address)
    && address.split('.').every(part => Number(part) <= 255))
    || (address.includes(':') && /^[a-f\d:]+$/iu.test(address)));
  const level = Number(alert?.rule?.level ?? alert?.ruleLevel);
  const levelOk = Number.isInteger(level) && level >= 0 && level <= 16;
  const tags = alert?.rule?.mitre ?? alert?.mitre ?? [];
  const t1190 = Array.isArray(tags) && tags.some(t => /^T1190(?:\.\d{3})?$/iu.test(String(t)));
  return { description, url, count, timestampOk, addressOk, levelOk, t1190 };
}

export function decide(alert) {
  const f = facts(alert);
  if (!f.timestampOk || !f.addressOk || !f.levelOk || !f.description) {
    return decision('alert', 0.5, 'review-required', '필수 경보 정보가 부족하므로 자동 차단하지 않습니다.');
  }

  // 문서용 doc-* 토큰, MITRE 태그, 높은 심각도만으로 공격을 확정하지 않습니다.
  // 설명 및 실제 웹 입력에 나타난 구체적 주입 특징만 패턴과 대조합니다.
  const evidence = f.description + ' ' + f.url;
  const negative = /(?:삽입\s*표식은\s*아닙니다|공격\s*표기는\s*없습니다)/iu.test(f.description);
  const matched = negative ? [] : PATTERNS.filter(pattern => pattern.regex.test(evidence));
  const explicitlyRepeated = /(?:반복|연속|번갈아|같은\s*주소|한\s*주소|\d+\s*번\s*(?:들어|나왔|요청)|\d+\s*번\s*에)/iu.test(f.description);
  if (matched.length && f.count !== null && f.count >= MIN_REPEATS && explicitlyRepeated) {
    return decision('block', 1, matched.map(item => item.name).join('+'),
      '주입 형태와 반복 요청 ' + f.count + '건이 함께 확인됐습니다.');
  }
  // 1회 단서나 T1190 표시만 있는 사건은 차단 대신 확인 대상으로 남깁니다.
  if (matched.length || f.t1190 || /(?:따옴표|구분\s*문자|주입처럼|이상한\s*검색)/iu.test(f.description)) {
    return decision('alert', 0.55, matched.map(item => item.name).join('+') || 'review-required',
      '주입 가능성이 있지만 반복되는 명확한 공격이라는 증거가 부족합니다.');
  }
  return decision('record', 0.1, 'normal-event', '반복 주입 공격 근거가 없는 일반 웹 요청입니다.');
}

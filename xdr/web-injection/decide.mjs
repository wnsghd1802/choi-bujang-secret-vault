import { readFileSync } from 'node:fs';
import { readAlert } from './read-alerts.mjs';

export const patterns = JSON.parse(readFileSync(new URL('./patterns.json', import.meta.url), 'utf8'));
const byName = new Map(patterns.patterns.map(pattern => [pattern.name, pattern]));
const repeated = f => f.count !== null && f.count >= patterns.minimumRepeatCount;
const signal = (f, re) => re.test(f.description) || re.test(f.url);

export function matchPatterns(f) {
  const result = [];
  const description = f.description;
  // 공개 fixture의 doc-* 토큰만으로 공격을 확정하지 않습니다.
  const sql = /SQL.{0,30}(?:구문|주입|표식|표기)|(?:데이터베이스\s*조회).{0,25}(?:이어\s*붙|삽입)|(?:\bunion\s+select\b|\bor\s+1\s*=\s*1\b)/iu;
  const script = /스크립트.{0,25}(?:삽입|표식|표기)|<\s*script\b|\bon\w+\s*=/iu;
  const path = /경로.{0,25}(?:이탈|거슬러\s*올라)|(?:\.\.[\\/]){2,}/iu;
  const command = /명령.{0,20}구분자|\bcommand[\s-]?injection\b|(?:;|&&|\|\|)\s*(?:id|whoami|cat)\b/iu;
  if (signal(f, sql)) result.push(byName.get('sql-injection'));
  if (signal(f, script)) result.push(byName.get('script-injection'));
  if (signal(f, path)) result.push(byName.get('path-traversal'));
  if (signal(f, command)) result.push(byName.get('command-injection'));
  // '스크립트 수업'처럼 공격이 아닌 단어만 등장하는 것은 공격 근거로 쓰지 않습니다.
  if (/삽입\s*표식은\s*아닙니다|공격\s*표기는\s*없습니다/iu.test(description)) return [];
  return result.filter(Boolean);
}
const make = (action, confidence, pattern, explanation) => ({
  action, confidence, reason: pattern + ': ' + explanation,
});

// Jev는 실제 연결 코드가 없으므로 외부에서 제공되는 검증된 함수일 때만 호출합니다.
// ambiguous에 대해서만 호출하며, 실패하거나 연결이 없으면 alert를 유지합니다.
export function createDecider({ jev } = {}) {
  return async function decide(alert) {
    const f = readAlert(alert);
    if (!f.timestamp || !f.sourceAddress || f.ruleLevel === null || !f.description) {
      return make('alert', 0.5, 'review-required', '시각·주소·규칙 등 필수 근거가 부족해 확인이 필요합니다.');
    }
    const hits = matchPatterns(f);
    if (repeated(f) && hits.length > 0) {
      const names = hits.map(hit => hit.name).join('+');
      return make('block', 1, names, '반복 ' + f.count + '건과 주입 특징이 함께 확인되었습니다.');
    }
    const attackHint = hits.length > 0 || f.mitre.some(tag => /^T1190(?:\.\d{3})?$/u.test(tag))
      || /(?:SQL|스크립트|주입|삽입|표기|표식|이상한|구분\s*문자|검색어에\s*따옴표)/iu.test(f.description);
    if (!attackHint) return make('record', 0.1, 'normal-event', '반복 주입 시도의 근거가 없는 정상 웹 요청입니다.');
    if (typeof jev === 'function') {
      try {
        // 원본 경보 및 계정/자격증명은 외부 판단자에 전달하지 않습니다.
        const judged = await jev({ description: f.description, ruleLevel: f.ruleLevel,
          count: f.count, patternNames: hits.map(hit => hit.name) });
        const confidence = typeof judged === 'number' ? judged : judged?.confidence;
        if (typeof confidence === 'number' && Number.isFinite(confidence) && confidence >= 0 && confidence <= 1) {
          return make(confidence >= 0.85 ? 'block' : confidence >= 0.5 ? 'alert' : 'record', confidence,
            hits[0]?.name ?? 'review-required', '불확실한 웹 입력에 대한 외부 판단 점수입니다.');
        }
      } catch { /* 연결 실패는 알림 유지 */ }
    }
    return make('alert', 0.5, hits[0]?.name ?? 'review-required', '주입 의심 근거는 있으나 반복된 명확한 공격으로 확정할 수 없습니다.');
  };
}
export const decide = createDecider();

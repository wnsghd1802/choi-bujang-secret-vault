import { STAGE12_CASES, checkedResult } from './stage12-cases.mjs';
import { decide, RULE_IDS } from './decider.mjs';
import { detect } from './detect.mjs';

const $ = id => document.getElementById(id);
const recordMap = new Map();
const expectedRepo = 'https://github.com/wnsghd1802/choi-bujang-secret-vault';
const allowedOrigins = new Set(['live-api', 'local-fixture', 'imported']);
const displayedTime = date => date ? new Date(date).toLocaleString('ko-KR') : '—';
const byId = new Map(STAGE12_CASES.map(item => [item.id, item]));
const addText = (node, value) => { node.textContent = String(value ?? '—'); return node; };
const element = (tag, value) => addText(document.createElement(tag), value);
const safeDate = value => typeof value === 'string'
  && /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?Z$/u.test(value)
  && Number.isFinite(Date.parse(value)) && Date.parse(value) <= Date.now() + 300000;

function saveEvidence(rec) {
  recordMap.set(rec.id, rec);
  render();
}
function viewState(rec) {
  if (!rec) return '미실행';
  if (rec.origin === 'imported') return '가져온 기록 · 재확인 필요';
  if (rec.result === 'error') return '검사 오류';
  return rec.passed ? (rec.origin === 'live-api' ? '현장 API 일치' : '로컬 모의 일치')
    : (rec.origin === 'live-api' ? '현장 API 불일치' : '로컬 모의 불일치');
}
function render() {
  const stage = $('warroom-stage').value;
  const state = $('warroom-filter').value;
  const rows = STAGE12_CASES.filter(item => {
    const rec = recordMap.get(item.id);
    const group = !rec ? 'pending' : rec.origin === 'imported' ? 'imported'
      : rec.passed ? 'pass' : 'fail';
    return (stage === 'all' || String(item.stage) === stage)
      && (state === 'all' || state === group);
  });
  const tbody = $('warroom-rows');
  const fragment = document.createDocumentFragment();
  for (const item of rows) {
    const rec = recordMap.get(item.id);
    const tr = document.createElement('tr');
    for (const value of [
      item.id, item.title, item.method + ' ' + item.path, item.expected,
      rec?.observed ?? '미실행 · 실제 결과 없음',
      rec?.requestId ? rec.requestId + (rec.serverRequestId ? ' (서버: ' + rec.serverRequestId + ')' : ' (클라이언트 발급)') : '—',
      displayedTime(rec?.checkedAt),
      viewState(rec),
    ]) tr.append(element('td', value));
    tr.cells[4].className = 'audit-observed';
    fragment.append(tr);
  }
  tbody.replaceChildren(fragment);
  $('warroom-total').textContent = String(STAGE12_CASES.length);
  const records = [...recordMap.values()];
  $('warroom-live').textContent = String(records.filter(rec => rec.origin === 'live-api' && rec.passed).length);
  $('warroom-local').textContent = String(records.filter(rec => rec.origin === 'local-fixture' && rec.passed).length);
  $('warroom-missing').textContent = String(STAGE12_CASES.length - records.filter(rec => rec.origin !== 'imported').length);
  $('warroom-visible').textContent = String(rows.length);
}
function makeRecord(item, fields) {
  return {
    id: item.id, method: item.method, path: item.path,
    requestId: crypto.randomUUID(), checkedAt: new Date().toISOString(),
    serverRequestId: null, httpStatus: null, origin: 'live-api',
    result: 'ok', passed: false, observed: '', ...fields,
  };
}
async function runSafeProbes() {
  const button = $('warroom-safe-run');
  button.disabled = true;
  $('warroom-feedback').textContent = '읽기 전용 공개·익명 요청을 확인하고 있습니다. 쓰기·복구 요청은 보내지 않습니다.';
  try {
    for (const item of STAGE12_CASES.filter(row => row.probe)) {
      const rec = makeRecord(item, {});
      try {
        // No cookie, bearer token, signing key, private note body or mutation.
        const response = await fetch(item.path, {
          method: 'GET', credentials: 'omit', cache: 'no-store', redirect: 'error',
          referrerPolicy: 'no-referrer', signal: AbortSignal.timeout(8000),
        });
        const data = item.probe === 'root-headers' ? null
          : await response.json().catch(() => null);
        rec.httpStatus = response.status;
        const requestId = response.headers.get('x-request-id');
        rec.serverRequestId = requestId && /^[A-Za-z0-9_-]{1,100}$/u.test(requestId) ? requestId : null;
        rec.passed = checkedResult(item, response.status, data, response.headers,
          { repoUrl: expectedRepo });
        rec.observed = 'HTTP ' + response.status + (rec.passed ? ' · 예상 조건 충족' : ' · 예상 조건 불충족');
        if (item.probe === 'identity') {
          const matching = data?.step === 12 && data?.repoUrl === expectedRepo;
          $('warroom-version').textContent = matching && /^[a-f0-9]{40}$/u.test(data?.commit ?? '')
            ? data.commit.slice(0, 12) + ' (배포 커밋)'
            : '단계·저장소·커밋 정보 재확인 필요';
        }
      } catch {
        rec.result = 'error';
        rec.observed = '요청·파싱 실패 (실제 응답 미확인)';
      }
      saveEvidence(rec);
    }
    $('warroom-feedback').textContent = '익명 GET만 확인했습니다. 인증·권한·복구·운영 회수 항목은 별도 확인이 필요합니다.';
  } finally { button.disabled = false; }
}
export function fixtureRequest(caseId, requestId) {
  const req = {
    schema: 'aleph.decision.v1', requestId, classId: 'class_fixture',
    projectId: 'project_fixture', subjectId: 'subject_fixture',
    deviceId: 'aaaaaaaaaaaaaaaa', service: 'notes',
    method: 'GET', route: 'GET /notes/:id', path: '/notes/demo', queryLength: 0,
    querySha256: '0'.repeat(64), at: new Date().toISOString(), policyRevision: 'local-fixture',
    deviceRegistered: true, stepUp: { verified: false, authAgeSeconds: null },
    signals: { source: 'judge_fixture', region: 'local', network: 'usual', hour: 14 },
    recentEvents: [],
  };
  if (caseId === 'S06-02') req.deviceRegistered = false;
  if (caseId === 'S06-03') req.deviceRegistered = 'true';
  if (caseId === 'S07-02' || caseId === 'S07-03') {
    req.signals = { source: 'judge_fixture', region: 'foreign', network: 'unusual', hour: 3 };
    req.recentEvents = [{ kind: 'risk_signal', ageSeconds: 60, count: 20 }];
  }
  if (caseId === 'S07-03') req.stepUp = { verified: true, authAgeSeconds: 60 };
  if (caseId === 'S08-02') req.queryLength = 1;
  if (caseId === 'S08-04') { req.route = 'GET /api/notes'; req.path = '/api/notes'; }
  return req;
}
const expectedDecisions = {
  'S06-01': 'allow', 'S06-02': 'deny', 'S06-03': 'deny',
  'S07-01': 'allow', 'S07-02': 'step_up', 'S07-03': 'allow',
  'S08-01': 'allow', 'S08-02': 'deny', 'S08-04': 'deny',
};
const eventSeries = (n, subject = 'fixture_a') =>
  Array.from({ length: n }, (_, i) => ({
    at: new Date(Date.UTC(2026, 9, 1) + i * 2000).toISOString(),
    method: 'GET', identity: { sub: subject },
  }));
const expectedDetections = { 'S09-01': 'observe', 'S09-02': 'propose_revocation', 'S09-03': 'observe' };

async function runLocalFixtures() {
  const button = $('warroom-local-run');
  button.disabled = true;
  try {
    for (const item of STAGE12_CASES.filter(row => row.id in expectedDecisions || row.id in expectedDetections)) {
      const rec = makeRecord(item, { origin: 'local-fixture' });
      try {
        if (item.id in expectedDecisions) {
          const result = await decide(fixtureRequest(item.id, rec.requestId));
          rec.passed = result.schema === 'aleph.decision.v1' && result.requestId === rec.requestId
            && result.decision === expectedDecisions[item.id]
            && Array.isArray(result.ruleIds) && result.ruleIds.length > 0
            && result.ruleIds.every(rule => RULE_IDS.includes(rule))
            && Object.keys(result).sort().join(',') === 'decision,reasonCode,requestId,ruleIds,schema';
          rec.observed = '로컬 decide(): ' + String(result.decision ?? '형식 오류');
        } else {
          const events = item.id === 'S09-01' ? eventSeries(120)
            : item.id === 'S09-02' ? eventSeries(121)
            : [...eventSeries(100), ...eventSeries(100, 'fixture_b')];
          const result = detect(events);
          rec.passed = result?.action === expectedDetections[item.id];
          rec.observed = '로컬 detect(): ' + String(result?.action ?? '형식 오류');
        }
      } catch {
        rec.result = 'error';
        rec.observed = '로컬 모의 호출 실패';
      }
      saveEvidence(rec);
    }
    $('warroom-feedback').textContent = '로컬 모의 검사를 기록했습니다. 운영 API·심판의 실행 결과는 아닙니다.';
  } finally { button.disabled = false; }
}
function exportRecords() {
  const exported = {
    schema: 'aleph.stage12.evidence.v1',
    disclaimer: '브라우저 자체 기록이며 독립적인 심판 또는 서버 서명 증거가 아닙니다.',
    records: [...recordMap.values()].filter(rec => rec.origin !== 'imported'),
  };
  const blob = new Blob([JSON.stringify(exported, null, 2) + '\n'], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url; a.download = 'stage12-browser-evidence.json';
  a.click(); URL.revokeObjectURL(url);
}
function validateImported(raw) {
  if (!raw || raw.schema !== 'aleph.stage12.evidence.v1' || !Array.isArray(raw.records)
      || raw.records.length > 41) throw new Error('증거 JSON 버전 또는 기록 수가 올바르지 않습니다.');
  const seen = new Set();
  const allowedKeys = new Set(['id', 'method', 'path', 'requestId', 'checkedAt',
    'serverRequestId', 'httpStatus', 'origin', 'result', 'passed', 'observed']);
  const output = [];
  for (const item of raw.records) {
    const info = byId.get(item?.id);
    if (!info || seen.has(item.id) || Object.keys(item).some(key => !allowedKeys.has(key))
      || !['live-api', 'local-fixture'].includes(item.origin)
      || info.method !== item.method || info.path !== item.path
      || !safeDate(item.checkedAt) || typeof item.requestId !== 'string'
      || !/^[0-9a-f-]{36}$/iu.test(item.requestId) || typeof item.observed !== 'string'
      || item.observed.length > 180 || typeof item.passed !== 'boolean'
      || !['ok', 'error'].includes(item.result)
      || (item.httpStatus !== null && (!Number.isInteger(item.httpStatus)
        || item.httpStatus < 100 || item.httpStatus > 599))
      || (item.origin === 'local-fixture' && item.httpStatus !== null)
      || (item.origin === 'live-api' && !info.probe)
      || (item.serverRequestId !== null && (typeof item.serverRequestId !== 'string'
        || !/^[A-Za-z0-9_-]{1,100}$/u.test(item.serverRequestId)))) {
      throw new Error('검사 ID·경로·시각 또는 응답 형식이 올바르지 않습니다.');
    }
    seen.add(item.id);
    // Imported claims are never elevated to independently verified results.
    output.push({ ...item, origin: 'imported', serverRequestId: null });
  }
  return output;
}
async function importRecords(event) {
  const input = event.target;
  const file = input.files?.[0];
  if (!file) return;
  try {
    if (file.size > 100000) throw new Error('파일이 너무 큽니다.');
    const parsed = JSON.parse(await file.text());
    const records = validateImported(parsed);
    // Atomic update: do not touch existing evidence when parsing or validation fails.
    for (const rec of records) {
      const existing = recordMap.get(rec.id);
      if (!existing || existing.origin === 'imported') recordMap.set(rec.id, rec);
    }
    render();
    $('warroom-feedback').textContent = '기록을 가져왔습니다. 기존의 직접 실행 증거를 덮어쓰지 않으며, 외부 기록은 통과로 집계하지 않습니다.';
  } catch (error) {
    $('warroom-feedback').textContent = '가져오기 실패: ' + error.message + ' · 기존 기록은 유지했습니다.';
  } finally { input.value = ''; }
}
export function initWarRoom() {
  if (!$('warroom')) return;
  $('warroom-policy').textContent = RULE_IDS.join(' · ');
  $('warroom-detection').textContent = '10분 내 동일 주체 GET 120건 초과 → 회수 제안 (운영 집행 미확인)';
  $('warroom-revocation').textContent = '실제 접속 회수 기록 없음 · 실행 확인 필요';
  $('warroom-version').textContent = '배포 버전 미확인 (익명 API 검사로 확인)';
  $('warroom-safe-run').addEventListener('click', () => void runSafeProbes());
  $('warroom-local-run').addEventListener('click', () => void runLocalFixtures());
  $('warroom-export').addEventListener('click', exportRecords);
  $('warroom-import').addEventListener('change', event => void importRecords(event));
  $('warroom-filter').addEventListener('change', render);
  $('warroom-stage').addEventListener('change', render);
  render();
}

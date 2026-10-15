import { test } from 'node:test';
import assert from 'node:assert/strict';
import { STAGE12_CASES, STAGE12_PROBES, checkedResult } from '../src/stage12-cases.mjs';
import { deploymentIdentity } from '../scripts/deployment-identity.mjs';
import { decide, RULE_IDS } from '../src/decider.mjs';
import { detect } from '../src/detect.mjs';
import { fixtureRequest } from '../src/stage12-workroom.js';
import config from '../aleph.config.json' with { type: 'json' };

test('stage 12 has exactly 41 different scenarios across stages 1-11', () => {
  assert.equal(config.step, 12);
  assert.equal(STAGE12_CASES.length, 41);
  assert.equal(new Set(STAGE12_CASES.map(row => row.id)).size, 41);
  const counts = [2, 3, 5, 4, 4, 3, 3, 4, 4, 5, 4];
  for (let step = 1; step <= 11; step++) {
    assert.equal(STAGE12_CASES.filter(row => row.stage === step).length, counts[step - 1]);
  }
  for (const row of STAGE12_CASES) {
    for (const name of ['id', 'stage', 'title', 'kind', 'method', 'path', 'expected']) assert.ok(row[name]);
    assert.ok(['api', 'engine', 'operation', 'static'].includes(row.kind));
  }
});
test('automatic browser probes are only anonymous GET requests', () => {
  const probed = STAGE12_CASES.filter(row => row.probe);
  assert.equal(probed.length, 9);
  assert.ok(probed.every(row => row.kind === 'api' && row.method === 'GET'
    && row.path.startsWith('/') && STAGE12_PROBES.has(row.probe)));
  assert.ok(STAGE12_CASES.every(row => row.method === 'GET' || !row.probe));
});
test('result checks do not turn unavailable, unauthorized or wrong-stage data into success', () => {
  const headers = new Headers({ 'X-Content-Type-Options': 'nosniff' });
  const id = { repoUrl: config.repoUrl };
  const c = probe => STAGE12_CASES.find(row => row.probe === probe);
  assert.equal(checkedResult(c('public-data'), 200, { notes: [] }, headers, id), true);
  assert.equal(checkedResult(c('public-data'), 200, { notes: [{ body: 'must not show' }] }, headers, id), false);
  assert.equal(checkedResult(c('root-headers'), 200, null, headers, id), true);
  assert.equal(checkedResult(c('root-headers'), 200, null, new Headers(), id), false);
  assert.equal(checkedResult(c('anonymous-notes'), 401, { error: '로그인이 필요합니다.' }, headers, id), true);
  assert.equal(checkedResult(c('anonymous-notes'), 200, {}, headers, id), false);
  assert.equal(checkedResult(c('anonymous-device'), 403, {}, headers, id), false);
  assert.equal(checkedResult(c('identity'), 200, { step: 11, repoUrl: config.repoUrl, commit: 'a'.repeat(40) }, headers, id), false);
  assert.equal(checkedResult(c('identity'), 200, { step: 12, repoUrl: config.repoUrl, commit: 'a'.repeat(40) }, headers, id), true);
});
test('deployment identity accepts 12 and preserves judge issuer', () => {
  const env = {
    VERCEL_GIT_PROVIDER: 'github', VERCEL_GIT_REPO_OWNER: 'wnsghd1802',
    VERCEL_GIT_REPO_SLUG: 'choi-bujang-secret-vault',
    VERCEL_GIT_COMMIT_SHA: 'a'.repeat(40),
    VERCEL_URL: 'choi-bujang-secret-vault-pied.vercel.app',
  };
  const result = deploymentIdentity(env, config);
  assert.equal(result.step, 12);
  assert.equal(result.judgeIssuer, config.judgeIssuer);
  assert.equal(result.repoUrl, config.repoUrl);
  assert.equal(result.originalApiUrl, config.originalApiUrl);
});
test('stage 6-8 local rule decisions still work without changing the decision contract', async () => {
  const base = {
    schema: 'aleph.decision.v1', requestId: 'test-stage12-fixture', classId: 'fixture', projectId: 'fixture',
    subjectId: 'fixture', deviceId: 'aaaaaaaaaaaaaaaa', service: 'notes',
    method: 'GET', route: 'GET /notes/:id', path: '/notes/demo', queryLength: 0,
    signals: { source: 'judge_fixture', region: 'local', network: 'usual', hour: 12 },
    recentEvents: [], deviceRegistered: true, stepUp: { verified: false, authAgeSeconds: null },
  };
  const allowed = await decide(base);
  assert.equal(allowed.decision, 'allow');
  assert.ok(allowed.ruleIds.every(rule => RULE_IDS.includes(rule)));
  assert.equal((await decide({ ...base, deviceRegistered: false })).decision, 'deny');
  assert.equal((await decide({ ...base, queryLength: 1 })).decision, 'deny');
  const risky = { ...base, signals: { source: 'judge_fixture', region: 'foreign', network: 'unusual', hour: 3 },
    recentEvents: [{ kind: 'risk_signal', ageSeconds: 60, count: 20 }] };
  assert.equal((await decide(risky)).decision, 'step_up');
  assert.equal((await decide({ ...risky, stepUp: { verified: true, authAgeSeconds: 60 } })).decision, 'allow');
});
test('stage 9 detector only proposes revocation in a local test, not execution', () => {
  const e = n => Array.from({ length: n }, (_, i) => ({
    method: 'GET', at: new Date(Date.UTC(2026, 9, 1) + i * 2000).toISOString(),
    identity: { sub: 'fixture' },
  }));
  assert.deepEqual(detect(e(120)), { action: 'observe' });
  assert.deepEqual(detect(e(121)), {
    action: 'propose_revocation', reasonCode: 'burst_read', subject: 'fixture',
  });
});

test('stage 12 workroom selects each fixture by case ID while preserving request ID', async () => {
  const requestId = '123e4567-e89b-42d3-a456-426614174000';
  const cases = [
    ['S06-01', 'allow'], ['S06-02', 'deny'], ['S06-03', 'deny'],
    ['S07-01', 'allow'], ['S07-02', 'step_up'], ['S07-03', 'allow'],
    ['S08-01', 'allow'], ['S08-02', 'deny'], ['S08-04', 'deny'],
  ];
  for (const [caseId, expected] of cases) {
    const request = fixtureRequest(caseId, requestId);
    assert.equal(request.requestId, requestId, caseId);
    const response = await decide(request);
    assert.equal(response.requestId, requestId, caseId);
    assert.equal(response.decision, expected, caseId);
    assert.ok(response.ruleIds.every(rule => RULE_IDS.includes(rule)), caseId);
  }
});

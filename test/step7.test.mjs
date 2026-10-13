import assert from 'node:assert/strict';
import { test } from 'node:test';
import { decide, RULE_IDS } from '../src/decider.mjs';

const request = () => ({
  schema: 'aleph.decision.v1',
  requestId: '8ecc7c0d-e793-4cb0-9f68-a8665e0daa55',
  classId: 'class_fixture', projectId: 'project_fixture',
  subjectId: 'learner_fixture', deviceId: 'aaaaaaaaaaaaaaaa',
  service: 'notes', method: 'GET', path: '/notes/demo', route: 'GET /notes/:id',
  queryLength: 0, deviceRegistered: true,
  signals: { source: 'judge_fixture', region: 'local', network: 'usual', hour: 14 },
  recentEvents: [],
  stepUp: { verified: false, authAgeSeconds: null },
});
const anomaly = () => ({
  ...request(),
  signals: { source: 'judge_fixture', region: 'foreign', network: 'unusual', hour: 3 },
  recentEvents: [{ kind: 'risk_signal', ageSeconds: 60, count: 20 }],
});
async function expectDecision(input, decision, reasonCode) {
  const output = await decide(input);
  assert.deepEqual(Object.keys(output).sort(), ['decision','reasonCode','requestId','ruleIds','schema']);
  assert.equal(output.schema, 'aleph.decision.v1');
  assert.equal(output.requestId, input.requestId);
  assert.equal(output.decision, decision);
  assert.equal(output.reasonCode, reasonCode);
  assert.ok(output.ruleIds.length > 0 && output.ruleIds.every(rule => RULE_IDS.includes(rule)));
}

test('stage 6 and 7 rules remain implemented', () => {
  assert.ok(RULE_IDS.includes('device_registered'));
  assert.ok(RULE_IDS.includes('step_up_required'));
});
test('registered normal request allows', async () => {
  await expectDecision(request(), 'allow', 'approved');
});
test('unregistered request denies even after step-up', async () => {
  await expectDecision({ ...anomaly(), deviceRegistered: false,
    stepUp: { verified: true, authAgeSeconds: 60 } }, 'deny', 'device_not_registered');
});
test('missing or invalid registration denies', async () => {
  for (const flag of [undefined, null, 'true', 1]) {
    await expectDecision({ ...request(), deviceRegistered: flag }, 'deny', 'device_not_registered');
  }
});
test('composite anomaly requires verification', async () => {
  await expectDecision(anomaly(), 'step_up', 'step_up_required');
});
test('confirmed fresh step-up re-allows simulated request', async () => {
  await expectDecision({ ...anomaly(), stepUp: { verified: true, authAgeSeconds: 60 } },
    'allow', 'approved');
});
test('missing or invalid step-up does not bypass verification', async () => {
  for (const stepUp of [undefined, { verified: false, authAgeSeconds: null },
    { verified: true, authAgeSeconds: null },
    { verified: true, authAgeSeconds: 901 },
    { verified: true, authAgeSeconds: -1 },
    { verified: 'true', authAgeSeconds: 60 }]) {
    await expectDecision({ ...anomaly(), stepUp }, 'step_up', 'step_up_required');
  }
});
test('one signal or stale and small activity burst does not step up', async () => {
  for (const patch of [
    { signals: { ...anomaly().signals, network: 'usual' } },
    { signals: { ...anomaly().signals, region: 'local' } },
    { signals: { ...anomaly().signals, hour: 14 } },
    { recentEvents: [] },
    { recentEvents: [{ kind: 'risk_signal', ageSeconds: 301, count: 20 }] },
    { recentEvents: [{ kind: 'risk_signal', ageSeconds: 60, count: 9 }] },
  ]) await expectDecision({ ...anomaly(), ...patch }, 'allow', 'approved');
});
test('unverified signal source is never treated as location evidence', async () => {
  for (const source of ['none', 'other', undefined]) {
    await expectDecision({ ...anomaly(),
      signals: { ...anomaly().signals, source } }, 'allow', 'approved');
  }
});

import assert from 'node:assert/strict';
import { test } from 'node:test';
import { decide, RULE_IDS } from '../src/decider.mjs';
import { fixtureRequests } from '../scripts/fixture-7.mjs';

// Judge-style independent invocation: no API, no DB or browser is imported.
const { normal, suspicious } = fixtureRequests();
async function check(input, decision, reasonCode) {
  const output = await decide(input);
  assert.equal(output.decision, decision);
  assert.equal(output.reasonCode, reasonCode);
  assert.equal(output.schema, 'aleph.decision.v1');
  assert.equal(output.requestId, input.requestId);
  assert.deepEqual(Object.keys(output).sort(),
    ['decision','reasonCode','requestId','ruleIds','schema']);
  assert.ok(output.ruleIds.length && output.ruleIds.every(id => RULE_IDS.includes(id)));
}

test('6th stage normal registration still allows', async () => check(normal, 'allow','approved'));
test('6th stage unregistered device still denies', async () =>
  check({ ...normal, deviceRegistered: false }, 'deny','device_not_registered'));
test('7th stage composite anomaly still step-ups', async () =>
  check(suspicious, 'step_up','step_up_required'));
test('7th stage fresh verification still allows', async () =>
  check({ ...suspicious, stepUp: { verified:true, authAgeSeconds:60 } },
    'allow','approved'));
test('unknown location source does not deny normal 7th stage fixture', async () => {
  for (const source of ['none','other',undefined]) {
    await check({ ...normal, signals: { ...normal.signals, source } }, 'allow','approved');
  }
});
test('individual note routes reach API ownership enforcement', async () => {
  for (const path of ['/notes/other-person','/notes/memo-foreign',
    '/notes/33333333-3333-4333-8333-333333333333']) {
    await check({ ...normal, path }, 'allow','approved');
  }
});
test('decider does not make up per-item owners from subject names', async () =>
  check({ ...normal, subjectId: 'different_subject' }, 'allow','approved'));
test('individual GET/PUT allow for API ownership check; DELETE and notice writes deny', async () => {
  const id = '33333333-3333-4333-8333-333333333333';
  for (const [route,method,path] of [
    ['GET /api/notes/:id','GET','/api/notes/'+id],
    ['PUT /api/notes/:id','PUT','/api/notes/'+id],
  ]) await check({ ...normal, route,method,path }, 'allow','approved');
  for (const [route,method,path] of [
    ['DELETE /api/notes/:id','DELETE','/api/notes/'+id],
    ['PUT /api/notices/:id','PUT','/api/notices/'+id],
  ]) await check({ ...normal, route,method,path }, 'deny','starter_not_ready');
});
test('collection reads and creates are never granted by decider', async () => {
  await check({ ...normal, method:'GET',route:'GET /notes',path:'/notes' }, 'deny','starter_not_ready');
  await check({ ...normal, method:'GET',route:'GET /api/notes',path:'/api/notes' }, 'deny','starter_not_ready');
  await check({ ...normal, method:'POST',route:'POST /api/notes',path:'/api/notes' }, 'deny','starter_not_ready');
});
test('query feature selector or nested path never permits zone crossover', async () => {
  await check({ ...normal,method:'GET',route:'GET /api/notes',
    path:'/api/notes',queryLength:10 }, 'deny','starter_not_ready');
  await check({ ...normal,path:'/notes/demo/export' }, 'deny','starter_not_ready');
});

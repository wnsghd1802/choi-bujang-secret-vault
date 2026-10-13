import { test } from 'node:test';
import assert from 'node:assert/strict';
import { detect } from '../src/detect.mjs';

const START = Date.UTC(2026, 9, 1);
const read = (n, { gap = 2000, sub = 'learner_fixture', start = START, method = 'GET' } = {}) =>
  Array.from({ length: n }, (_, i) => ({
    at: new Date(start + i * gap).toISOString(), method, identity: { sub },
  }));
const rev = sub => ({ action: 'propose_revocation', reasonCode: 'burst_read', subject: sub });
const obs = { action: 'observe' };

test('30 normal events are observed', () => assert.deepEqual(detect(read(30)), obs));
test('exactly 120 reads within ten minutes is observed', () => assert.deepEqual(detect(read(120)), obs));
test('121 reads within ten minutes proposes revocation', () => assert.deepEqual(detect(read(121)), rev('learner_fixture')));
test('200 reads within ten minutes proposes revocation', () => assert.deepEqual(detect(read(200)), rev('learner_fixture')));
test('different subjects are not aggregated', () =>
  assert.deepEqual(detect([...read(100), ...read(100, { sub: 'other_fixture' })]), obs));
test('200 reads over greater than ten minutes do not trigger', () =>
  assert.deepEqual(detect(read(200, { gap: 7000 })), obs));
test('ten minute inclusive boundary can contain 121 events', () =>
  assert.deepEqual(detect(read(121, { gap: 5000 })), rev('learner_fixture')));
test('just beyond the ten minute boundary cannot contain 121', () =>
  assert.deepEqual(detect(read(121, { gap: 5001 })), obs));
test('GET only; exclude POST and PUT', () =>
  assert.deepEqual(detect([...read(100), ...read(200, { method: 'POST' }),
    ...read(10, { method: 'PUT' })]), obs));
test('sliding window catches local burst in otherwise long history', () =>
  assert.deepEqual(detect([...read(300, { gap: 20000 }),
    ...read(121, { start: START + 86400000 })]), rev('learner_fixture')));
test('out-of-order events produce same result and do not mutate input', () => {
  const input = [...read(121)].reverse();
  const copy = structuredClone(input);
  assert.deepEqual(detect(input), rev('learner_fixture'));
  assert.deepEqual(input, copy);
});
test('same timestamp does not reduce the request count', () =>
  assert.deepEqual(detect(read(121, { gap: 0 })), rev('learner_fixture')));
test('invalid or incomplete events cannot create false positives', () =>
  assert.deepEqual(detect([...read(30),
    { method: 'GET', at: 'invalid', identity: { sub: 'learner_fixture' } },
    { method: 'GET', at: new Date(START).toISOString(), identity: {} }]), obs));
test('multiple suspicious identities return earliest detector (stable tie)', () =>
  assert.deepEqual(detect([...read(121, { sub: 'b' }), ...read(121, { sub: 'a' })]), rev('a')));
test('non-array input violates contract', () =>
  assert.throws(() => detect(null), { name: 'TypeError' }));

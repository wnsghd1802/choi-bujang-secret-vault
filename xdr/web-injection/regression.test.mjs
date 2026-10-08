import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createDecider } from './decide.mjs';
import { readAlert } from './read-alerts.mjs';
import { createDenyStore, withXdrGuard } from './enforce.mjs';

const make = (id, description, count, level = 11, mitre = ['T1190']) => ({
  id, timestamp: '2026-09-27T09:13:01+09:00',
  rule: { level, description, mitre },
  data: { srcip: '203.0.113.10', url: '/search?q=doc-marker',
    ...(count === null ? {} : { count: String(count) }) },
});
test('반복된 주입 네 유형은 block', async () => {
  for (const row of [
    make('sql', 'SQL 구문을 이어 붙인 요청이 12번 반복됐습니다.', 12),
    make('script', '스크립트 삽입 표기가 9번 반복됐습니다.', 9),
    make('path', '경로를 여러 단계 거슬러 올라가는 표기가 8번 반복됐습니다.', 8),
    make('cmd', '명령 구분자 표기가 연속 요청 11번에 있습니다.', 11),
  ]) {
    const r = await createDecider()(row);
    assert.equal(r.action, 'block');
    assert.equal(r.confidence, 1);
  }
});
test('정상은 record, 애매한 것은 alert; Jev는 애매할 때만 사용', async () => {
  let calls = 0;
  const decide = createDecider({ jev: async () => { calls++; return 0.6; } });
  assert.equal((await decide(make('b', 'SQL 구문 표기가 20번 반복됐습니다.', 20))).action, 'block');
  assert.equal((await decide(make('a', '검색어에 따옴표가 한 번 들어 있습니다.', 1, 6))).action, 'alert');
  assert.equal((await decide(make('n', '자료 목록을 조회했습니다.', null, 3, []))).action, 'record');
  assert.equal(calls, 1);
});
test('비밀번호·토큰처럼 보이는 값은 추출 결과와 판정 이유에서 가림', async () => {
  const row = make('safe', 'password=demo-placeholder token=dummy-token SQL 구문 표기', 1);
  assert.doesNotMatch(JSON.stringify(readAlert(row)), /demo-placeholder|dummy-token/);
  assert.doesNotMatch((await createDecider()(row)).reason, /demo-placeholder|dummy-token/);
});
test('정상 요청은 이전 판정기를 통과하며 거부 후보는 만료', async () => {
  const now = Date.parse('2026-09-27T09:13:30+09:00');
  const store = createDenyStore();
  const attack = make('a1', 'SQL 구문 표기가 12번 반복됐습니다.', 12);
  const normal = make('n1', '자료 목록을 조회했습니다.', null, 3, []);
  assert.equal(store.add(normal, await createDecider()(normal), now), null);
  const rule = store.add(attack, await createDecider()(attack), now);
  assert.deepEqual(rule.evidenceAlertIds, ['a1']);
  const guarded = withXdrGuard(req => ({ decision: 'allow', requestId: req.requestId }), {
    store, now: () => now, resolveVerifiedSourceIp: req => req.ip,
    denyResponse: (req, rule) => ({
      schema: 'aleph.decision.v1', requestId: req.requestId,
      decision: 'deny', reasonCode: 'web-injection', ruleIds: [rule.ruleId],
    }),
  });
  assert.equal((await guarded({ requestId: 'x', ip: '203.0.113.10' })).decision, 'deny');
  assert.equal((await guarded({ requestId: 'y', ip: '198.51.100.11' })).decision, 'allow');
  assert.equal(store.check('203.0.113.10', Date.parse(rule.expiresAt)), null);
});

import assert from 'node:assert/strict';
import { test } from 'node:test';
import { readFile } from 'node:fs/promises';
import { loadFixture, readAlerts, readAlert } from '../xdr/brute-force/read-alerts.mjs';
import { createDecider } from '../xdr/brute-force/decide.mjs';
import { createDenyStore, withXdrGuard } from '../xdr/brute-force/enforce.mjs';

const fixture = await loadFixture();
const event = (changes = {}) => ({ id: 'custom-event', timestamp: '2026-09-27T00:00:00Z',
  rule: { level: 12, description: '같은 주소에서 2분 동안 로그인 실패 40건', mitre: ['T1110'] },
  data: { srcip: '192.0.2.100', srcuser: 'user99', count: '40' }, ...changes });

test('공식 28건을 누락 없이 읽고 수동 검토한 공격/의심/정상과 일치한다', async () => {
  const rows = await readAlerts();
  assert.equal(rows.length, fixture.alerts.length);
  const decide = createDecider();
  // Independently reviewed fixture expectations: IDs are never used in detector rules.
  for (const alert of fixture.alerts) {
    const number = Number(alert.id.split('-')[1]);
    const expected = number <= 10 ? 'block' : number <= 19 ? 'alert' : 'record';
    assert.equal((await decide(alert)).action, expected, alert.id);
  }
});

test('새 주소/계정/경보 번호에서도 패턴이 동작하고 장시간 집계는 차단하지 않는다', async () => {
  assert.equal((await createDecider()(event())).action, 'block');
  const slow = event({ rule: { level: 12, description: '2시간 동안 로그인 실패 40건', mitre: ['T1110'] } });
  assert.equal((await createDecider()(slow)).action, 'alert');
  assert.equal((await createDecider()(event({ data: { srcip: 'bad', srcuser: 'user99', count: '40' } }))).action, 'alert');
  assert.equal((await createDecider()(event({ rule: { level: 12, description: '파일 읽기 성공', mitre: [] } }))).action, 'record');
});

test('낱개 실패를 5분 창으로 모으고 재전송은 중복 계산하지 않는다', async () => {
  const decide = createDecider();
  const single = event({ rule: { level: 3, description: '로그인 실패', mitre: [] },
    data: { srcip: '192.0.2.100', srcuser: 'user99', count: '1' } });
  for (let i = 0; i < 40; i++) assert.notEqual((await decide(single)).action, 'block');
  for (let i = 1; i < 29; i++) assert.notEqual((await decide({ ...single, id: `unique-${i}` })).action, 'block');
  assert.equal((await decide({ ...single, id: 'unique-29' })).action, 'block');
  assert.notEqual((await decide({ ...single, id: 'other-account', data: { ...single.data, srcuser: 'user98' } })).action, 'block');
  assert.notEqual((await decide({ ...single, id: 'later', timestamp: '2026-09-27T00:06:00Z' })).action, 'block');
});

test('애매한 경보는 T1110 태그만으로 차단하지 않는다', async () => {
  for (const alert of fixture.alerts.slice(10, 19)) {
    const out = await createDecider()(alert);
    assert.equal(out.action, 'alert', alert.id);
    assert.equal(out.confidence, 0.5, alert.id);
  }
});

test('일반 로그인 성공은 기록하고, 약한 정황과 단일 실패는 차단하지 않는다', async () => {
  assert.equal((await createDecider()(fixture.alerts[19])).action, 'record');
  const weak = event({ rule: { level: 12, description: '여러 사용자에게 동일 비번을 설정했습니다.', mitre: ['T1110'] } });
  const out = await createDecider()(weak);
  assert.notEqual(out.action, 'block');
  assert.equal((await createDecider()(event({
    rule: { level: 7, description: '같은 계정 로그인 실패 4건 이후 정상적으로 성공했습니다.', mitre: ['T1110'] },
    data: { srcip: '192.0.2.103', count: '4' },
  }))).action, 'alert');
});

test('추출은 허용한 5개 항목만 반환하고 알려진 비밀값 형태를 제거한다', () => {
  const out = readAlert(event({ rule: { level: 6, description: 'password="do not log" token=abc Bearer xyz user@example.test', mitre: [] },
    data: { srcip: '192.0.2.100', srcuser: 'person@example.test', password: 'raw-private-value' } }));
  assert.deepEqual(Object.keys(out), ['timestamp', 'sourceAddress', 'account', 'ruleLevel', 'description']);
  assert.doesNotMatch(JSON.stringify(out), /do not log|abc|xyz|person@|user@|raw-private-value/);
});

test('차단 규칙은 15분 뒤 만료되고 과거 재생/미래 경보/애매한 경보로 차단하지 않는다', async () => {
  const store = createDenyStore();
  const alert = event();
  const at = Date.parse(alert.timestamp);
  const out = await createDecider()(alert);
  assert.equal(store.add(alert, out, at - 1), null);
  const rule = store.add(alert, out, at);
  assert.equal(rule.action, 'deny');
  assert.deepEqual(rule.evidenceAlertIds, [alert.id]);
  assert.ok(store.check(alert.data.srcip, at + 899000));
  assert.equal(store.check(alert.data.srcip, at + 900000), null);
  assert.equal(store.add(alert, out, at + 900000), null);
  assert.equal(store.add(alert, { action: 'alert', confidence: 0.6 }, at), null);
  assert.equal(store.add(alert, { action: 'block', confidence: NaN }, at), null);
  assert.equal(store.check('192.0.2.101', at), null);
});

test('연결 어댑터는 검증된 주소만 쓰며 기존 거부/허용을 유지한다', async () => {
  const store = createDenyStore();
  const alert = event();
  let at = Date.parse(alert.timestamp);
  store.add(alert, await createDecider()(alert), at);
  let transportIp = '192.0.2.101';
  let called = 0;
  const base = async request => { called++; return { schema: 'aleph.decision.v1', requestId: request.requestId,
    decision: request.requestId === 'deny' ? 'deny' : 'allow', reasonCode: 'test_only', ruleIds: ['existing'] }; };
  const guarded = withXdrGuard(base, { store, resolveVerifiedSourceIp: () => transportIp, now: () => at,
    denyResponse: (request, rule) => ({ schema: 'aleph.decision.v1', requestId: request.requestId,
      decision: 'deny', reasonCode: 'test_only', ruleIds: [rule.ruleId] }) });
  assert.equal((await guarded({ requestId: 'ok', srcip: alert.data.srcip })).decision, 'allow');
  assert.equal((await guarded({ requestId: 'deny' })).decision, 'deny');
  transportIp = alert.data.srcip;
  assert.equal((await guarded({ requestId: 'blocked', srcip: '192.0.2.101' })).decision, 'deny');
  assert.equal(called, 2);
  at += 900000;
  assert.equal((await guarded({ requestId: 'ok' })).decision, 'allow');
});

test('기존 ZTNA 계약에 출발 IP를 임의로 추가하지 않는다', async () => {
  const { decide } = await import('../src/decider.mjs');
  const response = await decide({ requestId: 'baseline' });
  assert.equal(response.reasonCode, 'starter_not_ready');
  assert.equal(response.decision, 'deny');
  const source = await readFile(new URL('../xdr/brute-force/decide.mjs', import.meta.url), 'utf8');
  assert.doesNotMatch(source, /bf-0[1-9]|fetch\(/u);
});

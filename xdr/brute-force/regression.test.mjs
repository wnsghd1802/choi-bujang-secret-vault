import { test } from 'node:test';
import assert from 'node:assert/strict';
import { loadFixture, readAlert } from './read-alerts.mjs';
import { createDecider } from './decide.mjs';

const fixture = await loadFixture();

test('기본 판정기는 동기 호출과 await 호출에서 같은 결과를 반환한다', async () => {
  const direct = createDecider();
  const awaited = createDecider();
  for (const alert of fixture.alerts) {
    const result = direct(alert);
    assert.equal(typeof result?.then, 'undefined', '기본 판단은 즉시 반환해야 한다');
    assert.deepEqual(result, await awaited(alert));
  }
});

test('정제된 행도 원본과 같은 10/9/9 분류를 유지한다', async () => {
  const counts = { block: 0, alert: 0, record: 0 };
  for (const alert of fixture.alerts) {
    const row = readAlert(alert);
    const out = await createDecider()(row);
    counts[out.action] += 1;
  }
  assert.deepEqual(counts, { block: 10, alert: 9, record: 9 });
});

test('MITRE 태그나 높은 rule level이 없어도 명확한 공격 변형은 차단한다', async () => {
  const clear = [
    { timestamp: '2026-09-27T00:00:00Z', sourceAddress: '192.0.2.110', account: 'user01', ruleLevel: 7,
      description: '같은 주소에서 2분 안에 로그인 실패 24건이 반복됐습니다.' },
    { timestamp: '2026-09-27T00:00:01Z', sourceAddress: '192.0.2.111', account: 'user02', ruleLevel: 8,
      description: '같은 주소가 여러 계정에 같은 비밀번호를 연속으로 넣었습니다.' },
  ];
  for (const row of clear) {
    const out = await createDecider()(row);
    assert.equal(out.action, 'block');
    assert.ok(out.confidence >= 0.85);
  }
});

test('성공 정황·소수 실패·정상 이벤트는 차단하지 않는다', async () => {
  const rows = [
    { timestamp: '2026-09-27T00:00:00Z', sourceAddress: '192.0.2.120', account: 'user01', ruleLevel: 7,
      description: '5분 동안 로그인 실패 6건이 있고 그 뒤 성공했습니다.' },
    { timestamp: '2026-09-27T00:00:01Z', sourceAddress: '192.0.2.121', account: 'user02', ruleLevel: 8,
      description: '한 주소에서 실패 8건이 있고 간격은 고르지 않습니다.' },
    { timestamp: '2026-09-27T00:00:02Z', sourceAddress: '192.0.2.122', account: 'user03', ruleLevel: 3,
      description: '로그인이 성공했습니다.' },
  ];
  for (const row of rows) assert.notEqual((await createDecider()(row)).action, 'block');
});

const spray = () => {
  const alert = structuredClone(fixture.alerts.find(item => item.id === 'bf-02'));
  delete alert.data.srcuser;
  return alert;
};

test('여러 대상 계정이 확인된 대입 공격은 대표 계정 필드 없이도 차단한다', async () => {
  const result = await createDecider()(spray());
  assert.equal(result.action, 'block');
  assert.match(result.reason, /^password-spray:/u);
});

test('명시된 대상 계정 수나 출발 주소가 부족하면 차단하지 않는다', async () => {
  for (const mutate of [
    alert => { alert.data.accounts = 'user01,user02'; },
    alert => { alert.data.accounts = Array(8).fill('user01').join(','); },
    alert => { delete alert.data.srcip; },
  ]) {
    const alert = spray();
    mutate(alert);
    assert.notEqual((await createDecider()(alert)).action, 'block');
  }
});

test('대표 계정이 없는 일반 실패를 다른 계정과 합쳐 차단하지 않는다', async () => {
  const decide = createDecider();
  for (let i = 0; i < 35; i++) {
    const alert = spray();
    alert.id = `missing-account-${i}`;
    alert.rule = { level: 6, description: '로그인 실패', mitre: ['T1110'] };
    alert.data.count = '1';
    assert.notEqual((await decide(alert)).action, 'block');
  }
});

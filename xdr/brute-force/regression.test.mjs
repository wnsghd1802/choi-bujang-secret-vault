import { test } from 'node:test';
import assert from 'node:assert/strict';
import { loadFixture } from './read-alerts.mjs';
import { createDecider } from './decide.mjs';

const fixture = await loadFixture();
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

test('대표 계정이 없는 경보라도 출발 주소/수준/대상 계정 근거가 부족하면 차단하지 않는다', async () => {
  for (const mutate of [
    alert => { alert.data.accounts = 'user01,user02'; },
    alert => { alert.data.accounts = Array(8).fill('user01').join(','); },
    alert => { delete alert.data.srcip; },
    alert => { alert.rule.level = 6; },
    alert => { alert.rule.mitre = []; },
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

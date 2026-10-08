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
    assert.equal(typeof result?.then, 'undefined', '네트워크 없는 자체 판정은 즉시 반환해야 한다');
    assert.deepEqual(result, await awaited(alert));
  }
});

test('정제한 다섯 필드도 원본과 같은 개별 판정을 내린다', () => {
  for (const alert of fixture.alerts) {
    const raw = createDecider()(alert);
    const sanitized = createDecider()(readAlert(alert));
    assert.equal(sanitized.action, raw.action, alert.rule.description);
  }
});

test('낮은 rule level이어도 짧은 시간 반복 실패가 명확하면 차단한다', async () => {
  for (const row of [
    { timestamp: '2026-09-27T00:00:00Z', sourceAddress: '192.0.2.110', account: 'user01', ruleLevel: 7,
      description: '같은 주소에서 2분 안에 로그인 실패 8건이 반복됐습니다.' },
    { timestamp: '2026-09-27T00:00:01Z', sourceAddress: '192.0.2.111', account: '', ruleLevel: 8,
      description: '짧은 시간 동일 IP에서 인증 실패 12회가 연속 발생했습니다.' },
    { timestamp: '2026-09-27T00:00:02Z', sourceAddress: '192.0.2.112', account: 'user02', ruleLevel: 7,
      description: 'Rapid repeated login failures: 12 attempts in 2 minutes.' },
  ]) {
    const out = await createDecider()(row);
    assert.equal(out.action, 'block');
    assert.ok(out.confidence >= 0.85);
  }
});

test('여러 계정에 같은 비밀번호 대입은 숫자 필드가 없어도 명확한 공격으로 차단한다', async () => {
  const out = await createDecider()({
    timestamp: '2026-09-27T00:00:03Z',
    sourceAddress: '192.0.2.113',
    account: 'user03',
    ruleLevel: 6,
    description: '동일 IP에서 여러 사용자에게 같은 비밀번호를 연속으로 시도했습니다.',
  });
  assert.equal(out.action, 'block');
  assert.match(out.reason, /^password-spray:/u);
});

test('느린 누적·성공 뒤 소수 실패·불규칙한 8건은 자동 차단하지 않는다', async () => {
  const rows = [
    { timestamp: '2026-09-27T00:00:04Z', sourceAddress: '192.0.2.114', account: 'user04', ruleLevel: 12,
      description: '2시간 동안 로그인 실패 40건이 누적됐습니다.' },
    { timestamp: '2026-09-27T00:00:05Z', sourceAddress: '192.0.2.115', account: 'user05', ruleLevel: 7,
      description: '5분 동안 로그인 실패 6건이 있고 그 뒤 성공했습니다.' },
    { timestamp: '2026-09-27T00:00:06Z', sourceAddress: '192.0.2.116', account: 'user06', ruleLevel: 8,
      description: '한 주소에서 실패 8건이 있고 간격은 고르지 않습니다.' },
  ];
  for (const row of rows) assert.notEqual((await createDecider()(row)).action, 'block');
});

test('로그인 실패 1건 뒤 성공은 정상 기록으로 남긴다', async () => {
  const out = await createDecider()({
    timestamp: '2026-09-27T00:00:07Z',
    sourceAddress: '192.0.2.117',
    account: 'user07',
    ruleLevel: 3,
    description: '로그인 실패 1건 뒤에 성공했습니다.',
  });
  assert.equal(out.action, 'record');
});

test('출발 주소가 없으면 명확한 문구라도 차단 규칙을 만들지 않는다', async () => {
  const out = await createDecider()({
    timestamp: '2026-09-27T00:00:08Z',
    sourceAddress: '',
    account: 'user08',
    ruleLevel: 12,
    description: '1분 안에 로그인 실패 80건이 반복됐습니다.',
  });
  assert.notEqual(out.action, 'block');
});

test('같은 발신지에서 짧은 시간 반복된 실패는 다양한 문장 표현에서도 탐지한다', () => {
  const cases = [
    '동일 주소에서 2분 동안 로그인 시도 30회를 거부했습니다.',
    '30초 이내에 암호를 25회 틀렸습니다.',
  ];
  for (const description of cases) {
    const result = createDecider()({ timestamp: '2026-09-27T00:00:00Z',
      sourceAddress: '192.0.2.120', ruleLevel: 7, description });
    assert.equal(result.action, 'block', description);
  }
});

test('행동 근거가 충분할 때 미기재 rule level만으로 확정 탐지를 포기하지 않는다', () => {
  const result = createDecider()({ timestamp: '2026-09-27T00:00:00Z',
    sourceAddress: '192.0.2.127',
    description: '같은 주소에서 2분 동안 로그인 실패 40건을 반복했습니다.' });
  assert.equal(result.action, 'block');
});

test('여러 계정에 동일 비밀번호가 설정됐다는 문장만으로 차단하지 않는다', () => {
  const result = createDecider()({ timestamp: '2026-09-27T00:00:00Z',
    sourceAddress: '192.0.2.128', ruleLevel: 7,
    description: '여러 계정에 같은 비밀번호를 설정했습니다.' });
  assert.notEqual(result.action, 'block');
});

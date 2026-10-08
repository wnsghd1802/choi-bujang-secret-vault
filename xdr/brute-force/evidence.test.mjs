import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createDecider, facts } from './decide.mjs';

const make = (description, extras = {}) => ({
  id: `new-${description.length}`,
  timestamp: '2026-09-27T12:00:00Z',
  sourceAddress: '192.0.2.80',
  ruleLevel: 5,
  description,
  ...extras,
});

const confirmed = [
  '같은 주소에서 2분간 로그인 실패가 25차례 반복됐습니다.',
  '2분 동안 25번의 로그인 실패가 발생했습니다.',
  '1분 사이 로그인 실패 100건이 발생했습니다.',
  '30초 이내에 암호를 25회 틀렸습니다.',
  '로그인 실패 40건이 연속으로 쌓였습니다.',
  '동일 IP에서 짧은 시간에 인증 거부가 연속으로 몰렸습니다.',
  '같은 출발지에서 2분 동안 로그인 실패 8번 발생했습니다.',
  '한 IP에서 2분간 20차례 인증 실패 뒤 로그인에 성공했습니다.',
  '2분간 로그인 실패 90차례 후 성공했습니다.',
  '2분 안에 로그인 실패 12건 이후 성공했습니다.',
  '비밀번호를 한 글자씩 바꿔 넣는 로그인 실패 40건이 발생했습니다.',
  '서로 다른 사용자 10명에 동일 패스워드를 반복 시도했습니다.',
  '여러 계정에 같은 비밀번호를 연속으로 넣었습니다.',
  '계정 15개에 같은 비밀번호 실패가 이어졌습니다.',
  '같은 주소에서 여러 사용자 계정에 동일 암호를 반복 대입했습니다.',
  'password spraying across multiple accounts with the same password and repeated attempts',
  '40 failed logins within 2 minutes from one IP',
  '40 login failures within 2 minutes',
  'Rapid repeated login failures: 12 attempts in 2 minutes.',
  '50 authentication denials within 1 minute',
  '12 authentication denials within 60 seconds from one IP.',
  '40 failed password attempts in 2 minutes',
  '20 login failures with no success',
  '10분 동안 로그인 실패가 50건 발생했습니다.',
  '20분 동안 로그인 실패 90건 이후 성공했습니다.',
];

const uncertain = [
  '평소와 다른 주소에서 로그인 실패가 3건입니다.',
  '10분 동안 한 계정의 로그인 실패가 5건입니다.',
  '5분 동안 로그인 실패 6건이 있고 그 뒤 성공했습니다.',
  '한 주소에서 실패 8건이 있고 간격은 고르지 않습니다.',
  '2시간 동안 로그인 실패 40건이 누적됐습니다.',
  '같은 계정 로그인 실패 4건 뒤에 성공했습니다.',
  '인증 실패 한 번이 기록되었습니다.',
];

const normal = [
  '로그인이 성공했습니다.',
  '로그아웃했습니다.',
  '자료실 화면이 열렸습니다.',
  '세션 유지를 확인했습니다.',
  '로그인 실패 1건 뒤에 성공했습니다.',
  '여러 계정에 같은 비밀번호를 설정했습니다.',
  '비밀번호 변경이 성공했습니다.',
  '로그인 상태가 유지되고 있습니다.',
];

test('명확한 공격은 기존 개수와 무관하게 모두 block한다', () => {
  for (const description of confirmed) {
    const actual = createDecider()(make(description));
    assert.equal(actual.action, 'block', `${description}: ${JSON.stringify({ actual, facts: facts(make(description)) })}`);
    assert.equal(actual.confidence, 1.0);
  }
});

test('추가 근거가 없는 의심은 alert로 유지한다', () => {
  for (const description of uncertain) {
    assert.equal(createDecider()(make(description)).action, 'alert', description);
  }
});

test('정상적인 활동은 block하지 않는다', () => {
  for (const description of normal) {
    assert.equal(createDecider()(make(description)).action, 'record', description);
  }
});

test('식별 가능한 출발지 누락은 강한 패턴이어도 차단 규칙을 만들지 않는다', () => {
  const result = createDecider()(make('2분 동안 로그인 실패 80건', { sourceAddress: '' }));
  assert.notEqual(result.action, 'block');
});

test('공격자 주소·이벤트 ID·계정을 바꿔도 같은 근거면 판정이 같다', () => {
  const event = make('1분 사이 로그인 실패 100건이 발생했습니다.');
  for (const changed of [
    { ...event, id: 'swapped-001' },
    { ...event, sourceAddress: '198.51.100.20' },
    { ...event, account: 'another-user' },
  ]) assert.equal(createDecider()(changed).action, 'block');
});

test('실패 29건 미만의 독립 단일 경보들은 중복 전송을 차단으로 오인하지 않는다', () => {
  const decide = createDecider();
  const event = make('로그인 실패 1건', { id: 'retransmit' });
  for (let i = 0; i < 70; i++) assert.notEqual(decide(event).action, 'block');
  for (let i = 1; i < 29; i++) assert.notEqual(decide({ ...event, id: `unique-${i}` }).action, 'block');
  assert.equal(decide({ ...event, id: 'unique-29', account: 'another' }).action, 'block');
});

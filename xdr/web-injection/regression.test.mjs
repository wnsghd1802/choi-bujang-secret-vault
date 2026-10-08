import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile, mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { decide } from './decide.mjs';
import { readAlert, loadFixture } from './read-alerts.mjs';
import { createDenyStore, appendAlert, withXdrGuard } from './respond.mjs';

const make = (description, count, mitre = ['T1190'], ip = '203.0.113.10') => ({
  id: 'trial-1', timestamp: '2026-09-27T09:13:01+09:00',
  rule: { level: 10, mitre, description }, data: { srcip: ip, url: '/search?q=sample', ...(count == null ? {} : { count: String(count) }) },
});

test('패턴 명칭이 목록과 일치하고 독립 decide 에 import 및 I/O가 없다', async () => {
  const source = await readFile(new URL('./decide.mjs', import.meta.url), 'utf8');
  assert.doesNotMatch(source, /^\s*import\s|\bfetch\s*\(|\breadFile\s*\(|\bwriteFile\s*\(|\bprocess\./mu);
  const config = JSON.parse(await readFile(new URL('./patterns.json', import.meta.url), 'utf8'));
  for (const pattern of config.patterns) assert.ok(source.includes("name: '" + pattern.name + "'"));
  assert.equal(config.mitre, 'T1190');
});

test('동작을 판정 숫자에 맞추지 않고 네 가지 명확한 유형을 차단한다', () => {
  const examples = [
    '같은 주소에서 SQL 구문을 이어 붙인 요청이 12번 반복됐습니다.',
    '같은 주소에서 스크립트 삽입 표기가 9번 반복됐습니다.',
    '경로를 여러 단계 거슬러 올라가는 표기가 8번 반복됐습니다.',
    '명령 구분자 표기가 연속 요청 11번에 있습니다.',
  ];
  for (const [i, d] of examples.entries()) {
    const out = decide(make(d, [12, 9, 8, 11][i]));
    assert.equal(out.action, 'block', d);
    assert.equal(out.confidence, 1);
  }
});

test('단발성 주입 단서 및 태그만으로는 차단하지 않는다', () => {
  assert.equal(decide(make('검색어에 따옴표가 한 번 들어 있습니다. 반복은 없습니다.', 1)).action, 'alert');
  assert.equal(decide(make('스크립트라는 수업 단어가 한 번 있습니다. 삽입 표식은 아닙니다.', 1)).action, 'alert');
  assert.equal(decide(make('이상한 검색 1건 뒤에 정상 조회가 있습니다.', 1)).action, 'alert');
});

test('T1190이 없으면 정상 교재 검색/조회는 record, 주소 변경으로 차단하면 안 됨', () => {
  const normal = [
    make('SQL 수업 공지 제목을 조회했습니다.', 1, []),
    make('스크립트라는 수업 단어를 검색했습니다.', 1, []),
    make('자료 목록을 조회했습니다.', null, []),
  ];
  for (const row of normal) assert.equal(decide(row).action, 'record');
  const clear = make('SQL 구문 표기가 한 주소에서 20번 들어왔습니다.', 20, [], '198.51.100.19');
  assert.equal(decide(clear).action, 'block');
});

test('readAlert는 정상화하고 비밀값을 제외한다', () => {
  const a = make('password=TEST_ONLY token=TEST_ONLY SQL 구문 표기', 1);
  const safe = readAlert(a);
  assert.doesNotMatch(JSON.stringify(safe), /TEST_ONLY/);
  assert.equal(safe.sourceAddress, '203.0.113.10');
});

test('block 후보의 근거·만료·정상 요청 통과, 미검증 IP 거부', async () => {
  const store = createDenyStore();
  const now = Date.parse('2026-09-27T09:13:30+09:00');
  const malicious = make('같은 주소에서 SQL 구문 표기가 20번 반복됐습니다.', 20);
  const valid = store.add(malicious, decide(malicious), now);
  assert.deepEqual(valid.evidenceAlertIds, ['trial-1']);
  assert.equal(store.add(make('자료 목록을 조회했습니다.', null, []), { action: 'record', confidence: 0.1 }, now), null);
  const guard = withXdrGuard(req => ({ decision: 'allow', requestId: req.requestId }), {
    store, now: () => now,
    resolveVerifiedSourceIp: req => req.internalVerifiedIp,
    denyResponse: (req, rule) => ({ schema: 'aleph.decision.v1', requestId: req.requestId,
      decision: 'deny', reasonCode: 'approved_registry_code', ruleIds: [rule.ruleId] }),
  });
  assert.equal((await guard({ requestId: 'attack', internalVerifiedIp: '203.0.113.10' })).decision, 'deny');
  assert.equal((await guard({ requestId: 'normal', internalVerifiedIp: '192.0.2.12' })).decision, 'allow');
  await assert.rejects(guard({ requestId: 'missing' }), /검증되지 않은/);
  assert.equal(store.check('203.0.113.10', Date.parse(valid.expiresAt)), null);
});

test('알림 로그에는 비밀/주소/원문이 남지 않는다', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'wi-logs-'));
  try {
    const path = join(dir, 'alerts.log');
    const suspicious = make('password=TEST_ONLY SQL 구문 표기', 1);
    await appendAlert(path, suspicious, decide(suspicious));
    const content = await readFile(path, 'utf8');
    assert.match(content, /"action":"alert"/u);
    assert.doesNotMatch(content, /TEST_ONLY|203\.0\.113|SQL 구문 표기/u);
  } finally { await rm(dir, { recursive: true, force: true }); }
});

test('공식 가상 경보에서 정상 이벤트 차단이 없어야 한다', async () => {
  const fixture = await loadFixture();
  const misblocked = fixture.alerts.filter(a => a.rule.mitre.length === 0 && a.rule.level <= 3 && decide(a).action === 'block');
  assert.deepEqual(misblocked, []);
});

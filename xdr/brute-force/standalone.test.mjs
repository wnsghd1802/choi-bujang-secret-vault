import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { runInNewContext } from 'node:vm';
import { loadFixture } from './read-alerts.mjs';
import { createDecider } from './decide.mjs';

const code = await readFile(new URL('./decide.mjs', import.meta.url), 'utf8');
const isolated = () => runInNewContext(
  code.replace(/^export\s+/gmu, '') + '\n({ createDecider, patterns })',
  Object.create(null),
  { timeout: 2000 },
);

test('심판 격리 환경에서도 decide.mjs 파일 하나로 실행한다', () => {
  assert.doesNotMatch(code, /^\s*import\b|\brequire\s*\(|\bimport\s*\(/mu);
  assert.doesNotMatch(code, /\b(?:readFileSync|fetch\s*\(|process\.|Buffer\.)/mu);
  const module = isolated();
  assert.equal(typeof module.createDecider, 'function');
  assert.equal(module.patterns.moduleKey, 'brute-force');
  const base = { timestamp: '2026-09-27T00:00:00Z', sourceAddress: '192.0.2.78' };
  assert.equal(module.createDecider()({ ...base, description: '2분간 로그인 실패 90차례 후 성공했습니다.' }).action, 'block');
  assert.equal(module.createDecider()({ ...base, description: '로그인 실패 1건 뒤에 성공했습니다.' }).action, 'record');
});

test('격리 판정은 공개 경보마다 일반 판정과 동일하다', async () => {
  const vmDecide = isolated().createDecider();
  const regular = createDecider();
  for (const event of (await loadFixture()).alerts) {
    const a = vmDecide(event);
    const b = regular(event);
    assert.equal(a.action, b.action, event.id);
    assert.equal(a.confidence, b.confidence, event.id);
    assert.equal(a.reason, b.reason, event.id);
  }
});

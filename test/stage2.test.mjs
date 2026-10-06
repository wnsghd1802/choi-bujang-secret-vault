import assert from 'node:assert/strict';
import { test } from 'node:test';
import { readFile } from 'node:fs/promises';
import { deploymentIdentity } from '../scripts/deployment-identity.mjs';

test('public JSON stays empty after stage 3', async () => {
  for (const path of ['data.json', 'public/data.json']) {
    assert.deepEqual(JSON.parse(await readFile(new URL('../' + path, import.meta.url), 'utf8')).notes, []);
  }
  const html = await readFile(new URL('../public/index.html', import.meta.url), 'utf8');
  assert.match(html, /id="login-form"/);
  assert.match(html, /id="workspace" hidden/);
  assert.doesNotMatch(html, /SUPABASE_SECRET_KEY/);
});

test('deployment metadata records the current stage', async () => {
  const config = JSON.parse(await readFile(new URL('../aleph.config.json', import.meta.url), 'utf8'));
  const identity = deploymentIdentity({ VERCEL_GIT_PROVIDER: 'github', VERCEL_GIT_REPO_OWNER: 'wnsghd1802',
    VERCEL_GIT_REPO_SLUG: 'choi-bujang-secret-vault', VERCEL_GIT_COMMIT_SHA: 'a'.repeat(40), VERCEL_URL: 'test.vercel.app' }, config);
  assert.equal(identity.step, 3);
  assert.equal(identity.repoUrl, config.repoUrl);
});

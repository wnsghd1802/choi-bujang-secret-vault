import assert from 'node:assert/strict';
import { test } from 'node:test';
import { readFile } from 'node:fs/promises';
import { createClient } from '@supabase/supabase-js';
import { createNotesHandler } from '../api/notes.js';
import { deploymentIdentity } from '../scripts/deployment-identity.mjs';

const env = { SUPABASE_URL: 'https://unit-test.supabase.co', SUPABASE_SECRET_KEY: 'test-only-value' };
function response() {
  return { headers: {}, setHeader(k, v) { this.headers[k] = v; },
    status(code) { this.code = code; return this; }, json(value) { this.body = value; return this; } };
}

test('GET uses server key, returns DB records, and disables caching', async () => {
  let requested;
  const factory = (url, key, options) => createClient(url, key, { ...options, global: {
    fetch: async (url, init) => {
      requested = { url: String(url), headers: new Headers(init.headers) };
      return new Response(JSON.stringify([{ id: 1, title: 'test title', content: 'test content' }]), { headers: { 'content-type': 'application/json' } });
    },
  } });
  const res = response();
  await createNotesHandler(env, factory)({ method: 'GET', headers: { authorization: 'visitor-token' } }, res);
  assert.equal(res.code, 200);
  assert.equal(res.body.notes.length, 1);
  assert.match(requested.url, /\/rest\/v1\/notes\?/);
  assert.equal(requested.headers.get('apikey'), env.SUPABASE_SECRET_KEY);
  assert.notEqual(requested.headers.get('authorization'), 'visitor-token');
  assert.equal(res.headers['Cache-Control'], 'no-store');
  assert.equal(res.body.notes[0].title, 'test title');
});

test('database failures never expose upstream error details', async () => {
  const factory = (url, key, options) => createClient(url, key, { ...options, global: {
    fetch: async () => new Response(JSON.stringify({ message: 'PRIVATE_DB_DETAIL' }), { status: 403 }),
  } });
  const res = response();
  await createNotesHandler(env, factory)({ method: 'GET' }, res);
  assert.equal(res.code, 502);
  assert.doesNotMatch(JSON.stringify(res.body), /PRIVATE_DB_DETAIL|test-only-value/);
});

test('missing configuration fails closed and writes are refused', async () => {
  const unavailable = response();
  await createNotesHandler({})({ method: 'GET' }, unavailable);
  assert.equal(unavailable.code, 503);
  const denied = response();
  await createNotesHandler({})({ method: 'POST' }, denied);
  assert.equal(denied.code, 405);
  assert.equal(denied.headers.Allow, 'GET');
});

test('public files contain no notes and browser uses only the server API', async () => {
  const root = new URL('../', import.meta.url);
  for (const path of ['data.json', 'public/data.json']) {
    assert.deepEqual(JSON.parse(await readFile(new URL(path, root), 'utf8')).notes, []);
  }
  const html = await readFile(new URL('public/index.html', root), 'utf8');
  assert.match(html, /fetch\('\/api\/notes'/);
  assert.doesNotMatch(html, /SUPABASE_SECRET_KEY|supabase\.co|fetch\('\/data\.json'/);
});

test('deployment metadata records stage 2 rather than the old stage', () => {
  const config = JSON.parse(requireConfig());
  const identity = deploymentIdentity({ VERCEL_GIT_PROVIDER: 'github', VERCEL_GIT_REPO_OWNER: 'wnsghd1802',
    VERCEL_GIT_REPO_SLUG: 'choi-bujang-secret-vault', VERCEL_GIT_COMMIT_SHA: 'a'.repeat(40), VERCEL_URL: 'test.vercel.app' }, config);
  assert.equal(identity.step, 2);
  assert.equal(identity.repoUrl, config.repoUrl);
});

import { readFileSync } from 'node:fs';
function requireConfig() { return readFileSync(new URL('../aleph.config.json', import.meta.url), 'utf8'); }

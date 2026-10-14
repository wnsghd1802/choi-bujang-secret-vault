import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, randomBytes, sign } from 'node:crypto';
import { fingerprint, proofText, approvedProof, withDeviceGate } from '../src/device-security.mjs';

const userId = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const token = 'aaa.bbb.ccc';
function deviceFixture(state = 'approved') {
  const { publicKey, privateKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const jwk = publicKey.export({ format: 'jwk' });
  const clean = { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y };
  const id = fingerprint(clean);
  const used = new Set();
  const db = { from(table) {
    if (table === 'device_registrations') return {
      select() { return this; }, eq() { return this; },
      async maybeSingle() { return { data: { state, public_key: clean }, error: null }; },
    };
    if (table === 'device_proof_nonces') return {
      async insert(row) {
        if (used.has(row.nonce)) return { error: { code: '23505' } };
        used.add(row.nonce);
        return { error: null };
      },
    };
    throw Error('unexpected table');
  } };
  const now = Math.floor(Date.now() / 1000);
  const nonce = randomBytes(16).toString('hex');
  const at = String(now);
  const req = { method: 'GET', url: '/api/notes',
    headers: { authorization: 'Bearer ' + token, 'x-device-id': id,
      'x-device-nonce': nonce, 'x-device-at': at } };
  req.headers['x-device-signature'] = sign('sha256',
    Buffer.from(proofText('GET', req.url, '', at, nonce, token, userId)),
    { key: privateKey, dsaEncoding: 'ieee-p1363' }).toString('base64url');
  return { db, req, now };
}
function response() {
  return { status(n) { this.statusCode = n; return this; },
    json(body) { this.body = body; return this; } };
}
test('approved signature works once; replay and altered path fail closed', async () => {
  const f = deviceFixture();
  const actor = { kind: 'student', userId };
  assert.equal(await approvedProof(f.req, actor, f.db, f.now), true);
  assert.equal(await approvedProof(f.req, actor, f.db, f.now), false);
  const g = deviceFixture();
  g.req.url = '/api/notes?export=all';
  assert.equal(await approvedProof(g.req, actor, g.db, g.now), false);
});
test('pending and missing proofs cannot reach protected resources', async () => {
  const f = deviceFixture('pending');
  assert.equal(await approvedProof(f.req, { kind: 'student', userId }, f.db, f.now), false);
  let reached = 0;
  const app = withDeviceGate(async (_req, res) => { reached++; return res.status(200).json({ ok: true }); },
    { db: f.db, verifyLogin: async () => ({ kind: 'student', userId }) });
  const res = response();
  await app(f.req, res);
  assert.equal(res.statusCode, 403);
  assert.equal(reached, 0);
});
test('existing signed judge requests preserve stage 10 handler behavior', async () => {
  let reached = 0;
  const app = withDeviceGate(async (_req, res) => { reached++; return res.status(200).json({ ok: true }); },
    { verifyLogin: async () => ({ kind: 'judge', identity: 'b' }) });
  const res = response();
  await app({ method: 'POST', url: '/api/restore',
    headers: { authorization: 'Bearer ' + token } }, res);
  assert.equal(res.statusCode, 200);
  assert.equal(reached, 1);
});

import { createHash, createPublicKey, verify } from 'node:crypto';
import { createClient } from '@supabase/supabase-js';
import { createLoginVerifier } from './verify-login.mjs';
import { getServerDb } from './server-db-config.mjs';
import config from '../aleph.config.json' with { type: 'json' };

const sha = value => createHash('sha256').update(value).digest('hex');
export const validKey = key => key && typeof key === 'object' && !Array.isArray(key)
  && Object.keys(key).sort().join(',') === 'crv,kty,x,y'
  && key.kty === 'EC' && key.crv === 'P-256'
  && /^[\w-]{43}$/u.test(key.x) && /^[\w-]{43}$/u.test(key.y);
export const fingerprint = key => validKey(key) ? sha(key.x + '.' + key.y).slice(0, 16) : null;
export const proofText = (method, path, body, at, nonce, token, uid) =>
  [method, path, sha(body), at, nonce, sha(token), uid].join('\n');
export const dbFor = env => {
  const c = getServerDb(env);
  return c && createClient(c.url, c.secretKey, {
    auth: { persistSession: false, autoRefreshToken: false, detectSessionInUrl: false },
  });
};
export const verifierFor = env => {
  const c = getServerDb(env);
  return c && createLoginVerifier({ config, supabaseSecretKey: c.secretKey });
};
export async function approvedProof(req, actor, db, now = Math.floor(Date.now() / 1000)) {
  if (actor?.kind !== 'student') return false;
  const h = req.headers ?? {};
  const id = h['x-device-id'], at = h['x-device-at'];
  const nonce = h['x-device-nonce'], signature = h['x-device-signature'];
  const token = /^Bearer ([\w-]+\.[\w-]+\.[\w-]+)$/u.exec(h.authorization ?? '')?.[1];
  if (typeof id !== 'string' || !/^[a-f0-9]{16}$/u.test(id)
    || typeof at !== 'string' || !/^[0-9]{10}$/u.test(at)
    || Math.abs(Number(at) - now) > 30
    || typeof nonce !== 'string' || !/^[a-f0-9]{32}$/u.test(nonce)
    || typeof signature !== 'string' || !/^[\w-]{86}$/u.test(signature) || !token) return false;
  let path, body = '';
  try {
    const u = new URL(req.url, 'https://internal.invalid');
    path = u.pathname + u.search;
    if (!path.startsWith('/api/')) return false;
    if (['POST', 'PUT', 'PATCH'].includes(req.method))
      body = JSON.stringify(typeof req.body === 'string' ? JSON.parse(req.body) : req.body ?? '');
  } catch { return false; }
  const result = await db.from('device_registrations').select('state,public_key')
    .eq('user_id', actor.userId).eq('device_id', id).maybeSingle();
  const key = result.data?.public_key;
  if (result.error || result.data?.state !== 'approved' || !validKey(key)
    || fingerprint(key) !== id) return false;
  let good = false;
  try {
    good = verify('sha256', Buffer.from(proofText(req.method, path, body, at, nonce, token, actor.userId)),
      { key: createPublicKey({ key, format: 'jwk' }), dsaEncoding: 'ieee-p1363' },
      Buffer.from(signature, 'base64url'));
  } catch { return false; }
  if (!good) return false;
  const used = await db.from('device_proof_nonces').insert({ user_id: actor.userId, device_id: id, nonce });
  return !used.error; // Unique primary key prevents replay across serverless instances.
}
export function withDeviceGate(handler, { env = process.env, db, verifyLogin } = {}) {
  return async (req, res) => {
    if (!/^Bearer [\w-]+\.[\w-]+\.[\w-]+$/u.test(req.headers?.authorization ?? ''))
      return handler(req, res);
    try {
      const verifier = verifyLogin ?? verifierFor(env);
      if (!verifier) return res.status(503).json({ error: '기기 인증 서버 설정을 확인해 주세요.' });
      const actor = await verifier(req.headers.authorization);
      if (!actor || actor.kind === 'judge') return handler(req, res);
      if (actor.kind !== 'student') return res.status(403).json({ error: '기기가 확인되지 않았습니다.' });
      const database = db ?? dbFor(env);
      if (!database) return res.status(503).json({ error: '기기 DB 설정이 필요합니다.' });
      if (!await approvedProof(req, actor, database))
        return res.status(403).json({ error: '서버에 승인된 기기의 서명이 필요합니다.' });
      return handler(req, res);
    } catch { return res.status(503).json({ error: '서버에서 기기를 확인하지 못했습니다.' }); }
  };
}

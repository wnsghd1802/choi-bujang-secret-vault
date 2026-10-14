import { createHash } from 'node:crypto';
import { createClient } from '@supabase/supabase-js';
import { createLoginVerifier } from './verify-login.mjs';
import { getServerDb } from './server-db-config.mjs';
import { binary, hexDigest, verifyAssertion } from './device-webauthn.mjs';
import config from '../aleph.config.json' with { type: 'json' };

const origin = new URL(config.publicAppUrl).origin;
const rpId = new URL(config.publicAppUrl).hostname;
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
export function tokenDigest(authorization) {
  return typeof authorization === 'string' && /^Bearer [A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/u.test(authorization)
    && authorization.length <= 8192 ? hexDigest(authorization.slice(7)) : null;
}
export async function consumeChallenge(db, actor, challenge, authorization) {
  if (typeof challenge !== 'string' || !/^[A-Za-z0-9_-]{43}$/u.test(challenge)
      || !tokenDigest(authorization)) return null;
  // Atomic deletion makes challenges single-use, even with multiple serverless instances.
  const row = await db.from('device_challenges').delete()
    .eq('challenge', challenge).eq('user_id', actor.userId)
    .select('challenge,user_id,token_digest,purpose,request_method,request_path,body_digest,issued_at')
    .maybeSingle();
  if (row.error || !row.data || row.data.token_digest !== tokenDigest(authorization)) return null;
  const issued = Date.parse(row.data.issued_at);
  if (!Number.isFinite(issued) || Math.abs(Date.now() - issued) > 120000) return null;
  return row.data;
}
export async function verifyApprovedDevice(req, actor, db) {
  if (actor?.kind !== 'student') return false;
  const provided = req.headers?.['x-device-proof'];
  if (typeof provided !== 'string' || provided.length > 8192) return false;
  let proof;
  try {
    proof = JSON.parse(binary(provided, 6000).toString('utf8'));
    if (!proof || Object.keys(proof).sort().join(',') !== 'authenticatorData,challenge,clientDataJSON,id,signature')
      return false;
  } catch { return false; }
  // Delete challenge before validating evidence: invalid or replayed proofs fail closed.
  const record = await consumeChallenge(db, actor, proof.challenge, req.headers?.authorization);
  if (!record || record.purpose !== 'assert') return false;
  let path;
  try { const url = new URL(req.url, origin); path = url.pathname + url.search; }
  catch { return false; }
  let body = '';
  try {
    if (['POST','PUT','PATCH'].includes(req.method))
      body = JSON.stringify(typeof req.body === 'string' ? JSON.parse(req.body) : req.body ?? '');
  } catch { return false; }
  if (record.request_method !== req.method || record.request_path !== path
      || record.body_digest !== hexDigest(body)) return false;
  const found = await db.from('device_registrations')
    .select('device_id,credential_id,public_key,state,sign_count')
    .eq('user_id', actor.userId).eq('credential_id', proof.id).eq('state', 'approved')
    .maybeSingle();
  if (found.error || !found.data) return false;
  try {
    const { counter } = verifyAssertion(proof, record.challenge, origin, rpId,
      found.data.credential_id, found.data.public_key);
    const before = Number(found.data.sign_count ?? 0);
    if (counter !== 0 && counter <= before) return false;
    if (counter > before) {
      const updated = await db.from('device_registrations').update({ sign_count: counter })
        .eq('user_id', actor.userId).eq('device_id', found.data.device_id)
        .eq('sign_count', before).select('device_id').maybeSingle();
      if (updated.error || !updated.data) return false;
    }
    return true;
  } catch { return false; }
}

export function withDeviceGate(handler, { env = process.env, db, verifyLogin } = {}) {
  return async (req, res) => {
    const authorization = req.headers?.authorization;
    if (!tokenDigest(authorization)) return handler(req, res);
    try {
      const verifier = verifyLogin ?? verifierFor(env);
      if (!verifier) return res.status(503).json({ error: '서버 신원 확인 설정이 필요합니다.' });
      const actor = await verifier(authorization);
      // Earlier judge flow retains its original signed-token ownership checks.
      if (!actor || actor.kind === 'judge') return handler(req, res);
      if (actor.kind !== 'student') return res.status(403).json({ error: '확인된 기기가 필요합니다.' });
      const database = db ?? dbFor(env);
      if (!database) return res.status(503).json({ error: '기기 DB 설정이 필요합니다.' });
      if (!await verifyApprovedDevice(req, actor, database))
        return res.status(403).json({ error: '기기 인증기의 승인된 서명이 필요합니다.' });
      return handler(req, res);
    } catch {
      return res.status(503).json({ error: '서버 기기 인증을 완료하지 못했습니다.' });
    }
  };
}

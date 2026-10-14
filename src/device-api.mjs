import { randomBytes } from 'node:crypto';
import { dbFor, verifierFor, consumeChallenge, tokenDigest } from './device-security.mjs';
import { hexDigest, verifyRegistration } from './device-webauthn.mjs';
import config from '../aleph.config.json' with { type: 'json' };

const origin = new URL(config.publicAppUrl).origin;
const rpId = new URL(config.publicAppUrl).hostname;
const requestPath = (method, path) => {
  if (typeof path !== 'string' || path.length > 180
    || !/^\/(?:api\/notes(?:\/[0-9a-f-]{36})?|api\/restore|api\/notices\/[0-9a-f-]{36})$/iu.test(path)) return false;
  if (path === '/api/restore') return method === 'POST';
  if (path.startsWith('/api/notices/')) return method === 'PUT';
  if (path === '/api/notes') return method === 'GET' || method === 'POST';
  return ['GET', 'PUT', 'DELETE'].includes(method);
};
const bytesOfUuid = uuid => Buffer.from(uuid.replaceAll('-', ''), 'hex').toString('base64url');

export function createDeviceHandler({ env = process.env, db: suppliedDb, verifyLogin: suppliedVerifier } = {}) {
  return async (req, res) => {
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    const fail = (status, error) => res.status(status).json({ error });
    if (!['GET', 'POST'].includes(req.method)) {
      res.setHeader('Allow', 'GET, POST');
      return fail(405, '기기 승인 요청 방식을 확인해 주세요.');
    }
    const auth = req.headers?.authorization;
    if (!tokenDigest(auth)) return fail(401, '로그인이 필요합니다.');
    let actor, db;
    try {
      const verifier = suppliedVerifier ?? verifierFor(env);
      db = suppliedDb ?? dbFor(env);
      if (!verifier || !db) return fail(503, '서버 기기 등록 설정이 필요합니다.');
      actor = await verifier(auth);
    } catch { return fail(503, '로그인 확인에 실패했습니다.'); }
    if (actor?.kind !== 'student') return fail(403, '학생 로그인 계정이 필요합니다.');
    try {
      const url = new URL(req.url, origin);
      if (url.pathname !== '/api/device') return fail(400, '기기 승인 경로를 확인해 주세요.');
      if (req.method === 'GET') {
        const keys = [...url.searchParams.keys()];
        if (keys.some(key => key !== 'id') || keys.length > 1) return fail(400, '허용하지 않는 조회입니다.');
        let query = db.from('device_registrations').select('state,device_id').eq('user_id', actor.userId);
        if (keys.length) {
          const id = url.searchParams.get('id');
          if (!/^[a-f0-9]{16}$/u.test(id ?? '')) return fail(400, '기기 식별자를 확인해 주세요.');
          query = query.eq('device_id', id);
        }
        const response = await query.limit(50);
        if (response.error) throw response.error;
        const states = (response.data ?? []).map(item => item.state);
        const state = states.includes('approved') ? 'approved'
          : states.includes('pending') ? 'pending'
          : states.includes('revoked') ? 'revoked' : 'not_requested';
        return res.status(200).json({ state });
      }
      if (url.search || typeof req.body !== 'object' || !req.body || Array.isArray(req.body)) {
        return fail(400, '요청 형식을 확인해 주세요.');
      }
      const body = req.body;
      const action = body.action;
      if (action === 'register-start' || action === 'assert-start') {
        const isRegister = action === 'register-start';
        if ((isRegister && Object.keys(body).sort().join(',') !== 'action')
          || (!isRegister && Object.keys(body).sort().join(',') !== 'action,bodyDigest,method,path'))
          return fail(400, '허용하지 않는 등록 요청입니다.');
        if (!isRegister && (!requestPath(body.method, body.path)
            || typeof body.bodyDigest !== 'string' || !/^[a-f0-9]{64}$/u.test(body.bodyDigest))) {
          return fail(400, '허용하지 않는 보호 요청입니다.');
        }
        let credentialIds = [];
        if (!isRegister) {
          const found = await db.from('device_registrations').select('credential_id')
            .eq('user_id', actor.userId).eq('state', 'approved')
            .not('credential_id', 'is', null).limit(30);
          if (found.error) throw found.error;
          credentialIds = (found.data ?? []).map(item => item.credential_id)
            .filter(id => typeof id === 'string' && /^[A-Za-z0-9_-]{10,1400}$/u.test(id));
          if (!credentialIds.length) return fail(403, '서버에서 승인한 기기가 없습니다.');
        }
        const challenge = randomBytes(32).toString('base64url');
        const inserted = await db.from('device_challenges').insert({
          challenge, user_id: actor.userId, token_digest: tokenDigest(auth),
          purpose: isRegister ? 'register' : 'assert',
          request_method: isRegister ? '' : body.method,
          request_path: isRegister ? '' : body.path,
          body_digest: isRegister ? '' : body.bodyDigest,
        });
        if (inserted.error) throw inserted.error;
        return res.status(200).json({
          challenge, rpId,
          ...(isRegister ? { userHandle: bytesOfUuid(actor.userId) }
            : { credentialIds }),
        });
      }
      if (action === 'register-finish') {
        if (Object.keys(body).sort().join(',') !== 'action,attestationObject,challenge,clientDataJSON,id') {
          return fail(400, '인증기 등록 응답을 확인해 주세요.');
        }
        const record = await consumeChallenge(db, actor, body.challenge, auth);
        if (!record || record.purpose !== 'register') return fail(403, '등록 요청을 다시 시작해 주세요.');
        const registration = verifyRegistration(body, record.challenge, origin, rpId);
        const deviceId = hexDigest(registration.credentialId).slice(0, 16);
        const existing = await db.from('device_registrations')
          .select('state,credential_id,public_key').eq('user_id', actor.userId)
          .eq('device_id', deviceId).maybeSingle();
        if (existing.error) throw existing.error;
        if (existing.data) {
          if (existing.data.credential_id !== registration.credentialId
              || JSON.stringify(existing.data.public_key) !== JSON.stringify(registration.publicKey))
            return fail(409, '등록된 기기 정보와 다릅니다.');
          return res.status(200).json({ state: existing.data.state });
        }
        const inserted = await db.from('device_registrations').insert({
          user_id: actor.userId, device_id: deviceId,
          credential_id: registration.credentialId, public_key: registration.publicKey,
          sign_count: registration.counter, state: 'pending',
        });
        if (inserted.error) throw inserted.error;
        return res.status(202).json({ state: 'pending' });
      }
      return fail(400, '지원하지 않는 기기 등록 요청입니다.');
    } catch {
      return fail(503, '기기 등록 또는 인증기 요청을 처리하지 못했습니다.');
    }
  };
}

import { randomUUID } from 'node:crypto';
import { createClient } from '@supabase/supabase-js';
import { createLoginVerifier } from './verify-login.mjs';
import config from '../aleph.config.json' with { type: 'json' };

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/iu;
const fields = 'id,title,content';
const view = row => ({ id: row.id, title: row.title, body: row.content });

export function createNotesHandler({ item = false, env = process.env, db: suppliedDb,
  verifyLogin: suppliedVerifier } = {}) {
  let db = suppliedDb;
  let verifyLogin = suppliedVerifier;
  return async (req, res) => {
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    const fail = (status, error) => res.status(status).json({ error });
    const authorization = req.headers?.authorization;
    if (typeof authorization !== 'string' || !/^Bearer [\w-]+\.[\w-]+\.[\w-]+$/u.test(authorization)
        || authorization.length > 8192) return fail(401, '로그인이 필요합니다.');
    let actor;
    try {
      if (!verifyLogin) {
        if (env.SUPABASE_URL !== new URL(config.identityProvider.issuer).origin || !env.SUPABASE_SECRET_KEY) {
          return fail(503, '서버 로그인 설정을 확인해 주세요.');
        }
        verifyLogin = createLoginVerifier({ config, supabaseSecretKey: env.SUPABASE_SECRET_KEY });
      }
      actor = await verifyLogin(authorization);
    } catch { return fail(503, '로그인 확인을 완료하지 못했습니다.'); }
    if (!actor) return fail(401, '로그인이 만료되었거나 유효하지 않습니다. 다시 로그인해 주세요.');

    const methods = item ? ['GET', 'PUT', 'DELETE'] : ['GET', 'POST'];
    if (!methods.includes(req.method)) {
      res.setHeader('Allow', methods.join(', '));
      return fail(405, '지원하지 않는 요청 방식입니다.');
    }
    let id;
    if (item) {
      id = req.query?.id;
      if (typeof id !== 'string' || !UUID.test(id)) return fail(400, '올바른 메모 ID가 필요합니다.');
    }
    let body;
    if (['POST', 'PUT'].includes(req.method)) {
      try { body = typeof req.body === 'string' ? JSON.parse(req.body) : req.body; }
      catch { return fail(400, 'JSON 형식을 확인해 주세요.'); }
      if (req.method === 'PUT' && body && Object.hasOwn(body, 'owner_id') && body.owner_id !== actor.userId) {
        return fail(403, '메모 소유자는 변경할 수 없습니다.');
      }
      if (!body || Array.isArray(body) || typeof body.title !== 'string' || !body.title.trim()
          || body.title.length > 120 || typeof body.body !== 'string' || body.body.length > 10000) {
        return fail(400, '제목은 1~120자, 내용은 10,000자 이내로 입력해 주세요.');
      }
      if (req.method === 'POST') {
        if (body.id !== undefined && (typeof body.id !== 'string' || !UUID.test(body.id))) {
          return fail(400, '메모 ID는 UUID 형식이어야 합니다.');
        }
        id = body.id ?? randomUUID();
      }
    }
    try {
      db ??= createClient(env.SUPABASE_URL, env.SUPABASE_SECRET_KEY, {
        auth: { persistSession: false, autoRefreshToken: false, detectSessionInUrl: false },
      });
      const run = query => query.abortSignal(AbortSignal.timeout(8000));
      if (!item && req.method === 'GET') {
        const { data, error } = await run(db.from('notes').select(fields).eq('owner_id', actor.userId).order('id'));
        if (error) throw error;
        return res.status(200).json(data.map(view));
      }
      if (req.method === 'POST') {
        const { data, error } = await run(db.from('notes').insert({ id, title: body.title.trim(),
          content: body.body, owner_id: actor.userId }).select(fields).single());
        if (error?.code === '23505') return fail(409, '이미 사용 중인 메모 ID입니다.');
        if (error) throw error;
        return res.status(201).json(view(data));
      }
      // Match owner and ID atomically, including writes. Never update owner_id from input.
      let query = db.from('notes');
      if (req.method === 'GET') query = query.select(fields);
      if (req.method === 'PUT') query = query.update({ title: body.title.trim(), content: body.body });
      if (req.method === 'DELETE') query = query.delete();
      query = query.eq('id', id).eq('owner_id', actor.userId);
      if (req.method !== 'GET') query = query.select(fields);
      const { data, error } = await run(query.maybeSingle());
      if (error) throw error;
      if (!data) return fail(404, '메모를 찾을 수 없습니다.');
      return res.status(200).json(req.method === 'DELETE' ? { id: data.id, deleted: true } : view(data));
    } catch { return fail(502, '자료 처리에 실패했습니다. 서버 연결과 DB 설정을 확인해 주세요.'); }
  };
}

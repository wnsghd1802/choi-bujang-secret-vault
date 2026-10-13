import { createClient } from '@supabase/supabase-js';
import { createLoginVerifier } from './verify-login.mjs';
import { requestHasOnlyResourceId } from './resource-zones.mjs';
import config from '../aleph.config.json' with { type: 'json' };

// No browser role or menu flag can grant instructor rights.
// Only a verified session + an existing server-side instructor grant may update a notice.
export function createNoticeHandler({ env = process.env, db: suppliedDb,
  verifyLogin: suppliedVerifier } = {}) {
  return async (req, res) => {
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    const fail = (status, error) => res.status(status).json({ error });
    if (req.method !== 'PUT') {
      res.setHeader('Allow', 'PUT');
      return fail(405, '지원하지 않는 요청입니다.');
    }
    const authorization = req.headers?.authorization;
    if (typeof authorization !== 'string' || authorization.length > 8192
        || !/^Bearer [\w-]+\.[\w-]+\.[\w-]+$/u.test(authorization)) {
      return fail(401, '로그인이 필요합니다.');
    }
    let actor;
    try {
      let verifier = suppliedVerifier;
      if (!verifier) {
        if (env.SUPABASE_URL !== new URL(config.identityProvider.issuer).origin
            || !env.SUPABASE_SECRET_KEY) return fail(503, '서버 로그인 설정이 필요합니다.');
        verifier = createLoginVerifier({ config, supabaseSecretKey: env.SUPABASE_SECRET_KEY });
      }
      actor = await verifier(authorization);
    } catch { return fail(503, '로그인 확인을 완료하지 못했습니다.'); }
    // An instructor role must never be inferred from the body, route or judge token.
    if (!actor || actor.kind !== 'student'
        || !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/iu.test(actor.userId ?? '')) {
      return fail(403, '강사 권한을 확인하지 못했습니다.');
    }
    const id = req.query?.id;
    if (!requestHasOnlyResourceId(req, id, '/api/notices')) {
      return fail(400, '올바른 강사 공지 경로가 필요합니다.');
    }
    let body;
    try { body = typeof req.body === 'string' ? JSON.parse(req.body) : req.body; }
    catch { return fail(400, 'JSON 형식을 확인해 주세요.'); }
    if (!body || Array.isArray(body) || typeof body.title !== 'string'
      || !body.title.trim() || body.title.length > 120
      || typeof body.body !== 'string' || body.body.length > 10000) {
      return fail(400, '제목과 공지 내용을 확인해 주세요.');
    }
    try {
      const db = suppliedDb ?? createClient(env.SUPABASE_URL, env.SUPABASE_SECRET_KEY, {
        auth: { persistSession: false, autoRefreshToken: false, detectSessionInUrl: false },
      });
      // Empty or missing grants are denied; only server-managed rows count.
      const grant = await db.from('instructor_grants')
        .select('user_id').eq('user_id', actor.userId).eq('can_edit_notices', true)
        .maybeSingle().abortSignal(AbortSignal.timeout(8000));
      if (grant.error || !grant.data || grant.data.user_id !== actor.userId) {
        return fail(403, '강사 권한이 없습니다.');
      }
      const update = await db.from('instructor_notices')
        .update({ title: body.title.trim(), content: body.body })
        .eq('id', id).select('id,title,content')
        .maybeSingle().abortSignal(AbortSignal.timeout(8000));
      if (update.error) return fail(502, '공지 처리에 실패했습니다.');
      if (!update.data) return fail(404, '공지를 찾을 수 없습니다.');
      return res.status(200).json({ id: update.data.id, title: update.data.title,
        body: update.data.content });
    } catch { return fail(403, '강사 권한을 확인하지 못했습니다.'); }
  };
}

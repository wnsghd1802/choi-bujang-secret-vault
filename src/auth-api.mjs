import { createClient } from '@supabase/supabase-js';

// Use a fresh SDK client for every request: never share one user's auth state.
export function createAuthHandler({ env = process.env, clientFactory = createClient } = {}) {
  return async (req, res) => {
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    const fail = (status, error) => res.status(status).json({ error });
    if (req.method !== 'POST') {
      res.setHeader('Allow', 'POST');
      return fail(405, 'POST 요청만 지원합니다.');
    }
    if (!/^application\/json(?:;|$)/iu.test(req.headers?.['content-type'] ?? '')) {
      return fail(415, 'JSON 요청이 필요합니다.');
    }
    let body;
    try { body = typeof req.body === 'string' ? JSON.parse(req.body) : req.body; }
    catch { return fail(400, '요청 형식을 확인해 주세요.'); }
    if (!body || Array.isArray(body) || !['login', 'refresh', 'logout'].includes(body.action)) {
      return fail(400, '지원하지 않는 로그인 요청입니다.');
    }
    if (body.action === 'login' && (typeof body.email !== 'string' || body.email.length > 320 || !body.email.trim()
        || typeof body.password !== 'string' || !body.password || body.password.length > 1024)) {
      return fail(400, '이메일과 비밀번호를 입력해 주세요.');
    }
    if (body.action === 'refresh' && (typeof body.refresh_token !== 'string' || !body.refresh_token || body.refresh_token.length > 8192)) {
      return fail(401, '다시 로그인해 주세요.');
    }
    const authorization = req.headers?.authorization;
    if (body.action === 'logout' && (typeof authorization !== 'string' || authorization.length > 8192
        || !/^Bearer [\w-]+\.[\w-]+\.[\w-]+$/u.test(authorization))) {
      return fail(401, '로그인 정보가 필요합니다.');
    }
    if (!env.SUPABASE_URL || !env.SUPABASE_SECRET_KEY) return fail(503, '서버 로그인 설정이 필요합니다.');
    try {
      const client = clientFactory(env.SUPABASE_URL, env.SUPABASE_SECRET_KEY, {
        auth: { persistSession: false, autoRefreshToken: false, detectSessionInUrl: false },
      });
      if (body.action === 'logout') {
        const { error } = await client.auth.admin.signOut(authorization.slice(7), 'local');
        if (error && ![401, 403, 404].includes(error.status)) return fail(502, '서버 로그아웃을 완료하지 못했습니다.');
        return res.status(200).json({ signedOut: true });
      }
      const result = body.action === 'login'
        ? await client.auth.signInWithPassword({ email: body.email.trim(), password: body.password })
        : await client.auth.refreshSession({ refresh_token: body.refresh_token });
      if (result.error) {
        if (result.error.status === 429) return fail(429, '요청이 많습니다. 잠시 후 다시 시도해 주세요.');
        if (result.error.code === 'email_not_confirmed') return fail(401, '이메일 인증을 완료한 뒤 로그인해 주세요.');
        return fail(401, body.action === 'login' ? '이메일 또는 비밀번호가 올바르지 않습니다.' : '로그인이 만료되었습니다. 다시 로그인해 주세요.');
      }
      const session = result.data?.session;
      if (!session || typeof session.access_token !== 'string' || typeof session.refresh_token !== 'string'
          || !Number.isSafeInteger(session.expires_at) || typeof session.user?.id !== 'string') {
        return fail(502, '로그인 응답을 확인하지 못했습니다.');
      }
      // Only the intended user's session is returned. No keys or full user metadata.
      return res.status(200).json({ session: { access_token: session.access_token,
        refresh_token: session.refresh_token, expires_at: session.expires_at, user: { id: session.user.id } } });
    } catch { return fail(502, '로그인 서버에 연결하지 못했습니다.'); }
  };
}

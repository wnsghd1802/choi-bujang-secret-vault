import { dbFor, verifierFor, fingerprint, validKey } from './device-security.mjs';

export function createDeviceHandler({ env = process.env, db, verifyLogin } = {}) {
  return async (req, res) => {
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    const fail = (n, error) => res.status(n).json({ error });
    if (!['GET', 'POST'].includes(req.method)) return fail(405, '지원하지 않는 요청입니다.');
    const auth = req.headers?.authorization;
    if (typeof auth !== 'string' || auth.length > 8192
      || !/^Bearer [\w-]+\.[\w-]+\.[\w-]+$/u.test(auth)) return fail(401, '로그인이 필요합니다.');
    let actor;
    try {
      const verifier = verifyLogin ?? verifierFor(env);
      db ??= dbFor(env);
      if (!verifier || !db) return fail(503, '서버 기기 등록 설정이 필요합니다.');
      actor = await verifier(auth);
    } catch { return fail(503, '로그인 확인에 실패했습니다.'); }
    if (actor?.kind !== 'student') return fail(403, '학생 계정의 로그인 상태를 확인해 주세요.');
    try {
      const url = new URL(req.url, 'https://internal.invalid');
      if (url.pathname !== '/api/device') return fail(400, '기기 등록 주소가 올바르지 않습니다.');
      const read = async id => {
        const r = await db.from('device_registrations').select('state,public_key')
          .eq('user_id', actor.userId).eq('device_id', id).maybeSingle();
        if (r.error) throw r.error;
        return r.data;
      };
      if (req.method === 'GET') {
        const id = url.searchParams.get('id');
        if ([...url.searchParams.keys()].join(',') !== 'id'
          || !/^[a-f0-9]{16}$/u.test(id ?? '')) return fail(400, '기기 번호가 올바르지 않습니다.');
        const found = await read(id);
        return res.status(200).json({ state: found?.state ?? 'not_requested' });
      }
      if (url.search) return fail(400, '기기 등록 주소에 검색 조건을 사용할 수 없습니다.');
      let body;
      try { body = typeof req.body === 'string' ? JSON.parse(req.body) : req.body; }
      catch { return fail(400, 'JSON 형식이 올바르지 않습니다.'); }
      if (!body || Array.isArray(body) || Object.keys(body).sort().join(',') !== 'action,deviceId,publicKey'
          || body.action !== 'request' || !validKey(body.publicKey)
          || body.deviceId !== fingerprint(body.publicKey))
        return fail(400, '공개키와 기기 번호가 올바르지 않습니다.');
      const current = await read(body.deviceId);
      if (current) {
        if (fingerprint(current.public_key) !== body.deviceId)
          return fail(409, '이미 등록된 기기 정보와 다릅니다.');
        return res.status(200).json({ state: current.state });
      }
      const inserted = await db.from('device_registrations').insert({
        user_id: actor.userId, device_id: body.deviceId,
        public_key: body.publicKey, state: 'pending',
      });
      if (inserted.error) {
        const concurrent = await read(body.deviceId);
        if (!concurrent || fingerprint(concurrent.public_key) !== body.deviceId)
          return fail(503, '기기 요청을 저장하지 못했습니다.');
        return res.status(200).json({ state: concurrent.state });
      }
      return res.status(202).json({ state: 'pending' });
    } catch { return fail(503, '승인 상태 DB를 확인하지 못했습니다.'); }
  };
}

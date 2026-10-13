import { createClient } from '@supabase/supabase-js';
import { createLoginVerifier } from './verify-login.mjs';
import { noteOwnerId } from './note-owner.mjs';
import { isValidRestoreId, verifyPrivateCopy, validateRestoredRow, comparePrivateCopies } from './recovery-core.mjs';
import config from '../aleph.config.json' with { type: 'json' };

// Never allow arbitrary tables, owners, records or paths to be restored.
export function createRecoveryHandler({ env = process.env, db: suppliedDb,
  verifyLogin: suppliedVerifier } = {}) {
  return async (req, res) => {
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    const fail = (code, error) => res.status(code).json({ error });
    if (req.method !== 'POST') {
      res.setHeader('Allow', 'POST');
      return fail(405, 'POST 요청만 허용합니다.');
    }

    // An exact POST route with no query parameter prevents bulk restore,
    // selector aliasing, export or control of tables/owners.
    const query = req.query ?? {};
    if (!query || typeof query !== 'object' || Array.isArray(query)
        || Object.keys(query).length !== 0) return fail(400, '복구 요청 경로가 올바르지 않습니다.');
    if (typeof req.url === 'string') {
      let url;
      try { url = new URL(req.url, 'https://request.invalid'); }
      catch { return fail(400, '복구 경로를 확인해 주세요.'); }
      if (url.pathname !== '/api/restore' || url.search || url.hash) {
        return fail(400, '복구 경로를 확인해 주세요.');
      }
    }
    const authorization = req.headers?.authorization;
    if (typeof authorization !== 'string' || authorization.length > 8192
        || !/^Bearer [\w-]+\.[\w-]+\.[\w-]+$/u.test(authorization)) {
      return fail(401, '검증된 로그인 정보가 필요합니다.');
    }
    let actor;
    try {
      let verifyLogin = suppliedVerifier;
      if (!verifyLogin) {
        if (env.SUPABASE_URL !== new URL(config.identityProvider.issuer).origin
            || !env.SUPABASE_SECRET_KEY) return fail(503, '서버 인증 설정을 확인해 주세요.');
        verifyLogin = createLoginVerifier({ config, supabaseSecretKey: env.SUPABASE_SECRET_KEY });
      }
      actor = await verifyLogin(authorization);
    } catch { return fail(503, '요청 신원 확인에 실패했습니다.'); }

    // Stage 10 only: verified judge-B synthetic notes, never real students,
    // judge-A records, arbitrary user IDs or public backup endpoints.
    if (!actor || actor.kind !== 'judge' || actor.identity !== 'b'
        || !isValidRestoreId(actor.runId)) return fail(403, '시험 계정 B만 복구할 수 있습니다.');
    const ownerId = noteOwnerId(actor);
    if (!ownerId) return fail(403, '소유자를 검증하지 못했습니다.');

    let body;
    try { body = typeof req.body === 'string' ? JSON.parse(req.body) : req.body; }
    catch { return fail(400, 'JSON 형식을 확인해 주세요.'); }
    if (!body || typeof body !== 'object' || Array.isArray(body)
      || Object.keys(body).sort().join(',') !== 'id' || !isValidRestoreId(body.id)) {
      return fail(400, '복구할 시험 메모 ID 한 건만 지정해 주세요.');
    }


    try {
      const db = suppliedDb ?? createClient(env.SUPABASE_URL, env.SUPABASE_SECRET_KEY, {
        auth: { persistSession: false, autoRefreshToken: false, detectSessionInUrl: false },
      });
      const run = query => query.abortSignal(AbortSignal.timeout(8000));
      const { data: copy, error: backupError } = await run(db.from('test_note_backups')
        .select('id,owner_id,run_id,identity,title,content,content_sha256')
        .eq('id', body.id).eq('owner_id', ownerId).eq('run_id', actor.runId).maybeSingle());
      if (backupError) return fail(503, '비공개 안전 사본을 조회하지 못했습니다.');
      if (!copy) return fail(404, '지정한 시험 메모의 안전 사본이 없습니다.');
      if (!verifyPrivateCopy(copy, { id: body.id, ownerId, runId: actor.runId })) {
        return fail(409, '사본 ID·소유자·내용 해시 검증에 실패했습니다.');
      }
      // Final API snapshot re-read happens BEFORE any mutation. If this check
      // fails we must not restore the note or append an audit event. The RPC
      // independently re-verifies and restores atomically in the database.
      const { data: copyAgain, error: rereadError } = await run(db.from('test_note_backups')
        .select('id,owner_id,run_id,identity,title,content,content_sha256')
        .eq('id', body.id).eq('owner_id', ownerId).eq('run_id', actor.runId).maybeSingle());
      if (rereadError || !comparePrivateCopies(copy, copyAgain,
        { id: body.id, ownerId, runId: actor.runId })) {
        return fail(409, '안전 사본 재조회 및 검증에 실패했습니다.');
      }
      // Atomic restore, re-verification and audit append in ONE DB transaction.
      // No potentially failing cross-request read may follow this commit.
      const { data: restored, error: restoreError } = await run(db.rpc('restore_test_note_from_backup', {
        p_id: body.id, p_owner_id: ownerId, p_run_id: actor.runId,
        p_hash: copy.content_sha256,
      }));
      if (restoreError || !Array.isArray(restored) || restored.length !== 1
          || !validateRestoredRow(restored[0], copy)) {
        return fail(409, '시험 메모 복구가 검증되지 않았습니다.');
      }
      return res.status(200).json({ id: copy.id, restored: true, verified: true,
        contentSha256: copy.content_sha256 });
    } catch {
      // Deliberately do not leak table contents, token details or DB diagnostics.
      return fail(503, '시험 메모 복구를 확인하지 못했습니다.');
    }
  };
}

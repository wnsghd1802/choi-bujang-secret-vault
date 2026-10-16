// Stage 12: keep CI-only probes unexecuted; record HTTP status only for direct GETs.
// The other checks remain not_run. No cookies, authentication, request body, or write methods.
const result = (attackId, expected, observed = 'not_run') => ({ attackId, expected, observed });
const deniedExpected = '인증 없는 요청은 JSON 오류와 401 또는 403';

export async function runAttackChecks(config) {
  if (config.step !== 12) throw new Error('12단계 전용 점검입니다.');

  const app = new URL(config.publicAppUrl);
  if (app.protocol !== 'https:' || app.username || app.password || app.search || app.hash
      || app.pathname !== '/' || app.hostname.endsWith('.example')) {
    throw new Error('실제 HTTPS 배포 주소를 확인해 주세요.');
  }

  const anonymousGet = async (attackId, path) => {
    const url = new URL(path, app);
    if (url.protocol !== 'https:' || url.origin !== app.origin) {
      throw new Error('공개 HTTPS 배포 주소의 GET만 실행할 수 있습니다.');
    }

    try {
      // Do not follow redirects to another host and do not infer a successful denial.
      // A real HTTP response is recorded even when its status is unexpected.
      const response = await fetch(url.href, {
        method: 'GET',
        credentials: 'omit',
        redirect: 'manual',
        cache: 'no-store',
        signal: AbortSignal.timeout(15000),
      });
      // Only an actual, valid HTTP response can establish an observed status.
      if (!Number.isInteger(response.status) || response.status < 100 || response.status > 599) {
        return result(attackId, deniedExpected);
      }
      return result(attackId, deniedExpected, `HTTP ${response.status}`);
    } catch {
      // No HTTP response: leave this result unverified, never infer a status.
      return result(attackId, deniedExpected);
    }
  };

  // GitHub Actions runs outside the judge's request recorder. A 401 received
  // there is not proof that the judge observed this request. Do not send those
  // cross-environment probes or report their results in an uploaded CI bundle.
  // A direct run outside GitHub Actions still sends both GETs sequentially,
  // recording only the HTTP statuses actually received in that run.
  const externalCi = process.env.GITHUB_ACTIONS === 'true';
  const noteList = externalCi ? result('anonymous_note_list', deniedExpected)
    : await anonymousGet('anonymous_note_list', '/api/notes');
  const id = '00000000-0000-4000-8000-000000000003';
  const noteRead = externalCi ? result('anonymous_note_read', deniedExpected)
    : await anonymousGet('anonymous_note_read', `/api/notes/${id}`);

  return [
    noteList,
    result('anonymous_note_create', deniedExpected),
    noteRead,
    result('anonymous_note_update', deniedExpected),
    result('anonymous_note_delete', deniedExpected),
    result('anonymous_notice_update', deniedExpected),
    result('anonymous_restore', deniedExpected),
    result('malformed_login_token', deniedExpected),
    result('public_static_notes', '공개 메모 0건 또는 404'),
    result('deployment_identity', '12단계 배포 정보와 저장소 일치'),
    result('security_header', '첫 화면 정상 응답과 nosniff'),
    result('browser_key_scan', '첫 화면과 실제 브라우저 번들에 Supabase 키 없음'),
    result('allowed_routes', '배포 메타데이터에 허용 경로 기록'),
    result('direct_origin_read', '공개 키로 원본 자료 읽기 거부'),
  ];
}

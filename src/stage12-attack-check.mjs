// Stage 12 diagnostic isolation: no network requests are executed.
// Every check is marked not_run; this tests whether the isolated bundle failure
// comes from public GET calls or from the remaining bundle/Git execution path.
const result = (attackId, expected) => ({ attackId, expected, observed: 'not_run' });
const deniedExpected = '인증 없는 요청은 JSON 오류와 401 또는 403';

export async function runAttackChecks(config) {
  if (config.step !== 12) throw new Error('12단계 전용 점검입니다.');
  const app = new URL(config.publicAppUrl);
  if (app.protocol !== 'https:' || app.username || app.password || app.search || app.hash
      || app.pathname !== '/' || app.hostname.endsWith('.example')) {
    throw new Error('실제 HTTPS 배포 주소를 확인해 주세요.');
  }
  return [
    result('anonymous_note_list', deniedExpected),
    result('anonymous_note_create', deniedExpected),
    result('anonymous_note_read', deniedExpected),
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

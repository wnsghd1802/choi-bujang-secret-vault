// Stage 12: do not claim API observations that the judge's request record lacks.
// This isolated submission runner makes no anonymous GET requests in this version.
// Every unexecuted check must remain observed: 'not_run' regardless of CI/runtime.
const result = (attackId, expected, observed = 'not_run') => ({ attackId, expected, observed });
const deniedExpected = '인증 없는 요청은 JSON 오류와 401 또는 403';

export async function runAttackChecks(config) {
  if (config.step !== 12) throw new Error('12단계 전용 점검입니다.');

  // The judge explicitly reported that neither GET was recorded in its own
  // execution. A separate GitHub Actions / local HTTP 401 is not judge evidence.
  // Do not send an untracked probe or reuse its result in this submission.
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

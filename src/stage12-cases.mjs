// Stage 12 test register. This is a PLAN, not a fabricated record of execution.
// No bearer tokens, device proofs, private notes or identifiers are stored here.
const groups = [
  [1, [
    ['S01-01', '공개 메모 원문 비노출', 'api', 'GET', '/data.json', 'HTTP 200, notes 배열 0건', 'public-data'],
    ['S01-02', '첫 화면 보안 헤더', 'api', 'GET', '/', 'HTTP 200, X-Content-Type-Options: nosniff', 'root-headers'],
  ]],
  [2, [
    ['S02-01', '배포 저장소·단계 확인', 'api', 'GET', '/aleph.json', '배포 단계 12 및 저장소 일치', 'identity'],
    ['S02-02', '공개 메모 목록 재확인', 'api', 'GET', '/data.json', '개인 메모가 공개되지 않음', 'public-data'],
    ['S02-03', '자료실 화면 응답', 'api', 'GET', '/', '정상 HTML 응답과 nosniff', 'root-headers'],
  ]],
  [3, [
    ['S03-01', '익명 목록 요청 차단', 'api', 'GET', '/api/notes', 'HTTP 401/403 및 JSON 오류', 'anonymous-notes'],
    ['S03-02', '익명 단건 요청 차단', 'api', 'GET', '/api/notes/00000000-0000-4000-8000-000000000003', 'HTTP 401/403 및 JSON 오류', 'anonymous-note'],
    ['S03-03', '익명 메모 생성 차단', 'api', 'POST', '/api/notes', 'HTTP 401/403, 생성된 자료 없음'],
    ['S03-04', '익명 메모 수정 차단', 'api', 'PUT', '/api/notes/:id', 'HTTP 401/403, 원본 불변'],
    ['S03-05', '위조 토큰 읽기 거부', 'api', 'GET', '/api/notes', 'HTTP 401/403, 자료 반환 없음'],
  ]],
  [4, [
    ['S04-01', 'A 자신의 메모 읽기', 'api', 'GET', '/api/notes/:id', '검증된 A만 자신의 메모 조회'],
    ['S04-02', 'A의 B 메모 읽기 금지', 'api', 'GET', '/api/notes/:id', 'A로 B의 자료 조회 불가'],
    ['S04-03', 'B의 A 메모 변경 금지', 'api', 'PUT', '/api/notes/:id', 'B가 A의 자료 변경 불가'],
    ['S04-04', 'B 자신의 메모 수정', 'api', 'PUT', '/api/notes/:id', 'B 소유 자료만 수정'],
  ]],
  [5, [
    ['S05-01', '동일 출처 서버 경유', 'api', 'GET', '/api/notes', '승인된 접근은 서버 API를 사용'],
    ['S05-02', '원본 Data API 직접 조회 금지', 'api', 'GET', 'Supabase /rest/v1/notes', '익명/일반 사용자 직접 접근 금지'],
    ['S05-03', '브라우저 비밀키 미노출', 'static', 'SCAN', 'HTML 및 app.js', '서버 키·로그인 토큰이 공개 번들에 없음'],
    ['S05-04', '실패 응답 JSON 처리', 'api', 'GET', '/api/notes', '거부 시 JSON 오류 반환', 'anonymous-notes'],
  ]],
  [6, [
    ['S06-01', '등록된 기기 정상 접근', 'engine', 'decide', 'GET /notes/:id', 'deviceRegistered=true, 허용 경로에서 allow'],
    ['S06-02', '미등록 기기 접근 차단', 'engine', 'decide', 'GET /notes/:id', 'deviceRegistered=false에서 deny'],
    ['S06-03', '기기 값 위조 거부', 'engine', 'decide', 'GET /notes/:id', '불명확한 등록값을 허용하지 않음'],
  ]],
  [7, [
    ['S07-01', '정상 신호 통과', 'engine', 'decide', 'GET /notes/:id', '정상 가상 신호에서 allow'],
    ['S07-02', '복합 위험 재인증', 'engine', 'decide', 'GET /notes/:id', '검증된 위험 신호에서 step_up'],
    ['S07-03', '신선한 재인증 후 허용', 'engine', 'decide', 'GET /notes/:id', '신선한 검증 증거에서 allow'],
  ]],
  [8, [
    ['S08-01', '단건 자료 구역 허용', 'engine', 'decide', 'GET /notes/:id', '정확한 단건 경로 허용'],
    ['S08-02', '다중 식별자 우회 차단', 'engine', 'decide', 'GET /notes/:id?other=...', '추가 쿼리·다른 구역 거부'],
    ['S08-03', '교사 권한 위장 거부', 'api', 'PUT', '/api/notices/:id', '서버에 검증된 교사 권한 없으면 거부'],
    ['S08-04', '자료 목록 광역 허용 차단', 'engine', 'decide', 'GET /api/notes', '판정기의 단건 전용 규칙에서 deny'],
  ]],
  [9, [
    ['S09-01', '10분 120건은 관찰', 'engine', 'detect', '가상 GET 120건', 'observe'],
    ['S09-02', '10분 121건 회수 제안', 'engine', 'detect', '가상 GET 121건', 'propose_revocation'],
    ['S09-03', '서로 다른 사용자 분리', 'engine', 'detect', '다른 주체 GET 묶음', '주체를 합산하지 않고 observe'],
    ['S09-04', '운영 회수 집행 확인', 'operation', 'VERIFY', '운영 회수 상태', '실제 회수 집행·접속 거부 증거'],
  ]],
  [10, [
    ['S10-01', '익명 복구 요청 차단', 'api', 'POST', '/api/restore', 'HTTP 401/403, 복구 실행 안 됨'],
    ['S10-02', '검증된 시험 B만 복구', 'api', 'POST', '/api/restore', '검증된 B의 대상 1건만 복구'],
    ['S10-03', 'A의 B 복구 요청 거부', 'api', 'POST', '/api/restore', 'A 요청은 HTTP 403'],
    ['S10-04', '사본 위·변조 시 미복구', 'api', 'POST', '/api/restore', '변조 사본은 미복구, 기존 자료 유지'],
    ['S10-05', '실제 감사 영수증 보존', 'operation', 'VERIFY', '복구 및 감사 기록', '감사 이벤트 존재·기존 이력 불변 확인'],
  ]],
  [11, [
    ['S11-01', '익명 승인 기기 조회 차단', 'api', 'GET', '/api/device', 'HTTP 401/403 및 JSON 오류', 'anonymous-device'],
    ['S11-02', '미승인 기기 자료 접근 차단', 'api', 'GET', '/api/notes', '미승인 요청 거부, 원본 불변'],
    ['S11-03', '서명 재사용 방지', 'api', 'GET', '/api/notes', '만료·재사용 챌린지 거부'],
    ['S11-04', '보호 자료 오프라인 금지', 'operation', 'VERIFY', 'PWA 오프라인', '오프라인에서 보호 자료 접근 불가'],
  ]],
];
export const STAGE12_CASES = Object.freeze(groups.flatMap(([stage, rows]) => rows.map(
  ([id, title, kind, method, path, expected, probe]) => Object.freeze({
    id, stage, title, kind, method, path, expected, probe: probe ?? null,
  })
)));
export const STAGE12_PROBES = Object.freeze(new Set([
  'public-data', 'root-headers', 'identity', 'anonymous-notes',
  'anonymous-note', 'anonymous-device',
]));
export function checkedResult(caseInfo, status, data, headers, identity) {
  const denied = (status === 401 || status === 403) && data && typeof data.error === 'string';
  switch (caseInfo.probe) {
    case 'public-data':
      return status === 200 && Array.isArray(data?.notes) && data.notes.length === 0;
    case 'root-headers':
      return status === 200 && headers.get('x-content-type-options') === 'nosniff';
    case 'identity':
      return status === 200 && data?.step === 12 && data?.repoUrl === identity.repoUrl
        && typeof data?.commit === 'string' && /^[a-f0-9]{40}$/u.test(data.commit);
    case 'anonymous-notes':
    case 'anonymous-note':
    case 'anonymous-device':
      return Boolean(denied);
    default:
      return false;
  }
}

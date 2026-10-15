// Stage 12 bundle checks: anonymous public HTTPS GET only.
// The existing stage 1-11 checker remains unchanged in src/attack-check.mjs.
const expectedDenial = '인증 없는 요청은 JSON 오류와 401 또는 403';
const notRun = attackId => ({ attackId, expected: expectedDenial, observed: 'not_run' });

export async function runAttackChecks(config) {
  if (config.step !== 12) throw new Error('12단계 전용 점검입니다.');
  const app = new URL(config.publicAppUrl);
  if (app.protocol !== 'https:' || app.username || app.password || app.search || app.hash
      || app.pathname !== '/' || app.hostname.endsWith('.example')) {
    throw new Error('실제 HTTPS 배포 주소를 확인해 주세요.');
  }
  const get = path => fetch(new URL(path, app), { method: 'GET', redirect: 'error' });
  const anonymous = async (attackId, path) => {
    const response = await get(path);
    const payload = await response.json().catch(() => null);
    const denied = [401, 403].includes(response.status) && typeof payload?.error === 'string';
    return {
      attackId, expected: expectedDenial,
      observed: denied ? `JSON 오류로 거부 (HTTP ${response.status})`
        : `거부 조건 불충족 (HTTP ${response.status})`,
    };
  };
  const id = '00000000-0000-4000-8000-000000000003';
  const results = [
    await anonymous('anonymous_note_list', '/api/notes'),
    notRun('anonymous_note_create'),
    await anonymous('anonymous_note_read', `/api/notes/${id}`),
    notRun('anonymous_note_update'),
    notRun('anonymous_note_delete'),
    notRun('anonymous_notice_update'),
    notRun('anonymous_restore'),
    notRun('malformed_login_token'),
  ];

  const file = await get('/data.json');
  const data = await file.json().catch(() => null);
  results.push({
    attackId: 'public_static_notes', expected: '공개 메모 0건 또는 404',
    observed: file.status === 404 || (file.ok && Array.isArray(data?.notes) && data.notes.length === 0)
      ? '공개 메모 없음 확인' : '공개 파일 확인 실패',
  });
  const metadata = await get('/aleph.json');
  const identity = await metadata.json().catch(() => null);
  results.push({
    attackId: 'deployment_identity', expected: '12단계 배포 정보와 저장소 일치',
    observed: metadata.ok && identity?.step === 12 && identity?.repoUrl === config.repoUrl
      ? '단계와 저장소 일치; 커밋 별도 대조 필요' : '배포 정보 불일치',
  });
  const root = await get('/');
  results.push({
    attackId: 'security_header', expected: '첫 화면 정상 응답과 nosniff',
    observed: root.ok && root.headers.get('x-content-type-options') === 'nosniff'
      ? '정상 응답과 nosniff 확인' : '응답 또는 헤더 확인 실패',
  });
  const script = await get('/app.js');
  const html = await root.text();
  const code = await script.text();
  const leakedKey = /sb_(?:publishable|secret)_[A-Za-z0-9_-]{12,}|eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/u.test(html + code);
  results.push({
    attackId: 'browser_key_scan', expected: '첫 화면과 실제 브라우저 번들에 Supabase 키 없음',
    observed: root.ok && script.ok && !leakedKey
      ? '화면과 번들에서 키 패턴 미발견' : '화면 또는 번들 검사 실패',
  });
  results.push({
    attackId: 'allowed_routes', expected: '배포 메타데이터에 허용 경로 기록',
    observed: Array.isArray(identity?.allowedRoutes) && identity.allowedRoutes.length > 0
      ? '허용 경로 기록 확인' : '허용 경로 누락',
  });
  results.push({
    attackId: 'direct_origin_read', expected: '공개 키로 원본 자료 읽기 거부', observed: 'not_run',
  });
  return results;
}

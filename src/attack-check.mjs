// The student changes this check as each stage adds an attack to the same app.
// Never return tokens, private keys, real names, or note bodies.
export async function runAttackChecks(config) {
  if ([3, 4].includes(config.step)) return runStageThreeChecks(config);
  if (config.step === 2) return runStageTwoChecks(config);
  if (config.step !== 1) throw new Error('이 단계의 공격 점검을 src/attack-check.mjs에 구현해 주세요.');
  let app;
  try {
    app = new URL(config.publicAppUrl);
  } catch {
    throw new Error('aleph.config.json의 실제 배포 주소를 먼저 넣어 주세요.');
  }
  if (app.protocol !== 'https:' || app.username || app.password || app.search || app.hash
      || app.pathname !== '/' || app.hostname.endsWith('.example')) {
    throw new Error('aleph.config.json의 실제 배포 주소를 먼저 넣어 주세요.');
  }
  if (typeof config.sampleMarker !== 'string' || !config.sampleMarker) throw new Error('가상 메모의 확인 표시를 넣어 주세요.');
  const response = await fetch(new URL('/data.json', app), {
    redirect: 'error', signal: AbortSignal.timeout(10000),
  });
  let visible = false;
  if (response.ok) {
    try {
      const data = await response.json();
      visible = data?.sampleMarker === config.sampleMarker && Array.isArray(data.notes)
        && data.notes.length > 0;
    } catch {
      // A non-JSON response is a failed check, not a successful deployment.
    }
  }
  return [{ attackId: 'anonymous_note_read', expected: '비로그인 화면에서 가상 메모를 확인',
    observed: visible ? '비로그인 요청에서 공개 가상 메모 확인 표시가 보임' : `비로그인 요청에서 확인 표시가 보이지 않음 (HTTP ${response.status})` }];
}

async function runStageThreeChecks(config) {
  const app = new URL(config.publicAppUrl);
  if (app.protocol !== 'https:' || app.username || app.password || app.search || app.hash
      || app.pathname !== '/' || app.hostname.endsWith('.example')) throw new Error('실제 HTTPS 배포 주소를 확인해 주세요.');
  const get = (path, options = {}) => fetch(new URL(path, app), { ...options,
    redirect: 'error', signal: AbortSignal.timeout(10000),
  });
  const results = [];
  const id = '00000000-0000-4000-8000-000000000003';
  for (const [attackId, path, method, token] of [
    ['anonymous_note_list', '/api/notes', 'GET', null],
    ['anonymous_note_create', '/api/notes', 'POST', null],
    ['anonymous_note_read', `/api/notes/${id}`, 'GET', null],
    ['anonymous_note_update', `/api/notes/${id}`, 'PUT', null],
    ['anonymous_note_delete', `/api/notes/${id}`, 'DELETE', null],
    ['malformed_login_token', '/api/notes', 'GET', 'invalid.token.value'],
  ]) {
    // Invalid empty write requests cannot create a record even if authorization fails open.
    const response = await get(path, { method, headers: { 'Content-Type': 'application/json',
      ...(token ? { Authorization: `Bearer ${token}` } : {}) },
      ...(['POST', 'PUT'].includes(method) ? { body: '{}' } : {}),
    });
    const payload = await response.json().catch(() => null);
    const denied = [401, 403].includes(response.status) && typeof payload?.error === 'string';
    results.push({ attackId, expected: '인증 없는 요청은 JSON 오류와 401 또는 403',
      observed: denied ? `JSON 오류로 거부 (HTTP ${response.status})` : `거부 조건 불충족 (HTTP ${response.status})` });
  }
  const file = await get('/data.json');
  const data = await file.json().catch(() => null);
  results.push({ attackId: 'public_static_notes', expected: '공개 메모 0건 또는 404',
    observed: file.status === 404 || (file.ok && Array.isArray(data?.notes) && data.notes.length === 0) ? '공개 메모 없음 확인' : '공개 파일 확인 실패' });
  const metadata = await get('/aleph.json');
  const identity = await metadata.json().catch(() => null);
  results.push({ attackId: 'deployment_identity', expected: `${config.step}단계 배포 정보와 저장소 일치`,
    observed: metadata.ok && identity?.step === config.step && identity?.repoUrl === config.repoUrl ? '단계와 저장소 일치; 커밋 별도 대조 필요' : '배포 정보 불일치' });
  const root = await get('/');
  results.push({ attackId: 'security_header', expected: '첫 화면 정상 응답과 nosniff',
    observed: root.ok && root.headers.get('x-content-type-options') === 'nosniff' ? '정상 응답과 nosniff 확인' : '응답 또는 헤더 확인 실패' });
  return results;
}

async function runStageTwoChecks(config) {
  const app = new URL(config.publicAppUrl);
  if (app.protocol !== 'https:' || app.username || app.password || app.search || app.hash
      || app.pathname !== '/' || app.hostname.endsWith('.example')) {
    throw new Error('실제 HTTPS 배포 주소를 확인해 주세요.');
  }
  const get = path => fetch(new URL(path, app), {
    redirect: 'error', signal: AbortSignal.timeout(10000),
  });
  const root = await get('/');
  const file = await get('/data.json');
  const fileData = await file.json().catch(() => null);
  const empty = file.status === 404 || (file.ok && Array.isArray(fileData?.notes) && fileData.notes.length === 0);
  const metadata = await get('/aleph.json');
  const identity = await metadata.json().catch(() => null);
  const matches = metadata.ok && identity?.step === 2 && identity?.repoUrl === config.repoUrl;
  const api = await get('/api/notes');
  const payload = await api.json().catch(() => null);
  const count = Array.isArray(payload?.notes) ? payload.notes.length : null;
  return [
    { attackId: 'public_static_notes', expected: '공개 data.json에 메모가 없음', observed: empty ? '404 또는 메모 0건 확인' : `공개 파일 조건 불충족 (HTTP ${file.status})` },
    { attackId: 'deployment_identity', expected: '2단계 배포 정보와 제출 저장소 일치', observed: matches ? '단계와 저장소 일치; 커밋 대조는 별도 필요' : `배포 정보 불일치 (HTTP ${metadata.status})` },
    { attackId: 'security_header', expected: '첫 화면 응답에 nosniff 헤더', observed: root.ok && root.headers.get('x-content-type-options') === 'nosniff' ? '정상 응답과 nosniff 확인' : `헤더 또는 화면 응답 조건 불충족 (HTTP ${root.status})` },
    { attackId: 'remaining_public_api', expected: '가상 자료 4건 표시; 비로그인 API 접근은 아직 가능', observed: api.ok && count === 4 ? '비로그인 API에서 4건 확인; 인증 미구현' : `API 확인 실패 (HTTP ${api.status}, 건수 ${count ?? '확인 불가'})` },
  ];
}

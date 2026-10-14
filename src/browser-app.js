import { initWarRoom } from './stage12-workroom.js';
import { getDeviceStatus, requestDevice, signDeviceRequest } from './device-browser.js';
const $ = id => document.getElementById(id);
const sessionKey = 'byteback-session-v5';
let session = null;
let refreshInFlight = null;
let revision = 0;
let listRevision = 0;
let editing = null;
const showError = text => { $('status').textContent = text; };
// Remove only this project's old SDK session from earlier stages.
try { localStorage.removeItem('sb-fgluruiqasiexuqjvzhq-auth-token'); } catch {}

function saveSession(next) {
  session = next;
  // Never persist access or refresh tokens in browser storage.
  // Clean up the legacy snapshot without reading its secret contents.
  try { sessionStorage.removeItem(sessionKey); } catch {}
}

async function authRequest(body, accessToken) {
  const response = await fetch('/api/auth', { method: 'POST', cache: 'no-store',
    headers: { 'Content-Type': 'application/json', ...(accessToken ? { Authorization: `Bearer ${accessToken}` } : {}) },
    body: JSON.stringify(body),
  });
  const result = await response.json().catch(() => null);
  if (!response.ok) throw new Error(result?.error ?? '로그인 요청을 처리하지 못했습니다.');
  return result;
}

async function activeSession(force = false) {
  if (!session) throw new Error('로그인이 필요합니다.');
  if (!force && session.expires_at > Date.now() / 1000 + 60) return session;
  if (!refreshInFlight) {
    const previous = session;
    refreshInFlight = authRequest({ action: 'refresh', refresh_token: previous.refresh_token })
      .then(result => {
        if (session !== previous) throw new Error('로그인 상태가 변경되었습니다.');
        if (result.session?.user.id !== previous.user.id) throw new Error('다시 로그인해 주세요.');
        saveSession(result.session);
        return session;
      }).finally(() => { refreshInFlight = null; });
  }
  return refreshInFlight;
}

function resetEditor() {
  editing = null;
  $('note-form').reset();
  $('save').textContent = '메모 추가';
  $('cancel').hidden = true;
}

function setSession(next) {
  const changedUser = session?.user.id !== next?.user.id;
  saveSession(next);
  revision++;
  $('login-panel').hidden = !!next;
  $('workspace').hidden = true;
  $('device-panel').hidden = !next;
  $('logout').hidden = !next;
  $('account').textContent = next ? '로그인됨' : '로그인되지 않음';
  if (!next || changedUser) { $('notes').replaceChildren(); resetEditor(); }
  if (next) void updateDeviceAccess();
}

async function updateDeviceAccess() {
  const at = revision;
  $('device-state').textContent = '서버 승인 상태를 확인하고 있습니다.';
  try {
    const active = await activeSession();
    const state = await getDeviceStatus(active);
    if (at !== revision || !session) return;
    const approved = state === 'approved';
    $('device-state').textContent = approved ? '서버 승인 완료 · 기기 서명으로 자료 접근'
      : state === 'pending' ? '승인 대기 · 자료실 잠김 (관리자 확인 필요)'
      : state === 'revoked' ? '기기 승인 철회 · 자료실 잠김'
      : '미등록 기기 · 승인 요청 후 관리자 확인이 필요합니다.';
    $('workspace').hidden = !approved;
    if (approved) void loadNotes();
    else $('notes').replaceChildren();
  } catch (error) {
    if (at === revision) {
      $('workspace').hidden = true;
      $('device-state').textContent = error.message;
    }
  }
}
async function api(path, options = {}) {
  let active;
  try { active = await activeSession(); }
  catch (error) { setSession(null); showError(error.message); throw error; }
  const send = async current => {
    const method = options.method ?? 'GET';
    const proof = await signDeviceRequest(current, method, path, options.body ?? '');
    return fetch(path, { ...options, cache: 'no-store', headers: {
      'Content-Type': 'application/json', Authorization: `Bearer ${current.access_token}`, ...proof,
    } });
  };
  let response = await send(active);
  if (response.status === 401 && session === active) {
    try { active = await activeSession(true); response = await send(active); }
    catch (error) { setSession(null); showError(error.message); throw error; }
  }
  const result = await response.json().catch(() => null);
  if (response.status === 401 && session === active) {
    setSession(null);
    showError(result?.error ?? '로그인이 만료되었습니다. 다시 로그인해 주세요.');
  }
  if (!response.ok) throw new Error(result?.error ?? '요청을 처리하지 못했습니다.');
  return result;
}

async function loadNotes() {
  const at = revision;
  const listAt = ++listRevision;
  try {
    const notes = await api('/api/notes');
    if (at !== revision || listAt !== listRevision || !session) return;
    if (!Array.isArray(notes)) throw new Error('자료 형식을 확인해 주세요.');
    const cards = notes.map(note => {
      const li = document.createElement('li');
      const heading = document.createElement('h3');
      const content = document.createElement('p');
      const actions = document.createElement('div');
      const edit = document.createElement('button');
      const remove = document.createElement('button');
      heading.textContent = note.title;
      content.textContent = note.body;
      content.style.whiteSpace = 'pre-wrap';
      edit.textContent = '수정';
      remove.textContent = '삭제';
      edit.addEventListener('click', () => {
        editing = note.id;
        $('title').value = note.title;
        $('body').value = note.body;
        $('save').textContent = '수정 저장';
        $('cancel').hidden = false;
        $('title').focus();
      });
      remove.addEventListener('click', async () => {
        const before = revision;
        remove.disabled = true;
        try {
          await api(`/api/notes/${encodeURIComponent(note.id)}`, { method: 'DELETE' });
          if (before !== revision) return;
          if (editing === note.id) resetEditor();
          showError('메모를 삭제했습니다.');
          await loadNotes();
        } catch (error) { if (before === revision) showError(error.message); }
        finally { remove.disabled = false; }
      });
      actions.className = 'actions';
      actions.append(edit, remove);
      li.append(heading, content, actions);
      return li;
    });
    $('notes').replaceChildren(...cards);
    $('empty').hidden = notes.length !== 0;
  } catch (error) { if (at === revision) showError(error.message); }
}

$('login-form').addEventListener('submit', async event => {
  event.preventDefault();
  $('login').disabled = true;
  showError('로그인 중입니다.');
  try {
    const result = await authRequest({ action: 'login', email: $('email').value.trim(), password: $('password').value });
    $('password').value = '';
    setSession(result.session);
    showError('로그인했습니다.');
  } catch (error) { showError(error.message); }
  finally { $('password').value = ''; $('login').disabled = false; }
});
$('logout').addEventListener('click', async () => {
  $('logout').disabled = true;
  try {
    const previous = session;
    setSession(null);
    if (previous) await authRequest({ action: 'logout' }, previous.access_token);
    showError('로그아웃했습니다.');
  } catch { showError('이 브라우저에서 로그아웃했습니다. 서버 세션 종료는 확인하지 못했습니다.'); }
  finally { $('logout').disabled = false; }
});
$('device-request').addEventListener('click', async () => {
  $('device-request').disabled = true;
  try { await requestDevice(await activeSession()); await updateDeviceAccess(); }
  catch (error) { $('device-state').textContent = error.message; }
  finally { $('device-request').disabled = false; }
});
$('device-refresh').addEventListener('click', () => void updateDeviceAccess());
let installPrompt = null;
window.addEventListener('beforeinstallprompt', event => {
  event.preventDefault(); installPrompt = event; $('install').hidden = false;
});
$('install').addEventListener('click', async () => {
  if (!installPrompt) return;
  const prompt = installPrompt; installPrompt = null; $('install').hidden = true;
  await prompt.prompt();
});
if ('serviceWorker' in navigator) navigator.serviceWorker.register('/sw.js').catch(() => {});
$('note-form').addEventListener('submit', async event => {
  event.preventDefault();
  const at = revision;
  $('save').disabled = true;
  try {
    await api(editing ? `/api/notes/${encodeURIComponent(editing)}` : '/api/notes', {
      method: editing ? 'PUT' : 'POST', body: JSON.stringify({ title: $('title').value, body: $('body').value }),
    });
    if (at !== revision) return;
    resetEditor();
    showError('메모를 저장했습니다.');
    await loadNotes();
  } catch (error) { if (at === revision) showError(error.message); }
  finally { $('save').disabled = false; }
});
$('cancel').addEventListener('click', resetEditor);
// On startup erase earlier versions' stored credentials, never reload them.
try { sessionStorage.removeItem(sessionKey); } catch {}

// Stage 12 public, read-only incident room; private notes remain behind device approval.
initWarRoom();

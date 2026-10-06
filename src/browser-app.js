import { createClient } from '@supabase/supabase-js';
import { supabaseUrl, publishableKey } from './browser-config.js';

const auth = createClient(supabaseUrl, publishableKey);
const $ = id => document.getElementById(id);
let session = null;
let revision = 0;
let listRevision = 0;
let editing = null;
const showError = text => { $('status').textContent = text; };
const loginError = error => ({
  invalid_credentials: '이메일 또는 비밀번호가 올바르지 않습니다.',
  email_not_confirmed: '이메일 인증을 완료한 뒤 로그인해 주세요.',
  over_request_rate_limit: '요청이 많습니다. 잠시 후 다시 시도해 주세요.',
  user_banned: '이 계정은 현재 로그인할 수 없습니다.',
}[error?.code] ?? '로그인하지 못했습니다. 계정 정보와 인터넷 연결을 확인해 주세요.');

function resetEditor() {
  editing = null;
  $('note-form').reset();
  $('save').textContent = '메모 추가';
  $('cancel').hidden = true;
}

function setSession(next) {
  const changedUser = session?.user.id !== next?.user.id;
  session = next;
  revision++;
  $('login-panel').hidden = !!next;
  $('workspace').hidden = !next;
  $('logout').hidden = !next;
  $('account').textContent = next ? '로그인됨' : '로그인되지 않음';
  if (!next || changedUser) { $('notes').replaceChildren(); resetEditor(); }
  if (next) void loadNotes();
}

async function api(path, options = {}) {
  const active = session;
  if (!active) throw new Error('로그인이 필요합니다.');
  const response = await fetch(path, { ...options, cache: 'no-store', headers: {
    'Content-Type': 'application/json', Authorization: `Bearer ${active.access_token}`,
  } });
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
    const { error } = await auth.auth.signInWithPassword({ email: $('email').value.trim(), password: $('password').value });
    $('password').value = '';
    showError(error ? loginError(error) : '로그인했습니다.');
  } catch { showError('로그인 서버에 연결하지 못했습니다.'); }
  finally { $('password').value = ''; $('login').disabled = false; }
});
$('logout').addEventListener('click', async () => {
  $('logout').disabled = true;
  try {
    const { error } = await auth.auth.signOut({ scope: 'local' });
    if (error) throw error;
    setSession(null);
    showError('로그아웃했습니다.');
  } catch { showError('로그아웃하지 못했습니다. 다시 시도해 주세요.'); }
  finally { $('logout').disabled = false; }
});
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
auth.auth.onAuthStateChange((_event, next) => {
  // Keep SDK calls outside its auth event lock.
  setTimeout(() => setSession(next), 0);
});

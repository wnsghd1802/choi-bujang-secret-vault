// The application never creates or holds a device signing secret.
// WebAuthn performs signatures in a platform authenticator, not web storage.
const utf8 = new TextEncoder();
const base64url = value => {
  let text = '';
  for (const byte of new Uint8Array(value)) text += String.fromCharCode(byte);
  return btoa(text).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/u, '');
};
const bytes = encoded => {
  if (typeof encoded !== 'string' || !/^[A-Za-z0-9_-]+$/u.test(encoded)) {
    throw new Error('인증기 응답 형식이 올바르지 않습니다.');
  }
  const text = atob(encoded.replaceAll('-', '+').replaceAll('_', '/') + '='.repeat((4 - encoded.length % 4) % 4));
  return Uint8Array.from(text, char => char.charCodeAt(0));
};
const hash = async text => base64url(await crypto.subtle.digest('SHA-256', utf8.encode(text)));
const hexHash = async text => [...new Uint8Array(await crypto.subtle.digest('SHA-256', utf8.encode(text)))]
  .map(v => v.toString(16).padStart(2, '0')).join('');
async function api(session, action, extra = {}) {
  const response = await fetch('/api/device', {
    method: 'POST', cache: 'no-store',
    headers: { 'Content-Type': 'application/json', Authorization: 'Bearer ' + session.access_token },
    body: JSON.stringify({ action, ...extra }),
  });
  const data = await response.json().catch(() => null);
  if (!response.ok) throw new Error(data?.error ?? '기기 확인을 완료하지 못했습니다.');
  return data;
}
function requireAuthenticator() {
  if (!globalThis.PublicKeyCredential || !navigator.credentials?.create || !navigator.credentials?.get) {
    throw new Error('이 기기에서 WebAuthn 보안 인증기를 사용할 수 없습니다.');
  }
}
export async function getDeviceStatus(session) {
  const response = await fetch('/api/device', { method: 'GET', cache: 'no-store',
    headers: { Authorization: 'Bearer ' + session.access_token } });
  const data = await response.json().catch(() => null);
  if (!response.ok) throw new Error(data?.error ?? '기기 승인 상태를 조회하지 못했습니다.');
  return data.state;
}
export async function requestDevice(session) {
  requireAuthenticator();
  const start = await api(session, 'register-start');
  const credential = await navigator.credentials.create({ publicKey: {
    challenge: bytes(start.challenge),
    rp: { id: start.rpId, name: 'BYTE BACK 안전 자료실' },
    user: { id: bytes(start.userHandle), name: 'byteback-user', displayName: '자료실 사용자' },
    pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
    timeout: 60000, attestation: 'none',
    authenticatorSelection: { userVerification: 'required', residentKey: 'preferred' },
  } });
  if (!credential || credential.type !== 'public-key' || !credential.response?.attestationObject) {
    throw new Error('기기 등록이 취소됐거나 지원되지 않습니다.');
  }
  return api(session, 'register-finish', {
    id: base64url(credential.rawId), challenge: start.challenge,
    clientDataJSON: base64url(credential.response.clientDataJSON),
    attestationObject: base64url(credential.response.attestationObject),
  });
}
export async function signDeviceRequest(session, method, path, body = '') {
  requireAuthenticator();
  const start = await api(session, 'assert-start', { method, path, bodyDigest: await hexHash(body) });
  const credential = await navigator.credentials.get({ publicKey: {
    challenge: bytes(start.challenge), rpId: start.rpId,
    allowCredentials: start.credentialIds.map(id => ({
      type: 'public-key', id: bytes(id),
    })), userVerification: 'required', timeout: 60000,
  } });
  if (!credential || credential.type !== 'public-key' || !credential.response?.signature) {
    throw new Error('기기 인증이 취소됐습니다.');
  }
  const proof = { id: base64url(credential.rawId), challenge: start.challenge,
    clientDataJSON: base64url(credential.response.clientDataJSON),
    authenticatorData: base64url(credential.response.authenticatorData),
    signature: base64url(credential.response.signature) };
  return { 'X-Device-Proof': base64url(utf8.encode(JSON.stringify(proof))) };
}

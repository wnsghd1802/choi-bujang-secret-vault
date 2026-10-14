const encoder = new TextEncoder();
const hex = bytes => [...new Uint8Array(bytes)].map(x => x.toString(16).padStart(2, '0')).join('');
const hash = async value => hex(await crypto.subtle.digest('SHA-256', encoder.encode(value)));
// Only keep the signing key in this page's memory. A stored CryptoKey,
// even when non-extractable, violates this stage's no-browser-key-storage rule.
let currentDevice = null;
let generation = null;

// Remove an IndexedDB database created by the earlier stage-11 build.
// No secret values are read back, printed, or sent to the server.
const oldStoreCleanup = new Promise((resolve, reject) => {
  if (!globalThis.indexedDB) return resolve();
  const request = indexedDB.deleteDatabase('byteback-device-v11');
  request.onsuccess = () => resolve();
  request.onerror = () => reject(new Error('이전 기기 키 저장소를 지우지 못했습니다.'));
  request.onblocked = () => reject(new Error('이전 기기 키 저장소를 사용하는 다른 탭을 닫고 새로고침해 주세요.'));
});

async function deviceKey(create = false) {
  await oldStoreCleanup; // Fail closed if an old persisted key could not be removed.
  if (!globalThis.crypto?.subtle) throw new Error('HTTPS 보안 연결이 필요합니다.');
  if (currentDevice || !create) return currentDevice;
  if (!generation) {
    generation = (async () => {
      const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' },
        false, ['sign', 'verify']);
      const pub = await crypto.subtle.exportKey('jwk', pair.publicKey);
      const publicKey = { kty: pub.kty, crv: pub.crv, x: pub.x, y: pub.y };
      currentDevice = { privateKey: pair.privateKey, publicKey,
        deviceId: (await hash(publicKey.x + '.' + publicKey.y)).slice(0, 16) };
      return currentDevice;
    })().finally(() => { generation = null; });
  }
  return generation;
}
async function deviceFetch(path, method, session, body) {
  const response = await fetch(path, { method, cache: 'no-store',
    headers: { Authorization: 'Bearer ' + session.access_token, 'Content-Type': 'application/json' },
    ...(body ? { body: JSON.stringify(body) } : {}),
  });
  const result = await response.json().catch(() => null);
  if (!response.ok) throw new Error(result?.error ?? '기기 요청이 실패했습니다.');
  return result;
}
export async function getDeviceStatus(session) {
  const key = await deviceKey();
  if (!key) return 'not_requested';
  return (await deviceFetch('/api/device?id=' + key.deviceId, 'GET', session)).state;
}
export async function requestDevice(session) {
  const key = await deviceKey(true);
  return deviceFetch('/api/device', 'POST', session, {
    action: 'request', deviceId: key.deviceId, publicKey: key.publicKey,
  });
}
export async function signDeviceRequest(session, method, path, body = '') {
  const key = await deviceKey();
  if (!key) throw new Error('기기 승인 요청이 필요합니다.');
  const at = String(Math.floor(Date.now() / 1000));
  const nonce = hex(crypto.getRandomValues(new Uint8Array(16)));
  const message = [method, path, await hash(body), at, nonce,
    await hash(session.access_token), session.user.id].join('\n');
  const signature = new Uint8Array(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' },
    key.privateKey, encoder.encode(message)));
  let str = '';
  for (const byte of signature) str += String.fromCharCode(byte);
  return { 'X-Device-Id': key.deviceId, 'X-Device-At': at, 'X-Device-Nonce': nonce,
    'X-Device-Signature': btoa(str).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/u, '') };
}

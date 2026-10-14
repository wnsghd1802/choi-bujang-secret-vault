const encoder = new TextEncoder();
const hex = bytes => [...new Uint8Array(bytes)].map(x => x.toString(16).padStart(2, '0')).join('');
const hash = async value => hex(await crypto.subtle.digest('SHA-256', encoder.encode(value)));
function openStore() {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open('byteback-device-v11', 1);
    request.onupgradeneeded = () => request.result.createObjectStore('keys');
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(new Error('기기 키 저장소를 사용할 수 없습니다.'));
  });
}
async function recordStore(next) {
  const db = await openStore();
  try {
    return await new Promise((resolve, reject) => {
      const tx = db.transaction('keys', next ? 'readwrite' : 'readonly');
      const request = next ? tx.objectStore('keys').put(next, 'current')
        : tx.objectStore('keys').get('current');
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(new Error('기기 키를 읽거나 저장하지 못했습니다.'));
    });
  } finally { db.close(); }
}
async function deviceKey(create = false) {
  if (!crypto?.subtle || !indexedDB) throw new Error('HTTPS와 브라우저 기기 저장소가 필요합니다.');
  let key = await recordStore();
  if (!key && create) {
    const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' },
      false, ['sign', 'verify']);
    const pub = await crypto.subtle.exportKey('jwk', pair.publicKey);
    const publicKey = { kty: pub.kty, crv: pub.crv, x: pub.x, y: pub.y };
    key = { privateKey: pair.privateKey, publicKey,
      deviceId: (await hash(publicKey.x + '.' + publicKey.y)).slice(0, 16) };
    await recordStore(key);
  }
  return key;
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

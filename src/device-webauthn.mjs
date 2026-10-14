import { createHash, createPublicKey, verify } from 'node:crypto';

export const digest = value => createHash('sha256').update(value).digest();
export const hexDigest = value => digest(value).toString('hex');
export const base64url = value => Buffer.from(value).toString('base64url');
const isBase64url = value => typeof value === 'string' && /^[A-Za-z0-9_-]{1,16000}$/u.test(value);
export function binary(value, max = 12000) {
  if (!isBase64url(value)) throw new Error('bad_encoded_value');
  const decoded = Buffer.from(value, 'base64url');
  if (decoded.length > max || decoded.toString('base64url') !== value) throw new Error('bad_encoded_value');
  return decoded;
}
function cbor(buffer, pos = 0, depth = 0) {
  if (depth > 12 || pos >= buffer.length) throw new Error('invalid_attestation');
  const start = buffer[pos++];
  const major = start >> 5, info = start & 31;
  let n;
  if (info < 24) n = info;
  else if (info === 24) { if (pos >= buffer.length) throw new Error('invalid_attestation'); n = buffer[pos++]; }
  else if (info === 25) { if (pos + 2 > buffer.length) throw new Error('invalid_attestation'); n = buffer.readUInt16BE(pos); pos += 2; }
  else if (info === 26) { if (pos + 4 > buffer.length) throw new Error('invalid_attestation'); n = buffer.readUInt32BE(pos); pos += 4; }
  else throw new Error('invalid_attestation');
  if (n > 40000) throw new Error('invalid_attestation');
  if (major === 0 || major === 1) return { value: major === 0 ? n : -1 - n, pos };
  if (major === 2 || major === 3) {
    if (pos + n > buffer.length) throw new Error('invalid_attestation');
    const part = buffer.subarray(pos, pos + n);
    return { value: major === 2 ? part : part.toString('utf8'), pos: pos + n };
  }
  if (major === 4) {
    const arr = [];
    for (let i = 0; i < n; i++) { const el = cbor(buffer, pos, depth + 1); arr.push(el.value); pos = el.pos; }
    return { value: arr, pos };
  }
  if (major === 5) {
    const map = new Map();
    for (let i = 0; i < n; i++) {
      const key = cbor(buffer, pos, depth + 1); pos = key.pos;
      const value = cbor(buffer, pos, depth + 1); pos = value.pos;
      if (map.has(key.value)) throw new Error('invalid_attestation');
      map.set(key.value, value.value);
    }
    return { value: map, pos };
  }
  if (major === 7 && (n === 20 || n === 21 || n === 22)) return { value: n === 22 ? null : n === 21, pos };
  throw new Error('invalid_attestation');
}

export function checkClientData(encoded, type, challenge, origin) {
  const bytes = binary(encoded, 4096);
  const object = JSON.parse(bytes.toString('utf8'));
  if (!object || object.type !== type || object.challenge !== challenge || object.origin !== origin
    || object.crossOrigin === true) throw new Error('invalid_authenticator_origin_or_challenge');
  return bytes;
}
export function checkAuthData(data, rpId, { registration = false } = {}) {
  if (!Buffer.isBuffer(data) || data.length < 37 || !digest(rpId).equals(data.subarray(0, 32))) {
    throw new Error('invalid_relying_party');
  }
  const flags = data[32];
  // Both physical user presence and user verification are mandatory.
  if ((flags & 0x05) !== 0x05 || (registration && !(flags & 0x40))) throw new Error('user_verification_missing');
  const counter = data.readUInt32BE(33);
  if (!registration) return { counter };
  let pos = 37;
  if (pos + 18 > data.length) throw new Error('invalid_attested_credential');
  pos += 16; // AAGUID is public metadata.
  const idLength = data.readUInt16BE(pos); pos += 2;
  if (idLength < 1 || idLength > 1024 || pos + idLength >= data.length) throw new Error('invalid_attested_credential');
  const credentialId = base64url(data.subarray(pos, pos + idLength)); pos += idLength;
  const cose = cbor(data, pos);
  if (!(cose.value instanceof Map) || cose.value.get(1) !== 2 || cose.value.get(3) !== -7
    || cose.value.get(-1) !== 1) throw new Error('unsupported_authenticator_key');
  const x = cose.value.get(-2), y = cose.value.get(-3);
  if (!Buffer.isBuffer(x) || x.length !== 32 || !Buffer.isBuffer(y) || y.length !== 32) {
    throw new Error('invalid_authenticator_key');
  }
  const jwk = { kty: 'EC', crv: 'P-256', x: base64url(x), y: base64url(y) };
  createPublicKey({ key: jwk, format: 'jwk' });
  return { credentialId, publicKey: jwk, counter };
}
export function verifyRegistration({ clientDataJSON, attestationObject, id }, challenge, origin, rpId) {
  checkClientData(clientDataJSON, 'webauthn.create', challenge, origin);
  const bytes = binary(attestationObject);
  const decoded = cbor(bytes);
  if (decoded.pos !== bytes.length || !(decoded.value instanceof Map)
    || decoded.value.get('fmt') !== 'none'
    || !(decoded.value.get('authData') instanceof Buffer)
    || !(decoded.value.get('attStmt') instanceof Map)
    || decoded.value.get('attStmt').size !== 0) throw new Error('invalid_attestation');
  const registration = checkAuthData(decoded.value.get('authData'), rpId, { registration: true });
  if (registration.credentialId !== id) throw new Error('credential_id_mismatch');
  return registration;
}
export function verifyAssertion({ id, clientDataJSON, authenticatorData, signature },
  challenge, origin, rpId, knownId, key) {
  if (id !== knownId) throw new Error('credential_id_mismatch');
  const client = checkClientData(clientDataJSON, 'webauthn.get', challenge, origin);
  const auth = binary(authenticatorData, 4096);
  const { counter } = checkAuthData(auth, rpId);
  const sig = binary(signature, 1024);
  const signingBytes = Buffer.concat([auth, digest(client)]);
  const ok = verify('sha256', signingBytes, createPublicKey({ key, format: 'jwk' }), sig);
  if (!ok) throw new Error('invalid_authenticator_signature');
  return { counter };
}

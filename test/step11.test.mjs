import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, randomBytes, sign } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { verifyRegistration, verifyAssertion, base64url } from '../src/device-webauthn.mjs';
import { verifyApprovedDevice, tokenDigest, withDeviceGate } from '../src/device-security.mjs';
import config from '../aleph.config.json' with { type: 'json' };

const rpId = new URL(config.publicAppUrl).hostname;
const origin = new URL(config.publicAppUrl).origin;
const hash = data => createHash('sha256').update(data).digest();
const head = (type, count) => count < 24 ? Buffer.from([(type << 5) | count])
  : count < 256 ? Buffer.from([(type << 5) | 24, count])
  : Buffer.from([(type << 5) | 25, (count >> 8) & 255, count & 255]);
function cbor(value) {
  if (Buffer.isBuffer(value)) return Buffer.concat([head(2,value.length),value]);
  if (typeof value === 'string') {
    const b = Buffer.from(value); return Buffer.concat([head(3,b.length), b]);
  }
  if (typeof value === 'number') return value >= 0 ? head(0,value) : head(1,-1-value);
  if (value instanceof Map) return Buffer.concat([head(5,value.size),
    ...[...value.entries()].flatMap(([k,v]) => [cbor(k), cbor(v)])]);
  throw Error('unsupported_test_cbor');
}
const challenge = base64url(randomBytes(32));
const userId = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const token = 'aaa.bbb.ccc';
const client = type => base64url(Buffer.from(JSON.stringify({ type, origin, challenge, crossOrigin:false })));
const signer = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
const jwk = signer.publicKey.export({ format: 'jwk' });
const credentialIdBytes = randomBytes(32), credentialId = base64url(credentialIdBytes);
const cose = cbor(new Map([[1,2],[3,-7],[-1,1],
  [-2,Buffer.from(jwk.x,'base64url')],[-3,Buffer.from(jwk.y,'base64url')]]));
const authData = (flags, extra=Buffer.alloc(0)) => Buffer.concat([
  hash(rpId), Buffer.from([flags]), Buffer.alloc(4), extra,
]);
const credential = authData(0x45, Buffer.concat([
  Buffer.alloc(16), Buffer.from([0,credentialIdBytes.length]), credentialIdBytes,cose,
]));
const registration = { id: credentialId, clientDataJSON: client('webauthn.create'),
  attestationObject: base64url(cbor(new Map([
    ['fmt','none'], ['attStmt',new Map()], ['authData',credential],
  ]))) };
const claimed = verifyRegistration(registration, challenge, origin, rpId);
const assertionAuth = authData(0x05);
const assertionData = Buffer.from(client('webauthn.get'),'base64url');
const signature = sign('sha256', Buffer.concat([assertionAuth,hash(assertionData)]),signer.privateKey);
const proof = { id: credentialId, clientDataJSON: client('webauthn.get'),
  authenticatorData: base64url(assertionAuth), signature: base64url(signature), challenge };

test('WebAuthn registers only a verified origin, challenge and public ES256 key', () => {
  assert.equal(claimed.credentialId, credentialId);
  assert.equal(claimed.publicKey.x, jwk.x);
  assert.throws(() => verifyRegistration(registration, challenge, 'https://forged.invalid', rpId));
  assert.throws(() => verifyRegistration(registration, 'other', origin, rpId));
});
test('approved WebAuthn assertion verifies signature, RP binding and challenge', () => {
  assert.equal(verifyAssertion(proof,challenge,origin,rpId,credentialId,claimed.publicKey).counter,0);
  assert.throws(() => verifyAssertion(proof,challenge,origin,'forged.invalid',credentialId,claimed.publicKey));
  assert.throws(() => verifyAssertion({...proof,signature:base64url(Buffer.alloc(72))},
    challenge,origin,rpId,credentialId,claimed.publicKey));
});
test('server consumes challenge once and rejects replay or missing approval', async () => {
  let used=false;
  const db = { from(table) {
    if(table==='device_challenges') return {
      delete(){return this;},eq(){return this;},select(){return this;},
      async maybeSingle(){
        if(used)return {data:null,error:null};
        used=true;
        return {error:null,data:{challenge,user_id:userId,token_digest:tokenDigest('Bearer '+token),
          purpose:'assert',request_method:'GET',request_path:'/api/notes',
          body_digest:hash('').toString('hex'),issued_at:new Date().toISOString()}};
      },
    };
    if(table==='device_registrations')return {
      select(){return this;},eq(){return this;},
      async maybeSingle(){return {error:null,data:{credential_id:credentialId,
        public_key:claimed.publicKey,state:'approved',sign_count:0}};},
    };
    throw Error('unexpected db table');
  } };
  const req={method:'GET',url:'/api/notes',headers:{authorization:'Bearer '+token,
    'x-device-proof':base64url(Buffer.from(JSON.stringify(proof)))}};
  assert.equal(await verifyApprovedDevice(req,{kind:'student',userId},db),true);
  assert.equal(await verifyApprovedDevice(req,{kind:'student',userId},db),false);
  assert.equal(await verifyApprovedDevice({...req,headers:{authorization:'Bearer '+token}}, {kind:'student',userId},db),false);
});
test('existing stage10 judge request remains unchanged', async () => {
  let calls = 0;
  const wrapped=withDeviceGate((_req,res)=>{calls++;return res.status(200).json({ok:true});},
    {verifyLogin:async()=>({kind:'judge',identity:'b'})});
  const res={status(code){this.code=code;return this;},json(value){this.value=value;return this;}};
  await wrapped({headers:{authorization:'Bearer '+token}},res);
  assert.equal(res.code,200);assert.equal(calls,1);
});
test('browser client does not manage or persist device private signing keys', () => {
  const source=readFileSync(new URL('../src/device-browser.js',import.meta.url),'utf8');
  assert.doesNotMatch(source,/\bprivateKey\b|\bgenerateKey\s*\(|indexedDB|localStorage|sessionStorage/u);
  assert.match(source,/navigator\.credentials\.get\s*\(/u);
  assert.match(source,/navigator\.credentials\.create\s*\(/u);
});

import assert from 'node:assert/strict';
import { test } from 'node:test';
import { generateKeyPair, exportJWK, createLocalJWKSet, SignJWT } from 'jose';
import { createLoginVerifier } from '../src/verify-login.mjs';
import { createRecoveryHandler } from '../src/recovery-api.mjs';
import { createNotesHandler } from '../src/notes-api.mjs';
import { noteOwnerId } from '../src/note-owner.mjs';
import { contentDigest } from '../src/recovery-core.mjs';
import config from '../aleph.config.json' with { type: 'json' };

const USER = '11111111-1111-4111-8111-111111111111';
const RUN = '22222222-2222-4222-8222-222222222222';
const OTHER_RUN = '99999999-9999-4999-8999-999999999999';
const A_ID = '33333333-3333-4333-8333-333333333333';
const B_ID = '44444444-4444-4444-8444-444444444444';
const keys = await generateKeyPair('ES256');
const rogue = await generateKeyPair('ES256');
const jwk = await exportJWK(keys.publicKey);
const verifyLogin = createLoginVerifier({
  config, judgeKeySet: createLocalJWKSet({ keys: [jwk] }),
  supabaseClient: { auth: { async getClaims() {
    return { data: null, error: { message: 'not a student session' } };
  } } },
});
const issue = (identity='b', runId=RUN, privateKey=keys.privateKey) =>
  new SignJWT({ aleph_role: 'judge', aleph_identity: identity, aleph_run: runId })
    .setProtectedHeader({ alg: 'ES256' })
    .setIssuer(config.judgeIssuer)
    .setAudience(new URL(config.publicAppUrl).hostname)
    .setSubject(USER).setIssuedAt().setExpirationTime('5m').sign(privateKey);

function response() {
  return { headers: {}, setHeader(name,value) { this.headers[name] = value; },
    status(code) { this.code=code; return this; },
    json(value) { this.body=value; return this; } };
}
function request(method,url,jwt,body,query={}) {
  return {method,url,query,body,headers: jwt ? {authorization:'Bearer '+jwt}:{}};
}
function fakeDb() {
  const notes=new Map(), backups=new Map(), audits=[];
  return {notes,backups,audits,
    from(table) {
      assert.ok(['notes','test_note_backups'].includes(table));
      const rows = table === 'notes' ? notes : backups;
      const conditions=[];
      let one=false;
      const q={
        select(){return q}, eq(k,v){conditions.push([k,v]);return q},
        maybeSingle(){one=true;return q}, single(){one=true;return q},
        order(){return q},
        async abortSignal(){
          const data=[...rows.values()].filter(row=>conditions.every(([k,v])=>row[k]===v));
          return {data: one ? (data[0] ? {...data[0]}:null) : data.map(x=>({...x})),error:null};
        },
      };
      return q;
    },
    rpc(name,p){
      return {async abortSignal(){
        if (name==='create_test_note_with_backup') {
          if(notes.has(p.p_id)||backups.has(p.p_id)) return {data:null,error:{code:'23505'}};
          if (p.p_hash!==contentDigest(p.p_content)) return {data:null,error:{code:'digest'}};
          const row={id:p.p_id,owner_id:p.p_owner_id,title:p.p_title,content:p.p_content};
          const backup={...row,run_id:p.p_run_id,identity:'b',content_sha256:p.p_hash};
          notes.set(row.id,row);
          backups.set(row.id,backup);
          return {data:[{...row}],error:null};
        }
        if(name==='restore_test_note_from_backup'){
          const copy=backups.get(p.p_id),existing=notes.get(p.p_id);
          if(!copy || copy.owner_id!==p.p_owner_id || copy.run_id!==p.p_run_id
              || copy.identity!=='b' || copy.content_sha256!==p.p_hash
              || contentDigest(copy.content)!==copy.content_sha256
              || (existing && existing.owner_id!==copy.owner_id)) {
            return {data:null,error:{code:'restore_rejected'}};
          }
          const restored={id:copy.id,owner_id:copy.owner_id,title:copy.title,content:copy.content};
          notes.set(copy.id,restored);
          audits.push({note_id:copy.id,run_id:copy.run_id,restored_sha256:copy.content_sha256});
          return {data:[{...restored}],error:null};
        }
        throw new Error('Unexpected RPC');
      }};
    },
  };
}

test('signed judge B token is verified; forged B token is rejected as unauthenticated',async()=>{
  const db=fakeDb();
  const valid=await issue();
  const falseSignature=await issue('b',RUN,rogue.privateKey);
  assert.deepEqual((await verifyLogin('Bearer '+valid))?.identity,'b');
  assert.equal(await verifyLogin('Bearer '+falseSignature),null);
  const restore=createRecoveryHandler({db,verifyLogin});
  const denied=response();
  await restore(request('POST','/api/restore',falseSignature,{id:B_ID}),denied);
  assert.equal(denied.code,401);
  assert.equal(db.notes.size,0);
  assert.equal(db.audits.length,0);
});

test('signed B note create, corrupt, restore: exact ID, owner, digest and append-only audit',async()=>{
  const db=fakeDb();
  const aToken=await issue('a'),bToken=await issue('b');
  const aActor=await verifyLogin('Bearer '+aToken);
  const aRow={id:A_ID,owner_id:noteOwnerId(aActor),title:'A synthetic',content:'preserved A data'};
  db.notes.set(A_ID,{...aRow});
  const firstAudit={note_id:A_ID,restored_sha256:'already-preserved-event'};
  db.audits.push({...firstAudit});
  const create=createNotesHandler({db,verifyLogin});
  const createResult=response();
  await create(request('POST','/api/notes',bToken,{
    id:B_ID,title:'B protected copy',body:'original synthetic B data',
  }),createResult);
  assert.equal(createResult.code,201);
  assert.equal(db.backups.size,1);
  assert.equal(db.backups.get(B_ID).content_sha256,contentDigest('original synthetic B data'));
  const protectedCopy={...db.backups.get(B_ID)};
  db.notes.get(B_ID).title='attacker change';
  db.notes.get(B_ID).content='attacker content';
  const restore=createRecoveryHandler({db,verifyLogin});
  const deniedA=response();
  await restore(request('POST','/api/restore',aToken,{id:B_ID}),deniedA);
  assert.equal(deniedA.code,403);
  const restored=response();
  await restore(request('POST','/api/restore',bToken,{id:B_ID}),restored);
  assert.equal(restored.code,200);
  assert.equal(restored.body.restored,true);
  assert.equal(restored.body.verified,true);
  assert.equal(restored.body.contentSha256,protectedCopy.content_sha256);
  assert.deepEqual(db.notes.get(B_ID),{
    id:B_ID,owner_id:protectedCopy.owner_id,
    title:protectedCopy.title,content:protectedCopy.content,
  });
  assert.deepEqual(db.notes.get(A_ID),aRow);
  assert.deepEqual(db.backups.get(B_ID),protectedCopy);
  assert.deepEqual(db.audits[0],firstAudit);
  assert.equal(db.audits.length,2);
  assert.equal(db.audits[1].restored_sha256,protectedCopy.content_sha256);

  const get=createNotesHandler({item:true,db,verifyLogin});
  const asA=response(),asB=response();
  await get(request('GET','/api/notes/'+A_ID,aToken,null,{id:A_ID}),asA);
  await get(request('GET','/api/notes/'+A_ID,bToken,null,{id:A_ID}),asB);
  assert.equal(asA.code,200);
  assert.equal(asB.code,404);
  assert.equal(db.audits.length,2);
});

test('different run cannot steal B recovery; corrupted backup blocks all writes and audits',async()=>{
  const db=fakeDb();
  const bToken=await issue('b'),otherToken=await issue('b',OTHER_RUN);
  const create=createNotesHandler({db,verifyLogin});
  const created=response();
  await create(request('POST','/api/notes',bToken,{
    id:B_ID,title:'B safe',body:'synthetic immutable content',
  }),created);
  assert.equal(created.code,201);
  db.notes.get(B_ID).content='tampered content';
  const restore=createRecoveryHandler({db,verifyLogin});
  const other=response();
  await restore(request('POST','/api/restore',otherToken,{id:B_ID}),other);
  assert.equal(other.code,404);
  assert.equal(db.notes.get(B_ID).content,'tampered content');
  db.backups.get(B_ID).content_sha256='0'.repeat(64);
  const rejected=response();
  await restore(request('POST','/api/restore',bToken,{id:B_ID}),rejected);
  assert.equal(rejected.code,409);
  assert.equal(db.audits.length,0);
  assert.equal(db.notes.get(B_ID).content,'tampered content');
});

test('independent judge fixture without student Supabase keys restores B only', async()=>{
  // No student service key, production Vercel, remote JWKS or real Supabase data.
  const db=fakeDb();
  const keys=createLocalJWKSet({keys:[jwk]});
  const independentEnv={SUPABASE_URL:'https://isolated-judge-fixture.supabase.co'};
  const bToken=await issue('b');
  const aToken=await issue('a');
  const judgeOnly=createLoginVerifier({config,judgeKeySet:keys});
  assert.equal((await judgeOnly('Bearer '+bToken))?.identity,'b');
  assert.equal(await judgeOnly('Bearer '+await issue('b',RUN,rogue.privateKey)),null);
  const create=createNotesHandler({db,env:independentEnv,judgeKeySet:keys});
  const note=response();
  await create(request('POST','/api/notes',bToken,{id:B_ID,title:'B isolated',body:'synthetic original'}),note);
  assert.equal(note.code,201);
  assert.equal(db.backups.size,1);
  db.notes.get(B_ID).content='tampered independently';
  const recover=createRecoveryHandler({db,env:independentEnv,judgeKeySet:keys});
  const denied=response();
  await recover(request('POST','/api/restore',aToken,{id:B_ID}),denied);
  assert.equal(denied.code,403);
  const success=response();
  await recover(request('POST','/api/restore',bToken,{id:B_ID}),success);
  assert.equal(success.code,200);
  assert.equal(db.notes.get(B_ID).content,'synthetic original');
  assert.equal(db.audits.length,1);
  assert.equal(db.audits[0].restored_sha256,contentDigest('synthetic original'));
});

test('independent DB configuration cannot authenticate student tokens via unrelated key',async()=>{
  const fixtureEnv={
    SUPABASE_URL:'https://isolated-judge-fixture.supabase.co',
    SUPABASE_SECRET_KEY:'synthetic-fixture-service-key',
  };
  const db=fakeDb(), keys=createLocalJWKSet({keys:[jwk]});
  const create=createNotesHandler({db,env:fixtureEnv,judgeKeySet:keys});
  const fakeStudentJwt=await issue('b');
  const b=response();
  await create(request('POST','/api/notes',fakeStudentJwt,
    {id:B_ID,title:'B from isolated env',body:'synthetic'}),b);
  assert.equal(b.code,201,'isolated judge token must be independently verified');
  const isolatedVerifier=createLoginVerifier({config,judgeKeySet:keys});
  assert.equal(await isolatedVerifier('Bearer malformed.jwt.value'),null);
  const bad=response();
  await create(request('POST','/api/notes','malformed.jwt.value',
    {id:A_ID,title:'blocked',body:'blocked'}),bad);
  assert.equal(bad.code,401);
  assert.equal(db.notes.size,1);
});

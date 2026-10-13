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

test('pre-existing judge B note without a verified pre-attack snapshot must fail closed', async()=>{
  const db=fakeDb(), bToken=await issue('b');
  const actor=await verifyLogin('Bearer '+bToken);
  db.notes.set(B_ID,{id:B_ID,owner_id:noteOwnerId(actor),
    title:'pre-existing B',content:'already modified'});
  db.audits.push({note_id:A_ID,restored_sha256:'older audit event'});
  const beforeAudit=structuredClone(db.audits);
  const restore=createRecoveryHandler({db,verifyLogin});
  const result=response();
  await restore(request('POST','/api/restore',bToken,{id:B_ID}),result);
  assert.equal(result.code,404);
  assert.equal(db.notes.get(B_ID).content,'already modified',
    'never back up the possibly compromised live note during recovery');
  assert.equal(db.backups.size,0);
  assert.deepEqual(db.audits,beforeAudit,'no evidence may be rewritten or appended on failure');
});

test('pre-existing judge B note restores from a verified private pre-attack copy',async()=>{
  const db=fakeDb(), bToken=await issue('b'), aToken=await issue('a');
  const bActor=await verifyLogin('Bearer '+bToken);
  const aActor=await verifyLogin('Bearer '+aToken);
  const bOwner=noteOwnerId(bActor);
  const original={id:B_ID,owner_id:bOwner,title:'B safe before attack',
    content:'verified pre-attack snapshot'};
  const backup={...original,run_id:RUN,identity:'b',
    content_sha256:contentDigest(original.content)};
  const aNote={id:A_ID,owner_id:noteOwnerId(aActor),title:'A untouched',content:'A content'};
  db.notes.set(A_ID,{...aNote});
  db.notes.set(B_ID,{...original,content:'attacker corruption'});
  db.backups.set(B_ID,{...backup});
  db.audits.push({note_id:A_ID,restored_sha256:'preserved existing audit'});
  const restore=createRecoveryHandler({db,verifyLogin});
  const result=response();
  await restore(request('POST','/api/restore',bToken,{id:B_ID}),result);
  assert.equal(result.code,200);
  assert.deepEqual(db.notes.get(B_ID),original);
  assert.deepEqual(db.notes.get(A_ID),aNote);
  assert.deepEqual(db.backups.get(B_ID),backup);
  assert.equal(db.audits[0].restored_sha256,'preserved existing audit');
  assert.equal(db.audits.length,2);
  assert.equal(db.audits[1].restored_sha256,backup.content_sha256);
});

test('preseeded judge B snapshot under verified token sub restores without changing other notes',async()=>{
  const db=fakeDb(),bToken=await issue('b'),aToken=await issue('a');
  const ownerFromToken=(await verifyLogin('Bearer '+bToken)).userId;
  assert.notEqual(ownerFromToken,noteOwnerId(await verifyLogin('Bearer '+bToken)));
  const original={id:B_ID,owner_id:ownerFromToken,title:'B verified prior state',
    content:'pre-attack verified B data'};
  db.notes.set(B_ID,{...original,content:'attacker-changed B'});
  db.backups.set(B_ID,{...original,run_id:RUN,identity:'b',
    content_sha256:contentDigest(original.content)});
  const aNote={id:A_ID,owner_id:noteOwnerId(await verifyLogin('Bearer '+aToken)),
    title:'Account A',content:'A unchanged'};
  db.notes.set(A_ID,{...aNote});
  db.audits.push({note_id:A_ID,restored_sha256:'existing evidence'});
  const restore=createRecoveryHandler({db,verifyLogin});
  const denied=response();
  await restore(request('POST','/api/restore',aToken,{id:B_ID}),denied);
  assert.equal(denied.code,403);
  const result=response();
  await restore(request('POST','/api/restore',bToken,{id:B_ID}),result);
  assert.equal(result.code,200);
  assert.deepEqual(db.notes.get(B_ID),original);
  assert.deepEqual(db.notes.get(A_ID),aNote);
  assert.equal(db.audits.length,2);
  assert.equal(db.audits[0].restored_sha256,'existing evidence');
});

test('legacy owner compatibility rejects B snapshot without signed-run match',async()=>{
  const db=fakeDb(), token=await issue('b');
  const body='pre-attack B';
  db.notes.set(B_ID,{id:B_ID,owner_id:USER,title:'attacked',content:'corrupted'});
  db.backups.set(B_ID,{id:B_ID,owner_id:USER,run_id:OTHER_RUN,identity:'b',
    title:'safe',content:body,content_sha256:contentDigest(body)});
  const result=response();
  await createRecoveryHandler({db,verifyLogin})(request('POST','/api/restore',token,{id:B_ID}),result);
  assert.equal(result.code,404);
  assert.equal(db.audits.length,0);
  assert.equal(db.notes.get(B_ID).content,'corrupted');
});

test('legacy owner compatibility rejects an unverified foreign owner and never creates a backup',async()=>{
  const db=fakeDb(),token=await issue('b');
  db.notes.set(B_ID,{id:B_ID,owner_id:A_ID,title:'attacked',content:'corrupt'});
  db.backups.set(B_ID,{id:B_ID,owner_id:A_ID,run_id:RUN,identity:'b',
    title:'old',content:'safe',content_sha256:contentDigest('safe')});
  const res=response();
  await createRecoveryHandler({db,verifyLogin})(request('POST','/api/restore',token,{id:B_ID}),res);
  assert.equal(res.code,404);
  assert.equal(db.audits.length,0);
  assert.equal(db.notes.get(B_ID).content,'corrupt');
});

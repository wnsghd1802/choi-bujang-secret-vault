// Stage10 isolated judge-B preseeded-note probe.
// No real accounts, remote API, Vercel, Supabase, or user notes are touched.
import assert from 'node:assert/strict';
import {test} from 'node:test';
import {createRecoveryHandler} from '../src/recovery-api.mjs';
import {noteOwnerId} from '../src/note-owner.mjs';
import {contentDigest} from '../src/recovery-core.mjs';
import {decide} from '../src/decider.mjs';
import {fixtureRequests} from '../scripts/fixture-7.mjs';

const ACTOR={kind:'judge',identity:'b',userId:'11111111-1111-4111-8111-111111111111',
 runId:'22222222-2222-4222-8222-222222222222'};
const ID='44444444-4444-4444-8444-444444444444';
const DERIVED=noteOwnerId(ACTOR);
const SOURCE='Verified original before an independent test attack';
const COPY_BASE={id:ID,run_id:ACTOR.runId,identity:'b',title:'B safe',
 content:SOURCE,content_sha256:contentDigest(SOURCE)};
const res=()=>({setHeader(){},status(code){this.code=code;return this},
 json(body){this.body=body;return this}});
const req={method:'POST',url:'/api/restore',query:{},body:{id:ID},
 headers:{authorization:'Bearer mock.header.signature'}};
const keyMatches=(row,conditions)=>conditions.every(([k,v])=>row[k]===v);

function createDb({noteOwner,backupOwner=null}){
  const notes=new Map([[ID,{id:ID,owner_id:noteOwner,title:'ATTACKED B',
    content:'Tampered by isolated test'}]]);
  const backup=backupOwner?{...COPY_BASE,owner_id:backupOwner}:null;
  const audit=[];
  return {notes,backup,audit,
    from(table){
      assert.equal(table,'test_note_backups');
      const conditions=[];
      const q={select(){return q},eq(k,v){conditions.push([k,v]);return q},
        maybeSingle(){return q},
        async abortSignal(){return {data:backup&&keyMatches(backup,conditions)?{...backup}:null,error:null}}};
      return q;
    },
    rpc(name,p){
      assert.equal(name,'restore_test_note_from_backup');
      return {async abortSignal(){
        const present=notes.get(p.p_id);
        if(!backup || backup.owner_id!==p.p_owner_id||backup.run_id!==p.p_run_id
          ||backup.content_sha256!==p.p_hash ||
          (present && present.owner_id!==p.p_owner_id))
          return {data:null,error:{code:'foreign_or_missing_backup'}};
        const restored={id:backup.id,owner_id:backup.owner_id,
           title:backup.title,content:backup.content};
        notes.set(ID,restored);
        audit.push({note_id:ID,owner_id:p.p_owner_id,run_id:p.p_run_id,
          restored_sha256:p.p_hash});
        return {data:[{...restored}],error:null};
      }};
    },
  };
}

async function attempt(opts){
 const db=createDb(opts),response=res();
 const h=createRecoveryHandler({db,verifyLogin:async()=>ACTOR});
 await h(req,response);
 return {db,response};
}
test('preseeded B without pre-attack copy => 404, attacked note untouched, no audit',async()=>{
  const {db,response}=await attempt({noteOwner:DERIVED});
  assert.equal(response.code,404);
  assert.equal(db.notes.get(ID).content,'Tampered by isolated test');
  assert.equal(db.audit.length,0);
  console.log('CASE no_backup: 404 at backup lookup, no audit');
});
test('preseeded B and safe copy keyed to judge sub, handler derives different owner => 404',async()=>{
  assert.notEqual(DERIVED,ACTOR.userId);
  const {db,response}=await attempt({noteOwner:ACTOR.userId,backupOwner:ACTOR.userId});
  assert.equal(response.code,404);
  assert.equal(db.audit.length,0);
  console.log('CASE judge_sub_owner: 404 despite safe copy because owner mismatch');
});
test('safe copy owned by derived ID but attacked note still belongs to sub => 409',async()=>{
  const {db,response}=await attempt({noteOwner:ACTOR.userId,backupOwner:DERIVED});
  assert.equal(response.code,409);
  assert.equal(db.notes.get(ID).content,'Tampered by isolated test');
  assert.equal(db.audit.length,0);
  console.log('CASE existing_sub_note: 409 at database restore conflict');
});
test('preseeded B and copy both use exact derived owner => 200, one new audit',async()=>{
  const {db,response}=await attempt({noteOwner:DERIVED,backupOwner:DERIVED});
  assert.equal(response.code,200);
  assert.equal(db.notes.get(ID).content,SOURCE);
  assert.equal(db.audit.length,1);
  console.log('CASE matched_owner_and_copy: 200 and audit append');
});
test('stage8/9 decision module denies POST /api/restore if policy gate is invoked',async()=>{
  const normal=fixtureRequests().normal;
  const decision=await decide({...normal,service:'notes',
    method:'POST',route:'POST /api/restore',path:'/api/restore',queryLength:0});
  assert.equal(decision.decision,'deny');
  console.log('CASE decider_routed_restore: deny if judge runs this policy ahead of API');
});

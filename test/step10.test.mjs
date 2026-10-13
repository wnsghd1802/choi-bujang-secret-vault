import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createRecoveryHandler } from '../src/recovery-api.mjs';
import { createNotesHandler } from '../src/notes-api.mjs';
import { noteOwnerId } from '../src/note-owner.mjs';
import { contentDigest, verifyPrivateCopy } from '../src/recovery-core.mjs';

const USER='11111111-1111-4111-8111-111111111111';
const RUN='22222222-2222-4222-8222-222222222222';
const A_ID='33333333-3333-4333-8333-333333333333';
const B_ID='44444444-4444-4444-8444-444444444444';
const B={kind:'judge',userId:USER,runId:RUN,identity:'b'};
const A={...B,identity:'a'};
const headers={authorization:'Bearer x.y.z'};
const response=()=>({setHeader(){},status(code){this.code=code;return this},json(body){this.body=body;return this}});
const request=(id,overrides={})=>({method:'POST',url:'/api/restore',query:{},body:{id},headers,...overrides});
function fakeDb(){
  const notes=new Map(),backups=new Map(),audit=[];
  return {notes,backups,audit,
    from(table) {
      const rows=table==='notes'?notes:backups;
      const filters=[];let operation='select',values;
      const q={eq(k,v){filters.push([k,v]);return q},select(){return q},
        maybeSingle(){return q},single(){return q},order(){return q},
        insert(v){operation='insert';values=v;return q},
        update(v){operation='update';values=v;return q},
        delete(){operation='delete';return q},
        async abortSignal(){
          if(operation==='insert'){
            if(rows.has(values.id))return {error:{code:'23505'},data:null};
            rows.set(values.id,{...values});return {error:null,data:{...values}};
          }
          const selected=[...rows.values()].filter(row=>filters.every(([k,v])=>row[k]===v));
          if(operation==='update')selected.forEach(row=>Object.assign(row,values));
          if(operation==='delete')selected.forEach(row=>rows.delete(row.id));
          return {error:null,data:selected[0]?{...selected[0]}:null};
        }};
      return q;
    },
    rpc(name,p){
      return {async abortSignal(){
        if(name==='create_test_note_with_backup'){
          if(notes.has(p.p_id))return {error:{code:'23505'},data:null};
          const row={id:p.p_id,owner_id:p.p_owner_id,title:p.p_title,content:p.p_content};
          notes.set(row.id,row);
          backups.set(row.id,{...row,run_id:p.p_run_id,identity:'b',content_sha256:p.p_hash});
          return {error:null,data:[row]};
        }
        if(name==='restore_test_note_from_backup'){
          const copy=backups.get(p.p_id),present=notes.get(p.p_id);
          if(!copy || copy.owner_id!==p.p_owner_id || copy.run_id!==p.p_run_id
            || copy.content_sha256!==p.p_hash || copy.content_sha256!==contentDigest(copy.content)
            || (present && present.owner_id!==copy.owner_id))return {error:{code:'blocked'},data:null};
          const row={id:copy.id,owner_id:copy.owner_id,title:copy.title,content:copy.content};
          notes.set(copy.id,row);audit.push({id:copy.id});
          return {error:null,data:[row]};
        }
        throw Error('unexpected rpc');
      }};
    },
  };
}
async function createB(db){
  const res=response();
  await createNotesHandler({db,verifyLogin:async()=>B})({
    method:'POST',url:'/api/notes',headers,query:{},
    body:{id:B_ID,title:'safe',body:'original synthetic content'}
  },res);
  assert.equal(res.code,201);
}
const restore=async(db,req=request(B_ID),actor=B)=>{
  const res=response();
  await createRecoveryHandler({db,verifyLogin:async()=>actor})(req,res);
  return res;
};
test('verified judge-B creation makes separate immutable test backup',async()=>{
  const db=fakeDb();await createB(db);
  assert.equal(db.backups.size,1);
  assert.equal(db.backups.get(B_ID).content_sha256,contentDigest('original synthetic content'));
  assert.notEqual(noteOwnerId(A),noteOwnerId(B));
  assert.equal(noteOwnerId({kind:'student',userId:USER}),USER);
});
test('altered B restores exactly one record; A and previous audit preserved',async()=>{
  const db=fakeDb();await createB(db);
  db.audit.push({id:A_ID,kind:'existing_event'});
  const previousAudit=structuredClone(db.audit[0]);
  db.notes.set(A_ID,{id:A_ID,owner_id:noteOwnerId(A),title:'A safe',content:'unchanged'});
  const before=structuredClone(db.notes.get(A_ID));
  db.notes.get(B_ID).content='corrupted';
  const res=await restore(db);
  assert.equal(res.code,200);assert.equal(res.body.verified,true);
  assert.equal(db.notes.get(B_ID).content,'original synthetic content');
  assert.deepEqual(db.notes.get(A_ID),before);
  assert.equal(db.audit.length,2);
  assert.deepEqual(db.audit[0],previousAudit);
});
test('deleted test-B note can be recovered without touching another note',async()=>{
  const db=fakeDb();await createB(db);db.notes.delete(B_ID);
  const res=await restore(db);assert.equal(res.code,200);
  assert.equal(db.notes.get(B_ID).title,'safe');
});
test('judge A, student, missing token or another ID cannot restore B',async()=>{
  const db=fakeDb();await createB(db);
  assert.equal((await restore(db,request(B_ID),A)).code,403);
  assert.equal((await restore(db,request(B_ID),{kind:'student',userId:USER})).code,403);
  assert.equal((await restore(db,request(B_ID,{headers:{}}))).code,401);
  assert.equal((await restore(db,request(A_ID))).code,404);
  assert.equal(db.audit.length,0);
});
test('reject bulk, caller-owner, role, hash, query, non-POST and unexpected paths',async()=>{
  const db=fakeDb();await createB(db);
  for(const patch of [{method:'GET'},{body:{ids:[A_ID,B_ID]}},
    {body:{id:B_ID,owner_id:noteOwnerId(A)}},{body:{id:B_ID,role:'admin'}},
    {body:{id:B_ID,contentHash:'x'}},{query:{all:'1'}},
    {url:'/api/restore?all=1'}, {url:'/api/notes'}]){
      const res=await restore(db,request(B_ID,patch));
      assert.ok([400,405].includes(res.code));
  }
  assert.equal(db.audit.length,0);
});
test('bad copy hash or mismatched ID and run never restores',async()=>{
  const db=fakeDb();await createB(db);
  db.backups.get(B_ID).content_sha256='0'.repeat(64);
  const res=await restore(db);assert.equal(res.code,409);
  assert.equal(db.audit.length,0);
  const copy={...db.backups.get(B_ID),content_sha256:contentDigest('original synthetic content')};
  for(const changed of [{...copy,id:A_ID},{...copy,run_id:A_ID},
    {...copy,owner_id:noteOwnerId(A)},{...copy,content:'forged'}]){
    assert.equal(verifyPrivateCopy(changed,{id:B_ID,ownerId:noteOwnerId(B),runId:RUN}),false);
  }
});
test('same record ID belonging to another owner cannot be overwritten',async()=>{
  const db=fakeDb();await createB(db);
  const other={id:B_ID,owner_id:noteOwnerId(A),title:'A',content:'no overwrite'};
  db.notes.set(B_ID,{...other});
  const res=await restore(db);assert.equal(res.code,409);
  assert.deepEqual(db.notes.get(B_ID),other);
});

test('backup changed after first API read but before database restore cannot modify note',async()=>{
  const db=fakeDb();await createB(db);
  const originalRpc=db.rpc.bind(db);
  db.rpc=(name,args)=>{
    if(name==='restore_test_note_from_backup'){
      // Simulates an attacker changing the snapshot between API check and RPC.
      db.backups.get(B_ID).content='corrupt during verification';
    }
    return originalRpc(name,args);
  };
  db.notes.get(B_ID).content='already tampered';
  const res=await restore(db);
  assert.equal(res.code,409);
  assert.equal(db.notes.get(B_ID).content,'already tampered');
  assert.equal(db.audit.length,0);
});
test('backup changed on the API second read prevents all writes and preserves audit',async()=>{
  const db=fakeDb();await createB(db);
  db.notes.get(B_ID).content='already tampered';
  const noteBefore=structuredClone(db.notes.get(B_ID));
  db.audit.push({id:A_ID,kind:'existing_event'});
  const auditBefore=structuredClone(db.audit);
  const originalRpc=db.rpc.bind(db);
  let restoreCalls=0;
  db.rpc=(name,args)=>{
    if(name==='restore_test_note_from_backup')restoreCalls++;
    return originalRpc(name,args);
  };
  const from=db.from.bind(db);
  let backupReads=0;
  db.from=table=>{
    const query=from(table);
    if(table!=='test_note_backups')return query;
    const originalAbort=query.abortSignal;
    query.abortSignal=async function(){
      const answer=await originalAbort.call(this);
      backupReads++;
      if(backupReads===2){
        answer.data={...answer.data,content:'altered in the second read'};
      }
      return answer;
    };
    return query;
  };
  const res=await restore(db);
  assert.equal(backupReads,2);
  assert.equal(res.code,409);
  assert.equal(restoreCalls,0,'no restore transaction after failed backup re-read');
  assert.deepEqual(db.notes.get(B_ID),noteBefore);
  assert.deepEqual(db.audit,auditBefore);
});

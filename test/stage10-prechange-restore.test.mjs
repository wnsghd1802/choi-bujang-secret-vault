import {test} from 'node:test';
import assert from 'node:assert/strict';
import {createRecoveryHandler} from '../src/recovery-api.mjs';
import {noteOwnerId} from '../src/note-owner.mjs';
import {contentDigest} from '../src/recovery-core.mjs';

const runId='22222222-2222-4222-8222-222222222222';
const userId='11111111-1111-4111-8111-111111111111';
const actor={kind:'judge',identity:'b',runId,userId};
const a={...actor,identity:'a'};
const id='44444444-4444-4444-8444-444444444444';
const aId='33333333-3333-4333-8333-333333333333';
const original='direct DB seeded pre-attack B';
const copy={id,owner_id:noteOwnerId(actor),title:'Safe B',content:original,
  content_sha256:contentDigest(original)};
const request={method:'POST',url:'/api/restore',query:{},body:{id},
  headers:{authorization:'Bearer fake.valid.signature'}};
function response(){return {setHeader(){},status(code){this.code=code;return this},
  json(value){this.body=value;return this}};}
function fixture(initialCopy=copy){
  const copies=new Map(initialCopy?[[id,{...initialCopy}]]:[]);
  const notes=new Map([
    [id,{id,owner_id:copy.owner_id,title:'attacked',content:'tampered'}],
    [aId,{id:aId,owner_id:noteOwnerId(a),title:'A',content:'not B'}],
  ]);
  const past={note_id:aId,marker:'historical'};
  const audit=[{...past}];
  let calls=0,reads=0;
  return {notes,audit,copies,get calls(){return calls;},get reads(){return reads;},
    from(table){
      assert.ok(['test_note_backups','test_note_prechange_copies'].includes(table));
      const where=[];
      const q={select(){return q;},eq(k,v){where.push([k,v]);return q;},
        maybeSingle(){return q;},async abortSignal(){
          if(table==='test_note_prechange_copies')reads++;
          const data=table==='test_note_prechange_copies'?copies.get(id):null;
          return {data:data&&where.every(([k,v])=>data[k]===v)?{...data}:null,error:null};
        }};
      return q;
    },
    rpc(name,args){
      calls++;
      assert.equal(name,'restore_test_note_from_prechange');
      assert.equal(args.p_run_id,runId);
      assert.equal(args.p_owner_id,copy.owner_id);
      assert.equal(args.p_hash,copy.content_sha256);
      return {async abortSignal(){
        notes.set(id,{id,owner_id:copy.owner_id,title:copy.title,content:copy.content});
        audit.push({note_id:id,run_id:runId,hash:copy.content_sha256,event_id:2});
        return {data:[{...notes.get(id),audit_event_id:2}],error:null};
      }};
    },
  };
}
test('direct SQL-seeded B: verified prechange snapshot restores precisely B and appends audit',async()=>{
  const db=fixture();const r=response();
  await createRecoveryHandler({db,verifyLogin:async()=>actor})(request,r);
  assert.equal(r.code,200);
  assert.equal(db.reads,2);
  assert.equal(db.calls,1);
  assert.equal(db.notes.get(id).content,original);
  assert.equal(db.notes.get(aId).content,'not B');
  assert.deepEqual(db.audit[0],{note_id:aId,marker:'historical'});
  assert.equal(db.audit.length,2);
  assert.equal(r.body.auditRecorded,true);
});
test('judge A, other owner, missing snapshot, wrong digest never recover',async()=>{
  for(const [who,backup,code] of [
    [a,copy,403],
    [actor,{...copy,owner_id:noteOwnerId(a)},404],
    [actor,null,404],
    [actor,{...copy,content:'forged after modification'},409],
  ]){
    const db=fixture(backup),r=response();
    await createRecoveryHandler({db,verifyLogin:async()=>who})(request,r);
    assert.equal(r.code,code);
    assert.equal(db.calls,0);
    assert.equal(db.audit.length,1);
    assert.equal(db.notes.get(id).content,'tampered');
  }
});
test('second prechange snapshot read mismatch refuses all writes',async()=>{
  const db=fixture(),originalFrom=db.from.bind(db);
  db.from=table=>{
    const q=originalFrom(table);
    if(table==='test_note_prechange_copies'){
      const run=q.abortSignal.bind(q);
      q.abortSignal=async()=>{
        const result=await run();
        if(db.reads===2)result.data={...result.data,content:'changed meanwhile'};
        return result;
      };
    }
    return q;
  };
  const r=response();
  await createRecoveryHandler({db,verifyLogin:async()=>actor})(request,r);
  assert.equal(r.code,409);
  assert.equal(db.calls,0);
  assert.equal(db.audit.length,1);
});

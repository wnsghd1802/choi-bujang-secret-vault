// Isolated reproduction only: no production DB, Vercel, user notes or judge tokens.
// This proves how the real HTTP handler reacts to an injected inconsistent DB adapter.
// It does NOT claim that production PostgreSQL's atomic RPC behaves this way.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createRecoveryHandler } from '../src/recovery-api.mjs';
import { noteOwnerId } from '../src/note-owner.mjs';
import { contentDigest } from '../src/recovery-core.mjs';

const ACTOR = {
  kind: 'judge', identity: 'b',
  userId: '11111111-1111-4111-8111-111111111111',
  runId: '22222222-2222-4222-8222-222222222222',
};
const ID = '44444444-4444-4444-8444-444444444444';
const OTHER = '33333333-3333-4333-8333-333333333333';
const SAFE_CONTENT = 'safe synthetic memo before intrusion';

function fixture(mode) {
  const ownerId = noteOwnerId(ACTOR);
  const copy = {
    id: ID, owner_id: ownerId, run_id: ACTOR.runId,
    identity: 'b', title: 'safe B', content: SAFE_CONTENT,
    content_sha256: contentDigest(SAFE_CONTENT),
  };
  const notes = new Map([
    [ID, {id: ID, owner_id: ownerId, title: 'tampered B', content: 'attacker changed it'}],
    [OTHER, {id:OTHER,owner_id:'99999999-9999-4999-8999-999999999999',
      title:'unrelated A',content:'must never change'}],
  ]);
  const historical = {
    event_id: 1, note_id: OTHER,
    owner_id: '99999999-9999-4999-8999-999999999999',
    run_id:ACTOR.runId, restored_sha256:'previous-audit-marker',
    restored_at:'2026-10-12T09:00:00Z',
  };
  const audit = [{...historical}];
  const db = {
    from(table) {
      assert.ok(['test_note_backups','test_recovery_audit'].includes(table));
      const conditions=[];
      const query={
        select() { return query; },
        eq(k,v) { conditions.push([k,v]); return query; },
        maybeSingle(){ return query; },
        async abortSignal(){
          if(table==='test_recovery_audit'){
            return {data:audit.map(row=>({...row})),error:null};
          }
          const matches=conditions.every(([k,v])=>copy[k]===v);
          return {data:matches?{...copy}:null,error:null};
        },
      };
      return query;
    },
    rpc(name,p) {
      assert.equal(name,'restore_test_note_from_backup');
      return {async abortSignal(){
        assert.equal(p.p_id,ID);
        assert.equal(p.p_owner_id,ownerId);
        assert.equal(p.p_hash,copy.content_sha256);
        const restored={
          id:copy.id, owner_id:copy.owner_id,
          title:copy.title,content:copy.content,
        };
        notes.set(ID,restored);
        const receipt = {
          event_id:2, note_id:ID,owner_id:ownerId,run_id:ACTOR.runId,
          restored_sha256:copy.content_sha256,restored_at:'2026-10-13T12:01:00Z',
        };
        if(mode==='honest') audit.push({...receipt});
        if(mode==='drop_history') {
          audit.splice(0,audit.length);
          audit.push({...receipt});
        }
        // For 'missing_new_audit' the adapter claims a successful restore
        // but silently omits the required append, as an independent fixture may.
        return {data:[{...restored}],error:null};
      }};
    },
  };
  const res={
    headers:{},
    setHeader(k,v){this.headers[k]=v;},
    status(code){this.code=code;return this;},
    json(value){this.body=value;return this;},
  };
  const req={
    method:'POST',url:'/api/restore',query:{},
    body:{id:ID},headers:{authorization:'Bearer synthetic.header.signature'},
  };
  return {db,res,req,notes,audit,historical};
}

async function execute(mode) {
  const f=fixture(mode);
  const handler=createRecoveryHandler({db:f.db,verifyLogin:async()=>ACTOR});
  await handler(f.req,f.res);
  return f;
}
test('control: honest injected DB restores B and retains old audit plus new receipt',async()=>{
  const r=await execute('honest');
  assert.equal(r.res.code,200);
  assert.equal(r.audit.length,2);
  assert.equal(r.audit[0].restored_sha256,r.historical.restored_sha256);
  assert.equal(r.notes.get(OTHER).content,'must never change');
});

test('PATCH: missing new audit returns 409 instead of false HTTP 200',async()=>{
  const r=await execute('missing_new_audit');
  assert.equal(r.res.code,409);
  assert.equal(r.res.body.restored,undefined);
  assert.equal(r.audit.length,1);
  assert.equal(r.audit[0].restored_sha256,r.historical.restored_sha256);
  console.log('PATCH: HTTP 409 detects missing new receipt, but the already restored B is not rolled back');
});

test('PATCH: destroyed historical audit returns 409 instead of false HTTP 200',async()=>{
  const r=await execute('drop_history');
  assert.equal(r.res.code,409);
  assert.equal(r.audit.length,1);
  assert.notEqual(r.audit[0].restored_sha256,r.historical.restored_sha256);
  assert.equal(r.notes.get(OTHER).content,'must never change');
  console.log('PATCH: HTTP 409 detects deleted historical receipt, but DB mutation already occurred');
});

test('LIMITATION: post-commit audit checks cannot undo the restored B after HTTP 409',async()=>{
  for(const mode of ['missing_new_audit','drop_history']){
    const r=await execute(mode);
    assert.equal(r.res.code,409);
    assert.equal(r.notes.get(ID).content,SAFE_CONTENT,
      'B was already changed by RPC before the audit check rejected the response');
  }
});

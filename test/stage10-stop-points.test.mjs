// Diagnostic-only execution of the REAL recovery HTTP handler.
// No judge secrets, outbound requests, production DB, or deployment changes.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createRecoveryHandler } from '../src/recovery-api.mjs';
import { noteOwnerId } from '../src/note-owner.mjs';
import { contentDigest } from '../src/recovery-core.mjs';

const ID = '44444444-4444-4444-8444-444444444444';
const A_ID = '33333333-3333-4333-8333-333333333333';
const ACTOR = Object.freeze({
  kind:'judge', identity:'b',
  userId:'11111111-1111-4111-8111-111111111111',
  runId:'22222222-2222-4222-8222-222222222222',
});
const OWNER = noteOwnerId(ACTOR);
const TEXT = 'verified original synthetic B before breach';
const A_ORIGINAL = {id:A_ID,owner_id:'88888888-8888-4888-8888-888888888888',
  title:'Safe A',content:'A must not change'};
const DEFAULT_COPY = {
 id:ID,owner_id:OWNER,run_id:ACTOR.runId,identity:'b',
 title:'Original B',content:TEXT,content_sha256:contentDigest(TEXT),
};

function fixture(kind) {
  const audit=[{note_id:A_ID,restored_sha256:'older-audit'}];
  const notes=new Map([
    [ID,{id:ID,owner_id:OWNER,title:'Hacked B',content:'attacker update'}],
    [A_ID,{...A_ORIGINAL}],
  ]);
  let reads=0, rpcCalls=0;
  let copy={...DEFAULT_COPY};
  if(kind==='no_backup')copy=null;
  if(kind==='wrong_owner')copy={...copy,owner_id:'99999999-9999-4999-8999-999999999999'};
  if(kind==='wrong_run')copy={...copy,run_id:'77777777-7777-4777-8777-777777777777'};
  if(kind==='invalid_digest')copy={...copy,content_sha256:'0'.repeat(64)};
  if(kind==='preseeded_sub') {
    copy={...copy,owner_id:ACTOR.userId};
    notes.set(ID,{id:ID,owner_id:ACTOR.userId,title:'Hacked B',content:'attacker update'});
  }
  const db={
    from(table){
      assert.equal(table,'test_note_backups');
      const eqs=[];
      const q={
        select(){return q},
        eq(k,v){eqs.push([k,v]);return q},
        maybeSingle(){return q},
        async abortSignal(){
          reads++;
          let out=copy && eqs.every(([k,v])=>copy[k]===v)?{...copy}:null;
          if(kind==='changed_second_read'&&reads===2&&out)out.content='attacker changes copy between reads';
          return {data:out,error:null};
        },
      };
      return q;
    },
    rpc(name,p){
      assert.equal(name,'restore_test_note_from_backup');
      return {async abortSignal(){
        rpcCalls++;
        if(kind==='rpc_error')return {data:null,error:{message:'synthetic DB error'}};
        const existing=notes.get(ID);
        if(!copy||copy.id!==p.p_id||copy.owner_id!==p.p_owner_id
          ||copy.run_id!==p.p_run_id||copy.content_sha256!==p.p_hash
          ||contentDigest(copy.content)!==copy.content_sha256
          ||existing && existing.owner_id!==copy.owner_id)
          return {data:null,error:{message:'synthetic ownership / copy mismatch'}};
        const row={id:copy.id,owner_id:copy.owner_id,title:copy.title,content:copy.content};
        notes.set(ID,{...row});
        if(kind!=='dishonest_rpc_without_audit')
          audit.push({note_id:ID,restored_sha256:copy.content_sha256});
        return {data:[row],error:null};
      }};
    },
  };
  return {db,notes,audit,get reads(){return reads},get rpcCalls(){return rpcCalls}};
}

const scenarios=[
  {key:'anonymous',expect:401,phase:'authorization',hasBackup:true},
  {key:'invalid_identity',expect:401,phase:'verify_identity',hasBackup:true},
  {key:'judge_a',expect:403,phase:'judge_b_scope',hasBackup:true},
  {key:'bad_route',expect:400,phase:'route',hasBackup:true},
  {key:'no_backup',expect:404,phase:'verified_sub_backup'},
  {key:'wrong_owner',expect:404,phase:'verified_sub_backup'},
  {key:'wrong_run',expect:404,phase:'verified_sub_backup'},
  {key:'invalid_digest',expect:409,phase:'backup_integrity'},
  {key:'changed_second_read',expect:409,phase:'backup_reread'},
  {key:'rpc_error',expect:409,phase:'restore_rpc'},
  {key:'success',expect:200,phase:'completed',auditAdded:1},
  {key:'preseeded_sub',expect:200,phase:'completed',auditAdded:1},
  {key:'dishonest_rpc_without_audit',expect:200,phase:'completed',auditAdded:0},
];

test('identify exact stage of each synthetic recovery failure using S10_TRACE',async()=>{
  for(const s of scenarios){
    const f=fixture(s.key);
    const logs=[];
    const originalInfo=console.info;
    console.info=(...args)=>logs.push(args.join(' '));
    let status;
    try{
      const actor=s.key==='invalid_identity'?null
        :s.key==='judge_a'?{...ACTOR,identity:'a'}:ACTOR;
      const handler=createRecoveryHandler({db:f.db,verifyLogin:async()=>actor});
      const req={method:'POST',url:s.key==='bad_route'?'/api/restore?all=1':'/api/restore',
        query:{},body:{id:ID},
        headers:s.key==='anonymous'?{}:{authorization:'Bearer synthetic.header.signature'}};
      const res={setHeader(){},status(code){status=code;return this},
        json(body){this.body=body;return this}};
      await handler(req,res);
    }finally{console.info=originalInfo}
    assert.equal(status,s.expect,s.key+' status');
    const trace=logs.find(x=>x.includes('outcome='+(status===200?'success':'reject')));
    assert.ok(trace,s.key+' missing terminal trace');
    assert.ok(trace.includes('phase='+s.phase+' '),s.key+' unexpected phase '+trace);
    const expectedAudit=1+(s.auditAdded??0);
    assert.equal(f.audit.length,expectedAudit,s.key+' changed audit unexpectedly');
    assert.deepEqual(f.notes.get(A_ID),A_ORIGINAL,s.key+' changed A');
    if(status!==200)assert.equal(f.notes.get(ID).content,'attacker update',s.key+' changed B despite failure');
    if(status===200)assert.equal(f.notes.get(ID).content,TEXT,s.key+' did not restore B');
    console.log('LOCAL_PHASE case='+s.key+' status='+status+' phase='+s.phase+
      ' backupReads='+f.reads+' restoreRpcs='+f.rpcCalls+
      ' addedAudit='+(f.audit.length-1));
  }
});

test('only the DB transaction can guarantee audit and restore atomicity',()=>{
  const s=scenarios.find(x=>x.key==='dishonest_rpc_without_audit');
  assert.equal(s.expect,200);
  assert.equal(s.auditAdded,0);
  // A fake RPC claiming success without an audit still fools the HTTP handler.
  // Our actual PostgreSQL function (013) is expected to prevent this.
});

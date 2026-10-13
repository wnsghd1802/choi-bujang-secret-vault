import { test } from 'node:test';
import assert from 'node:assert/strict';
import { decide, RULE_IDS } from '../src/decider.mjs';
import { fixtureRequests } from '../scripts/fixture-7.mjs';
import config from '../aleph.config.json' with { type: 'json' };
import { createRecoveryHandler } from '../src/recovery-api.mjs';
import { noteOwnerId } from '../src/note-owner.mjs';
import { contentDigest } from '../src/recovery-core.mjs';

const {normal,suspicious}=fixtureRequests();
function recoveryRequest(extra={}){
 return {...normal, service:'notes',route:'POST /api/restore',
   path:'/api/restore',method:'POST',queryLength:0,...extra};
}
test('stage10 route declared to the engine must reach the strictly authenticated restore API',async()=>{
 assert.ok(config.allowedRoutes.includes('POST /api/restore'));
 assert.equal(config.restoreRoute,'POST /api/restore');
 const answer=await decide(recoveryRequest());
 assert.equal(answer.decision,'allow',
   'currently registered stage10 restore route is denied at the gateway before handler/audit runs');
 assert.ok(answer.ruleIds.every(x=>RULE_IDS.includes(x)));
});

test('new restore route must never unlock any other write/read routes',async()=>{
 for(const [path,method,route] of [
   ['/api/notes','POST','POST /api/notes'],
   ['/api/restore','GET','GET /api/restore'],
   ['/api/restore/all','POST','POST /api/restore'],
   ['/api/restore','DELETE','DELETE /api/restore'],
   ['/api/notices/id','PUT','PUT /api/notices/:id'],
 ]){
    const ans=await decide(recoveryRequest({path,method,route}));
    assert.equal(ans.decision,'deny',path+' '+method);
 }
 const noisy=await decide(recoveryRequest({queryLength:12}));
 assert.equal(noisy.decision,'deny');
 const unregistered=await decide(recoveryRequest({deviceRegistered:false}));
 assert.equal(unregistered.decision,'deny');
});

test('dangerous fixture still requests step-up for restore, then permits verified device',async()=>{
 const input=recoveryRequest({...suspicious, service:'notes',route:'POST /api/restore',
     path:'/api/restore',method:'POST',queryLength:0,deviceRegistered:true});
 const first=await decide(input);
 assert.equal(first.decision,'step_up');
 const second=await decide({...input,stepUp:{verified:true,authAgeSeconds:60}});
 assert.equal(second.decision,'allow');
});

test('gateway-to-restore completes precisely one B restoration, preserving A, B2, old audit',async()=>{
 const run='22222222-2222-4222-8222-222222222222',user='11111111-1111-4111-8111-111111111111';
 const b={kind:'judge',identity:'b',runId:run,userId:user};
 const a={...b,identity:'a'};
 const ownerB=noteOwnerId(b);
 const id='44444444-4444-4444-8444-444444444444';
 const aId='33333333-3333-4333-8333-333333333333';
 const bOther='55555555-5555-4555-8555-555555555555';
 const original='trusted B copy before compromise';
 const safe={id,owner_id:ownerB,run_id:run,identity:'b',title:'Safe B',
   content:original,content_sha256:contentDigest(original)};
 const notes=new Map([
  [id,{id,owner_id:ownerB,title:'Compromised B',content:'changed by attacker'}],
  [aId,{id:aId,owner_id:noteOwnerId(a),title:'A',content:'keep A'}],
  [bOther,{id:bOther,owner_id:ownerB,title:'Another B',content:'keep other B'}],
 ]);
 const beforeA=structuredClone(notes.get(aId)),beforeB2=structuredClone(notes.get(bOther));
 const past={note_id:aId,marker:'prior-audit'};
 const audit=[{...past}];
 const db={
  from(table){
   assert.equal(table,'test_note_backups');const cond=[];
   const q={select(){return q},eq(k,v){cond.push([k,v]);return q},
     maybeSingle(){return q},async abortSignal(){
      return {data:cond.every(([k,v])=>safe[k]===v)?{...safe}:null,error:null};
     }};
   return q;
  },
  rpc(name,params){assert.equal(name,'restore_test_note_from_backup');
   return {async abortSignal(){
    if(params.p_id!==id||params.p_owner_id!==ownerB||params.p_run_id!==run||
       params.p_hash!==safe.content_sha256) return {data:null,error:{code:'wrong_target'}};
    const restored={id,owner_id:ownerB,title:safe.title,content:safe.content};
    notes.set(id,restored);
    audit.push({note_id:id,owner_id:ownerB,run_id:run,restored_sha256:safe.content_sha256});
    return {data:[{...restored}],error:null};
   }};
  }
 };
 const policy=await decide(recoveryRequest());
 assert.equal(policy.decision,'allow');
 const handler=createRecoveryHandler({
  db,verifyLogin:async token=>token==='Bearer permitted.b.token'?b:
    token==='Bearer permitted.a.token'?a:null,
 });
 const request=auth=>({method:'POST',url:'/api/restore',query:{},body:{id},
   headers:{authorization:auth}});
 const reply=()=>({setHeader(){},status(code){this.statusCode=code;return this},
    json(data){this.payload=data;return this}});
 const forbidden=reply();
 await handler(request('Bearer permitted.a.token'),forbidden);
 assert.equal(forbidden.statusCode,403);
 assert.equal(audit.length,1);
 const ok=reply();
 await handler(request('Bearer permitted.b.token'),ok);
 assert.equal(ok.statusCode,200);
 assert.equal(ok.payload.verified,true);
 assert.equal(notes.get(id).content,original);
 assert.deepEqual(notes.get(aId),beforeA);
 assert.deepEqual(notes.get(bOther),beforeB2);
 assert.deepEqual(audit[0],past);
 assert.equal(audit.length,2);
 assert.equal(audit[1].restored_sha256,safe.content_sha256);
});

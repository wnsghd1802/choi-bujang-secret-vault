import assert from 'node:assert/strict';
import { test } from 'node:test';
import { decide, RULE_IDS } from '../src/decider.mjs';
import { resourceIdFor, requestHasOnlyResourceId } from '../src/resource-zones.mjs';
import { createNoticeHandler } from '../src/notices-api.mjs';
import { createNotesHandler } from '../src/notes-api.mjs';

const A = '11111111-1111-4111-8111-111111111111';
const B = '22222222-2222-4222-8222-222222222222';
const ID = '33333333-3333-4333-8333-333333333333';
const fixture = () => ({
  schema:'aleph.decision.v1', requestId:'test-8', deviceRegistered:true,
  classId:'class_fixture',projectId:'project_fixture',subjectId:'learner_fixture',deviceId:'aaaaaaaaaaaaaaaa',
  service:'notes', method:'GET', path:'/notes/demo', route:'GET /notes/:id', queryLength:0,
  signals:{source:'judge_fixture', region:'local', network:'usual', hour:14},
  recentEvents:[],stepUp:{verified:false,authAgeSeconds:null},
});
async function outcome(edit, expected) {
  const input={...fixture(),...edit};
  const output=await decide(input);
  assert.equal(output.decision,expected);
  assert.equal(output.schema,'aleph.decision.v1');
  assert.equal(output.requestId,input.requestId);
  assert.equal(Object.keys(output).length,5);
  assert.ok(output.ruleIds.every(rule=>RULE_IDS.includes(rule)));
}
const res=()=>({headers:{},setHeader(k,v){this.headers[k]=v},status(code){this.code=code;return this},json(value){this.body=value;return this}});
const req=(method='PUT',query={id:ID},body={title:'notice',body:'text'})=>({
  method,query,body,url:'/api/notices/'+ID,
  headers:{authorization:'Bearer x.y.z'},
});
test('zones have distinct server resource namespaces with preserved UUIDs',()=>{
  assert.equal(resourceIdFor('memo',ID),'memo:'+ID);
  assert.equal(resourceIdFor('instructor_notice',ID),'instructor_notice:'+ID);
  assert.notEqual(resourceIdFor('memo',ID),resourceIdFor('instructor_notice',ID));
  assert.equal(resourceIdFor('role=teacher',ID),null);
});
test('valid existing notes fixture stays allowed',async()=>outcome({},'allow'));
test('unregistered device always rejected first',async()=>outcome({deviceRegistered:false},'deny'));
test('strict route blocks id2, nested export and unknown routes',async()=>{
  for (const edit of [
    {route:'GET /notes/:id2'}, {path:'/notes/demo/export'},
    {path:'/notes/demo/../other'}, {route:'GET /unknown/:id',path:'/unknown/demo'},
    {route:'PUT /announcements/:id',path:'/announcements/demo',method:'PUT',service:'announcements'},
    {route:'GET /notes/:id',method:'POST'},
    {route:'GET /notes/:id',path:'/api/notes/demo'},
    {queryLength:1},
  ]) await outcome(edit,'deny');
});
test('individual notes delegate verified ownership to API, collection denies',async()=>{
  await outcome({route:'PUT /api/notes/:id',method:'PUT',path:'/api/notes/'+ID},'allow');
  await outcome({route:'GET /api/notes/:id',method:'GET',path:'/api/notes/'+ID},'allow');
  await outcome({route:'GET /api/notes',path:'/api/notes'},'deny');
  await outcome({route:'POST /api/notes',method:'POST',path:'/api/notes'},'deny');
  await outcome({route:'DELETE /api/notes/:id',method:'DELETE',path:'/api/notes/'+ID},'deny');
});
test('7th stage composite anomaly retains step-up requirement',async()=>{
  const risky={signals:{source:'judge_fixture',region:'foreign',network:'unusual',hour:3},
    recentEvents:[{kind:'risk_signal',ageSeconds:60,count:20}]};
  await outcome(risky,'step_up');
  await outcome({...risky,stepUp:{verified:true,authAgeSeconds:60}},'allow');
});
test('resource URL and query selector checks fail closed',()=>{
  assert.equal(requestHasOnlyResourceId({query:{id:ID},url:'/api/notes/'+ID},ID,'/api/notes'),true);
  assert.equal(requestHasOnlyResourceId({query:{id:ID,id2:B},url:'/api/notes/'+ID},ID,'/api/notes'),false);
  assert.equal(requestHasOnlyResourceId({query:{id:ID},url:'/api/notes/'+ID+'?export=1'},ID,'/api/notes'),false);
  assert.equal(requestHasOnlyResourceId({query:{id:ID},url:'/api/notes/'+ID+'/export'},ID,'/api/notes'),false);
});
test('notices API denies untrusted role if no stored instructor grant',async()=>{
  let writes=0;
  const db={from(table){assert.equal(table,'instructor_grants');const q={select(){return q},eq(){return q},maybeSingle(){return q},
    async abortSignal(){return {data:null,error:null}}};return q;}};
  const handler=createNoticeHandler({db,verifyLogin:async()=>({kind:'student',userId:A})});
  const response=res();
  await handler({...req(),body:{title:'x',body:'y',role:'teacher'}},response);
  assert.equal(response.code,403);assert.equal(writes,0);
});
test('notices API only writes with a verified identity plus trusted DB grant',async()=>{
  let writes=0;
  const db={from(table){
    const q={select(){return q},eq(){return q},update(){writes++;return q},maybeSingle(){return q},
      async abortSignal(){return table==='instructor_grants'
        ?{data:{user_id:A},error:null}
        :{data:{id:ID,title:'notice',content:'text'},error:null}}};
    return q;
  }};
  const handler=createNoticeHandler({db,verifyLogin:async()=>({kind:'student',userId:A})});
  const response=res();await handler(req(),response);
  assert.equal(response.code,200);assert.equal(writes,1);
  const denied=res();await handler({...req(),query:{id:ID,id2:B}},denied);
  assert.equal(denied.code,400);assert.equal(writes,1);
});
test('notes API still blocks route-selector injection without querying DB',async()=>{
  let reads=0;
  const db={from(){reads++;throw Error('should not access')}};
  const handler=createNotesHandler({item:true,db,verifyLogin:async()=>({kind:'student',userId:A})});
  const response=res();await handler({
    method:'GET',headers:{authorization:'Bearer x.y.z'},query:{id:ID,id2:B},
    url:'/api/notes/'+ID,
  },response);
  assert.equal(response.code,400);assert.equal(reads,0);
});

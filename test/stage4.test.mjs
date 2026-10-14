import assert from 'node:assert/strict';
import { test } from 'node:test';
import { readFile } from 'node:fs/promises';
import { decide, RULE_IDS } from '../src/decider.mjs';
import { detect } from '../src/detect.mjs';
import { fixtureRequests } from '../scripts/fixture-7.mjs';
import config from '../aleph.config.json' with { type: 'json' };

const expectedFields=['decision','reasonCode','requestId','ruleIds','schema'];
const {normal,suspicious}=fixtureRequests();
async function expectDecision(request,decision,reasonCode) {
  const output=await decide(request);
  assert.equal(output.schema,'aleph.decision.v1');
  assert.equal(output.requestId,request.requestId);
  assert.deepEqual(Object.keys(output).sort(),expectedFields);
  assert.equal(output.decision,decision);
  assert.equal(output.reasonCode,reasonCode);
  assert.ok(output.ruleIds.length > 0);
  assert.ok(output.ruleIds.every(id=>RULE_IDS.includes(id)));
}

test('stages 1-2: legacy public data stores expose no notes',async()=>{
  for(const location of ['../data.json','../public/data.json']){
    const data=JSON.parse(await readFile(new URL(location,import.meta.url),'utf8'));
    assert.deepEqual(data.notes,[],'no public notes: '+location);
  }
});

test('stages 3-5: deployed identity and route contracts are not overwritten',()=>{
  assert.equal(config.step,11);
  assert.equal(config.publicAppUrl,'https://choi-bujang-secret-vault-pied.vercel.app');
  assert.equal(config.originalApiUrl,'https://fgluruiqasiexuqjvzhq.supabase.co/rest/v1/notes');
  assert.equal(config.identityProvider.issuer,'https://fgluruiqasiexuqjvzhq.supabase.co/auth/v1');
  assert.equal(config.judgeIssuer,'https://aleph-judge-production.up.railway.app/defense/judge');
  assert.deepEqual(config.allowedRoutes,[
    'GET /api/notes','POST /api/notes','GET /api/notes/:id',
    'PUT /api/notes/:id','DELETE /api/notes/:id',
    'PUT /api/notices/:id','POST /api/restore',
    'GET /api/device','POST /api/device',
  ]);
});

test('stage 6: registered normal request stays allowed, unregistered is denied',async()=>{
  await expectDecision(normal,'allow','approved');
  await expectDecision({...normal,deviceRegistered:false},'deny','device_not_registered');
});

test('stage 7: anomaly needs step-up and verified recent step-up restores access',async()=>{
  await expectDecision(suspicious,'step_up','step_up_required');
  await expectDecision({...suspicious,stepUp:{verified:true,authAgeSeconds:45}},'allow','approved');
  await expectDecision({...suspicious,stepUp:{verified:true,authAgeSeconds:901}},'step_up','step_up_required');
});

test('stage 8: cross-zone, collection and export requests stay denied',async()=>{
  for(const patch of [
    {method:'GET',route:'GET /api/notes',path:'/api/notes'},
    {method:'POST',route:'POST /api/notes',path:'/api/notes'},
    {method:'PUT',route:'PUT /api/notices/:id',path:'/api/notices/demo'},
    {method:'GET',route:'GET /api/notes/:id',path:'/api/notes/demo/export'},
    {method:'GET',route:'GET /api/notes/:id',path:'/api/notes/demo',queryLength:1},
  ]) {
    await expectDecision({...normal,...patch},'deny','starter_not_ready');
  }
});

test('stage 9: 120 normal reads observed, 121 rapid reads propose only, no direct revocation',()=>{
  const events=count=>Array.from({length:count},(_,i)=>({
    method:'GET',at:new Date(Date.UTC(2026,9,1)+i*1000).toISOString(),
    identity:{sub:'student_fixture'},
  }));
  assert.deepEqual(detect(events(120)),{action:'observe'});
  assert.deepEqual(detect(events(121)),{
    action:'propose_revocation',reasonCode:'burst_read',subject:'student_fixture',
  });
  assert.deepEqual(detect(events(121).map(e=>({...e,method:'POST'}))),{action:'observe'});
});

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { decide, RULE_IDS } from '../src/decider.mjs';
import { fixtureRequests } from '../scripts/fixture-7.mjs';
import config from '../aleph.config.json' with { type: 'json' };

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

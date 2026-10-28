import test from 'node:test';
import assert from 'node:assert/strict';
import {createWindowsObservationReader,normalizeWindowsObservation} from '../src/windows-observation.mjs';
const time='2026-10-28T01:00:00.000Z';
const valid={
  schema:'kimjh.windows-observation.v1',source:'windows-read-only',windowHours:24,
  network:{status:'ok',adapters:[{name:'Ethernet',ipv4:'192.168.10.3',gateway:'192.168.10.1'}],observedAt:time},
  firewall:{status:'ok',profiles:[{name:'Private',enabled:true,inbound:'Block',outbound:'Allow'}],observedAt:time},
  system:{status:'ok',error:2,warning:7,limited:false,observedAt:time},
  application:{status:'ok',error:0,warning:0,limited:false,observedAt:time},
};
test('valid read-only data preserved with independent source',()=>{
 const result=normalizeWindowsObservation(valid,time);
 assert.equal(result.network.adapters[0].ipv4,'192.168.10.3');
 assert.equal(result.firewall.profiles[0].enabled,true);
 assert.equal(result.system.warning,7);
 assert.equal(result.application.error,0);
});
test('bad network does not erase valid firewall or event totals',()=>{
 const result=normalizeWindowsObservation({...valid,network:{status:'unavailable',reason:'NETWORK_QUERY_UNAVAILABLE',observedAt:time}},time);
 assert.equal(result.network.status,'unavailable');
 assert.equal(result.firewall.status,'ok');
 assert.equal(result.system.error,2);
});
test('permission denied and unknown errors become unavailable, never zero',()=>{
 const result=normalizeWindowsObservation({...valid,system:{status:'unavailable',reason:'EVENT_LOG_UNAVAILABLE',observedAt:time},application:{status:'unavailable',reason:'SENSITIVE_TRACE',observedAt:time}},time);
 assert.equal(result.system.status,'unavailable');
 assert.equal(result.application.reason,'READ_RESULT_UNVERIFIED');
 assert.equal(result.system.error,undefined);
});
test('malformed counts and firewall profiles do not become success',()=>{
 const r=normalizeWindowsObservation({...valid,system:{status:'ok',error:-1,warning:0,limited:false,observedAt:time},
 firewall:{status:'ok',profiles:[{name:'Public',enabled:true,inbound:'Allow',outbound:'Mutate'}],observedAt:time}},time);
 assert.equal(r.system.status,'unavailable');
 assert.equal(r.firewall.status,'unavailable');
});
test('capped results remain bounded and flagged',()=>{
 const result=normalizeWindowsObservation({...valid,system:{status:'ok',error:1200,warning:3800,limited:true,observedAt:time}},time);
 assert.equal(result.system.limited,true);
});
test('unsupported OS returns explicit unavailable without running script',async()=>{
 const read=createWindowsObservationReader({platform:'linux',run:()=>{throw Error('should not run');},now:()=>time});
 const result=await read();
 assert.equal(result.network.reason,'WINDOWS_ONLY');
 assert.equal(result.system.status,'unavailable');
});
test('PowerShell failures do not leak raw errors',async()=>{
 const read=createWindowsObservationReader({platform:'win32',run:()=>{throw Error('SECRET C:/Users/hidden');},now:()=>time});
 const result=await read();
 assert.equal(result.network.reason,'POWERSHELL_UNAVAILABLE');
 assert.equal(JSON.stringify(result).includes('hidden'),false);
});
test('mock PowerShell JSON produces normalized results',async()=>{
 const read=createWindowsObservationReader({platform:'win32',run:async()=>({stdout:JSON.stringify(valid)}),now:()=>time});
 const result=await read();
 assert.equal(result.system.warning,7);
});

test('malformed IP and missing observedAt affect only their own fields',()=>{
 const result=normalizeWindowsObservation({...valid,
 network:{status:'ok',adapters:[{name:'Ethernet',ipv4:null,gateway:''}],observedAt:time},
 firewall:{status:'ok',profiles:[{name:'Private',enabled:true,inbound:'Block',outbound:'Allow'}]}},time);
 assert.equal(result.network.status,'unavailable');
 assert.equal(result.firewall.status,'unavailable');
 assert.equal(result.system.status,'ok');
});

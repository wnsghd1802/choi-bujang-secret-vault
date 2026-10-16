import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile,mkdtemp,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {resolve,dirname,join} from 'node:path';
import {fileURLToPath} from 'node:url';
import {decide} from '../xdr/exfiltration/decide.mjs';
import {readAlerts,loadFixture} from '../xdr/exfiltration/read-alerts.mjs';
import {createDenyStore,appendAlert,withXdrGuard} from '../xdr/exfiltration/respond.mjs';
import {runXdr} from '../scripts/xdr-run.mjs';
const root=resolve(dirname(fileURLToPath(import.meta.url)),'..'),fixture=await loadFixture();

test('exactly one five-field redacted output for every Wazuh event',async()=>{
 const rows=await readAlerts();
 assert.equal(rows.length,fixture.alerts.length);
 for(const row of rows)assert.deepEqual(Object.keys(row).sort(),
   ['account','description','ruleLevel','sourceAddress','timestamp']);
 const probe=await readAlerts({schema:'aleph.xdr.fixture.v1',moduleKey:'exfiltration',alerts:[{
   timestamp:fixture.alerts[0].timestamp,
   data:{srcip:'192.0.2.20',srcuser:'password=supersecret'},
   rule:{level:12,description:'Authorization: Bearer sensitivebearer'}}]});
 assert.ok(!JSON.stringify(probe).includes('supersecret'));
 assert.ok(!JSON.stringify(probe).includes('sensitivebearer'));
});
test('ATT&CK evidence for each pattern and standalone no-import decider',async()=>{
 const cfg=JSON.parse(await readFile(join(root,'xdr/exfiltration/patterns.json'),'utf8'));
 assert.deepEqual(cfg.mitre,['T1041','T1048']);
 assert.equal(cfg.patterns.length,6);
 for(const x of cfg.patterns)assert.ok(x.name&&x.condition&&x.evidence&&!/[\r\n]/u.test(x.evidence));
 const body=await readFile(join(root,'xdr/exfiltration/decide.mjs'),'utf8');
 assert.ok(!/^\s*import\s/gmu.test(body));
 assert.ok(!/readFile|writeFile|fetch\s*\(|node:|require\s*\(/u.test(body));
});
test('30 decisions: 10 clear blocks, 10 ambiguous alerts, 10 normal records',()=>{
 assert.equal(fixture.alerts.length,30);
 for(let i=0;i<fixture.alerts.length;i++){
   const v=decide(fixture.alerts[i]),expected=i<10?'block':i<20?'alert':'record';
   assert.equal(v.action,expected,fixture.alerts[i].id);
   assert.equal(v.action,v.confidence>=.85?'block':v.confidence>=.5?'alert':'record');
   assert.ok(v.reason&&!/[\r\n]/u.test(v.reason));
 }
 assert.equal(decide({rule:{level:15,mitre:['T1048'],
   description:'수업 자료 주소로 작은 동기화가 끝났습니다.'},
   data:{dstip:'198.51.100.10',bytes:'50000'}}).action,'record');
 assert.equal(decide({rule:{level:15,mitre:['T1048'],
   description:'압축 파일이 처음 보는 주소로 나갔습니다.'},data:{bytes:'90000000'}}).action,'alert');
 assert.equal(decide({rule:{level:15,description:'파일 전송은 없습니다.'},
   data:{dstip:'203.0.113.81',bytes:'90000000'}}).action,'record');
 assert.equal(decide({rule:{level:15,description:'전송이 실패 1건으로 끝났습니다. 목적지는 처음 봅니다.'},
   data:{dstip:'203.0.113.81',bytes:'0'}}).action,'alert');
});
test('deny rules need verified destination; same-IP normal request must pass',async()=>{
 const alert=fixture.alerts[0],now=Date.parse(alert.timestamp)+1000,store=createDenyStore();
 assert.equal(store.add(fixture.alerts[20],decide(fixture.alerts[20]),'192.0.2.10',now),null);
 assert.equal(store.add(fixture.alerts[10],decide(fixture.alerts[10]),'192.0.2.80',now),null);
 assert.equal(store.add(alert,decide(alert),'203.0.113.51',now),null);
 const rule=store.add(alert,decide(alert),alert.data.dstip,now);
 assert.equal(rule.ruleId,'xdr.exfiltration');
 assert.deepEqual(rule.evidenceAlertIds,['ex-01']);
 assert.ok(Date.parse(rule.expiresAt)>now);
 const original=async request=>({schema:'aleph.decision.v1',requestId:request.requestId,
    decision:'allow',reasonCode:'approved',ruleIds:['resource_zone']});
 const guard=withXdrGuard(original,{
   store,resolveVerifiedDestination:async r=>r.serverVerifiedDestination,
   currentTransferIsSuspicious:async r=>r.serverConfirmedExfil===true,
   denyResponse:async(r,rule)=>({schema:'aleph.decision.v1',requestId:r.requestId,
      decision:'deny',reasonCode:'starter_not_ready',ruleIds:[rule.ruleId]}),
   now:()=>now
 });
 assert.equal((await guard({requestId:'normal',serverVerifiedDestination:alert.data.dstip,
   serverConfirmedExfil:false})).decision,'allow');
 assert.equal((await guard({requestId:'other',serverVerifiedDestination:'192.0.2.10',
   serverConfirmedExfil:true})).decision,'allow');
 assert.equal((await guard({requestId:'attack',serverVerifiedDestination:alert.data.dstip,
   serverConfirmedExfil:true})).decision,'deny');
 assert.equal(store.check(alert.data.dstip,now+900001),null);
});
test('safe per-line alerts; repeated runner writes identical committed result',async()=>{
 const folder=await mkdtemp(join(tmpdir(),'exfiltration-xdr-'));
 try{
   const file=join(folder,'alerts.log');
   await appendAlert(fixture.alerts[0],decide(fixture.alerts[0]),file);
   await appendAlert(fixture.alerts[10],decide(fixture.alerts[10]),file);
   assert.equal(await appendAlert(fixture.alerts[20],decide(fixture.alerts[20]),file),false);
   const logged=await readFile(file,'utf8');
   assert.equal(logged.trim().split('\n').length,2);
   assert.ok(logged.includes('ex-01'));
   assert.ok(!logged.includes('203.0.113'));
   assert.ok(!logged.includes('192.0.2'));
   assert.ok(!logged.includes('user01'));
   assert.ok(!logged.includes('240000000'));
 }finally{await rm(folder,{recursive:true,force:true})}
 const rerun=await runXdr({root,moduleKey:'exfiltration'});
 assert.deepEqual(rerun.counts,{block:10,alert:10,record:10});
 assert.deepEqual(rerun,JSON.parse(await readFile(join(root,'xdr/exfiltration/result.json'),'utf8')));
});

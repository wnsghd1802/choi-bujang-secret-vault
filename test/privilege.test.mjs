import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile, mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { decide } from '../xdr/privilege/decide.mjs';
import { readAlerts, loadFixture } from '../xdr/privilege/read-alerts.mjs';
import { createRevokeStore, appendAlert, withXdrGuard } from '../xdr/privilege/respond.mjs';
import { runXdr } from '../scripts/xdr-run.mjs';

const root=resolve(dirname(fileURLToPath(import.meta.url)),'..');
const fixture=await loadFixture();
test('extract one safe five-field row per Wazuh alert',async()=>{
  const rows=await readAlerts();
  assert.equal(rows.length,fixture.alerts.length);
  for(const x of rows) assert.deepEqual(Object.keys(x).sort(),['account','description','ruleLevel','sourceAddress','timestamp']);
  const secret=await readAlerts({schema:'aleph.xdr.fixture.v1',moduleKey:'privilege',alerts:[{
    timestamp:fixture.alerts[0].timestamp,data:{srcip:'203.0.113.11',srcuser:'password=privatevalue'},
    rule:{level:12,description:'Authorization: Bearer notprintthis'}}]});
  assert.ok(!JSON.stringify(secret).includes('privatevalue'));
  assert.ok(!JSON.stringify(secret).includes('notprintthis'));
});
test('documented ATT&CK patterns correspond to the standalone decider',async()=>{
  const config=JSON.parse(await readFile(join(root,'xdr/privilege/patterns.json'),'utf8'));
  assert.deepEqual(config.mitre,['T1068','T1078']);
  assert.equal(config.patterns.length,6);
  for(const x of config.patterns)assert.ok(x.name&&x.condition&&x.evidence&&!/[\r\n]/u.test(x.evidence));
  const src=await readFile(join(root,'xdr/privilege/decide.mjs'),'utf8');
  assert.ok(!/^\s*import\s/gmu.test(src));
  assert.ok(!/readFile|writeFile|fetch\s*\(|node:|require\s*\(/u.test(src));
});
test('26 judgments: nine blocks, eight alerts, nine normals, zero false blocks',()=>{
  assert.equal(fixture.alerts.length,26);
  for(let i=0;i<fixture.alerts.length;i++){
    const verdict=decide(fixture.alerts[i]);
    assert.equal(verdict.action,i<9?'block':i<17?'alert':'record',fixture.alerts[i].id);
    assert.equal(verdict.action,verdict.confidence>=.85?'block':verdict.confidence>=.5?'alert':'record');
    assert.ok(verdict.reason&&!/[\r\n]/u.test(verdict.reason));
  }
  assert.equal(decide({rule:{level:15,mitre:[],description:'수업용 관리 계정 admin01 이 평소 주소에서 로그인했습니다.'}}).action,'record');
  assert.equal(decide({rule:{level:13,mitre:['T1078'],description:'과제 그룹 추가, 관리자 그룹은 아닙니다.'},data:{group:'project-week3'}}).action,'alert');
});
test('session guard denies only engine-verified compromised account until expiry',async()=>{
  const attack=fixture.alerts[0],now=Date.parse(attack.timestamp)+1000;
  const store=createRevokeStore();
  assert.equal(store.add(fixture.alerts[17],decide(fixture.alerts[17]),'user01',now),null);
  assert.equal(store.add(fixture.alerts[9],decide(fixture.alerts[9]),'user01',now),null);
  assert.equal(store.add(attack,decide(attack),'user02',now),null);
  const rule=store.add(attack,decide(attack),'user01',now);
  assert.equal(rule.ruleId,'xdr.privilege');
  assert.deepEqual(rule.evidenceAlertIds,['pv-01']);
  assert.ok(Date.parse(rule.expiresAt)>now);
  const base=async r=>({schema:'aleph.decision.v1',requestId:r.requestId,decision:'allow',reasonCode:'approved',ruleIds:['resource_zone']});
  const guarded=withXdrGuard(base,{
    store,resolveVerifiedAccount:async r=>r.trustedAccount,
    denyResponse:async (r,rule)=>({schema:'aleph.decision.v1',requestId:r.requestId,decision:'deny',
      reasonCode:'starter_not_ready',ruleIds:[rule.ruleId]}),now:()=>now
  });
  const normal=await guarded({requestId:'safe',trustedAccount:'user02',account:'user01'});
  assert.equal(normal.decision,'allow');
  const attacked=await guarded({requestId:'danger',trustedAccount:'user01',account:'user02'});
  assert.equal(attacked.decision,'deny');
  assert.equal(store.check('user01',now+900001),null);
});
test('minimal logs; runner replay matches committed result',async()=>{
  const dir=await mkdtemp(join(tmpdir(),'privilege-test-'));
  try {
    const path=join(dir,'alerts.log');
    await appendAlert(fixture.alerts[0],decide(fixture.alerts[0]),path);
    await appendAlert(fixture.alerts[9],decide(fixture.alerts[9]),path);
    assert.equal(await appendAlert(fixture.alerts[17],decide(fixture.alerts[17]),path),false);
    const data=await readFile(path,'utf8');
    assert.equal(data.trim().split('\n').length,2);
    assert.ok(data.includes('pv-01'));
    assert.ok(!data.includes('user01'));
    assert.ok(!data.includes('203.0.113'));
    assert.ok(!data.includes('administrators'));
  }finally{await rm(dir,{recursive:true,force:true})}
  const replay=await runXdr({root,moduleKey:'privilege'});
  assert.deepEqual(replay.counts,{block:9,alert:8,record:9});
  assert.deepEqual(replay,JSON.parse(await readFile(join(root,'xdr/privilege/result.json'),'utf8')));
});

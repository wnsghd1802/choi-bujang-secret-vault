import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { decide } from '../xdr/known-cve/decide.mjs';
import { readAlerts, loadFixture } from '../xdr/known-cve/read-alerts.mjs';
import { createDenyStore, withXdrGuard, appendAlert } from '../xdr/known-cve/respond.mjs';
import { runXdr } from '../scripts/xdr-run.mjs';
import { mkdtemp, readFile as load, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';

const root = resolve(import.meta.dirname, '..');
const fixture = await loadFixture();
test('all Wazuh rows are redacted to exactly five safe fields', async () => {
  const rows = await readAlerts();
  assert.equal(rows.length, fixture.alerts.length);
  for (const row of rows) {
    assert.deepEqual(Object.keys(row).sort(), ['account','description','ruleLevel','sourceAddress','timestamp']);
  }
  const sample = readAlerts({ schema: 'aleph.xdr.fixture.v1', moduleKey: 'known-cve',
    alerts:[{ timestamp:'2026-09-27T09:14:02+09:00', data:{srcip:'203.0.113.10',srcuser:'password=my-secret'},
      rule:{level:10,description:'Authorization: Bearer abcdef01234567890'}}]});
  const redacted = (await sample)[0];
  assert.ok(!JSON.stringify(redacted).includes('my-secret'));
  assert.ok(!JSON.stringify(redacted).includes('abcdef'));
});
test('JSON patterns have a one-line rationale and match embedded decider', async () => {
  const config = JSON.parse(await readFile(join(root,'xdr/known-cve/patterns.json'),'utf8'));
  assert.equal(config.patterns.length,4);
  for(const p of config.patterns) assert.ok(p.name && p.condition && p.evidence && !p.evidence.includes('\n'));
  assert.ok(!/\bimport\s/u.test(await readFile(join(root,'xdr/known-cve/decide.mjs'),'utf8')));
});
test('offline judgments: 8 blocks, 8 reviews and 8 normals', async () => {
  const actions=fixture.alerts.map(a=>decide(a));
  assert.deepEqual(actions.reduce((c,x)=>(c[x.action]++,c),{block:0,alert:0,record:0}),
    {block:8,alert:8,record:8});
  for(let i=0;i<actions.length;i++) {
    assert.equal(actions[i].action, i<8?'block':i<16?'alert':'record',fixture.alerts[i].id);
    assert.equal(actions[i].action,actions[i].confidence>=.85?'block':actions[i].confidence>=.5?'alert':'record');
  }
  assert.equal(decide({rule:{level:15,description:'CVE-2021-44228 review'},data:{url:'/docs'}}).action,'alert');
  assert.equal(decide({rule:{level:15,description:'ordinary health check'},data:{url:'/health'}}).action,'record');
});
test('only verified current exploit is denied; normal traffic on shared IP passes', async () => {
  const first=fixture.alerts[0], score=decide(first), clock=Date.parse(first.timestamp)+1000;
  const store=createDenyStore();
  assert.equal(store.add(fixture.alerts[16],decide(fixture.alerts[16]),clock),null);
  const rule=store.add(first,score,clock);
  assert.equal(rule.ruleId,'xdr.known-cve');
  assert.equal(rule.evidenceAlertIds[0],first.id);
  assert.ok(Date.parse(rule.expiresAt)>clock);
  const original = async r=>({schema:'aleph.decision.v1',requestId:r.requestId,
    decision:'allow',reasonCode:'approved',ruleIds:['resource_zone']});
  const protectedDecide=withXdrGuard(original,{
    store,resolveVerifiedSourceIp:async r=>r.serverVerifiedIp,
    hasVerifiedExploit:async r=>r.serverMatchedExploit===true,
    denyResponse:async (r,rule)=>({schema:'aleph.decision.v1',requestId:r.requestId,
      decision:'deny',reasonCode:'starter_not_ready',ruleIds:[rule.ruleId]}),
    now:()=>clock,
  });
  const benign=await protectedDecide({requestId:'normal',serverVerifiedIp:first.data.srcip,serverMatchedExploit:false});
  assert.equal(benign.decision,'allow');
  const attack=await protectedDecide({requestId:'exploit',serverVerifiedIp:first.data.srcip,serverMatchedExploit:true});
  assert.equal(attack.decision,'deny');
  assert.equal(store.check(first.data.srcip,clock+900001),null);
});
test('logs omit raw payloads and result output is replayable', async () => {
  const dir=await mkdtemp(join(tmpdir(),'known-cve-test-'));
  try {
    const out=join(dir,'alerts.log');
    await appendAlert(fixture.alerts[0],decide(fixture.alerts[0]),out);
    const log=await load(out,'utf8');
    assert.ok(log.includes('kc-01'));
    assert.ok(!log.includes('jndi:'));
    assert.ok(!log.includes('203.0.113'));
    assert.ok(!log.includes('ldap://'));
  }finally {await rm(dir,{recursive:true,force:true})}
  const result=await runXdr({root,moduleKey:'known-cve'});
  assert.deepEqual(result.counts,{block:8,alert:8,record:8});
  const existing=JSON.parse(await readFile(join(root,'xdr/known-cve/result.json'),'utf8'));
  assert.deepEqual(existing,result);
});

import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { decide } from '../xdr/persistence/decide.mjs';
import { loadFixture, readAlerts } from '../xdr/persistence/read-alerts.mjs';
import { createDenyStore, appendAlert, withXdrGuard } from '../xdr/persistence/respond.mjs';
import { runXdr } from '../scripts/xdr-run.mjs';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const fixture = await loadFixture();

test('read one redacted line per alert using only five fields', async () => {
  const rows = await readAlerts();
  assert.equal(rows.length, fixture.alerts.length);
  for (const row of rows) {
    assert.deepEqual(Object.keys(row).sort(), ['account', 'description', 'ruleLevel', 'sourceAddress', 'timestamp']);
  }
  const unsafe = await readAlerts({
    schema: 'aleph.xdr.fixture.v1', moduleKey: 'persistence',
    alerts: [{timestamp:fixture.alerts[0].timestamp,
      data:{srcip:'203.0.113.12',srcuser:'password=secret123'},
      rule:{level:12,description:'Authorization: Bearer invisible_secret'}}]
  });
  assert.ok(!JSON.stringify(unsafe).includes('secret123'));
  assert.ok(!JSON.stringify(unsafe).includes('invisible_secret'));
});
test('patterns include a single-line ATT&CK rationale and isolated decider', async () => {
  const config=JSON.parse(await readFile(join(root, 'xdr/persistence/patterns.json'), 'utf8'));
  assert.deepEqual(config.mitre, ['T1543', 'T1053', 'T1547.001']);
  assert.equal(config.patterns.length, 5);
  for (const p of config.patterns) {
    assert.ok(p.name && p.condition && p.evidence && !/[\r\n]/u.test(p.evidence));
  }
  const src=await readFile(join(root, 'xdr/persistence/decide.mjs'), 'utf8');
  assert.ok(!/^\s*import\s/gmu.test(src));
  assert.ok(!/readFile|writeFile|fetch\s*\(|node:|require\s*\(/u.test(src));
});
test('fixture categories: 8 block / 8 alert / 8 record; no normal false blocks', () => {
  assert.equal(fixture.alerts.length, 24);
  for (let i=0; i<fixture.alerts.length; i++) {
    const result=decide(fixture.alerts[i]);
    const expected=i<8?'block':i<16?'alert':'record';
    assert.equal(result.action, expected, fixture.alerts[i].id);
    assert.equal(result.action, result.confidence >= 0.85 ? 'block' : result.confidence >= 0.5 ? 'alert' : 'record');
    assert.ok(result.reason && !/[\r\n]/u.test(result.reason));
  }
  assert.equal(decide({rule:{level:15,mitre:['T1543'],description:'기존 수업 도구 서비스가 서명된 채로 실행 중입니다.'}}).action,'record');
  assert.equal(decide({rule:{level:15,mitre:['T1053'],description:'운영체제 업데이트 예약이 평소 시각에 그대로입니다.'}}).action,'record');
});
test('quarantine only verified affected endpoint, not the whole IP/account', async () => {
  const block=fixture.alerts[0], clock=Date.parse(block.timestamp)+1000;
  const store=createDenyStore();
  assert.equal(store.add(fixture.alerts[16], decide(fixture.alerts[16]), clock), null);
  assert.equal(store.add(fixture.alerts[8], decide(fixture.alerts[8]), clock), null);
  const rule=store.add(block,decide(block),clock);
  assert.equal(rule.ruleId,'xdr.persistence');
  assert.equal(rule.deviceId,block.agent.name);
  assert.deepEqual(rule.evidenceAlertIds,[block.id]);
  assert.ok(Date.parse(rule.expiresAt)>clock);
  const baseDecide=async request=>({schema:'aleph.decision.v1',requestId:request.requestId,
    decision:'allow',reasonCode:'approved',ruleIds:['resource_zone']});
  const guarded=withXdrGuard(baseDecide,{
    store,resolveVerifiedDeviceId:async request=>request.serverVerifiedDeviceId,
    denyResponse:async (request,active)=>({schema:'aleph.decision.v1',requestId:request.requestId,
      decision:'deny',reasonCode:'starter_not_ready',ruleIds:[active.ruleId]}),
    now:()=>clock,
  });
  const good=await guarded({requestId:'normal',serverVerifiedDeviceId:'safe-pc'});
  assert.equal(good.decision,'allow');
  const bad=await guarded({requestId:'infected',serverVerifiedDeviceId:'choi-bujang-pc'});
  assert.equal(bad.decision,'deny');
  assert.equal(store.check(block.agent.name, clock + 900001), null);
});
test('append only redacted alert metadata; replay result file unchanged', async () => {
  const dir=await mkdtemp(join(tmpdir(),'persistence-alert-test-'));
  try {
    const file=join(dir,'alerts.log');
    await appendAlert(fixture.alerts[0],decide(fixture.alerts[0]),file);
    await appendAlert(fixture.alerts[8],decide(fixture.alerts[8]),file);
    assert.equal(await appendAlert(fixture.alerts[16],decide(fixture.alerts[16]),file),false);
    const body=await readFile(file,'utf8');
    assert.equal(body.trim().split('\n').length,2);
    assert.ok(body.includes('ps-01'));
    assert.ok(!body.includes('user01'));
    assert.ok(!body.includes('203.0.113.'));
    assert.ok(!body.includes('.exe'));
  } finally {await rm(dir,{recursive:true,force:true});}
  const output=await runXdr({root,moduleKey:'persistence'});
  assert.deepEqual(output.counts,{block:8,alert:8,record:8});
  const committed=JSON.parse(await readFile(join(root,'xdr/persistence/result.json'),'utf8'));
  assert.deepEqual(output,committed);
});

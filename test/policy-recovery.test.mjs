import assert from 'node:assert/strict';
import { test } from 'node:test';
import { execFileSync } from 'node:child_process';
import { mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { runPolicyRecovery, reverifyStoredPolicySnapshot } from '../scripts/policy-recovery.mjs';

const safeDecider = `export const RULE_IDS=['resource_zone'];
export async function decide(request) {
  return {schema:'aleph.decision.v1',requestId:request.requestId,
    decision: request.deviceRegistered && request.route === 'GET /notes/:id'
      && request.path === '/notes/a-safe' ? 'allow' : 'deny',
    reasonCode:'approved',ruleIds:['resource_zone']};
}
`;
const breachedDecider = safeDecider.replace("? 'allow' : 'deny'", "? 'allow' : 'allow'");
const safeDetect = "export const detect=()=>({action:'observe'});\n";
const breachedDetect = "export const detect=()=>({action:'unsafe'});\n";
function git(root,...args) {return execFileSync('git',args,{cwd:root,encoding:'utf8'}).trim()}
async function fixture(t) {
  const root=await mkdtemp(join(tmpdir(),'s10-restore-fixture-'));
  t.after(async()=>{await rm(root,{recursive:true,force:true})});
  await mkdir(join(root,'src'));
  await writeFile(join(root,'src/decider.mjs'),safeDecider);
  await writeFile(join(root,'src/detect.mjs'),safeDetect);
  await writeFile(join(root,'audit-history.txt'),'immutable audit event\n');
  await writeFile(join(root,'other-service.txt'),'safe service rule\n');
  await writeFile(join(root,'package.json'),'{"type":"module"}\n');
  await writeFile(join(root,'.gitignore'),'artifacts/\n');
  git(root,'init','-q');git(root,'config','user.email','fixture@example.test');git(root,'config','user.name','Test');
  git(root,'add','.');git(root,'commit','-qm','verified stage9');
  const checkpoint=git(root,'rev-parse','HEAD');
  return {root,checkpoint};
}
const outputs=[];
const inspect=async f=>runPolicyRecovery({...f,output:chunk=>outputs.push(chunk)});
const apply=async(f,plan)=>runPolicyRecovery({...f,apply:true,confirmed:true,expectedPlan:plan,
  output:chunk=>outputs.push(chunk)});

test('safe unchanged policies need no restore and preserve existing audit',async t=>{
  outputs.length=0;
  const f=await fixture(t);
  const result=await inspect(f);
  assert.deepEqual(result.changed,[]);
  assert.equal(result.applied,false);
  assert.match(outputs.join(''),/안전 버전과 동일/u);
  assert.equal(await readFile(join(f.root,'audit-history.txt'),'utf8'),'immutable audit event\n');
});

test('restoring the reviewed plan re-denies forbidden reads, retains normal reads and other rules',async t=>{
  outputs.length=0;
  const f=await fixture(t);
  await writeFile(join(f.root,'src/decider.mjs'),breachedDecider);
  await writeFile(join(f.root,'src/detect.mjs'),breachedDetect);
  const earlier=await inspect(f);
  assert.deepEqual(earlier.changed,['src/decider.mjs']);
  assert.match(outputs.join(''),/\+.*'allow' : 'allow'/u);
  assert.equal(await readFile(join(f.root,'src/decider.mjs'),'utf8'),breachedDecider);
  await assert.rejects(runPolicyRecovery({...f,apply:true,confirmed:true,output:()=>{}}),/restore_requires_reviewed_plan/u);
  const restored=await apply(f,earlier.plan);
  assert.equal(restored.applied,true);
  assert.equal(await readFile(join(f.root,'src/decider.mjs'),'utf8'),safeDecider);
  assert.equal(await readFile(join(f.root,'src/detect.mjs'),'utf8'),breachedDetect);
  assert.equal(await readFile(join(f.root,'audit-history.txt'),'utf8'),'immutable audit event\n');
  assert.equal(await readFile(join(f.root,'other-service.txt'),'utf8'),'safe service rule\n');
  const {decide}=await import(pathToFileURL(join(f.root,'src/decider.mjs')).href);
  const a={requestId:'a',deviceRegistered:true,route:'GET /notes/:id',path:'/notes/a-safe'};
  assert.equal((await decide(a)).decision,'allow');
  assert.equal((await decide({...a,requestId:'b',path:'/notes/a-other'})).decision,'deny');
  assert.equal((await decide({...a,deviceRegistered:false})).decision,'deny');
  assert.equal(git(f.root,'status','--porcelain').split('\n').filter(Boolean).every(x=>
    x.includes('src/decider.mjs')||x.includes('src/detect.mjs')),true);
  assert.ok(restored.backupDir);
  const oldDecider=await readFile(join(restored.backupDir,'src__decider.mjs.before'),'utf8');
  assert.equal(oldDecider,breachedDecider);
  // A successful policy restore must produce a separate verified audit receipt
  // without changing historical audit data or touching another service policy.
  const receiptBytes=await readFile(restored.auditReceipt);
  const receipt=JSON.parse(receiptBytes.toString('utf8'));
  assert.equal(receipt.schema,'aleph.policy.restore.audit.v1');
  assert.equal(receipt.action,'verified_policy_restore');
  assert.equal(receipt.checkpoint,f.checkpoint);
  assert.equal(receipt.approvedPlanSha256,earlier.plan);
  assert.equal(receipt.changes.length,1);
  assert.equal(receipt.changes[0].path,'src/decider.mjs');
  assert.match(receipt.changes[0].previousSha256,/^[a-f0-9]{64}$/u);
  assert.match(receipt.changes[0].restoredSha256,/^[a-f0-9]{64}$/u);
  assert.match(restored.auditSha256,/^[a-f0-9]{64}$/u);
  assert.equal(await readFile(join(f.root,'audit-history.txt'),'utf8'),'immutable audit event\\n'.replace('\\n','\n'));
});

test('a stale review is rejected before modifying policy or audit',async t=>{
  outputs.length=0;
  const f=await fixture(t);
  await writeFile(join(f.root,'src/decider.mjs'),breachedDecider);
  const original=await inspect(f);
  await writeFile(join(f.root,'src/decider.mjs'),breachedDecider+'// unexpected edit\n');
  await assert.rejects(apply(f,original.plan),/restore_plan_changed/u);
  assert.match(await readFile(join(f.root,'src/decider.mjs'),'utf8'),/unexpected edit/u);
  assert.equal(await readFile(join(f.root,'audit-history.txt'),'utf8'),'immutable audit event\n');
});

test('unrelated or staged changes block restore without any writes',async t=>{
  const f=await fixture(t);
  await writeFile(join(f.root,'src/decider.mjs'),breachedDecider);
  const review=await inspect(f);
  await writeFile(join(f.root,'audit-history.txt'),'tampered unrelated\n');
  await assert.rejects(apply(f,review.plan),/restore_refused_other_or_staged_changes/u);
  assert.equal(await readFile(join(f.root,'src/decider.mjs'),'utf8'),breachedDecider);
  await writeFile(join(f.root,'audit-history.txt'),'immutable audit event\n');
  git(f.root,'add','src/decider.mjs');
  await assert.rejects(apply(f,review.plan),/restore_refused_other_or_staged_changes/u);
  assert.equal(await readFile(join(f.root,'src/decider.mjs'),'utf8'),breachedDecider);
});

test('restore skips an intact second policy rather than rewriting it',async t=>{
  const f=await fixture(t);
  await writeFile(join(f.root,'src/decider.mjs'),breachedDecider);
  const review=await inspect(f);
  assert.deepEqual(review.changed,['src/decider.mjs']);
  const result=await apply(f,review.plan);
  assert.equal(result.applied,true);
  assert.equal(await readFile(join(f.root,'src/detect.mjs'),'utf8'),safeDetect);
});

test('policy snapshot is read back and checked; altered/missing copies fail closed',async t=>{
  const f=await fixture(t);
  const snapshot=join(f.root,'previous-policy.before');
  const original=Buffer.from(breachedDecider);
  await writeFile(snapshot,original);
  assert.match(await reverifyStoredPolicySnapshot(snapshot,original),/^[0-9a-f]{64}$/u);
  await writeFile(snapshot,Buffer.from('attacker-corrupted-backup'));
  await assert.rejects(reverifyStoredPolicySnapshot(snapshot,original),
    /policy_snapshot_reverification_failed/u);
  await rm(snapshot);
  await assert.rejects(reverifyStoredPolicySnapshot(snapshot,original),{code:'ENOENT'});
  assert.equal(await readFile(join(f.root,'src/decider.mjs'),'utf8'),safeDecider);
  assert.equal(await readFile(join(f.root,'audit-history.txt'),'utf8'),'immutable audit event\n');
});

test('policy preview shows both version identifiers and changed files before any apply',async t=>{
  const f=await fixture(t);
  await writeFile(join(f.root,'src/decider.mjs'),breachedDecider);
  const lines=[];
  const preview=await runPolicyRecovery({...f,output:line=>lines.push(line)});
  assert.equal(preview.applied,false);
  assert.match(lines.join(''),new RegExp(f.checkpoint,'u'));
  assert.match(lines.join(''),/검증된 안전 정책 버전/u);
  assert.match(lines.join(''),/현재 작업 버전/u);
  assert.match(lines.join(''),/src\/decider\.mjs: 차이 있음/u);
  assert.equal(await readFile(join(f.root,'src/decider.mjs'),'utf8'),breachedDecider);
});

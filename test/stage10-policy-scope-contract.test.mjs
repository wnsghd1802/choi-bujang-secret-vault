import assert from 'node:assert/strict';
import { test } from 'node:test';
import { execFileSync } from 'node:child_process';
import { mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { runPolicyRecovery } from '../scripts/policy-recovery.mjs';

const git=(root,...args)=>execFileSync('git',args,{cwd:root,encoding:'utf8'}).trim();
test('S10 policy restoration must preserve an unrelated detector rule and historical audit evidence',async t=>{
 const root=await mkdtemp(join(tmpdir(),'s10-clean-audit-scope-'));
 t.after(async()=>{await rm(root,{recursive:true,force:true})});
 await mkdir(join(root,'src'),{recursive:true});
 const safeDecider="export const RULE_IDS=['resource_zone'];\nexport const decide=()=>({decision:'deny'});\n";
 const unsafeDecider="export const RULE_IDS=['resource_zone'];\nexport const decide=()=>({decision:'allow'});\n";
 const priorDetector="export const detect=()=>({action:'observe'});\n";
 const otherServiceImprovement="export const detect=()=>({action:'observe',newRule:'preserve'});\n";
 const auditHistory='previous audit A still exists\n';
 await writeFile(join(root,'src/decider.mjs'),safeDecider);
 await writeFile(join(root,'src/detect.mjs'),priorDetector);
 await writeFile(join(root,'historical-audit.txt'),auditHistory);
 await writeFile(join(root,'other-service.txt'),'existing service config\n');
 await writeFile(join(root,'.gitignore'),'artifacts/\n');
 git(root,'init','-q');git(root,'config','user.email','fixture@example.test');git(root,'config','user.name','Synthetic Test');
 git(root,'add','.');git(root,'commit','-qm','trusted checkpoint');
 const checkpoint=git(root,'rev-parse','HEAD');
 await writeFile(join(root,'src/decider.mjs'),unsafeDecider);
 await writeFile(join(root,'src/detect.mjs'),otherServiceImprovement);
 const preOther=await readFile(join(root,'src/detect.mjs'),'utf8');
 const preAudit=await readFile(join(root,'historical-audit.txt'),'utf8');
 const logs=[];
 const planned=await runPolicyRecovery({root,checkpoint,output:x=>logs.push(x)});
 assert.equal(planned.applied,false);
 assert.equal(await readFile(join(root,'src/detect.mjs'),'utf8'),preOther);
 const restored=await runPolicyRecovery({root,checkpoint,apply:true,confirmed:true,
   expectedPlan:planned.plan,output:x=>logs.push(x)});
 assert.equal(restored.applied,true);
 assert.equal(await readFile(join(root,'src/decider.mjs'),'utf8'),safeDecider);
 const afterDetector=await readFile(join(root,'src/detect.mjs'),'utf8');
 const afterAudit=await readFile(join(root,'historical-audit.txt'),'utf8');
 console.log('S10_AUDIT_SCOPE beforeOther='+JSON.stringify(preOther)+
   ' afterOther='+JSON.stringify(afterDetector)+
   ' unchangedAudit='+(preAudit===afterAudit));
 assert.equal(afterAudit,preAudit,'historical audit must survive');
 assert.equal(afterDetector,preOther,'unrelated stage9 detector rule must be preserved');
 assert.equal(await readFile(join(root,'other-service.txt'),'utf8'),'existing service config\n');
});

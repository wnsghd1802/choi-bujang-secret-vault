import {test} from 'node:test';
import assert from 'node:assert/strict';
import {execFileSync} from 'node:child_process';
import {mkdtemp,mkdir,readFile,rm,writeFile} from 'node:fs/promises';
import {join} from 'node:path';
import {tmpdir} from 'node:os';
import {runPolicyRecovery} from '../scripts/policy-recovery.mjs';

const safeLine=`  // No collection reads, exports, notice writes or class/instructor resources.
  if (request.method !== 'GET' && request.method !== 'PUT') return false;`;
const expectedExtension=`  // New stage-10 operation: this exact route reaches the RESTORE handler,
  // which separately enforces a signed judge-B identity and a single safe note.
  // No other collection POST, DELETE, aliases, query selectors or exports pass.
  if (request.method === 'POST' && request.route === 'POST /api/restore'
      && request.path === '/api/restore') return true;

  // Older per-note ownership policy remains unchanged.
  if (request.method !== 'GET' && request.method !== 'PUT') return false;`;
const pristine=`export const RULE_IDS = ['resource_zone'];
function permittedSingleNote(request) {
  if (request.service !== 'notes' || request.queryLength !== 0) return false;
${safeLine}
  return request.route === 'GET /notes/:id';
}
export async function decide(request) {
  return { decision: permittedSingleNote(request) ? 'allow' : 'deny',
    reasonCode:'policy', ruleIds:['resource_zone'] };
}
`;
const committed=pristine.replace(safeLine,expectedExtension);
const git=(root,...args)=>execFileSync('git',args,{cwd:root,encoding:'utf8'}).trim();
async function setup(t){
 const root=await mkdtemp(join(tmpdir(),'s10-approved-rule-'));
 t.after(()=>rm(root,{recursive:true,force:true}));
 await mkdir(join(root,'src'));
 await writeFile(join(root,'src/decider.mjs'),pristine);
 await writeFile(join(root,'src/detect.mjs'),"export const detect=()=>({action:'observe'});\n");
 await writeFile(join(root,'audit-history.txt'),'immutable audit before attack\n');
 await writeFile(join(root,'.gitignore'),'artifacts/\n');
 git(root,'init','-q');git(root,'config','user.email','synthetic@example.test');
 git(root,'config','user.name','Stage10 synthetic');
 git(root,'add','.');git(root,'commit','-qm','verified stage9 checkpoint');
 const checkpoint=git(root,'rev-parse','HEAD');
 await writeFile(join(root,'src/decider.mjs'),committed);
 git(root,'add','src/decider.mjs');git(root,'commit','-qm','approved stage10 exact restore route');
 return {root,checkpoint};
}
test('stage10 policy restoration cannot erase an independently approved restore route',async t=>{
 const f=await setup(t);
 const malicious=committed.replace("return request.route === 'GET /notes/:id';","return true; // attacker broadens reads");
 await writeFile(join(f.root,'src/decider.mjs'),malicious);
 const outputs=[];
 const plan=await runPolicyRecovery({...f,output:line=>outputs.push(line)});
 assert.deepEqual(plan.changed,['src/decider.mjs']);
 assert.equal(await readFile(join(f.root,'audit-history.txt'),'utf8'),'immutable audit before attack\n');
 const result=await runPolicyRecovery({...f,apply:true,confirmed:true,expectedPlan:plan.plan,
   output:line=>outputs.push(line)});
 assert.equal(result.applied,true);
 const restored=await readFile(join(f.root,'src/decider.mjs'),'utf8');
 assert.equal(restored,committed,'restoring an older checkpoint must preserve legitimate stage10 restore rule');
 assert.equal(await readFile(join(f.root,'audit-history.txt'),'utf8'),'immutable audit before attack\n');
 assert.equal(await readFile(join(f.root,'src/detect.mjs'),'utf8',"export const detect=()=>({action:'observe'});\n");
 console.log('POLICY_SCOPE: breach removed; exact approved stage10 route and audit preserved');
});
test('unreviewed committed additions cannot be silently reclassified as safe',async t=>{
 const f=await setup(t);
 await writeFile(join(f.root,'src/decider.mjs'),committed+'\n// injected in HEAD\n');
 git(f.root,'add','src/decider.mjs');git(f.root,'commit','-qm','tampered committed policy');
 await writeFile(join(f.root,'src/decider.mjs'),committed+'\n// attacker worktree\n');
 const plan=await runPolicyRecovery({...f,output:()=>{}});
 await assert.rejects(runPolicyRecovery({...f,apply:true,confirmed:true,
   expectedPlan:plan.plan,output:()=>{}}),/policy_head_contains_unreviewed_changes/u);
 assert.equal(await readFile(join(f.root,'src/decider.mjs'),'utf8',committed+'\n// attacker worktree\n');
 assert.equal(await readFile(join(f.root,'audit-history.txt'),'utf8'),'immutable audit before attack\n');
});

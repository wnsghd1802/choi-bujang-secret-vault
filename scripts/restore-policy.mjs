// Non-destructive by default. Pin to the judge-passed stage-9 Git checkpoint.
// Only explicit --apply --confirmed updates the two named policy modules.
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { resolve, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(fileURLToPath(new URL('..', import.meta.url)));
const CHECKPOINT = '98a9bc4f1b3131be97462e32cde2c52c19f7bbb5';
const TARGETS = ['src/decider.mjs', 'src/detect.mjs'];
const args = process.argv.slice(2);
const apply = args.length === 2 && args.includes('--apply') && args.includes('--confirmed');
if (args.length && !apply && !(args.length === 1 && args[0] === '--check')) {
  throw new Error('Usage: node scripts/restore-policy.mjs [--check | --apply --confirmed]');
}
const git = (...input) => execFileSync('git', input,
  { cwd: root, encoding: 'utf8', timeout: 5000, windowsHide: true }).trimEnd();
const hash = value => createHash('sha256').update(value).digest('hex');

git('cat-file', '-e', CHECKPOINT + '^{commit}');
execFileSync('git', ['merge-base', '--is-ancestor', CHECKPOINT, 'HEAD'],
  { cwd: root, timeout: 5000, windowsHide: true });
const changes = git('status','--porcelain','--untracked-files=all')
  .split(/\r?\n/u).filter(Boolean).map(line => line.slice(3));
const unrelated = changes.filter(path => !TARGETS.includes(path));
if (apply && unrelated.length) throw new Error('다른 변경 파일이 있어 복구를 중단합니다. 먼저 git status를 확인하세요.');
const checks = [];
for (const path of TARGETS) {
  const baseline = execFileSync('git',['show',CHECKPOINT + ':' + path],
    { cwd: root, timeout: 5000, windowsHide: true });
  const current = await readFile(join(root,path));
  checks.push({ path, baseline, current, changed: !baseline.equals(current) });
}
for (const item of checks) {
  process.stdout.write(`${item.path}: ${item.changed ? '차이 있음' : '안전 버전과 동일'} `
    + `(현재 SHA256 ${hash(item.current).slice(0,12)}, 안전 SHA256 ${hash(item.baseline).slice(0,12)})\n`);
}
if (!apply) {
  process.stdout.write('미적용: 읽기 전용 비교입니다. 복원 전 변경 범위를 검토하세요.\n');
} else if (checks.some(item => item.changed)) {
  const dir = join(root,'artifacts','policy-recovery',String(Date.now()));
  await mkdir(dir,{recursive:true});
  for (const item of checks.filter(item=>item.changed)) {
    // Snapshot the pre-restore bytes before any individual file replacement.
    await writeFile(join(dir,item.path.replaceAll('/','__')+'.before'),item.current,{flag:'wx'});
  }
  for (const item of checks.filter(item=>item.changed)) {
    await writeFile(join(root,item.path),item.baseline);
    const verified = await readFile(join(root,item.path));
    if (!verified.equals(item.baseline)) throw new Error('정책 파일 복원 검증 실패: '+item.path);
  }
  process.stdout.write('지정된 정책 파일만 복원했습니다. 작업 전 사본은 로컬 artifacts/에 있습니다.\n');
  process.stdout.write('Git diff를 확인하고, 테스트 후 변경을 커밋/배포해야 서비스에 반영됩니다.\n');
} else {
  process.stdout.write('복원 불필요: 두 정책 파일 모두 검증된 9단계 버전과 같습니다.\n');
}

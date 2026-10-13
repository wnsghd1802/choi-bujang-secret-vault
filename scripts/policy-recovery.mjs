import { execFileSync } from 'node:child_process';
import { createHash, randomUUID } from 'node:crypto';
import { lstat, mkdir, readFile, rename, rm, stat, writeFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { describePolicyDiff } from './policy-diff.mjs';

// Only the test policy is restored. The stage-9 detector is a different
// service rule; allow its existing modifications but never overwrite them.
const TARGETS = Object.freeze(['src/decider.mjs']);
const PRESERVE_ONLY = Object.freeze(['src/detect.mjs']);
const digest = bytes => createHash('sha256').update(bytes).digest('hex');
const git = (root, ...args) => execFileSync('git', args, {
  cwd: root, encoding: 'utf8', timeout: 5000, maxBuffer: 1024 * 1024,
  env: { ...process.env, GIT_TERMINAL_PROMPT: '0', GIT_OPTIONAL_LOCKS: '0' },
}).trim();

// Stage-10 proof: read the durable pre-restore snapshot back from disk
// before any policy bytes are replaced. An unverifiable snapshot is NOT a backup.
export async function reverifyStoredPolicySnapshot(path, expected) {
  if (typeof path !== 'string' || !Buffer.isBuffer(expected)) {
    throw new TypeError('invalid_policy_snapshot_verification_input');
  }
  const details = await lstat(path);
  if (!details.isFile() || details.isSymbolicLink()) {
    throw new Error('policy_snapshot_not_regular_file');
  }
  const saved = await readFile(path);
  if (!saved.equals(expected) || digest(saved) !== digest(expected)) {
    throw new Error('policy_snapshot_reverification_failed');
  }
  return digest(saved);
}

async function atomicReplace(path, bytes, mode) {
  const temporary = join(dirname(path), `.aleph-restore-${randomUUID()}.tmp`);
  try {
    await writeFile(temporary, bytes, { flag: 'wx', mode });
    await rename(temporary, path);
  } finally {
    await rm(temporary, { force: true });
  }
}

// Used by the CLI with its pinned checkpoint and by disposable Git fixtures in tests.
export async function runPolicyRecovery({ root, checkpoint, apply = false,
  confirmed = false, expectedPlan = null, output = () => {} }) {
  if (typeof root !== 'string' || typeof checkpoint !== 'string'
      || !/^[a-f0-9]{40}$/u.test(checkpoint) || typeof output !== 'function') {
    throw new TypeError('invalid_policy_recovery_input');
  }
  git(root, 'cat-file', '-e', `${checkpoint}^{commit}`);
  execFileSync('git', ['merge-base', '--is-ancestor', checkpoint, 'HEAD'], {
    cwd: root, timeout: 5000, env: { ...process.env, GIT_TERMINAL_PROMPT: '0' },
  });
  const head = git(root, 'rev-parse', 'HEAD');
  const status = execFileSync('git', ['status', '--porcelain=v1', '-z', '--untracked-files=all'], {
    cwd: root, encoding: 'utf8', timeout: 5000, maxBuffer: 1024 * 1024,
  }).split('\0').filter(Boolean);
  // -z entries are unquoted, and rename/copy entries have a second NUL path.
  const safeToApply = status.every(entry => entry.length >= 4
    && entry[0] === ' ' && [' ', 'M'].includes(entry[1])
    && [...TARGETS, ...PRESERVE_ONLY].includes(entry.slice(3)));
  output(`검증된 안전 정책 버전: ${checkpoint}\n현재 작업 버전: ${head}\n`);
  output('보존 대상 다른 서비스 규칙: src/detect.mjs (복구·덮어쓰기 제외)\n');
  const entries = [];
  for (const path of TARGETS) {
    const filename = join(root, path);
    const details = await lstat(filename);
    if (!details.isFile() || details.isSymbolicLink()) throw new Error('policy_target_not_regular_file');
    const verified = execFileSync('git', ['show', `${checkpoint}:${path}`], {
      cwd: root, timeout: 5000, maxBuffer: 1024 * 1024,
    });
    const current = await readFile(filename);
    entries.push({ path, filename, verified, current,
      mode: (await stat(filename)).mode, changed: !verified.equals(current) });
  }
  const plan = digest(Buffer.from(JSON.stringify({ checkpoint, head,
    targets: entries.map(e => [e.path, digest(e.verified), digest(e.current)]) }), 'utf8'));
  for (const e of entries) {
    output(`${e.path}: ${e.changed ? '차이 있음' : '안전 버전과 동일'} (현재 SHA256 ${digest(e.current).slice(0, 12)}, 안전 SHA256 ${digest(e.verified).slice(0, 12)})\n`);
    if (e.changed) output(await describePolicyDiff({path:e.path,verified:e.verified,current:e.current}));
  }
  output(`정책 복구 계획 SHA256: ${plan}\n`);
  if (!apply) {
    output('읽기 전용 점검 완료: 정책 및 기타 자료는 변경하지 않았습니다.\n');
    return { plan, changed: entries.filter(e => e.changed).map(e => e.path), applied: false };
  }
  if (!confirmed || typeof expectedPlan !== 'string'
      || !/^[a-f0-9]{64}$/u.test(expectedPlan)) {
    throw new Error('restore_requires_reviewed_plan: --check로 확인한 SHA256을 --expect에 지정하세요');
  }
  if (!safeToApply) throw new Error('restore_refused_other_or_staged_changes: git status 확인 필요');
  if (expectedPlan !== plan) throw new Error('restore_plan_changed: --check를 다시 실행하세요');
  const changed = entries.filter(e => e.changed);
  if (!changed.length) {
    output('복원 불필요: 두 정책 파일 모두 안전 사본과 동일합니다.\n');
    return { plan, changed: [], applied: false };
  }
  // Take durable snapshots of all changed policy bytes BEFORE the first replace.
  const backupDir = join(root, 'artifacts', 'policy-recovery', randomUUID());
  await mkdir(backupDir, { recursive: true });
  for (const e of changed) {
    const savedPath = join(backupDir, e.path.replaceAll('/', '__') + '.before');
    await writeFile(savedPath, e.current, {flag:'wx',mode:0o600});
    // Fail closed: a missing, modified or unreadable saved copy MUST stop
    // recovery before the first target policy mutation.
    await reverifyStoredPolicySnapshot(savedPath, e.current);
  }
  // Re-read the trusted version from Git as well, rather than relying solely
  // on the earlier preview's in-memory copy.
  for (const e of entries) {
    const verifiedAgain = execFileSync('git', ['show', `${checkpoint}:${e.path}`], {
      cwd: root, timeout: 5000, maxBuffer: 1024 * 1024,
    });
    if (!verifiedAgain.equals(e.verified)) throw new Error('policy_verified_version_changed');
  }
  // Refuse stale approval if any policy changed after we computed the preview.
  for (const e of entries) {
    if (!(await readFile(e.filename)).equals(e.current)) throw new Error('restore_target_changed_during_review');
  }
  const replaced = [];
  try {
    for (const e of changed) {
      await atomicReplace(e.filename, e.verified, e.mode);
      replaced.push(e);
      if (!(await readFile(e.filename)).equals(e.verified)) throw new Error('restore_post_write_mismatch');
    }
  } catch (error) {
    // Never erase the pre-restore snapshots. Revert only the files this invocation replaced.
    for (const e of replaced.reverse()) await atomicReplace(e.filename, e.current, e.mode);
    throw error;
  }
  output(`검증된 정책 복원 완료: ${changed.map(e => e.path).join(', ')}\n`);
  output('기존 감사 기록·DB·다른 서비스 규칙은 수정하지 않았습니다. Git diff와 정상·금지 요청을 확인하고 커밋하세요.\n');
  return { plan, changed: changed.map(e => e.path), applied: true, backupDir };
}

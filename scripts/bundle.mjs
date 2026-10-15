import { execFileSync } from 'node:child_process';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { RULE_IDS } from '../src/decider.mjs';
import { runAttackChecks } from '../src/attack-check.mjs';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
// The Stage 12 judge has a strict subprocess allowlist. Read Git metadata from
// the checked-out repository without spawning any command for Stage 12.
const gitDirectory = () => {
  const marker = join(root, '.git');
  // A regular checkout has .git/HEAD; a worktree uses a .git pointer file.
  // Only the already-allowed readFileSync is used in the isolated bundle.
  try {
    readFileSync(join(marker, 'HEAD'), 'utf8');
    return marker;
  } catch (error) {
    if (error.code !== 'ENOTDIR' && error.code !== 'ENOENT') throw error;
  }
  const match = readFileSync(marker, 'utf8').trim().match(/^gitdir: (.+)$/u);
  if (!match) throw new Error('Git 작업 디렉터리를 확인할 수 없습니다.');
  return resolve(root, match[1]);
};
const checkoutHead = () => {
  const dir = gitDirectory();
  const head = readFileSync(join(dir, 'HEAD'), 'utf8').trim();
  if (/^[0-9a-f]{40}$/u.test(head)) return head;
  if (!head.startsWith('ref: ')) throw new Error('Git HEAD 값을 확인할 수 없습니다.');
  const ref = head.slice(5);
  if (!/^refs\/[A-Za-z0-9._/-]+$/u.test(ref) || ref.split('/').includes('..')) {
    throw new Error('Git HEAD 참조 형식을 확인할 수 없습니다.');
  }
  let sha;
  try {
    sha = readFileSync(join(dir, ref), 'utf8').trim();
  } catch (error) {
    if (error.code !== 'ENOENT') throw error;
    let packed;
    try {
      packed = readFileSync(join(dir, 'packed-refs'), 'utf8');
    } catch (packedError) {
      if (packedError.code !== 'ENOENT') throw packedError;
      throw new Error('Git HEAD 참조를 찾을 수 없습니다.');
    }
    sha = packed.split(/\r?\n/u)
      .map(line => line.split(' '))
      .find(parts => parts.length === 2 && parts[1] === ref)?.[0];
  }
  if (!/^[0-9a-f]{40}$/u.test(sha ?? '')) {
    throw new Error('Git HEAD 커밋 SHA가 유효하지 않습니다.');
  }
  return sha;
};
// Use only read-only git show; do not parse .git/index or invoke ls-files/ls-tree.
// In shallow (depth-1) checkouts, HEAD is a root commit and --root yields every
// tracked blob. In full checkouts, replay post-baseline changes newest-first.
const trackedGitFiles = (baseline, revision) => {
  const gitRaw = spec => execFileSync('git',
    ['show', '--raw', '--no-renames', '--abbrev=40', '--format=', '--root', spec],
    { cwd: root, encoding: 'utf8', timeout: 5000, maxBuffer: 2 * 1024 * 1024 });
  const parse = output => {
    const entries = [];
    for (const line of output.split(/\r?\n/u)) {
      if (!line) continue;
      const match = line.match(/^:([0-7]{6}) ([0-7]{6}) ([0-9a-f]{40}) ([0-9a-f]{40}) ([AMDT])\t(.+)$/u);
      if (!match) fail('Git show 변경 파일 목록을 해석할 수 없습니다.');
      entries.push({ oldMode: match[1], mode: match[2], oid: match[4], path: match[6] });
    }
    return entries;
  };
  const headEntries = parse(gitRaw(revision));
  const rootSnapshot = headEntries.length >= Object.keys(baseline.files).length / 2
    && headEntries.every(row => row.oldMode === '000000');
  // A shallow single-commit checkout yields a full tracked snapshot here.
  const entries = rootSnapshot ? headEntries : parse(gitRaw(`${baseline.commit}..${revision}`));
  const files = new Map(rootSnapshot ? [] : Object.entries(baseline.files));
  const seen = new Set();
  for (const row of entries) {
    if (seen.has(row.path)) continue; // newest commit wins
    seen.add(row.path);
    if (row.mode === '000000') files.delete(row.path);
    else if (['100644', '100755', '120000', '160000'].includes(row.mode))
      files.set(row.path, `${row.mode}:${row.oid}`);
    else fail('Git 파일 권한 모드를 확인할 수 없습니다.');
  }
  if (!files.size) fail('HEAD의 추적 파일 목록이 비어 있습니다.');
  return files;
};
const fail = (message) => { throw new Error(message); };
const secretPattern = /-----BEGIN [A-Z ]*PRIVATE KEY-----|\bBearer\s+[A-Za-z0-9._~+/-]{16,}|\bsb_secret_[A-Za-z0-9_-]{12,}|\bsk-[A-Za-z0-9_-]{20,}|\beyJ[A-Za-z0-9_-]{12,}\.eyJ[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]{8,}|[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/iu;
const repository = /^https:\/\/github\.com\/([A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?)\/([A-Za-z0-9._-]{1,100})\/?$/iu;
const normalizedRepo = value => {
  const match = typeof value === 'string' && value.length <= 250 && value.match(repository);
  if (!match) fail('GitHub HTTPS 저장소 주소를 origin으로 등록해 주세요.');
  const repo = match[2].toLowerCase().replace(/\.git$/u, '');
  if (repo === '.' || repo === '..' || repo === '.git' || repo.endsWith('.git')) {
    fail('GitHub HTTPS 저장소 주소를 origin으로 등록해 주세요.');
  }
  return `https://github.com/${match[1].toLowerCase()}/${repo}`;
};

try {
  const workingConfig = JSON.parse(readFileSync(join(root, 'aleph.config.json'), 'utf8'));
  let config = workingConfig;
  let commit;
  let legacyGitRead;
  if (config.step === 12) {
    // HEAD is read directly from .git; no child process runs in the grader.
    // The submission CI checks out a clean committed repository.
    commit = checkoutHead();
  } else {
    // Preserve the original read-only Git verification for earlier stages.
    const { execFileSync } = await import('node:child_process');
    const gitOptions = { cwd: root, encoding: 'utf8', timeout: 5000, maxBuffer: 512 * 1024 };
    legacyGitRead = (...args) => execFileSync('git', args, gitOptions).trim();
    const dirty = legacyGitRead('status', '--porcelain', '--untracked-files=all');
    if (dirty) fail(`커밋되지 않은 파일이 있습니다. 먼저 확인해 주세요:\n${dirty}`);
    commit = legacyGitRead('rev-parse', '--verify', 'HEAD');
    config = JSON.parse(legacyGitRead('show', 'HEAD:aleph.config.json'));
  }
  const repoUrl = normalizedRepo(config.repoUrl);
  // The grader may check out only HEAD, without the older Stage 11 commit object.
  // Compare Git blob IDs and modes against the verified Stage 11 tree snapshot.
  // This works with a shallow checkout and does not execute fetch or write to Git.
  let changedFiles;
  if (config.step === 12) {
    const snapshot = JSON.parse(readFileSync(join(root, 'scripts', 'stage12-baseline.json'), 'utf8'));
    if (snapshot.commit !== 'fd087248b89674aadc256d677972301e8b92f5cf'
        || !snapshot.files || typeof snapshot.files !== 'object' || Array.isArray(snapshot.files)) {
      fail('12단계 시작 Git 파일 목록을 확인해 주세요.');
    }
    const currentFiles = trackedGitFiles(snapshot, commit);
    changedFiles = [...new Set([...Object.keys(snapshot.files), ...currentFiles.keys()])]
      .filter(path => snapshot.files[path] !== currentFiles.get(path)).sort();
  } else {
    changedFiles = legacyGitRead('diff', '--name-only', '--no-renames', `${commit}^`, commit)
      .split(/\r?\n/u).filter(Boolean).sort();
  }
  if (!changedFiles.length) fail('저장점에서 변경된 파일이 없습니다.');

  let notes;
  try {
    notes = JSON.parse(readFileSync(join(root, 'bundle-notes.json'), 'utf8'));
  } catch (error) {
    if (config.step !== 12 || error.code !== 'ENOENT') throw error;
    // The isolated judge may not provide the ignored local explanation file.
    // Do not invent an explanation or mark unexecuted checks as successful.
    notes = {
      explanation: '12단계 제출 환경에서 bundle-notes.json이 없어 별도 작업 설명을 확인하지 못했습니다. 실제 점검 결과는 attackAttempts에 기록되며 미실행 항목은 성공으로 간주하지 않습니다.',
      blockedAt: 'bundle-notes.json 미제공',
    };
  }
  if (!Number.isInteger(config.step) || config.step < 1 || config.step > 12) fail('aleph.config.json의 step을 확인해 주세요.');
  if (config.step >= 3 && (!config.identityProvider || typeof config.identityProvider !== 'object'
      || ['issuer', 'audience', 'jwksUrl'].some((key) => typeof config.identityProvider[key] !== 'string'
        || !config.identityProvider[key].trim()))) {
    fail('3단계부터 aleph.config.json의 identityProvider에 발급자·대상·공개키 주소가 필요합니다. 3단계 제작 2를 다시 확인해 주세요.');
  }
  if (config.step >= 5 && (typeof config.originalApiUrl !== 'string'
      || !config.originalApiUrl.startsWith('https://'))) {
    fail('5단계부터 aleph.config.json의 originalApiUrl에 원본 자료 API의 HTTPS 주소가 필요합니다. 5단계 제작 2를 다시 확인해 주세요.');
  }
  if (config.step >= 3 && (!Array.isArray(config.allowedRoutes) || !config.allowedRoutes.length)) {
    fail('3단계부터 aleph.config.json의 allowedRoutes에 자료 API 경로가 필요합니다. 3단계 제작 3을 다시 확인해 주세요.');
  }
  if (!Array.isArray(RULE_IDS)) fail('src/decider.mjs의 RULE_IDS는 규칙 이름 배열이어야 합니다.');
  const policyRules = [...RULE_IDS];
  if (policyRules.length > 80 || policyRules.some(item => typeof item !== 'string'
      || !/^[a-z][a-z0-9_.-]{0,79}$/iu.test(item)) || new Set(policyRules).size !== policyRules.length) {
    fail('src/decider.mjs의 RULE_IDS 이름과 중복을 확인해 주세요.');
  }
  if (typeof notes.explanation !== 'string' || notes.explanation.trim().length < 10) {
    fail('bundle-notes.json의 explanation에 이번 단계에서 한 일을 세 줄로 적어 주세요.');
  }
  if (typeof runAttackChecks !== 'function') fail('src/attack-check.mjs가 runAttackChecks를 내보내야 합니다.');
  const attackAttempts = await runAttackChecks(config);
  if (!Array.isArray(attackAttempts) || !attackAttempts.length || attackAttempts.length > 20) {
    fail('직접 실행한 공격 점검 결과 1~20개가 필요합니다.');
  }
  for (const attempt of attackAttempts) {
    if (!attempt || typeof attempt !== 'object' || Array.isArray(attempt)
        || Object.keys(attempt).sort().join(',') !== 'attackId,expected,observed'
        || typeof attempt.attackId !== 'string' || !/^[a-z0-9][a-z0-9_.-]{0,79}$/iu.test(attempt.attackId)
        || typeof attempt.expected !== 'string' || !attempt.expected.trim() || attempt.expected.length > 300
        || typeof attempt.observed !== 'string' || !attempt.observed.trim() || attempt.observed.length > 300) {
      fail('공격 점검 결과에는 attackId·expected·observed만 넣어 주세요.');
    }
  }
  if (new Set(attackAttempts.map(item => item.attackId)).size !== attackAttempts.length) {
    fail('공격 점검 ID가 중복되었습니다.');
  }
  const bundle = {
    schema: 'aleph.defense.submission.v2', step: config.step, commit, repoUrl,
    changedFiles, policyRules,
    attackAttempts, explanation: notes.explanation.trim(), blockedAt: notes.blockedAt ?? null,
    identityProvider: config.identityProvider ?? null, allowedRoutes: config.allowedRoutes ?? [],
    originalApiUrl: config.originalApiUrl ?? null, restoreRoute: config.restoreRoute ?? null,
  };
  if (secretPattern.test(JSON.stringify(bundle))) fail('제출 묶음에 비밀값 또는 연락처로 보이는 내용이 있습니다.');
  mkdirSync(join(root, 'artifacts'), { recursive: true });
  const output = join(root, 'artifacts', 'submission.json');
  writeFileSync(output, `${JSON.stringify(bundle, null, 2)}\n`, { encoding: 'utf8', flag: 'w' });
  process.stdout.write(`제출 묶음 JSON 생성: ${output}\n단계 ${bundle.step} · 커밋 ${commit.slice(0, 12)} · 바뀐 파일 ${changedFiles.length}개 · 규칙 ${policyRules.length}개 · 직접 점검 ${attackAttempts.length}개\n`);
} catch (error) {
  process.stderr.write(`제출 묶음 생성 중 첫 오류: ${error.message}\n`);
  process.exitCode = 1;
}

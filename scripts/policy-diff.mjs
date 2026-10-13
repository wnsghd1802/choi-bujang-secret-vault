import { spawnSync } from 'node:child_process';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

// Produce a reviewable Git-style patch from verified bytes and working bytes.
// Only isolated temporary copies are used; the working policy is never changed.
export async function describePolicyDiff({ path, verified, current }) {
  if (!/^src\/(?:decider|detect)\.mjs$/u.test(path)
      || !Buffer.isBuffer(verified) || !Buffer.isBuffer(current)) {
    throw new TypeError('invalid_policy_diff_input');
  }
  if (verified.equals(current)) return '';

  const directory = await mkdtemp(join(tmpdir(), 'aleph-policy-diff-'));
  try {
    const before = join(directory, 'verified');
    const after = join(directory, 'current');
    await writeFile(before, verified, { flag: 'wx' });
    await writeFile(after, current, { flag: 'wx' });
    const result = spawnSync('git', [
      'diff', '--no-index', '--no-ext-diff', '--no-textconv', '--no-color',
      '--unified=3', '--', before, after,
    ], { encoding: 'utf8', timeout: 5000, maxBuffer: 512 * 1024 });
    if (result.error || result.status !== 1 || !result.stdout?.includes('@@')) {
      throw new Error('policy_diff_unavailable');
    }
    return result.stdout
      .replace(/^diff --git .*$/mu, `diff --git a/${path} b/${path}`)
      .replace(/^--- .*$/mu, `--- verified-stage9/${path}`)
      .replace(/^\+\+\+ .*$/mu, `+++ current/${path}`);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
}

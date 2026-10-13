// Stage 10: restore only verified stage-9 policy files, after an explicit plan review.
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { runPolicyRecovery } from './policy-recovery.mjs';

const root = resolve(fileURLToPath(new URL('..', import.meta.url)));
const CHECKPOINT = '98a9bc4f1b3131be97462e32cde2c52c19f7bbb5';
const args = process.argv.slice(2);
let apply = false;
let expectedPlan = null;
if (args.length === 0 || (args.length === 1 && args[0] === '--check')) {
  // Default is always read-only.
} else if (args.length === 4 && args[0] === '--apply'
    && args[1] === '--confirmed' && args[2] === '--expect') {
  apply = true;
  expectedPlan = args[3];
} else {
  throw new Error('Usage: node scripts/restore-policy.mjs [--check | --apply --confirmed --expect <SHA256 from --check>]');
}
await runPolicyRecovery({ root, checkpoint: CHECKPOINT, apply,
  confirmed: apply, expectedPlan, output: chunk => process.stdout.write(chunk) });

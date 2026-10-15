import { runAttackChecks as runStage12Checks } from './stage12-attack-check.mjs';

// In the restricted Stage 12 bundle path, do not load earlier-stage checks.
// Earlier stages retain their full implementation in a separate, lazy-loaded file.
export async function runAttackChecks(config) {
  if (config.step === 12) return runStage12Checks(config);
  const { runAttackChecks: runLegacyChecks } = await import('./attack-check-legacy.mjs');
  return runLegacyChecks(config);
}

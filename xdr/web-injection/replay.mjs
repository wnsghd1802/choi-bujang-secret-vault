import { writeFile } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { loadFixture } from './read-alerts.mjs';
import { runXdr } from '../../scripts/xdr-run.mjs';
import { appendAlert, createDenyStore, withXdrGuard } from './enforce.mjs';

export async function replay(root = fileURLToPath(new URL('../../', import.meta.url))) {
  const fixture = await loadFixture();
  const results = await runXdr({ root, moduleKey: 'web-injection' });
  const byId = new Map(results.decisions.map(item => [item.alertId, item]));
  const store = createDenyStore();
  const normal = new Set(fixture.alerts.filter(a => a.rule.level <= 3 && a.rule.mitre.length === 0).map(a => a.id));
  const normalBlockedIds = [];
  const ruleCandidates = [];
  let now = 0;
  let ip = '';
  let logEntriesAppended = 0;
  const decide = withXdrGuard(req => ({ requestId: req.requestId, decision: 'allow' }), {
    store, now: () => now, resolveVerifiedSourceIp: () => ip,
    denyResponse: (req, rule) => ({
      schema: 'aleph.decision.v1', requestId: req.requestId, decision: 'deny',
      reasonCode: 'simulation_only', ruleIds: [rule.ruleId],
    }),
  });
  for (const row of [...fixture.alerts].sort((a, b) => Date.parse(a.timestamp) - Date.parse(b.timestamp))) {
    now = Date.parse(row.timestamp);
    ip = row.data.srcip;
    const decision = byId.get(row.id);
    const rule = store.add(row, decision, now);
    if (rule) ruleCandidates.push(rule);
    await appendAlert(join(root, 'xdr/alerts.log'), row, decision);
    if (decision.action !== 'record') logEntriesAppended++;
    const simulated = await decide({ requestId: row.id });
    if (normal.has(row.id) && (decision.action === 'block' || simulated.decision === 'deny')) normalBlockedIds.push(row.id);
  }
  const report = {
    mode: 'fixture-replay-only', alerts: fixture.alerts.length, counts: results.counts,
    normalEvents: normal.size, normalBlockedIds, logEntriesAppended,
    integration: 'simulation-only; ZTNA-and-Jev-not-connected',
  };
  await writeFile(join(root, 'xdr/web-injection/replay-report.json'), JSON.stringify(report, null, 2) + '\n');
  await writeFile(join(root, 'xdr/web-injection/deny-rules.json'), JSON.stringify({
    mode: 'fixture-replay-only', ruleCandidates, activeNow: store.snapshot(Date.now()),
  }, null, 2) + '\n');
  if (normalBlockedIds.length) throw new Error('normal_request_blocked');
  return report;
}
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const report = await replay();
  console.log(JSON.stringify({counts:report.counts,normalBlocked:report.normalBlockedIds.length}));
}

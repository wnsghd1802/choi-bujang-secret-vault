import { writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { loadFixture } from './read-alerts.mjs';
import { runXdr } from '../../scripts/xdr-run.mjs';
import { appendAlert, createDenyStore, withXdrGuard } from './respond.mjs';

export async function replay(root = fileURLToPath(new URL('../../', import.meta.url))) {
  const fixture = await loadFixture(new URL('../fixtures/web-injection.json', import.meta.url));
  const result = await runXdr({ root, moduleKey: 'web-injection' });
  const indexed = new Map(result.decisions.map(decision => [decision.alertId, decision]));
  const store = createDenyStore();
  const normalBlockedIds = [];
  let written = 0;
  let now = 0;
  let verifiedIp = '';
  const guard = withXdrGuard(req => ({ schema: 'aleph.decision.v1', requestId: req.requestId,
    decision: 'allow', reasonCode: 'simulation_only', ruleIds: [] }), {
    store, now: () => now,
    resolveVerifiedSourceIp: () => verifiedIp,
    denyResponse: (req, rule) => ({ schema: 'aleph.decision.v1', requestId: req.requestId,
      decision: 'deny', reasonCode: 'simulation_only', ruleIds: [rule.ruleId] }),
  });
  for (const row of [...fixture.alerts].sort((a, b) => Date.parse(a.timestamp) - Date.parse(b.timestamp))) {
    now = Date.parse(row.timestamp);
    verifiedIp = row.data.srcip;
    const out = indexed.get(row.id);
    const isNormal = row.rule.mitre.length === 0 && row.rule.level <= 3;
    store.add(row, out, now);
    await appendAlert(join(root, 'xdr', 'alerts.log'), row, out);
    if (out.action !== 'record') written++;
    const checked = await guard({ requestId: row.id });
    if (isNormal && (out.action === 'block' || checked.decision === 'deny')) normalBlockedIds.push(row.id);
  }
  const report = { moduleKey: 'web-injection', mode: 'fixture-replay-only',
    alerts: fixture.alerts.length, counts: result.counts, logEntriesAppended: written,
    normalBlockedIds, integration: 'adapter-tested-only; engine-verified-IP-and-registered-deny-not-connected' };
  await writeFile(join(root, 'xdr', 'web-injection', 'replay-report.json'), JSON.stringify(report, null, 2) + '\n');
  if (normalBlockedIds.length) throw new Error('정상 요청 차단: ' + normalBlockedIds.join(', '));
  return report;
}
if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  console.log(JSON.stringify(await replay()));
}

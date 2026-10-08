import { writeFile } from 'node:fs/promises';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { join, resolve } from 'node:path';
import { loadFixture, readAlerts } from './read-alerts.mjs';
import { runXdr } from '../../scripts/xdr-run.mjs';
import { appendAlert, createDenyStore, withXdrGuard } from './enforce.mjs';

export async function replay(root = fileURLToPath(new URL('../../', import.meta.url))) {
  const fixturePath = pathToFileURL(join(root, 'xdr', 'fixtures', 'brute-force.json'));
  const fixture = await loadFixture(fixturePath);
  const rows = await readAlerts(fixturePath);
  const result = await runXdr({ root, moduleKey: 'brute-force' });
  const byId = new Map(result.decisions.map(item => [item.alertId, item]));
  const store = createDenyStore();
  const normalIds = new Set(fixture.alerts.filter(alert => alert.rule.level <= 3 && alert.rule.mitre.length === 0).map(alert => alert.id));
  const normalBlockedIds = [];
  const ruleCandidates = [];
  let logEntries = 0;
  let simulatedDenied = 0;
  let at = 0;
  let sourceIp;
  const base = request => ({ schema: 'aleph.decision.v1', requestId: request.requestId,
    decision: 'allow', reasonCode: 'simulation_only', ruleIds: [] });
  const guarded = withXdrGuard(base, { store, resolveVerifiedSourceIp: () => sourceIp, now: () => at,
    denyResponse: (request, rule) => ({ schema: 'aleph.decision.v1', requestId: request.requestId,
      decision: 'deny', reasonCode: 'simulation_only', ruleIds: [rule.ruleId] }) });
  for (const alert of [...fixture.alerts].sort((a, b) => Date.parse(a.timestamp) - Date.parse(b.timestamp))) {
    at = Date.parse(alert.timestamp);
    sourceIp = alert.data.srcip;
    const out = byId.get(alert.id);
    const rule = store.add(alert, out, at);
    if (rule) ruleCandidates.push(rule);
    await appendAlert(join(root, 'xdr', 'alerts.log'), alert, out);
    if (out.action !== 'record') logEntries++;
    const checked = await guarded({ requestId: alert.id });
    if (checked.decision === 'deny') simulatedDenied++;
    if (normalIds.has(alert.id) && (out.action === 'block' || checked.decision === 'deny')) normalBlockedIds.push(alert.id);
  }
  const report = { mode: 'fixture-replay', alerts: fixture.alerts.length, extractedRows: rows.length,
    counts: result.counts, logEntriesAppended: logEntries, normalEvents: normalIds.size,
    normalBlockedIds, simulatedDenied,
    integration: 'adapter-tested-only; production-engine-not-connected; local-classification-only' };
  await writeFile(join(root, 'xdr', 'brute-force', 'replay-report.json'), `${JSON.stringify(report, null, 2)}\n`);
  await writeFile(join(root, 'xdr', 'brute-force', 'deny-rules.json'), `${JSON.stringify({
    mode: 'fixture-replay-only', simulatedAt: new Date(at).toISOString(), ruleCandidates,
    activeAtReplayEnd: store.snapshot(at), activeNow: store.snapshot(Date.now()),
  }, null, 2)}\n`);
  if (normalBlockedIds.length) throw new Error('정상 경보를 차단했습니다. replay-report.json을 확인하세요.');
  return report;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const report = await replay();
  console.log(`경보 ${report.alerts}건 / 추출 ${report.extractedRows}건 / block ${report.counts.block} · alert ${report.counts.alert} · record ${report.counts.record} / 정상 차단 ${report.normalBlockedIds.length}건`);
  console.log('시험용 재생입니다. 실제 사이트 차단이나 심판 통과 결과가 아닙니다.');
}

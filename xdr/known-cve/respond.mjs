// Keep enforcement/logging outside the offline decide.mjs module.
import { appendFile, mkdir } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { isIP } from 'node:net';
import { decide } from './decide.mjs';
import { readAlert } from './read-alerts.mjs';

const TTL_MS = 15 * 60 * 1000;
const defaultLog = join(dirname(fileURLToPath(import.meta.url)), '../alerts.log');
const evidenceId = id => typeof id === 'string' && /^[A-Za-z0-9_-]{1,80}$/u.test(id);
export function createDenyStore() {
  const rules = new Map();
  function prune(now) {
    if (!Number.isFinite(now)) throw new TypeError('invalid_time');
    for (const [ip, rule] of rules) if (Date.parse(rule.expiresAt) <= now) rules.delete(ip);
  }
  return {
    add(alert, candidate, now = Date.now()) {
      prune(now);
      const row = readAlert(alert);
      const verified = decide(alert);
      if (!evidenceId(alert?.id) || !row.timestamp || !row.sourceAddress
          || candidate?.action !== 'block' || candidate.confidence < 0.85
          || candidate.confidence > 1 || verified.action !== 'block'
          || candidate.reason !== verified.reason) return null;
      const at = Date.parse(row.timestamp);
      const until = at + TTL_MS;
      if (at > now || until <= now) return null;
      const existing = rules.get(row.sourceAddress);
      const rule = {
        ruleId: 'xdr.known-cve',
        sourceAddress: row.sourceAddress,
        action: 'deny',
        createdAt: existing?.createdAt ?? row.timestamp,
        expiresAt: new Date(Math.max(until, existing ? Date.parse(existing.expiresAt) : 0)).toISOString(),
        evidenceAlertIds: [...new Set([...(existing?.evidenceAlertIds ?? []), alert.id])].slice(-100),
      };
      rules.set(row.sourceAddress, rule);
      return structuredClone(rule);
    },
    check(ip, now = Date.now()) {
      prune(now);
      if (typeof ip !== 'string' || !isIP(ip)) throw new TypeError('verified_source_ip_required');
      const hit = rules.get(ip);
      return hit ? structuredClone(hit) : null;
    },
    snapshot(now = Date.now()) { prune(now); return structuredClone([...rules.values()]); },
  };
}
// Only redacted metadata goes to xdr/alerts.log. No raw request, tokens or users.
export async function appendAlert(alert, decision, logPath = defaultLog) {
  if (!['block', 'alert'].includes(decision?.action)) return false;
  const row = readAlert(alert);
  const allowed = /^(jndi-remote-header|jndi-remote-query|cve-reference-review|scanner-trace-review)/u;
  const entry = {
    schema: 'aleph.xdr.alert.v1', moduleKey: 'known-cve',
    alertId: evidenceId(alert?.id) ? alert.id : '',
    timestamp: row.timestamp, action: decision.action,
    confidence: Number.isFinite(decision.confidence) ? decision.confidence : 0,
    pattern: allowed.exec(decision.reason ?? '')?.[1] ?? 'review-required',
  };
  await mkdir(dirname(logPath), { recursive: true });
  await appendFile(logPath, JSON.stringify(entry) + '\n', 'utf8');
  return true;
}
// Enforcement requires server-verified IP AND a verified exploit match on the
// CURRENT request. An IP-only deny would also block innocent shared-IP users.
// The engine-owned denyResponse must use a registered reason code and contract.
export function withXdrGuard(baseDecide, { store, resolveVerifiedSourceIp, hasVerifiedExploit, denyResponse, now = Date.now }) {
  if ([baseDecide, resolveVerifiedSourceIp, hasVerifiedExploit, denyResponse, now].some(x => typeof x !== 'function')
      || !store || typeof store.check !== 'function') throw new TypeError('trusted_ZTNA_adapter_required');
  return async request => {
    const original = await baseDecide(request);
    const ip = await resolveVerifiedSourceIp(request);
    if (typeof ip !== 'string' || !isIP(ip)) throw new TypeError('verified_source_ip_required');
    const rule = store.check(ip, now());
    if (!rule || !await hasVerifiedExploit(request, rule) || original?.decision === 'deny') return original;
    const response = await denyResponse(request, rule);
    if (response?.schema !== 'aleph.decision.v1' || response.requestId !== request?.requestId
        || response.decision !== 'deny' || typeof response.reasonCode !== 'string'
        || !Array.isArray(response.ruleIds) || !response.ruleIds.includes(rule.ruleId)
        || Object.keys(response).sort().join(',') !== 'decision,reasonCode,requestId,ruleIds,schema') {
      throw new TypeError('invalid_registered_ZTNA_denial');
    }
    return response;
  };
}

// Optional adapter: keep logs and ZTNA enforcement strictly outside decide.mjs.
import { appendFile, mkdir } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { decide } from './decide.mjs';
import { readAlert } from './read-alerts.mjs';

const TTL_MS = 15 * 60 * 1000;
const defaultLog = join(dirname(fileURLToPath(import.meta.url)), '../alerts.log');
const validId = value => typeof value === 'string' && /^[a-z0-9][a-z0-9._-]{0,99}$/iu.test(value);
const validEvidenceId = value => typeof value === 'string' && /^[A-Za-z0-9_-]{1,80}$/u.test(value);

export function createDenyStore() {
  const rules = new Map();
  function prune(now) {
    if (!Number.isFinite(now)) throw new TypeError('invalid_time');
    for (const [deviceId, rule] of rules) {
      if (Date.parse(rule.expiresAt) <= now) rules.delete(deviceId);
    }
  }
  return {
    add(alert, candidate, now = Date.now()) {
      prune(now);
      const verified = decide(alert);
      const row = readAlert(alert);
      // The calling Wazuh collector must have authenticated the alert's agent.
      // Never create account-wide or source-IP bans from an alert.
      const deviceId = alert?.agent?.id ?? alert?.agent?.name;
      if (!validEvidenceId(alert?.id) || !validId(deviceId) || !row.timestamp
          || candidate?.action !== 'block' || verified.action !== 'block'
          || candidate.confidence !== verified.confidence || candidate.reason !== verified.reason)
        return null;
      const at = Date.parse(row.timestamp);
      const expires = at + TTL_MS;
      if (at > now || expires <= now) return null;
      const prior = rules.get(deviceId);
      const rule = {
        ruleId: 'xdr.persistence',
        deviceId,
        action: 'deny',
        createdAt: prior?.createdAt ?? row.timestamp,
        expiresAt: new Date(Math.max(expires, prior ? Date.parse(prior.expiresAt) : 0)).toISOString(),
        evidenceAlertIds: [...new Set([...(prior?.evidenceAlertIds ?? []), alert.id])].slice(-100),
      };
      rules.set(deviceId, rule);
      return structuredClone(rule);
    },
    check(verifiedDeviceId, now = Date.now()) {
      prune(now);
      if (!validId(verifiedDeviceId)) throw new TypeError('verified_device_required');
      const found = rules.get(verifiedDeviceId);
      return found ? structuredClone(found) : null;
    },
    snapshot(now = Date.now()) { prune(now); return structuredClone([...rules.values()]); },
  };
}

// Store a minimal newline-delimited alert, never account, full path, executable
// command, log payload, source address, password, token or private key.
export async function appendAlert(alert, candidate, logPath = defaultLog) {
  if (!['block', 'alert'].includes(candidate?.action)) return false;
  const row = readAlert(alert);
  const verified = decide(alert);
  if (!validEvidenceId(alert?.id) || !row.timestamp || verified.action !== candidate.action
      || verified.confidence !== candidate.confidence || verified.reason !== candidate.reason)
    return false;
  const pattern = /^(unsigned-service-install|suspicious-scheduled-task|unlisted-startup-entry|combined-autostart|persistence-review)$/u;
  const entry = {
    schema: 'aleph.xdr.alert.v1', moduleKey: 'persistence',
    alertId: alert.id, timestamp: row.timestamp,
    action: candidate.action, confidence: candidate.confidence,
    pattern: pattern.test(candidate.reason) ? candidate.reason : 'review-required',
  };
  await mkdir(dirname(logPath), { recursive: true });
  await appendFile(logPath, JSON.stringify(entry) + '\n', 'utf8');
  return true;
}

// An engine-side, verified device identity is REQUIRED; incoming user-supplied
// request.device and srcip are never trusted as quarantine identities.
// Denial structure/reason code comes from a registered engine callback.
export function withXdrGuard(baseDecide, { store, resolveVerifiedDeviceId, denyResponse, now = Date.now }) {
  if ([baseDecide, resolveVerifiedDeviceId, denyResponse, now].some(value => typeof value !== 'function')
      || !store || typeof store.check !== 'function') throw new TypeError('trusted_ZTNA_adapter_required');
  return async request => {
    const existing = await baseDecide(request);
    if (existing?.decision === 'deny') return existing;
    const id = await resolveVerifiedDeviceId(request);
    if (!validId(id)) throw new TypeError('verified_device_required');
    const rule = store.check(id, now());
    if (!rule) return existing;
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

// Optional ZTNA adapter: authentication integration, writing and alerts stay OUTSIDE decide.mjs.
import { appendFile, mkdir } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { decide } from './decide.mjs';
import { readAlert } from './read-alerts.mjs';

const TTL_MS = 15 * 60 * 1000;
const DEFAULT_LOG = join(dirname(fileURLToPath(import.meta.url)), '../alerts.log');
const validAlertId = x => typeof x === 'string' && /^[A-Za-z0-9_-]{1,80}$/u.test(x);
const validAccount = x => typeof x === 'string' && /^[a-zA-Z0-9._@-]{1,100}$/u.test(x);
export function createRevokeStore() {
  const rules = new Map();
  function prune(now) {
    if (!Number.isFinite(now)) throw new TypeError('invalid_time');
    for (const [account, rule] of rules)
      if (Date.parse(rule.expiresAt) <= now) rules.delete(account);
  }
  return {
    // The caller must authenticate the Wazuh collector and the account identifier.
    // Never trust a login request's own claimed account or raw alert srcuser alone.
    add(alert, verdict, verifiedAccount, now = Date.now()) {
      prune(now);
      const row = readAlert(alert), checked = decide(alert);
      if (!validAlertId(alert?.id) || !validAccount(verifiedAccount)
          || row.account !== verifiedAccount || !row.timestamp
          || checked.action !== 'block' || verdict?.action !== 'block'
          || verdict.confidence !== checked.confidence || verdict.reason !== checked.reason)
        return null;
      const at = Date.parse(row.timestamp), expires = at + TTL_MS;
      if (at > now || expires <= now) return null;
      const previous = rules.get(verifiedAccount);
      const rule = {
        ruleId: 'xdr.privilege', accountId: verifiedAccount, action: 'deny',
        createdAt: previous?.createdAt ?? row.timestamp,
        expiresAt: new Date(Math.max(expires, previous ? Date.parse(previous.expiresAt) : 0)).toISOString(),
        evidenceAlertIds: [...new Set([...(previous?.evidenceAlertIds ?? []), alert.id])].slice(-100),
      };
      rules.set(verifiedAccount, rule);
      return structuredClone(rule);
    },
    check(verifiedAccount, now = Date.now()) {
      prune(now);
      if (!validAccount(verifiedAccount)) throw new TypeError('verified_account_required');
      const active = rules.get(verifiedAccount);
      return active ? structuredClone(active) : null;
    },
    snapshot(now = Date.now()) {
      prune(now);
      return structuredClone([...rules.values()]);
    },
  };
}
export async function appendAlert(alert, verdict, logPath = DEFAULT_LOG) {
  if (!['block','alert'].includes(verdict?.action) || !validAlertId(alert?.id)) return false;
  const row = readAlert(alert), checked = decide(alert);
  if (!row.timestamp || checked.action !== verdict.action
      || checked.confidence !== verdict.confidence || checked.reason !== verdict.reason)
    return false;
  const known = /^(unexpected-admin-group-grant|post-elevation-command|unusual-admin-command|cross-account-admin-use|rapid-admin-regrant|privilege-review)$/u;
  const entry = {
    schema:'aleph.xdr.alert.v1', moduleKey:'privilege',
    alertId:alert.id, timestamp:row.timestamp, action:verdict.action,
    confidence:verdict.confidence,
    pattern: known.test(verdict.reason) ? verdict.reason : 'privilege-review',
  };
  await mkdir(dirname(logPath),{recursive:true});
  await appendFile(logPath, JSON.stringify(entry)+'\n','utf8');
  return true;
}
// Engine verifies identity and supplies the registered denial constructor.
// Until wired into the SDP engine this is an in-memory deny guard,
// NOT proof of remote JWT/token/session invalidation.
export function withXdrGuard(baseDecide,{store,resolveVerifiedAccount,denyResponse,now=Date.now}) {
  if ([baseDecide,resolveVerifiedAccount,denyResponse,now].some(x=>typeof x!=='function')
      || !store || typeof store.check!=='function') throw new TypeError('trusted_ZTNA_adapter_required');
  return async request=>{
    const current=await baseDecide(request);
    if (current?.decision==='deny') return current;
    const verifiedAccount=await resolveVerifiedAccount(request);
    if (!validAccount(verifiedAccount)) throw new TypeError('verified_account_required');
    const active=store.check(verifiedAccount,now());
    if (!active) return current;
    const response=await denyResponse(request,active);
    if (response?.schema!=='aleph.decision.v1' || response.requestId!==request?.requestId
        || response.decision!=='deny' || typeof response.reasonCode!=='string'
        || !Array.isArray(response.ruleIds) || !response.ruleIds.includes(active.ruleId)
        || Object.keys(response).sort().join(',')!=='decision,reasonCode,requestId,ruleIds,schema')
      throw new TypeError('invalid_registered_ZTNA_denial');
    return response;
  };
}

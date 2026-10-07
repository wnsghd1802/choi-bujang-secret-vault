import { appendFile, mkdir } from 'node:fs/promises';
import { dirname } from 'node:path';
import { isIP } from 'node:net';
import { digest, readAlert } from './read-alerts.mjs';
import { patterns } from './decide.mjs';

export function createDenyStore() {
  const rules = new Map();
  function prune(now) {
    if (!Number.isFinite(now)) throw new Error('검증된 시각이 필요합니다.');
    for (const [sourceIp, rule] of rules) if (Date.parse(rule.expiresAt) <= now) rules.delete(sourceIp);
  }
  return {
    add(alert, decision, now = Date.now()) {
      prune(now);
      const row = readAlert(alert);
      const confidence = decision?.confidence;
      if (decision?.action !== 'block' || !Number.isFinite(confidence) || confidence < 0.85 || confidence > 1 ||
          !row.sourceIp || !row.timestamp || typeof alert?.id !== 'string') return null;
      const created = Date.parse(row.timestamp);
      const expires = created + patterns.blockTtlSeconds * 1000;
      // Old replays cannot renew bans; future events cannot ban present users.
      if (created > now || expires <= now) return null;
      const prior = rules.get(row.sourceIp);
      const evidenceId = `event-${digest(alert.id)}`;
      const rule = { ruleId: 'xdr.brute-force', sourceIp: row.sourceIp, action: 'deny',
        createdAt: prior?.createdAt ?? row.timestamp,
        expiresAt: new Date(Math.max(expires, prior ? Date.parse(prior.expiresAt) : 0)).toISOString(),
        evidenceIds: [...new Set([...(prior?.evidenceIds ?? []), evidenceId])].slice(-100) };
      rules.set(row.sourceIp, rule);
      return structuredClone(rule);
    },
    check(sourceIp, now = Date.now()) {
      prune(now);
      if (typeof sourceIp !== 'string' || !isIP(sourceIp)) throw new Error('서버가 확인한 출발 주소가 필요합니다.');
      const rule = rules.get(sourceIp);
      return rule ? structuredClone(rule) : null;
    },
    snapshot(now = Date.now()) { prune(now); return structuredClone([...rules.values()]); },
  };
}

export async function appendAlert(logPath, alert, decision) {
  if (!['block', 'alert'].includes(decision?.action)) return;
  const row = readAlert(alert);
  const event = { schema: 'aleph.xdr.alert.v1', eventRef: `event-${digest(alert?.id ?? '')}`,
    timestamp: row.timestamp, action: decision.action, confidence: decision.confidence,
    // Deliberately exclude raw reasons, logs, IPs, accounts and arbitrary model output.
    pattern: /^(repeated-failures|password-spray|multi-account-failures|ambiguous-failures|invalid-alert):/u.exec(decision.reason ?? '')?.[1] ?? 'review-required' };
  await mkdir(dirname(logPath), { recursive: true });
  await appendFile(logPath, `${JSON.stringify(event)}\n`, 'utf8');
}

// Engine adapter: the existing request contract is untouched. The host supplies
// verified transport metadata and its OWN registered deny response constructor.
export function withXdrGuard(baseDecide, { store, resolveVerifiedSourceIp, denyResponse, now = Date.now }) {
  if (![baseDecide, resolveVerifiedSourceIp, denyResponse, now].every(value => typeof value === 'function') || !store) {
    throw new Error('기존 판정기, 검증된 주소 공급자, 등록된 거부 응답 함수가 필요합니다.');
  }
  return async request => {
    const ip = await resolveVerifiedSourceIp(request);
    const rule = store.check(ip, now());
    if (!rule) return baseDecide(request);
    const response = await denyResponse(request, rule);
    if (response?.decision !== 'deny' || response.requestId !== request.requestId || response.schema !== 'aleph.decision.v1' ||
        typeof response.reasonCode !== 'string' || !Array.isArray(response.ruleIds) || response.ruleIds.length === 0 ||
        Object.keys(response).sort().join(',') !== 'decision,reasonCode,requestId,ruleIds,schema') {
      throw new Error('엔진에 등록된 거부 응답 계약과 맞지 않습니다.');
    }
    return response;
  };
}

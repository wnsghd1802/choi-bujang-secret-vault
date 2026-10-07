import { appendFile, mkdir } from 'node:fs/promises';
import { dirname } from 'node:path';
import { isIP } from 'node:net';
import { readAlert } from './read-alerts.mjs';
import { patterns } from './decide.mjs';

export function createDenyStore() {
  const rules = new Map();
  function prune(now) {
    if (!Number.isFinite(now)) throw new Error('검증된 시각이 필요합니다.');
    for (const [sourceAddress, rule] of rules) {
      if (Date.parse(rule.expiresAt) <= now) rules.delete(sourceAddress);
    }
  }
  return {
    add(alert, decision, now = Date.now()) {
      prune(now);
      const row = readAlert(alert);
      const confidence = decision?.confidence;
      if (decision?.action !== 'block' || !Number.isFinite(confidence) || confidence < 0.85 || confidence > 1
          || !row.sourceAddress || !row.timestamp || typeof alert?.id !== 'string') return null;

      const created = Date.parse(row.timestamp);
      const expires = created + patterns.blockTtlSeconds * 1000;
      if (created > now || expires <= now) return null;

      const prior = rules.get(row.sourceAddress);
      const rule = {
        ruleId: 'xdr.brute-force',
        sourceAddress: row.sourceAddress,
        action: 'deny',
        createdAt: prior?.createdAt ?? row.timestamp,
        expiresAt: new Date(Math.max(expires, prior ? Date.parse(prior.expiresAt) : 0)).toISOString(),
        evidenceAlertIds: [...new Set([...(prior?.evidenceAlertIds ?? []), alert.id])].slice(-100),
      };
      rules.set(row.sourceAddress, rule);
      return structuredClone(rule);
    },
    check(sourceAddress, now = Date.now()) {
      prune(now);
      if (typeof sourceAddress !== 'string' || !isIP(sourceAddress)) throw new Error('서버가 확인한 출발 주소가 필요합니다.');
      const rule = rules.get(sourceAddress);
      return rule ? structuredClone(rule) : null;
    },
    snapshot(now = Date.now()) {
      prune(now);
      return structuredClone([...rules.values()]);
    },
  };
}

export async function appendAlert(logPath, alert, decision) {
  if (!['block', 'alert'].includes(decision?.action)) return;
  const row = readAlert(alert);
  const event = {
    schema: 'aleph.xdr.alert.v1',
    alertId: typeof alert?.id === 'string' ? alert.id : '',
    timestamp: row.timestamp,
    action: decision.action,
    confidence: decision.confidence,
    pattern: /^(rapid-same-source-failures|password-spray|normal-event):/u.exec(decision.reason ?? '')?.[1] ?? 'review-required',
  };
  await mkdir(dirname(logPath), { recursive: true });
  await appendFile(logPath, `${JSON.stringify(event)}\n`, 'utf8');
}

export function withXdrGuard(baseDecide, { store, resolveVerifiedSourceIp, denyResponse, now = Date.now }) {
  if (![baseDecide, resolveVerifiedSourceIp, denyResponse, now].every(value => typeof value === 'function') || !store) {
    throw new Error('기존 판정기, 검증된 주소 공급자, 등록된 거부 응답 함수가 필요합니다.');
  }
  return async request => {
    const sourceAddress = await resolveVerifiedSourceIp(request);
    const rule = store.check(sourceAddress, now());
    if (!rule) return baseDecide(request);
    const response = await denyResponse(request, rule);
    if (response?.decision !== 'deny' || response.requestId !== request.requestId || response.schema !== 'aleph.decision.v1'
        || typeof response.reasonCode !== 'string' || !Array.isArray(response.ruleIds) || response.ruleIds.length === 0
        || Object.keys(response).sort().join(',') !== 'decision,reasonCode,requestId,ruleIds,schema') {
      throw new Error('엔진에 등록된 거부 응답 계약과 맞지 않습니다.');
    }
    return response;
  };
}

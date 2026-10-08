import { appendFile, mkdir } from 'node:fs/promises';
import { dirname } from 'node:path';
import { isIP } from 'node:net';
import { readAlert } from './read-alerts.mjs';
import { patterns } from './decide.mjs';

export function createDenyStore() {
  const rules = new Map();
  const prune = now => {
    if (!Number.isFinite(now)) throw new TypeError('검증된 시각이 필요합니다.');
    for (const [ip, rule] of rules) if (Date.parse(rule.expiresAt) <= now) rules.delete(ip);
  };
  return {
    add(alert, decision, now = Date.now()) {
      prune(now);
      const f = readAlert(alert);
      if (decision?.action !== 'block' || !Number.isFinite(decision.confidence)
          || decision.confidence < 0.85 || decision.confidence > 1 || !f.timestamp || !f.sourceAddress
          || typeof alert?.id !== 'string') return null;
      const created = Date.parse(f.timestamp);
      const expires = created + patterns.blockTtlSeconds * 1000;
      if (created > now || expires <= now) return null;
      const previous = rules.get(f.sourceAddress);
      const rule = {
        ruleId: 'xdr.web-injection', sourceAddress: f.sourceAddress, action: 'deny',
        createdAt: previous?.createdAt ?? f.timestamp,
        expiresAt: new Date(Math.max(expires, previous ? Date.parse(previous.expiresAt) : 0)).toISOString(),
        evidenceAlertIds: [...new Set([...(previous?.evidenceAlertIds ?? []), alert.id])].slice(-100),
      };
      rules.set(f.sourceAddress, rule);
      return structuredClone(rule);
    },
    check(ip, now = Date.now()) {
      prune(now);
      if (typeof ip !== 'string' || !isIP(ip)) throw new TypeError('엔진이 확인한 출발 IP가 필요합니다.');
      return rules.has(ip) ? structuredClone(rules.get(ip)) : null;
    },
    snapshot(now = Date.now()) { prune(now); return structuredClone([...rules.values()]); },
  };
}

export async function appendAlert(logPath, alert, decision) {
  if (decision?.action !== 'block' && decision?.action !== 'alert') return;
  const f = readAlert(alert);
  const entry = {
    schema: 'aleph.xdr.alert.v1',
    moduleKey: 'web-injection',
    alertId: typeof alert?.id === 'string' ? alert.id : '',
    timestamp: f.timestamp,
    action: decision.action,
    confidence: decision.confidence,
    pattern: /^(sql-injection|script-injection|path-traversal|command-injection|review-required)/u.exec(decision.reason ?? '')?.[1] ?? 'review-required',
  };
  await mkdir(dirname(logPath), { recursive: true });
  await appendFile(logPath, JSON.stringify(entry) + '\n', 'utf8');
}

// 운영 연결 부품: 현재 요청 계약에 없는 출발 IP는 절대 추정하지 않습니다.
export function withXdrGuard(baseDecide, { store, resolveVerifiedSourceIp, denyResponse, now = Date.now }) {
  if ([baseDecide, resolveVerifiedSourceIp, denyResponse, now].some(fn => typeof fn !== 'function') || !store) {
    throw new TypeError('기존 판정기, 검증된 IP 공급자, 기존 deny 응답 함수가 필요합니다.');
  }
  return async request => {
    const ip = await resolveVerifiedSourceIp(request);
    const deny = store.check(ip, now());
    if (!deny) return baseDecide(request);
    const response = await denyResponse(request, deny);
    if (response?.schema !== 'aleph.decision.v1' || response.decision !== 'deny'
      || response.requestId !== request.requestId || typeof response.reasonCode !== 'string'
      || !Array.isArray(response.ruleIds) || response.ruleIds.length < 1
      || Object.keys(response).sort().join(',') !== 'decision,reasonCode,requestId,ruleIds,schema') {
      throw new TypeError('기존 ZTNA 거부 응답 계약과 맞지 않습니다.');
    }
    return response;
  };
}

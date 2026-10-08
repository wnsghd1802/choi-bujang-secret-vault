import { appendFile, mkdir } from 'node:fs/promises';
import { dirname } from 'node:path';
import { isIP } from 'node:net';
import { readAlert } from './read-alerts.mjs';

const TTL_MS = 15 * 60 * 1000;
export function createDenyStore() {
  const rules = new Map();
  function prune(at) {
    if (!Number.isFinite(at)) throw new TypeError('유효한 현재 시각이 필요합니다.');
    for (const [ip, rule] of rules) if (Date.parse(rule.expiresAt) <= at) rules.delete(ip);
  }
  return {
    add(alert, decision, now = Date.now()) {
      prune(now);
      const row = readAlert(alert);
      if (decision?.action !== 'block' || !Number.isFinite(decision.confidence)
        || decision.confidence < 0.85 || decision.confidence > 1 || !row.sourceAddress || !row.timestamp
        || typeof alert?.id !== 'string' || !/^[\w-]{1,80}$/u.test(alert.id)) return null;
      const start = Date.parse(row.timestamp);
      const expiration = start + TTL_MS;
      if (start > now || expiration <= now) return null;
      const prev = rules.get(row.sourceAddress);
      const candidate = {
        ruleId: 'xdr.web-injection',
        sourceAddress: row.sourceAddress,
        action: 'deny',
        createdAt: prev?.createdAt ?? row.timestamp,
        expiresAt: new Date(Math.max(expiration, prev ? Date.parse(prev.expiresAt) : 0)).toISOString(),
        evidenceAlertIds: [...new Set([...(prev?.evidenceAlertIds ?? []), alert.id])].slice(-100),
      };
      rules.set(row.sourceAddress, candidate);
      return structuredClone(candidate);
    },
    check(verifiedIp, now = Date.now()) {
      prune(now);
      if (!isIP(verifiedIp)) throw new TypeError('신뢰할 수 있는 IP가 필요합니다.');
      const rule = rules.get(verifiedIp);
      return rule ? structuredClone(rule) : null;
    },
    snapshot(now = Date.now()) { prune(now); return structuredClone([...rules.values()]); },
  };
}

// IP·계정·URL·원문·토큰은 감사 로그에 쓰지 않습니다. block/alert만 한 줄씩 추가합니다.
export async function appendAlert(logPath, alert, decision) {
  if (decision?.action !== 'block' && decision?.action !== 'alert') return;
  const row = readAlert(alert);
  const matched = /^(sql-injection|script-injection|path-traversal|command-injection|review-required)/u.exec(decision.reason ?? '');
  const entry = {
    schema: 'aleph.xdr.alert.v1', moduleKey: 'web-injection',
    alertId: /^[\w-]{1,80}$/u.test(alert?.id ?? '') ? alert.id : '',
    timestamp: row.timestamp, action: decision.action,
    confidence: Number.isFinite(decision.confidence) ? decision.confidence : 0,
    pattern: matched?.[1] ?? 'review-required',
  };
  await mkdir(dirname(logPath), { recursive: true });
  await appendFile(logPath, JSON.stringify(entry) + '\n', 'utf8');
}

// 연결 어댑터일 뿐, ZTNA 엔진에 없는 IP 필드/이유 코드를 새로 만들어 넣지 않습니다.
// resolveVerifiedSourceIp는 신뢰 가능한 엔진 쪽에서 주입해야 하고,
// denyResponse는 기존에 등록된 거부 응답 생성자여야 합니다.
export function withXdrGuard(baseDecide, { store, resolveVerifiedSourceIp, denyResponse, now = Date.now }) {
  if ([baseDecide, resolveVerifiedSourceIp, denyResponse, now].some(v => typeof v !== 'function') || !store) {
    throw new TypeError('기존 ZTNA 판정기와 검증된 주소/거부 응답 공급자가 필요합니다.');
  }
  return async request => {
    const ip = await resolveVerifiedSourceIp(request);
    if (!isIP(ip)) throw new TypeError('검증되지 않은 출발 주소로 판정할 수 없습니다.');
    const rule = store.check(ip, now());
    if (!rule) return baseDecide(request);
    const response = await denyResponse(request, rule);
    if (response?.schema !== 'aleph.decision.v1' || response.requestId !== request?.requestId
      || response.decision !== 'deny' || typeof response.reasonCode !== 'string'
      || !Array.isArray(response.ruleIds) || !response.ruleIds.includes(rule.ruleId)
      || Object.keys(response).sort().join(',') !== 'decision,reasonCode,requestId,ruleIds,schema') {
      throw new TypeError('기존 ZTNA 응답 계약과 다릅니다.');
    }
    return response;
  };
}

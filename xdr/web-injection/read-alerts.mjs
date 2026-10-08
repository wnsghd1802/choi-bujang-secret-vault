import { readFile } from 'node:fs/promises';
import { isIP } from 'node:net';

export const fixtureUrl = new URL('../fixtures/web-injection.json', import.meta.url);
const PRIVATE_DATA = [
  /\bBearer\s+\S+/giu,
  /(?:\b(?:password|passwd|pwd|secret|token|api[_-]?key)\b|비밀번호|암호|토큰)\s*[:=]\s*(?:"[^"]*"|'[^']*'|[^\s,;&]+)/giu,
  /\beyJ[\w-]+\.[\w-]+\.[\w-]+\b/gu,
  /\b(?:sk[-_]|sb_secret_)[\w-]+/gu,
  /[\w.+-]+@[\w.-]+\.[a-z]{2,}/giu,
  /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/gu,
];
export function safeText(value, max = 500) {
  let text = typeof value === 'string' ? value : '';
  for (const secret of PRIVATE_DATA) text = text.replace(secret, '[REDACTED]');
  return text.replace(/[\r\n\u0000-\u001f]/gu, ' ').slice(0, max);
}
const nonNegativeInt = value => /^(?:0|[1-9]\d{0,8})$/u.test(String(value ?? '')) ? Number(value) : null;
export function readAlert(alert) {
  const rawTime = alert?.timestamp ?? alert?.time;
  const rawIp = alert?.data?.srcip ?? alert?.sourceAddress;
  const rawLevel = alert?.rule?.level ?? alert?.ruleLevel;
  const level = Number(rawLevel);
  const description = safeText(alert?.rule?.description ?? alert?.description);
  const url = safeText(alert?.data?.url ?? alert?.url);
  const declaredCount = nonNegativeInt(alert?.data?.count ?? alert?.count);
  const descriptionCounts = [...description.matchAll(/(\d+)\s*(?:건|번|회)(?:\s|$|[.,])/gu)].map(match => Number(match[1]));
  const mitre = alert?.rule?.mitre;
  return {
    timestamp: typeof rawTime === 'string' && Number.isFinite(Date.parse(rawTime)) ? new Date(rawTime).toISOString() : null,
    sourceAddress: typeof rawIp === 'string' && isIP(rawIp) ? rawIp : null,
    ruleLevel: Number.isInteger(level) && level >= 0 && level <= 16 ? level : null,
    description, url,
    count: declaredCount ?? (descriptionCounts.length ? Math.max(...descriptionCounts) : null),
    mitre: Array.isArray(mitre) ? mitre.filter(item => typeof item === 'string').slice(0, 12) : [],
  };
}
export async function loadFixture(source = fixtureUrl) {
  const fixture = source && typeof source === 'object' && !(source instanceof URL) && !Array.isArray(source)
    ? source : JSON.parse(await readFile(source, 'utf8'));
  if (fixture?.schema !== 'aleph.xdr.fixture.v1' || fixture.moduleKey !== 'web-injection' || !Array.isArray(fixture.alerts)) {
    throw new TypeError('invalid_web_injection_fixture');
  }
  return fixture;
}
export async function readAlerts(source = fixtureUrl) {
  return (await loadFixture(source)).alerts.map(readAlert);
}

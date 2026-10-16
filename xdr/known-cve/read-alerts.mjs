// Read-only, redacted Wazuh fixture parser. Never export raw user agents or URL bodies.
import { readFile } from 'node:fs/promises';
import { isIP } from 'node:net';

export const fixtureUrl = new URL('../fixtures/known-cve.json', import.meta.url);
const SECRET_PATTERNS = [
  /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/giu,
  /\bBearer\s+[^\s,;]+/giu,
  /\b(?:password|passwd|pwd|secret|token|api[_-]?key)\s*[:=]\s*(?:"[^"]*"|'[^']*'|[^\s,;]+)/giu,
  /\beyJ[\w-]+\.[\w-]+\.[\w-]+\b/gu,
  /\b(?:sk[-_]|sb_secret_)[\w-]+/gu,
  /[\w.+-]+@[\w.-]+\.[a-z]{2,}/giu,
];
function safeText(input, length = 300) {
  let value = typeof input === 'string' ? input.slice(0, 4000) : '';
  for (const re of SECRET_PATTERNS) value = value.replace(re, '[REDACTED]');
  return value.replace(/[\u0000-\u001f\u007f]/gu, ' ').slice(0, length);
}
export function readAlert(alert) {
  const date = alert?.timestamp ?? alert?.time;
  const ip = alert?.data?.srcip ?? alert?.sourceAddress;
  const level = Number(alert?.rule?.level ?? alert?.ruleLevel);
  return {
    timestamp: typeof date === 'string' && Number.isFinite(Date.parse(date))
      ? new Date(date).toISOString() : null,
    sourceAddress: typeof ip === 'string' && isIP(ip) ? ip : null,
    account: safeText(alert?.data?.srcuser ?? alert?.account, 100),
    ruleLevel: Number.isInteger(level) && level >= 0 && level <= 16 ? level : null,
    description: safeText(alert?.rule?.description ?? alert?.description),
  };
}
export async function loadFixture(source = fixtureUrl) {
  const data = source && typeof source === 'object' && !(source instanceof URL) && !Array.isArray(source)
    ? source : JSON.parse(await readFile(source, 'utf8'));
  if (data?.schema !== 'aleph.xdr.fixture.v1' || data.moduleKey !== 'known-cve'
      || !Array.isArray(data.alerts)) throw new TypeError('invalid_known_cve_fixture');
  return data;
}
export async function readAlerts(source = fixtureUrl) {
  return (await loadFixture(source)).alerts.map(readAlert);
}

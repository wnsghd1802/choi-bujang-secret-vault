import { readFile } from 'node:fs/promises';
import { isIP } from 'node:net';

export const fixtureUrl = new URL('../fixtures/web-injection.json', import.meta.url);
const REDACT = [
  /\bBearer\s+\S+/giu,
  /(?:\b(?:password|passwd|pwd|secret|token|api[_-]?key)\b|비밀번호|암호|토큰)\s*[:=]\s*(?:"[^"]*"|'[^']*'|[^\s,;]+)/giu,
  /\beyJ[\w-]+\.[\w-]+\.[\w-]+\b/gu,
  /\b(?:sk[-_]|sb_secret_)[\w-]+/gu,
  /[\w.+-]+@[\w.-]+\.[a-z]{2,}/giu,
  /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/gu,
];
export function safeText(value, maxLength = 500) {
  let text = typeof value === 'string' ? value : '';
  for (const re of REDACT) text = text.replace(re, '[REDACTED]');
  return text.replace(/[\r\n\u0000-\u001f]/gu, ' ').slice(0, maxLength);
}
export function readAlert(alert) {
  const date = alert?.timestamp ?? alert?.time;
  const address = alert?.data?.srcip ?? alert?.sourceAddress;
  const rawLevel = alert?.rule?.level ?? alert?.ruleLevel;
  const level = Number(rawLevel);
  const rawCount = alert?.data?.count ?? alert?.count;
  const count = /^(?:0|[1-9]\d{0,8})$/u.test(String(rawCount ?? '')) ? Number(rawCount) : null;
  const rawTags = alert?.rule?.mitre ?? alert?.mitre;
  return {
    timestamp: typeof date === 'string' && Number.isFinite(Date.parse(date)) ? new Date(date).toISOString() : null,
    sourceAddress: typeof address === 'string' && isIP(address) ? address : null,
    account: safeText(alert?.data?.srcuser ?? alert?.account),
    ruleLevel: Number.isInteger(level) && level >= 0 && level <= 16 ? level : null,
    description: safeText(alert?.rule?.description ?? alert?.description),
    url: safeText(alert?.data?.url ?? alert?.url),
    count,
    mitre: Array.isArray(rawTags) ? rawTags.filter(v => typeof v === 'string').slice(0, 12) : [],
  };
}
export async function loadFixture(source = fixtureUrl) {
  const data = source && typeof source === 'object' && !(source instanceof URL) && !Array.isArray(source)
    ? source : JSON.parse(await readFile(source, 'utf8'));
  if (data?.schema !== 'aleph.xdr.fixture.v1' || data?.moduleKey !== 'web-injection' || !Array.isArray(data.alerts)) {
    throw new TypeError('invalid_web_injection_fixture');
  }
  return data;
}
export async function readAlerts(source = fixtureUrl) {
  return (await loadFixture(source)).alerts.map(readAlert);
}

import { readFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { isIP } from 'node:net';

export const fixtureUrl = new URL('../fixtures/brute-force.json', import.meta.url);
export const digest = value => createHash('sha256').update(String(value)).digest('hex').slice(0, 24);

const SECRET_LIKE = [
  /\bBearer\s+\S+/giu,
  /(?:\b(?:password|passwd|pwd|secret|token|api[_-]?key)\b|비밀번호|암호|토큰)\s*[:=]\s*(?:"[^"]*"|'[^']*'|[^\s,;]+)/giu,
  /\beyJ[\w-]+\.[\w-]+\.[\w-]+\b/gu,
  /\b(?:sk[-_]|sb_secret_)[\w-]+/gu,
  /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/gu,
  /[\w.+-]+@[\w.-]+\.[a-z]{2,}/giu,
];

export function safeDescription(value) {
  let text = typeof value === 'string' ? value : '';
  for (const pattern of SECRET_LIKE) text = text.replace(pattern, '[REDACTED]');
  return text.replace(/[\r\n\u0000-\u001f]/gu, ' ').slice(0, 500);
}

const safeAccount = value => {
  const text = safeDescription(value);
  return /[\w.+-]+@[\w.-]+\.[a-z]{2,}/iu.test(text) ? '[REDACTED]' : text;
};

export function readAlert(alert) {
  const rawTimestamp = alert?.timestamp ?? alert?.time ?? alert?.at;
  const rawSource = alert?.data?.srcip ?? alert?.sourceAddress ?? alert?.sourceIp ?? alert?.srcip;
  const rawAccount = alert?.data?.srcuser ?? alert?.account ?? alert?.srcuser ?? alert?.user ?? '';
  const rawLevel = alert?.rule?.level ?? alert?.ruleLevel ?? alert?.level;
  const rawDescription = alert?.rule?.description ?? alert?.description;
  const level = Number(rawLevel);

  return {
    timestamp: typeof rawTimestamp === 'string' && Number.isFinite(Date.parse(rawTimestamp))
      ? new Date(rawTimestamp).toISOString() : null,
    sourceAddress: typeof rawSource === 'string' && isIP(rawSource) ? rawSource : null,
    account: safeAccount(rawAccount),
    ruleLevel: Number.isInteger(level) && level >= 0 && level <= 16 ? level : null,
    description: safeDescription(rawDescription),
  };
}

export async function loadFixture(source = fixtureUrl) {
  if (source && typeof source === 'object' && !(source instanceof URL) && !Array.isArray(source)) {
    if (source?.schema !== 'aleph.xdr.fixture.v1' || source.moduleKey !== 'brute-force' || !Array.isArray(source.alerts)) {
      throw new TypeError('invalid_brute_force_fixture');
    }
    return source;
  }
  const fixture = JSON.parse(await readFile(source, 'utf8'));
  if (fixture?.schema !== 'aleph.xdr.fixture.v1' || fixture.moduleKey !== 'brute-force' || !Array.isArray(fixture.alerts)) {
    throw new TypeError('invalid_brute_force_fixture');
  }
  return fixture;
}

export async function readAlerts(source = fixtureUrl) {
  return (await loadFixture(source)).alerts.map(readAlert);
}

import { readFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { isIP } from 'node:net';

export const fixtureUrl = new URL('../fixtures/brute-force.json', import.meta.url);
export const digest = value => createHash('sha256').update(String(value)).digest('hex').slice(0, 24);

export function safeDescription(value) {
  if (typeof value !== 'string') return '';
  return value
    .replace(/(?:password|passwd|pwd|token|secret|api[_-]?key|비밀번호)\s*[:=]\s*(?:"[^"]*"|'[^']*'|[^\s,;]+)/giu, '[REDACTED]')
    .replace(/Bearer\s+\S+/giu, '[REDACTED]')
    .replace(/eyJ[\w-]+\.[\w-]+\.[\w-]+/gu, '[REDACTED]')
    .replace(/\b(?:sk[-_]|sb_secret_)[\w-]+/gu, '[REDACTED]')
    .replace(/[\w.+-]+@[\w.-]+\.[a-z]{2,}/giu, '[REDACTED]')
    .replace(/[\r\n\u0000-\u001f]/gu, ' ').slice(0, 500);
}

export function readAlert(alert) {
  const timestamp = typeof alert?.timestamp === 'string' && Number.isFinite(Date.parse(alert.timestamp))
    ? new Date(alert.timestamp).toISOString() : null;
  const account = typeof alert?.data?.srcuser === 'string' ? alert.data.srcuser : '';
  return {
    timestamp,
    sourceIp: typeof alert?.data?.srcip === 'string' && isIP(alert.data.srcip) ? alert.data.srcip : null,
    account: /^user\d{1,6}$/u.test(account) ? account : account ? `account-${digest(account)}` : null,
    level: Number.isInteger(alert?.rule?.level) && alert.rule.level >= 0 && alert.rule.level <= 16 ? alert.rule.level : null,
    description: safeDescription(alert?.rule?.description),
  };
}

export async function loadFixture(url = fixtureUrl) {
  const fixture = JSON.parse(await readFile(url, 'utf8'));
  if (fixture?.schema !== 'aleph.xdr.fixture.v1' || fixture.moduleKey !== 'brute-force' || !Array.isArray(fixture.alerts)) {
    throw new Error('무차별 로그인 경보 형식이 아닙니다.');
  }
  return fixture;
}

export async function readAlerts(url = fixtureUrl) {
  return (await loadFixture(url)).alerts.map(readAlert);
}

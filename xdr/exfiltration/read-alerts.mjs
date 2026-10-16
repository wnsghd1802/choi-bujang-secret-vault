// Wazuh read-only fixture parser; never expose raw URLs, payloads or destinations.
import { readFile } from 'node:fs/promises';
import { isIP } from 'node:net';
export const fixtureUrl = new URL('../fixtures/exfiltration.json', import.meta.url);
const REDACT = [
  /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/giu,
  /\bBearer\s+[^\s,;]+/giu,
  /\b(?:password|passwd|pwd|secret|token|api[_-]?key)\s*[:=]\s*(?:"[^"]*"|'[^']*'|[^\s,;]+)/giu,
  /\beyJ[\w-]+\.[\w-]+\.[\w-]+\b/gu,
  /\b(?:sk[-_]|sb_secret_)[\w-]+/gu,
  /[\w.+-]+@[\w.-]+\.[a-z]{2,}/giu,
];
function safeText(value,length=300){
 let str=typeof value==='string'?value.slice(0,4000):'';
 for(const re of REDACT)str=str.replace(re,'[REDACTED]');
 return str.replace(/[\u0000-\u001f\u007f]/gu,' ').slice(0,length);
}
export function readAlert(alert){
 const date=alert?.timestamp??alert?.time;
 const ip=alert?.data?.srcip??alert?.sourceAddress;
 const level=Number(alert?.rule?.level??alert?.ruleLevel);
 return {
   timestamp:typeof date==='string'&&Number.isFinite(Date.parse(date))?new Date(date).toISOString():null,
   sourceAddress:typeof ip==='string'&&isIP(ip)?ip:null,
   account:safeText(alert?.data?.srcuser??alert?.account,100),
   ruleLevel:Number.isInteger(level)&&level>=0&&level<=16?level:null,
   description:safeText(alert?.rule?.description??alert?.description),
 };
}
export async function loadFixture(source=fixtureUrl){
 const value=source&&typeof source==='object'&&!(source instanceof URL)&&!Array.isArray(source)
   ?source:JSON.parse(await readFile(source,'utf8'));
 if(value?.schema!=='aleph.xdr.fixture.v1'||value.moduleKey!=='exfiltration'||!Array.isArray(value.alerts))
   throw new TypeError('invalid_exfiltration_fixture');
 return value;
}
export async function readAlerts(source=fixtureUrl){
 return (await loadFixture(source)).alerts.map(readAlert);
}

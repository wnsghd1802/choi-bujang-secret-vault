// Stores expiring destination deny candidates and emits redacted alerts.
// The standalone decide.mjs does not import this module or perform any I/O.
import { appendFile, mkdir } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { isIP } from 'node:net';
import { decide } from './decide.mjs';
import { readAlert } from './read-alerts.mjs';
const TTL=15*60*1000;
const DEFAULT_LOG=join(dirname(fileURLToPath(import.meta.url)),'../alerts.log');
const validAlertId=x=>typeof x==='string'&&/^[A-Za-z0-9_-]{1,80}$/u.test(x);
export function createDenyStore(){
 const rules=new Map();
 const prune=now=>{
  if(!Number.isFinite(now))throw new TypeError('invalid_time');
  for(const [dst,rule] of rules)if(Date.parse(rule.expiresAt)<=now)rules.delete(dst);
 };
 return {
  // verifiedDestination is trusted network evidence supplied by the authenticated
  // collector, not a value copied from an untrusted client request.
  add(alert,decision,verifiedDestination,now=Date.now()){
   prune(now);
   const row=readAlert(alert),actual=decide(alert),dst=alert?.data?.dstip;
   if(!validAlertId(alert?.id)||!row.timestamp||!isIP(dst)||!isIP(verifiedDestination)
      ||dst!==verifiedDestination||decision?.action!=='block'||actual.action!=='block'
      ||decision.confidence!==actual.confidence||decision.reason!==actual.reason)return null;
   const at=Date.parse(row.timestamp),expires=at+TTL;
   if(at>now||expires<=now)return null;
   const previous=rules.get(dst);
   const rule={
     ruleId:'xdr.exfiltration',destinationAddress:dst,action:'deny',
     createdAt:previous?.createdAt??row.timestamp,
     expiresAt:new Date(Math.max(expires,previous?Date.parse(previous.expiresAt):0)).toISOString(),
     evidenceAlertIds:[...new Set([...(previous?.evidenceAlertIds??[]),alert.id])].slice(-100),
   };
   rules.set(dst,rule);
   return structuredClone(rule);
  },
  check(verifiedDestination,now=Date.now()){
   prune(now);
   if(!isIP(verifiedDestination))throw new TypeError('verified_destination_required');
   const item=rules.get(verifiedDestination);
   return item?structuredClone(item):null;
  },
  snapshot(now=Date.now()){prune(now);return structuredClone([...rules.values()]);},
 };
}
// No raw IP addresses, users, amounts, URLs or sensitive strings enter alerts.log.
export async function appendAlert(alert,decision,logPath=DEFAULT_LOG){
 if(!['block','alert'].includes(decision?.action)||!validAlertId(alert?.id))return false;
 const row=readAlert(alert),actual=decide(alert);
 if(!row.timestamp||actual.action!==decision.action||actual.confidence!==decision.confidence
    ||actual.reason!==decision.reason)return false;
 const accepted=/^(unknown-destination-bulk|offhours-archive-transfer|repeated-bulk-egress|unusual-port-egress|full-collection-export|exfil-review)$/u;
 const entry={schema:'aleph.xdr.alert.v1',moduleKey:'exfiltration',alertId:alert.id,
   timestamp:row.timestamp,action:decision.action,confidence:decision.confidence,
   pattern:accepted.test(decision.reason)?decision.reason:'exfil-review'};
 await mkdir(dirname(logPath),{recursive:true});
 await appendFile(logPath,JSON.stringify(entry)+'\n','utf8');
 return true;
}
// Engine verifies destination and current suspicious egress before returning an
// engine-registered deny. Innocent users to the same destination are unaffected.
// Never invent request identity, source IP or a new SDP reason code.
export function withXdrGuard(baseDecide,{store,resolveVerifiedDestination,
  currentTransferIsSuspicious,denyResponse,now=Date.now()}){
 if([baseDecide,resolveVerifiedDestination,currentTransferIsSuspicious,denyResponse,now]
   .some(f=>typeof f!=='function')||!store||typeof store.check!=='function')
   throw new TypeError('trusted_ZTNA_adapter_required');
 return async request=>{
   const existing=await baseDecide(request);
   if(existing?.decision==='deny')return existing;
   const dst=await resolveVerifiedDestination(request);
   if(!isIP(dst))throw new TypeError('verified_destination_required');
   const rule=store.check(dst,now());
   if(!rule||!(await currentTransferIsSuspicious(request,rule)))return existing;
   const output=await denyResponse(request,rule);
   if(output?.schema!=='aleph.decision.v1'||output.requestId!==request?.requestId
      ||output.decision!=='deny'||typeof output.reasonCode!=='string'
      ||!Array.isArray(output.ruleIds)||!output.ruleIds.includes(rule.ruleId)
      ||Object.keys(output).sort().join(',')!=='decision,reasonCode,requestId,ruleIds,schema')
     throw new TypeError('invalid_registered_ZTNA_denial');
   return output;
 };
}

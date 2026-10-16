// Isolated judge module: no imports, file/network I/O or runtime dependencies.
// These pattern names and their conditions are copied from patterns.json.
const PATTERNS = Object.freeze([
  {
    "name": "unknown-destination-bulk",
    "condition": "Outbound transfer >=50MB to newly seen destination, with file batch, archive or repeated copying",
    "evidence": "MITRE ATT&CK T1048: exfiltration over alternate protocol plus novel destination and large volume"
  },
  {
    "name": "offhours-archive-transfer",
    "condition": "An >=50MB archive sent outside work/class hours to a newly seen address",
    "evidence": "MITRE ATT&CK T1048: suspicious external archive egress after business hours"
  },
  {
    "name": "repeated-bulk-egress",
    "condition": "High-volume outbound transfer >=50MB repeated at least five times to a destination",
    "evidence": "MITRE ATT&CK T1041: repeated data movement over command-and-control or another communication channel"
  },
  {
    "name": "unusual-port-egress",
    "condition": "High-volume multi-file outbound transfer >=50MB over a port not normally used",
    "evidence": "MITRE ATT&CK T1048: abnormal transfer protocol or port with substantial outgoing volume"
  },
  {
    "name": "full-collection-export",
    "condition": "At least 100 documents or whole vault copied outside in >=50MB burst",
    "evidence": "MITRE ATT&CK T1041: bulk collection egress over a communications channel"
  },
  {
    "name": "exfil-review",
    "condition": "Unverified destination, uncommon transfer, archive or T1041/T1048 tag without sufficient combined evidence",
    "evidence": "MITRE ATT&CK T1041 and T1048: partial indicators need investigation, not automatic block"
  }
]);
export function decide(alert) {
 const result=(confidence,reason)=>({action:confidence>=.85?'block':confidence>=.5?'alert':'record',confidence,reason});
 if(!alert||typeof alert!=='object'||Array.isArray(alert))return result(.1,'normal-event');
 const d=alert.data&&typeof alert.data==='object'&&!Array.isArray(alert.data)?alert.data:{};
 const descValue=alert?.rule?.description??alert.description,description=typeof descValue==='string'?descValue.slice(0,3000):'';
 const destination=d.dstip??alert.destinationIp,hasDestination=typeof destination==='string' && /^(?:\d{1,3}\.){3}\d{1,3}$/u.test(destination) && destination.split('.').every(s=>Number(s)<=255);
 const safeInt=x=>((typeof x==='number'&&Number.isSafeInteger(x)&&x>=0)||(typeof x==='string'&&/^(?:0|[1-9]\d{0,15})$/u.test(x)&&Number.isSafeInteger(Number(x))))?Number(x):null;
 const bytes=safeInt(d.bytes??alert.bytes),files=safeInt(d.files??alert.files),count=safeInt(d.count??alert.count);
 const hit=re=>re.test(description),tagged=Array.isArray(alert?.rule?.mitre??alert.mitre) && (alert?.rule?.mitre??alert.mitre).some(t=>/^T104(?:1|8)(?:\.\d{3})?$/iu.test(String(t)));
 const egress=hit(/나갔|전송|반출|복사|올라갔|유출|내보냈|upload|outbound|exfiltrat|sent|export/iu);
 const unknown=hit(/처음\s*보는\s*(?:목적지|주소)|평소와\s*다른\s*주소|낯선\s*외부\s*주소|unknown\s*destination|unfamiliar\s*(?:address|destination)|new\s*destination/iu);
 const archive=hit(/압축\s*파일|메모\s*묶음|zip\s*file|archive|compressed\s*file/iu);
 const offHour=hit(/수업\s*시간\s*밖|업무\s*시간\s*밖|수업\s*끝|근무\s*시간\s*외|야간|새벽|after[ -]?hours|outside\s*(?:work|office)\s*hours/iu);
 const repeated=hit(/반복|연속|[2-9]\d*\s*번|여러\s*번|repeated|multiple\s*times/iu);
 const unusualPort=hit(/평소에\s*쓰지\s*않던\s*포트|낯선\s*포트|unusual\s*port|nonstandard\s*port/iu);
 const whole=hit(/자료실\s*전체|전체\s*자료|entire\s*repository|whole\s*vault|entire\s*collection/iu);
 const command=hit(/명령\s*통로|command.and.control|C2\s*channel/iu);
 const multiple=hit(/목적지\s*두\s*곳|여러\s*목적지|multiple\s*destinations/iu);
 const failed=hit(/전송이?\s*실패|전송\s*실패|실패\s*1건|not\s*sent|transfer\s*failed/iu);
 const routine=hit(/수업\s*자료\s*주소.{0,25}동기화가?\s*끝|정상\s*동기화가?\s*끝|평소.{0,15}(?:작은\s*동기화|완료된\s*동기화)/iu);
 const noTransfer=hit(/파일\s*전송은\s*없|전송(?:은|이)?\s*(?:없|않)|no\s*(?:file\s*)?transfer|not\s*transferred/iu);
 if(noTransfer&&!tagged) return result(.1,'normal-event');
 if(routine&&bytes!==null&&bytes<1000000) return result(.1,'normal-event');
 if(hasDestination&&bytes!==null&&bytes>=50000000&&egress&&!failed&&!noTransfer) {
   if(unknown&&archive&&offHour)return result(.99,PATTERNS[1].name);
   if(command&&unknown&&repeated&&(count??0)>=5)return result(.99,PATTERNS[2].name);
   if(unusualPort&&(files??0)>=20)return result(.97,PATTERNS[3].name);
   if(whole&&(files??0)>=100)return result(.99,PATTERNS[4].name);
   if(unknown&&(files??0)>=20)return result(.97,PATTERNS[0].name);
   if(unknown&&archive&&(files??0)>=2)return result(.97,PATTERNS[0].name);
   if(repeated&&(count??0)>=5)return result(.96,PATTERNS[2].name);
   if(multiple&&archive)return result(.96,PATTERNS[0].name);
   if(unknown&&(repeated||command))return result(.95,PATTERNS[0].name);
 }
 // High rule severity, technique tag, or a destination alone cannot justify blocking.
 if(tagged||egress||unknown||archive||unusualPort||command)return result(.58,PATTERNS[5].name);
 return result(.1,'normal-event');
}

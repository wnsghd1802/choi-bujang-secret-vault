// Offline XDR persistence decider: no imports, file I/O, network calls or engine changes.
// PATTERNS are duplicated here for standalone judge execution; same names as patterns.json.
const PATTERNS = Object.freeze([
  { name: 'unsigned-service-install', condition: 'new/modified unsigned service plus temporary executable or repeated registrations' },
  { name: 'suspicious-scheduled-task', condition: 'unknown/random/after-hours scheduled task launches temporary executable' },
  { name: 'unlisted-startup-entry', condition: 'unlisted startup executable or new reboot-persistent temporary service' },
  { name: 'combined-autostart', condition: 'startup item and scheduled task point to the same temporary executable' },
  { name: 'persistence-review', condition: 'incomplete evidence of service/task/startup change' },
]);
const bounded = x => typeof x === 'string' ? x.slice(0, 3000) : '';
const result = (confidence, reason) => ({
  action: confidence >= 0.85 ? 'block' : confidence >= 0.5 ? 'alert' : 'record',
  confidence, reason,
});
const matches = (regexp, ...values) => values.some(value => regexp.test(value));
export function decide(alert) {
  if (!alert || typeof alert !== 'object' || Array.isArray(alert))
    return result(0.1, 'normal-event');
  const d = alert.data && typeof alert.data === 'object' ? alert.data : {};
  const description = bounded(alert?.rule?.description ?? alert.description);
  const path = bounded(d.path ?? d.image ?? d.executable ?? alert.path);
  const evidence = description + ' ' + path;
  const level = Number(alert?.rule?.level ?? alert.ruleLevel);
  const validLevel = Number.isInteger(level) && level >= 0 && level <= 16;
  const tags = alert?.rule?.mitre ?? alert.mitre;
  const tagged = Array.isArray(tags) && tags.some(tag => /^T(?:1543|1053|1547)(?:\.\d{3})?$/iu.test(String(tag)));
  const service = matches(/서비스|service|systemd|daemon/iu, description);
  const task = matches(/예약\s*작업|scheduled\s*task|schtasks|cron(?:tab)?/iu, description);
  const startup = matches(/시작\s*(?:폴더|프로그램|항목)|startup|autostart/iu, description, path);
  const temporary = matches(/임시\s*폴더|\\temp\\|\/tmp\/|\/temp\/|appdata\\local\\temp\\/iu, evidence);
  const newOrChanged = matches(/새\s*서비스|처음\s*보는|등록|추가|생겼|생성|바뀌|변경|새로|new\b|installed|created|modified/iu, description);
  const unsigned = matches(/서명\s*없는|서명(?:이)?\s*없|서명되지\s*않|unsigned|untrusted\s*signature/iu, description);
  const unlisted = matches(/평소\s*목록에\s*없는|처음\s*보는|낯선|목록에\s*없|unknown|unlisted|unrecognized/iu, description);
  const replaced = matches(/실행\s*파일이\s*바뀌|바이너리\s*변경|binary\s*(?:change|replace)/iu, description);
  const repeated = matches(/연속|반복|repeated|multiple\s*registrations/iu, description)
    && (Number(d.count) >= 2 || /[2-9]\d*\s*(?:건|회|번)|multiple/iu.test(description));
  const randomTask = matches(/임의\s*문자열|무작위|난수|random(?:ized)?\s*name/iu, description);
  const outsideHours = matches(/시간\s*밖|야간|새벽|after[ -]?hours|outside.*hours/iu, description);
  const persistent = matches(/다시\s*켜도\s*남|재부팅.*남|reboot.*persist|remain.*reboot/iu, description);
  const sameTarget = matches(/같은\s*임시\s*파일|같은\s*파일|same\s*(?:file|binary)/iu, description);
  const startupPath = /\\start menu\\programs\\startup\\/iu.test(path);
  const executable = /\.(?:exe|com|bat|cmd|ps1)\b/iu.test(path);
  const explicitBenign = matches(
    /서명된\s*채|서명되어\s*있|정상\s*서명|평소\s*시각에\s*그대로|기존\s*예약\s*작업.*마쳤|시작\s*프로그램\s*목록을\s*읽기만|로그인했습니다|로그아웃했습니다|자료실\s*화면|정의\s*업데이트|기존\s*수업\s*도구\s*서비스/iu,
    description
  );
  // MITRE tags and severity alone never establish persistence or justify a deny.
  if (explicitBenign && !unsigned && !unlisted && !replaced && !randomTask)
    return result(0.1, 'normal-event');
  if (task && startup && temporary && sameTarget)
    return result(0.99, PATTERNS[3].name);
  if (service && unsigned && newOrChanged && (temporary || repeated || replaced))
    return result(0.97, PATTERNS[0].name);
  if (task && temporary && (unlisted || randomTask || outsideHours))
    return result(0.96, PATTERNS[1].name);
  if ((startup && unlisted && newOrChanged && (startupPath || executable))
      || (service && unlisted && persistent && temporary && newOrChanged))
    return result(0.95, PATTERNS[2].name);

  // A signed old service or a routine scheduled job is not suspicious merely
  // because it has T1543/T1053 metadata. Unconfirmed changes trigger review only.
  if (description && (service || task || startup || temporary || (tagged && validLevel)))
    return result(0.58, PATTERNS[4].name);
  return result(0.1, 'normal-event');
}

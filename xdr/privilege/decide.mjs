// Standalone offline decision module: no imports, network, filesystem or engine rule changes.
// The definitions below are an exact embedded copy of patterns.json's patterns.
const PATTERNS = Object.freeze([
  {
    "name": "unexpected-admin-group-grant",
    "condition": "An ordinary account is assigned Administrators from an unfamiliar source, while using admin commands, or as part of mass account grants",
    "evidence": "MITRE ATT&CK T1078: unauthorized use of a valid account with unexpected administrative group privileges"
  },
  {
    "name": "post-elevation-command",
    "condition": "An account just gained administrator privilege then executes administrator commands, or the privilege appears from an unknown source",
    "evidence": "MITRE ATT&CK T1068 and T1078: unexpected elevation followed by privileged activity"
  },
  {
    "name": "unusual-admin-command",
    "condition": "Administrator command outside working/class hours from a previously unseen source",
    "evidence": "MITRE ATT&CK T1078: abnormal time and origin can indicate stolen credential use"
  },
  {
    "name": "cross-account-admin-use",
    "condition": "A user invokes a privileged command with another account's authority",
    "evidence": "MITRE ATT&CK T1078: another legitimate account's privileges are used"
  },
  {
    "name": "rapid-admin-regrant",
    "condition": "Removed administrator membership is rapidly restored",
    "evidence": "MITRE ATT&CK T1078: unexpected reinstatement of administrator privileges"
  },
  {
    "name": "privilege-review",
    "condition": "Unconfirmed administrator/group/privileged-action warning without sufficient combined evidence for denial",
    "evidence": "MITRE ATT&CK T1068 and T1078: an incomplete privilege signal warrants alert rather than automatic blocking"
  }
]);
const safe = x => typeof x === 'string' ? x.slice(0, 3000) : '';
const result = (confidence, reason) => ({
  action: confidence >= 0.85 ? 'block' : confidence >= 0.5 ? 'alert' : 'record',
  confidence, reason,
});
export function decide(alert) {
  if (!alert || typeof alert !== 'object' || Array.isArray(alert)) return result(0.1, 'normal-event');
  const data = alert.data && typeof alert.data === 'object' ? alert.data : {};
  const description = safe(alert?.rule?.description ?? alert.description);
  const group = safe(data.group ?? alert.group);
  const mitre = alert?.rule?.mitre ?? alert.mitre;
  const hasTag = Array.isArray(mitre) && mitre.some(x => /^T(?:1068|1078)(?:\.\d{3})?$/iu.test(String(x)));
  const adminGroup = /^(?:administrators|administrator|admins|관리자(?:\s*그룹)?)$/iu.test(group)
    || /관리자\s*그룹/iu.test(description);
  const groupAdded = /(?:관리자\s*그룹.{0,30}(?:추가|들어가|들어왔|등록|가입)|(?:추가|등록|들어감).{0,20}관리자\s*그룹)/iu.test(description);
  const unfamiliarSource = /(?:원격\s*주소|처음\s*보는\s*주소|낯선\s*주소|요청\s*주소는\s*처음\s*봅니다|unfamiliar\s*(?:source|address)|unknown\s*(?:source|ip))/iu.test(description);
  const unusualHour = /(?:수업\s*시간\s*밖|업무.{0,10}(?:아닌|않는)\s*시각|업무\s*시간\s*밖|근무\s*시간\s*외|야간|새벽|after[ -]?hours|outside\s*(?:work|office)\s*hours)/iu.test(description);
  const adminCommand = /(?:관리자\s*명령|권한\s*명령|관리자급\s*명령|admin(?:istrator)?\s*command|privileged\s*command)/iu.test(description);
  const commandRun = /(?:명령.{0,20}(?:실행|사용)|(?:실행|사용).{0,20}명령|command.{0,25}executed)/iu.test(description);
  const newAdmin = /(?:방금\s*관리자가\s*된|관리자\s*권한으로\s*바뀌|관리자\s*권한을\s*얻|권한\s*상승.{0,15}(?:직후|후에)|newly\s*elevated)/iu.test(description);
  const anotherAccount = /(?:다른\s*계정의\s*권한으로|타인\s*계정(?:의)?\s*권한|another\s*account.?s\s*privileges|impersonat(?:ed|ing))/iu.test(description);
  const rapidRegrant = /(?:관리자\s*그룹에서\s*빠진.{0,55}(?:다시|재추가|재등록)|removed.{0,40}administrator.{0,40}readd)/iu.test(description);
  const manyAccounts = (Number.isSafeInteger(Number(data.count)) && Number(data.count) >= 3
    && Number(data.count) <= 1000000) || /(?:계정\s*[3-9]\d*개|[3-9]\d*\s*(?:개|명)의?\s*계정)/iu.test(description);
  const ordinary = /(?:평범한\s*계정|일반\s*계정|보통\s*계정|ordinary\s*account)/iu.test(description);
  const failedOrCancelled = /(?:취소됐|실패\s*1건|관리자\s*그룹은\s*아닙니다|변경은\s*없습니다|명령은\s*없습니다|한\s*번\s*실행|1건으로\s*끝났)/iu.test(description);

  if (rapidRegrant && adminGroup) return result(0.98, PATTERNS[4].name);
  if (anotherAccount && adminCommand && commandRun) return result(0.98, PATTERNS[3].name);
  if (adminGroup && groupAdded
      && (unfamiliarSource || (commandRun && !failedOrCancelled) || manyAccounts || ordinary))
    return result(0.97, PATTERNS[0].name);
  if (newAdmin && ((adminCommand && commandRun) || unfamiliarSource))
    return result(0.96, PATTERNS[1].name);
  if (unusualHour && unfamiliarSource && adminCommand && commandRun)
    return result(0.95, PATTERNS[2].name);
  if (adminGroup && groupAdded && unusualHour && commandRun)
    return result(0.96, PATTERNS[0].name);

  // T1068/T1078 labels and high Wazuh levels alone NEVER produce a block.
  // Single cancelled attempts, routine group reads and normal admin login are safe.
  const directConcern = /(?:관리자|권한|elevat|privileg|administrator|admin\s*command)/iu.test(description);
  if (hasTag || (directConcern && description)) return result(0.58, PATTERNS[5].name);
  return result(0.1, 'normal-event');
}

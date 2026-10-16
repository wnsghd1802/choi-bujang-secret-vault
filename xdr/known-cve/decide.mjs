// Offline, single-file CVE-2021-44228 detector. No imports, file I/O or network calls.
// PATTERNS mirror names and conditions in patterns.json. No actual lookup is performed.
const PATTERNS = Object.freeze([
  { name: 'jndi-remote-header', kind: 'complete remote JNDI in HTTP header or user agent' },
  { name: 'jndi-remote-query', kind: 'complete remote JNDI in request URL/query' },
  { name: 'cve-reference-review', kind: 'CVE, Log4j or JNDI textual reference only' },
  { name: 'scanner-trace-review', kind: 'known exploit scan or lookup hint' },
]);
const REMOTE_LOOKUP = /\$\{\s*jndi\s*:\s*(?:ldap|ldaps|rmi|dns|iiop|nis):\/\/[^\s{}]{1,300}\}/iu;
const CVE_REFERENCE = /CVE[\s-]*2021[\s-]*44228|\blog4j\b|\blog4shell\b|\bjndi\b/iu;
const SCAN_HINT = /취약점|원격\s*조회|조회\s*구문|점검\s*도구|스캔|중괄호|라이브러리|악용|잘린\s*글자|lookup|scanner|probe|exploit|vulnerability|T1190/iu;
const safe = value => typeof value === 'string' ? value.slice(0, 4096) : '';
function decodeOnce(text) {
  if (!text.includes('%')) return text;
  try { return decodeURIComponent(text); } catch { return text; }
}
function requestFields(alert) {
  const d = alert?.data ?? {};
  const request = alert?.request ?? {};
  const headers = [
    d.useragent, d.userAgent, d.headers, d.header, alert?.useragent, alert?.userAgent,
    alert?.headers, request.userAgent, request.headers, request.header,
  ];
  const queries = [
    d.url, d.uri, d.query, d.args, alert?.url, alert?.uri,
    alert?.query, request.url, request.uri, request.query, request.args,
  ];
  function values(list) {
    const out = [];
    for (const item of list) {
      if (typeof item === 'string') out.push(decodeOnce(safe(item)));
      else if (item && typeof item === 'object' && !Array.isArray(item)) {
        for (const [name, value] of Object.entries(item).slice(0, 40)) {
          if (typeof value === 'string') out.push(decodeOnce(safe(name + ': ' + value)));
        }
      }
    }
    return out;
  }
  return { headers: values(headers), queries: values(queries) };
}
const out = (confidence, name) => ({
  action: confidence >= 0.85 ? 'block' : confidence >= 0.5 ? 'alert' : 'record',
  confidence, reason: name,
});
export function decide(alert) {
  if (!alert || typeof alert !== 'object' || Array.isArray(alert)) return out(0.1, 'normal-event');
  const fields = requestFields(alert);
  const headerMatch = fields.headers.some(item => REMOTE_LOOKUP.test(item));
  const queryMatch = fields.queries.some(item => REMOTE_LOOKUP.test(item));
  if (headerMatch || queryMatch) {
    const names = [];
    if (headerMatch) names.push(PATTERNS[0].name);
    if (queryMatch) names.push(PATTERNS[1].name);
    return out(headerMatch && queryMatch ? 0.99 : 0.96, names.join('+'));
  }

  // Description-only lookups, T1190 classification and scanner strings never
  // justify blocking a user. They may warrant review but not enforcement.
  const description = safe(alert?.rule?.description ?? alert?.description);
  const raw = fields.headers.concat(fields.queries).join(' ').slice(0, 8192);
  const tags = alert?.rule?.mitre ?? alert?.mitre;
  const tagged = Array.isArray(tags) && tags.some(tag => /^T1190(?:\.\d{3})?$/iu.test(String(tag)));
  if (CVE_REFERENCE.test(description) || CVE_REFERENCE.test(raw))
    return out(0.6, PATTERNS[2].name);
  if (SCAN_HINT.test(description) || SCAN_HINT.test(raw) || tagged)
    return out(0.55, PATTERNS[3].name);
  return out(0.1, 'normal-event');
}

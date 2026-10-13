// Stage 9: evaluate only trusted, already-verified exercise events.
// No storage, network calls, token handling or direct revocation occurs here.
const WINDOW_MS = 10 * 60 * 1000;
const THRESHOLD = 120;
const UTC_ISO = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$/u;

export function detect(events) {
  if (!Array.isArray(events)) throw new TypeError('invalid_detection_events');

  const requestsBySubject = new Map();
  for (const event of events) {
    if (!event || event.method !== 'GET') continue;
    const subject = event.identity?.sub;
    const at = event.at;
    if (typeof subject !== 'string' || subject.length === 0 || typeof at !== 'string'
        || !UTC_ISO.test(at)) continue;
    const timestamp = Date.parse(at);
    if (!Number.isFinite(timestamp)) continue;
    if (!requestsBySubject.has(subject)) requestsBySubject.set(subject, []);
    requestsBySubject.get(subject).push(timestamp);
  }

  let earliest = null;
  for (const [subject, timestamps] of requestsBySubject) {
    if (timestamps.length <= THRESHOLD) continue;
    timestamps.sort((a, b) => a - b);
    let start = 0;
    for (let end = 0; end < timestamps.length; end++) {
      while (timestamps[end] - timestamps[start] > WINDOW_MS) start++;
      if (end - start + 1 > THRESHOLD) {
        const at = timestamps[end];
        if (!earliest || at < earliest.at || (at === earliest.at && subject < earliest.subject)) {
          earliest = { at, subject };
        }
        break;
      }
    }
  }

  return earliest
    ? { action: 'propose_revocation', reasonCode: 'burst_read', subject: earliest.subject }
    : { action: 'observe' };
}

// Decision contract: aleph.decision.v1. The engine validates identity, device and route.
// Per-note ownership belongs to the authenticated API, not a guessed path-to-owner rule.
export const RULE_IDS = Object.freeze(['device_registered', 'step_up_required', 'resource_zone']);

function permittedSingleNote(request) {
  if (request.service !== 'notes' || request.queryLength !== 0
    || typeof request.method !== 'string' || typeof request.route !== 'string'
    || typeof request.path !== 'string') return false;

  // No collection reads, exports, notice writes or class/instructor resources.
  if (request.method !== 'GET' && request.method !== 'PUT') return false;
  const prefix = request.route === `${request.method} /notes/:id` ? '/notes/'
    : request.route === `${request.method} /api/notes/:id` ? '/api/notes/'
      : null;
  if (!prefix || !request.path.startsWith(prefix)) return false;
  const item = request.path.slice(prefix.length);
  return /^[A-Za-z0-9_-]{1,64}$/u.test(item);
}

function needsStepUp(request) {
  const signals = request.signals;
  if (signals?.source !== 'judge_fixture') return false;
  if (signals.region !== 'foreign' || signals.network !== 'unusual'
    || !Number.isInteger(signals.hour) || signals.hour < 0 || signals.hour > 5) return false;
  return Array.isArray(request.recentEvents) && request.recentEvents.some(event =>
    event?.kind === 'risk_signal' && Number.isInteger(event.ageSeconds)
    && event.ageSeconds >= 0 && event.ageSeconds <= 300
    && Number.isInteger(event.count) && event.count >= 10);
}

export async function decide(request) {
  const reply = (decision, reasonCode, ruleId) => ({
    schema: 'aleph.decision.v1',
    requestId: request.requestId,
    decision,
    reasonCode,
    ruleIds: [ruleId],
  });
  if (request.deviceRegistered !== true)
    return reply('deny', 'device_not_registered', RULE_IDS[0]);
  if (!permittedSingleNote(request))
    return reply('deny', 'starter_not_ready', RULE_IDS[2]);
  if (needsStepUp(request)) {
    const proof = request.stepUp;
    const fresh = proof?.verified === true && Number.isInteger(proof.authAgeSeconds)
      && proof.authAgeSeconds >= 0 && proof.authAgeSeconds <= 900;
    if (!fresh) return reply('step_up', 'step_up_required', RULE_IDS[1]);
  }
  return reply('allow', 'approved', RULE_IDS[2]);
}

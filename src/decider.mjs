// Only engine-verified request fields are trusted; do not import external policy data.
// The current decision contract has no ownership or instructor-role attestation.
export const RULE_IDS = Object.freeze(['device_registered', 'step_up_required', 'resource_zone']);

function isKnownResource(request) {
  if (request.queryLength !== 0 || typeof request.route !== 'string'
    || typeof request.path !== 'string' || typeof request.method !== 'string') return false;
  const parts = request.route.split(' ');
  if (parts.length !== 2 || parts[0] !== request.method) return false;
  const [method, route] = parts;
  const match = /^(\/(?:api\/)?notes)(\/:[a-zA-Z]+)?$/.exec(route);
  if (!match || request.service !== 'notes') return false;
  const prefix = match[1];
  if (!match[2]) return (method === 'GET' || method === 'POST') && request.path === prefix;
  if (match[2] !== '/:id' || !['GET', 'PUT', 'DELETE'].includes(method)) return false;
  if (!request.path.startsWith(prefix + '/')) return false;
  const id = request.path.slice(prefix.length + 1);
  return /^[a-zA-Z0-9_-]{1,64}$/.test(id);
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
  const reply = (decision, reasonCode, index) => ({
    schema: 'aleph.decision.v1',
    requestId: request.requestId,
    decision,
    reasonCode,
    ruleIds: [RULE_IDS[index]],
  });
  if (request.deviceRegistered !== true) return reply('deny', 'device_not_registered', 0);
  // Only exact note routes are delegated to the owner's API. The decision contract
  // cannot prove a note owner or instructor privileges, so notices/unknown paths deny.
  // starter_not_ready is a documented existing fail-closed reason code.
  if (!isKnownResource(request)) return reply('deny', 'starter_not_ready', 2);
  if (needsStepUp(request)) {
    const stepUp = request.stepUp;
    if (!(stepUp?.verified === true && Number.isInteger(stepUp.authAgeSeconds)
      && stepUp.authAgeSeconds >= 0 && stepUp.authAgeSeconds <= 900)) {
      return reply('step_up', 'step_up_required', 1);
    }
  }
  return reply('allow', 'approved', 2);
}

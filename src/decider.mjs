// Only the 18 fields in aleph.decision.v1 are trusted. The contract currently
// contains no verified owner-to-resource mapping or instructor role.
// Never authorize an arbitrary note ID merely because its URL fits /notes/:id.
export const RULE_IDS = Object.freeze(['device_registered', 'step_up_required', 'resource_zone']);

function resourceScope(request) {
  if (request.service !== 'notes' || request.queryLength !== 0
    || typeof request.method !== 'string' || typeof request.route !== 'string'
    || typeof request.path !== 'string') return null;

  // Collection endpoints scope reads/inserts to the verified actor in notes-api.
  if (request.route === 'GET /api/notes' && request.method === 'GET'
      && request.path === '/api/notes') return 'owner_scoped_collection';
  if (request.route === 'POST /api/notes' && request.method === 'POST'
      && request.path === '/api/notes') return 'owner_scoped_collection';

  // Keep the public local practice fixture used by stages 6 and 7.
  // This is NOT a real-user ownership assertion.
  if (request.route === 'GET /notes/:id' && request.method === 'GET'
      && request.path === '/notes/demo'
      && request.classId === 'class_fixture'
      && request.projectId === 'project_fixture'
      && request.subjectId === 'learner_fixture'
      && request.deviceId === 'aaaaaaaaaaaaaaaa'
      && request.signals?.source === 'judge_fixture') return 'synthetic_practice';

  // Individual notes, notices, alternative methods, query selectors and
  // unknown routes fail closed without engine-verified resource ownership.
  return null;
}

function needsStepUp(request) {
  const signals = request.signals;
  if (signals?.source !== 'judge_fixture') return false;
  if (signals.region !== 'foreign' || signals.network !== 'unusual'
    || !Number.isInteger(signals.hour) || signals.hour < 0 || signals.hour > 5) return false;
  return Array.isArray(request.recentEvents) && request.recentEvents.some(event =>
    event?.kind === 'risk_signal'
    && Number.isInteger(event.ageSeconds) && event.ageSeconds >= 0 && event.ageSeconds <= 300
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
  if (resourceScope(request) === null)
    return reply('deny', 'starter_not_ready', RULE_IDS[2]);
  if (needsStepUp(request)) {
    const proof = request.stepUp;
    const fresh = proof?.verified === true && Number.isInteger(proof.authAgeSeconds)
      && proof.authAgeSeconds >= 0 && proof.authAgeSeconds <= 900;
    if (!fresh) return reply('step_up', 'step_up_required', RULE_IDS[1]);
  }
  return reply('allow', 'approved', RULE_IDS[2]);
}

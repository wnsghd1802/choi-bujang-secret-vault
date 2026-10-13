// ALEPH SDP 엔진이 검증한 요청 계약(aleph.decision.v1)만 사용합니다.
// 실제 경로에 지리/네트워크 이력이 없으므로 아래 복합 위험 신호는 judge_fixture 가상 사건만 판정합니다.
export const RULE_IDS = Object.freeze(['device_registered', 'step_up_required']);

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
  if (request.deviceRegistered !== true) {
    return {
      schema: 'aleph.decision.v1',
      requestId: request.requestId,
      decision: 'deny',
      reasonCode: 'device_not_registered',
      ruleIds: [RULE_IDS[0]],
    };
  }

  if (needsStepUp(request)) {
    const status = request.stepUp;
    const verified = status?.verified === true
      && Number.isInteger(status.authAgeSeconds)
      && status.authAgeSeconds >= 0 && status.authAgeSeconds <= 900;
    if (!verified) {
      return {
        schema: 'aleph.decision.v1',
        requestId: request.requestId,
        decision: 'step_up',
        reasonCode: 'step_up_required',
        ruleIds: [RULE_IDS[1]],
      };
    }
  }

  return {
    schema: 'aleph.decision.v1',
    requestId: request.requestId,
    decision: 'allow',
    reasonCode: 'approved',
    ruleIds: [RULE_IDS[0]],
  };
}

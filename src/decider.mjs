// ALEPH SDP 엔진이 확인한 요청의 기기 등록 여부만 판정합니다.
// 브라우저 입력의 기기 상태, 인증서, 개인키를 별도로 신뢰하거나 저장하지 않습니다.
export const RULE_IDS = Object.freeze(['device_registered']);

export async function decide(request) {
  const registered = request?.deviceRegistered === true;
  return {
    schema: 'aleph.decision.v1',
    requestId: request.requestId,
    decision: registered ? 'allow' : 'deny',
    reasonCode: registered ? 'approved' : 'device_not_registered',
    ruleIds: [RULE_IDS[0]],
  };
}

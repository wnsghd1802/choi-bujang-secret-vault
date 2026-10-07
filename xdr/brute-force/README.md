# XDR-01 무차별 로그인 탐지

## 실행

```sh
npm run xdr:run -- brute-force
node xdr/brute-force/replay.mjs
node --test test/brute-force.test.mjs test/xdr-run.test.mjs xdr/brute-force/regression.test.mjs
```

첫 명령은 공식 실행기로 `result.json`을 만들고, 두 번째 명령은 시험 경보를 시간 순서로 다시 흘려 만료형 거부 규칙과 `xdr/alerts.log`를 확인합니다.

현재 공식 가상 경보 28건은 **block 10 · alert 9 · record 9**, 정상 이벤트 block **0건**입니다. 이 숫자는 공개 fixture에 대한 현재 결과이며 비공개 심판 정답을 뜻하지 않습니다.

## 과제 조건에 맞춘 구성

- `read-alerts.mjs`: 각 경보에서 **timestamp · sourceAddress · account · ruleLevel · description** 다섯 항목만 추출합니다. 비밀번호·토큰·개인키·이메일 형태는 출력 전에 가립니다.
- `patterns.json`: 근거 있는 두 패턴만 둡니다. `rapid-same-source-failures`는 MITRE ATT&CK T1110/T1110.001, `password-spray`는 T1110.003에 근거하며 각 패턴의 `basis`는 한 줄입니다.
- `decide.mjs`: 명확한 반복 실패와 password spray는 rule level 자체를 필수 조건으로 삼지 않고 행동 근거로 block합니다. 애매한 경보만 Jev 콜백으로 보내며, Jev가 없거나 실패하면 confidence 0.5의 alert로 남깁니다. 0.85 이상 block, 0.5 이상 alert, 그 아래 record 기준을 그대로 사용합니다.
- 짧은 시간 반복 실패는 한국어/영어 표현, 정제된 다섯 필드 행, 숫자 집계가 없는 고수준 반복 표현도 처리합니다. 반대로 5분을 넘는 느린 누적, 성공 뒤 소수 실패, 불규칙한 소수 실패는 자동 차단하지 않습니다.
- `enforce.mjs`: block 결정만 15분짜리 ZTNA 거부 후보로 만들고 `evidenceAlertIds`에 실제 근거 경보 번호를 붙입니다. 정상 요청은 기존 판정기로 그대로 넘기며 기존 ZTNA 규칙은 수정하지 않습니다.
- `xdr/alerts.log`: block/alert만 JSONL 한 줄씩 추가하고 주소·계정·원문은 기록하지 않습니다. 이 파일은 실행 산출물이므로 Git에는 넣지 않습니다.

## 기존 ZTNA와의 연결 한계

현재 `docs/DECIDER_REQUEST.md`의 요청 계약에는 출발 IP가 없습니다. 따라서 브라우저 본문이나 임의 헤더에서 주소를 만들어 기존 판정기에 추가하지 않습니다. `withXdrGuard()`는 운영 엔진이 이미 확인한 출발 주소와 기존 deny 응답 생성자를 주입받는 연결 부품입니다.

정상 기대: 정상 이벤트는 record이고 기존 정책의 정상 요청은 그대로 통과합니다.

거부 기대: 명확한 공격은 block이고 해당 주소의 거부 후보에는 만료 시각과 근거 경보 번호가 남습니다.

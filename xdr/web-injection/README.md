# 보너스 XDR-02 — 웹 입력 조작 탐지

기존 `src/decider.mjs` 및 `xdr/brute-force/`는 수정하지 않는 독립 모듈입니다. 경보는 실습용 가상 Wazuh 데이터입니다.

## 실행

```sh
npm run xdr:run -- web-injection
node xdr/web-injection/replay.mjs
node --test xdr/web-injection/regression.test.mjs
```

- `read-alerts.mjs`: 원본 경보를 보존하며 시각, 출발 IP, 규칙 수준, 설명, URL, 반복 횟수, MITRE 표시만 읽습니다. 자격증명처럼 보이는 값은 가립니다.
- `patterns.json`: MITRE ATT&CK T1190에 기반한 SQL 주입·스크립트 삽입·경로 이탈·명령 구분자 네 패턴과 각 근거를 담습니다.
- `decide.mjs`: 반복 5건 이상과 명확한 공격 패턴이 동시에 확인되면 block(1.0); 애매하면 alert(0.5); 정상 조회는 record(0.1)입니다. 학습용 `doc-*` 토큰만으로 공격을 확정하지 않습니다.
- Jev는 현재 저장소에 실제 연결 코드가 없습니다. 검증된 `jev` 함수를 `createDecider({ jev })`로 전달할 때만 애매한 요청을 문의합니다. 미연결·실패 시 alert 유지이며 실제 Jev 연결 성공을 주장하지 않습니다.
- `enforce.mjs`: block 판정만 15분 만료형 ZTNA 거부 후보로 남깁니다. 운영 연결은 서버가 확인한 IP 및 기존 deny 응답 생성자를 주입해야 합니다. 원래 판정 규칙은 변경하지 않습니다.
- `replay.mjs`: 가상 경보를 실행해 `result.json`, `replay-report.json`, `deny-rules.json`, `xdr/alerts.log`를 생성합니다. 로그에 비밀·IP·검색어·원문은 저장하지 않으며 `xdr/alerts.log`는 Git에서 제외됩니다.

정상 기대: 일반 조회는 record이며 기존 ZTNA 판정기로 넘어갑니다.
차단 기대: 반복되는 명확한 주입 경보만 block이며 규칙 후보에 만료 시각과 근거 경보 id가 남습니다.

공개 fixture 결과와 심판의 비공개 판정은 다를 수 있습니다. 운영 ZTNA에 실제 적용한 것으로 보고하지 않습니다.

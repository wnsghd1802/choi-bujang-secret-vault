# 보너스 XDR-02 — 웹 입력 조작 탐지

기존 `src/decider.mjs`, 다른 XDR 모듈과 fixture를 변경하지 않는 독립 구현입니다.

## 실행 및 확인

```sh
npm run xdr:run -- web-injection
node xdr/web-injection/replay.mjs
node --test xdr/web-injection/regression.test.mjs test/xdr-run.test.mjs
```

- `read-alerts.mjs`: 가상 Wazuh 경보의 시각, 유효한 출발 주소, 계정, 경보 수준, 설명, URL, 건수 및 T1190을 읽습니다. 암호·토큰·개인키·메일 주소 형태는 가립니다.
- `patterns.json`: MITRE ATT&CK T1190을 참고한 SQL 주입, 스크립트 삽입, 경로 이탈, 명령 구분자 네 가지 특징과 각 패턴별 한 줄 근거입니다.
- `decide.mjs`: 패턴을 파일 상수로 재정의한 독립형 순수 함수입니다. **import, 네트워크, 파일 입출력, Jev 없이** 원본 경보를 분류합니다. 반복된 명확한 주입만 block(1.0), 근거가 불충분한 T1190 의심은 alert(0.55), 그 밖의 정상 요청은 record(0.1)입니다. 단순한 SQL/스크립트 수업 단어나 문서용 `doc-*` 토큰만으로 차단하지 않습니다.
- `respond.mjs`: block만 15분 만료의 거부 **후보**로 만들며, 근거 경보 번호를 기록합니다. block/alert는 원문과 개인정보를 제외한 메타데이터로 `xdr/alerts.log`에 한 줄씩 추가합니다. 기존 ZTNA 판정 함수를 감싸는 선택적 연결 어댑터를 제공하지만 운영 판정기를 고치거나 연결하지는 않습니다.
- `replay.mjs`: 동일한 가상 경보를 시간 순서로 재생하여 후보, 만료 및 정상 조회 오차단 여부를 확인합니다. `replay-report.json`은 모의 결과이며 심판 판정이 아닙니다.

**운영 연결의 조건:** `docs/DECIDER_REQUEST.md`의 ZTNA 요청에는 출발 IP가 없습니다. 따라서 사용자가 보낸 요청에서 임의 IP를 신뢰하지 않으며 실제 엔진이 검증한 출발 IP 공급자 및 기존 등록된 거부 응답 함수가 있을 때만 어댑터를 연결할 수 있습니다. 개발환경 fixture 테스트가 통과해도 운영 사이트를 실제 차단했다는 뜻은 아닙니다.

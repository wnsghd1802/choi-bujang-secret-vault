# XDR-01 탐지 근거 중심 검증

## 이번 변경의 목적

분류 결과의 특정 건수에 맞추는 검사를 제거했습니다. `block`은 충분한 반복·빈도·Password Spraying 근거로 판정하고, 증거가 불충분한 경보는 `alert`, 정상 활동은 `record`로 판정합니다. 외부 판정 서비스 호출은 구현하지 않았습니다.

## 수정된 탐지 범위

- 로그인 실패·인증 거부의 한국어 `차례/번/회/건` 및 영어 `failed logins`, `authentication denials` 등 숫자 표현
- `1분 사이`, `2분간`, `within 2 minutes` 등 시간 범위
- 다수 계정에 동일 비밀번호를 반복 대입하는 Password Spraying
- 단시간 실패 8건 이상, 5분 이내 다량 실패 20건 이상, 5분 이상 1시간 이하에서도 총 30건 이상이면서 분당 3건 이상의 지속 공격
- 대량 실패 후 로그인 성공이 발생하더라도 공격 이력을 무효화하지 않음
- 같은 출발 IP의 단일 실패 이벤트 30개 집계, 이벤트 ID 재전송 중복 제거, 오래된 이벤트 만료
- 정상 로그인/로그아웃, 단발 실패 뒤 성공, 낮은 빈도의 로그인 실패, 비밀번호 설정 설명은 과도하게 차단하지 않음

## Node.js 22 로컬 검사

1. `node --test test/brute-force.test.mjs test/xdr-run.test.mjs xdr/brute-force/regression.test.mjs xdr/brute-force/evidence.test.mjs`: 28개 테스트 통과, 실패 0개.
2. 추가 사례 40개: 명확한 공격 25/25 `block`, 의심 7/7 `alert`, 정상 8/8 `record`.
3. 원본 ZIP의 판정 코드와 같은 40개 사례를 비교: 공격 25개 중 원본은 12개 차단, 이번 버전은 25개 차단. 원본 대비 13개 탐지 누락을 개선했습니다. 정상 8개 중 원본 7개가 `record`, 수정본 8개가 `record`.
4. `node scripts/xdr-run.mjs brute-force`: 공개 경보 결과 생성 완료. 공개 경보의 합계는 비공개 채점의 정답도, 코드의 유지 목표도 아닙니다.
5. `node xdr/brute-force/replay.mjs`: 수업용 경보 재생 및 만료형 거부 후보 점검, 정상 이벤트의 모의 차단 0건. 운영 시스템 차단은 실행하지 않았습니다.

`node --test test/*.test.mjs xdr/brute-force/*.test.mjs` 전체 실행에서는 Supabase SDK가 설치되지 않은 압축 해제 환경 때문에 기존 `stage3`와 `stage5` 테스트 두 개가 `ERR_MODULE_NOT_FOUND`로 실행되지 않았습니다. XDR 범위 28개 테스트는 모두 통과했습니다. 기존 인증·DB·ZTNA 코드는 변경하지 않았습니다.

## 제한

공개 경보와 자체 작성한 테스트에 대한 로컬 결과입니다. **비공개 심판의 정답표나 심판 통과를 보증하지 않습니다.** 특히 자연어 설명에 의존하는 방식이므로 새로운 로그 표현이나 부정·예외 문구에 대해서는 추가 검증이 필요합니다. 자동 차단 판단을 실제 운영 환경에 연결하기 전에는 정상 사용자 영향과 오차단 가능성을 별도로 검토해야 합니다.

## 직접 확인

```sh
node --test test/brute-force.test.mjs test/xdr-run.test.mjs xdr/brute-force/regression.test.mjs xdr/brute-force/evidence.test.mjs
npm run xdr:run -- brute-force
node xdr/brute-force/replay.mjs
```

`result.json`을 열어 개별 경보의 `action`, `confidence`, `reason`을 확인하고, `replay-report.json`의 `normalBlockedIds`가 빈 배열인지 확인하세요.

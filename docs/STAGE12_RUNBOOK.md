# 12단계 탈환 작전실 — 실행·증거·복구 런북

## 1. 역할과 출처

| 내용 | 출처 | 현재 확인 범위 |
|---|---|---|
| 18항목 `aleph.decision.v1` 요청·응답 규약, 신원·기기·경로 검증, 허용 사유 등록부 | ALEPH SDP 제공 엔진 / `docs/DECIDER_REQUEST.md` | 공개 계약 문서 |
| 판정 규칙 `device_registered`, `step_up_required`, `resource_zone` | 학생 `src/decider.mjs` | 소스 + Node 가상 입력 |
| 10분 120건 초과 GET의 회수 제안 | 학생 `src/detect.mjs`; `docs/DETECT_EVENTS.md` | Node 가상 사건, 운영 집행 아님 |
| 사용자 접근 거부 및 기기 승인 | 학생 `src/device-api.mjs`, `src/device-security.mjs` | 서버 로직; 실제 승인 상태는 DB에서 별도 확인 |
| 단일 시험 B 복구 및 원자적 감사 영수증 | 학생 `src/recovery-api.mjs`와 단계 10 SQL 마이그레이션 | 로컬·격리 테스트와 실제 API 결과 구분 |
| 41종 화면 및 요청·시간·출처 표시 | 학생 `src/stage12-cases.mjs`, `src/stage12-workroom.js` | 읽기 전용 익명 API 검사/로컬 모의는 UI에서 직접 재현 |

엔진을 사칭해 `request.role`, `request.identity`, `request.geo`, `request.device`를 생성하지 않습니다. 학생은 엔진이 전달한 `request.deviceRegistered`, `request.stepUp`, `request.signals`, `request.recentEvents`, 경로·쿼리 메타데이터를 사용합니다. 별도 교사 권한은 사용자가 주장한 문자열 대신 서버의 승인 저장값으로 확인합니다.

## 2. 최초 설치·실행

1. 프로젝트를 공식 GitHub 저장소에서 다시 복제합니다. `node --version`은 Node.js 22 이상이어야 합니다.
2. `npm ci`로 잠긴 의존성을 설치합니다.
3. `npm run test:12`와 `npm run test:10`, `node --test test/step11.test.mjs`를 실행해 로컬 회귀 검사를 기록합니다.
4. `npm run build -- --local`로 정적 번들을 빌드합니다. 배포 시 빌드는 Vercel의 Git 저장소·커밋·도메인 시스템 변수를 이용해 `public/aleph.json`을 생성합니다.
5. 필요한 Supabase 구성은 기존 환경의 서버 전용 설정 화면에서만 지정합니다. 서버 키·비밀번호·토큰·기기 개인키를 파일/콘솔/스크린샷/제출 JSON에 복사하지 않습니다.
6. DB 마이그레이션은 현재 적용 상태와 스키마/정책을 먼저 확인한 뒤 **필요한 항목만** 순서대로 적용합니다. 기존 실습 메모·불변 감사 기록·다른 팀의 데이터를 삭제하거나 재초기화하지 않습니다. 변경 전 백업을 확보합니다.
7. 배포된 `/aleph.json`의 `step`·`repoUrl`·`commit`과 공개 첫 화면의 작전실을 확인합니다.

## 3. API/로컬 검증 분리

- **실제 API 읽기 전용:** 작전실의 `익명 GET 실제 API 검사`는 공개 자료와 승인되지 않은 GET 경로에만 접근합니다. 쿠키 및 인증 헤더를 보내지 않으며 요청 본문을 저장하지 않습니다. HTTP 응답 상태, 사전에 정한 최소 필드, 요청 시각만 증거로 저장합니다. 네트워크 오류는 통과가 아닙니다.
- **로컬 모의:** `판정·탐지 로컬 모의 검사`는 12개의 가상 계약 사건을 평가합니다. 이 응답은 실제 사용자 세션 및 운영 집행과 무관합니다.
- **실제 로그인 및 권한:** 가상의 A/B 사용자 및 승인된 인증기로 보호 GET을 호출하고 API 상태·대상 소유권·시각을 확인합니다. 실서버 요청 ID 헤더가 있으면 별도 수집하며, 브라우저가 자체 발급한 요청 ID를 서버 추적 ID라고 주장하지 않습니다.
- **변경·복원:** 실제 학생 메모를 쓰지 않고, 별도 격리된 테스트 데이터와 침해 전 검증 사본을 사용합니다. 정상 CRUD와 교차 소유권 차단, B 복원, 변조 사본 거부를 **실제 결과를 받은 뒤에만** 표기합니다. 복구 감사 영수증과 변경 전후 메모 수·소유권·정책·이력을 확인합니다.
- **실제 회수:** 운영 엔진이 검증한 사건 전달, 실제 회수 조치 및 조치 후 401/403을 독립적으로 확인합니다. 학생 `detect()`의 `propose_revocation`만으로 실제 회수 성공을 주장하지 않습니다.
- 41종 항목은 `src/stage12-cases.mjs`에 있으며 **구현된 모든 항목이 자동 실행되는 것은 아닙니다**. 언제든 미실행은 미실행이라고 기록합니다.

## 4. 증거 기록 취급

작전실은 테스트 시각, 테스트 ID, 요청 방법·경로, 기대 결과, 실제 HTTP 상태 또는 로컬 모의 결과를 구별합니다. `stage12-browser-evidence.json`을 내려받아 별도 관리할 수 있습니다. 메모 원문·비밀번호·액세스/리프레시 토큰·인증 서명·서버키는 저장하지 않습니다.

기록 가져오기 기능은 스키마, 41종 고유 ID, 시각, 출처, 허용 상태 코드 및 해당 경로를 **전부 검사**하고 유효하지 않은 파일이면 기존 결과를 유지합니다. 불러온 내용의 참·거짓은 암호학적으로 증명되지 않으므로 “가져온 기록 · 재확인 필요”로만 표시하며 통과 점수에 반영하지 않습니다. 운영 엔진과 연동한 서명 검증 보고서로 대체하려면 별도 공식 계약이 필요합니다.

## 5. 장애 시 원상복구

1. 먼저 `git status`, `git diff`로 현재 수정과 이전 단계를 구분합니다. `git reset --hard`나 DB 전체 초기화를 실행하지 않습니다.
2. `npm run policy:check`로 보호 정책의 고정 체크포인트/현재 버전과 변경 범위를 확인합니다. 위험한 변경이 발견되면 정책 복구 실행 전 계획 해시, 변경 대상 및 **사본 재조회 검증**을 수행합니다.
3. 복구 대상의 침해 이전 정상 사본과 해시·제목·소유자·행 ID를 확인합니다. 사본이 없거나 다르면 추정 복구를 실행하지 않습니다.
4. 복구는 허가된 가상 B의 대상 1건에 한정하며, 기존 A·다른 B·다른 서비스 기록을 비교해 보존합니다. SQL 함수의 성공 반환 및 감사 이벤트 ID를 서버·DB에서 재확인합니다.
5. 정책/메모/DB 감사 기록과 운영 회수 상태를 별도 증거로 남깁니다. 인증서명·비밀값은 기록하지 않습니다.

## 6. 최종 저장점·제출

```sh
npm ci
npm run test:12
npm run test:10
node --test test/step11.test.mjs
npm run build -- --local
git status
git diff
git add README.md docs/STAGE12_RUNBOOK.md public/index.html src/stage12-* src/browser-app.js aleph.config.json scripts test/stage12.test.mjs .github/workflows/stage12-war-room.yml package.json
git commit -m "12단계 저장점"
# 배포 상태와 /aleph.json을 확인한 후, 비추적 bundle-notes.json에 사실 기반의 실행 설명 작성
npm run bundle
```

`npm run bundle`은 실행 환경의 실제 배포 API에 익명 확인 요청을 보냅니다. `artifacts/submission.json`을 제출하되 이 파일 및 `bundle-notes.json`을 Git에 올리지 않습니다. 실행하지 않은 배포·API 시험을 통과로 채우지 않습니다.

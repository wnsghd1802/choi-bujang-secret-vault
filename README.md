# BYTE BACK 방어전 — 9단계: 도플갱어 탐지 및 권한 회수 제안

- **탐지 구현:** `src/detect.mjs`는 문서 `docs/DETECT_EVENTS.md`에 정의된 `detect(events)` 계약을 그대로 따릅니다. 각 가상 사건의 `at`, `method`, `identity.sub`만 사용하며 데이터를 저장하거나 토큰·실명·메모 본문을 출력하지 않습니다.
- **규칙:** 같은 검증된 주체의 **GET 요청이 임의의 10분 구간 내에 120건을 초과할 때만** `{action:'propose_revocation',reasonCode:'burst_read',subject:<해당 sub>}`를 반환합니다. 정확히 120건, 다른 주체들의 합계, GET이 아닌 사건, 10분 밖의 분산 조회는 `{action:'observe'}`입니다. 입력 순서에 의존하지 않는 슬라이딩 윈도우 검사입니다.
- **한계:** 현재 사건 계약에는 실제 위치·네트워크·기기 ID·접근 권한의 실시간 회수 여부가 포함되지 않습니다. 따라서 그런 신호를 임의로 생성하거나 로그를 저장하지 않습니다. 탐지 함수는 **회수를 제안만** 하고 실제 토큰을 무효화하거나 접속을 차단하지 않습니다. 운영 엔진의 검증된 사건 전달 및 회수 집행, 회수 시간은 별도의 연동 및 시험이 필요합니다.
- **유지 사항:** 6단계 기기 등록, 7단계 복합 이상 확인, 8단계 자원 구역 판정과 심판 a/b별 메모 소유권, 기존 API·화면·DB는 변경하지 않았습니다. 배포 메타데이터만 9단계로 갱신하고 기존 URL·발급자·허용 경로·원본 API를 그대로 사용합니다.

로컬 테스트: `npm run detect:test` (공개 연습 6개), `node --test test/step9.test.mjs` (경계·오탐·시간창 15개 추가 검증), `npm run decider:test`, `npm run fixture:7`. 이 결과는 운영 사건 전달이나 심판 통과를 증명하지 않습니다.

저장점 커밋 후 로컬 비공개 `bundle-notes.json`을 준비하고 `npm run bundle`을 실행하면 제출용 `artifacts/submission.json`을 만들 수 있습니다. 이 두 파일은 Git에 커밋하지 않습니다.

---

# 8단계 재수정 — 판정기 목록 차단 및 심판 a/b 소유권 분리

이 기록이 아래의 이전 8단계 시도보다 **최신 기준**입니다. S08_OTHER_ZONE_ALLOWED 실패가 반복돼 심판이 단독으로 호출하는 판정과 실제 API의 소유권 책임을 나눠 다시 수정했습니다.

- 판정기 `src/decider.mjs`: `GET /notes/:id`와 `PUT /notes/:id` (또는 해당 `/api/notes/:id` 형태)의 **단일 메모 읽기·수정**만 허용합니다. `GET /notes`, `GET /api/notes` 등 전체 목록 경로, 공지 쓰기, 수상한 쿼리, export 및 다른 구역 경로는 `deny`입니다. 개별 메모의 주인 비교는 판정기에서 추정하지 않고 실제 API에 맡깁니다. 기기 등록과 복합 이상 접속 재확인 규칙은 유지합니다.
- 실제 메모 API `src/notes-api.mjs`: 서명이 검증된 심판 토큰의 `userId(sub)`, `runId(aleph_run)`, `identity(a/b)`를 구별해 `notes.owner_id`에 들어가는 결정적 UUID를 만듭니다(`src/note-owner.mjs`). 같은 `sub`여도 a/b는 서로 다른 소유자입니다. 생성·목록·개별 조회·수정·삭제 모두 같은 검증된 소유자 키로 범위를 한정합니다. 실제 학생 세션은 검증된 기존 사용자 UUID를 그대로 사용합니다. 별도 DB 마이그레이션이나 학생 메모 변환은 없습니다.
- 참고: 기존 자료실 화면의 목록 조회는 실제 API가 검증된 사용자별로 필터링하며, 판정기의 목록 허용 여부와 구별됩니다. 브라우저에서 제공한 `role`, `owner_id` 또는 임의의 a/b 값을 신뢰하지 않습니다. 강사 공지는 기존 서버 권한 검사가 유지되며 일반 학생에게 허용하지 않습니다.

검증 명령: `npm run decider:test`, `npm run fixture:7`, `node --test test/stage3.test.mjs test/step7.test.mjs test/step8.test.mjs test/step8-judge-isolation.test.mjs`. 로컬 검사는 실제 심판의 통과 증거가 아닙니다. 저장점 커밋 뒤 `npm run bundle`로 제출 JSON을 생성하세요. `bundle-notes.json` 및 `artifacts/submission.json`은 GitHub에 올리지 않습니다.

---

## 8단계 재점검: 독립 판정기에서 다른 구역 요청 허용 방지

심판의 `S08_OTHER_ZONE_ALLOWED` 결과(48/100)를 근거로 `src/decider.mjs`의 리소스 판정을 보완했습니다. 이전에는 `GET /notes/:id` 모양만 맞으면 소유자 증거 없이 임의 ID를 허용했습니다. 현재 요청 계약 `aleph.decision.v1`은 검증된 자원 소유자 또는 강사 역할을 제공하지 않으므로, 판정기가 단독 실행될 때 알 수 없는 개별 메모 ID의 GET/PUT/DELETE, 강사 공지 수정 및 우회 경로는 `deny / starter_not_ready`로 실패 폐쇄 처리합니다. ID 형식만으로 소유자를 추정하지 않습니다.

정확한 `GET /api/notes` 및 `POST /api/notes` 컬렉션 경로는 기존 서버의 검증된 로그인 및 `owner_id` 범위 제한에 위임합니다. 6·7단계에서 제공한 공개 **로컬 가상 요청** `GET /notes/demo`는 해당 테스트가 사용하는 검증 가능한 픽스처 조합에 한해서만 유지하며 실제 사용자 소유 메모라는 뜻이 아닙니다. `RULE_IDS` 및 응답 5개 필드는 유지합니다.

**한계 및 영향:** 운영 판정 엔진이 개별 메모의 소유자 확인 결과를 전달하지 않는 현재 계약 아래에서는 판정기에서 개별 ID의 정상 소유와 타인 소유를 동시에 구별할 수 없습니다. 판정기가 실제 API 앞에서 모든 개인 메모 요청을 강제한다면, 개별 메모 읽기·수정·삭제도 거부될 수 있습니다. 기존 자료실 API의 `owner_id` 필터와 웹 화면은 변경하지 않았지만, 정책 엔진과 연결한 상태의 완전한 기능 보장은 별도로 검증해야 합니다. 안전한 허용을 위해서는 운영 엔진이 검증한 소유자·강사 권한을 계약에 추가해야 합니다.

재현: `node --test test/step8-judge-isolation.test.mjs`, `npm run decider:test`, `npm run fixture:7`. 다른 구역 경로를 통한 허용 시도를 단독 판정기 테스트로 재현했으며, 테스트 결과는 운영 심판 결과가 아닙니다. 이전 8단계 테스트의 개별 자원 허용 기대값도 검증 불가 구역 거부로 정정했습니다. DB 자료·이전 단계 로직 및 비밀값은 변경하지 않았습니다.

---

# BYTE BACK 방어전 — 8단계: 자료마다 갈 수 있는 구역을 나눕니다

기존 `notes.id` UUID와 메모 응답 구조를 유지하면서, 서버 내부 자원 식별자를 `memo:<UUID>`와 `instructor_notice:<UUID>`로 분리했습니다(`src/resource-zones.mjs`). 화면 메뉴·원본 메모·기존 소유자 RLS·로그인 코드·XDR 방어 파일은 바꾸지 않았습니다.

판정기는 기존 `device_registered`, `step_up_required` 규칙과 새 `resource_zone` 규칙을 사용합니다. `service/method/route/path/queryLength`가 일치하는 **정확한 메모 경로**만 기존 권한 검사를 수행하는 API에 위임합니다. `id2`·중첩 경로·`export`·비어 있지 않은 쿼리·알 수 없는 경로, 강사 공지 수정은 판정기에서 거부합니다. 이유 코드는 등록 여부를 확인할 수 없는 신규 문자열 대신 기존 시작 틀의 `starter_not_ready`를 사용하여 실패 시 닫히도록 했습니다. `aleph.decision.v1`에는 메모 저장 소유자나 검증된 강사 역할이 제공되지 않으므로 이 정보가 있다고 가정하지 않습니다.

실제 `/api/notes` 및 `/api/notes/:id`는 검증된 토큰에서 얻은 `actor.userId`와 DB의 `owner_id`를 계속 비교합니다. 메모 API에 우회 쿼리를 넣거나 다른 사용자의 UUID를 요청해도 데이터가 반환되지 않도록 서버 경로 점검을 추가했습니다. 브라우저 요청 본문의 `role` 또는 `owner_id`를 권한 근거로 사용하지 않습니다.

새 `PUT /api/notices/:id`는 별도 **강사 공지 전용 API**입니다. 검증된 학생 세션 외에는 접근할 수 없으며, 서버에서 `instructor_grants.can_edit_notices`를 확인한 경우에만 `instructor_notices` 저장 항목을 수정합니다. 강사 권한 기록이 비어 있거나 테이블이 없다면 거부합니다. 누구도 강사라고 임의로 등록하지 않았습니다.

**수동 적용 필요:** `migrations/008-resource-zones.sql`은 기존 `public.notes`에 손대지 않고 새 `instructor_grants` 및 `instructor_notices` 테이블만 생성하며, anon/authenticated의 직접 테이블 접근은 허용하지 않습니다. 아직 실제 Supabase에 적용되지 않았으며 기존 자료는 그대로입니다. 진짜 강사 권한은 운영자가 신원을 별도 확인한 뒤 서버 측에서 저장해야 하고, 강사 판정 권한의 엔진 연동은 향후 운영 계약이 필요합니다. 따라서 현재의 심판용 로컬 검증은 실제 강사 수정 기능의 운영 성공 증거가 아닙니다.

검증: `npm run decider:test`, `npm run fixture:7`, `node --test test/step7.test.mjs test/step8.test.mjs`, `npm run build -- --local`. 커밋 후 로컬에서 비공개 `bundle-notes.json`을 준비하고 `npm run bundle`로 제출 묶음을 생성합니다. 이 결과를 심판 판정으로 기록하지 않습니다.

---

# BYTE BACK 방어전 — 7단계: 평소와 다른 접속은 다시 확인합니다

6단계의 `device_registered` 규칙을 유지하고 `step_up_required`를 추가했습니다. 운영 엔진이 검증하여 전달하는 `deviceRegistered`, `signals`, `recentEvents`, `stepUp`만 사용하며 미등록 기기는 언제나 `deny / device_not_registered`로 먼저 거부합니다.

로컬 가상 사건(`signals.source: judge_fixture`)에서 심야 시각, 처음 보는 네트워크, 낯선 지역, 5분 이내의 활동 급증이 **모두** 겹치면 `step_up / step_up_required`를 요청합니다. 지역이나 시각 한 가지가 달라지는 것만으로 사용자를 거부하지 않습니다. 복합 이상 사건이어도 운영 엔진이 검증한 최근 추가 확인(`stepUp.verified === true`, `authAgeSeconds` 0~900)이 있으면 다시 `allow / approved`로 판정합니다.

**운영 한계:** 현재 실제 접속 경로의 위치·네트워크 정보 출처는 `none`이고 값은 `unknown`입니다. 가상 `judge_fixture` 정보를 실제 위치 증거로 간주하지 않습니다. 기존 `/api/auth`에는 일반 로그인·갱신·로그아웃 기능만 있으며, 판정 엔진과 결합된 새 로그인 증명 확인 계약은 보이지 않습니다. 그러므로 실제 재로그인 토큰·인증서를 새로 만들거나 브라우저에서 신뢰하지 않습니다. 실제 재확인 UI/자료 차단은 운영 엔진의 별도 계약이 제공된 환경에서 검증해야 합니다.

검증: `npm run decider:test`, `npm run fixture:7`. 로컬 테스트는 운영 심판 통과를 의미하지 않습니다. 기존 자료실을 빌드할 때는 `npm run build -- --local`; 저장점을 커밋한 뒤 개인 환경에 비공개 `bundle-notes.json`을 준비하고 `npm run bundle`로 제출 JSON을 생성합니다. `bundle-notes.json`과 `artifacts/submission.json`은 Git에 넣지 않습니다.

기존 배포 주소, 로그인 발급자, 허용 경로, 원본 API, 사용자 DB 및 XDR 보너스 코드는 변경하지 않았습니다.

---

# BYTE BACK 방어전 — 6단계: 등록된 기기만 자료실에

운영 엔진이 검증하여 전달하는 `request.deviceRegistered` 값만 사용합니다. `true`인 요청은 `allow / approved`, `false`이거나 값이 없거나 잘못된 요청은 `deny / device_not_registered`로 판정합니다. `RULE_IDS`에는 실제 구현된 `device_registered` 규칙 하나만 둡니다. 브라우저가 보낸 기기 등록 주장이나 개인키를 사용하지 않습니다.

로컬 가상 요청 검사: `npm run decider:test` (등록 기기 통과 / 미등록 기기 거부). 기존 웹 화면과 자료 API를 확인하려면 `npm run build -- --local` 및 배포된 자료실에서 정상 로그인·자료 조회를 점검합니다. 이 로컬 검사는 실제 운영 릴레이의 기기 등록 확인이나 심판 통과를 증명하지 않습니다. 6단계 설정으로 `npm run bundle`을 실행하려면 저장점 커밋 후 로컬 `bundle-notes.json`이 필요합니다. 기존 5단계 화면·DB 권한·XDR 보너스 코드는 변경하지 않습니다.

---

## 보너스 XDR-02 저장점

웹 입력 조작 보너스 과제를 `xdr/web-injection/`에 독립 모듈로 추가했습니다. `decide.mjs`는 **import/Jev/외부 요청/파일 I/O 없이** 원본 경보만으로 SQL 주입, 스크립트 삽입, 경로 이탈, 명령 구분자의 반복 단서를 판정합니다. T1190 태그나 수업 단어만으로 차단하지 않습니다.

재현 명령: `npm run xdr:run -- web-injection`. 검사: `node --test xdr/web-injection/regression.test.mjs test/xdr-run.test.mjs`. 후보 차단/로그 모의 재생: `node xdr/web-injection/replay.mjs`. 공개 가상 경보 26건의 로컬 결과는 block 8, alert 9, record 9이며 정상 요청 차단은 0건입니다. 숫자는 목표나 비공개 심판 정답이 아닙니다.

`respond.mjs`는 검증된 출발 IP와 등록된 ZTNA 거부 응답을 외부에서 제공받아야 하는 **연결 어댑터**입니다. 현재 실제 반 엔진은 IP 필드를 제공하지 않으므로 운영 차단은 미연결입니다. 기존 무차별 로그인 규칙, ZTNA 판정 규칙, 경보 원본, 배포/DB 설정은 변경하지 않았습니다.

# BYTE BACK 방어전 — 5단계: 자료 요청을 서버 한곳으로

## 보너스 XDR-01 저장점

`npm run xdr:run -- brute-force`로 수업용 무차별 로그인 경보를 분류합니다. **기존 분류 건수는 정답이 아니며 유지 조건으로 사용하지 않습니다.** 행동 근거가 명확한 공격은 `block(1.0)`, 불충분한 의심은 `alert(0.5)`, 정상 활동은 `record(0.1)`로 판정합니다. 외부 판정 서비스 호출 없이 구현했으며 반복 로그인 실패와 Password Spraying을 탐지합니다. 단순 실패 횟수뿐 아니라 시간 범위, 시도 패턴, 계정 분산을 검사하고, 다량의 실패 뒤 성공한 사례도 자동으로 정상 처리하지 않습니다.

테스트: `node --test test/brute-force.test.mjs test/xdr-run.test.mjs xdr/brute-force/regression.test.mjs xdr/brute-force/evidence.test.mjs`. 추가 공격 문장, 의심·정상 사례, IP별 누적·중복 제거 및 실패 로그 검증 기준은 [XDR-01 검증 결과](xdr/brute-force/VALIDATION.md)를 참고하세요. 테스트 결과와 운영 심판 판정은 별개입니다.

`node xdr/brute-force/replay.mjs`로 로컬 모의 거부 후보와 만료 시각 및 근거 경보 ID를 확인할 수 있습니다. 실제 ZTNA 서버와 연결되어 있지는 않습니다. `docs/DECIDER_REQUEST.md`의 계약에 출발 IP가 없어 기존 판정기 계약을 임의로 수정하지 않았습니다. 기존 자료실 코드·배포 설정·DB는 변경하지 않았습니다.

## 현재 기능

- 브라우저의 메모 직접 Supabase 호출은 없음: 기존 `/api/notes` 경로를 유지합니다.
- 메모 읽기·추가·수정·삭제는 서버가 로그인 토큰과 소유자를 확인한 뒤 처리합니다. 원본 `src/verify-login.mjs`는 변경하지 않았습니다.
- 추가 점수 항목을 위해 로그인·갱신·로그아웃도 `/api/auth`에서 공식 Supabase SDK로 처리합니다. 브라우저 번들에 Supabase 공개 키나 서버 키를 포함하지 않습니다.
- 로그인 응답은 해당 사용자 세션에 필요한 토큰·만료 시각·사용자 ID만 포함합니다. 서버는 요청마다 새 SDK 클라이언트를 사용하며 비밀번호·토큰을 로그에 남기지 않습니다.
- 브라우저 세션은 sessionStorage에 보관합니다. 업그레이드 후 다시 로그인하세요. 메모 응답 규격과 A/B 소유권 검사는 4단계와 같습니다.

## DB 적용

기존 4단계 DB에서 `migrations/005-server-only.sql`을 실행합니다. public.notes의 PUBLIC·anon·authenticated 테이블 및 열 권한만 회수합니다. RLS와 기존 네 소유자 정책, 서버 권한, 데이터 및 다른 테이블은 유지합니다.

실행 전후 information_schema.role_table_grants와 has_table_privilege 결과를 비교합니다. 최종 결과:

| 역할 | SELECT / INSERT / UPDATE / DELETE | RLS |
|---|---|---|
| anon | 모두 false | true |
| authenticated | 모두 false | true |
| service_role | 모두 true | true |

로그인한 사용자도 Supabase Data API로 메모에 직접 접근하지 못합니다. 서버 전용 역할은 RLS를 우회하므로 서버의 로그인·소유자 검사가 계속 필요합니다. 이전 단계의 권한 SQL을 다시 실행하면 직접 접근 권한이 열릴 수 있으므로 재실행하지 않습니다.

## 설정과 빌드

기존 Vercel 환경변수 SUPABASE_URL, SUPABASE_SECRET_KEY를 그대로 사용합니다. 새 환경변수는 필요하지 않습니다. 키를 소스나 공개 파일에 넣지 않습니다.

```sh
npm ci
node --test test/*.test.mjs
npm run build -- --local
```

aleph.config.json은 단계 5와 실제 메모 API의 allowedRoutes를 기록합니다. originalApiUrl은 쿼리 없는 `https://fgluruiqasiexuqjvzhq.supabase.co/rest/v1/notes`입니다. 배포 시 생성하는 /aleph.json에도 단계·커밋·allowedRoutes·originalApiUrl을 기록합니다. 공개 data.json은 빈 목록이며 첫 화면에 nosniff 헤더를 유지합니다.

## 검증과 남은 한계

로컬 API/인증 테스트 15개와 빌드가 통과했습니다. 인증 테스트는 실제 SDK에 모의 응답을 연결하여 로그인·갱신·로그아웃 요청, 세션 응답 최소화, 오류 처리 및 키 비노출을 확인합니다. 실제 계정 로그인 성공을 대신하지 않습니다.

임시 PostgreSQL 환경에서 기존 4단계 검사 23개와 추가 5단계 검사 15개가 통과했습니다. anon/authenticated 직접 CRUD 거부, service_role CRUD 유지, 데이터·네 정책·다른 테이블 보존 및 SQL 재실행을 확인했습니다. 실제 Supabase 적용 여부는 사용자의 실행 결과로 별도 확인합니다.

배포 후 확인할 항목:
- A와 B 각각 자신의 메모만 보고 추가·수정·삭제·로그아웃할 수 있는지.
- 비로그인 메모 요청이 JSON 401이고 타인 ID 접근이 거부되는지.
- 공개 키 및 로그인 토큰으로 원본 Data API에 직접 접근해도 자료가 반환되지 않는지.
- 화면 번들에 공개/서버 키가 없고, /aleph.json 경로 정보와 보안 헤더가 유지되는지.

과거 커밋과 옛 배포에 남은 공개 기록을 삭제한 것은 아닙니다. 공개 키를 화면에서 제거하는 것만으로 권한이 보호되는 것도 아닙니다. 실제 직접 접근 차단은 DB 권한 회수로 보장합니다. 로그아웃해도 이미 발급된 액세스 토큰은 만료 전까지 유효할 수 있습니다. 브라우저 세션 토큰은 JavaScript가 접근할 수 있으므로 XSS 방어도 계속 필요합니다.

## 저장점과 제출

변경을 `5단계 저장점`으로 커밋·배포한 뒤 확인합니다. 제외된 bundle-notes.json에 실제 확인과 미확인 사항을 구분해 적고 npm run bundle을 실행합니다. 제출 묶음은 커밋하지 않습니다.

자동 점검은 익명 거부·공개 자료·메타데이터·헤더·브라우저 키 비노출을 검사합니다. 원본 직접 읽기 검사는 로컬 SUPABASE_PUBLISHABLE_KEY가 있을 때만 실행하고 없으면 미실행으로 기록합니다. 실제 A/B 로그인 및 교차 접근 검사를 수행하지 않았으면 수행했다고 기록하지 않습니다.

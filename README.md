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

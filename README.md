# BYTE BACK 방어전 — 4단계: 로그인해도 내 자료만

## 현재 기능

- Supabase 이메일·비밀번호 로그인/로그아웃과 원본 `src/verify-login.mjs`를 유지합니다.
- 메모 목록·단건 조회·수정·삭제는 모두 서버에서 검증한 사용자 ID와 `owner_id`가 같은 행만 다룹니다.
- 단건 GET·PUT·DELETE의 ID 조건과 소유자 조건을 같은 DB 쿼리에 넣습니다. 타인 자료와 없는 자료는 동일한 JSON 404를 반환합니다.
- 추가 시 소유자는 검증된 ID로 강제 지정합니다. 수정은 제목·본문만 갱신하고 소유자는 유지합니다. 다른 `owner_id`로 바꾸는 PUT은 403으로 거부합니다.
- 응답·입력 규격은 유지합니다. POST `{id?,title,body}`, PUT `{title,body}`, 단건 응답 `{id,title,body}`, 목록은 본인 메모 배열, 삭제 응답 `{id,deleted:true}`.
- 토큰이 없거나 유효하지 않으면 자료 없이 JSON 401. 보안 헤더와 빈 공개 JSON을 유지합니다.

## DB 적용 순서

1. 공식 Authentication 화면에서 A·B 두 계정을 준비합니다. 비밀번호는 공유하지 않습니다.
2. 공개 저장소 밖의 시험 자료 SQL에서 A·B 이메일을 직접 입력합니다. auth.users에서 ID를 찾아 기존 가상 자료 네 건을 A에 연결하고 B 시험 메모 한 건을 준비합니다. 이메일이나 메모 본문을 포함한 파일은 GitHub에 올리지 않습니다.
3. SQL Editor에서 `migrations/004-owner-rls.sql`을 실행합니다. 이 파일은 public.notes만 변경합니다.

DB 정책은 PUBLIC·anon·authenticated의 기존 테이블/열 권한을 회수하고, authenticated에 SELECT·INSERT·UPDATE·DELETE만 허용합니다.
SELECT·DELETE는 기존 행 USING, INSERT는 새 행 WITH CHECK, UPDATE는 USING과 WITH CHECK 모두 `(select auth.uid()) = owner_id`를 검사합니다.
동일 테이블의 오래된 정책을 교체하여 permissive 정책이 합쳐져 제한을 우회하지 않게 합니다. 다른 테이블은 변경하지 않습니다.
SQL의 실행 전후 결과로 information_schema.role_table_grants와 has_table_privilege를 대조합니다. 최종 결과는 anon 4개 권한 false, authenticated 4개 true, RLS true, 정책 4개입니다. authenticated의 true는 모든 행 접근이 아니라 RLS가 허용하는 자기 행의 작업 권한입니다.

서버 전용 service_role은 RLS를 우회하므로 서버의 소유자 검사도 반드시 유지합니다. 심판 시험 계정은 Supabase auth.users 외래키 없이 원본 검증 도우미로 인증한 ID를 사용합니다.
기존 `migrations/003-auth-notes.sql`은 이전 단계 기록입니다. 4단계 정책 적용 후 다시 실행하지 않습니다.

## 설정·빌드

기존 Vercel `SUPABASE_URL`, `SUPABASE_SECRET_KEY`를 유지합니다. 공개 URL과 publishable key는 `src/browser-config.js`에 있습니다.
`aleph.config.json`에는 단계 4, 실제 발급자, 실제 GET·POST·PUT·DELETE 경로가 기록되어 있습니다. `judgeIssuer`와 로그인 검증 도우미는 원본을 유지합니다.

```sh
npm ci
node --test test/*.test.mjs
npm run build -- --local
```

실제 배포 빌드는 `/aleph.json`에 해당 GitHub 커밋과 단계 4를 기록하고, 화면용 SDK 번들을 생성하며, 공개 `data.json`을 빈 목록으로 유지합니다.

## 검증과 남은 한계

API 단위 테스트는 A·B 각각 정상 CRUD, 상대 ID 직접 조회·수정·삭제 거부, 소유자 변경 거부, 타인 메모 내용·존재 정보 비노출, 위조·만료·다른 서비스용 토큰 거부를 확인합니다.
임시 PostgreSQL 환경에서는 동일 정책 SQL의 A/B 행 접근·쓰기 제한, 익명 거부, 소유권 이전 거부, 기존 데이터와 다른 테이블 보존, SQL 재실행을 확인했습니다. 이것은 실제 Supabase 적용 결과나 운영 심판 판정이 아닙니다.

배포 후 확인:
- A·B는 각자 자기 메모만 보고 추가·수정·삭제할 수 있어야 합니다.
- 상대 ID를 직접 지정한 GET·PUT·DELETE는 404, 소유자 이전 PUT은 403이어야 합니다.
- 비로그인 요청은 JSON 401, 공개 자료는 0건, nosniff 헤더가 있어야 합니다.
- 공개 키만 사용한 Supabase Data API 접근은 거부되어야 합니다. authenticated 직접 DB 접근은 로컬 정책 시험과 구분해 기록하며 심판 재현 가능 범위를 과장하지 않습니다.
- `/aleph.json`의 단계·커밋을 GitHub와 비교합니다.

과거 공개 커밋·옛 배포는 여전히 남습니다. 이전 배포 주소가 자동으로 보호된다고 주장하지 않습니다. 로그아웃한 액세스 토큰도 만료 전까지 유효할 수 있으며 즉시 회수는 구현하지 않았습니다.

## 저장점과 제출

변경을 `4단계 저장점`으로 커밋·배포한 뒤 검사합니다. 비밀값과 메모 본문은 포함하지 않습니다.
제외 처리된 `bundle-notes.json`에 실제 확인 및 미확인 결과를 기록하고 `npm run bundle`로 배포 자기 점검을 실행합니다.
이 점검은 비로그인 거부와 공개 자료·메타데이터·헤더를 확인합니다. A/B 교차 접근 검사를 수행하지 않았으면 수행했다고 적지 않습니다.
정상 사용자 시험은 사용자 확인, 로컬 합성 시험은 로컬 결과, 실제 배포 HTTP 검사는 실제 결과로 구분합니다. 제출 묶음과 bundle-notes.json은 커밋하지 않습니다.

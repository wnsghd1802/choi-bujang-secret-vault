# BYTE BACK 방어전 — 3단계: 진짜 로그인

## 현재 기능

- Supabase 공식 SDK의 이메일·비밀번호 로그인과 로그아웃을 사용합니다. 브라우저에는 공개 URL과 publishable key만 포함합니다.
- 서버는 원본 `src/verify-login.mjs`로 토큰을 검증합니다. 이 도우미는 수정하지 않았습니다. 사용자 ID나 역할을 브라우저 입력으로 신뢰하지 않습니다.
- `/api/notes`의 GET은 로그인 사용자의 메모 배열, POST는 `{id?,title,body}`를 받아 `{id,title,body}`를 반환합니다. ID를 생략하면 서버가 UUID를 만듭니다.
- `/api/notes/:id`의 GET·PUT·DELETE는 토큰이 필요합니다. PUT 입력은 `{title,body}`, 단건 응답은 `{id,title,body}`, 삭제 응답은 `{id,deleted:true}`입니다. 없는 메모는 404입니다.
- POST의 `owner_id`는 검증된 로그인 사용자 ID로 저장합니다. 브라우저가 보낸 `owner_id`, `userId`, `role`은 무시합니다.
- 메모 본문은 DB의 `content` 열에 저장하고 API에서는 `body`로 매핑합니다.
- 토큰이 없거나 유효하지 않으면 자료를 내보내지 않고 JSON 오류와 401을 반환합니다. 모든 자료 응답은 `no-store`입니다.

## 이번 단계에 남는 약점

로그인 확인은 소유권 확인과 다릅니다. **단건 GET·PUT·DELETE는 아직 소유자를 검사하지 않습니다.** 다른 계정의 ID를 알면 접근할 수 있는 허점은 4단계에서 고칩니다. 목록만 로그인 사용자 소유 메모로 제한합니다.
로그아웃해도 이미 발급된 액세스 토큰은 만료될 때까지 유효할 수 있습니다. 즉시 토큰 회수 기능을 구현했다고 주장하지 않습니다.
이전 공개 커밋·옛 배포 이력은 남아 있습니다. 과거 노출은 해소되지 않았습니다. 가상 자료만 사용합니다.

## DB 준비

같은 Supabase 프로젝트의 SQL Editor에서 `migrations/003-auth-notes.sql`을 실행합니다.
기존 메모 본문과 `owner_id`를 보존하고 숫자 ID를 UUID로 바꿉니다. RLS를 유지하고 일반 역할의 직접 접근을 차단하며 서버 역할에 CRUD 권한을 부여합니다.
기존 네 메모는 소유자가 없는 상태로 DB에 남습니다. 새 계정의 목록에 자동 배정하지 않습니다. 로그인 뒤 직접 추가한 메모가 내 목록에 표시됩니다.
`owner_id`에는 auth.users 외래키를 걸지 않습니다. 제공된 심판의 시험 계정도 확인 도우미를 통해 요청할 수 있어야 합니다.

## 계정과 환경변수

Supabase Authentication → Users에서 실습용 계정 A를 준비합니다. 비밀번호는 공식 입력 화면에서 직접 설정하며 코드·Git·채팅에 공유하지 않습니다.
이메일 인증을 요구하는 설정이면 인증을 완료해야 로그인됩니다. 가입 버튼은 이번 화면에 구현하지 않았습니다.

Vercel의 기존 `SUPABASE_URL`, `SUPABASE_SECRET_KEY` 환경변수를 유지합니다.
`SUPABASE_URL`은 `aleph.config.json`의 identityProvider 발급자와 같은 프로젝트여야 합니다.
공개 URL과 키는 `src/browser-config.js`, 검증 발급자·대상·JWKS 및 실제 API 경로는 `aleph.config.json`에 있습니다.
`judgeIssuer`와 `src/verify-login.mjs`는 원본 그대로 유지했습니다.

## 빌드와 검사

```sh
npm ci
node --test test/*.test.mjs
npm run build -- --local
```

`npm run build`는 공식 SDK를 브라우저용 `public/app.js`로 묶고, 공개 JSON을 빈 목록으로 유지하며 `/aleph.json`을 실제 Vercel 환경정보로 생성합니다.
서버 전용 파일이나 환경변수는 브라우저 빌드에 포함하지 않습니다. Vercel에 서버 키를 저장한 뒤 GitHub 변경을 배포합니다.
보안 헤더 `X-Content-Type-Options: nosniff`는 유지합니다.

로컬 테스트는 실제 Supabase 계정 로그인이나 배포 성공을 대신하지 않습니다. 합성 키와 시험 토큰으로 서명 위조·만료·잘못된 대상·다른 발급자 거부, 인증 없는 읽기와 쓰기 거부, 서버 소유자 지정, CRUD/404와 오류 정보 비노출을 검사합니다.

## 배포 후 직접 확인

1. 시크릿 창에서 자료 대신 로그인 화면이 나타나는지 확인합니다.
2. `/api/notes`에 토큰 없이 GET/POST, 단건 경로에 GET/PUT/DELETE를 보내 JSON 오류와 401/403인지 확인합니다.
3. A 계정으로 로그인하고 가상 메모 추가 → 수정 → 삭제 → 로그아웃을 확인합니다. 비밀번호·토큰은 검사 기록에 출력하지 않습니다.
4. 서버 키가 브라우저 코드에 없는지 확인합니다. `/data.json`은 메모 0건이어야 합니다.
5. `/aleph.json`의 단계 3·저장소·커밋과 실제 GitHub 배포를 대조합니다.
6. 로그인 없는 Supabase 직접 DB 읽기는 거부되어야 합니다. 정상 로그인과 별개 검사입니다.

## 저장점과 제출

변경을 `3단계 저장점`으로 커밋한 다음 실제 배포에서 검사합니다.
제외 처리된 `bundle-notes.json`에 실제 확인과 미확인 사항, 남은 약점을 기록하고 `npm run bundle`을 실행합니다.
`src/attack-check.mjs`는 배포된 URL에 직접 요청하여 비로그인 거부와 공개 파일·메타데이터·헤더를 검사합니다. 사용자 비밀번호나 토큰은 요구하지 않으며 정상 A 계정 CRUD는 별도로 확인해야 합니다.
제출 묶음과 로그에 비밀키·사용자 토큰·메모 본문을 넣지 않습니다. 로컬 자기 점검은 운영 심판 판정이 아닙니다.

# BYTE BACK 방어전 — 2단계

## 현재 기능과 남은 한계

- 화면은 Vercel 서버 함수 `GET /api/notes`에서 가상 자료를 받아 표시합니다.
- 메모는 Supabase `public.notes`에만 보관합니다. 저장소의 `data.json`과 `public/data.json`은 빈 목록입니다.
- `owner_id uuid` 칸은 준비되어 있으나 아직 사용자 연결이나 로그인은 구현하지 않았습니다.
- DB 테이블은 RLS를 켜고 `anon`과 `authenticated`의 직접 읽기 권한을 제거합니다. 서버 역할만 읽습니다.
- **서버 API는 아직 공개되어 있습니다.** 누구나 `/api/notes`로 가상 자료를 읽을 수 있습니다. 인증은 3단계 작업이며 실제 개인정보를 넣으면 안 됩니다.
- 이전 공개 커밋과 이전 배포에는 옛 자료가 남습니다. 현재 파일에서 제거해도 과거 공개 이력은 삭제되지 않습니다. 과거 노출을 해결했다고 주장하지 않습니다.

## 서버 설정과 배포

Vercel 프로젝트의 Environment Variables에 다음 두 값을 등록합니다.

- `SUPABASE_URL`: 이번 실습용 Supabase 프로젝트 URL
- `SUPABASE_SECRET_KEY`: 같은 프로젝트의 서버 전용 Secret key

키는 Vercel의 비밀 입력란에만 저장합니다. 브라우저 코드, Git, 로그, 제출 묶음에는 넣지 않습니다. 환경변수 변경 후에는 새 배포가 필요합니다.

Supabase 테이블: `public.notes(id bigint primary key, owner_id uuid, title text, content text)`.
실습 SQL은 공개 저장소 밖에서 SQL Editor로 실행합니다. 메모 본문이 포함된 SQL 파일은 커밋하지 않습니다.

Vercel은 루트 `api/notes.js`를 서버 함수로 배포하고 `public`을 정적 파일로 배포합니다.
`npm run build`는 공개 자료를 빈 목록으로 만들고 Vercel 시스템 변수에서 실제 커밋과 저장소를 읽어 `/aleph.json`을 생성합니다.
`X-Content-Type-Options: nosniff`를 응답에 적용합니다.

## 로컬 검사

```sh
npm ci
node --test test/*.test.mjs
npm run build -- --local
```

로컬 빌드는 정적 결과물만 준비하며, Vercel 서버 함수나 실제 Supabase 연결 성공을 증명하지 않습니다.
정상 결과: 코드 검사 통과, 공개 JSON의 메모 0건.
거부 결과: 자료 API의 POST 요청은 405, 서버 설정 누락은 503, DB 오류는 비밀값 없는 502 응답.

## 현재 파일의 메모·비밀값 검사

공개 자료에서 문장을 다시 복사해 저장하지 말고, DB에 보관한 메모 문장으로 최신 작업 파일과 배포 정적 파일을 비교합니다.

```sh
git grep -n -E '실습용 가상 .* 기록' -- .
```

검색 결과가 없어야 합니다. 키 검사 결과에는 값 자체를 출력하지 않습니다.
외부 검사 결과나 옛 커밋을 현재 커밋 검사 결과로 대신하지 않습니다.

## 배포 후 직접 확인

1. 첫 화면에 가상 자료 카드 네 개가 표시되는지 확인합니다.
2. `/data.json`의 메모가 0건인지 확인합니다.
3. `/aleph.json`의 단계 2, 저장소, 커밋을 실제 배포와 비교합니다.
4. 첫 화면 응답의 `X-Content-Type-Options`가 `nosniff`인지 확인합니다.
5. `/api/notes`는 비로그인으로도 읽힙니다. 이 남은 약점을 기록합니다.
6. 공개용 Supabase 키로 DB 직접 읽기는 거부되어야 합니다. SQL 결과만으로 실제 HTTP 검증까지 했다고 기록하지 않습니다.

## 저장점과 제출 묶음

실제 검사 후 커밋을 만들고, 제외 처리된 `bundle-notes.json`에 `explanation`(변경·검사·남은 한계 설명)과 `blockedAt`을 기록한 뒤 `npm run bundle`을 실행합니다.
이 명령은 배포에 실제 요청을 보내 점검합니다. 생성된 `artifacts/submission.json`과 `bundle-notes.json`은 커밋하지 않습니다.
배포가 이전 커밋이면 먼저 배포를 완료합니다. 로컬 점검은 수업 포털의 심판 판정이 아닙니다.

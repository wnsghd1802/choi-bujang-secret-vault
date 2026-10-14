## 11단계 — 설치형 웹앱 및 서버 검증 기기 승인 (2026-10-14)

- 기존 로그인 자료실에 PWA manifest, 설치 안내, 승인 요청·결과 화면을 추가합니다. 설치했다는 표시나 브라우저 저장값은 승인 근거가 아닙니다.
- 학생의 보호 API 요청에는 서명된 로그인 JWT 외에도 서버 DB에서 승인된 P-256 공개키로 검증한 요청별 서명이 필요합니다. 서명에는 경로·메서드·본문 지문·시각·일회용 난수·토큰 지문·검증 사용자 ID가 포함됩니다. 난수 재사용은 DB에서 거부합니다.
- `migrations/020-stage11-device-approval.sql`을 적용하면 기기 등록 요청은 `pending`으로만 기록됩니다. 관리자는 별도 신원 확인을 완료한 뒤 Supabase Table Editor에서 해당 행의 `state`를 `approved`로 변경해야 합니다. 앱 화면에서 직접 승인하거나 단순히 설치한 것만으로 권한을 주지 않습니다.
- 기기 개인키는 비추출 가능한 브라우저 CryptoKey로 생성하여 IndexedDB에 보관합니다. 기기키가 없거나 승인되지 않은 상태에서는 자료실을 보여주지 않고 서버가 API 접근을 거부합니다. 다른 브라우저·기기는 별도 승인되어야 합니다.
- 10단계 서명된 심판 요청과 DB 복구 로직은 그대로 유지합니다. 서비스 워커는 공개 앱 셸만 저장하고 인증 API 및 보호 자료는 캐시하지 않습니다.
- 자체 검증: `npm ci && node scripts/build-public.mjs --local && node --test test/step11.test.mjs && npm run test:10 && npm run decider:test`. 최종 제출은 `11단계 저장점` 커밋 후 `npm run bundle`. 실제 심판 점수는 미확인입니다.

---

## 10단계 — 복원 전 전체 사본 무결성 검증 (2026-10-14)

- 직전 심판 결과: `9757f488` 48/100점, 미통과 `S10_AUDIT_DROPPED`. 이번 변경의 심판 평가 결과는 **미확인**입니다.
- 문제: 기존 저장값 `content_sha256`은 본문만 보호합니다. 제목만 변조하는 경우 본문 해시가 유지될 수 있습니다. 침해 후 기록된 해시를 원본의 증명으로 오인해서도 안 됩니다.
- `migrations/019-stage10-full-snapshot-reverification.sql`: **새로 생성되는** 백업/변경 전 사본에 대해 `id`, `owner_id`, `run_id`(변경 직전 사본은 내부 구분값), `identity`, `title`, `content`를 하나의 SHA-256 검증값에 묶습니다. 불변 저장소에 최초 INSERT 시점에 기록하고, 복원 함수가 **메모 변경 전** 이 검증값을 대조하고 복원 후 사본 재조회에서도 재확인합니다.
- 이전 사본이 있다면 자동으로 진짜 원본이라고 봉인하지 않도록 마이그레이션이 **실패하고 수동 검증을 요구**합니다. 기존 메모·감사 이력은 그대로 두며 기존 복구 경로와 감사 영수증 생성은 유지합니다.
- `test/fixtures/stage10-full-snapshot-reverification.sql`은 제목만 조작하고 본문 해시는 정상인 가상 백업을 만들어 **복원·감사 변경을 모두 거부**하는지 시험합니다. 정상 사본의 복원·감사 생성도 검사합니다.
- 한계: SHA-256은 원본의 **사후 변경 여부**를 확인하는 장치이지, 심판이 실제 침해 전에 사본을 만들었는지 증명하는 외부 서명은 아닙니다. DB 소유자 권한 공격자가 데이터와 해시를 함께 조작하면 별도 신뢰할 만한 서명/감사 기준이 필요합니다.

---

## 10단계 — SQL 직접 생성된 B 메모의 변경 직전 사본 확보 (2026-10-14)

- 이전 심판 판정 기준점: `40f429f8`, **48/100**, 유일 미통과 `S10_AUDIT_DROPPED`. 이 변경 후 심판 점수는 미확인입니다.
- **재현한 결함:** 심판이 메모를 독립 DB에서 먼저 INSERT하고 직접 UPDATE/DELETE하면, 기존 `POST /api/notes`의 사본 생성 RPC가 불리지 않으므로 백업도 감사 기록도 생성되지 않습니다.
- **새 복구 경로:** `migrations/018-stage10-direct-seed-prechange.sql`은 UUIDv5 소유자의 첫 UPDATE/DELETE *직전* `OLD` 행을 서버 비공개·불변 사본에 기록합니다. 기존 B 전용 안전 사본이 있으면 이중 저장하지 않습니다. SQL 직접 변경된 ID/소유자 계보도 저장합니다. UUIDv4 일반 학생 메모는 새 테이블로 복제하지 않습니다.
- **사용 제한:** `src/recovery-api.mjs`은 기존 서명 검증 B JWT와 정상 사본을 우선 확인한 뒤, 없을 때만 **서명된 B 토큰에서 유도된 UUIDv5 정규 소유자 + 지정한 1건**의 변경 전 사본을 검증·재조회하고 전용 SQL 함수로 복구합니다. DB 함수는 메모 원본·해시 및 대상 복구를 재검증하면서 감사 이벤트를 **실제 서명된 run ID**로 추가하고 영수증을 반환합니다. B가 아닌 사용자, 일반 학생의 메모, 다른 메모는 복구할 수 없습니다.
- **검증:** Supabase 실 DB의 `BEGIN ... ROLLBACK` 격리 SQL에서 API 우회 B INSERT → ID/소유자/본문 SQL 공격 → B 1건 복구 + 감사 추가 → 다른 사용자 기록 불변이 통과했습니다. SQL fixture 및 Node 핸들러 검사를 GitHub Actions에 추가했습니다.
- **한계:** 첫 변조 전에 트리거가 설치되어 있어야 하며, judge DB가 별개이면서 이 SQL 마이그레이션이 설치되지 않는 경우 효과가 없습니다. UUIDv5가 아닌 기존 judge sub UUIDv4 소유자 직접 생성도 자동으로 분류할 수 없습니다. UUIDv5는 공식적으로 B만 뜻하지 않으므로 A도 변조되는 경우 후보 사본이 저장될 수 있지만, A JWT로 B 복구를 실행할 수는 없습니다. 이 변경이 심판 판정에 반영되는지는 다음 제출로 확인해야 합니다.

---

## 10단계 — 정책 복구 감사 영수증 누락 보완 (2026-10-14)

- **심판 현황:** 직전 `a6e1644e` 제출 48/100점, 미통과 `S10_AUDIT_DROPPED`. 이번 변경의 심판 판정은 **미확인**입니다.
- **직접 비교한 사실:** 실제 Supabase에서 가상 A, B 및 다른 B를 둔 후 안전 사본 생성·B 메모 ID/소유자/내용 변조·단일 메모 복구를 `BEGIN ... ROLLBACK`으로 실험했습니다. 복구 후 지정 B 외 모든 메모, 기존 감사 행, 다른 백업, B 사본, DB RLS 정책이 이전 상태와 일치했고, B 복구 감사 이벤트가 생성됐습니다. 현재 복구 RPC의 일반적인 범위 초과 변경은 재현되지 않았습니다.
- **다른 복구 경로의 확정된 감사 증거 공백:** `scripts/policy-recovery.mjs`는 정책 변경 전 사본을 검증하여 저장하지만, 완료된 정책 복구를 증명하는 별도 감사 영수증을 저장하지 않았습니다. 이에 **실제 정책 파일 변경 후** `artifacts/policy-recovery/<일회성 UUID>/policy-restore-event.json`을 `wx` 새 파일로 생성하고, checkpoint/현재 커밋/확인한 계획 해시/복구 파일의 전후 SHA256만 기록합니다. 내용·토큰은 저장하지 않습니다. 재조회에 실패하면 본 실행의 복구 대상만 롤백하고, 기존 감사나 다른 서비스 파일은 변경하지 않습니다.
- **독립 경로:** SQL의 `test_recovery_audit`는 메모 복구 영수증이고, 새 파일은 정책 복구 영수증입니다. 두 경로가 같은 심판 조건의 대상인지는 공개되지 않았으므로 점수 상승을 보장하지 않습니다.
- **제출 메타데이터 주의:** `scripts/bundle.mjs`의 `changedFiles`는 마지막 커밋의 변경 파일만 열거합니다. 직전 `a6e1644e`는 README만 변경했습니다. 이 사실과 48점의 인과관계는 미확인입니다.

---

## 10단계 — 신뢰한 행 변경 이력의 직접 조작 차단 (2026-10-14)

- **이전 심판 기준점:** `d28f1a35` 48/100점, 유일한 미통과 `S10_AUDIT_DROPPED`. **이번 보완의 심판 결과는 미확인**입니다.
- **기존 DB에서 확인한 결함:** `service_role`이 `public.test_b_mutation_lineage`의 INSERT/UPDATE/DELETE를 직접 할 수 있었습니다. 침해 이전 B 안전 사본이 있어도 임의 계보를 주입하면 정상 복구 함수가 **다른 소유자 A의 행을 B로 덮어쓰고 정상 감사 영수증을 발급**하는 경우를 `BEGIN ... ROLLBACK` 시험에서 재현했습니다. 기존 사용자 데이터는 변경하지 않았습니다.
- **최소 보완:** `migrations/017-stage10-lineage-write-gate.sql`에서 서버 역할의 직접 INSERT/DELETE/TRUNCATE를 회수하고, UPDATE는 복구 함수의 `SELECT ... FOR UPDATE`에 필요하므로 유지하되 **실제 DML은 테이블 소유자 권한에서 실행되는 신뢰한 DB 트리거만 통과**하도록 BEFORE UPDATE 게이트를 설치합니다.
- **격리 검증:** `test/fixtures/stage10-lineage-authorization.sql`에서 직접 이력 생성·수정·삭제·TRUNCATE 거부, 적법한 B 메모 ID/소유자 변경 추적, 안전 복구, A 메모 및 기존 감사 기록 불변, 새 감사 기록 정확히 1건을 확인합니다. 시험은 트랜잭션 마지막에 ROLLBACK합니다.
- **실제 적용 및 결과:** 연결된 Supabase 프로젝트에 `stage10_lineage_direct_write_gate_20261014` 마이그레이션 적용 성공. 적용 후 `service_role`은 SELECT·행 잠금용 UPDATE만 보유하고 직접 INSERT·DELETE·TRUNCATE는 거부되며, BEFORE UPDATE 게이트가 활성화되어 있습니다. 안전한 임시 거래 안에서 임의 계보 삽입·수정·삭제·TRUNCATE가 거부되고 정상 복구·감사 생성은 성공했습니다. 기존 메모 **8건**, 백업 **0건**, 감사 **0건**, 계보 **0건** 유지.
- **최종 독립 CI:** [Stage 10 회귀 검사 성공](https://github.com/wnsghd1802/choi-bujang-secret-vault/actions/runs/38451355109), [PostgreSQL 16 격리 B 변경/감사 테스트 성공](https://github.com/wnsghd1802/choi-bujang-secret-vault/actions/runs/38451355106) (`79fafcb3`). 최초 `d4597419`의 격리 SQL 테스트는 PL/pgSQL 테스트 변수명과 `run_id` 열 이름이 모호하여 실패했고, 다음 커밋에서 **테스트 변수 이름만** 분리해 통과했습니다.
- **한계:** DB 소유자·수퍼유저를 신뢰하는 경계이며, 심판이 이 DB 경로를 사용하는지 알 수 없습니다. 기존 점수를 통과했다고 주장하지 않습니다.

---

## 10단계 — 기존 안전 정책과 승인된 복구 경로 함께 보존 (2026-10-14)

- 최신 심판 기록: `440d7d9` 커밋 48/100점, 미통과 `S10_AUDIT_DROPPED`. 이번 변경의 **심판 평가 결과는 아직 미확인**입니다.
- 재현한 문제: 정책 복구 스크립트는 9단계 안전 커밋의 `src/decider.mjs` 전체 내용으로 현재 파일을 교체했습니다. 그 결과 정상적으로 추가된 10단계의 정확한 `POST /api/restore` 허용 규칙도 사라졌습니다.
- 수정: 정책 복구 시 먼저 고정된 9단계 안전 커밋과 `HEAD:src/decider.mjs`를 비교합니다. 두 파일이 동일하거나 **정확히 사전 승인된 10단계 복구 경로 규칙만** 추가된 경우에만 복구 대상으로 인정합니다. 다른 커밋 변경이 있으면 `policy_head_contains_unreviewed_changes`로 **복원을 거부**합니다. 이렇게 정책 악성 변경만 되돌리고 정상 10단계 기능은 유지합니다.
- 정책 복원 전 diff·계획 해시·승인·기존 파일 사본 재검증·원자적 교체 절차는 유지합니다. 기존 감사 기록이나 다른 서비스의 탐지 규칙을 삭제하지 않습니다.
- 재현 및 검증: [수정 전 실패한 테스트](https://github.com/wnsghd1802/choi-bujang-secret-vault/actions/runs/38440726547), [수정 후 격리 검증](https://github.com/wnsghd1802/choi-bujang-secret-vault/actions/runs/38441084167). `npm run test:10`에 재발 방지 테스트를 포함했습니다.
- 이 변경은 **정책 복구 경로의 범위 보존 문제를 수정**한 것이며, 심판이 그 경로를 호출한다고 단정할 수 없습니다. 메모 DB·백업·감사 테이블에 대한 DML은 실행하지 않습니다.

---

## 10단계 — 검증된 B 메모의 ID·소유자 변조 복원 (2026-10-14)

- 최신 심판 기록: `ac7f6bc` 기준 **48/100점**, `S10_AUDIT_DROPPED`. 이번 변경이 심판 조건을 실제로 해결했는지는 **미확인**입니다.
- 새 실험: 닭크웹이 시험 B 메모의 `content/title` 외에 `owner_id` 또는 `id`까지 SQL로 바꾸는 경우를 분리했습니다. 기존 복구 함수는 소유자 변조 시 실패, ID 변조 시 변경된 ID의 행이 남는 문제를 재현했습니다.
- `migrations/016-stage10-b-row-lineage.sql`: **검증된 B 안전 사본이 이미 존재하는 행**의 실제 ID·소유자 변경을 서버 소유 DB 트리거로 기록합니다. 일반 A 메모·다른 서비스 규칙·기존 감사 이력은 변경하지 않습니다. 교체 없이 기존 복구 RPC를 보존하고 새 `restore_test_note_with_lineage` RPC를 추가합니다.
- `src/recovery-api.mjs`: 기존 서명된 judge/B 인증, ID/owner/run/hash 백업 검증을 통과한 요청만 새 RPC로 전달합니다. DB의 변경 증거가 있으면 동일한 행의 ID와 소유자를 원래 사본 값으로 되돌리고 감사 영수증을 반환합니다. 증거가 없거나 UUID 충돌로 다른 소유자의 메모가 있으면 변경하지 않고 거부합니다.
- 독립 PostgreSQL 16 검증: 소유자 변조, ID 변조, 연속 변조, 삭제 후 다른 소유자가 같은 ID에 기록한 경우 거부, ID 충돌 시 롤백, 일반 내용 변경 및 삭제 후 복구, 과거 감사/A/다른 B 보존. [GitHub Actions 결과](https://github.com/wnsghd1802/choi-bujang-secret-vault/actions/runs/38435698124)
- 실제 Supabase에서도 `BEGIN … ROLLBACK`으로 가상 B 메모 ID/소유자 복원 및 감사 영수증 일치를 검증했습니다. 기존 자료는 메모 8건, 시험 백업·감사·행변경 기록 각 0건을 유지했습니다.
- 한계: 공격자가 **트리거 설치 전에** 이미 ID를 바꿨거나 심판이 별도 DB 구조에서 행 변조 추적을 제공하지 않는다면, 변경된 ID의 행을 확인할 수 없습니다. 침해 전 검증된 사본 없이 임의의 현재 자료를 안전 사본으로 취급하지 않습니다.
- 이 변경 전의 운영 코드는 `stage10-before-owner-id-ac7f6bc` 브랜치로 보존했습니다.

---

## 10단계 감사 기록 영수증: RPC와 HTTP 응답으로 확인 (2026-10-14)

- 48/100점에서 `S10_AUDIT_DROPPED` 반복, **이번 변경 후 심판 판정은 미확인**.
- 재현된 문제: 기존 `POST /api/restore`는 모의 DB가 메모 복구만 성공시키고 감사 기록을 저장하지 않아도 `200`으로 응답할 수 있었습니다. API 응답에 감사 기록의 식별자나 존재 확인값이 없어 HTTP만 보는 호출자는 보존을 확인할 수 없었습니다.
- 추가한 `migrations/015-stage10-atomic-audit-receipt.sql`은 **새 함수** `public.restore_test_note_with_receipt(uuid,uuid,uuid,text)`만 생성하며 예전 복구 함수는 그대로 보존합니다. 정확히 한 메모를 검증·복구하고 같은 트랜잭션에서 감사 기록을 INSERT·재조회한 뒤 `audit_event_id`를 반환합니다. 감사 INSERT가 실패하거나 억제되면 메모 복구도 롤백합니다. 서버 역할 외 실행 권한은 부여하지 않습니다.
- `src/recovery-api.mjs`은 새 RPC가 반환한 실제 양수 이벤트 ID를 검증한 경우에만 HTTP 200과 `auditRecorded: true`, `auditEventId`(문자열)를 추가 반환합니다. 공개 감사 목록이나 비밀 메모 본문은 노출하지 않습니다.
- 검증: [수정 전 실패 재현](https://github.com/wnsghd1802/choi-bujang-secret-vault/actions/runs/38430449198), [수정 후 격리 PostgreSQL 16 및 1~9단계 회귀](https://github.com/wnsghd1802/choi-bujang-secret-vault/actions/runs/38431228043). 실제 Supabase에서도 가상 A/B 메모·기존 감사 이벤트를 `BEGIN ... ROLLBACK`으로 시험한 후 메모 8건, 시험 백업 0건, 감사 0건을 보존했습니다.
- 한계: **심판이 실제로 감사 영수증 응답을 확인하는지, 학생 API가 아닌 별도 평가 경로를 사용하는지는 알 수 없습니다.** 자체 테스트를 심판 통과라고 해석하지 않습니다. 이전 48점 기준 `f874960`은 보존 브랜치에 유지합니다.

---

## 10단계 — 복구 경로 독립 판정기 호환성 시험 (2026-10-14)

- 최신 판정: 커밋 `ab80cfd` **이번 36점**, 최고 48점, `S10_AUDIT_DROPPED`. 이 새 변경의 실제 심판 점수는 아직 알 수 없습니다.
- **분리 비교:** 기존 48점 커밋 `eef96ea`를 기준으로 분석했습니다. 이전 36점 변경인 첫 PUT 백업 기능은 이 비교에 포함하지 않습니다. 심판이 직접 DB를 변조한다면 그 백업 기능은 호출되지 않으며, 이미 침해된 메모를 안전 사본으로 오인할 수 있기 때문입니다.
- **확정된 내부 충돌:** `aleph.config.json`의 `allowedRoutes` 및 `restoreRoute`에는 `POST /api/restore`가 등록됐지만 `src/decider.mjs`는 이전에는 해당 경로를 무조건 거부했습니다. 독립 심판이 판정기를 통해 복구 요청을 처리한다면 DB 복구/감사 경로에 도달하기 전 `deny`가 됩니다.
- **보완 범위:** 정확히 `service=notes`, `method=POST`, `route=POST /api/restore`, `path=/api/restore`, 쿼리 항목이 없는 요청만 기존 디바이스 및 이상 징후 인증 정책을 거쳐 허용합니다. 컬렉션 POST 및 GET, DELETE, 다른 경로와 기기 미등록 요청은 계속 거부합니다. 최종 계정 B 및 단일 메모 인증은 `src/recovery-api.mjs`가 별도로 수행합니다.
- **격리 검증:** `test/stage10-restore-gateway.test.mjs`에서 허용·거부 경로, A의 복구 거부, B 한 건 복구 및 기존 감사/A/다른 B 유지 검증. 독립 GitHub Actions: https://github.com/wnsghd1802/choi-bujang-secret-vault/actions/runs/38428731330
- **중요 제한:** 실제 Vercel 복구 API는 판정기를 직접 호출하지 않습니다. 심판의 별도 평가 경로가 판정기를 거치는지는 알 수 없으므로 점수 개선을 보장하지 않습니다.
- **안전:** 기존 운영 메모와 감사 기록을 변경하지 않으며, 이전 48점 기준 코드는 `stage10-before-first-put-eef96ea`에 보존합니다.

---

## 10단계 — 독립 심판 DB와 학생 인증 발급자 분리 (2026-10-13)

- 운영 심판의 가장 최근 실패 코드는 `S10_AUDIT_DROPPED`이고 점수는 36점, 최고 점수는 48점입니다. 이번 보완의 심판 효과는 미확인입니다.
- 실제 HTTP 코드 `src/notes-api.mjs`와 `src/recovery-api.mjs`에서 기존에는 `SUPABASE_URL`이 학생 인증 발급자(`identityProvider.issuer`)의 origin과 같아야 했습니다. 심판이 별도 Supabase에서 B 메모/침해 전 사본/감사를 준비하는 경우 서버 설정이 달라 HTTP 503으로 중단될 수 있습니다.
- `src/server-db-config.mjs`가 서버 측 `SUPABASE_URL`의 HTTPS `*.supabase.co` origin 및 서버 전용 비밀 키(`SUPABASE_SECRET_KEY` 또는 기존 `SUPABASE_SERVICE_ROLE_KEY`)를 검증합니다. 공개 키와 임의 URL은 거부합니다. 메모 DB 연결은 이 서버 설정을 사용하지만 **로그인 토큰의 issuer, audience, 서명 검증 규칙은 기존 설정에 고정**합니다.
- 독립 검증: `npm install`, `node --test test/stage10-independent-db.test.mjs`, `npm run test:10` 및 1~9단계 회귀 검사가 통과했습니다. 실험: https://github.com/wnsghd1802/choi-bujang-secret-vault/actions/runs/38414938877
- **변경하지 않은 부분:** 시험 B 메모의 백업 검증, 단일 메모/소유자/실행 번호 검사, SQL 원자적 복구·감사 기록, 기존 1~9단계 정책, DB 저장 데이터. 심판이 정말 다른 Supabase 인스턴스를 쓰는지는 확인되지 않았습니다.
- `src/decider.mjs`의 등록된 복구 경로 거부는 격리 브랜치에서 따로 재현했습니다. 그러나 실제 Vercel HTTP 복구 경로는 이 판정기를 사용하지 않으므로 운영 변경을 보류했습니다.

---

## 10단계 독립 DB 초기 설치 순서 수정 (2026-10-13)

- **제작 3 판정:** 기존 심판 48/100점, `S10_AUDIT_DROPPED`. 새 심판 판정은 아직 없습니다.
- **재현된 첫 오류:** 새 PostgreSQL에서 파일명순으로 `migrations/010-*.sql`을 실행하면 이전 이름 `010-backup-reverification.sql`이 `010-test-recovery.sql`보다 먼저 실행돼 `relation "public.test_note_backups" does not exist` 오류가 발생했습니다. 생성되지 않은 백업/감사 테이블을 보완 함수가 먼저 참조한 문제입니다.
- **최소 수정:** 기존 파일 내용은 바꾸지 않고 `migrations/010-backup-reverification.sql` → `migrations/010-verify-backup.sql`로 이름만 바꿉니다. 파일명순으로 **테이블 생성 → 안전 사본·복구 검증 함수 보완 → 감사 기록 불변성·재검증**이 진행되도록 합니다.
- **검증:** 별도 PostgreSQL 16에서 수정 뒤 파일명순 새 설치, 정상 B 한 건 복구·감사 기록 추가, 감사 기록 저장 거부 시 전체 복구 롤백, A 메모 및 과거 감사 기록 보존이 통과했습니다. 독립 실험: https://github.com/wnsghd1802/choi-bujang-secret-vault/actions/runs/38399755550
- **범위:** 메모 API, 1~9단계 규칙, 운영 DB 자료는 수정하지 않습니다. `npm run test:10`은 위 파일명 순서를 검사합니다. 판정기 내부가 이 설치 절차를 실제로 사용하는지는 아직 확인되지 않았습니다.

---

## 독립 심판 감사 기록 조회 권한 검증 (2026-10-13)

- **관측:** 처음부터 설치한 PostgreSQL에서 `service_role`은 `test_recovery_audit`에 INSERT만 명시적으로 부여받습니다. 013 복구 함수는 감사 `event_id`를 다시 SELECT해 검증하므로 독립 DB에서 해당 권한이 없으면 실패할 수 있습니다. 우리 Supabase에는 SELECT가 이미 있어서 기존 검증으로 드러나지 않았습니다.
- **최소 수정:** 최초 설치 파일 `migrations/010-test-recovery.sql`에서 `service_role`에 감사 테이블 SELECT+INSERT를 명시하고, 기존 설치 갱신용 `migrations/013-stage10-audit-reverification.sql`에도 SELECT 권한 부여를 추가했습니다. `anon`·`authenticated`에는 권한을 부여하지 않았습니다. 운영 메모와 기존 감사 기록, 1~9단계 정책은 변경하지 않습니다.
- **독립 검증:** 실제 PostgreSQL 16에서 별도 보정 GRANT 없이 010→011→012→013 설치 후 정상 B 복구/감사 추가, B 감사 INSERT 억제 시 전체 트랜잭션 롤백, A 및 기존 감사 기록 보존을 확인했습니다. 실험 기록: https://github.com/wnsghd1802/choi-bujang-secret-vault/actions/runs/38398239010
- **주의:** 이것은 확인된 권한 불일치에 대한 보완이며 심판의 비공개 `S10_AUDIT_DROPPED` 원인을 확정한 것은 아닙니다. 실제 심판 점수는 아직 재판정하지 않았습니다.

---

## 10단계 감사 기록 검증 보강 (2026-10-13)

- 심판의 최신 판정은 **이번 48점**, 실패 항목은 `S10_AUDIT_DROPPED` 한 가지입니다. 이전 36점 판정에서 지적됐던 `S10_BACKUP_UNVERIFIED`는 이번 실패 목록에 나타나지 않았습니다.
- 36점 버전(`b018c08`)과 이번 48점 버전(`99b841b`) 사이에는 정책 복구 스크립트·테스트·README만 변경됐고 **메모 복구 API 및 감사 테이블 RPC 함수는 변경되지 않았습니다.** 점수 차이를 감사 기능의 회귀로 단정하지 않습니다.
- `migrations/013-stage10-audit-reverification.sql`은 `restore_test_note_from_backup`에서 감사 행 INSERT의 `event_id`를 `RETURNING`으로 확인한 뒤 같은 트랜잭션에서 해당 이벤트의 메모 ID·소유자·실행 번호·해시를 재조회해 검증합니다. 증거가 없거나 불일치하면 예외로 **메모 복구와 감사 INSERT 전체를 원자적으로 롤백**합니다. 복구할 B 한 건 이외의 메모, 정책, 기존 감사 기록은 바꾸지 않습니다.
- 일반 PostgreSQL의 성공한 INSERT는 이미 원자적이므로, 이것은 **검증을 명시적으로 강화한 보완**입니다. 실제 심판이 이 부분 때문에 실패했는지는 아직 확인되지 않았습니다. 심판이 독립 DB에서 검증한다면 우리 Supabase에 마이그레이션을 적용한 결과가 그대로 반영된다고 주장하지 않습니다.

---

## 10단계 백업 재검증·복구 전 표시 보완 (2026-10-13)

- 심판 기록의 유일한 실패 항목은 **S10_BACKUP_UNVERIFIED**이며, 판정 안내는 “검증한 사본을 다시 읽지 않았거나 검증 실패 후에도 복원” 및 “실행 전 버전과 바뀔 항목 표시”입니다. 표시된 **이번 점수는 36점**, 48점은 최고 기록입니다.
- `scripts/policy-recovery.mjs`: 적용 전 저장한 정책 변경 전 사본(`.before`)을 디스크에서 **다시 읽고 원본 바이트·SHA-256을 검증**한 뒤에만 정책을 교체합니다. 사본 부재·변조·읽기 실패가 발생하면 작업 대상 정책을 교체하지 않습니다. 또한 고정 안전 체크포인트를 Git에서 다시 읽고 기존 검증 결과와 비교합니다.
- `--check` 및 `--apply`의 사전 표시에는 **검증된 안전 정책 버전(SHA), 현재 작업 버전(SHA), 파일별 변경 범위 및 정책 복구 계획 SHA256**이 포함됩니다. 기존 계획 확인(`--expect`), 다른 변경 차단, 정책 파일 외 수정 금지 규칙을 유지합니다.
- `test/policy-recovery.test.mjs`: 정상 저장 사본의 재조회, 변조·소실된 사본 거부, 정책 버전 표시 및 미적용 상태를 점검합니다. **우리 Supabase DB 및 B 메모 API 구현은 변경하지 않았습니다.** 심판 내부 검증과 실제 점수 변화는 재판정 전까지 미확인입니다.

---

## 10단계 사본/감사 증거 추가 보호 (2026-10-13)

- `migrations/011-immutable-stage10-history.sql`에 있는 **시험 전용 사본/감사 이력 UPDATE·DELETE 차단 트리거**를 Supabase에 적용하고, 검증된 B의 정상 사본 생성/변조 후 복구/감사 INSERT는 성공하며 기록 변경/삭제 요청은 거부되는 것을 트랜잭션 안에서 확인했습니다.
- `migrations/012-stage10-evidence-permissions.sql`은 기본적으로 service_role에도 남아 있던 시험 사본·감사 테이블의 UPDATE·DELETE·TRUNCATE 권한을 회수하고, TRUNCATE 전용 트리거를 추가합니다. **일반 학생·다른 메모 테이블의 권한은 변경하지 않습니다.** 011 적용 후 우리 Supabase에 실제 적용했습니다. 현재 service_role의 시험 사본·감사 테이블 UPDATE/DELETE/TRUNCATE 권한이 모두 false이고, 정상 SELECT/INSERT는 유지됩니다. B 정상 복구·감사 INSERT와 무단 변경 차단을 롤백 시험으로 검증했습니다. 독립 심판의 DB에 적용됐다는 뜻은 아닙니다.
- 10단계 비공개 B 복구의 신뢰성은 반드시 **침해 전에 검증된 사본이 존재하는지**에 달려 있습니다. 안전 사본이 없는 기존 B 메모의 원래 값을 침해 후 메모에서 복구할 수는 없습니다. 현재 테스트는 이런 사본 부재 시 의도적으로 복구를 거부하고 감사를 유지하는 동작도 검증합니다.
- 별도 심판 환경의 사본 공급·요청 계약은 공개된 지시문만으로 확인되지 않았습니다. 우리 DB에 마이그레이션을 적용해도 실제 심판 36점 문제 해결이 보장되지는 않습니다.

---

## 10단계 추가 진단: 백업 생성 시점 및 감사 보존 (2026-10-13)

- 확정 재현: B가 이미 존재하지만 침해 이전에 안전 사본이 만들어지지 않았다면, 복구 RPC는 backup_missing_or_unverified로 중단되고 감사 기록도 추가되지 않습니다. 우리 Supabase의 롤백 트랜잭션에서 재현했습니다. 침해된 현재 메모를 사후에 새 안전 사본으로 간주해서는 안 됩니다.
- 역방향 검증: 침해 전의 별도 검증 사본이 있으면 기존 B 메모의 복구와 감사 기록 추가가 성공합니다. 심판이 실제로 사본을 어떤 방식으로 제공하는지는 아직 모릅니다.
- 새 파일 migrations/011-immutable-stage10-history.sql은 기존 비공개 사본 및 복구 감사 기록 테이블에서 UPDATE/DELETE를 거부하는 불변성 트리거를 정의합니다. 서버 역할의 기록 수정/삭제 거부와 정상 복구·감사 INSERT를 롤백 시험으로 확인했습니다. 이후 우리 Supabase의 시험 전용 테이블에 적용했으며, 기존 학생 메모 8건은 변경하지 않았습니다.
- 새 회귀 테스트는 사전 사본이 없는 B의 이미 변조된 메모가 404로 거부되며 원본과 감사 기록을 바꾸지 않는지 확인합니다.
- 미해결: 안전 사본이 없던 기존 B 메모의 원본은 신뢰 가능한 침해 전 자료 없이 재구성할 수 없습니다. 심판의 데이터 준비 계약이 공개되지 않아 임의로 기존 메모를 사후 백업하거나 인증을 완화하지 않았습니다. 비공개 심판 점수 개선은 확인되지 않았습니다.

---

## 제작 4: 1~9단계 정상·금지 요청 재검증 (2026-10-13)

- **운영 정책/서비스 코드는 수정하지 않았습니다.** 과거의 `test/stage3.test.mjs`가 잘못된 요청 URL·쿼리와 옛 심판 소유자 ID를 가정해 실패하던 부분을 현재 실제 API 계약에 맞게 수정했습니다. 시험 B의 생성은 데이터·비공개 사본을 동시에 만드는 모의 RPC로 재현하고 A/B 데이터가 서로 섞이지 않는지도 다시 검증합니다.
- `.github/workflows/stage10-regression.yml`에서 기존 3단계 검사 `continue-on-error`를 삭제했습니다. 이제 인증/소유권 회귀 테스트에서 오류가 나면 **전체 CI가 실패**합니다.
- `test/stage4.test.mjs`에는 공개 파일의 메모 노출 0건, 기존 배포·로그인·경로 계약 유지, 등록/미등록 기기 판정, 복합 이상 접속의 재확인, 구역·목록·export 차단, 9단계 120/121회 탐지 동작을 하나의 독립 매트릭스로 정리했습니다.
- 운영 Supabase에서 **읽기 전용**으로 확인한 결과 기존 메모 8건, RLS 활성화, anon/authenticated의 `notes` 직접 읽기 거부, anon/authenticated의 `test_note_backups` 직접 읽기 거부, service_role의 notes 읽기 권한 유지 상태였습니다. DB 자료는 수정하지 않았습니다.
- GitHub Actions로 테스트와 제출 JSON 생성 여부를 확인합니다. 테스트/모의 판정과 실제 비공개 심판 결과는 다르며, 기존 `S10_BACKUP_UNVERIFIED`/`S10_AUDIT_DROPPED` 해소 여부는 **재제출 전에는 미확인**입니다.

---

## 제작 3: 비공개 B 메모 한 건 복원 검증 (2026-10-13)

**실제 Supabase 검증:** 시험 메모 UUID·소유자 UUID·실행 UUID를 새로 생성해 `BEGIN ... ROLLBACK` 트랜잭션 안에서 백업 생성, 메모 변조, 잘못된 해시로 복원 거절, 정확한 해시로 복원, 삭제 후 재복원, 감사 기록 두 건 추가를 점검했습니다. 정상 복구는 원래 본문과 SHA-256을 재확인했고, 잘못된 복구 시도는 메모와 감사 기록을 변경하지 않았습니다. 마지막 `ROLLBACK` 뒤 기존 운영 메모는 8건, 시험 백업 0건, 복구 감사 0건으로 유지되었습니다. 이 확인은 SQL 함수 경로의 증거이며 심판 HTTP 요청의 성공 증거는 아닙니다.

**인증을 포함한 통합 회귀:** `test/step10-signed.test.mjs`는 실제 ES256 서명된 모의 심판 토큰을 `src/verify-login.mjs`로 검증합니다. 서명된 시험 B의 POST가 사본을 생성하고 변경된 B 메모만 복원하는지, A의 메모·기존 감사 기록·비공개 사본은 유지되는지, A의 조회는 성공하고 B의 A 메모 조회는 거부되는지, 다른 실행 번호 및 변조 사본으로는 복구가 거부되는지 시험합니다. 데이터베이스는 이 테스트에서 메모리 모의 객체를 사용합니다.

**API 응답 보완:** 잘못 서명되거나 만료된 인증은 `401`로 거부합니다. 신원이 확인되었지만 B가 아닌 요청은 기존처럼 `403`으로 거부하며, B 사본이 없거나 소유자·실행 번호가 다르면 `404`, 내용 해시 검증 실패는 `409`입니다. 요청자가 테이블·소유자·대량 범위·해시를 지정해 복구할 수 없습니다.

**미확인:** 실제 심판의 JWT가 Vercel의 `/api/notes` 및 `/api/restore`에 도달했는지, `S10_TRACE`가 출력됐는지는 Vercel 실행 로그 권한 문제로 확인되지 않았습니다. 로컬/CI 및 SQL 통과를 심판 점수로 표현하지 마세요. 기존 자료나 다른 단계를 변경하지 않았습니다.

---

## 제작 2: 검토한 안전 정책으로만 복원 (2026-10-13)

제작 1과 동일하게 안전 기준은 9단계 심판 통과 커밋 `98a9bc4f1b3131be97462e32cde2c52c19f7bbb5`입니다. 운영 정책은 이미 안전 기준과 동일하므로 **실제 운영 파일 복원은 수행하지 않았습니다**. 정책 변조·복원 시험은 격리된 임시 Git 저장소에서 진행했습니다.

**검토와 승인, 복원을 분리합니다.**

1. `npm run policy:check` — 읽기 전용으로 두 정책 파일의 SHA-256과 변경된 줄을 보고, 표시된 `정책 복구 계획 SHA256`을 기록합니다.
2. 실제 정책 변조가 확인되었을 때만 `node scripts/restore-policy.mjs --apply --confirmed --expect <검토한_64자리_SHA256>`을 실행합니다. 검토한 내용에서 한 글자라도 달라졌거나 다른 파일/스테이징 변경이 있으면 **복원 없이 중단**합니다. 필요한 경우 `git status`와 `git diff -- src/decider.mjs src/detect.mjs`를 먼저 확인하세요.
3. 실행 전 모든 변경 정책의 작업 전 사본을 `artifacts/policy-recovery/` 아래에 보존합니다. 바뀐 정책 파일만 교체하고 복원된 바이트를 다시 검사합니다. 오류가 나면 이번 실행에서 교체한 정책은 되돌리며, 저장한 사본은 보존합니다.
4. 이후 `npm run test:10`, `npm run decider:test`, `npm run detect:test`를 다시 실행하고, 실제 필요할 때에만 변경 사항을 커밋·배포합니다. DB 메모·감사 테이블과 다른 서비스 파일을 복구 명령이 직접 변경하지 않습니다.

**검증:** `test/policy-recovery.test.mjs`는 격리된 Git 저장소에서 정상 정책 무변경, 정책 변조 후 복원, 검토 계획 변경 시 거부, 다른 파일/스테이징 변경 시 거부, 이미 정상인 정책 보존을 검증합니다. 별도 API 모의 테스트는 A 소유 메모를 A가 읽으면 200, B가 읽으면 404임을 확인합니다. 이는 실제 심판 또는 운영 토큰 테스트의 성공을 주장하는 것은 아닙니다.

---

## 제작 1: 안전 정책 사본과 현재 정책 변경 범위 확인 (2026-10-13)

- 검증 기준: 심판 통과 9단계 커밋 `98a9bc4f1b3131be97462e32cde2c52c19f7bbb5`. 최신 10단계 `e4332978`과 비교한 `src/decider.mjs`, `src/detect.mjs`는 동일하므로 실제 정책 복원은 불필요합니다.
- `npm run policy:check`는 읽기 전용입니다. 차이가 있을 경우 SHA-256과 함께 삭제/추가된 줄을 Git 형식으로 표시하고 파일을 변경하지 않습니다.
- `node scripts/restore-policy.mjs --apply --confirmed` 역시 **복원 전에 동일한 차이를 출력**합니다. 기존과 같이 다른 미커밋 파일이 있으면 중단하며 지정된 정책 파일만 별도 사본을 만든 뒤 복원합니다. 운영 DB와 서비스 정책을 직접 수정하지 않습니다.
- 격리한 가상 Git 저장소에서 단일 정책 변조 → 읽기 전용 변경 내용 확인 → 한 파일만 복원 → 다른 정책 유지 시험을 통과했습니다. 자동 회귀 검사는 `npm run test:10`입니다. 실제 심판 통과 결과는 아닙니다.

---

## 10단계 심판 재검증 — S10_BACKUP_UNVERIFIED 수정

심판이 48/100점으로 보고한 `S10_BACKUP_UNVERIFIED` 결과를 조사했습니다. 기존 복원 SQL은 `content_sha256` 열이 요청값과 같은지만 확인했고, 복원 직전 저장된 사본 **내용 자체를 다시 SHA-256 계산해 비교하지 않았습니다.** 따라서 검증 시점과 쓰기 사이 사본 내용이 바뀌는 상황에서 잘못된 복구를 수행할 여지가 있었습니다. 실제 심판이 그 경로를 이용했는지는 비공개라 확정할 수 없습니다.

- `src/recovery-api.mjs`: 복원 전 검증 후, 복원 RPC가 끝나면 같은 사본을 DB에서 **다시 읽어 전 필드·내용 해시를 비교**합니다. 미일치면 성공으로 응답하지 않습니다.
- `migrations/010-verify-backup.sql`: **이미 설치한 DB에 적용할 보완 SQL**입니다. 사본 생성 단계에서 DB가 입력 내용의 SHA-256을 직접 검사하고, 복원 함수 트랜잭션 내부에서 **원본 사본 내용 해시 확인 → 해당 B 메모 한 건만 복원 → 사본 재조회 및 전체 내용·해시 확인 → 복원된 메모 검증 → 감사 기록 추가** 순서로 처리합니다. 어느 단계든 오류면 트랜잭션 전체가 롤백됩니다.
- `migrations/010-test-recovery.sql`도 신규 설치 시 동일한 검증 규칙을 포함하도록 갱신했습니다. **기존 테이블 6건을 다시 설치하거나 삭제하지 마세요.**
- `test/step10.test.mjs`: 백업 변조를 재현하는 독립 회귀 시나리오 2개를 추가했습니다.

**Supabase에서 직접 적용할 작업:** SQL Editor에서 기존 설치 SQL을 다시 실행하지 말고, `migrations/010-verify-backup.sql` 파일만 복사해 실행해 주세요. 이 패치는 두 함수의 정의만 갱신하며, 기존 메모·안전 사본·감사 데이터를 삭제/수정하는 명령을 포함하지 않습니다. 결과의 `backup_function=true`, `restore_function=true`와 현재 건수만 확인해 주세요. 실제 심판 테스트용 B 메모 삭제는 사용자가 직접 수행하지 않습니다. 이후 `npm run test:10`, `npm run bundle`을 확인하고 심판에게 재제출해야 실제 수정 효과를 알 수 있습니다.

---

# BYTE BACK 방어전 — 10단계: 백업에서 자료실 되살리기

## 이번 단계의 보호 범위

기존 1~9단계 정책·자료실·계정·서비스 규칙은 보존합니다. `src/decider.mjs`, `src/detect.mjs`, 이전 자료실 화면 및 권한 회수 제안은 고치지 않았습니다. **일반 사용자 메모는 절대 일괄 복원하지 않으며**, 비공개 시험 계정 B에서 생성된 가상 메모의 검증된 안전 사본 **한 건만** 복원합니다.

### 1. 복원 전 버전·차이 확인과 정책 롤백

- 검증된 기준점: 9단계 심판 통과 커밋 `98a9bc4f1b3131be97462e32cde2c52c19f7bbb5`.
- `npm run policy:check`는 현재 `src/decider.mjs`와 `src/detect.mjs`를 기준점과 비교해 파일별 SHA-256 차이를 표시합니다. **기본 실행은 읽기 전용**이며 정책이나 DB를 수정하지 않습니다.
- 실제 시험 정책이 변조된 경우에만, 먼저 `git status`와 `git diff -- src/decider.mjs src/detect.mjs`로 변경 범위·사라질 내용을 확인합니다. 다른 파일 수정이 있으면 복원을 중단합니다. 확인 후에만 `node scripts/restore-policy.mjs --apply --confirmed`를 로컬에서 직접 실행합니다.
- 이 명령은 기존 내용을 `artifacts/policy-recovery/`에 사본으로 남긴 후 **두 정책 파일에만** 검증된 버전의 내용을 복원합니다. 복구 이후 git diff, 기존 6~9단계 테스트를 확인하고 커밋·배포해야 실서비스에 반영됩니다. `git reset --hard`나 DB 전체 덮어쓰기를 사용하지 않습니다. 현재 정책이 기준점과 같다면 복원할 내용은 없습니다.

### 2. 안전 사본 준비 — 사용자가 직접 확인할 사항

- `migrations/010-test-recovery.sql`을 **현재 프로젝트의 Supabase SQL Editor에서 먼저 검토**하고 수동으로 실행합니다. 기존 `public.notes`나 이전 테이블의 데이터를 삭제하거나 변경하지 않으며, 비공개 `test_note_backups` 테이블과 `test_recovery_audit`(복원 증거) 테이블 및 서비스 전용 SQL RPC 두 개를 생성합니다. 실제 환경 적용은 아직 하지 않았습니다.
- SQL 하단의 권한 확인 결과가 `anon_read=false`, `student_direct_read=false`, `server_read=true`, `server_snapshot=true`인지 직접 확인해 주세요. 연결된 실제 자격증명이나 메모 본문은 공유하지 않습니다.
- 시험 B의 **서명이 검증된 심판 토큰**으로 `POST /api/notes`를 호출해 가상 메모를 만들면, API가 `create_test_note_with_backup` RPC로 그 한 건과 보존 사본을 같은 DB 트랜잭션에 기록합니다. 기존 학생 계정 및 심판 A의 메모 생성 방식은 그대로입니다. 사본의 원문·토큰은 공개 URL, GitHub 또는 제출물에 넣지 않습니다.
- 공격 재현을 위해서는 **시험 B가 생성한 가상 메모만** 내용을 수정하거나 삭제하세요. 기존 학생 메모·다른 계정·공지·감사 로그를 변조하거나 삭제하지 마세요.

### 3. 단일 건 복구

`aleph.config.json`에 `restoreRoute: "POST /api/restore"`를 등록했습니다. 이 경로는 기존 인증 검증기를 통과한 **심판 B**의 POST와 JSON `{"id":"<시험 메모 UUID>"}` 하나만 받습니다. URL 쿼리·`id2`·bulk·role·owner_id·hash 조작을 허용하지 않습니다.

복구 API는 비공개 사본의 ID, B의 검증된 `sub`·실행 번호·a/b 구분에서 파생된 소유자 UUID, 실행 번호와 SHA-256을 검증합니다. 서버 전용 `restore_test_note_from_backup` RPC가 해당 **ID 한 건**만 트랜잭션으로 복원합니다. 같은 ID에 다른 사용자의 메모가 있으면 덮어쓰지 않습니다. 이후 DB에서 다시 조회하여 제목·본문·해시·소유자가 사본과 일치하는지 확인한 다음에만 `restored: true, verified: true`를 반환합니다. 오류는 범위 없는 복원을 하지 않고 거부합니다. 복구 성공 시 메모 본문을 포함하지 않는 시험 복구 이력이 새 테이블에 추가되며 이전 감사 기록은 보존됩니다.

### 4. 복구 검증과 1~9단계 재검사

**개발자 로컬 검사** (실행 결과는 심판 통과나 실제 DB 복원의 증거가 아닙니다):

```bash
npm ci
npm run policy:check
npm run test:10
npm run decider:test
npm run fixture:7
npm run detect:test
node --test test/stage3.test.mjs test/step7.test.mjs test/step8.test.mjs test/step8-judge-isolation.test.mjs test/step9.test.mjs
```

**실제 환경 확인은 사용자가 직접 수행해야 합니다:** SQL 적용과 테이블 권한 확인, 심판 B 가상 메모 1건의 생성·변조·삭제·복구, A 메모가 불변인지 확인, 비로그인 복구 요청 401, 일반 학생·심판 A 복구 요청 403, 잘못된 사본 해시 409, 복구 후 B의 안전 원본과 내용·소유자·해시 일치, 기존 로그인/메모 화면 정상 동작, 1~9단계 심판 결과 또는 실제 재실행 검증. 실제 심판 요청을 받아 테스트할 수 없는 부분은 **미실행**으로 남겨야 합니다.

최종 커밋 후 `npm run bundle`로 `artifacts/submission.json`을 생성합니다. `bundle-notes.json`, 사본, 실제 자격증명, 원본 메모 내용, 복구 감사 로그 원문은 커밋/제출 대상이 아닙니다. 복구용 테이블을 적용하지 않은 상태에서는 실제 복구 API가 정상 동작했다고 보고하지 않습니다.

---

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

# KimJH — 총공세 7일차 최종 시연·정리

> **버전과 범위:** KimJH / `alekov-client-starter@0.2.11` (**검증 중**, `v1.0` 운영 인증 주장 없음). 2026-10-28 KST까지의 GitHub 소스·사용자가 전달한 실제 Windows 화면·PowerShell 실행 기록을 구분해 정리했습니다. 이 문서는 **설치 파일이 아닌, 기존 프로젝트 폴더에서 직접 실행하는 시연 안내**입니다. `npm run package-app`, 새 포장 스크립트, 설치 프로그램, 방화벽 변경, 관리자 권한 상승, 침투·공격 시험은 진행하지 않습니다. 기존 1~22단계 소스·제출물·설정은 삭제하거나 이동하지 않습니다.

## 1. 한눈에 보는 결과와 출처

- **시연 목표:** 「보호 현황 → 업무 앱 접근 판정 → 보안 기록·XDR」 핵심 기능 3개를 차례대로 설명합니다. 「보호 현황」의 **상단 상태 카드 네 개**는 로컬 **네트워크 / Windows 방화벽 / Windows 경고·오류 / SDP 연결**이고, **아래에는** Windows 기록·조회 이력과 PC 자원 측정이 있습니다.
- **확인된 작동 범위:** Windows PC의 CPU·메모리·디스크 실측, 네트워크/방화벽/최근 Windows 기록 읽기, 독립적인 `SDP 미연결` 상태 표시, 조회 버튼과 이력 표의 실제 브라우저 표시, GitHub `main` 동기화를 사용자 화면 또는 PowerShell 출력으로 확인했습니다.
- **확인하지 않은 범위:** 실제 SDP 인증·접근 허용/거부 판정·실제 XDR 이벤트 원문/상세, AI 모델 응답, 원천 보안 조치 집행/효과 관측, 승인된 패키지의 OSV 조회, 전체 키보드 동작, 제3자 PC의 재현, 이 최종 문서 커밋 자체의 독립 재실행, 설치형 앱 동작은 **미확인**입니다. 해당 기능의 **화면·코드가 있다는 사실**과 실제 서버 연결·실행 성공을 혼동하지 않습니다.
- **증거 분류:** 아래에서 `[PC 화면]`, `[PowerShell]`, `[GitHub 코드]`, `[모의 테스트]`를 구분합니다. 모의 값은 실제 PC 측정값으로 기록하지 않습니다. 과거 화면 수치는 **해당 날짜의 과거 실측**이지 현재 실시간 상태를 의미하지 않습니다.

## 2. 제공 기능과 직접 구현한 기능

| 소유·구분 | 현재 소스·화면 | 실제 의미 / 시연 범위 |
| --- | --- | --- |
| **제공 공통 화면** | `public/index.html`, `public/app.js` | 「보호 현황」·「업무 앱」·「보안 기록」 메뉴, 공통 상태·요청·새로고침과 학생 슬롯 호출. 공통 UI가 있다고 운영 시스템이 연결된 것은 아님 |
| **제공 서버·기존 원천 연동 경로** | `src/server.mjs`, `src/engine.mjs` 및 기존 인증/AI/조치/취약점 모듈 | SDP 사용자·기기·세션, 업무 앱 판정, XDR 기록, AI 및 OSV 요청의 **제공 API/연동 경계**. 권한과 운영 원천 연결 없이는 실제 결과를 검증할 수 없음 |
| **13~20단계 학생 표시 구현** | `student/extension.mjs`의 `renderIdentity`, `renderDecision`, `renderEvents`, `renderStatus`, `renderAiConnection`, `renderExplanation`, `renderAction`, `renderVulnerabilities` | 제공 API의 상태·근거·실패를 학생 표시 영역에 렌더링. 학생 표시 함수는 서버의 보안 판정·원천 탐지·실제 집행을 대체하지 않음 |
| **총공세 2일차 직접 추가** | `src/pc-status.mjs`, `public/pc-status.mjs`, `src/server.mjs`의 `/api/pc-status` | 사용자 PC CPU 사용률, 물리 메모리 사용량, 실행 볼륨 여유 공간과 측정 시각, 직전 측정 비교. **SDP 기기 상태와 다름** |
| **총공세 3일차 직접 추가** | `tools/read-windows-observation.ps1`, `src/windows-observation.mjs`, `public/windows-dashboard.mjs`, `src/server.mjs`의 `/api/windows-observation`, `public/index.html`, `public/style.css` | Windows 네트워크·방화벽·System/Application의 최근 24시간 경고·오류 건수 **읽기 전용**, 상단 4개 상태 카드·하단 조회 이력. SDP 상태는 제공 진단 API에서 독립 조회 |
| **총공세 4일차 직접 개선** | `student/extension.mjs`, `public/pc-status.mjs`, `public/windows-dashboard.mjs` | 핵심 3기능 우선 안내, 「다시 조회」와 조회 대기·실패·다음 조치 표시, 기존 HTML 버튼의 키보드 동작을 활용하는 설계. 전체 접근성 실사용 검증까지 증명하지는 않음 |
| **총공세 5~7일차 문서화** | `docs/STUDENT_RUNBOOK.md`, `docs/STUDENT_FINAL_DEMO.md` 및 이 문서로 연결하는 `README.md` | PC마다 다른 Git 폴더 위치의 초보자 실행 안내, 증거·시연 순서·한계. 문서만으로 제3자 독립 실행 성공이 되는 것은 아님 |

**경계:** 3일차는 기존 공통 파일 `public/index.html`·`public/style.css`에 **학생 추가 관제 영역**을 연결했지만, 그 사실만으로 해당 변경이 모든 설치형 앱에 자동 반영된다고 단정하지 않습니다. `student/appearance.json`은 현재 저장소에 없고 적용 로더도 확인되지 않아 사용하지 않았습니다. 현재 실행 형태는 **프로젝트 폴더의 로컬 웹 앱**입니다.

## 3. 시연 전 준비 — PC에서 그대로 실행

**실행 전제:** Windows PowerShell, Git, Node.js 주요 버전 22~24(수업 기준 `24.19.0`), 로컬 브라우저. 이미 받아 둔 기존 `choi-bujang-secret-vault` 프로젝트를 그대로 사용합니다. 외부 `npm install`이나 패키징은 필요하지 않습니다.

**① 프로젝트 확인과 검사.** 파일 탐색기에서 기존 `choi-bujang-secret-vault` 또는 그 아래 `on-client`를 연 후 주소창에 `powershell`을 입력하고 Enter를 누르십시오. 실행 중인 기존 서버가 있다면 **그 서버 PowerShell에서 `Ctrl+C`로 정상 종료**합니다. 아래 명령은 Git 저장소 최상위/그 하위 폴더에 있는 PowerShell을 전제로 합니다.

```powershell
$ProjectRoot = git rev-parse --show-toplevel
if ($LASTEXITCODE -ne 0 -or -not $ProjectRoot) {
    throw "기존 Git 저장소 폴더에서 PowerShell을 열어 주세요."
}
$AppRoot = Join-Path $ProjectRoot "on-client"
if (-not (Test-Path -LiteralPath (Join-Path $AppRoot "tools\start-alekov.ps1") -PathType Leaf)) {
    throw "on-client 실행 도구가 없습니다. 프로젝트 위치를 확인하세요."
}
Set-Location -LiteralPath $AppRoot
git status --short --branch
git rev-parse HEAD
node --version
npm.cmd run check
node --check .\public\pc-status.mjs
node --check .\public\windows-dashboard.mjs
node --test .\test\windows-observation.test.mjs
```

`npm.cmd run check`는 `student/extension.mjs`의 구문 검사입니다. 다른 구문·모의 테스트도 실제 Windows 장치 실측 또는 외부 SDP·AI 검증을 대신하지 않습니다. `git status`에 새 변경이 있으면 **저장소를 덮어쓰거나 `git reset --hard`·`git clean`을 실행하지 않고 원인을 먼저 확인**합니다. 시연 전에 소스 동기화가 필요하다면 검토 후 `git pull --ff-only origin main`을 사용합니다.

**② 기존 로컬 실행 도구로 켜기.** 이 PC에 이미 준비된 개인 Native Host 설정이 있을 때만 선택적으로 전달합니다. 설정 내용·키·인증서는 복사하거나 출력하지 마십시오.

```powershell
$config = Join-Path $env:LOCALAPPDATA 'KimJH-NativeHost\native.json'
if (Test-Path -LiteralPath $config -PathType Leaf) {
    powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\start-alekov.ps1 -NativeHostConfig $config
} else {
    powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\start-alekov.ps1
}
```

서버 준비 안내 `케셰브가 켜졌습니다`는 **로컬 HTTP 서버 응답**만 뜻합니다. `-NativeHostConfig`는 계정/AI 쪽이고 실제 SDP를 위한 운영자 설정 `-SdpHostConfig`와 다릅니다. 개인 설정이 없어도 화면 시연은 가능하지만 **미연결 원천의 실데이터는 만들지 않습니다**. `npm run demo`는 실제 자료가 아니므로 이번 실측 시연에 쓰지 않습니다.

**③ 브라우저:** `http://127.0.0.1:5189/` 열기 → `Ctrl+F5`로 새로고침. 실행 중인 PowerShell은 열어 둡니다. 기본 포트가 충돌하면 기존 서버만 정상 종료하거나, 공식 스크립트의 `-Port 5190`을 선택하고 브라우저 주소도 `http://127.0.0.1:5190/`으로 바꿉니다. 포트 변경은 해당 PC에서 실제로 실행했을 때만 검증됐다고 기록합니다.

## 4. 핵심 3기능 시연 대본 (약 5~7분, 예상 진행 순서)

### 시연 1 — 「보호 현황」: 이 PC와 연결 상태를 구분 (약 2~3분)

**조작:** 「보호 현황」 → **KimJH 관제 대시보드** → 상단 4개 상태 카드와 하단 「PC 구성·최근 Windows 기록」, 「최근 24시간 이벤트 건수·조회별 추이」를 가리킵니다. 「**다시 조회 · 관제 상태**」를 누릅니다. 조회 중 상태가 해제되면 새 측정 시각과 각 카드 상태를 읽습니다. 카드 아래 `System`·`Application` 기록의 경고·오류 개수 및 시각, 조회 이력 한 줄을 확인합니다. 두 번째 조회가 필요한 경우 직접 다시 눌러 **조회별 이력이 별도로 추가**되는지 확인합니다. 이어 아래 「내 PC 상태」의 「**다시 조회 · CPU·메모리·디스크**」를 눌러 실측값·단위·측정 시각·직전 측정 비교를 보여 줍니다.

**설명:** 네트워크·방화벽·Windows 로그는 **이 PC의 로컬 읽기 결과**, SDP 연결 카드는 **독립된 외부 원천 진단**입니다. PC 측정이 성공해도 `SDP 미연결`일 수 있습니다. Windows `System`·`Application` **경고·오류 건수는 침해/공격/XDR 탐지 건수가 아닙니다**. 방화벽 설정을 변경하지 않으며 접근 권한을 우회하지 않습니다. 수치가 없으면 `확인 불가`·원인·다음 조치를 그대로 보여 주고 **과거 수치나 예시를 현재값으로 바꾸지 않습니다**.

**시연 종료 조건:** 네 카드·하단 기록/추이가 화면에서 보이는지와 새 시각을 확인. 실제 조회가 실패해도 그것을 실패로 명시하면 됩니다. 실측값의 크기나 SDP 연결 성공을 시연 합격 조건으로 꾸미지 않습니다.

### 시연 2 — 「업무 앱」: 판정 결과·미연결 구분 (약 1~2분)

**조작:** 왼쪽 「**업무 앱**」 탭 → 제공 앱 목록/접속 판정 영역과 학생 표시 `renderDecision` 영역을 차례로 보여 줍니다. 현재처럼 SDP가 미연결이면 **연결 없음·판정 확인 불가·다음 조치**를 읽습니다. 기존 운영자 권한과 실제 앱 목록이 확인되지 않는 상황에서 **임의 앱을 선택하거나 접속 요청을 강제로 보내지 않습니다**.

**설명:** 학생 화면은 제공 API가 보낸 `allow`(허용)·`deny`(거부)·`challenge`(추가 확인)·`unknown`(확인 불가)을 구분해 표시합니다. **판정 표시 코드를 구현한 것과 실제 업무 앱에 접속하여 허용/차단을 확인한 것은 다릅니다.** 연결이 없으면 무조건 허용 또는 거부 결과를 만들지 않습니다.

**확인 범위:** 메뉴·학생 판정 영역 및 연결 없음/요청 전 안내는 과거 브라우저 캡처로 확인. **실제 허용·차단·추가 확인 판정, 대상 업무 앱에 대한 실제 접속**은 미확인입니다.

### 시연 3 — 「보안 기록」: 접속 기록과 XDR의 근거 경계 (약 1~2분)

**조작:** 왼쪽 「**보안 기록**」 탭 → 제공 기록 영역과 학생 `renderEvents`의 상태/오류 표시를 설명합니다. SDP·XDR 원천이 미연결이면 기록을 가져오지 못했다는 표시와 「다시 불러오기」 안내를 보여 줍니다. 실제 원천이 연결돼 본인의 검증된 기록이 있는 경우에만 필터(종류/앱/접속 상태)와 사건 상세(근거/규칙/세션·기기·접속 상태)를 시연합니다. **실제 기록이 없는 경우 목록·필터·상세 동작을 실측 성공이라고 말하지 않습니다.**

**설명:** 접속/XDR 기록은 **기존 SDP/XDR 원천**의 결과이고, 보호 현황의 Windows System/Application 이벤트 집계와 **서로 다른 데이터**입니다. `0건`, `연결 없음`, `확인 불가`는 다릅니다. 조회 실패를 `0건`이라고 표기하지 않습니다. AI 설명·조치 제안 영역이 보여도 실제 모델 추론·원천 조치 실행은 별도 미검증 기능입니다.

**확인 범위:** 기존 브라우저에서 연결 없음·기록 조회 실패 안내를 관찰. **실제 XDR 기록 원문, 유효한 사건의 필터·상세 선택, 근거 분석, 집행 결과**는 미확인입니다.

### 선택 사항 — 확인 가능한 보조 영역 (약 30초)

「보호 현황」의 도움정보·AI 연결·설치 패키지 조회 상태가 있음을 설명할 수 있지만, **AI 승인 = 모델 응답 성공**, `not_configured` = 취약점 없음, `AI 제안` = 보안 조치 실행이라고 설명하지 않습니다. 실제 모델·OSV 요청과 권한은 이 시연에서 시험하지 않았습니다.

## 5. 실제 확인 근거 — 화면·실행 기록·GitHub (모두 구분)

### 5-1. 사용자 PC 화면에서 직접 관찰된 과거 실측

| 사용자 화면의 시점 (KST) | 관찰 내용 | 증거·해석 |
| --- | --- | --- |
| **2026-10-28 10:31:46~47** | CPU **4.8%**(약 650ms 측정), 메모리 사용 **7.6 / 전체 15.8 GiB**, 앱 볼륨 여유 **58.0 / 전체 382.4 GiB** | **[PC 화면] 2일차 실제 측정 카드**. 현재 PC의 새 측정값이 아니며, 직전 값과의 비교는 최초 조회 당시 미확인 |
| **2026-10-28 10:59:44~45경** | 네트워크 **IPv4 어댑터 2개**, 방화벽 **도메인·개인·공용 3개 켜짐**, 최근 24시간 Windows 오류 **4건**(System 3 + Application 1), 경고 **11건**(System 6 + Application 5) | **[PC 화면] 3일차 실제 관제 카드 및 하단 기록·조회 이력**. 로컬 Windows 운영 상태 **관측값**일 뿐 침해 탐지 수치가 아님 |
| **2026-10-28 11:23경** | 「다시 조회 · 관제 상태」 버튼, 네 카드, Windows 경고/오류 기록, `SDP 미연결 · PC 조회와 별개`, 하단 이력 표시 | **[PC 화면] 4일차 새 UI 반영 확인**. `Tab`/`Enter`만으로 조작한 실사용 결과, 강제 실패 시나리오까지 확인된 것은 아님 |

이전 채팅에서 전달된 **화면 관찰에 대한 기록**이며, 원본 이미지 파일이 GitHub에 자동 첨부됐다는 의미는 아닙니다. IP·사용자 계정·토큰 등 민감한 값이 포함된 전체 화면을 제출 자료로 올리지 마십시오. 새로 시연한 결과는 **그때 새로 조회한 시간**만 별도로 적습니다.

### 5-2. 실제 PowerShell/Git 실행 기록

| 시점 | 사용자 PC에서 확인된 명령/결과 | 말할 수 있는 것 |
| --- | --- | --- |
| **6일차, 2026-10-28** | `git pull --ff-only origin main` → `Updating c791725..799c7f4`, `Fast-forward` | 이전 파일을 강제 삭제하지 않고 5일차 문서 커밋을 로컬에 반영 |
| **6일차, 2026-10-28** | `git status --short --branch` → `## main...origin/main` | **그때** 미커밋 변경이 보고되지 않았고 원격 추적 상태가 일치 |
| **6일차, 2026-10-28** | `git rev-parse HEAD` → `799c7f4b9c08cc83cab9c9531275c505aa3d3830` | 그때 사용한 실제 **40자리 커밋 번호** |
| **6일차, 2026-10-28** | `git remote get-url origin` → `https://github.com/wnsghd1802/choi-bujang-secret-vault.git` | 확인된 원격 저장소 |
| **6일차, 2026-10-28** | `git push origin main` → `Everything up-to-date`; `git fetch origin` 이후 `git log --oneline --left-right HEAD...origin/main` → **출력 없음** | **그때** 로컬·원격 커밋 차이가 없음을 확인; 7일차 새 문서 커밋 이후 상태를 자동 보장하지는 않음 |

### 5-3. GitHub 코드/커밋으로 확인한 구현 이력

| 이력 | 확인에 사용할 커밋·자료 | 확인한 사실과 한계 |
| --- | --- | --- |
| 21~22단계 재현 기준 | `0c78f4f78d3d41322ead0a80bc5395ca0d411e7c` 및 `docs/STUDENT_RELEASE_RECORD.md` | 별도 폴더 문법·연결 없음·미설정 화면 일부 재현. **현재 최종 커밋에서 실제 AI/SDP/조치 성공을 증명하지 않음** |
| 2일차 PC 실측 코드 | `fe9414257841303176ba36593ad647db29c83c52` | 로컬 CPU/메모리/디스크 측정 기능 추가 |
| 3일차 Windows 관제 | `2e6155d607bb7061b4d8ead617d9fca4dfb156cd` | 읽기 전용 Windows 관측·상단 카드·하단 이력 추가 |
| 4일차 UI 다듬기 | `c7917258a1e437490bc6a7f3389ee1728fba6ebd` | 학생 핵심 안내와 재조회·대기·실패 대응 |
| 5일차 안내서 / 6일차 동기화 기준 | `799c7f4b9c08cc83cab9c9531275c505aa3d3830` | 초보자 실행 안내 정리 및 사용자 PC의 깨끗한 `main`/원격 동기화 확인 |
| **7일차 최종 시연 문서** | **이 문서를 포함하는 새 커밋을 생성한 후 `git rev-parse HEAD`로 확인** | Git 커밋 자체의 SHA를 커밋 전에 문서 안에 고정할 수 없으므로 **5일차 SHA를 7일차 최종 SHA라고 부르지 않음** |

**[모의 테스트]** 3~4일차 개발 중 Node.js/가짜 API·DOM 입력에서 성공/일부 오류/SDP 미연결/재조회 상태를 검증했으나, 가상의 수치를 **사용자 PC 실측값으로 표시하지 않습니다**. `on-client/package.json`의 `npm.cmd run check` 또한 **학생 모듈의 문법 검사**이지 실제 보안 연동의 통합 검사가 아닙니다.

## 6. 한계 및 남은 검증

| 구분 | 현재 검증 수준 | 나중에 확인하려면 |
| --- | --- | --- |
| SDP 연결·업무 앱 허용/차단 | **SDP 미연결 확인 / 실제 판정 미확인** | 운영자가 정식 SDP 연결·대상·자격을 승인한 뒤 실제 원천 응답과 시각을 확인 |
| 실제 XDR 이벤트·근거·규칙 상세 | **연결 실패 화면 확인 / 실원천 사건 미확인** | 본인 권한 범위 내 실제 이벤트가 있는 경우에만 목록·필터·상세를 검증 |
| AI 연결·설명 | 포털 승인 일부 화면만 확인, **실제 모델 응답·근거 설명 미확인** | 운영자 권한·모델 제공 상태, 안전한 실제 사건의 설명 결과 확인 |
| 보안 조치 실행·결과 | **미확인** | 운영자 승인된 원천 조치 연결과 사람 확인·ACK·실제 효과 조회를 별도 검증. 이번 시연에서는 실행하지 않음 |
| OSV 패키지별 취약점 확인 | **`PROJECT_NOT_CONFIGURED`/`not_configured` 화면 확인**, 실제 승인 패키지·OSV ID 미확인 | 운영자가 승인한 프로젝트/패키지 버전과 실제 조회 결과 확인 |
| 방화벽·Windows 로그 | 사용자 PC에서 읽기 성공 관찰, **보안 안전성 판단 아님** | 개별 조회 시각·권한·조회 상한·실패 사유를 확인하고, 설정은 수정하지 않음 |
| 키보드만으로 전체 화면 사용 | 기본 버튼·접근성 속성 설계 확인, **실사용 전체 검증 미확인** | `Tab`/`Enter`/`Space`, 포커스와 오류 읽기 등을 실제 PC에서 차례로 관찰 |
| 타 PC·제3자 실행 및 동일 최종 SHA 전체 재현 | 과거 22단계 **다른 폴더, 같은 PC의 구버전 화면 일부** 재현; 이번 7일차 커밋으로는 미확인 | 개인정보/인증 파일은 이전하지 않고 새 환경의 동일 SHA·문법·로컬 화면·종료·재실행을 다시 관찰 |
| 설치형 패키징/배포 | **실행하지 않음** | 과정 이후 별도 공식 안내·사용자 승인 시에만 검토. 이번 작업에서 `npm run package-app`과 새 포장 스크립트 금지 |
| 배포 수준·운영 인증 | `0.2.11 (검증 중)` | 코드 시연·과거 공식 단계 통과를 근거로 `v1.0`/실운영 인증을 선언하지 않음 |

## 7. 최종 시연 후 확인·제출 메모

실제 사용자 PC에서 시연을 마친 **다음에만** 아래 사항을 체크합니다. **문서를 GitHub에 커밋하는 것과 학생 PC에서 재실행한 것은 다른 증거**입니다.

- [ ] 기존 `on-client` 실행 도구로 서버 시작. 접속한 **브라우저 포트**와 로컬 HTTP 상태 확인
- [ ] `보호 현황`: 상단 카드 4개·하단 Windows 기록/조회 이력·PC 자원 측정. 새 조회 **시각**, 단위, 부분 실패/`SDP 미연결` 상태 따로 기록
- [ ] `업무 앱`: 제공 판정 화면/학생 안내 확인. 실원천 판정이 없으면 **미확인** 유지
- [ ] `보안 기록`: 학생 연결·오류 메시지와 XDR 원천 제한을 구분. 실제 사건이 없으면 **상세 성공을 주장하지 않음**
- [ ] 키보드만으로 버튼 조작, 종료 `Ctrl+C`와 재실행까지 **실제 했는지** 구분해 기록
- [ ] GitHub 최종 `main`과 사용자 PC의 `git rev-parse HEAD` 40자리 SHA 일치 확인; 비밀값 없이 제출할 저장소 URL·SHA 준비

시연 후 PowerShell에서 **기존 저장소 루트**를 열고 다음을 실행해 제출 기준을 확인합니다. `git pull`·`git push`가 거절되면 **`--force`/`reset --hard`를 사용하지 않고 원인부터 확인**하십시오.

```powershell
git status --short --branch
git rev-parse HEAD
git remote get-url origin
git fetch origin
git log --oneline --left-right HEAD...origin/main
```

**최종 GitHub 저장소:** `https://github.com/wnsghd1802/choi-bujang-secret-vault`

**비교용 6일차 HEAD (최종 7일차 SHA 아님):** `799c7f4b9c08cc83cab9c9531275c505aa3d3830`

**7일차 최종 제출 SHA:** **커밋·GitHub 반영 후 실제 `git rev-parse HEAD` 출력값**을 사용합니다. 여기에는 미리 채우거나 예시 SHA를 실제값으로 표시하지 않습니다.

**추가 참고:** [학생 실행 설명서](STUDENT_RUNBOOK.md) · [22단계 독립 재현·릴리스 기록](STUDENT_RELEASE_RECORD.md) · [최종 제공 제품 안내](FINAL_PRODUCT_GUIDE.md). 기존 제출·설정은 그대로 보존합니다.

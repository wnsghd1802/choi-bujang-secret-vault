# 내 보안 Agent 시작 틀 0.2.11

이 보안 Agent는 회사 직원이 자기 로그인 상태, 업무 앱 접속 결과, 최근 접속 기록과 보안 경보를 보는 보안 앱입니다. 13단계부터 22단계까지 이 프로젝트 하나로 화면을 채워 가며 완성합니다. 처음이라면 docs/GETTING_STARTED_STUDENT.md부터 읽습니다. 무엇을 왜 만드는지와 단계별 순서가 그 문서에 있습니다.

이 시작 틀을 받은 것만으로 단계를 통과하지 않습니다. 단계마다 docs/STUDENT_PROMPTS.md의 안내를 수업용 AI에 붙여 넣어 student/extension.mjs를 고치고, 화면에서 확인하고, 커밋한 뒤 ALEPH에 제출합니다. 제출하면 서버가 그 커밋의 코드를 받아 AI가 단계 과제 기준으로 읽고 판정합니다. 코드를 실행해서 판정하지 않습니다.

## 켜기

검수 환경은 Node.js 24.19.0이며 외부 npm 의존성이 없습니다. 이 폴더의 PowerShell에서 아래를 실행하고 PC 브라우저로 http://127.0.0.1:5189 를 엽니다. 자세한 켜기·끄기·다시 켜기는 docs/STUDENT_LAUNCH_GUIDE.md에 있습니다.

    powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\start-alekov.ps1

npm start도 같은 서버를 켭니다. 기본 실행은 실제 회사 시스템(기존 엔진)에 연결되지 않은 상태입니다. npm run demo는 예제 자료로 화면을 보여 줄 뿐이며 실제 연결이나 성취가 아닙니다. npm run check는 student/extension.mjs의 문법만 확인합니다.

## 지킬 것

- 기존 1~3차 프로젝트와 학생 파일은 지우거나 덮어쓰지 않습니다. 새 폴더에서 시작하거나, 이미 하던 프로젝트를 이어 씁니다.
- AI 열쇠·비밀번호·토큰을 코드, 커밋, 캡처, 도움정보에 넣지 않습니다. 주소나 열쇠를 직접 입력하는 칸도 만들지 않습니다.
- 현재 `on-client` 저장소에는 `.env.example`이 없습니다. 개인 비밀 설정을 만들어 커밋하거나 새 복제 폴더에 복사하지 않습니다.

## 더 읽을 곳

- 단계별 안내와 AI에 붙여 넣을 문장: docs/STUDENT_PROMPTS.md
- 단계별 확인 항목: docs/CURRICULUM.json, docs/IMPLEMENTATION_CONTRACT.md
- 오류 코드별 해결: docs/CONNECTION_TROUBLESHOOT.md
- 시작 틀 업데이트(내 파일 보존): docs/STARTER_UPDATE.md
- 실제 회사 시스템(SDP)·앱 안 AI 연결은 담당자가 따로 안내할 때만 씁니다: docs/SDP_HOST_CONNECTION.md, docs/AI_SETUP_GUIDE.md. 이 연결은 앱을 처음 켜고 13~16단계 화면을 만들거나 공식 AI 코드 판정을 받기 위한 전제 조건은 아닙니다. 다만 17단계 이후의 실제 연결과 새 환경 재현은 해당 단계의 기준에 따라 따로 확인합니다.

## KimJH 총공세 7일차 — 최종 시연·정리

최종 관제 대시보드 **핵심 3기능 시연 순서**, 기존 제공 기능과 학생 구현 구분, 실제 Windows PC 화면·Git 증거, **SDP·XDR·AI·조치 등 미확인 항목**, 기존 프로젝트 폴더의 재현 절차는 [최종 시연·정리 문서](docs/STUDENT_FINAL_DEMO.md)에 기록했습니다. **프로젝트 폴더에서만 실행**하며 설치형 포장·패키징은 진행하지 않습니다. 문서 추가만으로 실제 보안 원천 연결이나 제3자 재현을 성공했다고 주장하지 않습니다.

## KimJH 학생 설명서 (21단계 작성)

**목적:** KimJH는 사용자 본인의 로그인·기기·세션, 업무 앱 접근 판정, XDR 기록, AI 설명·조치 제안 및 OSV 설치 패키지 조회 상태를 보여 주는 보안 Agent입니다. 실제 접근 판정·탐지·집행은 기존 SDP/원천 시스템의 영역이고 학생 화면이 이를 직접 실행하지 않습니다.

**실행 환경:** Windows PowerShell에서 확인된 Node.js `v24.19.0`, 앱 버전 `0.2.11`. Git 최상위는 `choi-bujang-secret-vault`이고 이 앱의 실행 폴더는 `on-client`입니다. `on-client/package.json`에 외부 npm 의존성은 없고, 이 하위 폴더에는 `package-lock.json`이 없습니다. 최상위 프로젝트의 패키지 파일과 혼동하지 않습니다. Windows 세부 버전, 다른 OS·브라우저에서의 재현은 미확인입니다.

**시작과 종료:** `on-client`에서 `powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\start-alekov.ps1`을 실행해 로컬 `http://127.0.0.1:5189/`에 접속합니다. 서버가 응답했다는 출력은 실제 SDP·AI 연결 성공을 증명하지 않습니다. 중지는 실행 창의 `Ctrl+C`이며, 재실행은 같은 명령입니다. 본인 PC에서 이미 준비된 Native Host를 사용하는 실제 명령·확인 순서는 아래 학생 문서에 있습니다.

**기능 구성:** 브라우저 ↔ `public/app.js` ↔ `src/server.mjs` ↔ 기존 엔진 어댑터·AI 연결/CLCO 게이트·OSV 스캐너. 학생 기능은 `student/extension.mjs`의 `renderIdentity`, `renderDecision`, `renderEvents`, `renderStatus`, `renderAiConnection`, `renderExplanation`, `renderAction`, `renderVulnerabilities`에 있으며 제공 UI·서버·판정기와 분리됩니다.

**확인한 범위:** 20단계까지의 학생 화면·문법 검사 및 `not_configured` 상태는 실제 PC에서 확인했습니다. 현재 AI 앱의 모델 응답·실제 SDP 집행·OSV 패키지별 조회는 확인되지 않았습니다. 미조회·실패는 취약점 없음이나 안전을 뜻하지 않습니다. 인증 설정·열쇠는 문서와 Git에 포함하지 않습니다.

**실제 작업 경로, 설치/실행/검증 명령, 텍스트 구성도, 오류별 확인, 21단계 제출 방식:** [`docs/STUDENT_RUNBOOK.md`](docs/STUDENT_RUNBOOK.md).

## KimJH 릴리스 검증 기록 (22단계)

**표기 버전:** `alekov-client-starter 0.2.11 (검증 중)` — `v1.0`이 아닙니다. 21단계 기준 소스 `0c78f4f78d3d41322ead0a80bc5395ca0d411e7c`를 별도 `KimJH-stage22-repro` 폴더에 복제하여 Git SHA 일치·`npm.cmd run check` 정상 종료·보호 현황/업무 앱/보안 기록과 패키지 조회 화면을 확인했습니다. 이는 **연결 없음(`disconnected`)·`not_configured` 상태의 화면 표시 재현**이지 실제 보안 원천/AI/OSV 취약점 조회 성공이 아닙니다.

**종료·재실행, 실제 AI·SDP·조치 집행, 데이터베이스 복원, 이 문서를 포함하는 최종 SHA의 독립 재실행은 미확인**으로 남깁니다. 학생이 실제 관찰한 시각·증거, 13~21단계 표, 데이터 백업·복원 계획, 새 폴더로 이동하는 방법 및 미완료 항목은 [`docs/STUDENT_RELEASE_RECORD.md`](docs/STUDENT_RELEASE_RECORD.md)에 기록했습니다. 최종 제출에 사용하는 SHA는 **이 문서까지 포함하는 Git 커밋의 40자리 SHA**입니다.

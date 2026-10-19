// 이 파일은 학생이 같은 프로젝트에서 이어서 구현합니다.
// 제공 UI를 받은 것만으로 단계 완료를 인정하지 않습니다.
export function createStudentView() {
  return {
    renderIdentity({ me, devices, sessions }) {
      const root = document.createElement('div');
      const deviceStates = {
        compliant: '보안 기준 충족',
        noncompliant: '보안 기준 미충족',
        unknown: '확인 불가',
      };
      const sessionStates = {
        active: '활성',
        expired: '만료',
        revoked: '철회됨',
        unknown: '확인 불가',
      };
      const modeStates = {
        demo: '예제 자료',
        disconnected: '연결 없음',
        unknown: '확인 불가',
      };
      const addText = (parent, tag, value) => {
        const element = document.createElement(tag);
        element.textContent = value;
        parent.appendChild(element);
        return element;
      };
      const addSection = (title, resource) => {
        const section = document.createElement('section');
        root.appendChild(section);
        addText(section, 'h3', title);
        if (resource && Object.hasOwn(modeStates, resource.mode)) {
          addText(section, 'p', `연결 상태: ${modeStates[resource.mode]}`);
        }
        if (!resource || resource.status === 'loading') {
          addText(section, 'p', '불러오는 중');
          return null;
        }
        if (resource.status === 'error') {
          const message = resource.error && typeof resource.error.message === 'string' && resource.error.message
            ? resource.error.message : '오류 내용을 확인할 수 없습니다.';
          addText(section, 'p', `연결 실패: ${message}`);
          return null;
        }
        if (resource.status !== 'ok' || !resource.data) {
          addText(section, 'p', '확인 불가');
          return null;
        }
        return section;
      };

      const account = addSection('현재 로그인 사용자·기기·세션', me);
      if (account) {
        const { user, device, session } = me.data;
        addText(account, 'p', `사용자: ${user.label} (ID: ${user.id})`);
        addText(account, 'p', `현재 기기: ${device.label} (ID: ${device.id}) · 보안 상태: ${deviceStates[device.status] || deviceStates.unknown}(${device.status})`);
        addText(account, 'p', `현재 세션: ${session.id} · 세션 상태: ${sessionStates[session.status] || sessionStates.unknown}(${session.status})`);
      }

      const deviceSection = addSection('내 기기 목록', devices);
      if (deviceSection) {
        if (devices.data.length === 0) addText(deviceSection, 'p', '표시할 기기가 없습니다.');
        else {
          const list = document.createElement('ul');
          deviceSection.appendChild(list);
          for (const device of devices.data) {
            addText(list, 'li', `${device.label} (ID: ${device.id}) · 보안 상태: ${deviceStates[device.status] || deviceStates.unknown}(${device.status})`);
          }
        }
      }

      const sessionSection = addSection('내 세션 목록', sessions);
      if (sessionSection) {
        if (sessions.data.length === 0) addText(sessionSection, 'p', '표시할 세션이 없습니다.');
        else {
          const list = document.createElement('ul');
          sessionSection.appendChild(list);
          for (const session of sessions.data) {
            addText(list, 'li', `세션 ID: ${session.id} · 세션 상태: ${sessionStates[session.status] || sessionStates.unknown}(${session.status})`);
          }
        }
      }
      return root;
    },
    renderDecision({ status, mode, data, error, appId }) {
      const root = document.createElement('div');
      const addText = (value) => {
        const paragraph = document.createElement('p');
        paragraph.textContent = value;
        root.appendChild(paragraph);
      };
      const modes = {
        demo: '예제 자료 · 실제 연결 판정이 아닙니다.',
        disconnected: '연결 없음',
        unknown: '연결 상태 확인 불가',
      };
      if (Object.hasOwn(modes, mode)) addText(`데이터 상태: ${modes[mode]}`);

      if (status === 'idle') {
        addText('업무 앱 하나를 선택하고 접속 요청 버튼을 누르세요.');
        return root;
      }

      if (appId) addText(`요청한 업무 앱 ID: ${appId}`);

      if (status === 'loading') {
        addText('접속 판정 확인 중');
        return root;
      }

      if (status === 'error') {
        const message = typeof error?.message === 'string' && error.message
          ? error.message : '오류 내용을 확인할 수 없습니다.';
        const unverified = error?.code === 'CONTRACT_MISMATCH' || error?.code === 'ENGINE_RESULT_UNVERIFIED';
        addText(`${unverified ? '판정 확인 불가' : '접속 판정 요청 실패'}: ${message}`);
        addText('요청 실패 또는 확인 불가는 접근 거부(deny) 판정도, 접근 허용(allow) 판정도 아닙니다.');
        return root;
      }

      if (status !== 'ok' || !data) {
        addText('판정 확인 불가(unknown) · 접근 허용으로 간주하지 않습니다.');
        return root;
      }

      const labels = {
        allow: '접근 허용',
        deny: '접근 거부',
        challenge: '추가 확인 필요',
        unknown: '판정 확인 불가',
      };
      const decision = Object.hasOwn(labels, data.decision) ? data.decision : 'unknown';
      addText(`업무 앱 ID: ${data.appId}`);
      addText(`접속 판정: ${labels[decision]}(${decision})`);
      if (decision === 'allow') {
        addText('정책상 접근 허용이며 실제 업무 앱 접속 성공을 보장하지 않습니다.');
      } else if (decision === 'challenge') {
        addText('추가 인증 또는 확인이 필요합니다. 이 앱은 확인 절차를 대신 수행하지 않습니다.');
      } else if (decision === 'unknown') {
        addText('판정 결과를 확인할 수 없습니다. 접근 허용으로 간주하지 않습니다.');
      }
      addText(`판정 이유: ${typeof data.reason === 'string' && data.reason ? data.reason : '사유 정보 없음'}`);
      addText(`판정 시각: ${typeof data.checkedAt === 'string' && data.checkedAt ? data.checkedAt : '확인 불가'}`);
      return root;
    },
    renderEvents() { return '학생 구현 대기: 본인 접속·XDR 기록을 연결하세요.'; },
    renderStatus() { return '학생 구현 대기: 기기·세션·알림과 연결 점검 상태를 구분하세요.'; },
    renderVulnerabilities() { return '학생 구현 대기: 정확한 설치 버전·OSV 출처·조회 시각·부분 결과·조회 실패를 구분하세요.'; },
    renderAiConnection() { return '학생 구현 대기: 모델 응답 점검과 실제 사건 설명을 구분하고 AI 오류·취소·수동 복구를 안내하세요.'; },
    renderExplanation() { return '학생 구현 대기: 선택한 사건의 근거·규칙·현재 상태와 AI 설명을 연결하세요. 제안은 자동 실행하지 않습니다.'; },
    renderAction() { return '학생 구현 대기: 현재 사건·조치·실제 대상·사람 확인·ACK와 원천 효과·unknown을 구분하세요.'; },
  };
}

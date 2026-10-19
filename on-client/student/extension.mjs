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
    renderEvents({ status, mode, data, error }) {
      const root = document.createElement('div');
      const addText = (parent, tag, value) => {
        const node = document.createElement(tag);
        node.textContent = value;
        parent.appendChild(node);
        return node;
      };
      const modeLabels = {
        demo: '예제 자료 · 실제 연결 기록이 아닙니다.',
        disconnected: '연결 없음',
        unknown: '연결 상태 확인 불가',
      };
      if (Object.hasOwn(modeLabels, mode)) addText(root, 'p', `데이터 상태: ${modeLabels[mode]}`);

      if (status === 'loading') {
        addText(root, 'p', '보안 기록 불러오는 중');
        return root;
      }
      if (status === 'error') {
        const message = typeof error?.message === 'string' && error.message
          ? error.message : '오류 내용을 확인할 수 없습니다.';
        const unverified = error?.code === 'CONTRACT_MISMATCH' || error?.code === 'ENGINE_RESULT_UNVERIFIED';
        addText(root, 'p', `${unverified ? '확인 불가 · ' : ''}기록을 불러오지 못했습니다: ${message}`);
        return root;
      }
      if (status !== 'ok' || !Array.isArray(data)) {
        addText(root, 'p', '기록 상태를 확인할 수 없습니다.');
        return root;
      }

      const sorted = [...data].sort((a, b) => Date.parse(b.at) - Date.parse(a.at));
      if (sorted.length === 0) {
        addText(root, 'p', '표시할 기록이 없습니다.');
        return root;
      }

      const kindLabels = { access: '접속 기록', xdr: 'XDR 경보' };
      const accessLabels = { allowed: '접근 허용', denied: '접근 거부', unknown: '확인 불가' };
      const sessionLabels = { active: '활성', expired: '만료', revoked: '철회됨', unknown: '확인 불가' };
      const deviceLabels = { compliant: '보안 기준 충족', noncompliant: '보안 기준 미충족', unknown: '확인 불가' };
      const labelStatus = (labels, value) => `${labels[value] || '확인 불가'}(${value})`;
      const appLabel = (appId) => appId == null ? '앱 ID 확인 불가' : appId;
      const addFilter = (title, values, displayValue) => {
        const label = document.createElement('label');
        label.textContent = `${title}: `;
        const select = document.createElement('select');
        for (const value of ['all', ...values]) {
          const option = document.createElement('option');
          option.value = value;
          option.textContent = value === 'all' ? '전체' : displayValue(value);
          select.appendChild(option);
        }
        select.value = 'all';
        label.appendChild(select);
        filters.appendChild(label);
        return select;
      };
      const filters = document.createElement('div');
      root.appendChild(filters);
      const kinds = [...new Set(sorted.map(event => event.kind))];
      const apps = [...new Set(sorted.map(event => event.appId ?? ''))];
      const accesses = [...new Set(sorted.map(event => event.state.access))];
      const kindFilter = addFilter('기록 종류', kinds, value => `${kindLabels[value] || '확인 불가'}(${value})`);
      const appFilter = addFilter('업무 앱', apps, value => value === '' ? '앱 ID 없음' : value);
      const accessFilter = addFilter('접속 상태', accesses, value => labelStatus(accessLabels, value));
      const count = addText(root, 'p', '');
      const list = document.createElement('ul');
      root.appendChild(list);

      const makeDetail = (event) => {
        const detail = document.createElement('div');
        detail.setAttribute('data-student-event-detail', event.id);
        addText(detail, 'h4', '기록 상세');
        addText(detail, 'p', `사건 ID: ${event.id}`);
        addText(detail, 'p', `업무 앱 ID: ${appLabel(event.appId)}`);
        const addEntries = (title, entries) => {
          addText(detail, 'h4', title);
          if (entries.length === 0) {
            addText(detail, 'p', `${title} 없음`);
          } else {
            const entryList = document.createElement('ul');
            for (const entry of entries) addText(entryList, 'li', `ID: ${entry.id} · 내용: ${entry.text}`);
            detail.appendChild(entryList);
          }
        };
        addEntries('근거', event.evidence);
        addEntries('규칙', event.rules);
        addText(detail, 'p', `접속 상태: ${labelStatus(accessLabels, event.state.access)}`);
        addText(detail, 'p', `세션 상태: ${labelStatus(sessionLabels, event.state.session)}`);
        addText(detail, 'p', `기기 상태: ${labelStatus(deviceLabels, event.state.device)}`);
        return detail;
      };
      const updateList = () => {
        const filtered = sorted.filter(event =>
          (kindFilter.value === 'all' || event.kind === kindFilter.value)
          && (appFilter.value === 'all' || (event.appId ?? '') === appFilter.value)
          && (accessFilter.value === 'all' || event.state.access === accessFilter.value));
        count.textContent = `표시 ${filtered.length}건 / 조회 ${sorted.length}건`;
        list.replaceChildren();
        if (filtered.length === 0) {
          addText(list, 'li', '현재 필터에 해당하는 기록이 없습니다.');
          return;
        }
        for (const event of filtered) {
          const item = document.createElement('li');
          item.setAttribute('data-student-event-id', event.id);
          addText(item, 'p', `사건 ID: ${event.id}`);
          addText(item, 'p', `발생 시각: ${event.at}`);
          addText(item, 'p', `기록 종류: ${kindLabels[event.kind] || '확인 불가'}(${event.kind})`);
          addText(item, 'p', `업무 앱: ${appLabel(event.appId)}`);
          addText(item, 'p', `요약: ${event.summary}`);
          const button = document.createElement('button');
          button.type = 'button';
          button.textContent = `${event.id} 상세`;
          button.setAttribute('aria-expanded', 'false');
          item.appendChild(button);
          let detail = null;
          button.addEventListener('click', () => {
            if (detail) {
              detail.remove();
              detail = null;
              button.setAttribute('aria-expanded', 'false');
            } else {
              detail = makeDetail(event);
              item.appendChild(detail);
              button.setAttribute('aria-expanded', 'true');
            }
          });
          list.appendChild(item);
        }
      };
      for (const select of [kindFilter, appFilter, accessFilter]) {
        select.addEventListener('change', updateList);
      }
      updateList();
      return root;
    },
    renderStatus() { return '학생 구현 대기: 기기·세션·알림과 연결 점검 상태를 구분하세요.'; },
    renderVulnerabilities() { return '학생 구현 대기: 정확한 설치 버전·OSV 출처·조회 시각·부분 결과·조회 실패를 구분하세요.'; },
    renderAiConnection() { return '학생 구현 대기: 모델 응답 점검과 실제 사건 설명을 구분하고 AI 오류·취소·수동 복구를 안내하세요.'; },
    renderExplanation() { return '학생 구현 대기: 선택한 사건의 근거·규칙·현재 상태와 AI 설명을 연결하세요. 제안은 자동 실행하지 않습니다.'; },
    renderAction() { return '학생 구현 대기: 현재 사건·조치·실제 대상·사람 확인·ACK와 원천 효과·unknown을 구분하세요.'; },
  };
}

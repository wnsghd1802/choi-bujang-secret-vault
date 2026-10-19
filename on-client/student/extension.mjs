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
        if (Array.isArray(event.supportedActions) && event.supportedActions.length > 0) {
          addText(detail, 'h4', '미지원 조치');
          addText(detail, 'p', '조치 실행 연결은 준비 중입니다. 아래 버튼은 비활성 상태이며, 조치 요청을 전송하지 않습니다.');
          for (const action of event.supportedActions) {
            const unsupportedButton = document.createElement('button');
            unsupportedButton.type = 'button';
            unsupportedButton.textContent = `${action} 미지원`;
            unsupportedButton.disabled = true;
            detail.appendChild(unsupportedButton);
          }
        }
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
    renderStatus({ devices, sessions, notifications, diagnostics, mode }) {
  const root = document.createElement('div');
  const addText = (parent, tag, value) => {
    const node = document.createElement(tag);
    node.textContent = value;
    parent.appendChild(node);
    return node;
  };
  const section = (title) => {
    const area = document.createElement('section');
    root.appendChild(area);
    addText(area, 'h3', title);
    return area;
  };
  const modeLabels = {
    connected: '기존 서버 연결',
    demo: '예제 자료 · 실제 연결 상태가 아닙니다.',
    disconnected: '기존 서버 연결 없음',
    unknown: '연결 상태 확인 불가',
  };
  addText(root, 'p', `데이터 상태: ${modeLabels[mode] || modeLabels.unknown}`);
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
  const stateLabel = (labels, value) => `${labels[value] || '확인 불가'}(${value})`;
  const errorMessage = (resource) =>
    typeof resource?.error?.message === 'string' && resource.error.message
      ? resource.error.message : '오류 상세 정보를 확인할 수 없습니다.';
  const isTimeout = (resource) =>
    /TIMEOUT|TIMED_OUT/i.test(String(resource?.error?.code || ''))
    || /시간\s*초과|timed?\s*out/i.test(errorMessage(resource));
  const renderCollection = (title, resource, emptyMessage, describe) => {
    const area = section(title);
    if (!resource || resource.status === 'loading') {
      addText(area, 'p', `${title} 불러오는 중`);
      return;
    }
    if (resource.status === 'error') {
      addText(area, 'p', `${title} 조회 실패${isTimeout(resource) ? ' (시간 초과)' : ''}: ${errorMessage(resource)}`);
      addText(area, 'p', '다시 시도는 위쪽 「다시 불러오기」 버튼을 직접 누르세요. 자동 재시도는 수행하지 않습니다.');
      return;
    }
    if (resource.status !== 'ok' || !Array.isArray(resource.data)) {
      addText(area, 'p', `${title} 상태를 확인할 수 없습니다.`);
      return;
    }
    if (resource.data.length === 0) {
      addText(area, 'p', emptyMessage);
      return;
    }
    const list = document.createElement('ul');
    for (const entry of resource.data) addText(list, 'li', describe(entry));
    area.appendChild(list);
  };

  renderCollection('내 기기 목록', devices, '등록된 기기가 없습니다.',
    (device) => `${device.label} (ID: ${device.id}) · 보안 상태: ${stateLabel(deviceStates, device.status)}`);
  renderCollection('현재 세션', sessions, '현재 확인된 연결이 없습니다.',
    (session) => `세션 ID: ${session.id} · 세션 상태: ${stateLabel(sessionStates, session.status)}`);
  addText(root, 'p', '세션 정보는 현재 검증된 연결 1건만 대상으로 하며, 과거 세션 전체 목록이 아닙니다.');

  const notificationArea = section('보안 알림');
  if (!Array.isArray(notifications) || notifications.length === 0) {
    addText(notificationArea, 'p', '주의할 알림이 없습니다.');
  } else {
    const list = document.createElement('ul');
    for (const notice of notifications) {
      addText(list, 'li', `자료(resource): ${notice.resource} · 코드(code): ${notice.code} · 내용(message): ${notice.message}`);
    }
    notificationArea.appendChild(list);
  }

  const diagnosticArea = section('진단 정보');
  let copyPayload = null;
  if (!diagnostics || diagnostics.status === 'idle') {
    addText(diagnosticArea, 'p', '진단 정보를 아직 조회하지 않았습니다. 제공 화면의 「도움정보 불러오기」 버튼으로 조회하세요.');
  } else if (diagnostics.status === 'loading') {
    addText(diagnosticArea, 'p', '진단 정보 불러오는 중');
  } else if (diagnostics.status === 'error') {
    addText(diagnosticArea, 'p', `진단 정보 조회 실패${isTimeout(diagnostics) ? ' (시간 초과)' : ''}: ${errorMessage(diagnostics)}`);
    addText(diagnosticArea, 'p', '다시 시도하려면 제공 화면의 「도움정보 불러오기」 버튼을 직접 누르세요.');
  } else if (diagnostics.status === 'ok' && diagnostics.data && typeof diagnostics.data === 'object') {
    const safeValue = (value, limit = 100) =>
      typeof value === 'string'
      && value.length > 0
      && value.length <= limit
      && /^[A-Za-z0-9._:@+-]+$/.test(value)
      && !/^(?:sk[-_]|gh[pousr]_|eyJ|Bearer)/i.test(value)
        ? value : '확인 불가';
    const data = diagnostics.data;
    const fields = {
      requestId: safeValue(data.requestId),
      component: safeValue(data.component),
      version: safeValue(data.version),
      checkedAt: safeValue(data.checkedAt),
      'engine.mode': safeValue(data.engine?.mode),
      'engine.code': safeValue(data.engine?.code),
    };
    const list = document.createElement('ul');
    for (const [key, value] of Object.entries(fields)) addText(list, 'li', `${key}: ${value}`);
    diagnosticArea.appendChild(list);
    copyPayload = JSON.stringify(fields, null, 2);
  } else {
    addText(diagnosticArea, 'p', '진단 정보 상태를 확인할 수 없습니다.');
  }
  addText(diagnosticArea, 'p', '도움정보 복사는 장애 문의에 필요한 진단 정보만 클립보드에 복사합니다. 비밀번호·인증 토큰·API 키는 포함하지 않습니다.');
  const copyButton = document.createElement('button');
  copyButton.type = 'button';
  copyButton.textContent = '도움정보 복사';
  copyButton.disabled = copyPayload === null;
  diagnosticArea.appendChild(copyButton);
  const copyNotice = addText(diagnosticArea, 'p', copyPayload === null ? '복사할 진단 결과가 없습니다.' : '복사는 버튼을 누를 때만 실행됩니다.');
  copyNotice.setAttribute('role', 'status');
  copyButton.addEventListener('click', () => {
    if (copyPayload === null) return;
    if (typeof navigator === 'undefined' || typeof navigator.clipboard?.writeText !== 'function') {
      copyNotice.textContent = '클립보드 기능을 사용할 수 없습니다. 브라우저 권한을 확인하세요.';
      return;
    }
    navigator.clipboard.writeText(copyPayload).then(() => {
      copyNotice.textContent = '진단 도움정보를 클립보드에 복사했습니다.';
    }).catch(() => {
      copyNotice.textContent = '도움정보 복사에 실패했습니다. 클립보드 권한을 확인하고 직접 다시 시도하세요.';
    });
  });
  return root;
},
    renderVulnerabilities() { return '학생 구현 대기: 정확한 설치 버전·OSV 출처·조회 시각·부분 결과·조회 실패를 구분하세요.'; },
    renderAiConnection() { return '학생 구현 대기: 모델 응답 점검과 실제 사건 설명을 구분하고 AI 오류·취소·수동 복구를 안내하세요.'; },
    renderExplanation() { return '학생 구현 대기: 선택한 사건의 근거·규칙·현재 상태와 AI 설명을 연결하세요. 제안은 자동 실행하지 않습니다.'; },
    renderAction() { return '학생 구현 대기: 현재 사건·조치·실제 대상·사람 확인·ACK와 원천 효과·unknown을 구분하세요.'; },
  };
}

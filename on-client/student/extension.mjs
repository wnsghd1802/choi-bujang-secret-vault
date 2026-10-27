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
          const code = typeof resource.error?.code === 'string'
            && /^[A-Z][A-Z0-9_]{0,63}$/.test(resource.error.code) ? resource.error.code : null;
          addText(section, 'p', `연결 실패: ${message}`);
          if (code) addText(section, 'p', `오류 코드: ${code}`);
          if (resource.mode === 'disconnected' || code === 'ENGINE_NOT_CONNECTED') {
            addText(section, 'p', '기존 SDP 엔진이 연결되지 않았습니다. 운영자가 승인한 -SdpHostConfig 연결 여부를 확인하세요. AI 계정용 -NativeHostConfig는 SDP 연결을 대신하지 않습니다.');
          } else {
            addText(section, 'p', '실제 사용자·기기·세션을 확인하지 못했습니다. 연결 상태를 확인한 뒤 「다시 불러오기」로 직접 재조회하세요.');
          }
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
        if (mode === 'disconnected') {
          addText('기존 SDP 엔진 연결이 없어 업무 앱 목록과 접근 판정을 확인할 수 없습니다. 앱 선택·판정 요청은 실행되지 않았습니다.');
          addText('운영자에게 SDP 연결 상태를 확인한 뒤 제공 화면의 「다시 불러오기」를 직접 누르세요.');
        } else {
          addText('업무 앱 하나를 선택하고 접속 요청 버튼을 누르세요.');
        }
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
        if (typeof error?.code === 'string' && /^[A-Z][A-Z0-9_]{0,63}$/.test(error.code)) {
          addText(`오류 코드: ${error.code}`);
        }
        addText('요청 실패 또는 확인 불가는 접근 거부(deny) 판정도, 접근 허용(allow) 판정도 아닙니다.');
        addText(mode === 'disconnected' || error?.code === 'ENGINE_NOT_CONNECTED'
          ? '기존 SDP 연결이 준비되지 않았습니다. 운영자 연결 상태를 확인하세요. 임의 판정을 만들지 않습니다.'
          : '실제 판정이 확인되지 않았습니다. 제공 화면의 「다시 불러오기」로 앱 목록을 확인한 뒤 직접 다시 요청하세요.');
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
        if (typeof error?.code === 'string' && /^[A-Z][A-Z0-9_]{0,63}$/.test(error.code)) {
          addText(root, 'p', `오류 코드: ${error.code}`);
        }
        addText(root, 'p', mode === 'disconnected' || error?.code === 'ENGINE_NOT_CONNECTED'
          ? '기존 SDP·XDR 기록 원천이 연결되지 않았습니다. 운영자가 승인한 -SdpHostConfig를 확인하세요. 조회 실패는 기록 0건이 아닙니다.'
          : '기록을 확인하지 못했습니다. 제공 화면의 「다시 불러오기」로 직접 재조회하세요. 자동 재시도하거나 빈 성공으로 표시하지 않습니다.');
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
    renderVulnerabilities({ status, mode, data, error }) {
      const root = document.createElement('section');
      const addText = (parent, tag, value) => {
        const node = document.createElement(tag);
        node.textContent = String(value);
        parent.appendChild(node);
        return node;
      };
      const modes = {
        connected: '연결됨',
        demo: '예제 자료',
        disconnected: '연결 없음',
        unknown: '연결 상태 확인 불가',
      };
      if (Object.hasOwn(modes, mode)) addText(root, 'p', `데이터 모드: ${modes[mode]} (${mode})`);

      if (status === 'idle') {
        addText(root, 'p', '조회 전 · 설치 패키지 및 OSV 조회를 아직 실행하지 않았습니다.');
        return root;
      }
      if (status === 'loading') {
        addText(root, 'p', '조회 중 · 현재 요청의 결과를 확인하고 있습니다. 이전 조회 표는 표시하지 않습니다.');
        return root;
      }
      if (status === 'error') {
        const safeMessage = typeof error?.message === 'string' && error.message.length > 0
          && error.message.length <= 500 && !/[\u0000-\u001f\u007f]/.test(error.message)
          && !/(?:Bearer\s+\S+|sk-[A-Za-z0-9_-]{8,}|-----BEGIN [A-Z ]*KEY-----|(?:password|비밀번호|api[_ -]?key|token|토큰)\s*[:=]\s*\S+)/i.test(error.message)
          ? error.message : '오류 상세 내용을 확인할 수 없습니다.';
        addText(root, 'p', `조회 실패: ${safeMessage}`);
        if (typeof error?.code === 'string' && /^[A-Z][A-Z0-9_]{0,63}$/.test(error.code)) {
          addText(root, 'p', `오류 코드: ${error.code}`);
        }
        addText(root, 'p', '조회 실패·취소는 취약점 없음이 아닙니다. 이전 결과를 현재 결과로 표시하지 않습니다.');
        return root;
      }
      if (status !== 'ok') {
        addText(root, 'p', '조회 상태 확인 불가 · 현재 결과를 표시할 수 없습니다.');
        return root;
      }

      const scanStates = {
        complete: '승인된 대상 모두 조회',
        partial: '일부 조회 실패 · 확인된 결과만 유효',
        not_checked: '아직 조회 안 함 · 승인된 공개 조회 대상 없음',
        not_configured: '조회 준비 미완료 · 대상 프로젝트 설정 없음',
        unverifiable: 'lock 파일 확인 불가 · 설치 목록 검증 불가',
      };
      if (!data || !Object.hasOwn(scanStates, data.status) || !Array.isArray(data.packages)) {
        addText(root, 'p', '조회 결과 형식 확인 불가 · 취약점 없음으로 판단할 수 없습니다.');
        return root;
      }
      const summary = addText(root, 'p', `전체 조회 상태: ${scanStates[data.status]} (${data.status})`);
      summary.setAttribute('role', 'status');
      if (data.status === 'not_configured') {
        addText(root, 'p', '점검 대상 설정이 없습니다. 서버 운영자가 ON_PROJECT_DIRECTORY에 승인된 실제 프로젝트 경로를 지정해야 합니다. 학생 화면에서 대상이나 인증 정보를 임의로 입력하지 않습니다.');
      } else if (data.status === 'not_checked') {
        addText(root, 'p', '승인된 공개 패키지 조회 대상이 없습니다. 운영자가 ON_APPROVED_PUBLIC_PACKAGES 승인 목록과 설치 메타데이터를 확인해야 하며, 취약점 없음으로 판단하지 않습니다.');
      } else if (data.status === 'unverifiable') {
        addText(root, 'p', '대상 프로젝트의 package-lock.json과 설치된 패키지 메타데이터를 검증할 수 없습니다. 파일을 임의 변경하거나 확인 불가를 안전으로 표시하지 않습니다.');
      }
      if (data.lockfileVersion !== undefined && data.lockfileVersion !== null) {
        addText(root, 'p', `lockfileVersion (package-lock.json 형식 버전): ${data.lockfileVersion}`);
      }
      if (typeof data.lockfileHash === 'string') addText(root, 'p', `lockfileHash (잠금 파일 해시): ${data.lockfileHash}`);
      if (typeof data.checkedAt === 'string') addText(root, 'p', `checkedAt (전체 조회 시각): ${data.checkedAt}`);
      addText(root, 'p', '설치 버전은 package-lock.json과 설치된 node_modules의 메타데이터를 대조한 결과입니다. 버전 범위가 아닌 정확한 설치 버전을 표시합니다.');

      if (data.packages.length === 0) {
        if (data.status === 'complete') {
          addText(root, 'p', '조회 결과에 표시할 패키지가 없습니다. 앱 전체의 안전을 보장하지 않습니다.');
        } else if (data.status === 'partial') {
          addText(root, 'p', '일부 조회가 실패했으며 표시할 패키지 결과가 없습니다. 취약점 없음으로 판단하지 않습니다.');
        } else {
          addText(root, 'p', '패키지별 조회 결과가 없습니다. 미조회·설정 미완료·검증 불가 상태를 취약점 없음으로 판단하지 않습니다.');
        }
        return root;
      }

      const table = document.createElement('table');
      addText(table, 'caption', '패키지별 정확한 설치 버전 및 OSV 조회 결과');
      const thead = document.createElement('thead');
      const headerRow = document.createElement('tr');
      for (const label of ['패키지 이름', '정확한 설치 버전', '패키지 조회 상태', 'OSV 조회 출처', '패키지 조회 시각', '알려진 취약점 ID · 수정 시각']) {
        const header = addText(headerRow, 'th', label);
        header.setAttribute('scope', 'col');
      }
      thead.appendChild(headerRow);
      table.appendChild(thead);
      const tbody = document.createElement('tbody');
      const exactVersion = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/;
      for (const pkg of data.packages) {
        if (!pkg || typeof pkg !== 'object') continue;
        const name = typeof pkg.name === 'string' ? pkg.name : '확인 불가';
        const version = typeof pkg.version === 'string' && exactVersion.test(pkg.version) ? pkg.version : null;
        const findings = Array.isArray(pkg.vulnerabilities) ? pkg.vulnerabilities : [];
        const row = document.createElement('tr');
        row.setAttribute('data-student-package-name', name);
        row.setAttribute('data-student-package-version', version ?? '');
        addText(row, 'td', name);
        addText(row, 'td', version ?? '정확한 설치 버전 확인 불가');
        const packageStates = {
          known_vulnerabilities: '알려진 취약점 항목 있음 (known_vulnerabilities)',
          none_found: '조회 범위에서 알려진 항목 없음 (none_found) · 안전 보장은 아님',
          unverifiable: findings.length > 0
            ? '일부 확인·전체 조회 확인 불가 (unverifiable)'
            : '조회 확인 불가 (unverifiable) · 취약점 없음이 아님',
        };
        addText(row, 'td', packageStates[pkg.status] ?? '패키지 조회 상태 확인 불가');
        addText(row, 'td', typeof pkg.source === 'string' ? pkg.source : '출처 확인 불가');
        addText(row, 'td', typeof pkg.checkedAt === 'string' ? pkg.checkedAt : '조회 시각 확인 불가');
        const details = document.createElement('td');
        if (findings.length > 0) {
          const list = document.createElement('ul');
          for (const finding of findings) {
            addText(list, 'li', `ID: ${finding?.id ?? '확인 불가'} · modified (수정 시각): ${finding?.modified ?? '확인 불가'}`);
          }
          details.appendChild(list);
        } else if (pkg.status === 'none_found') {
          addText(details, 'span', '조회 범위에서 알려진 항목 없음 · 패키지의 안전을 보장하지 않습니다.');
        } else {
          addText(details, 'span', '확인된 취약점 ID 없음 · 조회 완료 또는 취약점 없음으로 간주하지 않습니다.');
        }
        row.appendChild(details);
        tbody.appendChild(row);
      }
      table.appendChild(tbody);
      root.appendChild(table);
      addText(root, 'p', 'OSV는 알려진 취약점 정보입니다. 조회 결과가 없다는 사실만으로 패키지 또는 앱 전체가 안전하다고 보장할 수 없습니다.');
      return root;
    },
    renderAiConnection({ status, mode, data, error, checkedAt, explanationAccepted }) {
      const root = document.createElement('div');
      const addText = (value) => {
        const paragraph = document.createElement('p');
        paragraph.textContent = value;
        root.appendChild(paragraph);
      };
      const modes = {
        connected: '연결 자료',
        demo: '예제 자료 · 실제 앱 권한 확인이 아닙니다.',
        disconnected: '연결 없음',
        unknown: '연결 상태 확인 불가',
      };
      if (mode === 'demo' || mode === 'disconnected' || mode === 'unknown') {
        addText('데이터 모드: ' + modes[mode]);
      }
      if (status === 'idle') {
        addText('AI 연결 점검 전 · 이전 점검 결과는 현재 결과가 아닙니다.');
        addText('계정 연결 및 앱 승인을 확인한 뒤 「현재 API 연결 점검」을 직접 누르세요.');
        return root;
      }
      if (status === 'loading') {
        addText('AI 연결 점검 중 · 현재 앱 권한과 모델 목록 응답을 확인하고 있습니다.');
        addText('결과가 확인되기 전에는 연결 성공이나 사건 설명 성공으로 간주하지 않습니다.');
        return root;
      }
      if (status === 'ok') {
        if (data?.transportChecked !== true
          || !['test', 'verified'].includes(data.audienceAuthorization)
          || !Number.isInteger(data.modelCount) || data.modelCount < 0
          || typeof checkedAt !== 'string' || !Number.isFinite(Date.parse(checkedAt))) {
          addText('AI 연결 점검 결과를 확인할 수 없습니다. 연결 성공으로 간주하지 않습니다.');
          return root;
        }
        addText(data.audienceAuthorization === 'test'
          ? '시험 연결 점검(test) · 실제 앱 이용 권한은 아직 확인되지 않았습니다.'
          : '앱 권한 확인 후 점검(verified) · 점검 시각 기준의 결과입니다.');
        addText('modelCount (응답 모델 수): ' + data.modelCount);
        addText('checkedAt (점검 시각): ' + checkedAt);
        addText('모델 목록 응답만 점검했습니다. 사건 설명은 아직 실행하지 않았습니다.');
        return root;
      }
      if (status === 'error') {
        const guidance = {
          ON_AI_PROVISIONING_PENDING: '계정 연결 또는 앱 이용 권한을 준비 중입니다. 담당자에게 현재 권한을 확인하세요.',
          ON_AI_AUTHORIZATION_CHANGED: '점검 도중 이용 권한이 변경됐습니다. 담당자에게 현재 권한을 확인하세요.',
          SUBJECT_SCOPE_UNVERIFIED: '현재 계정과 프로젝트 연결을 확인할 수 없습니다. 담당자에게 확인하세요.',
          WB_CLCO_AUTH_REQUIRED: 'AI 인증을 확인하지 못했습니다. 계정 연결과 앱 승인을 다시 확인하고 담당자에게 문의하세요.',
          WB_CLCO_ACCESS_BLOCKED: '앱의 AI 접근이 제한됐습니다. 담당자에게 이용 권한을 확인하세요.',
          WB_CLCO_COHORT_BUDGET_EXHAUSTED: '반의 AI 사용량이 소진됐습니다. 담당자에게 확인하세요.',
          WB_CLCO_LIMIT_REACHED: 'AI 이용 한도에 도달했습니다. 담당자에게 확인하세요.',
          WB_CLCO_SESSION_CLOSED: '현재 AI 이용 시간이 아닙니다. 허용 시간을 확인하세요.',
          WB_CLCO_RATE_LIMITED: 'AI 요청이 일시 제한됐습니다. 잠시 후 직접 다시 점검하세요.',
          WB_CLCO_SERVER_UNAVAILABLE: 'AI 서비스가 응답하지 않습니다. 잠시 후 직접 다시 점검하세요.',
          WB_CLCO_NETWORK_ERROR: 'AI 서버 네트워크 연결을 확인하세요. 잠시 후 직접 다시 점검하세요.',
          WB_CLCO_TIMEOUT: 'AI 응답 시간이 초과됐습니다. 잠시 후 직접 다시 점검하세요.',
          REQUEST_TIMEOUT: '요청 처리 시간이 초과됐습니다. 잠시 후 직접 다시 점검하세요.',
          ENGINE_TIMEOUT: '서버 확인 시간이 초과됐습니다. 잠시 후 직접 다시 점검하세요.',
          TIMEOUT: 'AI 응답 시간이 초과됐습니다. 잠시 후 직접 다시 점검하세요.',
          WB_CLCO_CANCELLED: 'AI 연결 점검이 취소됐습니다. 이전 결과는 현재 결과가 아닙니다.',
          REQUEST_CANCELLED: 'AI 연결 점검이 취소됐습니다. 이전 결과는 현재 결과가 아닙니다.',
          CANCELLED: 'AI 연결 점검이 취소됐습니다. 이전 결과는 현재 결과가 아닙니다.',
          ON_AI_MODEL_LIST_EMPTY: '현재 앱 권한으로 사용할 수 있는 모델이 없습니다. 담당자에게 모델 허용 설정을 확인하세요.',
          MODEL_NOT_CONFIGURED: '허용된 AI 모델이 설정되지 않았습니다. 담당자에게 확인하세요.',
          AI_REQUEST_UNVERIFIED: 'AI 연결 또는 점검 결과를 확인할 수 없습니다. 담당자에게 계정·앱 권한을 확인하세요.',
        };
        const code = typeof error?.code === 'string' && Object.hasOwn(guidance, error.code)
          ? error.code : 'AI_REQUEST_UNVERIFIED';
        const secretPattern = /(?:Bearer\s+\S+|sk-(?:proj-|ant-|svcacct-)?[A-Za-z0-9_-]{8,}|-----BEGIN [A-Z ]*PRIVATE KEY-----|(?:api[_ -]?key|authorization|password|비밀번호|토큰)\s*[:=]\s*\S+)/i;
        const message = code === error?.code && typeof error?.message === 'string'
          && error.message.length > 0 && error.message.length <= 500
          && !secretPattern.test(error.message) && !/[\u0000-\u001f\u007f]/.test(error.message)
          ? error.message : '안전하게 표시할 수 있는 오류 메시지가 없습니다.';
        addText('AI 연결 점검 실패 · 오류 코드: ' + code);
        addText('오류 메시지: ' + message);
        addText('조치 안내: ' + guidance[code]);
        addText('자동으로 재점검하지 않습니다. 사용자가 「현재 API 연결 점검」 또는 「AI 연결 점검」을 직접 누르세요.');
        return root;
      }
      addText('AI 연결 점검 상태를 확인할 수 없습니다. 연결 성공으로 간주하지 않습니다.');
      return root;
    },
    renderExplanation({ event, explanation, checkedAt }) {
      const root = document.createElement('div');
      const addText = (tag, value, parent = root) => {
        const node = document.createElement(tag);
        node.textContent = value;
        parent.appendChild(node);
        return node;
      };
      const safeCodes = [
        'ON_AI_PROVISIONING_PENDING', 'WB_CLCO_AUTH_REQUIRED', 'WB_CLCO_ACCESS_BLOCKED',
        'WB_CLCO_COHORT_BUDGET_EXHAUSTED', 'WB_CLCO_LIMIT_REACHED',
        'WB_CLCO_SESSION_CLOSED', 'WB_CLCO_RATE_LIMITED', 'WB_CLCO_SERVER_UNAVAILABLE',
        'WB_CLCO_NETWORK_ERROR', 'WB_CLCO_TIMEOUT', 'REQUEST_TIMEOUT', 'ENGINE_TIMEOUT',
        'TIMEOUT', 'WB_CLCO_CANCELLED', 'REQUEST_CANCELLED', 'CANCELLED',
        'ON_AI_INVALID_INPUT', 'ON_AI_INVALID_OUTPUT', 'ON_AI_AUTHORIZATION_CHANGED',
        'SUBJECT_SCOPE_UNVERIFIED', 'AI_REQUEST_UNVERIFIED', 'ON_AI_MODEL_LIST_EMPTY',
        'MODEL_NOT_CONFIGURED',
      ];
      const secretPattern = /(?:Bearer\s+\S+|sk-(?:proj-|ant-|svcacct-)?[A-Za-z0-9_-]{8,}|-----BEGIN [A-Z ]*PRIVATE KEY-----|(?:api[_ -]?key|authorization|password|비밀번호|토큰)\s*[:=]\s*\S+)/i;
      const safeText = (value, max) => typeof value === 'string' && value.trim().length > 0
        && value.length <= max && !secretPattern.test(value)
        && !/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/.test(value);
      const validId = (value) => typeof value === 'string'
        && /^[A-Za-z0-9][A-Za-z0-9._:-]{0,79}$/.test(value);
      const invalid = (reason) => {
        addText('p', 'AI 사건 설명 사용 불가: ' + reason);
        addText('p', '검증되지 않은 AI 설명은 표시하지 않습니다. 기존 보안 기록과 접속 판정은 그대로 유지됩니다.');
        return root;
      };
    
      if (!event) {
        addText('p', '보안 기록에서 설명할 기록을 먼저 선택하세요.');
        return root;
      }
      if (explanation?.status === 'error') {
        const code = safeCodes.includes(explanation.error?.code)
          ? explanation.error.code : 'AI_REQUEST_UNVERIFIED';
        const message = code === explanation.error?.code && safeText(explanation.error?.message, 500)
          ? explanation.error.message : '안전하게 표시할 수 있는 오류 메시지가 없습니다.';
        addText('p', 'AI 사건 설명 실패 · 오류 코드: ' + code);
        addText('p', '오류 메시지: ' + message);
        if (code === 'ON_AI_INVALID_INPUT') {
          addText('p', '사건의 근거·규칙 또는 입력이 부족해 설명을 생성할 수 없습니다.');
        } else if (code === 'ON_AI_INVALID_OUTPUT') {
          addText('p', 'AI 설명의 근거·응답 형식·조치 미실행 여부를 확인할 수 없습니다. 이미 실행했다고 표시한 설명도 사용할 수 없습니다.');
        }
        addText('p', '기존 보안 기록과 업무 앱 판정은 그대로 유지됩니다. AI 설명 실패가 과제 실패를 뜻하지는 않습니다.');
        return root;
      }
    
      if (!explanation || explanation.status === 'idle') {
        addText('p', 'AI 사건 설명 요청 전입니다. AI 연결 점검만으로 사건 설명이 생성되지는 않습니다.');
        return root;
      }
      if (explanation.status === 'loading') {
        addText('p', '선택한 사건의 AI 설명 요청 중입니다. 아직 설명 결과나 조치 실행을 확인하지 않았습니다.');
        return root;
      }
      if (explanation.status !== 'ok') {
        return invalid('AI 설명 상태를 확인할 수 없습니다.');
      }
    
      const data = explanation.data;
      if (!validId(event.id) || !Array.isArray(event.evidence) || event.evidence.length === 0
          || !Array.isArray(event.rules) || event.rules.length === 0
          || !event.state || typeof event.state !== 'object'
          || !Array.isArray(event.supportedActions)) {
        return invalid('현재 사건의 ID, 근거, 규칙 또는 상태 정보가 부족합니다.');
      }
      const validRows = (rows) => rows.every(row => row && validId(row.id)
        && safeText(row.text, 2000));
      if (!validRows(event.evidence) || !validRows(event.rules)
          || new Set(event.evidence.map(row => row.id)).size !== event.evidence.length
          || !event.supportedActions.every(validId)) {
        return invalid('현재 사건의 근거·규칙 또는 지원 조치 정보를 확인할 수 없습니다.');
      }
      if (!data || !safeText(data.summary, 1500) || !Array.isArray(data.evidenceIds)
          || !Array.isArray(data.proposals)) {
        return invalid('AI 설명 요약 또는 인용 근거의 형식을 확인할 수 없습니다.');
      }
      if (data.executed !== false || data.requiresHumanConfirmation !== true) {
        return invalid('AI가 조치를 이미 실행했다고 표시했거나 사람 확인·미실행 조건이 충족되지 않았습니다.');
      }
    
      const evidenceById = new Map(event.evidence.map(row => [row.id, row.text]));
      if (data.evidenceIds.length !== evidenceById.size
          || new Set(data.evidenceIds).size !== data.evidenceIds.length
          || !data.evidenceIds.every(id => validId(id) && evidenceById.has(id))) {
        return invalid('인용한 근거 ID가 현재 사건의 근거와 일치하지 않습니다. 없는 근거를 만들어 보충하지 않습니다.');
      }
      if (!data.proposals.every(proposal => proposal && validId(proposal.action)
          && event.supportedActions.includes(proposal.action)
          && safeText(proposal.reason, 500)
          && Array.isArray(proposal.evidenceIds) && proposal.evidenceIds.length > 0
          && new Set(proposal.evidenceIds).size === proposal.evidenceIds.length
          && proposal.evidenceIds.every(id => validId(id) && evidenceById.has(id)))) {
        return invalid('AI 조치 제안의 지원 여부나 인용 근거가 현재 사건과 일치하지 않습니다.');
      }
    
      // Only attach the success marker after every binding and safety check passed.
      root.setAttribute('data-student-explanation-event', event.id);
      addText('h3', 'AI 설명(참고용)');
      addText('p', '사건 ID: ' + event.id);
      addText('p', 'AI 요약: ' + data.summary);
      addText('h4', '인용한 사건 근거');
      const evidenceList = document.createElement('ul');
      for (const id of data.evidenceIds) {
        addText('li', id + ' — ' + evidenceById.get(id), evidenceList);
      }
      root.appendChild(evidenceList);
    
      addText('h4', '사건에 적용된 규칙');
      const ruleList = document.createElement('ul');
      for (const rule of event.rules) {
        addText('li', rule.id + ' — ' + rule.text, ruleList);
      }
      root.appendChild(ruleList);
    
      addText('h4', '현재 사건 상태');
      const states = [
        ['접속', 'access', { allowed: '접근 허용', denied: '접근 거부', unknown: '확인 불가' }],
        ['세션', 'session', { active: '활성', expired: '만료', revoked: '철회됨', unknown: '확인 불가' }],
        ['기기', 'device', { compliant: '보안 기준 충족', noncompliant: '보안 기준 미충족', unknown: '확인 불가' }],
      ];
      const unknownStates = [];
      for (const [label, key, labels] of states) {
        const value = event.state[key];
        const known = typeof value === 'string' && Object.hasOwn(labels, value);
        const display = known ? value : 'unknown';
        addText('p', label + ': ' + labels[display] + '(' + display + ')');
        if (display === 'unknown') unknownStates.push(label);
      }
      addText('p', unknownStates.length
        ? '확인 불가 상태: ' + unknownStates.join(', ') + ' · 정상 또는 안전으로 판정하지 않습니다.'
        : '확인 불가 상태: 없음');
    
      addText('h4', 'AI 조치 제안');
      if (data.proposals.length === 0) {
        addText('p', event.supportedActions.length === 0
          ? '연동 시스템이 지원하는 조치가 없어 AI 제안이 없습니다(정상).'
          : 'AI가 제안한 조치가 없습니다. 조치가 실행되었다는 뜻은 아닙니다.');
      } else {
        const proposalsList = document.createElement('ul');
        for (const proposal of data.proposals) {
          addText('li', '조치: ' + proposal.action + ' · 이유: ' + proposal.reason
            + ' · 인용 근거 ID: ' + proposal.evidenceIds.join(', ')
            + ' · 사람 확인이 필요하며 실행되지 않았습니다.', proposalsList);
        }
        root.appendChild(proposalsList);
      }
      addText('p', 'AI 설명은 참고용 해석입니다. 사실 판단은 사건 근거·규칙·연동 시스템 상태를 기준으로 하며, 어떤 보안 조치도 실행하지 않았습니다.');
      return root;
    },
    renderAction({
      status = 'idle', event = null, actionId = null, target = null,
      receipt = null, observation = null, message = null,
      confirmationExpiresAt = null, error = null,
    } = {}) {
      // Every call creates a new DOM tree; no previous action, request or result is retained.
      const root = document.createElement('div');
      const addText = (tag, value) => {
        const element = document.createElement(tag);
        element.textContent = value;
        root.appendChild(element);
        return element;
      };
      const secretPattern = /(?:Bearer\s+\S+|sk-(?:proj-|ant-|svcacct-)?[A-Za-z0-9_-]{8,}|-----BEGIN [A-Z ]*PRIVATE KEY-----|(?:api[_ -]?key|authorization|password|비밀번호|토큰)\s*[:=]\s*\S+)/i;
      const safeValue = (value) => {
        if (typeof value !== 'string' && typeof value !== 'number') return '';
        const text = String(value).trim();
        return text && text.length <= 500 && !secretPattern.test(text) ? text : '';
      };
      const eventId = safeValue(event?.id);
      const currentActionId = safeValue(actionId);
      const requestId = safeValue(receipt?.requestId);
      const receiptId = safeValue(receipt?.receiptId);
      const observedAt = safeValue(observation?.observedAt);
      const receiptEventId = safeValue(receipt?.eventId);
      const receiptActionId = safeValue(receipt?.actionId);
      const mismatchedReceipt = (eventId && receiptEventId && eventId !== receiptEventId)
        || (currentActionId && receiptActionId && currentActionId !== receiptActionId);
      const effectConfirmed = status === 'succeeded' && observation?.effectApplied === true
        && Boolean(observedAt) && Boolean(receiptId) && !mismatchedReceipt;

      if (eventId) root.setAttribute('data-student-action-event', eventId);
      if (requestId) root.setAttribute('data-student-action-request', requestId);
      addText('h3', '보안 조치 요청 상태와 실제 결과');
      const descriptions = {
        idle: '아직 미실행(idle). AI 제안은 실제 보안 조치 집행이 아닙니다.',
        loading: '조치 준비 또는 연동 시스템 결과 조회 중(loading). 집행 효과는 아직 확인되지 않았습니다.',
        prepared: '준비됨·미실행(prepared). 실제 대상과 확인 기한을 확인한 뒤 별도의 사람 확인이 필요합니다.',
        executing: '사람 확인 후 서버에 전달 중(executing). 처리 결과나 실제 효과는 아직 확인되지 않았습니다.',
        pending: '서버 접수·처리 중(pending). 접수 응답(ACK)은 집행 성공이나 효과 확인이 아닙니다.',
        denied: '연동 시스템이 조치를 거절했습니다(denied). 효과 확인 상태가 아닙니다.',
        failed: '연동 시스템의 조치 처리가 실패했습니다(failed). 효과가 확인되지 않았습니다.',
        unknown: '결과 불명(unknown). 성공 또는 효과 없음으로 판단하지 마세요. 제공 화면의 「원천 결과만 재조회」로 결과만 확인하고 재집행하지 마세요.',
        expired: '사람 확인 기한이 지났습니다(expired). 기존 준비로 집행하지 말고 다시 준비하여 대상과 조치를 확인하세요.',
        error: '조치 요청이 처리되지 않았습니다(error). 오류 내용을 확인하세요.',
      };
      if (status === 'succeeded') {
        addText('p', effectConfirmed
          ? '연동 시스템의 실제 효과 확인(succeeded). 관측 결과에 따라 효과가 적용되었습니다.'
          : '상태값: succeeded · 결과 불명(unknown). 효과 관측과 요청 근거를 확인할 수 없어 성공이나 효과 없음으로 판단하지 마세요. 제공 화면의 「원천 결과만 재조회」로 결과만 확인하세요.');
      } else {
        addText('p', Object.hasOwn(descriptions, status)
          ? descriptions[status] : '조치 상태 확인 불가. 성공 또는 효과 없음으로 판단하지 마세요.');
      }

      if (eventId) addText('p', '현재 사건 ID: ' + eventId);
      if (Array.isArray(event?.evidence)) {
        const evidenceIds = event.evidence.map((item) => safeValue(item?.id)).filter(Boolean);
        if (evidenceIds.length) addText('p', '현재 사건 근거 ID: ' + evidenceIds.join(', '));
      }
      if (currentActionId) addText('p', '조치 ID: ' + currentActionId);
      const targetId = safeValue(target?.id);
      const targetGeneration = safeValue(target?.generation);
      if (targetId) addText('p', '실제 대상 ID: ' + targetId);
      if (targetGeneration) addText('p', '대상 세대(generation): ' + targetGeneration);
      if (confirmationExpiresAt && safeValue(confirmationExpiresAt)) {
        addText('p', '사람 확인 기한(confirmationExpiresAt): ' + safeValue(confirmationExpiresAt));
      }
      if (requestId) addText('p', '서버 요청 ID(requestId): ' + requestId);
      if (receiptId) addText('p', '서버 접수 기록 ID(receiptId): ' + receiptId);
      const receiptVersion = safeValue(receipt?.version);
      if (receiptVersion) addText('p', '접수 기록 버전(version): ' + receiptVersion);
      if (receiptEventId) addText('p', '접수 기록 사건 ID(eventId): ' + receiptEventId);
      if (receiptActionId) addText('p', '접수 기록 조치 ID(actionId): ' + receiptActionId);
      if (typeof receipt?.replayed === 'boolean') {
        addText('p', '기존 요청 응답 재사용(replayed): ' + String(receipt.replayed)
          + (receipt.replayed ? ' · 중복 응답은 새로운 조치 집행이나 효과 확인의 증거가 아닙니다.' : ' · 이 값만으로 실제 효과를 판단하지 않습니다.'));
      }
      if (receipt?.superseded === true) {
        addText('p', '이전 조회 결과는 최신 처리 상태를 대신하지 않습니다(superseded). 결과만 재조회하세요.');
      }
      if (mismatchedReceipt) {
        addText('p', '현재 사건·조치 ID와 접수 기록의 ID가 일치하지 않습니다. 결과 확인 불가이며, 다른 조치의 결과를 현재 조치 성공으로 간주하지 않습니다.');
      }
      if (effectConfirmed) {
        addText('p', '연동 시스템 관측 시각(observedAt): ' + observedAt);
        addText('p', '연동 시스템 실제 효과(effectApplied): true');
        addText('p', '효과를 확인한 접수 기록(receiptId): ' + receiptId);
      }
      if (['denied', 'failed', 'error', 'expired', 'idle', 'loading'].includes(status)) {
        const safeMessage = safeValue(message);
        if (safeMessage) addText('p', '상태 안내: ' + safeMessage);
      }
      if (status === 'error' || status === 'expired') {
        const errorCode = typeof error?.code === 'string' && /^[A-Z][A-Z0-9_]{0,79}$/.test(error.code)
          ? error.code : '';
        const errorMessage = safeValue(error?.message);
        if (errorCode) addText('p', '오류 코드: ' + errorCode);
        if (errorMessage) addText('p', '오류 메시지: ' + errorMessage);
      }
      if (status === 'prepared') {
        addText('p', '조치 준비만으로는 집행되지 않습니다. 제공 화면의 「대상과 조치를 확인했으며 집행합니다」를 누르기 전 실제 대상과 기한을 확인해야 합니다.');
      }
      if (status === 'idle' && !eventId || Array.isArray(event?.supportedActions) && event.supportedActions.length === 0) {
        addText('p', '현재 제공된 기록에는 연동 시스템이 지원하는 조치가 없어 「조치 준비」 버튼이 나오지 않는 것이 정상입니다.');
      }
      addText('p', '보안 조치는 제공 화면에서만 준비·사람 확인·전달·결과 재조회합니다. 학생 화면은 집행 요청이나 확인 티켓을 만들지 않습니다. 「조치 화면 취소」는 이미 서버에 전달된 조치의 효과를 되돌리지 않습니다.');
      return root;
    },
  };
}

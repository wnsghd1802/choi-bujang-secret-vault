// 2일차 추가 UI. 기존 공통 UI/학생 렌더러와 별도로, 실제 응답만 표시한다.
const button = document.getElementById('pc-status-measure');
const message = document.getElementById('pc-status-message');
const names = {cpu: 'CPU 사용률', memory: '메모리 사용량', disk: '디스크 남은 공간'};
const reasons = {
  CPU_TIMES_UNAVAILABLE: '운영체제가 CPU 시간 정보를 제공하지 않았습니다.',
  CPU_SAMPLING_UNAVAILABLE: 'CPU 측정 구간을 완료하지 못했습니다.',
  CPU_INTERVAL_UNVERIFIABLE: 'CPU 시간 차이를 검증할 수 없습니다.',
  MEMORY_READING_UNVERIFIABLE: '메모리 전체·여유 값의 일관성을 확인할 수 없습니다.',
  MEMORY_READING_UNAVAILABLE: '운영체제 메모리 정보를 읽지 못했습니다.',
  DISK_READING_UNVERIFIABLE: '앱이 있는 볼륨의 남은 공간을 검증할 수 없습니다.',
  DISK_READING_UNAVAILABLE: '앱이 있는 볼륨의 파일시스템 정보를 읽지 못했습니다.',
};
const keys = Object.keys(names);
const metricNode = (key, field) => document.getElementById(`pc-status-${key}-${field}`);
let previous = null;
let running = false;

function parseMetric(metric, key) {
  if (!metric || typeof metric !== 'object' || typeof metric.measuredAt !== 'string' ||
      !/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/.test(metric.measuredAt) ||
      !Number.isFinite(Date.parse(metric.measuredAt))) return null;
  if (metric.status === 'unavailable' && Object.hasOwn(reasons, metric.reason)) return metric;
  if (metric.status !== 'ok' || !Number.isFinite(metric.value) || metric.value < 0 ||
      metric.unit !== (key === 'cpu' ? '%' : 'GiB')) return null;
  if (key === 'cpu' && (metric.value > 100 || !Number.isInteger(metric.intervalMs) || metric.intervalMs < 100)) return null;
  if (key !== 'cpu' && (!Number.isFinite(metric.totalGiB) || metric.totalGiB < metric.value || metric.totalGiB <= 0)) return null;
  return metric;
}
function fmtTime(date) {
  return new Date(date).toLocaleString('ko-KR', {year: 'numeric', month: '2-digit', day: '2-digit',
    hour: '2-digit', minute: '2-digit', second: '2-digit', timeZoneName: 'short'});
}
function showUnavailable(key, reason, date = null) {
  metricNode(key, 'value').textContent = `확인 불가 — ${reason}`;
  metricNode(key, 'time').textContent = date ? `측정 시각: ${fmtTime(date)}` : '측정 시각: 확인 불가';
  metricNode(key, 'compare').textContent = '직전 측정 비교: 확인 불가';
}
function paint(data) {
  if (data?.schema !== 'kimjh.pc-status.v1' || data?.source !== 'local-node-os' ||
      !data.metrics || typeof data.metrics !== 'object') {
    throw Error('SCHEMA_UNVERIFIED');
  }
  const current = {};
  for (const key of keys) {
    const metric = parseMetric(data.metrics[key], key);
    if (!metric) {
      showUnavailable(key, '서버 응답 형식을 확인할 수 없습니다.');
      current[key] = null;
      continue;
    }
    current[key] = metric;
    if (metric.status === 'unavailable') {
      showUnavailable(key, reasons[metric.reason], metric.measuredAt);
      continue;
    }
    const note = key === 'memory' ? ` / 전체 ${metric.totalGiB.toFixed(1)} GiB` :
      key === 'disk' ? ` / 볼륨 전체 ${metric.totalGiB.toFixed(1)} GiB` : ` (${metric.intervalMs} ms 구간 평균)`;
    metricNode(key, 'value').textContent = `${metric.value.toFixed(1)} ${metric.unit}${note} · 실제 측정`;
    metricNode(key, 'time').textContent = `측정 시각: ${fmtTime(metric.measuredAt)}`;
    const old = previous?.[key];
    if (old?.status !== 'ok') {
      metricNode(key, 'compare').textContent = '직전 측정 비교: 비교할 실제 값 없음';
      continue;
    }
    const delta = metric.value - old.value;
    const change = Math.abs(delta) < 0.05 ? '변화 없음' : `${delta > 0 ? '+' : '−'}${Math.abs(delta).toFixed(1)} ${metric.unit}`;
    metricNode(key, 'compare').textContent = `직전 측정 대비: ${change} · 이전 ${fmtTime(old.measuredAt)}`;
  }
  previous = current;
}
if (button && message && keys.every(key => ['value', 'time', 'compare'].every(field => metricNode(key, field)))) {
  button.addEventListener('click', async () => {
    if (running) return;
    running = true;
    button.disabled = true;
    message.textContent = '로컬 PC 자원 측정 중 · 자동 재시도하지 않습니다.';
    const controller = new AbortController();
    const deadline = setTimeout(() => controller.abort(), 8000);
    try {
      const response = await fetch('/api/pc-status', {method: 'GET', credentials: 'same-origin', cache: 'no-store', signal: controller.signal});
      if (!response.ok) throw Error('HTTP_ERROR');
      const result = await response.json();
      if (result?.ok !== true) throw Error('API_ERROR');
      paint(result.data);
      message.textContent = 'PC에서 직접 측정한 결과입니다. 예시값이나 기존 SDP 기기 상태가 아닙니다.';
    } catch {
      for (const key of keys) showUnavailable(key, '로컬 서버 측정 결과를 읽지 못했습니다. 연결 상태를 확인한 뒤 직접 다시 측정하세요.');
      previous = null;
      message.textContent = '측정 실패 · 확인 불가. 이전 결과는 현재 측정값으로 표시하지 않습니다.';
    } finally {
      clearTimeout(deadline);
      running = false;
      button.disabled = false;
    }
  });
}

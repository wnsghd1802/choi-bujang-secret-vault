// KimJH 총공세 3일차 — Windows 네트워크/방화벽/기록의 읽기 전용 로컬 관측.
// 외부에서 온 stderr, 운영체제 예외 본문, 경로, 이벤트 본문은 브라우저로 반환하지 않는다.
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {fileURLToPath} from 'node:url';
import {isIP} from 'node:net';

const execFileAsync = promisify(execFile);
const scriptPath = fileURLToPath(new URL('../tools/read-windows-observation.ps1', import.meta.url));
const reasons = new Set([
  'WINDOWS_ONLY', 'POWERSHELL_UNAVAILABLE', 'READ_TIMED_OUT', 'READ_RESULT_UNVERIFIED',
  'NETWORK_QUERY_UNAVAILABLE', 'NETWORK_NO_IPV4',
  'FIREWALL_QUERY_UNAVAILABLE', 'FIREWALL_PROFILES_UNAVAILABLE',
  'EVENT_LOG_UNAVAILABLE',
]);
const at = value => typeof value === 'string' && /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/.test(value)
  && Number.isFinite(Date.parse(value)) ? value : null;
const shortText = value => typeof value === 'string' && value.trim().length > 0 &&
  value.length <= 90 && !/[\u0000-\u001f\u007f]/.test(value);
const unavailable = (reason, measuredAt) => ({status:'unavailable',reason,observedAt:measuredAt});
function fallback(reason, measuredAt) {
  return {schema:'kimjh.windows-observation.v1',source:'windows-read-only',windowHours:24,
    network:unavailable(reason,measuredAt),firewall:unavailable(reason,measuredAt),
    system:unavailable(reason,measuredAt),application:unavailable(reason,measuredAt)};
}
function normalizeOne(input, kind, fallbackTime) {
  const validatedTime = at(input?.observedAt);
  const time = validatedTime || fallbackTime;
  if (input?.status === 'ok' && !validatedTime) return unavailable('READ_RESULT_UNVERIFIED',fallbackTime);
  if (input?.status === 'unavailable') {
    return unavailable(reasons.has(input.reason) ? input.reason : 'READ_RESULT_UNVERIFIED',time);
  }
  if (input?.status !== 'ok') return unavailable('READ_RESULT_UNVERIFIED',time);
  if (kind === 'network') {
    if (!Array.isArray(input.adapters) || input.adapters.length < 1 || input.adapters.length > 8) {
      return unavailable('READ_RESULT_UNVERIFIED',time);
    }
    const adapters = input.adapters.map(item => {
      if (!shortText(item?.name) || typeof item.ipv4 !== 'string' || isIP(item.ipv4) !== 4 ||
        typeof item.gateway !== 'string' || (item.gateway !== '' && isIP(item.gateway) !== 4)) return null;
      return {name:item.name,ipv4:item.ipv4,gateway:item.gateway};
    });
    return adapters.includes(null) ? unavailable('READ_RESULT_UNVERIFIED',time)
      : {status:'ok',adapters,observedAt:time};
  }
  if (kind === 'firewall') {
    if (!Array.isArray(input.profiles) || input.profiles.length < 1 || input.profiles.length > 3) {
      return unavailable('READ_RESULT_UNVERIFIED',time);
    }
    const allowed = new Set(['Domain','Private','Public']);
    const modes = new Set(['Allow','Block','NotConfigured']);
    const seen = new Set(), profiles = [];
    for (const item of input.profiles) {
      if (!allowed.has(item?.name) || seen.has(item.name) || typeof item.enabled !== 'boolean' ||
          !modes.has(item.inbound) || !modes.has(item.outbound)) {
        return unavailable('READ_RESULT_UNVERIFIED',time);
      }
      seen.add(item.name);
      profiles.push({name:item.name,enabled:item.enabled,inbound:item.inbound,outbound:item.outbound});
    }
    return {status:'ok',profiles,observedAt:time};
  }
  if (!Number.isSafeInteger(input.error) || input.error < 0 || input.error > 5000 ||
      !Number.isSafeInteger(input.warning) || input.warning < 0 ||
      input.warning > 5000 || input.error + input.warning > 5000 || typeof input.limited !== 'boolean') {
    return unavailable('READ_RESULT_UNVERIFIED',time);
  }
  return {status:'ok',error:input.error,warning:input.warning,limited:input.limited,observedAt:time};
}

export function normalizeWindowsObservation(raw, now = new Date().toISOString()) {
  const time = at(now) || new Date().toISOString();
  if (!raw || raw.schema !== 'kimjh.windows-observation.v1' ||
      raw.source !== 'windows-read-only' || raw.windowHours !== 24) {
    return fallback('READ_RESULT_UNVERIFIED',time);
  }
  return {schema:'kimjh.windows-observation.v1',source:'windows-read-only',windowHours:24,
    network:normalizeOne(raw.network,'network',time),
    firewall:normalizeOne(raw.firewall,'firewall',time),
    system:normalizeOne(raw.system,'system',time),
    application:normalizeOne(raw.application,'application',time)};
}

async function defaultRunner(signal) {
  return execFileAsync('powershell.exe',
    ['-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',scriptPath],
    {encoding:'utf8',windowsHide:true,timeout:12000,maxBuffer:65536,signal});
}

export function createWindowsObservationReader({
  platform=process.platform,run=defaultRunner,now=()=>new Date().toISOString(),
}={}) {
  return async function readWindowsObservation({signal}={}) {
    const timestamp = now();
    if (platform !== 'win32') return fallback('WINDOWS_ONLY',timestamp);
    try {
      const result = await run(signal);
      const text = result?.stdout;
      if (typeof text !== 'string' || text.length > 65536) return fallback('READ_RESULT_UNVERIFIED',timestamp);
      return normalizeWindowsObservation(JSON.parse(text.replace(/^\uFEFF/,'')),timestamp);
    } catch (error) {
      const reason = error?.killed || error?.code === 'ETIMEDOUT' || error?.name === 'AbortError'
        ? 'READ_TIMED_OUT' : 'POWERSHELL_UNAVAILABLE';
      return fallback(reason,timestamp);
    }
  };
}
export const readWindowsObservation = createWindowsObservationReader();

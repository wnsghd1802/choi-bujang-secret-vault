// KimJH 2일차: 앱이 실행 중인 PC에서 일반 사용자 권한으로 읽는 자원 통계.
// 측정 실패는 샘플 숫자나 0으로 바꾸지 않고 unavailable로 반환한다.
import {cpus, totalmem, freemem} from 'node:os';
import {statfs} from 'node:fs/promises';
import {setTimeout as sleep} from 'node:timers/promises';
import {fileURLToPath} from 'node:url';

const GIB = 1024 ** 3;
const APP_PATH = fileURLToPath(new URL('../', import.meta.url));
const roundOne = value => Math.round(value * 10) / 10;
const unavailable = (reason, at) => ({status: 'unavailable', reason, measuredAt: at});
const finiteNonnegative = value => Number.isFinite(value) && value >= 0;

function cpuTicks(cores) {
  if (!Array.isArray(cores) || cores.length === 0) return null;
  let total = 0, idle = 0;
  for (const core of cores) {
    if (!core || !core.times) return null;
    const times = core.times;
    const values = ['user', 'nice', 'sys', 'idle', 'irq'].map(key => times[key]);
    if (!values.every(finiteNonnegative)) return null;
    total += values.reduce((sum, value) => sum + value, 0);
    idle += times.idle;
  }
  return finiteNonnegative(total) && finiteNonnegative(idle) ? {total, idle, count: cores.length} : null;
}

export function createPcStatusReader({
  readCpus = cpus, readTotalMemory = totalmem, readFreeMemory = freemem,
  readFilesystem = statfs, wait = sleep, now = () => new Date().toISOString(),
  diskPath = APP_PATH, intervalMs = 650,
} = {}) {
  async function cpu(signal) {
    let first, second;
    try {
      first = cpuTicks(readCpus());
      if (!first) return unavailable('CPU_TIMES_UNAVAILABLE', now());
      await wait(intervalMs, undefined, {signal});
      second = cpuTicks(readCpus());
    } catch {
      return unavailable('CPU_SAMPLING_UNAVAILABLE', now());
    }
    if (!second || first.count !== second.count) return unavailable('CPU_TIMES_UNAVAILABLE', now());
    const totalDiff = second.total - first.total;
    const idleDiff = second.idle - first.idle;
    if (!(totalDiff > 0) || idleDiff < 0 || idleDiff > totalDiff) {
      return unavailable('CPU_INTERVAL_UNVERIFIABLE', now());
    }
    return {status: 'ok', value: roundOne(Math.max(0, Math.min(100, 100 * (1 - idleDiff / totalDiff)))),
      unit: '%', intervalMs, measuredAt: now()};
  }

  function memory() {
    try {
      const total = readTotalMemory(), free = readFreeMemory();
      if (!(total > 0) || !finiteNonnegative(free) || free > total) {
        return unavailable('MEMORY_READING_UNVERIFIABLE', now());
      }
      return {status: 'ok', value: roundOne((total - free) / GIB), unit: 'GiB',
        totalGiB: roundOne(total / GIB), measuredAt: now()};
    } catch {
      return unavailable('MEMORY_READING_UNAVAILABLE', now());
    }
  }

  async function disk() {
    try {
      const data = await readFilesystem(diskPath);
      const size = Number(data?.bsize), available = Number(data?.bavail), blocks = Number(data?.blocks);
      const availableBytes = size * available, totalBytes = size * blocks;
      if (!(size > 0) || !finiteNonnegative(available) || !finiteNonnegative(blocks) ||
        !Number.isSafeInteger(availableBytes) || !Number.isSafeInteger(totalBytes) ||
        availableBytes > totalBytes || totalBytes <= 0) {
        return unavailable('DISK_READING_UNVERIFIABLE', now());
      }
      return {status: 'ok', value: roundOne(availableBytes / GIB), unit: 'GiB',
        totalGiB: roundOne(totalBytes / GIB), measuredAt: now()};
    } catch {
      return unavailable('DISK_READING_UNAVAILABLE', now());
    }
  }

  return async function readPcStatus({signal} = {}) {
    const [cpuResult, memoryResult, diskResult] = await Promise.all([
      cpu(signal), Promise.resolve().then(memory), disk(),
    ]);
    return {schema: 'kimjh.pc-status.v1', source: 'local-node-os',
      metrics: {cpu: cpuResult, memory: memoryResult, disk: diskResult}};
  };
}

export const readPcStatus = createPcStatusReader();

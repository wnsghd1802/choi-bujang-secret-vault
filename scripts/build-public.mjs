import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { deploymentIdentity } from './deployment-identity.mjs';
import { build } from 'esbuild';

const root = resolve(import.meta.dirname, '..');
const output = resolve(root, 'public', 'data.json');
const config = JSON.parse(await readFile(resolve(root, 'aleph.config.json'), 'utf8'));
if (config.step !== 5) throw new Error('현재 빌드는 5단계 자료실용입니다.');
await mkdir(resolve(root, 'public'), { recursive: true });
await writeFile(output, '{"notes":[]}\n', 'utf8');
console.log('공개 data.json에는 메모를 포함하지 않습니다.');
await build({ entryPoints: [resolve(root, 'src/browser-app.js')],
  outfile: resolve(root, 'public/app.js'), bundle: true, minify: true,
  platform: 'browser', format: 'esm', target: ['es2022'], sourcemap: false,
});
if (!process.argv.includes('--local')) {
  const identity = deploymentIdentity(process.env, config);
  await writeFile(resolve(root, 'public', 'aleph.json'),
    `${JSON.stringify(identity, null, 2)}\n`, 'utf8');
  console.log('배포 저장소·커밋·주소를 public/aleph.json에 기록했습니다.');
}

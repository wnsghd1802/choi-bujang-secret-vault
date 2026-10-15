'use strict';

// Only enforce this policy inside the bundle Node process, not npm's own launcher.
// Self-test mode deliberately exercises forbidden operations without sending them.
const path = require('node:path');
const fs = require('node:fs');
const isBundle = /(?:^|[/\\])scripts[/\\]bundle\.mjs$/u.test(process.argv[1] || '');
if (isBundle || process.env.STAGE12_POLICY_SELF_TEST === '1') {
  const cp = require('node:child_process');
  const { syncBuiltinESMExports } = require('node:module');
  const root = path.resolve(__dirname, '../..');
  const config = JSON.parse(fs.readFileSync(path.join(root, 'aleph.config.json'), 'utf8'));
  const publicOrigin = new URL(config.publicAppUrl).origin;
  const observed = [];
  const reject = (reason) => { throw new Error('STAGE12_POLICY_REJECT: ' + reason); };

  // Trace the eager module import graph (lazy legacy checks are not part of stage 12).
  const seen = new Set();
  const traverse = (filename) => {
    if (seen.has(filename)) return;
    seen.add(filename);
    const source = fs.readFileSync(filename, 'utf8');
    const re = /^\s*import\s+(?:[^'"\n]+?\s+from\s+)?['"]([^'"\n]+)['"]/gmu;
    for (const match of source.matchAll(re)) {
      const specifier = match[1];
      if (specifier.startsWith('node:')) {
        if (!['node:fs', 'node:path', 'node:url', 'node:child_process', 'node:crypto'].includes(specifier)) {
          reject('forbidden built-in import: ' + specifier);
        }
      } else if (specifier.startsWith('.')) {
        const dependency = path.resolve(path.dirname(filename), specifier);
        if (!dependency.startsWith(root + path.sep)) reject('import escapes repository');
        traverse(dependency);
      } else {
        reject('third-party package import: ' + specifier);
      }
    }
  };
  traverse(path.join(root, 'scripts/bundle.mjs'));
  process.stderr.write('[STAGE12_POLICY] eager imports: ' +
    [...seen].map(p => path.relative(root, p)).join(', ') + '\n');

  const allowedGit = (args) => {
    if (!Array.isArray(args) || args.some(a => typeof a !== 'string')) return false;
    const [verb, ...rest] = args;
    if (verb === 'status') return rest.join(' ') === '--porcelain --untracked-files=all';
    if (verb === 'rev-parse') return rest.join(' ') === '--verify HEAD';
    if (verb === 'show') return rest.length === 1 && rest[0] === 'HEAD:aleph.config.json';
    if (verb === 'ls-tree') return rest.length === 3 && rest[0] === '-r' &&
      rest[1] === '-z' && /^[0-9a-f]{40}$/u.test(rest[2]);
    if (verb === 'diff') return rest.length === 4 && rest[0] === '--name-only' &&
      rest[1] === '--no-renames' && rest.slice(2).every(r => /^[0-9a-f]{40}$/u.test(r));
    return false;
  };

  const originalExecFileSync = cp.execFileSync;
  cp.execFileSync = function guardedExecFileSync(command, args, options) {
    if (command !== 'git' || !allowedGit(args)) reject('non-readonly git or external command');
    observed.push('git ' + args[0]);
    return originalExecFileSync.call(cp, command, args, options);
  };
  for (const method of ['exec', 'execSync', 'execFile', 'spawn', 'spawnSync', 'fork']) {
    cp[method] = () => reject('forbidden child_process.' + method);
  }
  syncBuiltinESMExports();

  const originalFetch = globalThis.fetch;
  globalThis.fetch = async function guardedFetch(input, init) {
    const u = new URL(typeof input === 'string' ? input : input.url || String(input));
    const method = String(init?.method || input?.method || 'GET').toUpperCase();
    if (u.protocol !== 'https:' || u.origin !== publicOrigin || !['GET', 'HEAD'].includes(method) ||
      u.username || u.password || init?.body || init?.headers || input?.headers?.has?.('authorization')) {
      reject('network request outside public HTTPS GET/HEAD');
    }
    observed.push('https ' + method + ' ' + u.pathname);
    return originalFetch.call(globalThis, input, init);
  };
  process.on('exit', () => {
    process.stderr.write('[STAGE12_POLICY] approved operations: ' + JSON.stringify(observed) + '\n');
  });
}

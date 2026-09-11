import { readFile, stat } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const packageFile = resolve(root, 'package.json');
const packageJson = JSON.parse(await readFile(packageFile, 'utf8'));
const checks = [];

async function exists(relativePath) {
  try {
    await stat(resolve(root, relativePath));
    return true;
  } catch {
    return false;
  }
}

function check(name, ok, detail) {
  checks.push({ name, ok: Boolean(ok), detail });
}

check('package-name', packageJson.name === 'securitycontext', packageJson.name);
check('module-type', packageJson.type === 'module', packageJson.type);
check('engines', packageJson.engines?.node === '>=22.22.3 <23 || >=24.11.1 <25', packageJson.engines?.node);
check('root-import-export', packageJson.exports?.['.']?.import === './src/index.mjs', packageJson.exports?.['.']);
check('register-export', packageJson.exports?.['./register'] === './src/register.mjs', packageJson.exports?.['./register']);
let rootLock;
let dependencyLock;
try {
  rootLock = JSON.parse(await readFile(resolve(root, 'package-lock.json'), 'utf8'));
} catch (error) {
  check('package-lock', false, error.code || error.message);
}
try {
  dependencyLock = JSON.parse(await readFile(resolve(root, 'data/dependency-lock.json'), 'utf8'));
} catch (error) {
  check('dependency-lock', false, error.code || error.message);
}
if (rootLock && dependencyLock) {
  check('dependency-lock-sync', JSON.stringify(rootLock) === JSON.stringify(dependencyLock), {
    root: { name: rootLock.name, lockfileVersion: rootLock.lockfileVersion, packages: Object.keys(rootLock.packages || {}).length },
    artifact: { name: dependencyLock.name, lockfileVersion: dependencyLock.lockfileVersion, packages: Object.keys(dependencyLock.packages || {}).length },
  });
}
try {
  const packagedCli = await readFile(resolve(root, 'data/securityctl.py'), 'utf8');
  let canonicalCli;
  try { canonicalCli = await readFile(resolve(root, '../scripts/securityctl.py'), 'utf8'); } catch { canonicalCli = null; }
  check('securityctl-present', packagedCli.startsWith('#!/usr/bin/env python3\n'), 'data/securityctl.py');
  if (canonicalCli !== null) check('securityctl-canonical-sync', packagedCli === canonicalCli, 'data/securityctl.py matches ../scripts/securityctl.py');
  const stdlib = new Set(['argparse', 'datetime', 'fcntl', 'json', 'os', 're', 'pathlib', 'sys', 'tempfile', 'time', 'uuid']);
  const imports = [...packagedCli.matchAll(/^(?:import|from)\s+([A-Za-z_][A-Za-z0-9_]*)/gm)].map((match) => match[1]);
  check('securityctl-python-dependencies', imports.every((name) => stdlib.has(name)), { imports, policy: 'python-standard-library-only' });
} catch (error) {
  check('securityctl-present', false, error.code || error.message);
}
for (const path of [
  'src/index.mjs', 'src/register.mjs', 'src/index.d.ts', 'src/bootstrap.mjs',
  'src/adapters/frameworks.mjs', 'src/adapters/sinks.mjs', 'src/adapters/models.mjs',
  'src/core/runtime.mjs', 'src/core/state.mjs', 'src/transform/index.mjs',
  'README.md', 'README.en.md', 'docs/verification.md', 'docs/compatibility.md',
  'docs/guide.zh-CN.md', 'docs/guide.en.md',
  'data/dependency-lock.json', 'data/securityctl.py', 'data/current-verification.json',
]) {
  check(`file:${path}`, await exists(path), path);
}
for (const path of ['src/index.mjs', 'src/register.mjs']) {
  if (await exists(path)) check(`published:${path}`, packageJson.files?.includes('src'), packageJson.files);
}

const result = {
  schemaVersion: 1,
  source: 'security_context',
  package: { name: packageJson.name, version: packageJson.version },
  checks,
  status: checks.every((entry) => entry.ok) ? 'ready' : 'blocked',
};
process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
if (result.status !== 'ready') process.exit(2);

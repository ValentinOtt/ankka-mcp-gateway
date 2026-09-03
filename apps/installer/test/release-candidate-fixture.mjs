import { execFileSync } from 'node:child_process';
import { chmod, mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

export const FIXTURE_PAYLOAD = Object.freeze({
  'payload/installer/assets/installer-4e5f6a7b.css': 'body{margin:0}',
  'payload/installer/index.html': '<main>installer</main>',
  'payload/worker-cleanup/index.js': 'export class AdminState {}\nexport default {};\n',
  'payload/worker-retirement/index.js': 'export default {};\n',
  'payload/worker/index.js': "const CONTROL_PLANE_ORIGIN = 'https://deploy.ankka.ai';\nexport class AdminState {}\nexport default { fetch() { return new Response(CONTROL_PLANE_ORIGIN); } };\n",
});

export const FIXTURE_ADMIN_OUTPUT = Object.freeze({
  'payload/admin/assets/admin-0a1b2c3d.js': 'admin();',
  'payload/admin/index.html': '<main>admin</main>',
  'payload/admin/LICENSE.txt': 'Synthetic Apache-2.0 project license fixture.\n',
  'payload/admin/THIRD_PARTY_LICENSES.txt': 'Synthetic third-party license fixture.\n',
});

export const FIXTURE_RELEASE_FILES = Object.freeze({
  ...FIXTURE_ADMIN_OUTPUT,
  ...FIXTURE_PAYLOAD,
});

export function fixtureGit(root, ...args) {
  return execFileSync('git', ['-C', root, ...args], {
    encoding: 'utf8',
    env: {
      PATH: process.env.PATH,
      HOME: process.env.HOME,
      GIT_CONFIG_NOSYSTEM: '1',
      GIT_AUTHOR_NAME: 'test',
      GIT_AUTHOR_EMAIL: 'test@example.invalid',
      GIT_COMMITTER_NAME: 'test',
      GIT_COMMITTER_EMAIL: 'test@example.invalid',
    },
  }).trim();
}

export async function releaseCandidateCheckout(files = FIXTURE_PAYLOAD) {
  const sandbox = await mkdtemp(path.join(os.tmpdir(), 'gateway-release-candidate-'));
  const source = path.join(sandbox, 'public');
  await mkdir(source);
  for (const [relative, contents] of Object.entries(files)) {
    const target = path.join(source, ...relative.split('/'));
    await mkdir(path.dirname(target), { recursive: true });
    await writeFile(target, contents);
  }
  for (const relative of [
    'apps/installer/scripts/build-gateway-release-candidate.mjs',
    'apps/installer/scripts/sign-gateway-release.mjs',
  ]) {
    const target = path.join(source, ...relative.split('/'));
    await mkdir(path.dirname(target), { recursive: true });
    await writeFile(
      target,
      await readFile(new URL(`../scripts/${path.basename(relative)}`, import.meta.url)),
    );
  }

  const installerRoot = path.join(source, 'apps', 'installer');
  const installerSourceRoot = path.join(installerRoot, 'src');
  await mkdir(installerSourceRoot, { recursive: true });
  await writeFile(path.join(installerRoot, 'package.json'), JSON.stringify({
    name: '@ankka/gateway-installer',
    private: true,
    type: 'module',
  }));
  await writeFile(path.join(installerRoot, 'tsconfig.json'), JSON.stringify({
    compilerOptions: { target: 'ES2022', module: 'ESNext' },
  }));
  await writeFile(path.join(installerSourceRoot, 'customer-gateway-entrypoint.ts'), `
    import runtime, { AdminState } from '../../../payload/worker/index.js';
    export { AdminState };
    export default runtime;
  `);
  await writeFile(path.join(installerSourceRoot, 'customer-gateway-bootstrap-entrypoint.ts'), `
    import { AdminState as RuntimeAdminState } from '../../../payload/worker/index.js';
    declare const __ANKKA_FINAL_RUNTIME_SOURCE__: string;
    export class AdminState extends RuntimeAdminState {}
    export default {
      fetch() {
        return new Response(String(__ANKKA_FINAL_RUNTIME_SOURCE__.length));
      },
    };
  `);

  const adminRoot = path.join(source, 'apps', 'admin');
  await mkdir(adminRoot, { recursive: true });
  await writeFile(path.join(source, 'package.json'), JSON.stringify({
    private: true,
    workspaces: ['apps/*'],
  }));
  await writeFile(path.join(adminRoot, 'package.json'), JSON.stringify({
    name: '@ankka/gateway-admin',
    private: true,
    type: 'module',
    scripts: { build: 'node build.mjs' },
  }));
  const adminFiles = Object.fromEntries(
    Object.entries(FIXTURE_ADMIN_OUTPUT)
      .map(([relative, contents]) => [relative.slice('payload/admin/'.length), contents]),
  );
  await writeFile(path.join(adminRoot, 'build.mjs'), `
    import { mkdir, rm, writeFile } from 'node:fs/promises';
    import path from 'node:path';
    const root = new URL('./dist/', import.meta.url);
    await rm(root, { recursive: true, force: true });
    for (const [relative, contents] of Object.entries(${JSON.stringify(adminFiles)})) {
      const target = path.join(root.pathname, ...relative.split('/'));
      await mkdir(path.dirname(target), { recursive: true });
      await writeFile(target, contents);
    }
  `);
  await writeFile(path.join(source, '.gitignore'), 'dist/\n');
  await writeFile(path.join(source, 'README.md'), 'public\n');
  fixtureGit(source, 'init', '-q');
  fixtureGit(source, 'add', '-A');
  fixtureGit(source, 'commit', '-q', '-m', 'release inputs');

  return {
    sandbox,
    source,
    commit: fixtureGit(source, 'rev-parse', 'HEAD'),
    output: path.join(sandbox, 'candidate'),
    async cleanup() {
      await chmod(sandbox, 0o700).catch(() => {});
      await rm(sandbox, { recursive: true, force: true });
    },
  };
}

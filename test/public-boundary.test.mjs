import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const checker = path.join(repositoryRoot, 'scripts', 'check-public-boundary.mjs');

test('public-boundary check covers publishable untracked files and force-tracked output', async () => {
  const fixture = await mkdtemp(path.join(os.tmpdir(), 'ankka-public-boundary-'));
  const gitEnv = {
    ...process.env,
    GIT_AUTHOR_EMAIL: 'fixture@example.com',
    GIT_AUTHOR_NAME: 'Public Boundary Fixture',
    GIT_COMMITTER_EMAIL: 'fixture@example.com',
    GIT_COMMITTER_NAME: 'Public Boundary Fixture',
  };

  try {
    git(fixture, ['init', '--quiet'], gitEnv);
    await writeFile(path.join(fixture, 'README.md'), '# Safe fixture\n');
    git(fixture, ['add', 'README.md'], gitEnv);
    git(fixture, ['commit', '--quiet', '-m', 'safe'], gitEnv);

    const safe = run(fixture);
    assert.equal(safe.status, 0, safe.stderr);

    const token = `${['github', 'pat'].join('_')}_${'a'.repeat(32)}`;
    await writeFile(path.join(fixture, 'notes.txt'), `${token}\n`);
    const unsafeUntracked = run(fixture);
    assert.equal(unsafeUntracked.status, 1);
    assert.match(unsafeUntracked.stderr, /notes\.txt contains GitHub fine-grained token/u);
    assert.equal(unsafeUntracked.stderr.includes(token), false);
    await rm(path.join(fixture, 'notes.txt'));

    await mkdir(path.join(fixture, 'dist'));
    await writeFile(path.join(fixture, 'dist', 'bundle.js'), 'safe();\n');
    git(fixture, ['add', '--force', 'dist/bundle.js'], gitEnv);
    const unsafeTrackedOutput = run(fixture);
    assert.equal(unsafeTrackedOutput.status, 1);
    assert.match(
      unsafeTrackedOutput.stderr,
      /dist\/bundle\.js is forbidden generated output/u,
    );
  } finally {
    await rm(fixture, { recursive: true, force: true });
  }
});

test('public-boundary check rejects embedded opaque credentials but allows explicit placeholders', async () => {
  const fixture = await mkdtemp(path.join(os.tmpdir(), 'ankka-public-boundary-credential-'));
  const gitEnv = fixtureGitEnv();

  try {
    git(fixture, ['init', '--quiet'], gitEnv);
    const apiTokenName = ['CLOUDFLARE', 'API', 'TOKEN'].join('_');
    const oauthSecretName = ['CLOUDFLARE', 'OAUTH', 'CLIENT', 'SECRET'].join('_');
    await writeFile(
      path.join(fixture, '.dev.vars.example'),
      `${apiTokenName}=<cloudflare-api-token>\n` +
        `${oauthSecretName}=<cloudflare-oauth-client-secret>\n`,
    );
    git(fixture, ['add', '.dev.vars.example'], gitEnv);
    git(fixture, ['commit', '--quiet', '-m', 'safe placeholders'], gitEnv);
    assert.equal(run(fixture).status, 0);

    const credential = 'OPAQUEVALUE';
    await writeFile(path.join(fixture, 'notes.txt'), `${apiTokenName}=${credential}\n`);
    const unsafe = run(fixture);
    assert.equal(unsafe.status, 1);
    assert.match(unsafe.stderr, /notes\.txt contains embedded opaque credential assignment/u);
    assert.equal(unsafe.stderr.includes(credential), false);
  } finally {
    await rm(fixture, { recursive: true, force: true });
  }
});

test('public-boundary check rejects generated release names and conservative JSON shapes', async () => {
  const fixture = await mkdtemp(path.join(os.tmpdir(), 'ankka-public-boundary-release-output-'));
  const gitEnv = fixtureGitEnv();

  try {
    git(fixture, ['init', '--quiet'], gitEnv);
    await writeFile(path.join(fixture, 'README.md'), '# Safe fixture\n');
    git(fixture, ['add', 'README.md'], gitEnv);
    git(fixture, ['commit', '--quiet', '-m', 'safe'], gitEnv);

    await writeFile(path.join(fixture, 'release-envelope.json'), '{}\n');
    const named = run(fixture);
    assert.equal(named.status, 1);
    assert.match(named.stderr, /release-envelope\.json has a forbidden filename/u);
    await rm(path.join(fixture, 'release-envelope.json'));

    await writeFile(path.join(fixture, 'isolated-canary-target.reviewed.json'), '{}\n');
    const isolatedTarget = run(fixture);
    assert.equal(isolatedTarget.status, 1);
    assert.match(
      isolatedTarget.stderr,
      /isolated-canary-target\.reviewed\.json has a forbidden filename/u,
    );
    await rm(path.join(fixture, 'isolated-canary-target.reviewed.json'));

    const generatedManifest = {
      artifact: { treeSha256: 'a'.repeat(64) },
      cloudflare: {},
      components: {},
      oauthScopeIds: [],
      release: 'gateway-v1.2.3',
      schemaVersion: 1,
      sourceCommit: 'b'.repeat(40),
    };
    await writeFile(path.join(fixture, 'renamed.json'), JSON.stringify(generatedManifest));
    const shaped = run(fixture);
    assert.equal(shaped.status, 1);
    assert.match(shaped.stderr, /renamed\.json contains generated release candidate manifest/u);
  } finally {
    await rm(fixture, { recursive: true, force: true });
  }
});

test('public-boundary check fails closed for ambiguous bytes and permits known binary types', async () => {
  const fixture = await mkdtemp(path.join(os.tmpdir(), 'ankka-public-boundary-bytes-'));
  const gitEnv = fixtureGitEnv();

  try {
    git(fixture, ['init', '--quiet'], gitEnv);
    await writeFile(path.join(fixture, 'README.md'), '# Safe fixture\n');
    git(fixture, ['add', 'README.md'], gitEnv);
    git(fixture, ['commit', '--quiet', '-m', 'safe'], gitEnv);

    await writeFile(path.join(fixture, 'mystery'), Buffer.from([0x73, 0x00, 0x66]));
    const nul = run(fixture);
    assert.equal(nul.status, 1);
    assert.match(nul.stderr, /mystery contains NUL bytes without a known binary type/u);
    await rm(path.join(fixture, 'mystery'));

    await writeFile(path.join(fixture, 'mystery'), Buffer.from([0xc3, 0x28]));
    const invalid = run(fixture);
    assert.equal(invalid.status, 1);
    assert.match(invalid.stderr, /mystery is not valid UTF-8 and has no known binary type/u);
    await rm(path.join(fixture, 'mystery'));

    await writeFile(path.join(fixture, 'large.txt'), Buffer.alloc(2_000_001, 0x61));
    const oversized = run(fixture);
    assert.equal(oversized.status, 1);
    assert.match(oversized.stderr, /large\.txt is oversized textual content/u);
    await rm(path.join(fixture, 'large.txt'));

    await writeFile(path.join(fixture, 'image.png'), Buffer.from([0x89, 0x50, 0x00, 0xff]));
    const binary = run(fixture);
    assert.equal(binary.status, 0, binary.stderr);
  } finally {
    await rm(fixture, { recursive: true, force: true });
  }
});

function run(directory) {
  return spawnSync(process.execPath, [checker, '--repo', directory], {
    encoding: 'utf8',
  });
}

function git(directory, args, env) {
  execFileSync('git', ['-C', directory, ...args], {
    env,
    stdio: 'pipe',
  });
}

function fixtureGitEnv() {
  return {
    ...process.env,
    GIT_AUTHOR_EMAIL: 'fixture@example.com',
    GIT_AUTHOR_NAME: 'Public Boundary Fixture',
    GIT_COMMITTER_EMAIL: 'fixture@example.com',
    GIT_COMMITTER_NAME: 'Public Boundary Fixture',
  };
}

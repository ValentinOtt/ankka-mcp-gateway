import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { mkdir, mkdtemp, rm, symlink, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const checker = path.join(repositoryRoot, 'scripts', 'check-public-history.mjs');

test('public-history check examines removed files and redacts matched values', async () => {
  const fixture = await mkdtemp(path.join(os.tmpdir(), 'ankka-public-history-'));
  const gitEnv = {
    ...process.env,
    GIT_AUTHOR_EMAIL: 'fixture@example.com',
    GIT_AUTHOR_NAME: 'Public History Fixture',
    GIT_COMMITTER_EMAIL: 'fixture@example.com',
    GIT_COMMITTER_NAME: 'Public History Fixture',
  };

  try {
    git(fixture, ['init', '--quiet'], gitEnv);
    await writeFile(path.join(fixture, 'README.md'), '# Safe fixture\n');
    git(fixture, ['add', 'README.md'], gitEnv);
    git(fixture, ['commit', '--quiet', '-m', 'safe'], gitEnv);

    const safe = spawnSync(process.execPath, [checker, '--repo', fixture], {
      encoding: 'utf8',
    });
    assert.equal(safe.status, 0, safe.stderr);

    const token = `gh${'p'}_${'a'.repeat(36)}`;
    await writeFile(path.join(fixture, 'removed.txt'), `${token}\n`);
    git(fixture, ['add', 'removed.txt'], gitEnv);
    git(fixture, ['commit', '--quiet', '-m', 'add unsafe history'], gitEnv);
    await rm(path.join(fixture, 'removed.txt'));
    git(fixture, ['add', '--all'], gitEnv);
    git(fixture, ['commit', '--quiet', '-m', 'remove unsafe file'], gitEnv);

    const unsafe = spawnSync(process.execPath, [checker, '--repo', fixture], {
      encoding: 'utf8',
    });
    assert.equal(unsafe.status, 1);
    assert.match(unsafe.stderr, /removed\.txt contains GitHub token/);
    assert.equal(unsafe.stderr.includes(token), false);
  } finally {
    await rm(fixture, { recursive: true, force: true });
  }
});

test('public-history check examines commit and annotated-tag metadata', async () => {
  const fixture = await mkdtemp(path.join(os.tmpdir(), 'ankka-public-history-metadata-'));
  const gitEnv = {
    ...process.env,
    GIT_AUTHOR_EMAIL: 'fixture@example.com',
    GIT_AUTHOR_NAME: 'Public History Fixture',
    GIT_COMMITTER_EMAIL: 'fixture@example.com',
    GIT_COMMITTER_NAME: 'Public History Fixture',
  };

  try {
    git(fixture, ['init', '--quiet'], gitEnv);
    await writeFile(path.join(fixture, 'README.md'), '# Safe fixture\n');
    git(fixture, ['add', 'README.md'], gitEnv);
    git(fixture, ['commit', '--quiet', '-m', 'safe'], gitEnv);

    const token = `gh${'p'}_${'b'.repeat(36)}`;
    git(fixture, ['commit', '--quiet', '--allow-empty', '-m', `metadata ${token}`], gitEnv);
    const unsafeCommit = spawnSync(process.execPath, [checker, '--repo', fixture], {
      encoding: 'utf8',
    });
    assert.equal(unsafeCommit.status, 1);
    assert.match(unsafeCommit.stderr, /commit [0-9a-f]+ contains GitHub token/u);
    assert.equal(unsafeCommit.stderr.includes(token), false);

    const accessKey = `${['AK', 'IA'].join('')}${'C'.repeat(16)}`;
    git(fixture, ['tag', '-a', 'unsafe-metadata', '-m', `metadata ${accessKey}`], gitEnv);
    const unsafeTag = spawnSync(process.execPath, [checker, '--repo', fixture], {
      encoding: 'utf8',
    });
    assert.equal(unsafeTag.status, 1);
    assert.match(unsafeTag.stderr, /annotated tag [0-9a-f]+ contains AWS access key/u);
    assert.equal(unsafeTag.stderr.includes(accessKey), false);
  } finally {
    await rm(fixture, { recursive: true, force: true });
  }
});

test('public-history check enumerates every path for identical blobs', async () => {
  const fixture = await mkdtemp(path.join(os.tmpdir(), 'ankka-public-history-alias-'));
  const gitEnv = fixtureGitEnv();

  try {
    git(fixture, ['init', '--quiet'], gitEnv);
    await mkdir(path.join(fixture, 'zzz'));
    const shared = Buffer.from('identical safe bytes\n');
    await writeFile(path.join(fixture, 'aaa.txt'), shared);
    await writeFile(path.join(fixture, 'zzz', 'release-envelope.json'), shared);
    git(fixture, ['add', '--all'], gitEnv);
    git(fixture, ['commit', '--quiet', '-m', 'identical aliases'], gitEnv);

    const unsafe = run(fixture);
    assert.equal(unsafe.status, 1);
    assert.match(
      unsafe.stderr,
      /zzz\/release-envelope\.json has a forbidden filename in reachable history/u,
    );
  } finally {
    await rm(fixture, { recursive: true, force: true });
  }
});

test('public-history check rejects oversized and NUL-bearing text but permits known binary blobs', async () => {
  const fixture = await mkdtemp(path.join(os.tmpdir(), 'ankka-public-history-bytes-'));
  const gitEnv = fixtureGitEnv();

  try {
    git(fixture, ['init', '--quiet'], gitEnv);
    await writeFile(path.join(fixture, 'image.png'), Buffer.from([0x89, 0x50, 0x00, 0xff]));
    git(fixture, ['add', 'image.png'], gitEnv);
    git(fixture, ['commit', '--quiet', '-m', 'safe binary'], gitEnv);
    assert.equal(run(fixture).status, 0);

    await writeFile(path.join(fixture, 'large.txt'), Buffer.alloc(2_000_001, 0x61));
    await writeFile(path.join(fixture, 'nul.txt'), Buffer.from([0x73, 0x00, 0x66]));
    git(fixture, ['add', 'large.txt', 'nul.txt'], gitEnv);
    git(fixture, ['commit', '--quiet', '-m', 'unsafe text encodings'], gitEnv);

    const unsafe = run(fixture);
    assert.equal(unsafe.status, 1);
    assert.match(unsafe.stderr, /large\.txt is oversized textual content in reachable history/u);
    assert.match(unsafe.stderr, /nul\.txt is textual content containing NUL bytes/u);
    assert.doesNotMatch(unsafe.stderr, /image\.png/u);
  } finally {
    await rm(fixture, { recursive: true, force: true });
  }
});

test('public-history check scans lightweight ref names without revealing them', async () => {
  const fixture = await mkdtemp(path.join(os.tmpdir(), 'ankka-public-history-ref-'));
  const gitEnv = fixtureGitEnv();

  try {
    git(fixture, ['init', '--quiet'], gitEnv);
    await writeFile(path.join(fixture, 'README.md'), '# Safe fixture\n');
    git(fixture, ['add', 'README.md'], gitEnv);
    git(fixture, ['commit', '--quiet', '-m', 'safe'], gitEnv);

    const token = `gh${'p'}_${'d'.repeat(36)}`;
    git(fixture, ['tag', token], gitEnv);
    git(fixture, ['tag', 'release-envelope.json'], gitEnv);
    const unsafe = run(fixture);
    assert.equal(unsafe.status, 1);
    assert.match(unsafe.stderr, /<redacted ref> targeting [0-9a-f]+ contains GitHub token/u);
    assert.match(
      unsafe.stderr,
      /refs\/tags\/release-envelope\.json targeting [0-9a-f]+ has a forbidden generated or sensitive name/u,
    );
    assert.equal(unsafe.stderr.includes(token), false);
  } finally {
    await rm(fixture, { recursive: true, force: true });
  }
});

test('public-history check rejects generated shapes, output directories, symlinks, and gitlinks', async () => {
  const fixture = await mkdtemp(path.join(os.tmpdir(), 'ankka-public-history-structures-'));
  const gitEnv = fixtureGitEnv();

  try {
    git(fixture, ['init', '--quiet'], gitEnv);
    await mkdir(path.join(fixture, 'coverage'));
    await writeFile(path.join(fixture, 'coverage', 'report.txt'), 'generated\n');
    await writeFile(path.join(fixture, 'README.md'), '# Safe fixture\n');
    await writeFile(path.join(fixture, 'renamed.json'), JSON.stringify({
      artifact: { treeSha256: 'a'.repeat(64) },
      cloudflare: {},
      components: {},
      oauthScopeIds: [],
      release: 'gateway-v1.2.3',
      schemaVersion: 1,
      sourceCommit: 'b'.repeat(40),
    }));
    await symlink('README.md', path.join(fixture, 'README-link'));
    git(fixture, ['add', '--all'], gitEnv);
    git(fixture, ['commit', '--quiet', '-m', 'unsafe structures'], gitEnv);
    const commitId = gitOutput(fixture, ['rev-parse', 'HEAD'], gitEnv).trim();
    git(fixture, ['update-index', '--add', '--cacheinfo', `160000,${commitId},vendor-module`], gitEnv);
    git(fixture, ['commit', '--quiet', '-m', 'gitlink'], gitEnv);

    const unsafe = run(fixture);
    assert.equal(unsafe.status, 1);
    assert.match(unsafe.stderr, /coverage\/report\.txt is forbidden generated output/u);
    assert.match(unsafe.stderr, /renamed\.json contains generated release candidate manifest/u);
    assert.match(unsafe.stderr, /README-link is a symbolic link in reachable history/u);
    assert.match(unsafe.stderr, /vendor-module is a gitlink in reachable history/u);
  } finally {
    await rm(fixture, { recursive: true, force: true });
  }
});

test('public-history check scans only the publishable surface', async () => {
  const fixture = await mkdtemp(path.join(os.tmpdir(), 'ankka-public-history-scope-'));
  const gitEnv = fixtureGitEnv();
  const token = `gh${'p'}_${'f'.repeat(36)}`;

  try {
    git(fixture, ['init', '--quiet'], gitEnv);
    await writeFile(path.join(fixture, 'README.md'), '# Safe fixture\n');
    git(fixture, ['add', 'README.md'], gitEnv);
    git(fixture, ['commit', '--quiet', '-m', 'safe'], gitEnv);

    git(fixture, ['switch', '--quiet', '-c', 'private-work'], gitEnv);
    await writeFile(path.join(fixture, 'private.txt'), `${token}\n`);
    git(fixture, ['add', 'private.txt'], gitEnv);
    git(fixture, ['commit', '--quiet', '-m', 'private material'], gitEnv);
    const privateCommit = gitOutput(fixture, ['rev-parse', 'HEAD'], gitEnv).trim();
    git(fixture, ['switch', '--quiet', '-'], gitEnv);
    git(fixture, ['branch', '--quiet', '-D', 'private-work'], gitEnv);
    git(fixture, ['update-ref', 'refs/remotes/private-mirror/main', privateCommit], gitEnv);

    const scoped = run(fixture);
    assert.equal(scoped.status, 0, scoped.stderr);

    git(fixture, ['update-ref', 'refs/remotes/origin/feature', privateCommit], gitEnv);
    const publishable = run(fixture);
    assert.equal(publishable.status, 1);
    assert.match(publishable.stderr, /private\.txt contains GitHub token/u);
    assert.equal(publishable.stderr.includes(token), false);
  } finally {
    await rm(fixture, { recursive: true, force: true });
  }
});

test('public-history check grandfathers only retired naming in an exact public baseline', async () => {
  const fixture = await mkdtemp(path.join(os.tmpdir(), 'ankka-public-history-baseline-'));
  const gitEnv = fixtureGitEnv();
  const retiredName = ['Company', 'Gateway'].join(' ');

  try {
    git(fixture, ['init', '--quiet'], gitEnv);
    await writeFile(path.join(fixture, 'README.md'), `# ${retiredName}\n`);
    git(fixture, ['add', 'README.md'], gitEnv);
    git(fixture, ['commit', '--quiet', '-m', `publish ${retiredName}`], gitEnv);
    const baseline = gitOutput(fixture, ['rev-parse', 'HEAD'], gitEnv).trim();

    await writeFile(path.join(fixture, 'README.md'), '# Safe current name\n');
    git(fixture, ['add', 'README.md'], gitEnv);
    git(fixture, ['commit', '--quiet', '-m', 'retire old name'], gitEnv);
    const allowed = run(fixture, baseline);
    assert.equal(allowed.status, 0, allowed.stderr);

    await writeFile(path.join(fixture, 'regression.md'), `# ${retiredName}\n`);
    git(fixture, ['add', 'regression.md'], gitEnv);
    git(fixture, ['commit', '--quiet', '-m', 'reintroduce old name'], gitEnv);
    const rejected = run(fixture, baseline);
    assert.equal(rejected.status, 1);
    assert.match(rejected.stderr, /contains retired gateway product name/u);
  } finally {
    await rm(fixture, { recursive: true, force: true });
  }
});

test('public-history baseline does not grandfather credentials', async () => {
  const fixture = await mkdtemp(path.join(os.tmpdir(), 'ankka-public-history-baseline-secret-'));
  const gitEnv = fixtureGitEnv();
  const token = `gh${'p'}_${'e'.repeat(36)}`;

  try {
    git(fixture, ['init', '--quiet'], gitEnv);
    await writeFile(path.join(fixture, 'removed.txt'), `${token}\n`);
    git(fixture, ['add', 'removed.txt'], gitEnv);
    git(fixture, ['commit', '--quiet', '-m', 'published fixture'], gitEnv);
    const baseline = gitOutput(fixture, ['rev-parse', 'HEAD'], gitEnv).trim();
    await rm(path.join(fixture, 'removed.txt'));
    git(fixture, ['add', '--all'], gitEnv);
    git(fixture, ['commit', '--quiet', '-m', 'remove fixture'], gitEnv);

    const rejected = run(fixture, baseline);
    assert.equal(rejected.status, 1);
    assert.match(rejected.stderr, /removed\.txt contains GitHub token/u);
    assert.equal(rejected.stderr.includes(token), false);
  } finally {
    await rm(fixture, { recursive: true, force: true });
  }
});

function run(directory, baseline) {
  const baselineArgs = baseline === undefined
    ? []
    : ['--allow-retired-product-name-through', baseline];
  return spawnSync(process.execPath, [checker, '--repo', directory, ...baselineArgs], {
    encoding: 'utf8',
  });
}

function git(directory, args, env) {
  execFileSync('git', ['-C', directory, ...args], {
    env,
    stdio: 'pipe',
  });
}

function gitOutput(directory, args, env) {
  return execFileSync('git', ['-C', directory, ...args], {
    encoding: 'utf8',
    env,
    stdio: ['ignore', 'pipe', 'pipe'],
  });
}

function fixtureGitEnv() {
  return {
    ...process.env,
    GIT_AUTHOR_EMAIL: 'fixture@example.com',
    GIT_AUTHOR_NAME: 'Public History Fixture',
    GIT_COMMITTER_EMAIL: 'fixture@example.com',
    GIT_COMMITTER_NAME: 'Public History Fixture',
  };
}

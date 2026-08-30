import { execFile } from 'node:child_process';
import { access, chmod, mkdir, mkdtemp, rm, symlink, writeFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { promisify } from 'node:util';
import test from 'node:test';
import assert from 'node:assert/strict';

const execFileAsync = promisify(execFile);
const cli = fileURLToPath(new URL('../src/canary-lifecycle-cli.ts', import.meta.url));
const LOCK_CONFIRMATION = 'remove-inspected-stale-receipt-lock';
const target = {
  accountId: 'a'.repeat(32),
  zoneId: 'b'.repeat(32),
  hostname: 'ankka-canary-cli.disposable.example',
  endpoint: 'https://ankka-synthetic-canary.example.net/mcp',
  receipt: '/tmp/ankka-canary-cli.receipt.json',
};

function args(mode = 'preview') {
  return [
    mode,
    '--account-id',
    target.accountId,
    '--zone-id',
    target.zoneId,
    '--hostname',
    target.hostname,
    '--synthetic-mcp-url',
    target.endpoint,
    '--receipt',
    target.receipt,
    ...(mode === 'run'
      ? [
          '--approve',
          `canary-lifecycle-${'1'.repeat(24)}`,
          '--confirm-disposable-target',
          `canary-target-${'2'.repeat(24)}`,
        ]
      : []),
  ];
}

test('prints standalone lifecycle help without reading secrets', async () => {
  const result = await execFileAsync(process.execPath, [cli, '--help'], {
    encoding: 'utf8',
  });
  assert.match(result.stdout, /preview/);
  assert.match(result.stdout, /confirm-disposable-target/);
  assert.match(result.stdout, /preview --profile/);
  assert.match(result.stdout, /run --profile/);
  assert.match(result.stdout, /ANKKA_CANARY_DIRECTORY/);
  assert.match(result.stdout, /lock inspect/);
  assert.match(result.stdout, /lock recover/);
  assert.match(result.stdout, new RegExp(LOCK_CONFIRMATION));
  assert.match(result.stdout, /CLOUDFLARE_API_TOKEN/);
  assert.match(result.stdout, /--authentication <email\|service_token>/);
  assert.match(result.stdout, /Authentication defaults to email/);
  assert.match(result.stdout, /ANKKA_CANARY_ALLOWED_EMAIL/);
  assert.match(result.stdout, /ANKKA_CANARY_SERVICE_TOKEN_ID/);
  assert.match(result.stdout, /CF_ACCESS_CLIENT_ID/);
  assert.match(result.stdout, /CF_ACCESS_CLIENT_SECRET/);
  assert.equal(result.stderr, '');
});

test('profile mode cannot override its enrolled authentication', async () => {
  await assert.rejects(
    execFileAsync(process.execPath, [
      cli, 'preview', '--profile', 'cloudflare-lifecycle',
      '--authentication', 'service_token',
    ], {
      encoding: 'utf8',
      env: { ...process.env, CLOUDFLARE_API_TOKEN: '' },
    }),
    (error) => {
      assert.equal(error.code, 2);
      assert.match(error.stderr, /accepts only --profile and --json/);
      return true;
    },
  );
});

test('raw CLI accepts only the two explicit authentication choices', async () => {
  for (const authentication of ['email', 'service_token']) {
    await assert.rejects(
      execFileAsync(process.execPath, [cli, ...args(), '--authentication', authentication], {
        encoding: 'utf8',
        env: {
          ...process.env,
          CLOUDFLARE_API_TOKEN: '',
          ANKKA_CANARY_ALLOWED_EMAIL: '',
          ANKKA_CANARY_SERVICE_TOKEN_ID: '',
          CF_ACCESS_CLIENT_ID: '',
          CF_ACCESS_CLIENT_SECRET: '',
        },
      }),
      (error) => {
        assert.equal(error.code, 2);
        assert.match(error.stderr, /operator-controlled environment/);
        return true;
      },
    );
  }
  for (const authentication of ['oauth', 'SERVICE_TOKEN', 'must-not-escape']) {
    await assert.rejects(
      execFileAsync(process.execPath, [cli, ...args(), '--authentication', authentication], {
        encoding: 'utf8',
        env: { ...process.env, CLOUDFLARE_API_TOKEN: '' },
      }),
      (error) => {
        assert.equal(error.code, 2);
        assert.match(error.stderr, /--authentication must be email or service_token/);
        assert.doesNotMatch(error.stderr, /must-not-escape/);
        return true;
      },
    );
  }
});

test('raw CLI authentication requires one value without duplicates', async () => {
  for (const flags of [
    ['--authentication'],
    ['--authentication', ''],
    ['--authentication', 'email', '--authentication', 'service_token'],
  ]) {
    await assert.rejects(
      execFileAsync(process.execPath, [cli, ...args(), ...flags], { encoding: 'utf8' }),
      (error) => {
        assert.equal(error.code, 2);
        assert.match(error.stderr, /--authentication (?:requires a value|may only be provided once)/);
        return true;
      },
    );
  }
});

test('profile mode rejects mixed raw options before reading profiles or secrets', async () => {
  const selectedProfile = 'cloudflare-lifecycle';
  const selectedAccount = 'must-not-echo-account';
  await assert.rejects(
    execFileAsync(process.execPath, [
      cli,
      'run',
      '--profile',
      selectedProfile,
      '--account-id',
      selectedAccount,
    ], {
      encoding: 'utf8',
      env: {
        ...process.env,
        CLOUDFLARE_API_TOKEN: '',
        ANKKA_CANARY_ALLOWED_EMAIL: '',
      },
    }),
    (error) => {
      assert.equal(error.code, 2);
      assert.match(error.stderr, /accepts only --profile and --json/);
      assert.doesNotMatch(error.stderr, new RegExp(selectedProfile));
      assert.doesNotMatch(error.stderr, new RegExp(selectedAccount));
      return true;
    },
  );
});

test('profile mode loads an owner-only external target before reading environment secrets', async () => {
  const directory = await mkdtemp(path.join(tmpdir(), 'ankka-canary-profile-cli-'));
  const profiles = path.join(directory, 'profiles');
  const profileId = 'cloudflare-lifecycle';
  const profilePath = path.join(profiles, `${profileId}.json`);
  const profile = {
    schemaVersion: 1,
    kind: 'ankka-cloudflare-disposable-canary-profile',
    profileId,
    accountId: target.accountId,
    zoneId: target.zoneId,
    hostname: target.hostname,
    syntheticMcpUrl: target.endpoint,
  };
  try {
    await chmod(directory, 0o700);
    await mkdir(profiles, { mode: 0o700 });
    await chmod(profiles, 0o700);
    await writeFile(profilePath, JSON.stringify(profile), { mode: 0o600 });
    await chmod(profilePath, 0o600);

    await assert.rejects(
      execFileAsync(process.execPath, [cli, 'preview', '--profile', profileId], {
        encoding: 'utf8',
        env: {
          ...process.env,
          ANKKA_CANARY_DIRECTORY: directory,
          CLOUDFLARE_API_TOKEN: '',
          ANKKA_CANARY_ALLOWED_EMAIL: '',
        },
      }),
      (error) => {
        assert.equal(error.code, 2);
        assert.match(error.stderr, /operator-controlled environment/);
        for (const value of [
          profileId,
          profile.accountId,
          profile.zoneId,
          profile.hostname,
          profile.syntheticMcpUrl,
          directory,
        ]) {
          assert.equal(error.stderr.includes(value), false);
        }
        return true;
      },
    );

    const inspection = await execFileAsync(process.execPath, [
      cli,
      'lock',
      'inspect',
      '--profile',
      profileId,
      '--store',
      'receipt',
      '--json',
    ], {
      encoding: 'utf8',
      env: {
        ...process.env,
        ANKKA_CANARY_DIRECTORY: directory,
        CLOUDFLARE_API_TOKEN: '',
        ANKKA_CANARY_ALLOWED_EMAIL: '',
      },
    });
    assert.deepEqual(JSON.parse(inspection.stdout), {
      schemaVersion: 1,
      kind: 'canary_lock_inspection',
      store: 'receipt',
      status: 'not_found',
      lockRemoved: false,
    });
    assert.equal(inspection.stderr, '');

    const redirectedReceipts = path.join(directory, 'redirected-receipts');
    await mkdir(redirectedReceipts, { mode: 0o700 });
    await symlink(redirectedReceipts, path.join(directory, 'receipts'));
    await assert.rejects(
      execFileAsync(process.execPath, [
        cli,
        'lock',
        'inspect',
        '--profile',
        profileId,
        '--store',
        'receipt',
      ], {
        encoding: 'utf8',
        env: {
          ...process.env,
          ANKKA_CANARY_DIRECTORY: directory,
          CLOUDFLARE_API_TOKEN: '',
          ANKKA_CANARY_ALLOWED_EMAIL: '',
        },
      }),
      (error) => {
        assert.equal(error.code, 2);
        assert.match(error.stderr, /receipt directory could not be prepared safely/);
        assert.equal(error.stderr.includes(redirectedReceipts), false);
        return true;
      },
    );
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test('invalid profile names fail with a fixed error and never read secrets', async () => {
  const invalidName = '../must-not-echo-profile';
  await assert.rejects(
    execFileAsync(process.execPath, [cli, 'run', '--profile', invalidName], {
      encoding: 'utf8',
      env: {
        ...process.env,
        CLOUDFLARE_API_TOKEN: '',
        ANKKA_CANARY_ALLOWED_EMAIL: '',
      },
    }),
    (error) => {
      assert.equal(error.code, 2);
      assert.match(error.stderr, /profile name is invalid/);
      assert.equal(error.stderr.includes(invalidName), false);
      return true;
    },
  );
});

test('rejects token flags without echoing their values', async () => {
  const secret = 'must-not-escape';
  for (const flag of ['--token', '--service-token-id', '--client-id', '--client-secret']) {
    await assert.rejects(
      execFileAsync(process.execPath, [cli, ...args(), flag, secret], {
        encoding: 'utf8',
      }),
      (error) => {
        assert.equal(error.code, 2);
        assert.match(error.stderr, /unknown option/);
        assert.doesNotMatch(error.stderr, new RegExp(secret));
        return true;
      },
    );
  }
});

test('missing environment secrets fail before provider calls and selected values stay hidden', async () => {
  await assert.rejects(
    execFileAsync(process.execPath, [cli, ...args()], {
      encoding: 'utf8',
      env: {
        ...process.env,
        CLOUDFLARE_API_TOKEN: '',
        ANKKA_CANARY_ALLOWED_EMAIL: '',
      },
    }),
    (error) => {
      assert.equal(error.code, 2);
      assert.match(error.stderr, /operator-controlled environment/);
      for (const value of Object.values(target)) {
        assert.doesNotMatch(error.stderr, new RegExp(value.replaceAll('.', '\\.')));
      }
      return true;
    },
  );
});

test('run requires both exact approval arguments before reading secrets', async () => {
  const incomplete = args('run').slice(0, -2);
  await assert.rejects(
    execFileAsync(process.execPath, [cli, ...incomplete], { encoding: 'utf8' }),
    (error) => {
      assert.equal(error.code, 2);
      assert.match(error.stderr, /--confirm-disposable-target is required/);
      return true;
    },
  );
});

test('lock inspection needs no Cloudflare secrets and requires explicit store selection', async () => {
  const receipt = `/tmp/ankka-canary-no-lock-${process.pid}-${Date.now()}.json`;
  const result = await execFileAsync(process.execPath, [
    cli,
    'lock',
    'inspect',
    '--receipt',
    receipt,
    '--store',
    'cleanup',
    '--json',
  ], {
    encoding: 'utf8',
    env: {
      ...process.env,
      CLOUDFLARE_API_TOKEN: '',
      ANKKA_CANARY_ALLOWED_EMAIL: '',
    },
  });
  assert.deepEqual(JSON.parse(result.stdout), {
    schemaVersion: 1,
    kind: 'canary_lock_inspection',
    store: 'cleanup',
    status: 'not_found',
    lockRemoved: false,
  });
  assert.equal(result.stderr, '');
  assert.doesNotMatch(result.stdout, new RegExp(receipt.replaceAll('.', '\\.')));

  await assert.rejects(
    execFileAsync(process.execPath, [
      cli,
      'lock',
      'inspect',
      '--receipt',
      receipt,
    ], { encoding: 'utf8' }),
    (error) => {
      assert.equal(error.code, 2);
      assert.match(error.stderr, /--store is required/);
      return true;
    },
  );
});

test('standalone CLI inspects and recovers exact stale locks for both local stores', async () => {
  const directory = await mkdtemp(path.join(tmpdir(), 'ankka-canary-lock-cli-'));
  const receipt = path.join(directory, 'canary.receipt.json');
  try {
    for (const store of ['receipt', 'cleanup']) {
      const lockId = `stale-${store}-lock`;
      const targetPath = store === 'receipt' ? receipt : `${receipt}.cleanup-recovery`;
      const lockDirectory = path.join(
        path.dirname(targetPath),
        `.${path.basename(targetPath)}.lock`,
      );
      const metadata = {
        version: 1,
        lockId,
        ownerId: `stale-${store}-owner`,
        pid: 2_147_483_647,
        createdAt: '2026-08-22T12:00:00.000Z',
        operationId: 'canary-lifecycle',
      };
      await mkdir(lockDirectory, { mode: 0o700 });
      await chmod(lockDirectory, 0o700);
      const metadataPath = path.join(lockDirectory, `${lockId}.json`);
      await writeFile(metadataPath, JSON.stringify(metadata), { mode: 0o600 });
      await chmod(metadataPath, 0o600);

      const inspection = await execFileAsync(process.execPath, [
        cli,
        'lock',
        'inspect',
        '--receipt',
        receipt,
        '--store',
        store,
        '--json',
      ], {
        encoding: 'utf8',
        env: {
          ...process.env,
          CLOUDFLARE_API_TOKEN: '',
          ANKKA_CANARY_ALLOWED_EMAIL: '',
        },
      });
      const report = JSON.parse(inspection.stdout);
      assert.equal(report.status, 'stale_candidate');
      assert.equal(report.lockId, lockId);
      assert.equal(report.operationId, 'canary-lifecycle');
      assert.equal(report.store, store);
      assert.doesNotMatch(inspection.stdout, new RegExp(metadata.ownerId));
      assert.doesNotMatch(inspection.stdout, new RegExp(String(metadata.pid)));
      assert.doesNotMatch(inspection.stdout, new RegExp(receipt.replaceAll('.', '\\.')));

      const recovery = await execFileAsync(process.execPath, [
        cli,
        'lock',
        'recover',
        '--receipt',
        receipt,
        '--store',
        store,
        '--lock-id',
        lockId,
        '--confirm',
        LOCK_CONFIRMATION,
        '--json',
      ], {
        encoding: 'utf8',
        env: {
          ...process.env,
          CLOUDFLARE_API_TOKEN: '',
          ANKKA_CANARY_ALLOWED_EMAIL: '',
        },
      });
      assert.deepEqual(JSON.parse(recovery.stdout), {
        schemaVersion: 1,
        kind: 'canary_lock_recovery_result',
        store,
        status: 'removed',
        lockId,
        lockRemoved: true,
      });
      await assert.rejects(access(lockDirectory), (error) => error?.code === 'ENOENT');
    }
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test('lock recover rejects a wrong confirmation without inspecting or echoing the lock ID', async () => {
  const secretLikeLockId = 'must-not-echo-lock-id';
  await assert.rejects(
    execFileAsync(process.execPath, [
      cli,
      'lock',
      'recover',
      '--receipt',
      '/tmp/unused-canary-lock.receipt.json',
      '--store',
      'receipt',
      '--lock-id',
      secretLikeLockId,
      '--confirm',
      'yes',
    ], { encoding: 'utf8' }),
    (error) => {
      assert.equal(error.code, 2);
      assert.match(error.stderr, new RegExp(LOCK_CONFIRMATION));
      assert.doesNotMatch(error.stderr, new RegExp(secretLikeLockId));
      return true;
    },
  );
});

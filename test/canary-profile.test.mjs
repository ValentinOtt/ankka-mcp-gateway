import { chmod, lstat, mkdir, mkdtemp, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import test from 'node:test';
import assert from 'node:assert/strict';

import {
  assertCanaryReceiptDirectorySafe,
  CanaryProfileError,
  defaultCanaryProfileDirectory,
  ensureCanaryReceiptDirectory,
  readCanaryProfile,
  resolveCanaryProfilePaths,
} from '../src/canary-profile.ts';

const PROFILE_ID = 'cloudflare-lifecycle';
const ACCOUNT_ID = 'a'.repeat(32);
const ZONE_ID = 'b'.repeat(32);
const HOSTNAME = 'ankka-canary-cli.disposable.example';
const ENDPOINT = 'https://synthetic-canary.example.net/mcp';

function validProfile(overrides = {}) {
  return {
    schemaVersion: 1,
    kind: 'ankka-cloudflare-disposable-canary-profile',
    profileId: PROFILE_ID,
    accountId: ACCOUNT_ID,
    zoneId: ZONE_ID,
    hostname: HOSTNAME,
    syntheticMcpUrl: ENDPOINT,
    ...overrides,
  };
}

async function createFixture(contents = validProfile()) {
  const directory = await mkdtemp(path.join(tmpdir(), 'ankka-canary-profile-'));
  await chmod(directory, 0o700);
  const profiles = path.join(directory, 'profiles');
  await mkdir(profiles, { mode: 0o700 });
  await chmod(profiles, 0o700);
  const profilePath = path.join(profiles, `${PROFILE_ID}.json`);
  const serialized = Buffer.isBuffer(contents) ? contents : JSON.stringify(contents);
  await writeFile(profilePath, serialized, { mode: 0o600 });
  await chmod(profilePath, 0o600);
  return { directory, profilePath };
}

test('loads one strict external profile and derives a stable local receipt path', async () => {
  const fixture = await createFixture();
  try {
    const profile = await readCanaryProfile(PROFILE_ID, { directory: fixture.directory });
    assert.equal(profile.profileId, PROFILE_ID);
    assert.equal(profile.accountId, ACCOUNT_ID);
    assert.equal(profile.zoneId, ZONE_ID);
    assert.equal(profile.hostname, HOSTNAME);
    assert.equal(profile.syntheticMcpUrl, ENDPOINT);
    assert.equal(Object.hasOwn(profile, 'authentication'), false);
    assert.equal(
      profile.receiptPath,
      path.join(fixture.directory, 'receipts', `${PROFILE_ID}.receipt.json`),
    );

    await ensureCanaryReceiptDirectory(profile);
    const receiptDirectory = await lstat(path.join(fixture.directory, 'receipts'));
    assert.equal(receiptDirectory.isDirectory(), true);
    assert.equal(receiptDirectory.mode & 0o077, 0);

    const second = await readCanaryProfile(PROFILE_ID, { directory: fixture.directory });
    assert.equal(second.receiptPath, profile.receiptPath);
  } finally {
    await rm(fixture.directory, { recursive: true, force: true });
  }
});

test('profiles can explicitly select email or service-token authentication without credentials', async () => {
  for (const authentication of ['email', 'service_token']) {
    const fixture = await createFixture(validProfile({ authentication }));
    try {
      const profile = await readCanaryProfile(PROFILE_ID, { directory: fixture.directory });
      assert.equal(profile.authentication, authentication);
      assert.equal(profile.accountId, ACCOUNT_ID);
      assert.equal(profile.hostname, HOSTNAME);
      assert.equal(Object.isFrozen(profile), true);
    } finally {
      await rm(fixture.directory, { recursive: true, force: true });
    }
  }
});

test('rejects unknown fields and malformed target values with fixed redacted errors', async () => {
  const invalidProfiles = [
    validProfile({ token: 'must-not-escape' }),
    validProfile({ authentication: 'service_token', serviceTokenId: 'must-not-escape' }),
    validProfile({ authentication: 'service_token', clientId: 'must-not-escape' }),
    validProfile({ authentication: 'service_token', clientSecret: 'must-not-escape' }),
    validProfile({ authentication: { mode: 'service_token', secret: 'must-not-escape' } }),
    ...['oauth', 'SERVICE_TOKEN', '', 'must-not-escape', null, true, 1, ['email']]
      .map((authentication) => validProfile({ authentication })),
    validProfile({ profileId: 'different-profile' }),
    validProfile({ accountId: 'not-an-account-id' }),
    validProfile({ hostname: 'ordinary.example.com' }),
    validProfile({ syntheticMcpUrl: 'https://business.example.com/mcp' }),
    validProfile({ syntheticMcpUrl: `${ENDPOINT}?token=must-not-escape` }),
  ];
  for (const contents of invalidProfiles) {
    const fixture = await createFixture(contents);
    try {
      await assert.rejects(
        readCanaryProfile(PROFILE_ID, { directory: fixture.directory }),
        (error) => {
          assert.ok(error instanceof CanaryProfileError);
          assert.equal(error.code, 'profile_invalid');
          assert.doesNotMatch(error.message, /must-not-escape|different-profile|business/u);
          assert.equal(error.message.includes(fixture.directory), false);
          assert.equal(error.message.includes(ACCOUNT_ID), false);
          return true;
        },
      );
    } finally {
      await rm(fixture.directory, { recursive: true, force: true });
    }
  }
});

test('rejects traversal names and repository-local profile directories', async () => {
  for (const name of ['../escape', 'Cloudflare', 'name.json', 'a/b', 'å-profile']) {
    assert.throws(
      () => resolveCanaryProfilePaths(name, { directory: tmpdir() }),
      (error) => error instanceof CanaryProfileError && error.code === 'profile_name_invalid',
    );
  }
  assert.throws(
    () => resolveCanaryProfilePaths(PROFILE_ID, { directory: process.cwd() }),
    (error) => error instanceof CanaryProfileError && error.code === 'directory_invalid',
  );
  assert.throws(
    () => defaultCanaryProfileDirectory({ ANKKA_CANARY_DIRECTORY: 'relative/path' }, tmpdir()),
    (error) => error instanceof CanaryProfileError && error.code === 'directory_invalid',
  );
});

test('rejects permissive, oversized, symlinked, and invalid UTF-8 profile files', async () => {
  const permissive = await createFixture();
  try {
    await chmod(permissive.profilePath, 0o644);
    await assert.rejects(
      readCanaryProfile(PROFILE_ID, { directory: permissive.directory }),
      (error) => error instanceof CanaryProfileError && error.code === 'profile_unsafe',
    );
  } finally {
    await rm(permissive.directory, { recursive: true, force: true });
  }

  const oversized = await createFixture(Buffer.alloc(4097, 0x20));
  try {
    await assert.rejects(
      readCanaryProfile(PROFILE_ID, { directory: oversized.directory }),
      (error) => error instanceof CanaryProfileError && error.code === 'profile_unsafe',
    );
  } finally {
    await rm(oversized.directory, { recursive: true, force: true });
  }

  const invalidUtf8 = await createFixture(Buffer.from([0xc3, 0x28]));
  try {
    await assert.rejects(
      readCanaryProfile(PROFILE_ID, { directory: invalidUtf8.directory }),
      (error) => error instanceof CanaryProfileError && error.code === 'profile_invalid',
    );
  } finally {
    await rm(invalidUtf8.directory, { recursive: true, force: true });
  }

  const linked = await createFixture();
  const target = path.join(linked.directory, 'target.json');
  try {
    await writeFile(target, JSON.stringify(validProfile()), { mode: 0o600 });
    await rm(linked.profilePath);
    await symlink(target, linked.profilePath);
    await assert.rejects(
      readCanaryProfile(PROFILE_ID, { directory: linked.directory }),
      (error) => error instanceof CanaryProfileError && error.code === 'profile_unsafe',
    );
  } finally {
    await rm(linked.directory, { recursive: true, force: true });
  }
});

test('rejects unsafe profile directories before reading profile contents', async () => {
  const fixture = await createFixture(validProfile({ token: 'must-not-escape' }));
  try {
    await chmod(path.join(fixture.directory, 'profiles'), 0o755);
    await assert.rejects(
      readCanaryProfile(PROFILE_ID, { directory: fixture.directory }),
      (error) => {
        assert.ok(error instanceof CanaryProfileError);
        assert.equal(error.code, 'profile_unsafe');
        assert.doesNotMatch(error.message, /must-not-escape/u);
        return true;
      },
    );
  } finally {
    await rm(fixture.directory, { recursive: true, force: true });
  }
});

test('profile lock paths allow a missing receipt directory but reject a symlinked one', async () => {
  const fixture = await createFixture();
  const outside = await mkdtemp(path.join(tmpdir(), 'ankka-canary-receipts-outside-'));
  try {
    await chmod(outside, 0o700);
    const profile = await readCanaryProfile(PROFILE_ID, { directory: fixture.directory });
    await assert.doesNotReject(assertCanaryReceiptDirectorySafe(profile));

    await symlink(outside, profile.receiptDirectory);
    await assert.rejects(
      assertCanaryReceiptDirectorySafe(profile),
      (error) => {
        assert.ok(error instanceof CanaryProfileError);
        assert.equal(error.code, 'receipt_directory_unavailable');
        assert.equal(error.message.includes(outside), false);
        return true;
      },
    );
  } finally {
    await rm(fixture.directory, { recursive: true, force: true });
    await rm(outside, { recursive: true, force: true });
  }
});

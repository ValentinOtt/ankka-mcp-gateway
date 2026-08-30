import test from 'node:test';
import assert from 'node:assert/strict';

import {
  CanaryProfileCommandError,
  executeCanaryProfileLifecycleCommand,
} from '../src/canary-profile-command.ts';

const PROFILE_ID = 'cloudflare-lifecycle';
const ACCOUNT_ID = 'a'.repeat(32);
const ZONE_ID = 'b'.repeat(32);
const HOSTNAME = 'ankka-canary-cli.disposable.example';
const ENDPOINT = 'https://synthetic-canary.example.net/mcp';
const RECEIPT = '/private/tmp/ankka-canary/receipts/cloudflare-lifecycle.receipt.json';
const APPROVAL = `canary-lifecycle-${'1'.repeat(24)}`;
const TARGET_CONFIRMATION = `canary-target-${'2'.repeat(24)}`;

function profile(overrides = {}) {
  return Object.freeze({
    schemaVersion: 1,
    kind: 'ankka-cloudflare-disposable-canary-profile',
    profileId: PROFILE_ID,
    accountId: ACCOUNT_ID,
    zoneId: ZONE_ID,
    hostname: HOSTNAME,
    syntheticMcpUrl: ENDPOINT,
    directory: '/private/tmp/ankka-canary',
    profilesDirectory: '/private/tmp/ankka-canary/profiles',
    profilePath: `/private/tmp/ankka-canary/profiles/${PROFILE_ID}.json`,
    receiptDirectory: '/private/tmp/ankka-canary/receipts',
    receiptPath: RECEIPT,
    ...overrides,
  });
}

function previewResult(overrides = {}) {
  const report = {
    schemaVersion: 1,
    kind: 'cloudflare_canary_lifecycle_preview',
    operation: 'apply_lifecycle',
    ready: true,
    writesPerformed: false,
    approvalId: APPROVAL,
    targetConfirmationId: TARGET_CONFIRMATION,
    changes: [],
    cleanup: [],
    ...overrides,
  };
  return { report, output: 'safe preview', exitCode: 0 };
}

function result() {
  return {
    report: {
      schemaVersion: 1,
      kind: 'cloudflare_canary_lifecycle_result',
      status: 'complete',
      resourceLifecycle: 'removed',
      interactiveVerification: 'verified',
      installedStateVerified: true,
      portalToolCallVerified: true,
      idempotentApplyVerified: true,
      cleanup: { status: 'removed', ownedResourceCount: 0 },
    },
    output: 'safe result',
    exitCode: 0,
  };
}

test('profile preview loads the enrolled target without preparing or mutating local state', async () => {
  const calls = [];
  let preparations = 0;
  const output = await executeCanaryProfileLifecycleCommand(
    { mode: 'preview', profileId: PROFILE_ID, json: false },
    {
      readProfile: async (profileId) => {
        assert.equal(profileId, PROFILE_ID);
        return profile();
      },
      prepareReceiptDirectory: async () => { preparations += 1; },
      executeLifecycle: async (invocation) => {
        calls.push(invocation);
        return previewResult();
      },
    },
  );

  assert.equal(output.output, 'safe preview');
  assert.equal(preparations, 0);
  assert.deepEqual(calls, [{
    mode: 'preview',
    accountId: ACCOUNT_ID,
    zoneId: ZONE_ID,
    hostname: HOSTNAME,
    syntheticMcpUrl: ENDPOINT,
    receiptPath: RECEIPT,
    json: false,
  }]);
});

test('profile run forwards only fresh structured approvals into one existing run', async () => {
  const calls = [];
  const preparations = [];
  const enrolled = profile();
  const output = await executeCanaryProfileLifecycleCommand(
    { mode: 'run', profileId: PROFILE_ID, json: true },
    {
      readProfile: async () => enrolled,
      prepareReceiptDirectory: async (value) => { preparations.push(value); },
      executeLifecycle: async (invocation) => {
        calls.push(invocation);
        return invocation.mode === 'preview' ? previewResult() : result();
      },
    },
  );

  assert.equal(output.output, 'safe result');
  assert.deepEqual(preparations, [enrolled]);
  assert.equal(calls.length, 2);
  assert.deepEqual(calls[0], {
    mode: 'preview',
    accountId: ACCOUNT_ID,
    zoneId: ZONE_ID,
    hostname: HOSTNAME,
    syntheticMcpUrl: ENDPOINT,
    receiptPath: RECEIPT,
    json: true,
  });
  assert.deepEqual(calls[1], {
    ...calls[0],
    mode: 'run',
    approvalId: APPROVAL,
    targetConfirmationId: TARGET_CONFIRMATION,
  });
  for (const value of [ACCOUNT_ID, ZONE_ID, HOSTNAME, ENDPOINT, RECEIPT]) {
    assert.equal(output.output.includes(value), false);
  }
});

test('profile authentication opts into service tokens for both preview and run', async () => {
  for (const authentication of [undefined, 'email', 'service_token']) {
    const calls = [];
    await executeCanaryProfileLifecycleCommand(
      { mode: 'run', profileId: PROFILE_ID },
      {
        readProfile: async () => profile(
          authentication === undefined ? {} : { authentication },
        ),
        prepareReceiptDirectory: async () => {},
        executeLifecycle: async (invocation) => {
          calls.push(invocation);
          return invocation.mode === 'preview' ? previewResult() : result();
        },
      },
    );
    assert.equal(calls.length, 2);
    for (const invocation of calls) {
      if (authentication === 'service_token') {
        assert.equal(invocation.authentication, 'service_token');
      } else {
        assert.equal(Object.hasOwn(invocation, 'authentication'), false);
      }
      assert.equal(Object.hasOwn(invocation, 'serviceTokenId'), false);
      assert.equal(Object.hasOwn(invocation, 'clientId'), false);
      assert.equal(Object.hasOwn(invocation, 'clientSecret'), false);
    }
  }
});

test('profile invocation cannot override enrolled authentication or supply credentials', async () => {
  for (const override of [
    { authentication: 'email' },
    { authentication: 'service_token' },
    { serviceTokenId: 'must-not-escape' },
    { clientId: 'must-not-escape' },
    { clientSecret: 'must-not-escape' },
  ]) {
    let profileReads = 0;
    await assert.rejects(
      executeCanaryProfileLifecycleCommand(
        { mode: 'preview', profileId: PROFILE_ID, ...override },
        {
          readProfile: async () => {
            profileReads += 1;
            return profile({ authentication: 'service_token' });
          },
        },
      ),
      (error) => {
        assert.ok(error instanceof CanaryProfileCommandError);
        assert.equal(error.code, 'invalid_invocation');
        assert.doesNotMatch(error.message, /must-not-escape/);
        return true;
      },
    );
    assert.equal(profileReads, 0);
  }
});

test('an unsafe preview prevents run and is never retried', async () => {
  for (const unsafe of [
    previewResult({ writesPerformed: true }),
    previewResult({ approvalId: 'wrong' }),
    { ...previewResult(), exitCode: 3 },
  ]) {
    let calls = 0;
    await assert.rejects(
      executeCanaryProfileLifecycleCommand(
        { mode: 'run', profileId: PROFILE_ID },
        {
          readProfile: async () => profile(),
          prepareReceiptDirectory: async () => {},
          executeLifecycle: async () => {
            calls += 1;
            return unsafe;
          },
        },
      ),
      (error) => error instanceof CanaryProfileCommandError && error.code === 'preview_invalid',
    );
    assert.equal(calls, 1);
  }
});

test('profile and receipt preparation failures happen before lifecycle execution', async () => {
  let lifecycleCalls = 0;
  await assert.rejects(
    executeCanaryProfileLifecycleCommand(
      { mode: 'run', profileId: PROFILE_ID },
      {
        readProfile: async () => profile(),
        prepareReceiptDirectory: async () => { throw new Error('unavailable'); },
        executeLifecycle: async () => {
          lifecycleCalls += 1;
          return previewResult();
        },
      },
    ),
  );
  assert.equal(lifecycleCalls, 0);

  await assert.rejects(
    executeCanaryProfileLifecycleCommand(
      { mode: 'run', profileId: PROFILE_ID, receiptPath: RECEIPT },
      {
        readProfile: async () => profile(),
        prepareReceiptDirectory: async () => {},
        executeLifecycle: async () => previewResult(),
      },
    ),
    (error) => error instanceof CanaryProfileCommandError && error.code === 'invalid_invocation',
  );
});

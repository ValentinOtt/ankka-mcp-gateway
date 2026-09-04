import assert from 'node:assert/strict';
import test from 'node:test';

import {
  verifyBootstrapReceiptProviderState,
  verifyBootstrapReceiptProviderStateWithReason,
} from '../payload/worker/index.js';
import {
  BOOTSTRAP_GRANT,
  cloudflareProvider,
  goldenClaim,
  installReadyGateway,
  portalOnlyClaim,
  withProviderFetch,
} from './payload-lifecycle.mjs';

// The Stage 2 converger re-verifies the receipt right after the bootstrap
// answers ready, with a fresh claim (new request id and issue time) against
// the same provider state. This is the check that returned false on the
// live install of 2026-09-04.

test('the receipt verification accepts the receipt the bootstrap just wrote (portal with a source)', async () => {
  const provider = cloudflareProvider();
  const { env, storage } = await installReadyGateway({ provider, claimInput: goldenClaim() });
  const later = { ...goldenClaim('B'.repeat(22)), cloudflareAccessToken: BOOTSTRAP_GRANT };
  const verified = await withProviderFetch(provider.fetch, () =>
    verifyBootstrapReceiptProviderState(later, env, storage, Date.now()));
  assert.equal(verified, true);
});

test('the receipt verification accepts a portal-only receipt, as the live install had', async () => {
  const provider = cloudflareProvider();
  const claimInput = await portalOnlyClaim();
  const { env, storage } = await installReadyGateway({
    provider,
    claimInput,
    environmentBindings: { ANKKA_INSTALL_ID: claimInput.expected.installationId },
  });
  const later = { ...await portalOnlyClaim('B'.repeat(22)), cloudflareAccessToken: BOOTSTRAP_GRANT };
  const verified = await withProviderFetch(provider.fetch, () =>
    verifyBootstrapReceiptProviderState(later, env, storage, Date.now()));
  assert.equal(verified, true);
});

const emptyList = () => Response.json({ success: true, errors: [], messages: [], result: [] }, {
  headers: { 'content-type': 'application/json' },
});

test('the verification names the resource and status it disagrees on, with fixed words only', async () => {
  let hideDns = false;
  const provider = cloudflareProvider({
    onRequest: ({ request }) => {
      const url = new URL(request.url);
      if (hideDns && request.method === 'GET' && url.pathname.endsWith('/dns_records')) return emptyList();
      return undefined;
    },
  });
  const { env, storage } = await installReadyGateway({ provider, claimInput: goldenClaim() });
  const later = { ...goldenClaim('B'.repeat(22)), cloudflareAccessToken: BOOTSTRAP_GRANT };
  const intact = await withProviderFetch(provider.fetch, () =>
    verifyBootstrapReceiptProviderStateWithReason(later, env, storage, Date.now()));
  assert.deepEqual(intact, { verified: true, reason: null });
  hideDns = true;
  const vanished = await withProviderFetch(provider.fetch, () =>
    verifyBootstrapReceiptProviderStateWithReason(later, env, storage, Date.now()));
  assert.deepEqual(vanished, { verified: false, reason: 'dns_record_absent' });
  assert.match(vanished.reason, /^[a-z][a-z0-9_]{0,120}$/u);

  const empty = { get: async () => undefined };
  assert.deepEqual(await withProviderFetch(provider.fetch, () =>
    verifyBootstrapReceiptProviderStateWithReason(later, env, empty, Date.now())),
  { verified: false, reason: 'receipt_missing' });
  assert.deepEqual(await withProviderFetch(provider.fetch, () =>
    verifyBootstrapReceiptProviderStateWithReason({ ...later, expiresAt: later.issuedAt - 1 }, env, storage, Date.now())),
  { verified: false, reason: 'claim_invalid' });
  assert.deepEqual(await withProviderFetch(provider.fetch, () =>
    verifyBootstrapReceiptProviderStateWithReason(later, {}, storage, Date.now())),
  { verified: false, reason: 'environment_invalid' });
});

test('the verification reads an unsettled provider answer again before naming it, with its status', async () => {
  let appListFailures = 0;
  const provider = cloudflareProvider({
    onRequest: ({ request }) => {
      const url = new URL(request.url);
      if (request.method === 'GET' && url.pathname.endsWith('/access/apps') && appListFailures > 0) {
        appListFailures -= 1;
        return Response.json({ success: false, errors: [{ code: 10000, message: 'unsettled' }], messages: [], result: null }, {
          status: 500, headers: { 'content-type': 'application/json' },
        });
      }
      return undefined;
    },
  });
  // Portal-only, so the first application discovery is the portal's.
  const claimInput = await portalOnlyClaim();
  const { env, storage } = await installReadyGateway({
    provider,
    claimInput,
    environmentBindings: { ANKKA_INSTALL_ID: claimInput.expected.installationId },
  });
  const later = { ...await portalOnlyClaim('B'.repeat(22)), cloudflareAccessToken: BOOTSTRAP_GRANT };
  // One unsettled answer is read past.
  appListFailures = 1;
  assert.deepEqual(await withProviderFetch(provider.fetch, () =>
    verifyBootstrapReceiptProviderStateWithReason(later, env, storage, Date.now())),
  { verified: true, reason: null });
  // A provider that never settles is named with the last HTTP status and code.
  appListFailures = 99;
  assert.deepEqual(await withProviderFetch(provider.fetch, () =>
    verifyBootstrapReceiptProviderStateWithReason(later, env, storage, Date.now())),
  { verified: false, reason: 'portal_access_application_unknown_http_500_code_10000' });
});

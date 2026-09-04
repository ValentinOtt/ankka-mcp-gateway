import assert from 'node:assert/strict';
import test from 'node:test';

import {
  BOOTSTRAP_GRANT,
  cloudflareProvider,
  derivedBootstrapClaim,
  installReadyGateway,
} from './payload-lifecycle.mjs';

// Cloudflare refuses a resource id with two hyphens in a row (error 7001,
// "not valid ID format"). A portal hostname whose truncated key hint ends on
// a label boundary produced one; the sixth real install of 2026-09-04 stopped
// on it at the portal discovery. The payload and the hosted side derive the
// same keys, so the fixture's derivation stands in for the hosted side here.

test('the payload never writes a resource key with two hyphens in a row, and agrees with the hosted derivation', async () => {
  const hostname = 'mcpsixz.example.com';
  const claimInput = await derivedBootstrapClaim({
    schemaVersion: 1,
    connect: { name: 'Boundary Gateway', hostname, codeMode: 'default_on' },
    access: { adminEmails: ['admin@example.com'], memberEmails: ['owner@example.com'] },
    sources: [],
  }, 'A'.repeat(22), BOOTSTRAP_GRANT);
  const provider = cloudflareProvider();
  const { body, readyReceipt } = await installReadyGateway({
    provider,
    claimInput,
    environmentBindings: { ANKKA_INSTALL_ID: claimInput.expected.installationId },
  });
  assert.equal(body.status, 'ready');
  const keys = readyReceipt.resources.map((resource) => resource.key);
  assert.ok(keys.length >= 4, 'the receipt names every resource');
  for (const key of keys) {
    assert.doesNotMatch(key, /--/u, key);
    assert.match(key, /^[a-z-]+-[a-z0-9-]*[a-z0-9]-[a-f0-9]{8}$|^[a-z-]+-[a-f0-9]+$/u, key);
  }
  const portal = readyReceipt.resources.find((resource) => resource.kind === 'portal');
  assert.ok(portal, 'the receipt has the portal');
  assert.match(portal.key, /^portal-mcpsixz-example-[a-f0-9]{8}$/u);
});

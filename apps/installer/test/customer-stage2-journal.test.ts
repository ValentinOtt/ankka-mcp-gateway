import { describe, expect, it } from 'vitest';

import type { CustomerGatewayFreshPreflightAttestation } from
  '../src/cloudflare-gateway-fresh-preflight';
import {
  CUSTOMER_STAGE2_ACTION_ORDER,
  acquireCustomerStage2Lease,
  armCustomerStage2Action,
  completeCustomerStage2Journal,
  createCustomerStage2Journal,
  parseCustomerStage2Journal,
  prepareCustomerStage2Action,
  releaseCustomerStage2Lease,
  submitCustomerStage2Action,
  verifyCustomerStage2Action,
} from '../src/customer-stage2-journal';

const NOW = 1_800_000_000_000;
const ATTEMPT = `attempt_${'a'.repeat(24)}`;
const NEXT_ATTEMPT = `attempt_${'b'.repeat(24)}`;
const ACCOUNT_ID = 'c'.repeat(32);
const ZONE_ID = 'd'.repeat(32);
const INSTALL_ID = `acg-${'e'.repeat(24)}`;
const PLAN_ID = `plan-${'f'.repeat(24)}`;
const PLAN_HASH = `sha256:${'1'.repeat(64)}`;
const CONFIGURATION_HASH = `sha256:${'2'.repeat(64)}`;
const DESIRED_HASH = `sha256:${'3'.repeat(64)}`;
const RELEASE_HASH = '4'.repeat(64);

const preflight: CustomerGatewayFreshPreflightAttestation = {
  schemaVersion: 1,
  kind: 'customer_gateway_fresh_preflight',
  accountId: ACCOUNT_ID,
  zoneId: ZONE_ID,
  planId: PLAN_ID,
  planHash: PLAN_HASH,
  installationId: INSTALL_ID,
  configurationHash: CONFIGURATION_HASH,
  desiredHash: DESIRED_HASH,
  releaseId: 'gateway-v1.0.0',
  releaseArtifactSha256: RELEASE_HASH,
  zeroCandidateKinds: ['portal', 'portal_access_application', 'portal_access_policy', 'dns_record'],
  checkedAt: NOW - 1,
  expiresAt: NOW + 30_000,
  attestationHash: `sha256:${'5'.repeat(64)}`,
};

function initial() {
  return createCustomerStage2Journal({
    now: NOW,
    leaseExpiresAt: NOW + 300_000,
    attemptId: ATTEMPT,
    identity: {
      accountId: ACCOUNT_ID,
      zoneId: ZONE_ID,
      zoneName: 'example.com',
      installId: INSTALL_ID,
      planId: PLAN_ID,
      planHash: PLAN_HASH,
      configurationHash: CONFIGURATION_HASH,
      desiredHash: DESIRED_HASH,
      workerName: 'ankka-gateway-test-acg-eeeeeeeeeeeeeeeeeeeeeeee',
      workerId: '6'.repeat(32),
      namespaceId: '7'.repeat(32),
      bootstrapVersionId: '11111111-1111-4111-8111-111111111111',
      releaseId: 'gateway-v1.0.0',
      releaseArtifactSha256: RELEASE_HASH,
      finalRuntimeSha256: 'a'.repeat(64),
      updateChannel: 'stable',
      updateKeyId: 'release-key-v1',
      updatePublicKey: 'B'.repeat(43),
      ownershipReceiptSha256: `sha256:${'8'.repeat(64)}`,
    },
    organization: {
      name: 'Example team',
      authDomain: 'example.cloudflareaccess.com',
      issuer: 'https://example.cloudflareaccess.com',
    },
    identityProviderIds: ['idp-b', 'idp-a'],
    workersSubdomain: 'tenant',
    preflight,
  });
}

describe('customer Stage 2 convergence journal', () => {
  it('brackets every fixed mutation and completes only after terminal verification', () => {
    let journal = initial();
    expect(journal.identityProviderIds).toEqual(['idp-a', 'idp-b']);
    let now = NOW;
    for (const name of CUSTOMER_STAGE2_ACTION_ORDER) {
      journal = prepareCustomerStage2Action(journal, {
        attemptId: ATTEMPT,
        now: ++now,
        name,
        record: { schemaVersion: 1, kind: name, requestHash: `sha256:${'9'.repeat(64)}` },
      });
      journal = armCustomerStage2Action(journal, { attemptId: ATTEMPT, now: ++now, name });
      journal = submitCustomerStage2Action(journal, {
        attemptId: ATTEMPT,
        now: ++now,
        name,
        locator: { schemaVersion: 1, providerId: `${name}-id` },
      });
      journal = verifyCustomerStage2Action(journal, { attemptId: ATTEMPT, now: ++now, name });
    }
    expect(journal.actions).toHaveLength(CUSTOMER_STAGE2_ACTION_ORDER.length);
    expect(journal.completedAt).toBeNull();
    journal = completeCustomerStage2Journal(journal, { attemptId: ATTEMPT, now: ++now });
    expect(journal.completedAt).toBe(now);
    expect(journal.lease).toBeNull();
    expect(parseCustomerStage2Journal(JSON.parse(JSON.stringify(journal)))).toEqual(journal);
  });

  it('does not let a second attempt enter before lease expiry', () => {
    const journal = initial();
    expect(() => acquireCustomerStage2Lease(journal, {
      attemptId: NEXT_ATTEMPT,
      now: NOW + 1,
      leaseExpiresAt: NOW + 600_000,
    })).toThrowError(/conflict/u);
    const recovered = acquireCustomerStage2Lease(journal, {
      attemptId: NEXT_ATTEMPT,
      now: NOW + 300_001,
      leaseExpiresAt: NOW + 600_000,
    });
    expect(recovered.lease?.attemptId).toBe(NEXT_ATTEMPT);
  });

  it('releases a failed attempt without weakening the next ownership-bound lease', () => {
    const released = releaseCustomerStage2Lease(initial(), {
      attemptId: ATTEMPT,
      now: NOW + 1,
    });
    expect(released.lease).toBeNull();
    expect(released.revision).toBe(2);
    const recovered = acquireCustomerStage2Lease(released, {
      attemptId: NEXT_ATTEMPT,
      now: NOW + 2,
      leaseExpiresAt: NOW + 300_002,
    });
    expect(recovered.lease?.attemptId).toBe(NEXT_ATTEMPT);
    expect(() => releaseCustomerStage2Lease(recovered, {
      attemptId: ATTEMPT,
      now: NOW + 3,
    })).toThrowError(/conflict/u);
  });

  it('rejects out-of-order actions and credential-shaped durable fields', () => {
    const journal = initial();
    expect(() => prepareCustomerStage2Action(journal, {
      attemptId: ATTEMPT,
      now: NOW + 1,
      name: 'gateway_resources',
      record: { schemaVersion: 1 },
    })).toThrowError(/conflict/u);
    expect(() => prepareCustomerStage2Action(journal, {
      attemptId: ATTEMPT,
      now: NOW + 1,
      name: 'management_access_application',
      record: { accessToken: 'must-never-persist' },
    })).toThrowError(/invalid/u);
  });
});

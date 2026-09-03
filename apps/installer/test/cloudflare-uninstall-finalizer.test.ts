import {
  issueCloudflareBootstrapOwnershipHandoff,
  proveCloudflareBootstrapOwnershipAdoption,
  verifyCloudflareBootstrapOwnershipHandoff,
  type CloudflareBootstrapOwnershipAdoptionReceipt,
  type CloudflareBootstrapOwnershipHandoffDraft,
  type CloudflareBootstrapOwnershipProviderReadback,
} from '../src/cloudflare-bootstrap-ownership-handoff';
import {
  authorizeCloudflareUninstallFinalizer,
  CLOUDFLARE_UNINSTALL_FINALIZER_READBACK_MAX_AGE_MS,
  type CloudflareUninstallFinalizerAuthorizationInput,
  type CloudflareUninstallFinalizerProviderReadback,
  type CloudflareUninstallFinalizerTombstone,
} from '../src/cloudflare-uninstall-finalizer';
import { base64UrlEncode } from '../src/crypto';

const HANDOFF_NOW = 2_000_000_000_000;
const FINALIZER_NOW = HANDOFF_NOW + 86_400_000;
const ACCOUNT_ID = 'a'.repeat(32);
const INSTALL_ID = `acg-${'b'.repeat(24)}`;
const WORKER_ID = 'c'.repeat(32);
const NAMESPACE_ID = 'd'.repeat(32);
const READY_CHECKSUM = `sha256:${'e'.repeat(64)}`;
const FINALIZER_NONCE = base64UrlEncode(new Uint8Array(32).fill(7));
const INERT_RELEASE = Object.freeze({
  id: 'gateway-v9.9.9',
  artifactSha256: 'f'.repeat(64),
});

function handoffDraft(): CloudflareBootstrapOwnershipHandoffDraft {
  return {
    accountId: ACCOUNT_ID,
    adminState: {
      binding: 'ADMIN_STATE',
      className: 'AdminState',
      namespaceId: NAMESPACE_ID,
      storage: 'sqlite',
      workerProviderId: WORKER_ID,
    },
    bootstrapSecret: {
      commitment: `sha256:${'1'.repeat(64)}`,
      expiresAt: HANDOFF_NOW + 60_000,
    },
    expiresAt: HANDOFF_NOW + 120_000,
    installId: INSTALL_ID,
    issuedAt: HANDOFF_NOW,
    plan: { id: `plan-${'3'.repeat(24)}`, hash: `sha256:${'4'.repeat(64)}` },
    release: {
      id: 'gateway-v1.2.3',
      artifactSha256: '2'.repeat(64),
    },
    worker: {
      name: 'ankka-gateway-finalizer-fixture',
      providerId: WORKER_ID,
    },
  };
}

async function fixture(): Promise<{
  adoption: CloudflareBootstrapOwnershipAdoptionReceipt;
  handoff: string;
  publicKey: string;
}> {
  const keys = await crypto.subtle.generateKey('Ed25519', true, ['sign', 'verify']);
  const publicKey = base64UrlEncode(
    new Uint8Array(await crypto.subtle.exportKey('raw', keys.publicKey)),
  );
  const handoff = await issueCloudflareBootstrapOwnershipHandoff(
    handoffDraft(),
    keys.privateKey,
  );
  const statement = (await verifyCloudflareBootstrapOwnershipHandoff({
    now: HANDOFF_NOW + 1,
    pinnedPublicKey: publicKey,
    serializedHandoff: handoff,
  })).statement;
  const readback: CloudflareBootstrapOwnershipProviderReadback = {
    accountId: statement.accountId,
    adminState: statement.adminState,
    bootstrapSecret: statement.bootstrapSecret,
    handoff: {
      expiresAt: statement.expiresAt,
      issuedAt: statement.issuedAt,
      nonce: statement.nonce,
    },
    installId: statement.installId,
    observedAt: HANDOFF_NOW + 5_000,
    plan: statement.plan,
    purpose: 'cloudflare_bootstrap_ownership_provider_readback',
    release: statement.release,
    schemaVersion: 2,
    worker: statement.worker,
  };
  const adoption = await proveCloudflareBootstrapOwnershipAdoption({
    now: HANDOFF_NOW + 5_000,
    pinnedPublicKey: publicKey,
    providerReadback: readback,
    serializedHandoff: handoff,
  });
  return { adoption, handoff, publicKey };
}

function tombstone(
  adoption: CloudflareBootstrapOwnershipAdoptionReceipt,
): CloudflareUninstallFinalizerTombstone {
  return {
    accountId: adoption.accountId,
    expiresAt: FINALIZER_NOW + 60_000,
    finalizerNonce: FINALIZER_NONCE,
    handoffNonce: adoption.handoff.nonce,
    inertRelease: INERT_RELEASE,
    installId: adoption.installId,
    issuedAt: FINALIZER_NOW - 1,
    lifecycle: {
      adminStateRetired: true,
      customerGrantRevocation: 'confirmed',
      dependentReceiptResourcesAbsent: true,
      foreignResourcesUnchanged: true,
      workersDevDisabled: true,
    },
    purpose: 'cloudflare_uninstall_finalizer_tombstone',
    readyReceiptChecksum: READY_CHECKSUM,
    root: {
      worker: {
        name: adoption.ownership.worker.name,
        providerId: adoption.ownership.worker.providerId,
      },
      adminStateNamespace: {
        providerId: adoption.ownership.adminStateNamespace.providerId,
      },
    },
    schemaVersion: 1,
  };
}

function providerReadback(
  adoption: CloudflareBootstrapOwnershipAdoptionReceipt,
): CloudflareUninstallFinalizerProviderReadback {
  return {
    accountId: adoption.accountId,
    activeRelease: INERT_RELEASE,
    adminStateClassPresent: false,
    installId: adoption.installId,
    observedAt: FINALIZER_NOW,
    purpose: 'cloudflare_uninstall_finalizer_provider_readback',
    root: {
      worker: {
        name: adoption.ownership.worker.name,
        providerId: adoption.ownership.worker.providerId,
      },
      adminStateNamespace: {
        providerId: adoption.ownership.adminStateNamespace.providerId,
      },
    },
    schemaVersion: 1,
    workersDevEnabled: false,
  };
}

async function authorize(
  overrides: Partial<CloudflareUninstallFinalizerAuthorizationInput> = {},
) {
  const prepared = await fixture();
  return authorizeCloudflareUninstallFinalizer({
    now: FINALIZER_NOW,
    pinnedHandoffPublicKey: prepared.publicKey,
    serializedOwnershipHandoff: prepared.handoff,
    ownershipAdoptionReceipt: prepared.adoption,
    expectedReadyReceiptChecksum: READY_CHECKSUM,
    expectedFinalizerNonce: FINALIZER_NONCE,
    customerTombstone: tombstone(prepared.adoption),
    providerReadback: providerReadback(prepared.adoption),
    ...overrides,
  });
}

describe('hosted Cloudflare uninstall finalizer', () => {
  it('emits only the exact adopted root deletions', async () => {
    const intent = await authorize();
    expect(intent).toMatchObject({
      accountId: ACCOUNT_ID,
      installId: INSTALL_ID,
      readyReceiptChecksum: READY_CHECKSUM,
      inertRelease: INERT_RELEASE,
      deletionOrder: [
        { kind: 'cloudflare_durable_object_namespace', providerId: NAMESPACE_ID },
        {
          kind: 'cloudflare_worker',
          name: 'ankka-gateway-finalizer-fixture',
          providerId: WORKER_ID,
        },
      ],
      mustReverifyExactRootBeforeEachDelete: true,
    });
    expect(Object.isFrozen(intent)).toBe(true);
    expect(Object.isFrozen(intent.deletionOrder)).toBe(true);
    expect(JSON.stringify(intent)).not.toContain('access_application');
    expect(JSON.stringify(intent)).not.toContain('dns_record');
  });

  it('requires the trusted ready-receipt checksum and fresh finalizer nonce', async () => {
    await expect(authorize({
      expectedReadyReceiptChecksum: `sha256:${'3'.repeat(64)}`,
    })).rejects.toMatchObject({ code: 'receipt_mismatch' });
    await expect(authorize({
      expectedFinalizerNonce: base64UrlEncode(new Uint8Array(32).fill(8)),
    })).rejects.toMatchObject({ code: 'ownership_mismatch' });
  });

  it('rejects a different root, stale readback, or non-confirmed lifecycle', async () => {
    const prepared = await fixture();
    const validReadback = providerReadback(prepared.adoption);
    const differentRoot: CloudflareUninstallFinalizerProviderReadback = {
      ...validReadback,
      root: {
        ...validReadback.root,
        worker: {
          name: prepared.adoption.ownership.worker.name,
          providerId: '4'.repeat(32),
        },
      },
    };
    await expect(authorize({ providerReadback: differentRoot })).rejects.toMatchObject({
      code: 'ownership_mismatch',
    });

    await expect(authorize({
      providerReadback: {
        ...providerReadback(prepared.adoption),
        observedAt: FINALIZER_NOW - CLOUDFLARE_UNINSTALL_FINALIZER_READBACK_MAX_AGE_MS - 1,
      },
    })).rejects.toMatchObject({ code: 'readback_stale' });

    const validTombstone = tombstone(prepared.adoption);
    const notRevoked = {
      ...validTombstone,
      lifecycle: {
        ...validTombstone.lifecycle,
        customerGrantRevocation: 'unconfirmed',
      },
    };
    await expect(authorize({ customerTombstone: notRevoked })).rejects.toMatchObject({
      code: 'invalid',
    });
  });

  it('rejects forged historical adoption evidence', async () => {
    const prepared = await fixture();
    await expect(authorize({
      ownershipAdoptionReceipt: {
        ...prepared.adoption,
        ownership: {
          ...prepared.adoption.ownership,
          worker: {
            ...prepared.adoption.ownership.worker,
            providerId: '5'.repeat(32),
          },
        },
      },
    })).rejects.toMatchObject({ code: 'ownership_mismatch' });
  });
});

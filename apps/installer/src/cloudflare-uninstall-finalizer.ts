import * as v from 'valibot';

import {
  verifyCloudflareBootstrapOwnershipHistory,
  type CloudflareBootstrapOwnershipAdoptionReceipt,
} from './cloudflare-bootstrap-ownership-handoff';
import type { BoundaryValue } from './boundary';
import { deepFreezePlainData, isPlainDataTree } from './plain-data';

const ACCOUNT_ID = /^[a-f0-9]{32}$/u;
const INSTALL_ID = /^acg-[a-f0-9]{24}$/u;
const WORKER_NAME = /^[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$/u;
const PROVIDER_ID = /^[a-f0-9]{32}$/u;
const RELEASE_ID = /^gateway-v(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)$/u;
const SHA256 = /^[a-f0-9]{64}$/u;
const SHA256_COMMITMENT = /^sha256:[a-f0-9]{64}$/u;
const TOKEN = /^[A-Za-z0-9_-]{43}$/u;

export const CLOUDFLARE_UNINSTALL_FINALIZER_SCHEMA_VERSION = 1 as const;
export const CLOUDFLARE_UNINSTALL_FINALIZER_TTL_MS = 5 * 60 * 1_000;
export const CLOUDFLARE_UNINSTALL_FINALIZER_READBACK_MAX_AGE_MS = 30_000;

const timestampSchema = v.pipe(v.number(), v.safeInteger(), v.minValue(0));
const accountIdSchema = v.pipe(v.string(), v.regex(ACCOUNT_ID));
const installIdSchema = v.pipe(v.string(), v.regex(INSTALL_ID));
const providerIdSchema = v.pipe(v.string(), v.regex(PROVIDER_ID));
const releaseSchema = v.strictObject({
  id: v.pipe(v.string(), v.regex(RELEASE_ID)),
  artifactSha256: v.pipe(v.string(), v.regex(SHA256)),
});
const rootSchema = v.strictObject({
  worker: v.strictObject({
    name: v.pipe(v.string(), v.regex(WORKER_NAME)),
    providerId: providerIdSchema,
  }),
  adminStateNamespace: v.strictObject({ providerId: providerIdSchema }),
});
const tombstoneSchema = v.strictObject({
  accountId: accountIdSchema,
  expiresAt: timestampSchema,
  finalizerNonce: v.pipe(v.string(), v.regex(TOKEN)),
  handoffNonce: v.pipe(v.string(), v.regex(TOKEN)),
  inertRelease: releaseSchema,
  installId: installIdSchema,
  issuedAt: timestampSchema,
  lifecycle: v.strictObject({
    adminStateRetired: v.literal(true),
    customerGrantRevocation: v.literal('confirmed'),
    dependentReceiptResourcesAbsent: v.literal(true),
    foreignResourcesUnchanged: v.literal(true),
    workersDevDisabled: v.literal(true),
  }),
  purpose: v.literal('cloudflare_uninstall_finalizer_tombstone'),
  readyReceiptChecksum: v.pipe(v.string(), v.regex(SHA256_COMMITMENT)),
  root: rootSchema,
  schemaVersion: v.literal(CLOUDFLARE_UNINSTALL_FINALIZER_SCHEMA_VERSION),
});
const providerReadbackSchema = v.strictObject({
  accountId: accountIdSchema,
  activeRelease: releaseSchema,
  adminStateClassPresent: v.literal(false),
  installId: installIdSchema,
  observedAt: timestampSchema,
  purpose: v.literal('cloudflare_uninstall_finalizer_provider_readback'),
  root: rootSchema,
  schemaVersion: v.literal(CLOUDFLARE_UNINSTALL_FINALIZER_SCHEMA_VERSION),
  workersDevEnabled: v.literal(false),
});

export type CloudflareUninstallFinalizerTombstone = v.InferOutput<typeof tombstoneSchema>;
export type CloudflareUninstallFinalizerProviderReadback =
  v.InferOutput<typeof providerReadbackSchema>;

export interface CloudflareUninstallFinalizerIntent {
  readonly accountId: string;
  readonly installId: string;
  readonly readyReceiptChecksum: string;
  readonly inertRelease: {
    readonly id: string;
    readonly artifactSha256: string;
  };
  readonly deletionOrder: readonly [
    Readonly<{
      kind: 'cloudflare_durable_object_namespace';
      providerId: string;
    }>,
    Readonly<{
      kind: 'cloudflare_worker';
      name: string;
      providerId: string;
    }>,
  ];
  readonly verifiedAt: number;
  readonly expiresAt: number;
  readonly mustReverifyExactRootBeforeEachDelete: true;
}

export type CloudflareUninstallFinalizerErrorCode =
  | 'expired'
  | 'invalid'
  | 'ownership_mismatch'
  | 'readback_stale'
  | 'receipt_mismatch';

export class CloudflareUninstallFinalizerError extends Error {
  constructor(readonly code: CloudflareUninstallFinalizerErrorCode) {
    super(code);
    this.name = 'CloudflareUninstallFinalizerError';
  }
}

function fail(code: CloudflareUninstallFinalizerErrorCode = 'invalid'): never {
  throw new CloudflareUninstallFinalizerError(code);
}

function sameRoot(
  ownership: CloudflareBootstrapOwnershipAdoptionReceipt['ownership'],
  tombstone: CloudflareUninstallFinalizerTombstone,
  readback: CloudflareUninstallFinalizerProviderReadback,
): boolean {
  const worker = ownership.worker;
  const namespace = ownership.adminStateNamespace;
  return tombstone.root.worker.name === worker.name &&
    tombstone.root.worker.providerId === worker.providerId &&
    tombstone.root.adminStateNamespace.providerId === namespace.providerId &&
    readback.root.worker.name === worker.name &&
    readback.root.worker.providerId === worker.providerId &&
    readback.root.adminStateNamespace.providerId === namespace.providerId;
}

/**
 * Produces the only two root deletions the hosted finalizer may perform. The
 * caller supplies the pinned historical handoff, a trusted journal checksum,
 * a fresh one-time nonce, and provider reads assembled by the fixed finalizer.
 * No caller-provided resource list is accepted.
 */
export interface CloudflareUninstallFinalizerAuthorizationInput {
  readonly now: number;
  readonly pinnedHandoffPublicKey: string;
  readonly serializedOwnershipHandoff: string;
  readonly ownershipAdoptionReceipt: CloudflareBootstrapOwnershipAdoptionReceipt;
  readonly expectedReadyReceiptChecksum: string;
  readonly expectedFinalizerNonce: string;
  readonly customerTombstone: BoundaryValue;
  readonly providerReadback: BoundaryValue;
}

export async function authorizeCloudflareUninstallFinalizer(
  input: CloudflareUninstallFinalizerAuthorizationInput,
): Promise<CloudflareUninstallFinalizerIntent> {
  if (!Number.isSafeInteger(input.now) || input.now < 0 ||
      !SHA256_COMMITMENT.test(input.expectedReadyReceiptChecksum) ||
      !TOKEN.test(input.expectedFinalizerNonce)) fail();
  let ownership: CloudflareBootstrapOwnershipAdoptionReceipt;
  try {
    ownership = await verifyCloudflareBootstrapOwnershipHistory({
      adoptionReceipt: input.ownershipAdoptionReceipt,
      pinnedPublicKey: input.pinnedHandoffPublicKey,
      serializedHandoff: input.serializedOwnershipHandoff,
    });
  } catch {
    fail('ownership_mismatch');
  }
  if (!isPlainDataTree(input.customerTombstone) || !isPlainDataTree(input.providerReadback)) fail();
  const tombstoneResult = v.safeParse(tombstoneSchema, input.customerTombstone);
  const readbackResult = v.safeParse(providerReadbackSchema, input.providerReadback);
  if (!tombstoneResult.success || !readbackResult.success) fail();
  const tombstone = tombstoneResult.output;
  const readback = readbackResult.output;
  if (tombstone.expiresAt <= tombstone.issuedAt ||
      tombstone.expiresAt - tombstone.issuedAt > CLOUDFLARE_UNINSTALL_FINALIZER_TTL_MS ||
      input.now < tombstone.issuedAt || input.now >= tombstone.expiresAt) fail('expired');
  if (readback.observedAt > input.now ||
      input.now - readback.observedAt > CLOUDFLARE_UNINSTALL_FINALIZER_READBACK_MAX_AGE_MS) {
    fail('readback_stale');
  }
  if (tombstone.readyReceiptChecksum !== input.expectedReadyReceiptChecksum) {
    fail('receipt_mismatch');
  }
  if (tombstone.finalizerNonce !== input.expectedFinalizerNonce ||
      tombstone.handoffNonce !== ownership.handoff.nonce ||
      tombstone.accountId !== ownership.accountId || tombstone.installId !== ownership.installId ||
      readback.accountId !== ownership.accountId || readback.installId !== ownership.installId ||
      !sameRoot(ownership.ownership, tombstone, readback)) fail('ownership_mismatch');
  if (readback.activeRelease.id !== tombstone.inertRelease.id ||
      readback.activeRelease.artifactSha256 !== tombstone.inertRelease.artifactSha256) {
    fail('ownership_mismatch');
  }

  return deepFreezePlainData({
    accountId: ownership.accountId,
    installId: ownership.installId,
    readyReceiptChecksum: tombstone.readyReceiptChecksum,
    inertRelease: tombstone.inertRelease,
    deletionOrder: [
      {
        kind: 'cloudflare_durable_object_namespace' as const,
        providerId: ownership.ownership.adminStateNamespace.providerId,
      },
      {
        kind: 'cloudflare_worker' as const,
        name: ownership.ownership.worker.name,
        providerId: ownership.ownership.worker.providerId,
      },
    ] as const,
    verifiedAt: input.now,
    expiresAt: tombstone.expiresAt,
    mustReverifyExactRootBeforeEachDelete: true as const,
  });
}

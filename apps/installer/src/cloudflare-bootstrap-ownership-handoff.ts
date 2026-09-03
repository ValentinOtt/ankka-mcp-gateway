import * as v from 'valibot';

import { canonicalJson } from './canonical-json';
import { deepFreezePlainData, isPlainDataTree } from './plain-data';

const ACCOUNT_ID = /^[a-f0-9]{32}$/u;
const INSTALL_ID = /^acg-[a-f0-9]{24}$/u;
const WORKER_NAME = /^[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$/u;
const PROVIDER_ID = /^[a-f0-9]{32}$/u;
const RELEASE_ID = /^gateway-v(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)$/u;
const SHA256 = /^[a-f0-9]{64}$/u;
const SHA256_COMMITMENT = /^sha256:[a-f0-9]{64}$/u;
const PLAN_ID = /^plan-[a-f0-9]{24}$/u;
const NONCE = /^[A-Za-z0-9_-]{43}$/u;
const PUBLIC_KEY = /^[A-Za-z0-9_-]{43}$/u;
const SIGNATURE = /^[A-Za-z0-9_-]{86}$/u;
const MAX_ENVELOPE_CHARACTERS = 8_192;
const MAX_STATEMENT_CHARACTERS = 4_096;

export const CLOUDFLARE_BOOTSTRAP_OWNERSHIP_HANDOFF_SCHEMA_VERSION = 2 as const;
export const CLOUDFLARE_BOOTSTRAP_OWNERSHIP_HANDOFF_PURPOSE =
  'cloudflare_bootstrap_ownership_handoff' as const;
export const CLOUDFLARE_BOOTSTRAP_OWNERSHIP_HANDOFF_ENVELOPE_PURPOSE =
  'cloudflare_bootstrap_ownership_handoff_envelope' as const;
export const CLOUDFLARE_BOOTSTRAP_OWNERSHIP_HANDOFF_SIGNATURE_CONTEXT =
  'ankka-cloudflare-bootstrap-ownership-handoff-v2' as const;
export const CLOUDFLARE_BOOTSTRAP_OWNERSHIP_HANDOFF_MAX_TTL_MS = 10 * 60 * 1_000;
export const CLOUDFLARE_BOOTSTRAP_PROVIDER_READBACK_MAX_AGE_MS = 30_000;

const timestampSchema = v.pipe(v.number(), v.safeInteger(), v.minValue(0));
const serializedEnvelopeSchema = v.pipe(
  v.string(),
  v.minLength(1),
  v.maxLength(MAX_ENVELOPE_CHARACTERS),
);
const accountIdSchema = v.pipe(v.string(), v.regex(ACCOUNT_ID));
const installIdSchema = v.pipe(v.string(), v.regex(INSTALL_ID));
const workerNameSchema = v.pipe(v.string(), v.regex(WORKER_NAME));
const providerIdSchema = v.pipe(v.string(), v.regex(PROVIDER_ID));
const releaseSchema = v.strictObject({
  id: v.pipe(v.string(), v.regex(RELEASE_ID)),
  artifactSha256: v.pipe(v.string(), v.regex(SHA256)),
});
const planSchema = v.strictObject({
  id: v.pipe(v.string(), v.regex(PLAN_ID)),
  hash: v.pipe(v.string(), v.regex(SHA256_COMMITMENT)),
});
const workerSchema = v.strictObject({
  name: workerNameSchema,
  providerId: providerIdSchema,
});
const adminStateSchema = v.strictObject({
  binding: v.literal('ADMIN_STATE'),
  className: v.literal('AdminState'),
  namespaceId: providerIdSchema,
  storage: v.literal('sqlite'),
  workerProviderId: providerIdSchema,
});
const bootstrapSecretSchema = v.strictObject({
  commitment: v.pipe(v.string(), v.regex(SHA256_COMMITMENT)),
  expiresAt: timestampSchema,
});
const handoffDraftSchema = v.strictObject({
  accountId: accountIdSchema,
  adminState: adminStateSchema,
  bootstrapSecret: bootstrapSecretSchema,
  expiresAt: timestampSchema,
  installId: installIdSchema,
  issuedAt: timestampSchema,
  plan: planSchema,
  release: releaseSchema,
  worker: workerSchema,
});
const handoffStatementSchema = v.strictObject({
  accountId: accountIdSchema,
  adminState: adminStateSchema,
  bootstrapSecret: bootstrapSecretSchema,
  expiresAt: timestampSchema,
  installId: installIdSchema,
  issuedAt: timestampSchema,
  nonce: v.pipe(v.string(), v.regex(NONCE)),
  purpose: v.literal(CLOUDFLARE_BOOTSTRAP_OWNERSHIP_HANDOFF_PURPOSE),
  plan: planSchema,
  release: releaseSchema,
  schemaVersion: v.literal(CLOUDFLARE_BOOTSTRAP_OWNERSHIP_HANDOFF_SCHEMA_VERSION),
  worker: workerSchema,
});
const handoffEnvelopeSchema = v.strictObject({
  purpose: v.literal(CLOUDFLARE_BOOTSTRAP_OWNERSHIP_HANDOFF_ENVELOPE_PURPOSE),
  schemaVersion: v.literal(CLOUDFLARE_BOOTSTRAP_OWNERSHIP_HANDOFF_SCHEMA_VERSION),
  signature: v.pipe(v.string(), v.regex(SIGNATURE)),
  signatureContext: v.literal(CLOUDFLARE_BOOTSTRAP_OWNERSHIP_HANDOFF_SIGNATURE_CONTEXT),
  statement: v.pipe(v.string(), v.minLength(1), v.maxLength(MAX_STATEMENT_CHARACTERS)),
});
const providerReadbackSchema = v.strictObject({
  accountId: accountIdSchema,
  adminState: adminStateSchema,
  bootstrapSecret: bootstrapSecretSchema,
  handoff: v.strictObject({
    expiresAt: timestampSchema,
    issuedAt: timestampSchema,
    nonce: v.pipe(v.string(), v.regex(NONCE)),
  }),
  installId: installIdSchema,
  observedAt: timestampSchema,
  purpose: v.literal('cloudflare_bootstrap_ownership_provider_readback'),
  plan: planSchema,
  release: releaseSchema,
  schemaVersion: v.literal(CLOUDFLARE_BOOTSTRAP_OWNERSHIP_HANDOFF_SCHEMA_VERSION),
  worker: workerSchema,
});
const adoptionReceiptSchema = v.strictObject({
  adoptedAt: timestampSchema,
  accountId: accountIdSchema,
  handoff: v.strictObject({
    expiresAt: timestampSchema,
    issuedAt: timestampSchema,
    nonce: v.pipe(v.string(), v.regex(NONCE)),
  }),
  installId: installIdSchema,
  ownership: v.strictObject({
    worker: v.strictObject({
      kind: v.literal('cloudflare_worker'),
      name: workerNameSchema,
      providerId: providerIdSchema,
    }),
    adminStateNamespace: v.strictObject({
      binding: v.literal('ADMIN_STATE'),
      className: v.literal('AdminState'),
      kind: v.literal('cloudflare_durable_object_namespace'),
      providerId: providerIdSchema,
      storage: v.literal('sqlite'),
      workerProviderId: providerIdSchema,
    }),
  }),
  providerReadAt: timestampSchema,
  purpose: v.literal('cloudflare_bootstrap_ownership_adoption_receipt'),
  plan: planSchema,
  release: releaseSchema,
  schemaVersion: v.literal(CLOUDFLARE_BOOTSTRAP_OWNERSHIP_HANDOFF_SCHEMA_VERSION),
});

type ParsedHandoffStatement = v.InferOutput<typeof handoffStatementSchema>;
type ParsedProviderReadback = v.InferOutput<typeof providerReadbackSchema>;

interface ParsedCanonicalHandoffEnvelope {
  readonly signature: string;
  readonly statement: ParsedHandoffStatement;
  readonly serializedStatement: string;
}

export interface CloudflareBootstrapOwnershipHandoffDraft {
  readonly accountId: string;
  readonly adminState: {
    readonly binding: 'ADMIN_STATE';
    readonly className: 'AdminState';
    readonly namespaceId: string;
    readonly storage: 'sqlite';
    /** Immutable Cloudflare Worker ID to which this namespace was observed attached. */
    readonly workerProviderId: string;
  };
  readonly bootstrapSecret: {
    /** SHA-256 commitment. The secret itself is never carried here. */
    readonly commitment: string;
    readonly expiresAt: number;
  };
  readonly expiresAt: number;
  readonly installId: string;
  readonly issuedAt: number;
  readonly plan: {
    readonly id: string;
    readonly hash: string;
  };
  readonly release: {
    readonly id: string;
    /** Exact aggregate release artifact SHA-256, without a prefix. */
    readonly artifactSha256: string;
  };
  readonly worker: {
    /** A create-only name asserted fresh by Stage 1; never sufficient ownership evidence alone. */
    readonly name: string;
    /** Immutable Worker provider ID returned by Cloudflare after creation. */
    readonly providerId: string;
  };
}

export interface CloudflareBootstrapOwnershipHandoffStatement
  extends CloudflareBootstrapOwnershipHandoffDraft {
  readonly nonce: string;
  readonly purpose: typeof CLOUDFLARE_BOOTSTRAP_OWNERSHIP_HANDOFF_PURPOSE;
  readonly schemaVersion: typeof CLOUDFLARE_BOOTSTRAP_OWNERSHIP_HANDOFF_SCHEMA_VERSION;
}

export interface VerifiedCloudflareBootstrapOwnershipHandoff {
  readonly statement: CloudflareBootstrapOwnershipHandoffStatement;
  readonly verification: 'ed25519';
}

export interface CloudflareBootstrapOwnershipProviderReadback {
  readonly accountId: string;
  readonly adminState: CloudflareBootstrapOwnershipHandoffDraft['adminState'];
  readonly bootstrapSecret: CloudflareBootstrapOwnershipHandoffDraft['bootstrapSecret'];
  readonly handoff: {
    readonly expiresAt: number;
    readonly issuedAt: number;
    readonly nonce: string;
  };
  readonly installId: string;
  /** Time at which the caller completed fresh Cloudflare management API reads. */
  readonly observedAt: number;
  readonly purpose: 'cloudflare_bootstrap_ownership_provider_readback';
  readonly plan: CloudflareBootstrapOwnershipHandoffDraft['plan'];
  readonly release: CloudflareBootstrapOwnershipHandoffDraft['release'];
  readonly schemaVersion: typeof CLOUDFLARE_BOOTSTRAP_OWNERSHIP_HANDOFF_SCHEMA_VERSION;
  readonly worker: CloudflareBootstrapOwnershipHandoffDraft['worker'];
}

export interface CloudflareBootstrapOwnershipAdoptionReceipt {
  readonly adoptedAt: number;
  readonly accountId: string;
  readonly handoff: {
    readonly expiresAt: number;
    readonly issuedAt: number;
    readonly nonce: string;
  };
  readonly installId: string;
  readonly ownership: {
    readonly worker: {
      readonly kind: 'cloudflare_worker';
      readonly name: string;
      readonly providerId: string;
    };
    readonly adminStateNamespace: {
      readonly binding: 'ADMIN_STATE';
      readonly className: 'AdminState';
      readonly kind: 'cloudflare_durable_object_namespace';
      readonly providerId: string;
      readonly storage: 'sqlite';
      readonly workerProviderId: string;
    };
  };
  readonly providerReadAt: number;
  readonly purpose: 'cloudflare_bootstrap_ownership_adoption_receipt';
  readonly plan: CloudflareBootstrapOwnershipHandoffDraft['plan'];
  readonly release: CloudflareBootstrapOwnershipHandoffDraft['release'];
  readonly schemaVersion: typeof CLOUDFLARE_BOOTSTRAP_OWNERSHIP_HANDOFF_SCHEMA_VERSION;
}

export type CloudflareBootstrapOwnershipHandoffErrorCode =
  | 'expired'
  | 'identity_mismatch'
  | 'invalid'
  | 'invalid_signature'
  | 'not_yet_valid'
  | 'receipt_mismatch'
  | 'provider_readback_stale';

export class CloudflareBootstrapOwnershipHandoffError extends Error {
  constructor(readonly code: CloudflareBootstrapOwnershipHandoffErrorCode) {
    super(code);
    this.name = 'CloudflareBootstrapOwnershipHandoffError';
  }
}

function fail(code: CloudflareBootstrapOwnershipHandoffErrorCode = 'invalid'): never {
  throw new CloudflareBootstrapOwnershipHandoffError(code);
}

function base64UrlEncode(bytes: Uint8Array): string {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/u, '');
}

function base64UrlDecode(value: string, expectedByteLength: number): Uint8Array<ArrayBuffer> {
  if (!/^[A-Za-z0-9_-]+$/u.test(value)) fail();
  const padded = value.replaceAll('-', '+').replaceAll('_', '/') +
    '='.repeat((4 - (value.length % 4)) % 4);
  let binary: string;
  try {
    binary = atob(padded);
  } catch {
    fail();
  }
  const bytes = new Uint8Array(new ArrayBuffer(binary.length));
  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }
  if (bytes.byteLength !== expectedByteLength || base64UrlEncode(bytes) !== value) fail();
  return bytes;
}

function parsePlainStrict<
  Input,
  Schema extends v.BaseSchema<unknown, unknown, v.BaseIssue<unknown>>,
>(
  schema: Schema,
  input: Input,
): v.InferOutput<Schema> {
  if (!isPlainDataTree(input)) fail();
  const parsed = v.safeParse(schema, input);
  if (!parsed.success) fail();
  return parsed.output;
}

function validateStatementLifetime(statement: Pick<
  ParsedHandoffStatement,
  'bootstrapSecret' | 'expiresAt' | 'issuedAt'
>): void {
  if (
    statement.expiresAt <= statement.issuedAt ||
    statement.expiresAt - statement.issuedAt >
      CLOUDFLARE_BOOTSTRAP_OWNERSHIP_HANDOFF_MAX_TTL_MS ||
    statement.bootstrapSecret.expiresAt <= statement.issuedAt ||
    statement.bootstrapSecret.expiresAt > statement.expiresAt
  ) fail();
}

function validateOwnershipGraph(statement: Pick<
  ParsedHandoffStatement,
  'adminState' | 'worker'
>): void {
  if (statement.adminState.workerProviderId !== statement.worker.providerId) fail();
}

function validateNonce(nonce: string): void {
  base64UrlDecode(nonce, 32);
}

function signaturePayload(statement: string): string {
  return canonicalJson({
    purpose: CLOUDFLARE_BOOTSTRAP_OWNERSHIP_HANDOFF_ENVELOPE_PURPOSE,
    schemaVersion: CLOUDFLARE_BOOTSTRAP_OWNERSHIP_HANDOFF_SCHEMA_VERSION,
    signatureContext: CLOUDFLARE_BOOTSTRAP_OWNERSHIP_HANDOFF_SIGNATURE_CONTEXT,
    statement,
  });
}

function validEd25519PrivateKey(key: CryptoKey): boolean {
  return key.type === 'private' && key.algorithm.name === 'Ed25519' && key.usages.includes('sign');
}

/** Generate the nonce bound into every issued handoff. */
export function randomCloudflareBootstrapOwnershipHandoffNonce(): string {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return base64UrlEncode(bytes);
}

/**
 * Create the canonical, Ed25519-signed Stage-1 handoff. The private key stays
 * with the issuer; the serialized envelope deliberately carries no verifier.
 */
export async function issueCloudflareBootstrapOwnershipHandoff(
  input: CloudflareBootstrapOwnershipHandoffDraft,
  signingPrivateKey: CryptoKey,
): Promise<string> {
  const draft = parsePlainStrict(handoffDraftSchema, input);
  validateStatementLifetime(draft);
  validateOwnershipGraph(draft);
  if (!validEd25519PrivateKey(signingPrivateKey)) fail();

  const statement: CloudflareBootstrapOwnershipHandoffStatement = {
    accountId: draft.accountId,
    adminState: draft.adminState,
    bootstrapSecret: draft.bootstrapSecret,
    expiresAt: draft.expiresAt,
    installId: draft.installId,
    issuedAt: draft.issuedAt,
    nonce: randomCloudflareBootstrapOwnershipHandoffNonce(),
    plan: draft.plan,
    purpose: CLOUDFLARE_BOOTSTRAP_OWNERSHIP_HANDOFF_PURPOSE,
    release: draft.release,
    schemaVersion: CLOUDFLARE_BOOTSTRAP_OWNERSHIP_HANDOFF_SCHEMA_VERSION,
    worker: draft.worker,
  };
  const serializedStatement = canonicalJson(statement);
  const signatureBytes = await crypto.subtle.sign(
    'Ed25519',
    signingPrivateKey,
    new TextEncoder().encode(signaturePayload(serializedStatement)),
  );
  return canonicalJson({
    purpose: CLOUDFLARE_BOOTSTRAP_OWNERSHIP_HANDOFF_ENVELOPE_PURPOSE,
    schemaVersion: CLOUDFLARE_BOOTSTRAP_OWNERSHIP_HANDOFF_SCHEMA_VERSION,
    signature: base64UrlEncode(new Uint8Array(signatureBytes)),
    signatureContext: CLOUDFLARE_BOOTSTRAP_OWNERSHIP_HANDOFF_SIGNATURE_CONTEXT,
    statement: serializedStatement,
  });
}

function parseCanonicalEnvelope(serialized: string): ParsedCanonicalHandoffEnvelope {
  const serializedResult = v.safeParse(serializedEnvelopeSchema, serialized);
  if (!serializedResult.success) fail();
  const wire = serializedResult.output;
  let decoded: unknown;
  try {
    decoded = JSON.parse(wire);
  } catch {
    fail();
  }
  const envelope = parsePlainStrict(handoffEnvelopeSchema, decoded);
  try {
    if (canonicalJson(envelope) !== wire) fail();
  } catch {
    fail();
  }

  let rawStatement: unknown;
  try {
    rawStatement = JSON.parse(envelope.statement);
  } catch {
    fail();
  }
  const statement = parsePlainStrict(handoffStatementSchema, rawStatement);
  try {
    if (canonicalJson(statement) !== envelope.statement) fail();
  } catch {
    fail();
  }
  validateStatementLifetime(statement);
  validateOwnershipGraph(statement);
  validateNonce(statement.nonce);
  return {
    signature: envelope.signature,
    statement,
    serializedStatement: envelope.statement,
  };
}

/**
 * Verify canonical bytes and Ed25519 with a customer-pinned raw public key.
 * The key is an explicit trusted input and is never selected from the envelope.
 */
export async function verifyCloudflareBootstrapOwnershipHandoff(input: {
  readonly now: number;
  /** Raw 32-byte Ed25519 public key encoded as canonical unpadded base64url. */
  readonly pinnedPublicKey: string;
  readonly serializedHandoff: string;
}): Promise<VerifiedCloudflareBootstrapOwnershipHandoff> {
  if (!Number.isSafeInteger(input.now) || input.now < 0 || !PUBLIC_KEY.test(input.pinnedPublicKey)) {
    fail();
  }
  const parsed = await verifySignedHandoff({
    pinnedPublicKey: input.pinnedPublicKey,
    serializedHandoff: input.serializedHandoff,
  });
  if (input.now < parsed.statement.issuedAt) fail('not_yet_valid');
  if (
    input.now >= parsed.statement.expiresAt ||
    input.now >= parsed.statement.bootstrapSecret.expiresAt
  ) fail('expired');

  return deepFreezePlainData({
    statement: parsed.statement,
    verification: 'ed25519' as const,
  });
}

async function verifySignedHandoff(input: {
  readonly pinnedPublicKey: string;
  readonly serializedHandoff: string;
}): Promise<ParsedCanonicalHandoffEnvelope> {
  if (!PUBLIC_KEY.test(input.pinnedPublicKey)) fail();
  const parsed = parseCanonicalEnvelope(input.serializedHandoff);
  const publicKeyBytes = base64UrlDecode(input.pinnedPublicKey, 32);
  const signatureBytes = base64UrlDecode(parsed.signature, 64);
  let publicKey: CryptoKey;
  try {
    publicKey = await crypto.subtle.importKey(
      'raw',
      publicKeyBytes,
      { name: 'Ed25519' },
      false,
      ['verify'],
    );
  } catch {
    fail();
  }
  let verified = false;
  try {
    verified = await crypto.subtle.verify(
      'Ed25519',
      publicKey,
      signatureBytes,
      new TextEncoder().encode(signaturePayload(parsed.serializedStatement)),
    );
  } catch {
    fail('invalid_signature');
  }
  if (!verified) fail('invalid_signature');
  return parsed;
}

function sameIdentity(
  statement: CloudflareBootstrapOwnershipHandoffStatement,
  readback: ParsedProviderReadback,
): boolean {
  return readback.accountId === statement.accountId &&
    readback.installId === statement.installId &&
    readback.worker.name === statement.worker.name &&
    readback.worker.providerId === statement.worker.providerId &&
    readback.adminState.binding === statement.adminState.binding &&
    readback.adminState.className === statement.adminState.className &&
    readback.adminState.namespaceId === statement.adminState.namespaceId &&
    readback.adminState.storage === statement.adminState.storage &&
    readback.adminState.workerProviderId === statement.adminState.workerProviderId &&
    readback.adminState.workerProviderId === readback.worker.providerId &&
    readback.plan.id === statement.plan.id &&
    readback.plan.hash === statement.plan.hash &&
    readback.release.id === statement.release.id &&
    readback.release.artifactSha256 === statement.release.artifactSha256 &&
    readback.bootstrapSecret.commitment === statement.bootstrapSecret.commitment &&
    readback.bootstrapSecret.expiresAt === statement.bootstrapSecret.expiresAt &&
    readback.handoff.issuedAt === statement.issuedAt &&
    readback.handoff.expiresAt === statement.expiresAt &&
    readback.handoff.nonce === statement.nonce;
}

/**
 * Re-verifies the signed handoff, then projects ownership only after a recent
 * caller-supplied Cloudflare readback matches every signed identity. The
 * caller must assemble `providerReadback` from fresh provider responses, not
 * from the Stage-1 request or a name lookup.
 */
export async function proveCloudflareBootstrapOwnershipAdoption(input: {
  readonly now: number;
  readonly pinnedPublicKey: string;
  readonly providerReadback: unknown;
  readonly serializedHandoff: string;
}): Promise<CloudflareBootstrapOwnershipAdoptionReceipt> {
  const verified = await verifyCloudflareBootstrapOwnershipHandoff(input);
  const readback = parsePlainStrict(providerReadbackSchema, input.providerReadback);
  if (
    readback.observedAt < verified.statement.issuedAt ||
    readback.observedAt > input.now ||
    input.now - readback.observedAt > CLOUDFLARE_BOOTSTRAP_PROVIDER_READBACK_MAX_AGE_MS
  ) fail('provider_readback_stale');
  if (!sameIdentity(verified.statement, readback)) fail('identity_mismatch');

  return deepFreezePlainData({
    accountId: verified.statement.accountId,
    adoptedAt: input.now,
    handoff: {
      expiresAt: verified.statement.expiresAt,
      issuedAt: verified.statement.issuedAt,
      nonce: verified.statement.nonce,
    },
    installId: verified.statement.installId,
    ownership: {
      adminStateNamespace: {
        binding: verified.statement.adminState.binding,
        className: verified.statement.adminState.className,
        kind: 'cloudflare_durable_object_namespace' as const,
        providerId: verified.statement.adminState.namespaceId,
        storage: verified.statement.adminState.storage,
        workerProviderId: verified.statement.adminState.workerProviderId,
      },
      worker: {
        kind: 'cloudflare_worker' as const,
        name: verified.statement.worker.name,
        providerId: verified.statement.worker.providerId,
      },
    },
    providerReadAt: readback.observedAt,
    plan: verified.statement.plan,
    purpose: 'cloudflare_bootstrap_ownership_adoption_receipt' as const,
    release: verified.statement.release,
    schemaVersion: CLOUDFLARE_BOOTSTRAP_OWNERSHIP_HANDOFF_SCHEMA_VERSION,
  });
}

/**
 * Re-authenticates a persisted adoption receipt for later cleanup. Handoff
 * expiry limits when adoption may happen; it does not erase the historical
 * Ed25519 ownership evidence after a valid adoption has completed.
 */
export async function verifyCloudflareBootstrapOwnershipHistory(input: {
  readonly adoptionReceipt: unknown;
  readonly pinnedPublicKey: string;
  readonly serializedHandoff: string;
}): Promise<CloudflareBootstrapOwnershipAdoptionReceipt> {
  const parsed = await verifySignedHandoff({
    pinnedPublicKey: input.pinnedPublicKey,
    serializedHandoff: input.serializedHandoff,
  });
  const receipt = parsePlainStrict(adoptionReceiptSchema, input.adoptionReceipt);
  const statement = parsed.statement;
  if (
    receipt.adoptedAt < statement.issuedAt || receipt.adoptedAt >= statement.expiresAt ||
    receipt.adoptedAt >= statement.bootstrapSecret.expiresAt ||
    receipt.providerReadAt < statement.issuedAt || receipt.providerReadAt > receipt.adoptedAt ||
    receipt.adoptedAt - receipt.providerReadAt >
      CLOUDFLARE_BOOTSTRAP_PROVIDER_READBACK_MAX_AGE_MS
  ) fail('receipt_mismatch');
  const expected: CloudflareBootstrapOwnershipAdoptionReceipt = {
    accountId: statement.accountId,
    adoptedAt: receipt.adoptedAt,
    handoff: {
      expiresAt: statement.expiresAt,
      issuedAt: statement.issuedAt,
      nonce: statement.nonce,
    },
    installId: statement.installId,
    ownership: {
      adminStateNamespace: {
        binding: statement.adminState.binding,
        className: statement.adminState.className,
        kind: 'cloudflare_durable_object_namespace',
        providerId: statement.adminState.namespaceId,
        storage: statement.adminState.storage,
        workerProviderId: statement.adminState.workerProviderId,
      },
      worker: {
        kind: 'cloudflare_worker',
        name: statement.worker.name,
        providerId: statement.worker.providerId,
      },
    },
    providerReadAt: receipt.providerReadAt,
    plan: statement.plan,
    purpose: 'cloudflare_bootstrap_ownership_adoption_receipt',
    release: statement.release,
    schemaVersion: CLOUDFLARE_BOOTSTRAP_OWNERSHIP_HANDOFF_SCHEMA_VERSION,
  };
  if (canonicalJson(receipt) !== canonicalJson(expected)) fail('receipt_mismatch');
  return deepFreezePlainData(expected);
}

import * as v from 'valibot';

import { boundaryValueSchema } from './boundary';
import { canonicalJson } from './canonical-json';
import {
  createCloudflareGatewayRelayTicket,
  CLOUDFLARE_GATEWAY_RELAY_TICKET_TTL_MS,
} from './cloudflare-gateway-relay-ticket';
import {
  CUSTOMER_CLOUDFLARE_OPERATIONS,
  RECEIPT_OWNED_CLOUDFLARE_RESOURCE_KINDS,
  type CustomerCloudflareOperation,
  type ReceiptOwnedCloudflareResourceKind,
} from './cloudflare-operation-authority';
import { base64UrlDecode, base64UrlEncode, randomBase64Url, sha256Hex } from './crypto';
import { deepFreezePlainData, isPlainDataTree } from './plain-data';
import { CUSTOMER_INSTALL_OAUTH_CALLBACK_PATH } from './customer-install-paths';

const ACCOUNT_ID = /^[a-f0-9]{32}$/u;
const INSTALL_ID = /^acg-[a-f0-9]{24}$/u;
const PROVIDER_ID = /^[a-f0-9]{32}$/u;
const WORKER_NAME = /^[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$/u;
const CLIENT_ID = /^[A-Za-z0-9_-]{16,128}$/u;
const TOKEN = /^[A-Za-z0-9_-]{43}$/u;
const PUBLIC_KEY = /^[A-Za-z0-9_-]{43}$/u;
const SIGNATURE = /^[A-Za-z0-9_-]{86}$/u;
const SHA256 = /^sha256:[a-f0-9]{64}$/u;
const KEY_ID = /^[a-z0-9](?:[a-z0-9._-]{0,62}[a-z0-9])?$/u;
const MAX_CERTIFICATE_CHARACTERS = 8_192;
const MAX_STATEMENT_CHARACTERS = 4_096;
const MAX_SEALED_KEY_CHARACTERS = 1_024;
const OWNERSHIP_PRIVATE_KEY_BYTES = 48;
const OWNERSHIP_KEY_IV_BYTES = 12;

export const CLOUDFLARE_GATEWAY_OWNERSHIP_CERTIFICATE_CONTEXT =
  'ankka-cloudflare-gateway-ownership-certificate-v1' as const;
export const CLOUDFLARE_GATEWAY_OWNERSHIP_PROOF_CONTEXT =
  'ankka-cloudflare-gateway-relay-proof-v1' as const;
export const CLOUDFLARE_GATEWAY_OWNERSHIP_CHALLENGE_REQUEST_CONTEXT =
  'ankka-cloudflare-gateway-relay-challenge-request-v1' as const;
export const CLOUDFLARE_GATEWAY_OWNERSHIP_PRIVATE_KEY_CONTEXT =
  'ankka-cloudflare-gateway-ownership-private-key-v1' as const;
export const CLOUDFLARE_GATEWAY_OWNERSHIP_WRAP_KEY_BINDING =
  'ANKKA_GATEWAY_OWNERSHIP_WRAP_KEY' as const;
export const CLOUDFLARE_GATEWAY_OWNERSHIP_CHALLENGE_TTL_MS = 2 * 60 * 1_000;
export const CLOUDFLARE_GATEWAY_OWNERSHIP_CHALLENGE_REQUEST_TTL_MS = 2 * 60 * 1_000;
export const CLOUDFLARE_GATEWAY_OWNERSHIP_CLOCK_SKEW_MS = 30 * 1_000;
export const CLOUDFLARE_GATEWAY_RELAY_TICKET_ISSUER_TTL_MS = 2 * 60 * 1_000;

const timestampSchema = v.pipe(v.number(), v.safeInteger(), v.minValue(0));
const receiptKindsSchema = v.union([
  v.array(v.picklist(RECEIPT_OWNED_CLOUDFLARE_RESOURCE_KINDS)),
  v.null(),
]);
const certificateStatementSchema = v.strictObject({
  schemaVersion: v.literal(1),
  purpose: v.literal('cloudflare_gateway_ownership_certificate'),
  accountId: v.pipe(v.string(), v.regex(ACCOUNT_ID)),
  installId: v.pipe(v.string(), v.regex(INSTALL_ID)),
  worker: v.strictObject({
    name: v.pipe(v.string(), v.regex(WORKER_NAME)),
    providerId: v.pipe(v.string(), v.regex(PROVIDER_ID)),
  }),
  adminStateNamespaceId: v.pipe(v.string(), v.regex(PROVIDER_ID)),
  bootstrapCallback: v.pipe(v.string(), v.url()),
  gatewayCallback: v.pipe(v.string(), v.url()),
  publicClientId: v.pipe(v.string(), v.regex(CLIENT_ID)),
  ownershipKey: v.strictObject({
    algorithm: v.literal('Ed25519'),
    publicKey: v.pipe(v.string(), v.regex(PUBLIC_KEY)),
  }),
  handoffSha256: v.pipe(v.string(), v.regex(SHA256)),
  certificateId: v.pipe(v.string(), v.regex(TOKEN)),
  issuedAt: timestampSchema,
});
const certificateEnvelopeSchema = v.strictObject({
  schemaVersion: v.literal(1),
  purpose: v.literal('cloudflare_gateway_ownership_certificate_envelope'),
  keyId: v.pipe(v.string(), v.regex(KEY_ID)),
  signatureContext: v.literal(CLOUDFLARE_GATEWAY_OWNERSHIP_CERTIFICATE_CONTEXT),
  statement: v.pipe(v.string(), v.minLength(1), v.maxLength(MAX_STATEMENT_CHARACTERS)),
  signature: v.pipe(v.string(), v.regex(SIGNATURE)),
});
const challengeRequestStatementSchema = v.strictObject({
  schemaVersion: v.literal(1),
  purpose: v.literal('cloudflare_gateway_relay_challenge_request'),
  certificateSha256: v.pipe(v.string(), v.regex(SHA256)),
  operation: v.picklist(CUSTOMER_CLOUDFLARE_OPERATIONS),
  requestNonce: v.pipe(v.string(), v.regex(TOKEN)),
  issuedAt: timestampSchema,
});
const challengeRequestEnvelopeSchema = v.strictObject({
  schemaVersion: v.literal(1),
  purpose: v.literal('cloudflare_gateway_relay_challenge_request_envelope'),
  certificate: v.pipe(
    v.string(),
    v.minLength(1),
    v.maxLength(MAX_CERTIFICATE_CHARACTERS),
  ),
  signatureContext: v.literal(CLOUDFLARE_GATEWAY_OWNERSHIP_CHALLENGE_REQUEST_CONTEXT),
  statement: v.pipe(v.string(), v.minLength(1), v.maxLength(MAX_STATEMENT_CHARACTERS)),
  signature: v.pipe(v.string(), v.regex(SIGNATURE)),
});
const proofStatementSchema = v.strictObject({
  schemaVersion: v.literal(1),
  purpose: v.literal('cloudflare_gateway_relay_ownership_proof'),
  certificateSha256: v.pipe(v.string(), v.regex(SHA256)),
  gatewayCallback: v.pipe(v.string(), v.url()),
  operation: v.picklist(CUSTOMER_CLOUDFLARE_OPERATIONS),
  receiptResourceKinds: receiptKindsSchema,
  challenge: v.pipe(v.string(), v.regex(TOKEN)),
  challengeExpiresAt: timestampSchema,
  issuedAt: timestampSchema,
});
const proofEnvelopeSchema = v.strictObject({
  schemaVersion: v.literal(1),
  purpose: v.literal('cloudflare_gateway_relay_ownership_proof_envelope'),
  certificate: v.pipe(
    v.string(),
    v.minLength(1),
    v.maxLength(MAX_CERTIFICATE_CHARACTERS),
  ),
  signatureContext: v.literal(CLOUDFLARE_GATEWAY_OWNERSHIP_PROOF_CONTEXT),
  statement: v.pipe(v.string(), v.minLength(1), v.maxLength(MAX_STATEMENT_CHARACTERS)),
  signature: v.pipe(v.string(), v.regex(SIGNATURE)),
});
const sealedOwnershipPrivateKeySchema = v.strictObject({
  schemaVersion: v.literal(1),
  purpose: v.literal('cloudflare_gateway_ownership_private_key'),
  algorithm: v.literal('Ed25519'),
  encryption: v.literal('A256GCM'),
  publicKey: v.pipe(v.string(), v.regex(PUBLIC_KEY)),
  iv: v.pipe(v.string(), v.regex(/^[A-Za-z0-9_-]{16}$/u)),
  ciphertext: v.pipe(v.string(), v.regex(/^[A-Za-z0-9_-]{86}$/u)),
});

type ParsedCertificateStatement = v.InferOutput<typeof certificateStatementSchema>;
type ParsedChallengeRequestStatement = v.InferOutput<typeof challengeRequestStatementSchema>;
type ParsedProofStatement = v.InferOutput<typeof proofStatementSchema>;

export interface CloudflareGatewayOwnershipCertificateDraft {
  readonly accountId: string;
  readonly installId: string;
  readonly worker: {
    readonly name: string;
    readonly providerId: string;
  };
  readonly adminStateNamespaceId: string;
  /** Temporary workers.dev callback used only during initial installation. */
  readonly bootstrapCallback: string;
  /** Permanent Access-protected callback used for every later operation. */
  readonly gatewayCallback: string;
  readonly publicClientId: string;
  readonly ownershipPublicKey: string;
  /** Digest of the exact signed Stage 1 ownership handoff used for this adoption. */
  readonly handoffSha256: string;
  readonly issuedAt: number;
  readonly keyId: string;
}

export interface VerifiedCloudflareGatewayOwnershipCertificate {
  readonly statement: ParsedCertificateStatement;
  readonly keyId: string;
  readonly certificateSha256: string;
  readonly verification: 'ed25519';
}

export interface CloudflareGatewayOwnershipChallengeRecord {
  readonly certificateSha256: string;
  readonly operation: CustomerCloudflareOperation;
  readonly challengeSha256: string;
  readonly expiresAt: number;
}

/**
 * The relay stores only short-lived hashes and a fixed operation. It stores no
 * account, Worker, callback, resource ID, receipt, or raw challenge. `put`
 * atomically replaces the prior record for the same certificate and operation;
 * only a request signed by that certificate's customer key may reach it.
 */
export interface CloudflareGatewayOwnershipChallengeStore {
  put(record: CloudflareGatewayOwnershipChallengeRecord): Promise<boolean>;
  consume(record: CloudflareGatewayOwnershipChallengeRecord): Promise<boolean>;
}

export interface CloudflareGatewayOwnershipChallenge {
  readonly challenge: string;
  readonly certificateSha256: string;
  readonly expiresAt: number;
}

export interface CloudflareGatewayOwnershipKeyPair {
  /** Non-extractable private key retained only for the active customer invocation. */
  readonly privateKey: CryptoKey;
  /** Canonical raw Ed25519 public key safe to include in the ownership certificate. */
  readonly publicKey: string;
}

export interface SealedCloudflareGatewayOwnershipKeyPair
  extends CloudflareGatewayOwnershipKeyPair {
  /** Authenticated ciphertext safe to persist in the customer Durable Object. */
  readonly sealedPrivateKey: string;
}

export interface VerifiedCloudflareGatewayOwnershipProof {
  readonly accountId: string;
  readonly installId: string;
  readonly workerName: string;
  readonly workerProviderId: string;
  readonly adminStateNamespaceId: string;
  readonly gatewayCallback: string;
  readonly publicClientId: string;
  readonly operation: CustomerCloudflareOperation;
  readonly receiptResourceKinds: readonly ReceiptOwnedCloudflareResourceKind[] | null;
  readonly certificateSha256: string;
  readonly verification: 'ed25519-possession-and-single-use-challenge';
}

export type CloudflareGatewayOwnershipProofErrorCode =
  | 'invalid'
  | 'invalid_certificate'
  | 'invalid_signature'
  | 'expired'
  | 'not_yet_valid'
  | 'operation_mismatch'
  | 'replayed'
  | 'store_unavailable';

export class CloudflareGatewayOwnershipProofError extends Error {
  constructor(readonly code: CloudflareGatewayOwnershipProofErrorCode) {
    super(code);
    this.name = 'CloudflareGatewayOwnershipProofError';
  }
}

function fail(code: CloudflareGatewayOwnershipProofErrorCode = 'invalid'): never {
  throw new CloudflareGatewayOwnershipProofError(code);
}

function validGatewayCallback(value: string): boolean {
  try {
    const url = new URL(value);
    return url.protocol === 'https:' && url.username === '' && url.password === '' && url.port === '' &&
      url.pathname === CUSTOMER_INSTALL_OAUTH_CALLBACK_PATH && url.search === '' && url.hash === '' &&
      url.hostname === url.hostname.toLowerCase() && url.hostname.includes('.');
  } catch {
    return false;
  }
}

function validBootstrapCallback(value: string, workerName: string): boolean {
  if (!validGatewayCallback(value)) return false;
  const hostname = new URL(value).hostname;
  return hostname.startsWith(`${workerName}.`) && hostname.endsWith('.workers.dev');
}

function validPrivateKey(key: CryptoKey): boolean {
  return key.type === 'private' && key.algorithm.name === 'Ed25519' && key.usages.includes('sign');
}

function decodePublicKey(value: string): Uint8Array<ArrayBuffer> {
  let bytes: Uint8Array;
  try {
    bytes = base64UrlDecode(value);
  } catch {
    fail('invalid_certificate');
  }
  if (bytes.byteLength !== 32 || base64UrlEncode(bytes) !== value) fail('invalid_certificate');
  const owned = new Uint8Array(new ArrayBuffer(32));
  owned.set(bytes);
  bytes.fill(0);
  return owned;
}

function parseCanonical<Schema extends v.BaseSchema<unknown, unknown, v.BaseIssue<unknown>>>(
  schema: Schema,
  serialized: string,
  error: CloudflareGatewayOwnershipProofErrorCode,
): v.InferOutput<Schema> {
  let decoded: unknown;
  try {
    decoded = JSON.parse(serialized);
  } catch {
    fail(error);
  }
  if (!isPlainDataTree(decoded)) fail(error);
  const boundary = v.safeParse(boundaryValueSchema, decoded);
  const parsed = boundary.success ? v.safeParse(schema, boundary.output) : null;
  if (!parsed?.success || canonicalJson(parsed.output) !== serialized) fail(error);
  return parsed.output;
}

function parseEnvelope<Schema extends v.BaseSchema<unknown, unknown, v.BaseIssue<unknown>>>(
  schema: Schema,
  serialized: string,
  error: CloudflareGatewayOwnershipProofErrorCode,
): v.InferOutput<Schema> {
  if (serialized.length < 1 || serialized.length > MAX_CERTIFICATE_CHARACTERS) fail(error);
  return parseCanonical(schema, serialized, error);
}

function certificateSignaturePayload(statement: string, keyId: string): string {
  return canonicalJson({
    keyId,
    purpose: 'cloudflare_gateway_ownership_certificate_envelope',
    schemaVersion: 1,
    signatureContext: CLOUDFLARE_GATEWAY_OWNERSHIP_CERTIFICATE_CONTEXT,
    statement,
  });
}

function proofSignaturePayload(statement: string): string {
  return canonicalJson({
    purpose: 'cloudflare_gateway_relay_ownership_proof_envelope',
    schemaVersion: 1,
    signatureContext: CLOUDFLARE_GATEWAY_OWNERSHIP_PROOF_CONTEXT,
    statement,
  });
}

function challengeRequestSignaturePayload(statement: string): string {
  return canonicalJson({
    purpose: 'cloudflare_gateway_relay_challenge_request_envelope',
    schemaVersion: 1,
    signatureContext: CLOUDFLARE_GATEWAY_OWNERSHIP_CHALLENGE_REQUEST_CONTEXT,
    statement,
  });
}

async function verifyEd25519(
  publicKeyValue: string,
  signatureValue: string,
  payload: string,
  error: CloudflareGatewayOwnershipProofErrorCode,
): Promise<void> {
  const publicKeyBytes = decodePublicKey(publicKeyValue);
  let signatureBytes: Uint8Array<ArrayBuffer>;
  try {
    const decoded = base64UrlDecode(signatureValue);
    signatureBytes = new Uint8Array(new ArrayBuffer(decoded.byteLength));
    signatureBytes.set(decoded);
    decoded.fill(0);
  } catch {
    publicKeyBytes.fill(0);
    fail(error);
  }
  try {
    if (signatureBytes.byteLength !== 64 || base64UrlEncode(signatureBytes) !== signatureValue) {
      fail(error);
    }
    const publicKey = await crypto.subtle.importKey(
      'raw',
      publicKeyBytes,
      { name: 'Ed25519' },
      false,
      ['verify'],
    );
    if (!await crypto.subtle.verify(
      'Ed25519',
      publicKey,
      signatureBytes,
      new TextEncoder().encode(payload),
    )) fail(error);
  } catch (caught) {
    if (caught instanceof CloudflareGatewayOwnershipProofError) throw caught;
    fail(error);
  } finally {
    publicKeyBytes.fill(0);
    signatureBytes.fill(0);
  }
}

function validReceiptKinds(
  operation: CustomerCloudflareOperation,
  kinds: readonly ReceiptOwnedCloudflareResourceKind[] | null,
): boolean {
  if (operation !== 'uninstall') return kinds === null;
  return kinds !== null && kinds.length >= 1 &&
    kinds.length <= RECEIPT_OWNED_CLOUDFLARE_RESOURCE_KINDS.length &&
    new Set(kinds).size === kinds.length;
}

/**
 * Generates an invocation-local proof-of-possession key inside the customer
 * Gateway. Use the sealed variant below when the key must survive restarts.
 */
export async function generateCloudflareGatewayOwnershipKeyPair(): Promise<
  CloudflareGatewayOwnershipKeyPair
> {
  let pair: CryptoKeyPair;
  try {
    pair = await crypto.subtle.generateKey('Ed25519', false, ['sign', 'verify']);
  } catch {
    fail('invalid_signature');
  }
  if (!validPrivateKey(pair.privateKey) || pair.privateKey.extractable ||
      pair.publicKey.type !== 'public' || pair.publicKey.algorithm.name !== 'Ed25519' ||
      !pair.publicKey.usages.includes('verify') || !pair.publicKey.extractable) {
    fail('invalid_signature');
  }
  let publicKeyBytes: Uint8Array<ArrayBuffer>;
  try {
    const exported = await crypto.subtle.exportKey('raw', pair.publicKey);
    publicKeyBytes = new Uint8Array(new ArrayBuffer(exported.byteLength));
    publicKeyBytes.set(new Uint8Array(exported));
  } catch {
    fail('invalid_signature');
  }
  try {
    if (publicKeyBytes.byteLength !== 32) fail('invalid_signature');
    return Object.freeze({
      privateKey: pair.privateKey,
      publicKey: base64UrlEncode(publicKeyBytes),
    });
  } finally {
    publicKeyBytes.fill(0);
  }
}

function decodeExactBase64Url(
  value: string,
  expectedBytes: number,
): Uint8Array<ArrayBuffer> {
  let decoded: Uint8Array;
  try {
    decoded = base64UrlDecode(value);
  } catch {
    fail('invalid_signature');
  }
  if (decoded.byteLength !== expectedBytes || base64UrlEncode(decoded) !== value) {
    decoded.fill(0);
    fail('invalid_signature');
  }
  const owned = new Uint8Array(new ArrayBuffer(expectedBytes));
  owned.set(decoded);
  decoded.fill(0);
  return owned;
}

async function ownershipWrappingKey(encodedKey: string): Promise<CryptoKey> {
  if (!TOKEN.test(encodedKey)) fail('invalid_signature');
  const bytes = decodeExactBase64Url(encodedKey, 32);
  try {
    return await crypto.subtle.importKey(
      'raw',
      bytes,
      { name: 'AES-GCM' },
      false,
      ['encrypt', 'decrypt'],
    );
  } catch {
    fail('invalid_signature');
  } finally {
    bytes.fill(0);
  }
}

function ownershipPrivateKeyAdditionalData(publicKey: string): Uint8Array<ArrayBuffer> {
  return new TextEncoder().encode(canonicalJson({
    schemaVersion: 1,
    purpose: 'cloudflare_gateway_ownership_private_key_aad',
    context: CLOUDFLARE_GATEWAY_OWNERSHIP_PRIVATE_KEY_CONTEXT,
    publicKey,
  }));
}

async function verifyOwnershipKeyPair(privateKey: CryptoKey, publicKey: string): Promise<void> {
  const payload = `${CLOUDFLARE_GATEWAY_OWNERSHIP_PRIVATE_KEY_CONTEXT}.pair-check`;
  let signature: Uint8Array<ArrayBuffer>;
  try {
    signature = new Uint8Array(await crypto.subtle.sign(
      'Ed25519',
      privateKey,
      new TextEncoder().encode(payload),
    ));
  } catch {
    fail('invalid_signature');
  }
  try {
    await verifyEd25519(
      publicKey,
      base64UrlEncode(signature),
      payload,
      'invalid_signature',
    );
  } finally {
    signature.fill(0);
  }
}

/**
 * Generates the proof key inside the customer Gateway, seals its PKCS#8 bytes
 * under a dedicated customer-Worker secret, and returns only a non-extractable
 * in-memory key plus authenticated ciphertext for Durable Object persistence.
 */
export async function generateSealedCloudflareGatewayOwnershipKeyPair(
  wrappingKey: string,
): Promise<SealedCloudflareGatewayOwnershipKeyPair> {
  let generated: CryptoKeyPair;
  try {
    generated = await crypto.subtle.generateKey('Ed25519', true, ['sign', 'verify']);
  } catch {
    return fail('invalid_signature');
  }
  let publicKeyBytes: Uint8Array<ArrayBuffer> | undefined;
  let privateKeyBytes: Uint8Array<ArrayBuffer> | undefined;
  let iv: Uint8Array<ArrayBuffer> | undefined;
  let ciphertext: Uint8Array<ArrayBuffer> | undefined;
  let additionalData: Uint8Array<ArrayBuffer> | undefined;
  try {
    publicKeyBytes = new Uint8Array(await crypto.subtle.exportKey('raw', generated.publicKey));
    privateKeyBytes = new Uint8Array(await crypto.subtle.exportKey('pkcs8', generated.privateKey));
    if (publicKeyBytes.byteLength !== 32 ||
        privateKeyBytes.byteLength !== OWNERSHIP_PRIVATE_KEY_BYTES) fail('invalid_signature');
    const publicKey = base64UrlEncode(publicKeyBytes);
    const privateKey = await crypto.subtle.importKey(
      'pkcs8',
      privateKeyBytes,
      { name: 'Ed25519' },
      false,
      ['sign'],
    );
    if (!validPrivateKey(privateKey) || privateKey.extractable) fail('invalid_signature');
    await verifyOwnershipKeyPair(privateKey, publicKey);
    iv = new Uint8Array(new ArrayBuffer(OWNERSHIP_KEY_IV_BYTES));
    crypto.getRandomValues(iv);
    additionalData = ownershipPrivateKeyAdditionalData(publicKey);
    ciphertext = new Uint8Array(await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv, additionalData },
      await ownershipWrappingKey(wrappingKey),
      privateKeyBytes,
    ));
    if (ciphertext.byteLength !== OWNERSHIP_PRIVATE_KEY_BYTES + 16) {
      fail('invalid_signature');
    }
    return Object.freeze({
      privateKey,
      publicKey,
      sealedPrivateKey: canonicalJson({
        schemaVersion: 1,
        purpose: 'cloudflare_gateway_ownership_private_key',
        algorithm: 'Ed25519',
        encryption: 'A256GCM',
        publicKey,
        iv: base64UrlEncode(iv),
        ciphertext: base64UrlEncode(ciphertext),
      }),
    });
  } catch (error) {
    if (error instanceof CloudflareGatewayOwnershipProofError) throw error;
    return fail('invalid_signature');
  } finally {
    publicKeyBytes?.fill(0);
    privateKeyBytes?.fill(0);
    iv?.fill(0);
    ciphertext?.fill(0);
    additionalData?.fill(0);
  }
}

/**
 * Opens customer-owned ciphertext and imports the Ed25519 private key as
 * non-extractable. Plain PKCS#8 bytes exist only during this invocation and
 * are overwritten after import and pair verification.
 */
export async function openSealedCloudflareGatewayOwnershipPrivateKey(input: {
  readonly sealedPrivateKey: string;
  readonly wrappingKey: string;
  readonly expectedPublicKey: string;
}): Promise<CryptoKey> {
  if (input.sealedPrivateKey.length < 1 ||
      input.sealedPrivateKey.length > MAX_SEALED_KEY_CHARACTERS) fail('invalid_signature');
  const envelope = parseCanonical(
    sealedOwnershipPrivateKeySchema,
    input.sealedPrivateKey,
    'invalid_signature',
  );
  if (envelope.publicKey !== input.expectedPublicKey) fail('invalid_signature');
  decodePublicKey(envelope.publicKey).fill(0);
  const iv = decodeExactBase64Url(envelope.iv, OWNERSHIP_KEY_IV_BYTES);
  const ciphertext = decodeExactBase64Url(
    envelope.ciphertext,
    OWNERSHIP_PRIVATE_KEY_BYTES + 16,
  );
  const additionalData = ownershipPrivateKeyAdditionalData(envelope.publicKey);
  let plaintext: Uint8Array<ArrayBuffer> | undefined;
  try {
    plaintext = new Uint8Array(await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv, additionalData },
      await ownershipWrappingKey(input.wrappingKey),
      ciphertext,
    ));
    if (plaintext.byteLength !== OWNERSHIP_PRIVATE_KEY_BYTES) fail('invalid_signature');
    const privateKey = await crypto.subtle.importKey(
      'pkcs8',
      plaintext,
      { name: 'Ed25519' },
      false,
      ['sign'],
    );
    if (!validPrivateKey(privateKey) || privateKey.extractable) fail('invalid_signature');
    await verifyOwnershipKeyPair(privateKey, envelope.publicKey);
    return privateKey;
  } catch (error) {
    if (error instanceof CloudflareGatewayOwnershipProofError) throw error;
    return fail('invalid_signature');
  } finally {
    iv.fill(0);
    ciphertext.fill(0);
    additionalData.fill(0);
    plaintext?.fill(0);
  }
}

/**
 * Stage 1 calls this only after exact provider read-back and a token-free
 * `/health` response from the exact random customer Worker. The health response
 * carries the public key generated in customer Durable Object storage; the
 * private key never crosses the customer boundary.
 */
export async function issueCloudflareGatewayOwnershipCertificate(
  input: CloudflareGatewayOwnershipCertificateDraft,
  issuerPrivateKey: CryptoKey,
): Promise<string> {
  if (!validPrivateKey(issuerPrivateKey) ||
      !validBootstrapCallback(input.bootstrapCallback, input.worker.name) ||
      !validGatewayCallback(input.gatewayCallback) ||
      input.bootstrapCallback === input.gatewayCallback) {
    fail('invalid_certificate');
  }
  const candidate = v.safeParse(certificateStatementSchema, {
    schemaVersion: 1,
    purpose: 'cloudflare_gateway_ownership_certificate',
    accountId: input.accountId,
    installId: input.installId,
    worker: input.worker,
    adminStateNamespaceId: input.adminStateNamespaceId,
    bootstrapCallback: input.bootstrapCallback,
    gatewayCallback: input.gatewayCallback,
    publicClientId: input.publicClientId,
    ownershipKey: { algorithm: 'Ed25519', publicKey: input.ownershipPublicKey },
    handoffSha256: input.handoffSha256,
    certificateId: randomBase64Url(32),
    issuedAt: input.issuedAt,
  });
  if (!candidate.success || !KEY_ID.test(input.keyId)) fail('invalid_certificate');
  decodePublicKey(candidate.output.ownershipKey.publicKey).fill(0);
  const statement = canonicalJson(candidate.output);
  const signature = base64UrlEncode(new Uint8Array(await crypto.subtle.sign(
    'Ed25519',
    issuerPrivateKey,
    new TextEncoder().encode(certificateSignaturePayload(statement, input.keyId)),
  )));
  return canonicalJson({
    schemaVersion: 1,
    purpose: 'cloudflare_gateway_ownership_certificate_envelope',
    keyId: input.keyId,
    signatureContext: CLOUDFLARE_GATEWAY_OWNERSHIP_CERTIFICATE_CONTEXT,
    statement,
    signature,
  });
}

export async function verifyCloudflareGatewayOwnershipCertificate(input: {
  readonly certificate: string;
  readonly pinnedIssuerPublicKey: string;
  readonly expectedKeyId: string;
  readonly expectedPublicClientId: string;
}): Promise<VerifiedCloudflareGatewayOwnershipCertificate> {
  const envelope = parseEnvelope(
    certificateEnvelopeSchema,
    input.certificate,
    'invalid_certificate',
  );
  if (envelope.keyId !== input.expectedKeyId ||
      envelope.signatureContext !== CLOUDFLARE_GATEWAY_OWNERSHIP_CERTIFICATE_CONTEXT) {
    fail('invalid_certificate');
  }
  const statement = parseCanonical(
    certificateStatementSchema,
    envelope.statement,
    'invalid_certificate',
  );
  if (statement.publicClientId !== input.expectedPublicClientId ||
      !validBootstrapCallback(statement.bootstrapCallback, statement.worker.name) ||
      !validGatewayCallback(statement.gatewayCallback) ||
      statement.bootstrapCallback === statement.gatewayCallback) {
    fail('invalid_certificate');
  }
  await verifyEd25519(
    input.pinnedIssuerPublicKey,
    envelope.signature,
    certificateSignaturePayload(envelope.statement, envelope.keyId),
    'invalid_certificate',
  );
  return deepFreezePlainData({
    statement,
    keyId: envelope.keyId,
    certificateSha256: `sha256:${await sha256Hex(input.certificate)}`,
    verification: 'ed25519' as const,
  });
}

/**
 * Customer-side preflight for challenge issuance. Requiring possession here
 * prevents a copied public certificate from allocating or rotating relay
 * challenge state.
 */
export async function createCloudflareGatewayOwnershipChallengeRequest(input: {
  readonly certificate: string;
  readonly certificateSha256: string;
  readonly operation: CustomerCloudflareOperation;
  readonly now: number;
  readonly ownershipPrivateKey: CryptoKey;
}): Promise<string> {
  if (!validPrivateKey(input.ownershipPrivateKey) || !Number.isSafeInteger(input.now) ||
      input.now < 0 || input.certificate.length < 1 ||
      input.certificate.length > MAX_CERTIFICATE_CHARACTERS) fail('invalid_signature');
  const candidate = v.safeParse(challengeRequestStatementSchema, {
    schemaVersion: 1,
    purpose: 'cloudflare_gateway_relay_challenge_request',
    certificateSha256: input.certificateSha256,
    operation: input.operation,
    requestNonce: randomBase64Url(32),
    issuedAt: input.now,
  });
  if (!candidate.success) fail();
  const statement = canonicalJson(candidate.output);
  const signature = base64UrlEncode(new Uint8Array(await crypto.subtle.sign(
    'Ed25519',
    input.ownershipPrivateKey,
    new TextEncoder().encode(challengeRequestSignaturePayload(statement)),
  )));
  return canonicalJson({
    schemaVersion: 1,
    purpose: 'cloudflare_gateway_relay_challenge_request_envelope',
    certificate: input.certificate,
    signatureContext: CLOUDFLARE_GATEWAY_OWNERSHIP_CHALLENGE_REQUEST_CONTEXT,
    statement,
    signature,
  });
}

async function verifyCloudflareGatewayOwnershipChallengeRequest(input: {
  readonly request: string;
  readonly pinnedIssuerPublicKey: string;
  readonly expectedKeyId: string;
  readonly expectedPublicClientId: string;
  readonly expectedOperation: CustomerCloudflareOperation;
  readonly now: number;
}): Promise<Readonly<{
  certificateSha256: string;
  statement: ParsedChallengeRequestStatement;
}>> {
  if (!Number.isSafeInteger(input.now) || input.now < 0) fail();
  const envelope = parseEnvelope(challengeRequestEnvelopeSchema, input.request, 'invalid');
  const certificate = await verifyCloudflareGatewayOwnershipCertificate({
    certificate: envelope.certificate,
    pinnedIssuerPublicKey: input.pinnedIssuerPublicKey,
    expectedKeyId: input.expectedKeyId,
    expectedPublicClientId: input.expectedPublicClientId,
  });
  const statement: ParsedChallengeRequestStatement = parseCanonical(
    challengeRequestStatementSchema,
    envelope.statement,
    'invalid',
  );
  if (statement.operation !== input.expectedOperation) fail('operation_mismatch');
  if (statement.certificateSha256 !== certificate.certificateSha256 ||
      statement.issuedAt > input.now + CLOUDFLARE_GATEWAY_OWNERSHIP_CLOCK_SKEW_MS) fail();
  if (statement.issuedAt + CLOUDFLARE_GATEWAY_OWNERSHIP_CHALLENGE_REQUEST_TTL_MS <= input.now) {
    fail('expired');
  }
  await verifyEd25519(
    certificate.statement.ownershipKey.publicKey,
    envelope.signature,
    challengeRequestSignaturePayload(envelope.statement),
    'invalid_signature',
  );
  return deepFreezePlainData({
    certificateSha256: certificate.certificateSha256,
    statement,
  });
}

export async function issueCloudflareGatewayOwnershipChallenge(input: {
  readonly request: string;
  readonly pinnedIssuerPublicKey: string;
  readonly expectedKeyId: string;
  readonly expectedPublicClientId: string;
  readonly expectedOperation: CustomerCloudflareOperation;
  readonly now: number;
  readonly store: CloudflareGatewayOwnershipChallengeStore;
}): Promise<CloudflareGatewayOwnershipChallenge> {
  if (!CUSTOMER_CLOUDFLARE_OPERATIONS.includes(input.expectedOperation)) fail();
  const request = await verifyCloudflareGatewayOwnershipChallengeRequest(input);
  const challenge = randomBase64Url(32);
  const expiresAt = input.now + CLOUDFLARE_GATEWAY_OWNERSHIP_CHALLENGE_TTL_MS;
  const record = Object.freeze({
    certificateSha256: request.certificateSha256,
    operation: input.expectedOperation,
    challengeSha256: `sha256:${await sha256Hex(challenge)}`,
    expiresAt,
  });
  let stored: boolean;
  try {
    stored = await input.store.put(record);
  } catch {
    fail('store_unavailable');
  }
  if (!stored) fail('store_unavailable');
  return Object.freeze({ challenge, certificateSha256: request.certificateSha256, expiresAt });
}

/** Create the customer-side proof. Only the customer-owned private key can sign it. */
export async function createCloudflareGatewayOwnershipProof(input: {
  readonly certificate: string;
  readonly certificateSha256: string;
  readonly gatewayCallback: string;
  readonly operation: CustomerCloudflareOperation;
  readonly receiptResourceKinds?: readonly ReceiptOwnedCloudflareResourceKind[];
  readonly challenge: string;
  readonly challengeExpiresAt: number;
  readonly now: number;
  readonly ownershipPrivateKey: CryptoKey;
}): Promise<string> {
  if (!validPrivateKey(input.ownershipPrivateKey) ||
      !validGatewayCallback(input.gatewayCallback)) fail('invalid_signature');
  const candidate = v.safeParse(proofStatementSchema, {
    schemaVersion: 1,
    purpose: 'cloudflare_gateway_relay_ownership_proof',
    certificateSha256: input.certificateSha256,
    gatewayCallback: input.gatewayCallback,
    operation: input.operation,
    receiptResourceKinds: input.receiptResourceKinds ?? null,
    challenge: input.challenge,
    challengeExpiresAt: input.challengeExpiresAt,
    issuedAt: input.now,
  });
  if (!candidate.success || !validReceiptKinds(
    candidate.output.operation,
    candidate.output.receiptResourceKinds,
  )) fail();
  const statement = canonicalJson(candidate.output);
  const signature = base64UrlEncode(new Uint8Array(await crypto.subtle.sign(
    'Ed25519',
    input.ownershipPrivateKey,
    new TextEncoder().encode(proofSignaturePayload(statement)),
  )));
  return canonicalJson({
    schemaVersion: 1,
    purpose: 'cloudflare_gateway_relay_ownership_proof_envelope',
    certificate: input.certificate,
    signatureContext: CLOUDFLARE_GATEWAY_OWNERSHIP_PROOF_CONTEXT,
    statement,
    signature,
  });
}

export async function verifyAndConsumeCloudflareGatewayOwnershipProof(input: {
  readonly proof: string;
  readonly pinnedIssuerPublicKey: string;
  readonly expectedKeyId: string;
  readonly expectedPublicClientId: string;
  readonly expectedOperation: CustomerCloudflareOperation;
  readonly now: number;
  readonly store: CloudflareGatewayOwnershipChallengeStore;
}): Promise<VerifiedCloudflareGatewayOwnershipProof> {
  if (!Number.isSafeInteger(input.now) || input.now < 0) fail();
  const envelope = parseEnvelope(proofEnvelopeSchema, input.proof, 'invalid');
  const certificate = await verifyCloudflareGatewayOwnershipCertificate({
    certificate: envelope.certificate,
    pinnedIssuerPublicKey: input.pinnedIssuerPublicKey,
    expectedKeyId: input.expectedKeyId,
    expectedPublicClientId: input.expectedPublicClientId,
  });
  const statement: ParsedProofStatement = parseCanonical(
    proofStatementSchema,
    envelope.statement,
    'invalid',
  );
  if (statement.operation !== input.expectedOperation ||
      statement.gatewayCallback !== certificate.statement.gatewayCallback) {
    fail('operation_mismatch');
  }
  if (statement.certificateSha256 !== certificate.certificateSha256 ||
      !validReceiptKinds(statement.operation, statement.receiptResourceKinds) ||
      statement.issuedAt > input.now + CLOUDFLARE_GATEWAY_OWNERSHIP_CLOCK_SKEW_MS ||
      statement.challengeExpiresAt <= statement.issuedAt ||
      statement.challengeExpiresAt - statement.issuedAt >
        CLOUDFLARE_GATEWAY_OWNERSHIP_CHALLENGE_TTL_MS + CLOUDFLARE_GATEWAY_OWNERSHIP_CLOCK_SKEW_MS) {
    fail();
  }
  if (statement.challengeExpiresAt <= input.now) fail('expired');
  await verifyEd25519(
    certificate.statement.ownershipKey.publicKey,
    envelope.signature,
    proofSignaturePayload(envelope.statement),
    'invalid_signature',
  );
  const challengeRecord = Object.freeze({
    certificateSha256: certificate.certificateSha256,
    operation: statement.operation,
    challengeSha256: `sha256:${await sha256Hex(statement.challenge)}`,
    expiresAt: statement.challengeExpiresAt,
  });
  let consumed: boolean;
  try {
    consumed = await input.store.consume(challengeRecord);
  } catch {
    fail('store_unavailable');
  }
  if (!consumed) fail('replayed');
  return deepFreezePlainData({
    accountId: certificate.statement.accountId,
    installId: certificate.statement.installId,
    workerName: certificate.statement.worker.name,
    workerProviderId: certificate.statement.worker.providerId,
    adminStateNamespaceId: certificate.statement.adminStateNamespaceId,
    gatewayCallback: certificate.statement.gatewayCallback,
    publicClientId: certificate.statement.publicClientId,
    operation: statement.operation,
    receiptResourceKinds: statement.receiptResourceKinds === null
      ? null
      : [...statement.receiptResourceKinds],
    certificateSha256: certificate.certificateSha256,
    verification: 'ed25519-possession-and-single-use-challenge' as const,
  });
}

/**
 * Server-side composition used only after the proof and one-time challenge
 * pass. The relay HMAC key remains here and is never returned to the Gateway.
 */
export async function issueCloudflareGatewayRelayTicketFromOwnershipProof(input: {
  readonly proof: string;
  readonly pinnedIssuerPublicKey: string;
  readonly expectedKeyId: string;
  readonly expectedPublicClientId: string;
  readonly expectedOperation: CustomerCloudflareOperation;
  readonly now: number;
  readonly ticketExpiresAt: number;
  readonly relayTicketSigningKey: string;
  readonly store: CloudflareGatewayOwnershipChallengeStore;
}): Promise<string> {
  if (input.ticketExpiresAt <= input.now ||
      input.ticketExpiresAt - input.now > CLOUDFLARE_GATEWAY_RELAY_TICKET_TTL_MS) fail();
  const proof = await verifyAndConsumeCloudflareGatewayOwnershipProof(input);
  const ticketInput = {
    accountId: proof.accountId,
    installId: proof.installId,
    workerName: proof.workerName,
    gatewayCallback: proof.gatewayCallback,
    publicClientId: proof.publicClientId,
    operation: proof.operation,
    nonce: randomBase64Url(32),
    now: input.now,
    expiresAt: input.ticketExpiresAt,
    signingKey: input.relayTicketSigningKey,
  };
  return proof.receiptResourceKinds === null
    ? createCloudflareGatewayRelayTicket(ticketInput)
    : createCloudflareGatewayRelayTicket({
      ...ticketInput,
      receiptResourceKinds: proof.receiptResourceKinds,
    });
}

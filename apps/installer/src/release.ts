import * as v from 'valibot';

import { base64UrlDecode, base64UrlEncode } from './crypto';
import { DeployError } from './errors';
import {
  canonicalJson,
  parseCanonicalReleaseManifest,
  type ReleaseFileRecord,
  type ReleaseManifest,
} from './release-manifest';

export interface ReleaseEnvironment {
  GATEWAY_RELEASE_ENVELOPE_JSON?: string;
  GATEWAY_RELEASE_CHANNEL?: string;
}

export const RELEASE_ENVELOPE_SCHEMA_VERSION = 2 as const;
export const RELEASE_SIGNATURE_CONTEXT = 'ankka-mcp-gateway-release-envelope-v2' as const;
const RELEASE_CHANNEL_PATTERN = /^(?:canary|stable)$/u;
const KEY_ID_PATTERN = /^[a-z0-9][a-z0-9._-]{0,63}$/u;
const SIGNATURE_PATTERN = /^[A-Za-z0-9_-]{86}$/u;
const signedReleaseEnvelopeSchema = v.strictObject({
  channel: v.string(),
  keyId: v.string(),
  manifest: v.string(),
  schemaVersion: v.literal(RELEASE_ENVELOPE_SCHEMA_VERSION),
  signature: v.string(),
  signatureContext: v.literal(RELEASE_SIGNATURE_CONTEXT),
});
const releasePayloadFileSchema = v.strictObject({
  bytes: v.instance(Uint8Array),
  path: v.string(),
});

export interface VerifiedRelease {
  readonly verification: 'ed25519';
  readonly keyId: string;
  readonly manifest: ReleaseManifest;
}

/**
 * Immutable release bytes returned by a trusted payload provider. Blob is used
 * deliberately: unlike Uint8Array, its contents cannot be mutated by a caller,
 * and every `arrayBuffer()` call returns a new copy.
 */
export interface VerifiedReleasePayloadBlob {
  readonly path: string;
  readonly byteSize: number;
  readonly contentType: string;
  readonly sha256: string;
  readonly bytes: Blob;
}

export interface VerifiedReleaseBundle extends VerifiedRelease {
  /** Reviewed immutable publication channel that selected this exact bundle. */
  readonly channel: string;
  /** Canonical signed envelope retained for customer-side update verification. */
  readonly envelope: SignedReleaseEnvelope;
  readonly payload: readonly VerifiedReleasePayloadBlob[];
  /** Raw Ed25519 verification key encoded as unpadded base64url. Public, never secret. */
  readonly publicKey: string;
}

export interface ReleaseManifestProvider {
  loadVerifiedRelease(env: ReleaseEnvironment): Promise<VerifiedRelease>;
}

/**
 * Release provider required by the reviewed synchronous install path. The
 * callback receives the exact immutable bundle that produced its static plan;
 * a manifest-only provider can never enter the mutation executor.
 */
export interface ReleaseBundleProvider extends ReleaseManifestProvider {
  loadVerifiedReleaseBundle(env: ReleaseEnvironment): Promise<VerifiedReleaseBundle>;
}

export interface SignedReleaseEnvelope {
  readonly schemaVersion: typeof RELEASE_ENVELOPE_SCHEMA_VERSION;
  readonly channel: string;
  readonly keyId: string;
  /** Exact UTF-8 contents of the public artifact's canonical manifest.json. */
  readonly manifest: string;
  /** Unpadded base64url Ed25519 signature over the canonical v2 release statement. */
  readonly signature: string;
  readonly signatureContext: typeof RELEASE_SIGNATURE_CONTEXT;
}

export interface ReleasePayloadFile {
  readonly path: string;
  readonly bytes: Uint8Array;
}

interface ParsedEnvelope extends SignedReleaseEnvelope {
  readonly parsedManifest: ReleaseManifest;
}

// Intentionally empty until release signing is provisioned and reviewed. A
// deploy of this scaffold therefore cannot truthfully advertise a signed
// release or begin OAuth. Adding a key is a code review, not an env toggle.
const PINNED_RELEASE_PUBLIC_KEYS: Readonly<Record<string, string>> = Object.freeze({});

function invalid(): never {
  throw new DeployError(503, 'release_invalid');
}

export function releaseSignatureCanonicalJson(
  channel: string,
  keyId: string,
  manifest: string,
): string {
  if (
    !RELEASE_CHANNEL_PATTERN.test(channel) ||
    !KEY_ID_PATTERN.test(keyId) ||
    manifest.length === 0
  ) invalid();
  return canonicalJson({
    channel,
    keyId,
    manifest,
    schemaVersion: RELEASE_ENVELOPE_SCHEMA_VERSION,
    signatureContext: RELEASE_SIGNATURE_CONTEXT,
  });
}

function parseEnvelope(serialized: string, expectedChannel: string): ParsedEnvelope {
  if (!RELEASE_CHANNEL_PATTERN.test(expectedChannel)) invalid();
  let value: v.InferOutput<typeof signedReleaseEnvelopeSchema>;
  try {
    const result = v.safeParse(signedReleaseEnvelopeSchema, JSON.parse(serialized));
    if (!result.success) invalid();
    value = result.output;
  } catch {
    invalid();
  }
  try {
    if (canonicalJson(value) !== serialized) invalid();
  } catch {
    invalid();
  }
  if (
    value.channel !== expectedChannel ||
    !KEY_ID_PATTERN.test(value.keyId) ||
    !SIGNATURE_PATTERN.test(value.signature)
  ) invalid();
  return Object.freeze({
    schemaVersion: RELEASE_ENVELOPE_SCHEMA_VERSION,
    channel: value.channel,
    keyId: value.keyId,
    manifest: value.manifest,
    parsedManifest: parseCanonicalReleaseManifest(value.manifest),
    signature: value.signature,
    signatureContext: RELEASE_SIGNATURE_CONTEXT,
  });
}

async function sha256Hex(bytes: Uint8Array): Promise<string> {
  const owned = new Uint8Array(bytes.byteLength);
  owned.set(bytes);
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', owned));
  return [...digest].map((byte) => byte.toString(16).padStart(2, '0')).join('');
}

function sha256HexText(value: string): Promise<string> {
  return sha256Hex(new TextEncoder().encode(value));
}

function allFileRecords(manifest: ReleaseManifest): ReleaseFileRecord[] {
  return [
    ...manifest.components.admin.files,
    ...manifest.components.installer.files,
    ...manifest.components.worker.files,
    ...manifest.components.workerCleanup.files,
    ...manifest.components.workerRetirement.files,
  ].sort((left, right) => left.path < right.path ? -1 : left.path > right.path ? 1 : 0);
}

export async function verifyReleaseManifestDigests(manifest: ReleaseManifest): Promise<void> {
  for (const component of [
    'admin',
    'installer',
    'worker',
    'workerCleanup',
    'workerRetirement',
  ] as const) {
    const expected = await sha256HexText(canonicalJson(manifest.components[component].files));
    if (expected !== manifest.components[component].treeSha256) invalid();
  }
  const expectedArtifactTree = await sha256HexText(canonicalJson(allFileRecords(manifest)));
  if (expectedArtifactTree !== manifest.artifact.treeSha256) invalid();
}

export async function verifyReleasePayload(
  manifest: ReleaseManifest,
  payload: readonly ReleasePayloadFile[],
): Promise<void> {
  await verifyReleaseManifestDigests(manifest);
  const parsed = v.safeParse(v.array(releasePayloadFileSchema), payload);
  if (!parsed.success || parsed.output.length !== manifest.artifact.fileCount) invalid();

  const supplied = new Map<string, Uint8Array>();
  for (const entry of parsed.output) {
    if (supplied.has(entry.path)) invalid();
    const owned = new Uint8Array(entry.bytes.byteLength);
    owned.set(entry.bytes);
    supplied.set(entry.path, owned);
  }

  let totalBytes = 0;
  for (const record of allFileRecords(manifest)) {
    const bytes = supplied.get(record.path);
    if (!bytes || bytes.byteLength !== record.byteSize) invalid();
    totalBytes += bytes.byteLength;
    if (!Number.isSafeInteger(totalBytes) || await sha256Hex(bytes) !== record.sha256) invalid();
    supplied.delete(record.path);
  }
  if (supplied.size !== 0 || totalBytes !== manifest.artifact.byteSize) invalid();
}

export async function verifySignedReleaseEnvelope(
  serialized: string,
  expectedChannel: string,
  pinnedPublicKeys: Readonly<Record<string, string>>,
  payload: readonly ReleasePayloadFile[],
): Promise<VerifiedRelease> {
  const envelope = parseEnvelope(serialized, expectedChannel);
  const encodedPublicKey = pinnedPublicKeys[envelope.keyId];
  if (!encodedPublicKey) throw new DeployError(503, 'release_unavailable');
  let publicKeyBytes: Uint8Array<ArrayBuffer>;
  let signatureBytes: Uint8Array<ArrayBuffer>;
  try {
    const decodedKey = base64UrlDecode(encodedPublicKey);
    const decodedSignature = base64UrlDecode(envelope.signature);
    publicKeyBytes = new Uint8Array(decodedKey.byteLength);
    signatureBytes = new Uint8Array(decodedSignature.byteLength);
    publicKeyBytes.set(decodedKey);
    signatureBytes.set(decodedSignature);
    if (
      base64UrlEncode(publicKeyBytes) !== encodedPublicKey ||
      base64UrlEncode(signatureBytes) !== envelope.signature
    ) invalid();
  } catch {
    invalid();
  }
  if (publicKeyBytes.byteLength !== 32 || signatureBytes.byteLength !== 64) invalid();

  let verified = false;
  try {
    const publicKey = await crypto.subtle.importKey(
      'raw',
      publicKeyBytes,
      { name: 'Ed25519' },
      false,
      ['verify'],
    );
    verified = await crypto.subtle.verify(
      'Ed25519',
      publicKey,
      signatureBytes,
      new TextEncoder().encode(releaseSignatureCanonicalJson(
        envelope.channel,
        envelope.keyId,
        envelope.manifest,
      )),
    );
  } catch {
    invalid();
  }
  if (!verified) invalid();
  await verifyReleasePayload(envelope.parsedManifest, payload);
  return Object.freeze({
    verification: 'ed25519',
    keyId: envelope.keyId,
    manifest: envelope.parsedManifest,
  });
}

export class EnvironmentReleaseManifestProvider implements ReleaseBundleProvider {
  async loadVerifiedRelease(env: ReleaseEnvironment): Promise<VerifiedRelease> {
    if (!env.GATEWAY_RELEASE_ENVELOPE_JSON || !env.GATEWAY_RELEASE_CHANNEL) {
      throw new DeployError(503, 'release_unavailable');
    }
    // This scaffold deliberately has neither a pinned key nor an artifact
    // fetcher. A future reviewed provider must fetch every payload file and pass
    // it here; pinning a key alone cannot accidentally enable a release.
    return verifySignedReleaseEnvelope(
      env.GATEWAY_RELEASE_ENVELOPE_JSON,
      env.GATEWAY_RELEASE_CHANNEL,
      PINNED_RELEASE_PUBLIC_KEYS,
      Object.freeze([]),
    );
  }

  async loadVerifiedReleaseBundle(_env: ReleaseEnvironment): Promise<VerifiedReleaseBundle> {
    // The default entrypoint deliberately has no payload source. Keeping this
    // method fail-closed prevents an injected executor from receiving a
    // manifest-shaped value without the exact verified release bytes.
    throw new DeployError(503, 'release_unavailable');
  }
}

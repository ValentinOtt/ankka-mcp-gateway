import { DeployError } from './errors';
import {
  parseExactReleaseBundleIdentity,
  type ExactReleaseBundleIdentity,
} from './exact-release-bundle';
import {
  RELEASE_ENVELOPE_SCHEMA_VERSION,
  RELEASE_SIGNATURE_CONTEXT,
  verifySignedReleaseEnvelope,
  type ReleasePayloadFile,
  type VerifiedReleaseBundle,
  type VerifiedReleasePayloadBlob,
} from './release';
import {
  MAX_CANONICAL_MANIFEST_BYTES,
  MAX_RELEASE_FILE_BYTES,
  MAX_RELEASE_PAYLOAD_BYTES,
  parseCanonicalReleaseManifest,
  type ReleaseFileRecord,
  type ReleaseManifest,
} from './release-manifest';

const MAX_RELEASE_OBJECT_COUNT = 10_000;
const LIST_PAGE_SIZE = 1_000;
const MAX_LIST_PAGES = Math.ceil((MAX_RELEASE_OBJECT_COUNT + 1) / LIST_PAGE_SIZE) + 1;
const MAX_ENVELOPE_BYTES = (2 * MAX_CANONICAL_MANIFEST_BYTES) + 4_096;
const RELEASE_BUCKET_ROOT = 'ankka-mcp-gateway/releases';
const ENVELOPE_FILENAME = 'release-envelope.json';
const ENVELOPE_CONTENT_TYPE = 'application/json; charset=utf-8';

export type PinnedR2Release = ExactReleaseBundleIdentity;

export interface R2ReleaseBundleProvider {
  loadVerifiedReleaseBundle(bucket: R2Bucket): Promise<VerifiedReleaseBundle>;
}

export interface R2ExactReleaseBundleProvider {
  loadVerifiedReleaseBundleForIdentity(
    bucket: R2Bucket,
    identity: ExactReleaseBundleIdentity,
  ): Promise<VerifiedReleaseBundle>;
}

interface ParsedEnvelopeIndex {
  readonly envelope: Readonly<{
    readonly schemaVersion: typeof RELEASE_ENVELOPE_SCHEMA_VERSION;
    readonly channel: string;
    readonly keyId: string;
    readonly manifest: string;
    readonly signature: string;
    readonly signatureContext: typeof RELEASE_SIGNATURE_CONTEXT;
  }>;
  readonly serialized: string;
  readonly manifest: ReleaseManifest;
}

interface ReadObject {
  readonly bytes: Uint8Array;
  readonly contentType: string | undefined;
}

function invalid(): never {
  throw new DeployError(503, 'release_invalid');
}

function unavailable(): never {
  throw new DeployError(503, 'release_unavailable');
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function exactKeys(value: Record<string, unknown>, keys: readonly string[]): boolean {
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  return actual.length === expected.length && actual.every((key, index) => key === expected[index]);
}

function parsePin(input: PinnedR2Release): Readonly<PinnedR2Release> {
  return parseExactReleaseBundleIdentity(input);
}

function releasePrefix(pin: PinnedR2Release): string {
  return `${RELEASE_BUCKET_ROOT}/${pin.channel}/${pin.release}/`;
}

function envelopeKey(pin: PinnedR2Release): string {
  return `${releasePrefix(pin)}${ENVELOPE_FILENAME}`;
}

function allFileRecords(manifest: ReleaseManifest): readonly ReleaseFileRecord[] {
  return Object.freeze([
    ...manifest.components.admin.files,
    ...manifest.components.installer.files,
    ...manifest.components.worker.files,
    ...manifest.components.workerCleanup.files,
    ...manifest.components.workerRetirement.files,
  ].sort((left, right) => left.path < right.path ? -1 : left.path > right.path ? 1 : 0));
}

async function readObject(
  bucket: R2Bucket,
  key: string,
  maximumBytes: number,
  expectedBytes?: number,
): Promise<ReadObject | null> {
  let object: R2ObjectBody | null;
  try {
    object = await bucket.get(key);
  } catch {
    unavailable();
  }
  if (object === null) return null;
  if (
    object.key !== key ||
    !Number.isSafeInteger(object.size) ||
    object.size < 0 ||
    object.size > maximumBytes ||
    (expectedBytes !== undefined && object.size !== expectedBytes)
  ) invalid();
  let raw: ArrayBuffer;
  try {
    raw = await object.arrayBuffer();
  } catch {
    unavailable();
  }
  const received = new Uint8Array(raw);
  if (
    received.byteLength !== object.size ||
    (expectedBytes !== undefined && received.byteLength !== expectedBytes)
  ) invalid();
  const bytes = new Uint8Array(received.byteLength);
  bytes.set(received);
  return Object.freeze({
    bytes,
    contentType: object.httpMetadata?.contentType,
  });
}

function decodeUtf8(bytes: Uint8Array): string {
  try {
    return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch {
    invalid();
  }
}

function parseEnvelopeIndex(serialized: string, pin: PinnedR2Release): ParsedEnvelopeIndex {
  let input: unknown;
  try {
    input = JSON.parse(serialized);
  } catch {
    invalid();
  }
  if (!isRecord(input) || !exactKeys(input, [
    'channel', 'keyId', 'manifest', 'schemaVersion', 'signature', 'signatureContext',
  ])) invalid();
  if (
    input.schemaVersion !== RELEASE_ENVELOPE_SCHEMA_VERSION ||
    input.channel !== pin.channel ||
    input.keyId !== pin.keyId ||
    typeof input.manifest !== 'string' ||
    typeof input.signature !== 'string' ||
    input.signatureContext !== RELEASE_SIGNATURE_CONTEXT
  ) invalid();
  const manifest = parseCanonicalReleaseManifest(input.manifest);
  if (
    manifest.release !== pin.release ||
    manifest.artifact.treeSha256 !== pin.artifactSha256 ||
    manifest.artifact.fileCount > MAX_RELEASE_OBJECT_COUNT ||
    manifest.artifact.byteSize > MAX_RELEASE_PAYLOAD_BYTES
  ) invalid();
  return Object.freeze({
    envelope: Object.freeze({
      schemaVersion: RELEASE_ENVELOPE_SCHEMA_VERSION,
      channel: pin.channel,
      keyId: input.keyId,
      manifest: input.manifest,
      signature: input.signature,
      signatureContext: RELEASE_SIGNATURE_CONTEXT,
    }),
    serialized,
    manifest,
  });
}

async function exactPrefixObjects(
  bucket: R2Bucket,
  prefix: string,
): Promise<ReadonlyMap<string, number>> {
  const objects = new Map<string, number>();
  const cursors = new Set<string>();
  let cursor: string | undefined;
  let pageCount = 0;
  while (true) {
    pageCount += 1;
    if (pageCount > MAX_LIST_PAGES) invalid();
    let page: R2Objects;
    try {
      page = await bucket.list({ prefix, limit: LIST_PAGE_SIZE, ...(cursor ? { cursor } : {}) });
    } catch {
      unavailable();
    }
    if (!page || !Array.isArray(page.objects) || typeof page.truncated !== 'boolean') invalid();
    for (const object of page.objects) {
      if (
        !object ||
        typeof object.key !== 'string' ||
        !object.key.startsWith(prefix) ||
        !Number.isSafeInteger(object.size) ||
        object.size < 0 ||
        objects.has(object.key)
      ) invalid();
      objects.set(object.key, object.size);
      if (objects.size > MAX_RELEASE_OBJECT_COUNT + 1) invalid();
    }
    if (!page.truncated) break;
    if (
      typeof page.cursor !== 'string' ||
      page.cursor.length === 0 ||
      page.cursor.length > 4_096 ||
      cursors.has(page.cursor) ||
      page.objects.length === 0
    ) invalid();
    cursors.add(page.cursor);
    cursor = page.cursor;
  }
  return objects;
}

function assertExactObjectSet(
  listed: ReadonlyMap<string, number>,
  expected: ReadonlyMap<string, number>,
): void {
  if (listed.size !== expected.size) invalid();
  for (const [key, size] of expected) {
    if (listed.get(key) !== size) invalid();
  }
}

function immutablePayload(
  records: readonly ReleaseFileRecord[],
  payload: readonly ReleasePayloadFile[],
): readonly VerifiedReleasePayloadBlob[] {
  const recordsByPath = new Map(records.map((record) => [record.path, record]));
  const blobs = payload.map((file) => {
    const record = recordsByPath.get(file.path);
    if (!record) invalid();
    const copy = new Uint8Array(file.bytes.byteLength);
    copy.set(file.bytes);
    const blob = new Blob([copy], { type: record.contentType });
    copy.fill(0);
    return Object.freeze({
      path: record.path,
      byteSize: record.byteSize,
      contentType: record.contentType,
      sha256: record.sha256,
      bytes: blob,
    });
  });
  return Object.freeze(blobs);
}

/**
 * Private release-bucket consumer. The pin is constructor data compiled into a
 * reviewed entrypoint; no environment string can select a channel, key, or
 * release. This module is intentionally not imported by the default Worker.
 */
export class PinnedR2ReleaseBundleProvider implements R2ReleaseBundleProvider {
  readonly #pin: Readonly<PinnedR2Release>;

  constructor(pin: PinnedR2Release) {
    this.#pin = parsePin(pin);
  }

  async loadVerifiedReleaseBundle(bucket: R2Bucket): Promise<VerifiedReleaseBundle> {
    if (!bucket || typeof bucket.get !== 'function' || typeof bucket.list !== 'function') unavailable();
    const prefix = releasePrefix(this.#pin);
    const expectedEnvelopeKey = envelopeKey(this.#pin);
    const envelope = await readObject(bucket, expectedEnvelopeKey, MAX_ENVELOPE_BYTES);
    if (!envelope) unavailable();
    if (envelope.contentType !== ENVELOPE_CONTENT_TYPE) invalid();
    const indexed = parseEnvelopeIndex(decodeUtf8(envelope.bytes), this.#pin);
    const records = allFileRecords(indexed.manifest);

    const expectedObjects = new Map<string, number>([[expectedEnvelopeKey, envelope.bytes.byteLength]]);
    for (const record of records) {
      const key = `${prefix}${record.path}`;
      if (expectedObjects.has(key)) invalid();
      expectedObjects.set(key, record.byteSize);
    }
    const listed = await exactPrefixObjects(bucket, prefix);
    assertExactObjectSet(listed, expectedObjects);

    const mutablePayload: ReleasePayloadFile[] = [];
    try {
      let totalBytes = 0;
      for (const record of records) {
        const object = await readObject(bucket, `${prefix}${record.path}`, MAX_RELEASE_FILE_BYTES, record.byteSize);
        if (!object || object.contentType !== record.contentType) invalid();
        totalBytes += object.bytes.byteLength;
        if (!Number.isSafeInteger(totalBytes) || totalBytes > MAX_RELEASE_PAYLOAD_BYTES) invalid();
        mutablePayload.push({ path: record.path, bytes: object.bytes });
      }
      if (totalBytes !== indexed.manifest.artifact.byteSize) invalid();
      const verified = await verifySignedReleaseEnvelope(
        indexed.serialized,
        this.#pin.channel,
        Object.freeze({ [this.#pin.keyId]: this.#pin.publicKey }),
        mutablePayload,
      );
      if (
        verified.keyId !== this.#pin.keyId ||
        verified.manifest.release !== this.#pin.release ||
        verified.manifest.artifact.treeSha256 !== this.#pin.artifactSha256
      ) invalid();
      const payload = immutablePayload(records, mutablePayload);
      return Object.freeze({
        ...verified,
        channel: this.#pin.channel,
        envelope: indexed.envelope,
        payload,
        publicKey: this.#pin.publicKey,
      });
    } finally {
      envelope.bytes.fill(0);
      for (const file of mutablePayload) file.bytes.fill(0);
    }
  }
}

/**
 * Historical immutable release loader for returning uninstall. Selection is
 * the exact installed identity imported from the customer-owned Worker; the
 * loader never reads a mutable channel pointer or substitutes the runtime's
 * currently promoted release.
 */
export class ExactR2ReleaseBundleProvider implements R2ExactReleaseBundleProvider {
  loadVerifiedReleaseBundleForIdentity(
    bucket: R2Bucket,
    identity: ExactReleaseBundleIdentity,
  ): Promise<VerifiedReleaseBundle> {
    return new PinnedR2ReleaseBundleProvider(identity).loadVerifiedReleaseBundle(bucket);
  }
}

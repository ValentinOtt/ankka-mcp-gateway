import * as v from 'valibot';

import {
  MAX_CANONICAL_MANIFEST_BYTES,
  MAX_RELEASE_FILE_BYTES,
  MAX_RELEASE_PAYLOAD_BYTES,
  canonicalJson,
  parseCanonicalReleaseManifest,
  type ReleaseFileRecord,
  type ReleaseManifest,
} from './release-manifest';
const RELEASE_BUCKET_ROOT = 'ankka-mcp-gateway/releases';
const PUBLICATION_INTENT_ROOT = 'ankka-mcp-gateway/publication-intents/v1';
const ENVELOPE_FILENAME = 'release-envelope.json';
const ENVELOPE_CONTENT_TYPE = 'application/json; charset=utf-8';
const INTENT_CONTENT_TYPE = 'application/json; charset=utf-8';
const MAX_RELEASE_OBJECT_COUNT = 10_001;
const MAX_ENVELOPE_BYTES = (2 * MAX_CANONICAL_MANIFEST_BYTES) + 4_096;
const MAX_TOTAL_OBJECT_BYTES = MAX_RELEASE_PAYLOAD_BYTES + MAX_ENVELOPE_BYTES;
const MAX_INTENT_BYTES = 8_192;
const MAX_R2_KEY_BYTES = 1_024;
const MAX_PAYLOAD_PATH_BYTES = 900;
const LIST_PAGE_SIZE = 1_000;
const MAX_LIST_PAGES = Math.ceil(MAX_RELEASE_OBJECT_COUNT / LIST_PAGE_SIZE) + 1;
const SHA256_PATTERN = /^[a-f0-9]{64}$/u;
const RELEASE_PATTERN = /^gateway-v(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)$/u;
const CHANNEL_PATTERN = /^(?:canary|stable)$/u;
const KEY_ID_PATTERN = /^[a-z0-9][a-z0-9._-]{0,63}$/u;
const SIGNATURE_PATTERN = /^[A-Za-z0-9_-]{86}$/u;
const SAFE_SEGMENT = /^[A-Za-z0-9._-]+$/u;
const CREDENTIAL_NAME = /(?:^|[-_.])(?:api[-_.]?key|client[-_.]?secret|credential|credentials|password|passwd|private[-_.]?key|secret|secrets|token|tokens)(?:[-_.]|$)/iu;
const MUTABLE_CHANNELS = new Set(['current', 'latest', 'mutable']);
const RELEASE_ENVELOPE_SCHEMA_VERSION = 2;
const RELEASE_SIGNATURE_CONTEXT = 'ankka-mcp-gateway-release-envelope-v2';
const safeNonnegativeIntegerSchema = v.pipe(v.number(), v.safeInteger(), v.minValue(0));
const planEntrySchema = v.strictObject({
  byteSize: safeNonnegativeIntegerSchema,
  contentType: v.string(),
  key: v.string(),
  sha256: v.string(),
  sourcePath: v.string(),
});
const objectPlanSchema = v.strictObject({
  artifactSha256: v.string(),
  channel: v.string(),
  immutability: v.strictObject({
    externalAtomicCreateOnlyRequired: v.literal(true),
    overwriteAllowed: v.literal(false),
  }),
  keyId: v.string(),
  objectCount: safeNonnegativeIntegerSchema,
  objects: v.array(planEntrySchema),
  prefix: v.string(),
  release: v.string(),
  schemaVersion: v.literal(1),
  totalByteSize: safeNonnegativeIntegerSchema,
});
const publicationBlobSchema = v.strictObject({
  bytes: v.instance(Blob),
  key: v.string(),
});
const releaseEnvelopeSchema = v.strictObject({
  channel: v.string(),
  keyId: v.string(),
  manifest: v.string(),
  schemaVersion: v.literal(RELEASE_ENVELOPE_SCHEMA_VERSION),
  signature: v.string(),
  signatureContext: v.literal(RELEASE_SIGNATURE_CONTEXT),
});
const publicationIntentSchema = v.strictObject({
  artifactSha256: v.string(),
  channel: v.string(),
  createdAt: safeNonnegativeIntegerSchema,
  keyId: v.string(),
  objectCount: safeNonnegativeIntegerSchema,
  objectPlanSha256: v.string(),
  prefix: v.string(),
  release: v.string(),
  schemaVersion: v.literal(1),
  totalByteSize: safeNonnegativeIntegerSchema,
});
const publicationInputSchema = v.strictObject({
  blobs: v.array(publicationBlobSchema),
  bucket: v.object({
    get: v.function(),
    list: v.function(),
    put: v.function(),
  }),
  clock: v.object({ now: v.function() }),
  objectPlan: v.unknown(),
});

export type R2ReleasePublicationErrorCode =
  | 'release_publication_conflict'
  | 'release_publication_invalid'
  | 'release_publication_unavailable';

export class R2ReleasePublicationError extends Error {
  readonly code: R2ReleasePublicationErrorCode;

  constructor(code: R2ReleasePublicationErrorCode) {
    super(code);
    this.name = 'R2ReleasePublicationError';
    this.code = code;
  }
}

export interface R2ReleaseObjectPlanEntry {
  readonly byteSize: number;
  readonly contentType: string;
  readonly key: string;
  readonly sha256: string;
  readonly sourcePath: string;
}

export interface R2ReleaseObjectPlan {
  readonly artifactSha256: string;
  readonly channel: string;
  readonly immutability: {
    readonly externalAtomicCreateOnlyRequired: true;
    readonly overwriteAllowed: false;
  };
  readonly keyId: string;
  readonly objectCount: number;
  readonly objects: readonly R2ReleaseObjectPlanEntry[];
  readonly prefix: string;
  readonly release: string;
  readonly schemaVersion: 1;
  readonly totalByteSize: number;
}

export interface R2ReleasePublicationBlob {
  readonly key: string;
  readonly bytes: Blob;
}

export interface R2ReleasePublicationClock {
  now(): number;
}

export interface PublishR2ReleaseInput {
  readonly blobs: readonly R2ReleasePublicationBlob[];
  readonly bucket: R2ReleaseBucket;
  readonly clock: R2ReleasePublicationClock;
  /** The exact JSON-parsed `r2-object-plan.json` emitted by the offline signer. */
  readonly objectPlan: unknown;
}

export interface R2ReleaseStoredObject {
  readonly key: string;
  readonly size: number;
  readonly httpMetadata?: { readonly contentType?: string };
  readonly customMetadata?: Readonly<Record<string, string>>;
  arrayBuffer(): Promise<ArrayBuffer>;
}

export interface R2ReleaseListedObject {
  readonly key: string;
  readonly size: number;
}

export type R2ReleaseObjectPage =
  | {
      readonly objects: readonly R2ReleaseListedObject[];
      readonly truncated: false;
    }
  | {
      readonly objects: readonly R2ReleaseListedObject[];
      readonly truncated: true;
      readonly cursor: string;
    };

export interface R2ReleasePutOptions {
  readonly onlyIf: Headers;
  readonly sha256: string;
  readonly httpMetadata: { readonly contentType: string };
  readonly customMetadata: Readonly<Record<string, string>>;
}

/** Exact customer-owned R2 capability required by the release publisher. */
export interface R2ReleaseBucket {
  get(key: string): Promise<R2ReleaseStoredObject | null>;
  put(
    key: string,
    value: Uint8Array<ArrayBuffer>,
    options: R2ReleasePutOptions,
  ): Promise<{ readonly key: string } | null>;
  list(options: {
    readonly prefix: string;
    readonly limit: number;
    readonly cursor?: string;
  }): Promise<R2ReleaseObjectPage>;
}

export interface R2ReleasePublicationResult {
  readonly schemaVersion: 1;
  readonly status: 'published';
  readonly channel: string;
  readonly release: string;
  readonly prefix: string;
  readonly intentKey: string;
  readonly objectCount: number;
  readonly totalByteSize: number;
  readonly objectPlanSha256: string;
  readonly createdAt: number;
}

interface PublicationIntent {
  readonly artifactSha256: string;
  readonly channel: string;
  readonly createdAt: number;
  readonly keyId: string;
  readonly objectCount: number;
  readonly objectPlanSha256: string;
  readonly prefix: string;
  readonly release: string;
  readonly schemaVersion: 1;
  readonly totalByteSize: number;
}

interface DesiredObject {
  readonly key: string;
  readonly bytes: Uint8Array<ArrayBuffer>;
  readonly byteSize: number;
  readonly contentType: string;
  readonly sha256: string;
  readonly customMetadata: Readonly<Record<string, string>>;
}

interface ReadObject {
  readonly key: string;
  readonly bytes: Uint8Array<ArrayBuffer>;
  readonly byteSize: number;
  readonly contentType: string | undefined;
  readonly customMetadata: Readonly<Record<string, string>> | undefined;
}

interface PreparedPublication {
  readonly plan: R2ReleaseObjectPlan;
  readonly planSha256: string;
  readonly envelope: DesiredObject;
  readonly payloads: readonly DesiredObject[];
  readonly allReleaseObjects: readonly DesiredObject[];
}

function invalid(): never {
  throw new R2ReleasePublicationError('release_publication_invalid');
}

function conflict(): never {
  throw new R2ReleasePublicationError('release_publication_conflict');
}

function unavailable(): never {
  throw new R2ReleasePublicationError('release_publication_unavailable');
}

function lexicalCompare(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function safePath(value: string): boolean {
  if (
    value.length === 0 ||
    value.includes('\\') ||
    value.includes('%') ||
    Array.from(value).some((character) => {
      const code = character.charCodeAt(0);
      return code <= 31 || code === 127;
    })
  ) return false;
  return value.split('/').every((segment) =>
    SAFE_SEGMENT.test(segment) &&
    segment !== '.' &&
    segment !== '..' &&
    !CREDENTIAL_NAME.test(segment));
}

function immutablePlanEntry(
  input: v.InferOutput<typeof planEntrySchema>,
): R2ReleaseObjectPlanEntry {
  if (
    input.byteSize > MAX_TOTAL_OBJECT_BYTES ||
    input.contentType.length === 0 ||
    !safePath(input.key) ||
    new TextEncoder().encode(input.key).byteLength > MAX_R2_KEY_BYTES ||
    !SHA256_PATTERN.test(input.sha256) ||
    !safePath(input.sourcePath)
  ) invalid();
  return Object.freeze({
    byteSize: input.byteSize,
    contentType: input.contentType,
    key: input.key,
    sha256: input.sha256,
    sourcePath: input.sourcePath,
  });
}

function parseObjectPlan<Input>(input: Input): R2ReleaseObjectPlan {
  const result = v.safeParse(objectPlanSchema, input);
  if (!result.success) invalid();
  const value = result.output;
  if (
    !SHA256_PATTERN.test(value.artifactSha256) ||
    !CHANNEL_PATTERN.test(value.channel) ||
    MUTABLE_CHANNELS.has(value.channel) ||
    !KEY_ID_PATTERN.test(value.keyId) ||
    !RELEASE_PATTERN.test(value.release) ||
    value.objectCount > MAX_RELEASE_OBJECT_COUNT || value.objectCount < 2 ||
    value.totalByteSize > MAX_TOTAL_OBJECT_BYTES
  ) invalid();

  const expectedPrefix = `${RELEASE_BUCKET_ROOT}/${value.channel}/${value.release}/`;
  if (value.prefix !== expectedPrefix || !safePath(expectedPrefix.slice(0, -1))) invalid();
  const objects = value.objects.map(immutablePlanEntry);
  if (objects.length !== value.objectCount) invalid();
  const keys = new Set<string>();
  let totalByteSize = 0;
  for (let index = 0; index < objects.length; index += 1) {
    const object = objects.at(index);
    const previous = objects.at(index - 1);
    if (
      object === undefined ||
      !object.key.startsWith(expectedPrefix) ||
      object.key === expectedPrefix ||
      object.sourcePath !== `objects/${object.key}` ||
      keys.has(object.key) ||
      (index > 0 && (previous === undefined || previous.key >= object.key))
    ) invalid();
    keys.add(object.key);
    totalByteSize += object.byteSize;
    if (!Number.isSafeInteger(totalByteSize) || totalByteSize > MAX_TOTAL_OBJECT_BYTES) invalid();
  }
  if (totalByteSize !== value.totalByteSize) invalid();
  return Object.freeze({
    artifactSha256: value.artifactSha256,
    channel: value.channel,
    immutability: Object.freeze({
      externalAtomicCreateOnlyRequired: true,
      overwriteAllowed: false,
    }),
    keyId: value.keyId,
    objectCount: value.objectCount,
    objects: Object.freeze(objects),
    prefix: expectedPrefix,
    release: value.release,
    schemaVersion: 1,
    totalByteSize: value.totalByteSize,
  });
}

function parseBlobInputs<Input>(
  input: Input,
  plan: R2ReleaseObjectPlan,
): readonly R2ReleasePublicationBlob[] {
  const result = v.safeParse(v.array(publicationBlobSchema), input);
  if (!result.success || result.output.length !== plan.objects.length) invalid();
  const blobs: R2ReleasePublicationBlob[] = [];
  for (let index = 0; index < result.output.length; index += 1) {
    const entry = result.output.at(index);
    const object = plan.objects.at(index);
    if (
      entry === undefined || object === undefined ||
      entry.key !== object.key ||
      entry.bytes.size !== object.byteSize ||
      entry.bytes.type !== object.contentType
    ) invalid();
    blobs.push(Object.freeze({ key: entry.key, bytes: entry.bytes }));
  }
  return Object.freeze(blobs);
}

async function sha256Hex(bytes: Uint8Array<ArrayBuffer>): Promise<string> {
  let digest: Uint8Array<ArrayBuffer>;
  try {
    digest = new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));
  } catch {
    unavailable();
  }
  return [...digest].map((byte) => byte.toString(16).padStart(2, '0')).join('');
}

async function blobBytes(blob: Blob, maximumBytes: number): Promise<Uint8Array<ArrayBuffer>> {
  if (blob.size > maximumBytes) invalid();
  let raw: ArrayBuffer;
  try {
    raw = await blob.arrayBuffer();
  } catch {
    invalid();
  }
  const bytes = new Uint8Array(raw);
  if (bytes.byteLength !== blob.size) invalid();
  const owned = new Uint8Array(bytes.byteLength);
  owned.set(bytes);
  return owned;
}

function releaseRecords(manifest: ReleaseManifest): readonly ReleaseFileRecord[] {
  return Object.freeze([
    ...manifest.components.admin.files,
    ...manifest.components.installer.files,
    ...manifest.components.worker.files,
    ...manifest.components.workerCleanup.files,
    ...manifest.components.workerRetirement.files,
  ].sort((left, right) => lexicalCompare(left.path, right.path)));
}

function decodeUtf8(bytes: Uint8Array<ArrayBuffer>): string {
  try {
    return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch {
    invalid();
  }
}

function parseEnvelope(serialized: string, plan: R2ReleaseObjectPlan): ReleaseManifest {
  let parsed: v.InferOutput<typeof releaseEnvelopeSchema>;
  try {
    const result = v.safeParse(releaseEnvelopeSchema, JSON.parse(serialized));
    if (!result.success) invalid();
    parsed = result.output;
    if (canonicalJson(parsed) !== serialized) invalid();
  } catch (error) {
    if (error instanceof R2ReleasePublicationError) throw error;
    invalid();
  }
  if (
    parsed.channel !== plan.channel ||
    parsed.keyId !== plan.keyId ||
    !SIGNATURE_PATTERN.test(parsed.signature)
  ) invalid();
  let manifest: ReleaseManifest;
  try {
    manifest = parseCanonicalReleaseManifest(parsed.manifest);
  } catch {
    invalid();
  }
  if (
    manifest.release !== plan.release ||
    manifest.artifact.treeSha256 !== plan.artifactSha256
  ) invalid();
  return manifest;
}

async function assertManifestTreeDigests(manifest: ReleaseManifest): Promise<void> {
  for (const component of [
    'admin',
    'installer',
    'worker',
    'workerCleanup',
    'workerRetirement',
  ] as const) {
    const bytes = new TextEncoder().encode(canonicalJson(manifest.components[component].files));
    if (await sha256Hex(bytes) !== manifest.components[component].treeSha256) invalid();
  }
  const records = releaseRecords(manifest);
  const bytes = new TextEncoder().encode(canonicalJson(records));
  if (await sha256Hex(bytes) !== manifest.artifact.treeSha256) invalid();
}

function releaseObjectMetadata(
  plan: R2ReleaseObjectPlan,
  object: R2ReleaseObjectPlanEntry,
  kind: 'payload' | 'release-envelope',
  planSha256: string,
): Readonly<Record<string, string>> {
  return Object.freeze({
    ankkaKind: kind,
    ankkaObjectSha256: object.sha256,
    ankkaPlanSha256: planSha256,
    ankkaRelease: plan.release,
  });
}

async function preparePublication<ObjectPlan, BlobInput>(
  objectPlan: ObjectPlan,
  blobInput: BlobInput,
): Promise<PreparedPublication> {
  const plan = parseObjectPlan(objectPlan);
  const blobs = parseBlobInputs(blobInput, plan);
  const planSha256 = await sha256Hex(new TextEncoder().encode(canonicalJson(plan)));
  const desired: DesiredObject[] = [];
  for (let index = 0; index < plan.objects.length; index += 1) {
    const object = plan.objects.at(index);
    const blob = blobs.at(index);
    if (object === undefined || blob === undefined) invalid();
    const maximum = object.key === `${plan.prefix}${ENVELOPE_FILENAME}`
      ? MAX_ENVELOPE_BYTES
      : MAX_RELEASE_FILE_BYTES;
    const bytes = await blobBytes(blob.bytes, maximum);
    if (await sha256Hex(bytes) !== object.sha256) invalid();
    desired.push(Object.freeze({
      key: object.key,
      bytes,
      byteSize: object.byteSize,
      contentType: object.contentType,
      sha256: object.sha256,
      customMetadata: releaseObjectMetadata(
        plan,
        object,
        object.key === `${plan.prefix}${ENVELOPE_FILENAME}` ? 'release-envelope' : 'payload',
        planSha256,
      ),
    }));
  }

  const envelopeKey = `${plan.prefix}${ENVELOPE_FILENAME}`;
  const envelope = desired.find((object) => object.key === envelopeKey);
  if (!envelope || envelope.contentType !== ENVELOPE_CONTENT_TYPE) invalid();
  const manifest = parseEnvelope(decodeUtf8(envelope.bytes), plan);
  await assertManifestTreeDigests(manifest);
  const records = releaseRecords(manifest);
  if (
    plan.objectCount !== records.length + 1 ||
    plan.totalByteSize !== manifest.artifact.byteSize + envelope.byteSize
  ) invalid();
  const expected = new Map<string, ReleaseFileRecord>(records.map((record) => [
    `${plan.prefix}${record.path}`,
    record,
  ]));
  if (expected.size !== records.length) invalid();
  for (const object of plan.objects) {
    if (object.key === envelopeKey) continue;
    const record = expected.get(object.key);
    if (
      !record ||
      object.key.slice(plan.prefix.length) !== record.path ||
      new TextEncoder().encode(record.path).byteLength > MAX_PAYLOAD_PATH_BYTES ||
      object.byteSize !== record.byteSize ||
      object.contentType !== record.contentType ||
      object.sha256 !== record.sha256
    ) invalid();
    expected.delete(object.key);
  }
  if (expected.size !== 0) invalid();
  const payloads = desired.filter((object) => object !== envelope);
  return Object.freeze({
    plan,
    planSha256,
    envelope,
    payloads: Object.freeze(payloads),
    allReleaseObjects: Object.freeze(desired),
  });
}

function bytesEqual(left: Uint8Array<ArrayBuffer>, right: Uint8Array<ArrayBuffer>): boolean {
  if (left.byteLength !== right.byteLength) return false;
  let mismatch = 0;
  for (let index = 0; index < left.byteLength; index += 1) {
    const leftByte = left.at(index);
    const rightByte = right.at(index);
    if (leftByte === undefined || rightByte === undefined) return false;
    mismatch |= leftByte ^ rightByte;
  }
  return mismatch === 0;
}

function metadataEqual(
  actual: Readonly<Record<string, string>> | undefined,
  expected: Readonly<Record<string, string>>,
): boolean {
  if (!actual) return false;
  const actualKeys = Object.keys(actual).sort();
  const expectedKeys = Object.keys(expected).sort();
  return actualKeys.length === expectedKeys.length &&
    actualKeys.every((key, index) => key === expectedKeys[index] && actual[key] === expected[key]);
}

async function readObject(
  bucket: R2ReleaseBucket,
  key: string,
  maximumBytes: number,
): Promise<ReadObject | null> {
  let object: R2ReleaseStoredObject | null;
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
    object.size > maximumBytes
  ) conflict();
  let raw: ArrayBuffer;
  try {
    raw = await object.arrayBuffer();
  } catch {
    unavailable();
  }
  const bytes = new Uint8Array(raw);
  if (bytes.byteLength !== object.size) conflict();
  const owned = new Uint8Array(bytes.byteLength);
  owned.set(bytes);
  return Object.freeze({
    key,
    bytes: owned,
    byteSize: object.size,
    contentType: object.httpMetadata?.contentType,
    customMetadata: object.customMetadata ? Object.freeze({ ...object.customMetadata }) : undefined,
  });
}

function assertExactRead(actual: ReadObject, expected: DesiredObject): void {
  if (
    actual.key !== expected.key ||
    actual.byteSize !== expected.byteSize ||
    actual.contentType !== expected.contentType ||
    !metadataEqual(actual.customMetadata, expected.customMetadata) ||
    !bytesEqual(actual.bytes, expected.bytes)
  ) conflict();
}

async function putCreateOnly(bucket: R2ReleaseBucket, desired: DesiredObject): Promise<void> {
  try {
    await bucket.put(desired.key, desired.bytes, {
      onlyIf: new Headers({ 'If-None-Match': '*' }),
      sha256: desired.sha256,
      httpMetadata: { contentType: desired.contentType },
      customMetadata: { ...desired.customMetadata },
    });
  } catch {
    // A rejected request can be a transport/timeout ambiguity after R2 committed
    // it. Strongly consistent exact GET settlement below is authoritative.
  }
  const observed = await readObject(bucket, desired.key, desired.byteSize);
  if (!observed) unavailable();
  assertExactRead(observed, desired);
}

function intentKey(plan: R2ReleaseObjectPlan): string {
  return `${PUBLICATION_INTENT_ROOT}/${plan.channel}/${plan.release}.json`;
}

function parsePublicationIntent(
  serialized: string,
  prepared: PreparedPublication,
  now: number,
): PublicationIntent {
  let parsed: v.InferOutput<typeof publicationIntentSchema>;
  try {
    const result = v.safeParse(publicationIntentSchema, JSON.parse(serialized));
    if (!result.success) conflict();
    parsed = result.output;
    if (canonicalJson(parsed) !== serialized) conflict();
  } catch (error) {
    if (error instanceof R2ReleasePublicationError) throw error;
    conflict();
  }
  const plan = prepared.plan;
  if (
    parsed.artifactSha256 !== plan.artifactSha256 ||
    parsed.channel !== plan.channel ||
    parsed.createdAt > now ||
    parsed.keyId !== plan.keyId ||
    parsed.objectCount !== plan.objectCount ||
    parsed.objectPlanSha256 !== prepared.planSha256 ||
    parsed.prefix !== plan.prefix ||
    parsed.release !== plan.release ||
    parsed.totalByteSize !== plan.totalByteSize
  ) conflict();
  return Object.freeze({ ...parsed });
}

function intentMetadata(
  intent: PublicationIntent,
  intentSha256: string,
): Readonly<Record<string, string>> {
  return Object.freeze({
    ankkaKind: 'publication-intent',
    ankkaObjectSha256: intentSha256,
    ankkaPlanSha256: intent.objectPlanSha256,
    ankkaRelease: intent.release,
  });
}

async function desiredIntent(
  prepared: PreparedPublication,
  bucket: R2ReleaseBucket,
  now: number,
): Promise<{ desired: DesiredObject; existed: boolean; intent: PublicationIntent }> {
  const key = intentKey(prepared.plan);
  const existing = await readObject(bucket, key, MAX_INTENT_BYTES);
  let intent: PublicationIntent;
  let bytes: Uint8Array<ArrayBuffer>;
  if (existing) {
    intent = parsePublicationIntent(decodeUtf8(existing.bytes), prepared, now);
    bytes = existing.bytes;
  } else {
    const plan = prepared.plan;
    intent = Object.freeze({
      artifactSha256: plan.artifactSha256,
      channel: plan.channel,
      createdAt: now,
      keyId: plan.keyId,
      objectCount: plan.objectCount,
      objectPlanSha256: prepared.planSha256,
      prefix: plan.prefix,
      release: plan.release,
      schemaVersion: 1,
      totalByteSize: plan.totalByteSize,
    });
    bytes = new TextEncoder().encode(canonicalJson(intent));
  }
  if (bytes.byteLength === 0 || bytes.byteLength > MAX_INTENT_BYTES) conflict();
  const digest = await sha256Hex(bytes);
  const desired = Object.freeze({
    key,
    bytes,
    byteSize: bytes.byteLength,
    contentType: INTENT_CONTENT_TYPE,
    sha256: digest,
    customMetadata: intentMetadata(intent, digest),
  });
  if (existing) assertExactRead(existing, desired);
  return Object.freeze({ desired, existed: existing !== null, intent });
}

async function listedPrefixObjects(
  bucket: R2ReleaseBucket,
  prefix: string,
): Promise<ReadonlyMap<string, number>> {
  const objects = new Map<string, number>();
  const cursors = new Set<string>();
  let cursor: string | undefined;
  let pages = 0;
  while (true) {
    pages += 1;
    if (pages > MAX_LIST_PAGES) conflict();
    let page: R2ReleaseObjectPage;
    try {
      const options = cursor === undefined
        ? { prefix, limit: LIST_PAGE_SIZE }
        : { prefix, limit: LIST_PAGE_SIZE, cursor };
      page = await bucket.list(options);
    } catch {
      unavailable();
    }
    for (const object of page.objects) {
      if (
        !object.key.startsWith(prefix) ||
        !Number.isSafeInteger(object.size) ||
        object.size < 0 ||
        object.size > MAX_TOTAL_OBJECT_BYTES ||
        objects.has(object.key)
      ) conflict();
      objects.set(object.key, object.size);
      if (objects.size > MAX_RELEASE_OBJECT_COUNT) conflict();
    }
    if (!page.truncated) break;
    const nextCursor = page.cursor;
    if (
      nextCursor === undefined ||
      nextCursor.length === 0 ||
      nextCursor.length > 4_096 ||
      cursors.has(nextCursor) ||
      page.objects.length === 0
    ) conflict();
    cursors.add(nextCursor);
    cursor = nextCursor;
  }
  return objects;
}

function assertExistingSubset(
  listed: ReadonlyMap<string, number>,
  expected: ReadonlyMap<string, number>,
  requireEmpty: boolean,
): void {
  if (requireEmpty && listed.size !== 0) conflict();
  for (const [key, size] of listed) {
    if (expected.get(key) !== size) conflict();
  }
}

function assertExactSet(
  listed: ReadonlyMap<string, number>,
  expected: ReadonlyMap<string, number>,
): void {
  if (listed.size !== expected.size) conflict();
  for (const [key, size] of expected) {
    if (listed.get(key) !== size) conflict();
  }
}

/**
 * Publishes one offline-signed release with consumer-atomic visibility. The
 * immutable intent burns the exact channel/release ID, every write is
 * conditional create-only, and the signed envelope is the final commit marker.
 * This module has no route, environment, Wrangler, or production-entrypoint
 * integration; an authenticated operator boundary must inject the R2 bucket.
 */
export async function publishCreateOnlyR2Release(
  input: PublishR2ReleaseInput,
): Promise<R2ReleasePublicationResult> {
  if (!v.safeParse(publicationInputSchema, input).success) invalid();
  const prepared = await preparePublication(input.objectPlan, input.blobs);
  let now: number;
  try {
    now = input.clock.now();
  } catch {
    invalid();
  }
  if (!Number.isSafeInteger(now) || now < 0) invalid();

  const intent = await desiredIntent(prepared, input.bucket, now);
  await putCreateOnly(input.bucket, intent.desired);

  const expected = new Map(prepared.allReleaseObjects.map((object) => [object.key, object.byteSize]));
  const before = await listedPrefixObjects(input.bucket, prepared.plan.prefix);
  assertExistingSubset(before, expected, !intent.existed);

  for (const payload of prepared.payloads) await putCreateOnly(input.bucket, payload);
  await putCreateOnly(input.bucket, prepared.envelope);

  const after = await listedPrefixObjects(input.bucket, prepared.plan.prefix);
  assertExactSet(after, expected);
  const observedIntent = await readObject(input.bucket, intent.desired.key, intent.desired.byteSize);
  if (!observedIntent) conflict();
  assertExactRead(observedIntent, intent.desired);
  for (const object of prepared.allReleaseObjects) {
    const observed = await readObject(input.bucket, object.key, object.byteSize);
    if (!observed) conflict();
    assertExactRead(observed, object);
  }

  return Object.freeze({
    schemaVersion: 1,
    status: 'published',
    channel: prepared.plan.channel,
    release: prepared.plan.release,
    prefix: prepared.plan.prefix,
    intentKey: intent.desired.key,
    objectCount: prepared.plan.objectCount,
    totalByteSize: prepared.plan.totalByteSize,
    objectPlanSha256: prepared.planSha256,
    createdAt: intent.intent.createdAt,
  });
}

import { DeployError } from './errors';
import type { VerifiedWorkerDirectUploadRelease } from './cloudflare-worker-direct-upload';
import {
  RELEASE_ENVELOPE_SCHEMA_VERSION,
  RELEASE_SIGNATURE_CONTEXT,
  verifyReleaseManifestDigests,
  type VerifiedReleaseBundle,
} from './release';
import {
  APPROVED_CLOUDFLARE_RELEASE_CONTRACT,
  canonicalJson,
  MAX_RELEASE_FILE_BYTES,
  MAX_RELEASE_PAYLOAD_BYTES,
  parseReleaseManifest,
  type ReleaseComponentName,
  type ReleaseFileRecord,
  type ReleaseManifest,
} from './release-manifest';

const KEY_ID_PATTERN = /^[a-z0-9][a-z0-9._-]{0,63}$/u;
const CONTROL_CHARACTER = /[\u0000-\u001f\u007f]/u;
const WORKER_PREFIX = 'payload/worker/';
const WORKER_CLEANUP_PREFIX = 'payload/worker-cleanup/';
const WORKER_RETIREMENT_PREFIX = 'payload/worker-retirement/';
const ADMIN_PREFIX = 'payload/admin/';

type CleanupContract = typeof APPROVED_CLOUDFLARE_RELEASE_CONTRACT.workerVariants.cleanup;
type RetirementContract = typeof APPROVED_CLOUDFLARE_RELEASE_CONTRACT.workerVariants.retirement;

export interface VerifiedCleanupWorkerRelease {
  readonly verification: 'ed25519';
  readonly release: string;
  /** Aggregate release digest, shared by every variant. */
  readonly artifactSha256: string;
  readonly componentSha256: string;
  readonly variant: 'cleanup';
  readonly worker: {
    readonly contract: CleanupContract;
    readonly modules: readonly VerifiedWorkerDirectUploadRelease['worker']['modules'][number][];
  };
}

export interface VerifiedRetirementWorkerRelease {
  readonly verification: 'ed25519';
  readonly release: string;
  /** Aggregate release digest, shared by every variant. */
  readonly artifactSha256: string;
  readonly componentSha256: string;
  readonly variant: 'retirement';
  readonly worker: {
    readonly contract: RetirementContract;
    readonly modules: readonly VerifiedWorkerDirectUploadRelease['worker']['modules'][number][];
  };
}

/**
 * Complete signed Worker handoff. The installer component is deliberately not
 * represented: its bytes are still read and verified before this value is
 * returned, then discarded.
 */
export interface VerifiedGatewayWorkerReleaseSet {
  readonly primary: VerifiedWorkerDirectUploadRelease;
  readonly cleanup: VerifiedCleanupWorkerRelease;
  readonly retirement: VerifiedRetirementWorkerRelease;
}

interface ExpectedPayloadRecord {
  readonly component: ReleaseComponentName;
  readonly record: ReleaseFileRecord;
}

interface PayloadSnapshot extends ExpectedPayloadRecord {
  readonly blob: Blob;
}

function invalid(): never {
  throw new DeployError(503, 'release_invalid');
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
}

function exactKeys(value: Record<string, unknown>, keys: readonly string[]): boolean {
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  return actual.length === expected.length && actual.every((key, index) => key === expected[index]);
}

function lexicalCompare(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function safeRelativePath(value: string): boolean {
  if (
    value.length === 0 ||
    value.startsWith('/') ||
    value.includes('\\') ||
    CONTROL_CHARACTER.test(value)
  ) return false;
  return value.split('/').every((segment) => segment !== '' && segment !== '.' && segment !== '..');
}

function assertApprovedCloudflareContract(manifestInput: Record<string, unknown>): void {
  const cloudflare = manifestInput.cloudflare;
  try {
    if (canonicalJson(cloudflare) !== canonicalJson(APPROVED_CLOUDFLARE_RELEASE_CONTRACT)) invalid();
  } catch {
    invalid();
  }
  if (!isRecord(cloudflare) || !isRecord(cloudflare.durableObjects)) invalid();
  if (!exactKeys(cloudflare.durableObjects, ['bindings', 'exports'])) invalid();
  if (!isRecord(cloudflare.durableObjects.exports)) invalid();
  if (!exactKeys(cloudflare.durableObjects.exports, ['AdminState'])) invalid();
  const adminState = cloudflare.durableObjects.exports.AdminState;
  if (
    !isRecord(adminState) ||
    !exactKeys(adminState, ['storage', 'type']) ||
    adminState.storage !== 'sqlite' ||
    adminState.type !== 'durable-object'
  ) invalid();

  if (Object.hasOwn(cloudflare.durableObjects, 'migrations')) invalid();
  if (!isRecord(cloudflare.workerVariants) || !exactKeys(cloudflare.workerVariants, ['cleanup', 'retirement'])) {
    invalid();
  }
  const cleanup = cloudflare.workerVariants.cleanup;
  const retirement = cloudflare.workerVariants.retirement;
  if (!isRecord(cleanup) || !isRecord(retirement)) invalid();
  if (Object.hasOwn(cleanup, 'migrations') || Object.hasOwn(retirement, 'migrations')) invalid();
  if (
    !isRecord(cleanup.durableObjects) ||
    Object.hasOwn(cleanup.durableObjects, 'migrations') ||
    canonicalJson(cleanup.durableObjects) !== canonicalJson({
      bindings: [{ binding: 'ADMIN_STATE', className: 'AdminState' }],
      exports: { AdminState: { storage: 'sqlite', type: 'durable-object' } },
    }) ||
    !isRecord(retirement.durableObjects) ||
    Object.hasOwn(retirement.durableObjects, 'migrations') ||
    canonicalJson(retirement.durableObjects) !== canonicalJson({
      bindings: [],
      exports: { AdminState: { state: 'deleted', type: 'durable-object' } },
    })
  ) invalid();
}

function expectedPayload(manifest: ReleaseManifest): readonly ExpectedPayloadRecord[] {
  const expected: ExpectedPayloadRecord[] = [];
  for (const component of [
    'admin',
    'installer',
    'worker',
    'workerCleanup',
    'workerRetirement',
  ] as const) {
    for (const record of manifest.components[component].files) {
      expected.push(Object.freeze({ component, record }));
    }
  }
  expected.sort((left, right) => lexicalCompare(left.record.path, right.record.path));
  return Object.freeze(expected);
}

function snapshotPayload(
  input: readonly unknown[],
  expected: readonly ExpectedPayloadRecord[],
  manifest: ReleaseManifest,
): ReadonlyMap<string, PayloadSnapshot> {
  if (input.length !== manifest.artifact.fileCount || input.length !== expected.length) invalid();
  const records = new Map(expected.map((entry) => [entry.record.path, entry]));
  const snapshots = new Map<string, PayloadSnapshot>();
  let declaredBytes = 0;

  for (const entry of input) {
    if (!isRecord(entry) || !exactKeys(entry, ['byteSize', 'bytes', 'contentType', 'path', 'sha256'])) invalid();
    if (typeof entry.path !== 'string' || snapshots.has(entry.path)) invalid();
    const expectedEntry = records.get(entry.path);
    if (!expectedEntry) invalid();
    const { record } = expectedEntry;
    if (
      typeof entry.byteSize !== 'number' ||
      !Number.isSafeInteger(entry.byteSize) ||
      entry.byteSize < 0 ||
      (entry.byteSize === 0 && expectedEntry.component !== 'installer') ||
      entry.byteSize > MAX_RELEASE_FILE_BYTES ||
      entry.byteSize !== record.byteSize ||
      typeof entry.contentType !== 'string' ||
      entry.contentType !== record.contentType ||
      typeof entry.sha256 !== 'string' ||
      entry.sha256 !== record.sha256 ||
      !(entry.bytes instanceof Blob) ||
      entry.bytes.size !== record.byteSize ||
      entry.bytes.type !== record.contentType
    ) invalid();
    declaredBytes += entry.byteSize;
    if (!Number.isSafeInteger(declaredBytes) || declaredBytes > MAX_RELEASE_PAYLOAD_BYTES) invalid();
    snapshots.set(entry.path, Object.freeze({
      component: expectedEntry.component,
      record,
      blob: entry.bytes,
    }));
  }
  if (snapshots.size !== expected.length || declaredBytes !== manifest.artifact.byteSize) invalid();
  return snapshots;
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');
}

async function sha256(bytes: Uint8Array): Promise<string> {
  const owned = new Uint8Array(bytes.byteLength);
  owned.set(bytes);
  return bytesToHex(new Uint8Array(await crypto.subtle.digest('SHA-256', owned)));
}

async function readExactBlob(snapshot: PayloadSnapshot): Promise<Uint8Array> {
  let buffer: ArrayBuffer;
  try {
    buffer = await Blob.prototype.arrayBuffer.call(snapshot.blob) as ArrayBuffer;
  } catch {
    invalid();
  }
  if (
    !(buffer instanceof ArrayBuffer) ||
    (buffer.byteLength === 0 && snapshot.component !== 'installer') ||
    buffer.byteLength > MAX_RELEASE_FILE_BYTES ||
    buffer.byteLength !== snapshot.record.byteSize
  ) invalid();
  const bytes = new Uint8Array(buffer);
  if (await sha256(bytes) !== snapshot.record.sha256) invalid();
  return bytes;
}

function workerModuleName(path: string, prefix: string): string {
  if (!path.startsWith(prefix)) invalid();
  const name = path.slice(prefix.length);
  if (!safeRelativePath(name)) invalid();
  return name;
}

function adminAssetPath(path: string): string {
  if (!path.startsWith(ADMIN_PREFIX)) invalid();
  const relative = path.slice(ADMIN_PREFIX.length);
  if (!safeRelativePath(relative)) invalid();
  return `/${relative}`;
}

/**
 * Pure handoff from the signed release-bundle boundary to the reviewed Worker
 * direct-upload primitive. This module is intentionally not runtime-wired.
 */
export async function adaptVerifiedReleaseBundleForWorkerDirectUpload(
  bundle: VerifiedReleaseBundle,
): Promise<VerifiedWorkerDirectUploadRelease> {
  return (await adaptVerifiedReleaseBundleForGatewayDeployments(bundle)).primary;
}

/**
 * Pure handoff from the signed five-component release bundle to the three
 * customer-Worker deployment variants. This module is intentionally not
 * runtime-wired.
 */
export async function adaptVerifiedReleaseBundleForGatewayDeployments(
  bundle: VerifiedReleaseBundle,
): Promise<VerifiedGatewayWorkerReleaseSet> {
  const input: unknown = bundle;
  if (!isRecord(input) || !exactKeys(input, [
    'channel', 'envelope', 'keyId', 'manifest', 'payload', 'publicKey', 'verification',
  ])) invalid();
  if (
    input.verification !== 'ed25519' ||
    typeof input.channel !== 'string' || !/^(?:canary|stable)$/u.test(input.channel) ||
    typeof input.keyId !== 'string' ||
    !KEY_ID_PATTERN.test(input.keyId) ||
    !isRecord(input.manifest) ||
    !isRecord(input.envelope) ||
    !exactKeys(input.envelope, [
      'channel', 'keyId', 'manifest', 'schemaVersion', 'signature', 'signatureContext',
    ]) ||
    input.envelope.schemaVersion !== RELEASE_ENVELOPE_SCHEMA_VERSION ||
    input.envelope.channel !== input.channel ||
    input.envelope.keyId !== input.keyId ||
    input.envelope.manifest !== canonicalJson(input.manifest) ||
    typeof input.envelope.signature !== 'string' ||
    !/^[A-Za-z0-9_-]{86}$/u.test(input.envelope.signature) ||
    input.envelope.signatureContext !== RELEASE_SIGNATURE_CONTEXT ||
    typeof input.publicKey !== 'string' ||
    !/^[A-Za-z0-9_-]{43}$/u.test(input.publicKey) ||
    !Array.isArray(input.payload)
  ) invalid();

  assertApprovedCloudflareContract(input.manifest);
  const manifest = parseReleaseManifest(input.manifest);
  await verifyReleaseManifestDigests(manifest);
  const expected = expectedPayload(manifest);
  const snapshots = snapshotPayload(input.payload, expected, manifest);
  const modules: Array<VerifiedWorkerDirectUploadRelease['worker']['modules'][number]> = [];
  const cleanupModules: Array<VerifiedWorkerDirectUploadRelease['worker']['modules'][number]> = [];
  const retirementModules: Array<VerifiedWorkerDirectUploadRelease['worker']['modules'][number]> = [];
  const assets: Array<VerifiedWorkerDirectUploadRelease['worker']['assets']['files'][number]> = [];
  let readBytes = 0;

  for (const expectedEntry of expected) {
    const snapshot = snapshots.get(expectedEntry.record.path);
    if (!snapshot || snapshot.component !== expectedEntry.component || snapshot.record !== expectedEntry.record) invalid();
    const bytes = await readExactBlob(snapshot);
    readBytes += bytes.byteLength;
    if (!Number.isSafeInteger(readBytes) || readBytes > MAX_RELEASE_PAYLOAD_BYTES) invalid();

    if (snapshot.component === 'worker') {
      modules.push(Object.freeze({
        name: workerModuleName(snapshot.record.path, WORKER_PREFIX),
        contentType: snapshot.record.contentType,
        sha256: snapshot.record.sha256,
        bytes,
      }));
    } else if (snapshot.component === 'workerCleanup') {
      cleanupModules.push(Object.freeze({
        name: workerModuleName(snapshot.record.path, WORKER_CLEANUP_PREFIX),
        contentType: snapshot.record.contentType,
        sha256: snapshot.record.sha256,
        bytes,
      }));
    } else if (snapshot.component === 'workerRetirement') {
      retirementModules.push(Object.freeze({
        name: workerModuleName(snapshot.record.path, WORKER_RETIREMENT_PREFIX),
        contentType: snapshot.record.contentType,
        sha256: snapshot.record.sha256,
        bytes,
      }));
    } else if (snapshot.component === 'admin') {
      assets.push(Object.freeze({
        path: adminAssetPath(snapshot.record.path),
        contentType: snapshot.record.contentType,
        sha256: snapshot.record.sha256,
        bytes,
      }));
    } else {
      // Installer files prove aggregate release completeness but are never part
      // of the customer Worker upload.
      bytes.fill(0);
    }
  }
  if (
    readBytes !== manifest.artifact.byteSize ||
    modules.length !== manifest.components.worker.fileCount ||
    cleanupModules.length !== manifest.components.workerCleanup.fileCount ||
    retirementModules.length !== manifest.components.workerRetirement.fileCount ||
    assets.length !== manifest.components.admin.fileCount ||
    !modules.some((module) => module.name === manifest.cloudflare.mainModule) ||
    !cleanupModules.some((module) => module.name === manifest.cloudflare.workerVariants.cleanup.mainModule) ||
    !retirementModules.some((module) => module.name === manifest.cloudflare.workerVariants.retirement.mainModule) ||
    !assets.some((asset) => asset.path === '/index.html')
  ) invalid();

  modules.sort((left, right) => lexicalCompare(left.name, right.name));
  cleanupModules.sort((left, right) => lexicalCompare(left.name, right.name));
  retirementModules.sort((left, right) => lexicalCompare(left.name, right.name));
  assets.sort((left, right) => lexicalCompare(left.path, right.path));
  const durableObjectBinding = manifest.cloudflare.durableObjects.bindings[0];
  const durableObjectExport = manifest.cloudflare.durableObjects.exports.AdminState;
  const primary: VerifiedWorkerDirectUploadRelease = Object.freeze({
    verification: 'ed25519',
    release: manifest.release,
    artifactSha256: manifest.artifact.treeSha256,
    worker: Object.freeze({
      mainModule: manifest.cloudflare.mainModule,
      compatibilityDate: manifest.cloudflare.compatibilityDate,
      compatibilityFlags: Object.freeze([] as const),
      modules: Object.freeze(modules),
      assets: Object.freeze({
        binding: manifest.cloudflare.assets.binding,
        notFoundHandling: manifest.cloudflare.assets.notFoundHandling,
        runWorkerFirst: Object.freeze(['/__ankka/*', '/api/*'] as const),
        files: Object.freeze(assets),
      }),
      durableObject: Object.freeze({
        binding: durableObjectBinding.binding,
        className: durableObjectBinding.className,
        storage: durableObjectExport.storage,
      }),
    }),
  });
  const cleanup: VerifiedCleanupWorkerRelease = Object.freeze({
    verification: 'ed25519',
    release: manifest.release,
    artifactSha256: manifest.artifact.treeSha256,
    componentSha256: manifest.components.workerCleanup.treeSha256,
    variant: 'cleanup',
    worker: Object.freeze({
      contract: manifest.cloudflare.workerVariants.cleanup,
      modules: Object.freeze(cleanupModules),
    }),
  });
  const retirement: VerifiedRetirementWorkerRelease = Object.freeze({
    verification: 'ed25519',
    release: manifest.release,
    artifactSha256: manifest.artifact.treeSha256,
    componentSha256: manifest.components.workerRetirement.treeSha256,
    variant: 'retirement',
    worker: Object.freeze({
      contract: manifest.cloudflare.workerVariants.retirement,
      modules: Object.freeze(retirementModules),
    }),
  });
  return Object.freeze({ primary, cleanup, retirement });
}

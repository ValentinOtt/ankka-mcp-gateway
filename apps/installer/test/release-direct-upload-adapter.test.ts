import { REQUIRED_OAUTH_SCOPES } from '../src/constants';
import { prepareVerifiedWorkerRelease } from '../src/cloudflare-worker-direct-upload';
import {
  adaptVerifiedReleaseBundleForGatewayDeployments,
  adaptVerifiedReleaseBundleForWorkerDirectUpload,
} from '../src/release-direct-upload-adapter';
import type { VerifiedReleaseBundle, VerifiedReleasePayloadBlob } from '../src/release';
import {
  APPROVED_CLOUDFLARE_RELEASE_CONTRACT,
  canonicalJson,
  MAX_RELEASE_FILE_BYTES,
  parseReleaseManifest,
  type ReleaseComponent,
  type ReleaseFileRecord,
  type ReleaseManifest,
} from '../src/release-manifest';

const encoder = new TextEncoder();
const decoder = new TextDecoder();

interface Fixture {
  readonly bundle: VerifiedReleaseBundle;
  readonly manifest: ReleaseManifest;
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');
}

async function sha256(value: Uint8Array | string): Promise<string> {
  const bytes = typeof value === 'string' ? encoder.encode(value) : value;
  const owned = new Uint8Array(bytes.byteLength);
  owned.set(bytes);
  return bytesToHex(new Uint8Array(await crypto.subtle.digest('SHA-256', owned)));
}

async function file(
  path: string,
  contentType: string,
  bytes: Uint8Array,
): Promise<{ readonly bytes: Uint8Array; readonly record: ReleaseFileRecord }> {
  return {
    bytes,
    record: Object.freeze({
      byteSize: bytes.byteLength,
      contentType,
      path,
      sha256: await sha256(bytes),
    }),
  };
}

async function component(files: readonly ReleaseFileRecord[]): Promise<ReleaseComponent> {
  return Object.freeze({
    byteSize: files.reduce((total, entry) => total + entry.byteSize, 0),
    fileCount: files.length,
    files: Object.freeze([...files]),
    treeSha256: await sha256(canonicalJson(files)),
  });
}

async function fixture(): Promise<Fixture> {
  const source = [
    await file(
      'payload/admin/app.js',
      'text/javascript; charset=utf-8',
      encoder.encode('globalThis.__ADMIN_RELEASE__ = true;'),
    ),
    await file(
      'payload/admin/index.html',
      'text/html; charset=utf-8',
      encoder.encode('<!doctype html><main>admin</main>'),
    ),
    await file(
      'payload/installer/index.html',
      'text/html; charset=utf-8',
      encoder.encode('<!doctype html><main>installer-only-marker</main>'),
    ),
    await file(
      'payload/worker-cleanup/index.js',
      'application/javascript+module',
      encoder.encode('export class AdminState {}; export default { fetch() { return new Response("cleanup"); } };'),
    ),
    await file(
      'payload/worker-retirement/index.js',
      'application/javascript+module',
      encoder.encode('export default { fetch() { return new Response(null, { status: 410 }); } };'),
    ),
    await file(
      'payload/worker/index.js',
      'application/javascript+module',
      encoder.encode('export default { fetch() { return new Response("ok"); } };'),
    ),
    await file(
      'payload/worker/support.wasm',
      'application/wasm',
      Uint8Array.of(0, 97, 115, 109, 1, 0, 0, 0),
    ),
  ] as const;
  const admin = await component(source.slice(0, 2).map((entry) => entry.record));
  const installer = await component(source.slice(2, 3).map((entry) => entry.record));
  const workerCleanup = await component(source.slice(3, 4).map((entry) => entry.record));
  const workerRetirement = await component(source.slice(4, 5).map((entry) => entry.record));
  const worker = await component(source.slice(5).map((entry) => entry.record));
  const records = source.map((entry) => entry.record);
  const manifest = parseReleaseManifest({
    artifact: {
      byteSize: records.reduce((total, entry) => total + entry.byteSize, 0),
      fileCount: records.length,
      treeSha256: await sha256(canonicalJson(records)),
    },
    cloudflare: APPROVED_CLOUDFLARE_RELEASE_CONTRACT,
    components: { admin, installer, worker, workerCleanup, workerRetirement },
    oauthScopeIds: REQUIRED_OAUTH_SCOPES,
    release: 'gateway-v1.2.3',
    schemaVersion: 1,
    sourceCommit: '0123456789abcdef0123456789abcdef01234567',
  });
  const payload = Object.freeze(source.map((entry): VerifiedReleasePayloadBlob => Object.freeze({
    ...entry.record,
    bytes: new Blob([new Uint8Array(entry.bytes)], { type: entry.record.contentType }),
  })));
  return {
    manifest,
    bundle: Object.freeze({
      verification: 'ed25519',
      channel: 'stable',
      keyId: 'release-key-1',
      envelope: Object.freeze({
        schemaVersion: 2, channel: 'stable', keyId: 'release-key-1',
        manifest: canonicalJson(manifest), signature: 'A'.repeat(86),
        signatureContext: 'ankka-mcp-gateway-release-envelope-v2',
      }),
      manifest,
      payload,
      publicKey: 'A'.repeat(43),
    }),
  };
}

function replacePayload(
  bundle: VerifiedReleaseBundle,
  payload: readonly unknown[],
): VerifiedReleaseBundle {
  return { ...bundle, payload } as unknown as VerifiedReleaseBundle;
}

function rawManifest(manifest: ReleaseManifest): Record<string, unknown> {
  return JSON.parse(canonicalJson(manifest)) as Record<string, unknown>;
}

function replaceManifest(
  bundle: VerifiedReleaseBundle,
  manifest: unknown,
): VerifiedReleaseBundle {
  return { ...bundle, manifest } as unknown as VerifiedReleaseBundle;
}

async function expectInvalid(bundle: VerifiedReleaseBundle): Promise<void> {
  await expect(adaptVerifiedReleaseBundleForWorkerDirectUpload(bundle)).rejects.toMatchObject({
    code: 'release_invalid',
    status: 503,
  });
}

describe('verified release bundle direct-upload adapter', () => {
  it('binds aggregate release identity and maps only Worker modules and admin assets', async () => {
    const input = await fixture();
    const release = await adaptVerifiedReleaseBundleForWorkerDirectUpload(input.bundle);

    expect(release).toMatchObject({
      verification: 'ed25519',
      release: input.manifest.release,
      artifactSha256: input.manifest.artifact.treeSha256,
      worker: {
        mainModule: 'index.js',
        compatibilityDate: '2026-08-08',
        compatibilityFlags: [],
        durableObject: { binding: 'ADMIN_STATE', className: 'AdminState', storage: 'sqlite' },
        assets: {
          binding: 'ASSETS',
          notFoundHandling: 'single-page-application',
          runWorkerFirst: ['/__ankka/*', '/api/*'],
        },
      },
    });
    expect(release.artifactSha256).not.toBe(input.manifest.components.worker.treeSha256);
    expect(release.artifactSha256).not.toBe(input.manifest.components.admin.treeSha256);
    expect(release.worker.modules.map((entry) => [entry.name, entry.contentType])).toEqual([
      ['index.js', 'application/javascript+module'],
      ['support.wasm', 'application/wasm'],
    ]);
    expect(release.worker.assets.files.map((entry) => [entry.path, entry.contentType])).toEqual([
      ['/app.js', 'text/javascript; charset=utf-8'],
      ['/index.html', 'text/html; charset=utf-8'],
    ]);
    const uploadedText = [
      ...release.worker.modules.map((entry) => decoder.decode(entry.bytes)),
      ...release.worker.assets.files.map((entry) => decoder.decode(entry.bytes)),
    ].join('\n');
    expect(uploadedText).not.toContain('installer-only-marker');
    expect(Object.isFrozen(release)).toBe(true);
    expect(Object.isFrozen(release.worker.modules)).toBe(true);
    expect(Object.isFrozen(release.worker.assets.files)).toBe(true);

    const prepared = await prepareVerifiedWorkerRelease({
      accountId: 'a'.repeat(32),
      workerName: 'ankka-gateway-example',
      release,
      plainTextBindings: {
        ADMIN_EMAILS: 'admin@example.com',
        ANKKA_GATEWAY_RELEASE: release.release,
        ANKKA_GATEWAY_RELEASE_SHA256: `sha256:${release.artifactSha256}`,
        ANKKA_MANAGEMENT_HOSTNAME: 'manage.example.com',
        ANKKA_UPDATE_CHANNEL: 'stable',
        ANKKA_UPDATE_KEY_ID: 'release-key-1',
        ANKKA_UPDATE_PUBLIC_KEY: 'A'.repeat(43),
        ANKKA_WORKERS_SUBDOMAIN: 'customer-workers',
        ANKKA_WORKER_NAME: 'ankka-gateway-example',
        CF_ACCESS_AUD: 'access-audience-tag',
        CF_ACCESS_ISSUER: 'https://example.cloudflareaccess.com',
        CLOUDFLARE_ACCOUNT_ID: 'a'.repeat(32),
        CLOUDFLARE_ZONE_ID: 'b'.repeat(32),
        CLOUDFLARE_ZONE_NAME: 'example.com',
        ZERO_TRUST_READY: 'true',
      },
      bootstrapNonce: 'bootstrap_nonce_value_that_is_never_returned',
    });
    expect(prepared.modules.map((entry) => entry.name)).toEqual(['index.js', 'support.wasm']);
    expect(prepared.assets.map((entry) => entry.path)).toEqual(['/app.js', '/index.html']);
  });

  it('exposes exact cleanup and declarative-retirement variants without installer bytes', async () => {
    const input = await fixture();
    const releases = await adaptVerifiedReleaseBundleForGatewayDeployments(input.bundle);

    expect(releases.primary.artifactSha256).toBe(input.manifest.artifact.treeSha256);
    expect(releases.cleanup).toMatchObject({
      verification: 'ed25519',
      release: input.manifest.release,
      artifactSha256: input.manifest.artifact.treeSha256,
      componentSha256: input.manifest.components.workerCleanup.treeSha256,
      variant: 'cleanup',
      worker: {
        contract: {
          component: 'workerCleanup',
          payloadDirectory: 'payload/worker-cleanup',
          publicPath: '/__ankka/uninstall',
          durableObjects: {
            bindings: [{ binding: 'ADMIN_STATE', className: 'AdminState' }],
            exports: { AdminState: { storage: 'sqlite', type: 'durable-object' } },
          },
        },
      },
    });
    expect(releases.retirement).toMatchObject({
      verification: 'ed25519',
      release: input.manifest.release,
      artifactSha256: input.manifest.artifact.treeSha256,
      componentSha256: input.manifest.components.workerRetirement.treeSha256,
      variant: 'retirement',
      worker: {
        contract: {
          component: 'workerRetirement',
          payloadDirectory: 'payload/worker-retirement',
          durableObjects: {
            bindings: [],
            exports: { AdminState: { state: 'deleted', type: 'durable-object' } },
          },
        },
      },
    });
    expect(releases.cleanup.worker.modules.map((entry) => entry.name)).toEqual(['index.js']);
    expect(releases.retirement.worker.modules.map((entry) => entry.name)).toEqual(['index.js']);
    const exposedText = [
      ...releases.primary.worker.modules,
      ...releases.primary.worker.assets.files,
      ...releases.cleanup.worker.modules,
      ...releases.retirement.worker.modules,
    ].map((entry) => decoder.decode(entry.bytes)).join('\n');
    expect(exposedText).not.toContain('installer-only-marker');
    expect(Object.isFrozen(releases)).toBe(true);
    expect(Object.isFrozen(releases.cleanup)).toBe(true);
    expect(Object.isFrozen(releases.cleanup.worker.modules)).toBe(true);
    expect(Object.isFrozen(releases.retirement.worker.modules)).toBe(true);
  });

  it('reads fresh immutable Blob contents instead of sharing prior output arrays', async () => {
    const input = await fixture();
    const first = await adaptVerifiedReleaseBundleForWorkerDirectUpload(input.bundle);
    const expected = first.worker.modules[0].bytes[0];
    first.worker.modules[0].bytes[0] ^= 0xff;

    const second = await adaptVerifiedReleaseBundleForWorkerDirectUpload(input.bundle);
    expect(second.worker.modules[0].bytes[0]).toBe(expected);
  });

  it('rejects missing, extra, duplicate, and traversal payload paths', async () => {
    const input = await fixture();
    const payload = input.bundle.payload;
    await expectInvalid(replacePayload(input.bundle, payload.slice(1)));
    await expectInvalid(replacePayload(
      input.bundle,
      payload.filter((entry) => !entry.path.startsWith('payload/installer/')),
    ));
    await expectInvalid(replacePayload(input.bundle, [
      { ...payload[0], path: 'payload/admin/extra.js' },
      ...payload.slice(1),
    ]));
    await expectInvalid(replacePayload(input.bundle, [payload[0], payload[0], ...payload.slice(2)]));
    await expectInvalid(replacePayload(input.bundle, [
      ...payload.slice(0, 2),
      { ...payload[2], path: 'payload/installer/../worker/index.js' },
      ...payload.slice(3),
    ]));
  });

  it('rejects payload metadata that is not the exact manifest record relation', async () => {
    const input = await fixture();
    const payload = input.bundle.payload;
    await expectInvalid(replacePayload(input.bundle, [
      { ...payload[0], sha256: payload[1].sha256 },
      ...payload.slice(1),
    ]));
    await expectInvalid(replacePayload(input.bundle, [
      { ...payload[0], contentType: 'application/javascript+module' },
      ...payload.slice(1),
    ]));
    await expectInvalid(replacePayload(input.bundle, [
      { ...payload[0], byteSize: payload[0].byteSize + 1 },
      ...payload.slice(1),
    ]));
  });

  it('rejects Blob type, size, and byte-digest mismatches', async () => {
    const input = await fixture();
    const payload = input.bundle.payload;
    await expectInvalid(replacePayload(input.bundle, [
      { ...payload[0], bytes: new Blob(['wrong type and bytes'], { type: 'text/plain' }) },
      ...payload.slice(1),
    ]));
    await expectInvalid(replacePayload(input.bundle, [
      { ...payload[0], bytes: new Blob([new Uint8Array(payload[0].byteSize + 1)], { type: payload[0].contentType }) },
      ...payload.slice(1),
    ]));
    const original = new Uint8Array(await payload[0].bytes.arrayBuffer());
    original[0] ^= 0xff;
    await expectInvalid(replacePayload(input.bundle, [
      { ...payload[0], bytes: new Blob([original], { type: payload[0].contentType }) },
      ...payload.slice(1),
    ]));
  });

  it('rejects unknown bundle and payload fields', async () => {
    const input = await fixture();
    await expectInvalid({ ...input.bundle, provider: 'r2' } as unknown as VerifiedReleaseBundle);
    await expectInvalid({
      ...input.bundle,
      envelope: { ...input.bundle.envelope, provider: 'r2' },
    } as unknown as VerifiedReleaseBundle);
    await expectInvalid(replacePayload(input.bundle, [
      { ...input.bundle.payload[0], mutableUrl: 'https://example.invalid' },
      ...input.bundle.payload.slice(1),
    ]));
  });

  it('rejects a non-Ed25519 provenance marker or malformed key id', async () => {
    const input = await fixture();
    await expectInvalid({ ...input.bundle, verification: 'checksum' } as unknown as VerifiedReleaseBundle);
    await expectInvalid({ ...input.bundle, keyId: '../release-key' });
    await expectInvalid({
      ...input.bundle,
      envelope: { ...input.bundle.envelope, channel: 'canary' },
    } as unknown as VerifiedReleaseBundle);
    await expectInvalid({
      ...input.bundle,
      envelope: {
        keyId: input.bundle.envelope.keyId,
        manifest: input.bundle.envelope.manifest,
        schemaVersion: 1,
        signature: input.bundle.envelope.signature,
      },
    } as unknown as VerifiedReleaseBundle);
  });

  it('re-validates component and aggregate tree hashes', async () => {
    const input = await fixture();
    const componentMismatch = rawManifest(input.manifest);
    const components = componentMismatch.components as Record<string, Record<string, unknown>>;
    components.worker.treeSha256 = 'f'.repeat(64);
    await expectInvalid(replaceManifest(input.bundle, componentMismatch));

    const aggregateMismatch = rawManifest(input.manifest);
    (aggregateMismatch.artifact as Record<string, unknown>).treeSha256 = 'e'.repeat(64);
    await expectInvalid(replaceManifest(input.bundle, aggregateMismatch));
  });

  it('rejects a manifest record placed under the wrong component', async () => {
    const input = await fixture();
    const manifest = rawManifest(input.manifest);
    const components = manifest.components as Record<string, Record<string, unknown>>;
    const adminFiles = components.admin.files as Array<Record<string, unknown>>;
    adminFiles[0].path = 'payload/worker/app.js';
    await expectInvalid(replaceManifest(input.bundle, manifest));
  });

  it('rejects Cloudflare Durable Object migrations or a changed exports contract', async () => {
    const input = await fixture();
    const withMigrations = rawManifest(input.manifest);
    const cloudflare = withMigrations.cloudflare as Record<string, unknown>;
    cloudflare.durableObjects = {
      ...(cloudflare.durableObjects as Record<string, unknown>),
      migrations: [{ new_sqlite_classes: ['AdminState'], tag: 'v1' }],
    };
    await expectInvalid(replaceManifest(input.bundle, withMigrations));

    const changedExports = rawManifest(input.manifest);
    const changedCloudflare = changedExports.cloudflare as Record<string, Record<string, unknown>>;
    changedCloudflare.durableObjects.exports = {
      AdminState: { storage: 'durable', type: 'durable-object' },
    };
    await expectInvalid(replaceManifest(input.bundle, changedExports));

    const cleanupMigration = rawManifest(input.manifest);
    const cleanupCloudflare = cleanupMigration.cloudflare as Record<string, Record<string, unknown>>;
    const cleanupVariants = cleanupCloudflare.workerVariants as Record<string, Record<string, unknown>>;
    cleanupVariants.cleanup.migrations = [{ deletedClasses: ['AdminState'], tag: 'v2' }];
    await expectInvalid(replaceManifest(input.bundle, cleanupMigration));

    const retirementDrift = rawManifest(input.manifest);
    const retirementCloudflare = retirementDrift.cloudflare as Record<string, Record<string, unknown>>;
    const variants = retirementCloudflare.workerVariants as Record<string, Record<string, unknown>>;
    const retirementObjects = variants.retirement.durableObjects as Record<string, unknown>;
    retirementObjects.exports = { AdminState: { storage: 'sqlite', type: 'durable-object' } };
    await expectInvalid(replaceManifest(input.bundle, retirementDrift));
  });

  it('enforces the per-file bound before reading a Blob', async () => {
    const input = await fixture();
    const payload = input.bundle.payload;
    await expectInvalid(replacePayload(input.bundle, [
      { ...payload[0], byteSize: MAX_RELEASE_FILE_BYTES + 1 },
      ...payload.slice(1),
    ]));
  });
});

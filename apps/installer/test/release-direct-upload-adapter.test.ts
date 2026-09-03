import * as v from 'valibot';

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
import { requiredFixture } from './fixtures';

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
  const bytes = v.is(v.string(), value) ? encoder.encode(value) : value;
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
      'payload/worker-bootstrap/index.js',
      'application/javascript+module',
      encoder.encode('export class AdminState {}; export default { fetch() { return new Response("bootstrap"); } };'),
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
      encoder.encode('// ankka-control-plane-origin:https://deploy.ankka.ai\nexport default { fetch() { return new Response("ok"); } };'),
    ),
    await file(
      'payload/worker/support.wasm',
      'application/wasm',
      Uint8Array.of(0, 97, 115, 109, 1, 0, 0, 0),
    ),
  ] as const;
  const admin = await component(source.slice(0, 2).map((entry) => entry.record));
  const installer = await component(source.slice(2, 3).map((entry) => entry.record));
  const workerBootstrap = await component(source.slice(3, 4).map((entry) => entry.record));
  const workerCleanup = await component(source.slice(4, 5).map((entry) => entry.record));
  const workerRetirement = await component(source.slice(5, 6).map((entry) => entry.record));
  const worker = await component(source.slice(6).map((entry) => entry.record));
  const records = source.map((entry) => entry.record);
  const manifest = parseReleaseManifest({
    artifact: {
      byteSize: records.reduce((total, entry) => total + entry.byteSize, 0),
      fileCount: records.length,
      treeSha256: await sha256(canonicalJson(records)),
    },
    cloudflare: APPROVED_CLOUDFLARE_RELEASE_CONTRACT,
    controlPlaneOrigin: 'https://deploy.ankka.ai',
    components: { admin, installer, worker, workerBootstrap, workerCleanup, workerRetirement },
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

function replacePayload<Payload>(
  bundle: VerifiedReleaseBundle,
  payload: Payload,
) {
  return { ...bundle, payload };
}

function replaceManifest<Manifest>(
  bundle: VerifiedReleaseBundle,
  manifest: Manifest,
) {
  return { ...bundle, manifest };
}

function withFilePatch<Patch extends object>(
  manifest: ReleaseManifest,
  componentName: keyof ReleaseManifest['components'],
  fileIndex: number,
  patch: Patch,
) {
  const component = manifest.components[componentName];
  return {
    ...manifest,
    components: {
      ...manifest.components,
      [componentName]: {
        ...component,
        files: component.files.map((entry, index) => index === fileIndex ? { ...entry, ...patch } : entry),
      },
    },
  };
}

async function expectInvalid<Input>(bundle: Input): Promise<void> {
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
        ANKKA_INSTALL_ID: `acg-${'e'.repeat(24)}`,
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
    expect(releases.bootstrap).toMatchObject({
      verification: 'ed25519',
      release: input.manifest.release,
      artifactSha256: input.manifest.artifact.treeSha256,
      componentSha256: input.manifest.components.workerBootstrap.treeSha256,
      worker: {
        mainModule: 'index.js',
        durableObject: { binding: 'ADMIN_STATE', className: 'AdminState', storage: 'sqlite' },
      },
    });
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
      ...releases.bootstrap.worker.modules,
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
    const firstModule = requiredFixture(first.worker.modules.at(0), 'first worker module');
    const expected = requiredFixture(firstModule.bytes.at(0), 'first worker byte');
    firstModule.bytes[0] = expected ^ 0xff;

    const second = await adaptVerifiedReleaseBundleForWorkerDirectUpload(input.bundle);
    const secondModule = requiredFixture(second.worker.modules.at(0), 'second worker module');
    expect(secondModule.bytes.at(0)).toBe(expected);
  });

  it('rejects missing, extra, duplicate, and traversal payload paths', async () => {
    const input = await fixture();
    const payload = input.bundle.payload;
    const first = requiredFixture(payload.at(0), 'first payload');
    const third = requiredFixture(payload.at(2), 'third payload');
    await expectInvalid(replacePayload(input.bundle, payload.slice(1)));
    await expectInvalid(replacePayload(
      input.bundle,
      payload.filter((entry) => !entry.path.startsWith('payload/installer/')),
    ));
    await expectInvalid(replacePayload(input.bundle, [
      { ...first, path: 'payload/admin/extra.js' },
      ...payload.slice(1),
    ]));
    await expectInvalid(replacePayload(input.bundle, [first, first, ...payload.slice(2)]));
    await expectInvalid(replacePayload(input.bundle, [
      ...payload.slice(0, 2),
      { ...third, path: 'payload/installer/../worker/index.js' },
      ...payload.slice(3),
    ]));
  });

  it('rejects payload metadata that is not the exact manifest record relation', async () => {
    const input = await fixture();
    const payload = input.bundle.payload;
    const first = requiredFixture(payload.at(0), 'first payload');
    const second = requiredFixture(payload.at(1), 'second payload');
    await expectInvalid(replacePayload(input.bundle, [
      { ...first, sha256: second.sha256 },
      ...payload.slice(1),
    ]));
    await expectInvalid(replacePayload(input.bundle, [
      { ...first, contentType: 'application/javascript+module' },
      ...payload.slice(1),
    ]));
    await expectInvalid(replacePayload(input.bundle, [
      { ...first, byteSize: first.byteSize + 1 },
      ...payload.slice(1),
    ]));
  });

  it('rejects Blob type, size, and byte-digest mismatches', async () => {
    const input = await fixture();
    const payload = input.bundle.payload;
    const first = requiredFixture(payload.at(0), 'first payload');
    await expectInvalid(replacePayload(input.bundle, [
      { ...first, bytes: new Blob(['wrong type and bytes'], { type: 'text/plain' }) },
      ...payload.slice(1),
    ]));
    await expectInvalid(replacePayload(input.bundle, [
      { ...first, bytes: new Blob([new Uint8Array(first.byteSize + 1)], { type: first.contentType }) },
      ...payload.slice(1),
    ]));
    const original = new Uint8Array(await first.bytes.arrayBuffer());
    const firstByte = requiredFixture(original.at(0), 'first payload byte');
    original[0] = firstByte ^ 0xff;
    await expectInvalid(replacePayload(input.bundle, [
      { ...first, bytes: new Blob([original], { type: first.contentType }) },
      ...payload.slice(1),
    ]));
  });

  it('rejects unknown bundle and payload fields', async () => {
    const input = await fixture();
    await expectInvalid({ ...input.bundle, provider: 'r2' });
    await expectInvalid({
      ...input.bundle,
      envelope: { ...input.bundle.envelope, provider: 'r2' },
    });
    await expectInvalid(replacePayload(input.bundle, [
      { ...input.bundle.payload[0], mutableUrl: 'https://example.invalid' },
      ...input.bundle.payload.slice(1),
    ]));
  });

  it('rejects a non-Ed25519 provenance marker or malformed key id', async () => {
    const input = await fixture();
    await expectInvalid({ ...input.bundle, verification: 'checksum' });
    await expectInvalid({ ...input.bundle, keyId: '../release-key' });
    await expectInvalid({
      ...input.bundle,
      envelope: { ...input.bundle.envelope, channel: 'canary' },
    });
    await expectInvalid({
      ...input.bundle,
      envelope: {
        keyId: input.bundle.envelope.keyId,
        manifest: input.bundle.envelope.manifest,
        schemaVersion: 1,
        signature: input.bundle.envelope.signature,
      },
    });
  });

  it('re-validates component and aggregate tree hashes', async () => {
    const input = await fixture();
    const componentMismatch = {
      ...input.manifest,
      components: {
        ...input.manifest.components,
        worker: { ...input.manifest.components.worker, treeSha256: 'f'.repeat(64) },
      },
    };
    await expectInvalid(replaceManifest(input.bundle, componentMismatch));

    const aggregateMismatch = {
      ...input.manifest,
      artifact: { ...input.manifest.artifact, treeSha256: 'e'.repeat(64) },
    };
    await expectInvalid(replaceManifest(input.bundle, aggregateMismatch));
  });

  it('rejects a manifest record placed under the wrong component', async () => {
    const input = await fixture();
    const manifest = withFilePatch(input.manifest, 'admin', 0, { path: 'payload/worker/app.js' });
    await expectInvalid(replaceManifest(input.bundle, manifest));
  });

  it('rejects Cloudflare Durable Object migrations or a changed exports contract', async () => {
    const input = await fixture();
    const approved = input.manifest.cloudflare;
    const withMigrations = {
      ...input.manifest,
      cloudflare: {
        ...approved,
        durableObjects: {
          ...approved.durableObjects,
          migrations: [{ new_sqlite_classes: ['AdminState'], tag: 'v1' }],
        },
      },
    };
    await expectInvalid(replaceManifest(input.bundle, withMigrations));

    const changedExports = {
      ...input.manifest,
      cloudflare: {
        ...approved,
        durableObjects: {
          ...approved.durableObjects,
          exports: { AdminState: { storage: 'durable', type: 'durable-object' } },
        },
      },
    };
    await expectInvalid(replaceManifest(input.bundle, changedExports));

    const cleanupMigration = {
      ...input.manifest,
      cloudflare: {
        ...approved,
        workerVariants: {
          ...approved.workerVariants,
          cleanup: {
            ...approved.workerVariants.cleanup,
            migrations: [{ deletedClasses: ['AdminState'], tag: 'v2' }],
          },
        },
      },
    };
    await expectInvalid(replaceManifest(input.bundle, cleanupMigration));

    const retirementDrift = {
      ...input.manifest,
      cloudflare: {
        ...approved,
        workerVariants: {
          ...approved.workerVariants,
          retirement: {
            ...approved.workerVariants.retirement,
            durableObjects: {
              ...approved.workerVariants.retirement.durableObjects,
              exports: { AdminState: { storage: 'sqlite', type: 'durable-object' } },
            },
          },
        },
      },
    };
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

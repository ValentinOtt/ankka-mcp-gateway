import { REQUIRED_OAUTH_SCOPES } from '../src/constants';
import { base64UrlEncode } from '../src/crypto';
import {
  EnvironmentReleaseManifestProvider,
  RELEASE_ENVELOPE_SCHEMA_VERSION,
  RELEASE_SIGNATURE_CONTEXT,
  releaseSignatureCanonicalJson,
  verifyReleasePayload,
  verifySignedReleaseEnvelope,
  type ReleasePayloadFile,
} from '../src/release';
import {
  APPROVED_CLOUDFLARE_RELEASE_CONTRACT,
  canonicalJson,
  parseReleaseManifest,
  type ReleaseFileRecord,
  type ReleaseManifest,
} from '../src/release-manifest';
import { manifest as structuralManifest } from './fixtures';

const encoder = new TextEncoder();

async function sha256Hex(value: string | Uint8Array): Promise<string> {
  const bytes = typeof value === 'string' ? encoder.encode(value) : value;
  const owned = new Uint8Array(bytes.byteLength);
  owned.set(bytes);
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', owned));
  return [...digest].map((byte) => byte.toString(16).padStart(2, '0')).join('');
}

async function releaseFixture(): Promise<{
  manifest: ReleaseManifest;
  manifestBytes: string;
  payload: readonly ReleasePayloadFile[];
}> {
  const payload = Object.freeze([
    Object.freeze({ path: 'payload/admin/index.html', bytes: encoder.encode('<!doctype html>admin') }),
    Object.freeze({ path: 'payload/installer/index.html', bytes: encoder.encode('<!doctype html>installer') }),
    Object.freeze({
      path: 'payload/worker-cleanup/index.js',
      bytes: encoder.encode('export class AdminState {}; export default { fetch() {} };'),
    }),
    Object.freeze({
      path: 'payload/worker-retirement/index.js',
      bytes: encoder.encode('export default { fetch() {} };'),
    }),
    Object.freeze({ path: 'payload/worker/index.js', bytes: encoder.encode('export default { fetch() {} };') }),
  ]);
  const record = async (
    file: ReleasePayloadFile,
    contentType: string,
  ): Promise<ReleaseFileRecord> => ({
    byteSize: file.bytes.byteLength,
    contentType,
    path: file.path,
    sha256: await sha256Hex(file.bytes),
  });
  const adminFiles = [await record(payload[0], 'text/html; charset=utf-8')];
  const installerFiles = [await record(payload[1], 'text/html; charset=utf-8')];
  const workerCleanupFiles = [await record(payload[2], 'application/javascript+module')];
  const workerRetirementFiles = [await record(payload[3], 'application/javascript+module')];
  const workerFiles = [await record(payload[4], 'application/javascript+module')];
  const allFiles = [
    ...adminFiles,
    ...installerFiles,
    ...workerCleanupFiles,
    ...workerRetirementFiles,
    ...workerFiles,
  ];
  const component = async (files: readonly ReleaseFileRecord[]) => ({
    byteSize: files.reduce((total, file) => total + file.byteSize, 0),
    fileCount: files.length,
    files,
    treeSha256: await sha256Hex(canonicalJson(files)),
  });
  const manifest = parseReleaseManifest({
    artifact: {
      byteSize: allFiles.reduce((total, file) => total + file.byteSize, 0),
      fileCount: allFiles.length,
      treeSha256: await sha256Hex(canonicalJson(allFiles)),
    },
    cloudflare: APPROVED_CLOUDFLARE_RELEASE_CONTRACT,
    components: {
      admin: await component(adminFiles),
      installer: await component(installerFiles),
      worker: await component(workerFiles),
      workerCleanup: await component(workerCleanupFiles),
      workerRetirement: await component(workerRetirementFiles),
    },
    oauthScopeIds: REQUIRED_OAUTH_SCOPES,
    release: 'gateway-v1.2.3',
    schemaVersion: 1,
    sourceCommit: '0123456789abcdef0123456789abcdef01234567',
  });
  return { manifest, manifestBytes: canonicalJson(manifest), payload };
}

async function signer() {
  const keyPair = await crypto.subtle.generateKey('Ed25519', true, ['sign', 'verify']);
  const publicKey = base64UrlEncode(
    new Uint8Array(await crypto.subtle.exportKey('raw', keyPair.publicKey)),
  );
  const envelope = async (manifestBytes: string, extra: Record<string, unknown> = {}) => {
    const channel = 'stable';
    const signature = await crypto.subtle.sign(
      'Ed25519',
      keyPair.privateKey,
      encoder.encode(releaseSignatureCanonicalJson(channel, 'test-key', manifestBytes)),
    );
    return canonicalJson({
      schemaVersion: RELEASE_ENVELOPE_SCHEMA_VERSION,
      channel,
      keyId: 'test-key',
      manifest: manifestBytes,
      signature: base64UrlEncode(new Uint8Array(signature)),
      signatureContext: RELEASE_SIGNATURE_CONTEXT,
      ...extra,
    });
  };
  return { envelope, publicKey };
}

describe('signed rich release gate', () => {
  it('pins one declarative SQLite Durable Object export and rejects migration metadata', () => {
    expect(APPROVED_CLOUDFLARE_RELEASE_CONTRACT.durableObjects).toEqual({
      bindings: [{ binding: 'ADMIN_STATE', className: 'AdminState' }],
      exports: {
        AdminState: { storage: 'sqlite', type: 'durable-object' },
      },
    });
    expect(Object.hasOwn(APPROVED_CLOUDFLARE_RELEASE_CONTRACT.durableObjects, 'migrations')).toBe(false);
    expect(APPROVED_CLOUDFLARE_RELEASE_CONTRACT.workerVariants.cleanup).toMatchObject({
      component: 'workerCleanup',
      payloadDirectory: 'payload/worker-cleanup',
      publicPath: '/__ankka/uninstall',
      durableObjects: {
        bindings: [{ binding: 'ADMIN_STATE', className: 'AdminState' }],
        exports: { AdminState: { storage: 'sqlite', type: 'durable-object' } },
      },
    });
    expect(APPROVED_CLOUDFLARE_RELEASE_CONTRACT.workerVariants.retirement).toMatchObject({
      component: 'workerRetirement',
      payloadDirectory: 'payload/worker-retirement',
      durableObjects: {
        bindings: [],
        exports: { AdminState: { state: 'deleted', type: 'durable-object' } },
      },
    });
    expect(Object.hasOwn(APPROVED_CLOUDFLARE_RELEASE_CONTRACT.workerVariants.cleanup, 'migrations')).toBe(false);
    expect(Object.hasOwn(APPROVED_CLOUDFLARE_RELEASE_CONTRACT.workerVariants.retirement, 'migrations')).toBe(false);
  });

  it('fails closed when no signed release is configured or no key is pinned', async () => {
    const provider = new EnvironmentReleaseManifestProvider();
    await expect(provider.loadVerifiedRelease({})).rejects.toMatchObject({ code: 'release_unavailable' });
    await expect(provider.loadVerifiedRelease({
      GATEWAY_RELEASE_ENVELOPE_JSON: canonicalJson({
        schemaVersion: RELEASE_ENVELOPE_SCHEMA_VERSION,
        channel: 'stable',
        keyId: 'unknown',
        manifest: canonicalJson(structuralManifest),
        signature: base64UrlEncode(new Uint8Array(64)),
        signatureContext: RELEASE_SIGNATURE_CONTEXT,
      }),
      GATEWAY_RELEASE_CHANNEL: 'stable',
    })).rejects.toMatchObject({ code: 'release_unavailable' });
  });

  it('verifies canonical manifest bytes, Ed25519, all tree digests, and every payload file', async () => {
    const fixture = await releaseFixture();
    const signing = await signer();
    const serialized = await signing.envelope(fixture.manifestBytes);
    await expect(verifySignedReleaseEnvelope(
      serialized,
      'stable',
      { 'test-key': signing.publicKey },
      fixture.payload,
    )).resolves.toMatchObject({
      verification: 'ed25519',
      keyId: 'test-key',
      manifest: fixture.manifest,
    });
  });

  it('rejects cross-channel replay and legacy manifest-only envelopes', async () => {
    const fixture = await releaseFixture();
    const signing = await signer();
    const stableEnvelope = await signing.envelope(fixture.manifestBytes);
    await expect(verifySignedReleaseEnvelope(
      stableEnvelope,
      'canary',
      { 'test-key': signing.publicKey },
      fixture.payload,
    )).rejects.toMatchObject({ code: 'release_invalid' });
    await expect(verifySignedReleaseEnvelope(
      stableEnvelope,
      'preview',
      { 'test-key': signing.publicKey },
      fixture.payload,
    )).rejects.toMatchObject({ code: 'release_invalid' });

    const legacy = JSON.parse(stableEnvelope) as Record<string, unknown>;
    delete legacy.channel;
    delete legacy.signatureContext;
    legacy.schemaVersion = 1;
    await expect(verifySignedReleaseEnvelope(
      canonicalJson(legacy),
      'stable',
      { 'test-key': signing.publicKey },
      fixture.payload,
    )).rejects.toMatchObject({ code: 'release_invalid' });
  });

  it('rejects a valid signature over noncanonical or schema-expanded manifest bytes', async () => {
    const fixture = await releaseFixture();
    const signing = await signer();
    const noncanonical = ` ${fixture.manifestBytes}`;
    await expect(verifySignedReleaseEnvelope(
      await signing.envelope(noncanonical),
      'stable',
      { 'test-key': signing.publicKey },
      fixture.payload,
    )).rejects.toMatchObject({ code: 'release_invalid' });

    const expanded = canonicalJson({ ...fixture.manifest, publishedAt: '2026-08-23T00:00:00Z' });
    await expect(verifySignedReleaseEnvelope(
      await signing.envelope(expanded),
      'stable',
      { 'test-key': signing.publicKey },
      fixture.payload,
    )).rejects.toMatchObject({ code: 'release_invalid' });
  });

  it('rejects a signature after any signed file record changes', async () => {
    const fixture = await releaseFixture();
    const signing = await signer();
    const signatureForOriginal = await signing.envelope(fixture.manifestBytes);
    const originalEnvelope = JSON.parse(signatureForOriginal) as Record<string, unknown>;
    const tampered = structuredClone(fixture.manifest) as unknown as Record<string, unknown>;
    const components = tampered.components as Record<string, Record<string, unknown>>;
    const worker = components.worker;
    const files = worker.files as Array<Record<string, unknown>>;
    files[0].sha256 = 'd'.repeat(64);
    originalEnvelope.manifest = canonicalJson(tampered);
    await expect(verifySignedReleaseEnvelope(
      canonicalJson(originalEnvelope),
      'stable',
      { 'test-key': signing.publicKey },
      fixture.payload,
    )).rejects.toMatchObject({ code: 'release_invalid' });
  });

  it('rejects signed internal tree drift and any missing, extra, duplicate, resized, or changed payload', async () => {
    const fixture = await releaseFixture();
    const signing = await signer();
    const changedTree = structuredClone(fixture.manifest) as unknown as Record<string, unknown>;
    const changedComponents = changedTree.components as Record<string, Record<string, unknown>>;
    changedComponents.worker.treeSha256 = 'd'.repeat(64);
    await expect(verifySignedReleaseEnvelope(
      await signing.envelope(canonicalJson(changedTree)),
      'stable',
      { 'test-key': signing.publicKey },
      fixture.payload,
    )).rejects.toMatchObject({ code: 'release_invalid' });

    await expect(verifyReleasePayload(fixture.manifest, fixture.payload.slice(1)))
      .rejects.toMatchObject({ code: 'release_invalid' });
    await expect(verifyReleasePayload(fixture.manifest, [
      ...fixture.payload,
      { path: 'payload/admin/extra.js', bytes: encoder.encode('extra') },
    ])).rejects.toMatchObject({ code: 'release_invalid' });
    await expect(verifyReleasePayload(fixture.manifest, [
      fixture.payload[0],
      fixture.payload[0],
      fixture.payload[2],
    ])).rejects.toMatchObject({ code: 'release_invalid' });
    await expect(verifyReleasePayload(fixture.manifest, fixture.payload.map((file, index) =>
      index === 0 ? { ...file, bytes: encoder.encode('changed but longer') } : file,
    ))).rejects.toMatchObject({ code: 'release_invalid' });
    await expect(verifyReleasePayload(fixture.manifest, fixture.payload.map((file, index) =>
      index === 0 ? { ...file, bytes: encoder.encode('X'.repeat(file.bytes.byteLength)) } : file,
    ))).rejects.toMatchObject({ code: 'release_invalid' });
  });

  it('rejects signed drift in scopes, content types, safety flags, bindings, and envelope fields', async () => {
    const fixture = await releaseFixture();
    const signing = await signer();
    const mutations: Array<Record<string, unknown>> = [];

    mutations.push({ ...fixture.manifest, oauthScopeIds: REQUIRED_OAUTH_SCOPES.slice().reverse() });

    const contentType = structuredClone(fixture.manifest) as unknown as Record<string, unknown>;
    const contentComponents = contentType.components as Record<string, Record<string, unknown>>;
    const contentFiles = contentComponents.worker.files as Array<Record<string, unknown>>;
    contentFiles[0].contentType = 'text/javascript; charset=utf-8';
    mutations.push(contentType);

    const observable = structuredClone(fixture.manifest) as unknown as Record<string, unknown>;
    (observable.cloudflare as Record<string, unknown>).observability = { enabled: true };
    mutations.push(observable);

    const workersDev = structuredClone(fixture.manifest) as unknown as Record<string, unknown>;
    (workersDev.cloudflare as Record<string, unknown>).workersDev = true;
    mutations.push(workersDev);

    const binding = structuredClone(fixture.manifest) as unknown as Record<string, unknown>;
    const cloudflare = binding.cloudflare as Record<string, unknown>;
    const durableObjects = cloudflare.durableObjects as Record<string, unknown>;
    durableObjects.bindings = [{ binding: 'OTHER_STATE', className: 'AdminState' }];
    mutations.push(binding);

    const durableObjectExport = structuredClone(fixture.manifest) as unknown as Record<string, unknown>;
    const exportCloudflare = durableObjectExport.cloudflare as Record<string, unknown>;
    const exportObjects = exportCloudflare.durableObjects as Record<string, unknown>;
    exportObjects.exports = { AdminState: { storage: 'memory', type: 'durable-object' } };
    mutations.push(durableObjectExport);

    for (const mutate of [
      (cloudflare: Record<string, unknown>) => {
        const assets = cloudflare.assets as Record<string, unknown>;
        assets.runWorkerFirst = ['/api/*', '/__ankka/bootstrap'];
      },
      (cloudflare: Record<string, unknown>) => { cloudflare.compatibilityDate = '2026-08-09'; },
      (cloudflare: Record<string, unknown>) => { cloudflare.previewUrls = true; },
      (cloudflare: Record<string, unknown>) => { cloudflare.sendMetrics = true; },
      (cloudflare: Record<string, unknown>) => {
        cloudflare.dependenciesInstrumentation = { enabled: true };
      },
      (cloudflare: Record<string, unknown>) => {
        const bindings = cloudflare.publicBindings as Record<string, unknown>;
        bindings.variables = [
          ...bindings.variables as string[],
          'MUTABLE_ENDPOINT',
        ];
      },
      (cloudflare: Record<string, unknown>) => {
        const objects = cloudflare.durableObjects as Record<string, unknown>;
        delete objects.exports;
      },
      (cloudflare: Record<string, unknown>) => {
        const objects = cloudflare.durableObjects as Record<string, unknown>;
        objects.migrations = [{ newSqliteClasses: ['AdminState'], tag: 'v1' }];
      },
      (cloudflare: Record<string, unknown>) => {
        const variants = cloudflare.workerVariants as Record<string, Record<string, unknown>>;
        variants.cleanup.migrations = [{ deletedClasses: ['AdminState'], tag: 'v2' }];
      },
      (cloudflare: Record<string, unknown>) => {
        const variants = cloudflare.workerVariants as Record<string, Record<string, unknown>>;
        const retirement = variants.retirement.durableObjects as Record<string, unknown>;
        retirement.exports = { AdminState: { storage: 'sqlite', type: 'durable-object' } };
      },
    ]) {
      const changed = structuredClone(fixture.manifest) as unknown as Record<string, unknown>;
      mutate(changed.cloudflare as Record<string, unknown>);
      mutations.push(changed);
    }

    for (const mutation of mutations) {
      await expect(verifySignedReleaseEnvelope(
        await signing.envelope(canonicalJson(mutation)),
        'stable',
        { 'test-key': signing.publicKey },
        fixture.payload,
      )).rejects.toMatchObject({ code: 'release_invalid' });
    }

    await expect(verifySignedReleaseEnvelope(
      await signing.envelope(fixture.manifestBytes, { mutableUrl: 'https://example.invalid' }),
      'stable',
      { 'test-key': signing.publicKey },
      fixture.payload,
    )).rejects.toMatchObject({ code: 'release_invalid' });
  });

  it('rejects inconsistent record, component, and aggregate metadata even when signed', async () => {
    const fixture = await releaseFixture();
    const signing = await signer();
    const mutations: Array<Record<string, unknown>> = [];

    const fileSize = structuredClone(fixture.manifest) as unknown as Record<string, unknown>;
    const fileSizeComponents = fileSize.components as Record<string, Record<string, unknown>>;
    const fileSizeFiles = fileSizeComponents.admin.files as Array<Record<string, unknown>>;
    fileSizeFiles[0].byteSize = Number(fileSizeFiles[0].byteSize) + 1;
    mutations.push(fileSize);

    const componentCount = structuredClone(fixture.manifest) as unknown as Record<string, unknown>;
    const countComponents = componentCount.components as Record<string, Record<string, unknown>>;
    countComponents.worker.fileCount = 2;
    mutations.push(componentCount);

    const artifactSize = structuredClone(fixture.manifest) as unknown as Record<string, unknown>;
    const artifact = artifactSize.artifact as Record<string, unknown>;
    artifact.byteSize = Number(artifact.byteSize) + 1;
    mutations.push(artifactSize);

    const unknownRecordField = structuredClone(fixture.manifest) as unknown as Record<string, unknown>;
    const unknownComponents = unknownRecordField.components as Record<string, Record<string, unknown>>;
    const unknownFiles = unknownComponents.worker.files as Array<Record<string, unknown>>;
    unknownFiles[0].downloadUrl = 'https://mutable.invalid/index.js';
    mutations.push(unknownRecordField);

    for (const mutation of mutations) {
      await expect(verifySignedReleaseEnvelope(
        await signing.envelope(canonicalJson(mutation)),
        'stable',
        { 'test-key': signing.publicKey },
        fixture.payload,
      )).rejects.toMatchObject({ code: 'release_invalid' });
    }
  });
});

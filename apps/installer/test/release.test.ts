import * as v from 'valibot';

import { REQUIRED_OAUTH_SCOPES } from '../src/constants';
import { base64UrlEncode } from '../src/crypto';
import type { BoundaryObject } from '../src/boundary';
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
import { manifest as structuralManifest, requiredFixture } from './fixtures';

const encoder = new TextEncoder();
const testEnvelopeSchema = v.strictObject({
  channel: v.string(),
  keyId: v.string(),
  manifest: v.string(),
  schemaVersion: v.number(),
  signature: v.string(),
  signatureContext: v.string(),
});

async function sha256Hex(value: string | Uint8Array): Promise<string> {
  const bytes = v.is(v.string(), value) ? encoder.encode(value) : value;
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
  const adminFiles = [await record(requiredFixture(payload.at(0), 'admin payload'), 'text/html; charset=utf-8')];
  const installerFiles = [await record(requiredFixture(payload.at(1), 'installer payload'), 'text/html; charset=utf-8')];
  const workerCleanupFiles = [await record(requiredFixture(payload.at(2), 'cleanup payload'), 'application/javascript+module')];
  const workerRetirementFiles = [await record(requiredFixture(payload.at(3), 'retirement payload'), 'application/javascript+module')];
  const workerFiles = [await record(requiredFixture(payload.at(4), 'worker payload'), 'application/javascript+module')];
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
  const envelope = async (manifestBytes: string, extra: BoundaryObject = {}) => {
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

function parsedEnvelope(serialized: string): v.InferOutput<typeof testEnvelopeSchema> {
  return v.parse(testEnvelopeSchema, JSON.parse(serialized));
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
        files: component.files.map((file, index) => index === fileIndex ? { ...file, ...patch } : file),
      },
    },
  };
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

    const current = parsedEnvelope(stableEnvelope);
    const legacy = {
      keyId: current.keyId,
      manifest: current.manifest,
      schemaVersion: 1,
      signature: current.signature,
    };
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
    const originalEnvelope = parsedEnvelope(signatureForOriginal);
    const tampered = withFilePatch(fixture.manifest, 'worker', 0, { sha256: 'd'.repeat(64) });
    const tamperedEnvelope = { ...originalEnvelope, manifest: canonicalJson(tampered) };
    await expect(verifySignedReleaseEnvelope(
      canonicalJson(tamperedEnvelope),
      'stable',
      { 'test-key': signing.publicKey },
      fixture.payload,
    )).rejects.toMatchObject({ code: 'release_invalid' });
  });

  it('rejects signed internal tree drift and any missing, extra, duplicate, resized, or changed payload', async () => {
    const fixture = await releaseFixture();
    const signing = await signer();
    const changedTree = {
      ...fixture.manifest,
      components: {
        ...fixture.manifest.components,
        worker: { ...fixture.manifest.components.worker, treeSha256: 'd'.repeat(64) },
      },
    };
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
    const firstPayload = requiredFixture(fixture.payload.at(0), 'first payload');
    await expect(verifyReleasePayload(fixture.manifest, [
      firstPayload,
      firstPayload,
      requiredFixture(fixture.payload.at(2), 'third payload'),
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
    const approved = fixture.manifest.cloudflare;
    const mutations = [
      { ...fixture.manifest, oauthScopeIds: REQUIRED_OAUTH_SCOPES.slice().reverse() },
      withFilePatch(fixture.manifest, 'worker', 0, {
        contentType: 'text/javascript; charset=utf-8',
      }),
      { ...fixture.manifest, cloudflare: { ...approved, observability: { enabled: true } } },
      { ...fixture.manifest, cloudflare: { ...approved, workersDev: true } },
      {
        ...fixture.manifest,
        cloudflare: {
          ...approved,
          durableObjects: {
            ...approved.durableObjects,
            bindings: [{ binding: 'OTHER_STATE', className: 'AdminState' }],
          },
        },
      },
      {
        ...fixture.manifest,
        cloudflare: {
          ...approved,
          durableObjects: {
            ...approved.durableObjects,
            exports: { AdminState: { storage: 'memory', type: 'durable-object' } },
          },
        },
      },
      {
        ...fixture.manifest,
        cloudflare: {
          ...approved,
          assets: { ...approved.assets, runWorkerFirst: ['/api/*', '/__ankka/bootstrap'] },
        },
      },
      { ...fixture.manifest, cloudflare: { ...approved, compatibilityDate: '2026-08-09' } },
      { ...fixture.manifest, cloudflare: { ...approved, previewUrls: true } },
      { ...fixture.manifest, cloudflare: { ...approved, sendMetrics: true } },
      {
        ...fixture.manifest,
        cloudflare: { ...approved, dependenciesInstrumentation: { enabled: true } },
      },
      {
        ...fixture.manifest,
        cloudflare: {
          ...approved,
          publicBindings: {
            ...approved.publicBindings,
            variables: [...approved.publicBindings.variables, 'MUTABLE_ENDPOINT'],
          },
        },
      },
      {
        ...fixture.manifest,
        cloudflare: {
          ...approved,
          durableObjects: { bindings: approved.durableObjects.bindings },
        },
      },
      {
        ...fixture.manifest,
        cloudflare: {
          ...approved,
          durableObjects: {
            ...approved.durableObjects,
            migrations: [{ newSqliteClasses: ['AdminState'], tag: 'v1' }],
          },
        },
      },
      {
        ...fixture.manifest,
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
      },
      {
        ...fixture.manifest,
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
      },
    ];

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
    const mutations = [
      withFilePatch(fixture.manifest, 'admin', 0, {
        byteSize: requiredFixture(fixture.manifest.components.admin.files.at(0), 'admin file').byteSize + 1,
      }),
      {
        ...fixture.manifest,
        components: {
          ...fixture.manifest.components,
          worker: { ...fixture.manifest.components.worker, fileCount: 2 },
        },
      },
      {
        ...fixture.manifest,
        artifact: { ...fixture.manifest.artifact, byteSize: fixture.manifest.artifact.byteSize + 1 },
      },
      withFilePatch(fixture.manifest, 'worker', 0, {
        downloadUrl: 'https://mutable.invalid/index.js',
      }),
    ];

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

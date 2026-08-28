import { REQUIRED_OAUTH_SCOPES } from '../src/constants';
import { base64UrlEncode } from '../src/crypto';
import {
  ExactR2ReleaseBundleProvider,
  PinnedR2ReleaseBundleProvider,
  type PinnedR2Release,
} from '../src/r2-release-provider';
import {
  RELEASE_ENVELOPE_SCHEMA_VERSION,
  RELEASE_SIGNATURE_CONTEXT,
  releaseSignatureCanonicalJson,
  type ReleasePayloadFile,
} from '../src/release';
import {
  APPROVED_CLOUDFLARE_RELEASE_CONTRACT,
  canonicalJson,
  parseReleaseManifest,
  type ReleaseFileRecord,
  type ReleaseManifest,
} from '../src/release-manifest';

const encoder = new TextEncoder();
const decoder = new TextDecoder();
const RELEASE_BUCKET_ROOT = 'ankka-mcp-gateway/releases';
const ENVELOPE_FILENAME = 'release-envelope.json';
const ENVELOPE_CONTENT_TYPE = 'application/json; charset=utf-8';

interface StoredObject {
  bytes: Uint8Array;
  contentType: string;
  reportedSize?: number;
  returnedKey?: string;
}

class FakeR2 {
  readonly objects = new Map<string, StoredObject>();
  readonly getKeys: string[] = [];
  readonly listPrefixes: string[] = [];
  duplicateListKey: string | null = null;
  listPageSize = 1_000;
  throwOnGet = false;
  throwOnList = false;

  put(key: string, bytes: Uint8Array, contentType: string): void {
    const copy = new Uint8Array(bytes.byteLength);
    copy.set(bytes);
    this.objects.set(key, { bytes: copy, contentType });
  }

  bucket(): R2Bucket {
    const fake = this;
    return {
      async get(key: string): Promise<R2ObjectBody | null> {
        fake.getKeys.push(key);
        if (fake.throwOnGet) throw new Error('fake get failure');
        const stored = fake.objects.get(key);
        if (!stored) return null;
        return {
          key: stored.returnedKey ?? key,
          size: stored.reportedSize ?? stored.bytes.byteLength,
          httpMetadata: { contentType: stored.contentType },
          async arrayBuffer(): Promise<ArrayBuffer> {
            const copy = new Uint8Array(stored.bytes.byteLength);
            copy.set(stored.bytes);
            return copy.buffer;
          },
        } as unknown as R2ObjectBody;
      },
      async list(options?: R2ListOptions): Promise<R2Objects> {
        fake.listPrefixes.push(options?.prefix ?? '');
        if (fake.throwOnList) throw new Error('fake list failure');
        const prefix = options?.prefix ?? '';
        const offset = options?.cursor ? Number(options.cursor) : 0;
        const limit = Math.min(options?.limit ?? 1_000, fake.listPageSize);
        const keys = [...fake.objects.keys()].filter((key) => key.startsWith(prefix)).sort();
        if (fake.duplicateListKey && keys.includes(fake.duplicateListKey)) {
          keys.splice(keys.indexOf(fake.duplicateListKey) + 1, 0, fake.duplicateListKey);
        }
        const selected = keys.slice(offset, offset + limit);
        const nextOffset = offset + selected.length;
        const truncated = nextOffset < keys.length;
        return {
          objects: selected.map((key) => {
            const stored = fake.objects.get(key);
            if (!stored) throw new Error('fake list state');
            return {
              key,
              size: stored.reportedSize ?? stored.bytes.byteLength,
            } as R2Object;
          }),
          truncated,
          ...(truncated ? { cursor: String(nextOffset) } : {}),
          delimitedPrefixes: [],
        } as R2Objects;
      },
    } as unknown as R2Bucket;
  }
}

async function sha256Hex(value: string | Uint8Array): Promise<string> {
  const bytes = typeof value === 'string' ? encoder.encode(value) : value;
  const owned = new Uint8Array(bytes.byteLength);
  owned.set(bytes);
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', owned));
  return [...digest].map((byte) => byte.toString(16).padStart(2, '0')).join('');
}

async function signedFixture(
  release = 'gateway-v1.2.3',
  channel: 'canary' | 'stable' = 'canary',
): Promise<{
  bucket: FakeR2;
  envelopeKey: string;
  manifest: ReleaseManifest;
  payload: readonly ReleasePayloadFile[];
  pin: PinnedR2Release;
  prefix: string;
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
    release,
    schemaVersion: 1,
    sourceCommit: '0123456789abcdef0123456789abcdef01234567',
  });
  const keyPair = await crypto.subtle.generateKey('Ed25519', true, ['sign', 'verify']);
  const publicKey = base64UrlEncode(
    new Uint8Array(await crypto.subtle.exportKey('raw', keyPair.publicKey)),
  );
  const manifestBytes = canonicalJson(manifest);
  const signature = base64UrlEncode(new Uint8Array(await crypto.subtle.sign(
    'Ed25519',
    keyPair.privateKey,
    encoder.encode(releaseSignatureCanonicalJson(channel, 'test-key', manifestBytes)),
  )));
  const envelope = encoder.encode(canonicalJson({
    schemaVersion: RELEASE_ENVELOPE_SCHEMA_VERSION,
    channel,
    keyId: 'test-key',
    manifest: manifestBytes,
    signature,
    signatureContext: RELEASE_SIGNATURE_CONTEXT,
  }));
  const prefix = `${RELEASE_BUCKET_ROOT}/${channel}/${manifest.release}/`;
  const envelopeKey = `${prefix}${ENVELOPE_FILENAME}`;
  const bucket = new FakeR2();
  bucket.put(envelopeKey, envelope, ENVELOPE_CONTENT_TYPE);
  const recordsByPath = new Map(allFiles.map((file) => [file.path, file]));
  for (const file of payload) {
    const recordValue = recordsByPath.get(file.path);
    if (!recordValue) throw new Error('fixture record');
    bucket.put(`${prefix}${file.path}`, file.bytes, recordValue.contentType);
  }
  return {
    bucket,
    envelopeKey,
    manifest,
    payload,
    pin: Object.freeze({
      schemaVersion: 1,
      channel,
      release: manifest.release,
      keyId: 'test-key',
      publicKey,
      artifactSha256: manifest.artifact.treeSha256,
    }),
    prefix,
  };
}

function provider(pin: PinnedR2Release): PinnedR2ReleaseBundleProvider {
  return new PinnedR2ReleaseBundleProvider(pin);
}

function copyFixtureObjects(source: FakeR2, target: FakeR2): void {
  for (const [key, object] of source.objects) {
    target.put(key, object.bytes, object.contentType);
  }
}

describe('pinned R2 rich release bundle provider', () => {
  it('loads only the exact pinned prefix and returns frozen immutable byte blobs', async () => {
    const fixture = await signedFixture();
    fixture.bucket.listPageSize = 2;
    const bundle = await provider(fixture.pin).loadVerifiedReleaseBundle(fixture.bucket.bucket());
    expect(bundle).toMatchObject({
      verification: 'ed25519',
      keyId: fixture.pin.keyId,
      manifest: fixture.manifest,
    });
    expect(bundle.payload.map((file) => file.path)).toEqual(fixture.payload.map((file) => file.path));
    expect(Object.isFrozen(bundle)).toBe(true);
    expect(Object.isFrozen(bundle.payload)).toBe(true);
    expect(bundle.payload.every(Object.isFrozen)).toBe(true);

    const admin = bundle.payload[0];
    const firstRead = new Uint8Array(await admin.bytes.arrayBuffer());
    const expectedFirstByte = firstRead[0];
    firstRead[0] ^= 0xff;
    const stored = fixture.bucket.objects.get(`${fixture.prefix}${admin.path}`);
    if (!stored) throw new Error('fixture object');
    stored.bytes[0] ^= 0xff;
    const secondRead = new Uint8Array(await admin.bytes.arrayBuffer());
    expect(secondRead[0]).toBe(expectedFirstByte);
  });

  it('rejects a missing envelope or payload object and normalizes R2 transport failures', async () => {
    const missingEnvelope = await signedFixture();
    missingEnvelope.bucket.objects.delete(missingEnvelope.envelopeKey);
    await expect(provider(missingEnvelope.pin).loadVerifiedReleaseBundle(missingEnvelope.bucket.bucket()))
      .rejects.toMatchObject({ code: 'release_unavailable' });

    const missingPayload = await signedFixture();
    missingPayload.bucket.objects.delete(`${missingPayload.prefix}payload/admin/index.html`);
    await expect(provider(missingPayload.pin).loadVerifiedReleaseBundle(missingPayload.bucket.bucket()))
      .rejects.toMatchObject({ code: 'release_invalid' });

    const failedGet = await signedFixture();
    failedGet.bucket.throwOnGet = true;
    await expect(provider(failedGet.pin).loadVerifiedReleaseBundle(failedGet.bucket.bucket()))
      .rejects.toMatchObject({ code: 'release_unavailable' });

    const failedList = await signedFixture();
    failedList.bucket.throwOnList = true;
    await expect(provider(failedList.pin).loadVerifiedReleaseBundle(failedList.bucket.bucket()))
      .rejects.toMatchObject({ code: 'release_unavailable' });
  });

  it('rejects an extra or duplicated object inside the exact release prefix', async () => {
    const extra = await signedFixture();
    extra.bucket.put(`${extra.prefix}payload/admin/extra.js`, encoder.encode('extra'), 'text/javascript; charset=utf-8');
    await expect(provider(extra.pin).loadVerifiedReleaseBundle(extra.bucket.bucket()))
      .rejects.toMatchObject({ code: 'release_invalid' });

    const duplicate = await signedFixture();
    duplicate.bucket.duplicateListKey = `${duplicate.prefix}payload/admin/index.html`;
    await expect(provider(duplicate.pin).loadVerifiedReleaseBundle(duplicate.bucket.bucket()))
      .rejects.toMatchObject({ code: 'release_invalid' });

    const otherRelease = await signedFixture();
    otherRelease.bucket.put(
      `${RELEASE_BUCKET_ROOT}/stable/gateway-v9.9.9/unrelated`,
      encoder.encode('unrelated release'),
      'application/octet-stream',
    );
    await expect(provider(otherRelease.pin).loadVerifiedReleaseBundle(otherRelease.bucket.bucket()))
      .resolves.toMatchObject({ keyId: otherRelease.pin.keyId });
  });

  it('rejects noncanonical or signature-tampered release envelopes', async () => {
    const noncanonical = await signedFixture();
    const noncanonicalObject = noncanonical.bucket.objects.get(noncanonical.envelopeKey);
    if (!noncanonicalObject) throw new Error('fixture envelope');
    noncanonicalObject.bytes = encoder.encode(` ${decoder.decode(noncanonicalObject.bytes)}`);
    await expect(provider(noncanonical.pin).loadVerifiedReleaseBundle(noncanonical.bucket.bucket()))
      .rejects.toMatchObject({ code: 'release_invalid' });

    const tampered = await signedFixture();
    const tamperedObject = tampered.bucket.objects.get(tampered.envelopeKey);
    if (!tamperedObject) throw new Error('fixture envelope');
    const parsed = JSON.parse(decoder.decode(tamperedObject.bytes)) as Record<string, unknown>;
    if (typeof parsed.signature !== 'string') throw new Error('fixture signature');
    parsed.signature = `${parsed.signature[0] === 'A' ? 'B' : 'A'}${parsed.signature.slice(1)}`;
    tamperedObject.bytes = encoder.encode(canonicalJson(parsed));
    await expect(provider(tampered.pin).loadVerifiedReleaseBundle(tampered.bucket.bucket()))
      .rejects.toMatchObject({ code: 'release_invalid' });

    const replay = await signedFixture();
    const stablePrefix = `${RELEASE_BUCKET_ROOT}/stable/${replay.manifest.release}/`;
    for (const [key, object] of [...replay.bucket.objects]) {
      replay.bucket.put(
        key.replace(replay.prefix, stablePrefix),
        object.bytes,
        object.contentType,
      );
      replay.bucket.objects.delete(key);
    }
    await expect(provider({ ...replay.pin, channel: 'stable' }).loadVerifiedReleaseBundle(replay.bucket.bucket()))
      .rejects.toMatchObject({ code: 'release_invalid' });
  });

  it('rejects truncated, resized, content-type-drifted, or same-size tampered objects', async () => {
    const cases: Array<(fixture: Awaited<ReturnType<typeof signedFixture>>) => void> = [
      (fixture) => {
        const object = fixture.bucket.objects.get(`${fixture.prefix}payload/admin/index.html`);
        if (!object) throw new Error('fixture object');
        object.bytes = object.bytes.slice(0, -1);
        object.reportedSize = fixture.manifest.components.admin.files[0].byteSize;
      },
      (fixture) => {
        const object = fixture.bucket.objects.get(`${fixture.prefix}payload/admin/index.html`);
        if (!object) throw new Error('fixture object');
        object.reportedSize = object.bytes.byteLength + 1;
      },
      (fixture) => {
        const object = fixture.bucket.objects.get(`${fixture.prefix}payload/admin/index.html`);
        if (!object) throw new Error('fixture object');
        object.contentType = 'application/octet-stream';
      },
      (fixture) => {
        const object = fixture.bucket.objects.get(`${fixture.prefix}payload/admin/index.html`);
        if (!object) throw new Error('fixture object');
        object.bytes[0] ^= 0xff;
      },
    ];
    for (const mutate of cases) {
      const fixture = await signedFixture();
      mutate(fixture);
      await expect(provider(fixture.pin).loadVerifiedReleaseBundle(fixture.bucket.bucket()))
        .rejects.toMatchObject({ code: 'release_invalid' });
    }
  });

  it('rejects pin drift in channel, release, key ID, public key, or artifact digest', async () => {
    const fixture = await signedFixture();
    const pins: unknown[] = [
      { ...fixture.pin, channel: '../canary' },
      { ...fixture.pin, release: 'gateway-v1.2.4' },
      { ...fixture.pin, keyId: 'another-key' },
      { ...fixture.pin, publicKey: 'A'.repeat(43) },
      { ...fixture.pin, artifactSha256: 'f'.repeat(64) },
    ];
    for (const pin of pins) {
      await expect(Promise.resolve().then(() => provider(pin as PinnedR2Release)
        .loadVerifiedReleaseBundle(fixture.bucket.bucket())))
        .rejects.toMatchObject({ code: expect.stringMatching(/^release_(?:invalid|unavailable)$/u) });
    }
  });

  it('rejects an envelope object whose returned key, declared size, or content type drifts', async () => {
    const mutations: Array<(object: StoredObject) => void> = [
      (object) => { object.returnedKey = 'different/key'; },
      (object) => { object.reportedSize = object.bytes.byteLength + 1; },
      (object) => { object.contentType = 'application/json'; },
    ];
    for (const mutate of mutations) {
      const fixture = await signedFixture();
      const object = fixture.bucket.objects.get(fixture.envelopeKey);
      if (!object) throw new Error('fixture envelope');
      mutate(object);
      await expect(provider(fixture.pin).loadVerifiedReleaseBundle(fixture.bucket.bucket()))
        .rejects.toMatchObject({ code: 'release_invalid' });
    }
  });
});

describe('exact historical R2 release lookup for returning uninstall', () => {
  it('loads installed N after the reviewed runtime and channel have advanced to N+1', async () => {
    const installed = await signedFixture('gateway-v1.2.2', 'stable');
    const promoted = await signedFixture('gateway-v1.2.3', 'stable');
    copyFixtureObjects(installed.bucket, promoted.bucket);

    const current = await provider(promoted.pin).loadVerifiedReleaseBundle(promoted.bucket.bucket());
    expect(current.manifest.release).toBe('gateway-v1.2.3');
    promoted.bucket.getKeys.length = 0;
    promoted.bucket.listPrefixes.length = 0;

    const historical = await new ExactR2ReleaseBundleProvider()
      .loadVerifiedReleaseBundleForIdentity(promoted.bucket.bucket(), installed.pin);
    expect(historical.manifest.release).toBe('gateway-v1.2.2');
    expect(historical.manifest.artifact.treeSha256).toBe(installed.pin.artifactSha256);
    expect(promoted.bucket.getKeys.length).toBeGreaterThan(1);
    expect(promoted.bucket.getKeys.every((key) => key.startsWith(installed.prefix))).toBe(true);
    expect(promoted.bucket.listPrefixes.every((prefix) => prefix === installed.prefix)).toBe(true);
    expect(promoted.bucket.getKeys.some((key) => key.startsWith(promoted.prefix))).toBe(false);
  });

  it('does not fall back to N+1 when the installed immutable prefix is missing or hash-mismatched', async () => {
    const installed = await signedFixture('gateway-v1.2.2', 'stable');
    const promoted = await signedFixture('gateway-v1.2.3', 'stable');
    copyFixtureObjects(installed.bucket, promoted.bucket);
    const exact = new ExactR2ReleaseBundleProvider();

    promoted.bucket.objects.delete(installed.envelopeKey);
    await expect(exact.loadVerifiedReleaseBundleForIdentity(promoted.bucket.bucket(), installed.pin))
      .rejects.toMatchObject({ code: 'release_unavailable' });
    expect(promoted.bucket.getKeys.every((key) => key.startsWith(installed.prefix))).toBe(true);
    expect(promoted.bucket.getKeys.some((key) => key.startsWith(promoted.prefix))).toBe(false);

    const hashMismatch = await signedFixture('gateway-v1.2.2', 'stable');
    copyFixtureObjects(hashMismatch.bucket, promoted.bucket);
    await expect(exact.loadVerifiedReleaseBundleForIdentity(promoted.bucket.bucket(), {
      ...hashMismatch.pin,
      artifactSha256: 'f'.repeat(64),
    })).rejects.toMatchObject({ code: 'release_invalid' });
  });

  it('rejects a historical signature mismatch and cross-channel replay while N+1 remains present', async () => {
    const installed = await signedFixture('gateway-v1.2.2', 'canary');
    const promoted = await signedFixture('gateway-v1.2.3', 'stable');
    copyFixtureObjects(installed.bucket, promoted.bucket);
    const exact = new ExactR2ReleaseBundleProvider();
    const envelope = promoted.bucket.objects.get(installed.envelopeKey);
    if (!envelope) throw new Error('historical envelope');
    const parsed = JSON.parse(decoder.decode(envelope.bytes)) as Record<string, unknown>;
    if (typeof parsed.signature !== 'string') throw new Error('historical signature');
    parsed.signature = `${parsed.signature[0] === 'A' ? 'B' : 'A'}${parsed.signature.slice(1)}`;
    envelope.bytes = encoder.encode(canonicalJson(parsed));
    await expect(exact.loadVerifiedReleaseBundleForIdentity(promoted.bucket.bucket(), installed.pin))
      .rejects.toMatchObject({ code: 'release_invalid' });

    const replay = await signedFixture('gateway-v1.2.2', 'canary');
    const stablePrefix = `${RELEASE_BUCKET_ROOT}/stable/${replay.manifest.release}/`;
    for (const [key, object] of replay.bucket.objects) {
      promoted.bucket.put(key.replace(replay.prefix, stablePrefix), object.bytes, object.contentType);
    }
    await expect(exact.loadVerifiedReleaseBundleForIdentity(promoted.bucket.bucket(), {
      ...replay.pin,
      channel: 'stable',
    })).rejects.toMatchObject({ code: 'release_invalid' });
  });
});

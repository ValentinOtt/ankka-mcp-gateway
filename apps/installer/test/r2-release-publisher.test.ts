import { REQUIRED_OAUTH_SCOPES } from '../src/constants';
import {
  R2ReleasePublicationError,
  publishCreateOnlyR2Release,
  type R2ReleaseBucket,
  type R2ReleaseObjectPlan,
  type R2ReleasePublicationBlob,
  type R2ReleasePutOptions,
} from '../src/r2-release-publisher';
import {
  APPROVED_CLOUDFLARE_RELEASE_CONTRACT,
  canonicalJson,
  type ReleaseFileRecord,
} from '../src/release-manifest';
import { requiredFixture } from './fixtures';

const encoder = new TextEncoder();
const CHANNEL = 'canary';
const RELEASE = 'gateway-v1.2.3';
const KEY_ID = 'gateway-release-canary-1';
const ROOT = 'ankka-mcp-gateway/releases';
const PREFIX = `${ROOT}/${CHANNEL}/${RELEASE}/`;
const ENVELOPE_KEY = `${PREFIX}release-envelope.json`;
const INTENT_KEY = `ankka-mcp-gateway/publication-intents/v1/${CHANNEL}/${RELEASE}.json`;
const JSON_CONTENT_TYPE = 'application/json; charset=utf-8';
const NOW = 1_787_430_000_000;

interface StoredObject {
  bytes: Uint8Array<ArrayBuffer>;
  contentType: string;
  customMetadata: Record<string, string>;
}

interface PutCall {
  key: string;
  options: R2ReleasePutOptions;
}

function copyBytes(value: Uint8Array): Uint8Array<ArrayBuffer> {
  const copy = new Uint8Array(value.byteLength);
  copy.set(value);
  return copy;
}

class FakeR2 {
  readonly objects = new Map<string, StoredObject>();
  readonly putCalls: PutCall[] = [];
  readonly throwAfterStoreOnce = new Set<string>();
  readonly throwBeforeStoreOnce = new Set<string>();
  readonly corruptGet = new Set<string>();
  readonly deleteAfterPut = new Map<string, string>();

  seed(
    key: string,
    bytes: Uint8Array,
    contentType = 'application/octet-stream',
    customMetadata: Readonly<Record<string, string>> = {},
  ): void {
    this.objects.set(key, {
      bytes: copyBytes(bytes),
      contentType,
      customMetadata: { ...customMetadata },
    });
  }

  mutateBytes(key: string, bytes: Uint8Array): void {
    const stored = this.objects.get(key);
    if (!stored) throw new Error('missing fake object');
    stored.bytes = copyBytes(bytes);
  }

  bucket(): R2ReleaseBucket {
    const bucket: R2ReleaseBucket = {
      put: async (key, value, options) => {
        this.putCalls.push({ key, options });
        if (this.throwBeforeStoreOnce.delete(key)) throw new Error('transport failed before commit');
        if (options.onlyIf.get('if-none-match') !== '*') {
          throw new Error('missing create-only condition');
        }
        if (this.objects.has(key)) return null;
        this.seed(key, value, options.httpMetadata.contentType, options.customMetadata);
        const deleteKey = this.deleteAfterPut.get(key);
        if (deleteKey) this.objects.delete(deleteKey);
        if (this.throwAfterStoreOnce.delete(key)) throw new Error('transport failed after commit');
        const stored = this.objects.get(key);
        if (!stored) throw new Error('fake object deleted');
        return {
          key,
          size: stored.bytes.byteLength,
          httpMetadata: { contentType: stored.contentType },
          customMetadata: { ...stored.customMetadata },
        };
      },
      get: async (key) => {
        const stored = this.objects.get(key);
        if (!stored) return null;
        const returned = copyBytes(stored.bytes);
        if (this.corruptGet.has(key) && returned.byteLength > 0) {
          const firstByte = requiredFixture(returned.at(0), 'returned object byte');
          returned[0] = firstByte ^ 0xff;
        }
        return {
          key,
          size: stored.bytes.byteLength,
          httpMetadata: { contentType: stored.contentType },
          customMetadata: { ...stored.customMetadata },
          async arrayBuffer(): Promise<ArrayBuffer> {
            return returned.buffer.slice(0);
          },
        };
      },
      list: async (options) => {
        const offset = options.cursor ? Number(options.cursor) : 0;
        const keys = [...this.objects.keys()].filter((key) => key.startsWith(options.prefix)).sort();
        const selected = keys.slice(offset, offset + options.limit);
        const next = offset + selected.length;
        const objects = selected.map((key) => ({
            key,
            size: this.objects.get(key)?.bytes.byteLength ?? -1,
          }));
        return next < keys.length
          ? { objects, truncated: true, cursor: String(next) }
          : { objects, truncated: false };
      },
    };
    return bucket;
  }
}

async function sha256Hex(value: Uint8Array): Promise<string> {
  const bytes = copyBytes(value);
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));
  return [...digest].map((byte) => byte.toString(16).padStart(2, '0')).join('');
}

async function record(
  path: string,
  contentType: string,
  contents: string,
): Promise<{ record: ReleaseFileRecord; bytes: Uint8Array<ArrayBuffer> }> {
  const bytes = encoder.encode(contents);
  return {
    bytes,
    record: Object.freeze({
      byteSize: bytes.byteLength,
      contentType,
      path,
      sha256: await sha256Hex(bytes),
    }),
  };
}

async function fixture(): Promise<{
  plan: R2ReleaseObjectPlan;
  blobs: readonly R2ReleasePublicationBlob[];
  payloadKeys: readonly string[];
}> {
  const files = [
    await record('payload/admin/index.html', 'text/html; charset=utf-8', '<main>admin</main>'),
    await record('payload/installer/index.html', 'text/html; charset=utf-8', '<main>installer</main>'),
    await record(
      'payload/worker-cleanup/index.js',
      'application/javascript+module',
      'export class AdminState {}; export default {}',
    ),
    await record(
      'payload/worker-retirement/index.js',
      'application/javascript+module',
      'export default {}',
    ),
    await record('payload/worker/index.js', 'application/javascript+module', 'export default {}'),
  ];
  const component = async (selected: readonly typeof files[number][]) => {
    const records = selected.map((entry) => entry.record);
    return {
      byteSize: records.reduce((total, entry) => total + entry.byteSize, 0),
      fileCount: records.length,
      files: records,
      treeSha256: await sha256Hex(encoder.encode(canonicalJson(records))),
    };
  };
  const records = files.map((entry) => entry.record);
  const artifact = {
      byteSize: records.reduce((total, entry) => total + entry.byteSize, 0),
      fileCount: records.length,
      treeSha256: await sha256Hex(encoder.encode(canonicalJson(records))),
    };
  const manifest = canonicalJson({
    artifact,
    cloudflare: APPROVED_CLOUDFLARE_RELEASE_CONTRACT,
    components: {
      admin: await component(files.slice(0, 1)),
      installer: await component(files.slice(1, 2)),
      worker: await component(files.slice(4, 5)),
      workerCleanup: await component(files.slice(2, 3)),
      workerRetirement: await component(files.slice(3, 4)),
    },
    oauthScopeIds: REQUIRED_OAUTH_SCOPES,
    release: RELEASE,
    schemaVersion: 1,
    sourceCommit: '0123456789abcdef0123456789abcdef01234567',
  });
  const envelopeBytes = encoder.encode(canonicalJson({
    channel: CHANNEL,
    keyId: KEY_ID,
    manifest,
    schemaVersion: 2,
    signature: 'A'.repeat(86),
    signatureContext: 'ankka-mcp-gateway-release-envelope-v2',
  }));
  const objectInputs = [
    {
      bytes: envelopeBytes,
      contentType: JSON_CONTENT_TYPE,
      key: ENVELOPE_KEY,
      sha256: await sha256Hex(envelopeBytes),
    },
    ...files.map((entry) => ({
      bytes: entry.bytes,
      contentType: entry.record.contentType,
      key: `${PREFIX}${entry.record.path}`,
      sha256: entry.record.sha256,
    })),
  ].sort((left, right) => left.key < right.key ? -1 : left.key > right.key ? 1 : 0);
  const objects = objectInputs.map((entry) => ({
    byteSize: entry.bytes.byteLength,
    contentType: entry.contentType,
    key: entry.key,
    sha256: entry.sha256,
    sourcePath: `objects/${entry.key}`,
  }));
  const plan = {
    artifactSha256: artifact.treeSha256,
    channel: CHANNEL,
    immutability: {
      externalAtomicCreateOnlyRequired: true,
      overwriteAllowed: false,
    },
    keyId: KEY_ID,
    objectCount: objects.length,
    objects,
    prefix: PREFIX,
    release: RELEASE,
    schemaVersion: 1,
    totalByteSize: objects.reduce((total, object) => total + object.byteSize, 0),
  } as const;
  return {
    plan,
    blobs: Object.freeze(objectInputs.map((entry) => Object.freeze({
      key: entry.key,
      bytes: new Blob([entry.bytes], { type: entry.contentType }),
    }))),
    payloadKeys: Object.freeze(objectInputs.filter((entry) => entry.key !== ENVELOPE_KEY).map((entry) => entry.key)),
  };
}

interface PublicationClock {
  now(): number;
}

function clock(now = NOW): PublicationClock {
  return { now: () => now };
}

async function publish(input: Awaited<ReturnType<typeof fixture>>, r2: FakeR2, now = NOW) {
  return publishCreateOnlyR2Release({
    blobs: input.blobs,
    bucket: r2.bucket(),
    clock: clock(now),
    objectPlan: input.plan,
  });
}

function expectCode(code: R2ReleasePublicationError['code']) {
  return expect.objectContaining({ code });
}

describe('create-only R2 release publisher', () => {
  it('writes intent first, payloads next, envelope last, then verifies the exact committed set', async () => {
    const input = await fixture();
    const r2 = new FakeR2();
    const result = await publish(input, r2);

    expect(result).toEqual({
      schemaVersion: 1,
      status: 'published',
      channel: CHANNEL,
      release: RELEASE,
      prefix: PREFIX,
      intentKey: INTENT_KEY,
      objectCount: input.plan.objectCount,
      totalByteSize: input.plan.totalByteSize,
      objectPlanSha256: expect.stringMatching(/^[a-f0-9]{64}$/u),
      createdAt: NOW,
    });
    expect(r2.putCalls.map((call) => call.key)).toEqual([
      INTENT_KEY,
      ...input.payloadKeys,
      ENVELOPE_KEY,
    ]);
    expect(r2.putCalls.every((call) =>
      call.options.onlyIf instanceof Headers &&
      call.options.onlyIf.get('if-none-match') === '*' &&
      call.options.sha256.length === 64 &&
      call.options.httpMetadata.contentType.length > 0 &&
      Object.keys(call.options.customMetadata).length > 0)).toBe(true);
    for (const call of r2.putCalls) {
      const stored = r2.objects.get(call.key);
      if (!stored) throw new Error('published fake object missing');
      const contentType = call.options.httpMetadata.contentType;
      expect(call.options.sha256).toBe(stored.customMetadata.ankkaObjectSha256);
      expect(contentType).toBe(stored.contentType);
    }
    expect([...r2.objects.keys()].filter((key) => key.startsWith(PREFIX)).sort())
      .toEqual(input.plan.objects.map((entry) => entry.key));
  });

  it('is restartable when every conditional create reports a conflict with identical bytes', async () => {
    const input = await fixture();
    const r2 = new FakeR2();
    const first = await publish(input, r2);
    const before = [...r2.objects].map(([key, value]) => [key, [...value.bytes]] as const);

    const second = await publish(input, r2, NOW + 60_000);

    expect(second.createdAt).toBe(first.createdAt);
    expect(r2.putCalls.slice(input.plan.objectCount + 1).map((call) => call.key)).toEqual([
      INTENT_KEY,
      ...input.payloadKeys,
      ENVELOPE_KEY,
    ]);
    expect([...r2.objects].map(([key, value]) => [key, [...value.bytes]] as const)).toEqual(before);
  });

  it('rejects a conditional conflict whose exact GET differs and never overwrites it', async () => {
    const input = await fixture();
    const r2 = new FakeR2();
    await publish(input, r2);
    const target = requiredFixture(input.payloadKeys.at(0), 'first payload key');
    const original = r2.objects.get(target);
    if (!original) throw new Error('fixture object missing');
    const replacement = new Uint8Array(original.bytes.byteLength);
    replacement.fill(0x78);
    r2.mutateBytes(target, replacement);

    await expect(publish(input, r2, NOW + 1)).rejects.toEqual(
      expectCode('release_publication_conflict'),
    );
    expect([...r2.objects.get(target)?.bytes ?? []]).toEqual([...replacement]);
  });

  it('settles an ambiguous put that landed, including the envelope commit marker', async () => {
    const input = await fixture();
    const r2 = new FakeR2();
    r2.throwAfterStoreOnce.add(ENVELOPE_KEY);

    await expect(publish(input, r2)).resolves.toMatchObject({ status: 'published' });
    expect(r2.objects.has(ENVELOPE_KEY)).toBe(true);
  });

  it('fails closed when an ambiguous put did not land, then resumes from the immutable intent', async () => {
    const input = await fixture();
    const r2 = new FakeR2();
    const firstPayload = requiredFixture(input.payloadKeys.at(0), 'first payload key');
    r2.throwBeforeStoreOnce.add(firstPayload);

    await expect(publish(input, r2)).rejects.toEqual(
      expectCode('release_publication_unavailable'),
    );
    expect(r2.objects.has(INTENT_KEY)).toBe(true);
    expect(r2.objects.has(ENVELOPE_KEY)).toBe(false);
    await expect(publish(input, r2, NOW + 1)).resolves.toMatchObject({ status: 'published' });
  });

  it('resumes after a crash with intent and a strict payload prefix but no envelope', async () => {
    const input = await fixture();
    const r2 = new FakeR2();
    const secondPayload = requiredFixture(input.payloadKeys.at(1), 'second payload key');
    r2.throwBeforeStoreOnce.add(secondPayload);

    await expect(publish(input, r2)).rejects.toEqual(
      expectCode('release_publication_unavailable'),
    );
    expect(r2.objects.has(INTENT_KEY)).toBe(true);
    expect(r2.objects.has(requiredFixture(input.payloadKeys.at(0), 'first payload key'))).toBe(true);
    expect(r2.objects.has(secondPayload)).toBe(false);
    expect(r2.objects.has(ENVELOPE_KEY)).toBe(false);
    await expect(publish(input, r2, NOW + 5_000)).resolves.toMatchObject({ status: 'published' });
  });

  it('rejects corrupt data returned by exact GET even when the create itself succeeded', async () => {
    const input = await fixture();
    const r2 = new FakeR2();
    r2.corruptGet.add(requiredFixture(input.payloadKeys.at(0), 'first payload key'));

    await expect(publish(input, r2)).rejects.toEqual(
      expectCode('release_publication_conflict'),
    );
    expect(r2.objects.has(ENVELOPE_KEY)).toBe(false);
  });

  it('burns the release ID but refuses an extra object already present under the exact prefix', async () => {
    const input = await fixture();
    const r2 = new FakeR2();
    const extraKey = `${PREFIX}payload/admin/extra.js`;
    r2.seed(extraKey, encoder.encode('extra'));

    await expect(publish(input, r2)).rejects.toEqual(
      expectCode('release_publication_conflict'),
    );
    expect(r2.objects.has(INTENT_KEY)).toBe(true);
    expect(r2.objects.has(extraKey)).toBe(true);
    expect(r2.objects.has(ENVELOPE_KEY)).toBe(false);
  });

  it('detects an object missing after the envelope write during final exact verification', async () => {
    const input = await fixture();
    const r2 = new FakeR2();
    const firstPayload = requiredFixture(input.payloadKeys.at(0), 'first payload key');
    r2.deleteAfterPut.set(ENVELOPE_KEY, firstPayload);

    await expect(publish(input, r2)).rejects.toEqual(
      expectCode('release_publication_conflict'),
    );
    expect(r2.objects.has(ENVELOPE_KEY)).toBe(true);
    expect(r2.objects.has(firstPayload)).toBe(false);
  });

  it.each([
    ['missing blob', (input: Awaited<ReturnType<typeof fixture>>) => ({
      plan: input.plan,
      blobs: input.blobs.slice(0, -1),
    })],
    ['extra blob', (input: Awaited<ReturnType<typeof fixture>>) => ({
      plan: input.plan,
      blobs: [...input.blobs, requiredFixture(input.blobs.at(0), 'first publication blob')],
    })],
    ['wrong blob order', (input: Awaited<ReturnType<typeof fixture>>) => ({
      plan: input.plan,
      blobs: [
        requiredFixture(input.blobs.at(1), 'second publication blob'),
        requiredFixture(input.blobs.at(0), 'first publication blob'),
        ...input.blobs.slice(2),
      ],
    })],
  ])('rejects an inexact blob set before the immutable intent: %s', async (_label, alter) => {
    const input = await fixture();
    const changed = alter(input);
    const r2 = new FakeR2();
    await expect(publishCreateOnlyR2Release({
      blobs: changed.blobs,
      bucket: r2.bucket(),
      clock: clock(),
      objectPlan: changed.plan,
    })).rejects.toEqual(expectCode('release_publication_invalid'));
    expect(r2.putCalls).toHaveLength(0);
  });

  it.each([
    ['duplicate key', (plan: R2ReleaseObjectPlan) => ({
      ...plan,
      objects: [plan.objects[0], { ...plan.objects[0] }, ...plan.objects.slice(2)],
    })],
    ['noncanonical order', (plan: R2ReleaseObjectPlan) => ({
      ...plan,
      objects: [plan.objects[1], plan.objects[0], ...plan.objects.slice(2)],
    })],
    ['unsafe key', (plan: R2ReleaseObjectPlan) => ({
      ...plan,
      objects: plan.objects.map((object, index) => index === 0
        ? {
            ...object,
            key: `${PREFIX}payload/../escape.js`,
            sourcePath: `objects/${PREFIX}payload/../escape.js`,
          }
        : object),
    })],
    ['oversized object', (plan: R2ReleaseObjectPlan) => {
      const byteSize = (32 * 1024 * 1024) + (16 * 1024 * 1024) + 4_097;
      const objects = plan.objects.map((object, index) => index === 0
        ? { ...object, byteSize }
        : object);
      return {
        ...plan,
        objects,
        totalByteSize: objects.reduce((total, object) => total + object.byteSize, 0),
      };
    }],
    ['mutable channel alias', (plan: R2ReleaseObjectPlan) => {
      const prefix = `${ROOT}/current/${RELEASE}/`;
      return {
        ...plan,
        channel: 'current',
        prefix,
        objects: plan.objects.map((object) => {
          const key = object.key.replace(PREFIX, prefix);
          return { ...object, key, sourcePath: `objects/${key}` };
        }),
      };
    }],
    ['mutable source alias', (plan: R2ReleaseObjectPlan) => ({
      ...plan,
      objects: plan.objects.map((object, index) => index === 0
        ? { ...object, sourcePath: 'objects/ankka-mcp-gateway/releases/current.json' }
        : object),
    })],
  ])('rejects a non-signer or mutable plan before R2 mutation: %s', async (_label, alter) => {
    const input = await fixture();
    const plan = alter(input.plan);
    const r2 = new FakeR2();
    await expect(publishCreateOnlyR2Release({
      blobs: input.blobs,
      bucket: r2.bucket(),
      clock: clock(),
      objectPlan: plan,
    })).rejects.toEqual(expectCode('release_publication_invalid'));
    expect(r2.putCalls).toHaveLength(0);
  });

  it('rejects replaying a canary-bound envelope through a stable publication plan', async () => {
    const input = await fixture();
    const stablePrefix = `${ROOT}/stable/${RELEASE}/`;
    const plan = {
      ...input.plan,
      channel: 'stable',
      prefix: stablePrefix,
      objects: input.plan.objects.map((object) => {
        const key = object.key.replace(PREFIX, stablePrefix);
        return { ...object, key, sourcePath: `objects/${key}` };
      }),
    };
    const blobs = input.blobs.map((blob) => Object.freeze({
      key: blob.key.replace(PREFIX, stablePrefix),
      bytes: blob.bytes,
    }));
    const r2 = new FakeR2();
    await expect(publishCreateOnlyR2Release({
      blobs,
      bucket: r2.bucket(),
      clock: clock(),
      objectPlan: plan,
    })).rejects.toEqual(expectCode('release_publication_invalid'));
    expect(r2.putCalls).toHaveLength(0);
  });
});

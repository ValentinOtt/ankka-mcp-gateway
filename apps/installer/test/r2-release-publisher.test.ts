import { REQUIRED_OAUTH_SCOPES } from '../src/constants';
import {
  R2ReleasePublicationError,
  publishCreateOnlyR2Release,
  type R2ReleaseObjectPlan,
  type R2ReleasePublicationBlob,
} from '../src/r2-release-publisher';
import {
  APPROVED_CLOUDFLARE_RELEASE_CONTRACT,
  canonicalJson,
  type ReleaseFileRecord,
} from '../src/release-manifest';

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
  options: R2PutOptions | undefined;
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
    customMetadata: Record<string, string> = {},
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

  bucket(): R2Bucket {
    const fake = this;
    return {
      async put(
        key: string,
        value: ReadableStream | ArrayBuffer | ArrayBufferView | string | null | Blob,
        options?: R2PutOptions,
      ): Promise<R2Object | null> {
        fake.putCalls.push({ key, options });
        if (fake.throwBeforeStoreOnce.delete(key)) throw new Error('transport failed before commit');
        const condition = options?.onlyIf;
        if (!(condition instanceof Headers) || condition.get('if-none-match') !== '*') {
          throw new Error('missing create-only condition');
        }
        if (fake.objects.has(key)) return null;
        if (!(value instanceof Uint8Array)) throw new Error('unexpected fake value');
        const contentType = options?.httpMetadata instanceof Headers
          ? options.httpMetadata.get('content-type') ?? ''
          : options?.httpMetadata?.contentType ?? '';
        fake.seed(key, value, contentType, options?.customMetadata ?? {});
        const deleteKey = fake.deleteAfterPut.get(key);
        if (deleteKey) fake.objects.delete(deleteKey);
        if (fake.throwAfterStoreOnce.delete(key)) throw new Error('transport failed after commit');
        const stored = fake.objects.get(key);
        if (!stored) throw new Error('fake object deleted');
        return {
          key,
          size: stored.bytes.byteLength,
          httpMetadata: { contentType: stored.contentType },
          customMetadata: { ...stored.customMetadata },
        } as unknown as R2Object;
      },
      async get(key: string): Promise<R2ObjectBody | null> {
        const stored = fake.objects.get(key);
        if (!stored) return null;
        const returned = copyBytes(stored.bytes);
        if (fake.corruptGet.has(key) && returned.byteLength > 0) returned[0] ^= 0xff;
        return {
          key,
          size: stored.bytes.byteLength,
          httpMetadata: { contentType: stored.contentType },
          customMetadata: { ...stored.customMetadata },
          async arrayBuffer(): Promise<ArrayBuffer> {
            return returned.buffer.slice(0);
          },
        } as unknown as R2ObjectBody;
      },
      async list(options?: R2ListOptions): Promise<R2Objects> {
        const prefix = options?.prefix ?? '';
        const offset = options?.cursor ? Number(options.cursor) : 0;
        const limit = options?.limit ?? 1_000;
        const keys = [...fake.objects.keys()].filter((key) => key.startsWith(prefix)).sort();
        const selected = keys.slice(offset, offset + limit);
        const next = offset + selected.length;
        return {
          objects: selected.map((key) => ({
            key,
            size: fake.objects.get(key)?.bytes.byteLength ?? -1,
          } as R2Object)),
          truncated: next < keys.length,
          ...(next < keys.length ? { cursor: String(next) } : {}),
          delimitedPrefixes: [],
        } as R2Objects;
      },
    } as unknown as R2Bucket;
  }
}

async function sha256Hex(value: string | Uint8Array): Promise<string> {
  const bytes = typeof value === 'string' ? encoder.encode(value) : copyBytes(value);
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
      treeSha256: await sha256Hex(canonicalJson(records)),
    };
  };
  const records = files.map((entry) => entry.record);
  const manifest = canonicalJson({
    artifact: {
      byteSize: records.reduce((total, entry) => total + entry.byteSize, 0),
      fileCount: records.length,
      treeSha256: await sha256Hex(canonicalJson(records)),
    },
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
  const artifactSha256 = JSON.parse(manifest).artifact.treeSha256 as string;
  const plan = {
    artifactSha256,
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

function clock(now = NOW): { now(): number } {
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
      call.options?.onlyIf instanceof Headers &&
      call.options.onlyIf.get('if-none-match') === '*' &&
      typeof call.options.sha256 === 'string' &&
      call.options.httpMetadata !== undefined &&
      call.options.customMetadata !== undefined)).toBe(true);
    for (const call of r2.putCalls) {
      const stored = r2.objects.get(call.key);
      if (!stored) throw new Error('published fake object missing');
      const contentType = call.options?.httpMetadata instanceof Headers
        ? call.options.httpMetadata.get('content-type')
        : call.options?.httpMetadata?.contentType;
      expect(call.options?.sha256).toBe(stored.customMetadata.ankkaObjectSha256);
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
    const target = input.payloadKeys[0];
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
    const firstPayload = input.payloadKeys[0];
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
    const secondPayload = input.payloadKeys[1];
    r2.throwBeforeStoreOnce.add(secondPayload);

    await expect(publish(input, r2)).rejects.toEqual(
      expectCode('release_publication_unavailable'),
    );
    expect(r2.objects.has(INTENT_KEY)).toBe(true);
    expect(r2.objects.has(input.payloadKeys[0])).toBe(true);
    expect(r2.objects.has(secondPayload)).toBe(false);
    expect(r2.objects.has(ENVELOPE_KEY)).toBe(false);
    await expect(publish(input, r2, NOW + 5_000)).resolves.toMatchObject({ status: 'published' });
  });

  it('rejects corrupt data returned by exact GET even when the create itself succeeded', async () => {
    const input = await fixture();
    const r2 = new FakeR2();
    r2.corruptGet.add(input.payloadKeys[0]);

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
    r2.deleteAfterPut.set(ENVELOPE_KEY, input.payloadKeys[0]);

    await expect(publish(input, r2)).rejects.toEqual(
      expectCode('release_publication_conflict'),
    );
    expect(r2.objects.has(ENVELOPE_KEY)).toBe(true);
    expect(r2.objects.has(input.payloadKeys[0])).toBe(false);
  });

  it.each([
    ['missing blob', (input: Awaited<ReturnType<typeof fixture>>) => ({
      plan: input.plan,
      blobs: input.blobs.slice(0, -1),
    })],
    ['extra blob', (input: Awaited<ReturnType<typeof fixture>>) => ({
      plan: input.plan,
      blobs: [...input.blobs, input.blobs[0]],
    })],
    ['wrong blob order', (input: Awaited<ReturnType<typeof fixture>>) => ({
      plan: input.plan,
      blobs: [input.blobs[1], input.blobs[0], ...input.blobs.slice(2)],
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
    ['duplicate key', (plan: Record<string, any>) => {
      plan.objects[1] = { ...plan.objects[0] };
    }],
    ['noncanonical order', (plan: Record<string, any>) => {
      [plan.objects[0], plan.objects[1]] = [plan.objects[1], plan.objects[0]];
    }],
    ['unsafe key', (plan: Record<string, any>) => {
      plan.objects[0].key = `${PREFIX}payload/../escape.js`;
      plan.objects[0].sourcePath = `objects/${plan.objects[0].key}`;
    }],
    ['oversized object', (plan: Record<string, any>) => {
      plan.objects[0].byteSize = (32 * 1024 * 1024) + (16 * 1024 * 1024) + 4_097;
      plan.totalByteSize = plan.objects.reduce((total: number, object: { byteSize: number }) => total + object.byteSize, 0);
    }],
    ['mutable channel alias', (plan: Record<string, any>) => {
      plan.channel = 'current';
      plan.prefix = `${ROOT}/current/${RELEASE}/`;
      for (const object of plan.objects) {
        object.key = object.key.replace(PREFIX, plan.prefix);
        object.sourcePath = `objects/${object.key}`;
      }
    }],
    ['mutable source alias', (plan: Record<string, any>) => {
      plan.objects[0].sourcePath = 'objects/ankka-mcp-gateway/releases/current.json';
    }],
  ])('rejects a non-signer or mutable plan before R2 mutation: %s', async (_label, mutate) => {
    const input = await fixture();
    const plan = structuredClone(input.plan) as Record<string, any>;
    mutate(plan);
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
    const plan = structuredClone(input.plan) as unknown as R2ReleaseObjectPlan;
    (plan as { channel: string }).channel = 'stable';
    (plan as { prefix: string }).prefix = stablePrefix;
    for (const object of plan.objects as Array<R2ReleaseObjectPlan['objects'][number]>) {
      (object as { key: string }).key = object.key.replace(PREFIX, stablePrefix);
      (object as { sourcePath: string }).sourcePath = `objects/${object.key}`;
    }
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

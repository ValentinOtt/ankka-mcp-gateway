import * as v from 'valibot';

import type { BoundaryValue } from '../src/boundary';
import { REQUIRED_OAUTH_SCOPES } from '../src/constants';
import { base64UrlEncode } from '../src/crypto';
import type { CustomerCloudflareTransport } from '../src/customer-cloudflare-grant';
import {
  CustomerRuntimeUpdateError,
  runCustomerRuntimeUpdate,
  type CustomerRuntimeControlCommand,
  type CustomerRuntimeUpdateInput,
} from '../src/customer-runtime-update';
import { releaseSignatureCanonicalJson, type VerifiedReleaseBundle, type VerifiedReleasePayloadBlob } from '../src/release';
import {
  APPROVED_CLOUDFLARE_RELEASE_CONTRACT,
  canonicalJson,
  parseReleaseManifest,
  type ReleaseComponent,
  type ReleaseFileRecord,
} from '../src/release-manifest';
import { buildPublicUpdateChannel } from '../src/update-channel';
import type { R2ReleaseReadBucket } from '../src/r2-release-provider';
import { createTwoStageDeployRuntime, type TwoStageDeployEnv } from '../src/two-stage-runtime';

const CONTROL_PLANE = 'https://deploy.ankka.ai';
const ACCOUNT_ID = 'a'.repeat(32);
const WORKER_ID = 'b'.repeat(32);
const WORKER_NAME = 'ankka-gateway-test';
const ACCESS_TOKEN = `token_${'d'.repeat(32)}`;
const OLD_VERSION = '11111111-1111-4111-8111-111111111111';
const DEPLOYMENT = '22222222-2222-4222-8222-222222222222';
const KEY_ID = 'release-2026-09-test';
const FROM_RELEASE = 'gateway-v0.1.34';
const TO_RELEASE = 'gateway-v0.1.35';
const SESSION_JWT = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJzZXNzaW9uIn0.c2Vzc2lvbi1zaWduYXR1cmU';
const COMPLETION_JWT = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJjb21wbGV0ZSJ9.Y29tcGxldGlvbi1zaWduYXR1cmU';
const encoder = new TextEncoder();

function hex(bytes: Uint8Array): string {
  return [...bytes].map((byte) => byte.toString(16).padStart(2, '0')).join('');
}

async function sha256(input: Uint8Array | string): Promise<string> {
  const bytes = v.is(v.string(), input) ? encoder.encode(input) : input;
  const owned = new Uint8Array(new ArrayBuffer(bytes.byteLength));
  owned.set(bytes);
  return hex(new Uint8Array(await crypto.subtle.digest('SHA-256', owned)));
}

async function source(path: string, contentType: string, body: string) {
  const bytes = encoder.encode(body);
  return Object.freeze({
    bytes,
    record: Object.freeze({ path, contentType, byteSize: bytes.byteLength, sha256: await sha256(bytes) }),
  });
}

async function component(files: readonly { readonly record: ReleaseFileRecord }[]): Promise<ReleaseComponent> {
  const records = Object.freeze(files.map((file) => file.record));
  return Object.freeze({
    byteSize: records.reduce((sum, file) => sum + file.byteSize, 0),
    fileCount: records.length,
    files: records,
    treeSha256: await sha256(canonicalJson(records)),
  });
}

interface SignedRelease {
  readonly bundle: VerifiedReleaseBundle;
  readonly publicKey: string;
  readonly files: ReadonlyMap<string, Uint8Array>;
  readonly workerSource: string;
}

/** A complete release bundle signed with a key generated for this test. */
async function signedRelease(releaseId = TO_RELEASE, signingKey?: CryptoKeyPair): Promise<SignedRelease> {
  const workerSource = `// ankka-control-plane-origin:${CONTROL_PLANE}\nexport class AdminState{};export default{fetch(){return new Response("${releaseId}")}};`;
  const admin = [
    await source('payload/admin/assets/admin-0badc0de.js', 'text/javascript; charset=utf-8', 'globalThis.__admin=35;'),
    await source('payload/admin/index.html', 'text/html; charset=utf-8', '<!doctype html><main>admin v35</main>'),
  ];
  const installer = [await source('payload/installer/index.html', 'text/html; charset=utf-8', '<!doctype html><main>installer</main>')];
  const worker = [await source('payload/worker/index.js', 'application/javascript+module', workerSource)];
  const workerBootstrap = [await source('payload/worker-bootstrap/index.js', 'application/javascript+module',
    'export class AdminState{};export default{fetch(){return new Response("bootstrap")}};')];
  const workerCleanup = [await source('payload/worker-cleanup/index.js', 'application/javascript+module',
    'export class AdminState{};export default{fetch(){return new Response("cleanup")}};')];
  const workerRetirement = [await source('payload/worker-retirement/index.js', 'application/javascript+module',
    'export default{fetch(){return new Response(null,{status:410})}};')];
  const all = Object.freeze([...admin, ...installer, ...worker, ...workerBootstrap, ...workerCleanup, ...workerRetirement]);
  const manifest = parseReleaseManifest({
    artifact: {
      byteSize: all.reduce((sum, file) => sum + file.record.byteSize, 0),
      fileCount: all.length,
      treeSha256: await sha256(canonicalJson(all.map((file) => file.record).sort((left, right) =>
        left.path < right.path ? -1 : left.path > right.path ? 1 : 0))),
    },
    cloudflare: APPROVED_CLOUDFLARE_RELEASE_CONTRACT,
    controlPlaneOrigin: CONTROL_PLANE,
    components: {
      admin: await component(admin),
      installer: await component(installer),
      worker: await component(worker),
      workerBootstrap: await component(workerBootstrap),
      workerCleanup: await component(workerCleanup),
      workerRetirement: await component(workerRetirement),
    },
    oauthScopeIds: REQUIRED_OAUTH_SCOPES,
    release: releaseId,
    schemaVersion: 1,
    sourceCommit: '0123456789abcdef0123456789abcdef01234567',
  });
  const keyPair = signingKey ?? await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']);
  const publicKey = base64UrlEncode(new Uint8Array(await crypto.subtle.exportKey('raw', keyPair.publicKey)));
  const serializedManifest = canonicalJson(manifest);
  const signature = base64UrlEncode(new Uint8Array(await crypto.subtle.sign(
    'Ed25519', keyPair.privateKey, encoder.encode(releaseSignatureCanonicalJson('canary', KEY_ID, serializedManifest)),
  )));
  const payload = Object.freeze(all.map((file): VerifiedReleasePayloadBlob => {
    const owned = new Uint8Array(new ArrayBuffer(file.bytes.byteLength));
    owned.set(file.bytes);
    return Object.freeze({ ...file.record, bytes: new Blob([owned], { type: file.record.contentType }) });
  }));
  const bundle: VerifiedReleaseBundle = Object.freeze({
    verification: 'ed25519',
    channel: 'canary',
    keyId: KEY_ID,
    envelope: Object.freeze({
      schemaVersion: 2, channel: 'canary', keyId: KEY_ID,
      manifest: serializedManifest, signature,
      signatureContext: 'ankka-mcp-gateway-release-envelope-v2',
    }),
    manifest,
    payload,
    publicKey,
  });
  return {
    bundle,
    publicKey,
    files: new Map(all.map((file) => [file.record.path, file.bytes])),
    workerSource,
  };
}

function currentBindings(publicKey: string) {
  return {
    ADMIN_EMAILS: 'admin@example.com',
    ANKKA_INSTALL_ID: `acg-${'c'.repeat(24)}`,
    ANKKA_GATEWAY_RELEASE: FROM_RELEASE,
    ANKKA_GATEWAY_RELEASE_SHA256: `sha256:${'1'.repeat(64)}`,
    ANKKA_MANAGEMENT_HOSTNAME: 'manage.example.com',
    ANKKA_UPDATE_CHANNEL: 'canary',
    ANKKA_UPDATE_KEY_ID: KEY_ID,
    ANKKA_UPDATE_PUBLIC_KEY: publicKey,
    ANKKA_WORKERS_SUBDOMAIN: 'customer',
    ANKKA_WORKER_NAME: WORKER_NAME,
    CF_ACCESS_AUD: 'e'.repeat(64),
    CF_ACCESS_ISSUER: 'https://team.cloudflareaccess.com',
    CLOUDFLARE_ACCOUNT_ID: ACCOUNT_ID,
    CLOUDFLARE_ZONE_ID: 'f'.repeat(32),
    CLOUDFLARE_ZONE_NAME: 'example.com',
    ZERO_TRUST_READY: 'true',
  };
}

interface Recorded {
  readonly method: string;
  readonly url: string;
  readonly authorization: string | null;
  readonly form: FormData | null;
}

interface ProviderFake {
  readonly transport: CustomerCloudflareTransport;
  readonly requests: Recorded[];
  readonly events: string[];
  readonly tamper: { file: string | null; descriptorRelease: string | null; uploadStatus: number };
}

function envelope(result: BoundaryValue, status = 200): Response {
  return Response.json({ success: true, errors: [], messages: [], result }, { status });
}

function providerFake(release: SignedRelease, options: {
  readonly currentRelease?: string;
  readonly controlPlane?: (request: Request) => Promise<Response>;
} = {}): ProviderFake {
  const requests: Recorded[] = [];
  const events: string[] = [];
  const tamper: ProviderFake['tamper'] = { file: null, descriptorRelease: null, uploadStatus: 200 };
  const channel = buildPublicUpdateChannel(release.bundle);
  const bindings = currentBindings(release.publicKey);
  bindings.ANKKA_GATEWAY_RELEASE = options.currentRelease ?? FROM_RELEASE;
  const releasePath = `/api/releases/canary/by-id/${release.bundle.manifest.release}/${release.bundle.manifest.artifact.treeSha256}`;
  const transport: CustomerCloudflareTransport = async (input, init) => {
    const request = input instanceof Request ? input : new Request(input, init);
    const url = new URL(request.url);
    const method = request.method;
    const form = request.headers.get('content-type')?.startsWith('multipart/form-data') ? await request.formData() : null;
    requests.push({ method, url: request.url, authorization: request.headers.get('authorization'), form });
    if (url.origin === CONTROL_PLANE && method === 'GET') {
      if (options.controlPlane !== undefined) return options.controlPlane(request);
      if (url.pathname === releasePath) {
        events.push('descriptor');
        const served = tamper.descriptorRelease === null
          ? channel
          : { ...channel, release: { ...channel.release, id: tamper.descriptorRelease } };
        return Response.json(served);
      }
      const prefix = `${releasePath}/files/`;
      const path = url.pathname.startsWith(prefix) ? url.pathname.slice(prefix.length) : undefined;
      const bytes = path === undefined ? undefined : release.files.get(path);
      if (bytes === undefined) return new Response('missing', { status: 404 });
      events.push(`file:${path}`);
      const body = tamper.file === path ? encoder.encode('tampered') : bytes;
      const owned = new Uint8Array(new ArrayBuffer(body.byteLength));
      owned.set(body);
      return new Response(owned, { headers: { 'content-type': 'application/octet-stream' } });
    }
    if (url.origin !== 'https://api.cloudflare.com') throw new Error(`unexpected origin ${url.origin}`);
    expect(request.headers.get('authorization')).toMatch(/^Bearer /u);
    const path = url.pathname.replace(`/client/v4/accounts/${ACCOUNT_ID}`, '');
    if (method === 'GET' && path === `/workers/workers/${WORKER_NAME}`) {
      events.push('worker');
      return envelope({ id: WORKER_ID, name: WORKER_NAME, tags: ['ankka-mcp-gateway'] });
    }
    if (method === 'GET' && path === `/workers/scripts/${WORKER_NAME}/deployments`) {
      events.push('deployments');
      return envelope({ deployments: [{ id: DEPLOYMENT, versions: [{ version_id: OLD_VERSION, percentage: 100 }] }] });
    }
    if (method === 'GET' && path === `/workers/workers/${WORKER_ID}/versions/${OLD_VERSION}`) {
      events.push('version');
      return envelope({
        id: OLD_VERSION,
        compatibility_date: '2026-08-08',
        main_module: 'index.js',
        bindings: [
          { name: 'ADMIN_STATE', type: 'durable_object_namespace', class_name: 'AdminState' },
          { name: 'ANKKA_GATEWAY_OWNERSHIP_WRAP_KEY', type: 'secret_text' },
          { name: 'ASSETS', type: 'assets' },
          ...Object.entries(bindings).map(([name, text]) => ({ name, type: 'plain_text', text })),
        ],
      });
    }
    if (method === 'POST' && path === `/workers/scripts/${WORKER_NAME}/assets-upload-session`) {
      events.push('asset-session');
      const manifest = v.parse(v.object({ manifest: v.record(v.string(), v.object({ hash: v.string(), size: v.number() })) }),
        await request.json());
      const hashes = [...new Set(Object.values(manifest.manifest).map((entry) => entry.hash))];
      return envelope({ jwt: SESSION_JWT, buckets: [hashes] }, 201);
    }
    if (method === 'POST' && path === '/workers/assets/upload') {
      events.push('asset-bucket');
      expect(request.headers.get('authorization')).toBe(`Bearer ${SESSION_JWT}`);
      return envelope({ jwt: COMPLETION_JWT }, 201);
    }
    if (method === 'PUT' && path === `/workers/scripts/${WORKER_NAME}`) {
      events.push('script-upload');
      return tamper.uploadStatus === 200
        ? envelope({ id: WORKER_NAME })
        : Response.json({ success: false, errors: [{ code: 10000, message: 'synthetic' }], messages: [], result: null }, { status: tamper.uploadStatus });
    }
    throw new Error(`unexpected request ${method} ${path}`);
  };
  return { transport, requests, events, tamper };
}

function input(fake: ProviderFake, release: SignedRelease, commands: CustomerRuntimeControlCommand[], handovers: string[]): CustomerRuntimeUpdateInput {
  return {
    accessToken: ACCESS_TOKEN,
    accountId: ACCOUNT_ID,
    workerName: WORKER_NAME,
    controlPlaneOrigin: CONTROL_PLANE,
    channel: 'canary',
    updateKeyId: KEY_ID,
    updatePublicKey: release.publicKey,
    target: { release: TO_RELEASE, artifactSha256: `sha256:${release.bundle.manifest.artifact.treeSha256}` },
    transport: fake.transport,
    control: async (command) => {
      commands.push(command);
      fake.events.push(`control:${command.command}${command.command === 'progress' ? `:${command.stage}` : ''}`);
      return true;
    },
    armHandover: async ({ fromVersionId }) => {
      handovers.push(fromVersionId);
      fake.events.push('handover');
    },
  };
}

const metadataSchema = v.looseObject({
  assets: v.strictObject({
    config: v.strictObject({
      not_found_handling: v.literal('single-page-application'),
      run_worker_first: v.tuple([v.literal('/__ankka/*'), v.literal('/api/*')]),
    }),
    jwt: v.string(),
  }),
  bindings: v.array(v.looseObject({ name: v.string(), type: v.string() })),
  compatibility_date: v.literal('2026-08-08'),
  compatibility_flags: v.tuple([]),
  main_module: v.literal('index.js'),
});

async function historicalServer(retained: SignedRelease, promoted: SignedRelease) {
  const objects = new Map<string, { bytes: Uint8Array; contentType: string }>();
  const reads: string[] = [];
  for (const release of [retained, promoted]) {
    const prefix = `ankka-mcp-gateway/releases/canary/${release.bundle.manifest.release}/`;
    objects.set(`${prefix}release-envelope.json`, {
      bytes: encoder.encode(canonicalJson(release.bundle.envelope)), contentType: 'application/json; charset=utf-8',
    });
    for (const file of release.bundle.payload) {
      objects.set(`${prefix}${file.path}`, { bytes: new Uint8Array(await file.bytes.arrayBuffer()), contentType: file.contentType });
    }
  }
  const bucket: R2ReleaseReadBucket = {
    get: async (key) => {
      reads.push(key);
      const stored = objects.get(key);
      if (stored === undefined) return null;
      return {
        key, size: stored.bytes.byteLength, httpMetadata: { contentType: stored.contentType },
        arrayBuffer: async () => new Uint8Array(stored.bytes).buffer,
      };
    },
    list: async ({ prefix }) => ({
      objects: [...objects].filter(([key]) => key.startsWith(prefix)).map(([key, value]) => ({ key, size: value.bytes.byteLength })),
      truncated: false,
    }),
  };
  const worker = createTwoStageDeployRuntime({
    schemaVersion: 1, channel: 'canary', controlPlaneOrigin: CONTROL_PLANE,
    release: promoted.bundle.manifest.release, artifactSha256: promoted.bundle.manifest.artifact.treeSha256,
    keyId: KEY_ID, publicKey: promoted.publicKey,
  });
  // SAFETY: public release reads must need only the bucket, never session or OAuth bindings.
  const env = { GATEWAY_RELEASE_BUCKET: bucket } as TwoStageDeployEnv;
  return {
    objects, reads,
    fetch: (request: Request) => worker.fetch(request, env),
    retainedPath: `/api/releases/canary/by-id/${retained.bundle.manifest.release}/${retained.bundle.manifest.artifact.treeSha256}`,
  };
}

describe('gateway-local runtime update', () => {
  it('rolls back through the public server to the signed retained release after the channel advances', async () => {
    const key = await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']);
    const retained = await signedRelease(TO_RELEASE, key);
    const promoted = await signedRelease('gateway-v0.1.36', key);
    const server = await historicalServer(retained, promoted);
    const latest = await server.fetch(new Request(`${CONTROL_PLANE}/api/releases/canary`));
    expect(await latest.json()).toMatchObject({ release: { id: 'gateway-v0.1.36' } });
    const fake = providerFake(retained, { currentRelease: 'gateway-v0.1.36', controlPlane: server.fetch });
    const commands: CustomerRuntimeControlCommand[] = [];
    const handovers: string[] = [];
    await expect(runCustomerRuntimeUpdate(input(fake, retained, commands, handovers)))
      .resolves.toEqual({ status: 'uploaded', fromVersionId: OLD_VERSION });
    expect(handovers).toEqual([OLD_VERSION]);
    const publicRequests = fake.requests.filter((request) => new URL(request.url).origin === CONTROL_PLANE);
    expect(publicRequests).toHaveLength(retained.files.size + 1);
    expect(publicRequests.every((request) => request.authorization === null &&
      new URL(request.url).pathname.startsWith(server.retainedPath))).toBe(true);
    const uploaded = fake.requests.find((request) => request.method === 'PUT')?.form?.get('index.js');
    if (!(uploaded instanceof Blob)) throw new Error('rollback upload missing');
    expect(await uploaded.text()).toBe(retained.workerSource);
    // The descriptor and all files reuse one verified immutable bundle.
    const envelopeKey = `ankka-mcp-gateway/releases/canary/${TO_RELEASE}/release-envelope.json`;
    expect(server.reads.filter((key) => key === envelopeKey)).toHaveLength(1);
  });

  it('loads a retained release even when the promoted bundle is unavailable', async () => {
    const key = await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']);
    const retained = await signedRelease(TO_RELEASE, key);
    const promoted = await signedRelease('gateway-v0.1.36', key);
    const server = await historicalServer(retained, promoted);
    server.objects.delete('ankka-mcp-gateway/releases/canary/gateway-v0.1.36/release-envelope.json');
    const descriptor = await server.fetch(new Request(`${CONTROL_PLANE}${server.retainedPath}`));
    expect(descriptor.status).toBe(200);
    expect(descriptor.headers.get('set-cookie')).toBeNull();
    expect(await descriptor.json()).toMatchObject({ release: { id: TO_RELEASE } });
    expect((await server.fetch(new Request(`${CONTROL_PLANE}/api/releases/canary`))).status).toBe(503);
  });

  it('never substitutes the current channel for missing, mismatched, corrupt, or untrusted retained bytes', async () => {
    for (const fault of ['missing', 'digest', 'corrupt', 'key'] as const) {
      const key = await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']);
      const retained = await signedRelease(TO_RELEASE, key);
      const promoted = await signedRelease('gateway-v0.1.36', fault === 'key' ? undefined : key);
      const server = await historicalServer(retained, promoted);
      const prefix = `ankka-mcp-gateway/releases/canary/${TO_RELEASE}/`;
      if (fault === 'missing') server.objects.delete(`${prefix}release-envelope.json`);
      if (fault === 'corrupt') {
        const file = server.objects.get(`${prefix}payload/worker/index.js`);
        if (file === undefined || file.bytes[0] === undefined) throw new Error('fixture file missing');
        file.bytes[0] = file.bytes[0] ^ 1;
      }
      const fake = providerFake(retained, { currentRelease: 'gateway-v0.1.36', controlPlane: server.fetch });
      const commands: CustomerRuntimeControlCommand[] = [];
      const handovers: string[] = [];
      const base = input(fake, retained, commands, handovers);
      await expect(runCustomerRuntimeUpdate({
        ...base,
        target: fault === 'digest' ? { release: TO_RELEASE, artifactSha256: `sha256:${'0'.repeat(64)}` } : base.target,
      })).rejects.toMatchObject({ code: 'release_unavailable', stage: 'release_read' });
      expect(handovers).toEqual([]);
      expect(fake.events).not.toContain('asset-session');
      expect(fake.events).not.toContain('script-upload');
      expect(commands.at(-1)).toEqual({
        command: 'fail', failureCode: 'runtime_release_read_release_unavailable', recoveryRequired: false,
      });
    }
  });

  it('limits public historical reads to the pinned channel and exact manifest files without caller-supplied trust', async () => {
    const key = await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']);
    const retained = await signedRelease(TO_RELEASE, key);
    const server = await historicalServer(retained, await signedRelease('gateway-v0.1.36', key));
    for (const [path, method, status] of [
      [server.retainedPath.replace('/canary/', '/stable/'), 'GET', 404],
      [server.retainedPath, 'POST', 405],
      [`${server.retainedPath}?keyId=other&publicKey=${retained.publicKey}`, 'GET', 404],
      [`${server.retainedPath}/files/manifest.json`, 'GET', 404],
      [`${server.retainedPath}/files/payload/worker/missing.js`, 'GET', 404],
      [`${server.retainedPath}/files/payload/%2e%2e/%2e%2e/release-envelope.json`, 'GET', 404],
    ] as const) {
      const response = await server.fetch(new Request(`${CONTROL_PLANE}${path}`, { method }));
      expect(response.status).toBe(status);
      expect(response.headers.get('set-cookie')).toBeNull();
    }
    const file = await server.fetch(new Request(`${CONTROL_PLANE}${server.retainedPath}/files/payload/worker/index.js`));
    expect(file.status).toBe(200);
    expect(await file.text()).toBe(retained.workerSource);
  });

  it('verifies the exact bundle against its own update key, hands over, then replaces itself with inherited secrets', async () => {
    const release = await signedRelease();
    const fake = providerFake(release);
    const commands: CustomerRuntimeControlCommand[] = [];
    const handovers: string[] = [];
    const result = await runCustomerRuntimeUpdate(input(fake, release, commands, handovers));
    expect(result).toEqual({ status: 'uploaded', fromVersionId: OLD_VERSION });
    expect(handovers).toEqual([OLD_VERSION]);
    expect(commands).toEqual([
      { command: 'begin' },
      { command: 'progress', stage: 'current_verified', fromVersionId: OLD_VERSION, toVersionId: null },
      { command: 'progress', stage: 'assets_uploaded', fromVersionId: OLD_VERSION, toVersionId: null },
    ]);
    const files = [...release.files.keys()].map((path) => `file:${path}`);
    expect(fake.events).toEqual([
      'control:begin', 'worker', 'deployments', 'version', 'control:progress:current_verified',
      'descriptor', ...files, 'asset-session', 'asset-bucket', 'control:progress:assets_uploaded',
      'handover', 'script-upload',
    ]);
    // Nothing touches the journal after the handover; the new version finishes it.
    expect(fake.events.indexOf('handover')).toBeLessThan(fake.events.indexOf('script-upload'));

    const upload = fake.requests.find((entry) => entry.method === 'PUT');
    if (upload === undefined || upload.form === null) throw new Error('script upload missing');
    expect(new URL(upload.url).searchParams.get('bindings_inherit')).toBe('strict');
    const metadataFile = upload.form.get('metadata');
    if (!(metadataFile instanceof Blob)) throw new Error('metadata missing');
    const metadata = v.parse(metadataSchema, JSON.parse(await metadataFile.text()));
    expect(metadata.assets.jwt).toBe(COMPLETION_JWT);
    const bindingsByName = new Map(metadata.bindings.map((binding) => [binding.name, binding]));
    expect(bindingsByName.get('ADMIN_STATE')).toEqual({ name: 'ADMIN_STATE', type: 'inherit', version_id: 'latest' });
    expect(bindingsByName.get('ANKKA_GATEWAY_OWNERSHIP_WRAP_KEY')).toEqual({
      name: 'ANKKA_GATEWAY_OWNERSHIP_WRAP_KEY', type: 'inherit', version_id: 'latest',
    });
    expect(bindingsByName.get('ASSETS')).toEqual({ name: 'ASSETS', type: 'assets' });
    expect(bindingsByName.get('ANKKA_GATEWAY_RELEASE')).toEqual({ name: 'ANKKA_GATEWAY_RELEASE', type: 'plain_text', text: TO_RELEASE });
    expect(bindingsByName.get('ANKKA_GATEWAY_RELEASE_SHA256')).toEqual({
      name: 'ANKKA_GATEWAY_RELEASE_SHA256', type: 'plain_text', text: `sha256:${release.bundle.manifest.artifact.treeSha256}`,
    });
    expect(bindingsByName.get('ANKKA_INSTALL_ID')).toEqual({ name: 'ANKKA_INSTALL_ID', type: 'plain_text', text: `acg-${'c'.repeat(24)}` });
    expect(bindingsByName.has('ANKKA_BOOTSTRAP_NONCE')).toBe(false);
    expect(metadata.bindings).toHaveLength(19);
    const module = upload.form.get('index.js');
    if (!(module instanceof Blob)) throw new Error('module missing');
    expect(await module.text()).toBe(release.workerSource);
    expect(JSON.stringify(fake.requests.map((entry) => entry.url))).not.toContain(ACCESS_TOKEN);
  });

  it('refuses a control plane that serves another release or altered bytes, and fails the journal before any upload', async () => {
    for (const [prepare, code, stage, targetRelease] of [
      // A descriptor whose release contradicts its own signed manifest is not a release at all.
      [(fake: ProviderFake) => { fake.tamper.descriptorRelease = 'gateway-v0.1.36'; }, 'release_invalid', 'release_read', TO_RELEASE],
      // The control plane has no exact bundle for the action's approved identity.
      [() => undefined, 'release_unavailable', 'release_read', 'gateway-v0.1.36'],
      [(fake: ProviderFake) => { fake.tamper.file = 'payload/worker/index.js'; }, 'release_invalid', 'release_read'],
      [(fake: ProviderFake) => { fake.tamper.file = 'payload/admin/index.html'; }, 'release_invalid', 'release_read'],
    ] as const) {
      const release = await signedRelease();
      const fake = providerFake(release);
      prepare(fake);
      const commands: CustomerRuntimeControlCommand[] = [];
      const handovers: string[] = [];
      let failure: CustomerRuntimeUpdateError | null = null;
      try {
        const base = input(fake, release, commands, handovers);
        await runCustomerRuntimeUpdate({
          ...base,
          target: { release: targetRelease ?? TO_RELEASE, artifactSha256: base.target.artifactSha256 },
        });
      } catch (error) {
        failure = error instanceof CustomerRuntimeUpdateError ? error : null;
      }
      expect(failure?.code).toBe(code);
      expect(failure?.stage).toBe(stage);
      expect(handovers).toEqual([]);
      expect(fake.events).not.toContain('script-upload');
      expect(fake.events).not.toContain('asset-session');
      expect(commands.at(-1)).toEqual({
        command: 'fail', failureCode: `runtime_${stage}_${code}`, recoveryRequired: false,
      });
    }
  });

  it('reports an unknown upload without failing the journal it already handed over', async () => {
    const release = await signedRelease();
    const fake = providerFake(release);
    fake.tamper.uploadStatus = 500;
    const commands: CustomerRuntimeControlCommand[] = [];
    const handovers: string[] = [];
    await expect(runCustomerRuntimeUpdate(input(fake, release, commands, handovers))).rejects.toMatchObject({
      code: 'provider_rejected', stage: 'script_upload',
    });
    expect(handovers).toEqual([OLD_VERSION]);
    expect(commands.some((command) => command.command === 'fail')).toBe(false);
  });

  it('will not update a Worker whose bindings name another key, channel, or the target release itself', async () => {
    const release = await signedRelease();
    const fake = providerFake(release);
    const commands: CustomerRuntimeControlCommand[] = [];
    const handovers: string[] = [];
    await expect(runCustomerRuntimeUpdate({
      ...input(fake, release, commands, handovers),
      updateKeyId: 'release-other',
    })).rejects.toMatchObject({ code: 'provider_rejected', stage: 'current_read' });
    expect(fake.events).not.toContain('descriptor');
    expect(commands.at(-1)).toEqual({
      command: 'fail', failureCode: 'runtime_current_read_provider_rejected', recoveryRequired: false,
    });
  });
});

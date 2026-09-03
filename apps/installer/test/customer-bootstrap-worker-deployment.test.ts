import { describe, expect, it } from 'vitest';
import * as v from 'valibot';

import { boundaryValueSchema, type BoundaryValue } from '../src/boundary';
import {
  deployCustomerBootstrapWorker,
  type CustomerBootstrapPlainBindings,
  type DeployCustomerBootstrapWorkerInput,
  type VerifiedCustomerBootstrapWorkerRelease,
} from '../src/customer-bootstrap-worker-deployment';
import { CUSTOMER_BOOTSTRAP_PLAIN_BINDINGS } from '../src/customer-bootstrap-worker-readback';

const ACCOUNT_ID = 'a'.repeat(32);
const WORKER_ID = 'b'.repeat(32);
const NAMESPACE_ID = 'c'.repeat(32);
const WORKER_NAME = 'ankka-gateway-shop-acg-1234567890abcdef12345678';
const VERSION_ID = '11111111-1111-4111-8111-111111111111';
const DEPLOYMENT_ID = '22222222-2222-4222-8222-222222222222';
const ACCESS_TOKEN = `token_${'x'.repeat(32)}`;
const BOOTSTRAP_ID = `boot_${'y'.repeat(24)}`;
const BOOTSTRAP_NONCE = 'n'.repeat(43);
const OWNERSHIP_WRAP_KEY = 'w'.repeat(43);
const RELEASE_HASH = 'd'.repeat(64);
const COMPONENT_HASH = 'e'.repeat(64);

function success(result: BoundaryValue, status = 200): Response {
  return Response.json({ success: true, errors: [], messages: [], result }, { status });
}

function absent(): Response {
  return Response.json({ success: false, errors: [{ code: 10090, message: 'not found' }], messages: [], result: null }, { status: 404 });
}

function bytesToBase64(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes));
}

async function sha256(bytes: Uint8Array): Promise<string> {
  const owned = new Uint8Array(bytes.byteLength);
  owned.set(bytes);
  return [...new Uint8Array(await crypto.subtle.digest('SHA-256', owned))]
    .map((byte) => byte.toString(16).padStart(2, '0')).join('');
}

function bindings(): CustomerBootstrapPlainBindings {
  return Object.freeze({
    ANKKA_BOOTSTRAP_CALLBACK: `https://${WORKER_NAME}.tenant.workers.dev/__ankka/install/oauth/callback`,
    ANKKA_BOOTSTRAP_EXPIRES_AT: '1800000060000',
    ANKKA_BOOTSTRAP_ID: BOOTSTRAP_ID,
    ANKKA_BOOTSTRAP_SECRET_SHA256: `sha256:${'f'.repeat(64)}`,
    ANKKA_GATEWAY_RELEASE: 'gateway-v1.0.0',
    ANKKA_GATEWAY_RELEASE_SHA256: `sha256:${RELEASE_HASH}`,
    ANKKA_INSTALL_ID: 'acg-1234567890abcdef12345678',
    ANKKA_INSTALLER_ORIGIN: 'https://deploy.ankka.ai',
    ANKKA_MANAGEMENT_HOSTNAME: 'manage.example.com',
    ANKKA_PLAN_HASH: `sha256:${'2'.repeat(64)}`,
    ANKKA_PLAN_ID: `plan-${'1'.repeat(24)}`,
    ANKKA_UPDATE_CHANNEL: 'stable',
    ANKKA_UPDATE_KEY_ID: 'release-key-v1',
    ANKKA_UPDATE_PUBLIC_KEY: 'p'.repeat(43),
    ANKKA_WORKER_NAME: WORKER_NAME,
    CLOUDFLARE_ACCOUNT_ID: ACCOUNT_ID,
    CLOUDFLARE_CUSTOMER_OAUTH_CLIENT_ID: `client_${'q'.repeat(24)}`,
    CLOUDFLARE_OWNERSHIP_ISSUER_KEY_ID: 'ownership-key-v1',
    CLOUDFLARE_OWNERSHIP_ISSUER_PUBLIC_KEY: 'i'.repeat(43),
  });
}

async function release(): Promise<VerifiedCustomerBootstrapWorkerRelease> {
  const source = new TextEncoder().encode('export class AdminState{};export default{fetch(){return new Response("ok")}};');
  const index = new TextEncoder().encode('<!doctype html><title>Ankka</title>');
  return Object.freeze({
    verification: 'ed25519',
    release: 'gateway-v1.0.0',
    artifactSha256: RELEASE_HASH,
    componentSha256: COMPONENT_HASH,
    worker: Object.freeze({
      mainModule: 'index.js',
      compatibilityDate: '2026-08-08',
      compatibilityFlags: Object.freeze([] as const),
      modules: Object.freeze([Object.freeze({
        name: 'index.js',
        contentType: 'application/javascript+module',
        sha256: await sha256(source),
        bytes: source,
      })]),
      assets: Object.freeze({
        binding: 'ASSETS',
        notFoundHandling: 'single-page-application',
        runWorkerFirst: Object.freeze(['/__ankka/*', '/api/*'] as const),
        files: Object.freeze([Object.freeze({
          path: '/index.html',
          contentType: 'text/html; charset=utf-8',
          sha256: await sha256(index),
          bytes: index,
        })]),
      }),
      durableObject: Object.freeze({
        binding: 'ADMIN_STATE',
        className: 'AdminState',
        storage: 'sqlite',
      }),
    }),
  });
}

interface ProviderOptions {
  readonly initial?: 'absent' | 'foreign-version' | 'foreign-tags';
  readonly uploadThrowsAfterApply?: boolean;
}

const fixtureBindingSchema = v.looseObject({
  name: v.string(),
  type: v.string(),
  text: v.optional(v.string()),
  class_name: v.optional(v.string()),
});
const fixtureMetadataSchema = v.looseObject({
  annotations: v.looseObject({ 'workers/tag': v.string() }),
  assets: v.looseObject({ config: boundaryValueSchema }),
  bindings: v.array(fixtureBindingSchema),
  compatibility_date: v.string(),
  compatibility_flags: v.array(v.string()),
  exports: boundaryValueSchema,
  main_module: v.string(),
});
type FixtureMetadata = v.InferOutput<typeof fixtureMetadataSchema>;

async function providerFixture(options: ProviderOptions = {}) {
  const verifiedRelease = await release();
  let workerExists = options.initial !== 'absent' && options.initial !== undefined;
  let active = options.initial === 'foreign-version';
  let metadata: FixtureMetadata | null = null;
  let sourceBase64 = bytesToBase64(verifiedRelease.worker.modules[0]?.bytes ?? new Uint8Array());
  const writes: string[] = [];
  const requests: string[] = [];

  if (active) {
    const plain = CUSTOMER_BOOTSTRAP_PLAIN_BINDINGS.map((name) => ({
      name, type: 'plain_text', text: bindings()[name],
    }));
    metadata = {
      annotations: { 'workers/tag': 'foreign' },
      assets: { config: { not_found_handling: 'single-page-application', run_worker_first: ['/__ankka/*', '/api/*'] } },
      bindings: [
        { name: 'ADMIN_STATE', type: 'durable_object_namespace', class_name: 'AdminState', namespace_id: NAMESPACE_ID },
        { name: 'ASSETS', type: 'assets' },
        { name: 'ANKKA_BOOTSTRAP_NONCE', type: 'secret_text' },
        { name: 'ANKKA_GATEWAY_OWNERSHIP_WRAP_KEY', type: 'secret_text' },
        ...plain,
      ],
      compatibility_date: '2026-08-08',
      compatibility_flags: [],
      exports: { AdminState: { type: 'durable-object', storage: 'sqlite' } },
      main_module: 'index.js',
    };
  }

  const transport = async (target: RequestInfo | URL, init: RequestInit = {}): Promise<Response> => {
    const request = target instanceof Request ? target : new Request(target, init);
    const url = new URL(request.url);
    requests.push(`${request.method} ${url.pathname}`);
    expect(request.headers.get('authorization')).toBe(`Bearer ${ACCESS_TOKEN}`);

    if (request.method === 'GET' && url.pathname.endsWith(`/workers/workers/${WORKER_NAME}`)) {
      if (!workerExists) return absent();
      const tags = options.initial === 'foreign-tags'
        ? ['ankka-mcp-gateway', 'foreign']
        : ['ankka-mcp-gateway', 'ankka-stage1-bootstrap', `ankka-bootstrap-id:${BOOTSTRAP_ID}`];
      return success({
        id: WORKER_ID,
        name: WORKER_NAME,
        logpush: false,
        observability: { enabled: false },
        subdomain: { enabled: false, previews_enabled: false },
        tags,
        tail_consumers: [],
      });
    }
    if (request.method === 'POST' && url.pathname.endsWith('/workers/workers')) {
      writes.push('worker-create');
      workerExists = true;
      return success({ id: WORKER_ID }, 201);
    }
    if (request.method === 'POST' && url.pathname.endsWith('/assets-upload-session')) {
      writes.push('asset-session');
      return success({ jwt: `asset_${'j'.repeat(32)}`, buckets: [] });
    }
    if (request.method === 'PUT' && url.pathname.endsWith(`/workers/scripts/${WORKER_NAME}`)) {
      writes.push('script-upload');
      const form = await request.formData();
      const metadataPart = v.parse(v.instance(File), form.get('metadata'));
      const sourcePart = v.parse(v.instance(File), form.get('index.js'));
      metadata = v.parse(fixtureMetadataSchema, JSON.parse(await metadataPart.text()));
      const sourceBytes = new Uint8Array(await sourcePart.arrayBuffer());
      sourceBase64 = bytesToBase64(sourceBytes);
      active = true;
      if (options.uploadThrowsAfterApply) throw new Error('connection-lost-after-apply');
      return success({ id: VERSION_ID });
    }
    if (request.method === 'GET' && url.pathname.endsWith(`/workers/scripts/${WORKER_NAME}/deployments`)) {
      return success({ deployments: active ? [{
        id: DEPLOYMENT_ID,
        versions: [{ version_id: VERSION_ID, percentage: 100 }],
      }] : [] });
    }
    if (request.method === 'GET' && url.pathname.endsWith(`/workers/workers/${WORKER_ID}/versions/${VERSION_ID}`)) {
      if (!metadata) return absent();
      const returnedBindings = metadata.bindings.map((binding) => binding.type === 'secret_text'
        ? { name: binding.name, type: 'secret_text' }
        : binding.name === 'ADMIN_STATE'
          ? { ...binding, namespace_id: NAMESPACE_ID }
          : binding);
      return success(v.parse(boundaryValueSchema, {
        ...metadata,
        id: VERSION_ID,
        bindings: returnedBindings,
        modules: [{
          name: 'index.js',
          content_type: 'application/javascript+module',
          content_base64: sourceBase64,
        }],
      }));
    }
    if (request.method === 'GET' && url.pathname.endsWith('/workers/durable_objects/namespaces')) {
      return Response.json({
        success: true,
        errors: [],
        messages: [],
        result: active ? [{
          id: NAMESPACE_ID,
          class: 'AdminState',
          name: `${WORKER_NAME}-AdminState`,
          script: WORKER_NAME,
          use_sqlite: true,
        }] : [],
        result_info: {
          page: 1,
          per_page: 1000,
          count: active ? 1 : 0,
          total_count: active ? 1 : 0,
        },
      });
    }
    throw new Error(`unexpected ${request.method} ${url.pathname}`);
  };

  return { verifiedRelease, transport, writes, requests };
}

async function input(
  fixture: Awaited<ReturnType<typeof providerFixture>>,
): Promise<DeployCustomerBootstrapWorkerInput> {
  return {
    accessToken: ACCESS_TOKEN,
    accountId: ACCOUNT_ID,
    workerName: WORKER_NAME,
    bootstrapId: BOOTSTRAP_ID,
    release: fixture.verifiedRelease,
    plainTextBindings: bindings(),
    bootstrapNonce: BOOTSTRAP_NONCE,
    ownershipWrapKey: OWNERSHIP_WRAP_KEY,
    transport: fixture.transport,
    wait: async () => undefined,
  };
}

describe('restricted customer bootstrap Worker deployment', () => {
  it('creates, uploads, and independently reads back the exact Worker and SQLite namespace', async () => {
    const fixture = await providerFixture({ initial: 'absent' });
    const result = await deployCustomerBootstrapWorker(await input(fixture));
    expect(result).toMatchObject({
      workerId: WORKER_ID,
      namespaceId: NAMESPACE_ID,
      deploymentId: DEPLOYMENT_ID,
      versionId: VERSION_ID,
      recovery: 'created',
    });
    expect(fixture.writes).toEqual(['worker-create', 'asset-session', 'script-upload']);
    expect(JSON.stringify(result)).not.toContain(ACCESS_TOKEN);
    expect(JSON.stringify(result)).not.toContain(BOOTSTRAP_NONCE);
    expect(JSON.stringify(result)).not.toContain(OWNERSHIP_WRAP_KEY);
  });

  it('recovers an upload whose provider response was lost without a duplicate mutation', async () => {
    const fixture = await providerFixture({ initial: 'absent', uploadThrowsAfterApply: true });
    const result = await deployCustomerBootstrapWorker(await input(fixture));
    expect(result.recovery).toBe('created');
    expect(fixture.writes.filter((write) => write === 'script-upload')).toHaveLength(1);
  });

  it('reconciles a repeated callback entirely from exact provider readback', async () => {
    const fixture = await providerFixture({ initial: 'absent' });
    const deployInput = await input(fixture);
    await deployCustomerBootstrapWorker(deployInput);
    fixture.writes.splice(0);
    const recovered = await deployCustomerBootstrapWorker(deployInput);
    expect(recovered.recovery).toBe('recovered');
    expect(fixture.writes).toEqual([]);
  });

  it('rejects an existing Worker with foreign tags before any write', async () => {
    const fixture = await providerFixture({ initial: 'foreign-tags' });
    await expect(deployCustomerBootstrapWorker(await input(fixture))).rejects.toMatchObject({
      code: 'worker_name_collision',
      stage: 'worker_read',
    });
    expect(fixture.writes).toEqual([]);
  });

  it('does not overwrite a tagged Worker serving a different active version', async () => {
    const fixture = await providerFixture({ initial: 'foreign-version' });
    await expect(deployCustomerBootstrapWorker(await input(fixture))).rejects.toMatchObject({
      code: 'worker_name_collision',
      stage: 'version_read',
    });
    expect(fixture.writes).toEqual([]);
  });
});

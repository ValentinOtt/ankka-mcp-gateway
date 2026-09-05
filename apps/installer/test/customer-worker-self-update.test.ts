import * as v from 'valibot';
import { describe, expect, it } from 'vitest';

import { boundaryObjectSchema, type BoundaryObject, type BoundaryValue } from '../src/boundary';
import type { GatewayWorkerPlainTextBindings } from '../src/cloudflare-worker-direct-upload';
import { sha256Hex } from '../src/crypto';
import {
  CustomerWorkerSelfUpdateError,
  inspectCustomerWorkerFinalRuntime,
  publishCustomerWorkerFinalRuntime,
} from '../src/customer-worker-self-update';

const inheritedBindingSchema = v.looseObject({ type: v.literal('inherit') });
const ACCOUNT_ID = 'a'.repeat(32);
const WORKER_ID = 'b'.repeat(32);
const WORKER_NAME = 'ankka-gateway-test';
const OLD_VERSION = '11111111-1111-4111-8111-111111111111';
const FINAL_VERSION = '22222222-2222-4222-8222-222222222222';
const OLD_DEPLOYMENT = '33333333-3333-4333-8333-333333333333';
const FINAL_DEPLOYMENT = '44444444-4444-4444-8444-444444444444';
const ACCESS_TOKEN = `token_${'c'.repeat(32)}`;
const FINAL_SOURCE = 'export class AdminState { fetch() { return new Response("ready"); } }\n';

const BINDINGS: GatewayWorkerPlainTextBindings = Object.freeze({
  ADMIN_EMAILS: 'owner@example.com',
  ANKKA_INSTALL_ID: 'acg-1234567890abcdef12345678',
  ANKKA_GATEWAY_RELEASE: 'gateway-v1.0.0',
  ANKKA_GATEWAY_RELEASE_SHA256: `sha256:${'d'.repeat(64)}`,
  ANKKA_MANAGEMENT_HOSTNAME: 'manage.example.com',
  ANKKA_UPDATE_CHANNEL: 'stable',
  ANKKA_UPDATE_KEY_ID: `ed25519-${'e'.repeat(16)}`,
  ANKKA_UPDATE_PUBLIC_KEY: 'A'.repeat(43),
  ANKKA_WORKERS_SUBDOMAIN: 'tenant',
  ANKKA_WORKER_NAME: WORKER_NAME,
  CF_ACCESS_AUD: 'access-audience-tag',
  CF_ACCESS_ISSUER: 'https://tenant.cloudflareaccess.com',
  CLOUDFLARE_ACCOUNT_ID: ACCOUNT_ID,
  CLOUDFLARE_ZONE_ID: 'f'.repeat(32),
  CLOUDFLARE_ZONE_NAME: 'example.com',
  ZERO_TRUST_READY: 'true',
});

function envelope(result: BoundaryValue, status = 200): Response {
  return new Response(JSON.stringify({
    success: status < 300,
    errors: [],
    messages: [],
    result,
  }), { status, headers: { 'content-type': 'application/json' } });
}

function base64(value: string): string {
  const bytes = new TextEncoder().encode(value);
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function finalBindings(overrides: readonly BoundaryObject[] = []): readonly BoundaryObject[] {
  const values: BoundaryObject[] = [
    { name: 'ADMIN_STATE', type: 'durable_object_namespace', class_name: 'AdminState' },
    { name: 'ASSETS', type: 'assets' },
    { name: 'ANKKA_GATEWAY_OWNERSHIP_WRAP_KEY', type: 'secret_text' },
    ...Object.entries(BINDINGS).map(([name, text]) => ({ name, text, type: 'plain_text' })),
  ];
  for (const override of overrides) {
    const index = values.findIndex((binding) => binding.name === override.name);
    if (index >= 0) values[index] = override;
    else values.push(override);
  }
  return values;
}

function finalVersion(bindings = finalBindings(), source = FINAL_SOURCE): BoundaryObject {
  return {
    id: FINAL_VERSION,
    main_module: 'index.js',
    compatibility_date: '2026-08-08',
    compatibility_flags: [],
    modules: [{
      name: 'index.js',
      content_type: 'application/javascript+module',
      content_base64: base64(source),
    }],
    bindings,
    exports: { AdminState: { type: 'durable-object', storage: 'sqlite' } },
  };
}

interface ProviderFixtureOptions {
  readonly activeFinal?: boolean;
  readonly source?: string;
  readonly workerId?: string;
  readonly finalBindings?: readonly BoundaryObject[];
}

function providerFixture(options: ProviderFixtureOptions = {}) {
  let activeFinal = options.activeFinal ?? false;
  const calls: string[] = [];
  let uploadedMetadata: BoundaryObject | null = null;
  let uploadedSource: string | null = null;
  const transport = async (input: RequestInfo | URL, init: RequestInit = {}): Promise<Response> => {
    const request = input instanceof Request ? input : new Request(input, init);
    const url = new URL(request.url);
    calls.push(`${request.method} ${url.pathname}${url.search}`);
    expect(request.headers.get('authorization')).toBe(`Bearer ${ACCESS_TOKEN}`);
    if (url.pathname.endsWith(`/workers/workers/${WORKER_NAME}`)) {
      return envelope({
        id: options.workerId ?? WORKER_ID,
        name: WORKER_NAME,
        tags: ['ankka-mcp-gateway'],
      });
    }
    if (url.pathname.endsWith(`/workers/scripts/${WORKER_NAME}/deployments`)) {
      return envelope({ deployments: [{
        id: activeFinal ? FINAL_DEPLOYMENT : OLD_DEPLOYMENT,
        versions: [{
          version_id: activeFinal ? FINAL_VERSION : OLD_VERSION,
          percentage: 100,
        }],
      }] });
    }
    if (url.pathname.endsWith(`/workers/workers/${WORKER_ID}/versions/${FINAL_VERSION}`)) {
      expect(url.searchParams.get('include')).toBe('modules');
      return envelope(finalVersion(options.finalBindings ?? finalBindings(), options.source));
    }
    if (url.pathname.endsWith(`/workers/scripts/${WORKER_NAME}/secrets/ANKKA_BOOTSTRAP_NONCE`) &&
        request.method === 'DELETE') {
      // Secrets survive uploads; the nonce must be removed explicitly.
      if (!activeFinal) throw new Error('nonce deleted before the final upload');
      return envelope(null);
    }
    if (url.pathname.endsWith(`/workers/scripts/${WORKER_NAME}`) && request.method === 'PUT') {
      expect(url.searchParams.get('bindings_inherit')).toBe('strict');
      const body = init.body;
      expect(body).toBeInstanceOf(FormData);
      if (!(body instanceof FormData)) throw new TypeError('upload body');
      const metadata = body.get('metadata');
      const source = body.get('index.js');
      if (!(metadata instanceof Blob) || !(source instanceof Blob)) throw new TypeError('upload files');
      const parsedMetadata = v.safeParse(boundaryObjectSchema, JSON.parse(await metadata.text()));
      if (!parsedMetadata.success) throw new TypeError('upload metadata');
      uploadedMetadata = parsedMetadata.output;
      uploadedSource = await source.text();
      activeFinal = true;
      return envelope({ id: FINAL_VERSION });
    }
    throw new Error(`unexpected request ${request.method} ${url}`);
  };
  return {
    calls,
    transport,
    uploadedMetadata: () => uploadedMetadata,
    uploadedSource: () => uploadedSource,
  };
}

async function input(transport: (input: RequestInfo | URL, init?: RequestInit) => Promise<Response>) {
  return {
    accessToken: ACCESS_TOKEN,
    accountId: ACCOUNT_ID,
    workerName: WORKER_NAME,
    expectedWorkerId: WORKER_ID,
    finalRuntimeSource: FINAL_SOURCE,
    finalRuntimeSha256: await sha256Hex(FINAL_SOURCE),
    bindings: BINDINGS,
    transport,
    wait: async () => undefined,
  };
}

describe('customer Worker final self-update', () => {
  it('uploads and verifies a 4 MiB final runtime with inherited state', async () => {
    const source = 'a'.repeat(4 * 1024 * 1024);
    const provider = providerFixture({ source });
    await expect(publishCustomerWorkerFinalRuntime({
      ...await input(provider.transport),
      finalRuntimeSource: source,
      finalRuntimeSha256: await sha256Hex(source),
      previousVersionId: OLD_VERSION,
    })).resolves.toMatchObject({ versionId: FINAL_VERSION });
    expect(provider.uploadedSource() === source).toBe(true);
  });

  it('strictly inherits only customer-owned state and verifies the exact active result', async () => {
    const provider = providerFixture();
    const result = await publishCustomerWorkerFinalRuntime({
      ...await input(provider.transport),
      previousVersionId: OLD_VERSION,
    });

    expect(result).toEqual({
      workerId: WORKER_ID,
      deploymentId: FINAL_DEPLOYMENT,
      versionId: FINAL_VERSION,
      finalRuntimeSha256: await sha256Hex(FINAL_SOURCE),
    });
    expect(provider.uploadedSource()).toBe(FINAL_SOURCE);
    const metadata = provider.uploadedMetadata();
    expect(metadata).not.toBeNull();
    expect(metadata?.keep_assets).toBe(true);
    const bindings = metadata?.bindings;
    expect(Array.isArray(bindings)).toBe(true);
    if (!Array.isArray(bindings)) throw new TypeError('metadata bindings');
    const inherited = bindings.filter((binding) => v.is(inheritedBindingSchema, binding));
    expect(inherited).toEqual([
      // The script upload API only inherits from the latest version; the
      // previous version is proven equal to it right before the upload.
      { name: 'ADMIN_STATE', type: 'inherit', version_id: 'latest' },
      { name: 'ANKKA_GATEWAY_OWNERSHIP_WRAP_KEY', type: 'inherit', version_id: 'latest' },
      { name: 'ASSETS', type: 'inherit', version_id: 'latest' },
    ]);
    expect(JSON.stringify(metadata)).not.toContain('ANKKA_BOOTSTRAP_NONCE');
    expect(JSON.stringify(metadata)).not.toContain('secret_text');
    const upload = provider.calls.indexOf(
      `PUT /client/v4/accounts/${ACCOUNT_ID}/workers/scripts/${WORKER_NAME}?bindings_inherit=strict`,
    );
    const nonceDelete = provider.calls.indexOf(
      `DELETE /client/v4/accounts/${ACCOUNT_ID}/workers/scripts/${WORKER_NAME}/secrets/ANKKA_BOOTSTRAP_NONCE`,
    );
    const finalRead = provider.calls.findIndex((call) => call.includes(`/versions/${FINAL_VERSION}`));
    expect(upload).toBeGreaterThanOrEqual(0);
    expect(nonceDelete).toBeGreaterThan(upload);
    expect(finalRead).toBeGreaterThan(nonceDelete);
  });

  it('recovers by exact readback without publishing again', async () => {
    const provider = providerFixture({ activeFinal: true });
    const result = await inspectCustomerWorkerFinalRuntime(await input(provider.transport));
    expect(result?.versionId).toBe(FINAL_VERSION);
    expect(provider.calls.some((call) => call.startsWith('PUT '))).toBe(false);
  });

  it.each(['declared', 'streamed'] as const)('bounds %s version responses before parsing', async (kind) => {
    const provider = providerFixture({ activeFinal: true });
    const transport = async (target: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
      const url = target instanceof Request ? target.url : target.toString();
      if (url.includes(`/versions/${FINAL_VERSION}`)) {
        const oversized = 16 * 1024 * 1024 + 1;
        return kind === 'declared'
          ? new Response('{}', { headers: { 'content-length': String(oversized) } })
          : new Response('x'.repeat(oversized));
      }
      return provider.transport(target, init);
    };
    await expect(inspectCustomerWorkerFinalRuntime(await input(transport))).rejects.toMatchObject({
      code: 'provider_unknown', stage: 'version_read', outcome: 'unknown',
    });
    expect(provider.calls.every((call) => call.startsWith('GET '))).toBe(true);
  });

  it('rejects a substituted Worker identity before upload', async () => {
    const provider = providerFixture({ workerId: '9'.repeat(32) });
    await expect(publishCustomerWorkerFinalRuntime({
      ...await input(provider.transport),
      previousVersionId: OLD_VERSION,
    })).rejects.toMatchObject({
      name: CustomerWorkerSelfUpdateError.name,
      code: 'provider_mismatch',
      stage: 'worker_read',
    });
    expect(provider.calls.some((call) => call.startsWith('PUT '))).toBe(false);
  });

  it('rejects a final version that retains the bootstrap nonce', async () => {
    const provider = providerFixture({
      activeFinal: true,
      finalBindings: finalBindings([{ name: 'ANKKA_BOOTSTRAP_NONCE', type: 'plain_text', text: 'forbidden' }]),
    });
    expect(await inspectCustomerWorkerFinalRuntime(await input(provider.transport))).toBeNull();
  });
});

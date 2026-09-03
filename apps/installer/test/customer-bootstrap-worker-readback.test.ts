import { describe, expect, it } from 'vitest';

import type { BoundaryValue } from '../src/boundary';

import { issueCloudflareBootstrapOwnershipHandoff } from
  '../src/cloudflare-bootstrap-ownership-handoff';
import {
  CUSTOMER_BOOTSTRAP_PLAIN_BINDINGS,
  readCustomerBootstrapWorkerOwnership,
} from '../src/customer-bootstrap-worker-readback';
import { base64UrlEncode } from '../src/crypto';

const NOW = 1_800_000_000_000;
const ACCOUNT_ID = 'a'.repeat(32);
const WORKER_ID = 'b'.repeat(32);
const NAMESPACE_ID = 'c'.repeat(32);
const WORKER_NAME = 'ankka-gateway-test-acg-1234567890abcdef12345678';
const INSTALL_ID = 'acg-1234567890abcdef12345678';
const VERSION_ID = '11111111-1111-4111-8111-111111111111';
const DEPLOYMENT_ID = '22222222-2222-4222-8222-222222222222';
const SECRET_COMMITMENT = `sha256:${'d'.repeat(64)}`;
const PLAN_ID = `plan-${'e'.repeat(24)}`;
const PLAN_HASH = `sha256:${'f'.repeat(64)}`;
const RELEASE_HASH = '1'.repeat(64);
const ACCESS_TOKEN = `token_${'g'.repeat(32)}`;
const BOOTSTRAP_SOURCE = new TextEncoder().encode('export default { fetch() {} };');

const EXPECTED_BINDINGS = Object.freeze({
  ANKKA_BOOTSTRAP_CALLBACK: `https://${WORKER_NAME}.tenant.workers.dev/__ankka/install/oauth/callback`,
  ANKKA_BOOTSTRAP_EXPIRES_AT: String(NOW + 60_000),
  ANKKA_BOOTSTRAP_ID: `boot_${'h'.repeat(24)}`,
  ANKKA_BOOTSTRAP_SECRET_SHA256: SECRET_COMMITMENT,
  ANKKA_GATEWAY_RELEASE: 'gateway-v1.0.0',
  ANKKA_GATEWAY_RELEASE_SHA256: `sha256:${RELEASE_HASH}`,
  ANKKA_INSTALL_ID: INSTALL_ID,
  ANKKA_INSTALLER_ORIGIN: 'https://deploy.ankka.ai',
  ANKKA_MANAGEMENT_HOSTNAME: 'manage.example.com',
  ANKKA_PLAN_HASH: PLAN_HASH,
  ANKKA_PLAN_ID: PLAN_ID,
  ANKKA_UPDATE_CHANNEL: 'stable',
  ANKKA_UPDATE_KEY_ID: 'release-key-v1',
  ANKKA_UPDATE_PUBLIC_KEY: 'A'.repeat(43),
  ANKKA_WORKER_NAME: WORKER_NAME,
  CLOUDFLARE_ACCOUNT_ID: ACCOUNT_ID,
  CLOUDFLARE_CUSTOMER_OAUTH_CLIENT_ID: `client_${'i'.repeat(24)}`,
  CLOUDFLARE_OWNERSHIP_ISSUER_KEY_ID: 'ownership-key-v1',
  CLOUDFLARE_OWNERSHIP_ISSUER_PUBLIC_KEY: 'B'.repeat(43),
});

function json(result: BoundaryValue): Response {
  return new Response(JSON.stringify({ success: true, errors: [], messages: [], result }), {
    status: 200,
    headers: { 'content-type': 'application/json' },
  });
}

async function sourceSha256(): Promise<string> {
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', BOOTSTRAP_SOURCE));
  return Array.from(digest, (byte) => byte.toString(16).padStart(2, '0')).join('');
}

async function signingFixture() {
  const pair = await crypto.subtle.generateKey('Ed25519', true, ['sign', 'verify']);
  const publicKey = base64UrlEncode(
    new Uint8Array(await crypto.subtle.exportKey('raw', pair.publicKey)),
  );
  const serializedHandoff = await issueCloudflareBootstrapOwnershipHandoff({
    accountId: ACCOUNT_ID,
    adminState: {
      binding: 'ADMIN_STATE',
      className: 'AdminState',
      namespaceId: NAMESPACE_ID,
      storage: 'sqlite',
      workerProviderId: WORKER_ID,
    },
    bootstrapSecret: { commitment: SECRET_COMMITMENT, expiresAt: NOW + 60_000 },
    expiresAt: NOW + 120_000,
    installId: INSTALL_ID,
    issuedAt: NOW,
    plan: { id: PLAN_ID, hash: PLAN_HASH },
    release: { id: 'gateway-v1.0.0', artifactSha256: RELEASE_HASH },
    worker: { name: WORKER_NAME, providerId: WORKER_ID },
  }, pair.privateKey);
  return { publicKey, serializedHandoff };
}

function provider(bindings = [
  { name: 'ADMIN_STATE', type: 'durable_object_namespace', class_name: 'AdminState', namespace_id: NAMESPACE_ID },
  { name: 'ASSETS', type: 'assets' },
  { name: 'ANKKA_BOOTSTRAP_NONCE', type: 'secret_text' },
  { name: 'ANKKA_GATEWAY_OWNERSHIP_WRAP_KEY', type: 'secret_text' },
  ...CUSTOMER_BOOTSTRAP_PLAIN_BINDINGS.map((name) => ({
    name,
    type: 'plain_text',
    text: EXPECTED_BINDINGS[name],
  })),
]) {
  return async (input: RequestInfo | URL, init: RequestInit = {}): Promise<Response> => {
    const request = input instanceof Request ? input : new Request(input, init);
    const url = new URL(request.url);
    expect(request.headers.get('authorization')).toBe(`Bearer ${ACCESS_TOKEN}`);
    if (url.pathname.endsWith(`/workers/workers/${WORKER_NAME}`)) {
      return json({
        id: WORKER_ID,
        name: WORKER_NAME,
        logpush: false,
        observability: { enabled: false },
        subdomain: { enabled: true, previews_enabled: false },
        tags: [
          'ankka-mcp-gateway',
          'ankka-stage1-bootstrap',
          `ankka-bootstrap-id:${EXPECTED_BINDINGS.ANKKA_BOOTSTRAP_ID}`,
        ],
        tail_consumers: [],
      });
    }
    if (url.pathname.endsWith(`/workers/scripts/${WORKER_NAME}/deployments`)) {
      return json({ deployments: [{
        id: DEPLOYMENT_ID,
        versions: [{ version_id: VERSION_ID, percentage: 100 }],
      }] });
    }
    if (url.pathname.endsWith(`/workers/workers/${WORKER_ID}/versions/${VERSION_ID}`)) {
      return json({
        id: VERSION_ID,
        main_module: 'index.js',
        compatibility_date: '2026-08-08',
        compatibility_flags: [],
        bindings,
        assets: {
          config: {
            not_found_handling: 'single-page-application',
            run_worker_first: ['/__ankka/*', '/api/*'],
          },
        },
        exports: { AdminState: { type: 'durable-object', storage: 'sqlite' } },
        modules: [{
          name: 'index.js',
          content_type: 'application/javascript+module',
          content_base64: btoa(String.fromCharCode(...BOOTSTRAP_SOURCE)),
        }],
      });
    }
    if (url.pathname.endsWith('/workers/durable_objects/namespaces')) {
      return new Response(JSON.stringify({
        success: true,
        errors: [],
        messages: [],
        result: [{
          id: NAMESPACE_ID,
          class: 'AdminState',
          name: `${WORKER_NAME}-AdminState`,
          script: WORKER_NAME,
          use_sqlite: true,
        }],
        result_info: { page: 1, per_page: 1000, count: 1, total_count: 1 },
      }), { status: 200, headers: { 'content-type': 'application/json' } });
    }
    throw new Error(`unexpected ${request.method} ${url}`);
  };
}

describe('customer Stage 1 Worker ownership readback', () => {
  it('builds adoption evidence only from the exact active Worker and namespace', async () => {
    const signing = await signingFixture();
    let now = NOW + 1;
    const result = await readCustomerBootstrapWorkerOwnership({
      accessToken: ACCESS_TOKEN,
      accountId: ACCOUNT_ID,
      workerName: WORKER_NAME,
      serializedHandoff: signing.serializedHandoff,
      pinnedIssuerPublicKey: signing.publicKey,
      expectedBootstrapSourceSha256: await sourceSha256(),
      expectedBindings: EXPECTED_BINDINGS,
      transport: provider(),
      now: () => now++,
    });
    expect(result.activeVersionId).toBe(VERSION_ID);
    expect(result.providerReadback).toMatchObject({
      accountId: ACCOUNT_ID,
      installId: INSTALL_ID,
      worker: { name: WORKER_NAME, providerId: WORKER_ID },
      adminState: { namespaceId: NAMESPACE_ID, workerProviderId: WORKER_ID },
      plan: { id: PLAN_ID, hash: PLAN_HASH },
    });
    expect(JSON.stringify(result)).not.toContain(ACCESS_TOKEN);
  });

  it('rejects a substituted namespace or unexpected binding', async () => {
    const signing = await signingFixture();
    const badBindings = [
      { name: 'ADMIN_STATE', type: 'durable_object_namespace', class_name: 'AdminState', namespace_id: '9'.repeat(32) },
      { name: 'ASSETS', type: 'assets' },
      { name: 'ANKKA_BOOTSTRAP_NONCE', type: 'secret_text' },
      { name: 'ANKKA_GATEWAY_OWNERSHIP_WRAP_KEY', type: 'secret_text' },
      ...CUSTOMER_BOOTSTRAP_PLAIN_BINDINGS.map((name) => ({
        name,
        type: 'plain_text',
        text: EXPECTED_BINDINGS[name],
      })),
      { name: 'UNREVIEWED_SECRET', type: 'secret_text' },
    ];
    await expect(readCustomerBootstrapWorkerOwnership({
      accessToken: ACCESS_TOKEN,
      accountId: ACCOUNT_ID,
      workerName: WORKER_NAME,
      serializedHandoff: signing.serializedHandoff,
      pinnedIssuerPublicKey: signing.publicKey,
      expectedBootstrapSourceSha256: await sourceSha256(),
      expectedBindings: EXPECTED_BINDINGS,
      transport: provider(badBindings),
      now: () => NOW + 1,
    })).rejects.toMatchObject({ code: 'identity_mismatch' });
  });
});

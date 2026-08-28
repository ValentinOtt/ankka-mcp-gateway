import { beforeAll, describe, expect, it } from 'vitest';

import { REQUIRED_OAUTH_SCOPES, OAUTH_COOKIE, PUBLIC_ORIGIN } from '../src/constants';
import { base64UrlEncode } from '../src/crypto';
import type { GatewayDeployEnv } from '../src/env';
import { createGatewayDeployWorker } from '../src/index';
import {
  sourceActionRuntimeFixture,
  type SourceActionRuntimeFixture,
} from './source-action-runtime-fixture';

const NOW = Date.UTC(2026, 7, 26, 1, 0, 0);
const ACCOUNT_ID = 'a'.repeat(32);
const ACTION_ID = `action_${'A'.repeat(32)}`;
const ACTION_KEY = 'BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc';
const MANAGEMENT_ORIGIN = 'https://manage.example.com';
const WORKER_ID = 'b'.repeat(32);
const VERSION_ID = '11111111-1111-4111-8111-111111111111';
const DEPLOYMENT_ID = '22222222-2222-4222-8222-222222222222';
let signedRuntime: SourceActionRuntimeFixture;
let activeDeployment: Readonly<Record<string, unknown>>;
let attackerRuntime: SourceActionRuntimeFixture;
let attackerDeployment: Readonly<Record<string, unknown>>;

beforeAll(async () => {
  signedRuntime = await sourceActionRuntimeFixture({
    accountId: ACCOUNT_ID,
    actorEmail: 'admin@example.com',
    managementHostname: 'manage.example.com',
    workerId: WORKER_ID,
    workerName: 'ankka-gateway-example',
    workersSubdomain: 'customer-workers',
  });
  activeDeployment = await signedRuntime.deploymentResult(DEPLOYMENT_ID, VERSION_ID);
  attackerRuntime = await sourceActionRuntimeFixture({
    accountId: ACCOUNT_ID,
    actorEmail: 'admin@example.com',
    managementHostname: 'attacker.example',
    workerId: WORKER_ID,
    workerName: 'ankka-gateway-example',
    workersSubdomain: 'customer-workers',
  });
  attackerDeployment = await attackerRuntime.deploymentResult(DEPLOYMENT_ID, VERSION_ID);
});

function cookiePair(header: string): string {
  return header.split(';', 1)[0] ?? '';
}

function envelope(result: unknown): Response {
  return new Response(JSON.stringify({ success: true, errors: [], messages: [], result }), {
    headers: { 'content-type': 'application/json' },
  });
}

function workerEnv(): GatewayDeployEnv {
  return {
    GATEWAY_DEPLOY_SESSION: {} as DurableObjectNamespace,
    CLOUDFLARE_OAUTH_CLIENT_ID: 'cloudflare-client-id-value',
    CLOUDFLARE_OAUTH_CLIENT_SECRET: 'cloudflare-client-secret-value',
    DEPLOY_SESSION_ENCRYPTION_KEY: base64UrlEncode(new Uint8Array(32).fill(7)),
    BOOTSTRAP_NONCE_DERIVATION_KEY: base64UrlEncode(new Uint8Array(32).fill(8)),
  };
}

function managementClaim(managementOrigin = MANAGEMENT_ORIGIN) {
  return {
    schemaVersion: 1,
    actionId: ACTION_ID,
    actionKey: ACTION_KEY,
    actorEmail: 'admin@example.com',
    accountId: ACCOUNT_ID,
    workerName: 'ankka-gateway-example',
    workersSubdomain: 'customer-workers',
    managementOrigin,
    releaseIdentity: signedRuntime.identity,
    expiresAt: NOW + 10 * 60 * 1000,
  };
}

function runtimePreflightResponse(
  url: URL,
  runtime: SourceActionRuntimeFixture = signedRuntime,
  deployment: Readonly<Record<string, unknown>> = activeDeployment,
): Response | null {
  if (url.pathname.endsWith('/workers/workers/ankka-gateway-example')) {
    return envelope({
      id: WORKER_ID,
      name: 'ankka-gateway-example',
      tags: ['ankka-mcp-gateway'],
    });
  }
  if (url.pathname.endsWith('/workers/scripts/ankka-gateway-example/deployments')) {
    return envelope({ deployments: [deployment] });
  }
  if (url.pathname.endsWith(`/workers/workers/${WORKER_ID}/versions/${VERSION_ID}`)) {
    return envelope(runtime.versionResult(VERSION_ID));
  }
  return null;
}

const exactReleaseProvider = {
  async loadVerifiedReleaseBundleForIdentity() {
    return signedRuntime.bundle;
  },
};

async function requestManagementAuthorization(
  worker: ReturnType<typeof createGatewayDeployWorker>,
  env: GatewayDeployEnv,
  claim: unknown,
): Promise<Response> {
  const handoff = base64UrlEncode(new TextEncoder().encode(JSON.stringify(claim)));
  return worker.fetch(new Request(`${PUBLIC_ORIGIN}/api/management/authorize`, {
    method: 'POST',
    headers: { origin: PUBLIC_ORIGIN, 'content-type': 'application/json' },
    body: JSON.stringify({ handoff }),
  }), env);
}

async function authorizeManagement(
  worker: ReturnType<typeof createGatewayDeployWorker>,
  env: GatewayDeployEnv,
  managementOrigin = MANAGEMENT_ORIGIN,
  claim: unknown = managementClaim(managementOrigin),
): Promise<{ readonly oauth: string; readonly state: string }> {
  const authorize = await requestManagementAuthorization(worker, env, claim);
  expect(authorize.status).toBe(200);
  const payload = await authorize.json() as { authorizationUrl: string };
  const state = new URL(payload.authorizationUrl).searchParams.get('state');
  expect(state).toMatch(/^[A-Za-z0-9_-]{43}$/u);
  const oauth = cookiePair(authorize.headers.get('set-cookie') ?? '');
  expect(oauth.startsWith(`${OAUTH_COOKIE}=`)).toBe(true);
  return { oauth, state: state as string };
}

describe('management source OAuth', () => {
  it('authorizes without a hosted session and relays one memory-only grant to the customer Worker', async () => {
    let enabled = false;
    let customerPosts = 0;
    let revoked = 0;
    const transport = async (input: RequestInfo | URL, init: RequestInit = {}) => {
      const request = new Request(input, init);
      const url = new URL(request.url);
      if (url.href === 'https://dash.cloudflare.com/oauth2/token') {
        return new Response(JSON.stringify({
          access_token: 'ephemeral-management-source-token',
          token_type: 'Bearer',
          scope: REQUIRED_OAUTH_SCOPES.join(' '),
        }), { headers: { 'content-type': 'application/json' } });
      }
      if (url.href === 'https://dash.cloudflare.com/oauth2/revoke') {
        revoked += 1;
        return new Response('{}', { headers: { 'content-type': 'application/json' } });
      }
      if (url.pathname === '/client/v4/user') {
        return envelope({ id: 'user-identifier', email: 'admin@example.com' });
      }
      if (url.pathname === '/client/v4/accounts') {
        return envelope([{ id: ACCOUNT_ID, name: 'Example account' }]);
      }
      if (url.pathname.endsWith('/workers/subdomain')) return envelope({ subdomain: 'customer-workers' });
      if (url.pathname.endsWith('/workers/domains')) return envelope([{
        hostname: 'manage.example.com', service: 'ankka-gateway-example', environment: 'production',
      }]);
      const runtime = runtimePreflightResponse(url);
      if (runtime) return runtime;
      if (url.origin === 'https://api.cloudflare.com' && url.pathname.endsWith('/subdomain')) {
        if (request.method === 'GET') return envelope({ enabled, previews_enabled: false });
        const body = await request.json() as { enabled: boolean };
        enabled = body.enabled;
        return envelope({ enabled, previews_enabled: false });
      }
      if (url.hostname.endsWith('.workers.dev') && request.method === 'HEAD') {
        return new Response(null, { status: 204, headers: { 'x-ankka-source-action': 'ready' } });
      }
      if (url.hostname.endsWith('.workers.dev') && request.method === 'POST') {
        customerPosts += 1;
        const body = await request.json() as Record<string, unknown>;
        expect(body.cloudflareAccessToken).toBe('ephemeral-management-source-token');
        return new Response(JSON.stringify({
          schemaVersion: 1,
          actionId: ACTION_ID,
          sourceId: 'source-0123456789abcdef',
          status: 'succeeded',
          expiresAt: new Date(NOW + 10 * 60 * 1000).toISOString(),
          failureCode: null,
        }), { headers: { 'content-type': 'application/json' } });
      }
      throw new Error(`unexpected request ${request.method} ${url.href}`);
    };
    const env = workerEnv();
    let callbackExecuted = false;
    const worker = createGatewayDeployWorker({
      now: () => NOW,
      transport,
      exactReleaseProvider,
      managementCallbackResponse: async ({ execute }) => {
        await execute();
        callbackExecuted = true;
        return new Response('<!doctype html><title>Applying</title>', {
          headers: { 'content-type': 'text/html; charset=utf-8' },
        });
      },
    });
    const { oauth, state } = await authorizeManagement(worker, env);

    const unverifiedContext = await worker.fetch(new Request(`${PUBLIC_ORIGIN}/api/management/context`, {
      headers: { cookie: oauth },
    }), env);
    expect(unverifiedContext.status).toBe(404);
    expect(JSON.stringify(await unverifiedContext.json())).not.toContain(MANAGEMENT_ORIGIN);

    const callback = await worker.fetch(new Request(
      `${PUBLIC_ORIGIN}/oauth/callback?code=authorization-code-value&state=${state}`,
      { headers: { cookie: oauth } },
    ), env, { waitUntil() {} } as unknown as ExecutionContext);
    expect(callback.status).toBe(200);
    expect(callbackExecuted).toBe(true);
    expect(customerPosts).toBe(1);
    expect(enabled).toBe(false);
    expect(revoked).toBe(1);

    const verifiedOauth = cookiePair(callback.headers.get('set-cookie') ?? '');
    expect(verifiedOauth.startsWith(`${OAUTH_COOKIE}=`)).toBe(true);
    expect(verifiedOauth).not.toBe(oauth);
    const context = await worker.fetch(new Request(`${PUBLIC_ORIGIN}/api/management/context`, {
      headers: { cookie: verifiedOauth },
    }), env);
    expect(context.status).toBe(200);
    expect(await context.json()).toMatchObject({
      actionId: ACTION_ID,
      managementUrl: `${MANAGEMENT_ORIGIN}/?sourceAction=${ACTION_ID}`,
    });
    expect(context.headers.get('set-cookie')).toContain(`${OAUTH_COOKIE}=;`);
  });

  it('keeps a denied unsigned management handoff on the fixed installer origin', async () => {
    const env = workerEnv();
    const worker = createGatewayDeployWorker({ now: () => NOW });
    const attackerOrigin = 'https://attacker.example';
    const { oauth, state } = await authorizeManagement(worker, env, attackerOrigin);

    const denied = await worker.fetch(new Request(
      `${PUBLIC_ORIGIN}/oauth/callback?error=access_denied&state=${state}`,
      { headers: { cookie: oauth } },
    ), env);

    expect(denied.status).toBe(303);
    expect(denied.headers.get('location')).toBe(`${PUBLIC_ORIGIN}/`);
    expect(denied.headers.get('set-cookie')).toContain(`${OAUTH_COOKIE}=;`);
    expect(JSON.stringify([...denied.headers])).not.toContain(attackerOrigin);
    const context = await worker.fetch(new Request(`${PUBLIC_ORIGIN}/api/management/context`, {
      headers: { cookie: oauth },
    }), env);
    expect(context.status).toBe(404);
    expect(JSON.stringify(await context.json())).not.toContain(attackerOrigin);
  });

  it('rejects legacy, missing, or structurally tampered release identity before sealing OAuth state', async () => {
    let providerCalls = 0;
    const env = workerEnv();
    const worker = createGatewayDeployWorker({
      now: () => NOW,
      transport: async () => {
        providerCalls += 1;
        throw new Error('provider access must not be reached');
      },
    });
    const current = managementClaim();
    const { releaseIdentity: _releaseIdentity, ...legacyClaim } = current;
    const invalidClaims = [
      legacyClaim,
      { ...current, releaseIdentity: null },
      { ...current, releaseIdentity: { ...current.releaseIdentity, copiedAuthority: true } },
    ];

    for (const claim of invalidClaims) {
      const response = await requestManagementAuthorization(worker, env, claim);
      expect(response.status).toBe(400);
      expect(response.headers.get('set-cookie')).toBeNull();
    }
    expect(providerCalls).toBe(0);
  });

  it('does not exchange a provider grant for a valid-shaped but mismatched release identity', async () => {
    let providerCalls = 0;
    let bundleLoads = 0;
    const env = workerEnv();
    const tamperedIdentity = Object.freeze({
      ...signedRuntime.identity,
      artifactSha256: 'f'.repeat(64),
    });
    const worker = createGatewayDeployWorker({
      now: () => NOW,
      transport: async () => {
        providerCalls += 1;
        throw new Error('provider access must not be reached');
      },
      exactReleaseProvider: {
        async loadVerifiedReleaseBundleForIdentity(_env, identity) {
          bundleLoads += 1;
          expect(identity).toEqual(tamperedIdentity);
          return signedRuntime.bundle;
        },
      },
    });
    const { oauth, state } = await authorizeManagement(
      worker,
      env,
      MANAGEMENT_ORIGIN,
      { ...managementClaim(), releaseIdentity: tamperedIdentity },
    );

    const callback = await worker.fetch(new Request(
      `${PUBLIC_ORIGIN}/oauth/callback?code=authorization-code-value&state=${state}`,
      { headers: { cookie: oauth } },
    ), env);

    expect(callback.status).toBe(303);
    expect(callback.headers.get('location')).toBe(`${PUBLIC_ORIGIN}/`);
    expect(callback.headers.get('set-cookie')).toContain(`${OAUTH_COOKIE}=;`);
    expect(bundleLoads).toBe(1);
    expect(providerCalls).toBe(0);
  });

  it('does not release an arbitrary management origin when provider-domain verification fails', async () => {
    let revoked = 0;
    const attackerOrigin = 'https://attacker.example';
    const transport = async (input: RequestInfo | URL, init: RequestInit = {}) => {
      const request = new Request(input, init);
      const url = new URL(request.url);
      if (url.href === 'https://dash.cloudflare.com/oauth2/token') {
        return new Response(JSON.stringify({
          access_token: 'ephemeral-management-source-token',
          token_type: 'Bearer',
          scope: REQUIRED_OAUTH_SCOPES.join(' '),
        }), { headers: { 'content-type': 'application/json' } });
      }
      if (url.href === 'https://dash.cloudflare.com/oauth2/revoke') {
        revoked += 1;
        return new Response('{}', { headers: { 'content-type': 'application/json' } });
      }
      if (url.pathname === '/client/v4/user') {
        return envelope({ id: 'user-identifier', email: 'admin@example.com' });
      }
      if (url.pathname === '/client/v4/accounts') {
        return envelope([{ id: ACCOUNT_ID, name: 'Example account' }]);
      }
      if (url.pathname.endsWith('/workers/subdomain')) return envelope({ subdomain: 'customer-workers' });
      if (url.pathname.endsWith('/workers/domains')) return envelope([]);
      throw new Error(`unexpected request ${request.method} ${url.href}`);
    };
    const env = workerEnv();
    const worker = createGatewayDeployWorker({ now: () => NOW, transport, exactReleaseProvider });
    const { oauth, state } = await authorizeManagement(worker, env, attackerOrigin);

    const callback = await worker.fetch(new Request(
      `${PUBLIC_ORIGIN}/oauth/callback?code=authorization-code-value&state=${state}`,
      { headers: { cookie: oauth } },
    ), env);

    expect(callback.status).toBe(303);
    expect(callback.headers.get('location')).toBe(`${PUBLIC_ORIGIN}/`);
    expect(callback.headers.get('set-cookie')).toContain(`${OAUTH_COOKIE}=;`);
    expect(JSON.stringify([...callback.headers])).not.toContain(attackerOrigin);
    expect(revoked).toBe(1);
    const context = await worker.fetch(new Request(`${PUBLIC_ORIGIN}/api/management/context`, {
      headers: { cookie: oauth },
    }), env);
    expect(context.status).toBe(404);
    expect(JSON.stringify(await context.json())).not.toContain(attackerOrigin);
  });

  it('does not release an arbitrary management origin when the verified customer relay fails', async () => {
    let enabled = false;
    let customerPosts = 0;
    let revoked = 0;
    const attackerOrigin = 'https://attacker.example';
    const transport = async (input: RequestInfo | URL, init: RequestInit = {}) => {
      const request = new Request(input, init);
      const url = new URL(request.url);
      if (url.href === 'https://dash.cloudflare.com/oauth2/token') {
        return new Response(JSON.stringify({
          access_token: 'ephemeral-management-source-token',
          token_type: 'Bearer',
          scope: REQUIRED_OAUTH_SCOPES.join(' '),
        }), { headers: { 'content-type': 'application/json' } });
      }
      if (url.href === 'https://dash.cloudflare.com/oauth2/revoke') {
        revoked += 1;
        return new Response('{}', { headers: { 'content-type': 'application/json' } });
      }
      if (url.pathname === '/client/v4/user') {
        return envelope({ id: 'user-identifier', email: 'admin@example.com' });
      }
      if (url.pathname === '/client/v4/accounts') {
        return envelope([{ id: ACCOUNT_ID, name: 'Example account' }]);
      }
      if (url.pathname.endsWith('/workers/subdomain')) return envelope({ subdomain: 'customer-workers' });
      if (url.pathname.endsWith('/workers/domains')) return envelope([{
        hostname: 'attacker.example', service: 'ankka-gateway-example', environment: 'production',
      }]);
      const runtime = runtimePreflightResponse(url, attackerRuntime, attackerDeployment);
      if (runtime) return runtime;
      if (url.origin === 'https://api.cloudflare.com' && url.pathname.endsWith('/subdomain')) {
        if (request.method === 'GET') return envelope({ enabled, previews_enabled: false });
        const body = await request.json() as { enabled: boolean };
        enabled = body.enabled;
        return envelope({ enabled, previews_enabled: false });
      }
      if (url.hostname.endsWith('.workers.dev') && request.method === 'HEAD') {
        return new Response(null, { status: 204, headers: { 'x-ankka-source-action': 'ready' } });
      }
      if (url.hostname.endsWith('.workers.dev') && request.method === 'POST') {
        customerPosts += 1;
        return new Response(JSON.stringify({
          schemaVersion: 1,
          actionId: ACTION_ID,
          sourceId: null,
          status: 'failed',
          expiresAt: new Date(NOW + 10 * 60 * 1000).toISOString(),
          failureCode: 'source_action_failed',
        }), { status: 409, headers: { 'content-type': 'application/json' } });
      }
      throw new Error(`unexpected request ${request.method} ${url.href}`);
    };
    const env = workerEnv();
    const worker = createGatewayDeployWorker({ now: () => NOW, transport, exactReleaseProvider });
    const { oauth, state } = await authorizeManagement(worker, env, attackerOrigin);

    const callback = await worker.fetch(new Request(
      `${PUBLIC_ORIGIN}/oauth/callback?code=authorization-code-value&state=${state}`,
      { headers: { cookie: oauth } },
    ), env);

    expect(callback.status).toBe(303);
    expect(callback.headers.get('location')).toBe(`${PUBLIC_ORIGIN}/`);
    expect(callback.headers.get('set-cookie')).toContain(`${OAUTH_COOKIE}=;`);
    expect(JSON.stringify([...callback.headers])).not.toContain(attackerOrigin);
    expect(customerPosts).toBe(1);
    expect(enabled).toBe(false);
    expect(revoked).toBe(1);
    const context = await worker.fetch(new Request(`${PUBLIC_ORIGIN}/api/management/context`, {
      headers: { cookie: oauth },
    }), env);
    expect(context.status).toBe(404);
    expect(JSON.stringify(await context.json())).not.toContain(attackerOrigin);
  });
});

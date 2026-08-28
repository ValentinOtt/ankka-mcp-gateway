import { beforeAll, describe, expect, it } from 'vitest';
import * as v from 'valibot';

import type { JsonObject, JsonValue } from '../src/boundary';
import { relaySourceAction } from '../src/source-action-relay';
import {
  sourceActionRuntimeFixture,
  type SourceActionRuntimeFixture,
} from './source-action-runtime-fixture';

const ACCOUNT_ID = 'a'.repeat(32);
const ACTION_ID = `action_${'A'.repeat(32)}`;
const ACTION_KEY = 'BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc';
const ACCESS_TOKEN = 'source-action-access-token-value';
const NOW = Date.UTC(2026, 7, 26, 0, 0, 0);
const WORKER_ID = 'b'.repeat(32);
const VERSION_ID = '11111111-1111-4111-8111-111111111111';
const DEPLOYMENT_ID = '22222222-2222-4222-8222-222222222222';
const DRIFT_DEPLOYMENT_ID = '33333333-3333-4333-8333-333333333333';
let signedRuntime: SourceActionRuntimeFixture;
let activeDeployment: JsonObject;
let driftDeployment: JsonObject;

const workersDevRequestSchema = v.strictObject({
  enabled: v.boolean(),
  previews_enabled: v.optional(v.boolean()),
});
const sourceActionRequestSchema = v.strictObject({
  schemaVersion: v.literal(1),
  actionId: v.string(),
  actionKey: v.string(),
  actorEmail: v.string(),
  accountId: v.string(),
  issuedAt: v.number(),
  expiresAt: v.number(),
  cloudflareAccessToken: v.string(),
});

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
  driftDeployment = await signedRuntime.deploymentResult(DRIFT_DEPLOYMENT_ID, VERSION_ID);
});

function envelope(result: JsonValue, status = 200): Response {
  return new Response(JSON.stringify({
    success: status >= 200 && status < 300,
    errors: [],
    messages: [],
    result,
  }), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}

function runtimeBindings(overrides: Readonly<Record<string, string>> = {}): readonly JsonValue[] {
  const values = { ...signedRuntime.bindings, ...overrides };
  return [
    { name: 'ADMIN_STATE', type: 'durable_object_namespace', class_name: 'AdminState' },
    { name: 'ASSETS', type: 'assets' },
    ...Object.entries(values).map(([name, text]) => ({ name, text, type: 'plain_text' })),
  ];
}

function runtimePreflightResponse(
  url: URL,
  options: Readonly<{
    bindingOverrides?: Readonly<Record<string, string>>;
    moduleBytes?: Uint8Array;
    managementService?: string;
    workerTags?: readonly string[];
    deployment?: JsonObject;
  }> = {},
): Response | null {
  if (url.pathname.endsWith('/workers/subdomain')) return envelope({ subdomain: 'customer-workers' });
  if (url.pathname.endsWith('/workers/domains')) return envelope([{
    hostname: 'manage.example.com',
    service: options.managementService ?? 'ankka-gateway-example',
    environment: 'production',
  }]);
  if (url.pathname.endsWith('/workers/workers/ankka-gateway-example')) {
    return envelope({
      id: WORKER_ID,
      name: 'ankka-gateway-example',
      tags: options.workerTags ?? ['ankka-mcp-gateway'],
    });
  }
  if (url.pathname.endsWith('/workers/scripts/ankka-gateway-example/deployments')) {
    return envelope({ deployments: [options.deployment ?? activeDeployment] });
  }
  if (url.pathname.endsWith(`/workers/workers/${WORKER_ID}/versions/${VERSION_ID}`)) {
    return envelope({
      ...signedRuntime.versionResult(VERSION_ID, options.moduleBytes),
      bindings: runtimeBindings(options.bindingOverrides),
    });
  }
  return null;
}

function input(transport: (input: RequestInfo | URL, init?: RequestInit) => Promise<Response>) {
  return {
    accessToken: ACCESS_TOKEN,
    accountId: ACCOUNT_ID,
    workerName: 'ankka-gateway-example',
    workersSubdomain: 'customer-workers',
    managementOrigin: 'https://manage.example.com',
    actionId: ACTION_ID,
    actionKey: ACTION_KEY,
    actorEmail: 'admin@example.com',
    expiresAt: NOW + 10 * 60 * 1000,
    releaseIdentity: signedRuntime.identity,
    releaseBundle: signedRuntime.bundle,
    transport,
    now: () => NOW,
  } as const;
}

describe('source action relay', () => {
  it('opens only the exact Worker route, submits one HMAC action, and closes the route', async () => {
    let enabled = false;
    let customerPosts = 0;
    const providerWrites: boolean[] = [];
    const transport = async (requestInput: RequestInfo | URL, init: RequestInit = {}) => {
      const request = new Request(requestInput, init);
      const url = new URL(request.url);
      if (url.origin === 'https://api.cloudflare.com') {
        expect(request.headers.get('authorization')).toBe(`Bearer ${ACCESS_TOKEN}`);
        expect(request.redirect).toBe('manual');
        const preflight = runtimePreflightResponse(url);
        if (preflight) return preflight;
        if (request.method === 'GET') return envelope({ enabled, previews_enabled: false });
        const body = v.parse(workersDevRequestSchema, await request.json());
        expect(body.previews_enabled).toBe(false);
        enabled = body.enabled;
        providerWrites.push(enabled);
        return envelope({ enabled, previews_enabled: false });
      }
      expect(url.href).toBe(
        'https://ankka-gateway-example.customer-workers.workers.dev/__ankka/source-action',
      );
      if (request.method === 'HEAD') {
        expect(enabled).toBe(true);
        return new Response(null, { status: 204, headers: { 'x-ankka-source-action': 'ready' } });
      }
      customerPosts += 1;
      expect(enabled).toBe(true);
      expect(request.headers.get('authorization')).toBeNull();
      expect(request.headers.get('cookie')).toBeNull();
      expect(request.headers.get('x-ankka-source-action-signature')).toMatch(/^sha256=[a-f0-9]{64}$/u);
      const body = v.parse(sourceActionRequestSchema, await request.json());
      expect(body).toMatchObject({
        schemaVersion: 1,
        actionId: ACTION_ID,
        actionKey: ACTION_KEY,
        actorEmail: 'admin@example.com',
        accountId: ACCOUNT_ID,
        cloudflareAccessToken: ACCESS_TOKEN,
      });
      return new Response(JSON.stringify({
        schemaVersion: 1,
        actionId: ACTION_ID,
        sourceId: 'source-0123456789abcdef',
        status: 'succeeded',
        expiresAt: new Date(NOW + 10 * 60 * 1000).toISOString(),
        failureCode: null,
      }), { headers: { 'content-type': 'application/json' } });
    };

    const result = await relaySourceAction(input(transport));
    expect(result).toEqual({
      schemaVersion: 1,
      actionId: ACTION_ID,
      status: 'succeeded',
      managementUrl: `https://manage.example.com/?sourceAction=${ACTION_ID}`,
    });
    expect(customerPosts).toBe(1);
    expect(providerWrites).toEqual([true, false]);
    expect(enabled).toBe(false);
  });

  it('still disables the exact route when the customer action response is rejected', async () => {
    let enabled = false;
    const providerWrites: boolean[] = [];
    const transport = async (requestInput: RequestInfo | URL, init: RequestInit = {}) => {
      const request = new Request(requestInput, init);
      const url = new URL(request.url);
      if (url.origin === 'https://api.cloudflare.com') {
        const preflight = runtimePreflightResponse(url);
        if (preflight) return preflight;
        if (request.method === 'GET') return envelope({ enabled, previews_enabled: false });
        const body = v.parse(workersDevRequestSchema, await request.json());
        enabled = body.enabled;
        providerWrites.push(enabled);
        return envelope({ enabled, previews_enabled: false });
      }
      if (request.method === 'HEAD') {
        return new Response(null, { status: 204, headers: { 'x-ankka-source-action': 'ready' } });
      }
      return new Response(JSON.stringify({ schemaVersion: 1, error: 'source_action_rejected' }), {
        status: 409,
        headers: { 'content-type': 'application/json' },
      });
    };

    await expect(relaySourceAction(input(transport))).rejects.toMatchObject({ code: 'session_conflict' });
    expect(providerWrites).toEqual([true, false]);
    expect(enabled).toBe(false);
  });

  it('rejects a management domain that is not attached to the claimed Worker before route mutation', async () => {
    let providerWrites = 0;
    const transport = async (requestInput: RequestInfo | URL, init: RequestInit = {}) => {
      const request = new Request(requestInput, init);
      const url = new URL(request.url);
      const preflight = runtimePreflightResponse(url, { managementService: 'different-worker' });
      if (preflight) return preflight;
      if (request.method === 'POST') providerWrites += 1;
      throw new Error(`unexpected request ${request.method} ${url.href}`);
    };

    await expect(relaySourceAction(input(transport))).rejects.toMatchObject({ code: 'session_conflict' });
    expect(providerWrites).toBe(0);
  });

  it('attempts and verifies the compensating disable after an ambiguous enable response', async () => {
    let enabled = false;
    const providerWrites: boolean[] = [];
    let enableResponseLost = false;
    const transport = async (requestInput: RequestInfo | URL, init: RequestInit = {}) => {
      const request = new Request(requestInput, init);
      const url = new URL(request.url);
      const preflight = runtimePreflightResponse(url);
      if (preflight) return preflight;
      if (url.origin === 'https://api.cloudflare.com' && request.method === 'GET') {
        return envelope({ enabled, previews_enabled: false });
      }
      if (url.origin === 'https://api.cloudflare.com') {
        const body = v.parse(workersDevRequestSchema, await request.json());
        enabled = body.enabled;
        providerWrites.push(enabled);
        if (enabled && !enableResponseLost) {
          enableResponseLost = true;
          throw new Error('response lost after apply');
        }
        return envelope({ enabled, previews_enabled: false });
      }
      throw new Error('customer route must not be reached');
    };

    await expect(relaySourceAction(input(transport))).rejects.toMatchObject({ code: 'oauth_grant_invalid' });
    expect(providerWrites).toEqual([true, false]);
    expect(enabled).toBe(false);
  });

  it('rejects an unrelated Worker before any route or customer-control write', async () => {
    let providerWrites = 0;
    let customerCalls = 0;
    const transport = async (requestInput: RequestInfo | URL, init: RequestInit = {}) => {
      const request = new Request(requestInput, init);
      const url = new URL(request.url);
      if (url.origin !== 'https://api.cloudflare.com') {
        customerCalls += 1;
        throw new Error('customer route must not be reached');
      }
      const preflight = runtimePreflightResponse(url, { workerTags: ['customer-worker'] });
      if (preflight) return preflight;
      if (request.method === 'GET') return envelope({ enabled: false, previews_enabled: false });
      providerWrites += 1;
      throw new Error('provider write must not be reached');
    };

    await expect(relaySourceAction(input(transport))).rejects.toMatchObject({ code: 'session_conflict' });
    expect(providerWrites).toBe(0);
    expect(customerCalls).toBe(0);
  });

  it('rejects an emulated Worker with binding drift before relaying the grant', async () => {
    let providerWrites = 0;
    let customerCalls = 0;
    const transport = async (requestInput: RequestInfo | URL, init: RequestInit = {}) => {
      const request = new Request(requestInput, init);
      const url = new URL(request.url);
      if (url.origin !== 'https://api.cloudflare.com') {
        customerCalls += 1;
        throw new Error('customer route must not be reached');
      }
      const preflight = runtimePreflightResponse(url, {
        bindingOverrides: { CLOUDFLARE_ACCOUNT_ID: 'd'.repeat(32) },
      });
      if (preflight) return preflight;
      if (request.method === 'GET') return envelope({ enabled: false, previews_enabled: false });
      providerWrites += 1;
      throw new Error('provider write must not be reached');
    };

    await expect(relaySourceAction(input(transport))).rejects.toMatchObject({ code: 'session_conflict' });
    expect(providerWrites).toBe(0);
    expect(customerCalls).toBe(0);
  });

  it('rejects identity-mismatched release authority before provider access', async () => {
    let providerCalls = 0;
    const transport = async () => {
      providerCalls += 1;
      throw new Error('provider access must not be reached');
    };
    const base = input(transport);
    await expect(relaySourceAction({
      ...base,
      releaseIdentity: Object.freeze({ ...signedRuntime.identity, publicKey: 'B'.repeat(43) }),
    })).rejects.toMatchObject({ code: 'session_conflict' });
    expect(providerCalls).toBe(0);
  });

  it('rejects copied tags and bindings when the active module bytes are not the signed release', async () => {
    let providerWrites = 0;
    let tokenBearingPosts = 0;
    const transport = async (requestInput: RequestInfo | URL, init: RequestInit = {}) => {
      const request = new Request(requestInput, init);
      const url = new URL(request.url);
      if (url.hostname.endsWith('.workers.dev')) {
        if (request.method === 'POST') tokenBearingPosts += 1;
        throw new Error('customer route must not be reached');
      }
      const preflight = runtimePreflightResponse(url, {
        moduleBytes: new TextEncoder().encode('lookalike module'),
      });
      if (preflight) return preflight;
      if (request.method === 'GET') return envelope({ enabled: false, previews_enabled: false });
      providerWrites += 1;
      throw new Error('provider mutation must not be reached');
    };

    await expect(relaySourceAction(input(transport))).rejects.toMatchObject({ code: 'session_conflict' });
    expect(providerWrites).toBe(0);
    expect(tokenBearingPosts).toBe(0);
  });

  it('detects active-deployment drift in the closing read before route mutation', async () => {
    let deploymentReads = 0;
    let providerWrites = 0;
    let tokenBearingPosts = 0;
    const transport = async (requestInput: RequestInfo | URL, init: RequestInit = {}) => {
      const request = new Request(requestInput, init);
      const url = new URL(request.url);
      if (url.hostname.endsWith('.workers.dev')) {
        if (request.method === 'POST') tokenBearingPosts += 1;
        throw new Error('customer route must not be reached');
      }
      if (url.pathname.endsWith('/workers/scripts/ankka-gateway-example/deployments')) {
        deploymentReads += 1;
        return envelope({ deployments: [deploymentReads === 3 ? driftDeployment : activeDeployment] });
      }
      const preflight = runtimePreflightResponse(url);
      if (preflight) return preflight;
      if (request.method === 'GET') return envelope({ enabled: false, previews_enabled: false });
      providerWrites += 1;
      throw new Error('provider mutation must not be reached');
    };

    await expect(relaySourceAction(input(transport))).rejects.toMatchObject({ code: 'session_conflict' });
    expect(deploymentReads).toBe(3);
    expect(providerWrites).toBe(0);
    expect(tokenBearingPosts).toBe(0);
  });

  it('re-proves the same runtime after route readiness and closes without forwarding on drift', async () => {
    let deploymentReads = 0;
    let enabled = false;
    const providerWrites: boolean[] = [];
    let tokenBearingPosts = 0;
    const transport = async (requestInput: RequestInfo | URL, init: RequestInit = {}) => {
      const request = new Request(requestInput, init);
      const url = new URL(request.url);
      if (url.hostname.endsWith('.workers.dev')) {
        if (request.method === 'HEAD') {
          return new Response(null, { status: 204, headers: { 'x-ankka-source-action': 'ready' } });
        }
        tokenBearingPosts += 1;
        throw new Error('credential-bearing action must not be reached');
      }
      if (url.pathname.endsWith('/workers/scripts/ankka-gateway-example/deployments')) {
        deploymentReads += 1;
        return envelope({ deployments: [deploymentReads >= 4 ? driftDeployment : activeDeployment] });
      }
      const preflight = runtimePreflightResponse(url);
      if (preflight) return preflight;
      if (request.method === 'GET') return envelope({ enabled, previews_enabled: false });
      const body = v.parse(workersDevRequestSchema, await request.json());
      enabled = body.enabled;
      providerWrites.push(enabled);
      return envelope({ enabled, previews_enabled: false });
    };

    await expect(relaySourceAction(input(transport))).rejects.toMatchObject({ code: 'session_conflict' });
    expect(providerWrites).toEqual([true, false]);
    expect(enabled).toBe(false);
    expect(tokenBearingPosts).toBe(0);
  });

  it('rejects a provider redirect without following it or exposing the route', async () => {
    let calls = 0;
    const transport = async (requestInput: RequestInfo | URL, init: RequestInit = {}) => {
      calls += 1;
      const request = new Request(requestInput, init);
      expect(request.redirect).toBe('manual');
      return new Response(null, {
        status: 307,
        headers: { location: 'https://example.invalid/credential-target' },
      });
    };

    await expect(relaySourceAction(input(transport))).rejects.toMatchObject({ code: 'oauth_grant_invalid' });
    expect(calls).toBe(1);
  });
});

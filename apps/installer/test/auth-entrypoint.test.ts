import { describe, expect, it } from 'vitest';

import {
  createCloudflareAuthWorker,
  type CloudflareAuthDurableObjectNamespace,
  type CloudflareAuthEnv,
} from '../src/auth-entrypoint';
import { randomBase64Url } from '../src/crypto';

const AUTH_ORIGIN = 'https://auth.ankka.ai';

function environment(
  fetcher: (request: Request) => Promise<Response> = async () => new Response(null, { status: 204 }),
): CloudflareAuthEnv & { readonly requestedNames: string[]; readonly forwarded: string[] } {
  const requestedNames: string[] = [];
  const forwarded: string[] = [];
  const namespace: CloudflareAuthDurableObjectNamespace = {
    idFromName(name) {
      requestedNames.push(name);
      const id: DurableObjectId = Object.create(null);
      Object.defineProperties(id, {
        toString: { value: () => name },
        equals: { value: (other: DurableObjectId) => other.toString() === name },
        name: { value: name },
      });
      return id;
    },
    get() {
      return {
        async fetch(request) {
          forwarded.push(request.url);
          return fetcher(request);
        },
      };
    },
  };
  return {
    CLOUDFLARE_CUSTOMER_OAUTH_CLIENT_ID: 'customer_oauth_client_1234567890',
    CLOUDFLARE_RELAY_STATE_KEY: randomBase64Url(32),
    CLOUDFLARE_RELAY_TICKET_KEY: randomBase64Url(32),
    CLOUDFLARE_OWNERSHIP_ISSUER_PUBLIC_KEY: randomBase64Url(32),
    CLOUDFLARE_OWNERSHIP_ISSUER_KEY_ID: 'ownership-v1',
    GATEWAY_OWNERSHIP_CHALLENGE: namespace,
    requestedNames,
    forwarded,
  };
}

describe('auth.ankka.ai production entrypoint', () => {
  it('advertises a code-only relay with no token-exchange capability', async () => {
    const response = await createCloudflareAuthWorker().fetch(
      new Request(`${AUTH_ORIGIN}/health`),
      environment(),
    );
    expect(response.status).toBe(200);
    await expect(response.json()).resolves.toEqual({
      schemaVersion: 1,
      ok: true,
      role: 'cloudflare-code-relay',
      tokenExchange: false,
    });
    expect(response.headers.get('cache-control')).toBe('no-store');
    expect(response.headers.get('referrer-policy')).toBe('no-referrer');
    expect(response.headers.get('access-control-allow-origin')).toBeNull();
  });

  it('routes install recovery and later fixed operations to operation shards', async () => {
    const env = environment(async () => Response.json({ ok: true }));
    const install = await createCloudflareAuthWorker().fetch(new Request(
      `${AUTH_ORIGIN}/oauth/relay-ticket/challenge/install`,
      { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{}' },
    ), env);
    expect(install.status).toBe(200);
    const response = await createCloudflareAuthWorker().fetch(new Request(
      `${AUTH_ORIGIN}/oauth/relay-ticket/challenge/source-update`,
      { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{}' },
    ), env);
    expect(response.status).toBe(200);
    expect(env.requestedNames).toEqual(['v1:install', 'v1:source-update']);
    expect(env.forwarded).toHaveLength(2);

    const removedInitialRoute = await createCloudflareAuthWorker().fetch(new Request(
      `${AUTH_ORIGIN}/oauth/relay-ticket/initial`,
      { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{}' },
    ), env);
    expect(removedInitialRoute.status).toBe(404);
    expect(env.requestedNames).toEqual(['v1:install', 'v1:source-update']);
  });

  it('fails closed for the wrong origin or incomplete configuration', async () => {
    const env = environment();
    const wrongOrigin = await createCloudflareAuthWorker().fetch(
      new Request('https://deploy.ankka.ai/health'),
      env,
    );
    expect(wrongOrigin.status).toBe(503);

    const invalid = await createCloudflareAuthWorker().fetch(
      new Request(`${AUTH_ORIGIN}/health`),
      { ...env, CLOUDFLARE_RELAY_TICKET_KEY: '' },
    );
    expect(invalid.status).toBe(503);
    await expect(invalid.json()).resolves.toEqual({
      schemaVersion: 1,
      error: 'relay_unavailable',
    });
  });
});

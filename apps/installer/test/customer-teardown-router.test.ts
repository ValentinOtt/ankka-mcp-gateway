import * as v from 'valibot';
import { describe, expect, it } from 'vitest';
import { canonicalJson } from '../src/canonical-json';
import { CLOUDFLARE_CODE_RELAY_CALLBACK } from '../src/cloudflare-code-relay';
import { exactOperationScopes } from '../src/cloudflare-operation-authority';
import { base64UrlDecode, base64UrlEncode, openCustomerTeardownCookie } from '../src/crypto';
import { operationSignature } from '../src/customer-operation-secrets';
import { parseCustomerTeardownAttempt, type CustomerTeardownAttempt, type CustomerTeardownAttemptPort } from '../src/customer-teardown-attempt';
import { createCustomerTeardownRouter, CUSTOMER_TEARDOWN_PATH, CUSTOMER_TEARDOWN_START_PATH, type CustomerTeardownDependencies } from '../src/customer-teardown-router';
import { boundaryObjectSchema } from '../src/boundary';

const NOW = 1_800_000_000_000, ORIGIN = 'https://manage.example.com', HOSTED = 'https://deploy.example.com';
const KEY = base64UrlEncode(new Uint8Array(32).fill(5));
const ACCESS_TOKEN = `synthetic_${'t'.repeat(32)}`;
const KINDS = ['access_application', 'access_policy', 'dns_record', 'mcp_portal', 'mcp_server'] as const;
const SCOPES = exactOperationScopes('uninstall', KINDS).join(' ');
const config = { accountId: 'a'.repeat(32), installId: `acg-${'b'.repeat(24)}`, publicClientId: 'c'.repeat(32),
  managementOrigin: ORIGIN, controlPlaneOrigin: HOSTED, workerName: 'ankka-gateway', workersSubdomain: 'customer', encryptionKey: KEY };
const claim = { schemaVersion: 3, actionType: 'gateway_teardown', actionId: `action_${'d'.repeat(32)}`, actionKey: KEY,
  actorEmail: 'admin@example.com', accountId: config.accountId, installationId: config.installId,
  controlPlaneOrigin: HOSTED, managementOrigin: ORIGIN, workerName: config.workerName, workersSubdomain: config.workersSubdomain,
  gatewayName: 'Example gateway', portalHostname: 'mcp.example.com', expiresAt: NOW + 600_000 };
const completion = { schemaVersion: 1, actionId: claim.actionId, installationId: config.installId, status: 'gateway_removed',
  removedResourceCount: 7, readyReceiptChecksum: `sha256:${'e'.repeat(64)}`, dependencyResourcesHash: `sha256:${'f'.repeat(64)}` };
type Options = { scope?: string; accountRefused?: boolean; refresh?: boolean; revokeFails?: boolean; applyFails?: boolean; wrongCompletion?: boolean; relayFails?: boolean };
function fixture(options: Options = {}) {
  let at = NOW, stored: CustomerTeardownAttempt | null = null, state = '', cookie = '', signatures = 0;
  const events: string[] = [], durableWrites: string[] = [], revoked: string[] = [], warnings: boolean[] = [];
  const port: CustomerTeardownAttemptPort = {
    read: async () => stored,
    compareAndSet: async (revision, value) => {
      if ((stored?.revision ?? null) !== revision) return false;
      stored = parseCustomerTeardownAttempt(value); durableWrites.push(canonicalJson(stored)); return true;
    },
  };
  const dependencies: CustomerTeardownDependencies = {
    attempts: port, now: () => at, assertOperational: async () => undefined,
    issueRelayTicket: async (kinds) => { expect(kinds).toEqual(KINDS); return { relayTicket: `${'r'.repeat(64)}.${'s'.repeat(43)}`, expiresAt: at + 120_000 }; },
    transport: async (target, init) => {
      const url = String(target);
      if (url.endsWith('/oauth/start/uninstall')) {
        if (options.relayFails) return Response.json({}, { status: 503 });
        const input = v.parse(v.strictObject({ relayTicket: v.string(), gatewayState: v.string(), pkceChallenge: v.string(), gatewayCallback: v.string() }), JSON.parse(String(init?.body)));
        state = input.gatewayState;
        const authorization = new URL('https://dash.cloudflare.com/oauth2/auth');
        authorization.search = new URLSearchParams({ response_type: 'code', client_id: config.publicClientId,
          redirect_uri: CLOUDFLARE_CODE_RELAY_CALLBACK, scope: SCOPES, state: `${'q'.repeat(64)}.${'s'.repeat(43)}`,
          code_challenge: input.pkceChallenge, code_challenge_method: 'S256' }).toString();
        return Response.json({ schemaVersion: 1, authorizationUrl: authorization.href });
      }
      if (url.endsWith('/oauth2/token')) {
        expect(stored?.phase).toBe('exchanging'); events.push('exchange');
        const result = { access_token: ACCESS_TOKEN, token_type: 'bearer', scope: options.scope ?? SCOPES };
        return Response.json(options.refresh ? { ...result, refresh_token: 'synthetic_refresh_token_never_persist' } : result);
      }
      if (url.endsWith('/oauth2/revoke')) {
        events.push('revoke'); revoked.push(new URLSearchParams(String(init?.body)).get('token') ?? '');
        return Response.json({}, { status: options.revokeFails ? 503 : 200 });
      }
      expect(url).toBe(`https://api.cloudflare.com/client/v4/accounts/${config.accountId}/access/ai-controls/mcp/portals`);
      events.push('probe'); return Response.json({ success: !options.accountRefused, result: [] }, { status: options.accountRefused ? 403 : 200 });
    },
    command: async (kind, body, signature) => {
      expect(signature).toBe(await operationSignature(KEY, body));
      const input = v.parse(boundaryObjectSchema, JSON.parse(body));
      expect(input.actionId).toBe(claim.actionId); expect(input.installationId).toBe(config.installId); events.push(kind);
      if (kind === 'prove') return Response.json({ schemaVersion: 1, actionId: claim.actionId, status: 'authorized', receiptResourceKinds: KINDS, authority: {} });
      if (kind === 'settle') return Response.json({});
      expect(input.cloudflareAccessToken).toBe(ACCESS_TOKEN); expect(stored?.phase).toBe('exchanging');
      if (options.applyFails) return Response.json({}, { status: 409 });
      return Response.json(options.wrongCompletion ? { ...completion, installationId: `acg-${'0'.repeat(24)}` } : completion);
    },
    signHandoff: async (result, prior) => {
      expect(result).toEqual(completion); expect(events.at(-2)).toBe('revoke'); expect(events.at(-1)).toBe('settle');
      signatures++; warnings.push(prior); events.push('sign'); return 'synthetic_signed_handoff';
    },
  };
  const router = createCustomerTeardownRouter(config, dependencies);
  async function start(changes: Partial<typeof claim> = {}, origin = ORIGIN) {
    const handoff = base64UrlEncode(new TextEncoder().encode(canonicalJson({ ...claim, expiresAt: at + 600_000, ...changes })));
    const response = await router.fetch(new Request(`${ORIGIN}${CUSTOMER_TEARDOWN_START_PATH}`, { method: 'POST',
      headers: { origin, 'content-type': 'application/json' }, body: JSON.stringify({ schemaVersion: 1, handoff }) }));
    cookie = response.headers.get('set-cookie')?.split(';')[0] ?? ''; return response;
  }
  const callbackRequest = () => new Request(`${ORIGIN}/__ankka/install/oauth/callback?code=synthetic_authorization_code&state=${state}`, { headers: { cookie } });
  return { router, start, callbackRequest, events, durableWrites, warnings, revoked,
    callback: () => router.fetch(callbackRequest()), current: () => stored, cookie: () => cookie,
    signatures: () => signatures, later: () => { at += 600_001; }, options };
}

describe('gateway-local teardown authorization', () => {
  it('reviews without provider work, then proves, removes, revokes, and signs in order', async () => {
    const f = fixture(); const page = await f.router.fetch(new Request(`${ORIGIN}${CUSTOMER_TEARDOWN_PATH}`));
    expect(await page.text()).toContain('Two temporary Cloudflare approvals'); expect(f.events).toEqual([]);
    expect((await f.start()).status).toBe(200); const response = await f.callback(); expect(response.status).toBe(303);
    const location = new URL(response.headers.get('location') ?? ''); expect(location.origin + location.pathname).toBe(`${HOSTED}/teardown`);
    expect(new TextDecoder().decode(base64UrlDecode(location.hash.slice(1)))).toBe('synthetic_signed_handoff');
    expect(f.events).toEqual(['prove', 'exchange', 'probe', 'apply', 'revoke', 'settle', 'sign']);
    expect(f.current()?.phase).toBe('settled'); expect(f.revoked).toEqual([ACCESS_TOKEN]);
    const sealed = f.cookie().slice(f.cookie().indexOf('=') + 1), secret = await openCustomerTeardownCookie(KEY, sealed, NOW);
    for (const write of f.durableWrites) {
      expect(write).not.toContain(KEY); expect(write).not.toContain(secret.verifier); expect(write).not.toContain(ACCESS_TOKEN);
    }
    expect(sealed).not.toContain(secret.verifier); expect(sealed).not.toContain(KEY);
  });
  it('atomically spends a callback before a simultaneous replay can exchange', async () => {
    const f = fixture(); await f.start(); const request = f.callbackRequest();
    const responses = await Promise.all([f.router.fetch(new Request(request.url, { headers: request.headers })), f.router.fetch(new Request(request.url, { headers: request.headers }))]);
    expect(responses.map((r) => r.status).sort()).toEqual([303, 409]);
    expect(f.events.filter((e) => e === 'exchange')).toHaveLength(1); expect(f.signatures()).toBe(1);
    expect((await f.callback()).status).toBe(400);
  });
  for (const options of [{ scope: `${SCOPES} workers-scripts.write` }, { accountRefused: true }, { refresh: true }]) {
    it(`rejects an unusable grant before deletion: ${JSON.stringify(options)}`, async () => {
      const f = fixture(options); await f.start(); const response = await f.callback();
      expect(response.headers.get('location')).toContain('result=recovery_required');
      expect(f.events).not.toContain('apply'); expect(f.signatures()).toBe(0); expect(f.revoked).toContain(ACCESS_TOKEN);
      if (options.refresh) expect(f.revoked).toContain('synthetic_refresh_token_never_persist');
    });
  }
  for (const options of [{ applyFails: true }, { wrongCompletion: true }, { revokeFails: true }]) {
    it(`cannot sign incomplete or unrevoked removal: ${JSON.stringify(options)}`, async () => {
      const priorWarning = options.revokeFails === true;
      const f = fixture(options); await f.start(); await f.callback();
      expect(f.signatures()).toBe(0); expect(f.current()?.phase).toBe('settled');
      expect(f.current()?.priorGrantRevocationUnconfirmed).toBe(options.revokeFails === true);
      f.options.applyFails = false; f.options.wrongCompletion = false; f.options.revokeFails = false;
      expect((await f.start()).status).toBe(200); await f.callback(); expect(f.signatures()).toBe(1); expect(f.warnings).toEqual([priorWarning]);
    });
  }
  it('rejects changed authority and cross-origin starts; denied and expired callbacks cannot exchange', async () => {
    const f = fixture(); expect((await f.start({}, 'https://foreign.example')).status).toBe(403);
    expect((await f.start({ installationId: `acg-${'0'.repeat(24)}` })).status).toBe(400); expect(f.events).toEqual([]);
    await f.start(); const request = f.callbackRequest(), url = new URL(request.url); url.searchParams.delete('code'); url.searchParams.set('error', 'authorization_rejected');
    expect((await f.router.fetch(new Request(url, { headers: request.headers }))).status).toBe(303);
    expect(f.events).not.toContain('exchange'); expect(f.current()?.phase).toBe('settled');
    await f.start(); f.later(); expect((await f.callback()).status).toBe(409); expect(f.events).not.toContain('exchange');
  });
  it('settles a refused relay so a fresh consent can start immediately', async () => {
    const f = fixture({ relayFails: true }); expect((await f.start()).status).toBe(503);
    expect(f.current()?.phase).toBe('settled'); f.options.relayFails = false; expect((await f.start()).status).toBe(200);
  });
});

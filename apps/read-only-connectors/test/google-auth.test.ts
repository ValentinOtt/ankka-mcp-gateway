import { exportPKCS8, generateKeyPair, jwtVerify } from 'jose';
import { afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import {
  createGoogleAuthorization, GOOGLE_AUTH_LIMITS, GOOGLE_PROVIDER_SCOPES,
  GOOGLE_TOKEN_ENDPOINT, GoogleAuthorizationError,
} from '../src/google-auth';
import type { ConnectorJson } from '../src/request';

let publicKey: CryptoKey;
let privateKeyPem: string;
beforeAll(async () => {
  // Ephemeral synthetic key material is generated in memory and never written.
  const pair = await generateKeyPair('RS256', { extractable: true });
  publicKey = pair.publicKey;
  privateKeyPem = await exportPKCS8(pair.privateKey);
});
afterEach(() => { vi.useRealTimers(); vi.restoreAllMocks(); });
function secret(overrides: Record<string, ConnectorJson> = {}): string {
  return JSON.stringify({
    type: 'service_account', project_id: 'synthetic-project', private_key_id: 'a'.repeat(40),
    private_key: privateKeyPem, client_email: 'synthetic-reader@synthetic-project.iam.gserviceaccount.com',
    token_uri: GOOGLE_TOKEN_ENDPOINT, ...overrides,
  });
}
function tokenResponse(overrides: Record<string, ConnectorJson> = {}): Response {
  return Response.json({ access_token: 'synthetic-access-token', token_type: 'Bearer', expires_in: 3_600, ...overrides });
}
function createAuthorization() { return createGoogleAuthorization(secret(), 'search-console'); }

describe('deployment-owned fixed-scope Google service-account authorization', () => {
  it.each([
    { provider: 'search-console', scope: 'https://www.googleapis.com/auth/webmasters.readonly' },
    { provider: 'google-analytics', scope: 'https://www.googleapis.com/auth/analytics.readonly' },
    { provider: 'bigquery', scope: 'https://www.googleapis.com/auth/bigquery' },
  ] as const)('signs only the fixed $provider scope and posts once to the fixed token endpoint', async ({ provider, scope }) => {
    const outbound = vi.fn<typeof globalThis.fetch>(async () => tokenResponse({ scope }));
    const authorize = createGoogleAuthorization(secret(), provider);
    expect(outbound).not.toHaveBeenCalled();
    expect(await authorize(outbound)).toEqual({ Authorization: 'Bearer synthetic-access-token' });
    expect(outbound).toHaveBeenCalledOnce();
    const [url, init] = outbound.mock.calls[0] ?? [];
    expect(url).toBe(GOOGLE_TOKEN_ENDPOINT);
    expect(init?.method).toBe('POST');
    expect(init?.redirect).toBe('manual');
    expect([...new Headers(init?.headers).entries()]).toEqual([
      ['accept', 'application/json'], ['content-type', 'application/x-www-form-urlencoded'],
    ]);
    const form = new URLSearchParams(String(init?.body));
    expect([...form.keys()]).toEqual(['grant_type', 'assertion']);
    expect(form.get('grant_type')).toBe('urn:ietf:params:oauth:grant-type:jwt-bearer');
    const jwt = await jwtVerify(form.get('assertion') ?? '', publicKey, { algorithms: ['RS256'], audience: GOOGLE_TOKEN_ENDPOINT });
    expect(jwt.protectedHeader).toEqual({ alg: 'RS256', typ: 'JWT', kid: 'a'.repeat(40) });
    expect(jwt.payload.iss).toBe('synthetic-reader@synthetic-project.iam.gserviceaccount.com');
    expect(GOOGLE_PROVIDER_SCOPES[provider]).toBe(scope);
    expect(jwt.payload.scope).toBe(scope);
    expect(Object.keys(jwt.payload).sort()).toEqual(['aud', 'exp', 'iat', 'iss', 'scope']);
    expect((jwt.payload.exp ?? 0) - (jwt.payload.iat ?? 0)).toBe(GOOGLE_AUTH_LIMITS.assertionSeconds);
    expect(String(init?.body)).not.toContain(privateKeyPem);
  });

  it.each([
    'https://www.googleapis.com/auth/cloud-platform',
    'https://www.googleapis.com/auth/cloud-platform.read-only',
    'https://www.googleapis.com/auth/cloud-platform.read-only https://www.googleapis.com/auth/bigquery',
  ])('rejects an unexpected BigQuery token scope %s', async (scope) => {
    const outbound = vi.fn<typeof globalThis.fetch>(async () => tokenResponse({ scope }));
    await expect(createGoogleAuthorization(secret(), 'bigquery')(outbound))
      .rejects.toEqual(new GoogleAuthorizationError('GOOGLE_AUTH_FAILED'));
    expect(outbound).toHaveBeenCalledOnce();
  });

  it('keeps each issued token request-local with no cache', async () => {
    const outbound = vi.fn<typeof globalThis.fetch>()
      .mockResolvedValueOnce(tokenResponse({ access_token: 'synthetic-first-token' }))
      .mockResolvedValueOnce(tokenResponse({ access_token: 'synthetic-second-token' }));
    const authorize = createAuthorization();
    expect(await authorize(outbound)).toEqual({ Authorization: 'Bearer synthetic-first-token' });
    expect(await authorize(outbound)).toEqual({ Authorization: 'Bearer synthetic-second-token' });
    expect(outbound).toHaveBeenCalledTimes(2);
  });

  it.each([
    { type: 'authorized_user' }, { type: 'external_account' },
    { token_uri: 'https://evil.example.com/token' }, { token_uri: 'http://oauth2.googleapis.com/token' },
    { token_uri: 'https://oauth2.googleapis.com/token?scope=write' },
    { auth_uri: 'https://evil.example.com/auth' }, { universe_domain: 'evil.example.com' },
    { subject: 'synthetic-user@example.com' }, { scope: 'https://www.googleapis.com/auth/webmasters' },
    { refresh_token: 'synthetic-refresh-token' }, { client_email: 'someone@example.com' },
    { client_email: 'synthetic-reader@other-project.iam.gserviceaccount.com' },
    { client_x509_cert_url: 'https://evil.example.com/certs' }, { private_key_id: 'not-a-key-id' },
    { private_key: 'x'.repeat(GOOGLE_AUTH_LIMITS.secretBytes) },
  ])('rejects unsupported or routing/delegation-confused configuration %j', (overrides) => {
    expect(() => createGoogleAuthorization(secret(overrides), 'search-console'))
      .toThrow(new GoogleAuthorizationError('GOOGLE_AUTH_CONFIGURATION_INVALID'));
  });

  it('rejects an invalid signing key before fetching without exposing it', async () => {
    const outbound = vi.fn<typeof globalThis.fetch>();
    const authorize = createGoogleAuthorization(secret({ private_key: 'sentinel-invalid-private-key' }), 'search-console');
    await expect(authorize(outbound)).rejects.toEqual(new GoogleAuthorizationError('GOOGLE_AUTH_FAILED'));
    expect(outbound).not.toHaveBeenCalled();
  });

  it.each([301, 302, 303, 307, 308])('rejects token redirect status %s without forwarding the signed assertion or making a second fetch', async (status) => {
    const redirectTarget = 'https://evil.example.com/token';
    const outbound = vi.fn<typeof globalThis.fetch>(async () => Response.redirect(redirectTarget, status));
    await expect(createAuthorization()(outbound)).rejects.toEqual(new GoogleAuthorizationError('GOOGLE_AUTH_FAILED'));
    expect(outbound).toHaveBeenCalledOnce();
    const [url, init] = outbound.mock.calls[0] ?? [];
    expect(url).toBe(GOOGLE_TOKEN_ENDPOINT);
    expect(init?.method).toBe('POST');
    expect(init?.redirect).toBe('manual');
    expect(new URLSearchParams(String(init?.body)).has('assertion')).toBe(true);
    expect(outbound.mock.calls.some(([destination]) => String(destination) === redirectTarget)).toBe(false);
  });

  it('does not accept already-followed, changed, broad, or invalid token responses', async () => {
    const wrongUrl = tokenResponse();
    Object.defineProperty(wrongUrl, 'url', { value: 'https://evil.example.com/token' });
    const redirected = tokenResponse();
    Object.defineProperty(redirected, 'redirected', { value: true });
    const responses = [
      redirected, wrongUrl,
      new Response('sentinel-server-secret', { status: 500 }),
      new Response('sentinel-server-secret', { headers: { 'Content-Type': 'text/plain' } }),
      new Response('not-json', { headers: { 'Content-Type': 'application/json' } }),
      tokenResponse({ token_type: 'Basic' }), tokenResponse({ expires_in: 3_601 }), tokenResponse({ expires_in: 0 }),
      tokenResponse({ scope: 'https://www.googleapis.com/auth/webmasters' }),
      tokenResponse({ access_token: 'sentinel\r\nInjected: header' }), tokenResponse({ access_token: 'short' }),
      tokenResponse({ access_token: 'x'.repeat(4_097) }),
      new Response('{}', { headers: { 'Content-Type': 'application/json', 'Content-Length': String(GOOGLE_AUTH_LIMITS.responseBytes + 1) } }),
      new Response(new Uint8Array([0xc3, 0x28]), { headers: { 'Content-Type': 'application/json' } }),
    ];
    for (const response of responses) {
      const outbound = vi.fn<typeof globalThis.fetch>(async () => response);
      await expect(createAuthorization()(outbound)).rejects.toEqual(new GoogleAuthorizationError('GOOGLE_AUTH_FAILED'));
      expect(outbound).toHaveBeenCalledOnce();
    }
  });

  it('bounds actual response bytes and chunks even with a lying or absent length', async () => {
    const responses = [
      new Response('x'.repeat(GOOGLE_AUTH_LIMITS.responseBytes + 1), { headers: { 'Content-Type': 'application/json', 'Content-Length': '1' } }),
      new Response(new ReadableStream<Uint8Array>({ start(controller) {
        for (let index = 0; index <= GOOGLE_AUTH_LIMITS.responseChunks; index += 1) controller.enqueue(new Uint8Array());
        controller.close();
      } }), { headers: { 'Content-Type': 'application/json' } }),
    ];
    for (const response of responses) {
      await expect(createAuthorization()(vi.fn(async () => response)))
        .rejects.toEqual(new GoogleAuthorizationError('GOOGLE_AUTH_FAILED'));
    }
  });

  it('bounds a stalled fetch and a stalled body including nonsettling cancellation', async () => {
    vi.useFakeTimers();
    for (const stallsAt of ['fetch', 'body']) {
      const cancel = vi.fn(() => new Promise<void>(() => {}));
      const outbound = vi.fn<typeof globalThis.fetch>(() => stallsAt === 'fetch'
        ? new Promise<Response>(() => {})
        : Promise.resolve(new Response(new ReadableStream<Uint8Array>({ cancel }), { headers: { 'Content-Type': 'application/json' } })));
      const result = createAuthorization()(outbound).catch((error: GoogleAuthorizationError) => error);
      await vi.waitFor(() => expect(outbound).toHaveBeenCalledOnce());
      await vi.advanceTimersByTimeAsync(GOOGLE_AUTH_LIMITS.milliseconds);
      expect(await result).toEqual(new GoogleAuthorizationError('GOOGLE_AUTH_FAILED'));
      expect(outbound.mock.calls[0]?.[1]?.signal?.aborted).toBe(true);
      if (stallsAt === 'body') expect(cancel).toHaveBeenCalled();
    }
  });

  it('never returns raw failures, causes, credentials, or logs', async () => {
    const log = vi.spyOn(console, 'log');
    const errorLog = vi.spyOn(console, 'error');
    const outbound = vi.fn<typeof globalThis.fetch>(async () => { throw new Error('sentinel-auth-fetch-secret'); });
    const error = await createAuthorization()(outbound).catch((caught: GoogleAuthorizationError) => caught);
    expect(error).toEqual(new GoogleAuthorizationError('GOOGLE_AUTH_FAILED'));
    expect(error).not.toHaveProperty('cause');
    expect(JSON.stringify(error)).not.toContain('sentinel');
    expect(log).not.toHaveBeenCalled();
    expect(errorLog).not.toHaveBeenCalled();
  });
});

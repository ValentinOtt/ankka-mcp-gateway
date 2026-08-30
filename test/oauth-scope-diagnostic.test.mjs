import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import worker, {
  DIAGNOSTIC_CLIENT_ID,
  MAX_REGISTRATION_BYTES,
  OAUTH_SCOPE_FIXTURE_ID,
  handleOAuthScopeDiagnosticRequest,
} from '../fixtures/oauth-scope-diagnostic/worker.mjs';

const ORIGIN = 'https://oauth-diagnostic.invalid';
const CALLBACK = 'https://client.invalid/oauth/callback';

function request(path, init) {
  return new Request(`${ORIGIN}${path}`, init);
}

function authorize(scope, overrides = {}) {
  const params = new URLSearchParams({
    client_id: DIAGNOSTIC_CLIENT_ID,
    response_type: 'code',
    redirect_uri: CALLBACK,
    code_challenge: 'a'.repeat(43),
    code_challenge_method: 'S256',
    state: 'synthetic-diagnostic-state',
    ...overrides,
  });
  if (scope !== undefined) params.set('scope', scope);
  return request(`/authorize?${params}`);
}

function register(body = { redirect_uris: [CALLBACK] }, headers = {}) {
  return registerText(JSON.stringify(body), headers);
}

function registerText(body, headers = {}) {
  return request('/register', {
    method: 'POST',
    headers: { 'content-type': 'application/json', ...headers },
    body,
  });
}

async function expectFixedError(input, status = 400, error = 'invalid_request') {
  const response = await worker.fetch(input);
  assert.equal(response.status, status);
  assert.deepEqual(await response.json(), { error });
  assert.equal(response.headers.has('location'), false);
  assert.equal(response.headers.has('set-cookie'), false);
}

test('OAuth diagnostic identifies itself without claiming authorization', async () => {
  assert.equal(worker.fetch, handleOAuthScopeDiagnosticRequest);
  const response = await worker.fetch(request('/health'));
  assert.deepEqual(await response.json(), {
    status: 'ok', fixture: OAUTH_SCOPE_FIXTURE_ID, authorizationIssued: false,
  });
});

test('MCP always challenges without consuming bodies or accepting credentials', async () => {
  for (const method of ['GET', 'POST']) {
    const init = {
      method,
      headers: { authorization: 'Bearer synthetic-credential-not-authority', cookie: 'synthetic=unused' },
    };
    if (method === 'POST') init.body = 'not JSON and never parsed';
    const input = request('/mcp', init);
    const response = await worker.fetch(input);
    assert.equal(response.status, 401);
    assert.equal(input.bodyUsed, false);
    assert.equal(response.headers.get('www-authenticate'),
      `Bearer resource_metadata="${ORIGIN}/.well-known/oauth-protected-resource/mcp", scope="ankka:read"`);
    assert.deepEqual(await response.json(), { error: 'authorization_required' });
  }
});

test('metadata has exact same-origin endpoints and a read-only resource challenge', async () => {
  for (const path of ['/.well-known/oauth-protected-resource', '/.well-known/oauth-protected-resource/mcp']) {
    assert.deepEqual(await (await worker.fetch(request(path))).json(), {
      resource: `${ORIGIN}/mcp`, authorization_servers: [ORIGIN],
      scopes_supported: ['ankka:read'], bearer_methods_supported: ['header'],
    });
  }
  assert.deepEqual(await (await worker.fetch(request('/.well-known/oauth-authorization-server'))).json(), {
    issuer: ORIGIN,
    authorization_endpoint: `${ORIGIN}/authorize`, token_endpoint: `${ORIGIN}/token`,
    registration_endpoint: `${ORIGIN}/register`, scopes_supported: ['ankka:read', 'ankka:write'],
    response_types_supported: ['code'], grant_types_supported: ['authorization_code'],
    token_endpoint_auth_methods_supported: ['none'], code_challenge_methods_supported: ['S256'],
  });
});

test('DCR only returns validated public fields and does not infer registration scopes', async () => {
  const metadata = {
    redirect_uris: [CALLBACK], client_name: 'Synthetic client',
    client_uri: 'https://client.invalid/', logo_uri: 'https://client.invalid/logo.png',
    response_types: ['code'], grant_types: ['authorization_code'], token_endpoint_auth_method: 'none',
  };
  const response = await worker.fetch(register(metadata));
  assert.equal(response.status, 201);
  assert.deepEqual(await response.json(), { client_id: DIAGNOSTIC_CLIENT_ID, ...metadata });
  for (const scope of ['ankka:read', 'ankka:write', 'ankka:write ankka:read']) {
    const body = await (await worker.fetch(register({ redirect_uris: [CALLBACK], scope }))).json();
    assert.equal(body.scope, scope);
    assert.equal(body.client_id, DIAGNOSTIC_CLIENT_ID);
    assert.equal(Object.hasOwn(body, 'client_secret'), false);
  }
  const absent = await (await worker.fetch(register())).json();
  assert.equal(Object.hasOwn(absent, 'scope'), false);
});

test('DCR accepts optional refresh metadata in either order without issuing credentials', async () => {
  for (const grantTypes of [
    ['authorization_code', 'refresh_token'],
    ['refresh_token', 'authorization_code'],
  ]) {
    const metadata = {
      redirect_uris: [CALLBACK], client_name: 'Synthetic client',
      response_types: ['code'], grant_types: grantTypes, token_endpoint_auth_method: 'none',
    };
    const response = await worker.fetch(register(metadata));
    assert.equal(response.status, 201);
    assert.deepEqual(await response.json(), { client_id: DIAGNOSTIC_CLIENT_ID, ...metadata });
    assert.equal(response.headers.has('location'), false);
    assert.equal(response.headers.has('set-cookie'), false);
  }
});

test('authorization reports only redacted requested-scope classifications', async () => {
  for (const [scope, scopeClass, readRequested, writeRequested] of [
    [undefined, 'missing', false, false],
    ['ankka:read', 'read_only', true, false],
    ['ankka:write ankka:read', 'read_and_write', true, true],
    ['ankka:write', 'write_only', false, true],
    ['ankka:read unrelated:scope', 'unsupported', true, false],
    ['', 'unsupported', false, false],
    ['ankka:read ankka:read', 'unsupported', true, false],
  ]) {
    const response = await worker.fetch(authorize(scope, { resource: `${ORIGIN}/mcp` }));
    assert.equal(response.status, 200);
    assert.equal(response.headers.has('location'), false);
    assert.deepEqual(await response.json(), {
      fixture: OAUTH_SCOPE_FIXTURE_ID, authorizationIssued: false,
      scopeClass, readRequested, writeRequested,
    });
  }
});

test('authorization rejects unknown/duplicate parameters and missing or malformed required values', async () => {
  for (const overrides of [
    { client_id: 'unknown-diagnostic-client' }, { response_type: 'token' },
    { code_challenge_method: 'plain' }, { code_challenge: 'short' },
    { code_challenge: `${'a'.repeat(42)}=` }, { state: '' }, { state: 'x'.repeat(513) },
    { redirect_uri: 'http://localhost/callback' }, { resource: 'https://other.invalid/mcp' },
    { resource: `${ORIGIN}/mcp?extra=1` }, { prompt: 'consent' },
  ]) await expectFixedError(authorize('ankka:read', overrides));
  for (const key of ['client_id', 'response_type', 'redirect_uri', 'code_challenge', 'code_challenge_method', 'state']) {
    const url = new URL(authorize('ankka:read').url);
    url.searchParams.delete(key);
    await expectFixedError(new Request(url));
  }
  await expectFixedError(new Request(`${authorize('ankka:read').url}&scope=ankka%3Awrite`));
  await expectFixedError(new Request(`${authorize('ankka:read').url}&state=duplicate`));
  await expectFixedError(authorize('x'.repeat(257)));
  await expectFixedError(authorize('ankka:read\nankka:write'));
  await expectFixedError(request(`/authorize?${'x'.repeat(8193)}`));
});

test('DCR rejects unknown values, duplicate JSON keys, invalid shapes and secrets', async () => {
  for (const body of [
    null, [], {}, { redirect_uris: [] }, { redirect_uris: [CALLBACK, CALLBACK] },
    { redirect_uris: Array.from({ length: 5 }, (_, i) => `${CALLBACK}/${i}`) },
    { redirect_uris: [CALLBACK], client_secret: 'synthetic-rejected-value' },
    { redirect_uris: [CALLBACK], extra: 'unknown' },
    { redirect_uris: [CALLBACK], scope: 'ankka:read unrelated:scope' },
    { redirect_uris: [CALLBACK], scope: '' }, { redirect_uris: [CALLBACK], scope: null },
    { redirect_uris: [CALLBACK], grant_types: ['refresh_token'] },
    { redirect_uris: [CALLBACK], grant_types: [] },
    { redirect_uris: [CALLBACK], grant_types: ['authorization_code', 'authorization_code'] },
    { redirect_uris: [CALLBACK], grant_types: ['authorization_code', 'refresh_token', 'refresh_token'] },
    { redirect_uris: [CALLBACK], grant_types: ['authorization_code', 'client_credentials'] },
    { redirect_uris: [CALLBACK], grant_types: ['authorization_code', 'refresh_token', 'unknown'] },
    { redirect_uris: [CALLBACK], grant_types: 'authorization_code' },
    { redirect_uris: [CALLBACK], grant_types: null },
    { redirect_uris: [CALLBACK], response_types: ['token'] },
    { redirect_uris: [CALLBACK], token_endpoint_auth_method: 'client_secret_basic' },
    { redirect_uris: [CALLBACK], client_name: 'x'.repeat(129) },
    { redirect_uris: [CALLBACK], client_name: { nested: 'unexpected' } },
    { redirect_uris: [CALLBACK], client_name: 'newline\n' },
  ]) await expectFixedError(register(body));
  for (const text of [
    `{"redirect_uris":["${CALLBACK}"],"redirect_uris":["${CALLBACK}"]}`,
    `{"redirect_uris":["${CALLBACK}"],"redirect_\\u0075ris":["${CALLBACK}"]}`,
    '{malformed JSON',
  ]) await expectFixedError(registerText(text));
  // A quoted apparent key inside a string is data, not a duplicated JSON key.
  const valid = await worker.fetch(register({ redirect_uris: [CALLBACK], client_name: '"redirect_uris": synthetic' }));
  assert.equal(valid.status, 201);
  await expectFixedError(register({}, { 'content-type': 'text/plain' }));
});

test('arbitrary callback/metadata URLs cannot redirect or initiate outbound fetch', async (t) => {
  t.mock.method(globalThis, 'fetch', () => { throw new Error('outbound fetch forbidden'); });
  for (const uri of ['javascript:alert(1)', 'file:///tmp/fixture', 'http://client.invalid/',
    'http://localhost/callback', 'https://user:password@client.invalid/',
    'https://client.invalid/#fragment', 'not a URL', 'https://client.invalid/white space']) {
    await expectFixedError(register({ redirect_uris: [uri] }));
    await expectFixedError(register({ redirect_uris: [CALLBACK], logo_uri: uri }));
    await expectFixedError(authorize('ankka:read', { redirect_uri: uri }));
  }
  const response = await worker.fetch(authorize('ankka:read', { redirect_uri: 'https://external.invalid/never-visit' }));
  assert.equal(response.status, 200);
  assert.equal(response.headers.has('location'), false);
  assert.equal(globalThis.fetch.mock.callCount(), 0);
});

test('bounded streamed registration rejects actual or declared oversize input and read failures', async () => {
  await expectFixedError(register({}, { 'content-length': String(MAX_REGISTRATION_BYTES + 1) }),
    413, 'request_too_large');
  await expectFixedError(register({}, { 'content-length': 'not-a-number' }));
  let cancelled = false;
  const input = request('/register', {
    method: 'POST', headers: { 'content-type': 'application/json', 'content-length': '2' }, duplex: 'half',
    body: new ReadableStream({
      pull(controller) { controller.enqueue(new Uint8Array(2048).fill(32)); },
      cancel() { cancelled = true; },
    }),
  });
  await expectFixedError(input, 413, 'request_too_large');
  assert.equal(cancelled, true);
  await expectFixedError(request('/register', {
    method: 'POST', headers: { 'content-type': 'application/json' }, duplex: 'half',
    body: new ReadableStream({ start(controller) { controller.error(new Error('synthetic-detail-not-reflected')); } }),
  }));
});

test('registration bounds empty chunks and stalled bodies without retaining input', async () => {
  await expectFixedError(request('/register', {
    method: 'POST', headers: { 'content-type': 'application/json' }, duplex: 'half',
    body: new ReadableStream({ pull(controller) { controller.enqueue(new Uint8Array()); } }),
  }), 413, 'request_too_large');
  let cancelled = false;
  await expectFixedError(request('/register', {
    method: 'POST', headers: { 'content-type': 'application/json' }, duplex: 'half',
    body: new ReadableStream({ cancel() { cancelled = true; } }),
  }), 408, 'request_timeout');
  assert.equal(cancelled, true);
});

test('token endpoint never reads, reflects, redirects, or issues credentials', async () => {
  for (const body of [
    'code=synthetic-secret-canary&grant_type=authorization_code',
    'refresh_token=synthetic-never-issued&grant_type=refresh_token',
  ]) {
    const input = request('/token', { method: 'POST', body });
    await expectFixedError(input, 400, 'unsupported_grant_type');
    assert.equal(input.bodyUsed, false);
  }
});

test('every non-MCP route rejects inbound cookies and authorization headers', async () => {
  for (const path of ['/health', '/.well-known/oauth-protected-resource',
    '/.well-known/oauth-authorization-server', '/register', '/authorize', '/token', '/missing']) {
    for (const headers of [{ authorization: 'Bearer synthetic-never-reflected' }, { cookie: 'synthetic=never-reflected' }]) {
      await expectFixedError(request(path, { headers }), 400, 'credentials_not_accepted');
    }
  }
});

test('cross-origin requests, unexpected routes, queries, and methods fail closed', async () => {
  for (const origin of ['https://cross-origin.invalid', 'null']) {
    await expectFixedError(request('/health', { headers: { origin } }), 403, 'origin_not_allowed');
    await expectFixedError(request('/mcp', { headers: { origin } }), 403, 'origin_not_allowed');
    await expectFixedError(register(undefined, { origin }), 403, 'origin_not_allowed');
  }
  assert.equal((await worker.fetch(request('/health', { headers: { origin: ORIGIN } }))).status, 200);
  for (const path of ['/health', '/mcp', '/register', '/token', '/.well-known/oauth-authorization-server']) {
    await expectFixedError(request(`${path}?redirect_uri=https://external.invalid`));
    await expectFixedError(request(path, { method: 'OPTIONS' }), 405, 'method_not_allowed');
  }
  await expectFixedError(request('/missing'), 404, 'not_found');
  await expectFixedError(request('/authorize', { method: 'POST' }), 405, 'method_not_allowed');
});

test('all response paths use no-store, CSP, no-referrer and no CORS or cookies', async () => {
  for (const input of [request('/health'), request('/mcp'), register(), authorize('ankka:read'),
    request('/token', { method: 'POST' }), request('/missing'), request('/health?bad=1')]) {
    const response = await worker.fetch(input);
    assert.equal(response.headers.get('cache-control'), 'no-store');
    assert.equal(response.headers.get('referrer-policy'), 'no-referrer');
    assert.equal(response.headers.get('content-security-policy'), "default-src 'none'; frame-ancestors 'none'");
    assert.equal(response.headers.get('cross-origin-resource-policy'), 'same-origin');
    for (const name of ['access-control-allow-origin', 'access-control-allow-credentials', 'location', 'set-cookie']) {
      assert.equal(response.headers.has(name), false);
    }
  }
});

test('fixture configuration disables query logging and carries no deployment authority', async () => {
  const configText = await readFile(new URL('../fixtures/oauth-scope-diagnostic/wrangler.jsonc', import.meta.url), 'utf8');
  const config = JSON.parse(configText.replace(/^\s*\/\/.*$/gm, ''));
  assert.equal(config.compatibility_date, '2026-08-30');
  assert.equal(config.main, 'worker.mjs');
  assert.equal(config.observability.enabled, false);
  assert.equal(config.observability.logs.enabled, false);
  assert.equal(config.observability.logs.invocation_logs, false);
  assert.equal(config.observability.traces.enabled, false);
  assert.equal(config.logpush, false);
  for (const key of ['account_id', 'route', 'routes', 'vars', 'kv_namespaces', 'durable_objects', 'services']) {
    assert.equal(Object.hasOwn(config, key), false);
  }
});

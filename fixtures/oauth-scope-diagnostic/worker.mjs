// A non-authorizing diagnostic: no grants, tokens, persistence, or outbound I/O.
export const OAUTH_SCOPE_FIXTURE_ID = 'ankka-oauth-scope-diagnostic';
// Public protocol identifier, deliberately fixed and not an authentication secret.
export const DIAGNOSTIC_CLIENT_ID = 'ankka-diagnostic-public-client';
export const MAX_REGISTRATION_BYTES = 8192;
const READ_SCOPE = 'ankka:read';
const WRITE_SCOPE = 'ankka:write';
const RESPONSE_HEADERS = Object.freeze({
  'content-type': 'application/json; charset=utf-8',
  'cache-control': 'no-store',
  'content-security-policy': "default-src 'none'; frame-ancestors 'none'",
  'referrer-policy': 'no-referrer',
  'x-content-type-options': 'nosniff',
  'cross-origin-resource-policy': 'same-origin',
});

function json(status, body, headers = {}) {
  return new Response(JSON.stringify(body), {
    status, headers: { ...RESPONSE_HEADERS, ...headers },
  });
}

function invalid() {
  throw new Error('invalid_request');
}

function methodNotAllowed(allow) {
  return json(405, { error: 'method_not_allowed' }, { allow });
}

function httpsUrl(value) {
  // oxlint-disable-next-line anti-slop/no-runtime-typeof -- This is the dependency-free URL input parser, not a downstream domain check.
  if (typeof value !== 'string' || value.length > 2048 || /\s/.test(value)) invalid();
  const url = new URL(value);
  if (url.protocol !== 'https:' || url.username || url.password || url.hash) invalid();
  return value;
}

function queryParameters(url, allowed) {
  if (url.search.length > 8192) invalid();
  const seen = new Set();
  for (const [key] of url.searchParams) {
    if (!allowed.includes(key) || seen.has(key)) invalid();
    seen.add(key);
  }
  return url.searchParams;
}

function scopeReport(scope) {
  const values = scope === null ? [] : scope.split(' ');
  const readRequested = values.includes(READ_SCOPE);
  const writeRequested = values.includes(WRITE_SCOPE);
  const unsupported = values.some((value) => value !== READ_SCOPE && value !== WRITE_SCOPE)
    || new Set(values).size !== values.length;
  const scopeClass = scope === null ? 'missing' : unsupported ? 'unsupported'
    : readRequested && writeRequested ? 'read_and_write'
      : readRequested ? 'read_only' : 'write_only';
  return { scopeClass, readRequested, writeRequested };
}

async function registrationBody(request) {
  if (!/^application\/json(?:\s*;\s*charset=utf-8)?$/i.test(
    request.headers.get('content-type') ?? '',
  )) invalid();
  const length = request.headers.get('content-length');
  if (length !== null && !/^\d+$/.test(length)) invalid();
  if (Number(length) > MAX_REGISTRATION_BYTES) throw new Error('request_too_large');
  if (!request.body) invalid();
  const reader = request.body.getReader();
  const decoder = new TextDecoder('utf-8', { fatal: true });
  let bytes = 0;
  let chunks = 0;
  let text = '';
  let timer;
  const deadline = new Promise((_, reject) => {
    timer = setTimeout(() => reject(new Error('request_timeout')), 2000);
  });
  try {
    while (true) {
      const { value, done } = await Promise.race([reader.read(), deadline]);
      if (done) break;
      bytes += value.byteLength;
      if (bytes > MAX_REGISTRATION_BYTES || ++chunks > 128) {
        throw new Error('request_too_large');
      }
      text += decoder.decode(value, { stream: true });
    }
    text += decoder.decode();
  } finally {
    clearTimeout(timer);
    // Cancellation is best-effort; never let an uncooperative source delay the reply.
    void reader.cancel().catch(() => {});
  }
  const body = JSON.parse(text);
  // Tokenize JSON strings before checking keys, including escaped duplicate names.
  const tokens = text.match(/"(?:\\[\s\S]|[^"\\])*"|[{}[\]:,]/g) ?? [];
  const keys = new Set();
  for (let index = 0; index < tokens.length - 1; index++) {
    if (tokens[index + 1] !== ':') continue;
    const key = JSON.parse(tokens[index]);
    if (keys.has(key)) invalid();
    keys.add(key);
  }
  return body;
}

async function register(request) {
  const body = await registrationBody(request);
  const allowed = ['redirect_uris', 'client_name', 'client_uri', 'logo_uri',
    'grant_types', 'response_types', 'token_endpoint_auth_method', 'scope'];
  // oxlint-disable-next-line anti-slop/no-runtime-typeof -- Parse the untrusted JSON object's exact shape at the registration boundary.
  if (!body || typeof body !== 'object' || Array.isArray(body)
    || Object.keys(body).some((key) => !allowed.includes(key))) invalid();
  if (!Array.isArray(body.redirect_uris) || body.redirect_uris.length < 1
    || body.redirect_uris.length > 4) invalid();
  const redirectUris = body.redirect_uris.map(httpsUrl);
  if (new Set(redirectUris).size !== redirectUris.length) invalid();
  const result = {
    client_id: DIAGNOSTIC_CLIENT_ID,
    redirect_uris: redirectUris,
    token_endpoint_auth_method: 'none',
    grant_types: ['authorization_code'],
    response_types: ['code'],
  };
  // Clients may register refresh support; this fixture still never issues tokens.
  if (Object.hasOwn(body, 'grant_types')) {
    if (!Array.isArray(body.grant_types) || !body.grant_types.includes('authorization_code')
      || body.grant_types.length > 2 || new Set(body.grant_types).size !== body.grant_types.length
      || body.grant_types.some((grant) => !['authorization_code', 'refresh_token'].includes(grant))) {
      invalid();
    }
    result.grant_types = body.grant_types;
  }
  for (const [key, expected] of [
    ['response_types', ['code']],
    ['token_endpoint_auth_method', 'none'],
  ]) {
    if (Object.hasOwn(body, key) && JSON.stringify(body[key]) !== JSON.stringify(expected)) {
      invalid();
    }
  }
  if (Object.hasOwn(body, 'client_name')) {
    // oxlint-disable-next-line anti-slop/no-runtime-typeof -- Validate the primitive before the bounded client-name grammar at the I/O boundary.
    if (typeof body.client_name !== 'string' || !/^[\x20-\x7e]{1,128}$/.test(body.client_name)) {
      invalid();
    }
    result.client_name = body.client_name;
  }
  for (const key of ['client_uri', 'logo_uri']) {
    if (Object.hasOwn(body, key)) result[key] = httpsUrl(body[key]);
  }
  if (Object.hasOwn(body, 'scope')) {
    // oxlint-disable-next-line anti-slop/no-runtime-typeof -- Parse the primitive and exact diagnostic scope subset before returning metadata.
    if (typeof body.scope !== 'string' || body.scope.length > 64
      || scopeReport(body.scope).scopeClass === 'unsupported') invalid();
    result.scope = body.scope;
  }
  return json(201, result);
}

function authorize(url) {
  const params = queryParameters(url, ['client_id', 'response_type', 'redirect_uri',
    'code_challenge', 'code_challenge_method', 'state', 'scope', 'resource']);
  if (params.get('client_id') !== DIAGNOSTIC_CLIENT_ID
    || params.get('response_type') !== 'code'
    || params.get('code_challenge_method') !== 'S256'
    || !/^[A-Za-z0-9_-]{43}$/.test(params.get('code_challenge') ?? '')
    || !/^[\x20-\x7e]{1,512}$/.test(params.get('state') ?? '')) invalid();
  httpsUrl(params.get('redirect_uri'));
  if (params.has('resource') && params.get('resource') !== `${url.origin}/mcp`) invalid();
  const scope = params.get('scope');
  if (scope !== null && (scope.length > 256 || /[^\x20-\x7e]/.test(scope))) invalid();
  return json(200, {
    fixture: OAUTH_SCOPE_FIXTURE_ID,
    authorizationIssued: false,
    ...scopeReport(scope),
  });
}

export async function handleOAuthScopeDiagnosticRequest(request) {
  try {
    const url = new URL(request.url);
    if (request.url.length > 12288 || url.username || url.password || url.hash) invalid();
    const origin = request.headers.get('origin');
    if (origin !== null && origin !== url.origin) return json(403, { error: 'origin_not_allowed' });
    if (url.pathname === '/mcp') {
      if (!['GET', 'POST'].includes(request.method)) return methodNotAllowed('GET, POST');
      queryParameters(url, []);
      return json(401, { error: 'authorization_required' }, {
        'www-authenticate': `Bearer resource_metadata="${url.origin}/.well-known/oauth-protected-resource/mcp", scope="${READ_SCOPE}"`,
      });
    }
    if (request.headers.has('authorization') || request.headers.has('cookie')) {
      return json(400, { error: 'credentials_not_accepted' });
    }
    if (url.pathname === '/authorize') {
      if (request.method !== 'GET') return methodNotAllowed('GET');
      return authorize(url);
    }
    queryParameters(url, []);
    if (url.pathname === '/register') {
      if (request.method !== 'POST') return methodNotAllowed('POST');
      return await register(request);
    }
    if (url.pathname === '/token') {
      if (request.method !== 'POST') return methodNotAllowed('POST');
      return json(400, { error: 'unsupported_grant_type' });
    }
    if (!['/health', '/.well-known/oauth-protected-resource',
      '/.well-known/oauth-protected-resource/mcp',
      '/.well-known/oauth-authorization-server'].includes(url.pathname)) {
      return json(404, { error: 'not_found' });
    }
    if (request.method !== 'GET') return methodNotAllowed('GET');
    if (url.pathname === '/health') {
      return json(200, { status: 'ok', fixture: OAUTH_SCOPE_FIXTURE_ID, authorizationIssued: false });
    }
    if (url.pathname.startsWith('/.well-known/oauth-protected-resource')) {
      return json(200, {
        resource: `${url.origin}/mcp`, authorization_servers: [url.origin],
        scopes_supported: [READ_SCOPE], bearer_methods_supported: ['header'],
      });
    }
    return json(200, {
      issuer: url.origin,
      authorization_endpoint: `${url.origin}/authorize`,
      token_endpoint: `${url.origin}/token`,
      registration_endpoint: `${url.origin}/register`,
      scopes_supported: [READ_SCOPE, WRITE_SCOPE],
      response_types_supported: ['code'], grant_types_supported: ['authorization_code'],
      token_endpoint_auth_methods_supported: ['none'], code_challenge_methods_supported: ['S256'],
    });
  } catch (error) {
    if (error instanceof Error && error.message === 'request_too_large') {
      return json(413, { error: 'request_too_large' });
    }
    if (error instanceof Error && error.message === 'request_timeout') {
      return json(408, { error: 'request_timeout' });
    }
    return json(400, { error: 'invalid_request' });
  }
}

export default { fetch: handleOAuthScopeDiagnosticRequest };

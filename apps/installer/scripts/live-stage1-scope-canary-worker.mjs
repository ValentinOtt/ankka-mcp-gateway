/**
 * Disposable, customer-account Worker used to qualify the Stage 1 Cloudflare
 * OAuth boundary. It is deliberately not imported by the installer runtime.
 *
 * Required bindings (set only on the disposable canary Worker):
 * - CANARY_OAUTH_CLIENT_ID: OAuth client, authorization code + PKCE
 * - CANARY_TOKEN_ENDPOINT_AUTH_METHOD: `none` or `client_secret_basic`
 * - CANARY_OAUTH_CLIENT_SECRET: secret binding required only for
 *   `client_secret_basic`
 * - CANARY_EXPECTED_ACCOUNT_ID: the one account selected at consent
 * - CANARY_CALLBACK_URL: exact https://...workers.dev/callback URI
 * - CANARY_STATE_KEY: random secret used only to authenticate the PKCE cookie
 * - CANARY_FINALIZER_*: optional exact inert root identifiers and artifact
 *   digest used only by the separate hosted uninstall-finalizer qualification
 *
 * The Dashboard qualification may use the `_SECRET` aliases for the three
 * public configuration values so a subsequent Quick Edit version inherits
 * them alongside CANARY_STATE_KEY. The production uploader supplies ordinary
 * text bindings in the same multipart upload as the Worker module.
 *
 * The OAuth access token, refresh token (if Cloudflare returns one), asset
 * upload JWTs, and PKCE verifier are request-local. None is logged, persisted,
 * or returned. The lifecycle route retires and deletes the target before
 * revocation. The handoff route instead revokes immediately after provider
 * read-back, keeps only the short-lived bootstrap capability in an authenticated
 * HttpOnly browser cookie, and retries edge readiness without a management
 * token before transferring the capability in a URL fragment to the customer
 * Worker. The optional finalizer mode re-verifies the exact inert root before
 * each fixed deletion and never accepts a browser-provided resource target.
 */

const API_ORIGIN = 'https://api.cloudflare.com';
const AUTHORIZE_URL = 'https://dash.cloudflare.com/oauth2/auth';
const TOKEN_URL = 'https://dash.cloudflare.com/oauth2/token';
const REVOKE_URL = 'https://dash.cloudflare.com/oauth2/revoke';
const EXACT_SCOPE = 'workers-scripts.write';
const COMPATIBILITY_DATE = '2026-08-08';
const COOKIE_NAME = '__Host-ankka-stage1-canary';
const COOKIE_TTL_SECONDS = 10 * 60;
const TARGET_PREFIX = 'ankka-stage1-probe-';
const MAX_PROVIDER_BYTES = 1024 * 1024;

const ACCOUNT_ID = /^[a-f0-9]{32}$/u;
const CLIENT_ID = /^[A-Za-z0-9_-]{16,128}$/u;
const TOKEN_ENDPOINT_AUTH_METHODS = new Set(['none', 'client_secret_basic']);
const WORKER_ID = /^[a-f0-9]{32}$/u;
const WORKERS_DOMAIN_ID = /^(?:[a-f0-9]{32}|[a-f0-9]{40})$/u;
const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/u;
const DNS_LABEL = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/u;
const HOSTNAME = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/u;
const SHA256 = /^[a-f0-9]{64}$/u;
const SAFE_TOKEN = /^[A-Za-z0-9._~-]{20,8192}$/u;
const STATE_VALUE = /^[A-Za-z0-9_-]{43}$/u;
const TARGET_NAME = /^ankka-stage1-probe-[a-f0-9]{16}$/u;

const encoder = new TextEncoder();
const decoder = new TextDecoder('utf-8', { fatal: true, ignoreBOM: false });

class CanaryError extends Error {
  constructor(code, detail = 'none') {
    super(code);
    this.name = 'CanaryError';
    this.code = code;
    this.detail = detail;
  }
}

function fail(code, detail) {
  throw new CanaryError(code, detail);
}

function fixedFailure(error) {
  return error instanceof CanaryError ? `${error.code}_${error.detail}` : 'internal_failure';
}

function isRecord(value) {
  return Object.prototype.toString.call(value) === '[object Object]';
}

function isString(value) {
  return Object.prototype.toString.call(value) === '[object String]';
}

function containsControlCharacter(value) {
  return [...value].some((character) => {
    const point = character.codePointAt(0) ?? 0;
    return point <= 31 || point === 127;
  });
}

function validClientSecret(value) {
  return isString(value) && value.length >= 16 && value.length <= 512 &&
    !value.includes(':') && !containsControlCharacter(value);
}

function emptyProviderList(value) {
  return value === null || (Array.isArray(value) && value.length === 0);
}

function base64Url(bytes) {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/u, '');
}

function base64(bytes) {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function decodeBase64Url(value) {
  if (!/^[A-Za-z0-9_-]+$/u.test(value)) fail('state_invalid');
  const padding = '='.repeat((4 - (value.length % 4)) % 4);
  const binary = atob(value.replaceAll('-', '+').replaceAll('_', '/') + padding);
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

function randomBytes(length) {
  const value = new Uint8Array(length);
  crypto.getRandomValues(value);
  return value;
}

function randomToken() {
  return base64Url(randomBytes(32));
}

function randomHex(length) {
  return [...randomBytes(length)].map((byte) => byte.toString(16).padStart(2, '0')).join('');
}

async function sha256Bytes(value) {
  const bytes = isString(value) ? encoder.encode(value) : value;
  return new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));
}

async function sha256Hex(value) {
  return [...await sha256Bytes(value)].map((byte) => byte.toString(16).padStart(2, '0')).join('');
}

async function hmac(key, value) {
  const imported = await crypto.subtle.importKey(
    'raw',
    encoder.encode(key),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  );
  return base64Url(new Uint8Array(await crypto.subtle.sign('HMAC', imported, encoder.encode(value))));
}

function constantTimeEqual(left, right) {
  const leftBytes = encoder.encode(left);
  const rightBytes = encoder.encode(right);
  let mismatch = leftBytes.length ^ rightBytes.length;
  const length = Math.max(leftBytes.length, rightBytes.length);
  for (let index = 0; index < length; index += 1) {
    mismatch |= (leftBytes[index] ?? 0) ^ (rightBytes[index] ?? 0);
  }
  return mismatch === 0;
}

function exactKeys(value, expected) {
  if (!isRecord(value)) return false;
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  return actual.length === wanted.length && actual.every((key, index) => key === wanted[index]);
}

function optionalFinalizerConfig(env) {
  const values = [
    env.CANARY_FINALIZER_WORKER_NAME,
    env.CANARY_FINALIZER_WORKER_ID,
    env.CANARY_FINALIZER_NAMESPACE_ID,
    env.CANARY_FINALIZER_ROOT_DOMAIN_ID,
    env.CANARY_FINALIZER_ROOT_HOSTNAME,
    env.CANARY_FINALIZER_INERT_SHA256,
  ];
  if (values.every((value) => value === undefined)) return undefined;
  if (!DNS_LABEL.test(values[0] ?? '') || !WORKER_ID.test(values[1] ?? '') ||
      !WORKER_ID.test(values[2] ?? '') || !WORKERS_DOMAIN_ID.test(values[3] ?? '') ||
      !HOSTNAME.test(values[4] ?? '') || !SHA256.test(values[5] ?? '')) {
    fail('canary_config_invalid');
  }
  return Object.freeze({
    workerName: values[0],
    workerId: values[1],
    namespaceId: values[2],
    rootDomainId: values[3],
    rootHostname: values[4],
    inertSha256: values[5],
  });
}

function parseConfig(env) {
  const clientId = env.CANARY_OAUTH_CLIENT_ID_SECRET ?? env.CANARY_OAUTH_CLIENT_ID;
  const expectedAccountId = env.CANARY_EXPECTED_ACCOUNT_ID_SECRET ?? env.CANARY_EXPECTED_ACCOUNT_ID;
  const callbackUrl = env.CANARY_CALLBACK_URL_SECRET ?? env.CANARY_CALLBACK_URL;
  const tokenEndpointAuthMethod = env.CANARY_TOKEN_ENDPOINT_AUTH_METHOD;
  const clientSecret = env.CANARY_OAUTH_CLIENT_SECRET;
  const stateKey = env.CANARY_STATE_KEY;
  if (!CLIENT_ID.test(clientId ?? '') || !ACCOUNT_ID.test(expectedAccountId ?? '') ||
      !TOKEN_ENDPOINT_AUTH_METHODS.has(tokenEndpointAuthMethod) ||
      (tokenEndpointAuthMethod === 'client_secret_basic' && !validClientSecret(clientSecret)) ||
      (tokenEndpointAuthMethod === 'none' && clientSecret !== undefined) ||
      !isString(stateKey) || stateKey.length < 43 || stateKey.length > 256) {
    fail('canary_config_invalid');
  }
  let callback;
  try {
    callback = new URL(callbackUrl);
  } catch {
    fail('canary_config_invalid');
  }
  if (callback.protocol !== 'https:' || callback.username !== '' || callback.password !== '' ||
      callback.port !== '' || callback.pathname !== '/callback' || callback.search !== '' ||
      callback.hash !== '' || !callback.hostname.endsWith('.workers.dev')) {
    fail('canary_config_invalid');
  }
  return Object.freeze({
    clientId,
    clientSecret: tokenEndpointAuthMethod === 'client_secret_basic' ? clientSecret : undefined,
    expectedAccountId,
    callbackUrl: callback.href,
    stateKey,
    tokenEndpointAuthMethod,
    finalizer: optionalFinalizerConfig(env),
  });
}

function valuesPresent(env, names) {
  return names.every((name) => isString(env[name]) && env[name].length > 0);
}

function configHealth(env) {
  const accountId = env.CANARY_EXPECTED_ACCOUNT_ID_SECRET ?? env.CANARY_EXPECTED_ACCOUNT_ID;
  const callbackUrl = env.CANARY_CALLBACK_URL_SECRET ?? env.CANARY_CALLBACK_URL;
  const clientId = env.CANARY_OAUTH_CLIENT_ID_SECRET ?? env.CANARY_OAUTH_CLIENT_ID;
  const tokenEndpointAuthMethod = env.CANARY_TOKEN_ENDPOINT_AUTH_METHOD;
  const clientSecret = env.CANARY_OAUTH_CLIENT_SECRET;
  const fieldHealth = (value, pattern) => Object.freeze({
    length: isString(value) ? value.length : null,
    string: isString(value),
    trimmed: isString(value) && value.trim() === value,
    valid: pattern.test(value ?? ''),
  });
  let callbackValid = false;
  try {
    const callback = new URL(callbackUrl);
    callbackValid = callback.protocol === 'https:' && callback.username === '' &&
      callback.password === '' && callback.port === '' && callback.pathname === '/callback' &&
      callback.search === '' && callback.hash === '' && callback.hostname.endsWith('.workers.dev');
  } catch {
    callbackValid = false;
  }
  return Object.freeze({
    accountId: fieldHealth(accountId, ACCOUNT_ID),
    callbackUrl: Object.freeze({ ...fieldHealth(callbackUrl, /^https:\/\//u), valid: callbackValid }),
    clientId: fieldHealth(clientId, CLIENT_ID),
    clientAuthentication: Object.freeze({
      method: TOKEN_ENDPOINT_AUTH_METHODS.has(tokenEndpointAuthMethod) ? tokenEndpointAuthMethod : null,
      valid: tokenEndpointAuthMethod === 'client_secret_basic'
        ? validClientSecret(clientSecret)
        : tokenEndpointAuthMethod === 'none' && clientSecret === undefined,
    }),
    stateKey: isString(env.CANARY_STATE_KEY) && env.CANARY_STATE_KEY.length >= 43 &&
      env.CANARY_STATE_KEY.length <= 256,
    finalizer: valuesPresent(env, [
      'CANARY_FINALIZER_WORKER_NAME',
      'CANARY_FINALIZER_WORKER_ID',
      'CANARY_FINALIZER_NAMESPACE_ID',
      'CANARY_FINALIZER_ROOT_DOMAIN_ID',
      'CANARY_FINALIZER_ROOT_HOSTNAME',
      'CANARY_FINALIZER_INERT_SHA256',
    ]),
  });
}

function parseCookie(request) {
  const header = request.headers.get('cookie') ?? '';
  for (const part of header.split(';')) {
    const separator = part.indexOf('=');
    if (separator < 1) continue;
    if (part.slice(0, separator).trim() === COOKIE_NAME) return part.slice(separator + 1).trim();
  }
  return null;
}

function oauthSessionValid(value) {
  return exactKeys(value, [
    'bootstrapSecret', 'expiresAt', 'installId', 'mode', 'phase', 'state', 'target', 'verifier', 'version',
  ]) && value.version === 1 && value.phase === 'oauth' &&
    (value.mode === 'lifecycle' || value.mode === 'handoff' || value.mode === 'finalizer') &&
    STATE_VALUE.test(value.state) && STATE_VALUE.test(value.verifier) &&
    STATE_VALUE.test(value.bootstrapSecret) && TARGET_NAME.test(value.installId) &&
    (value.mode === 'finalizer' ? DNS_LABEL.test(value.target) : value.installId === value.target) &&
    Number.isSafeInteger(value.expiresAt) &&
    value.expiresAt > Date.now() && value.expiresAt <= Date.now() + COOKIE_TTL_SECONDS * 1000;
}

function handoffSessionValid(value) {
  if (!exactKeys(value, [
    'bootstrapSecret', 'expiresAt', 'installId', 'phase', 'target', 'version', 'workerUrl',
  ]) || value.version !== 1 || value.phase !== 'handoff' ||
      !STATE_VALUE.test(value.bootstrapSecret) || !TARGET_NAME.test(value.target) ||
      value.installId !== value.target || !Number.isSafeInteger(value.expiresAt) ||
      value.expiresAt <= Date.now() || value.expiresAt > Date.now() + COOKIE_TTL_SECONDS * 1000) {
    return false;
  }
  try {
    const url = new URL(value.workerUrl);
    return url.protocol === 'https:' && url.username === '' && url.password === '' &&
      url.port === '' && url.pathname === '/' && url.search === '' && url.hash === '' &&
      url.hostname.startsWith(`${value.target}.`) && url.hostname.endsWith('.workers.dev');
  } catch {
    return false;
  }
}

async function encodeSession(session, stateKey) {
  const payload = base64Url(encoder.encode(JSON.stringify(session)));
  return `${payload}.${await hmac(stateKey, payload)}`;
}

async function decodeSession(serialized, stateKey, validator) {
  if (!isString(serialized)) fail('state_missing');
  const parts = serialized.split('.');
  if (parts.length !== 2) fail('state_invalid');
  const [payload, signature] = parts;
  if (!payload || !signature || !constantTimeEqual(await hmac(stateKey, payload), signature)) {
    fail('state_invalid');
  }
  let value;
  try {
    value = JSON.parse(decoder.decode(decodeBase64Url(payload)));
  } catch {
    fail('state_invalid');
  }
  if (!validator(value)) fail('state_invalid');
  return Object.freeze({ ...value });
}

function noStoreHeaders(contentType) {
  return new Headers({
    'cache-control': 'no-store, max-age=0',
    'content-security-policy': "default-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'",
    'content-type': contentType,
    expires: '0',
    pragma: 'no-cache',
    'referrer-policy': 'no-referrer',
    'x-content-type-options': 'nosniff',
    'x-frame-options': 'DENY',
  });
}

function clearCookie(headers) {
  headers.append('set-cookie', `${COOKIE_NAME}=; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=0`);
}

async function setSessionCookie(headers, session, stateKey) {
  const maxAge = Math.max(1, Math.min(
    COOKIE_TTL_SECONDS,
    Math.ceil((session.expiresAt - Date.now()) / 1000),
  ));
  headers.append('set-cookie', `${COOKIE_NAME}=${await encodeSession(session, stateKey)}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=${maxAge}`);
}

function escapeHtml(value) {
  return value
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');
}

function page(title, body, status = 200, cleanAddress = false) {
  const headers = noStoreHeaders('text/html; charset=utf-8');
  const history = cleanAddress ? '<script>history.replaceState(null,"","/result")</script>' : '';
  return new Response(`<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>${escapeHtml(title)}</title><style>body{font:16px/1.5 system-ui,sans-serif;max-width:800px;margin:5rem auto;padding:0 1.25rem;color:#172033}a{display:inline-block;padding:.75rem 1rem;border-radius:.6rem;background:#172033;color:white;text-decoration:none}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#f4f6f8;padding:1rem;border-radius:.6rem}</style>${history}<h1>${escapeHtml(title)}</h1>${body}</html>`, { status, headers });
}

async function readBoundedJson(response) {
  if (response.status === 204) return null;
  const declared = response.headers.get('content-length');
  if (declared !== null && (!Number.isSafeInteger(Number(declared)) || Number(declared) > MAX_PROVIDER_BYTES)) {
    fail('provider_response_invalid');
  }
  if (!(response.headers.get('content-type') ?? '').toLowerCase().startsWith('application/json')) {
    fail('provider_response_invalid');
  }
  if (!response.body) fail('provider_response_invalid');
  const reader = response.body.getReader();
  const chunks = [];
  let length = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    length += value.byteLength;
    if (length > MAX_PROVIDER_BYTES) {
      await reader.cancel();
      fail('provider_response_invalid');
    }
    chunks.push(value);
  }
  const bytes = new Uint8Array(length);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  try {
    return JSON.parse(decoder.decode(bytes));
  } catch {
    fail('provider_response_invalid');
  }
}

async function requestJson(url, init) {
  let response;
  try {
    response = await fetch(url, {
      ...init,
      redirect: 'manual',
      signal: AbortSignal.timeout(20_000),
    });
  } catch {
    fail('provider_unavailable');
  }
  if (response.status >= 300 && response.status < 400) fail('provider_redirect_rejected');
  return Object.freeze({ status: response.status, value: await readBoundedJson(response) });
}

async function requestStatus(url, init) {
  let response;
  try {
    response = await fetch(url, {
      ...init,
      redirect: 'manual',
      signal: AbortSignal.timeout(20_000),
    });
  } catch {
    fail('provider_unavailable');
  }
  if (response.status >= 300 && response.status < 400) fail('provider_redirect_rejected');
  const declared = response.headers.get('content-length');
  if (declared !== null && (!Number.isSafeInteger(Number(declared)) || Number(declared) > 16 * 1024)) {
    fail('provider_response_invalid');
  }
  if (response.body) {
    const reader = response.body.getReader();
    let length = 0;
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      length += value.byteLength;
      if (length > 16 * 1024) {
        await reader.cancel();
        fail('provider_response_invalid');
      }
    }
  }
  return response.status;
}

function providerErrorCodes(value) {
  if (!isRecord(value) || !Array.isArray(value.errors)) return Object.freeze([]);
  return Object.freeze(value.errors
    .map((error) => isRecord(error) && Number.isSafeInteger(error.code) ? error.code : null)
    .filter((code) => code !== null)
    .slice(0, 8));
}

function successResult(response, statuses, stage) {
  if (!statuses.includes(response.status) || !isRecord(response.value) ||
      response.value.success !== true || !emptyProviderList(response.value.errors) ||
      !emptyProviderList(response.value.messages)) {
    fail(stage, `http_${response.status}`);
  }
  return response.value.result;
}

async function api(accessToken, path, init = {}) {
  const headers = new Headers(init.headers);
  headers.set('accept', 'application/json');
  headers.set('authorization', `Bearer ${accessToken}`);
  return requestJson(`${API_ORIGIN}${path}`, { ...init, headers });
}

function oauthClientRequest(config, values) {
  const headers = new Headers({
    accept: 'application/json',
    'content-type': 'application/x-www-form-urlencoded',
  });
  const body = new URLSearchParams(values);
  if (config.tokenEndpointAuthMethod === 'client_secret_basic') {
    headers.set('authorization', `Basic ${btoa(`${config.clientId}:${config.clientSecret}`)}`);
  } else {
    body.set('client_id', config.clientId);
  }
  return Object.freeze({ body, headers });
}

async function exchangeCode(config, code, verifier) {
  const clientRequest = oauthClientRequest(config, {
    code,
    code_verifier: verifier,
    grant_type: 'authorization_code',
    redirect_uri: config.callbackUrl,
  });
  const response = await requestJson(TOKEN_URL, {
    method: 'POST',
    headers: clientRequest.headers,
    body: clientRequest.body,
  });
  if (response.status !== 200 || !isRecord(response.value)) fail('oauth_exchange_failed', `http_${response.status}`);
  const accessToken = isString(response.value.access_token) ? response.value.access_token : undefined;
  const refreshToken = isString(response.value.refresh_token) ? response.value.refresh_token : undefined;
  const tokenType = isString(response.value.token_type) ? response.value.token_type.toLowerCase() : '';
  const scopes = isString(response.value.scope)
    ? [...new Set(response.value.scope.split(/\s+/u).filter(Boolean))].sort()
    : [];
  return { accessToken, refreshToken, tokenType, scopes };
}

async function revokeOne(config, token) {
  let lastFailure = 'not_attempted';
  for (let attempt = 0; attempt < 3; attempt += 1) {
    try {
      const clientRequest = oauthClientRequest(config, { token });
      const status = await requestStatus(REVOKE_URL, {
        method: 'POST',
        headers: clientRequest.headers,
        body: clientRequest.body,
      });
      if (status >= 200 && status < 300) return;
      lastFailure = `http_${status}`;
    } catch (error) {
      lastFailure = fixedFailure(error);
    }
    await sleep(500 * (attempt + 1));
  }
  fail('oauth_revoke_failed', lastFailure);
}

async function revokeAndProve(config, accessToken, refreshToken) {
  const tokens = [accessToken, refreshToken].filter((token) => isString(token));
  let failed = false;
  for (const token of tokens) {
    try {
      await revokeOne(config, token);
    } catch {
      failed = true;
    }
  }
  if (failed || !isString(accessToken)) fail('oauth_revoke_failed');
  let lastStatus = 'not_attempted';
  for (let attempt = 0; attempt < 3; attempt += 1) {
    const probe = await api(accessToken, '/client/v4/accounts?page=1&per_page=2', { method: 'GET' });
    if (probe.status === 401 || probe.status === 403) return 'confirmed';
    if (probe.status >= 200 && probe.status < 300) {
      lastStatus = `http_${probe.status}`;
    } else {
      lastStatus = `indeterminate_http_${probe.status}`;
    }
    await sleep(500 * (attempt + 1));
  }
  if (lastStatus === 'http_200') fail('oauth_revoke_not_effective');
  fail('oauth_revoke_unproven', lastStatus);
}

async function resolveOneAccount(accessToken, expectedAccountId) {
  const response = await api(accessToken, '/client/v4/accounts?page=1&per_page=2', { method: 'GET' });
  const result = successResult(response, [200], 'account_selection_failed');
  if (!Array.isArray(result) || result.length !== 1 || !isRecord(result[0]) ||
      result[0].id !== expectedAccountId) {
    fail('account_selection_failed', 'authorize_exactly_one_expected_account');
  }
  return expectedAccountId;
}

function accountPath(accountId, suffix) {
  if (!ACCOUNT_ID.test(accountId) || !suffix.startsWith('/')) fail('internal_target_invalid');
  return `/client/v4/accounts/${accountId}${suffix}`;
}

function activeModuleSource() {
  return `const encoder = new TextEncoder();
function json(value, status = 200, extraHeaders = {}) { return Response.json(value, { status, headers: { 'cache-control': 'no-store', ...extraHeaders } }); }
async function sha256Hex(value) { return [...new Uint8Array(await crypto.subtle.digest('SHA-256', encoder.encode(value)))].map((byte) => byte.toString(16).padStart(2, '0')).join(''); }
function exactKeys(value, expected) { if (Object.prototype.toString.call(value) !== '[object Object]') return false; const actual = Object.keys(value).sort(); const wanted = [...expected].sort(); return actual.length === wanted.length && actual.every((key, index) => key === wanted[index]); }
function secured(response) { const headers = new Headers(response.headers); headers.set('cache-control', 'no-store'); headers.set('content-security-policy', "default-src 'none'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'"); headers.set('referrer-policy', 'no-referrer'); headers.set('x-content-type-options', 'nosniff'); headers.set('x-frame-options', 'DENY'); return new Response(response.body, { status: response.status, statusText: response.statusText, headers }); }
export class AdminState {
  constructor(ctx, env) { this.ctx = ctx; this.env = env; }
  initialize() {
    this.ctx.storage.sql.exec('CREATE TABLE IF NOT EXISTS bootstrap (install_id TEXT PRIMARY KEY, commitment TEXT NOT NULL, expires_at INTEGER NOT NULL, consumed INTEGER NOT NULL CHECK (consumed IN (0, 1)))');
    this.ctx.storage.sql.exec('INSERT OR IGNORE INTO bootstrap (install_id, commitment, expires_at, consumed) VALUES (?, ?, ?, 0)', this.env.ANKKA_INSTALL_ID, this.env.ANKKA_BOOTSTRAP_COMMITMENT, Number(this.env.ANKKA_BOOTSTRAP_EXPIRES_AT));
  }
  async fetch(request) {
    this.initialize();
    const url = new URL(request.url);
    if (request.method === 'GET' && url.pathname === '/health') {
      const row = this.ctx.storage.sql.exec('SELECT consumed FROM bootstrap WHERE install_id = ?', this.env.ANKKA_INSTALL_ID).one();
      return json(
        { ok: true, database: 'sqlite', state: row.consumed === 1 ? 'consumed' : 'incomplete' },
        200,
        { 'access-control-allow-origin': this.env.ANKKA_INSTALLER_ORIGIN, vary: 'Origin' },
      );
    }
    if (request.method === 'POST' && url.pathname === '/bootstrap/continue') {
      let input;
      try { input = JSON.parse(await request.text()); } catch { return json({ ok: false }, 400); }
      if (!exactKeys(input, ['bootstrapId', 'secret']) || input.bootstrapId !== this.env.ANKKA_INSTALL_ID || !/^[A-Za-z0-9_-]{43}$/.test(input.secret)) return json({ ok: false }, 400);
      const commitment = await sha256Hex(input.secret);
      const cursor = this.ctx.storage.sql.exec('UPDATE bootstrap SET consumed = 1 WHERE install_id = ? AND commitment = ? AND consumed = 0 AND expires_at >= ?', this.env.ANKKA_INSTALL_ID, commitment, Date.now());
      return cursor.rowsWritten === 1 ? new Response(null, { status: 204 }) : json({ ok: false }, 409);
    }
    return new Response(null, { status: 404 });
  }
}
export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (request.method === 'GET' && url.pathname === '/') return secured(await env.ASSETS.fetch(request));
    if (!((request.method === 'GET' && url.pathname === '/health') || (request.method === 'POST' && url.pathname === '/bootstrap/continue'))) return new Response(null, { status: 404 });
    let body;
    if (request.method === 'POST') {
      if (request.headers.get('origin') !== url.origin || !(request.headers.get('content-type') ?? '').toLowerCase().startsWith('application/json')) return json({ ok: false }, 403);
      const declared = Number(request.headers.get('content-length') ?? '0');
      if (!Number.isSafeInteger(declared) || declared < 0 || declared > 512) return json({ ok: false }, 400);
      body = await request.text();
      if (body.length > 512) return json({ ok: false }, 400);
    }
    const id = env.ADMIN_STATE.idFromName('bootstrap');
    return env.ADMIN_STATE.get(id).fetch(new Request('https://admin-state.invalid' + url.pathname, { method: request.method, headers: request.headers, body }));
  }
};`;
}

function retirementModuleSource() {
  return "export default { fetch() { return new Response(null, { status: 404 }); } };";
}

function assetBytes() {
  return encoder.encode(`<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><meta name="referrer" content="no-referrer"><title>Ankka Stage 1 handoff</title><style>body{font:16px/1.5 system-ui,sans-serif;max-width:760px;margin:5rem auto;padding:0 1.25rem;color:#172033}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#f4f6f8;padding:1rem;border-radius:.6rem}</style><h1>Finishing secure setup</h1><pre id="result">Waiting for the customer Gateway…</pre><script>
const output=document.querySelector('#result');
const show=(value)=>{output.textContent=JSON.stringify(value,null,2);};
(async()=>{
  const parameters=new URLSearchParams(location.hash.slice(1));
  let secret=parameters.get('cap')??'';
  history.replaceState(null,'','/');
  if(!/^[A-Za-z0-9_-]{43}$/.test(secret)){show({outcome:'failed',failure:'handoff_capability_missing'});return;}
  const bootstrapId=location.hostname.split('.')[0]??'';
  const firstHealth=await fetch('/health',{cache:'no-store',credentials:'omit',referrerPolicy:'no-referrer'});
  const firstHealthValue=await firstHealth.json();
  let requestBody=JSON.stringify({bootstrapId,secret});
  const mutation={method:'POST',headers:{'content-type':'application/json'},body:requestBody,cache:'no-store',credentials:'omit',referrerPolicy:'no-referrer'};
  const first=await fetch('/bootstrap/continue',mutation);
  const replay=await fetch('/bootstrap/continue',mutation);
  secret='';requestBody='';
  const consumedHealth=await fetch('/health',{cache:'no-store',credentials:'omit',referrerPolicy:'no-referrer'});
  const consumedHealthValue=await consumedHealth.json();
  if(firstHealth.status!==200||firstHealthValue.ok!==true||firstHealthValue.database!=='sqlite'||firstHealthValue.state!=='incomplete'||first.status!==204||replay.status!==409||consumedHealth.status!==200||consumedHealthValue.state!=='consumed'){
    show({outcome:'failed',failure:'customer_handoff_verification_failed'});return;
  }
  show({outcome:'passed',scope:['workers-scripts.write'],managementReadback:'worker_version_deployment_sqlite_namespace',tokenRevocation:'confirmed_before_handoff',runtime:'asset_and_sqlite_health_verified_after_revocation',bootstrapCapability:'consumed_once_replay_rejected'});
})().catch(()=>show({outcome:'failed',failure:'customer_handoff_unavailable'}));
</script></html>`);
}

async function assetUploadHash(bytes) {
  return (await sha256Hex(`${base64(bytes)}html`)).slice(0, 32);
}

async function uploadAssets(accessToken, accountId, workerName) {
  const bytes = assetBytes();
  const hash = await assetUploadHash(bytes);
  const sessionResponse = await api(
    accessToken,
    accountPath(accountId, `/workers/scripts/${encodeURIComponent(workerName)}/assets-upload-session`),
    {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ manifest: { '/index.html': { hash, size: bytes.byteLength } } }),
    },
  );
  const session = successResult(sessionResponse, [200, 201], 'asset_session_failed');
  if (!isRecord(session) || !SAFE_TOKEN.test(session.jwt ?? '') || !Array.isArray(session.buckets)) {
    fail('asset_session_invalid');
  }
  if (session.buckets.length === 0) return session.jwt;
  let completionJwt;
  const seen = new Set();
  for (let index = 0; index < session.buckets.length; index += 1) {
    const bucket = session.buckets[index];
    if (!Array.isArray(bucket) || bucket.length !== 1 || bucket[0] !== hash || seen.has(hash)) {
      fail('asset_session_invalid');
    }
    seen.add(hash);
    const form = new FormData();
    form.append(hash, new Blob([base64(bytes)], { type: 'text/html; charset=utf-8' }), hash);
    const response = await requestJson(
      `${API_ORIGIN}${accountPath(accountId, '/workers/assets/upload')}?base64=true`,
      {
        method: 'POST',
        headers: { accept: 'application/json', authorization: `Bearer ${session.jwt}` },
        body: form,
      },
    );
    const isFinal = index === session.buckets.length - 1;
    const result = successResult(response, [isFinal ? 201 : 202], 'asset_upload_failed');
    if (isFinal) {
      if (!isRecord(result) || !SAFE_TOKEN.test(result.jwt ?? '')) fail('asset_upload_invalid');
      completionJwt = result.jwt;
    }
  }
  if (!SAFE_TOKEN.test(completionJwt ?? '')) fail('asset_upload_invalid');
  return completionJwt;
}

function activeMetadata(session, completionJwt, moduleSource) {
  return {
    annotations: { 'workers/tag': `ankka-stage1-canary:${session.target}` },
    assets: {
      config: {
        not_found_handling: 'single-page-application',
        run_worker_first: true,
      },
      jwt: completionJwt,
    },
    bindings: [
      { class_name: 'AdminState', name: 'ADMIN_STATE', type: 'durable_object_namespace' },
      { name: 'ANKKA_BOOTSTRAP_COMMITMENT', text: session.bootstrapCommitment, type: 'plain_text' },
      { name: 'ANKKA_BOOTSTRAP_EXPIRES_AT', text: String(session.expiresAt), type: 'plain_text' },
      { name: 'ANKKA_INSTALLER_ORIGIN', text: session.installerOrigin, type: 'plain_text' },
      { name: 'ANKKA_INSTALL_ID', text: session.installId, type: 'plain_text' },
      { name: 'ASSETS', type: 'assets' },
    ],
    compatibility_date: COMPATIBILITY_DATE,
    compatibility_flags: [],
    exports: { AdminState: { storage: 'sqlite', type: 'durable-object' } },
    main_module: 'index.js',
    modules: [{
      content_base64: base64(encoder.encode(moduleSource)),
      content_type: 'application/javascript+module',
      name: 'index.js',
    }],
  };
}

function retirementMetadata(moduleSource) {
  return {
    annotations: { 'workers/tag': 'ankka-stage1-canary:retirement' },
    bindings: [],
    compatibility_date: COMPATIBILITY_DATE,
    compatibility_flags: [],
    exports: { AdminState: { state: 'deleted', type: 'durable-object' } },
    main_module: 'index.js',
    modules: [{
      content_base64: base64(encoder.encode(moduleSource)),
      content_type: 'application/javascript+module',
      name: 'index.js',
    }],
  };
}

async function createWorkerContainer(accessToken, accountId, workerName) {
  const lookup = await api(
    accessToken,
    accountPath(accountId, `/workers/workers/${encodeURIComponent(workerName)}`),
    { method: 'GET' },
  );
  if (lookup.status !== 404) fail('worker_name_not_fresh', `http_${lookup.status}`);
  const body = {
    logpush: false,
    name: workerName,
    observability: { enabled: false },
    subdomain: { enabled: false, previews_enabled: false },
    tags: ['ankka-mcp-gateway', 'ankka-stage1-live-canary'],
    tail_consumers: [],
  };
  const created = await api(accessToken, accountPath(accountId, '/workers/workers'), {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  });
  const result = successResult(created, [200, 201], 'worker_create_failed');
  if (!isRecord(result) || !WORKER_ID.test(result.id ?? '')) fail('worker_create_invalid');
  const readback = successResult(await api(
    accessToken,
    accountPath(accountId, `/workers/workers/${result.id}`),
    { method: 'GET' },
  ), [200], 'worker_readback_failed');
  if (!isRecord(readback) || readback.id !== result.id || readback.name !== workerName ||
      !Array.isArray(readback.tags) || !readback.tags.includes('ankka-stage1-live-canary')) {
    fail('worker_readback_invalid');
  }
  return result.id;
}

async function submitVersion(accessToken, accountId, workerId, metadata) {
  return api(accessToken, accountPath(accountId, `/workers/workers/${workerId}/versions`), {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(metadata),
  });
}

async function deployVersion(accessToken, accountId, workerName, versionId, message) {
  const response = await api(
    accessToken,
    accountPath(accountId, `/workers/scripts/${encodeURIComponent(workerName)}/deployments`),
    {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        annotations: { 'workers/message': message },
        strategy: 'percentage',
        versions: [{ percentage: 100, version_id: versionId }],
      }),
    },
  );
  const result = successResult(response, [200, 201], 'deployment_failed');
  if (!isRecord(result) || !UUID.test(result.id ?? '')) fail('deployment_invalid');
  return result.id;
}

async function directScriptUpload(accessToken, accountId, workerName, metadata) {
  const form = new FormData();
  const module = metadata.modules[0];
  const directMetadata = { ...metadata };
  delete directMetadata.modules;
  form.append('metadata', new Blob([JSON.stringify(directMetadata)], { type: 'application/json' }), 'metadata.json');
  form.append('index.js', new Blob([decodeBase64(module.content_base64)], {
    type: 'application/javascript+module',
  }), 'index.js');
  const response = await requestJson(
    `${API_ORIGIN}${accountPath(accountId, `/workers/scripts/${encodeURIComponent(workerName)}`)}`,
    {
      method: 'PUT',
      headers: { accept: 'application/json', authorization: `Bearer ${accessToken}` },
      body: form,
    },
  );
  successResult(response, [200], 'direct_script_upload_failed');
}

function decodeBase64(value) {
  const binary = atob(value);
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

async function sleep(milliseconds) {
  await new Promise((resolve) => setTimeout(resolve, milliseconds));
}

async function activeDeployment(accessToken, accountId, workerName) {
  for (let attempt = 0; attempt < 6; attempt += 1) {
    const result = successResult(await api(
      accessToken,
      accountPath(accountId, `/workers/scripts/${encodeURIComponent(workerName)}/deployments`),
      { method: 'GET' },
    ), [200], 'deployment_readback_failed');
    const deployment = isRecord(result) && Array.isArray(result.deployments) ? result.deployments[0] : null;
    const version = isRecord(deployment) && Array.isArray(deployment.versions) ? deployment.versions[0] : null;
    if (isRecord(deployment) && UUID.test(deployment.id ?? '') && isRecord(version) &&
        UUID.test(version.version_id ?? '') && version.percentage === 100) {
      return Object.freeze({ deploymentId: deployment.id, versionId: version.version_id });
    }
    await sleep(250 * (attempt + 1));
  }
  fail('deployment_readback_invalid');
}

async function verifyVersion(accessToken, accountId, workerId, versionId, expectedModuleSource, active) {
  const result = successResult(await api(
    accessToken,
    accountPath(accountId, `/workers/workers/${workerId}/versions/${versionId}?include=modules`),
    { method: 'GET' },
  ), [200], 'version_readback_failed');
  if (!isRecord(result) || result.id !== versionId || result.main_module !== 'index.js' ||
      result.compatibility_date !== COMPATIBILITY_DATE || !Array.isArray(result.modules) ||
      result.modules.length !== 1 || !isRecord(result.modules[0]) ||
      result.modules[0].content_base64 !== base64(encoder.encode(expectedModuleSource))) {
    fail('version_readback_invalid');
  }
  if (active) {
    if (!isRecord(result.exports) || !isRecord(result.exports.AdminState) ||
        result.exports.AdminState.type !== 'durable-object' || result.exports.AdminState.storage !== 'sqlite' ||
        !Array.isArray(result.bindings) || !result.bindings.some((binding) =>
          isRecord(binding) && binding.name === 'ADMIN_STATE' && binding.type === 'durable_object_namespace')) {
      fail('version_topology_invalid');
    }
  }
  return result;
}

async function namespaceSnapshot(accessToken, accountId) {
  const items = [];
  let totalPages = 1;
  for (let page = 1; page <= totalPages; page += 1) {
    const result = await api(
      accessToken,
      accountPath(accountId, `/workers/durable_objects/namespaces?page=${page}&per_page=1000`),
      { method: 'GET' },
    );
    const value = successResult(result, [200], 'namespace_readback_failed');
    if (!Array.isArray(value) || !isRecord(result.value) || !isRecord(result.value.result_info)) {
      fail('namespace_readback_invalid');
    }
    const info = result.value.result_info;
    totalPages = Number.isSafeInteger(info.total_pages)
      ? Math.max(1, info.total_pages)
      : Math.max(1, Math.ceil((info.total_count ?? value.length) / 1000));
    items.push(...value);
    if (totalPages > 100) fail('namespace_readback_invalid');
  }
  return items;
}

async function targetNamespace(accessToken, accountId, workerName) {
  const matches = (await namespaceSnapshot(accessToken, accountId)).filter((item) =>
    isRecord(item) && item.script === workerName && item.class === 'AdminState');
  if (matches.length > 1) fail('namespace_ambiguous');
  return matches[0] ?? null;
}

async function waitForNamespace(accessToken, accountId, workerName, present) {
  for (let attempt = 0; attempt < 8; attempt += 1) {
    const namespace = await targetNamespace(accessToken, accountId, workerName);
    if (present && isRecord(namespace) && ACCOUNT_ID.test(namespace.id ?? '') && namespace.use_sqlite === true) {
      return namespace;
    }
    if (!present && namespace === null) return null;
    await sleep(300 * (attempt + 1));
  }
  fail(present ? 'namespace_not_created' : 'namespace_not_retired');
}

async function setWorkerSubdomain(accessToken, accountId, workerName, enabled) {
  const response = await api(
    accessToken,
    accountPath(accountId, `/workers/scripts/${encodeURIComponent(workerName)}/subdomain`),
    {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ enabled, previews_enabled: false }),
    },
  );
  successResult(response, [200], 'workers_dev_mutation_failed');
  const observed = successResult(await api(
    accessToken,
    accountPath(accountId, `/workers/scripts/${encodeURIComponent(workerName)}/subdomain`),
    { method: 'GET' },
  ), [200], 'workers_dev_readback_failed');
  if (!isRecord(observed) || observed.enabled !== enabled || observed.previews_enabled !== false) {
    fail('workers_dev_readback_invalid');
  }
}

async function accountWorkersSubdomain(accessToken, accountId) {
  const result = successResult(await api(
    accessToken,
    accountPath(accountId, '/workers/subdomain'),
    { method: 'GET' },
  ), [200], 'account_subdomain_failed');
  if (!isRecord(result) || !DNS_LABEL.test(result.subdomain ?? '')) fail('account_subdomain_invalid');
  return result.subdomain;
}

async function workerFetch(url, init, expectedStatuses) {
  let lastStatus = 'network';
  for (let attempt = 0; attempt < 8; attempt += 1) {
    let response;
    try {
      response = await fetch(url, { ...init, redirect: 'manual', signal: AbortSignal.timeout(10_000) });
    } catch {
      response = null;
    }
    if (response !== null && expectedStatuses.includes(response.status)) return response;
    lastStatus = response === null ? 'network' : String(response.status);
    if (response?.body) await response.body.cancel();
    await sleep(300 * (attempt + 1));
  }
  fail('workers_dev_probe_failed', `last_${lastStatus}`);
}

async function verifyRuntime(workerUrl, bootstrapSecret) {
  const health = await workerFetch(`${workerUrl}/health`, { method: 'GET' }, [200]);
  const healthValue = await readBoundedJson(health);
  if (!isRecord(healthValue) || healthValue.ok !== true || healthValue.database !== 'sqlite' ||
      healthValue.state !== 'incomplete') fail('health_probe_invalid');
  const asset = await workerFetch(`${workerUrl}/`, { method: 'GET' }, [200]);
  const assetText = await asset.text();
  if (assetText !== decoder.decode(assetBytes())) fail('asset_probe_invalid');
  const origin = new URL(workerUrl).origin;
  const bootstrapId = new URL(workerUrl).hostname.split('.')[0] ?? '';
  const mutation = {
    body: JSON.stringify({ bootstrapId, secret: bootstrapSecret }),
    headers: { 'content-type': 'application/json', origin },
    method: 'POST',
  };
  const first = await workerFetch(`${workerUrl}/bootstrap/continue`, {
    ...mutation,
  }, [204]);
  if (first.body) await first.body.cancel();
  const replay = await workerFetch(`${workerUrl}/bootstrap/continue`, {
    ...mutation,
  }, [409]);
  if (replay.body) await replay.body.cancel();
  const consumed = await workerFetch(`${workerUrl}/health`, { method: 'GET' }, [200]);
  const consumedValue = await readBoundedJson(consumed);
  if (!isRecord(consumedValue) || consumedValue.state !== 'consumed') fail('bootstrap_state_invalid');
}

async function proveWorkerDeleted(accessToken, accountId, workerName, workerId) {
  const beta = await api(
    accessToken,
    accountPath(accountId, `/workers/workers/${workerId}`),
    { method: 'GET' },
  );
  const script = await api(
    accessToken,
    accountPath(accountId, `/workers/scripts/${encodeURIComponent(workerName)}`),
    { method: 'GET' },
  );
  if (beta.status !== 404 || script.status !== 404) fail('worker_deletion_not_proven');
  let totalPages = 1;
  for (let page = 1; page <= totalPages; page += 1) {
    const response = await api(
      accessToken,
      accountPath(accountId, `/workers/scripts?page=${page}&per_page=1000`),
      { method: 'GET' },
    );
    const result = successResult(response, [200], 'worker_list_failed');
    if (!Array.isArray(result) || result.some((item) => isRecord(item) && item.id === workerName)) {
      fail('worker_deletion_not_proven');
    }
    const info = isRecord(response.value) && isRecord(response.value.result_info)
      ? response.value.result_info
      : null;
    totalPages = info && Number.isSafeInteger(info.total_pages) ? Math.max(1, info.total_pages) : 1;
    if (totalPages > 100) fail('worker_list_invalid');
  }
}

async function retireNamespace(accessToken, accountId, workerName, workerId, preferVersions) {
  const moduleSource = retirementModuleSource();
  const metadata = retirementMetadata(moduleSource);
  let versionPath = 'not_attempted';
  let reconciliationAt = 'direct_deploy';
  if (preferVersions) {
    const candidate = await submitVersion(accessToken, accountId, workerId, metadata);
    if (candidate.status >= 200 && candidate.status < 300) {
      const result = successResult(candidate, [200, 201], 'retirement_version_invalid');
      if (!isRecord(result) || !UUID.test(result.id ?? '')) fail('retirement_version_invalid');
      versionPath = 'accepted';
      const beforeDeploy = await targetNamespace(accessToken, accountId, workerName);
      reconciliationAt = beforeDeploy === null ? 'deployment' : 'version_upload';
      await deployVersion(
        accessToken,
        accountId,
        workerName,
        result.id,
        'ankka-stage1-canary-retirement',
      );
      await activeDeployment(accessToken, accountId, workerName);
      await verifyVersion(accessToken, accountId, workerId, result.id, moduleSource, false);
    } else {
      versionPath = `rejected_http_${candidate.status}_codes_${providerErrorCodes(candidate.value).join('-') || 'none'}`;
      await directScriptUpload(accessToken, accountId, workerName, metadata);
      await activeDeployment(accessToken, accountId, workerName);
    }
  } else {
    await directScriptUpload(accessToken, accountId, workerName, metadata);
    await activeDeployment(accessToken, accountId, workerName);
  }
  await waitForNamespace(accessToken, accountId, workerName, false);
  await waitForNamespace(accessToken, accountId, workerName, false);
  return Object.freeze({ reconciliationAt, versionPath });
}

async function bestEffortCleanup(state, accessToken, accountId, session) {
  if (!state.workerId || state.workerDeleted) return 'not_needed';
  let subdomainFailure = 'none';
  try {
    if (state.subdomainEnabled) {
      await setWorkerSubdomain(accessToken, accountId, session.target, false);
      state.subdomainEnabled = false;
    }
  } catch (error) {
    subdomainFailure = fixedFailure(error);
  }
  let gracefulFailure = 'none';
  try {
    if (await targetNamespace(accessToken, accountId, session.target)) {
      await retireNamespace(accessToken, accountId, session.target, state.workerId, false);
    }
    const deleted = await api(
      accessToken,
      accountPath(accountId, `/workers/workers/${state.workerId}`),
      { method: 'DELETE' },
    );
    if (![200, 202, 204].includes(deleted.status)) fail('worker_delete_failed', `http_${deleted.status}`);
    await proveWorkerDeleted(accessToken, accountId, session.target, state.workerId);
    state.workerDeleted = true;
    return subdomainFailure === 'none' ? 'graceful' : `graceful_after_${subdomainFailure}`;
  } catch (error) {
    gracefulFailure = fixedFailure(error);
  }
  try {
    const forced = await api(
      accessToken,
      accountPath(accountId, `/workers/scripts/${encodeURIComponent(session.target)}?force=true`),
      { method: 'DELETE' },
    );
    if (forced.status !== 404) successResult(forced, [200], 'worker_force_delete_failed');
    await proveWorkerDeleted(accessToken, accountId, session.target, state.workerId);
    await waitForNamespace(accessToken, accountId, session.target, false);
    state.workerDeleted = true;
    return `force_after_${subdomainFailure}_${gracefulFailure}`;
  } catch (error) {
    return `failed_after_${subdomainFailure}_${gracefulFailure}_${fixedFailure(error)}`;
  }
}

function initialCanaryState() {
  return {
    subdomainEnabled: false,
    workerDeleted: false,
    workerId: null,
  };
}

function initialCanaryResult() {
  return {
    accountSelection: 'one_exact_account',
    bootstrapCapability: 'not_tested',
    createReconciliationAt: 'not_observed',
    deletion: 'not_proven',
    lifecyclePath: 'not_attempted',
    retirementReconciliationAt: 'not_observed',
    retirementVersionPath: 'not_attempted',
    runtime: 'not_verified',
    scope: [EXACT_SCOPE],
    workerContainer: 'not_created',
    workersDev: 'not_verified',
  };
}

async function deployCanaryTopology(accessToken, accountId, session, state, result) {
  state.workerId = await createWorkerContainer(accessToken, accountId, session.target);
  result.workerContainer = 'created_and_read_back';
  const moduleSource = activeModuleSource();
  const completionJwt = await uploadAssets(accessToken, accountId, session.target);
  const metadata = activeMetadata(session, completionJwt, moduleSource);
  const candidate = await submitVersion(accessToken, accountId, state.workerId, metadata);
  let versionId;
  if (candidate.status >= 200 && candidate.status < 300) {
    const version = successResult(candidate, [200, 201], 'version_submit_invalid');
    if (!isRecord(version) || !UUID.test(version.id ?? '')) fail('version_submit_invalid');
    versionId = version.id;
    result.lifecyclePath = 'versions_api_accepted';
    const beforeDeploy = await targetNamespace(accessToken, accountId, session.target);
    result.createReconciliationAt = beforeDeploy === null ? 'deployment' : 'version_upload';
    await deployVersion(
      accessToken,
      accountId,
      session.target,
      versionId,
      'ankka-stage1-canary-bootstrap',
    );
  } else {
    result.lifecyclePath = `versions_api_rejected_http_${candidate.status}_codes_${providerErrorCodes(candidate.value).join('-') || 'none'}__direct_script_fallback`;
    const freshCompletionJwt = await uploadAssets(accessToken, accountId, session.target);
    await directScriptUpload(
      accessToken,
      accountId,
      session.target,
      activeMetadata(session, freshCompletionJwt, moduleSource),
    );
    result.createReconciliationAt = 'direct_deploy';
  }
  const active = await activeDeployment(accessToken, accountId, session.target);
  versionId = active.versionId;
  await verifyVersion(accessToken, accountId, state.workerId, versionId, moduleSource, true);
  await waitForNamespace(accessToken, accountId, session.target, true);
  const subdomain = await accountWorkersSubdomain(accessToken, accountId);
  await setWorkerSubdomain(accessToken, accountId, session.target, true);
  state.subdomainEnabled = true;
  result.workersDev = 'enabled_and_read_back';
  return `https://${session.target}.${subdomain}.workers.dev`;
}

function rethrowAfterCleanup(error, cleanup, state, session) {
  if (!state.workerDeleted) {
    throw new CanaryError(
      'canary_failed_with_residual_target',
      `${fixedFailure(error)}__cleanup_${cleanup}__target_${session.target}`,
    );
  }
  if (error instanceof CanaryError) {
    throw new CanaryError(error.code, `${error.detail}__cleanup_${cleanup}`);
  }
  throw new CanaryError('canary_internal_failure', `cleanup_${cleanup}`);
}

async function runStageOneCanary(accessToken, accountId, session) {
  const state = initialCanaryState();
  const result = initialCanaryResult();
  try {
    const workerUrl = await deployCanaryTopology(accessToken, accountId, session, state, result);
    await verifyRuntime(workerUrl, session.bootstrapSecret);
    result.runtime = 'asset_and_sqlite_health_verified';
    result.bootstrapCapability = 'consumed_once_replay_rejected';
    await setWorkerSubdomain(accessToken, accountId, session.target, false);
    state.subdomainEnabled = false;
    result.workersDev = 'enabled_verified_and_disabled';
    const retirement = await retireNamespace(
      accessToken,
      accountId,
      session.target,
      state.workerId,
      result.lifecyclePath === 'versions_api_accepted',
    );
    result.retirementVersionPath = retirement.versionPath;
    result.retirementReconciliationAt = retirement.reconciliationAt;
    const deleted = await api(
      accessToken,
      accountPath(accountId, `/workers/workers/${state.workerId}`),
      { method: 'DELETE' },
    );
    if (![200, 202, 204].includes(deleted.status)) fail('worker_delete_failed', `http_${deleted.status}`);
    await proveWorkerDeleted(accessToken, accountId, session.target, state.workerId);
    state.workerDeleted = true;
    result.deletion = 'worker_and_sqlite_namespace_absence_proven';
    return Object.freeze(result);
  } catch (error) {
    const cleanup = await bestEffortCleanup(state, accessToken, accountId, session);
    rethrowAfterCleanup(error, cleanup, state, session);
  }
}

async function runStageOneHandoffCanary(accessToken, accountId, session) {
  const state = initialCanaryState();
  const result = initialCanaryResult();
  try {
    const workerUrl = await deployCanaryTopology(accessToken, accountId, session, state, result);
    result.bootstrapCapability = 'committed_not_consumed';
    result.deletion = 'retained_for_post_revoke_handoff';
    result.runtime = 'deferred_until_after_revoke';
    return Object.freeze({ operation: Object.freeze(result), workerUrl });
  } catch (error) {
    const cleanup = await bestEffortCleanup(state, accessToken, accountId, session);
    rethrowAfterCleanup(error, cleanup, state, session);
  }
}

async function finalizerRootDomains(accessToken, accountId, finalizer) {
  const result = successResult(await api(
    accessToken,
    accountPath(
      accountId,
      `/workers/domains?hostname=${encodeURIComponent(finalizer.rootHostname)}&page=1&per_page=100`,
    ),
    { method: 'GET' },
  ), [200], 'finalizer_root_domain_list_failed');
  if (!Array.isArray(result)) fail('finalizer_root_domain_list_invalid');
  return result.filter((item) => isRecord(item) &&
    (item.id === finalizer.rootDomainId || item.hostname === finalizer.rootHostname ||
      item.service === finalizer.workerName));
}

async function verifyHostedFinalizerTarget(accessToken, accountId, finalizer) {
  const worker = successResult(await api(
    accessToken,
    accountPath(accountId, `/workers/workers/${encodeURIComponent(finalizer.workerName)}`),
    { method: 'GET' },
  ), [200], 'finalizer_worker_read_failed');
  if (!isRecord(worker) || worker.id !== finalizer.workerId ||
      worker.name !== finalizer.workerName) fail('finalizer_worker_read_invalid');

  const active = await activeDeployment(accessToken, accountId, finalizer.workerName);
  const version = successResult(await api(
    accessToken,
    accountPath(
      accountId,
      `/workers/workers/${finalizer.workerId}/versions/${active.versionId}?include=modules`,
    ),
    { method: 'GET' },
  ), [200], 'finalizer_version_read_failed');
  if (!isRecord(version) || version.id !== active.versionId || version.main_module !== 'index.js' ||
      !Array.isArray(version.modules) || version.modules.length !== 1 ||
      !isRecord(version.modules[0]) || !isString(version.modules[0].content_base64) ||
      await sha256Hex(decodeBase64(version.modules[0].content_base64)) !== finalizer.inertSha256 ||
      !Array.isArray(version.bindings) || version.bindings.length !== 1 ||
      !isRecord(version.bindings[0]) || version.bindings[0].name !== 'CANARY_PHASE' ||
      version.bindings[0].type !== 'plain_text' || version.bindings[0].text !== 'inert') {
    fail('finalizer_version_read_invalid');
  }

  const secrets = successResult(await api(
    accessToken,
    accountPath(accountId, `/workers/scripts/${encodeURIComponent(finalizer.workerName)}/secrets`),
    { method: 'GET' },
  ), [200], 'finalizer_secret_list_failed');
  if (!Array.isArray(secrets) || secrets.length !== 0) fail('finalizer_secret_list_invalid');

  const subdomain = successResult(await api(
    accessToken,
    accountPath(accountId, `/workers/scripts/${encodeURIComponent(finalizer.workerName)}/subdomain`),
    { method: 'GET' },
  ), [200], 'finalizer_workers_dev_read_failed');
  if (!isRecord(subdomain) || subdomain.enabled !== false || subdomain.previews_enabled !== false) {
    fail('finalizer_workers_dev_read_invalid');
  }

  const namespaces = await namespaceSnapshot(accessToken, accountId);
  if (namespaces.some((item) => isRecord(item) &&
      (item.id === finalizer.namespaceId || item.script === finalizer.workerName))) {
    fail('finalizer_namespace_still_present');
  }

  const domains = await finalizerRootDomains(accessToken, accountId, finalizer);
  if (domains.length !== 1 || domains[0].id !== finalizer.rootDomainId ||
      domains[0].hostname !== finalizer.rootHostname ||
      domains[0].service !== finalizer.workerName) fail('finalizer_root_domain_invalid');
  return Object.freeze({ activeVersionId: active.versionId });
}

async function waitForFinalizerRootDomainAbsence(accessToken, accountId, finalizer) {
  for (let attempt = 0; attempt < 10; attempt += 1) {
    if ((await finalizerRootDomains(accessToken, accountId, finalizer)).length === 0) return;
    await sleep(300 * (attempt + 1));
  }
  fail('finalizer_root_domain_not_absent');
}

async function runHostedFinalizerCanary(accessToken, accountId, finalizer) {
  await verifyHostedFinalizerTarget(accessToken, accountId, finalizer);
  const namespaceDelete = await api(
    accessToken,
    accountPath(accountId, `/workers/durable_objects/namespaces/${finalizer.namespaceId}`),
    { method: 'DELETE' },
  );
  if (![200, 202, 204, 404].includes(namespaceDelete.status)) {
    fail('finalizer_namespace_delete_failed', `http_${namespaceDelete.status}`);
  }

  await verifyHostedFinalizerTarget(accessToken, accountId, finalizer);
  const workerDelete = await api(
    accessToken,
    accountPath(accountId, `/workers/workers/${finalizer.workerId}`),
    { method: 'DELETE' },
  );
  if (![200, 202, 204].includes(workerDelete.status)) {
    fail('finalizer_worker_delete_failed', `http_${workerDelete.status}`);
  }
  await proveWorkerDeleted(accessToken, accountId, finalizer.workerName, finalizer.workerId);
  if ((await namespaceSnapshot(accessToken, accountId)).some((item) =>
    isRecord(item) && (item.id === finalizer.namespaceId || item.script === finalizer.workerName))) {
    fail('finalizer_namespace_deletion_not_proven');
  }
  await waitForFinalizerRootDomainAbsence(accessToken, accountId, finalizer);
  return Object.freeze({
    deletion: 'exact_inert_root_worker_and_namespace_absence_proven',
    foreignResources: 'unchanged_by_fixed_identifier_executor',
    providerReadback: 'reverified_before_each_root_delete',
    rootDomain: 'automatic_absence_proven',
    scope: [EXACT_SCOPE],
  });
}

async function start(request, config, mode) {
  const callback = new URL(config.callbackUrl);
  if (new URL(request.url).origin !== callback.origin) return new Response(null, { status: 404 });
  if (mode === 'finalizer' && config.finalizer === undefined) fail('canary_config_invalid');
  const verifier = randomToken();
  const session = Object.freeze({
    bootstrapSecret: randomToken(),
    expiresAt: Date.now() + COOKIE_TTL_SECONDS * 1000,
    installId: `${TARGET_PREFIX}${randomHex(8)}`,
    mode,
    phase: 'oauth',
    state: randomToken(),
    target: mode === 'finalizer' ? config.finalizer.workerName : '',
    verifier,
    version: 1,
  });
  const boundSession = Object.freeze({
    ...session,
    target: mode === 'finalizer' ? session.target : session.installId,
  });
  const challenge = base64Url(await sha256Bytes(verifier));
  const authorize = new URL(AUTHORIZE_URL);
  authorize.searchParams.set('response_type', 'code');
  authorize.searchParams.set('client_id', config.clientId);
  authorize.searchParams.set('redirect_uri', config.callbackUrl);
  authorize.searchParams.set('scope', EXACT_SCOPE);
  authorize.searchParams.set('state', boundSession.state);
  authorize.searchParams.set('code_challenge', challenge);
  authorize.searchParams.set('code_challenge_method', 'S256');
  const headers = noStoreHeaders('text/plain; charset=utf-8');
  headers.set('location', authorize.href);
  await setSessionCookie(headers, boundSession, config.stateKey);
  return new Response(null, { status: 303, headers });
}

async function handoff(request, config) {
  let session;
  try {
    session = await decodeSession(parseCookie(request), config.stateKey, handoffSessionValid);
  } catch {
    const response = page(
      'Stage 1 handoff expired',
      '<p>The short-lived bootstrap capability is no longer available. The disposable target remains inert and requires explicit cleanup.</p>',
      410,
    );
    clearCookie(response.headers);
    return response;
  }

  const target = JSON.stringify(session.workerUrl);
  const response = page(
    'Waiting for the customer Gateway',
    `<p>Cloudflare accepted and verified the restricted Gateway, and the OAuth token is already revoked. Waiting for the temporary customer hostname to reach the edge…</p><pre id="handoff-status">Checking…</pre><script>
const target=${target};
const status=document.querySelector('#handoff-status');
async function poll(){
  try {
    const response=await fetch(target+'health',{cache:'no-store',credentials:'omit',mode:'cors',referrerPolicy:'no-referrer'});
    if(response.status===200){
      const value=await response.json();
      if(value&&value.ok===true&&value.database==='sqlite'&&value.state==='incomplete'){
        location.replace('/handoff/ready');return;
      }
      status.textContent='The customer Gateway health proof did not match the reviewed release.';return;
    }
  }catch{}
  setTimeout(poll,1500);
}
poll();
</script>`,
    202,
  );
  response.headers.set(
    'content-security-policy',
    `default-src 'none'; connect-src ${new URL(session.workerUrl).origin}; base-uri 'none'; frame-ancestors 'none'; form-action 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'`,
  );
  return response;
}

async function handoffReady(request, config) {
  let session;
  try {
    session = await decodeSession(parseCookie(request), config.stateKey, handoffSessionValid);
  } catch {
    const response = page('Stage 1 handoff expired', '<p>The short-lived bootstrap capability is no longer available.</p>', 410);
    clearCookie(response.headers);
    return response;
  }
  const location = new URL(session.workerUrl);
  location.hash = new URLSearchParams({ cap: session.bootstrapSecret }).toString();
  const headers = noStoreHeaders('text/plain; charset=utf-8');
  headers.set('location', location.href);
  clearCookie(headers);
  return new Response('Continue in the customer Gateway.', { status: 303, headers });
}

async function callback(request, config) {
  const url = new URL(request.url);
  if (`${url.origin}${url.pathname}` !== config.callbackUrl) {
    return new Response(null, { status: 404 });
  }
  let accessToken;
  let refreshToken;
  let handoffState;
  let operation;
  let revocation = 'not_attempted';
  let failure = null;
  try {
    const session = await decodeSession(parseCookie(request), config.stateKey, oauthSessionValid);
    const state = url.searchParams.get('state') ?? '';
    const code = url.searchParams.get('code') ?? '';
    if (url.searchParams.has('error')) fail('oauth_authorization_rejected');
    if (!constantTimeEqual(state, session.state) || code.length < 8 || code.length > 4096 ||
        [...code].some((character) => (character.codePointAt(0) ?? 0) <= 31)) {
      fail('oauth_callback_invalid');
    }
    const exchanged = await exchangeCode(config, code, session.verifier);
    accessToken = exchanged.accessToken;
    refreshToken = exchanged.refreshToken;
    if (!SAFE_TOKEN.test(accessToken ?? '') || exchanged.tokenType !== 'bearer' ||
        exchanged.scopes.length !== 1 || exchanged.scopes[0] !== EXACT_SCOPE) {
      fail('oauth_grant_invalid');
    }
    if (refreshToken !== undefined) fail('unexpected_refresh_token');
    const accountId = await resolveOneAccount(accessToken, config.expectedAccountId);
    const bootstrapCommitment = await sha256Hex(session.bootstrapSecret);
    const deploymentSession = Object.freeze({
      ...session,
      bootstrapCommitment,
      installerOrigin: new URL(config.callbackUrl).origin,
    });
    if (session.mode === 'handoff') {
      const result = await runStageOneHandoffCanary(accessToken, accountId, deploymentSession);
      operation = result.operation;
      handoffState = Object.freeze({
        bootstrapSecret: session.bootstrapSecret,
        expiresAt: session.expiresAt,
        installId: session.installId,
        phase: 'handoff',
        target: session.target,
        version: 1,
        workerUrl: `${result.workerUrl}/`,
      });
    } else if (session.mode === 'finalizer') {
      operation = await runHostedFinalizerCanary(accessToken, accountId, config.finalizer);
    } else {
      operation = await runStageOneCanary(accessToken, accountId, deploymentSession);
    }
  } catch (error) {
    failure = error instanceof CanaryError
      ? { code: error.code, detail: error.detail }
      : { code: 'canary_internal_failure', detail: 'none' };
  } finally {
    if (isString(accessToken)) {
      try {
        revocation = await revokeAndProve(config, accessToken, refreshToken);
      } catch {
        revocation = 'failed';
      }
    }
    accessToken = undefined;
    refreshToken = undefined;
  }
  const passed = failure === null && operation !== undefined && revocation === 'confirmed';
  if (passed && handoffState !== undefined) {
    const headers = noStoreHeaders('text/plain; charset=utf-8');
    headers.set('location', '/handoff');
    await setSessionCookie(headers, handoffState, config.stateKey);
    return new Response('Waiting for the customer Gateway.', { status: 303, headers });
  }
  if (failure === null && revocation !== 'confirmed') {
    failure = handoffState === undefined
      ? { code: 'oauth_revoke_failed', detail: 'none' }
      : { code: 'oauth_revoke_failed_with_residual_target', detail: handoffState.target };
  }
  const output = passed
    ? { outcome: 'passed', operation, tokenRevocation: revocation }
    : { outcome: 'failed', failure: failure ?? { code: 'oauth_revoke_failed', detail: 'none' }, tokenRevocation: revocation };
  const body = `<pre>${escapeHtml(JSON.stringify(output, null, 2))}</pre>`;
  const response = page(passed ? 'Stage 1 canary passed' : 'Stage 1 canary failed', body, passed ? 200 : 500, true);
  clearCookie(response.headers);
  return response;
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (request.method === 'GET' && url.pathname === '/config-health') {
      return new Response(JSON.stringify(configHealth(env)), {
        headers: noStoreHeaders('application/json'),
      });
    }
    if (request.method === 'GET' && url.pathname === '/logo.svg') {
      return new Response(
        '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 128 128"><rect width="128" height="128" rx="24" fill="#0b5fff"/><path d="M34 94 58 34h12l24 60H80l-5-14H53l-5 14Zm23-26h14L64 49Z" fill="white"/></svg>',
        { headers: noStoreHeaders('image/svg+xml') },
      );
    }
    let config;
    try {
      config = parseConfig(env);
    } catch {
      return page('Canary not configured', '<p>The disposable Worker bindings are incomplete.</p>', 503);
    }
    if (request.method !== 'GET') return new Response(null, { status: 405, headers: noStoreHeaders('text/plain') });
    if (url.pathname === '/') {
      const finalizer = config.finalizer === undefined
        ? ''
        : '<p><a href="/finalizer-start">Run receipt-pinned hosted root finalizer</a></p>';
      return page('Ankka Stage 1 scope canary', `<p>Every disposable test requests only <code>workers-scripts.write</code>.</p><p><a href="/start">Run create, verify, delete, and revoke</a></p><p><a href="/handoff-start">Run post-revocation customer handoff</a></p>${finalizer}`);
    }
    if (url.pathname === '/start') return start(request, config, 'lifecycle');
    if (url.pathname === '/handoff-start') return start(request, config, 'handoff');
    if (url.pathname === '/finalizer-start') return start(request, config, 'finalizer');
    if (url.pathname === '/handoff') return handoff(request, config);
    if (url.pathname === '/handoff/ready') return handoffReady(request, config);
    if (url.pathname === '/callback') return callback(request, config);
    return new Response(null, { status: 404, headers: noStoreHeaders('text/plain') });
  },
};

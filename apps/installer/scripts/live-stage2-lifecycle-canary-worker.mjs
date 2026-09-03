/**
 * Disposable customer-owned Gateway used to qualify the Stage 2 boundary.
 *
 * The Gateway generates PKCE, receives a code through the code-only relay,
 * exchanges directly with Cloudflare, holds the grant in callback-local
 * memory, exercises only fresh canary resources, retires its SQLite Durable
 * Object into an inert release, revokes, proves revocation, and discards.
 * This file is never imported by the production installer.
 */

const API_ORIGIN = 'https://api.cloudflare.com';
const TOKEN_URL = 'https://dash.cloudflare.com/oauth2/token';
const REVOKE_URL = 'https://dash.cloudflare.com/oauth2/revoke';
const COMPATIBILITY_DATE = '2026-09-01';
const COOKIE_NAME = '__Host-ankka-stage2-canary';
// Canary-only allowance for a human completing Cloudflare consent. The cookie
// and Durable Object record are still one-time and carry no provider token.
const COOKIE_TTL_SECONDS = 30 * 60;
const MAX_PROVIDER_BYTES = 1024 * 1024;
const MAX_RELAY_BYTES = 16 * 1024;
const PORTAL_CNAME_TARGET = 'gateway.agents.cloudflare.com';
const CANARY_REVISION = 'stage2-secret-retirement-v15';
const EXACT_SCOPES = Object.freeze([
  'access-acct.read',
  'zone-access.write',
  'dns.write',
  'mcp-portals.write',
  'workers-routes.read',
  'workers-scripts.write',
  'zone.read',
].sort());

const ACCOUNT_ID = /^[a-f0-9]{32}$/u;
const PROVIDER_ID = /^(?:[a-f0-9]{32}|[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12})$/u;
const WORKERS_DOMAIN_ID = /^(?:[a-f0-9]{32}|[a-f0-9]{40})$/u;
const WORKER_NAME = /^[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$/u;
const CLIENT_ID = /^[A-Za-z0-9_-]{16,128}$/u;
const TOKEN = /^[A-Za-z0-9._~-]{20,8192}$/u;
const BASE64_TOKEN = /^[A-Za-z0-9_-]{43}$/u;
const RELAY_TICKET = /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]{43}$/u;
const HOSTNAME = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/u;
const EMAIL = /^[^\s@]{1,64}@[A-Za-z0-9.-]{1,190}$/u;

const encoder = new TextEncoder();
const decoder = new TextDecoder('utf-8', { fatal: true });

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

function isBoolean(value) {
  return Object.prototype.toString.call(value) === '[object Boolean]';
}

function isNumber(value) {
  return Object.prototype.toString.call(value) === '[object Number]';
}

function validAuthorizationCode(value) {
  return isString(value) && value.length >= 8 && value.length <= 4096 &&
    ![...value].some((character) => {
      const point = character.codePointAt(0) ?? 0;
      return point <= 31 || point === 127;
    });
}

function exactKeys(value, expected) {
  if (!isRecord(value)) return false;
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  return actual.length === wanted.length && actual.every((key, index) => key === wanted[index]);
}

function canonical(value) {
  if (value === null || isString(value) || isBoolean(value)) {
    return JSON.stringify(value);
  }
  if (isNumber(value)) {
    if (!Number.isFinite(value)) fail('canonical_invalid');
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (isRecord(value)) {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(',')}}`;
  }
  fail('canonical_invalid');
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
  if (!/^[A-Za-z0-9_-]+$/u.test(value)) fail('session_invalid');
  const padding = '='.repeat((4 - (value.length % 4)) % 4);
  let binary;
  try {
    binary = atob(value.replaceAll('-', '+').replaceAll('_', '/') + padding);
  } catch {
    fail('session_invalid');
  }
  const bytes = Uint8Array.from(binary, (character) => character.charCodeAt(0));
  if (base64Url(bytes) !== value) fail('session_invalid');
  return bytes;
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

async function hmac(keyValue, value) {
  const bytes = decodeBase64Url(keyValue);
  if (bytes.byteLength !== 32) fail('session_invalid');
  try {
    const key = await crypto.subtle.importKey(
      'raw', bytes, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign'],
    );
    return base64Url(new Uint8Array(await crypto.subtle.sign('HMAC', key, encoder.encode(value))));
  } finally {
    bytes.fill(0);
  }
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

function parseCookie(request) {
  const header = request.headers.get('cookie') ?? '';
  for (const part of header.split(';')) {
    const separator = part.indexOf('=');
    if (separator > 0 && part.slice(0, separator).trim() === COOKIE_NAME) {
      return part.slice(separator + 1).trim();
    }
  }
  return null;
}

function validHttpsUrl(value, pathname) {
  try {
    const url = new URL(value);
    return url.protocol === 'https:' && url.username === '' && url.password === '' && url.port === '' &&
      url.pathname === pathname && url.search === '' && url.hash === '';
  } catch {
    return false;
  }
}

function validWorkerHostname(hostname, workerName) {
  return hostname === `${workerName}.ankka.ai` ||
    (hostname.startsWith(`${workerName}.`) && hostname.endsWith('.workers.dev'));
}

function parseConfig(env) {
  const config = {
    accountId: env.CANARY_EXPECTED_ACCOUNT_ID,
    adminEmail: env.CANARY_ADMIN_EMAIL,
    callbackUrl: env.CANARY_GATEWAY_CALLBACK_URL,
    clientId: env.CANARY_PUBLIC_CLIENT_ID,
    relayStartUrl: env.CANARY_RELAY_START_URL,
    relayTicket: env.CANARY_RELAY_TICKET,
    relayWorkerName: env.CANARY_RELAY_WORKER_NAME,
    workerName: env.CANARY_WORKER_NAME,
    zoneName: env.CANARY_EXPECTED_ZONE_NAME,
  };
  if (!ACCOUNT_ID.test(config.accountId ?? '') || !CLIENT_ID.test(config.clientId ?? '') ||
      !WORKER_NAME.test(config.workerName ?? '') || !WORKER_NAME.test(config.relayWorkerName ?? '') ||
      !HOSTNAME.test(config.zoneName ?? '') ||
      config.zoneName !== config.zoneName?.toLowerCase() || !EMAIL.test(config.adminEmail ?? '') ||
      config.adminEmail !== config.adminEmail?.toLowerCase() ||
      !RELAY_TICKET.test(config.relayTicket ?? '') ||
      !validHttpsUrl(config.callbackUrl ?? '', '/__ankka/install/oauth/callback') ||
      !validHttpsUrl(config.relayStartUrl ?? '', '/oauth/start/install')) fail('canary_config_invalid');
  const callback = new URL(config.callbackUrl);
  const relay = new URL(config.relayStartUrl);
  if (!validWorkerHostname(callback.hostname, config.workerName) ||
      !validWorkerHostname(relay.hostname, config.relayWorkerName)) fail('canary_config_invalid');
  const relayCallback = new URL('/oauth/callback', relay.origin);
  return Object.freeze({ ...config, relayCallbackUrl: relayCallback.href });
}

function secureHeaders(contentType) {
  return new Headers({
    'cache-control': 'no-store, max-age=0',
    'content-security-policy': "default-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'; style-src 'unsafe-inline'",
    'content-type': contentType,
    expires: '0',
    pragma: 'no-cache',
    'referrer-policy': 'no-referrer',
    'x-content-type-options': 'nosniff',
    'x-frame-options': 'DENY',
  });
}

function json(value, status = 200, extraHeaders = []) {
  const headers = secureHeaders('application/json; charset=utf-8');
  for (const [name, headerValue] of extraHeaders) headers.append(name, headerValue);
  return new Response(JSON.stringify(value), { status, headers });
}

function escapeHtml(value) {
  return String(value).replaceAll('&', '&amp;').replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;').replaceAll('"', '&quot;').replaceAll("'", '&#39;');
}

function page(title, body, status = 200, extraHeaders = []) {
  const headers = secureHeaders('text/html; charset=utf-8');
  for (const [name, value] of extraHeaders) headers.append(name, value);
  return new Response(`<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><meta name="referrer" content="no-referrer"><title>${escapeHtml(title)}</title><style>body{font:16px/1.5 system-ui,sans-serif;max-width:850px;margin:5rem auto;padding:0 1.25rem;color:#172033}button{padding:.75rem 1rem;border:0;border-radius:.6rem;background:#172033;color:white;font:inherit}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#f4f6f8;padding:1rem;border-radius:.6rem}</style><h1>${escapeHtml(title)}</h1>${body}</html>`, { status, headers });
}

function clearCookie() {
  return ['set-cookie', `${COOKIE_NAME}=; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=0`];
}

async function readBoundedJson(response, limit = MAX_PROVIDER_BYTES) {
  if (response.status === 204) return null;
  const declared = response.headers.get('content-length');
  if (declared !== null && (!Number.isSafeInteger(Number(declared)) || Number(declared) > limit)) {
    fail('provider_response_invalid', `http_${response.status}_declared_length`);
  }
  const contentType = (response.headers.get('content-type') ?? '').toLowerCase();
  if (!contentType.startsWith('application/json') || !response.body) {
    fail(
      'provider_response_invalid',
      `http_${response.status}_${contentType === '' ? 'content_type_missing' : 'content_type_other'}`,
    );
  }
  const reader = response.body.getReader();
  const chunks = [];
  let length = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    length += value.byteLength;
    if (length > limit) {
      await reader.cancel();
      fail('provider_response_invalid', `http_${response.status}_body_too_large`);
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
    fail('provider_response_invalid', `http_${response.status}_json_invalid`);
  }
}

async function requestJson(url, init, limit = MAX_PROVIDER_BYTES) {
  let response;
  try {
    response = await fetch(url, { ...init, redirect: 'manual', signal: AbortSignal.timeout(20_000) });
  } catch {
    fail('provider_unavailable');
  }
  if (response.status >= 300 && response.status < 400) fail('provider_redirect_rejected');
  return Object.freeze({ status: response.status, value: await readBoundedJson(response, limit) });
}

function providerCodes(value) {
  if (!isRecord(value) || !Array.isArray(value.errors)) return [];
  return value.errors.map((error) => {
    if (!isRecord(error)) return null;
    if (Number.isSafeInteger(error.code)) return error.code;
    if (isString(error.code) && /^\d{1,9}$/u.test(error.code)) return Number(error.code);
    return null;
  }).filter((code) => code !== null).slice(0, 6);
}

function jsonValueKind(value) {
  if (Array.isArray(value)) return 'array';
  if (value === null) return 'null';
  if (isRecord(value)) return 'record';
  if (isString(value)) return 'string';
  if (isBoolean(value)) return 'boolean';
  if (isNumber(value)) return 'number';
  return 'invalid';
}

function providerEnvelopeSummary(value) {
  if (Array.isArray(value)) return 'array';
  if (value === null) return 'null';
  if (!isRecord(value)) return jsonValueKind(value);
  const success = value.success === true
    ? 'true'
    : value.success === false ? 'false' : jsonValueKind(value.success);
  let errors;
  if (Array.isArray(value.errors)) {
    errors = value.errors.length === 0 ? 'array_empty' : 'array_nonempty';
  } else if (value.errors === null) {
    errors = 'null';
  } else if (isRecord(value.errors)) {
    const keys = Object.keys(value.errors);
    const knownKeys = ['code', 'documentation_url', 'message', 'source'];
    const known = knownKeys.filter((key) => Object.hasOwn(value.errors, key));
    const unknown = keys.filter((key) => !knownKeys.includes(key));
    const unknownKinds = [...new Set(unknown.map((key) => {
      const item = value.errors[key];
      return jsonValueKind(item);
    }))].sort();
    const code = !Object.hasOwn(value.errors, 'code')
      ? 'missing'
      : Number.isSafeInteger(value.errors.code)
        ? value.errors.code === 0 ? 'integer_zero' : value.errors.code > 0 ? 'integer_positive' : 'integer_negative'
        : isString(value.errors.code)
          ? /^0+$/u.test(value.errors.code) ? 'string_zero' : /^\d+$/u.test(value.errors.code) ? 'string_positive' : 'string_other'
          : jsonValueKind(value.errors.code);
    const message = !Object.hasOwn(value.errors, 'message')
      ? 'missing'
      : isString(value.errors.message)
        ? value.errors.message === '' ? 'string_empty' : 'string_nonempty'
        : jsonValueKind(value.errors.message);
    errors = keys.length === 0
      ? 'object_empty'
      : `object_nonempty_${Math.min(keys.length, 9)}_known_${known.join('-') || 'none'}` +
        `_unknown_${Math.min(unknown.length, 9)}_${unknownKinds.join('-') || 'none'}` +
        `_code_${code}_message_${message}`;
  } else {
    errors = jsonValueKind(value.errors);
  }
  const result = Array.isArray(value.result)
    ? 'array'
    : jsonValueKind(value.result);
  return `record_success_${success}_errors_${errors}_result_${result}`;
}

function successResult(response, statuses, stage) {
  if (!statuses.includes(response.status) || !isRecord(response.value) ||
      response.value.success !== true || !Array.isArray(response.value.errors) ||
      response.value.errors.length !== 0) {
    fail(
      stage,
      `http_${response.status}_codes_${providerCodes(response.value).join('-') || 'none'}` +
        `_envelope_${providerEnvelopeSummary(response.value)}`,
    );
  }
  return response.value.result;
}

function workersDomainResult(response, statuses, stage) {
  const errors = isRecord(response.value) ? response.value.errors : undefined;
  const noErrors = errors === null || (Array.isArray(errors)
    ? errors.length === 0
    : isRecord(errors) && Object.keys(errors).length === 0);
  if (!statuses.includes(response.status) || !isRecord(response.value) ||
      response.value.success !== true || !noErrors) {
    fail(
      stage,
      `http_${response.status}_codes_${providerCodes(response.value).join('-') || 'none'}` +
        `_envelope_${providerEnvelopeSummary(response.value)}`,
    );
  }
  return response.value.result;
}

function workersNamespaceResult(response, statuses, stage) {
  const errors = isRecord(response.value) ? response.value.errors : undefined;
  const noErrors = errors === null || Array.isArray(errors) && errors.length === 0;
  if (!statuses.includes(response.status) || !isRecord(response.value) ||
      response.value.success !== true || !noErrors) {
    fail(
      stage,
      `http_${response.status}_codes_${providerCodes(response.value).join('-') || 'none'}` +
        `_envelope_${providerEnvelopeSummary(response.value)}`,
    );
  }
  return response.value.result;
}

function mcpControlResult(response, statuses, stage) {
  const value = response.value;
  const noErrors = isRecord(value) && (!Object.hasOwn(value, 'errors') ||
    value.errors === null || Array.isArray(value.errors) && value.errors.length === 0);
  if (!statuses.includes(response.status) || !isRecord(value) ||
      value.success !== true || !noErrors) {
    fail(
      stage,
      `http_${response.status}_codes_${providerCodes(value).join('-') || 'none'}` +
        `_envelope_${providerEnvelopeSummary(value)}`,
    );
  }
  return value.result;
}

function accountPath(accountId, suffix) {
  if (!ACCOUNT_ID.test(accountId) || !suffix.startsWith('/')) fail('internal_target_invalid');
  return `/client/v4/accounts/${accountId}${suffix}`;
}

function zonePath(zoneId, suffix) {
  if (!ACCOUNT_ID.test(zoneId) || !suffix.startsWith('/')) fail('internal_target_invalid');
  return `/client/v4/zones/${zoneId}${suffix}`;
}

async function api(accessToken, path, init = {}) {
  const headers = new Headers(init.headers);
  headers.set('accept', 'application/json');
  headers.set('authorization', `Bearer ${accessToken}`);
  return requestJson(`${API_ORIGIN}${path}`, { ...init, headers });
}

async function apiMutation(accessToken, path, method, body) {
  return api(accessToken, path, {
    method,
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  });
}

async function sleep(milliseconds) {
  await new Promise((resolve) => setTimeout(resolve, milliseconds));
}

function cleanRuntimeSource(phase) {
  return `export class CanaryState { constructor(ctx) { this.ctx = ctx; } fetch() { return new Response(null, { status: 404 }); } }
export default { fetch(request, env) { const url = new URL(request.url); if (request.method === 'GET' && url.pathname === '/health') return Response.json({ schemaVersion: 1, role: 'customer-gateway', phase: env.CANARY_PHASE }, { headers: { 'cache-control': 'no-store' } }); if (request.method === 'POST' && url.pathname === '/mcp') return Response.json({ jsonrpc: '2.0', id: null, result: { tools: [{ name: 'canary_ping' }] } }, { headers: { 'cache-control': 'no-store' } }); return new Response(null, { status: 404 }); } };\n//# source phase=${phase}`;
}

function inertRuntimeSource() {
  return "export default { fetch() { return new Response(null, { status: 404, headers: { 'cache-control': 'no-store' } }); } };\n//# inert ankka-live-stage2-canary";
}

function releaseMetadata(phase, moduleSource, retire = false) {
  return {
    annotations: {
      'workers/message': `ankka-live-stage2-canary:${phase}`,
      'workers/tag': `ankka-live-stage2-canary:${phase}`,
    },
    bindings: retire
      ? [{ name: 'CANARY_PHASE', text: phase, type: 'plain_text' }]
      : [
        { class_name: 'CanaryState', name: 'CANARY_STATE', type: 'durable_object_namespace' },
        { name: 'CANARY_PHASE', text: phase, type: 'plain_text' },
      ],
    compatibility_date: COMPATIBILITY_DATE,
    compatibility_flags: [],
    exports: retire
      ? { CanaryState: { state: 'deleted', type: 'durable-object' } }
      : { CanaryState: { storage: 'sqlite', type: 'durable-object' } },
    main_module: 'index.js',
    modules: [{
      content_base64: base64(encoder.encode(moduleSource)),
      content_type: 'application/javascript+module',
      name: 'index.js',
    }],
  };
}

async function directScriptUpload(accessToken, accountId, workerName, metadata, unknownOutcome = false) {
  const form = new FormData();
  const directMetadata = { ...metadata };
  delete directMetadata.modules;
  form.append('metadata', new Blob([JSON.stringify(directMetadata)], { type: 'application/json' }), 'metadata.json');
  form.append('index.js', new Blob([
    Uint8Array.from(atob(metadata.modules[0].content_base64), (character) => character.charCodeAt(0)),
  ], { type: 'application/javascript+module' }), 'index.js');
  let response;
  try {
    response = await fetch(
      `${API_ORIGIN}${accountPath(accountId, `/workers/scripts/${encodeURIComponent(workerName)}`)}`,
      {
        method: 'PUT',
        headers: { accept: 'application/json', authorization: `Bearer ${accessToken}` },
        body: form,
        redirect: 'manual',
        signal: AbortSignal.timeout(30_000),
      },
    );
  } catch {
    fail('direct_script_upload_unknown');
  }
  if (response.status !== 200) {
    const value = await readBoundedJson(response);
    fail('direct_script_upload_failed', `http_${response.status}_codes_${providerCodes(value).join('-') || 'none'}`);
  }
  if (unknownOutcome) {
    await response.body?.cancel();
    return;
  }
  await readBoundedJson(response);
}

async function activeDeployment(accessToken, accountId, workerName, afterVersionId) {
  for (let attempt = 0; attempt < 8; attempt += 1) {
    const result = successResult(await api(
      accessToken,
      accountPath(accountId, `/workers/scripts/${encodeURIComponent(workerName)}/deployments`),
      { method: 'GET' },
    ), [200], 'deployment_readback_failed');
    const deployment = isRecord(result) && Array.isArray(result.deployments) ? result.deployments[0] : null;
    const version = isRecord(deployment) && Array.isArray(deployment.versions) ? deployment.versions[0] : null;
    if (isRecord(deployment) && PROVIDER_ID.test(deployment.id ?? '') && isRecord(version) &&
        PROVIDER_ID.test(version.version_id ?? '') && version.percentage === 100 &&
        (afterVersionId === undefined || version.version_id !== afterVersionId)) {
      return Object.freeze({ deploymentId: deployment.id, versionId: version.version_id });
    }
    await sleep(250 * (attempt + 1));
  }
  fail('deployment_readback_invalid');
}

async function workerContainer(accessToken, accountId, workerName) {
  const result = successResult(await api(
    accessToken,
    accountPath(accountId, `/workers/workers/${encodeURIComponent(workerName)}`),
    { method: 'GET' },
  ), [200], 'worker_container_read_failed');
  if (!isRecord(result) || !PROVIDER_ID.test(result.id ?? '') || result.name !== workerName) {
    fail('worker_container_read_invalid');
  }
  return Object.freeze({ id: result.id, name: result.name });
}

async function verifyVersion(accessToken, accountId, workerId, versionId, source, phase, retired) {
  const result = successResult(await api(
    accessToken,
    accountPath(accountId, `/workers/workers/${workerId}/versions/${versionId}?include=modules`),
    { method: 'GET' },
  ), [200], 'version_readback_failed');
  if (!isRecord(result) || result.id !== versionId || result.main_module !== 'index.js' ||
      result.compatibility_date !== COMPATIBILITY_DATE || !Array.isArray(result.modules) ||
      result.modules.length !== 1 || !isRecord(result.modules[0]) ||
      result.modules[0].content_base64 !== base64(encoder.encode(source)) ||
      !Array.isArray(result.bindings) || !result.bindings.some((binding) =>
        isRecord(binding) && binding.name === 'CANARY_PHASE' && binding.text === phase)) {
    fail('version_readback_invalid');
  }
  const hasNamespace = result.bindings.some((binding) =>
    isRecord(binding) && binding.name === 'CANARY_STATE' &&
    binding.type === 'durable_object_namespace');
  if (hasNamespace === retired) fail('version_topology_invalid');
  return result;
}

async function namespaces(accessToken, accountId) {
  const result = workersNamespaceResult(await api(
    accessToken,
    accountPath(accountId, '/workers/durable_objects/namespaces?page=1&per_page=1000'),
    { method: 'GET' },
  ), [200], 'namespace_list_failed');
  if (!Array.isArray(result)) fail('namespace_list_invalid');
  return result;
}

async function waitForCanaryNamespace(accessToken, accountId, workerName, present) {
  for (let attempt = 0; attempt < 10; attempt += 1) {
    const matches = (await namespaces(accessToken, accountId)).filter((item) =>
      isRecord(item) && item.script === workerName && item.class === 'CanaryState');
    if (matches.length > 1) fail('namespace_ambiguous');
    if (present && matches.length === 1 && matches[0].use_sqlite === true) return matches[0];
    if (!present && matches.length === 0) return null;
    await sleep(300 * (attempt + 1));
  }
  fail(present ? 'namespace_not_present' : 'namespace_not_retired');
}

async function setWorkersDev(accessToken, accountId, workerName, enabled) {
  successResult(await apiMutation(
    accessToken,
    accountPath(accountId, `/workers/scripts/${encodeURIComponent(workerName)}/subdomain`),
    'POST',
    { enabled, previews_enabled: false },
  ), [200], 'workers_dev_mutation_failed');
  const observed = successResult(await api(
    accessToken,
    accountPath(accountId, `/workers/scripts/${encodeURIComponent(workerName)}/subdomain`),
    { method: 'GET' },
  ), [200], 'workers_dev_readback_failed');
  if (!isRecord(observed) || observed.enabled !== enabled || observed.previews_enabled !== false) {
    fail('workers_dev_readback_invalid');
  }
}

async function deleteRelayTicketSecret(accessToken, accountId, workerName) {
  const secretName = 'CANARY_RELAY_TICKET';
  successResult(await api(
    accessToken,
    accountPath(
      accountId,
      `/workers/scripts/${encodeURIComponent(workerName)}/secrets/${secretName}`,
    ),
    { method: 'DELETE' },
  ), [200], 'relay_ticket_secret_delete_failed');
  const secrets = successResult(await api(
    accessToken,
    accountPath(accountId, `/workers/scripts/${encodeURIComponent(workerName)}/secrets`),
    { method: 'GET' },
  ), [200], 'relay_ticket_secret_list_failed');
  if (!Array.isArray(secrets) || secrets.some((secret) =>
    isRecord(secret) && secret.name === secretName)) {
    fail('relay_ticket_secret_not_absent');
  }
}

async function collectList(accessToken, path, stage) {
  const response = await api(accessToken, path, { method: 'GET' });
  const result = successResult(response, [200], stage);
  if (!Array.isArray(result)) fail(stage, 'provider_shape');
  return result;
}

async function collectWorkersDomains(accessToken, path, stage) {
  const response = await api(accessToken, path, { method: 'GET' });
  const result = workersDomainResult(response, [200], stage);
  if (!Array.isArray(result)) fail(stage, 'provider_shape');
  return result;
}

async function exactWorkersDomainEventually(accessToken, path, predicate, listStage, invalidStage) {
  for (let attempt = 0; attempt < 8; attempt += 1) {
    const matches = (await collectWorkersDomains(accessToken, path, listStage)).filter(predicate);
    if (matches.length === 1) return matches[0];
    if (matches.length > 1) fail(invalidStage, 'ambiguous');
    await sleep(300 * (attempt + 1));
  }
  fail(invalidStage, 'missing');
}

async function getWorkersDomain(accessToken, path, expectedId, stage) {
  const result = workersDomainResult(
    await api(accessToken, path, { method: 'GET' }),
    [200],
    stage,
  );
  if (!isRecord(result) || result.id !== expectedId) fail(stage, 'provider_shape');
  return result;
}

async function deleteWorkersDomain(accessToken, path, stage) {
  const status = await requestStatus(`${API_ORIGIN}${path}`, {
    method: 'DELETE',
    headers: { accept: 'application/json', authorization: `Bearer ${accessToken}` },
  });
  if (![200, 202, 204].includes(status)) fail(stage, `http_${status}`);
  for (let attempt = 0; attempt < 6; attempt += 1) {
    const observed = await api(accessToken, path, { method: 'GET' });
    if (observed.status === 404) return;
    workersDomainResult(observed, [200], stage);
    await sleep(200 * (attempt + 1));
  }
  fail(stage, 'absence_unproven');
}

async function collectMcpControlList(accessToken, path, stage) {
  const result = mcpControlResult(
    await api(accessToken, path, { method: 'GET' }),
    [200],
    stage,
  );
  if (!Array.isArray(result)) fail(stage, 'provider_shape');
  return result;
}

async function createMcpControlResource(accessToken, path, body, expectedId, stage) {
  const result = mcpControlResult(
    await apiMutation(accessToken, path, 'POST', body),
    [200, 201],
    stage,
  );
  if (!isRecord(result) || result.id !== expectedId) fail(stage, 'provider_shape');
  return result;
}

async function getMcpControlResource(accessToken, path, expectedId, stage) {
  const result = mcpControlResult(
    await api(accessToken, path, { method: 'GET' }),
    [200],
    stage,
  );
  if (!isRecord(result) || result.id !== expectedId) fail(stage, 'provider_shape');
  return result;
}

async function updateMcpControlResource(accessToken, path, body, expectedId, stage) {
  const result = mcpControlResult(
    await apiMutation(accessToken, path, 'PUT', body),
    [200, 201],
    stage,
  );
  if (result !== null && (!isRecord(result) || result.id !== expectedId)) {
    fail(stage, 'provider_shape');
  }
}

async function deleteMcpControlResource(accessToken, path, stage) {
  const response = await api(accessToken, path, { method: 'DELETE' });
  if (response.status !== 204) mcpControlResult(response, [200, 202], stage);
  for (let attempt = 0; attempt < 6; attempt += 1) {
    const observed = await api(accessToken, path, { method: 'GET' });
    if (observed.status === 404) return;
    mcpControlResult(observed, [200], stage);
    await sleep(200 * (attempt + 1));
  }
  fail(stage, 'absence_unproven');
}

function exactOne(values, predicate, stage) {
  const matches = values.filter(predicate);
  if (matches.length !== 1) fail(stage, matches.length === 0 ? 'missing' : 'ambiguous');
  return matches[0];
}

async function exactListItemEventually(accessToken, path, predicate, listStage, invalidStage) {
  for (let attempt = 0; attempt < 6; attempt += 1) {
    const matches = (await collectList(accessToken, path, listStage)).filter(predicate);
    if (matches.length === 1) return matches[0];
    if (matches.length > 1) fail(invalidStage, 'ambiguous');
    await sleep(200 * (attempt + 1));
  }
  fail(invalidStage, 'missing');
}

async function resolveAccountAndZone(accessToken, config) {
  const accounts = await collectList(
    accessToken,
    '/client/v4/accounts?page=1&per_page=2',
    'account_selection_failed',
  );
  if (accounts.length !== 1 || !isRecord(accounts[0]) || accounts[0].id !== config.accountId) {
    fail('account_selection_failed', 'authorize_exactly_one_expected_account');
  }
  const zones = await collectList(
    accessToken,
    '/client/v4/zones?page=1&per_page=50',
    'zone_list_failed',
  );
  const zone = exactOne(
    zones,
    (value) => isRecord(value) && value.account?.id === config.accountId &&
      value.name === config.zoneName && ACCOUNT_ID.test(value.id ?? ''),
    'expected_zone_selection_failed',
  );
  return Object.freeze({ zoneId: zone.id, visibleZoneCount: zones.length });
}

async function zeroTrustBaseline(accessToken, accountId) {
  const organization = successResult(await api(
    accessToken,
    accountPath(accountId, '/access/organizations'),
    { method: 'GET' },
  ), [200], 'access_organization_get_failed');
  if (!isRecord(organization) || !HOSTNAME.test(organization.auth_domain ?? '') ||
      !organization.auth_domain.endsWith('.cloudflareaccess.com')) {
    fail('access_organization_invalid');
  }
  const identityProviders = await collectList(
    accessToken,
    accountPath(accountId, '/access/identity_providers?page=1&per_page=100'),
    'identity_provider_list_failed',
  );
  const usable = identityProviders.filter((provider) =>
    isRecord(provider) && PROVIDER_ID.test(provider.id ?? '') && isString(provider.type));
  if (usable.length === 0) fail('identity_provider_unavailable');
  return Object.freeze({
    authDomain: organization.auth_domain,
    identityProviderId: usable[0].id,
    identityProviderCount: usable.length,
  });
}

async function preflightNames(accessToken, accountId, zoneId, hostnames, workerName, keys) {
  const routes = await collectList(
    accessToken,
    `${zonePath(zoneId, '/workers/routes')}?page=1&per_page=100`,
    'worker_routes_list_failed',
  );
  for (const route of routes) {
    if (!isRecord(route) || !isString(route.pattern)) fail('worker_routes_list_invalid');
    if (hostnames.some((hostname) => route.pattern.toLowerCase().includes(hostname))) {
      fail('worker_route_collision');
    }
  }
  for (const hostname of hostnames) {
    const dns = await collectList(
      accessToken,
      `${zonePath(zoneId, '/dns_records')}?name.exact=${encodeURIComponent(hostname)}&page=1&per_page=100`,
      'dns_baseline_failed',
    );
    if (dns.length !== 0) fail('dns_collision');
    const domains = await collectWorkersDomains(
      accessToken,
      `${accountPath(accountId, '/workers/domains')}?hostname=${encodeURIComponent(hostname)}&page=1&per_page=100`,
      'custom_domain_baseline_failed',
    );
    if (domains.length !== 0) fail('custom_domain_collision');
    const apps = await collectList(
      accessToken,
      `${accountPath(accountId, '/access/apps')}?domain=${encodeURIComponent(hostname)}&page=1&per_page=100`,
      'access_application_baseline_failed',
    );
    if (apps.length !== 0) fail('access_application_collision');
  }
  const servers = await collectMcpControlList(
    accessToken,
    `${accountPath(accountId, '/access/ai-controls/mcp/servers')}?page=1&per_page=100`,
    'mcp_server_baseline_failed',
  );
  const portals = await collectMcpControlList(
    accessToken,
    `${accountPath(accountId, '/access/ai-controls/mcp/portals')}?page=1&per_page=100`,
    'mcp_portal_baseline_failed',
  );
  if (servers.some((value) => isRecord(value) && value.id === keys.serverId) ||
      portals.some((value) => isRecord(value) && value.id === keys.portalId)) {
    fail('mcp_resource_collision');
  }
  if (!WORKER_NAME.test(workerName)) fail('internal_target_invalid');
  return Object.freeze({ routeCount: routes.length });
}

async function createResource(accessToken, path, body, stage, expectedId = null) {
  const result = successResult(await apiMutation(accessToken, path, 'POST', body), [200, 201], stage);
  if (!isRecord(result) || (expectedId === null
    ? !PROVIDER_ID.test(result.id ?? '')
    : result.id !== expectedId)) fail(stage, 'provider_shape');
  return result;
}

async function getResource(accessToken, path, expectedId, stage) {
  const result = successResult(await api(accessToken, path, { method: 'GET' }), [200], stage);
  if (!isRecord(result) || result.id !== expectedId) fail(stage, 'provider_shape');
  return result;
}

async function updateResource(accessToken, path, body, expectedId, stage) {
  const result = successResult(await apiMutation(accessToken, path, 'PUT', body), [200, 201], stage);
  if (result !== null && (!isRecord(result) || result.id !== expectedId)) {
    fail(stage, 'provider_shape');
  }
}

async function deleteResource(accessToken, path, getPath, stage) {
  const response = await api(accessToken, path, { method: 'DELETE' });
  if (![200, 202, 204].includes(response.status) ||
      response.status !== 204 && (!isRecord(response.value) || response.value.success !== true)) {
    fail(stage, `http_${response.status}_codes_${providerCodes(response.value).join('-') || 'none'}`);
  }
  for (let attempt = 0; attempt < 6; attempt += 1) {
    const observed = await api(accessToken, getPath, { method: 'GET' });
    if (observed.status === 404) return;
    if (observed.status !== 200) fail(stage, `absence_http_${observed.status}`);
    await sleep(200 * (attempt + 1));
  }
  fail(stage, 'absence_unproven');
}

function initialResources() {
  return {
    accessApps: [],
    accessPolicies: [],
    customDomain: null,
    dnsRecord: null,
    portal: null,
    server: null,
  };
}

async function qualifyResourceEndpoints(accessToken, config, target, workerUrl, resources, result) {
  const suffix = randomHex(8);
  const managementHostname = `ankka-m-${suffix}.${config.zoneName}`;
  const portalHostname = `ankka-p-${suffix}.${config.zoneName}`;
  const serverId = `ankka-s-${suffix}`;
  const portalId = `ankka-p-${suffix}`;
  const marker = `ankka-live-stage2:${suffix}`;
  const zeroTrust = await zeroTrustBaseline(accessToken, config.accountId);
  result.accessRead = 'organization_and_identity_providers';
  const baseline = await preflightNames(
    accessToken,
    config.accountId,
    target.zoneId,
    [managementHostname, portalHostname],
    config.workerName,
    { serverId, portalId },
  );
  result.workerRoutes = `read_${baseline.routeCount}_collision_checked`;

  const managementAppBody = {
    allow_authenticate_via_warp: false,
    allowed_idps: [zeroTrust.identityProviderId],
    app_launcher_visible: false,
    auto_redirect_to_identity: false,
    domain: managementHostname,
    name: `Ankka live canary management [${marker}]`,
    session_duration: '24h',
    type: 'self_hosted',
  };
  const managementAppRoot = zonePath(target.zoneId, '/access/apps');
  const managementApp = await createResource(
    accessToken,
    managementAppRoot,
    managementAppBody,
    'management_app_create_failed',
  );
  const managementAppPath = `${managementAppRoot}/${managementApp.id}`;
  resources.accessApps.push({ id: managementApp.id, path: managementAppPath });
  await getResource(accessToken, managementAppPath, managementApp.id, 'management_app_get_failed');
  await exactListItemEventually(
    accessToken,
    managementAppRoot,
    (value) => isRecord(value) && value.id === managementApp.id && value.domain === managementHostname,
    'management_app_list_failed',
    'management_app_list_invalid',
  );

  const managementPolicyBody = {
    approval_required: false,
    decision: 'allow',
    exclude: [],
    include: [{ email: { email: config.adminEmail } }],
    isolation_required: false,
    name: `Ankka live canary administrators [${marker}]`,
    precedence: 1,
    purpose_justification_required: false,
    require: [],
  };
  const managementPolicyRoot = `${managementAppPath}/policies`;
  const managementPolicy = await createResource(
    accessToken, managementPolicyRoot, managementPolicyBody, 'management_policy_create_failed',
  );
  const managementPolicyPath = `${managementPolicyRoot}/${managementPolicy.id}`;
  resources.accessPolicies.push({
    appId: managementApp.id,
    path: managementPolicyPath,
    policyId: managementPolicy.id,
  });
  await getResource(accessToken, managementPolicyPath, managementPolicy.id, 'management_policy_get_failed');
  const policyList = await collectList(
    accessToken, `${managementPolicyRoot}?page=1&per_page=100`, 'management_policy_list_failed',
  );
  exactOne(policyList, (value) => isRecord(value) && value.id === managementPolicy.id, 'management_policy_list_invalid');
  const updatedPolicy = { ...managementPolicyBody, name: `${managementPolicyBody.name} verified` };
  await updateResource(
    accessToken, managementPolicyPath, updatedPolicy, managementPolicy.id, 'management_policy_update_failed',
  );
  const updatedPolicyRead = await getResource(
    accessToken, managementPolicyPath, managementPolicy.id, 'management_policy_update_readback_failed',
  );
  if (updatedPolicyRead.name !== updatedPolicy.name) fail('management_policy_update_readback_invalid');
  result.accessManagement = 'app_create_get_list__policy_create_get_list_update';

  const domainBody = {
    hostname: managementHostname,
    service: config.workerName,
    zone_id: target.zoneId,
    zone_name: config.zoneName,
  };
  const domainResult = workersDomainResult(await apiMutation(
    accessToken,
    accountPath(config.accountId, '/workers/domains'),
    'PUT',
    domainBody,
  ), [200, 201], 'custom_domain_create_failed');
  if (!isRecord(domainResult) || !WORKERS_DOMAIN_ID.test(domainResult.id ?? '')) {
    fail('custom_domain_create_invalid');
  }
  resources.customDomain = { id: domainResult.id, hostname: managementHostname };
  await getWorkersDomain(
    accessToken,
    accountPath(config.accountId, `/workers/domains/${domainResult.id}`),
    domainResult.id,
    'custom_domain_get_failed',
  );
  await exactWorkersDomainEventually(
    accessToken,
    `${accountPath(config.accountId, '/workers/domains')}?hostname=${encodeURIComponent(managementHostname)}&page=1&per_page=100`,
    (value) => isRecord(value) && value.id === domainResult.id &&
      value.hostname === managementHostname && value.service === config.workerName,
    'custom_domain_list_failed',
    'custom_domain_list_invalid',
  );
  result.customDomain = 'create_get_list';

  const serverBody = {
    id: serverId,
    name: `Ankka live source ${suffix}`,
    hostname: `${workerUrl}/mcp`,
    auth_type: 'unauthenticated',
    secure_web_gateway: false,
    description: marker,
    updated_prompts: [],
    updated_tools: [{ name: 'canary_ping', enabled: true }],
  };
  const server = await createMcpControlResource(
    accessToken,
    accountPath(config.accountId, '/access/ai-controls/mcp/servers'),
    serverBody,
    serverId,
    'mcp_server_create_failed',
  );
  resources.server = { id: server.id };
  const serverPath = accountPath(config.accountId, `/access/ai-controls/mcp/servers/${server.id}`);
  await getMcpControlResource(accessToken, serverPath, server.id, 'mcp_server_get_failed');
  const serverList = await collectMcpControlList(
    accessToken,
    `${accountPath(config.accountId, '/access/ai-controls/mcp/servers')}?page=1&per_page=100`,
    'mcp_server_list_failed',
  );
  exactOne(serverList, (value) => isRecord(value) && value.id === server.id, 'mcp_server_list_invalid');
  result.mcpServer = 'create_get_list';

  const portalBody = {
    id: portalId,
    name: `Ankka live portal ${suffix}`,
    hostname: portalHostname,
    code_mode: 'default_on',
    secure_web_gateway: false,
    description: marker,
  };
  const portal = await createMcpControlResource(
    accessToken,
    accountPath(config.accountId, '/access/ai-controls/mcp/portals'),
    portalBody,
    portalId,
    'mcp_portal_create_failed',
  );
  resources.portal = { id: portal.id };
  const portalPath = accountPath(config.accountId, `/access/ai-controls/mcp/portals/${portal.id}`);
  await getMcpControlResource(accessToken, portalPath, portal.id, 'mcp_portal_get_failed');
  const portalList = await collectMcpControlList(
    accessToken,
    `${accountPath(config.accountId, '/access/ai-controls/mcp/portals')}?page=1&per_page=100`,
    'mcp_portal_list_failed',
  );
  exactOne(portalList, (value) => isRecord(value) && value.id === portal.id, 'mcp_portal_list_invalid');
  const portalUpdateBody = {
    name: portalBody.name,
    hostname: portalBody.hostname,
    code_mode: portalBody.code_mode,
    secure_web_gateway: false,
    description: `${marker}:updated`,
  };
  await updateMcpControlResource(
    accessToken, portalPath, portalUpdateBody, portal.id, 'mcp_portal_update_failed',
  );
  const portalUpdated = await getMcpControlResource(
    accessToken, portalPath, portal.id, 'mcp_portal_update_readback_failed',
  );
  if (portalUpdated.description !== portalUpdateBody.description) fail('mcp_portal_update_readback_invalid');
  result.mcpPortal = 'create_get_list_update';

  const portalAppBody = {
    name: `Ankka live Portal ${suffix}`,
    type: 'mcp_portal',
    domain: portalHostname,
    destinations: [{ type: 'public', uri: portalHostname }],
    oauth_configuration: {
      enabled: true,
      dynamic_client_registration: {
        enabled: true,
        allow_any_on_localhost: true,
        allow_any_on_loopback: true,
      },
      grant: { access_token_lifetime: '15m', session_duration: '336h' },
    },
  };
  const portalAppRoot = zonePath(target.zoneId, '/access/apps');
  const portalApp = await createResource(
    accessToken,
    portalAppRoot,
    portalAppBody,
    'portal_access_app_create_failed',
  );
  const portalAppPath = `${portalAppRoot}/${portalApp.id}`;
  resources.accessApps.push({ id: portalApp.id, path: portalAppPath });
  await getResource(accessToken, portalAppPath, portalApp.id, 'portal_access_app_get_failed');

  const portalPolicyBody = {
    ...managementPolicyBody,
    name: `Ankka live Portal users [${marker}]`,
  };
  const portalPolicyRoot = `${portalAppPath}/policies`;
  const portalPolicy = await createResource(
    accessToken, portalPolicyRoot, portalPolicyBody, 'portal_access_policy_create_failed',
  );
  resources.accessPolicies.push({
    appId: portalApp.id,
    path: `${portalPolicyRoot}/${portalPolicy.id}`,
    policyId: portalPolicy.id,
  });
  await getResource(
    accessToken,
    `${portalPolicyRoot}/${portalPolicy.id}`,
    portalPolicy.id,
    'portal_access_policy_get_failed',
  );

  const dnsBody = {
    type: 'CNAME',
    name: portalHostname,
    content: PORTAL_CNAME_TARGET,
    proxied: true,
    ttl: 1,
    comment: marker,
  };
  const dnsRecord = await createResource(
    accessToken,
    zonePath(target.zoneId, '/dns_records'),
    dnsBody,
    'dns_record_create_failed',
  );
  resources.dnsRecord = { id: dnsRecord.id, zoneId: target.zoneId };
  const dnsPath = zonePath(target.zoneId, `/dns_records/${dnsRecord.id}`);
  const dnsRead = await getResource(accessToken, dnsPath, dnsRecord.id, 'dns_record_get_failed');
  if (dnsRead.name !== portalHostname || dnsRead.content !== PORTAL_CNAME_TARGET) {
    fail('dns_record_get_invalid');
  }
  const dnsList = await collectList(
    accessToken,
    `${zonePath(target.zoneId, '/dns_records')}?name.exact=${encodeURIComponent(portalHostname)}&page=1&per_page=100`,
    'dns_record_list_failed',
  );
  exactOne(dnsList, (value) => isRecord(value) && value.id === dnsRecord.id, 'dns_record_list_invalid');
  result.portalSurface = 'access_app_policy_and_dns_create_get_list';

  return Object.freeze({ managementHostname, portalHostname });
}

async function cleanupQualifiedResources(accessToken, config, resources) {
  if (resources.dnsRecord) {
    const path = zonePath(resources.dnsRecord.zoneId, `/dns_records/${resources.dnsRecord.id}`);
    await deleteResource(accessToken, path, path, 'dns_record_delete_failed');
    resources.dnsRecord = null;
  }
  if (resources.customDomain) {
    const path = accountPath(config.accountId, `/workers/domains/${resources.customDomain.id}`);
    await deleteWorkersDomain(accessToken, path, 'custom_domain_delete_failed');
    resources.customDomain = null;
  }
  for (const policy of [...resources.accessPolicies].reverse()) {
    const path = policy.path;
    await deleteResource(accessToken, path, path, 'access_policy_delete_failed');
    resources.accessPolicies.pop();
  }
  for (const application of [...resources.accessApps].reverse()) {
    const path = application.path;
    await deleteResource(accessToken, path, path, 'access_application_delete_failed');
    resources.accessApps.pop();
  }
  if (resources.portal) {
    const path = accountPath(
      config.accountId,
      `/access/ai-controls/mcp/portals/${encodeURIComponent(resources.portal.id)}`,
    );
    await deleteMcpControlResource(accessToken, path, 'mcp_portal_delete_failed');
    resources.portal = null;
  }
  if (resources.server) {
    const path = accountPath(
      config.accountId,
      `/access/ai-controls/mcp/servers/${encodeURIComponent(resources.server.id)}`,
    );
    await deleteMcpControlResource(accessToken, path, 'mcp_server_delete_failed');
    resources.server = null;
  }
}

async function bestEffortResourceCleanup(accessToken, config, resources) {
  try {
    await cleanupQualifiedResources(accessToken, config, resources);
    return 'complete';
  } catch (error) {
    return fixedFailure(error);
  }
}

async function qualifySelfUpdate(accessToken, config, result) {
  const container = await workerContainer(accessToken, config.accountId, config.workerName);
  await waitForCanaryNamespace(accessToken, config.accountId, config.workerName, true);

  const stableSource = cleanRuntimeSource('stable');
  const stableMetadata = releaseMetadata('stable', stableSource);
  await directScriptUpload(
    accessToken,
    config.accountId,
    config.workerName,
    stableMetadata,
    true,
  );
  const recovered = await activeDeployment(accessToken, config.accountId, config.workerName);
  await verifyVersion(
    accessToken,
    config.accountId,
    container.id,
    recovered.versionId,
    stableSource,
    'stable',
    false,
  );
  result.selfUpdate = 'direct_upload_unknown_outcome_recovered_by_active_readback';

  const candidateSource = cleanRuntimeSource('candidate');
  await directScriptUpload(
    accessToken,
    config.accountId,
    config.workerName,
    releaseMetadata('candidate', candidateSource),
  );
  const candidate = await activeDeployment(accessToken, config.accountId, config.workerName);
  await verifyVersion(
    accessToken,
    config.accountId,
    container.id,
    candidate.versionId,
    candidateSource,
    'candidate',
    false,
  );
  await directScriptUpload(
    accessToken,
    config.accountId,
    config.workerName,
    stableMetadata,
  );
  const rollback = await activeDeployment(accessToken, config.accountId, config.workerName);
  await verifyVersion(
    accessToken,
    config.accountId,
    container.id,
    rollback.versionId,
    stableSource,
    'stable',
    false,
  );
  result.rollback = 'prior_reviewed_release_republished_and_verified';
  return container;
}

async function retireCustomerRoot(accessToken, config, container, result) {
  const source = inertRuntimeSource();
  await directScriptUpload(
    accessToken,
    config.accountId,
    config.workerName,
    releaseMetadata('inert', source, true),
  );
  const active = await activeDeployment(accessToken, config.accountId, config.workerName);
  await verifyVersion(
    accessToken,
    config.accountId,
    container.id,
    active.versionId,
    source,
    'inert',
    true,
  );
  await deleteRelayTicketSecret(accessToken, config.accountId, config.workerName);
  const scrubbed = await activeDeployment(
    accessToken,
    config.accountId,
    config.workerName,
    active.versionId,
  );
  const scrubbedVersion = await verifyVersion(
    accessToken,
    config.accountId,
    container.id,
    scrubbed.versionId,
    source,
    'inert',
    true,
  );
  if (scrubbedVersion.bindings.some((binding) =>
    isRecord(binding) && binding.type === 'secret_text')) {
    fail('retired_version_secret_binding_present');
  }
  await waitForCanaryNamespace(accessToken, config.accountId, config.workerName, false);
  await setWorkersDev(accessToken, config.accountId, config.workerName, false);
  result.customerUninstall = 'dependent_resources_absent_inert_release_active_namespace_absent_relay_ticket_secret_absent_workers_dev_disabled';
  result.hostedFinalize = 'fresh_workers_scripts_write_grant_required';
}

function initialLifecycleResult() {
  return {
    accountSelection: 'one_exact_account',
    zoneDiscovery: 'not_qualified',
    accessRead: 'not_qualified',
    accessManagement: 'not_qualified',
    workerRoutes: 'not_qualified',
    customDomain: 'not_qualified',
    mcpServer: 'not_qualified',
    mcpPortal: 'not_qualified',
    portalSurface: 'not_qualified',
    publicReadiness: 'external_post_callback_required',
    selfUpdate: 'not_qualified',
    rollback: 'not_qualified',
    customerUninstall: 'not_qualified',
    hostedFinalize: 'not_started',
  };
}

async function runLifecycle(accessToken, config, workerUrl) {
  const resources = initialResources();
  const result = initialLifecycleResult();
  try {
    const target = await resolveAccountAndZone(accessToken, config);
    result.zoneDiscovery = `expected_zone_visible_in_${target.visibleZoneCount}_authorized_zones`;
    await qualifyResourceEndpoints(accessToken, config, target, workerUrl, resources, result);
    const container = await qualifySelfUpdate(accessToken, config, result);
    await cleanupQualifiedResources(accessToken, config, resources);
    result.accessManagement += '__delete_absence_proven';
    result.customDomain += '__delete_absence_proven';
    result.mcpServer += '__delete_absence_proven';
    result.mcpPortal += '__delete_absence_proven';
    result.portalSurface += '__delete_absence_proven';
    await retireCustomerRoot(accessToken, config, container, result);
    return Object.freeze(result);
  } catch (error) {
    const cleanup = await bestEffortResourceCleanup(accessToken, config, resources);
    throw new CanaryError('stage2_lifecycle_failed', `${fixedFailure(error)}__cleanup_${cleanup}`);
  }
}

async function exchangeCode(config, code, verifier) {
  const response = await requestJson(TOKEN_URL, {
    method: 'POST',
    headers: {
      accept: 'application/json',
      'content-type': 'application/x-www-form-urlencoded',
    },
    body: new URLSearchParams({
      client_id: config.clientId,
      code,
      code_verifier: verifier,
      grant_type: 'authorization_code',
      redirect_uri: config.relayCallbackUrl,
    }),
  });
  if (response.status !== 200 || !isRecord(response.value)) {
    fail('oauth_exchange_failed', `http_${response.status}`);
  }
  const scopes = isString(response.value.scope)
    ? [...new Set(response.value.scope.split(/\s+/u).filter(Boolean))].sort()
    : [];
  return Object.freeze({
    accessToken: isString(response.value.access_token) ? response.value.access_token : undefined,
    refreshToken: isString(response.value.refresh_token) ? response.value.refresh_token : undefined,
    tokenType: isString(response.value.token_type) ? response.value.token_type.toLowerCase() : '',
    scopes,
  });
}

async function requestStatus(url, init) {
  let response;
  try {
    response = await fetch(url, { ...init, redirect: 'manual', signal: AbortSignal.timeout(20_000) });
  } catch {
    fail('provider_unavailable');
  }
  if (response.status >= 300 && response.status < 400) fail('provider_redirect_rejected');
  let length = 0;
  if (response.body) {
    const reader = response.body.getReader();
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

async function revokeAndProve(config, accessToken, refreshToken) {
  const tokens = [accessToken, refreshToken].filter((value) => isString(value));
  for (const token of tokens) {
    let revoked = false;
    for (let attempt = 0; attempt < 3; attempt += 1) {
      const status = await requestStatus(REVOKE_URL, {
        method: 'POST',
        headers: {
          accept: 'application/json',
          'content-type': 'application/x-www-form-urlencoded',
        },
        body: new URLSearchParams({ client_id: config.clientId, token }),
      });
      if (status >= 200 && status < 300) {
        revoked = true;
        break;
      }
      await sleep(300 * (attempt + 1));
    }
    if (!revoked) fail('oauth_revoke_failed');
  }
  for (let attempt = 0; attempt < 3; attempt += 1) {
    const probe = await api(accessToken, '/client/v4/accounts?page=1&per_page=2', { method: 'GET' });
    if (probe.status === 401 || probe.status === 403) return 'confirmed';
    await sleep(400 * (attempt + 1));
  }
  fail('oauth_revoke_unproven');
}

function parseSessionPayload(serialized) {
  const parts = serialized.split('.');
  if (parts.length !== 2 || !parts[0] || !BASE64_TOKEN.test(parts[1] ?? '')) {
    fail('session_invalid');
  }
  let value;
  try {
    value = JSON.parse(decoder.decode(decodeBase64Url(parts[0])));
  } catch {
    fail('session_invalid');
  }
  if (!exactKeys(value, ['attemptId', 'expiresAt', 'state', 'verifier', 'version']) ||
      value.version !== 1 || !BASE64_TOKEN.test(value.attemptId ?? '') ||
      !BASE64_TOKEN.test(value.state ?? '') || !BASE64_TOKEN.test(value.verifier ?? '') ||
      !Number.isSafeInteger(value.expiresAt)) fail('session_invalid');
  return Object.freeze({ payload: parts[0], signature: parts[1], value });
}

export class CanaryState {
  constructor(ctx) {
    this.ctx = ctx;
  }

  initialize() {
    this.ctx.storage.sql.exec('CREATE TABLE IF NOT EXISTS singleton (id INTEGER PRIMARY KEY CHECK (id = 1), cookie_key TEXT NOT NULL)');
    this.ctx.storage.sql.exec('CREATE TABLE IF NOT EXISTS attempts (attempt_id TEXT PRIMARY KEY, state_sha256 TEXT NOT NULL, expires_at INTEGER NOT NULL, status TEXT NOT NULL CHECK (status IN (\'armed\', \'exchanging\')))');
    const rows = [...this.ctx.storage.sql.exec('SELECT cookie_key FROM singleton WHERE id = 1')];
    if (rows.length === 0) {
      this.ctx.storage.sql.exec('INSERT INTO singleton (id, cookie_key) VALUES (1, ?)', randomToken());
    }
    this.ctx.storage.sql.exec('DELETE FROM attempts WHERE expires_at < ?', Date.now());
  }

  cookieKey() {
    const row = this.ctx.storage.sql.exec('SELECT cookie_key FROM singleton WHERE id = 1').one();
    if (!BASE64_TOKEN.test(row.cookie_key ?? '')) fail('state_unavailable');
    return row.cookie_key;
  }

  async start() {
    const verifier = randomToken();
    const state = randomToken();
    const attemptId = randomToken();
    const expiresAt = Date.now() + COOKIE_TTL_SECONDS * 1_000;
    const value = Object.freeze({ version: 1, attemptId, state, verifier, expiresAt });
    const payload = base64Url(encoder.encode(canonical(value)));
    const signature = await hmac(this.cookieKey(), payload);
    this.ctx.storage.sql.exec(
      'INSERT INTO attempts (attempt_id, state_sha256, expires_at, status) VALUES (?, ?, ?, \'armed\')',
      attemptId,
      await sha256Hex(state),
      expiresAt,
    );
    return json({
      schemaVersion: 1,
      cookie: `${payload}.${signature}`,
      state,
      challenge: base64Url(await sha256Bytes(verifier)),
      expiresAt,
    });
  }

  async consume(request) {
    const value = await readBoundedJson(request, 8 * 1024);
    if (!exactKeys(value, ['cookie', 'state']) || !isString(value.cookie) ||
        !BASE64_TOKEN.test(value.state ?? '')) fail('session_invalid');
    const session = parseSessionPayload(value.cookie);
    if (!constantTimeEqual(session.signature, await hmac(this.cookieKey(), session.payload)) ||
        !constantTimeEqual(session.value.state, value.state) || session.value.expiresAt <= Date.now()) {
      fail('session_invalid');
    }
    const updated = this.ctx.storage.sql.exec(
      'UPDATE attempts SET status = \'exchanging\' WHERE attempt_id = ? AND state_sha256 = ? AND expires_at = ? AND expires_at >= ? AND status = \'armed\'',
      session.value.attemptId,
      await sha256Hex(value.state),
      session.value.expiresAt,
      Date.now(),
    );
    if (updated.rowsWritten !== 1) fail('session_replayed');
    return json({
      schemaVersion: 1,
      attemptId: session.value.attemptId,
      verifier: session.value.verifier,
    });
  }

  async fetch(request) {
    try {
      this.initialize();
      const url = new URL(request.url);
      if (request.method === 'POST' && url.pathname === '/start') return await this.start();
      if (request.method === 'POST' && url.pathname === '/consume') return await this.consume(request);
    } catch (error) {
      return json({ schemaVersion: 1, error: fixedFailure(error) }, 409);
    }
    return new Response(null, { status: 404 });
  }
}

async function stateCall(env, pathname, body) {
  let stub;
  try {
    stub = env.CANARY_STATE.get(env.CANARY_STATE.idFromName('v1'));
  } catch {
    fail('state_unavailable');
  }
  const response = await stub.fetch(new Request(`https://canary-state.invalid${pathname}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body ?? {}),
  }));
  const value = await readBoundedJson(response, 16 * 1024);
  if (response.status !== 200 || !isRecord(value)) fail('state_unavailable');
  return value;
}

function sameOriginMutation(request) {
  const url = new URL(request.url);
  return request.headers.get('origin') === url.origin &&
    (request.headers.get('content-type') ?? '').toLowerCase().startsWith('application/x-www-form-urlencoded');
}

function validAuthorizationUrl(value, config, challenge) {
  try {
    const url = new URL(value);
    const redirect = new URL(url.searchParams.get('redirect_uri') ?? '');
    const expectedRelay = new URL(config.relayStartUrl);
    const scopes = [...new Set((url.searchParams.get('scope') ?? '').split(/\s+/u).filter(Boolean))].sort();
    const keys = [...url.searchParams.keys()];
    const expectedKeys = [
      'response_type', 'client_id', 'redirect_uri', 'scope', 'state',
      'code_challenge', 'code_challenge_method',
    ];
    return url.origin + url.pathname === 'https://dash.cloudflare.com/oauth2/auth' &&
      keys.length === expectedKeys.length && new Set(keys).size === keys.length &&
      expectedKeys.every((key) => keys.includes(key)) &&
      url.searchParams.get('response_type') === 'code' &&
      url.searchParams.get('client_id') === config.clientId &&
      scopes.length === EXACT_SCOPES.length && scopes.every((scope, index) => scope === EXACT_SCOPES[index]) &&
      url.searchParams.get('code_challenge') === challenge &&
      url.searchParams.get('code_challenge_method') === 'S256' &&
      redirect.origin === expectedRelay.origin && redirect.pathname === '/oauth/callback' &&
      redirect.search === '' && redirect.hash === '';
  } catch {
    return false;
  }
}

async function oauthStart(request, env, config) {
  if (!sameOriginMutation(request)) return json({ schemaVersion: 1, error: 'forbidden' }, 403);
  const started = await stateCall(env, '/start');
  if (!BASE64_TOKEN.test(started.state ?? '') || !BASE64_TOKEN.test(started.challenge ?? '') ||
      !Number.isSafeInteger(started.expiresAt) || !isString(started.cookie)) {
    fail('state_unavailable');
  }
  const relay = await requestJson(config.relayStartUrl, {
    method: 'POST',
    headers: { accept: 'application/json', 'content-type': 'application/json' },
    body: JSON.stringify({
      relayTicket: config.relayTicket,
      gatewayState: started.state,
      pkceChallenge: started.challenge,
      gatewayCallback: config.callbackUrl,
    }),
  }, MAX_RELAY_BYTES);
  if (relay.status !== 200 || !exactKeys(relay.value, ['authorizationUrl', 'schemaVersion']) ||
      relay.value.schemaVersion !== 1 || !validAuthorizationUrl(
        relay.value.authorizationUrl,
        config,
        started.challenge,
      )) fail('relay_rejected');
  const maxAge = Math.max(1, Math.min(
    COOKIE_TTL_SECONDS,
    Math.ceil((started.expiresAt - Date.now()) / 1_000),
  ));
  const headers = secureHeaders('text/plain; charset=utf-8');
  headers.set('location', relay.value.authorizationUrl);
  headers.append(
    'set-cookie',
    `${COOKIE_NAME}=${started.cookie}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=${maxAge}`,
  );
  return new Response('Continue to Cloudflare.', { status: 303, headers });
}

async function oauthCallback(request, env, config) {
  const url = new URL(request.url);
  let accessToken;
  let refreshToken;
  let lifecycle;
  let failure = null;
  let revocation = 'not_attempted';
  try {
    const code = url.searchParams.get('code') ?? '';
    const state = url.searchParams.get('state') ?? '';
    if (url.searchParams.get('error') === 'authorization_rejected' &&
        url.searchParams.size === 2 && BASE64_TOKEN.test(state)) {
      fail('oauth_authorization_rejected');
    }
    if (url.searchParams.size !== 2 || !validAuthorizationCode(code) || !BASE64_TOKEN.test(state)) {
      fail('oauth_callback_invalid');
    }
    const cookie = parseCookie(request);
    if (!isString(cookie)) fail('session_missing');
    const consumed = await stateCall(env, '/consume', { cookie, state });
    if (!BASE64_TOKEN.test(consumed.attemptId ?? '') || !BASE64_TOKEN.test(consumed.verifier ?? '')) {
      fail('session_invalid');
    }
    const exchanged = await exchangeCode(config, code, consumed.verifier);
    accessToken = exchanged.accessToken;
    refreshToken = exchanged.refreshToken;
    if (!TOKEN.test(accessToken ?? '') || exchanged.tokenType !== 'bearer' ||
        exchanged.scopes.length !== EXACT_SCOPES.length ||
        !exchanged.scopes.every((scope, index) => scope === EXACT_SCOPES[index])) {
      fail('oauth_grant_invalid');
    }
    if (refreshToken !== undefined) fail('unexpected_refresh_token');
    lifecycle = await runLifecycle(accessToken, config, url.origin);
  } catch (error) {
    failure = { code: error instanceof CanaryError ? error.code : 'internal_failure', detail: error instanceof CanaryError ? error.detail : 'none' };
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
  if (failure === null && lifecycle !== undefined && revocation !== 'confirmed') {
    failure = { code: 'oauth_revoke_failed', detail: 'none' };
  }
  const passed = failure === null && lifecycle !== undefined && revocation === 'confirmed';
  const output = passed
    ? {
      outcome: 'passed',
      trustBoundary: {
        relay: 'code_only_no_verifier_no_exchange',
        token: 'customer_gateway_request_memory_only',
        refreshToken: 'not_issued',
      },
      lifecycle,
      tokenRevocation: revocation,
    }
    : { outcome: 'failed', failure, tokenRevocation: revocation };
  return page(
    passed ? 'Stage 2 canary passed' : 'Stage 2 canary failed',
    `<pre>${escapeHtml(JSON.stringify(output, null, 2))}</pre>`,
    passed ? 200 : 500,
    [clearCookie()],
  );
}

function configHealth(env) {
  const account = ACCOUNT_ID.test(env.CANARY_EXPECTED_ACCOUNT_ID ?? '');
  const admin = EMAIL.test(env.CANARY_ADMIN_EMAIL ?? '') &&
    env.CANARY_ADMIN_EMAIL === env.CANARY_ADMIN_EMAIL?.toLowerCase();
  const callback = validHttpsUrl(
    env.CANARY_GATEWAY_CALLBACK_URL ?? '',
    '/__ankka/install/oauth/callback',
  );
  const client = CLIENT_ID.test(env.CANARY_PUBLIC_CLIENT_ID ?? '');
  const relay = validHttpsUrl(env.CANARY_RELAY_START_URL ?? '', '/oauth/start/install');
  const ticket = RELAY_TICKET.test(env.CANARY_RELAY_TICKET ?? '');
  const worker = WORKER_NAME.test(env.CANARY_WORKER_NAME ?? '');
  const relayWorker = WORKER_NAME.test(env.CANARY_RELAY_WORKER_NAME ?? '');
  const zone = HOSTNAME.test(env.CANARY_EXPECTED_ZONE_NAME ?? '') &&
    env.CANARY_EXPECTED_ZONE_NAME === env.CANARY_EXPECTED_ZONE_NAME?.toLowerCase();
  const durableObject = Boolean(env.CANARY_STATE);
  let callbackHost = false;
  let relayHost = false;
  if (callback && worker) {
    const hostname = new URL(env.CANARY_GATEWAY_CALLBACK_URL).hostname;
    callbackHost = validWorkerHostname(hostname, env.CANARY_WORKER_NAME);
  }
  if (relay && relayWorker) {
    relayHost = validWorkerHostname(
      new URL(env.CANARY_RELAY_START_URL).hostname,
      env.CANARY_RELAY_WORKER_NAME,
    );
  }
  const configured = account && admin && callback && callbackHost && client && relay && relayHost &&
    ticket && worker && zone && durableObject;
  return {
    schemaVersion: 1,
    revision: CANARY_REVISION,
    configured,
    account,
    admin,
    callback,
    callbackHost,
    client,
    relay,
    relayHost,
    ticket,
    worker,
    zone,
    durableObject,
  };
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (request.method === 'GET' && url.pathname === '/config-health') {
      return json(configHealth(env));
    }
    if (request.method === 'POST' && url.pathname === '/mcp') {
      return json({ jsonrpc: '2.0', id: null, result: { tools: [{ name: 'canary_ping' }] } });
    }
    let config;
    try {
      config = parseConfig(env);
      if (url.origin !== new URL(config.callbackUrl).origin) fail('canary_config_invalid');
    } catch {
      return page('Canary not configured', '<p>The disposable customer Gateway bindings are incomplete.</p>', 503);
    }
    try {
      if (request.method === 'GET' && url.pathname === '/') {
        return page(
          'Ankka Stage 2 lifecycle canary',
          '<p>This requests the fixed temporary Stage 2 grant and keeps it only inside this customer Gateway invocation.</p><form method="post" action="/oauth/start"><button type="submit">Run Stage 2 qualification</button></form>',
        );
      }
      if (request.method === 'GET' && url.pathname === '/run') {
        return await oauthStart(new Request(`${url.origin}/oauth/start`, {
          method: 'POST',
          headers: {
            origin: url.origin,
            'content-type': 'application/x-www-form-urlencoded',
          },
          body: '',
        }), env, config);
      }
      if (request.method === 'GET' && url.pathname === '/health') {
        return json({ schemaVersion: 1, role: 'customer-gateway-bootstrap', state: 'incomplete' });
      }
      if (request.method === 'POST' && url.pathname === '/oauth/start') {
        return await oauthStart(request, env, config);
      }
      if (request.method === 'GET' && url.pathname === '/__ankka/install/oauth/callback') {
        return await oauthCallback(request, env, config);
      }
    } catch (error) {
      return page(
        'Stage 2 canary unavailable',
        `<pre>${escapeHtml(JSON.stringify({ outcome: 'failed', failure: fixedFailure(error) }, null, 2))}</pre>`,
        500,
        [clearCookie()],
      );
    }
    return new Response(null, { status: 404, headers: secureHeaders('text/plain; charset=utf-8') });
  },
};

/**
 * Disposable code-only relay for the live Stage 2 qualification.
 *
 * This module intentionally contains no OAuth token endpoint, client secret,
 * provider API transport, or generic redirect. It accepts one fixed `install`
 * operation, maps it to the reviewed scope ceiling, and relays only the code
 * to the exact customer Gateway callback signed into the short-lived ticket.
 */

const AUTHORIZE_URL = 'https://dash.cloudflare.com/oauth2/auth';
const EXACT_SCOPES = Object.freeze([
  'access-acct.read',
  'zone-access.write',
  'dns.write',
  'mcp-portals.write',
  'workers-routes.read',
  'workers-scripts.write',
  'zone.read',
]);
const START_PATH = '/oauth/start/install';
const CALLBACK_PATH = '/oauth/callback';
const TICKET_CONTEXT = 'ankka-live-stage2-relay-ticket-v1';
const STATE_CONTEXT = 'ankka-live-stage2-relay-state-v1';
const MAX_BODY_BYTES = 8 * 1024;
const MAX_STATE_BYTES = 8 * 1024;
// Canary-only allowance for a human completing Cloudflare consent while the
// verifier remains sealed in the customer Worker. Production keeps its tighter TTL.
const STATE_TTL_MS = 30 * 60 * 1_000;

const ACCOUNT_ID = /^[a-f0-9]{32}$/u;
const INSTALL_ID = /^acg-[a-f0-9]{24}$/u;
const WORKER_NAME = /^[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$/u;
const CLIENT_ID = /^[A-Za-z0-9_-]{16,128}$/u;
const TOKEN = /^[A-Za-z0-9_-]{43}$/u;
const PROVIDER_ERROR = /^[A-Za-z0-9._~-]{1,128}$/u;

const encoder = new TextEncoder();
const decoder = new TextDecoder('utf-8', { fatal: true });

class RelayError extends Error {}

function fail() {
  throw new RelayError('relay_rejected');
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

function exactQueryKeys(params, expected) {
  const actual = [...params.keys()].sort();
  const wanted = [...expected].sort();
  return actual.length === wanted.length && actual.every((key, index) => key === wanted[index]);
}

function base64Url(bytes) {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/u, '');
}

function decodeBase64Url(value) {
  if (!/^[A-Za-z0-9_-]+$/u.test(value)) fail();
  const padding = '='.repeat((4 - (value.length % 4)) % 4);
  let binary;
  try {
    binary = atob(value.replaceAll('-', '+').replaceAll('_', '/') + padding);
  } catch {
    fail();
  }
  const bytes = Uint8Array.from(binary, (character) => character.charCodeAt(0));
  if (base64Url(bytes) !== value) fail();
  return bytes;
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

function keyBytes(value) {
  const bytes = decodeBase64Url(value);
  if (bytes.byteLength !== 32 || !TOKEN.test(value)) fail();
  return bytes;
}

async function hmac(encodedKey, context, payload) {
  const bytes = keyBytes(encodedKey);
  try {
    const key = await crypto.subtle.importKey(
      'raw', bytes, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign'],
    );
    return base64Url(new Uint8Array(await crypto.subtle.sign(
      'HMAC', key, encoder.encode(`${context}.${payload}`),
    )));
  } finally {
    bytes.fill(0);
  }
}

function canonical(value) {
  if (value === null || isString(value) || isBoolean(value)) {
    return JSON.stringify(value);
  }
  if (isNumber(value)) {
    if (!Number.isFinite(value)) fail();
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (isRecord(value)) {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(',')}}`;
  }
  fail();
}

function validWorkerHostname(hostname, workerName) {
  return hostname === `${workerName}.ankka.ai` ||
    (hostname.startsWith(`${workerName}.`) && hostname.endsWith('.workers.dev'));
}

function validHttpsCallback(value, workerName) {
  try {
    const url = new URL(value);
    return url.protocol === 'https:' && url.username === '' && url.password === '' && url.port === '' &&
      url.pathname === '/__ankka/install/oauth/callback' && url.search === '' && url.hash === '' &&
      url.hostname === url.hostname.toLowerCase() && validWorkerHostname(url.hostname, workerName);
  } catch {
    return false;
  }
}

function parseConfig(env) {
  const value = {
    accountId: env.CANARY_EXPECTED_ACCOUNT_ID,
    callbackUrl: env.CANARY_RELAY_CALLBACK_URL,
    clientId: env.CANARY_PUBLIC_CLIENT_ID,
    gatewayCallback: env.CANARY_GATEWAY_CALLBACK,
    installId: env.CANARY_INSTALL_ID,
    relayStateKey: env.CANARY_RELAY_STATE_KEY,
    relayTicketKey: env.CANARY_RELAY_TICKET_KEY,
    relayWorkerName: env.CANARY_RELAY_WORKER_NAME,
    workerName: env.CANARY_GATEWAY_WORKER_NAME,
  };
  let callback;
  try {
    callback = new URL(value.callbackUrl);
  } catch {
    fail();
  }
  if (!ACCOUNT_ID.test(value.accountId ?? '') || !CLIENT_ID.test(value.clientId ?? '') ||
      !INSTALL_ID.test(value.installId ?? '') || !WORKER_NAME.test(value.workerName ?? '') ||
      !WORKER_NAME.test(value.relayWorkerName ?? '') ||
      !TOKEN.test(value.relayStateKey ?? '') || !TOKEN.test(value.relayTicketKey ?? '') ||
      !validHttpsCallback(value.gatewayCallback ?? '', value.workerName) ||
      callback.protocol !== 'https:' || callback.username !== '' || callback.password !== '' ||
      callback.port !== '' || callback.pathname !== CALLBACK_PATH || callback.search !== '' ||
      callback.hash !== '' || !validWorkerHostname(callback.hostname, value.relayWorkerName)) fail();
  return Object.freeze({ ...value, callbackUrl: callback.href });
}

function ticketClaimsValid(value, config, now) {
  return exactKeys(value, [
    'accountId', 'callback', 'clientId', 'expiresAt', 'installId', 'issuedAt', 'nonce',
    'operation', 'purpose', 'schemaVersion', 'workerName',
  ]) && value.schemaVersion === 1 && value.purpose === 'cloudflare-code-relay' &&
    value.operation === 'install' && value.accountId === config.accountId &&
    value.installId === config.installId && value.workerName === config.workerName &&
    value.callback === config.gatewayCallback && value.clientId === config.clientId &&
    TOKEN.test(value.nonce ?? '') && Number.isSafeInteger(value.issuedAt) &&
    Number.isSafeInteger(value.expiresAt) && value.issuedAt <= now && value.expiresAt > now &&
    value.expiresAt - value.issuedAt <= 15 * 60 * 1_000;
}

async function verifyTicket(ticket, config, now) {
  const parts = ticket.split('.');
  if (parts.length !== 2 || parts[0].length > 4096 || !TOKEN.test(parts[1] ?? '')) fail();
  const [payload, supplied] = parts;
  if (!payload || !supplied || !constantTimeEqual(
    supplied,
    await hmac(config.relayTicketKey, TICKET_CONTEXT, payload),
  )) fail();
  let value;
  try {
    value = JSON.parse(decoder.decode(decodeBase64Url(payload)));
  } catch {
    fail();
  }
  if (!ticketClaimsValid(value, config, now) || canonical(value) !== decoder.decode(decodeBase64Url(payload))) {
    fail();
  }
  return Object.freeze({ ...value });
}

async function sealState(value, key) {
  const payload = base64Url(encoder.encode(canonical(value)));
  return `${payload}.${await hmac(key, STATE_CONTEXT, payload)}`;
}

async function openState(serialized, key, now, workerName) {
  if (serialized.length > MAX_STATE_BYTES) fail();
  const parts = serialized.split('.');
  if (parts.length !== 2 || !parts[0] || !TOKEN.test(parts[1] ?? '') ||
      !constantTimeEqual(parts[1], await hmac(key, STATE_CONTEXT, parts[0]))) fail();
  let value;
  try {
    value = JSON.parse(decoder.decode(decodeBase64Url(parts[0])));
  } catch {
    fail();
  }
  if (!exactKeys(value, [
    'accountId', 'callback', 'expiresAt', 'gatewayState', 'installId', 'nonce',
    'operation', 'purpose', 'schemaVersion',
  ]) || value.schemaVersion !== 1 || value.purpose !== 'cloudflare-code-relay-state' ||
      value.operation !== 'install' || !ACCOUNT_ID.test(value.accountId ?? '') ||
      !INSTALL_ID.test(value.installId ?? '') || !TOKEN.test(value.gatewayState ?? '') ||
      !TOKEN.test(value.nonce ?? '') || !Number.isSafeInteger(value.expiresAt) ||
      value.expiresAt <= now || !validHttpsCallback(value.callback ?? '', workerName)) {
    fail();
  }
  return Object.freeze({ ...value });
}

function headers(contentType = 'application/json; charset=utf-8') {
  return new Headers({
    'cache-control': 'no-store, max-age=0',
    'content-security-policy': "default-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'",
    'content-type': contentType,
    expires: '0',
    pragma: 'no-cache',
    'referrer-policy': 'no-referrer',
    'x-content-type-options': 'nosniff',
  });
}

function json(value, status = 200) {
  return new Response(JSON.stringify(value), { status, headers: headers() });
}

function redirect(location) {
  const responseHeaders = headers('text/plain; charset=utf-8');
  responseHeaders.set('location', location);
  return new Response('Continue to the customer Gateway.', { status: 302, headers: responseHeaders });
}

async function readStart(request) {
  if (!(request.headers.get('content-type') ?? '').toLowerCase().startsWith('application/json')) fail();
  const declared = request.headers.get('content-length');
  if (declared !== null && (!Number.isSafeInteger(Number(declared)) || Number(declared) > MAX_BODY_BYTES)) fail();
  const text = await request.text();
  if (text.length > MAX_BODY_BYTES) fail();
  let value;
  try {
    value = JSON.parse(text);
  } catch {
    fail();
  }
  if (!exactKeys(value, ['gatewayCallback', 'gatewayState', 'pkceChallenge', 'relayTicket']) ||
      !TOKEN.test(value.gatewayState ?? '') || !TOKEN.test(value.pkceChallenge ?? '') ||
      !isString(value.relayTicket) || value.relayTicket.length > 4096) fail();
  return value;
}

async function start(request, config) {
  const body = await readStart(request);
  if (body.gatewayCallback !== config.gatewayCallback) fail();
  const ticket = await verifyTicket(body.relayTicket, config, Date.now());
  const state = await sealState({
    schemaVersion: 1,
    purpose: 'cloudflare-code-relay-state',
    operation: 'install',
    accountId: ticket.accountId,
    installId: ticket.installId,
    callback: ticket.callback,
    gatewayState: body.gatewayState,
    nonce: ticket.nonce,
    expiresAt: Date.now() + STATE_TTL_MS,
  }, config.relayStateKey);
  const authorize = new URL(AUTHORIZE_URL);
  authorize.searchParams.set('response_type', 'code');
  authorize.searchParams.set('client_id', config.clientId);
  authorize.searchParams.set('redirect_uri', config.callbackUrl);
  authorize.searchParams.set('scope', EXACT_SCOPES.join(' '));
  authorize.searchParams.set('state', state);
  authorize.searchParams.set('code_challenge', body.pkceChallenge);
  authorize.searchParams.set('code_challenge_method', 'S256');
  return json({ schemaVersion: 1, authorizationUrl: authorize.href });
}

async function callback(url, config) {
  const stateValue = url.searchParams.get('state') ?? '';
  const state = await openState(stateValue, config.relayStateKey, Date.now(), config.workerName);
  if (state.accountId !== config.accountId || state.installId !== config.installId ||
      state.callback !== config.gatewayCallback) fail();
  const location = new URL(state.callback);
  if (url.searchParams.has('code')) {
    const hasScopeEcho = url.searchParams.has('scope');
    if (!exactQueryKeys(
      url.searchParams,
      hasScopeEcho ? ['code', 'scope', 'state'] : ['code', 'state'],
    )) fail();
    if (hasScopeEcho && url.searchParams.get('scope') !== EXACT_SCOPES.join(' ')) fail();
    const code = url.searchParams.get('code') ?? '';
    if (!validAuthorizationCode(code)) fail();
    location.searchParams.set('code', code);
    location.searchParams.set('state', state.gatewayState);
    return redirect(location.href);
  }
  const allowed = new Set(['error', 'error_description', 'error_uri', 'state']);
  if (!url.searchParams.has('error') || !PROVIDER_ERROR.test(url.searchParams.get('error') ?? '') ||
      [...url.searchParams.keys()].some((key) => !allowed.has(key))) fail();
  location.searchParams.set('error', 'authorization_rejected');
  location.searchParams.set('state', state.gatewayState);
  return redirect(location.href);
}

export default {
  async fetch(request, env) {
    let url;
    try {
      url = new URL(request.url);
    } catch {
      return json({ schemaVersion: 1, error: 'not_found' }, 404);
    }
    if (request.method === 'GET' && url.pathname === '/health') {
      let configured = true;
      try {
        parseConfig(env);
      } catch {
        configured = false;
      }
      return json({ schemaVersion: 1, role: 'code-only-relay', configured });
    }
    let config;
    try {
      config = parseConfig(env);
      if (url.origin !== new URL(config.callbackUrl).origin || url.hash !== '') fail();
      if (request.method === 'POST' && url.pathname === START_PATH && url.search === '') {
        return await start(request, config);
      }
      if (request.method === 'GET' && url.pathname === CALLBACK_PATH) {
        return await callback(url, config);
      }
    } catch {
      return json({ schemaVersion: 1, error: 'relay_rejected' }, 400);
    }
    return json({ schemaVersion: 1, error: 'not_found' }, 404);
  },
};

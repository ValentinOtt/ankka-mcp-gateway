/**
 * Shared lifecycle fixture for the release payload tests.
 *
 * It runs the real primary Worker against a deterministic explicit-model
 * Cloudflare fake and hands the produced Durable Object storage, the exact
 * ready receipt, and the same provider state to the cleanup tests. The cleanup
 * tests never construct their starting state by hand.
 */
import assert from 'node:assert/strict';
import * as v from 'valibot';

import primaryWorker, { AdminState as PrimaryAdminState } from '../payload/worker/index.js';

export const ACCOUNT_ID = '1'.repeat(32);
export const ZONE_ID = '2'.repeat(32);
export const ZONE_NAME = 'example.com';
export const HOSTNAME = 'mcp.example.com';
export const GATEWAY_NAME = 'Example Gateway';
export const SOURCE_LABEL = 'Company context';
export const SOURCE_URL = 'https://source.example.net/mcp';
export const RELEASE = 'gateway-v0.1.0';
export const RELEASE_SHA256 = `sha256:${'9'.repeat(64)}`;
export const INSTALLATION_ID = 'acg-361551cea347ce8d598c04f7';
export const DESIRED_HASH = 'sha256:5a3c7ce6eaa1717711e35a27616cdaaa68814b78c1f34e0c84917f45c6c3edd3';
export const CONFIGURATION_HASH = 'sha256:adef4aee1b0500faf61c3d169c3ed0a0554ba0848e703ee3fa727fcd12a782cc';
export const BOOTSTRAP_NONCE_BYTES = Uint8Array.from({ length: 32 }, (_, index) => index + 1);
export const BOOTSTRAP_NONCE = Buffer.from(BOOTSTRAP_NONCE_BYTES).toString('base64url');
export const UNINSTALL_NONCE_BYTES = Uint8Array.from({ length: 32 }, (_, index) => 200 - index);
export const UNINSTALL_NONCE = Buffer.from(UNINSTALL_NONCE_BYTES).toString('base64url');
export const BOOTSTRAP_GRANT = 'synthetic-cloudflare-grant-never-store';
export const UNINSTALL_GRANT = 'synthetic-uninstall-grant-never-store';
export const STORAGE_KEY = 'ankka-mcp-gateway/uninstall-state/v1';
export const DURABLE_OBJECT_NAME = `v1:${INSTALLATION_ID}`;
export const RESOURCE_ORDER = Object.freeze([
  'mcp_server',
  'source_access_application',
  'source_access_policy',
  'portal',
  'portal_access_application',
  'portal_access_policy',
  'dns_record',
]);
export const PORTAL_RESOURCE_ORDER = Object.freeze([
  'portal',
  'portal_access_application',
  'portal_access_policy',
  'dns_record',
]);
export const DELETE_ORDER = Object.freeze([...RESOURCE_ORDER].reverse());
export const MANAGED_OAUTH = Object.freeze({
  enabled: true,
  dynamic_client_registration: {
    enabled: true,
    allow_any_on_localhost: true,
    allow_any_on_loopback: true,
  },
  grant: { access_token_lifetime: '15m', session_duration: '336h' },
});

const API = 'https://api.cloudflare.com';
const SERVERS = `/client/v4/accounts/${ACCOUNT_ID}/access/ai-controls/mcp/servers`;
const PORTALS = `/client/v4/accounts/${ACCOUNT_ID}/access/ai-controls/mcp/portals`;
const APPS = `/client/v4/zones/${ZONE_ID}/access/apps`;
const DNS = `/client/v4/zones/${ZONE_ID}/dns_records`;
const canonicalPrimitiveSchema = v.union([v.null(), v.boolean(), v.string()]);
const canonicalNumberSchema = v.pipe(v.number(), v.finite());
const canonicalRecordSchema = v.record(v.string(), v.unknown());

export function compareText(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
}

export function canonicalJson(value) {
  if (v.is(canonicalPrimitiveSchema, value) || v.is(canonicalNumberSchema, value)) {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (v.is(canonicalRecordSchema, value) && Object.getPrototypeOf(value) === Object.prototype) {
    return `{${Object.keys(value).sort(compareText).map(
      (key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`,
    ).join(',')}}`;
  }
  throw new TypeError('not canonical');
}

export async function prefixedSha256(value) {
  const serialized = v.is(v.string(), value) ? value : canonicalJson(value);
  const digest = new Uint8Array(await crypto.subtle.digest(
    'SHA-256',
    new TextEncoder().encode(serialized),
  ));
  return `sha256:${Buffer.from(digest).toString('hex')}`;
}

export async function hmac(rawBody, keyBytes) {
  const key = await crypto.subtle.importKey(
    'raw', keyBytes, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign'],
  );
  const digest = new Uint8Array(await crypto.subtle.sign(
    'HMAC', key, new TextEncoder().encode(rawBody),
  ));
  return `sha256=${Buffer.from(digest).toString('hex')}`;
}

export function marker(key) {
  return `acg:v1:${INSTALLATION_ID}:${key}`;
}

export function memoryStorage(initial) {
  const values = new Map(initial === undefined ? [] : [[STORAGE_KEY, structuredClone(initial)]]);
  const writes = [];
  return {
    writes,
    async get(key) {
      const value = values.get(key);
      return value === undefined ? undefined : structuredClone(value);
    },
    async put(key, value) {
      // Durable Object multi-key puts are atomic. Clone/validate the entire
      // batch before exposing any entry, preserving the single-key write log.
      // oxlint-disable-next-line anti-slop/no-runtime-typeof -- Storage API overload boundary: string key/value or a multi-key entries object.
      const entries = structuredClone(typeof key === 'string' ? [[key, value]] : Object.entries(key));
      for (const [entryKey, owned] of entries) {
        values.set(entryKey, owned);
        writes.push({ key: entryKey, value: structuredClone(owned) });
      }
    },
    snapshot(key = STORAGE_KEY) {
      const value = values.get(key);
      return value === undefined ? undefined : structuredClone(value);
    },
  };
}

/**
 * A Durable Object namespace fake. `objects` maps the namespace name to its
 * storage and survives a change of Worker class, which is exactly how the
 * cleanup release is bound to the primary Worker's existing namespace.
 */
export function durableNamespace(env, AdminStateClass, objects = new Map()) {
  return {
    objects,
    idFromName(name) { return name; },
    get(name) {
      if (!objects.has(name)) objects.set(name, { storage: memoryStorage() });
      const entry = objects.get(name);
      const instance = new AdminStateClass({ storage: entry.storage }, env);
      return { fetch: (request) => instance.fetch(request) };
    },
  };
}

export function primaryEnvironment({ objects, bindings = {} } = {}) {
  const env = {
    CLOUDFLARE_ACCOUNT_ID: ACCOUNT_ID,
    CLOUDFLARE_ZONE_ID: ZONE_ID,
    CLOUDFLARE_ZONE_NAME: ZONE_NAME,
    ANKKA_INSTALL_ID: INSTALLATION_ID,
    ANKKA_GATEWAY_RELEASE: RELEASE,
    ANKKA_GATEWAY_RELEASE_SHA256: RELEASE_SHA256,
    ANKKA_MANAGEMENT_HOSTNAME: 'manage.example.com',
    ANKKA_UPDATE_CHANNEL: 'stable',
    ANKKA_UPDATE_KEY_ID: 'test-release-key',
    ANKKA_UPDATE_PUBLIC_KEY: 'A'.repeat(43),
    ANKKA_WORKERS_SUBDOMAIN: 'tenant',
    ANKKA_WORKER_NAME: 'ankka-gateway-test',
    ZERO_TRUST_READY: 'true',
    ANKKA_BOOTSTRAP_NONCE: BOOTSTRAP_NONCE,
    ADMIN_EMAILS: 'admin@example.com,owner@example.com',
    CF_ACCESS_AUD: 'access-audience-tag',
    CF_ACCESS_ISSUER: 'https://tenant.cloudflareaccess.com',
    ...bindings,
  };
  env.ADMIN_STATE = durableNamespace(env, PrimaryAdminState, objects);
  return env;
}

export function cleanupEnvironment(extra = {}) {
  return {
    CLOUDFLARE_ACCOUNT_ID: ACCOUNT_ID,
    CLOUDFLARE_ZONE_ID: ZONE_ID,
    CLOUDFLARE_ZONE_NAME: ZONE_NAME,
    ANKKA_INSTALL_ID: INSTALLATION_ID,
    ANKKA_GATEWAY_RELEASE: RELEASE,
    ANKKA_GATEWAY_RELEASE_SHA256: RELEASE_SHA256,
    ZERO_TRUST_READY: 'true',
    ANKKA_UNINSTALL_NONCE: UNINSTALL_NONCE,
    ...extra,
  };
}

/** The hosted installer's golden bootstrap claim. */
export function goldenClaim(requestId = 'A'.repeat(22)) {
  const now = Math.floor(Date.now() / 1_000);
  return {
    schemaVersion: 1,
    requestId,
    issuedAt: now,
    expiresAt: now + 300,
    settingsRevision: 1,
    settings: {
      schemaVersion: 1,
      connect: { name: GATEWAY_NAME, hostname: HOSTNAME, codeMode: 'default_on' },
      access: {
        adminEmails: ['admin@example.com'],
        memberEmails: ['member@example.com', 'owner@example.com'],
      },
      sources: [{
        id: 'company-context',
        label: SOURCE_LABEL,
        url: SOURCE_URL,
        authentication: { mode: 'none', onBehalfOfUser: false },
        enabledTools: ['company_prepare', 'company_search'],
      }],
    },
    target: { accountId: ACCOUNT_ID, zoneId: ZONE_ID, zoneName: ZONE_NAME },
    release: { id: RELEASE, artifactSha256: RELEASE_SHA256 },
    expected: {
      configurationHash: CONFIGURATION_HASH,
      installationId: INSTALLATION_ID,
      desiredHash: DESIRED_HASH,
    },
    cloudflareAccessToken: BOOTSTRAP_GRANT,
  };
}

async function stableResourceKey(prefix, installationId, logicalId) {
  const digest = (await prefixedSha256({ installationId, prefix, logicalId })).slice('sha256:'.length);
  const hint = logicalId.toLowerCase().replace(/[^a-z0-9-]+/gu, '-').replace(/^-+|-+$/gu, '');
  const hintLength = Math.max(0, 32 - prefix.length - 10);
  const cut = hint.slice(0, hintLength).replace(/-+$/gu, '');
  return cut && hintLength > 0
    ? `${prefix}-${cut}-${digest.slice(0, 8)}`
    : `${prefix}-${digest.slice(0, 32 - prefix.length - 1)}`;
}

export async function derivedBootstrapClaim(
  settings,
  requestId,
  cloudflareAccessToken,
  target = { accountId: ACCOUNT_ID, zoneId: ZONE_ID, zoneName: ZONE_NAME },
  release = { id: RELEASE, artifactSha256: RELEASE_SHA256 },
) {
  const installationDigest = (await prefixedSha256({
    hostname: settings.connect.hostname, accountId: ACCOUNT_ID, zoneId: ZONE_ID,
  })).slice('sha256:'.length);
  const installationId = `acg-${installationDigest.slice(0, 24)}`;
  const allowedEmails = [...settings.access.adminEmails, ...settings.access.memberEmails].sort(compareText);
  const identitiesHash = await prefixedSha256({ emails: allowedEmails });
  const metadata = { manager: 'ankka-mcp-gateway', installationId };
  const emailAllowPolicy = {
    identitiesRef: 'access.allowedEmails', identityType: 'email',
    identityCount: allowedEmails.length, identitiesHash,
  };
  const source = settings.sources[0] ?? null;
  const mcpKey = source === null ? null : await stableResourceKey('mcp', installationId, source.id);
  const sourceApplicationKey = source === null
    ? null
    : await stableResourceKey('source-app', installationId, source.id);
  const sourceAccessKey = source === null
    ? null
    : await stableResourceKey('source-access', installationId, source.id);
  const portalKey = await stableResourceKey('portal', installationId, settings.connect.hostname);
  const portalApplicationKey = await stableResourceKey(
    'portal-app', installationId, settings.connect.hostname,
  );
  const portalAccessKey = await stableResourceKey(
    'portal-access', installationId, settings.connect.hostname,
  );
  const dnsKey = await stableResourceKey('dns', installationId, settings.connect.hostname);
  const sourceMappings = source === null ? [] : [{
    sourceResourceKey: mcpKey,
    defaultDisabled: true,
    allowedTools: [...source.enabledTools].sort(compareText),
    onBehalfOfUser: source.authentication.onBehalfOfUser,
  }];
  const sourceSpecifications = source === null ? [] : [
    { kind: 'mcp_server', key: mcpKey, desired: {
      metadata, sourceId: source.id, name: source.label, endpoint: source.url,
      capabilityMode: 'read_only', secureWebGateway: false,
      toolPolicy: { defaultDisabled: true, allowedTools: [...source.enabledTools].sort(compareText) },
      authentication: {
        mode: source.authentication.mode,
        onBehalfOfUser: source.authentication.onBehalfOfUser,
        credentialCustody: 'customer',
      },
    } },
    { kind: 'source_access_application', key: sourceApplicationKey, desired: {
      metadata, sourceResourceKey: mcpKey, applicationType: 'mcp',
    } },
    { kind: 'source_access_policy', key: sourceAccessKey, desired: {
      metadata, sourceApplicationResourceKey: sourceApplicationKey,
      defaultAction: 'deny', allow: emailAllowPolicy,
    } },
  ];
  const specifications = [
    ...sourceSpecifications,
    { kind: 'portal', key: portalKey, desired: {
      metadata, name: settings.connect.name, hostname: settings.connect.hostname,
      capabilityMode: 'read_only', codeMode: settings.connect.codeMode,
      secureWebGateway: false, sourceMappings,
    } },
    { kind: 'portal_access_application', key: portalApplicationKey, desired: {
      metadata, portalResourceKey: portalKey, name: settings.connect.name,
      hostname: settings.connect.hostname, applicationType: 'mcp_portal',
      destination: { type: 'public', uri: settings.connect.hostname },
      authentication: {
        mode: 'managed_oauth',
        dynamicClientRegistration: { enabled: true, allowAnyOnLocalhost: true, allowAnyOnLoopback: true },
        grant: { accessTokenLifetime: '15m', sessionDuration: '336h' },
      },
    } },
    { kind: 'portal_access_policy', key: portalAccessKey, desired: {
      metadata, portalApplicationResourceKey: portalApplicationKey,
      defaultAction: 'deny', allow: emailAllowPolicy,
    } },
    { kind: 'dns_record', key: dnsKey, desired: {
      metadata, recordType: 'CNAME', hostname: settings.connect.hostname,
      content: 'gateway.agents.cloudflare.com', proxied: true,
      dependsOnResourceKey: portalKey,
    } },
  ];
  const resources = await Promise.all(specifications.map(async (resource) => ({
    ...resource,
    desiredHash: await prefixedSha256({
      schemaVersion: 1, kind: resource.kind, key: resource.key, desired: resource.desired,
    }),
  })));
  const now = Math.floor(Date.now() / 1_000);
  return {
    schemaVersion: 1, requestId, issuedAt: now, expiresAt: now + 300,
    settingsRevision: 1, settings, target, release,
    expected: {
      configurationHash: await prefixedSha256({ schemaVersion: 1, settingsRevision: 1, settings, target, release }),
      installationId,
      desiredHash: await prefixedSha256({ schemaVersion: 1, installationId, resources }),
    },
    cloudflareAccessToken,
  };
}

/** The current hosted wizard's empty-Portal bootstrap claim. */
export async function portalOnlyClaim(requestId = 'A'.repeat(22), memberEmails = ['owner@example.com']) {
  return derivedBootstrapClaim({
    schemaVersion: 1,
    connect: { name: GATEWAY_NAME, hostname: HOSTNAME, codeMode: 'default_on' },
    access: { adminEmails: ['admin@example.com'], memberEmails },
    sources: [],
  }, requestId, BOOTSTRAP_GRANT);
}

/** A large valid claim with maximum-length fields and more than 51 users. */
export async function maximumBootstrapClaim(requestId = 'A'.repeat(22)) {
  const emailDomain = `${'d'.repeat(185)}.com`;
  const zoneName = `${'z'.repeat(63)}.${'z'.repeat(63)}.${'z'.repeat(61)}`;
  const portalHostname = `${'m'.repeat(63)}.${zoneName}`;
  const memberEmails = Array.from({ length: 60 }, (_value, index) => (
    `m${String(index).padStart(2, '0')}${'x'.repeat(61)}@${emailDomain}`
  ));
  const sourceUrlPrefix = 'https://source.example.net/';
  return derivedBootstrapClaim({
    schemaVersion: 1,
    connect: { name: 'G'.repeat(80), hostname: portalHostname, codeMode: 'default_on' },
    access: { adminEmails: [`${'a'.repeat(64)}@${emailDomain}`], memberEmails },
    sources: [{
      id: 'company-context',
      label: 'S'.repeat(80),
      url: `${sourceUrlPrefix}${'p'.repeat(2048 - sourceUrlPrefix.length)}`,
      authentication: { mode: 'none', onBehalfOfUser: false },
      enabledTools: Array.from({ length: 500 }, (_value, index) => (
        `tool_${String(index).padStart(3, '0')}_`.padEnd(128, 'x')
      )),
    }],
  }, requestId, 't'.repeat(16 * 1024), {
    accountId: ACCOUNT_ID,
    zoneId: ZONE_ID,
    zoneName,
  }, {
    id: `gateway-v${'1'.repeat(67)}.1.1`,
    artifactSha256: RELEASE_SHA256,
  });
}

export async function bootstrapRequest(input = goldenClaim()) {
  const body = canonicalJson(input);
  return new Request('https://worker.tenant.workers.dev/__ankka/bootstrap', {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      'x-ankka-bootstrap-signature': await hmac(body, BOOTSTRAP_NONCE_BYTES),
    },
    body,
  });
}

export async function uninstallClaim({
  requestId = 'A'.repeat(22),
  readyReceipt,
  token = UNINSTALL_GRANT,
  configurationHash = CONFIGURATION_HASH,
  installationId = INSTALLATION_ID,
  desiredHash = DESIRED_HASH,
} = {}) {
  assert.ok(readyReceipt, 'an uninstall claim carries the primary-produced ready receipt');
  const now = Math.floor(Date.now() / 1_000);
  return {
    schemaVersion: 1,
    requestId,
    issuedAt: now,
    expiresAt: now + 300,
    target: { accountId: ACCOUNT_ID, zoneId: ZONE_ID, zoneName: ZONE_NAME },
    release: { id: RELEASE, artifactSha256: RELEASE_SHA256 },
    expected: {
      configurationHash,
      installationId,
      desiredHash,
      readyReceipt,
    },
    cloudflareAccessToken: token,
  };
}

export async function uninstallRequest({
  requestId,
  readyReceipt,
  token,
  configurationHash,
  installationId,
  desiredHash,
  rawBody,
  signatureHeader,
  path = '/__ankka/uninstall',
  method = 'POST',
} = {}) {
  const body = rawBody ?? canonicalJson(await uninstallClaim({
    requestId, readyReceipt, token, configurationHash, installationId, desiredHash,
  }));
  const request = {
    method,
    headers: {
      'content-type': 'application/json',
      'x-ankka-uninstall-signature': signatureHeader ?? await hmac(body, UNINSTALL_NONCE_BYTES),
    },
  };
  if (method === 'POST') request.body = body;
  return new Request(`https://${HOSTNAME}${path}`, request);
}

export async function resealReadyReceipt(receipt) {
  const { checksum: _checksum, ...unsigned } = structuredClone(receipt);
  return { ...unsigned, checksum: await prefixedSha256(unsigned) };
}

function envelope(result, status = 200) {
  return new Response(JSON.stringify({
    success: status >= 200 && status < 300,
    errors: [],
    messages: [],
    result,
  }), { status, headers: { 'content-type': 'application/json; charset=utf-8' } });
}

/**
 * Deterministic Cloudflare fake for the explicit seven-resource model.
 *
 * Every resource, including both Access applications, exists only because a
 * POST created it. The same state serves bootstrap reads, uninstall reads, and
 * DELETEs, so a cleanup pass can only succeed by removing exactly what the
 * primary created.
 *
 * Options:
 * - `foreignApps`: Access applications present before bootstrap (collision model).
 * - `stripOauth`: the provider does not expose the Managed OAuth settings on
 *   the created Portal application (incompatible-application model).
 * - `onRequest({ request, state })`: return a Response to intercept, or
 *   throw to model an ambiguous transport outcome.
 */
export function cloudflareProvider({ foreignApps = [], stripOauth = false, onRequest } = {}) {
  const state = {
    server: null,
    servers: new Map(),
    portal: null,
    apps: new Map(foreignApps.map((app) => [app.id, structuredClone(app)])),
    policies: new Map(foreignApps.map((app) => [app.id, []])),
    dns: null,
    requests: [],
  };
  const hooks = { onRequest };
  let appCount = 0;
  let policyCount = 0;
  const appId = () => String.fromCharCode('a'.charCodeAt(0) + appCount++).repeat(32);
  const policyId = () => String.fromCharCode('m'.charCodeAt(0) + policyCount++).repeat(32);
  const readJson = async (request) => JSON.parse(await request.text());

  const providerFetch = async (request) => {
    assert.equal(new URL(request.url).origin, API);
    assert.equal(request.redirect, 'manual');
    assert.match(request.headers.get('authorization') ?? '', /^Bearer \S+$/u);
    const url = new URL(request.url);
    const method = request.method;
    const record = { method, pathname: url.pathname, search: url.search, body: null };
    if (method === 'POST' || method === 'PUT') record.body = await readJson(request.clone());
    state.requests.push(record);
    const intercepted = await hooks.onRequest?.({ request, state, record });
    if (intercepted instanceof Response) return intercepted;
    const { pathname } = url;

    // MCP server
    if (pathname === SERVERS && method === 'POST') {
      const created = { ...record.body, status: 'ready' };
      state.servers.set(created.id, created);
      state.server ??= created;
      return envelope(created);
    }
    if (pathname.startsWith(`${SERVERS}/`)) {
      const id = decodeURIComponent(pathname.slice(SERVERS.length + 1));
      if (method === 'GET') return state.servers.has(id) ? envelope(state.servers.get(id)) : envelope(null, 404);
      if (method === 'DELETE') {
        if (!state.servers.has(id)) return envelope(null, 404);
        state.servers.delete(id);
        if (state.server?.id === id) state.server = null;
        return envelope({ id });
      }
    }

    // Portal
    if (pathname === PORTALS && method === 'POST') {
      state.portal = { ...record.body };
      return envelope(state.portal);
    }
    if (pathname.startsWith(`${PORTALS}/`)) {
      const id = decodeURIComponent(pathname.slice(PORTALS.length + 1));
      if (method === 'GET') return state.portal?.id === id ? envelope(state.portal) : envelope(null, 404);
      if (method === 'PUT') {
        if (state.portal?.id !== id) return envelope(null, 404);
        state.portal = { id, ...record.body };
        return envelope(state.portal);
      }
      if (method === 'DELETE') {
        if (state.portal?.id !== id) return envelope(null, 404);
        state.portal = null;
        return envelope({ id });
      }
    }

    // Access applications and their policies
    if (pathname === APPS && method === 'GET') return envelope([...state.apps.values()]);
    if (pathname === APPS && method === 'POST') {
      const created = { id: appId(), ...record.body };
      if (stripOauth) delete created.oauth_configuration;
      state.apps.set(created.id, created);
      state.policies.set(created.id, []);
      return envelope(created);
    }
    if (pathname.startsWith(`${APPS}/`)) {
      const [id, policies, policyIdentifier] = pathname.slice(APPS.length + 1).split('/');
      if (policies === undefined) {
        if (method === 'GET') return state.apps.has(id) ? envelope(state.apps.get(id)) : envelope(null, 404);
        if (method === 'DELETE') {
          if (!state.apps.has(id)) return envelope(null, 404);
          state.apps.delete(id);
          state.policies.delete(id);
          return envelope({ id });
        }
      }
      if (policies === 'policies') {
        const list = state.policies.get(id);
        if (!list) return envelope(null, 404);
        if (policyIdentifier === undefined && method === 'GET') return envelope(list);
        if (policyIdentifier === undefined && method === 'POST') {
          const created = { id: policyId(), ...record.body };
          list.push(created);
          return envelope(created);
        }
        const index = list.findIndex((policy) => policy.id === policyIdentifier);
        if (method === 'GET') return index === -1 ? envelope(null, 404) : envelope(list[index]);
        if (method === 'DELETE') {
          if (index === -1) return envelope(null, 404);
          list.splice(index, 1);
          return envelope({ id: policyIdentifier });
        }
      }
    }

    // DNS
    if (pathname === DNS && method === 'GET') {
      const name = url.searchParams.get('name.exact');
      return envelope(state.dns && (name === null || state.dns.name === name) ? [state.dns] : []);
    }
    if (pathname === DNS && method === 'POST') {
      state.dns = { id: 'z'.repeat(32), ...record.body };
      return envelope(state.dns);
    }
    if (pathname.startsWith(`${DNS}/`)) {
      const id = pathname.slice(DNS.length + 1);
      if (method === 'GET') return state.dns?.id === id ? envelope(state.dns) : envelope(null, 404);
      if (method === 'DELETE') {
        if (state.dns?.id !== id) return envelope(null, 404);
        state.dns = null;
        return envelope({ id });
      }
    }
    throw new Error(`Unexpected provider request: ${method} ${pathname}`);
  };

  return {
    state,
    fetch: providerFetch,
    intercept(next) { hooks.onRequest = next; },
    requests: state.requests,
    policies: () => state.policies,
    posts: () => state.requests.filter(({ method }) => method === 'POST'),
    deletes: () => state.requests.filter(({ method }) => method === 'DELETE'),
    liveResourceCount: () => state.servers.size + (state.portal ? 1 : 0) + state.apps.size +
      [...state.policies.values()].reduce((total, list) => total + list.length, 0) + (state.dns ? 1 : 0),
  };
}

export async function withProviderFetch(providerFetch, run) {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = providerFetch;
  try {
    return await run();
  } finally {
    globalThis.fetch = originalFetch;
  }
}

/**
 * Runs the real primary Worker to `ready` through its public bootstrap route
 * and returns the produced Durable Object storage, the exact receipt the
 * hosted installer would later present, and the live provider state.
 */
export async function installReadyGateway({
  provider = cloudflareProvider(), objects = new Map(), claimInput = goldenClaim(), environmentBindings = {},
} = {}) {
  const env = primaryEnvironment({ objects, bindings: environmentBindings });
  const request = await bootstrapRequest(claimInput);
  const response = await withProviderFetch(provider.fetch, () => primaryWorker.fetch(request, env));
  assert.equal(response.status, 200, `bootstrap must reach ready: ${await response.clone().text()}`);
  const body = await response.json();
  assert.equal(body.status, 'ready');
  const entry = objects.get(`v1:${claimInput.expected.installationId}`);
  assert.ok(entry, 'bootstrap must populate the installation Durable Object');
  const readyReceipt = entry.storage.snapshot();
  assert.deepEqual(readyReceipt, body.receipt.evidence);
  return { env, objects, provider, body, readyReceipt, storage: entry.storage };
}

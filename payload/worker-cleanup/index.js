const API_ORIGIN = 'https://api.cloudflare.com';
const UNINSTALL_PATH = '/__ankka/uninstall';
const INTERNAL_UNINSTALL_PATH = '/uninstall';
const INTERNAL_SOURCE_UNINSTALL_PATH = '/source-uninstall';
const STORAGE_KEY = 'ankka-mcp-gateway/uninstall-state/v1';
const CONTROL_KEY = 'ankka-mcp-gateway/management-control/v1';
const SOURCES_KEY = 'ankka-mcp-gateway/management-sources/v1';
const SOURCE_CLEANUP_KEY = 'ankka-mcp-gateway/source-cleanup/v1';
const MANAGER = 'ankka-mcp-gateway';
const REQUEST_LIMIT_BYTES = 96 * 1024;
const PROVIDER_RESPONSE_LIMIT_BYTES = 64 * 1024;
const REQUEST_LIFETIME_SECONDS = 5 * 60;
const MAX_CLOCK_SKEW_SECONDS = 30;
const RESOURCE_ORDER = Object.freeze([
  'mcp_server',
  'source_access_application',
  'source_access_policy',
  'portal',
  'portal_access_application',
  'portal_access_policy',
  'dns_record',
]);
const PORTAL_RESOURCE_ORDER = Object.freeze([
  'portal',
  'portal_access_application',
  'portal_access_policy',
  'dns_record',
]);
const HASH = /^sha256:[a-f0-9]{64}$/u;
const INSTALLATION_ID = /^acg-[a-f0-9]{24}$/u;
const REQUEST_ID = /^[A-Za-z0-9_-]{22}$/u;
const RELEASE = /^[A-Za-z0-9][A-Za-z0-9._+-]{0,79}$/u;
const RESOURCE_KEY = /^[a-z][a-z0-9-]{0,31}$/u;
const SAFE_ID = /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$/u;
const ACCOUNT_ID = /^[a-f0-9]{32}$/u;
const SOURCE_ID = /^source-[a-f0-9]{16}$/u;
const HOST_LABEL = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/u;
const NONCE = /^[A-Za-z0-9_-]{43}$/u;
const SIGNATURE = /^sha256=[a-f0-9]{64}$/u;
const OBJECT_TAG = Object.prototype.toString;
const FUNCTION_SOURCE = Function.prototype.toString;

function hasPrimitiveTag(value, tag) {
  return Object(value) !== value && OBJECT_TAG.call(value) === tag;
}

function isText(value) {
  return hasPrimitiveTag(value, '[object String]');
}

function hasControlCharacter(value) {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code <= 31 || code === 127) return true;
  }
  return false;
}

function isFiniteNumber(value) {
  return hasPrimitiveTag(value, '[object Number]') && Number.isFinite(value);
}

function isBoolean(value) {
  return hasPrimitiveTag(value, '[object Boolean]');
}

function isReference(value) {
  return value !== null && value !== undefined && Object(value) === value;
}

function isCallable(value) {
  try {
    FUNCTION_SOURCE.call(value);
    return true;
  } catch {
    return false;
  }
}

function isObjectReference(value) {
  return isReference(value) && !isCallable(value);
}

function compareText(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
}

function isRecord(value) {
  if (value === null || !isObjectReference(value) || Array.isArray(value)) return false;
  try {
    if (Object.getPrototypeOf(value) !== Object.prototype) return false;
    const descriptors = Object.getOwnPropertyDescriptors(value);
    return Object.values(descriptors).every((descriptor) => (
      descriptor.enumerable === true && 'value' in descriptor
    ));
  } catch {
    return false;
  }
}

function exactKeys(value, expected) {
  if (!isRecord(value)) return false;
  const actual = Object.keys(value).sort(compareText);
  const keys = [...expected].sort(compareText);
  return actual.length === keys.length && actual.every((key, index) => key === keys[index]);
}

function isPlainData(value, seen = new Set()) {
  if (value === null || isBoolean(value) || isText(value) || isFiniteNumber(value)) return true;
  if (!isObjectReference(value) || seen.has(value)) return false;
  seen.add(value);
  if (Array.isArray(value)) return value.every((entry) => isPlainData(entry, seen));
  if (!isRecord(value)) return false;
  return Object.values(value).every((entry) => isPlainData(entry, seen));
}

function canonicalJson(value) {
  if (value === null || isBoolean(value) || isText(value)) {
    return JSON.stringify(value);
  }
  if (isFiniteNumber(value)) return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (isRecord(value)) {
    return `{${Object.keys(value)
      .sort(compareText)
      .map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`)
      .join(',')}}`;
  }
  throw new TypeError('canonical_json_invalid');
}

async function sha256(value) {
  const digest = new Uint8Array(await crypto.subtle.digest(
    'SHA-256',
    new TextEncoder().encode(isText(value) ? value : canonicalJson(value)),
  ));
  return `sha256:${[...digest].map((byte) => byte.toString(16).padStart(2, '0')).join('')}`;
}

function fixedJson(status, body, headers = {}) {
  return new Response(canonicalJson(body), {
    status,
    headers: {
      'cache-control': 'no-store',
      'content-type': 'application/json; charset=utf-8',
      'permissions-policy': 'camera=(), geolocation=(), microphone=()',
      'referrer-policy': 'no-referrer',
      'x-content-type-options': 'nosniff',
      ...headers,
    },
  });
}

function recovery(reason) {
  const retryable = reason === 'uninstall_recovery_required' ||
    reason === 'uninstall_fresh_grant_required' || reason === 'uninstall_blocked';
  return fixedJson(409, { schemaVersion: 1, error: reason, retryable });
}

function hostname(value) {
  if (
    !isText(value) || value.length > 253 || value !== value.toLowerCase() ||
    value.includes(':') || /^(?:\d+\.)+\d+$/u.test(value)
  ) return false;
  const labels = value.split('.');
  return labels.length >= 2 && labels.every((label) => HOST_LABEL.test(label));
}

function canonicalBase64Url32(value) {
  if (!isText(value) || !NONCE.test(value)) return null;
  let decoded;
  try {
    const raw = atob(`${value.replaceAll('-', '+').replaceAll('_', '/')}=`);
    decoded = Uint8Array.from(raw, (character) => character.charCodeAt(0));
  } catch {
    return null;
  }
  if (decoded.byteLength !== 32 || decoded.every((byte) => byte === 0)) {
    decoded.fill(0);
    return null;
  }
  const canonical = btoa(String.fromCharCode(...decoded))
    .replaceAll('+', '-')
    .replaceAll('/', '_')
    .replace(/=+$/u, '');
  if (canonical !== value) {
    decoded.fill(0);
    return null;
  }
  return decoded;
}

function hexBytes(value) {
  if (!isText(value) || !SIGNATURE.test(value)) return null;
  return Uint8Array.from(value.slice('sha256='.length).match(/../gu) ?? [], (hex) => (
    Number.parseInt(hex, 16)
  ));
}

async function verifyHmac(rawBody, encodedNonce, signatureHeader) {
  const keyBytes = canonicalBase64Url32(encodedNonce);
  const signature = hexBytes(signatureHeader);
  if (!keyBytes || !signature || signature.byteLength !== 32) {
    keyBytes?.fill(0);
    signature?.fill(0);
    return false;
  }
  try {
    const key = await crypto.subtle.importKey(
      'raw', keyBytes, { name: 'HMAC', hash: 'SHA-256' }, false, ['verify'],
    );
    return await crypto.subtle.verify(
      'HMAC', key, signature, new TextEncoder().encode(rawBody),
    );
  } catch {
    return false;
  } finally {
    keyBytes.fill(0);
    signature.fill(0);
  }
}

async function readBoundedText(request, limit) {
  const declared = request.headers.get('content-length');
  if (declared !== null) {
    const size = Number(declared);
    if (!Number.isSafeInteger(size) || size < 0 || size > limit) return null;
  }
  if (!request.body) return null;
  const reader = request.body.getReader();
  const chunks = [];
  let total = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      if (value.byteLength > limit - total) {
        try { await reader.cancel(); } catch { /* The size failure is authoritative. */ }
        return null;
      }
      if (value.byteLength > 0) {
        chunks.push(value.slice());
        total += value.byteLength;
      }
    }
    if (total === 0) return null;
    const bytes = new Uint8Array(total);
    let offset = 0;
    for (const chunk of chunks) {
      bytes.set(chunk, offset);
      offset += chunk.byteLength;
    }
    try {
      return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
    } catch {
      return null;
    } finally {
      bytes.fill(0);
    }
  } catch {
    try { await reader.cancel(); } catch { /* The fixed rejection remains authoritative. */ }
    return null;
  } finally {
    for (const chunk of chunks) chunk.fill(0);
    try { reader.releaseLock(); } catch { /* The fixed rejection remains authoritative. */ }
  }
}

function parseProvider(value, policy) {
  if (!exactKeys(value, policy ? ['id', 'parentId'] : ['id'])) return null;
  if (!isText(value.id) || !SAFE_ID.test(value.id)) return null;
  if (policy && (!isText(value.parentId) || !SAFE_ID.test(value.parentId))) return null;
  const provider = { id: value.id };
  if (policy) provider.parentId = value.parentId;
  return Object.freeze(provider);
}

async function parseReadyReceipt(value, expected) {
  if (!exactKeys(value, [
    'schemaVersion', 'manager', 'installationId', 'state', 'revision', 'release',
    'target', 'accessPolicy', 'desiredHash', 'resources', 'pending', 'checksum',
  ])) return null;
  if (
    value.schemaVersion !== 1 || value.manager !== MANAGER || value.state !== 'ready' ||
    value.installationId !== expected.installationId || !INSTALLATION_ID.test(value.installationId) ||
    !Number.isSafeInteger(value.revision) || value.revision < 0 ||
    value.release !== expected.release.id || !RELEASE.test(value.release) ||
    value.desiredHash !== expected.desiredHash || !HASH.test(value.desiredHash) ||
    value.pending !== null || !isText(value.checksum) || !HASH.test(value.checksum) ||
    !exactKeys(value.target, ['accountId', 'zoneId', 'zoneName', 'hostname']) ||
    value.target.accountId !== expected.target.accountId || value.target.zoneId !== expected.target.zoneId ||
    value.target.zoneName !== expected.target.zoneName || !hostname(value.target.hostname) ||
    !(value.target.hostname === value.target.zoneName || value.target.hostname.endsWith(`.${value.target.zoneName}`)) ||
    !exactKeys(value.accessPolicy, ['identityType', 'identityCount', 'identitiesHash']) ||
    value.accessPolicy.identityType !== 'email' || !Number.isSafeInteger(value.accessPolicy.identityCount) ||
    value.accessPolicy.identityCount < 1 || value.accessPolicy.identityCount > 10_000 ||
    !isText(value.accessPolicy.identitiesHash) || !HASH.test(value.accessPolicy.identitiesHash) ||
    !Array.isArray(value.resources)
  ) return null;

  const resourceOrder = value.resources.map((resource) => resource?.kind);
  const canonicalOrder = [RESOURCE_ORDER, PORTAL_RESOURCE_ORDER].find((candidate) => (
    candidate.length === resourceOrder.length && candidate.every((kind, index) => kind === resourceOrder[index])
  ));
  if (!canonicalOrder) return null;

  const resources = [];
  for (let index = 0; index < canonicalOrder.length; index += 1) {
    const resource = value.resources[index];
    const kind = canonicalOrder[index];
    const policy = kind === 'source_access_policy' || kind === 'portal_access_policy';
    if (!exactKeys(resource, policy
      ? ['kind', 'key', 'provider', 'desiredHash', 'marker', 'identityHash']
      : ['kind', 'key', 'provider', 'desiredHash', 'marker'])) return null;
    const provider = parseProvider(resource.provider, policy);
    if (
      !provider || resource.kind !== kind || !isText(resource.key) ||
      !RESOURCE_KEY.test(resource.key) || !isText(resource.desiredHash) ||
      !HASH.test(resource.desiredHash) ||
      resource.marker !== `acg:v1:${value.installationId}:${resource.key}` ||
      (policy && (resource.identityHash !== value.accessPolicy.identitiesHash || !HASH.test(resource.identityHash)))
    ) return null;
    const parsedResource = {
      kind, key: resource.key, provider, desiredHash: resource.desiredHash,
      marker: resource.marker,
    };
    if (policy) parsedResource.identityHash = resource.identityHash;
    resources.push(Object.freeze(parsedResource));
  }
  const sourceApplication = resources.find((resource) => resource.kind === 'source_access_application');
  const sourcePolicy = resources.find((resource) => resource.kind === 'source_access_policy');
  const portalApplication = resources.find((resource) => resource.kind === 'portal_access_application');
  const portalPolicy = resources.find((resource) => resource.kind === 'portal_access_policy');
  if ((sourceApplication && sourcePolicy?.provider.parentId !== sourceApplication.provider.id) ||
      (!sourceApplication && sourcePolicy) ||
      portalPolicy?.provider.parentId !== portalApplication?.provider.id) return null;
  const locators = new Set();
  const accessApplicationIds = new Set();
  for (const resource of resources) {
    const locator = `${resource.kind}\u0000${resource.provider.parentId ?? ''}\u0000${resource.provider.id}`;
    if (locators.has(locator)) return null;
    locators.add(locator);
    if (resource.kind === 'source_access_application' || resource.kind === 'portal_access_application') {
      if (accessApplicationIds.has(resource.provider.id)) return null;
      accessApplicationIds.add(resource.provider.id);
    }
  }
  const unsigned = {
    schemaVersion: 1,
    manager: MANAGER,
    installationId: value.installationId,
    state: 'ready',
    revision: value.revision,
    release: value.release,
    target: value.target,
    accessPolicy: value.accessPolicy,
    desiredHash: value.desiredHash,
    resources,
    pending: null,
  };
  if (await sha256(unsigned) !== value.checksum) return null;
  return Object.freeze({ ...unsigned, checksum: value.checksum });
}

const SOURCE_RESOURCE_ORDER = Object.freeze([
  'mcp_server', 'source_access_application', 'source_access_policy',
]);

function parseSourceResource(value, index, installationId) {
  const kind = SOURCE_RESOURCE_ORDER[index];
  const policy = kind === 'source_access_policy';
  if (!exactKeys(value, policy
    ? ['kind', 'key', 'provider', 'desiredHash', 'marker', 'identityHash']
    : ['kind', 'key', 'provider', 'desiredHash', 'marker']) || value.kind !== kind ||
      !isText(value.key) || !RESOURCE_KEY.test(value.key) ||
      !isText(value.desiredHash) || !HASH.test(value.desiredHash) ||
      value.marker !== `acg:v1:${installationId}:${value.key}` ||
      (policy && (!isText(value.identityHash) || !HASH.test(value.identityHash)))) return null;
  const provider = parseProvider(value.provider, policy);
  return provider ? Object.freeze({ ...value, provider }) : null;
}

function parseManagementControl(value, claim) {
  if (!exactKeys(value, [
    'schemaVersion', 'installationId', 'accountId', 'portal', 'audienceEmails', 'sourceOwnership',
  ]) || value.schemaVersion !== 1 || value.installationId !== claim.expected.installationId ||
      value.accountId !== claim.target.accountId || !exactKeys(value.portal, ['id', 'name', 'hostname', 'marker']) ||
      !isText(value.portal.id) || !SAFE_ID.test(value.portal.id) ||
      !isText(value.portal.name) || value.portal.name.length < 2 || value.portal.name.length > 80 ||
      !hostname(value.portal.hostname) || value.portal.marker !== `acg:v1:${value.installationId}:${value.portal.id}` ||
      !Array.isArray(value.audienceEmails) || value.audienceEmails.length < 1 || value.audienceEmails.length > 51 ||
      !Array.isArray(value.sourceOwnership) || value.sourceOwnership.length > 32) return null;
  const ownership = [];
  for (const source of value.sourceOwnership) {
    if (!exactKeys(source, ['sourceId', 'resources']) || !SOURCE_ID.test(source.sourceId) ||
        !Array.isArray(source.resources) || source.resources.length !== SOURCE_RESOURCE_ORDER.length) return null;
    const resources = source.resources.map((resource, index) => parseSourceResource(
      resource, index, value.installationId,
    ));
    if (resources.some((resource) => resource === null) ||
        resources[2].provider.parentId !== resources[1].provider.id) return null;
    ownership.push(Object.freeze({ sourceId: source.sourceId, resources: Object.freeze(resources) }));
  }
  if (new Set(ownership.map((source) => source.sourceId)).size !== ownership.length ||
      new Set(ownership.flatMap((source) => source.resources.map((resource) => (
        `${resource.kind}\u0000${resource.provider.parentId ?? ''}\u0000${resource.provider.id}`
      )))).size !== ownership.length * SOURCE_RESOURCE_ORDER.length) return null;
  return Object.freeze({ ...value, portal: Object.freeze({ ...value.portal }), sourceOwnership: Object.freeze(ownership) });
}

function parseManagementSources(value) {
  if (!exactKeys(value, ['schemaVersion', 'revision', 'applyMode', 'sources']) || value.schemaVersion !== 1 ||
      !Number.isSafeInteger(value.revision) || value.revision < 1 || value.applyMode !== 'oauth_per_action' ||
      !Array.isArray(value.sources) || value.sources.length > 32) return null;
  const sources = [];
  for (const source of value.sources) {
    const legacy = exactKeys(source, ['id', 'label', 'url', 'enabledTools', 'status']);
    const current = exactKeys(source, ['id', 'label', 'url', 'authMode', 'enabledTools', 'status']);
    if ((!legacy && !current) || !SOURCE_ID.test(source.id) ||
        !isText(source.label) || !Array.isArray(source.enabledTools) ||
        source.enabledTools.length < 1 || source.enabledTools.length > 64 ||
        (source.status !== 'installed' && source.status !== 'draft')) return null;
    const authMode = legacy ? 'none' : source.authMode;
    if (authMode !== 'none' && authMode !== 'oauth') return null;
    const tools = source.enabledTools.filter((tool) => isText(tool) && /^[A-Za-z0-9_.:/-]{1,128}$/u.test(tool));
    if (tools.length !== source.enabledTools.length || new Set(tools).size !== tools.length) return null;
    sources.push(Object.freeze({ ...source, authMode, enabledTools: Object.freeze([...tools]) }));
  }
  return Object.freeze({ ...value, sources: Object.freeze(sources) });
}

function isSourceCleanupResourceKey(value) {
  if (!isText(value)) return false;
  const [kind, sourceId, resourceKey, extra] = value.split('\0');
  return extra === undefined && /^[a-z_]+$/u.test(kind) &&
    SOURCE_ID.test(sourceId) && /^[a-z0-9-]+$/u.test(resourceKey);
}

function parseSourceCleanupState(value, controlHash, installationId) {
  if (!exactKeys(value, [
    'schemaVersion', 'installationId', 'controlHash', 'status', 'portalPhase',
    'removedKeys', 'pending',
  ]) || value.schemaVersion !== 1 || value.installationId !== installationId ||
      value.controlHash !== controlHash || (value.status !== 'uninstalling' && value.status !== 'removed') ||
      !['not_started', 'send_armed', 'submitted', 'complete'].includes(value.portalPhase) ||
      !Array.isArray(value.removedKeys) ||
      value.removedKeys.some((key) => !isSourceCleanupResourceKey(key)) ||
      new Set(value.removedKeys).size !== value.removedKeys.length) return null;
  let pending = null;
  if (value.pending !== null) {
    if (!exactKeys(value.pending, ['sourceId', 'kind', 'key', 'requestId', 'phase']) ||
        !SOURCE_ID.test(value.pending.sourceId) || !SOURCE_RESOURCE_ORDER.includes(value.pending.kind) ||
        !RESOURCE_KEY.test(value.pending.key) || !REQUEST_ID.test(value.pending.requestId) ||
        !['send_armed', 'submitted', 'not_applied'].includes(value.pending.phase)) return null;
    pending = Object.freeze({ ...value.pending });
  }
  if ((value.status === 'removed') !== (value.portalPhase === 'complete' && pending === null)) return null;
  return Object.freeze({ ...value, removedKeys: Object.freeze([...value.removedKeys]), pending });
}

function parseEnvironment(env) {
  if (!env || !isObjectReference(env)) return null;
  const value = {
    accountId: env.CLOUDFLARE_ACCOUNT_ID,
    zoneId: env.CLOUDFLARE_ZONE_ID,
    zoneName: env.CLOUDFLARE_ZONE_NAME,
    release: env.ANKKA_GATEWAY_RELEASE,
    releaseSha256: env.ANKKA_GATEWAY_RELEASE_SHA256,
    zeroTrustReady: env.ZERO_TRUST_READY,
    uninstallNonce: env.ANKKA_UNINSTALL_NONCE,
  };
  if (
    !isText(value.accountId) || !ACCOUNT_ID.test(value.accountId) ||
    !isText(value.zoneId) || !ACCOUNT_ID.test(value.zoneId) ||
    !hostname(value.zoneName) || !isText(value.release) || !RELEASE.test(value.release) ||
    !isText(value.releaseSha256) || !HASH.test(value.releaseSha256) ||
    value.zeroTrustReady !== 'true' || !isText(value.uninstallNonce) || !NONCE.test(value.uninstallNonce)
  ) return null;
  return Object.freeze(value);
}

async function parseClaim(value, environment, nowMs) {
  if (!exactKeys(value, [
    'schemaVersion', 'requestId', 'issuedAt', 'expiresAt', 'target', 'release',
    'expected', 'cloudflareAccessToken',
  ])) return null;
  if (
    value.schemaVersion !== 1 || !isText(value.requestId) || !REQUEST_ID.test(value.requestId) ||
    !Number.isSafeInteger(value.issuedAt) || !Number.isSafeInteger(value.expiresAt) ||
    value.expiresAt <= value.issuedAt || value.expiresAt - value.issuedAt > REQUEST_LIFETIME_SECONDS ||
    !exactKeys(value.target, ['accountId', 'zoneId', 'zoneName']) ||
    value.target.accountId !== environment.accountId || value.target.zoneId !== environment.zoneId ||
    value.target.zoneName !== environment.zoneName ||
    !exactKeys(value.release, ['id', 'artifactSha256']) || value.release.id !== environment.release ||
    value.release.artifactSha256 !== environment.releaseSha256 ||
    !exactKeys(value.expected, ['configurationHash', 'installationId', 'desiredHash', 'readyReceipt']) ||
    !isText(value.expected.configurationHash) || !HASH.test(value.expected.configurationHash) ||
    !isText(value.expected.installationId) || !INSTALLATION_ID.test(value.expected.installationId) ||
    !isText(value.expected.desiredHash) || !HASH.test(value.expected.desiredHash) ||
    !isText(value.cloudflareAccessToken) || value.cloudflareAccessToken.length === 0 ||
    value.cloudflareAccessToken.length > 16 * 1024 || value.cloudflareAccessToken.trim() !== value.cloudflareAccessToken ||
    hasControlCharacter(value.cloudflareAccessToken)
  ) return null;
  const now = Math.floor(nowMs / 1_000);
  if (value.issuedAt > now + MAX_CLOCK_SKEW_SECONDS || value.expiresAt < now ||
      now - value.issuedAt > REQUEST_LIFETIME_SECONDS) return null;
  const readyReceipt = await parseReadyReceipt(value.expected.readyReceipt, {
    installationId: value.expected.installationId,
    desiredHash: value.expected.desiredHash,
    release: value.release,
    target: value.target,
  });
  if (!readyReceipt) return null;
  return Object.freeze({
    schemaVersion: 1,
    requestId: value.requestId,
    issuedAt: value.issuedAt,
    expiresAt: value.expiresAt,
    target: Object.freeze({ ...value.target }),
    release: Object.freeze({ ...value.release }),
    expected: Object.freeze({
      configurationHash: value.expected.configurationHash,
      installationId: value.expected.installationId,
      desiredHash: value.expected.desiredHash,
      readyReceipt,
    }),
    cloudflareAccessToken: value.cloudflareAccessToken,
  });
}

async function verifyRequest(request, env, nowMs) {
  if (!(request instanceof Request) || request.method !== 'POST') return null;
  const contentType = request.headers.get('content-type')?.split(';', 1)[0]?.trim().toLowerCase();
  if (contentType !== 'application/json' || request.headers.has('authorization') ||
      request.headers.has('cookie') || request.headers.has('referer') || request.headers.has('origin')) return null;
  const environment = parseEnvironment(env);
  if (!environment) return null;
  const signature = request.headers.get('x-ankka-uninstall-signature');
  const rawBody = await readBoundedText(request, REQUEST_LIMIT_BYTES);
  if (!rawBody || !await verifyHmac(rawBody, environment.uninstallNonce, signature)) return null;
  let parsed;
  try {
    parsed = JSON.parse(rawBody);
  } catch {
    return null;
  }
  if (!isPlainData(parsed) || canonicalJson(parsed) !== rawBody) return null;
  const claim = await parseClaim(parsed, environment, nowMs);
  if (!claim) return null;
  return Object.freeze({ rawBody, claim, environment, signature });
}

function providerUrl(resource, receipt) {
  const account = encodeURIComponent(receipt.target.accountId);
  const zone = encodeURIComponent(receipt.target.zoneId);
  const id = encodeURIComponent(resource.provider.id);
  if (resource.kind === 'mcp_server') {
    return new URL(`/client/v4/accounts/${account}/access/ai-controls/mcp/servers/${id}`, API_ORIGIN);
  }
  if (resource.kind === 'portal') {
    return new URL(`/client/v4/accounts/${account}/access/ai-controls/mcp/portals/${id}`, API_ORIGIN);
  }
  if (resource.kind === 'source_access_application' || resource.kind === 'portal_access_application') {
    return new URL(`/client/v4/accounts/${account}/access/apps/${id}`, API_ORIGIN);
  }
  if (resource.kind === 'source_access_policy' || resource.kind === 'portal_access_policy') {
    return new URL(
      `/client/v4/accounts/${account}/access/apps/${encodeURIComponent(resource.provider.parentId)}/policies/${id}`,
      API_ORIGIN,
    );
  }
  return new URL(`/client/v4/zones/${zone}/dns_records/${id}`, API_ORIGIN);
}

async function discardBody(response) {
  try { await response.body?.cancel(); } catch { /* Provider status remains authoritative. */ }
}

async function readBoundedProviderJson(response) {
  const declared = response.headers.get('content-length');
  if (declared !== null) {
    const size = Number(declared);
    if (!Number.isSafeInteger(size) || size < 0 || size > PROVIDER_RESPONSE_LIMIT_BYTES) return null;
  }
  const contentType = response.headers.get('content-type')?.split(';', 1)[0]?.trim().toLowerCase();
  if (contentType !== 'application/json' || !response.body) return null;
  const reader = response.body.getReader();
  const chunks = [];
  let total = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      if (value.byteLength > PROVIDER_RESPONSE_LIMIT_BYTES - total) {
        try { await reader.cancel(); } catch { /* The bound remains authoritative. */ }
        return null;
      }
      if (value.byteLength > 0) {
        chunks.push(value.slice());
        total += value.byteLength;
      }
    }
    if (total === 0) return null;
    const bytes = new Uint8Array(total);
    let offset = 0;
    for (const chunk of chunks) {
      bytes.set(chunk, offset);
      offset += chunk.byteLength;
    }
    try {
      const parsed = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
      return isPlainData(parsed) ? parsed : null;
    } catch {
      return null;
    } finally {
      bytes.fill(0);
    }
  } finally {
    for (const chunk of chunks) chunk.fill(0);
    try { reader.releaseLock(); } catch { /* Provider parsing remains authoritative. */ }
  }
}

function destinationReferences(result, expectedType, expectedValue) {
  if (!Array.isArray(result.destinations)) return false;
  return result.destinations.some((destination) => {
    if (!isRecord(destination) || destination.type !== expectedType) return false;
    if (expectedType === 'via_mcp_server_portal') {
      return destination.mcp_server_id === expectedValue || destination.mcpServerId === expectedValue;
    }
    return destination.uri === expectedValue || destination.hostname === expectedValue;
  });
}

function liveOwnershipMatches(resource, result, receipt) {
  if (!isRecord(result) || result.id !== resource.provider.id) return false;
  if (resource.kind === 'mcp_server' || resource.kind === 'portal') {
    return result.description === resource.marker;
  }
  if (resource.kind === 'source_access_policy' || resource.kind === 'portal_access_policy') {
    return isText(result.name) &&
      (result.name === resource.marker || result.name.endsWith(` [${resource.marker}]`));
  }
  if (resource.kind === 'dns_record') {
    return result.name === receipt.target.hostname && result.comment === resource.marker;
  }
  if (resource.kind === 'source_access_application') {
    return result.type === 'mcp' && result.name === resource.marker && destinationReferences(
      result, 'via_mcp_server_portal', receipt.resources[0].provider.id,
    );
  }
  return result.type === 'mcp_portal' && (
    result.domain === receipt.target.hostname ||
    destinationReferences(result, 'public', receipt.target.hostname)
  );
}

async function providerRead(resource, receipt, token, providerFetch) {
  let response;
  try {
    response = await providerFetch(new Request(providerUrl(resource, receipt), {
      method: 'GET',
      headers: { accept: 'application/json', authorization: `Bearer ${token}` },
      redirect: 'manual',
    }));
  } catch {
    return Object.freeze({ status: 'unknown' });
  }
  if (!(response instanceof Response) || response.redirected ||
      (response.status >= 300 && response.status < 400)) {
    await discardBody(response instanceof Response ? response : new Response());
    return Object.freeze({ status: 'unknown' });
  }
  if (response.status === 404) {
    await discardBody(response);
    return Object.freeze({ status: 'absent' });
  }
  if (response.status === 401 || response.status === 403) {
    await discardBody(response);
    return Object.freeze({ status: 'auth' });
  }
  if (response.status === 429 || response.status >= 500) {
    await discardBody(response);
    return Object.freeze({ status: 'unknown' });
  }
  if (response.status !== 200) {
    await discardBody(response);
    return Object.freeze({ status: 'blocked' });
  }
  let envelope;
  try {
    envelope = await readBoundedProviderJson(response);
  } catch {
    return Object.freeze({ status: 'unknown' });
  }
  if (!isRecord(envelope) || envelope.success !== true || !liveOwnershipMatches(resource, envelope.result, receipt)) {
    return Object.freeze({ status: 'conflict' });
  }
  return Object.freeze({ status: 'present' });
}

async function providerDelete(resource, receipt, token, providerFetch) {
  let response;
  try {
    response = await providerFetch(new Request(providerUrl(resource, receipt), {
      method: 'DELETE',
      headers: { accept: 'application/json', authorization: `Bearer ${token}` },
      redirect: 'manual',
    }));
  } catch {
    return 'unknown';
  }
  if (!(response instanceof Response) || response.redirected ||
      (response.status >= 300 && response.status < 400)) {
    if (response instanceof Response) await discardBody(response);
    return 'unknown';
  }
  const status = response.status;
  await discardBody(response);
  if (status === 404) return 'absent';
  if (status >= 200 && status < 300) return 'submitted';
  if (status === 401 || status === 403) return 'auth';
  if (status === 429 || status >= 500) return 'unknown';
  return 'blocked';
}

async function providerPortalRead(control, token, providerFetch) {
  const url = new URL(
    `/client/v4/accounts/${encodeURIComponent(control.accountId)}/access/ai-controls/mcp/portals/${encodeURIComponent(control.portal.id)}`,
    API_ORIGIN,
  );
  let response;
  try {
    response = await providerFetch(new Request(url, {
      method: 'GET', headers: { accept: 'application/json', authorization: `Bearer ${token}` }, redirect: 'manual',
    }));
  } catch { return Object.freeze({ status: 'unknown', result: null }); }
  if (!(response instanceof Response) || response.redirected || response.status !== 200) {
    if (response instanceof Response) await discardBody(response);
    if (response instanceof Response && (response.status === 401 || response.status === 403)) {
      return Object.freeze({ status: 'auth', result: null });
    }
    return Object.freeze({ status: response instanceof Response && response.status === 404 ? 'absent' : 'unknown', result: null });
  }
  const envelope = await readBoundedProviderJson(response);
  if (!isRecord(envelope) || envelope.success !== true || !isRecord(envelope.result)) {
    return Object.freeze({ status: 'unknown', result: null });
  }
  return Object.freeze({ status: 'present', result: envelope.result });
}

function rootPortalBody(control, sources, rootReceipt) {
  const rootServer = resourceByKind(rootReceipt, 'mcp_server');
  if (!rootServer) {
    return Object.freeze({
      name: control.portal.name,
      hostname: control.portal.hostname,
      code_mode: 'default_on',
      secure_web_gateway: false,
      description: control.portal.marker,
      servers: Object.freeze([]),
    });
  }
  const ownership = control.sourceOwnership.find((source) => (
    source.resources[0].provider.id === rootServer.provider.id
  ));
  const source = ownership && sources.sources.find((candidate) => candidate.id === ownership.sourceId);
  if (!ownership || !source) return null;
  return Object.freeze({
    name: control.portal.name,
    hostname: control.portal.hostname,
    code_mode: 'default_on',
    secure_web_gateway: false,
    description: control.portal.marker,
    servers: Object.freeze([Object.freeze({
      server_id: rootServer.provider.id,
      default_disabled: true,
      on_behalf: false,
      updated_tools: Object.freeze(source.enabledTools.map((name) => Object.freeze({ name, enabled: true }))),
    })]),
  });
}

function portalIsRootOnly(value, control, expected) {
  if (!isRecord(value) || value.id !== control.portal.id || value.name !== expected.name ||
      value.hostname !== expected.hostname || value.code_mode !== 'default_on' ||
      value.secure_web_gateway !== false || value.description !== expected.description) return false;
  if (expected.servers.length === 0) return value.servers === undefined || (
    Array.isArray(value.servers) && value.servers.length === 0
  );
  if (!Array.isArray(value.servers) || value.servers.length !== expected.servers.length) return false;
  const mapping = value.servers[0];
  const desired = expected.servers[0];
  if (!isRecord(mapping) || (mapping.server_id ?? mapping.id) !== desired.server_id ||
      mapping.default_disabled !== true || mapping.on_behalf !== false || !Array.isArray(mapping.updated_tools) ||
      (Object.hasOwn(mapping, 'updated_prompts') &&
        (!Array.isArray(mapping.updated_prompts) || mapping.updated_prompts.length !== 0))) return false;
  const tools = mapping.updated_tools.map((tool) => isRecord(tool) && tool.enabled === true ? tool.name : null);
  return tools.every((tool) => isText(tool)) &&
    canonicalJson([...tools].sort(compareText)) === canonicalJson(
      desired.updated_tools.map((tool) => tool.name).sort(compareText),
    );
}

async function providerPortalUpdate(control, body, token, providerFetch) {
  const url = new URL(
    `/client/v4/accounts/${encodeURIComponent(control.accountId)}/access/ai-controls/mcp/portals/${encodeURIComponent(control.portal.id)}`,
    API_ORIGIN,
  );
  let response;
  try {
    response = await providerFetch(new Request(url, {
      method: 'PUT',
      headers: { accept: 'application/json', authorization: `Bearer ${token}`, 'content-type': 'application/json' },
      body: canonicalJson(body),
      redirect: 'manual',
    }));
  } catch { return 'unknown'; }
  if (!(response instanceof Response) || response.redirected) return 'unknown';
  const status = response.status;
  await discardBody(response);
  if (status >= 200 && status < 300) return 'submitted';
  if (status === 401 || status === 403) return 'auth';
  if (status === 429 || status >= 500) return 'unknown';
  return 'blocked';
}

function resourceByKind(receipt, kind) {
  return receipt.resources.find((resource) => resource.kind === kind) ?? null;
}

function deleteOrder(receipt) {
  return [...receipt.resources].reverse().map((resource) => resource.kind);
}

function exactReceiptAuthority(left, right) {
  try { return canonicalJson(left) === canonicalJson(right); } catch { return false; }
}

/**
 * The only legitimate entry into `uninstalling`. The root receipt is the exact
 * `ready` receipt the primary Worker stored; the authenticated claim must carry
 * a canonically identical copy before it may be adopted as cleanup authority.
 */
async function initialState(claim, rootReceipt) {
  const uninstallDigest = (await sha256({
    schemaVersion: 1,
    installationId: claim.expected.installationId,
    configurationHash: claim.expected.configurationHash,
    rootReceiptChecksum: rootReceipt.checksum,
    release: claim.release,
  })).slice('sha256:'.length, 'sha256:'.length + 24);
  return {
    schemaVersion: 1,
    status: 'uninstalling',
    installationId: claim.expected.installationId,
    configurationHash: claim.expected.configurationHash,
    desiredHash: claim.expected.desiredHash,
    release: claim.release,
    rootReceipt,
    uninstallId: `uninstall-${uninstallDigest}`,
    removedKinds: [],
    pending: null,
    removedReceipt: null,
  };
}

/**
 * Accepts the stored primary `ready` receipt only when it is a structurally
 * valid, checksum-verified receipt for this claim and is canonically identical
 * to the receipt the authenticated claim expects. Anything else — absent,
 * malformed, corrupted, partially matching, or a different installation — is
 * not cleanup authority.
 */
async function storedReadyReceipt(value, claim) {
  if (!isRecord(value) || value.state !== 'ready') return null;
  const parsed = await parseReadyReceipt(value, {
    installationId: claim.expected.installationId,
    desiredHash: claim.expected.desiredHash,
    release: claim.release,
    target: claim.target,
  });
  if (!parsed || !exactReceiptAuthority(value, claim.expected.readyReceipt) ||
      !exactReceiptAuthority(parsed, claim.expected.readyReceipt)) return null;
  return parsed;
}

function validStoredState(value, claim) {
  if (!exactKeys(value, [
    'schemaVersion', 'status', 'installationId', 'configurationHash', 'desiredHash',
    'release', 'rootReceipt', 'uninstallId', 'removedKinds', 'pending', 'removedReceipt',
  ])) return false;
  const expectedDeleteOrder = deleteOrder(value.rootReceipt);
  if (
    value.schemaVersion !== 1 || !['uninstalling', 'removed'].includes(value.status) ||
    value.installationId !== claim.expected.installationId ||
    value.configurationHash !== claim.expected.configurationHash ||
    value.desiredHash !== claim.expected.desiredHash || !exactReceiptAuthority(value.release, claim.release) ||
    !exactReceiptAuthority(value.rootReceipt, claim.expected.readyReceipt) ||
    !isText(value.uninstallId) || !/^uninstall-[a-f0-9]{24}$/u.test(value.uninstallId) ||
    !Array.isArray(value.removedKinds) ||
    value.removedKinds.some((kind, index) => kind !== expectedDeleteOrder[index])
  ) return false;
  if (value.pending !== null) {
    if (!exactKeys(value.pending, ['kind', 'key', 'requestId', 'phase']) ||
      value.pending.kind !== expectedDeleteOrder[value.removedKinds.length] ||
      !isText(value.pending.key) || !RESOURCE_KEY.test(value.pending.key) ||
      !isText(value.pending.requestId) || !REQUEST_ID.test(value.pending.requestId) ||
      !['send_armed', 'submitted', 'not_applied'].includes(value.pending.phase)) return false;
    const resource = resourceByKind(value.rootReceipt, value.pending.kind);
    if (!resource || resource.key !== value.pending.key) return false;
  }
  if (value.status === 'removed') {
    return value.removedKinds.length === expectedDeleteOrder.length && value.pending === null &&
      value.removedReceipt !== null;
  }
  // The final resource-prefix commit is durable before the tombstone write.
  // Keep that exact all-removed transitional state recoverable if the final
  // storage.put fails or the object is evicted between those two writes.
  return value.removedKinds.length <= expectedDeleteOrder.length && value.removedReceipt === null;
}

async function removedReceipt(root) {
  const unsigned = {
    schemaVersion: 1,
    manager: MANAGER,
    installationId: root.installationId,
    state: 'removed',
    revision: root.revision + (2 * root.resources.length) + 1,
    release: root.release,
    // Keep the tombstone JSON-shaped after Durable Object structured cloning.
    // Sharing these objects with rootReceipt would preserve aliases and make a
    // later plain-data validation indistinguishable from a cyclic graph.
    target: { ...root.target },
    accessPolicy: { ...root.accessPolicy },
    desiredHash: root.desiredHash,
    resources: [],
    pending: null,
  };
  if (!Number.isSafeInteger(unsigned.revision)) throw new TypeError('receipt_revision_invalid');
  return Object.freeze({ ...unsigned, checksum: await sha256(unsigned) });
}

function removedResponse(state, uninstallInvoked, resumed) {
  const evidence = state.removedReceipt;
  return fixedJson(200, {
    schemaVersion: 1,
    status: 'removed',
    installationId: state.installationId,
    configurationHash: state.configurationHash,
    uninstallId: state.uninstallId,
    release: state.release,
    receipt: { revision: evidence.revision, resourceCount: 0, evidence },
    uninstallInvoked,
    resumed,
  });
}

async function save(storage, state) {
  await storage.put(STORAGE_KEY, structuredClone(state));
}

function providerFailure(result) {
  if (result === 'auth') return recovery('uninstall_fresh_grant_required');
  if (result === 'unknown') return recovery('uninstall_recovery_required');
  if (result === 'conflict') return recovery('uninstall_requires_repair');
  return recovery('uninstall_blocked');
}

/**
 * Testable Durable Object core. OAuth material is used only to construct the
 * current provider requests and is never stored, returned, or logged.
 */
async function processCustomerUninstall(request, env, storage, providerFetch, nowMs = Date.now()) {
  const verified = await verifyRequest(request, env, nowMs);
  if (!verified) return fixedJson(400, { schemaVersion: 1, error: 'uninstall_rejected', retryable: false });
  const { claim } = verified;
  let state;
  let resumed = false;
  try {
    state = await storage.get(STORAGE_KEY);
  } catch {
    return recovery('uninstall_recovery_required');
  }
  if (state === undefined || !isPlainData(state)) {
    // No receipt-owned authority exists. A claim alone never starts an uninstall.
    return recovery('uninstall_request_mismatch');
  }
  if (isRecord(state) && state.state === 'ready') {
    const root = await storedReadyReceipt(state, claim);
    if (!root) return recovery('uninstall_request_mismatch');
    // ready -> uninstalling is durable before the first provider read.
    state = await initialState(claim, root);
    try { await save(storage, state); } catch { return recovery('uninstall_recovery_required'); }
  } else {
    resumed = true;
    if (!validStoredState(state, claim)) return recovery('uninstall_request_mismatch');
  }
  if (state.status === 'removed') {
    let expectedTombstone;
    try { expectedTombstone = await removedReceipt(state.rootReceipt); } catch {
      return recovery('uninstall_requires_repair');
    }
    if (!exactReceiptAuthority(state.removedReceipt, expectedTombstone)) {
      return recovery('uninstall_requires_repair');
    }
    return removedResponse(state, false, true);
  }

  const expectedDeleteOrder = deleteOrder(state.rootReceipt);
  while (state.removedKinds.length < expectedDeleteOrder.length) {
    const kind = expectedDeleteOrder[state.removedKinds.length];
    const resource = resourceByKind(state.rootReceipt, kind);
    if (!resource) return recovery('uninstall_requires_repair');

    if (state.pending !== null) {
      const observed = await providerRead(resource, state.rootReceipt, claim.cloudflareAccessToken, providerFetch);
      if (observed.status === 'absent') {
        state = { ...state, pending: null, removedKinds: [...state.removedKinds, kind] };
        try { await save(storage, state); } catch { return recovery('uninstall_recovery_required'); }
        continue;
      }
      if (observed.status !== 'present') return providerFailure(observed.status);
      if (state.pending.requestId === claim.requestId && state.pending.phase !== 'not_applied') {
        return recovery('uninstall_recovery_required');
      }
      if (state.pending.requestId === claim.requestId) {
        return recovery('uninstall_fresh_grant_required');
      }
      state = { ...state, pending: { ...state.pending, phase: 'not_applied' } };
      try { await save(storage, state); } catch { return recovery('uninstall_recovery_required'); }
    } else {
      const observed = await providerRead(resource, state.rootReceipt, claim.cloudflareAccessToken, providerFetch);
      if (observed.status === 'absent') {
        state = { ...state, removedKinds: [...state.removedKinds, kind] };
        try { await save(storage, state); } catch { return recovery('uninstall_recovery_required'); }
        continue;
      }
      if (observed.status !== 'present') return providerFailure(observed.status);
    }

    state = {
      ...state,
      pending: { kind, key: resource.key, requestId: claim.requestId, phase: 'send_armed' },
    };
    try { await save(storage, state); } catch { return recovery('uninstall_recovery_required'); }
    const deleted = await providerDelete(
      resource, state.rootReceipt, claim.cloudflareAccessToken, providerFetch,
    );
    if (deleted === 'auth' || deleted === 'blocked') {
      state = { ...state, pending: { ...state.pending, phase: 'not_applied' } };
      try { await save(storage, state); } catch { return recovery('uninstall_recovery_required'); }
      return providerFailure(deleted);
    }
    if (deleted === 'unknown') return recovery('uninstall_recovery_required');
    if (deleted === 'submitted') {
      state = { ...state, pending: { ...state.pending, phase: 'submitted' } };
      try { await save(storage, state); } catch { return recovery('uninstall_recovery_required'); }
      const verifiedAbsent = await providerRead(
        resource, state.rootReceipt, claim.cloudflareAccessToken, providerFetch,
      );
      if (verifiedAbsent.status === 'present') {
        state = { ...state, pending: { ...state.pending, phase: 'not_applied' } };
        try { await save(storage, state); } catch { return recovery('uninstall_recovery_required'); }
        return recovery('uninstall_fresh_grant_required');
      }
      if (verifiedAbsent.status !== 'absent') return providerFailure(verifiedAbsent.status);
    }
    state = { ...state, pending: null, removedKinds: [...state.removedKinds, kind] };
    try { await save(storage, state); } catch { return recovery('uninstall_recovery_required'); }
  }

  try {
    const tombstone = await removedReceipt(state.rootReceipt);
    state = { ...state, status: 'removed', removedReceipt: tombstone };
    await save(storage, state);
  } catch {
    return recovery('uninstall_recovery_required');
  }
  return removedResponse(state, true, resumed);
}

function sourceRemovalKey(sourceId, resource) {
  return `${resource.kind}\u0000${sourceId}\u0000${resource.key}`;
}

function sourceReceipt(rootReceipt, ownership) {
  return Object.freeze({ target: rootReceipt.target, resources: ownership.resources });
}

async function processManagementSourcesUninstall(request, env, storage, providerFetch, nowMs = Date.now()) {
  const verified = await verifyRequest(request, env, nowMs);
  if (!verified) return fixedJson(400, { schemaVersion: 1, error: 'uninstall_rejected', retryable: false });
  const { claim } = verified;
  let rawControl;
  let rawSources;
  try {
    rawControl = await storage.get(CONTROL_KEY);
    rawSources = await storage.get(SOURCES_KEY);
  } catch { return recovery('uninstall_recovery_required'); }
  // Releases before source-action support persisted editable source drafts but
  // had no customer-owned control record and therefore no day-two resources
  // to remove. Treat those journals as the legacy no-op case.
  if (rawControl === undefined) {
    return fixedJson(200, { schemaVersion: 1, status: 'removed', resourceCount: 0, resumed: false });
  }
  const control = parseManagementControl(rawControl, claim);
  const sources = parseManagementSources(rawSources);
  const rootReceipt = claim.expected.readyReceipt;
  const rootPortal = resourceByKind(rootReceipt, 'portal');
  const rootServer = resourceByKind(rootReceipt, 'mcp_server');
  if (!control || !sources || !rootPortal || control.portal.id !== rootPortal.provider.id ||
      control.portal.hostname !== rootReceipt.target.hostname || control.portal.marker !== rootPortal.marker) {
    return recovery('uninstall_requires_repair');
  }
  const rootOwnership = rootServer ? control.sourceOwnership.filter((source) => (
    source.resources[0].provider.id === rootServer.provider.id
  )) : [];
  if ((rootServer && rootOwnership.length !== 1) || (!rootServer && rootOwnership.length !== 0)) {
    return recovery('uninstall_requires_repair');
  }
  const extras = control.sourceOwnership.filter((source) => source !== rootOwnership[0])
    .sort((left, right) => compareText(right.sourceId, left.sourceId));
  const removal = extras.flatMap((source) => [...source.resources].reverse().map((resource) => Object.freeze({
    sourceId: source.sourceId,
    resource,
    receipt: sourceReceipt(rootReceipt, source),
  })));
  const controlHash = await sha256(control);
  let state;
  try { state = await storage.get(SOURCE_CLEANUP_KEY); } catch { return recovery('uninstall_recovery_required'); }
  if (state === undefined) {
    state = Object.freeze({
      schemaVersion: 1,
      installationId: claim.expected.installationId,
      controlHash,
      status: 'uninstalling',
      portalPhase: 'not_started',
      removedKeys: Object.freeze([]),
      pending: null,
    });
    try { await storage.put(SOURCE_CLEANUP_KEY, state); } catch { return recovery('uninstall_recovery_required'); }
  } else {
    state = parseSourceCleanupState(state, controlHash, claim.expected.installationId);
    if (!state) return recovery('uninstall_requires_repair');
  }
  if (state.status === 'removed') {
    const expectedKeys = removal.map((entry) => sourceRemovalKey(entry.sourceId, entry.resource));
    if (canonicalJson(state.removedKeys) !== canonicalJson(expectedKeys)) {
      return recovery('uninstall_requires_repair');
    }
    return fixedJson(200, {
      schemaVersion: 1, status: 'removed', resourceCount: removal.length, resumed: true,
    });
  }
  const portalBody = rootPortalBody(control, sources, rootReceipt);
  if (!portalBody) return recovery('uninstall_requires_repair');
  if (state.portalPhase !== 'complete') {
    const observed = await providerPortalRead(control, claim.cloudflareAccessToken, providerFetch);
    if (observed.status !== 'present') return providerFailure(observed.status);
    if (portalIsRootOnly(observed.result, control, portalBody)) {
      state = { ...state, portalPhase: 'complete' };
      try { await storage.put(SOURCE_CLEANUP_KEY, state); } catch { return recovery('uninstall_recovery_required'); }
    } else {
      if (state.portalPhase !== 'not_started') return recovery('uninstall_recovery_required');
      state = { ...state, portalPhase: 'send_armed' };
      try { await storage.put(SOURCE_CLEANUP_KEY, state); } catch { return recovery('uninstall_recovery_required'); }
      const updated = await providerPortalUpdate(control, portalBody, claim.cloudflareAccessToken, providerFetch);
      if (updated !== 'submitted') return providerFailure(updated);
      state = { ...state, portalPhase: 'submitted' };
      try { await storage.put(SOURCE_CLEANUP_KEY, state); } catch { return recovery('uninstall_recovery_required'); }
      const verifiedPortal = await providerPortalRead(control, claim.cloudflareAccessToken, providerFetch);
      if (verifiedPortal.status !== 'present' || !portalIsRootOnly(verifiedPortal.result, control, portalBody)) {
        return recovery('uninstall_recovery_required');
      }
      state = { ...state, portalPhase: 'complete' };
      try { await storage.put(SOURCE_CLEANUP_KEY, state); } catch { return recovery('uninstall_recovery_required'); }
    }
  }
  for (const entry of removal) {
    const key = sourceRemovalKey(entry.sourceId, entry.resource);
    if (state.removedKeys.includes(key)) continue;
    if (state.pending !== null) {
      if (state.pending.sourceId !== entry.sourceId || state.pending.kind !== entry.resource.kind ||
          state.pending.key !== entry.resource.key) return recovery('uninstall_requires_repair');
      const observed = await providerRead(
        entry.resource, entry.receipt, claim.cloudflareAccessToken, providerFetch,
      );
      if (observed.status === 'absent') {
        state = { ...state, pending: null, removedKeys: [...state.removedKeys, key] };
        try { await storage.put(SOURCE_CLEANUP_KEY, state); } catch { return recovery('uninstall_recovery_required'); }
        continue;
      }
      if (observed.status !== 'present') return providerFailure(observed.status);
      if (state.pending.requestId === claim.requestId && state.pending.phase !== 'not_applied') {
        return recovery('uninstall_recovery_required');
      }
      state = { ...state, pending: { ...state.pending, phase: 'not_applied' } };
      try { await storage.put(SOURCE_CLEANUP_KEY, state); } catch { return recovery('uninstall_recovery_required'); }
    } else {
      const observed = await providerRead(
        entry.resource, entry.receipt, claim.cloudflareAccessToken, providerFetch,
      );
      if (observed.status === 'absent') {
        state = { ...state, removedKeys: [...state.removedKeys, key] };
        try { await storage.put(SOURCE_CLEANUP_KEY, state); } catch { return recovery('uninstall_recovery_required'); }
        continue;
      }
      if (observed.status !== 'present') return providerFailure(observed.status);
    }
    state = {
      ...state,
      pending: {
        sourceId: entry.sourceId,
        kind: entry.resource.kind,
        key: entry.resource.key,
        requestId: claim.requestId,
        phase: 'send_armed',
      },
    };
    try { await storage.put(SOURCE_CLEANUP_KEY, state); } catch { return recovery('uninstall_recovery_required'); }
    const deleted = await providerDelete(
      entry.resource, entry.receipt, claim.cloudflareAccessToken, providerFetch,
    );
    if (deleted === 'auth' || deleted === 'blocked') {
      state = { ...state, pending: { ...state.pending, phase: 'not_applied' } };
      try { await storage.put(SOURCE_CLEANUP_KEY, state); } catch { return recovery('uninstall_recovery_required'); }
      return providerFailure(deleted);
    }
    if (deleted === 'unknown') return recovery('uninstall_recovery_required');
    state = { ...state, pending: { ...state.pending, phase: 'submitted' } };
    try { await storage.put(SOURCE_CLEANUP_KEY, state); } catch { return recovery('uninstall_recovery_required'); }
    const absent = await providerRead(
      entry.resource, entry.receipt, claim.cloudflareAccessToken, providerFetch,
    );
    if (absent.status !== 'absent') return absent.status === 'present'
      ? recovery('uninstall_fresh_grant_required')
      : providerFailure(absent.status);
    state = { ...state, pending: null, removedKeys: [...state.removedKeys, key] };
    try { await storage.put(SOURCE_CLEANUP_KEY, state); } catch { return recovery('uninstall_recovery_required'); }
  }
  state = { ...state, status: 'removed', pending: null };
  try { await storage.put(SOURCE_CLEANUP_KEY, state); } catch { return recovery('uninstall_recovery_required'); }
  return fixedJson(200, {
    schemaVersion: 1, status: 'removed', resourceCount: removal.length, resumed: false,
  });
}

export class AdminState {
  constructor(state, env) {
    this.state = state;
    this.env = env;
    this.queue = Promise.resolve();
  }

  fetch(request) {
    const operation = async () => {
      const url = new URL(request.url);
      if (url.pathname === INTERNAL_SOURCE_UNINSTALL_PATH) {
        return processManagementSourcesUninstall(
          request,
          this.env,
          this.state.storage,
          globalThis.fetch.bind(globalThis),
        );
      }
      if (url.pathname !== INTERNAL_UNINSTALL_PATH) {
        return fixedJson(404, { schemaVersion: 1, error: 'not_found' });
      }
      return processCustomerUninstall(
        request,
        this.env,
        this.state.storage,
        globalThis.fetch.bind(globalThis),
      );
    };
    const result = this.queue.then(operation, operation);
    this.queue = result.then(() => undefined, () => undefined);
    return result;
  }
}

async function handleUninstallRequest(request, env, nowMs = Date.now()) {
  const url = new URL(request.url);
  if (url.pathname !== UNINSTALL_PATH) {
    if (url.pathname.startsWith('/api/')) {
      return fixedJson(423, { schemaVersion: 1, error: 'uninstall_in_progress' });
    }
    return fixedJson(404, { schemaVersion: 1, error: 'not_found' });
  }
  if (request.method !== 'POST') {
    return fixedJson(405, { schemaVersion: 1, error: 'method_not_allowed' }, { allow: 'POST' });
  }
  const verified = await verifyRequest(request, env, nowMs);
  if (!verified || !env.ADMIN_STATE || !isCallable(env.ADMIN_STATE.idFromName) ||
      !isCallable(env.ADMIN_STATE.get)) {
    return fixedJson(400, { schemaVersion: 1, error: 'uninstall_rejected', retryable: false });
  }
  let stub;
  let managementStub;
  try {
    stub = env.ADMIN_STATE.get(env.ADMIN_STATE.idFromName(`v1:${verified.claim.expected.installationId}`));
    managementStub = env.ADMIN_STATE.get(env.ADMIN_STATE.idFromName('v1:management'));
  } catch {
    return recovery('uninstall_recovery_required');
  }
  if (!stub || !isCallable(stub.fetch) || !managementStub || !isCallable(managementStub.fetch)) {
    return recovery('uninstall_recovery_required');
  }
  try {
    const internalRequest = (path) => new Request(`https://admin-state.invalid${path}`, {
      method: 'POST',
      headers: {
        accept: 'application/json',
        'content-type': 'application/json',
        'x-ankka-uninstall-signature': verified.signature,
      },
      body: verified.rawBody,
      redirect: 'manual',
    });
    const sourceResponse = await managementStub.fetch(internalRequest(INTERNAL_SOURCE_UNINSTALL_PATH));
    if (!(sourceResponse instanceof Response) || sourceResponse.status !== 200) {
      return sourceResponse instanceof Response ? sourceResponse : recovery('uninstall_recovery_required');
    }
    const response = await stub.fetch(internalRequest(INTERNAL_UNINSTALL_PATH));
    if (!(response instanceof Response)) return recovery('uninstall_recovery_required');
    return response;
  } catch {
    return recovery('uninstall_recovery_required');
  }
}

export default {
  fetch(request, env) {
    return handleUninstallRequest(request, env);
  },
};

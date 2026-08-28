import { CloudflareApiError } from './cloudflare-client.mjs';

const CLOUDFLARE_ID = /^[a-fA-F0-9]{32}$/;
const DNS_LABEL = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
const SAFE_PROVIDER_CODE = /^\d{1,10}$/;
const SAFE_INTERNAL_CODES = new Set([
  'invalid_response',
  'network_error',
  'pagination_limit',
]);

const ZONE_PROBE = Object.freeze({ key: 'zone.read', method: 'getZone' });
const ACCOUNT_PROBES = Object.freeze([
  Object.freeze({
    key: 'access.identity_providers.read',
    method: 'listIdentityProviders',
    normalize(value) {
      if (!Array.isArray(value)) throw new InvalidProbeResponseError();
      return { configured: value.length > 0 };
    },
  }),
  listProbe('mcp.servers.read', 'listMcpServers'),
  listProbe('mcp.portals.read', 'listPortals'),
  listProbe('access.applications.read', 'listAccessApps'),
  Object.freeze({
    ...listProbe('dns.records.read', 'listDnsRecords'),
    arguments(hostname) {
      return [{ 'name.exact': hostname, match: 'all' }];
    },
  }),
]);
const ALL_PROBES = Object.freeze([ZONE_PROBE, ...ACCOUNT_PROBES]);

class InvalidProbeResponseError extends Error {}

/**
 * Exercise only the Cloudflare reads needed before the disposable-account
 * canary. The selected zone is verified before any account-level discovery.
 * The injected client may expose mutation methods, but this function never
 * looks them up or invokes them.
 */
export async function runCloudflareCanaryPreflight(options = {}) {
  requireExactObject(
    options,
    ['cloudflare', 'accountId', 'zoneId', 'hostname'],
    'preflight options',
  );
  const { cloudflare, accountId, zoneId } = options;
  const hostname = normalizeHostname(options.hostname, 'hostname');
  requireCloudflareId(accountId, 'accountId');
  requireCloudflareId(zoneId, 'zoneId');
  if (!isObject(cloudflare)) throw new TypeError('cloudflare must be an object');

  // Validate the complete read surface before issuing the first request. A
  // partially injected client therefore cannot leave a misleading partial run.
  for (const probe of ALL_PROBES) {
    if (typeof cloudflare[probe.method] !== 'function') {
      throw new TypeError('cloudflare must implement the complete preflight read surface');
    }
  }

  const zone = await executeZoneProbe(cloudflare, { accountId, zoneId, hostname });
  const zoneReady =
    zone.capability.status === 'available' &&
    zone.value?.targetMatches === true &&
    zone.value?.active === true &&
    zone.value?.hostnameInZone === true;

  if (!zoneReady) return buildEarlyReport(zone);

  const accountResults = await Promise.all(
    ACCOUNT_PROBES.map((probe) => executeProbe(cloudflare, probe, hostname)),
  );
  const identityProviders = accountResults[0];
  const prerequisites = zonePrerequisites(zone, {
    identityProviderStatus:
      identityProviders.capability.status === 'available'
        ? identityProviders.value?.configured === true
          ? 'ready'
          : 'not_ready'
        : 'unavailable',
  });
  return buildReport({
    prerequisites,
    results: [zone, ...accountResults],
  });
}

async function executeZoneProbe(cloudflare, target) {
  try {
    const raw = await cloudflare.getZone.call(cloudflare);
    if (raw === null) return missingResult('zone.read');
    if (
      !isObject(raw) ||
      typeof raw.id !== 'string' ||
      !CLOUDFLARE_ID.test(raw.id) ||
      !isObject(raw.account) ||
      typeof raw.account.id !== 'string' ||
      !CLOUDFLARE_ID.test(raw.account.id) ||
      typeof raw.status !== 'string'
    ) {
      throw new InvalidProbeResponseError();
    }
    const zoneName = normalizeHostname(raw.name, 'provider zone name');
    const targetMatches =
      raw.id.toLowerCase() === target.zoneId.toLowerCase() &&
      raw.account.id.toLowerCase() === target.accountId.toLowerCase();
    const active = raw.status === 'active';
    const hostnameInZone =
      targetMatches && active && isStrictSubdomain(target.hostname, zoneName);
    const code = !targetMatches
      ? 'target_mismatch'
      : !active
        ? 'zone_inactive'
        : !hostnameInZone
          ? 'hostname_outside_zone'
          : undefined;
    return {
      capability: Object.freeze({ key: 'zone.read', status: 'available' }),
      value: Object.freeze({ targetMatches, active, hostnameInZone }),
      diagnostic:
        code === undefined
          ? undefined
          : fixedDiagnostic('zone.read', code),
    };
  } catch (error) {
    const diagnostic = sanitizeDiagnostic('zone.read', error);
    return {
      capability: Object.freeze({
        key: 'zone.read',
        status: capabilityFailureStatus(diagnostic.httpStatus),
      }),
      diagnostic,
    };
  }
}

async function executeProbe(cloudflare, probe, hostname) {
  try {
    const args = typeof probe.arguments === 'function' ? probe.arguments(hostname) : [];
    const raw = await cloudflare[probe.method].call(cloudflare, ...args);
    const value = probe.normalize(raw);
    return {
      capability: Object.freeze({ key: probe.key, status: 'available' }),
      value,
    };
  } catch (error) {
    const diagnostic = sanitizeDiagnostic(probe.key, error);
    return {
      capability: Object.freeze({
        key: probe.key,
        status: capabilityFailureStatus(diagnostic.httpStatus),
      }),
      diagnostic,
    };
  }
}

function buildEarlyReport(zone) {
  const skipped = ACCOUNT_PROBES.map((probe) => ({
    capability: Object.freeze({ key: probe.key, status: 'skipped' }),
  }));
  return buildReport({
    prerequisites: zonePrerequisites(zone, { identityProviderStatus: 'unavailable' }),
    results: [zone, ...skipped],
  });
}

function buildReport({ prerequisites, results }) {
  const capabilities = results.map(({ capability }) => capability);
  const diagnostics = results.flatMap(({ diagnostic }) =>
    diagnostic === undefined ? [] : [diagnostic],
  );
  const ready =
    capabilities.every(({ status }) => status === 'available') &&
    prerequisites.every(({ status }) => status === 'ready');
  return freezeReport({
    schemaVersion: 1,
    kind: 'cloudflare_canary_preflight',
    ready,
    writesPerformed: false,
    prerequisites,
    capabilities,
    diagnostics,
  });
}

function zonePrerequisites(zone, { identityProviderStatus }) {
  const available = zone.capability.status === 'available';
  return [
    Object.freeze({
      key: 'selected_target_matches',
      status: available
        ? zone.value?.targetMatches === true
          ? 'ready'
          : 'not_ready'
        : 'unavailable',
    }),
    Object.freeze({
      key: 'zone_active',
      status:
        available && zone.value?.targetMatches === true
          ? zone.value?.active === true
            ? 'ready'
            : 'not_ready'
          : 'unavailable',
    }),
    Object.freeze({
      key: 'hostname_in_zone',
      status:
        available && zone.value?.targetMatches === true && zone.value?.active === true
          ? zone.value?.hostnameInZone === true
            ? 'ready'
            : 'not_ready'
          : 'unavailable',
    }),
    Object.freeze({
      key: 'zero_trust_identity_provider',
      status: identityProviderStatus,
    }),
  ];
}

function sanitizeDiagnostic(capability, error) {
  if (error instanceof InvalidProbeResponseError || error instanceof TypeError) {
    return fixedDiagnostic(capability, 'invalid_response');
  }
  if (error instanceof CloudflareApiError) {
    const httpStatus = safeHttpStatus(error.status);
    const codes = Array.isArray(error.codes)
      ? error.codes.filter(isSafeDiagnosticCode).slice(0, 20)
      : [];
    return Object.freeze({
      capability,
      httpStatus,
      codes: Object.freeze(codes.length > 0 ? codes : ['request_failed']),
    });
  }
  return fixedDiagnostic(capability, 'unexpected_error');
}

function fixedDiagnostic(capability, code, httpStatus = 0) {
  return Object.freeze({
    capability,
    httpStatus,
    codes: Object.freeze([code]),
  });
}

function missingResult(key) {
  return {
    capability: Object.freeze({ key, status: 'not_found' }),
    diagnostic: fixedDiagnostic(key, 'not_found', 404),
  };
}

function isSafeDiagnosticCode(value) {
  return (
    typeof value === 'string' &&
    (SAFE_PROVIDER_CODE.test(value) || SAFE_INTERNAL_CODES.has(value))
  );
}

function listProbe(key, method) {
  return Object.freeze({
    key,
    method,
    normalize(value) {
      if (!Array.isArray(value)) throw new InvalidProbeResponseError();
      return {};
    },
  });
}

function capabilityFailureStatus(status) {
  if (status === 401 || status === 403) return 'denied';
  if (status === 404) return 'not_found';
  return 'failed';
}

function normalizeHostname(value, label) {
  if (
    typeof value !== 'string' ||
    value.length === 0 ||
    value.length > 253 ||
    value.endsWith('.') ||
    /[\u0000-\u001f\u007f]/.test(value)
  ) {
    throw new TypeError(`${label} must be a valid DNS hostname`);
  }
  const normalized = value.toLowerCase();
  const labels = normalized.split('.');
  if (labels.length < 2 || labels.some((part) => !DNS_LABEL.test(part))) {
    throw new TypeError(`${label} must be a valid DNS hostname`);
  }
  return normalized;
}

function isStrictSubdomain(hostname, zoneName) {
  return hostname !== zoneName && hostname.endsWith(`.${zoneName}`);
}

function requireCloudflareId(value, label) {
  if (typeof value !== 'string' || !CLOUDFLARE_ID.test(value)) {
    throw new TypeError(`${label} must be a 32-character Cloudflare identifier`);
  }
}

function safeHttpStatus(value) {
  return Number.isInteger(value) && value >= 0 && value <= 599 ? value : 0;
}

function requireExactObject(value, fields, label) {
  if (!isObject(value)) throw new TypeError(`${label} must be an object`);
  if (Object.keys(value).some((key) => !fields.includes(key))) {
    throw new TypeError(`${label} contain unsupported fields`);
  }
}

function freezeReport(report) {
  Object.freeze(report.prerequisites);
  Object.freeze(report.capabilities);
  Object.freeze(report.diagnostics);
  return Object.freeze(report);
}

function isObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

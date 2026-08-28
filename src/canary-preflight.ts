import * as v from 'valibot';

import { CloudflareApiError } from './cloudflare-client.ts';
import {
  type BoundaryValue,
} from './json.ts';

const CLOUDFLARE_ID = /^[a-fA-F0-9]{32}$/;
const DNS_LABEL = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
const SAFE_PROVIDER_CODE = /^\d{1,10}$/;
const SAFE_INTERNAL_CODES = new Set([
  'invalid_response',
  'network_error',
  'pagination_limit',
]);
const stringSchema = v.string();
const numberSchema = v.number();
const functionSchema = v.function();
const zoneResponseSchema = v.object({
  account: v.object({ id: v.string() }),
  id: v.string(),
  name: v.string(),
  status: v.string(),
});

type CapabilityStatus = 'available' | 'denied' | 'failed' | 'not_found' | 'skipped';
type PrerequisiteStatus = 'not_ready' | 'ready' | 'unavailable';
type IdentityProviderStatus = PrerequisiteStatus;
type PreflightQuery = {
  readonly 'name.exact': string;
  readonly match: 'all';
};
type CloudflareReadMethod = (query?: PreflightQuery) => Promise<BoundaryValue>;

export interface CloudflarePreflightClient {
  readonly getZone: CloudflareReadMethod;
  readonly listAccessApps: CloudflareReadMethod;
  readonly listDnsRecords: CloudflareReadMethod;
  readonly listIdentityProviders: CloudflareReadMethod;
  readonly listMcpServers: CloudflareReadMethod;
  readonly listPortals: CloudflareReadMethod;
}

export interface CloudflareCanaryPreflightOptions {
  readonly accountId: string;
  readonly cloudflare: CloudflarePreflightClient;
  readonly hostname: string;
  readonly zoneId: string;
}

type Capability = {
  readonly key: string;
  readonly status: CapabilityStatus;
};

type Diagnostic = {
  readonly capability: string;
  readonly codes: readonly string[];
  readonly httpStatus: number;
};

type ProbeValue = {
  readonly active?: boolean;
  readonly configured?: boolean;
  readonly hostnameInZone?: boolean;
  readonly targetMatches?: boolean;
};

interface ProbeResult {
  readonly capability: Capability;
  readonly diagnostic?: Diagnostic | undefined;
  readonly value?: ProbeValue | undefined;
}

type Prerequisite = {
  readonly key: string;
  readonly status: PrerequisiteStatus;
};

export interface CloudflareCanaryPreflightReport {
  readonly capabilities: readonly Capability[];
  readonly diagnostics: readonly Diagnostic[];
  readonly kind: 'cloudflare_canary_preflight';
  readonly prerequisites: readonly Prerequisite[];
  readonly ready: boolean;
  readonly schemaVersion: 1;
  readonly writesPerformed: false;
}

interface ZoneTarget {
  readonly accountId: string;
  readonly hostname: string;
  readonly zoneId: string;
}

interface AccountProbe {
  readonly arguments?: (hostname: string) => readonly PreflightQuery[];
  readonly key: string;
  readonly method: keyof CloudflarePreflightClient;
  readonly normalize: (value: BoundaryValue) => ProbeValue;
}

interface ReportInput {
  readonly prerequisites: readonly Prerequisite[];
  readonly results: readonly ProbeResult[];
}

const ZONE_PROBE = Object.freeze({ key: 'zone.read', method: 'getZone' });
const ACCOUNT_PROBES: readonly AccountProbe[] = Object.freeze([
  Object.freeze({
    key: 'access.identity_providers.read',
    method: 'listIdentityProviders',
    normalize(value: BoundaryValue) {
      if (!Array.isArray(value)) throw new InvalidProbeResponseError();
      return { configured: value.length > 0 };
    },
  }),
  listProbe('mcp.servers.read', 'listMcpServers'),
  listProbe('mcp.portals.read', 'listPortals'),
  listProbe('access.applications.read', 'listAccessApps'),
  Object.freeze({
    ...listProbe('dns.records.read', 'listDnsRecords'),
    arguments(hostname: string): readonly PreflightQuery[] {
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
export async function runCloudflareCanaryPreflight(
  options: CloudflareCanaryPreflightOptions,
): Promise<CloudflareCanaryPreflightReport> {
  requireExactObject(
    options,
    ['cloudflare', 'accountId', 'zoneId', 'hostname'],
    'preflight options',
  );
  const { cloudflare, accountId, zoneId } = options;
  const hostname = normalizeHostname(options.hostname, 'hostname');
  requireCloudflareId(accountId, 'accountId');
  requireCloudflareId(zoneId, 'zoneId');
  if (!v.is(v.object({}), cloudflare)) throw new TypeError('cloudflare must be an object');

  // Validate the complete read surface before issuing the first request. A
  // partially injected client therefore cannot leave a misleading partial run.
  for (const probe of ALL_PROBES) {
    if (!v.safeParse(functionSchema, cloudflare[probe.method]).success) {
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
  const identityProviders = accountResults.at(0);
  if (!identityProviders) throw new Error('Preflight identity-provider probe is missing');
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

async function executeZoneProbe(
  cloudflare: CloudflarePreflightClient,
  target: ZoneTarget,
): Promise<ProbeResult> {
  try {
    const raw = await cloudflare.getZone();
    if (raw === null) return missingResult('zone.read');
    const parsed = v.safeParse(zoneResponseSchema, raw);
    if (!parsed.success
      || !CLOUDFLARE_ID.test(parsed.output.id)
      || !CLOUDFLARE_ID.test(parsed.output.account.id)) {
      throw new InvalidProbeResponseError();
    }
    const zoneResponse = parsed.output;
    const zoneName = normalizeHostname(zoneResponse.name, 'provider zone name');
    const targetMatches =
      zoneResponse.id.toLowerCase() === target.zoneId.toLowerCase() &&
      zoneResponse.account.id.toLowerCase() === target.accountId.toLowerCase();
    const active = zoneResponse.status === 'active';
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
    const parsedError = v.safeParse(v.instance(Error), error);
    const diagnostic = parsedError.success
      ? sanitizeDiagnostic('zone.read', parsedError.output)
      : fixedDiagnostic('zone.read', 'unexpected_error');
    return {
      capability: Object.freeze({
        key: 'zone.read',
        status: capabilityFailureStatus(diagnostic.httpStatus),
      }),
      diagnostic,
    };
  }
}

async function executeProbe(
  cloudflare: CloudflarePreflightClient,
  probe: AccountProbe,
  hostname: string,
): Promise<ProbeResult> {
  try {
    const args = probe.arguments ? probe.arguments(hostname) : [];
    const raw = await cloudflare[probe.method](...args);
    const value = probe.normalize(raw);
    return {
      capability: Object.freeze({ key: probe.key, status: 'available' }),
      value,
    };
  } catch (error) {
    const parsedError = v.safeParse(v.instance(Error), error);
    const diagnostic = parsedError.success
      ? sanitizeDiagnostic(probe.key, parsedError.output)
      : fixedDiagnostic(probe.key, 'unexpected_error');
    return {
      capability: Object.freeze({
        key: probe.key,
        status: capabilityFailureStatus(diagnostic.httpStatus),
      }),
      diagnostic,
    };
  }
}

function buildEarlyReport(zone: ProbeResult): CloudflareCanaryPreflightReport {
  const skipped = ACCOUNT_PROBES.map((probe) => ({
    capability: Object.freeze({ key: probe.key, status: 'skipped' }),
  }));
  return buildReport({
    prerequisites: zonePrerequisites(zone, { identityProviderStatus: 'unavailable' }),
    results: [zone, ...skipped],
  });
}

function buildReport({ prerequisites, results }: ReportInput): CloudflareCanaryPreflightReport {
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

function zonePrerequisites(
  zone: ProbeResult,
  { identityProviderStatus }: { readonly identityProviderStatus: IdentityProviderStatus },
): Prerequisite[] {
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

function sanitizeDiagnostic(capability: string, error: Error): Diagnostic {
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

function fixedDiagnostic(capability: string, code: string, httpStatus = 0): Diagnostic {
  return Object.freeze({
    capability,
    httpStatus,
    codes: Object.freeze([code]),
  });
}

function missingResult(key: string): ProbeResult {
  return {
    capability: Object.freeze({ key, status: 'not_found' }),
    diagnostic: fixedDiagnostic(key, 'not_found', 404),
  };
}

function isSafeDiagnosticCode(value: string): boolean {
  return (
    (SAFE_PROVIDER_CODE.test(value) || SAFE_INTERNAL_CODES.has(value))
  );
}

function listProbe(
  key: string,
  method: keyof CloudflarePreflightClient,
): AccountProbe {
  return Object.freeze({
    key,
    method,
    normalize(value: BoundaryValue) {
      if (!Array.isArray(value)) throw new InvalidProbeResponseError();
      return {};
    },
  });
}

function capabilityFailureStatus(status: number): CapabilityStatus {
  if (status === 401 || status === 403) return 'denied';
  if (status === 404) return 'not_found';
  return 'failed';
}

function normalizeHostname(value: string, label: string): string {
  if (
    !v.is(stringSchema, value) ||
    value.length === 0 ||
    value.length > 253 ||
    value.endsWith('.') ||
    hasControlCharacters(value)
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

function isStrictSubdomain(hostname: string, zoneName: string): boolean {
  return hostname !== zoneName && hostname.endsWith(`.${zoneName}`);
}

function requireCloudflareId(value: string, label: string): void {
  if (!v.is(stringSchema, value) || !CLOUDFLARE_ID.test(value)) {
    throw new TypeError(`${label} must be a 32-character Cloudflare identifier`);
  }
}

function safeHttpStatus(value: number): number {
  return v.is(numberSchema, value) && Number.isInteger(value) && value >= 0 && value <= 599
    ? value
    : 0;
}

function requireExactObject(
  value: CloudflareCanaryPreflightOptions,
  fields: readonly string[],
  label: string,
): void {
  if (!v.is(v.object({}), value)) throw new TypeError(`${label} must be an object`);
  if (Object.keys(value).some((key) => !fields.includes(key))) {
    throw new TypeError(`${label} contain unsupported fields`);
  }
}

function freezeReport(report: CloudflareCanaryPreflightReport): CloudflareCanaryPreflightReport {
  Object.freeze(report.prerequisites);
  Object.freeze(report.capabilities);
  Object.freeze(report.diagnostics);
  return Object.freeze(report);
}

function hasControlCharacters(value: string): boolean {
  return [...value].some((character) => {
    const codePoint = character.codePointAt(0);
    return codePoint !== undefined && (codePoint <= 31 || codePoint === 127);
  });
}

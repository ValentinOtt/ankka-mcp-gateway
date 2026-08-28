import type { GatewayResourceKind } from './schema';

const HASH = /^sha256:[0-9a-f]{64}$/u;
const INSTALLATION_ID = /^acg-[0-9a-f]{24}$/u;
const RELEASE = /^[A-Za-z0-9][A-Za-z0-9._+-]{0,79}$/u;
const RESOURCE_KEY = /^[a-z][a-z0-9-]{0,31}$/u;
const SAFE_OPAQUE_ID = /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$/u;
const HOST_LABEL = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/u;
const RESOURCE_ORDER = Object.freeze([
  'mcp_server',
  'source_access_application',
  'source_access_policy',
  'portal',
  'portal_access_application',
  'portal_access_policy',
  'dns_record',
] as const satisfies readonly GatewayResourceKind[]);
const PORTAL_RESOURCE_ORDER = Object.freeze([
  'portal',
  'portal_access_application',
  'portal_access_policy',
  'dns_record',
] as const satisfies readonly GatewayResourceKind[]);

type ReceiptResourceKind = GatewayResourceKind;

function canonicalResourceOrder(resources: readonly unknown[]): readonly GatewayResourceKind[] | null {
  const kinds = resources.map((resource) => isRecord(resource) ? resource.kind : null);
  return [RESOURCE_ORDER, PORTAL_RESOURCE_ORDER].find((candidate) => (
    candidate.length === kinds.length && candidate.every((kind, index) => kind === kinds[index])
  )) ?? null;
}

export interface InstallationReceiptTarget {
  readonly accountId: string;
  readonly zoneId: string;
  readonly zoneName: string;
  readonly hostname: string;
}
export interface InstallationReceiptAccessPolicy {
  readonly identityType: 'email';
  readonly identityCount: number;
  readonly identitiesHash: string;
}

export interface InstallationReceiptResourceExpectation {
  readonly kind: ReceiptResourceKind;
  readonly key: string;
  readonly desiredHash: string;
  readonly marker: string;
  readonly identityHash?: string;
}

export interface ReadyInstallationReceiptExpectation {
  readonly installationId: string;
  readonly release: string;
  readonly desiredHash: string;
  readonly target: InstallationReceiptTarget;
  readonly accessPolicy: InstallationReceiptAccessPolicy;
  readonly resources: readonly InstallationReceiptResourceExpectation[];
}

export interface InstallationReceiptResource {
  readonly kind: ReceiptResourceKind;
  readonly key: string;
  readonly provider: {
    readonly id: string;
    readonly parentId?: string;
  };
  readonly desiredHash: string;
  readonly marker: string;
  readonly identityHash?: string;
}

/**
 * Exact, checksum-protected public ownership evidence. It is deliberately
 * credential-free and safe to retain in the private install journal.
 */
export interface ReadyInstallationReceipt {
  readonly schemaVersion: 1;
  readonly manager: 'ankka-mcp-gateway';
  readonly installationId: string;
  readonly state: 'ready';
  readonly revision: number;
  readonly release: string;
  readonly target: InstallationReceiptTarget;
  readonly accessPolicy: InstallationReceiptAccessPolicy;
  readonly desiredHash: string;
  readonly resources: readonly InstallationReceiptResource[];
  readonly pending: null;
  readonly checksum: string;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
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

function exactKeys(value: Record<string, unknown>, expected: readonly string[]): boolean {
  const actual = Object.keys(value).sort(compareText);
  const keys = [...expected].sort(compareText);
  return actual.length === keys.length && actual.every((key, index) => key === keys[index]);
}

function compareText(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function canonicalJson(value: unknown): string {
  if (value === null || typeof value === 'boolean' || typeof value === 'string') {
    return JSON.stringify(value);
  }
  if (typeof value === 'number' && Number.isFinite(value)) return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (isRecord(value)) {
    return `{${Object.keys(value)
      .sort(compareText)
      .map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`)
      .join(',')}}`;
  }
  throw new TypeError('canonical_json_invalid');
}

async function sha256(value: string): Promise<string> {
  const digest = new Uint8Array(await crypto.subtle.digest(
    'SHA-256',
    new TextEncoder().encode(value),
  ));
  return `sha256:${[...digest].map((byte) => byte.toString(16).padStart(2, '0')).join('')}`;
}

function hostname(value: unknown): value is string {
  if (
    typeof value !== 'string' || value.length > 253 || value !== value.toLowerCase() ||
    value.includes(':') || /^(?:\d+\.)+\d+$/u.test(value)
  ) return false;
  const labels = value.split('.');
  return labels.length >= 2 && labels.every((label) => HOST_LABEL.test(label));
}

function sameTarget(value: unknown, expected: InstallationReceiptTarget): value is InstallationReceiptTarget {
  return isRecord(value) && exactKeys(value, ['accountId', 'zoneId', 'zoneName', 'hostname']) &&
    typeof value.accountId === 'string' && SAFE_OPAQUE_ID.test(value.accountId) &&
    typeof value.zoneId === 'string' && SAFE_OPAQUE_ID.test(value.zoneId) &&
    hostname(value.zoneName) && hostname(value.hostname) &&
    (value.hostname === value.zoneName || value.hostname.endsWith(`.${value.zoneName}`)) &&
    value.accountId === expected.accountId && value.zoneId === expected.zoneId &&
    value.zoneName === expected.zoneName && value.hostname === expected.hostname;
}

function sameAccessPolicy(
  value: unknown,
  expected: InstallationReceiptAccessPolicy,
): value is InstallationReceiptAccessPolicy {
  return isRecord(value) && exactKeys(value, ['identityType', 'identityCount', 'identitiesHash']) &&
    value.identityType === 'email' && Number.isSafeInteger(value.identityCount) &&
    (value.identityCount as number) >= 1 && (value.identityCount as number) <= 10_000 &&
    typeof value.identitiesHash === 'string' && HASH.test(value.identitiesHash) &&
    value.identityCount === expected.identityCount && value.identitiesHash === expected.identitiesHash;
}

function parseProvider(
  value: unknown,
  policy: boolean,
): { readonly id: string; readonly parentId?: string } | null {
  if (!isRecord(value) || !exactKeys(value, policy ? ['id', 'parentId'] : ['id'])) return null;
  if (typeof value.id !== 'string' || !SAFE_OPAQUE_ID.test(value.id)) return null;
  if (policy && (typeof value.parentId !== 'string' || !SAFE_OPAQUE_ID.test(value.parentId))) return null;
  return Object.freeze({ id: value.id, ...(policy ? { parentId: value.parentId as string } : {}) });
}

function parseResource(
  value: unknown,
  expected: InstallationReceiptResourceExpectation,
  installationId: string,
): InstallationReceiptResource | null {
  const policy = expected.kind === 'source_access_policy' || expected.kind === 'portal_access_policy';
  const expectedKeys = policy
    ? ['kind', 'key', 'provider', 'desiredHash', 'marker', 'identityHash']
    : ['kind', 'key', 'provider', 'desiredHash', 'marker'];
  if (!isRecord(value) || !exactKeys(value, expectedKeys)) return null;
  const provider = parseProvider(value.provider, policy);
  if (
    !provider || value.kind !== expected.kind || value.key !== expected.key ||
    typeof value.key !== 'string' || !RESOURCE_KEY.test(value.key) ||
    value.desiredHash !== expected.desiredHash || typeof value.desiredHash !== 'string' || !HASH.test(value.desiredHash) ||
    value.marker !== expected.marker || value.marker !== `acg:v1:${installationId}:${value.key}` ||
    (policy && (value.identityHash !== expected.identityHash || typeof value.identityHash !== 'string' || !HASH.test(value.identityHash)))
  ) return null;
  return Object.freeze({
    kind: expected.kind,
    key: expected.key,
    provider,
    desiredHash: expected.desiredHash,
    marker: expected.marker,
    ...(policy ? { identityHash: expected.identityHash as string } : {}),
  });
}

function exactExpectation(value: unknown): value is ReadyInstallationReceiptExpectation {
  if (!isRecord(value) || !exactKeys(value, [
    'installationId', 'release', 'desiredHash', 'target', 'accessPolicy', 'resources',
  ])) return false;
  if (
    typeof value.installationId !== 'string' || !INSTALLATION_ID.test(value.installationId) ||
    typeof value.release !== 'string' || !RELEASE.test(value.release) ||
    typeof value.desiredHash !== 'string' || !HASH.test(value.desiredHash) ||
    !isRecord(value.target) || !isRecord(value.accessPolicy) || !Array.isArray(value.resources)
  ) return false;
  const resourceOrder = canonicalResourceOrder(value.resources);
  if (!resourceOrder) return false;
  return value.resources.every((resource, index) => {
    if (!isRecord(resource)) return false;
    const policy = resourceOrder[index] === 'source_access_policy' || resourceOrder[index] === 'portal_access_policy';
    return exactKeys(resource, policy
      ? ['kind', 'key', 'desiredHash', 'marker', 'identityHash']
      : ['kind', 'key', 'desiredHash', 'marker']) &&
      resource.kind === resourceOrder[index] && typeof resource.key === 'string' && RESOURCE_KEY.test(resource.key) &&
      typeof resource.desiredHash === 'string' && HASH.test(resource.desiredHash) &&
      resource.marker === `acg:v1:${value.installationId}:${resource.key}` &&
      (!policy || (typeof resource.identityHash === 'string' && HASH.test(resource.identityHash)));
  });
}

/**
 * Parse the public receipt only when it is the exact ready/root receipt for the
 * reviewed seven-resource graph. Self-consistent but unbound receipts fail.
 */
export async function parseReadyInstallationReceipt(
  value: unknown,
  expected: ReadyInstallationReceiptExpectation,
): Promise<ReadyInstallationReceipt | null> {
  if (!exactExpectation(expected) || !isRecord(value) || !exactKeys(value, [
    'schemaVersion', 'manager', 'installationId', 'state', 'revision', 'release',
    'target', 'accessPolicy', 'desiredHash', 'resources', 'pending', 'checksum',
  ])) return null;
  if (
    value.schemaVersion !== 1 || value.manager !== 'ankka-mcp-gateway' ||
    value.installationId !== expected.installationId || value.state !== 'ready' ||
    !Number.isSafeInteger(value.revision) || (value.revision as number) < 0 ||
    value.release !== expected.release || value.desiredHash !== expected.desiredHash ||
    value.pending !== null || typeof value.checksum !== 'string' || !HASH.test(value.checksum) ||
    !sameTarget(value.target, expected.target) || !sameAccessPolicy(value.accessPolicy, expected.accessPolicy) ||
    !Array.isArray(value.resources) || value.resources.length !== expected.resources.length
  ) return null;

  const resources: InstallationReceiptResource[] = [];
  for (let index = 0; index < expected.resources.length; index += 1) {
    const parsed = parseResource(value.resources[index], expected.resources[index], expected.installationId);
    if (!parsed) return null;
    resources.push(parsed);
  }

  const providerLocators = new Set<string>();
  const accessApplicationIds = new Set<string>();
  for (const resource of resources) {
    const locator = `${resource.kind}\u0000${resource.provider.parentId ?? ''}\u0000${resource.provider.id}`;
    if (providerLocators.has(locator)) return null;
    providerLocators.add(locator);
    if (resource.kind === 'source_access_application' || resource.kind === 'portal_access_application') {
      if (accessApplicationIds.has(resource.provider.id)) return null;
      accessApplicationIds.add(resource.provider.id);
    }
  }
  const sourceApplication = resources.find((resource) => resource.kind === 'source_access_application');
  const sourcePolicy = resources.find((resource) => resource.kind === 'source_access_policy');
  const portalApplication = resources.find((resource) => resource.kind === 'portal_access_application');
  const portalPolicy = resources.find((resource) => resource.kind === 'portal_access_policy');
  if ((sourceApplication && sourcePolicy?.provider.parentId !== sourceApplication.provider.id) ||
      (!sourceApplication && sourcePolicy) ||
      portalPolicy?.provider.parentId !== portalApplication?.provider.id) return null;

  const unsigned = {
    schemaVersion: 1,
    manager: 'ankka-mcp-gateway',
    installationId: expected.installationId,
    state: 'ready',
    revision: value.revision,
    release: expected.release,
    target: value.target,
    accessPolicy: value.accessPolicy,
    desiredHash: expected.desiredHash,
    resources: value.resources,
    pending: null,
  };
  let checksum: string;
  try {
    checksum = await sha256(canonicalJson(unsigned));
  } catch {
    return null;
  }
  if (checksum !== value.checksum) return null;

  return Object.freeze({
    schemaVersion: 1,
    manager: 'ankka-mcp-gateway',
    installationId: expected.installationId,
    state: 'ready',
    revision: value.revision as number,
    release: expected.release,
    target: Object.freeze({ ...expected.target }),
    accessPolicy: Object.freeze({ ...expected.accessPolicy }),
    desiredHash: expected.desiredHash,
    resources: Object.freeze(resources),
    pending: null,
    checksum,
  });
}

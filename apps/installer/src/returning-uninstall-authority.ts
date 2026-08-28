import { sha256Hex } from './crypto';
import { DeployError } from './errors';
import {
  parseReadyInstallationReceipt,
  type InstallationReceiptResourceExpectation,
  type ReadyInstallationReceipt,
  type ReadyInstallationReceiptExpectation,
} from './provider-neutral-installation-receipt';
import { assertSecretFree } from './schema';

const ACTION_ID = /^action_[A-Za-z0-9_-]{32}$/u;
const ACCOUNT_ID = /^[a-f0-9]{32}$/u;
const INSTALLATION_ID = /^acg-[a-f0-9]{24}$/u;
const RELEASE = /^gateway-v(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)(?:-[a-z0-9.-]+)?$/u;
const HASH = /^sha256:[a-f0-9]{64}$/u;
const PROVIDER_ID = /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$/u;
const RESOURCE_KEY = /^[a-z][a-z0-9-]{0,31}$/u;
const SOURCE_ID = /^source-[a-f0-9]{16}$/u;
const WORKER_NAME = /^[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$/u;
const DNS_LABEL = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/u;
const TOOL = /^[A-Za-z0-9_.:/-]{1,128}$/u;
const EMAIL = /^[^\s@]{1,64}@[A-Za-z0-9.-]{1,190}$/u;
const UPDATE_CHANNEL = /^(?:canary|stable)$/u;
const UPDATE_KEY_ID = /^[a-z0-9][a-z0-9._-]{0,63}$/u;
const UPDATE_PUBLIC_KEY = /^[A-Za-z0-9_-]{43}$/u;

export interface ReturningUninstallControlResource {
  readonly kind: 'mcp_server' | 'source_access_application' | 'source_access_policy';
  readonly key: string;
  readonly provider: { readonly id: string; readonly parentId?: string };
  readonly desiredHash: string;
  readonly marker: string;
  readonly identityHash?: string;
}

export interface ReturningUninstallManagementControl {
  readonly schemaVersion: 1;
  readonly installationId: string;
  readonly accountId: string;
  readonly portal: {
    readonly id: string;
    readonly name: string;
    readonly hostname: string;
    readonly marker: string;
  };
  readonly audienceEmails: readonly string[];
  readonly sourceOwnership: readonly {
    readonly sourceId: string;
    readonly resources: readonly ReturningUninstallControlResource[];
  }[];
}

export interface ReturningUninstallManagementSources {
  readonly schemaVersion: 1;
  readonly revision: number;
  readonly applyMode: 'oauth_per_action';
  readonly sources: readonly {
    readonly id: string;
    readonly label: string;
    readonly url: string;
    readonly authMode: 'none' | 'oauth';
    readonly enabledTools: readonly string[];
    readonly status: 'installed' | 'draft';
  }[];
}

export interface ReturningUninstallRuntimeAuthority {
  readonly release: string;
  readonly artifactSha256: string;
  readonly updateChannel: 'canary' | 'stable';
  readonly updateKeyId: string;
  /** Raw Ed25519 verification key encoded as unpadded base64url. */
  readonly updatePublicKey: string;
  readonly accountId: string;
  readonly zoneId: string;
  readonly zoneName: string;
  readonly workerName: string;
  readonly workersSubdomain: string;
  readonly managementHostname: string;
}

/** Secret-free authority imported from the customer-owned management Worker. */
export interface ReturningUninstallImportedAuthority {
  readonly schemaVersion: 1;
  readonly actionId: string;
  readonly actorEmail: string;
  readonly installationId: string;
  readonly receipt: ReadyInstallationReceipt;
  readonly control: ReturningUninstallManagementControl;
  readonly sources: ReturningUninstallManagementSources;
  readonly runtime: ReturningUninstallRuntimeAuthority;
  /** Stable commitment to the customer-owned installation, independent of a one-time action. */
  readonly authorityHash: string;
  /** Per-action commitment that prevents authority rotation across actors or action ids. */
  readonly actionProofHash: string;
}

export interface ReturningUninstallAuthorityExpectation {
  readonly actionId: string;
  readonly actorEmail: string;
  readonly installationId: string;
  readonly accountId: string;
  readonly workerName: string;
  readonly workersSubdomain: string;
  readonly managementOrigin: string;
  readonly portalHostname: string;
  readonly gatewayName: string;
}

function record(value: unknown): value is Record<string, unknown> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  try {
    return Object.getPrototypeOf(value) === Object.prototype &&
      Reflect.ownKeys(value).every((key) => typeof key === 'string') &&
      Object.values(Object.getOwnPropertyDescriptors(value)).every((descriptor) => (
        descriptor.enumerable === true && Object.hasOwn(descriptor, 'value')
      ));
  } catch { return false; }
}

function exact(value: Record<string, unknown>, expected: readonly string[]): boolean {
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  return actual.length === wanted.length && actual.every((key, index) => key === wanted[index]);
}

function canonicalJson(value: unknown): string {
  if (value === null || typeof value === 'boolean' || typeof value === 'string') return JSON.stringify(value);
  if (typeof value === 'number' && Number.isFinite(value)) return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (record(value)) return `{${Object.keys(value).sort().map((key) => (
    `${JSON.stringify(key)}:${canonicalJson(value[key])}`
  )).join(',')}}`;
  throw new TypeError('canonical_returning_uninstall_authority');
}

function hostname(value: unknown): value is string {
  return typeof value === 'string' && value.length <= 253 && value === value.toLowerCase() &&
    !value.includes(':') && value.split('.').length >= 2 && value.split('.').every((label) => DNS_LABEL.test(label));
}

function publicUrl(value: unknown): value is string {
  if (typeof value !== 'string') return false;
  try {
    const url = new URL(value);
    return url.protocol === 'https:' && !url.username && !url.password && !url.port &&
      (url.pathname === '/' || url.pathname === '/mcp') && !url.search && !url.hash && hostname(url.hostname);
  } catch { return false; }
}

function normalizedEmails(value: unknown): readonly string[] | null {
  if (!Array.isArray(value) || value.length < 1 || value.length > 64) return null;
  if (value.some((email) => typeof email !== 'string' || email !== email.toLowerCase() || !EMAIL.test(email))) return null;
  const emails = [...value] as string[];
  if (emails.some((email, index) => index > 0 && email <= emails[index - 1])) return null;
  return Object.freeze(emails);
}

function provider(value: unknown, policy: boolean): { readonly id: string; readonly parentId?: string } | null {
  if (!record(value) || !exact(value, policy ? ['id', 'parentId'] : ['id']) ||
    typeof value.id !== 'string' || !PROVIDER_ID.test(value.id) ||
    (policy && (typeof value.parentId !== 'string' || !PROVIDER_ID.test(value.parentId)))) return null;
  return Object.freeze({ id: value.id, ...(policy ? { parentId: value.parentId as string } : {}) });
}

const SOURCE_RESOURCE_ORDER = Object.freeze([
  'mcp_server', 'source_access_application', 'source_access_policy',
] as const);

function controlResource(value: unknown, index: number, installationId: string): ReturningUninstallControlResource | null {
  const kind = SOURCE_RESOURCE_ORDER[index];
  const policy = kind === 'source_access_policy';
  if (!kind || !record(value) || !exact(value, policy
    ? ['kind', 'key', 'provider', 'desiredHash', 'marker', 'identityHash']
    : ['kind', 'key', 'provider', 'desiredHash', 'marker']) || value.kind !== kind ||
    typeof value.key !== 'string' || !RESOURCE_KEY.test(value.key) ||
    typeof value.desiredHash !== 'string' || !HASH.test(value.desiredHash) ||
    value.marker !== `acg:v1:${installationId}:${value.key}` ||
    (policy && (typeof value.identityHash !== 'string' || !HASH.test(value.identityHash)))) return null;
  const parsedProvider = provider(value.provider, policy);
  if (!parsedProvider) return null;
  return Object.freeze({
    kind,
    key: value.key,
    provider: parsedProvider,
    desiredHash: value.desiredHash,
    marker: value.marker,
    ...(policy ? { identityHash: value.identityHash as string } : {}),
  });
}

function parseControl(value: unknown, installationId: string, accountId: string): ReturningUninstallManagementControl | null {
  if (!record(value) || !exact(value, [
    'schemaVersion', 'installationId', 'accountId', 'portal', 'audienceEmails', 'sourceOwnership',
  ]) || value.schemaVersion !== 1 || value.installationId !== installationId || value.accountId !== accountId ||
    !record(value.portal) || !exact(value.portal, ['id', 'name', 'hostname', 'marker']) ||
    typeof value.portal.id !== 'string' || !PROVIDER_ID.test(value.portal.id) ||
    typeof value.portal.name !== 'string' || value.portal.name.length < 1 || value.portal.name.length > 128 ||
    /[\u0000-\u001f\u007f<>{}\\]/u.test(value.portal.name) || !hostname(value.portal.hostname) ||
    typeof value.portal.marker !== 'string' ||
    !Array.isArray(value.sourceOwnership) || value.sourceOwnership.length > 32) return null;
  const emails = normalizedEmails(value.audienceEmails);
  if (!emails) return null;
  const ownership: ReturningUninstallManagementControl['sourceOwnership'][number][] = [];
  const providerLocators = new Set<string>();
  for (const raw of value.sourceOwnership) {
    if (!record(raw) || !exact(raw, ['sourceId', 'resources']) || typeof raw.sourceId !== 'string' ||
      !SOURCE_ID.test(raw.sourceId) || !Array.isArray(raw.resources) || raw.resources.length !== 3) return null;
    const resources = raw.resources.map((item, index) => controlResource(item, index, installationId));
    if (resources.some((item) => item === null)) return null;
    const parsedResources = resources as ReturningUninstallControlResource[];
    if (parsedResources[2]?.provider.parentId !== parsedResources[1]?.provider.id) return null;
    for (const resource of parsedResources) {
      const locator = resource.kind === 'source_access_application'
        ? `access_application\u0000${resource.provider.id}`
        : resource.kind === 'source_access_policy'
          ? `access_policy\u0000${resource.provider.parentId}\u0000${resource.provider.id}`
          : `${resource.kind}\u0000${resource.provider.id}`;
      if (providerLocators.has(locator)) return null;
      providerLocators.add(locator);
    }
    ownership.push(Object.freeze({
      sourceId: raw.sourceId,
      resources: Object.freeze(parsedResources),
    }));
  }
  if (new Set(ownership.map((item) => item.sourceId)).size !== ownership.length) return null;
  return Object.freeze({
    schemaVersion: 1,
    installationId,
    accountId,
    portal: Object.freeze({
      id: value.portal.id,
      name: value.portal.name,
      hostname: value.portal.hostname,
      marker: value.portal.marker,
    }),
    audienceEmails: emails,
    sourceOwnership: Object.freeze(ownership),
  });
}

function parseSources(value: unknown): ReturningUninstallManagementSources | null {
  if (!record(value) || !exact(value, ['schemaVersion', 'revision', 'applyMode', 'sources']) ||
    value.schemaVersion !== 1 || !Number.isSafeInteger(value.revision) || (value.revision as number) < 1 ||
    value.applyMode !== 'oauth_per_action' || !Array.isArray(value.sources) || value.sources.length > 32) return null;
  const sources: ReturningUninstallManagementSources['sources'][number][] = [];
  for (const raw of value.sources) {
    if (!record(raw)) return null;
    const legacy = exact(raw, ['id', 'label', 'url', 'enabledTools', 'status']);
    const current = exact(raw, ['id', 'label', 'url', 'authMode', 'enabledTools', 'status']);
    const authMode = legacy ? 'none' : raw.authMode;
    if ((!legacy && !current) || typeof raw.id !== 'string' || !SOURCE_ID.test(raw.id) ||
      typeof raw.label !== 'string' || raw.label.length < 1 || raw.label.length > 128 ||
      /[\u0000-\u001f\u007f<>{}\\]/u.test(raw.label) || !publicUrl(raw.url) ||
      (authMode !== 'none' && authMode !== 'oauth') || !Array.isArray(raw.enabledTools) ||
      raw.enabledTools.length < 1 || raw.enabledTools.length > 64 ||
      raw.enabledTools.some((tool) => typeof tool !== 'string' || !TOOL.test(tool)) ||
      new Set(raw.enabledTools).size !== raw.enabledTools.length ||
      (raw.status !== 'installed' && raw.status !== 'draft')) return null;
    sources.push(Object.freeze({
      id: raw.id,
      label: raw.label,
      url: raw.url,
      authMode,
      enabledTools: Object.freeze([...(raw.enabledTools as string[])]),
      status: raw.status,
    }));
  }
  if (new Set(sources.map((item) => item.id)).size !== sources.length ||
    new Set(sources.map((item) => item.url)).size !== sources.length) return null;
  return Object.freeze({
    schemaVersion: 1,
    revision: value.revision as number,
    applyMode: 'oauth_per_action',
    sources: Object.freeze(sources),
  });
}

function parseRuntime(value: unknown, expectation: ReturningUninstallAuthorityExpectation): ReturningUninstallRuntimeAuthority | null {
  let expectedManagement: URL;
  try { expectedManagement = new URL(expectation.managementOrigin); } catch { return null; }
  if (!record(value) || !exact(value, [
    'release', 'artifactSha256', 'updateChannel', 'updateKeyId', 'updatePublicKey',
    'accountId', 'zoneId', 'zoneName', 'workerName', 'workersSubdomain', 'managementHostname',
  ]) || typeof value.release !== 'string' || !RELEASE.test(value.release) ||
    typeof value.artifactSha256 !== 'string' || !HASH.test(value.artifactSha256) ||
    typeof value.updateChannel !== 'string' || !UPDATE_CHANNEL.test(value.updateChannel) ||
    typeof value.updateKeyId !== 'string' || !UPDATE_KEY_ID.test(value.updateKeyId) ||
    typeof value.updatePublicKey !== 'string' || !UPDATE_PUBLIC_KEY.test(value.updatePublicKey) ||
    value.accountId !== expectation.accountId || typeof value.zoneId !== 'string' || !ACCOUNT_ID.test(value.zoneId) ||
    !hostname(value.zoneName) || value.workerName !== expectation.workerName ||
    value.workersSubdomain !== expectation.workersSubdomain || !hostname(value.managementHostname) ||
    value.managementHostname !== expectedManagement.hostname) return null;
  return Object.freeze({
    release: value.release,
    artifactSha256: value.artifactSha256,
    updateChannel: value.updateChannel as 'canary' | 'stable',
    updateKeyId: value.updateKeyId,
    updatePublicKey: value.updatePublicKey,
    accountId: value.accountId,
    zoneId: value.zoneId,
    zoneName: value.zoneName,
    workerName: value.workerName,
    workersSubdomain: value.workersSubdomain,
    managementHostname: value.managementHostname,
  });
}

function receiptExpectation(value: unknown): ReadyInstallationReceiptExpectation | null {
  if (!record(value) || !record(value.target) || !record(value.accessPolicy) || !Array.isArray(value.resources) ||
    typeof value.installationId !== 'string' || typeof value.release !== 'string' ||
    typeof value.desiredHash !== 'string') return null;
  const resources: InstallationReceiptResourceExpectation[] = [];
  for (const raw of value.resources) {
    if (!record(raw) || typeof raw.kind !== 'string' || typeof raw.key !== 'string' ||
      typeof raw.desiredHash !== 'string' || typeof raw.marker !== 'string') return null;
    resources.push(Object.freeze({
      kind: raw.kind as InstallationReceiptResourceExpectation['kind'],
      key: raw.key,
      desiredHash: raw.desiredHash,
      marker: raw.marker,
      ...(raw.identityHash === undefined ? {} : { identityHash: raw.identityHash as string }),
    }));
  }
  return Object.freeze({
    installationId: value.installationId,
    release: value.release,
    desiredHash: value.desiredHash,
    target: Object.freeze({ ...(value.target as unknown as ReadyInstallationReceiptExpectation['target']) }),
    accessPolicy: Object.freeze({
      ...(value.accessPolicy as unknown as ReadyInstallationReceiptExpectation['accessPolicy']),
    }),
    resources: Object.freeze(resources),
  });
}

export async function parseReturningUninstallImportedAuthority(
  value: unknown,
  expectation: ReturningUninstallAuthorityExpectation,
): Promise<ReturningUninstallImportedAuthority> {
  if (!ACTION_ID.test(expectation.actionId) || expectation.actorEmail !== expectation.actorEmail.toLowerCase() ||
    !EMAIL.test(expectation.actorEmail) || !INSTALLATION_ID.test(expectation.installationId) ||
    !ACCOUNT_ID.test(expectation.accountId) || !WORKER_NAME.test(expectation.workerName) ||
    !DNS_LABEL.test(expectation.workersSubdomain) || !hostname(expectation.portalHostname) ||
    typeof expectation.gatewayName !== 'string') throw new DeployError(400, 'bad_request');
  if (!record(value) || !exact(value, ['schemaVersion', 'actionId', 'status', 'authority']) ||
    value.schemaVersion !== 1 || value.actionId !== expectation.actionId || value.status !== 'authorized' ||
    !record(value.authority) || !exact(value.authority, [
      'schemaVersion', 'installationId', 'root', 'control', 'sources', 'runtime',
    ]) || value.authority.schemaVersion !== 1 || value.authority.installationId !== expectation.installationId ||
    !record(value.authority.root) || !exact(value.authority.root, ['receipt'])) {
    throw new DeployError(409, 'session_conflict');
  }
  const rawReceipt = value.authority.root.receipt;
  const expectedReceipt = receiptExpectation(rawReceipt);
  const receipt = expectedReceipt ? await parseReadyInstallationReceipt(rawReceipt, expectedReceipt) : null;
  const control = parseControl(value.authority.control, expectation.installationId, expectation.accountId);
  const sources = parseSources(value.authority.sources);
  const runtime = parseRuntime(value.authority.runtime, expectation);
  const rootPortal = receipt?.resources.find((resource) => resource.kind === 'portal');
  const rootSourceResources = receipt?.resources.filter((resource) => (
    SOURCE_RESOURCE_ORDER.includes(resource.kind as typeof SOURCE_RESOURCE_ORDER[number])
  )) ?? [];
  const receiptSourceOwners = control?.sourceOwnership.filter((ownership) => (
    ownership.resources.length === rootSourceResources.length && ownership.resources.every((resource, index) => (
      canonicalJson(resource) === canonicalJson(rootSourceResources[index])
    ))
  )) ?? [];
  const installedSourceIds = sources?.sources.filter((source) => source.status === 'installed')
    .map((source) => source.id).sort() ?? [];
  const ownershipSourceIds = control?.sourceOwnership.map((ownership) => ownership.sourceId).sort() ?? [];
  let providerLocatorsValid = receipt !== null && control !== null;
  const providerLocators = new Set<string>();
  if (receipt && control) {
    const addLocator = (resource: ReadyInstallationReceipt['resources'][number] | ReturningUninstallControlResource) => {
      const locator = resource.kind === 'source_access_application' || resource.kind === 'portal_access_application'
        ? `access_application\u0000${resource.provider.id}`
        : resource.kind === 'source_access_policy' || resource.kind === 'portal_access_policy'
          ? `access_policy\u0000${resource.provider.parentId}\u0000${resource.provider.id}`
          : `${resource.kind}\u0000${resource.provider.id}`;
      if (providerLocators.has(locator)) providerLocatorsValid = false;
      providerLocators.add(locator);
    };
    receipt.resources.forEach(addLocator);
    for (const ownership of control.sourceOwnership) {
      if (receiptSourceOwners.some((candidate) => candidate.sourceId === ownership.sourceId)) continue;
      ownership.resources.forEach(addLocator);
    }
  }
  if (!receipt || !control || !sources || !runtime ||
    receipt.installationId !== expectation.installationId || receipt.target.accountId !== expectation.accountId ||
    receipt.target.zoneId !== runtime.zoneId || receipt.target.zoneName !== runtime.zoneName ||
    receipt.target.hostname !== expectation.portalHostname || control.portal.hostname !== expectation.portalHostname ||
    control.portal.name !== expectation.gatewayName || control.portal.id !== rootPortal?.provider.id ||
    control.portal.marker !== rootPortal.marker ||
    canonicalJson(installedSourceIds) !== canonicalJson(ownershipSourceIds) ||
    !providerLocatorsValid ||
    (rootSourceResources.length > 0 ? receiptSourceOwners.length !== 1 : receiptSourceOwners.length !== 0)) {
    throw new DeployError(409, 'session_conflict');
  }
  const stableSemantic = Object.freeze({
    schemaVersion: 1 as const,
    installationId: expectation.installationId,
    receipt,
    control,
    sources,
    runtime,
  });
  const authorityHash = `sha256:${await sha256Hex(canonicalJson(stableSemantic))}`;
  const actionSemantic = Object.freeze({
    schemaVersion: 1 as const,
    authorityHash,
    actionId: expectation.actionId,
    actorEmail: expectation.actorEmail,
  });
  const actionProofHash = `sha256:${await sha256Hex(canonicalJson(actionSemantic))}`;
  const imported = Object.freeze({
    ...stableSemantic,
    actionId: expectation.actionId,
    actorEmail: expectation.actorEmail,
    authorityHash,
    actionProofHash,
  });
  assertSecretFree(imported);
  return imported;
}

export async function requireReturningUninstallImportedAuthority(
  value: unknown,
): Promise<ReturningUninstallImportedAuthority> {
  if (!record(value) || !record(value.control) || !record(value.control.portal) || !record(value.runtime) ||
    typeof value.actionId !== 'string' || typeof value.actorEmail !== 'string' ||
    typeof value.installationId !== 'string' ||
    typeof value.runtime.accountId !== 'string' || typeof value.runtime.workerName !== 'string' ||
    typeof value.runtime.workersSubdomain !== 'string' || typeof value.runtime.managementHostname !== 'string' ||
    typeof value.control.portal.hostname !== 'string' || typeof value.control.portal.name !== 'string') {
    throw new DeployError(500, 'session_invalid');
  }
  const parsed = await parseReturningUninstallImportedAuthority({
    schemaVersion: 1,
    actionId: value.actionId,
    status: 'authorized',
    authority: {
      schemaVersion: 1,
      installationId: value.installationId,
      root: { receipt: value.receipt },
      control: value.control,
      sources: value.sources,
      runtime: value.runtime,
    },
  }, {
    actionId: value.actionId,
    actorEmail: value.actorEmail,
    installationId: value.installationId,
    accountId: value.runtime.accountId,
    workerName: value.runtime.workerName,
    workersSubdomain: value.runtime.workersSubdomain,
    managementOrigin: `https://${value.runtime.managementHostname}`,
    portalHostname: value.control.portal.hostname,
    gatewayName: value.control.portal.name,
  }).catch(() => null);
  if (!parsed || parsed.authorityHash !== value.authorityHash || canonicalJson(parsed) !== canonicalJson(value)) {
    throw new DeployError(500, 'session_invalid');
  }
  return parsed;
}

export function returningUninstallAuthorityCanonicalJson(value: unknown): string {
  return canonicalJson(value);
}

import * as v from 'valibot';

import { canonicalJson } from './canonical-json';
import { sha256Hex } from './crypto';
import { DeployError } from './errors';
import { deepFreezePlainData, isPlainDataTree } from './plain-data';
import {
  parseReadyInstallationReceipt,
  readyInstallationReceiptExpectationFromCandidate,
  type ReadyInstallationReceipt,
} from './provider-neutral-installation-receipt';
import { assertSecretFree, type GatewayResourceKind } from './schema';

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
const MAX_ENABLED_TOOLS_PER_SOURCE = 500;
const MANAGEMENT_SOURCES_LIMIT_BYTES = 1024 * 1024;
const EMAIL = /^[^\s@]{1,64}@[A-Za-z0-9.-]{1,190}$/u;
const UPDATE_KEY_ID = /^[a-z0-9][a-z0-9._-]{0,63}$/u;
const UPDATE_PUBLIC_KEY = /^[A-Za-z0-9_-]{43}$/u;
const SOURCE_RESOURCE_ORDER = Object.freeze([
  'mcp_server',
  'source_access_application',
  'source_access_policy',
] as const satisfies readonly GatewayResourceKind[]);

function validHostname(value: string): boolean {
  return value.length <= 253 && value === value.toLowerCase() && !value.includes(':') &&
    value.split('.').length >= 2 && value.split('.').every((label) => DNS_LABEL.test(label));
}

function validPublicSourceUrl(value: string): boolean {
  if (value.length > 2048) return false;
  try {
    const url = new URL(value);
    const blockedSuffixes = ['.internal', '.invalid', '.local', '.localhost', '.onion', '.test'];
    return url.protocol === 'https:' && !url.username && !url.password && !url.port &&
      url.pathname !== '/' && !url.search && !url.hash && validHostname(url.hostname) &&
      url.hostname !== 'localhost' &&
      !blockedSuffixes.some((suffix) => url.hostname.endsWith(suffix)) && url.href === value;
  } catch {
    return false;
  }
}

function managementHostname(value: string): string | null {
  try {
    const url = new URL(value);
    if (url.protocol !== 'https:' || url.origin !== value || !validHostname(url.hostname)) return null;
    return url.hostname;
  } catch {
    return null;
  }
}

function validControlPlaneOrigin(value: string): boolean {
  try {
    const url = new URL(value);
    return url.protocol === 'https:' && url.origin === value && !url.username && !url.password &&
      !url.port && url.pathname === '/' && !url.search && !url.hash;
  } catch {
    return false;
  }
}

function validSafeName(value: string): boolean {
  return ![...value].some((character) => {
    const codePoint = character.codePointAt(0) ?? 0;
    return codePoint <= 31 || codePoint === 127 || '<>{}\\'.includes(character);
  });
}

function validSourceLabel(value: string): boolean {
  return value.length >= 2 && value.length <= 80 && value.trim() === value &&
    ![...value].some((character) => {
      const codePoint = character.codePointAt(0) ?? 0;
      return codePoint <= 31 || codePoint === 127;
    });
}

function normalizedEmailList(value: string[]): boolean {
  return value.every((email, index) => (
    email === email.toLowerCase() && EMAIL.test(email) &&
    (index === 0 || email > (value[index - 1] ?? ''))
  ));
}

const actionIdSchema = v.pipe(v.string(), v.regex(ACTION_ID));
const accountIdSchema = v.pipe(v.string(), v.regex(ACCOUNT_ID));
const installationIdSchema = v.pipe(v.string(), v.regex(INSTALLATION_ID));
const releaseSchema = v.pipe(v.string(), v.regex(RELEASE));
const hashSchema = v.pipe(v.string(), v.regex(HASH));
const providerIdSchema = v.pipe(v.string(), v.regex(PROVIDER_ID));
const resourceKeySchema = v.pipe(v.string(), v.regex(RESOURCE_KEY));
const sourceIdSchema = v.pipe(v.string(), v.regex(SOURCE_ID));
const workerNameSchema = v.pipe(v.string(), v.regex(WORKER_NAME));
const workersSubdomainSchema = v.pipe(v.string(), v.regex(DNS_LABEL));
const hostnameSchema = v.pipe(v.string(), v.check(validHostname));
const safeNameSchema = v.pipe(
  v.string(),
  v.minLength(1),
  v.maxLength(128),
  v.check(validSafeName),
);
const sourceLabelSchema = v.pipe(v.string(), v.check(validSourceLabel));
const emailSchema = v.pipe(
  v.string(),
  v.regex(EMAIL),
  v.check((email) => email === email.toLowerCase()),
);
const normalizedEmailsSchema = v.pipe(
  v.array(emailSchema),
  v.minLength(1),
  v.maxLength(64),
  v.check(normalizedEmailList),
);
const publicSourceUrlSchema = v.pipe(v.string(), v.check(validPublicSourceUrl));
const toolSchema = v.pipe(v.string(), v.regex(TOOL));
const enabledToolsSchema = v.pipe(
  v.array(toolSchema),
  v.minLength(1),
  v.maxLength(MAX_ENABLED_TOOLS_PER_SOURCE),
  v.check((tools) => new Set(tools).size === tools.length),
);
const providerSchema = v.strictObject({ id: providerIdSchema });
const policyProviderSchema = v.strictObject({ id: providerIdSchema, parentId: providerIdSchema });
const mcpServerResourceSchema = v.strictObject({
  kind: v.literal('mcp_server'),
  key: resourceKeySchema,
  provider: providerSchema,
  desiredHash: hashSchema,
  marker: v.string(),
});
const sourceApplicationResourceSchema = v.strictObject({
  kind: v.literal('source_access_application'),
  key: resourceKeySchema,
  provider: providerSchema,
  desiredHash: hashSchema,
  marker: v.string(),
});
const sourcePolicyResourceSchema = v.strictObject({
  kind: v.literal('source_access_policy'),
  key: resourceKeySchema,
  provider: policyProviderSchema,
  desiredHash: hashSchema,
  marker: v.string(),
  identityHash: hashSchema,
});
const controlResourceSchema = v.union([
  mcpServerResourceSchema,
  sourceApplicationResourceSchema,
  sourcePolicyResourceSchema,
]);
const controlSchema = v.strictObject({
  schemaVersion: v.literal(1),
  installationId: installationIdSchema,
  accountId: accountIdSchema,
  portal: v.strictObject({
    id: providerIdSchema,
    name: safeNameSchema,
    hostname: hostnameSchema,
    marker: v.string(),
  }),
  audienceEmails: normalizedEmailsSchema,
  sourceOwnership: v.pipe(v.array(v.strictObject({
    sourceId: sourceIdSchema,
    resources: v.pipe(v.array(controlResourceSchema), v.length(3)),
  })), v.maxLength(32)),
});
const sourceBaseSchema = {
  id: sourceIdSchema,
  label: sourceLabelSchema,
  url: publicSourceUrlSchema,
  enabledTools: enabledToolsSchema,
  status: v.picklist(['installed', 'draft']),
};
const legacySourceSchema = v.strictObject(sourceBaseSchema);
const currentSourceSchema = v.strictObject({
  ...sourceBaseSchema,
  authMode: v.picklist(['none', 'oauth']),
});
const sourcesSchema = v.strictObject({
  schemaVersion: v.literal(1),
  revision: v.pipe(v.number(), v.safeInteger(), v.minValue(1)),
  applyMode: v.literal('oauth_per_action'),
  sources: v.pipe(v.array(v.union([legacySourceSchema, currentSourceSchema])), v.maxLength(32)),
});
const runtimeSchema = v.strictObject({
  release: releaseSchema,
  artifactSha256: hashSchema,
  controlPlaneOrigin: v.string(),
  updateChannel: v.picklist(['canary', 'stable']),
  updateKeyId: v.pipe(v.string(), v.regex(UPDATE_KEY_ID)),
  updatePublicKey: v.pipe(v.string(), v.regex(UPDATE_PUBLIC_KEY)),
  accountId: accountIdSchema,
  zoneId: accountIdSchema,
  zoneName: hostnameSchema,
  workerName: workerNameSchema,
  workersSubdomain: workersSubdomainSchema,
  managementHostname: hostnameSchema,
});
const expectationSchema = v.strictObject({
  actionId: actionIdSchema,
  actorEmail: emailSchema,
  installationId: installationIdSchema,
  accountId: accountIdSchema,
  workerName: workerNameSchema,
  workersSubdomain: workersSubdomainSchema,
  managementOrigin: v.string(),
  portalHostname: hostnameSchema,
  gatewayName: safeNameSchema,
});
const importedEnvelopeSchema = v.strictObject({
  schemaVersion: v.literal(1),
  actionId: actionIdSchema,
  status: v.literal('authorized'),
  authority: v.strictObject({
    schemaVersion: v.literal(1),
    installationId: installationIdSchema,
    root: v.strictObject({ receipt: v.unknown() }),
    control: controlSchema,
    sources: sourcesSchema,
    runtime: runtimeSchema,
  }),
});
const storedAuthoritySchema = v.strictObject({
  schemaVersion: v.literal(1),
  actionId: actionIdSchema,
  actorEmail: emailSchema,
  installationId: installationIdSchema,
  receipt: v.unknown(),
  control: controlSchema,
  sources: sourcesSchema,
  runtime: runtimeSchema,
  authorityHash: hashSchema,
  actionProofHash: hashSchema,
});

type ParsedControl = v.InferOutput<typeof controlSchema>;
type ParsedSources = v.InferOutput<typeof sourcesSchema>;
type ParsedRuntime = v.InferOutput<typeof runtimeSchema>;
type ParsedExpectation = v.InferOutput<typeof expectationSchema>;

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
  readonly controlPlaneOrigin: string;
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

function providerLocator(resource: ReturningUninstallControlResource): string {
  if (resource.kind === 'source_access_application') {
    return `access_application\u0000${resource.provider.id}`;
  }
  if (resource.kind === 'source_access_policy') {
    return `access_policy\u0000${resource.provider.parentId ?? ''}\u0000${resource.provider.id}`;
  }
  return `${resource.kind}\u0000${resource.provider.id}`;
}

function parseControl(
  control: ParsedControl,
  installationId: string,
  accountId: string,
): ReturningUninstallManagementControl | null {
  if (control.installationId !== installationId || control.accountId !== accountId) return null;
  const providerLocators = new Set<string>();
  for (const ownership of control.sourceOwnership) {
    if (!SOURCE_RESOURCE_ORDER.every((kind, index) => ownership.resources[index]?.kind === kind)) return null;
    for (const resource of ownership.resources) {
      if (resource.marker !== `acg:v1:${installationId}:${resource.key}`) return null;
      const locator = providerLocator(resource);
      if (providerLocators.has(locator)) return null;
      providerLocators.add(locator);
    }
    const application = ownership.resources[1];
    const policy = ownership.resources[2];
    if (application?.kind !== 'source_access_application' || policy?.kind !== 'source_access_policy' ||
        policy.provider.parentId !== application.provider.id) return null;
  }
  if (new Set(control.sourceOwnership.map((ownership) => ownership.sourceId)).size !==
      control.sourceOwnership.length) return null;
  return deepFreezePlainData(control);
}

function parseSources(input: ParsedSources): ReturningUninstallManagementSources | null {
  const sources: ReturningUninstallManagementSources['sources'][number][] = input.sources.map((source) => ({
    id: source.id,
    label: source.label,
    url: source.url,
    authMode: 'authMode' in source ? source.authMode : 'none',
    enabledTools: source.enabledTools,
    status: source.status,
  }));
  if (new Set(sources.map((source) => source.id)).size !== sources.length ||
      new Set(sources.map((source) => source.url)).size !== sources.length) return null;
  const record = {
    schemaVersion: 1,
    revision: input.revision,
    applyMode: 'oauth_per_action',
    sources,
  } as const;
  if (new TextEncoder().encode(canonicalJson(record)).byteLength > MANAGEMENT_SOURCES_LIMIT_BYTES) {
    return null;
  }
  return deepFreezePlainData(record);
}

function parseRuntime(
  runtime: ParsedRuntime,
  expectation: ParsedExpectation,
  expectedManagementHostname: string,
): ReturningUninstallRuntimeAuthority | null {
  if (runtime.accountId !== expectation.accountId || runtime.workerName !== expectation.workerName ||
      runtime.workersSubdomain !== expectation.workersSubdomain ||
      runtime.managementHostname !== expectedManagementHostname ||
      !validControlPlaneOrigin(runtime.controlPlaneOrigin)) return null;
  return deepFreezePlainData(runtime);
}

function isSourceResourceKind(kind: GatewayResourceKind): boolean {
  return kind === 'mcp_server' || kind === 'source_access_application' || kind === 'source_access_policy';
}

function receiptProviderLocator(resource: ReadyInstallationReceipt['resources'][number]): string {
  if (resource.kind === 'source_access_application' || resource.kind === 'portal_access_application') {
    return `access_application\u0000${resource.provider.id}`;
  }
  if (resource.kind === 'source_access_policy' || resource.kind === 'portal_access_policy') {
    return `access_policy\u0000${resource.provider.parentId ?? ''}\u0000${resource.provider.id}`;
  }
  return `${resource.kind}\u0000${resource.provider.id}`;
}

interface StableAuthoritySemantic {
  readonly schemaVersion: 1;
  readonly installationId: string;
  readonly receipt: ReadyInstallationReceipt;
  readonly control: ReturningUninstallManagementControl;
  readonly sources: ReturningUninstallManagementSources;
  readonly runtime: ReturningUninstallRuntimeAuthority;
}

interface ActionAuthoritySemantic {
  readonly schemaVersion: 1;
  readonly authorityHash: string;
  readonly actionId: string;
  readonly actorEmail: string;
}

export async function parseReturningUninstallImportedAuthority<Input>(
  input: Input,
  expectationInput: ReturningUninstallAuthorityExpectation,
): Promise<ReturningUninstallImportedAuthority> {
  if (!isPlainDataTree(expectationInput)) throw new DeployError(400, 'bad_request');
  const expectationResult = v.safeParse(expectationSchema, expectationInput);
  const expectedManagementHostname = expectationResult.success
    ? managementHostname(expectationResult.output.managementOrigin)
    : null;
  if (!expectationResult.success || expectedManagementHostname === null) {
    throw new DeployError(400, 'bad_request');
  }
  if (!isPlainDataTree(input)) throw new DeployError(409, 'session_conflict');
  const envelopeResult = v.safeParse(importedEnvelopeSchema, input);
  if (!envelopeResult.success || envelopeResult.output.actionId !== expectationResult.output.actionId ||
      envelopeResult.output.authority.installationId !== expectationResult.output.installationId) {
    throw new DeployError(409, 'session_conflict');
  }

  const expectation = expectationResult.output;
  const authority = envelopeResult.output.authority;
  const expectedReceipt = readyInstallationReceiptExpectationFromCandidate(authority.root.receipt);
  const receipt = expectedReceipt
    ? await parseReadyInstallationReceipt(authority.root.receipt, expectedReceipt)
    : null;
  const control = parseControl(authority.control, expectation.installationId, expectation.accountId);
  const sources = parseSources(authority.sources);
  const runtime = parseRuntime(authority.runtime, expectation, expectedManagementHostname);
  const rootPortal = receipt?.resources.find((resource) => resource.kind === 'portal');
  const rootSourceResources = receipt?.resources.filter((resource) => isSourceResourceKind(resource.kind)) ?? [];
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
    for (const resource of receipt.resources) {
      const locator = receiptProviderLocator(resource);
      if (providerLocators.has(locator)) providerLocatorsValid = false;
      providerLocators.add(locator);
    }
    for (const ownership of control.sourceOwnership) {
      if (receiptSourceOwners.some((candidate) => candidate.sourceId === ownership.sourceId)) continue;
      for (const resource of ownership.resources) {
        const locator = providerLocator(resource);
        if (providerLocators.has(locator)) providerLocatorsValid = false;
        providerLocators.add(locator);
      }
    }
  }
  if (!receipt || !control || !sources || !runtime || !rootPortal ||
      receipt.installationId !== expectation.installationId || receipt.target.accountId !== expectation.accountId ||
      receipt.target.zoneId !== runtime.zoneId || receipt.target.zoneName !== runtime.zoneName ||
      receipt.target.hostname !== expectation.portalHostname || control.portal.hostname !== expectation.portalHostname ||
      control.portal.name !== expectation.gatewayName || control.portal.id !== rootPortal.provider.id ||
      control.portal.marker !== rootPortal.marker || canonicalJson(installedSourceIds) !== canonicalJson(ownershipSourceIds) ||
      !providerLocatorsValid ||
      (rootSourceResources.length > 0 ? receiptSourceOwners.length !== 1 : receiptSourceOwners.length !== 0)) {
    throw new DeployError(409, 'session_conflict');
  }

  const stableSemantic: StableAuthoritySemantic = {
    schemaVersion: 1,
    installationId: expectation.installationId,
    receipt,
    control,
    sources,
    runtime,
  };
  const authorityHash = `sha256:${await sha256Hex(canonicalJson(stableSemantic))}`;
  const actionSemantic: ActionAuthoritySemantic = {
    schemaVersion: 1,
    authorityHash,
    actionId: expectation.actionId,
    actorEmail: expectation.actorEmail,
  };
  const actionProofHash = `sha256:${await sha256Hex(canonicalJson(actionSemantic))}`;
  const imported: ReturningUninstallImportedAuthority = {
    ...stableSemantic,
    actionId: expectation.actionId,
    actorEmail: expectation.actorEmail,
    authorityHash,
    actionProofHash,
  };
  assertSecretFree(imported);
  return deepFreezePlainData(imported);
}

export async function requireReturningUninstallImportedAuthority<Input>(
  input: Input,
): Promise<ReturningUninstallImportedAuthority> {
  if (!isPlainDataTree(input)) throw new DeployError(500, 'session_invalid');
  const candidateResult = v.safeParse(storedAuthoritySchema, input);
  if (!candidateResult.success) throw new DeployError(500, 'session_invalid');
  const candidate = candidateResult.output;
  const parsed = await parseReturningUninstallImportedAuthority({
    schemaVersion: 1,
    actionId: candidate.actionId,
    status: 'authorized',
    authority: {
      schemaVersion: 1,
      installationId: candidate.installationId,
      root: { receipt: candidate.receipt },
      control: candidate.control,
      sources: candidate.sources,
      runtime: candidate.runtime,
    },
  }, {
    actionId: candidate.actionId,
    actorEmail: candidate.actorEmail,
    installationId: candidate.installationId,
    accountId: candidate.runtime.accountId,
    workerName: candidate.runtime.workerName,
    workersSubdomain: candidate.runtime.workersSubdomain,
    managementOrigin: `https://${candidate.runtime.managementHostname}`,
    portalHostname: candidate.control.portal.hostname,
    gatewayName: candidate.control.portal.name,
  }).catch(() => null);
  if (!parsed || parsed.authorityHash !== candidate.authorityHash || canonicalJson(parsed) !== canonicalJson(candidate)) {
    throw new DeployError(500, 'session_invalid');
  }
  return parsed;
}

export function returningUninstallAuthorityCanonicalJson<Value>(value: Value): string {
  return canonicalJson(value);
}

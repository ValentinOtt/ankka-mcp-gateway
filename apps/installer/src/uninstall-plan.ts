import type { RequiredOauthScope } from './constants';
import { sha256Hex } from './crypto';
import { DeployError } from './errors';
import {
  isCompleteInstallJournal,
  prepareFinalConvergenceRecordAndLocator,
  requireInstallJournal,
  type InstallJournal,
} from './install-journal';
import { assertSecretFree } from './schema';

const SAFE_INTEGER_MAX = Number.MAX_SAFE_INTEGER;
const PLAN_ID = /^uninstall-plan-[a-f0-9]{24}$/u;
const PREFIXED_SHA256 = /^sha256:[a-f0-9]{64}$/u;
const SHA256 = /^[a-f0-9]{64}$/u;
const INSTALLATION_ID = /^acg-[a-f0-9]{24}$/u;
const RELEASE = /^gateway-v(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)(?:-[a-z0-9.-]+)?$/u;
const WORKER_NAME = /^[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$/u;
const OWNERSHIP_MARKER = /^acg-[a-f0-9]{24}$/u;
const TOOL_NAME = /^[A-Za-z0-9_.:/-]{1,128}$/u;
const DNS_LABEL = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/u;
const CONTROL_CHARACTER = /[\u0000-\u001f\u007f]/u;
const EMAIL_LIKE = /(?:^|[^A-Za-z0-9.!#$%&'*+/=?^_`{|}~-])[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}(?:$|[^A-Za-z0-9.-])/u;

export const MAX_STATIC_UNINSTALL_PLAN_TTL_MS = 10 * 60 * 1_000;

export const STATIC_UNINSTALL_OAUTH_SCOPES = Object.freeze([
  'access-acct.write',
  'access.write',
  'account-settings.read',
  'dns.write',
  'mcp-portals.write',
  'memberships.read',
  'user-details.read',
  'workers-routes.read',
  'workers-scripts.write',
  'zone.read',
] as const satisfies readonly RequiredOauthScope[]);

export const STATIC_UNINSTALL_GATEWAY_RESOURCE_ORDER = Object.freeze([
  'mcp_server',
  'source_access_application',
  'source_access_policy',
  'portal',
  'portal_access_application',
  'portal_access_policy',
  'dns_record',
] as const);

export type StaticUninstallGatewayResourceKind =
  (typeof STATIC_UNINSTALL_GATEWAY_RESOURCE_ORDER)[number];

export const STATIC_UNINSTALL_STEP_ORDER = Object.freeze([
  'temporary_cleanup_workers_dev_bridge',
  'gateway_resources_remove',
  'management_custom_domain_remove',
  'management_admin_policy_remove',
  'management_access_application_remove',
  'admin_state_retire',
  'management_worker_remove',
  'no_ankka_managed_residue_verify',
] as const);

export const STATIC_UNINSTALL_TEMPORARY_WORKER_LIFECYCLE = Object.freeze([
  'cleanup_worker_version_create',
  'cleanup_worker_deployment_create',
  'workers_dev_enable',
  'gateway_resources_remove',
  'workers_dev_disable',
  'restore_clean_worker_deployment',
] as const);

export const STATIC_UNINSTALL_RETIREMENT_LIFECYCLE = Object.freeze([
  'retirement_worker_version_create',
  'retirement_worker_deployment_create',
  'admin_state_absence_prove',
] as const);

export type StaticUninstallStepKind = (typeof STATIC_UNINSTALL_STEP_ORDER)[number];

export const STATIC_UNINSTALL_RESIDUE_SCOPE = Object.freeze([
  'gateway_resources',
  'management_custom_domain',
  'management_dns_record',
  'overlapping_worker_route',
  'management_access_policy',
  'management_access_application',
  'admin_state',
  'management_worker',
] as const);

export const STATIC_UNINSTALL_PROVIDER_NOTICE =
  'Cloudflare retains the Advanced Certificate after the Custom Domain is removed. It is outside Ankka\'s reviewed OAuth scope and must be reviewed or removed manually in Cloudflare.' as const;

export const STATIC_UNINSTALL_STEP_SUMMARIES = Object.freeze({
  gateway_resources_remove:
    'Remove the customer gateway resources while the reviewed temporary cleanup bridge is active.',
  temporary_cleanup_workers_dev_bridge:
    'Create and deploy the reviewed cleanup Worker version, enable workers.dev with preview URLs disabled only as a bridge enclosing gateway removal, disable workers.dev, then restore the clean deployment before management resource removal.',
  management_custom_domain_remove:
    'Remove the exact management Custom Domain and require its same-name DNS companion to disappear.',
  management_admin_policy_remove:
    'Remove the exact management administrator Access policy before its parent application.',
  management_access_application_remove:
    'Remove the exact management Access application after its policy is absent.',
  admin_state_retire:
    'Create and deploy the reviewed retirement Worker version, remove the AdminState class, then prove its durable state is absent.',
  management_worker_remove:
    'Delete the exact management Worker only after AdminState retirement is proven.',
  no_ankka_managed_residue_verify:
    'Prove that no Ankka-managed gateway, management domain, DNS, overlapping route, Access, AdminState, or Worker residue remains.',
} as const);

export interface StaticUninstallGatewayResourceSummary {
  readonly kind: StaticUninstallGatewayResourceKind;
  readonly name: string;
  readonly hostname: string;
}

export interface StaticUninstallGatewayResourcesStep {
  readonly order: 2;
  readonly kind: 'gateway_resources_remove';
  readonly summary: typeof STATIC_UNINSTALL_STEP_SUMMARIES.gateway_resources_remove;
  readonly resources: readonly StaticUninstallGatewayResourceSummary[];
}

export interface StaticUninstallCleanupBridgeStep {
  readonly order: 1;
  readonly kind: 'temporary_cleanup_workers_dev_bridge';
  readonly summary: typeof STATIC_UNINSTALL_STEP_SUMMARIES.temporary_cleanup_workers_dev_bridge;
  readonly workerName: string;
  readonly temporaryWorkerLifecycle: typeof STATIC_UNINSTALL_TEMPORARY_WORKER_LIFECYCLE;
  readonly workersDev: {
    readonly enabledOnlyDuringCleanup: true;
    readonly previewUrlsEnabled: false;
    readonly disabledBeforeManagementRemoval: true;
  };
}

export interface StaticUninstallCustomDomainStep {
  readonly order: 3;
  readonly kind: 'management_custom_domain_remove';
  readonly summary: typeof STATIC_UNINSTALL_STEP_SUMMARIES.management_custom_domain_remove;
  readonly hostname: string;
  readonly workerName: string;
}

export interface StaticUninstallAdminPolicyStep {
  readonly order: 4;
  readonly kind: 'management_admin_policy_remove';
  readonly summary: typeof STATIC_UNINSTALL_STEP_SUMMARIES.management_admin_policy_remove;
  readonly name: string;
}

export interface StaticUninstallAccessApplicationStep {
  readonly order: 5;
  readonly kind: 'management_access_application_remove';
  readonly summary: typeof STATIC_UNINSTALL_STEP_SUMMARIES.management_access_application_remove;
  readonly name: string;
  readonly hostname: string;
}

export interface StaticUninstallAdminStateStep {
  readonly order: 6;
  readonly kind: 'admin_state_retire';
  readonly summary: typeof STATIC_UNINSTALL_STEP_SUMMARIES.admin_state_retire;
  readonly workerName: string;
  readonly retirementLifecycle: typeof STATIC_UNINSTALL_RETIREMENT_LIFECYCLE;
  readonly className: 'AdminState';
  readonly storage: 'sqlite';
}

export interface StaticUninstallWorkerStep {
  readonly order: 7;
  readonly kind: 'management_worker_remove';
  readonly summary: typeof STATIC_UNINSTALL_STEP_SUMMARIES.management_worker_remove;
  readonly workerName: string;
}

export interface StaticUninstallResidueStep {
  readonly order: 8;
  readonly kind: 'no_ankka_managed_residue_verify';
  readonly summary: typeof STATIC_UNINSTALL_STEP_SUMMARIES.no_ankka_managed_residue_verify;
  readonly scope: typeof STATIC_UNINSTALL_RESIDUE_SCOPE;
  readonly advancedCertificate: 'provider_retained_out_of_scope_manual';
}

export type StaticUninstallStep =
  | StaticUninstallGatewayResourcesStep
  | StaticUninstallCleanupBridgeStep
  | StaticUninstallCustomDomainStep
  | StaticUninstallAdminPolicyStep
  | StaticUninstallAccessApplicationStep
  | StaticUninstallAdminStateStep
  | StaticUninstallWorkerStep
  | StaticUninstallResidueStep;

export interface StaticUninstallPlan {
  readonly schemaVersion: 1;
  readonly planId: string;
  readonly planHash: string;
  readonly createdAt: number;
  readonly expiresAt: number;
  readonly writesPerformed: false;
  readonly installationId: string;
  readonly authorityHash: string;
  readonly requiredScopes: readonly RequiredOauthScope[];
  readonly gateway: {
    readonly name: string;
    readonly zoneName: string;
    readonly managementHostname: string;
    readonly portalHostname: string;
    readonly workerName: string;
  };
  readonly source: {
    readonly name: string;
    readonly hostname: string;
    readonly enabledTools: readonly string[];
  } | null;
  readonly release: {
    readonly id: string;
    readonly aggregateSha256: string;
  };
  readonly steps: readonly StaticUninstallStep[];
  readonly providerNotice: typeof STATIC_UNINSTALL_PROVIDER_NOTICE;
}

type StaticUninstallSemantic = Omit<StaticUninstallPlan, 'planId' | 'planHash' | 'createdAt' | 'expiresAt'>;

function invalid(status = 400, code: 'bad_request' | 'session_conflict' | 'session_invalid' = 'bad_request'): never {
  throw new DeployError(status, code);
}

function isPlainRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value) &&
    Object.getPrototypeOf(value) === Object.prototype;
}

function dataTree(
  value: unknown,
  active = new WeakSet<object>(),
  validated = new WeakSet<object>(),
): boolean {
  if (value === null || typeof value === 'string' || typeof value === 'boolean') return true;
  if (typeof value === 'number') return Number.isFinite(value);
  if (typeof value !== 'object') return false;
  if (validated.has(value)) return true;
  if (active.has(value)) return false;
  active.add(value);
  const array = Array.isArray(value);
  let valid = !((array && Object.getPrototypeOf(value) !== Array.prototype) ||
    (!array && Object.getPrototypeOf(value) !== Object.prototype));
  const keys = Reflect.ownKeys(value);
  if (keys.some((key) => typeof key === 'symbol')) valid = false;
  if (valid && array) {
    if (!keys.includes('length') || keys.length !== value.length + 1) valid = false;
    for (let index = 0; index < value.length; index += 1) {
      if (!Object.hasOwn(value, String(index))) valid = false;
    }
  }
  for (const key of valid ? keys : []) {
    if (array && key === 'length') continue;
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor || !Object.hasOwn(descriptor, 'value') || !descriptor.enumerable ||
      !dataTree(descriptor.value, active, validated)) {
      valid = false;
      break;
    }
  }
  active.delete(value);
  if (valid) validated.add(value);
  return valid;
}

function exactKeys(value: Record<string, unknown>, expected: readonly string[]): boolean {
  const actual = Object.keys(value).sort();
  const sorted = [...expected].sort();
  return actual.length === sorted.length && actual.every((key, index) => key === sorted[index]);
}

function canonicalJson(value: unknown): string {
  if (value === null || typeof value === 'string' || typeof value === 'boolean') return JSON.stringify(value);
  if (typeof value === 'number' && Number.isFinite(value)) return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (isPlainRecord(value)) {
    return `{${Object.keys(value).sort().map((key) =>
      `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(',')}}`;
  }
  throw new TypeError('canonical_uninstall_plan');
}

function canonicalEqual(left: unknown, right: unknown): boolean {
  try {
    return canonicalJson(left) === canonicalJson(right);
  } catch {
    return false;
  }
}

function deepFreeze<T>(value: T): T {
  if (value !== null && typeof value === 'object' && !Object.isFrozen(value)) {
    for (const child of Object.values(value as Record<string, unknown>)) deepFreeze(child);
    Object.freeze(value);
  }
  return value;
}

function safeInteger(value: unknown): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0 && value <= SAFE_INTEGER_MAX;
}

function validHostname(value: unknown): value is string {
  if (typeof value !== 'string' || value.length < 3 || value.length > 253 || value !== value.toLowerCase() ||
    value.endsWith('.') || value.includes('..')) return false;
  const labels = value.split('.');
  return labels.length >= 2 && labels.every((label) => DNS_LABEL.test(label));
}

function validPublicName(value: unknown, maximum = 128): value is string {
  return typeof value === 'string' && value.length > 0 && value.length <= maximum &&
    value.trim() === value && !CONTROL_CHARACTER.test(value) && !/[<>{}\\]/u.test(value) &&
    !value.includes('@') && !EMAIL_LIKE.test(` ${value} `);
}

function publicName(value: string, fallback: string): string {
  return validPublicName(value) ? value : fallback;
}

function canonicalTools(value: unknown): readonly string[] | null {
  if (!Array.isArray(value) || value.length < 1 || value.length > 64 ||
    !value.every((tool) => typeof tool === 'string' && TOOL_NAME.test(tool))) return null;
  const tools = [...value] as string[];
  const sorted = [...tools].sort();
  if (new Set(tools).size !== tools.length || !tools.every((tool, index) => tool === sorted[index])) return null;
  return Object.freeze(tools);
}

function exactScopes(value: unknown): value is readonly RequiredOauthScope[] {
  return Array.isArray(value) && value.length === STATIC_UNINSTALL_OAUTH_SCOPES.length &&
    value.every((scope, index) => scope === STATIC_UNINSTALL_OAUTH_SCOPES[index]);
}

function resourceSummaries(
  gatewayName: string,
  portalHostname: string,
  source: StaticUninstallPlan['source'],
): readonly StaticUninstallGatewayResourceSummary[] {
  return deepFreeze([
    ...(source === null ? [] : [
      { kind: 'mcp_server', name: source.name, hostname: source.hostname },
      { kind: 'source_access_application', name: `${source.name} source`, hostname: source.hostname },
      { kind: 'source_access_policy', name: `${source.name} users`, hostname: source.hostname },
    ] as StaticUninstallGatewayResourceSummary[]),
    { kind: 'portal', name: gatewayName, hostname: portalHostname },
    { kind: 'portal_access_application', name: `${gatewayName} portal`, hostname: portalHostname },
    { kind: 'portal_access_policy', name: `${gatewayName} portal users`, hostname: portalHostname },
    { kind: 'dns_record', name: portalHostname, hostname: portalHostname },
  ] as StaticUninstallGatewayResourceSummary[]);
}

function ownershipMarkerFromWorker(workerName: string): string | null {
  const match = workerName.match(/-(acg-[a-f0-9]{24})$/u);
  return match?.[1] && OWNERSHIP_MARKER.test(match[1]) ? match[1] : null;
}

function gatewaySlug(gatewayName: string): string {
  return gatewayName
    .toLowerCase()
    .replace(/[^a-z0-9]+/gu, '-')
    .replace(/^-+|-+$/gu, '')
    .slice(0, 20)
    .replace(/-$/u, '');
}

function stepsFor(input: {
  readonly gatewayName: string;
  readonly managementHostname: string;
  readonly portalHostname: string;
  readonly source: StaticUninstallPlan['source'];
  readonly workerName: string;
}): readonly StaticUninstallStep[] {
  const marker = ownershipMarkerFromWorker(input.workerName);
  if (!marker || input.workerName !== `ankka-gateway-${gatewaySlug(input.gatewayName)}-${marker}`) {
    return invalid(500, 'session_invalid');
  }
  return deepFreeze([
    {
      order: 1,
      kind: 'temporary_cleanup_workers_dev_bridge',
      summary: STATIC_UNINSTALL_STEP_SUMMARIES.temporary_cleanup_workers_dev_bridge,
      workerName: input.workerName,
      temporaryWorkerLifecycle: STATIC_UNINSTALL_TEMPORARY_WORKER_LIFECYCLE,
      workersDev: {
        enabledOnlyDuringCleanup: true,
        previewUrlsEnabled: false,
        disabledBeforeManagementRemoval: true,
      },
    },
    {
      order: 2,
      kind: 'gateway_resources_remove',
      summary: STATIC_UNINSTALL_STEP_SUMMARIES.gateway_resources_remove,
      resources: resourceSummaries(
        input.gatewayName,
        input.portalHostname,
        input.source,
      ),
    },
    {
      order: 3,
      kind: 'management_custom_domain_remove',
      summary: STATIC_UNINSTALL_STEP_SUMMARIES.management_custom_domain_remove,
      hostname: input.managementHostname,
      workerName: input.workerName,
    },
    {
      order: 4,
      kind: 'management_admin_policy_remove',
      summary: STATIC_UNINSTALL_STEP_SUMMARIES.management_admin_policy_remove,
      name: `${input.gatewayName} administrators [${marker}]`,
    },
    {
      order: 5,
      kind: 'management_access_application_remove',
      summary: STATIC_UNINSTALL_STEP_SUMMARIES.management_access_application_remove,
      name: `${input.gatewayName} management [${marker}]`,
      hostname: input.managementHostname,
    },
    {
      order: 6,
      kind: 'admin_state_retire',
      summary: STATIC_UNINSTALL_STEP_SUMMARIES.admin_state_retire,
      workerName: input.workerName,
      retirementLifecycle: STATIC_UNINSTALL_RETIREMENT_LIFECYCLE,
      className: 'AdminState',
      storage: 'sqlite',
    },
    {
      order: 7,
      kind: 'management_worker_remove',
      summary: STATIC_UNINSTALL_STEP_SUMMARIES.management_worker_remove,
      workerName: input.workerName,
    },
    {
      order: 8,
      kind: 'no_ankka_managed_residue_verify',
      summary: STATIC_UNINSTALL_STEP_SUMMARIES.no_ankka_managed_residue_verify,
      scope: STATIC_UNINSTALL_RESIDUE_SCOPE,
      advancedCertificate: 'provider_retained_out_of_scope_manual',
    },
  ] as StaticUninstallStep[]);
}

function semanticFromFields(input: {
  readonly writesPerformed: false;
  readonly installationId: string;
  readonly authorityHash: string;
  readonly requiredScopes: readonly RequiredOauthScope[];
  readonly gateway: StaticUninstallPlan['gateway'];
  readonly source: StaticUninstallPlan['source'];
  readonly release: StaticUninstallPlan['release'];
  readonly steps: readonly StaticUninstallStep[];
  readonly providerNotice: typeof STATIC_UNINSTALL_PROVIDER_NOTICE;
}): StaticUninstallSemantic {
  return deepFreeze({
    schemaVersion: 1,
    writesPerformed: input.writesPerformed,
    installationId: input.installationId,
    authorityHash: input.authorityHash,
    requiredScopes: [...input.requiredScopes],
    gateway: { ...input.gateway },
    source: input.source === null ? null : { ...input.source, enabledTools: [...input.source.enabledTools] },
    release: { ...input.release },
    steps: input.steps,
    providerNotice: input.providerNotice,
  });
}

function publicBoundary(value: unknown): void {
  assertSecretFree(value);
  const forbiddenKeys = new Set([
    'accountId',
    'zoneId',
    'workerId',
    'applicationId',
    'policyId',
    'domainId',
    'namespaceId',
    'namespaceName',
    'receipt',
    'journal',
    'bindingHash',
    'managementAccessAud',
  ]);
  const visit = (item: unknown): void => {
    if (typeof item === 'string' && (item.includes('@') || EMAIL_LIKE.test(` ${item} `))) {
      invalid(500, 'session_invalid');
    }
    if (Array.isArray(item)) {
      for (const child of item) visit(child);
      return;
    }
    if (!isPlainRecord(item)) return;
    for (const [key, child] of Object.entries(item)) {
      if (forbiddenKeys.has(key)) invalid(500, 'session_invalid');
      visit(child);
    }
  };
  visit(value);
}

function validatedPublicCore(input: Record<string, unknown>): {
  readonly installationId: string;
  readonly authorityHash: string;
  readonly gateway: StaticUninstallPlan['gateway'];
  readonly source: StaticUninstallPlan['source'];
  readonly release: StaticUninstallPlan['release'];
} {
  if (typeof input.installationId !== 'string' || !INSTALLATION_ID.test(input.installationId) ||
    typeof input.authorityHash !== 'string' || !PREFIXED_SHA256.test(input.authorityHash) ||
    !isPlainRecord(input.gateway) || !exactKeys(input.gateway, [
      'name', 'zoneName', 'managementHostname', 'portalHostname', 'workerName',
    ]) || !validPublicName(input.gateway.name, 80) || !validHostname(input.gateway.zoneName) ||
    !validHostname(input.gateway.managementHostname) || !validHostname(input.gateway.portalHostname) ||
    input.gateway.managementHostname === input.gateway.portalHostname ||
    !input.gateway.managementHostname.endsWith(`.${input.gateway.zoneName}`) ||
    !input.gateway.portalHostname.endsWith(`.${input.gateway.zoneName}`) ||
    typeof input.gateway.workerName !== 'string' || !WORKER_NAME.test(input.gateway.workerName) ||
    (input.source !== null && (
      !isPlainRecord(input.source) || !exactKeys(input.source, ['name', 'hostname', 'enabledTools']) ||
      !validPublicName(input.source.name, 80) || !validHostname(input.source.hostname)
    )) ||
    !isPlainRecord(input.release) || !exactKeys(input.release, ['id', 'aggregateSha256']) ||
    typeof input.release.id !== 'string' || !RELEASE.test(input.release.id) ||
    typeof input.release.aggregateSha256 !== 'string' || !SHA256.test(input.release.aggregateSha256)) {
    return invalid();
  }
  const tools = input.source === null ? null : canonicalTools(input.source.enabledTools);
  if (input.source !== null && !tools) return invalid();
  const marker = ownershipMarkerFromWorker(input.gateway.workerName);
  if (!marker || input.gateway.workerName !== `ankka-gateway-${gatewaySlug(input.gateway.name)}-${marker}`) {
    return invalid();
  }
  return deepFreeze({
    installationId: input.installationId,
    authorityHash: input.authorityHash,
    gateway: {
      name: input.gateway.name,
      zoneName: input.gateway.zoneName,
      managementHostname: input.gateway.managementHostname,
      portalHostname: input.gateway.portalHostname,
      workerName: input.gateway.workerName,
    },
    source: input.source === null ? null : {
      name: input.source.name as string,
      hostname: input.source.hostname as string,
      enabledTools: tools as readonly string[],
    },
    release: { id: input.release.id, aggregateSha256: input.release.aggregateSha256 },
  });
}

function immutableSemantic(plan: StaticUninstallPlan): StaticUninstallSemantic {
  return semanticFromFields({
    writesPerformed: plan.writesPerformed,
    installationId: plan.installationId,
    authorityHash: plan.authorityHash,
    requiredScopes: plan.requiredScopes,
    gateway: plan.gateway,
    source: plan.source,
    release: plan.release,
    steps: plan.steps,
    providerNotice: plan.providerNotice,
  });
}

export async function parseStaticUninstallPlan(value: unknown): Promise<StaticUninstallPlan> {
  if (!dataTree(value) || !isPlainRecord(value) || !exactKeys(value, [
    'schemaVersion', 'planId', 'planHash', 'createdAt', 'expiresAt', 'writesPerformed', 'installationId',
    'authorityHash',
    'requiredScopes', 'gateway', 'source', 'release', 'steps', 'providerNotice',
  ]) || value.schemaVersion !== 1 || typeof value.planId !== 'string' || !PLAN_ID.test(value.planId) ||
    typeof value.planHash !== 'string' || !PREFIXED_SHA256.test(value.planHash) ||
    !safeInteger(value.createdAt) || !safeInteger(value.expiresAt) || value.createdAt <= 0 ||
    value.expiresAt <= value.createdAt || value.expiresAt - value.createdAt > MAX_STATIC_UNINSTALL_PLAN_TTL_MS ||
    value.writesPerformed !== false || !exactScopes(value.requiredScopes) ||
    value.providerNotice !== STATIC_UNINSTALL_PROVIDER_NOTICE || !Array.isArray(value.steps)) {
    return invalid();
  }
  const core = validatedPublicCore(value);
  const expectedSteps = stepsFor({
    gatewayName: core.gateway.name,
    managementHostname: core.gateway.managementHostname,
    portalHostname: core.gateway.portalHostname,
    source: core.source,
    workerName: core.gateway.workerName,
  });
  if (!canonicalEqual(value.steps, expectedSteps)) return invalid();
  const semantic = semanticFromFields({
    writesPerformed: false,
    installationId: core.installationId,
    authorityHash: core.authorityHash,
    requiredScopes: STATIC_UNINSTALL_OAUTH_SCOPES,
    gateway: core.gateway,
    source: core.source,
    release: core.release,
    steps: expectedSteps,
    providerNotice: STATIC_UNINSTALL_PROVIDER_NOTICE,
  });
  const digest = await sha256Hex(canonicalJson(semantic));
  if (value.planId !== `uninstall-plan-${digest.slice(0, 24)}` || value.planHash !== `sha256:${digest}`) {
    return invalid();
  }
  const parsed = deepFreeze({
    ...semantic,
    planId: value.planId,
    planHash: value.planHash,
    createdAt: value.createdAt,
    expiresAt: value.expiresAt,
  });
  publicBoundary(parsed);
  return parsed;
}

function exactFinalConvergence(
  journal: InstallJournal,
  rebuilt: Awaited<ReturnType<typeof prepareFinalConvergenceRecordAndLocator>>,
): boolean {
  const action = journal.actions[journal.actions.length - 1];
  return Boolean(action && action.name === 'final_convergence' && action.phase === 'verified' &&
    canonicalEqual(action.record, rebuilt.record) && canonicalEqual(action.locator, rebuilt.locator));
}

export async function buildStaticUninstallPlan(
  installJournalInput: unknown,
  createdAt: number,
  expiresAt: number,
): Promise<StaticUninstallPlan> {
  if (!dataTree(installJournalInput)) return invalid();
  const journal = await requireInstallJournal(installJournalInput);
  if (!isCompleteInstallJournal(journal)) return invalid(409, 'session_conflict');
  const rebuilt = await prepareFinalConvergenceRecordAndLocator(journal);
  if (!exactFinalConvergence(journal, rebuilt) || !safeInteger(createdAt) || !safeInteger(expiresAt) ||
    createdAt < journal.updatedAt || createdAt >= journal.recoverUntil || expiresAt <= createdAt ||
    expiresAt - createdAt > MAX_STATIC_UNINSTALL_PLAN_TTL_MS || expiresAt > journal.recoverUntil) {
    return invalid(409, 'session_conflict');
  }
  const worker = journal.plan.managementResources.find((resource) => resource.kind === 'management_worker');
  if (!worker || !WORKER_NAME.test(worker.name)) return invalid(500, 'session_invalid');
  const firstSource = journal.plan.gatewayConfiguration.firstSource;
  const gateway = deepFreeze({
    name: journal.plan.gatewayConfiguration.gatewayName,
    zoneName: journal.plan.gatewayConfiguration.zoneName,
    managementHostname: journal.plan.gatewayConfiguration.managementHostname,
    portalHostname: journal.plan.gatewayConfiguration.portalHostname,
    workerName: worker.name,
  });
  let source: StaticUninstallPlan['source'] = null;
  if (firstSource !== null) {
    try {
      source = deepFreeze({
        name: publicName(firstSource.name, 'Configured source'),
        hostname: new URL(firstSource.url).hostname,
        enabledTools: [...firstSource.enabledTools],
      });
    } catch {
      return invalid(500, 'session_invalid');
    }
  }
  const release = deepFreeze({
    id: journal.releasePin.release,
    aggregateSha256: journal.releasePin.artifactSha256,
  });
  const steps = stepsFor({
    gatewayName: gateway.name,
    managementHostname: gateway.managementHostname,
    portalHostname: gateway.portalHostname,
    source,
    workerName: gateway.workerName,
  });
  const authorityHash = `sha256:${await sha256Hex(canonicalJson({
    adminStateNamespaceId: rebuilt.locator.adminStateNamespaceId,
    installBindingHash: journal.bindingHash,
    installConvergenceHash: rebuilt.locator.convergenceHash,
    readyReceiptChecksum: rebuilt.locator.customerReceiptEvidence.checksum,
  }))}`;
  const semantic = semanticFromFields({
    writesPerformed: false,
    installationId: journal.installationId,
    authorityHash,
    requiredScopes: STATIC_UNINSTALL_OAUTH_SCOPES,
    gateway,
    source,
    release,
    steps,
    providerNotice: STATIC_UNINSTALL_PROVIDER_NOTICE,
  });
  publicBoundary(semantic);
  const digest = await sha256Hex(canonicalJson(semantic));
  return parseStaticUninstallPlan({
    ...semantic,
    planId: `uninstall-plan-${digest.slice(0, 24)}`,
    planHash: `sha256:${digest}`,
    createdAt,
    expiresAt,
  });
}

export async function isRecoveryEquivalentUninstallPlan(
  baseline: unknown,
  candidate: unknown,
): Promise<boolean> {
  try {
    const parsedBaseline = await parseStaticUninstallPlan(baseline);
    const parsedCandidate = await parseStaticUninstallPlan(candidate);
    return parsedBaseline.planId === parsedCandidate.planId && parsedBaseline.planHash === parsedCandidate.planHash &&
      canonicalEqual(immutableSemantic(parsedBaseline), immutableSemantic(parsedCandidate));
  } catch {
    return false;
  }
}

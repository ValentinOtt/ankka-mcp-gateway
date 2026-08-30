import * as v from 'valibot';

import {
  boundaryObjectSchema,
  boundaryValueSchema,
  jsonValueSchema,
  type BoundaryValue,
} from './boundary';
import { canonicalJson } from './canonical-json';
import type { RequiredOauthScope } from './constants';
import { sha256Hex } from './crypto';
import { DeployError } from './errors';
import {
  isCompleteInstallJournal,
  prepareFinalConvergenceRecordAndLocator,
  requireInstallJournal,
  type InstallJournal,
} from './install-journal';
import { deepFreezePlainData, isPlainDataTree } from './plain-data';
import { assertSecretFree } from './schema';

const PLAN_ID = /^uninstall-plan-[a-f0-9]{24}$/u;
const PREFIXED_SHA256 = /^sha256:[a-f0-9]{64}$/u;
const SHA256 = /^[a-f0-9]{64}$/u;
const INSTALLATION_ID = /^acg-[a-f0-9]{24}$/u;
const RELEASE = /^gateway-v(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)(?:-[a-z0-9.-]+)?$/u;
const WORKER_NAME = /^[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$/u;
const OWNERSHIP_MARKER = /^acg-[a-f0-9]{24}$/u;
const TOOL_NAME = /^[A-Za-z0-9_.:/-]{1,128}$/u;
const MAX_ENABLED_TOOLS_PER_SOURCE = 500;
const DNS_LABEL = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/u;
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

// Schema-v1 hash/parser values, not display-only copy; preserve published plans.
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

const safeNonnegativeIntegerSchema = v.pipe(v.number(), v.safeInteger(), v.minValue(0));
const hostnameSchema = v.pipe(v.string(), v.check(validHostname));
const publicNameSchema = v.pipe(v.string(), v.check((value) => validPublicName(value, 80)));
const sourceSchema = v.strictObject({
  name: publicNameSchema,
  hostname: hostnameSchema,
  enabledTools: v.pipe(
    v.array(v.pipe(v.string(), v.regex(TOOL_NAME))),
    v.minLength(1),
    v.maxLength(MAX_ENABLED_TOOLS_PER_SOURCE),
  ),
});
const gatewaySchema = v.strictObject({
  name: publicNameSchema,
  zoneName: hostnameSchema,
  managementHostname: hostnameSchema,
  portalHostname: hostnameSchema,
  workerName: v.pipe(v.string(), v.regex(WORKER_NAME)),
});
const releaseSchema = v.strictObject({
  id: v.pipe(v.string(), v.regex(RELEASE)),
  aggregateSha256: v.pipe(v.string(), v.regex(SHA256)),
});
const staticUninstallPlanSchema = v.strictObject({
  schemaVersion: v.literal(1),
  planId: v.pipe(v.string(), v.regex(PLAN_ID)),
  planHash: v.pipe(v.string(), v.regex(PREFIXED_SHA256)),
  createdAt: safeNonnegativeIntegerSchema,
  expiresAt: safeNonnegativeIntegerSchema,
  writesPerformed: v.literal(false),
  installationId: v.pipe(v.string(), v.regex(INSTALLATION_ID)),
  authorityHash: v.pipe(v.string(), v.regex(PREFIXED_SHA256)),
  requiredScopes: v.array(v.string()),
  gateway: gatewaySchema,
  source: v.nullable(sourceSchema),
  release: releaseSchema,
  steps: v.array(jsonValueSchema),
  providerNotice: v.literal(STATIC_UNINSTALL_PROVIDER_NOTICE),
});

function invalid(status = 400, code: 'bad_request' | 'session_conflict' | 'session_invalid' = 'bad_request'): never {
  throw new DeployError(status, code);
}

function canonicalEqual<Left, Right>(left: Left, right: Right): boolean {
  try {
    return canonicalJson(left) === canonicalJson(right);
  } catch {
    return false;
  }
}

function validHostname(value: string): boolean {
  if (value.length < 3 || value.length > 253 || value !== value.toLowerCase() ||
    value.endsWith('.') || value.includes('..')) return false;
  const labels = value.split('.');
  return labels.length >= 2 && labels.every((label) => DNS_LABEL.test(label));
}

function unsafePublicNameCharacter(character: string): boolean {
  const codePoint = character.codePointAt(0);
  return codePoint === undefined || codePoint <= 0x1f || codePoint === 0x7f || '<>{}\\'.includes(character);
}

function validPublicName(value: string, maximum = 128): boolean {
  return value.length > 0 && value.length <= maximum && value.trim() === value &&
    ![...value].some(unsafePublicNameCharacter) &&
    !value.includes('@') && !EMAIL_LIKE.test(` ${value} `);
}

function publicName(value: string, fallback: string): string {
  return validPublicName(value) ? value : fallback;
}

function canonicalTools(value: readonly string[]): readonly string[] | null {
  const tools = [...value];
  const sorted = [...tools].sort();
  if (new Set(tools).size !== tools.length || !tools.every((tool, index) => tool === sorted[index])) return null;
  return Object.freeze(tools);
}

function exactScopes(value: readonly string[]): boolean {
  return value.length === STATIC_UNINSTALL_OAUTH_SCOPES.length &&
    value.every((scope, index) => scope === STATIC_UNINSTALL_OAUTH_SCOPES[index]);
}

function resourceSummaries(
  gatewayName: string,
  portalHostname: string,
  source: StaticUninstallPlan['source'],
): readonly StaticUninstallGatewayResourceSummary[] {
  const resources: StaticUninstallGatewayResourceSummary[] = [];
  if (source !== null) {
    resources.push(
      { kind: 'mcp_server', name: source.name, hostname: source.hostname },
      { kind: 'source_access_application', name: `${source.name} source`, hostname: source.hostname },
      { kind: 'source_access_policy', name: `${source.name} users`, hostname: source.hostname },
    );
  }
  resources.push(
    { kind: 'portal', name: gatewayName, hostname: portalHostname },
    { kind: 'portal_access_application', name: `${gatewayName} portal`, hostname: portalHostname },
    { kind: 'portal_access_policy', name: `${gatewayName} portal users`, hostname: portalHostname },
    { kind: 'dns_record', name: portalHostname, hostname: portalHostname },
  );
  return deepFreezePlainData(resources);
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
  const steps: StaticUninstallStep[] = [
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
  ];
  return deepFreezePlainData(steps);
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
  return deepFreezePlainData({
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

function publicBoundary<Value>(value: Value): void {
  const parsed = v.safeParse(boundaryValueSchema, value);
  if (!parsed.success) invalid(500, 'session_invalid');
  assertSecretFree(parsed.output);
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
  const visit = (item: BoundaryValue): void => {
    if (v.is(v.string(), item) && (item.includes('@') || EMAIL_LIKE.test(` ${item} `))) {
      invalid(500, 'session_invalid');
    }
    if (Array.isArray(item)) {
      for (const child of item) visit(child);
      return;
    }
    if (!v.is(boundaryObjectSchema, item)) return;
    for (const [key, child] of Object.entries(item)) {
      if (forbiddenKeys.has(key)) invalid(500, 'session_invalid');
      visit(child);
    }
  };
  visit(parsed.output);
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

export async function parseStaticUninstallPlan<Input>(input: Input): Promise<StaticUninstallPlan> {
  if (!isPlainDataTree(input)) return invalid();
  const result = v.safeParse(staticUninstallPlanSchema, input);
  if (!result.success) return invalid();
  const value = result.output;
  if (value.createdAt <= 0 || value.expiresAt <= value.createdAt ||
      value.expiresAt - value.createdAt > MAX_STATIC_UNINSTALL_PLAN_TTL_MS ||
      !exactScopes(value.requiredScopes) ||
      value.gateway.managementHostname === value.gateway.portalHostname ||
      !value.gateway.managementHostname.endsWith(`.${value.gateway.zoneName}`) ||
      !value.gateway.portalHostname.endsWith(`.${value.gateway.zoneName}`)) return invalid();
  const tools = value.source === null ? null : canonicalTools(value.source.enabledTools);
  const marker = ownershipMarkerFromWorker(value.gateway.workerName);
  if (!marker || value.gateway.workerName !== `ankka-gateway-${gatewaySlug(value.gateway.name)}-${marker}`) {
    return invalid();
  }
  let source: StaticUninstallPlan['source'] = null;
  if (value.source !== null) {
    if (tools === null) return invalid();
    source = {
      name: value.source.name,
      hostname: value.source.hostname,
      enabledTools: tools,
    };
  }
  const core = deepFreezePlainData({
    installationId: value.installationId,
    authorityHash: value.authorityHash,
    gateway: { ...value.gateway },
    source,
    release: { ...value.release },
  });
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
  const parsed = deepFreezePlainData({
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

export async function buildStaticUninstallPlan<Input>(
  installJournalInput: Input,
  createdAt: number,
  expiresAt: number,
): Promise<StaticUninstallPlan> {
  if (!isPlainDataTree(installJournalInput)) return invalid();
  const journal = await requireInstallJournal(installJournalInput);
  if (!isCompleteInstallJournal(journal)) return invalid(409, 'session_conflict');
  const rebuilt = await prepareFinalConvergenceRecordAndLocator(journal);
  if (!exactFinalConvergence(journal, rebuilt) || !v.is(safeNonnegativeIntegerSchema, createdAt) ||
    !v.is(safeNonnegativeIntegerSchema, expiresAt) ||
    createdAt < journal.updatedAt || createdAt >= journal.recoverUntil || expiresAt <= createdAt ||
    expiresAt - createdAt > MAX_STATIC_UNINSTALL_PLAN_TTL_MS || expiresAt > journal.recoverUntil) {
    return invalid(409, 'session_conflict');
  }
  const worker = journal.plan.managementResources.find((resource) => resource.kind === 'management_worker');
  if (!worker || !WORKER_NAME.test(worker.name)) return invalid(500, 'session_invalid');
  const firstSource = journal.plan.gatewayConfiguration.firstSource;
  const gateway = deepFreezePlainData({
    name: journal.plan.gatewayConfiguration.gatewayName,
    zoneName: journal.plan.gatewayConfiguration.zoneName,
    managementHostname: journal.plan.gatewayConfiguration.managementHostname,
    portalHostname: journal.plan.gatewayConfiguration.portalHostname,
    workerName: worker.name,
  });
  let source: StaticUninstallPlan['source'] = null;
  if (firstSource !== null) {
    try {
      source = deepFreezePlainData({
        name: publicName(firstSource.name, 'Configured source'),
        hostname: new URL(firstSource.url).hostname,
        enabledTools: [...firstSource.enabledTools],
      });
    } catch {
      return invalid(500, 'session_invalid');
    }
  }
  const release = deepFreezePlainData({
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

export async function isRecoveryEquivalentUninstallPlan<Baseline, Candidate>(
  baseline: Baseline,
  candidate: Candidate,
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

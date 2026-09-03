import { describe, expect, it, vi } from 'vitest';
import * as v from 'valibot';

import { jsonValueSchema, type JsonValue } from '../src/boundary';
import { canonicalJson } from '../src/canonical-json';
import {
  CloudflareUninstallManagementError,
  HOSTED_UNINSTALL_MANAGEMENT_DELETE_ORDER,
  HOSTED_UNINSTALL_MANAGEMENT_JOURNAL_ALLOWLIST,
  preflightHostedUninstallManagement,
  parseHostedUninstallManagementAbsenceEvidence,
  parseHostedUninstallManagementDeleteArm,
  parseHostedUninstallManagementDeleteIntent,
  parseHostedUninstallManagementDeleteRecoveryEvidence,
  parseHostedUninstallManagementDeleteSubmission,
  parseHostedUninstallManagementNoManagedResidueEvidence,
  parseHostedUninstallManagementNoManagedResidueResult,
  parseHostedUninstallManagementPreflightResult,
  prepareHostedUninstallManagementDeleteArm,
  prepareHostedUninstallManagementDeleteIntent,
  recoverHostedUninstallManagementDeleteOutcome,
  submitHostedUninstallManagementDeleteOnce,
  verifyHostedUninstallManagementDeleteAbsence,
  verifyHostedUninstallManagementNoManagedResidue,
  type CloudflareUninstallManagementCall,
  type CloudflareUninstallManagementErrorCode,
  type CloudflareUninstallManagementStage,
  type CloudflareUninstallManagementTransport,
  type HostedUninstallExternalNamespaceAbsenceEvidence,
  type HostedUninstallManagementContext,
  type HostedUninstallManagementDeleteAction,
  type HostedUninstallManagementDeletePrerequisites,
  type HostedUninstallManagementLifecycleEvidence,
} from '../src/cloudflare-uninstall-management';
import {
  managementAccessApplicationName,
  managementAdminPolicyName,
  managementOwnershipMarker,
  prepareManagementAccessApplicationIntent,
  prepareManagementAdminPolicyIntent,
  prepareManagementCustomDomainIntent,
} from '../src/cloudflare-management-surface';
import {
  deriveCustomerGatewayExpectedProjection,
  deriveCustomerGatewayInstallationReceiptExpectation,
  prepareCustomerBootstrapClaim,
} from '../src/customer-bootstrap-request';
import type { AuthorizedTarget } from '../src/cloudflare-target';
import { sha256Hex } from '../src/crypto';
import {
  acquireInstallJournalLease,
  armInstallJournalAction,
  computeInstallJournalBindingHash,
  createInstallJournal,
  prepareFinalConvergenceRecordAndLocator,
  prepareInstallJournalAction,
  submitInstallJournalAction,
  verifyInstallJournalAction,
  type InstallActionLocator,
  type InstallActionName,
  type InstallActionRecord,
  type InstallJournal,
  type WorkerVersionCreateRecord,
} from '../src/install-journal';
import { buildStaticDeployPlan, parseDeploySelection } from '../src/schema';
import { buildStaticUninstallPlan } from '../src/uninstall-plan';
import { manifest, NOW, requiredFixture, selectionInput, verifiedRelease } from './fixtures';
import { readyInstallationReceiptFixture } from './provider-neutral-installation-receipt-fixture';

const ACCOUNT_ID = 'a'.repeat(32);
const ZONE_ID = 'b'.repeat(32);
const WORKER_ID = 'c'.repeat(32);
const NAMESPACE_ID = 'd'.repeat(32);
const DOMAIN_ID = 'e'.repeat(32);
const CERTIFICATE_ID = '9fdf92c8-64c2-4a3d-b1af-e15304961145';
const APPLICATION_ID = 'f174e90a-fafe-4643-bbbc-4a0ed4fc8415';
const POLICY_ID = 'd174e90a-fafe-4643-bbbc-4a0ed4fc8415';
const RETIREMENT_VERSION_ID = 'b174e90a-fafe-4643-bbbc-4a0ed4fc8415';
const PROVISION_VERSION_ID = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
const PROVISION_DEPLOYMENT_ID = 'cccccccc-cccc-4ccc-8ccc-cccccccccccc';
const BOOTSTRAP_VERSION_ID = '11111111-1111-4111-8111-111111111111';
const BOOTSTRAP_DEPLOYMENT_ID = '22222222-2222-4222-8222-222222222222';
const CLEAN_VERSION_ID = '33333333-3333-4333-8333-333333333333';
const CLEAN_DEPLOYMENT_ID = '44444444-4444-4444-8444-444444444444';
const FOREIGN_ID = '1'.repeat(32);
const ROUTE_ID = '2'.repeat(32);
const DNS_ID = '3'.repeat(32);
const AUD = 'access-audience-token-1234567890';
const IDP_ONE = '4'.repeat(32);
const IDP_TWO = '5'.repeat(32);
const ACCESS_TOKEN = 'ephemeral_oauth_access_token_for_uninstall';
const UNINSTALL_CYCLE_ID = `uninstall-${'6'.repeat(24)}`;
const INSTALL_ATTEMPT_ID = `att_${'a'.repeat(32)}`;
const UNINSTALL_ATTEMPT_ID = `att_${'b'.repeat(32)}`;
const RECOVERY_ATTEMPT_ONE = `att_${'c'.repeat(32)}`;
const RECOVERY_ATTEMPT_TWO = `att_${'d'.repeat(32)}`;
const RECOVERY_ATTEMPT_THREE = `att_${'e'.repeat(32)}`;
const selection = parseDeploySelection(selectionInput);
const plan = await buildStaticDeployPlan(selection, manifest, NOW + 600_000);
const workerName = plan.managementResources.find((resource) => resource.kind === 'management_worker')?.name ?? '';
if (!workerName) throw new TypeError('worker fixture');
const target: AuthorizedTarget = Object.freeze({
  actor: Object.freeze({ id: 'actor_12345678', email: selection.basics.adminEmail }),
  account: Object.freeze({ id: ACCOUNT_ID, name: 'Example account' }),
  zone: Object.freeze({ id: ZONE_ID, name: selection.basics.zoneName, status: 'active' }),
});
let correlationTag = `ankka-worker-sha256:${'7'.repeat(64)}`;

async function fixtureHash<Input>(value: Input): Promise<string> {
  return sha256Hex(canonicalJson(v.parse(jsonValueSchema, value)));
}

const PLAIN_BINDING_NAMES = [
  'ADMIN_EMAILS', 'ANKKA_INSTALL_ID', 'ANKKA_GATEWAY_RELEASE', 'ANKKA_GATEWAY_RELEASE_SHA256',
  'ANKKA_MANAGEMENT_HOSTNAME', 'ANKKA_UPDATE_CHANNEL', 'ANKKA_UPDATE_KEY_ID', 'ANKKA_UPDATE_PUBLIC_KEY',
  'ANKKA_WORKERS_SUBDOMAIN', 'ANKKA_WORKER_NAME', 'CF_ACCESS_AUD',
  'CF_ACCESS_ISSUER', 'CLOUDFLARE_ACCOUNT_ID', 'CLOUDFLARE_ZONE_ID', 'CLOUDFLARE_ZONE_NAME',
  'ZERO_TRUST_READY',
] as const;
const PLAIN_BINDINGS: WorkerVersionCreateRecord['plainTextBindingHashes'] = Object.freeze(
  PLAIN_BINDING_NAMES.map((name, index) => Object.freeze({
    name,
    valueSha256: String(index % 10).repeat(64),
  })),
);

async function fixtureRecord(action: InstallActionName, phase?: 'provision' | 'bootstrap' | 'clean'): Promise<InstallActionRecord> {
  if (action === 'worker_create') {
    const requestHash = await fixtureHash({
      logpush: false, name: workerName, observability: { enabled: false },
      subdomain: { enabled: false, previews_enabled: false }, tags: ['ankka-mcp-gateway'], tail_consumers: [],
    });
    return { schemaVersion: 1, kind: 'worker_create', accountId: ACCOUNT_ID, workerName, requestHash,
      correlationTag: `ankka-worker-sha256:${requestHash}` };
  }
  if (action === 'management_access_application_create') {
    const allowedIdentityProviderIds = Object.freeze([IDP_ONE, IDP_TWO]);
    const intent = prepareManagementAccessApplicationIntent({ accountId: ACCOUNT_ID, zoneId: ZONE_ID, plan, allowedIdentityProviderIds });
    return { schemaVersion: 1, kind: action, accountId: ACCOUNT_ID, planId: plan.planId, planHash: plan.planHash,
      ownershipMarker: managementOwnershipMarker(plan), allowedIdentityProviderIds, intentHash: await fixtureHash(intent) };
  }
  if (action === 'management_admin_policy_create') {
    const intent = prepareManagementAdminPolicyIntent({ accountId: ACCOUNT_ID, zoneId: ZONE_ID, applicationId: APPLICATION_ID, plan });
    return { schemaVersion: 1, kind: action, accountId: ACCOUNT_ID, planId: plan.planId, planHash: plan.planHash,
      ownershipMarker: managementOwnershipMarker(plan), applicationId: APPLICATION_ID, intentHash: await fixtureHash(intent) };
  }
  if (action === 'management_custom_domain_attach') {
    const intent = prepareManagementCustomDomainIntent({ accountId: ACCOUNT_ID, zoneId: ZONE_ID, plan });
    return { schemaVersion: 1, kind: action, accountId: ACCOUNT_ID, zoneId: ZONE_ID,
      planId: plan.planId, planHash: plan.planHash, ownershipMarker: managementOwnershipMarker(plan),
      intentHash: await fixtureHash(intent) };
  }
  if (action === 'bootstrap_subdomain_enable' || action === 'bootstrap_subdomain_disable') {
    const enabled = action === 'bootstrap_subdomain_enable';
    return { schemaVersion: 1, kind: 'bootstrap_subdomain', accountId: ACCOUNT_ID, workerName, enabled,
      requestHash: await fixtureHash({ enabled, previews_enabled: false }) };
  }
  if (action.endsWith('_worker_version_create') && phase) {
    const releaseContract = {
      assetBinding: 'ASSETS' as const,
      assetConfig: { notFoundHandling: 'single-page-application' as const,
        runWorkerFirst: ['/__ankka/*', '/api/*'] as const },
      bootstrapBinding: phase === 'bootstrap' ? 'present' as const : 'absent' as const,
      compatibilityDate: '2026-08-08' as const, compatibilityFlags: [] as const,
      durableObject: { binding: 'ADMIN_STATE' as const, className: 'AdminState' as const, storage: 'sqlite' as const },
      exports: { AdminState: { type: 'durable-object' as const, storage: 'sqlite' as const } },
      mainModule: 'index.js' as const,
    };
    const assets = [{ path: '/index.html', uploadHash: 'f'.repeat(32), contentType: 'text/html; charset=utf-8', byteLength: 1 }];
    const modules = [{ name: 'index.js', contentType: 'application/javascript+module', contentSha256: 'e'.repeat(64), byteLength: 1 }];
    const requestHash = await fixtureHash({
      accountId: ACCOUNT_ID,
      assets: { binding: releaseContract.assetBinding, config: {
        notFoundHandling: releaseContract.assetConfig.notFoundHandling,
        runWorkerFirst: [...releaseContract.assetConfig.runWorkerFirst],
      }, files: assets },
      bindings: { bootstrap: releaseContract.bootstrapBinding, durableObject: releaseContract.durableObject,
        plainText: PLAIN_BINDINGS },
      compatibilityDate: releaseContract.compatibilityDate, compatibilityFlags: [], exports: releaseContract.exports,
      mainModule: releaseContract.mainModule, modules, phase, workerId: WORKER_ID, workerName,
    });
    return { schemaVersion: 1, kind: 'worker_version_create', phase, accountId: ACCOUNT_ID, workerName,
      workerId: WORKER_ID, requestHash, correlationTag: `ankka-version-${phase}-sha256:${requestHash}`,
      releaseContract, assets, plainTextBindingHashes: PLAIN_BINDINGS, modules };
  }
  if (action.endsWith('_worker_deployment_create') && phase) {
    const versionId = phase === 'provision' ? PROVISION_VERSION_ID : phase === 'bootstrap' ? BOOTSTRAP_VERSION_ID : CLEAN_VERSION_ID;
    const requestHash = await fixtureHash({ strategy: 'percentage', versions: [{ percentage: 100, version_id: versionId }] });
    return { schemaVersion: 1, kind: 'worker_deployment_create', phase, accountId: ACCOUNT_ID, workerName,
      workerId: WORKER_ID, versionId, requestHash, correlationTag: `ankka-deploy-${phase}-sha256:${requestHash}` };
  }
  throw new TypeError(`record:${action}`);
}

async function fixtureLocator(action: InstallActionName, phase?: 'provision' | 'bootstrap' | 'clean'): Promise<InstallActionLocator> {
  if (action === 'worker_create') return { kind: 'worker', accountId: ACCOUNT_ID, workerName, workerId: WORKER_ID };
  if (action === 'management_access_application_create') return { applicationId: APPLICATION_ID, aud: AUD };
  if (action === 'management_admin_policy_create') return { policyId: POLICY_ID };
  if (action === 'management_custom_domain_attach') return { domainId: DOMAIN_ID };
  if (action === 'bootstrap_subdomain_enable' || action === 'bootstrap_subdomain_disable') {
    return { enabled: action === 'bootstrap_subdomain_enable', previewsEnabled: false };
  }
  if (action.endsWith('_worker_version_create') && phase) {
    const record = await fixtureRecord(action, phase);
    if (record.kind !== 'worker_version_create') throw new TypeError('worker version fixture');
    const locator = { kind: 'version' as const, phase, accountId: ACCOUNT_ID, workerName, workerId: WORKER_ID,
      versionId: phase === 'provision' ? PROVISION_VERSION_ID : phase === 'bootstrap' ? BOOTSTRAP_VERSION_ID : CLEAN_VERSION_ID,
      requestHash: record.requestHash, correlationTag: record.correlationTag };
    // The provision version precedes the deployment that creates the namespace.
    return phase === 'provision' ? locator : { ...locator, namespaceId: NAMESPACE_ID };
  }
  if (action.endsWith('_worker_deployment_create') && phase) {
    const record = await fixtureRecord(action, phase);
    if (record.kind !== 'worker_deployment_create') throw new TypeError('worker deployment fixture');
    return { kind: 'deployment', phase, accountId: ACCOUNT_ID, workerName, workerId: WORKER_ID,
      versionId: record.versionId,
      deploymentId: phase === 'provision' ? PROVISION_DEPLOYMENT_ID : phase === 'bootstrap' ? BOOTSTRAP_DEPLOYMENT_ID : CLEAN_DEPLOYMENT_ID,
      requestHash: record.requestHash, correlationTag: record.correlationTag };
  }
  throw new TypeError(`locator:${action}`);
}

async function advanceFixture(
  journal: InstallJournal,
  action: InstallActionName,
  record: InstallActionRecord,
  locator: InstallActionLocator,
  clock: { now: number },
): Promise<InstallJournal> {
  journal = await prepareInstallJournalAction(journal, { expectedRevision: journal.revision,
    attemptId: INSTALL_ATTEMPT_ID, now: ++clock.now, action, record });
  journal = armInstallJournalAction(journal, { expectedRevision: journal.revision,
    attemptId: INSTALL_ATTEMPT_ID, now: ++clock.now, action });
  journal = await submitInstallJournalAction(journal, { expectedRevision: journal.revision,
    attemptId: INSTALL_ATTEMPT_ID, now: ++clock.now, action, locator });
  return verifyInstallJournalAction(journal, { expectedRevision: journal.revision,
    attemptId: INSTALL_ATTEMPT_ID, now: ++clock.now, action });
}

async function completeInstallJournalFixture(): Promise<InstallJournal> {
  const claim = await prepareCustomerBootstrapClaim({ selection, target, release: verifiedRelease, plan, nowMs: NOW,
    randomBytes: (length) => Uint8Array.from({ length }, (_value, index) => index + 1) });
  const releasePin = Object.freeze({ verification: 'ed25519' as const, keyId: verifiedRelease.keyId,
    release: manifest.release, artifactSha256: manifest.artifact.treeSha256 });
  const bindingHash = await computeInstallJournalBindingHash({ selection, plan, releasePin, target,
    installationId: claim.expected.installationId });
  const projection = await deriveCustomerGatewayExpectedProjection({ selection, target, plan,
    release: { id: manifest.release, artifactSha256: manifest.artifact.treeSha256 } });
  const preflight = { schemaVersion: 1 as const, kind: 'customer_gateway_fresh_preflight' as const,
    accountId: ACCOUNT_ID, zoneId: ZONE_ID, planId: plan.planId, planHash: plan.planHash,
    installationId: claim.expected.installationId, configurationHash: projection.expected.configurationHash,
    desiredHash: projection.expected.desiredHash, releaseId: manifest.release,
    releaseArtifactSha256: manifest.artifact.treeSha256, zeroCandidateKinds: projection.resourceKinds,
    checkedAt: NOW, expiresAt: NOW + 30_000 };
  let journal = await createInstallJournal({ schemaVersion: 1, now: NOW, recoverUntil: NOW + 86_400_000,
    selection, plan, releasePin, target, installationId: claim.expected.installationId, bindingHash,
    gatewayFreshPreflight: { ...preflight, attestationHash: `sha256:${await fixtureHash(preflight)}` } },
  selection, plan, NOW + 500_000, { attemptId: INSTALL_ATTEMPT_ID, approvedAt: NOW });
  const clock = { now: NOW };
  journal = acquireInstallJournalLease(journal, { expectedRevision: journal.revision,
    attemptId: INSTALL_ATTEMPT_ID, now: ++clock.now, leaseExpiresAt: clock.now + 300_000 });
  for (const [action, phase] of [
    ['worker_create'], ['management_access_application_create'], ['management_admin_policy_create'],
    ['provision_worker_version_create', 'provision'], ['provision_worker_deployment_create', 'provision'],
    ['bootstrap_worker_version_create', 'bootstrap'], ['bootstrap_worker_deployment_create', 'bootstrap'],
    ['bootstrap_subdomain_enable'],
  ] as const) {
    journal = await advanceFixture(journal, action, await fixtureRecord(action, phase), await fixtureLocator(action, phase), clock);
  }
  const enable = journal.actions.find((entry) => entry.name === 'bootstrap_subdomain_enable');
  if (!enable || enable.record.kind !== 'bootstrap_subdomain' || !enable.locator || !('enabled' in enable.locator)) {
    throw new TypeError('enable fixture');
  }
  const bootstrapClaim = await prepareCustomerBootstrapClaim({ selection, target, release: verifiedRelease, plan,
    nowMs: ++clock.now, randomBytes: (length) => Uint8Array.from({ length }, (_value, index) => index + 11) });
  const compactClaim = { schemaVersion: 1 as const, requestId: bootstrapClaim.requestId,
    issuedAt: bootstrapClaim.issuedAt, expiresAt: bootstrapClaim.expiresAt, accountId: ACCOUNT_ID, zoneId: ZONE_ID,
    zoneName: target.zone.name, accountWorkersSubdomain: 'example-account', installationId: journal.installationId,
    configurationHash: bootstrapClaim.expected.configurationHash, desiredHash: bootstrapClaim.expected.desiredHash };
  const bootstrapRecord: InstallActionRecord = { schemaVersion: 1, kind: 'customer_bootstrap_submit',
    accountId: ACCOUNT_ID, zoneId: ZONE_ID, zoneName: target.zone.name, accountWorkersSubdomain: 'example-account',
    installationId: journal.installationId, configurationHash: bootstrapClaim.expected.configurationHash,
    desiredHash: bootstrapClaim.expected.desiredHash, attempts: [{ schemaVersion: 1,
      approvalAttemptId: INSTALL_ATTEMPT_ID, requestId: bootstrapClaim.requestId,
      issuedAt: bootstrapClaim.issuedAt, expiresAt: bootstrapClaim.expiresAt,
      claimHash: `sha256:${await fixtureHash(compactClaim)}`, enable: { schemaVersion: 1,
        approvalAttemptId: INSTALL_ATTEMPT_ID, enabled: true, requestHash: enable.record.requestHash,
        phase: 'verified', locator: enable.locator, preparedAt: enable.preparedAt, sendArmedAt: enable.sendArmedAt,
        submittedAt: enable.submittedAt, verifiedAt: enable.verifiedAt }, disable: null, phase: 'prepared', locator: null,
      preparedAt: clock.now, sendArmedAt: null, submittedAt: null, verifiedAt: null }] };
  journal = await prepareInstallJournalAction(journal, { expectedRevision: journal.revision,
    attemptId: INSTALL_ATTEMPT_ID, now: clock.now, action: 'customer_bootstrap_submit', record: bootstrapRecord });
  journal = armInstallJournalAction(journal, { expectedRevision: journal.revision,
    attemptId: INSTALL_ATTEMPT_ID, now: ++clock.now, action: 'customer_bootstrap_submit' });
  const receiptExpectation = await deriveCustomerGatewayInstallationReceiptExpectation({ selection, target, plan,
    release: { id: manifest.release, artifactSha256: manifest.artifact.treeSha256 } });
  const receipt = await readyInstallationReceiptFixture(receiptExpectation, 14);
  const bootstrapLocator: InstallActionLocator = { schemaVersion: 1, status: 'ready', installationId: journal.installationId,
    approvedPlanId: `plan-${'7'.repeat(24)}`, configurationHash: bootstrapClaim.expected.configurationHash,
    desiredHash: bootstrapClaim.expected.desiredHash, settingsRevision: 1,
    release: { id: manifest.release, artifactSha256: `sha256:${manifest.artifact.treeSha256}` },
    gateway: { hostname: selection.basics.portalHostname, mcpUrl: `https://${selection.basics.portalHostname}/mcp` },
    receipt: { revision: 14, resourceCount: 7, evidence: receipt }, applyInvoked: true, resumed: false };
  journal = await submitInstallJournalAction(journal, { expectedRevision: journal.revision,
    attemptId: INSTALL_ATTEMPT_ID, now: ++clock.now, action: 'customer_bootstrap_submit', locator: bootstrapLocator });
  journal = verifyInstallJournalAction(journal, { expectedRevision: journal.revision,
    attemptId: INSTALL_ATTEMPT_ID, now: ++clock.now, action: 'customer_bootstrap_submit' });
  for (const [action, phase] of [
    ['bootstrap_subdomain_disable'], ['clean_worker_version_create', 'clean'],
    ['clean_worker_deployment_create', 'clean'], ['management_custom_domain_attach'],
  ] as const) {
    journal = await advanceFixture(journal, action, await fixtureRecord(action, phase), await fixtureLocator(action, phase), clock);
  }
  const final = await prepareFinalConvergenceRecordAndLocator(journal);
  return advanceFixture(journal, 'final_convergence', final.record, final.locator, clock);
}

const installJournal = await completeInstallJournalFixture();
const installedWorkerAction = installJournal.actions.find((action) => action.name === 'worker_create');
if (!installedWorkerAction || installedWorkerAction.record.kind !== 'worker_create') throw new TypeError('worker record');
correlationTag = installedWorkerAction.record.correlationTag;
const uninstallPlan = await buildStaticUninstallPlan(installJournal, installJournal.updatedAt, installJournal.updatedAt + 300_000);
const context: HostedUninstallManagementContext = Object.freeze({
  schemaVersion: 1,
  installJournal,
  approvalHistory: Object.freeze([Object.freeze({
    attemptId: UNINSTALL_ATTEMPT_ID,
    uninstallPlan,
    authorizedTarget: target,
  })]),
  activeAttemptId: UNINSTALL_ATTEMPT_ID,
});
const recoveryPlanOne = await buildStaticUninstallPlan(
  installJournal,
  uninstallPlan.createdAt + 100,
  uninstallPlan.expiresAt + 100,
);
const recoveryPlanTwo = await buildStaticUninstallPlan(
  installJournal,
  uninstallPlan.createdAt + 200,
  uninstallPlan.expiresAt + 200,
);
const recoveryPlanThree = await buildStaticUninstallPlan(
  installJournal,
  uninstallPlan.createdAt + 300,
  uninstallPlan.expiresAt + 300,
);
const approvalFixtures = Object.freeze([
  Object.freeze({ attemptId: UNINSTALL_ATTEMPT_ID, uninstallPlan, authorizedTarget: target }),
  Object.freeze({ attemptId: RECOVERY_ATTEMPT_ONE, uninstallPlan: recoveryPlanOne, authorizedTarget: target }),
  Object.freeze({ attemptId: RECOVERY_ATTEMPT_TWO, uninstallPlan: recoveryPlanTwo, authorizedTarget: target }),
  Object.freeze({ attemptId: RECOVERY_ATTEMPT_THREE, uninstallPlan: recoveryPlanThree, authorizedTarget: target }),
]);

function contextThroughApproval(index: 0 | 1 | 2 | 3): HostedUninstallManagementContext {
  const activeApproval = requiredFixture(approvalFixtures.at(index), 'active approval');
  return Object.freeze({
    schemaVersion: 1,
    installJournal,
    approvalHistory: Object.freeze(approvalFixtures.slice(0, index + 1)),
    activeAttemptId: activeApproval.attemptId,
  });
}

type ManagementRequest = Parameters<CloudflareUninstallManagementTransport>[0];
type ResponseFactory = (request: ManagementRequest, index: number) => Response | Promise<Response>;

interface RecordedTransport {
  readonly requests: ManagementRequest[];
  readonly transport: CloudflareUninstallManagementTransport;
}

function success(result: JsonValue, status = 200): Response {
  return Response.json({ errors: [], messages: [], result, success: true }, { status });
}

interface ListOverrides {
  readonly total_count?: number;
  readonly total_pages?: number;
}

function list(result: readonly JsonValue[], overrides: ListOverrides = {}): Response {
  const totalCount = overrides.total_count ?? result.length;
  return Response.json({
    errors: [],
    messages: [],
    result,
    result_info: {
      count: result.length,
      page: 1,
      per_page: 100,
      total_count: totalCount,
      total_pages: totalCount === 0 ? 0 : Math.ceil(totalCount / 100),
      ...overrides,
    },
    success: true,
  });
}

function singlePage(result: readonly JsonValue[]): Response {
  return Response.json({ errors: [], messages: [], result, success: true });
}

function failure(status = 400, message = 'provider rejected request'): Response {
  return Response.json({
    errors: [{ code: 1000, message }],
    messages: [],
    result: null,
    success: false,
  }, { status });
}

function recorded(factory: Response | ResponseFactory): RecordedTransport {
  const requests: ManagementRequest[] = [];
  return {
    requests,
    transport: async (request) => {
      const index = requests.length;
      requests.push(new Request(request));
      return factory instanceof Response ? factory.clone() : await factory(request, index);
    },
  };
}

function sequenced(steps: readonly (Response | ResponseFactory)[]): RecordedTransport {
  return recorded(async (request, index) => {
    const step = steps[index];
    if (!step) throw new TypeError('unexpected provider request');
    return step instanceof Response ? step.clone() : await step(request, index);
  });
}

function call(transport: CloudflareUninstallManagementTransport): CloudflareUninstallManagementCall {
  return { accessToken: ACCESS_TOKEN, transport };
}

function exactDomain(
  id = DOMAIN_ID,
  environment: 'omitted' | 'production' = 'omitted',
 ) {
  const domain = {
    cert_id: CERTIFICATE_ID,
    hostname: selection.basics.managementHostname,
    id,
    service: workerName,
    zone_id: ZONE_ID,
    zone_name: selection.basics.zoneName,
  };
  return environment === 'production' ? { ...domain, environment } : domain;
}

function exactPolicy(id = POLICY_ID) {
  return {
    approval_required: false,
    decision: 'allow',
    exclude: [],
    id,
    include: plan.managementAdminEmails.map((email) => ({ email: { email } })),
    isolation_required: false,
    name: managementAdminPolicyName(plan),
    precedence: 1,
    purpose_justification_required: false,
    require: [],
  };
}

function exactApplication(id = APPLICATION_ID, aud = AUD) {
  return {
    allow_authenticate_via_warp: false,
    allowed_idps: [IDP_ONE, IDP_TWO],
    app_launcher_visible: false,
    aud,
    auto_redirect_to_identity: false,
    domain: selection.basics.managementHostname,
    id,
    name: managementAccessApplicationName(plan),
    session_duration: '24h',
    type: 'self_hosted',
  };
}

/** The exact shape Cloudflare returns for an installed gateway (live 2026-08-23). */
function installedReferences() {
  return {
    dispatch_namespace_outbounds: [],
    domains: [{
      certificate_id: CERTIFICATE_ID,
      hostname: selection.basics.managementHostname,
      id: DOMAIN_ID,
      zone_id: ZONE_ID,
      zone_name: selection.basics.zoneName,
    }],
    durable_objects: [{
      namespace_id: NAMESPACE_ID,
      namespace_name: `${workerName}_AdminState`,
      worker_id: WORKER_ID,
      worker_name: workerName,
    }],
    queues: [],
    workers: [],
  };
}

function exactWorker() {
  const subdomainHostname = `${workerName}.example-account.workers.dev`;
  return {
    created_on: '2026-08-23T00:00:00.000Z',
    deployed_on: '2026-08-23T00:00:30.123456Z',
    id: WORKER_ID,
    logpush: false,
    name: workerName,
    observability: {
      enabled: false,
      head_sampling_rate: 1,
      redact_query_string: false,
      logs: { enabled: false, head_sampling_rate: 1, invocation_logs: true, persist: true, destinations: [] },
      traces: { enabled: false, head_sampling_rate: 1, persist: true, destinations: [] },
    },
    references: installedReferences(),
    subdomain: {
      enabled: false,
      preview_url_suffix: `-${subdomainHostname}`,
      previews_enabled: false,
      url: `https://${subdomainHostname}`,
    },
    tags: ['ankka-mcp-gateway', correlationTag],
    tail_consumers: [],
    updated_on: '2026-08-23T00:01:00.000Z',
  };
}

function managedCustomDomainDns() {
  return {
    content: '100::',
    id: DNS_ID,
    meta: { source: 'primary' },
    name: selection.basics.managementHostname,
    proxied: true,
    ttl: 1,
    type: 'AAAA',
  };
}

function preflightSteps(
  overrides: Partial<Record<number, Response | ResponseFactory>> = {},
): readonly (Response | ResponseFactory)[] {
  const defaults: readonly (Response | ResponseFactory)[] = [
    success(exactDomain()),
    singlePage([exactDomain()]),
    success(exactPolicy()),
    list([exactPolicy()]),
    success(exactApplication()),
    list([exactApplication()]),
    success(exactWorker()),
    list([{ id: WORKER_ID, name: workerName }]),
    success({ enabled: false, previews_enabled: false }),
    list([managedCustomDomainDns()]),
    singlePage([]),
  ];
  return defaults.map((value, index) => overrides[index] ?? value);
}

async function expectManagementError(
  operation: Promise<unknown>,
  code: CloudflareUninstallManagementErrorCode,
  stage: CloudflareUninstallManagementStage,
  outcome: CloudflareUninstallManagementError['outcome'],
): Promise<void> {
  try {
    await operation;
    expect.fail('expected CloudflareUninstallManagementError');
  } catch (error) {
    if (!(error instanceof CloudflareUninstallManagementError)) throw error;
    expect(error).toBeInstanceOf(CloudflareUninstallManagementError);
    expect(error).toMatchObject({ code, stage, outcome, canRetry: false });
    expect(error.message).toBe(code);
    expect(JSON.stringify(error)).not.toContain(ACCESS_TOKEN);
  }
}

function expectedDeletePath(action: HostedUninstallManagementDeleteAction): string {
  if (action === 'management_custom_domain_delete') {
    return `/client/v4/accounts/${ACCOUNT_ID}/workers/domains/${DOMAIN_ID}`;
  }
  if (action === 'management_admin_policy_delete') {
    return `/client/v4/zones/${ZONE_ID}/access/apps/${APPLICATION_ID}/policies/${POLICY_ID}`;
  }
  return `/client/v4/zones/${ZONE_ID}/access/apps/${APPLICATION_ID}`;
}

function deleteSuccess(action: HostedUninstallManagementDeleteAction): Response {
  if (action === 'management_custom_domain_delete') {
    return Response.json({ errors: [], messages: [], success: true });
  }
  // Live 2026-08-23: Access application and policy deletes answer 202.
  if (action === 'management_admin_policy_delete') return success({ id: POLICY_ID }, 202);
  return success({ id: APPLICATION_ID }, 202);
}

const namespaceAbsence: HostedUninstallExternalNamespaceAbsenceEvidence = Object.freeze({
  kind: 'admin_state_namespace_retirement',
  accountId: ACCOUNT_ID,
  workerName,
  workerId: WORKER_ID,
  uninstallCycleId: UNINSTALL_CYCLE_ID,
  namespaceId: NAMESPACE_ID,
  retirementVersionId: RETIREMENT_VERSION_ID,
  accountNamespaceCount: 0,
  firstSnapshotSha256: 'a'.repeat(64),
  secondSnapshotSha256: 'a'.repeat(64),
});

const AUTH_NOW = uninstallPlan.createdAt + 1;
const canonicalPreflight = await preflightHostedUninstallManagement(
  context,
  call(sequenced(preflightSteps()).transport),
  AUTH_NOW,
);
const domainPrerequisites: HostedUninstallManagementDeletePrerequisites = Object.freeze({
  schemaVersion: 1,
  action: 'management_custom_domain_delete',
  preflight: canonicalPreflight,
});
const domainIntent = await prepareHostedUninstallManagementDeleteIntent(
  context,
  'management_custom_domain_delete',
  domainPrerequisites,
);
const domainAbsence = await verifyHostedUninstallManagementDeleteAbsence(
  context,
  domainIntent,
  domainPrerequisites,
  call(sequenced([failure(404, 'not found'), singlePage([])]).transport),
);
const policyPrerequisites: HostedUninstallManagementDeletePrerequisites = Object.freeze({
  schemaVersion: 1,
  action: 'management_admin_policy_delete',
  domainAbsence,
});
const policyIntent = await prepareHostedUninstallManagementDeleteIntent(
  context,
  'management_admin_policy_delete',
  policyPrerequisites,
);
const policyAbsence = await verifyHostedUninstallManagementDeleteAbsence(
  context,
  policyIntent,
  policyPrerequisites,
  call(sequenced([failure(404, 'not found'), list([])]).transport),
);
const appPrerequisites: HostedUninstallManagementDeletePrerequisites = Object.freeze({
  schemaVersion: 1,
  action: 'management_access_application_delete',
  domainAbsence,
  policyAbsence,
});
const appIntent = await prepareHostedUninstallManagementDeleteIntent(
  context,
  'management_access_application_delete',
  appPrerequisites,
);
const appAbsence = await verifyHostedUninstallManagementDeleteAbsence(
  context,
  appIntent,
  appPrerequisites,
  call(sequenced([failure(404, 'not found'), list([])]).transport),
);
const canonicalIntents = Object.freeze([domainIntent, policyIntent, appIntent]);
const canonicalPrerequisites = Object.freeze([domainPrerequisites, policyPrerequisites, appPrerequisites]);
const deletionEvidence = Object.freeze([domainAbsence, policyAbsence, appAbsence]);

const workerDeleteBase = Object.freeze({
  accountId: ACCOUNT_ID,
  force: 'omitted' as const,
  method: 'DELETE' as const,
  namespaceId: NAMESPACE_ID,
  retirementProof: namespaceAbsence,
  retirementProofCommitment: 'b'.repeat(64),
  retirementVersionId: RETIREMENT_VERSION_ID,
  uninstallCycleId: UNINSTALL_CYCLE_ID,
  workerId: WORKER_ID,
  workerName,
});
const workerDeleteRequestHash = await fixtureHash(workerDeleteBase);
const lifecycleEvidence: HostedUninstallManagementLifecycleEvidence = Object.freeze({
  namespaceRetirement: namespaceAbsence,
  workerDeleteIntent: Object.freeze({
    kind: 'uninstall_worker_delete_intent',
    ...workerDeleteBase,
    requestHash: workerDeleteRequestHash,
    correlationTag: `ankka-un-w-delete-sha256:${workerDeleteRequestHash}`,
  }),
});

describe('private hosted-uninstall Cloudflare management boundary', () => {
  it('proves the exact installed domain, policy, app, Worker, workers.dev state, and one same-name DNS companion', async () => {
    const provider = sequenced(preflightSteps());
    const log = vi.spyOn(console, 'log').mockImplementation(() => undefined);
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => undefined);
    const error = vi.spyOn(console, 'error').mockImplementation(() => undefined);
    try {
      const result = await preflightHostedUninstallManagement(context, call(provider.transport), AUTH_NOW);
      expect(result).toMatchObject({
        schemaVersion: 1,
        status: 'ready',
        uninstallPlanId: uninstallPlan.planId,
        uninstallPlanHash: uninstallPlan.planHash,
        uninstallAuthorityHash: uninstallPlan.authorityHash,
        installBindingHash: installJournal.bindingHash,
        attemptId: context.activeAttemptId,
        ownershipMarker: managementOwnershipMarker(plan),
        checkedAt: AUTH_NOW,
        expiresAt: AUTH_NOW + 60_000,
      });
      expect(result.attestationSha256).toMatch(/^[a-f0-9]{64}$/u);
      expect(Object.isFrozen(result)).toBe(true);
      expect(log).not.toHaveBeenCalled();
      expect(warn).not.toHaveBeenCalled();
      expect(error).not.toHaveBeenCalled();
    } finally {
      log.mockRestore();
      warn.mockRestore();
      error.mockRestore();
    }

    expect(provider.requests.map((request) => new URL(request.url).pathname)).toEqual([
      `/client/v4/accounts/${ACCOUNT_ID}/workers/domains/${DOMAIN_ID}`,
      `/client/v4/accounts/${ACCOUNT_ID}/workers/domains`,
      `/client/v4/zones/${ZONE_ID}/access/apps/${APPLICATION_ID}/policies/${POLICY_ID}`,
      `/client/v4/zones/${ZONE_ID}/access/apps/${APPLICATION_ID}/policies`,
      `/client/v4/zones/${ZONE_ID}/access/apps/${APPLICATION_ID}`,
      `/client/v4/zones/${ZONE_ID}/access/apps`,
      `/client/v4/accounts/${ACCOUNT_ID}/workers/workers/${WORKER_ID}`,
      `/client/v4/accounts/${ACCOUNT_ID}/workers/workers`,
      `/client/v4/accounts/${ACCOUNT_ID}/workers/scripts/${workerName}/subdomain`,
      `/client/v4/zones/${ZONE_ID}/dns_records`,
      `/client/v4/zones/${ZONE_ID}/workers/routes`,
    ]);
    for (const request of provider.requests) {
      expect(new URL(request.url).origin).toBe('https://api.cloudflare.com');
      expect(request.method).toBe('GET');
      expect(request.headers.get('authorization')).toBe(`Bearer ${ACCESS_TOKEN}`);
      expect(request.headers.get('accept')).toBe('application/json');
      // workerd refuses redirect:'error'; 'manual' plus explicit 3xx rejection.
      expect(request.redirect).toBe('manual');
      expect(request.body).toBeNull();
    }
    const applicationListUrl = new URL(requiredFixture(provider.requests.at(1), 'application list request').url);
    expect(applicationListUrl.searchParams.get('hostname')).toBe(selection.basics.managementHostname);
    expect(applicationListUrl.searchParams.get('page')).toBeNull();
    expect(applicationListUrl.searchParams.get('per_page')).toBeNull();
    expect(new URL(requiredFixture(provider.requests.at(5), 'custom domain request').url).searchParams.get('domain')).toBe(selection.basics.managementHostname);
    expect(new URL(requiredFixture(provider.requests.at(9), 'DNS request').url).searchParams.get('name.exact')).toBe(selection.basics.managementHostname);
    expect(new URL(requiredFixture(provider.requests.at(10), 'route request').url).search).toBe('');
  });

  it('also accepts an installed Custom Domain whose managed DNS companion is hidden from DNS Records', async () => {
    const provider = sequenced(preflightSteps({ 9: list([]) }));
    await expect(preflightHostedUninstallManagement(context, call(provider.transport), AUTH_NOW)).resolves.toMatchObject({
      status: 'ready',
    });
  });

  it('accepts both provider-real Custom Domain environment spellings', async () => {
    const provider = sequenced(preflightSteps({
      0: success(exactDomain(DOMAIN_ID, 'production')),
      1: singlePage([exactDomain(DOMAIN_ID, 'production')]),
    }));
    await expect(preflightHostedUninstallManagement(
      context,
      call(provider.transport),
      AUTH_NOW,
    )).resolves.toMatchObject({ status: 'ready' });
  });

  it.each([
    ['domain drift', 0, success({ ...exactDomain(), service: 'foreign-worker' }), 'fresh_custom_domain_get'],
    ['policy drift', 2, success({ ...exactPolicy(), decision: 'bypass' }), 'fresh_admin_policy_get'],
    ['application drift', 4, success({ ...exactApplication(), aud: 'foreign-audience-token-1234' }), 'fresh_access_application_get'],
    ['Worker drift', 6, success({ ...exactWorker(), unexpected: true }), 'fresh_worker_get'],
    ['unsafe Worker observability', 6, success({
      ...exactWorker(), observability: { enabled: false, redact_query_string: true },
    }), 'fresh_worker_get'],
    ['Worker subdomain enabled', 6, success({
      ...exactWorker(), subdomain: { ...exactWorker().subdomain, enabled: true },
    }), 'fresh_worker_get'],
    ['Worker subdomain metadata injection', 6, success({
      ...exactWorker(), subdomain: {
        ...exactWorker().subdomain,
        url: `https://${workerName}.example-account.workers.dev?next=1`,
      },
    }), 'fresh_worker_get'],
    ['Worker subdomain metadata mismatch', 6, success({
      ...exactWorker(), subdomain: {
        ...exactWorker().subdomain,
        preview_url_suffix: '-foreign-worker.example-account.workers.dev',
      },
    }), 'fresh_worker_get'],
    ['Worker subdomain unexpected field', 6, success({
      ...exactWorker(), subdomain: { ...exactWorker().subdomain, unexpected: true },
    }), 'fresh_worker_get'],
    ['workers.dev enabled', 8, success({ enabled: true, previews_enabled: false }), 'fresh_workers_dev_get'],
  ] as const)('fails closed on %s before any mutation', async (_name, index, response, stage) => {
    const provider = sequenced(preflightSteps({ [index]: response }));
    await expectManagementError(
      preflightHostedUninstallManagement(context, call(provider.transport), AUTH_NOW),
      'provider_mismatch',
      stage,
      'rejected',
    );
    expect(provider.requests.every((request) => request.method === 'GET')).toBe(true);
  });

  it('requires a deployed Worker and the exact authoritative Custom Domain reference', async () => {
    const neverDeployed = sequenced(preflightSteps({
      6: success({ ...exactWorker(), deployed_on: null }),
    }));
    await expectManagementError(
      preflightHostedUninstallManagement(context, call(neverDeployed.transport), AUTH_NOW),
      'provider_mismatch',
      'fresh_worker_get',
      'rejected',
    );

    const missingDomainReference = sequenced(preflightSteps({
      6: success({ ...exactWorker(), references: {
        ...installedReferences(),
        domains: [],
      } }),
    }));
    await expectManagementError(
      preflightHostedUninstallManagement(context, call(missingDomainReference.transport), AUTH_NOW),
      'provider_mismatch',
      'fresh_worker_get',
      'rejected',
    );

    const wrongCertificate = sequenced(preflightSteps({
      6: success({ ...exactWorker(), references: {
        ...installedReferences(),
        domains: [{
          ...installedReferences().domains[0],
          certificate_id: '8'.repeat(32),
        }],
      } }),
    }));
    await expectManagementError(
      preflightHostedUninstallManagement(context, call(wrongCertificate.transport), AUTH_NOW),
      'provider_mismatch',
      'fresh_worker_get',
      'rejected',
    );
  });

  it('accepts documented RFC3339 timestamp precision instead of one JS-normalized spelling', async () => {
    const provider = sequenced(preflightSteps({
      6: success({
        ...exactWorker(),
        created_on: '2026-08-23T02:00:00+02:00',
        deployed_on: '2026-08-23T02:00:30.123456789+02:00',
        updated_on: '2026-08-23T02:01:00+02:00',
      }),
    }));
    await expect(preflightHostedUninstallManagement(
      context,
      call(provider.transport),
      AUTH_NOW,
    )).resolves.toMatchObject({ status: 'ready' });
  });

  it('accepts at most one current-schema DNS companion and rejects extras or an overlapping Worker route', async () => {
    const duplicateDns = sequenced(preflightSteps({
      9: list([managedCustomDomainDns(), { ...managedCustomDomainDns(), id: FOREIGN_ID }]),
    }));
    await expectManagementError(
      preflightHostedUninstallManagement(context, call(duplicateDns.transport), AUTH_NOW),
      'management_residue',
      'fresh_dns_collision_list',
      'rejected',
    );

    const overlappingRoute = sequenced(preflightSteps({
      10: singlePage([{ id: ROUTE_ID, pattern: `${selection.basics.managementHostname}/*`, script: workerName }]),
    }));
    await expectManagementError(
      preflightHostedUninstallManagement(context, call(overlappingRoute.transport), AUTH_NOW),
      'management_residue',
      'fresh_worker_route_list',
      'rejected',
    );
  });

  it('rejects ambiguous replacements and pagination claims beyond the fixed 20-page bound', async () => {
    const duplicateDomain = sequenced(preflightSteps({
      1: singlePage([exactDomain(), { ...exactDomain(), id: FOREIGN_ID }]),
    }));
    await expectManagementError(
      preflightHostedUninstallManagement(context, call(duplicateDomain.transport), AUTH_NOW),
      'provider_ambiguous',
      'fresh_custom_domain_list',
      'rejected',
    );

    const excessivePagination = sequenced(preflightSteps({
      3: list([exactPolicy()], { total_count: 2_001, total_pages: 21 }),
    }));
    await expectManagementError(
      preflightHostedUninstallManagement(context, call(excessivePagination.transport), AUTH_NOW),
      'provider_unknown',
      'fresh_admin_policy_list',
      'unknown',
    );
  });

  it('does not treat global filtered-list totals as the filtered result size', async () => {
    const globalTotals = { total_count: 2_000, total_pages: 20 };
    const provider = sequenced(preflightSteps({
      1: list([exactDomain()], globalTotals),
      5: list([exactApplication()], globalTotals),
      9: list([managedCustomDomainDns()], globalTotals),
    }));
    await expect(preflightHostedUninstallManagement(
      context,
      call(provider.transport),
      AUTH_NOW,
    )).resolves.toMatchObject({ status: 'ready' });
  });

  it('accepts documented optional Domain metadata but rejects malformed Domain or any Route metadata', async () => {
    const documentedDomainMetadata = sequenced(preflightSteps({
      1: list([exactDomain()]),
    }));
    await expect(preflightHostedUninstallManagement(
      context,
      call(documentedDomainMetadata.transport),
      AUTH_NOW,
    )).resolves.toMatchObject({ status: 'ready' });

    const documentedPartialDomainMetadata = sequenced(preflightSteps({
      1: Response.json({
        errors: [],
        messages: [],
        result: [exactDomain()],
        result_info: { count: 1 },
        success: true,
      }),
    }));
    await expect(preflightHostedUninstallManagement(
      context,
      call(documentedPartialDomainMetadata.transport),
      AUTH_NOW,
    )).resolves.toMatchObject({ status: 'ready' });

    const malformed = sequenced(preflightSteps({
      1: Response.json({
        errors: [],
        messages: [],
        result: [exactDomain()],
        result_info: { page: 2 },
        success: true,
      }),
    }));
    await expectManagementError(
      preflightHostedUninstallManagement(context, call(malformed.transport), AUTH_NOW),
      'provider_unknown',
      'fresh_custom_domain_list',
      'unknown',
    );

    const routeWithInventedPagination = sequenced(preflightSteps({
      10: list([]),
    }));
    await expectManagementError(
      preflightHostedUninstallManagement(context, call(routeWithInventedPagination.transport), AUTH_NOW),
      'provider_unknown',
      'fresh_worker_route_list',
      'unknown',
    );
  });

  it('rejects duplicate route IDs and bounds the provider SinglePage result', async () => {
    const duplicateRoute = { id: ROUTE_ID, pattern: 'unrelated.example.net/*', script: 'other-worker' };
    const provider = sequenced(preflightSteps({
      10: singlePage([duplicateRoute, duplicateRoute]),
    }));
    await expectManagementError(
      preflightHostedUninstallManagement(context, call(provider.transport), AUTH_NOW),
      'provider_ambiguous',
      'fresh_worker_route_list',
      'unknown',
    );

    const oversizedRoutes = Array.from({ length: 2_001 }, (_, index) => ({
      id: index.toString(16).padStart(32, '0'),
    }));
    const oversized = sequenced(preflightSteps({ 10: singlePage(oversizedRoutes) }));
    await expectManagementError(
      preflightHostedUninstallManagement(context, call(oversized.transport), AUTH_NOW),
      'provider_unknown',
      'fresh_worker_route_list',
      'unknown',
    );
  });

  it('binds authority to the complete install journal, uninstall plan, approval attempt, and exact target', async () => {
    const provider = recorded(success(null));
    const activeApproval = requiredFixture(context.approvalHistory.at(0), 'active approval');
    const wrongTarget = {
      ...context,
      approvalHistory: [{ ...activeApproval, authorizedTarget: {
        ...target, account: { ...target.account, id: FOREIGN_ID },
      } }],
    };
    await expectManagementError(
      preflightHostedUninstallManagement(wrongTarget, call(provider.transport), AUTH_NOW),
      'invalid_input',
      'validate',
      'not_sent',
    );
    const extraSelection = {
      ...context,
      selection,
    };
    await expectManagementError(
      preflightHostedUninstallManagement(extraSelection, call(provider.transport), AUTH_NOW),
      'invalid_input',
      'validate',
      'not_sent',
    );
    const forgedPlan = {
      ...context,
      approvalHistory: [{ ...activeApproval, uninstallPlan: {
        ...uninstallPlan, authorityHash: `sha256:${'f'.repeat(64)}`,
      } }],
    };
    await expectManagementError(
      preflightHostedUninstallManagement(forgedPlan, call(provider.transport), AUTH_NOW),
      'invalid_input',
      'validate',
      'not_sent',
    );
    for (const attemptId of [INSTALL_ATTEMPT_ID, 'attempt-uninstall-fixture-0001']) {
      await expectManagementError(
        preflightHostedUninstallManagement(
          { ...context, activeAttemptId: attemptId, approvalHistory: [{
            ...activeApproval, attemptId,
          }] },
          call(provider.transport),
          AUTH_NOW,
        ),
        'invalid_input',
        'validate',
        'not_sent',
      );
    }
    expect(provider.requests).toHaveLength(0);
  });

  it('rejects unapproved evidence origins and target, plan, or authority drift across grants', async () => {
    const contextB = contextThroughApproval(1);
    type DomainEvidencePatch = Partial<Pick<
      typeof domainAbsence,
      'attemptId' | 'accountId' | 'uninstallPlanHash' | 'uninstallAuthorityHash'
    >>;
    async function forgedDomainEvidence(patch: DomainEvidencePatch) {
      const { evidenceSha256: _discard, ...base } = domainAbsence;
      const semantic = { ...base, ...patch };
      return { ...semantic, evidenceSha256: await fixtureHash(semantic) };
    }
    const candidates = [
      await forgedDomainEvidence({ attemptId: `att_${'f'.repeat(32)}` }),
      await forgedDomainEvidence({ accountId: FOREIGN_ID }),
      await forgedDomainEvidence({ uninstallPlanHash: `sha256:${'1'.repeat(64)}` }),
      await forgedDomainEvidence({ uninstallAuthorityHash: `sha256:${'2'.repeat(64)}` }),
    ];
    for (const domainEvidence of candidates) {
      await expectManagementError(
        prepareHostedUninstallManagementDeleteIntent(
          contextB,
          'management_admin_policy_delete',
          { schemaVersion: 1, action: 'management_admin_policy_delete', domainAbsence: domainEvidence },
        ),
        'invalid_input',
        'validate',
        'not_sent',
      );
    }

    const firstApproval = contextB.approvalHistory[0];
    const secondApproval = contextB.approvalHistory[1];
    if (!firstApproval || !secondApproval) throw new Error('missing approval fixture');
    const duplicateAttempt = {
      ...contextB,
      approvalHistory: [firstApproval, {
        ...secondApproval,
        attemptId: firstApproval.attemptId,
      }],
      activeAttemptId: firstApproval.attemptId,
    };
    await expectManagementError(
      preflightHostedUninstallManagement(duplicateAttempt, call(recorded(success(null)).transport), AUTH_NOW),
      'invalid_input',
      'validate',
      'not_sent',
    );
  });

  it('emits exact secret-free intents and pure deep-frozen parsers reject extras or commitment drift', async () => {
    expect(HOSTED_UNINSTALL_MANAGEMENT_DELETE_ORDER).toEqual([
      'management_custom_domain_delete',
      'management_admin_policy_delete',
      'management_access_application_delete',
    ]);
    expect(HOSTED_UNINSTALL_MANAGEMENT_JOURNAL_ALLOWLIST.intent).toContain('uninstallAuthorityHash');
    expect(HOSTED_UNINSTALL_MANAGEMENT_JOURNAL_ALLOWLIST.intent).toContain('installConvergenceHash');
    expect(HOSTED_UNINSTALL_MANAGEMENT_JOURNAL_ALLOWLIST.intent).toContain('prerequisiteCommitments');
    for (const [index, intent] of canonicalIntents.entries()) {
      const prerequisites = requiredFixture(canonicalPrerequisites.at(index), `prerequisites ${index}`);
      expect(intent).toMatchObject({
        ordinal: index,
        uninstallPlanId: uninstallPlan.planId,
        uninstallPlanHash: uninstallPlan.planHash,
        uninstallAuthorityHash: uninstallPlan.authorityHash,
        installBindingHash: installJournal.bindingHash,
        attemptId: context.activeAttemptId,
      });
      expect(Object.keys(intent).sort()).toEqual([...HOSTED_UNINSTALL_MANAGEMENT_JOURNAL_ALLOWLIST.intent].sort());
      expect(JSON.stringify(intent)).not.toMatch(/bearer|authorization|secret|ephemeral_oauth/iu);
      expect(await parseHostedUninstallManagementDeleteIntent(
        context,
        prerequisites,
        intent,
      )).toEqual(intent);
      expect(await parseHostedUninstallManagementDeleteIntent(
        context,
        prerequisites,
        { ...intent, accessToken: ACCESS_TOKEN },
      )).toBeNull();
    }
    expect(await parseHostedUninstallManagementPreflightResult(context, canonicalPreflight)).toEqual(canonicalPreflight);
    const parsedPreflight = await parseHostedUninstallManagementPreflightResult(context, canonicalPreflight);
    expect(Object.isFrozen(requiredFixture(parsedPreflight ?? undefined, 'parsed preflight'))).toBe(true);
    expect(await parseHostedUninstallManagementPreflightResult(
      context,
      { ...canonicalPreflight, attestationSha256: '0'.repeat(64) },
    )).toBeNull();
  });

  it('requires a current preflight and fresh exact reads immediately before each destructive call', async () => {
    const providerSteps: readonly (readonly (Response | ResponseFactory)[])[] = [
      [success(exactDomain()), singlePage([exactDomain()]), deleteSuccess('management_custom_domain_delete')],
      [
        success(exactApplication()), list([exactApplication()]),
        failure(404, 'domain absent'), singlePage([]),
        success(exactPolicy()), list([exactPolicy()]),
        deleteSuccess('management_admin_policy_delete'),
      ],
      [
        success(exactApplication()), list([exactApplication()]),
        failure(404, 'domain absent'), singlePage([]),
        failure(404, 'policy absent'), list([]),
        deleteSuccess('management_access_application_delete'),
      ],
    ];
    for (const [index, intent] of canonicalIntents.entries()) {
      const prerequisites = requiredFixture(canonicalPrerequisites.at(index), `prerequisites ${index}`);
      const arm = await prepareHostedUninstallManagementDeleteArm(
        context,
        intent,
        prerequisites,
        AUTH_NOW + 10 + index,
      );
      expect(await parseHostedUninstallManagementDeleteArm(context, intent, prerequisites, arm)).toEqual(arm);
      const provider = sequenced(requiredFixture(providerSteps.at(index), `provider steps ${index}`));
      const submission = await submitHostedUninstallManagementDeleteOnce(
        context,
        intent,
        arm,
        prerequisites,
        call(provider.transport),
        AUTH_NOW + 20 + index,
      );
      expect(submission).toMatchObject({ status: 'submitted', action: intent.kind, attemptId: context.activeAttemptId });
      expect(await parseHostedUninstallManagementDeleteSubmission(
        context, intent, prerequisites, arm, submission,
      )).toEqual(submission);
      expect(await parseHostedUninstallManagementDeleteSubmission(
        context,
        intent,
        prerequisites,
        arm,
        { ...submission, locator: { id: FOREIGN_ID } },
      )).toBeNull();
      expect(provider.requests.at(-1)?.method).toBe('DELETE');
      expect(new URL(provider.requests.at(-1)?.url ?? '').pathname).toBe(expectedDeletePath(intent.kind));
      expect(provider.requests.slice(0, -1).every((request) => request.method === 'GET')).toBe(true);
    }

    const expiredArm = await prepareHostedUninstallManagementDeleteArm(
      context,
      domainIntent,
      domainPrerequisites,
      AUTH_NOW + 1,
    );
    const noCall = recorded(success(null));
    await expectManagementError(
      submitHostedUninstallManagementDeleteOnce(
        context,
        domainIntent,
        expiredArm,
        domainPrerequisites,
        call(noCall.transport),
        canonicalPreflight.expiresAt,
      ),
      'invalid_input',
      'validate',
      'not_sent',
    );
    expect(noCall.requests).toHaveLength(0);
  });

  it('rejects the invented result-bearing shape for Custom Domain DELETE', async () => {
    const arm = await prepareHostedUninstallManagementDeleteArm(
      context,
      domainIntent,
      domainPrerequisites,
      AUTH_NOW + 1,
    );
    const provider = sequenced([
      success(exactDomain()),
      singlePage([exactDomain()]),
      success({ id: DOMAIN_ID }),
    ]);
    await expectManagementError(
      submitHostedUninstallManagementDeleteOnce(
        context,
        domainIntent,
        arm,
        domainPrerequisites,
        call(provider.transport),
        AUTH_NOW + 2,
      ),
      'provider_unknown',
      'management_custom_domain_delete',
      'unknown',
    );
    expect(provider.requests.at(-1)?.method).toBe('DELETE');
  });

  it('accepts the live HTTP 202 for Access policy and application DELETE and still rejects 203', async () => {
    const fixtures = [
      {
        intent: policyIntent,
        prerequisites: policyPrerequisites,
        providerSteps: [
          success(exactApplication()), list([exactApplication()]),
          failure(404, 'domain absent'), singlePage([]),
          success(exactPolicy()), list([exactPolicy()]),
          success({ id: POLICY_ID }, 202),
        ],
      },
      {
        intent: appIntent,
        prerequisites: appPrerequisites,
        providerSteps: [
          success(exactApplication()), list([exactApplication()]),
          failure(404, 'domain absent'), singlePage([]),
          failure(404, 'policy absent'), list([]),
          success({ id: APPLICATION_ID }, 202),
        ],
      },
    ] as const;
    for (const fixture of fixtures) {
      const arm = await prepareHostedUninstallManagementDeleteArm(
        context,
        fixture.intent,
        fixture.prerequisites,
        AUTH_NOW + 1,
      );
      // Live 2026-08-23: Cloudflare answers 202 with the deleted id.
      const provider = sequenced(fixture.providerSteps);
      await expect(submitHostedUninstallManagementDeleteOnce(
        context,
        fixture.intent,
        arm,
        fixture.prerequisites,
        call(provider.transport),
        AUTH_NOW + 2,
      )).resolves.toMatchObject({ status: 'submitted', action: fixture.intent.kind });
      expect(provider.requests.at(-1)?.method).toBe('DELETE');

      const otherStatus = sequenced(fixture.providerSteps.map((step, index, steps) => (
        index === steps.length - 1
          ? success(fixture.intent.kind === 'management_admin_policy_delete' ? { id: POLICY_ID } : { id: APPLICATION_ID }, 203)
          : step.clone()
      )));
      const armAgain = await prepareHostedUninstallManagementDeleteArm(
        context,
        fixture.intent,
        fixture.prerequisites,
        AUTH_NOW + 3,
      );
      await expectManagementError(
        submitHostedUninstallManagementDeleteOnce(
          context,
          fixture.intent,
          armAgain,
          fixture.prerequisites,
          call(otherStatus.transport),
          AUTH_NOW + 4,
        ),
        'provider_unknown',
        fixture.intent.kind,
        'unknown',
      );
    }
  });

  it('binds policy/app intents to exact prior absence evidence and rejects reordered or forged prerequisites', async () => {
    await expectManagementError(
      prepareHostedUninstallManagementDeleteIntent(
        context,
        'management_admin_policy_delete',
        { ...policyPrerequisites, domainAbsence: { ...domainAbsence, evidenceSha256: '0'.repeat(64) } },
      ),
      'invalid_input',
      'validate',
      'not_sent',
    );
    await expectManagementError(
      prepareHostedUninstallManagementDeleteIntent(
        context,
        'management_access_application_delete',
        { ...appPrerequisites, policyAbsence: appAbsence },
      ),
      'invalid_input',
      'validate',
      'not_sent',
    );
  });

  it('proves exact delete absence and parsers recompute the evidence commitment', async () => {
    for (const [index, intent] of canonicalIntents.entries()) {
      const evidence = requiredFixture(deletionEvidence.at(index), `deletion evidence ${index}`);
      const prerequisites = requiredFixture(canonicalPrerequisites.at(index), `prerequisites ${index}`);
      expect(evidence).toMatchObject({
        status: 'absent',
        action: intent.kind,
        locator: intent.locator,
        evidenceSha256: expect.stringMatching(/^[a-f0-9]{64}$/u),
      });
      expect(await parseHostedUninstallManagementAbsenceEvidence(
        context,
        intent,
        prerequisites,
        evidence,
      )).toEqual(evidence);
      expect(await parseHostedUninstallManagementAbsenceEvidence(
        context,
        intent,
        prerequisites,
        { ...evidence, locator: { id: FOREIGN_ID } },
      )).toBeNull();
    }
  });

  it('carries exact deletion evidence across fresh approved grants through final convergence', async () => {
    const contextB = contextThroughApproval(1);
    const contextC = contextThroughApproval(2);
    const contextD = contextThroughApproval(3);

    const domainReadB = await verifyHostedUninstallManagementDeleteAbsence(
      contextB,
      domainIntent,
      domainPrerequisites,
      call(sequenced([failure(404, 'domain absent'), singlePage([])]).transport),
    );
    expect(domainReadB.attemptId).toBe(RECOVERY_ATTEMPT_ONE);
    const policyPrerequisitesB: HostedUninstallManagementDeletePrerequisites = Object.freeze({
      schemaVersion: 1,
      action: 'management_admin_policy_delete',
      domainAbsence: domainReadB,
    });
    const policyIntentB = await prepareHostedUninstallManagementDeleteIntent(
      contextB,
      'management_admin_policy_delete',
      policyPrerequisitesB,
    );
    expect(policyIntentB.attemptId).toBe(RECOVERY_ATTEMPT_ONE);

    const policyReadC = await verifyHostedUninstallManagementDeleteAbsence(
      contextC,
      policyIntentB,
      policyPrerequisitesB,
      call(sequenced([failure(404, 'policy absent'), list([])]).transport),
    );
    expect(policyReadC.attemptId).toBe(RECOVERY_ATTEMPT_TWO);
    const appPrerequisitesC: HostedUninstallManagementDeletePrerequisites = Object.freeze({
      schemaVersion: 1,
      action: 'management_access_application_delete',
      domainAbsence: domainReadB,
      policyAbsence: policyReadC,
    });
    const appIntentC = await prepareHostedUninstallManagementDeleteIntent(
      contextC,
      'management_access_application_delete',
      appPrerequisitesC,
    );
    expect(appIntentC.attemptId).toBe(RECOVERY_ATTEMPT_TWO);

    const appReadD = await verifyHostedUninstallManagementDeleteAbsence(
      contextD,
      appIntentC,
      appPrerequisitesC,
      call(sequenced([failure(404, 'application absent'), list([])]).transport),
    );
    expect(appReadD.attemptId).toBe(RECOVERY_ATTEMPT_THREE);
    const mixedEvidence = Object.freeze([domainReadB, policyReadC, appReadD]);
    const provider = sequenced([
      failure(404, 'domain absent'), singlePage([]),
      failure(404, 'application absent'), list([]),
      list([]), list([]), singlePage([]),
      failure(404, 'beta worker absent'), failure(404, 'script absent'), list([]),
      failure(404, 'beta worker absent'), failure(404, 'script absent'), list([]),
      list([]), list([]),
    ]);
    const result = await verifyHostedUninstallManagementNoManagedResidue(
      contextD,
      mixedEvidence,
      lifecycleEvidence,
      call(provider.transport),
    );
    expect(result.attemptId).toBe(RECOVERY_ATTEMPT_THREE);
    expect(result.evidence.deletionEvidence.map((entry) => entry.attemptId)).toEqual([
      RECOVERY_ATTEMPT_ONE,
      RECOVERY_ATTEMPT_TWO,
      RECOVERY_ATTEMPT_THREE,
    ]);
    await expect(parseHostedUninstallManagementNoManagedResidueResult(contextD, result)).resolves.toEqual(result);

    await expectManagementError(
      prepareHostedUninstallManagementDeleteArm(
        contextB,
        domainIntent,
        domainPrerequisites,
        recoveryPlanOne.createdAt + 1,
      ),
      'invalid_input',
      'validate',
      'not_sent',
    );
  });

  it('recovers historical send-armed deletes as exact absent or still-present/not-applied evidence', async () => {
    const contextB = contextThroughApproval(1);
    const actionFixtures = [
      { intent: domainIntent, prerequisites: domainPrerequisites,
        present: [success(exactDomain()), singlePage([exactDomain()])] },
      { intent: policyIntent, prerequisites: policyPrerequisites,
        present: [success(exactPolicy()), list([exactPolicy()])] },
      { intent: appIntent, prerequisites: appPrerequisites,
        present: [success(exactApplication()), list([exactApplication()])] },
    ] as const;
    for (const fixture of actionFixtures) {
      const arm = await prepareHostedUninstallManagementDeleteArm(
        context,
        fixture.intent,
        fixture.prerequisites,
        AUTH_NOW + 1,
      );
      const proof = await recoverHostedUninstallManagementDeleteOutcome(
        contextB,
        fixture.intent,
        arm,
        fixture.prerequisites,
        call(sequenced(fixture.present).transport),
      );
      expect(proof).toMatchObject({
        status: 'still_present',
        outcome: 'not_applied',
        action: fixture.intent.kind,
        attemptId: RECOVERY_ATTEMPT_ONE,
        deleteAttemptId: UNINSTALL_ATTEMPT_ID,
        intentSha256: arm.intentSha256,
        proof: 'id_get_200_and_complete_list_exact_match',
      });
      expect(await parseHostedUninstallManagementDeleteRecoveryEvidence(
        contextB,
        fixture.intent,
        arm,
        fixture.prerequisites,
        proof,
      )).toEqual(proof);
      expect(JSON.stringify(proof)).not.toMatch(/accessToken|authorization|providerBody/iu);
    }

    const domainArm = await prepareHostedUninstallManagementDeleteArm(
      context,
      domainIntent,
      domainPrerequisites,
      AUTH_NOW + 1,
    );
    const absent = await recoverHostedUninstallManagementDeleteOutcome(
      contextB,
      domainIntent,
      domainArm,
      domainPrerequisites,
      call(sequenced([failure(404, 'domain absent'), singlePage([])]).transport),
    );
    expect(absent).toMatchObject({ status: 'absent', attemptId: RECOVERY_ATTEMPT_ONE });
    expect(await parseHostedUninstallManagementDeleteRecoveryEvidence(
      contextB,
      domainIntent,
      domainArm,
      domainPrerequisites,
      absent,
    )).toEqual(absent);

    const drift = sequenced([success({ ...exactDomain(), service: 'foreign-worker' })]);
    await expectManagementError(
      recoverHostedUninstallManagementDeleteOutcome(
        contextB,
        domainIntent,
        domainArm,
        domainPrerequisites,
        call(drift.transport),
      ),
      'provider_mismatch',
      'management_custom_domain_recovery_get',
      'rejected',
    );
  });

  it('reruns Worker deletion recovery and two full namespace catalogues before claiming no managed residue', async () => {
    const provider = sequenced([
      failure(404, 'domain absent'), singlePage([]),
      failure(404, 'application absent'), list([]),
      list([]), list([]), singlePage([]),
      failure(404, 'beta worker absent'), failure(404, 'script absent'), list([]),
      failure(404, 'beta worker absent'), failure(404, 'script absent'), list([]),
      list([]), list([]),
    ]);
    const result = await verifyHostedUninstallManagementNoManagedResidue(
      context,
      deletionEvidence,
      lifecycleEvidence,
      call(provider.transport),
    );
    expect(result).toMatchObject({
      schemaVersion: 1,
      status: 'no_ankka_managed_residue',
      uninstallPlanId: uninstallPlan.planId,
      uninstallPlanHash: uninstallPlan.planHash,
      uninstallAuthorityHash: uninstallPlan.authorityHash,
      installBindingHash: installJournal.bindingHash,
      attemptId: context.activeAttemptId,
      managementHostname: selection.basics.managementHostname,
      dnsAbsenceObservations: 2,
      advancedCertificate: 'provider_retained_out_of_scope_not_observable_or_deleted',
      uninstallCycleId: UNINSTALL_CYCLE_ID,
      evidence: {
        kind: 'hosted_uninstall_no_managed_residue_evidence',
        deletionEvidence,
        workerDeletion: { kind: 'uninstall_worker_deletion_proof' },
        namespaceRetirement: namespaceAbsence,
        namespaceSnapshots: [
          { observation: 1, accountNamespaceCount: 0 },
          { observation: 2, accountNamespaceCount: 0 },
        ],
      },
    });
    expect(await parseHostedUninstallManagementNoManagedResidueEvidence(context, result.evidence)).toEqual(result.evidence);
    expect(Object.isFrozen(result.evidence)).toBe(true);
    expect(Object.isFrozen(result.evidence.namespaceSnapshots)).toBe(true);
    expect(await parseHostedUninstallManagementNoManagedResidueResult(context, result)).toEqual(result);
    expect(await parseHostedUninstallManagementNoManagedResidueResult(
      context,
      { ...result, namespaceSnapshotSha256: '0'.repeat(64) },
    )).toBeNull();
    expect(await parseHostedUninstallManagementNoManagedResidueResult(
      context,
      { ...result, evidence: { ...result.evidence, providerBody: { accessToken: ACCESS_TOKEN } } },
    )).toBeNull();
    expect(await parseHostedUninstallManagementNoManagedResidueEvidence(
      context,
      {
        ...result.evidence,
        namespaceSnapshots: [
          { ...result.evidence.namespaceSnapshots[0], accountNamespaceCount: 1 },
          result.evidence.namespaceSnapshots[1],
        ],
      },
    )).toBeNull();
    expect(provider.requests).toHaveLength(15);
    expect(provider.requests.every((request) => request.method === 'GET')).toBe(true);
    expect(provider.requests.filter((request) => request.url.includes('/durable_objects/namespaces'))).toHaveLength(2);
    expect(provider.requests.filter((request) => request.url.includes('/workers/workers/'))).toHaveLength(2);
  });

  it('rejects forged lifecycle authority and namespace residue before issuing a final claim', async () => {
    const noCall = recorded(success(null));
    await expectManagementError(
      verifyHostedUninstallManagementNoManagedResidue(
        context,
        deletionEvidence,
        { ...lifecycleEvidence, workerDeleteIntent: {
          ...lifecycleEvidence.workerDeleteIntent,
          namespaceId: FOREIGN_ID,
        } },
        call(noCall.transport),
      ),
      'invalid_input',
      'validate',
      'not_sent',
    );
    expect(noCall.requests).toHaveLength(0);

    const steps: (Response | ResponseFactory)[] = [
      failure(404), singlePage([]), failure(404), list([]), list([]), list([]), singlePage([]),
      failure(404), failure(404), list([]), failure(404), failure(404), list([]),
      list([{ id: NAMESPACE_ID, class: 'AdminState', name: 'retained', script: workerName, use_sqlite: true }]),
    ];
    const residue = sequenced(steps);
    await expectManagementError(
      verifyHostedUninstallManagementNoManagedResidue(
        context,
        deletionEvidence,
        lifecycleEvidence,
        call(residue.transport),
      ),
      'management_residue',
      'final_namespace_list',
      'rejected',
    );
  });

  it('bounds/redacts malformed provider bodies and never persists token/body/error payloads', async () => {
    const oversized = recorded(new Response('{}', {
      status: 200,
      headers: { 'content-length': String(128 * 1024 + 1), 'content-type': 'application/json' },
    }));
    await expectManagementError(
      preflightHostedUninstallManagement(context, call(oversized.transport), AUTH_NOW),
      'provider_unknown',
      'fresh_custom_domain_get',
      'unknown',
    );
    const malformed = recorded(Response.json({
      errors: [], messages: [], result: exactDomain(), success: true, token: ACCESS_TOKEN,
    }));
    await expectManagementError(
      preflightHostedUninstallManagement(context, call(malformed.transport), AUTH_NOW),
      'provider_unknown',
      'fresh_custom_domain_get',
      'unknown',
    );
    for (const value of [
      canonicalPreflight, ...canonicalIntents, ...deletionEvidence, lifecycleEvidence,
    ]) expect(JSON.stringify(value)).not.toContain(ACCESS_TOKEN);
  });
});

import { describe, expect, it } from 'vitest';
import * as v from 'valibot';

import {
  managementAccessApplicationName,
  managementAdminPolicyName,
  managementOwnershipMarker,
  prepareManagementAccessApplicationIntent,
  prepareManagementAdminPolicyIntent,
  prepareManagementCustomDomainIntent,
} from '../src/cloudflare-management-surface';
import {
  prepareHostedUninstallManagementDeleteArm,
  prepareHostedUninstallManagementDeleteIntent,
  type HostedUninstallManagementContext,
  type HostedUninstallManagementDeleteAction,
  type HostedUninstallManagementDeleteArm,
  type HostedUninstallManagementDeleteIntent,
  type HostedUninstallManagementDeletePrerequisites,
  type HostedUninstallManagementPreflightResult,
} from '../src/cloudflare-uninstall-management';
import type { AuthorizedTarget } from '../src/cloudflare-target';
import {
  prepareCleanupWorkerVersionMutation,
  prepareRetirementWorkerVersionMutation,
  prepareUninstallWorkerDeploymentMutation,
  type UninstallCleanupVariables,
} from '../src/cloudflare-uninstall-worker-lifecycle';
import {
  deriveCustomerGatewayExpectedProjection,
  deriveCustomerGatewayInstallationReceiptExpectation,
  prepareCustomerBootstrapClaim,
} from '../src/customer-bootstrap-request';
import {
  prepareCustomerUninstallRequest,
  type CustomerUninstallMutationPlan,
  type CustomerUninstallRecoveryReason,
  type RemovedInstallationReceipt,
} from '../src/customer-uninstall-request';
import { sha256, sha256Hex } from '../src/crypto';
import { OAUTH_COOKIE, PUBLIC_ORIGIN, REQUIRED_OAUTH_SCOPES, SESSION_COOKIE } from '../src/constants';
import { GatewayDeploySession } from '../src/durable/gateway-deploy-session';
import type { GatewayDeploySessionNamespace, GatewayDeploySessionStub } from '../src/env';
import { DeployError } from '../src/errors';
import { createGatewayDeployWorker } from '../src/index';
import type { FetchTransport } from '../src/oauth';
import type { UninstallExecutor } from '../src/uninstall-executor';
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
  type WorkerVersionLocator,
} from '../src/install-journal';
import { buildStaticDeployPlan, parseDeploySelection } from '../src/schema';
import {
  acquireUninstallJournalLease,
  appendUninstallManagementDeleteAttempt,
  appendUninstallManagementPreflight,
  appendCustomerGatewayRemoveAttempt,
  attachUninstallWorkerVersionRecovery,
  appendUninstallJournalApproval,
  armUninstallJournalAction,
  armCustomerGatewayRemoveRequest,
  armCustomerGatewayWorkersDev,
  computeUninstallJournalBindingHash,
  createUninstallJournal,
  discardPreflightOnlyUninstallJournal,
  expireUninstallJournalLease,
  isCompleteUninstallJournal,
  refreshUninstallJournalPreflight,
  recordCustomerGatewayWorkersDevNotApplied,
  recordUninstallManagementDeleteRecovery,
  releaseUninstallJournalLease,
  replacePreparedCustomerGatewayRemoveAttempt,
  replacePreparedCustomerGatewayWorkersDevDisable,
  replacePreparedUninstallJournalAction,
  requireUninstallJournal,
  prepareUninstallJournalAction,
  prepareUninstallFinalConvergenceRecordAndLocator,
  prepareCustomerGatewayWorkersDevDisable,
  submitCustomerGatewayWorkersDev,
  submitCustomerGatewayRemoveRequest,
  submitUninstallJournalAction,
  verifyCustomerGatewayWorkersDev,
  verifyCustomerGatewayRemoveRequest,
  verifyUninstallJournalAction,
  type CustomerGatewayRemoveActionRecord,
  type CustomerGatewayRemoveRequestAttempt,
  type ManagementDeleteActionRecord,
  type UninstallJournalAction,
  type UninstallJournal,
  type UninstallWorkersDevMutation,
} from '../src/uninstall-journal';
import {
  buildStaticUninstallPlan,
  parseStaticUninstallPlan,
  type StaticUninstallPlan,
} from '../src/uninstall-plan';
import type { VerifiedGatewayWorkerReleaseSet } from '../src/release-direct-upload-adapter';
import { APPROVED_CLOUDFLARE_RELEASE_CONTRACT } from '../src/release-manifest';
import { canonicalJson } from '../src/canonical-json';
import { boundaryObjectSchema, type BoundaryObject } from '../src/boundary';
import {
  FakeState,
  env,
  internalRequest,
  manifest,
  NOW,
  requiredFixture,
  releaseProvider,
  selectionInput,
  verifiedRelease,
} from './fixtures';
import { readyInstallationReceiptFixture } from './provider-neutral-installation-receipt-fixture';

const ACCOUNT_ID = 'a'.repeat(32);
const ZONE_ID = 'b'.repeat(32);
const WORKER_ID = 'c'.repeat(32);
const NAMESPACE_ID = 'd'.repeat(32);
const DOMAIN_ID = 'e'.repeat(32);
const APPLICATION_ID = 'f174e90a-fafe-4643-bbbc-4a0ed4fc8415';
const POLICY_ID = 'd174e90a-fafe-4643-bbbc-4a0ed4fc8415';
const PROVISION_VERSION_ID = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
const PROVISION_DEPLOYMENT_ID = 'cccccccc-cccc-4ccc-8ccc-cccccccccccc';
const BOOTSTRAP_VERSION_ID = '11111111-1111-4111-8111-111111111111';
const BOOTSTRAP_DEPLOYMENT_ID = '22222222-2222-4222-8222-222222222222';
const CLEAN_VERSION_ID = '33333333-3333-4333-8333-333333333333';
const CLEAN_DEPLOYMENT_ID = '44444444-4444-4444-8444-444444444444';
const AUD = 'access-audience-token-1234567890';
const IDP_ONE = '4'.repeat(32);
const INSTALL_ATTEMPT_ID = `att_${'i'.repeat(32)}`;
const UNINSTALL_ATTEMPT_ID = `att_${'u'.repeat(32)}`;
const RECOVERY_ATTEMPT_ID = `att_${'r'.repeat(32)}`;
const RECOVERY_ATTEMPT_TWO = `att_${'s'.repeat(32)}`;
const RECOVERY_ATTEMPT_THREE = `att_${'t'.repeat(32)}`;
const UNINSTALL_CYCLE_ID = `uninstall-${'6'.repeat(24)}`;
const CERTIFICATE_ID = '9fdf92c8-64c2-4a3d-b1af-e15304961145';
const NO_COMPATIBILITY_FLAGS: readonly [] = Object.freeze([]);

async function parseResponseObject(response: Response): Promise<BoundaryObject> {
  return v.parse(boundaryObjectSchema, await response.json());
}

function requireResponseObject(parent: BoundaryObject, property: string): BoundaryObject {
  return v.parse(boundaryObjectSchema, parent[property]);
}

function requireResponseString(parent: BoundaryObject, property: string): string {
  return v.parse(v.string(), parent[property]);
}

class ForwardingDurableObjectId implements DurableObjectId {
  constructor(readonly name: string) {}

  toString(): string {
    return this.name;
  }

  equals(other: DurableObjectId): boolean {
    return other.toString() === this.name;
  }
}

class ForwardingDeploySessionNamespace implements GatewayDeploySessionNamespace {
  constructor(
    private readonly sessionId: string,
    private readonly stub: GatewayDeploySessionStub,
  ) {}

  idFromName(name: string): DurableObjectId {
    return new ForwardingDurableObjectId(name);
  }

  get(id: DurableObjectId): GatewayDeploySessionStub {
    if (id.name !== this.sessionId) throw new Error('wrong session');
    return this.stub;
  }
}

const selection = parseDeploySelection(selectionInput);
const installPlan = await buildStaticDeployPlan(selection, manifest, NOW + 600_000);
const workerResource = installPlan.managementResources.find((resource) => resource.kind === 'management_worker');
if (!workerResource) throw new TypeError('worker fixture');
const workerName: string = workerResource.name;
const target: AuthorizedTarget = Object.freeze({
  actor: Object.freeze({ id: 'actor_12345678', email: selection.basics.adminEmail }),
  account: Object.freeze({ id: ACCOUNT_ID, name: 'Example account' }),
  zone: Object.freeze({ id: ZONE_ID, name: selection.basics.zoneName, status: 'active' }),
});

async function hash<Value>(value: Value): Promise<string> {
  return sha256Hex(canonicalJson(value));
}

const PLAIN_BINDING_NAMES = Object.freeze([
  'ADMIN_EMAILS', 'ANKKA_INSTALL_ID', 'ANKKA_GATEWAY_RELEASE', 'ANKKA_GATEWAY_RELEASE_SHA256',
  'ANKKA_MANAGEMENT_HOSTNAME', 'ANKKA_UPDATE_CHANNEL', 'ANKKA_UPDATE_KEY_ID', 'ANKKA_UPDATE_PUBLIC_KEY',
  'ANKKA_WORKERS_SUBDOMAIN', 'ANKKA_WORKER_NAME', 'CF_ACCESS_AUD',
  'CF_ACCESS_ISSUER', 'CLOUDFLARE_ACCOUNT_ID', 'CLOUDFLARE_ZONE_ID', 'CLOUDFLARE_ZONE_NAME',
  'ZERO_TRUST_READY',
] as const);
const PLAIN_BINDINGS: WorkerVersionCreateRecord['plainTextBindingHashes'] = Object.freeze(
  PLAIN_BINDING_NAMES.map((name, index) => Object.freeze({
    name,
    valueSha256: String(index % 10).repeat(64),
  })),
);

async function installRecord(action: InstallActionName, phase?: 'provision' | 'bootstrap' | 'clean'): Promise<InstallActionRecord> {
  if (action === 'worker_create') {
    const requestHash = await hash({
      logpush: false, name: workerName, observability: { enabled: false },
      subdomain: { enabled: false, previews_enabled: false }, tags: ['ankka-mcp-gateway'], tail_consumers: [],
    });
    return { schemaVersion: 1, kind: 'worker_create', accountId: ACCOUNT_ID, workerName, requestHash,
      correlationTag: `ankka-worker-sha256:${requestHash}` };
  }
  if (action === 'management_access_application_create') {
    const allowedIdentityProviderIds = Object.freeze([IDP_ONE]);
    const intent = prepareManagementAccessApplicationIntent({
      accountId: ACCOUNT_ID, zoneId: ZONE_ID, plan: installPlan, allowedIdentityProviderIds,
    });
    return { schemaVersion: 1, kind: action, accountId: ACCOUNT_ID, planId: installPlan.planId,
      planHash: installPlan.planHash, ownershipMarker: managementOwnershipMarker(installPlan),
      allowedIdentityProviderIds, intentHash: await hash(intent) };
  }
  if (action === 'management_admin_policy_create') {
    const intent = prepareManagementAdminPolicyIntent({ accountId: ACCOUNT_ID, zoneId: ZONE_ID, applicationId: APPLICATION_ID,
      plan: installPlan });
    return { schemaVersion: 1, kind: action, accountId: ACCOUNT_ID, planId: installPlan.planId,
      planHash: installPlan.planHash, ownershipMarker: managementOwnershipMarker(installPlan),
      applicationId: APPLICATION_ID, intentHash: await hash(intent) };
  }
  if (action === 'management_custom_domain_attach') {
    const intent = prepareManagementCustomDomainIntent({ accountId: ACCOUNT_ID, zoneId: ZONE_ID, plan: installPlan });
    return { schemaVersion: 1, kind: action, accountId: ACCOUNT_ID, zoneId: ZONE_ID,
      planId: installPlan.planId, planHash: installPlan.planHash,
      ownershipMarker: managementOwnershipMarker(installPlan), intentHash: await hash(intent) };
  }
  if (action === 'bootstrap_subdomain_enable' || action === 'bootstrap_subdomain_disable') {
    const enabled = action === 'bootstrap_subdomain_enable';
    return { schemaVersion: 1, kind: 'bootstrap_subdomain', accountId: ACCOUNT_ID, workerName, enabled,
      requestHash: await hash({ enabled, previews_enabled: false }) };
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
    const assets = [{ path: '/index.html', uploadHash: 'f'.repeat(32),
      contentType: 'text/html; charset=utf-8', byteLength: 1 }];
    const modules = [{ name: 'index.js', contentType: 'application/javascript+module',
      contentSha256: 'e'.repeat(64), byteLength: 1 }];
    const requestHash = await hash({
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
    const record: WorkerVersionCreateRecord = {
      schemaVersion: 1, kind: 'worker_version_create', phase, accountId: ACCOUNT_ID, workerName,
      workerId: WORKER_ID, requestHash, correlationTag: `ankka-version-${phase}-sha256:${requestHash}`,
      releaseContract, assets, plainTextBindingHashes: PLAIN_BINDINGS, modules,
    };
    return record;
  }
  if (action.endsWith('_worker_deployment_create') && phase) {
    const versionId = phase === 'provision' ? PROVISION_VERSION_ID : phase === 'bootstrap' ? BOOTSTRAP_VERSION_ID : CLEAN_VERSION_ID;
    const requestHash = await hash({ strategy: 'percentage', versions: [{ percentage: 100, version_id: versionId }] });
    return { schemaVersion: 1, kind: 'worker_deployment_create', phase, accountId: ACCOUNT_ID, workerName,
      workerId: WORKER_ID, versionId, requestHash,
      correlationTag: `ankka-deploy-${phase}-sha256:${requestHash}` };
  }
  throw new TypeError(`record:${action}`);
}

async function installLocator(action: InstallActionName, phase?: 'provision' | 'bootstrap' | 'clean'): Promise<InstallActionLocator> {
  if (action === 'worker_create') return { kind: 'worker', accountId: ACCOUNT_ID, workerName, workerId: WORKER_ID };
  if (action === 'management_access_application_create') return { applicationId: APPLICATION_ID, aud: AUD };
  if (action === 'management_admin_policy_create') return { policyId: POLICY_ID };
  if (action === 'management_custom_domain_attach') return { domainId: DOMAIN_ID };
  if (action === 'bootstrap_subdomain_enable' || action === 'bootstrap_subdomain_disable') {
    return { enabled: action === 'bootstrap_subdomain_enable', previewsEnabled: false };
  }
  if (action.endsWith('_worker_version_create') && phase) {
    const record = await installRecord(action, phase);
    if (record.kind !== 'worker_version_create') throw new TypeError('version record fixture');
    const locator: WorkerVersionLocator = {
      kind: 'version', phase, accountId: ACCOUNT_ID, workerName, workerId: WORKER_ID,
      versionId: phase === 'provision' ? PROVISION_VERSION_ID : phase === 'bootstrap' ? BOOTSTRAP_VERSION_ID : CLEAN_VERSION_ID,
      requestHash: record.requestHash, correlationTag: record.correlationTag,
    };
    // The provision version precedes the deployment that creates the namespace.
    return phase === 'provision' ? locator : { ...locator, namespaceId: NAMESPACE_ID };
  }
  if (action.endsWith('_worker_deployment_create') && phase) {
    const record = await installRecord(action, phase);
    if (record.kind !== 'worker_deployment_create') throw new TypeError('deployment record fixture');
    return { kind: 'deployment', phase, accountId: ACCOUNT_ID, workerName, workerId: WORKER_ID,
      versionId: record.versionId,
      deploymentId: phase === 'provision' ? PROVISION_DEPLOYMENT_ID : phase === 'bootstrap' ? BOOTSTRAP_DEPLOYMENT_ID : CLEAN_DEPLOYMENT_ID,
      requestHash: record.requestHash, correlationTag: record.correlationTag };
  }
  throw new TypeError(`locator:${action}`);
}

async function advanceInstall(
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

async function completeInstallJournal(): Promise<InstallJournal> {
  const claim = await prepareCustomerBootstrapClaim({ selection, target, release: verifiedRelease,
    plan: installPlan, nowMs: NOW,
    randomBytes: (length) => Uint8Array.from({ length }, (_value, index) => index + 1) });
  const releasePin = Object.freeze({ verification: 'ed25519' as const, keyId: verifiedRelease.keyId,
    release: manifest.release, artifactSha256: manifest.artifact.treeSha256 });
  const bindingHash = await computeInstallJournalBindingHash({ selection, plan: installPlan, releasePin, target,
    installationId: claim.expected.installationId });
  const projection = await deriveCustomerGatewayExpectedProjection({ selection, target, plan: installPlan,
    release: { id: manifest.release, artifactSha256: manifest.artifact.treeSha256 } });
  const preflight = { schemaVersion: 1 as const, kind: 'customer_gateway_fresh_preflight' as const,
    accountId: ACCOUNT_ID, zoneId: ZONE_ID, planId: installPlan.planId, planHash: installPlan.planHash,
    installationId: claim.expected.installationId, configurationHash: projection.expected.configurationHash,
    desiredHash: projection.expected.desiredHash, releaseId: manifest.release,
    releaseArtifactSha256: manifest.artifact.treeSha256, zeroCandidateKinds: projection.resourceKinds,
    checkedAt: NOW, expiresAt: NOW + 30_000 };
  let journal = await createInstallJournal({ schemaVersion: 1, now: NOW, recoverUntil: NOW + 86_400_000,
    selection, plan: installPlan, releasePin, target, installationId: claim.expected.installationId, bindingHash,
    gatewayFreshPreflight: { ...preflight, attestationHash: `sha256:${await hash(preflight)}` } },
  selection, installPlan, NOW + 500_000, { attemptId: INSTALL_ATTEMPT_ID, approvedAt: NOW });
  const clock = { now: NOW };
  journal = acquireInstallJournalLease(journal, { expectedRevision: journal.revision,
    attemptId: INSTALL_ATTEMPT_ID, now: ++clock.now, leaseExpiresAt: clock.now + 300_000 });
  for (const [action, phase] of [
    ['worker_create'], ['management_access_application_create'], ['management_admin_policy_create'],
    ['provision_worker_version_create', 'provision'], ['provision_worker_deployment_create', 'provision'],
    ['bootstrap_worker_version_create', 'bootstrap'], ['bootstrap_worker_deployment_create', 'bootstrap'],
    ['bootstrap_subdomain_enable'],
  ] as const) {
    journal = await advanceInstall(journal, action, await installRecord(action, phase),
      await installLocator(action, phase), clock);
  }
  const enable = journal.actions.find((entry) => entry.name === 'bootstrap_subdomain_enable');
  if (!enable || enable.record.kind !== 'bootstrap_subdomain' || !enable.locator || !('enabled' in enable.locator)) {
    throw new TypeError('enable fixture');
  }
  const bootstrapClaim = await prepareCustomerBootstrapClaim({ selection, target, release: verifiedRelease,
    plan: installPlan, nowMs: ++clock.now,
    randomBytes: (length) => Uint8Array.from({ length }, (_value, index) => index + 11) });
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
      claimHash: `sha256:${await hash(compactClaim)}`, enable: { schemaVersion: 1,
        approvalAttemptId: INSTALL_ATTEMPT_ID, enabled: true, requestHash: enable.record.requestHash,
        phase: 'verified', locator: enable.locator, preparedAt: enable.preparedAt, sendArmedAt: enable.sendArmedAt,
        submittedAt: enable.submittedAt, verifiedAt: enable.verifiedAt }, disable: null, phase: 'prepared', locator: null,
      preparedAt: clock.now, sendArmedAt: null, submittedAt: null, verifiedAt: null }] };
  journal = await prepareInstallJournalAction(journal, { expectedRevision: journal.revision,
    attemptId: INSTALL_ATTEMPT_ID, now: clock.now, action: 'customer_bootstrap_submit', record: bootstrapRecord });
  journal = armInstallJournalAction(journal, { expectedRevision: journal.revision,
    attemptId: INSTALL_ATTEMPT_ID, now: ++clock.now, action: 'customer_bootstrap_submit' });
  const receiptExpectation = await deriveCustomerGatewayInstallationReceiptExpectation({ selection, target,
    plan: installPlan, release: { id: manifest.release, artifactSha256: manifest.artifact.treeSha256 } });
  const receipt = await readyInstallationReceiptFixture(receiptExpectation, 14);
  const bootstrapLocator: InstallActionLocator = { schemaVersion: 1, status: 'ready',
    installationId: journal.installationId, approvedPlanId: `plan-${'7'.repeat(24)}`,
    configurationHash: bootstrapClaim.expected.configurationHash, desiredHash: bootstrapClaim.expected.desiredHash,
    settingsRevision: 1, release: { id: manifest.release, artifactSha256: `sha256:${manifest.artifact.treeSha256}` },
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
    journal = await advanceInstall(journal, action, await installRecord(action, phase),
      await installLocator(action, phase), clock);
  }
  const final = await prepareFinalConvergenceRecordAndLocator(journal);
  return advanceInstall(journal, 'final_convergence', final.record, final.locator, clock);
}

async function preflight(
  installJournal: InstallJournal,
  uninstallPlan: StaticUninstallPlan,
  attemptId: string,
  checkedAt: number,
): Promise<HostedUninstallManagementPreflightResult> {
  const final = installJournal.actions[installJournal.actions.length - 1]?.locator;
  if (!final || !('status' in final) || final.status !== 'converged') throw new TypeError('final fixture');
  const semantic = {
    schemaVersion: 1 as const,
    status: 'ready' as const,
    uninstallPlanId: uninstallPlan.planId,
    uninstallPlanHash: uninstallPlan.planHash,
    uninstallAuthorityHash: uninstallPlan.authorityHash,
    installBindingHash: installJournal.bindingHash,
    installConvergenceHash: final.convergenceHash,
    attemptId,
    ownershipMarker: managementOwnershipMarker(installPlan),
    accountId: ACCOUNT_ID,
    zoneId: ZONE_ID,
    workerId: WORKER_ID,
    namespaceId: NAMESPACE_ID,
    domainId: DOMAIN_ID,
    domainCertificateId: CERTIFICATE_ID,
    applicationId: APPLICATION_ID,
    policyId: POLICY_ID,
    checkedAt,
    expiresAt: Math.min(checkedAt + 60_000, uninstallPlan.expiresAt),
  };
  return { ...semantic, attestationSha256: await hash(semantic) };
}

function uninstallManagementContext(journal: UninstallJournal): HostedUninstallManagementContext {
  const activeApproval = requiredFixture(journal.approvalHistory.at(-1), 'active uninstall approval');
  return Object.freeze({
    schemaVersion: 1,
    installJournal: journal.installJournal,
    approvalHistory: Object.freeze(journal.approvalHistory.map((approval) => Object.freeze({
      attemptId: approval.attemptId,
      uninstallPlan: approval.plan,
      authorizedTarget: approval.authorizedTarget,
    }))),
    activeAttemptId: activeApproval.attemptId,
  });
}

function verifiedManagementAbsence(
  journal: UninstallJournal,
  action: HostedUninstallManagementDeleteAction,
) {
  const journalAction = journal.actions.find((entry) => entry.name === action);
  if (!journalAction || journalAction.phase !== 'verified' || !journalAction.locator ||
    !('status' in journalAction.locator) || journalAction.locator.status !== 'absent') {
    throw new TypeError(`missing ${action}`);
  }
  return journalAction.locator;
}

function customerRemoveAction(journal: UninstallJournal): UninstallJournalAction {
  const action = journal.actions.find((entry) => entry.name === 'customer_gateway_remove');
  if (!action || !('kind' in action.record) || action.record.kind !== 'customer_gateway_remove') {
    throw new TypeError('customer removal journal fixture missing');
  }
  return action;
}

function customerRemoveRecord(journal: UninstallJournal): CustomerGatewayRemoveActionRecord {
  const record = customerRemoveAction(journal).record;
  if (!('kind' in record) || record.kind !== 'customer_gateway_remove') {
    throw new TypeError('customer removal journal fixture missing');
  }
  return record;
}

function firstCustomerRemoveAttempt(journal: UninstallJournal): CustomerGatewayRemoveRequestAttempt {
  const attempt = customerRemoveRecord(journal).attempts[0];
  if (!attempt) throw new TypeError('customer removal attempt fixture missing');
  return attempt;
}

function managementDeleteRecord(
  journal: UninstallJournal,
  actionName: HostedUninstallManagementDeleteAction,
): ManagementDeleteActionRecord {
  const action = journal.actions.find((entry) => entry.name === actionName);
  if (!action || !('kind' in action.record) || action.record.kind !== 'uninstall_management_delete') {
    throw new TypeError(`management delete journal fixture missing: ${actionName}`);
  }
  return action.record;
}

function managementPrerequisites(
  journal: UninstallJournal,
  action: HostedUninstallManagementDeleteAction,
): HostedUninstallManagementDeletePrerequisites {
  if (action === 'management_custom_domain_delete') {
    const current = journal.managementPreflightHistory[journal.managementPreflightHistory.length - 1];
    if (!current) throw new TypeError('missing management preflight');
    return Object.freeze({ schemaVersion: 1, action, preflight: current });
  }
  const domainAbsence = verifiedManagementAbsence(journal, 'management_custom_domain_delete');
  if (action === 'management_admin_policy_delete') {
    return Object.freeze({ schemaVersion: 1, action, domainAbsence });
  }
  return Object.freeze({
    schemaVersion: 1,
    action,
    domainAbsence,
    policyAbsence: verifiedManagementAbsence(journal, 'management_admin_policy_delete'),
  });
}

async function managementAbsence(
  journal: UninstallJournal,
  intent: HostedUninstallManagementDeleteIntent,
) {
  const approval = requiredFixture(journal.approvalHistory.at(-1), 'active uninstall approval');
  const final = requiredFixture(journal.installJournal.actions.at(-1), 'install final action').locator;
  if (!final || !('status' in final) || final.status !== 'converged') throw new TypeError('install final');
  const semantic = {
    schemaVersion: 1 as const,
    status: 'absent' as const,
    action: intent.kind,
    uninstallPlanId: approval.plan.planId,
    uninstallPlanHash: approval.plan.planHash,
    uninstallAuthorityHash: approval.plan.authorityHash,
    installBindingHash: journal.installJournal.bindingHash,
    installConvergenceHash: final.convergenceHash,
    attemptId: approval.attemptId,
    ownershipMarker: managementOwnershipMarker(installPlan),
    accountId: ACCOUNT_ID,
    locator: intent.locator,
    proof: 'id_get_404_and_complete_list_absence' as const,
  };
  return Object.freeze({ ...semantic, evidenceSha256: await hash(semantic) });
}

async function managementStillPresent(
  journal: UninstallJournal,
  intent: HostedUninstallManagementDeleteIntent,
  arm: HostedUninstallManagementDeleteArm,
) {
  const approval = requiredFixture(journal.approvalHistory.at(-1), 'active uninstall approval');
  const final = requiredFixture(journal.installJournal.actions.at(-1), 'install final action').locator;
  if (!final || !('status' in final) || final.status !== 'converged') throw new TypeError('install final');
  const providerOwnership = intent.kind === 'management_custom_domain_delete'
    ? Object.freeze({ kind: 'management_custom_domain' as const, domainId: DOMAIN_ID,
      certificateId: CERTIFICATE_ID, hostname: selection.basics.managementHostname,
      workerName, zoneId: ZONE_ID, zoneName: selection.basics.zoneName })
    : intent.kind === 'management_admin_policy_delete'
      ? Object.freeze({ kind: 'management_admin_policy' as const, applicationId: APPLICATION_ID,
        policyId: POLICY_ID, name: managementAdminPolicyName(installPlan),
        adminEmails: Object.freeze([...installPlan.managementAdminEmails]) })
      : Object.freeze({ kind: 'management_access_application' as const, applicationId: APPLICATION_ID,
        aud: AUD, name: managementAccessApplicationName(installPlan),
        hostname: selection.basics.managementHostname,
        allowedIdentityProviderIds: Object.freeze([IDP_ONE]) });
  const providerOwnershipSha256 = await hash(providerOwnership);
  const semantic = {
    schemaVersion: 1 as const,
    status: 'still_present' as const,
    outcome: 'not_applied' as const,
    action: intent.kind,
    uninstallPlanId: approval.plan.planId,
    uninstallPlanHash: approval.plan.planHash,
    uninstallAuthorityHash: approval.plan.authorityHash,
    installBindingHash: journal.installJournal.bindingHash,
    installConvergenceHash: final.convergenceHash,
    attemptId: approval.attemptId,
    deleteAttemptId: intent.attemptId,
    ownershipMarker: managementOwnershipMarker(installPlan),
    accountId: ACCOUNT_ID,
    zoneId: ZONE_ID,
    intentSha256: arm.intentSha256,
    locator: intent.locator,
    providerOwnership,
    providerOwnershipSha256,
    proof: 'id_get_200_and_complete_list_exact_match' as const,
  };
  return Object.freeze({ ...semantic, evidenceSha256: await hash(semantic) });
}

function managementSubmission(
  intent: HostedUninstallManagementDeleteIntent,
  arm: HostedUninstallManagementDeleteArm,
) {
  return Object.freeze({
    schemaVersion: 1 as const,
    status: 'submitted' as const,
    action: intent.kind,
    attemptId: intent.attemptId,
    intentSha256: arm.intentSha256,
    locator: intent.locator,
  });
}

async function beginManagementDelete(
  journal: UninstallJournal,
  action: HostedUninstallManagementDeleteAction,
  clock: { now: number },
  submit = true,
): Promise<{
  readonly journal: UninstallJournal;
  readonly intent: HostedUninstallManagementDeleteIntent;
  readonly arm: HostedUninstallManagementDeleteArm;
  readonly prerequisites: HostedUninstallManagementDeletePrerequisites;
}> {
  const attemptId = requiredFixture(journal.approvalHistory.at(-1), 'active uninstall approval').attemptId;
  const prerequisites = managementPrerequisites(journal, action);
  const intent = await prepareHostedUninstallManagementDeleteIntent(
    uninstallManagementContext(journal),
    action,
    prerequisites,
  );
  journal = await prepareUninstallJournalAction(journal, {
    expectedRevision: journal.revision,
    attemptId,
    now: ++clock.now,
    action,
    record: { schemaVersion: 1, kind: 'uninstall_management_delete', prerequisites, intent },
  });
  const arm = await prepareHostedUninstallManagementDeleteArm(
    uninstallManagementContext(journal), intent, prerequisites, ++clock.now,
  );
  journal = await armUninstallJournalAction(journal, {
    expectedRevision: journal.revision,
    attemptId,
    now: clock.now,
    action,
    value: arm,
  });
  if (submit) {
    journal = await submitUninstallJournalAction(journal, {
      expectedRevision: journal.revision,
      attemptId,
      now: ++clock.now,
      action,
      value: managementSubmission(intent, arm),
    });
  }
  return { journal, intent, arm, prerequisites };
}

interface UninstallFixture {
  readonly installJournal: InstallJournal;
  readonly uninstallPlan: StaticUninstallPlan;
  readonly journal: UninstallJournal;
  readonly now: number;
}

async function initializedUninstall(): Promise<UninstallFixture> {
  const installJournal = await completeInstallJournal();
  const createdAt = installJournal.updatedAt + 1;
  const uninstallPlan = await buildStaticUninstallPlan(installJournal, createdAt, createdAt + 300_000);
  const now = createdAt + 1;
  const bindingHash = await computeUninstallJournalBindingHash({
    installJournal, uninstallPlan, uninstallCycleId: UNINSTALL_CYCLE_ID,
  });
  const journal = await createUninstallJournal({
    schemaVersion: 1,
    now,
    recoverUntil: installJournal.recoverUntil,
    installJournal,
    uninstallPlan,
    uninstallCycleId: UNINSTALL_CYCLE_ID,
    bindingHash,
    freshPreflight: await preflight(installJournal, uninstallPlan, UNINSTALL_ATTEMPT_ID, now),
  }, {
    attemptId: UNINSTALL_ATTEMPT_ID,
    approvedAt: createdAt,
    authorizedTarget: target,
  });
  return { installJournal, uninstallPlan, journal, now };
}

const deepFrozenContainerSchema = v.union([v.array(v.unknown()), v.object({})]);

function expectDeepFrozen<Value>(value: Value, seen = new Set<object>()): void {
  if (!v.is(deepFrozenContainerSchema, value) || seen.has(value)) return;
  seen.add(value);
  expect(Object.isFrozen(value)).toBe(true);
  for (const child of Object.values(value)) expectDeepFrozen(child, seen);
}

async function bytesHash(bytes: Uint8Array): Promise<string> {
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', new Uint8Array(bytes)));
  return [...digest].map((byte) => byte.toString(16).padStart(2, '0')).join('');
}

async function uninstallReleaseSet(): Promise<VerifiedGatewayWorkerReleaseSet> {
  const primaryBytes = new TextEncoder().encode('export default {fetch(){return new Response("ok")}};');
  const bootstrapBytes = new TextEncoder().encode('export class AdminState{}; export default {fetch(){}};');
  const cleanupBytes = new TextEncoder().encode('export class AdminState{}; export default {fetch(){}};');
  const retirementBytes = new TextEncoder().encode('export default {fetch(){return new Response(null,{status:410})}};');
  return Object.freeze({
    bootstrap: Object.freeze({
      verification: 'ed25519', release: manifest.release, artifactSha256: manifest.artifact.treeSha256,
      componentSha256: manifest.components.workerBootstrap.treeSha256,
      worker: Object.freeze({
        mainModule: 'index.js', compatibilityDate: '2026-08-08', compatibilityFlags: NO_COMPATIBILITY_FLAGS,
        modules: Object.freeze([Object.freeze({ name: 'index.js', contentType: 'application/javascript+module',
          sha256: await bytesHash(bootstrapBytes), bytes: bootstrapBytes })]),
        assets: Object.freeze({ binding: 'ASSETS', notFoundHandling: 'single-page-application',
          runWorkerFirst: Object.freeze(['/__ankka/*', '/api/*'] as const),
          files: Object.freeze([Object.freeze({ path: '/index.html', contentType: 'text/html; charset=utf-8',
            sha256: await bytesHash(new TextEncoder().encode('<p/>')), bytes: new TextEncoder().encode('<p/>') })]) }),
        durableObject: Object.freeze({ binding: 'ADMIN_STATE', className: 'AdminState', storage: 'sqlite' }),
      }),
    }),
    primary: Object.freeze({
      verification: 'ed25519', release: manifest.release, artifactSha256: manifest.artifact.treeSha256,
      worker: Object.freeze({
        mainModule: 'index.js', compatibilityDate: '2026-08-08', compatibilityFlags: NO_COMPATIBILITY_FLAGS,
        modules: Object.freeze([Object.freeze({ name: 'index.js', contentType: 'application/javascript+module',
          sha256: await bytesHash(primaryBytes), bytes: primaryBytes })]),
        assets: Object.freeze({ binding: 'ASSETS', notFoundHandling: 'single-page-application',
          runWorkerFirst: Object.freeze(['/__ankka/*', '/api/*'] as const),
          files: Object.freeze([Object.freeze({ path: '/index.html', contentType: 'text/html; charset=utf-8',
            sha256: await bytesHash(new TextEncoder().encode('<p/>')), bytes: new TextEncoder().encode('<p/>') })]) }),
        durableObject: Object.freeze({ binding: 'ADMIN_STATE', className: 'AdminState', storage: 'sqlite' }),
      }),
    }),
    cleanup: Object.freeze({
      verification: 'ed25519', release: manifest.release, artifactSha256: manifest.artifact.treeSha256,
      componentSha256: manifest.components.workerCleanup.treeSha256, variant: 'cleanup',
      worker: Object.freeze({ contract: APPROVED_CLOUDFLARE_RELEASE_CONTRACT.workerVariants.cleanup,
        modules: Object.freeze([Object.freeze({ name: 'index.js', contentType: 'application/javascript+module',
          sha256: await bytesHash(cleanupBytes), bytes: cleanupBytes })]) }),
    }),
    retirement: Object.freeze({
      verification: 'ed25519', release: manifest.release, artifactSha256: manifest.artifact.treeSha256,
      componentSha256: manifest.components.workerRetirement.treeSha256, variant: 'retirement',
      worker: Object.freeze({ contract: APPROVED_CLOUDFLARE_RELEASE_CONTRACT.workerVariants.retirement,
        modules: Object.freeze([Object.freeze({ name: 'index.js', contentType: 'application/javascript+module',
          sha256: await bytesHash(retirementBytes), bytes: retirementBytes })]) }),
    }),
  });
}

function cleanupVariables(): UninstallCleanupVariables {
  return Object.freeze({
    ANKKA_GATEWAY_RELEASE: manifest.release,
    ANKKA_GATEWAY_RELEASE_SHA256: `sha256:${manifest.artifact.treeSha256}`,
    CLOUDFLARE_ACCOUNT_ID: ACCOUNT_ID,
    CLOUDFLARE_ZONE_ID: ZONE_ID,
    CLOUDFLARE_ZONE_NAME: target.zone.name,
    ZERO_TRUST_READY: 'true',
  });
}

function namespacePresence() {
  return Object.freeze({
    kind: 'admin_state_namespace_presence' as const,
    accountId: ACCOUNT_ID,
    workerName,
    workerId: WORKER_ID,
    uninstallCycleId: UNINSTALL_CYCLE_ID,
    namespaceId: NAMESPACE_ID,
    namespaceName: 'ankka-admin-state',
    className: 'AdminState' as const,
    storage: 'sqlite' as const,
    accountNamespaceCount: 1,
    snapshotSha256: '1'.repeat(64),
  });
}

async function removedReceipt(
  mutation: CustomerUninstallMutationPlan,
): Promise<RemovedInstallationReceipt> {
  const root = mutation.ephemeral.claim.expected.readyReceipt;
  const unsigned = {
    schemaVersion: 1 as const,
    manager: 'ankka-mcp-gateway' as const,
    installationId: root.installationId,
    state: 'removed' as const,
    revision: root.revision + (2 * root.resources.length) + 1,
    release: root.release,
    target: structuredClone(root.target),
    accessPolicy: structuredClone(root.accessPolicy),
    desiredHash: root.desiredHash,
    resources: [] as const,
    pending: null,
  };
  return { ...unsigned, checksum: `sha256:${await hash(unsigned)}` };
}

async function removedLocator(mutation: CustomerUninstallMutationPlan) {
  const semantic = mutation.semantic;
  const evidence = await removedReceipt(mutation);
  return Object.freeze({
    schemaVersion: 1 as const,
    status: 'removed' as const,
    requestId: semantic.requestId,
    accountId: semantic.accountId,
    zoneId: semantic.zoneId,
    zoneName: semantic.zoneName,
    accountWorkersSubdomain: semantic.accountWorkersSubdomain,
    workerName: semantic.workerName,
    installationId: semantic.installationId,
    configurationHash: semantic.configurationHash,
    desiredHash: semantic.desiredHash,
    release: semantic.release,
    installBindingHash: semantic.installBindingHash,
    installConvergenceHash: semantic.installConvergenceHash,
    adminStateNamespaceId: semantic.adminStateNamespaceId,
    uninstallPlanId: semantic.uninstallPlanId,
    uninstallPlanHash: semantic.uninstallPlanHash,
    authorityHash: semantic.authorityHash,
    approvalAttemptId: semantic.approvalAttemptId,
    uninstallId: UNINSTALL_CYCLE_ID,
    receipt: { revision: evidence.revision, resourceCount: 0 as const, evidence },
    uninstallInvoked: true,
    resumed: false,
  });
}

function recoveryLocator(
  mutation: CustomerUninstallMutationPlan,
  reason: CustomerUninstallRecoveryReason,
  freshGrantRequired: boolean,
) {
  const semantic = mutation.semantic;
  return Object.freeze({
    schemaVersion: 1 as const,
    status: 'recovery_required' as const,
    requestId: semantic.requestId,
    accountId: semantic.accountId,
    zoneId: semantic.zoneId,
    zoneName: semantic.zoneName,
    accountWorkersSubdomain: semantic.accountWorkersSubdomain,
    workerName: semantic.workerName,
    installationId: semantic.installationId,
    configurationHash: semantic.configurationHash,
    desiredHash: semantic.desiredHash,
    release: semantic.release,
    installBindingHash: semantic.installBindingHash,
    installConvergenceHash: semantic.installConvergenceHash,
    adminStateNamespaceId: semantic.adminStateNamespaceId,
    uninstallPlanId: semantic.uninstallPlanId,
    uninstallPlanHash: semantic.uninstallPlanHash,
    authorityHash: semantic.authorityHash,
    approvalAttemptId: semantic.approvalAttemptId,
    reason,
    freshGrantRequired,
  });
}

async function cleanupReadyUninstall(): Promise<UninstallFixture & { readonly journal: UninstallJournal }> {
  const fixture = await initializedUninstall();
  let journal = acquireUninstallJournalLease(fixture.journal, {
    expectedRevision: fixture.journal.revision,
    attemptId: UNINSTALL_ATTEMPT_ID,
    now: fixture.now + 1,
    leaseExpiresAt: fixture.now + 240_000,
  });
  journal = await prepareUninstallJournalAction(journal, {
    expectedRevision: journal.revision,
    attemptId: UNINSTALL_ATTEMPT_ID,
    now: fixture.now + 2,
    action: 'cleanup_worker_version_create',
    record: {
      schemaVersion: 1,
      kind: 'uninstall_worker_version_create',
      stage: 'cleanup',
      accountId: ACCOUNT_ID,
      workerName,
      workerId: WORKER_ID,
      uninstallCycleId: UNINSTALL_CYCLE_ID,
      namespacePresence: namespacePresence(),
      release: manifest.release,
      artifactSha256: manifest.artifact.treeSha256,
      componentSha256: manifest.components.workerCleanup.treeSha256,
      recovery: null,
    },
  });
  const mutation = await prepareCleanupWorkerVersionMutation({
    accountId: ACCOUNT_ID,
    workerName,
    workerId: WORKER_ID,
    namespaceId: NAMESPACE_ID,
    uninstallCycleId: UNINSTALL_CYCLE_ID,
    releaseSet: await uninstallReleaseSet(),
    variables: cleanupVariables(),
    uninstallNonce: 'N'.repeat(43),
  });
  journal = await attachUninstallWorkerVersionRecovery(journal, {
    expectedRevision: journal.revision,
    attemptId: UNINSTALL_ATTEMPT_ID,
    now: fixture.now + 3,
    action: 'cleanup_worker_version_create',
    recovery: mutation.recovery,
  });
  journal = await armUninstallJournalAction(journal, { expectedRevision: journal.revision,
    attemptId: UNINSTALL_ATTEMPT_ID, now: fixture.now + 4, action: 'cleanup_worker_version_create' });
  const version = { kind: 'uninstall_worker_version' as const, stage: 'cleanup' as const,
    accountId: ACCOUNT_ID, workerName, workerId: WORKER_ID, uninstallCycleId: UNINSTALL_CYCLE_ID,
    versionId: '55555555-5555-4555-8555-555555555555', requestHash: mutation.recovery.requestHash,
    correlationTag: mutation.recovery.correlationTag };
  journal = await submitUninstallJournalAction(journal, { expectedRevision: journal.revision,
    attemptId: UNINSTALL_ATTEMPT_ID, now: fixture.now + 5, action: 'cleanup_worker_version_create', value: version });
  journal = await verifyUninstallJournalAction(journal, { expectedRevision: journal.revision,
    attemptId: UNINSTALL_ATTEMPT_ID, now: fixture.now + 6, action: 'cleanup_worker_version_create', value: version });
  const intent = await prepareUninstallWorkerDeploymentMutation({ stage: 'cleanup', accountId: ACCOUNT_ID,
    workerName, workerId: WORKER_ID, uninstallCycleId: UNINSTALL_CYCLE_ID, versionId: version.versionId });
  journal = await prepareUninstallJournalAction(journal, { expectedRevision: journal.revision,
    attemptId: UNINSTALL_ATTEMPT_ID, now: fixture.now + 7, action: 'cleanup_worker_deployment_create',
    record: { schemaVersion: 1, kind: 'uninstall_worker_deployment_create', stage: 'cleanup', intent } });
  journal = await armUninstallJournalAction(journal, { expectedRevision: journal.revision,
    attemptId: UNINSTALL_ATTEMPT_ID, now: fixture.now + 8, action: 'cleanup_worker_deployment_create' });
  const deployment = { kind: 'uninstall_worker_deployment' as const, stage: 'cleanup' as const,
    accountId: ACCOUNT_ID, workerName, workerId: WORKER_ID, uninstallCycleId: UNINSTALL_CYCLE_ID,
    versionId: version.versionId, deploymentId: '66666666-6666-4666-8666-666666666666',
    requestHash: intent.requestHash, correlationTag: intent.correlationTag };
  journal = await submitUninstallJournalAction(journal, { expectedRevision: journal.revision,
    attemptId: UNINSTALL_ATTEMPT_ID, now: fixture.now + 9, action: 'cleanup_worker_deployment_create', value: deployment });
  journal = await verifyUninstallJournalAction(journal, { expectedRevision: journal.revision,
    attemptId: UNINSTALL_ATTEMPT_ID, now: fixture.now + 10, action: 'cleanup_worker_deployment_create', value: deployment });
  return { ...fixture, journal };
}

async function customerRemovedBridgeEnabled(): Promise<UninstallFixture & {
  readonly journal: UninstallJournal;
  readonly clock: { now: number };
}> {
  const fixture = await cleanupReadyUninstall();
  let journal = fixture.journal;
  const clock = { now: fixture.now + 10 };
  const mutation = await prepareCustomerUninstallRequest({
    installJournal: fixture.installJournal,
    uninstallPlan: fixture.uninstallPlan,
    approval: { attemptId: UNINSTALL_ATTEMPT_ID, authorizedTarget: target },
    accountWorkersSubdomain: { accountId: ACCOUNT_ID, subdomain: 'example-account' },
    nowMs: ++clock.now,
    randomBytes: (length) => Uint8Array.from({ length }, (_value, index) => index + 91),
  });
  journal = await appendCustomerGatewayRemoveAttempt(journal, {
    expectedRevision: journal.revision, attemptId: UNINSTALL_ATTEMPT_ID,
    now: clock.now, semantic: mutation.semantic,
  });
  journal = await armCustomerGatewayWorkersDev(journal, {
    expectedRevision: journal.revision, attemptId: UNINSTALL_ATTEMPT_ID,
    now: ++clock.now, enabled: true,
  });
  journal = submitCustomerGatewayWorkersDev(journal, {
    expectedRevision: journal.revision, attemptId: UNINSTALL_ATTEMPT_ID,
    now: ++clock.now, enabled: true, locator: { enabled: true, previewsEnabled: false },
  });
  journal = verifyCustomerGatewayWorkersDev(journal, {
    expectedRevision: journal.revision, attemptId: UNINSTALL_ATTEMPT_ID,
    now: ++clock.now, enabled: true,
  });
  journal = armCustomerGatewayRemoveRequest(journal, {
    expectedRevision: journal.revision, attemptId: UNINSTALL_ATTEMPT_ID, now: ++clock.now,
  });
  journal = await submitCustomerGatewayRemoveRequest(journal, {
    expectedRevision: journal.revision, attemptId: UNINSTALL_ATTEMPT_ID,
    now: ++clock.now, locator: await removedLocator(mutation),
  });
  journal = verifyCustomerGatewayRemoveRequest(journal, {
    expectedRevision: journal.revision, attemptId: UNINSTALL_ATTEMPT_ID, now: ++clock.now,
  });
  return { ...fixture, journal, clock };
}

async function customerRequestVerifiedAcrossGrant(): Promise<UninstallFixture & {
  readonly journal: UninstallJournal;
  readonly clock: { now: number };
}> {
  const fixture = await cleanupReadyUninstall();
  let journal = fixture.journal;
  const clock = { now: fixture.now + 10 };
  const mutation = await prepareCustomerUninstallRequest({
    installJournal: fixture.installJournal,
    uninstallPlan: fixture.uninstallPlan,
    approval: { attemptId: UNINSTALL_ATTEMPT_ID, authorizedTarget: target },
    accountWorkersSubdomain: { accountId: ACCOUNT_ID, subdomain: 'example-account' },
    nowMs: ++clock.now,
    randomBytes: (length) => Uint8Array.from({ length }, (_value, index) => index + 211),
  });
  journal = await appendCustomerGatewayRemoveAttempt(journal, {
    expectedRevision: journal.revision, attemptId: UNINSTALL_ATTEMPT_ID,
    now: clock.now, semantic: mutation.semantic,
  });
  journal = await armCustomerGatewayWorkersDev(journal, {
    expectedRevision: journal.revision, attemptId: UNINSTALL_ATTEMPT_ID,
    now: ++clock.now, enabled: true,
  });
  journal = submitCustomerGatewayWorkersDev(journal, {
    expectedRevision: journal.revision, attemptId: UNINSTALL_ATTEMPT_ID,
    now: ++clock.now, enabled: true, locator: { enabled: true, previewsEnabled: false },
  });
  journal = verifyCustomerGatewayWorkersDev(journal, {
    expectedRevision: journal.revision, attemptId: UNINSTALL_ATTEMPT_ID,
    now: ++clock.now, enabled: true,
  });
  journal = armCustomerGatewayRemoveRequest(journal, {
    expectedRevision: journal.revision, attemptId: UNINSTALL_ATTEMPT_ID, now: ++clock.now,
  });
  if (!journal.lease) throw new TypeError('lease fixture');
  clock.now = journal.lease.expiresAt;
  journal = expireUninstallJournalLease(journal, clock.now);
  clock.now = mutation.semantic.expiresAt * 1_000 - 4;
  journal = (await rotateUninstallApproval(
    journal,
    fixture.installJournal,
    RECOVERY_ATTEMPT_ID,
    clock,
    fixture.uninstallPlan.expiresAt + 250_000,
  )).journal;
  clock.now = mutation.semantic.expiresAt * 1_000;
  journal = await submitCustomerGatewayRemoveRequest(journal, {
    expectedRevision: journal.revision,
    attemptId: RECOVERY_ATTEMPT_ID,
    now: ++clock.now,
    locator: await removedLocator(mutation),
  });
  journal = verifyCustomerGatewayRemoveRequest(journal, {
    expectedRevision: journal.revision, attemptId: RECOVERY_ATTEMPT_ID, now: ++clock.now,
  });
  return { ...fixture, journal, clock };
}

async function customerRemovedAndCleanRestored(): Promise<UninstallFixture & {
  readonly journal: UninstallJournal;
  readonly clock: { now: number };
}> {
  const fixture = await cleanupReadyUninstall();
  let journal = fixture.journal;
  const clock = { now: fixture.now + 10 };
  const accountWorkersSubdomain = Object.freeze({ accountId: ACCOUNT_ID, subdomain: 'example-account' });
  const mutation = await prepareCustomerUninstallRequest({
    installJournal: fixture.installJournal,
    uninstallPlan: fixture.uninstallPlan,
    approval: { attemptId: UNINSTALL_ATTEMPT_ID, authorizedTarget: target },
    accountWorkersSubdomain,
    nowMs: ++clock.now,
    randomBytes: (length) => Uint8Array.from({ length }, (_value, index) => index + 71),
  });
  journal = await appendCustomerGatewayRemoveAttempt(journal, {
    expectedRevision: journal.revision,
    attemptId: UNINSTALL_ATTEMPT_ID,
    now: clock.now,
    semantic: mutation.semantic,
  });
  journal = await armCustomerGatewayWorkersDev(journal, {
    expectedRevision: journal.revision, attemptId: UNINSTALL_ATTEMPT_ID,
    now: ++clock.now, enabled: true,
  });
  journal = submitCustomerGatewayWorkersDev(journal, {
    expectedRevision: journal.revision, attemptId: UNINSTALL_ATTEMPT_ID,
    now: ++clock.now, enabled: true, locator: { enabled: true, previewsEnabled: false },
  });
  journal = verifyCustomerGatewayWorkersDev(journal, {
    expectedRevision: journal.revision, attemptId: UNINSTALL_ATTEMPT_ID,
    now: ++clock.now, enabled: true,
  });
  journal = armCustomerGatewayRemoveRequest(journal, {
    expectedRevision: journal.revision, attemptId: UNINSTALL_ATTEMPT_ID, now: ++clock.now,
  });
  journal = await submitCustomerGatewayRemoveRequest(journal, {
    expectedRevision: journal.revision, attemptId: UNINSTALL_ATTEMPT_ID,
    now: ++clock.now, locator: await removedLocator(mutation),
  });
  journal = verifyCustomerGatewayRemoveRequest(journal, {
    expectedRevision: journal.revision, attemptId: UNINSTALL_ATTEMPT_ID, now: ++clock.now,
  });
  journal = await prepareCustomerGatewayWorkersDevDisable(journal, {
    expectedRevision: journal.revision, attemptId: UNINSTALL_ATTEMPT_ID, now: ++clock.now,
  });
  journal = await armCustomerGatewayWorkersDev(journal, {
    expectedRevision: journal.revision, attemptId: UNINSTALL_ATTEMPT_ID,
    now: ++clock.now, enabled: false,
  });
  journal = submitCustomerGatewayWorkersDev(journal, {
    expectedRevision: journal.revision, attemptId: UNINSTALL_ATTEMPT_ID,
    now: ++clock.now, enabled: false, locator: { enabled: false, previewsEnabled: false },
  });
  journal = verifyCustomerGatewayWorkersDev(journal, {
    expectedRevision: journal.revision, attemptId: UNINSTALL_ATTEMPT_ID,
    now: ++clock.now, enabled: false,
  });
  const intent = await prepareUninstallWorkerDeploymentMutation({
    stage: 'restore_clean', accountId: ACCOUNT_ID, workerName, workerId: WORKER_ID,
    uninstallCycleId: UNINSTALL_CYCLE_ID, versionId: CLEAN_VERSION_ID,
  });
  journal = await prepareUninstallJournalAction(journal, {
    expectedRevision: journal.revision, attemptId: UNINSTALL_ATTEMPT_ID,
    now: ++clock.now, action: 'restore_clean_worker_deployment',
    record: { schemaVersion: 1, kind: 'uninstall_worker_deployment_create', stage: 'restore_clean', intent },
  });
  journal = await armUninstallJournalAction(journal, {
    expectedRevision: journal.revision, attemptId: UNINSTALL_ATTEMPT_ID,
    now: ++clock.now, action: 'restore_clean_worker_deployment',
  });
  const deployment = Object.freeze({
    kind: 'uninstall_worker_deployment' as const,
    stage: 'restore_clean' as const,
    accountId: ACCOUNT_ID,
    workerName,
    workerId: WORKER_ID,
    uninstallCycleId: UNINSTALL_CYCLE_ID,
    versionId: CLEAN_VERSION_ID,
    deploymentId: '77777777-7777-4777-8777-777777777777',
    requestHash: intent.requestHash,
    correlationTag: intent.correlationTag,
  });
  journal = await submitUninstallJournalAction(journal, {
    expectedRevision: journal.revision, attemptId: UNINSTALL_ATTEMPT_ID,
    now: ++clock.now, action: 'restore_clean_worker_deployment', value: deployment,
  });
  journal = await verifyUninstallJournalAction(journal, {
    expectedRevision: journal.revision, attemptId: UNINSTALL_ATTEMPT_ID,
    now: ++clock.now, action: 'restore_clean_worker_deployment', value: deployment,
  });
  return { ...fixture, journal, clock };
}

async function managementReadyUninstall(): Promise<UninstallFixture & {
  readonly journal: UninstallJournal;
  readonly clock: { now: number };
}> {
  const fixture = await customerRemovedAndCleanRestored();
  const attestation = await preflight(
    fixture.installJournal,
    fixture.uninstallPlan,
    UNINSTALL_ATTEMPT_ID,
    ++fixture.clock.now,
  );
  const journal = await appendUninstallManagementPreflight(fixture.journal, {
    expectedRevision: fixture.journal.revision,
    attemptId: UNINSTALL_ATTEMPT_ID,
    now: fixture.clock.now,
    preflight: attestation,
  });
  return { ...fixture, journal };
}

async function managementDeletesVerified(): Promise<UninstallFixture & {
  readonly journal: UninstallJournal;
  readonly clock: { now: number };
}> {
  const fixture = await managementReadyUninstall();
  let { journal } = fixture;
  for (const action of [
    'management_custom_domain_delete',
    'management_admin_policy_delete',
    'management_access_application_delete',
  ] as const) {
    const started = await beginManagementDelete(journal, action, fixture.clock);
    journal = await verifyUninstallJournalAction(started.journal, {
      expectedRevision: started.journal.revision,
      attemptId: UNINSTALL_ATTEMPT_ID,
      now: ++fixture.clock.now,
      action,
      value: await managementAbsence(started.journal, started.intent),
    });
  }
  return { ...fixture, journal };
}

async function rotateUninstallApproval(
  journal: UninstallJournal,
  installJournal: InstallJournal,
  attemptId: string,
  clock: { now: number },
  expiresAt: number,
): Promise<{ readonly journal: UninstallJournal; readonly plan: StaticUninstallPlan }> {
  const activeAttemptId = requiredFixture(journal.approvalHistory.at(-1), 'active uninstall approval').attemptId;
  if (journal.lease) {
    journal = releaseUninstallJournalLease(journal, {
      expectedRevision: journal.revision,
      attemptId: activeAttemptId,
      now: ++clock.now,
    });
  }
  const createdAt = ++clock.now;
  const plan = await buildStaticUninstallPlan(installJournal, createdAt, expiresAt);
  journal = await appendUninstallJournalApproval(journal, plan, {
    expectedRevision: journal.revision,
    attemptId,
    now: ++clock.now,
    approvedAt: createdAt,
    authorizedTarget: target,
  });
  journal = acquireUninstallJournalLease(journal, {
    expectedRevision: journal.revision,
    attemptId,
    now: ++clock.now,
    leaseExpiresAt: Math.min(clock.now + 250_000, expiresAt),
  });
  return { journal, plan };
}

describe('durable uninstall journal authority and lease boundary', () => {
  it('binds the exact completed install, reviewed plan, target, release, receipt, namespace, and cycle', async () => {
    const fixture = await initializedUninstall();
    const parsed = await requireUninstallJournal(structuredClone(fixture.journal));
    expect(parsed).toEqual(fixture.journal);
    expect(parsed).not.toBe(fixture.journal);
    expect(parsed.bindingHash).toMatch(/^sha256:[a-f0-9]{64}$/u);
    expect(parsed.actions).toHaveLength(1);
    expect(parsed.actions[0]).toMatchObject({ name: 'uninstall_fresh_preflight', phase: 'verified' });
    expectDeepFrozen(parsed);
  });

  it('journals version preparation before ephemeral asset work and never rearms an unknown mutation', async () => {
    const fixture = await initializedUninstall();
    let journal = acquireUninstallJournalLease(fixture.journal, {
      expectedRevision: fixture.journal.revision,
      attemptId: UNINSTALL_ATTEMPT_ID,
      now: fixture.now + 1,
      leaseExpiresAt: fixture.now + 240_000,
    });
    journal = await prepareUninstallJournalAction(journal, {
      expectedRevision: journal.revision,
      attemptId: UNINSTALL_ATTEMPT_ID,
      now: fixture.now + 2,
      action: 'cleanup_worker_version_create',
      record: {
        schemaVersion: 1,
        kind: 'uninstall_worker_version_create',
        stage: 'cleanup',
        accountId: ACCOUNT_ID,
        workerName,
        workerId: WORKER_ID,
        uninstallCycleId: UNINSTALL_CYCLE_ID,
        namespacePresence: namespacePresence(),
        release: manifest.release,
        artifactSha256: manifest.artifact.treeSha256,
        componentSha256: manifest.components.workerCleanup.treeSha256,
        recovery: null,
      },
    });
    expect(journal.actions[1]).toMatchObject({
      name: 'cleanup_worker_version_create', phase: 'prepared',
      record: { recovery: null },
    });
    await expect(requireUninstallJournal(structuredClone(journal))).resolves.toEqual(journal);

    const mutation = await prepareCleanupWorkerVersionMutation({
      accountId: ACCOUNT_ID,
      workerName,
      workerId: WORKER_ID,
      namespaceId: NAMESPACE_ID,
      uninstallCycleId: UNINSTALL_CYCLE_ID,
      releaseSet: await uninstallReleaseSet(),
      variables: cleanupVariables(),
      uninstallNonce: 'N'.repeat(43),
    });
    journal = await attachUninstallWorkerVersionRecovery(journal, {
      expectedRevision: journal.revision,
      attemptId: UNINSTALL_ATTEMPT_ID,
      now: fixture.now + 3,
      action: 'cleanup_worker_version_create',
      recovery: mutation.recovery,
    });
    journal = await armUninstallJournalAction(journal, {
      expectedRevision: journal.revision,
      attemptId: UNINSTALL_ATTEMPT_ID,
      now: fixture.now + 4,
      action: 'cleanup_worker_version_create',
    });
    expect(requiredFixture(journal.actions.at(1), 'cleanup action').phase).toBe('send_armed');
    await expect(requireUninstallJournal(structuredClone(journal))).resolves.toEqual(journal);
    await expect(armUninstallJournalAction(journal, {
      expectedRevision: journal.revision,
      attemptId: UNINSTALL_ATTEMPT_ID,
      now: fixture.now + 5,
      action: 'cleanup_worker_version_create',
    })).rejects.toMatchObject({ code: 'session_conflict' });

    const submission = {
      kind: 'uninstall_worker_version' as const,
      stage: 'cleanup' as const,
      accountId: ACCOUNT_ID,
      workerName,
      workerId: WORKER_ID,
      uninstallCycleId: UNINSTALL_CYCLE_ID,
      versionId: '55555555-5555-4555-8555-555555555555',
      requestHash: mutation.recovery.requestHash,
      correlationTag: mutation.recovery.correlationTag,
    };
    journal = await submitUninstallJournalAction(journal, {
      expectedRevision: journal.revision,
      attemptId: UNINSTALL_ATTEMPT_ID,
      now: fixture.now + 5,
      action: 'cleanup_worker_version_create',
      value: submission,
    });
    expect(requiredFixture(journal.actions.at(1), 'cleanup action').phase).toBe('submitted');
    journal = await verifyUninstallJournalAction(journal, {
      expectedRevision: journal.revision,
      attemptId: UNINSTALL_ATTEMPT_ID,
      now: fixture.now + 6,
      action: 'cleanup_worker_version_create',
      value: submission,
    });
    expect(requiredFixture(journal.actions.at(1), 'cleanup action').phase).toBe('verified');

    for (const phase of ['send_armed', 'submitted', 'verified'] as const) {
      const stale = structuredClone(journal);
      const preflight = requiredFixture(stale.actions.at(0), 'uninstall preflight action').record;
      const action = requiredFixture(stale.actions.at(1), 'cleanup action');
      if (!('expiresAt' in preflight)) {
        throw new TypeError('uninstall action fixture missing');
      }
      const submitted = phase !== 'send_armed';
      Object.defineProperties(action, {
        phase: { value: phase },
        sendArmedAt: { value: preflight.expiresAt },
        submittedAt: { value: submitted ? preflight.expiresAt + 1 : null },
        verifiedAt: { value: phase === 'verified' ? preflight.expiresAt + 2 : null },
        locator: {
          value: submitted
            ? structuredClone(requiredFixture(journal.actions.at(1), 'cleanup action').locator)
            : null,
        },
      });
      Object.defineProperty(stale, 'updatedAt', { value: phase === 'verified'
        ? preflight.expiresAt + 2
        : submitted
          ? preflight.expiresAt + 1
          : preflight.expiresAt });
      await expect(requireUninstallJournal(stale)).rejects.toMatchObject({ code: 'session_invalid' });
    }

    const deploymentIntent = await prepareUninstallWorkerDeploymentMutation({
      stage: 'cleanup',
      accountId: ACCOUNT_ID,
      workerName,
      workerId: WORKER_ID,
      uninstallCycleId: UNINSTALL_CYCLE_ID,
      versionId: submission.versionId,
    });
    journal = await prepareUninstallJournalAction(journal, {
      expectedRevision: journal.revision,
      attemptId: UNINSTALL_ATTEMPT_ID,
      now: fixture.now + 7,
      action: 'cleanup_worker_deployment_create',
      record: { schemaVersion: 1, kind: 'uninstall_worker_deployment_create', stage: 'cleanup',
        intent: deploymentIntent },
    });
    await expect(prepareUninstallJournalAction(journal, {
      expectedRevision: journal.revision,
      attemptId: UNINSTALL_ATTEMPT_ID,
      now: fixture.now + 8,
      action: 'restore_clean_worker_deployment',
      record: { schemaVersion: 1, kind: 'uninstall_worker_deployment_create', stage: 'restore_clean',
        intent: deploymentIntent },
    })).rejects.toMatchObject({ code: 'session_conflict' });
    journal = await armUninstallJournalAction(journal, {
      expectedRevision: journal.revision,
      attemptId: UNINSTALL_ATTEMPT_ID,
      now: fixture.now + 8,
      action: 'cleanup_worker_deployment_create',
    });
    const deploymentSubmission = {
      kind: 'uninstall_worker_deployment' as const,
      stage: 'cleanup' as const,
      accountId: ACCOUNT_ID,
      workerName,
      workerId: WORKER_ID,
      uninstallCycleId: UNINSTALL_CYCLE_ID,
      versionId: submission.versionId,
      deploymentId: '66666666-6666-4666-8666-666666666666',
      requestHash: deploymentIntent.requestHash,
      correlationTag: deploymentIntent.correlationTag,
    };
    journal = await submitUninstallJournalAction(journal, {
      expectedRevision: journal.revision,
      attemptId: UNINSTALL_ATTEMPT_ID,
      now: fixture.now + 9,
      action: 'cleanup_worker_deployment_create',
      value: deploymentSubmission,
    });
    journal = await verifyUninstallJournalAction(journal, {
      expectedRevision: journal.revision,
      attemptId: UNINSTALL_ATTEMPT_ID,
      now: fixture.now + 10,
      action: 'cleanup_worker_deployment_create',
      value: deploymentSubmission,
    });
    await expect(requireUninstallJournal(structuredClone(journal))).resolves.toEqual(journal);

    const actionOrderRewind = structuredClone(journal);
    const secondAction = actionOrderRewind.actions[1];
    const thirdAction = actionOrderRewind.actions[2];
    if (!secondAction || !thirdAction) throw new TypeError('uninstall action fixture missing');
    Object.defineProperty(thirdAction, 'preparedAt', { value: secondAction.preparedAt });
    await expect(requireUninstallJournal(actionOrderRewind)).rejects.toMatchObject({
      code: 'session_invalid',
    });

  });

  it('pins each customer request to its approval while a fresh grant safely disables an older bridge', async () => {
    const fixture = await cleanupReadyUninstall();
    let journal = fixture.journal;
    const accountWorkersSubdomain = Object.freeze({ accountId: ACCOUNT_ID, subdomain: 'example-account' });
    const first = await prepareCustomerUninstallRequest({
      installJournal: fixture.installJournal,
      uninstallPlan: fixture.uninstallPlan,
      approval: { attemptId: UNINSTALL_ATTEMPT_ID, authorizedTarget: target },
      accountWorkersSubdomain,
      nowMs: fixture.now + 11,
      randomBytes: (length) => Uint8Array.from({ length }, (_value, index) => index + 31),
    });
    journal = await appendCustomerGatewayRemoveAttempt(journal, {
      expectedRevision: journal.revision,
      attemptId: UNINSTALL_ATTEMPT_ID,
      now: fixture.now + 11,
      semantic: first.semantic,
    });
    journal = await armCustomerGatewayWorkersDev(journal, {
      expectedRevision: journal.revision,
      attemptId: UNINSTALL_ATTEMPT_ID,
      now: fixture.now + 12,
      enabled: true,
    });
    journal = submitCustomerGatewayWorkersDev(journal, {
      expectedRevision: journal.revision,
      attemptId: UNINSTALL_ATTEMPT_ID,
      now: fixture.now + 13,
      enabled: true,
      locator: { enabled: true, previewsEnabled: false },
    });
    journal = verifyCustomerGatewayWorkersDev(journal, {
      expectedRevision: journal.revision,
      attemptId: UNINSTALL_ATTEMPT_ID,
      now: fixture.now + 14,
      enabled: true,
    });
    await expect(requireUninstallJournal(structuredClone(journal))).resolves.toEqual(journal);
    journal = releaseUninstallJournalLease(journal, {
      expectedRevision: journal.revision,
      attemptId: UNINSTALL_ATTEMPT_ID,
      now: fixture.now + 15,
    });
    const renewedPlan = await buildStaticUninstallPlan(
      fixture.installJournal,
      fixture.now + 16,
      fixture.now + 320_000,
    );
    journal = await appendUninstallJournalApproval(journal, renewedPlan, {
      expectedRevision: journal.revision,
      attemptId: RECOVERY_ATTEMPT_ID,
      now: fixture.now + 17,
      approvedAt: fixture.now + 16,
      authorizedTarget: target,
    });
    journal = acquireUninstallJournalLease(journal, {
      expectedRevision: journal.revision,
      attemptId: RECOVERY_ATTEMPT_ID,
      now: fixture.now + 18,
      leaseExpiresAt: fixture.now + 250_000,
    });
    expect(() => armCustomerGatewayRemoveRequest(journal, {
      expectedRevision: journal.revision,
      attemptId: RECOVERY_ATTEMPT_ID,
      now: fixture.now + 19,
    })).toThrowError(expect.objectContaining({ code: 'session_conflict' }));
    journal = await prepareCustomerGatewayWorkersDevDisable(journal, {
      expectedRevision: journal.revision,
      attemptId: RECOVERY_ATTEMPT_ID,
      now: fixture.now + 20,
    });
    journal = await armCustomerGatewayWorkersDev(journal, {
      expectedRevision: journal.revision,
      attemptId: RECOVERY_ATTEMPT_ID,
      now: fixture.now + 21,
      enabled: false,
    });
    journal = submitCustomerGatewayWorkersDev(journal, {
      expectedRevision: journal.revision,
      attemptId: RECOVERY_ATTEMPT_ID,
      now: fixture.now + 22,
      enabled: false,
      locator: { enabled: false, previewsEnabled: false },
    });
    journal = verifyCustomerGatewayWorkersDev(journal, {
      expectedRevision: journal.revision,
      attemptId: RECOVERY_ATTEMPT_ID,
      now: fixture.now + 23,
      enabled: false,
    });
    const second = await prepareCustomerUninstallRequest({
      installJournal: fixture.installJournal,
      uninstallPlan: renewedPlan,
      approval: { attemptId: RECOVERY_ATTEMPT_ID, authorizedTarget: target },
      accountWorkersSubdomain,
      nowMs: fixture.now + 24,
      randomBytes: (length) => Uint8Array.from({ length }, (_value, index) => index + 61),
    });
    journal = await appendCustomerGatewayRemoveAttempt(journal, {
      expectedRevision: journal.revision,
      attemptId: RECOVERY_ATTEMPT_ID,
      now: fixture.now + 24,
      semantic: second.semantic,
    });
    const customer = journal.actions.find((action) => action.name === 'customer_gateway_remove');
    expect(customer && 'kind' in customer.record && customer.record.kind === 'customer_gateway_remove'
      ? customer.record.attempts.map((attempt) => attempt.approvalAttemptId)
      : []).toEqual([UNINSTALL_ATTEMPT_ID, RECOVERY_ATTEMPT_ID]);
    expect(JSON.stringify(journal)).not.toContain('cloudflareAccessToken');
    await expect(requireUninstallJournal(structuredClone(journal))).resolves.toEqual(journal);
  });

  it('records a fresh append-only management attestation only after customer removal and clean restore', async () => {
    const fixture = await customerRemovedAndCleanRestored();
    const checkedAt = ++fixture.clock.now;
    const attestation = await preflight(
      fixture.installJournal,
      fixture.uninstallPlan,
      UNINSTALL_ATTEMPT_ID,
      checkedAt,
    );
    const journal = await appendUninstallManagementPreflight(fixture.journal, {
      expectedRevision: fixture.journal.revision,
      attemptId: UNINSTALL_ATTEMPT_ID,
      now: checkedAt,
      preflight: attestation,
    });
    expect(journal.managementPreflightHistory).toEqual([attestation]);
    await expect(requireUninstallJournal(structuredClone(journal))).resolves.toEqual(journal);
    expectDeepFrozen(journal);
  });

  it('refreshes management evidence append-only after expiry and across an exact recovery grant', async () => {
    const fixture = await customerRemovedAndCleanRestored();
    let { journal } = fixture;
    let checkedAt = ++fixture.clock.now;
    const first = await preflight(fixture.installJournal, fixture.uninstallPlan, UNINSTALL_ATTEMPT_ID, checkedAt);
    journal = await appendUninstallManagementPreflight(journal, {
      expectedRevision: journal.revision, attemptId: UNINSTALL_ATTEMPT_ID,
      now: checkedAt, preflight: first,
    });
    checkedAt += 1;
    await expect(appendUninstallManagementPreflight(journal, {
      expectedRevision: journal.revision, attemptId: UNINSTALL_ATTEMPT_ID,
      now: checkedAt,
      preflight: await preflight(fixture.installJournal, fixture.uninstallPlan, UNINSTALL_ATTEMPT_ID, checkedAt),
    })).rejects.toBeDefined();

    checkedAt += 60_000;
    const refreshed = await preflight(
      fixture.installJournal, fixture.uninstallPlan, UNINSTALL_ATTEMPT_ID, checkedAt,
    );
    journal = await appendUninstallManagementPreflight(journal, {
      expectedRevision: journal.revision, attemptId: UNINSTALL_ATTEMPT_ID,
      now: checkedAt, preflight: refreshed,
    });
    journal = releaseUninstallJournalLease(journal, {
      expectedRevision: journal.revision, attemptId: UNINSTALL_ATTEMPT_ID, now: ++checkedAt,
    });
    const renewed = await buildStaticUninstallPlan(
      fixture.installJournal, ++checkedAt, fixture.now + 360_000,
    );
    journal = await appendUninstallJournalApproval(journal, renewed, {
      expectedRevision: journal.revision, attemptId: RECOVERY_ATTEMPT_ID,
      now: ++checkedAt, approvedAt: checkedAt - 1, authorizedTarget: target,
    });
    journal = acquireUninstallJournalLease(journal, {
      expectedRevision: journal.revision, attemptId: RECOVERY_ATTEMPT_ID,
      now: ++checkedAt, leaseExpiresAt: fixture.now + 250_000,
    });
    const recoveryPreflight = await preflight(
      fixture.installJournal, renewed, RECOVERY_ATTEMPT_ID, ++checkedAt,
    );
    journal = await appendUninstallManagementPreflight(journal, {
      expectedRevision: journal.revision, attemptId: RECOVERY_ATTEMPT_ID,
      now: checkedAt, preflight: recoveryPreflight,
    });
    expect(journal.managementPreflightHistory.map((entry) => entry.attemptId)).toEqual([
      UNINSTALL_ATTEMPT_ID, UNINSTALL_ATTEMPT_ID, RECOVERY_ATTEMPT_ID,
    ]);
    await expect(requireUninstallJournal(structuredClone(journal))).resolves.toEqual(journal);
  });

  it('never replays unknown management DELETEs and retries domain, policy, and application under fresh grants', async () => {
    const fixture = await managementReadyUninstall();
    let { journal } = fixture;
    const { clock } = fixture;
    let started = await beginManagementDelete(journal, 'management_custom_domain_delete', clock);
    journal = started.journal;
    const originalDomainSubmission = managementSubmission(started.intent, started.arm);

    const originExpiresAt = fixture.uninstallPlan.expiresAt;
    if (!journal.lease) throw new TypeError('lease fixture');
    clock.now = journal.lease.expiresAt;
    journal = expireUninstallJournalLease(journal, clock.now);
    clock.now = originExpiresAt - 4;
    const rotatedDomain = await rotateUninstallApproval(
      journal,
      fixture.installJournal,
      RECOVERY_ATTEMPT_ID,
      clock,
      originExpiresAt + 300_000,
    );
    journal = rotatedDomain.journal;
    clock.now = originExpiresAt;
    const stillDomain = await managementStillPresent(journal, started.intent, started.arm);
    const tamperedDomain = structuredClone(stillDomain);
    Object.defineProperty(tamperedDomain, 'providerOwnershipSha256', { value: '0'.repeat(64) });
    await expect(recordUninstallManagementDeleteRecovery(journal, {
      expectedRevision: journal.revision,
      attemptId: RECOVERY_ATTEMPT_ID,
      now: ++clock.now,
      action: 'management_custom_domain_delete',
      evidence: tamperedDomain,
    })).rejects.toMatchObject({ code: 'bad_request' });
    journal = await recordUninstallManagementDeleteRecovery(journal, {
      expectedRevision: journal.revision,
      attemptId: RECOVERY_ATTEMPT_ID,
      now: ++clock.now,
      action: 'management_custom_domain_delete',
      evidence: stillDomain,
    });
    const domainActionAfterRecovery = journal.actions.find(
      (entry) => entry.name === 'management_custom_domain_delete',
    );
    expect(domainActionAfterRecovery && 'kind' in domainActionAfterRecovery.record &&
      domainActionAfterRecovery.record.kind === 'uninstall_management_delete'
      ? domainActionAfterRecovery.record.attempts[0]
      : null).toMatchObject({
      phase: 'not_applied',
      submission: originalDomainSubmission,
      submittedByAttemptId: UNINSTALL_ATTEMPT_ID,
      verifiedByAttemptId: RECOVERY_ATTEMPT_ID,
    });
    await expect(submitUninstallJournalAction(journal, {
      expectedRevision: journal.revision,
      attemptId: RECOVERY_ATTEMPT_ID,
      now: ++clock.now,
      action: 'management_custom_domain_delete',
      value: originalDomainSubmission,
    })).rejects.toMatchObject({ code: 'session_conflict' });

    const refreshed = await preflight(
      fixture.installJournal,
      rotatedDomain.plan,
      RECOVERY_ATTEMPT_ID,
      ++clock.now,
    );
    journal = await appendUninstallManagementPreflight(journal, {
      expectedRevision: journal.revision,
      attemptId: RECOVERY_ATTEMPT_ID,
      now: clock.now,
      preflight: refreshed,
    });

    async function retryCurrentAction(
      value: UninstallJournal,
      action: HostedUninstallManagementDeleteAction,
      attemptId: string,
    ): Promise<UninstallJournal> {
      const prerequisites = managementPrerequisites(value, action);
      const intent = await prepareHostedUninstallManagementDeleteIntent(
        uninstallManagementContext(value), action, prerequisites,
      );
      value = await appendUninstallManagementDeleteAttempt(value, {
        expectedRevision: value.revision,
        attemptId,
        now: ++clock.now,
        action,
        prerequisites,
        intent,
      });
      const arm = await prepareHostedUninstallManagementDeleteArm(
        uninstallManagementContext(value), intent, prerequisites, ++clock.now,
      );
      value = await armUninstallJournalAction(value, {
        expectedRevision: value.revision,
        attemptId,
        now: clock.now,
        action,
        value: arm,
      });
      value = await submitUninstallJournalAction(value, {
        expectedRevision: value.revision,
        attemptId,
        now: ++clock.now,
        action,
        value: managementSubmission(intent, arm),
      });
      return recordUninstallManagementDeleteRecovery(value, {
        expectedRevision: value.revision,
        attemptId,
        now: ++clock.now,
        action,
        evidence: await managementAbsence(value, intent),
      });
    }

    journal = await retryCurrentAction(
      journal, 'management_custom_domain_delete', RECOVERY_ATTEMPT_ID,
    );
    expect(journal.actions.find((entry) => entry.name === 'management_custom_domain_delete')).toMatchObject({
      phase: 'verified',
      submittedAt: expect.any(Number),
    });

    started = await beginManagementDelete(journal, 'management_admin_policy_delete', clock);
    journal = started.journal;
    const rotatedPolicy = await rotateUninstallApproval(
      journal,
      fixture.installJournal,
      RECOVERY_ATTEMPT_TWO,
      clock,
      rotatedDomain.plan.expiresAt + 100_000,
    );
    journal = rotatedPolicy.journal;
    journal = await recordUninstallManagementDeleteRecovery(journal, {
      expectedRevision: journal.revision,
      attemptId: RECOVERY_ATTEMPT_TWO,
      now: ++clock.now,
      action: 'management_admin_policy_delete',
      evidence: await managementStillPresent(journal, started.intent, started.arm),
    });
    journal = await retryCurrentAction(
      journal, 'management_admin_policy_delete', RECOVERY_ATTEMPT_TWO,
    );

    started = await beginManagementDelete(journal, 'management_access_application_delete', clock);
    journal = started.journal;
    const rotatedApplication = await rotateUninstallApproval(
      journal,
      fixture.installJournal,
      RECOVERY_ATTEMPT_THREE,
      clock,
      rotatedPolicy.plan.expiresAt + 100_000,
    );
    journal = rotatedApplication.journal;
    journal = await recordUninstallManagementDeleteRecovery(journal, {
      expectedRevision: journal.revision,
      attemptId: RECOVERY_ATTEMPT_THREE,
      now: ++clock.now,
      action: 'management_access_application_delete',
      evidence: await managementStillPresent(journal, started.intent, started.arm),
    });
    journal = await retryCurrentAction(
      journal, 'management_access_application_delete', RECOVERY_ATTEMPT_THREE,
    );

    for (const action of [
      'management_custom_domain_delete',
      'management_admin_policy_delete',
      'management_access_application_delete',
    ] as const) {
      const record = journal.actions.find((entry) => entry.name === action)?.record;
      expect(record && 'kind' in record && record.kind === 'uninstall_management_delete'
        ? record.attempts.map((attempt) => attempt.phase)
        : []).toEqual(['not_applied', 'verified']);
    }
    const actorTamper = structuredClone(journal);
    const verifiedAttempt = managementDeleteRecord(
      actorTamper,
      'management_admin_policy_delete',
    ).attempts[1];
    if (!verifiedAttempt) throw new TypeError('management delete attempt missing');
    Object.defineProperty(verifiedAttempt, 'verifiedByAttemptId', { value: RECOVERY_ATTEMPT_THREE });
    await expect(requireUninstallJournal(actorTamper)).rejects.toMatchObject({ code: 'session_invalid' });
    await expect(requireUninstallJournal(structuredClone(journal))).resolves.toEqual(journal);
    expectDeepFrozen(journal);
  }, 120_000);

  it('renews a safely prepared domain intent, but never repins an armed attempt', async () => {
    const fixture = await managementReadyUninstall();
    let { journal } = fixture;
    const { clock } = fixture;
    const prerequisitesA = managementPrerequisites(journal, 'management_custom_domain_delete');
    const intentA = await prepareHostedUninstallManagementDeleteIntent(
      uninstallManagementContext(journal), 'management_custom_domain_delete', prerequisitesA,
    );
    journal = await prepareUninstallJournalAction(journal, {
      expectedRevision: journal.revision,
      attemptId: UNINSTALL_ATTEMPT_ID,
      now: ++clock.now,
      action: 'management_custom_domain_delete',
      record: { schemaVersion: 1, kind: 'uninstall_management_delete', prerequisites: prerequisitesA, intent: intentA },
    });
    journal = releaseUninstallJournalLease(journal, {
      expectedRevision: journal.revision,
      attemptId: UNINSTALL_ATTEMPT_ID,
      now: ++clock.now,
    });
    const rotated = await rotateUninstallApproval(
      journal,
      fixture.installJournal,
      RECOVERY_ATTEMPT_ID,
      clock,
      fixture.uninstallPlan.expiresAt + 100_000,
    );
    journal = rotated.journal;
    const preflightB = await preflight(
      fixture.installJournal, rotated.plan, RECOVERY_ATTEMPT_ID, ++clock.now,
    );
    journal = await appendUninstallManagementPreflight(journal, {
      expectedRevision: journal.revision,
      attemptId: RECOVERY_ATTEMPT_ID,
      now: clock.now,
      preflight: preflightB,
    });
    const prerequisitesB = managementPrerequisites(journal, 'management_custom_domain_delete');
    const intentB = await prepareHostedUninstallManagementDeleteIntent(
      uninstallManagementContext(journal), 'management_custom_domain_delete', prerequisitesB,
    );
    journal = await replacePreparedUninstallJournalAction(journal, {
      expectedRevision: journal.revision,
      attemptId: RECOVERY_ATTEMPT_ID,
      now: ++clock.now,
      action: 'management_custom_domain_delete',
      record: { schemaVersion: 1, kind: 'uninstall_management_delete', prerequisites: prerequisitesB, intent: intentB },
    });
    const armB = await prepareHostedUninstallManagementDeleteArm(
      uninstallManagementContext(journal), intentB, prerequisitesB, ++clock.now,
    );
    journal = await armUninstallJournalAction(journal, {
      expectedRevision: journal.revision,
      attemptId: RECOVERY_ATTEMPT_ID,
      now: clock.now,
      action: 'management_custom_domain_delete',
      value: armB,
    });
    await expect(appendUninstallManagementPreflight(journal, {
      expectedRevision: journal.revision,
      attemptId: RECOVERY_ATTEMPT_ID,
      now: ++clock.now,
      preflight: await preflight(fixture.installJournal, rotated.plan, RECOVERY_ATTEMPT_ID, clock.now),
    })).rejects.toMatchObject({ code: 'session_conflict' });
    await expect(replacePreparedUninstallJournalAction(journal, {
      expectedRevision: journal.revision,
      attemptId: RECOVERY_ATTEMPT_ID,
      now: ++clock.now,
      action: 'management_custom_domain_delete',
      record: { schemaVersion: 1, kind: 'uninstall_management_delete', prerequisites: prerequisitesB, intent: intentB },
    })).rejects.toMatchObject({ code: 'session_conflict' });
    await expect(requireUninstallJournal(structuredClone(journal))).resolves.toEqual(journal);
  }, 20_000);

  it('builds an exact no-residue bundle and converges to one deterministic full tombstone across lease renewal', async () => {
    const fixture = await managementDeletesVerified();
    let { journal } = fixture;
    const { clock } = fixture;
    const releaseSet = await uninstallReleaseSet();
    const retirement = await prepareRetirementWorkerVersionMutation({
      accountId: ACCOUNT_ID,
      workerName,
      workerId: WORKER_ID,
      uninstallCycleId: UNINSTALL_CYCLE_ID,
      releaseSet,
    });
    journal = await prepareUninstallJournalAction(journal, {
      expectedRevision: journal.revision,
      attemptId: UNINSTALL_ATTEMPT_ID,
      now: ++clock.now,
      action: 'retirement_worker_version_create',
      record: {
        schemaVersion: 1,
        kind: 'uninstall_worker_version_create',
        stage: 'retirement',
        accountId: ACCOUNT_ID,
        workerName,
        workerId: WORKER_ID,
        uninstallCycleId: UNINSTALL_CYCLE_ID,
        namespacePresence: null,
        release: manifest.release,
        artifactSha256: manifest.artifact.treeSha256,
        componentSha256: manifest.components.workerRetirement.treeSha256,
        recovery: null,
      },
    });
    journal = await attachUninstallWorkerVersionRecovery(journal, {
      expectedRevision: journal.revision,
      attemptId: UNINSTALL_ATTEMPT_ID,
      now: ++clock.now,
      action: 'retirement_worker_version_create',
      recovery: retirement.recovery,
    });
    journal = await armUninstallJournalAction(journal, {
      expectedRevision: journal.revision,
      attemptId: UNINSTALL_ATTEMPT_ID,
      now: ++clock.now,
      action: 'retirement_worker_version_create',
    });
    const retirementVersion = Object.freeze({
      kind: 'uninstall_worker_version' as const,
      stage: 'retirement' as const,
      accountId: ACCOUNT_ID,
      workerName,
      workerId: WORKER_ID,
      uninstallCycleId: UNINSTALL_CYCLE_ID,
      versionId: '88888888-8888-4888-8888-888888888888',
      requestHash: retirement.recovery.requestHash,
      correlationTag: retirement.recovery.correlationTag,
    });
    journal = await submitUninstallJournalAction(journal, {
      expectedRevision: journal.revision,
      attemptId: UNINSTALL_ATTEMPT_ID,
      now: ++clock.now,
      action: 'retirement_worker_version_create',
      value: retirementVersion,
    });
    journal = await verifyUninstallJournalAction(journal, {
      expectedRevision: journal.revision,
      attemptId: UNINSTALL_ATTEMPT_ID,
      now: ++clock.now,
      action: 'retirement_worker_version_create',
      value: retirementVersion,
    });
    const retirementDeploymentIntent = await prepareUninstallWorkerDeploymentMutation({
      stage: 'retirement',
      accountId: ACCOUNT_ID,
      workerName,
      workerId: WORKER_ID,
      uninstallCycleId: UNINSTALL_CYCLE_ID,
      versionId: retirementVersion.versionId,
    });
    journal = await prepareUninstallJournalAction(journal, {
      expectedRevision: journal.revision,
      attemptId: UNINSTALL_ATTEMPT_ID,
      now: ++clock.now,
      action: 'retirement_worker_deployment_create',
      record: { schemaVersion: 1, kind: 'uninstall_worker_deployment_create', stage: 'retirement',
        intent: retirementDeploymentIntent },
    });
    journal = await armUninstallJournalAction(journal, {
      expectedRevision: journal.revision,
      attemptId: UNINSTALL_ATTEMPT_ID,
      now: ++clock.now,
      action: 'retirement_worker_deployment_create',
    });
    const retirementDeployment = Object.freeze({
      kind: 'uninstall_worker_deployment' as const,
      stage: 'retirement' as const,
      accountId: ACCOUNT_ID,
      workerName,
      workerId: WORKER_ID,
      uninstallCycleId: UNINSTALL_CYCLE_ID,
      versionId: retirementVersion.versionId,
      deploymentId: '99999999-9999-4999-8999-999999999999',
      requestHash: retirementDeploymentIntent.requestHash,
      correlationTag: retirementDeploymentIntent.correlationTag,
    });
    journal = await submitUninstallJournalAction(journal, {
      expectedRevision: journal.revision,
      attemptId: UNINSTALL_ATTEMPT_ID,
      now: ++clock.now,
      action: 'retirement_worker_deployment_create',
      value: retirementDeployment,
    });
    journal = await verifyUninstallJournalAction(journal, {
      expectedRevision: journal.revision,
      attemptId: UNINSTALL_ATTEMPT_ID,
      now: ++clock.now,
      action: 'retirement_worker_deployment_create',
      value: retirementDeployment,
    });
    const namespaceRetirement = Object.freeze({
      kind: 'admin_state_namespace_retirement' as const,
      accountId: ACCOUNT_ID,
      workerName,
      workerId: WORKER_ID,
      uninstallCycleId: UNINSTALL_CYCLE_ID,
      namespaceId: NAMESPACE_ID,
      retirementVersionId: retirementVersion.versionId,
      accountNamespaceCount: 0,
      firstSnapshotSha256: 'a'.repeat(64),
      secondSnapshotSha256: 'a'.repeat(64),
    });
    journal = await prepareUninstallJournalAction(journal, {
      expectedRevision: journal.revision,
      attemptId: UNINSTALL_ATTEMPT_ID,
      now: ++clock.now,
      action: 'admin_state_namespace_retired',
      record: { schemaVersion: 1, kind: 'admin_state_namespace_retired', proof: namespaceRetirement },
    });
    journal = await armUninstallJournalAction(journal, {
      expectedRevision: journal.revision,
      attemptId: UNINSTALL_ATTEMPT_ID,
      now: ++clock.now,
      action: 'admin_state_namespace_retired',
    });
    journal = await submitUninstallJournalAction(journal, {
      expectedRevision: journal.revision,
      attemptId: UNINSTALL_ATTEMPT_ID,
      now: ++clock.now,
      action: 'admin_state_namespace_retired',
      value: namespaceRetirement,
    });
    journal = await verifyUninstallJournalAction(journal, {
      expectedRevision: journal.revision,
      attemptId: UNINSTALL_ATTEMPT_ID,
      now: ++clock.now,
      action: 'admin_state_namespace_retired',
      value: namespaceRetirement,
    });

    const retirementProofCommitment = await hash(namespaceRetirement);
    const workerDeleteSemantic = {
      accountId: ACCOUNT_ID,
      force: 'omitted' as const,
      method: 'DELETE' as const,
      namespaceId: NAMESPACE_ID,
      retirementProof: namespaceRetirement,
      retirementProofCommitment,
      retirementVersionId: retirementVersion.versionId,
      uninstallCycleId: UNINSTALL_CYCLE_ID,
      workerId: WORKER_ID,
      workerName,
    };
    const workerDeleteRequestHash = await hash(workerDeleteSemantic);
    const workerDeleteIntent = Object.freeze({
      kind: 'uninstall_worker_delete_intent' as const,
      ...workerDeleteSemantic,
      requestHash: workerDeleteRequestHash,
      correlationTag: `ankka-un-w-delete-sha256:${workerDeleteRequestHash}`,
    });
    journal = await prepareUninstallJournalAction(journal, {
      expectedRevision: journal.revision,
      attemptId: UNINSTALL_ATTEMPT_ID,
      now: ++clock.now,
      action: 'management_worker_delete',
      record: { schemaVersion: 1, kind: 'management_worker_delete', intent: workerDeleteIntent, submission: null },
    });
    journal = await armUninstallJournalAction(journal, {
      expectedRevision: journal.revision,
      attemptId: UNINSTALL_ATTEMPT_ID,
      now: ++clock.now,
      action: 'management_worker_delete',
    });
    const workerDeleteSubmission = Object.freeze({
      kind: 'uninstall_worker_delete' as const,
      accountId: ACCOUNT_ID,
      workerName,
      workerId: WORKER_ID,
      uninstallCycleId: UNINSTALL_CYCLE_ID,
      namespaceId: NAMESPACE_ID,
      retirementVersionId: retirementVersion.versionId,
      retirementProofCommitment,
      requestHash: workerDeleteRequestHash,
      correlationTag: workerDeleteIntent.correlationTag,
    });
    journal = await submitUninstallJournalAction(journal, {
      expectedRevision: journal.revision,
      attemptId: UNINSTALL_ATTEMPT_ID,
      now: ++clock.now,
      action: 'management_worker_delete',
      value: workerDeleteSubmission,
    });
    const scriptSnapshotSha256 = await hash([]);
    const workerDeletion = Object.freeze({
      kind: 'uninstall_worker_deletion_proof' as const,
      accountId: ACCOUNT_ID,
      workerName,
      workerId: WORKER_ID,
      uninstallCycleId: UNINSTALL_CYCLE_ID,
      namespaceId: NAMESPACE_ID,
      retirementVersionId: retirementVersion.versionId,
      retirementProofCommitment,
      requestHash: workerDeleteRequestHash,
      firstScriptListSha256: scriptSnapshotSha256,
      secondScriptListSha256: scriptSnapshotSha256,
      scriptCount: 0,
    });
    journal = await verifyUninstallJournalAction(journal, {
      expectedRevision: journal.revision,
      attemptId: UNINSTALL_ATTEMPT_ID,
      now: ++clock.now,
      action: 'management_worker_delete',
      value: workerDeletion,
    });

    const deletionEvidence = Object.freeze([
      verifiedManagementAbsence(journal, 'management_custom_domain_delete'),
      verifiedManagementAbsence(journal, 'management_admin_policy_delete'),
      verifiedManagementAbsence(journal, 'management_access_application_delete'),
    ] as const);
    const namespaceSnapshot = (observation: 1 | 2) => Object.freeze({
      schemaVersion: 1 as const,
      kind: 'admin_state_namespace_absence_snapshot' as const,
      observation,
      accountId: ACCOUNT_ID,
      workerName,
      namespaceId: NAMESPACE_ID,
      uninstallCycleId: UNINSTALL_CYCLE_ID,
      accountNamespaceCount: 0,
      snapshotSha256: 'a'.repeat(64),
    });
    const namespaceSnapshots = Object.freeze([
      namespaceSnapshot(1),
      namespaceSnapshot(2),
    ] as const);
    const evidenceSemantic = {
      schemaVersion: 1 as const,
      kind: 'hosted_uninstall_no_managed_residue_evidence' as const,
      deletionEvidence,
      workerDeletion,
      namespaceRetirement,
      namespaceSnapshots,
    };
    const evidence = Object.freeze({
      ...evidenceSemantic,
      evidenceSha256: await hash(evidenceSemantic),
    });
    const approval = requiredFixture(journal.approvalHistory.at(-1), 'active uninstall approval');
    const installFinal = requiredFixture(journal.installJournal.actions.at(-1), 'install final action').locator;
    if (!installFinal || !('status' in installFinal) || installFinal.status !== 'converged') {
      throw new TypeError('install final');
    }
    const resultSemantic = {
      schemaVersion: 1 as const,
      status: 'no_ankka_managed_residue' as const,
      uninstallPlanId: approval.plan.planId,
      uninstallPlanHash: approval.plan.planHash,
      uninstallAuthorityHash: approval.plan.authorityHash,
      installBindingHash: journal.installJournal.bindingHash,
      installConvergenceHash: installFinal.convergenceHash,
      attemptId: approval.attemptId,
      ownershipMarker: managementOwnershipMarker(installPlan),
      managementHostname: selection.basics.managementHostname,
      dnsAbsenceObservations: 2 as const,
      advancedCertificate: 'provider_retained_out_of_scope_not_observable_or_deleted' as const,
      uninstallCycleId: UNINSTALL_CYCLE_ID,
      deletionEvidenceSha256: await hash(deletionEvidence),
      workerDeletionProofSha256: await hash(workerDeletion),
      namespaceRetirementProofSha256: await hash(namespaceRetirement),
      namespaceSnapshotSha256: await hash(namespaceSnapshots),
      evidence,
    };
    const noResidue = Object.freeze({ ...resultSemantic, proofSha256: await hash(resultSemantic) });
    const noResidueWithEvidence = async (
      nextEvidenceSemantic: Omit<typeof evidenceSemantic, 'workerDeletion' | 'namespaceSnapshots'> & {
        readonly workerDeletion: typeof workerDeletion;
        readonly namespaceSnapshots: typeof namespaceSnapshots;
      },
    ) => {
      const nextEvidence = Object.freeze({
        ...nextEvidenceSemantic,
        evidenceSha256: await hash(nextEvidenceSemantic),
      });
      const nextSemantic = {
        ...resultSemantic,
        deletionEvidenceSha256: await hash(nextEvidence.deletionEvidence),
        workerDeletionProofSha256: await hash(nextEvidence.workerDeletion),
        namespaceRetirementProofSha256: await hash(nextEvidence.namespaceRetirement),
        namespaceSnapshotSha256: await hash(nextEvidence.namespaceSnapshots),
        evidence: nextEvidence,
      };
      return Object.freeze({ ...nextSemantic, proofSha256: await hash(nextSemantic) });
    };
    const mismatchedWorkerDeletion = Object.freeze({
      ...workerDeletion,
      firstScriptListSha256: 'b'.repeat(64),
      secondScriptListSha256: 'b'.repeat(64),
    });
    const mismatchedPrerequisites = await noResidueWithEvidence({
      ...evidenceSemantic,
      workerDeletion: mismatchedWorkerDeletion,
    });
    await expect(prepareUninstallJournalAction(journal, {
      expectedRevision: journal.revision,
      attemptId: UNINSTALL_ATTEMPT_ID,
      now: ++clock.now,
      action: 'management_no_managed_residue',
      record: {
        schemaVersion: 1,
        kind: 'management_no_managed_residue',
        result: mismatchedPrerequisites,
      },
    })).rejects.toMatchObject({ code: 'bad_request' });
    const alternateNamespaceSnapshots: typeof namespaceSnapshots = Object.freeze([
      Object.freeze({ ...namespaceSnapshots[0], snapshotSha256: 'b'.repeat(64) }),
      Object.freeze({ ...namespaceSnapshots[1], snapshotSha256: 'b'.repeat(64) }),
    ]);
    const alternateNoResidue = await noResidueWithEvidence({
      ...evidenceSemantic,
      namespaceSnapshots: alternateNamespaceSnapshots,
    });
    journal = await prepareUninstallJournalAction(journal, {
      expectedRevision: journal.revision,
      attemptId: UNINSTALL_ATTEMPT_ID,
      now: ++clock.now,
      action: 'management_no_managed_residue',
      record: { schemaVersion: 1, kind: 'management_no_managed_residue', result: noResidue },
    });
    journal = await armUninstallJournalAction(journal, {
      expectedRevision: journal.revision,
      attemptId: UNINSTALL_ATTEMPT_ID,
      now: ++clock.now,
      action: 'management_no_managed_residue',
    });
    journal = await submitUninstallJournalAction(journal, {
      expectedRevision: journal.revision,
      attemptId: UNINSTALL_ATTEMPT_ID,
      now: ++clock.now,
      action: 'management_no_managed_residue',
      value: noResidue,
    });
    await expect(verifyUninstallJournalAction(journal, {
      expectedRevision: journal.revision,
      attemptId: UNINSTALL_ATTEMPT_ID,
      now: ++clock.now,
      action: 'management_no_managed_residue',
      value: alternateNoResidue,
    })).rejects.toMatchObject({ code: 'bad_request' });
    const renewedNoResidue = await rotateUninstallApproval(
      journal,
      fixture.installJournal,
      RECOVERY_ATTEMPT_ID,
      clock,
      fixture.uninstallPlan.expiresAt + 100_000,
    );
    journal = await verifyUninstallJournalAction(renewedNoResidue.journal, {
      expectedRevision: renewedNoResidue.journal.revision,
      attemptId: RECOVERY_ATTEMPT_ID,
      now: ++clock.now,
      action: 'management_no_managed_residue',
      value: noResidue,
    });
    const noResidueAction = journal.actions[12];
    expect(noResidueAction && 'kind' in noResidueAction.record &&
      noResidueAction.record.kind === 'management_no_managed_residue'
      ? noResidueAction.record
      : null).toMatchObject({
      preparedByAttemptId: UNINSTALL_ATTEMPT_ID,
      armedByAttemptId: UNINSTALL_ATTEMPT_ID,
      submittedByAttemptId: UNINSTALL_ATTEMPT_ID,
      verifiedByAttemptId: RECOVERY_ATTEMPT_ID,
    });
    await expect(requireUninstallJournal(structuredClone(journal))).resolves.toEqual(journal);
    const proofSwap = structuredClone(journal);
    const noResidueProof = proofSwap.actions[12];
    if (!noResidueProof) throw new TypeError('no-residue proof fixture missing');
    Object.defineProperty(noResidueProof, 'locator', {
      value: structuredClone(alternateNoResidue),
    });
    await expect(requireUninstallJournal(proofSwap)).rejects.toMatchObject({ code: 'session_invalid' });

    const convergence = await prepareUninstallFinalConvergenceRecordAndLocator(journal);
    journal = await prepareUninstallJournalAction(journal, {
      expectedRevision: journal.revision,
      attemptId: RECOVERY_ATTEMPT_ID,
      now: ++clock.now,
      action: 'uninstall_final_convergence',
      record: convergence.record,
    });
    journal = await armUninstallJournalAction(journal, {
      expectedRevision: journal.revision,
      attemptId: RECOVERY_ATTEMPT_ID,
      now: ++clock.now,
      action: 'uninstall_final_convergence',
    });
    journal = await submitUninstallJournalAction(journal, {
      expectedRevision: journal.revision,
      attemptId: RECOVERY_ATTEMPT_ID,
      now: ++clock.now,
      action: 'uninstall_final_convergence',
      value: convergence.locator,
    });
    const renewedFinal = await rotateUninstallApproval(
      journal,
      fixture.installJournal,
      RECOVERY_ATTEMPT_TWO,
      clock,
      renewedNoResidue.plan.expiresAt + 100_000,
    );
    journal = await verifyUninstallJournalAction(renewedFinal.journal, {
      expectedRevision: renewedFinal.journal.revision,
      attemptId: RECOVERY_ATTEMPT_TWO,
      now: ++clock.now,
      action: 'uninstall_final_convergence',
      value: convergence.locator,
    });
    expect(isCompleteUninstallJournal(journal)).toBe(true);
    const finalAction = requiredFixture(journal.actions.at(13), 'uninstall final action');
    expect(finalAction.locator).toEqual(convergence.locator);
    expect(JSON.stringify(finalAction.locator)).not.toMatch(
      /cloudflareAccessToken|clientSecret|"authorization"/iu,
    );
    await expect(requireUninstallJournal(structuredClone(journal))).resolves.toEqual(journal);

    const tampered = structuredClone(journal);
    const finalLocator = tampered.actions[13]?.locator;
    if (!finalLocator || !('management' in finalLocator)) {
      throw new TypeError('uninstall convergence fixture missing');
    }
    Object.defineProperty(finalLocator.management.customDomainAbsence, 'evidenceSha256', {
      value: 'f'.repeat(64),
    });
    await expect(requireUninstallJournal(tampered)).rejects.toMatchObject({ code: 'session_invalid' });
  }, 60_000);

  it('terminally records an armed enable observed false and requires a fresh customer cycle', async () => {
    const fixture = await cleanupReadyUninstall();
    let journal = fixture.journal;
    let now = fixture.now + 11;
    const first = await prepareCustomerUninstallRequest({
      installJournal: fixture.installJournal,
      uninstallPlan: fixture.uninstallPlan,
      approval: { attemptId: UNINSTALL_ATTEMPT_ID, authorizedTarget: target },
      accountWorkersSubdomain: { accountId: ACCOUNT_ID, subdomain: 'example-account' },
      nowMs: now,
      randomBytes: (length) => Uint8Array.from({ length }, (_value, index) => index + 111),
    });
    journal = await appendCustomerGatewayRemoveAttempt(journal, {
      expectedRevision: journal.revision, attemptId: UNINSTALL_ATTEMPT_ID,
      now, semantic: first.semantic,
    });
    journal = await armCustomerGatewayWorkersDev(journal, {
      expectedRevision: journal.revision, attemptId: UNINSTALL_ATTEMPT_ID,
      now: ++now, enabled: true,
    });
    expect(() => submitCustomerGatewayWorkersDev(journal, {
      expectedRevision: journal.revision, attemptId: UNINSTALL_ATTEMPT_ID,
      now: ++now, enabled: true, locator: { enabled: false, previewsEnabled: false },
    })).toThrowError(expect.objectContaining({ code: 'bad_request' }));
    journal = releaseUninstallJournalLease(journal, {
      expectedRevision: journal.revision, attemptId: UNINSTALL_ATTEMPT_ID, now: ++now,
    });
    const renewed = await buildStaticUninstallPlan(fixture.installJournal, ++now, fixture.now + 330_000);
    journal = await appendUninstallJournalApproval(journal, renewed, {
      expectedRevision: journal.revision, attemptId: RECOVERY_ATTEMPT_ID,
      now: ++now, approvedAt: now - 1, authorizedTarget: target,
    });
    journal = acquireUninstallJournalLease(journal, {
      expectedRevision: journal.revision, attemptId: RECOVERY_ATTEMPT_ID,
      now: ++now, leaseExpiresAt: fixture.now + 250_000,
    });
    journal = recordCustomerGatewayWorkersDevNotApplied(journal, {
      expectedRevision: journal.revision, attemptId: RECOVERY_ATTEMPT_ID,
      now: ++now, enabled: true, locator: { enabled: false, previewsEnabled: false },
    });
    await expect(armCustomerGatewayWorkersDev(journal, {
      expectedRevision: journal.revision, attemptId: RECOVERY_ATTEMPT_ID,
      now: ++now, enabled: true,
    })).rejects.toMatchObject({ code: 'session_conflict' });
    await expect(requireUninstallJournal(structuredClone(journal))).resolves.toEqual(journal);
    const second = await prepareCustomerUninstallRequest({
      installJournal: fixture.installJournal,
      uninstallPlan: renewed,
      approval: { attemptId: RECOVERY_ATTEMPT_ID, authorizedTarget: target },
      accountWorkersSubdomain: { accountId: ACCOUNT_ID, subdomain: 'example-account' },
      nowMs: ++now,
      randomBytes: (length) => Uint8Array.from({ length }, (_value, index) => index + 131),
    });
    journal = await appendCustomerGatewayRemoveAttempt(journal, {
      expectedRevision: journal.revision, attemptId: RECOVERY_ATTEMPT_ID,
      now, semantic: second.semantic,
    });
    const action = journal.actions.find((entry) => entry.name === 'customer_gateway_remove');
    expect(action && 'kind' in action.record && action.record.kind === 'customer_gateway_remove'
      ? action.record.attempts.map((entry) => entry.enable.phase)
      : []).toEqual(['not_applied', 'prepared']);
    await expect(requireUninstallJournal(structuredClone(journal))).resolves.toEqual(journal);

    const cycleRewind = structuredClone(journal);
    const persistedAttempts = customerRemoveRecord(cycleRewind).attempts;
    const firstAttempt = persistedAttempts[0];
    const secondAttempt = persistedAttempts[1];
    const customerAction = cycleRewind.actions.find((entry) => entry.name === 'customer_gateway_remove');
    if (!firstAttempt?.enable.verifiedAt || !secondAttempt || !customerAction) {
      throw new TypeError('customer removal cycle fixture missing');
    }
    const rewoundPreparedAt = firstAttempt.enable.verifiedAt - 1;
    Object.defineProperty(secondAttempt, 'preparedAt', { value: rewoundPreparedAt });
    Object.defineProperty(secondAttempt.enable, 'preparedAt', { value: rewoundPreparedAt });
    Object.defineProperty(customerAction, 'preparedAt', { value: rewoundPreparedAt });
    await expect(requireUninstallJournal(cycleRewind)).rejects.toMatchObject({ code: 'session_invalid' });
  });

  it('appends a fresh disable after an armed disable is observed still enabled', async () => {
    const fixture = await customerRemovedBridgeEnabled();
    let { journal } = fixture;
    let { now } = fixture.clock;
    journal = await prepareCustomerGatewayWorkersDevDisable(journal, {
      expectedRevision: journal.revision, attemptId: UNINSTALL_ATTEMPT_ID, now: ++now,
    });
    journal = await armCustomerGatewayWorkersDev(journal, {
      expectedRevision: journal.revision, attemptId: UNINSTALL_ATTEMPT_ID,
      now: ++now, enabled: false,
    });
    expect(() => recordCustomerGatewayWorkersDevNotApplied(journal, {
      expectedRevision: journal.revision, attemptId: UNINSTALL_ATTEMPT_ID,
      now: ++now, enabled: false, locator: { enabled: false, previewsEnabled: false },
    })).toThrowError(expect.objectContaining({ code: 'bad_request' }));
    journal = releaseUninstallJournalLease(journal, {
      expectedRevision: journal.revision, attemptId: UNINSTALL_ATTEMPT_ID, now: ++now,
    });
    const renewed = await buildStaticUninstallPlan(fixture.installJournal, ++now, fixture.now + 330_000);
    journal = await appendUninstallJournalApproval(journal, renewed, {
      expectedRevision: journal.revision, attemptId: RECOVERY_ATTEMPT_ID,
      now: ++now, approvedAt: now - 1, authorizedTarget: target,
    });
    journal = acquireUninstallJournalLease(journal, {
      expectedRevision: journal.revision, attemptId: RECOVERY_ATTEMPT_ID,
      now: ++now, leaseExpiresAt: fixture.now + 250_000,
    });
    journal = recordCustomerGatewayWorkersDevNotApplied(journal, {
      expectedRevision: journal.revision, attemptId: RECOVERY_ATTEMPT_ID,
      now: ++now, enabled: false, locator: { enabled: true, previewsEnabled: false },
    });
    await expect(requireUninstallJournal(structuredClone(journal))).resolves.toEqual(journal);
    journal = await prepareCustomerGatewayWorkersDevDisable(journal, {
      expectedRevision: journal.revision, attemptId: RECOVERY_ATTEMPT_ID, now: ++now,
    });
    journal = await armCustomerGatewayWorkersDev(journal, {
      expectedRevision: journal.revision, attemptId: RECOVERY_ATTEMPT_ID,
      now: ++now, enabled: false,
    });
    journal = submitCustomerGatewayWorkersDev(journal, {
      expectedRevision: journal.revision, attemptId: RECOVERY_ATTEMPT_ID,
      now: ++now, enabled: false, locator: { enabled: false, previewsEnabled: false },
    });
    journal = verifyCustomerGatewayWorkersDev(journal, {
      expectedRevision: journal.revision, attemptId: RECOVERY_ATTEMPT_ID,
      now: ++now, enabled: false,
    });
    const action = journal.actions.find((entry) => entry.name === 'customer_gateway_remove');
    expect(action).toMatchObject({ phase: 'verified' });
    expect(action && 'kind' in action.record && action.record.kind === 'customer_gateway_remove'
      ? requiredFixture(action.record.attempts.at(0), 'customer remove attempt').disableAttempts
        .map((entry) => [entry.approvalAttemptId, entry.phase])
      : []).toEqual([
      [UNINSTALL_ATTEMPT_ID, 'not_applied'],
      [RECOVERY_ATTEMPT_ID, 'verified'],
    ]);
    await expect(requireUninstallJournal(structuredClone(journal))).resolves.toEqual(journal);
  });

  it('settles an armed enable under the latest grant and rejects a first-disable authority rewind', async () => {
    const fixture = await cleanupReadyUninstall();
    let { journal } = fixture;
    const clock = { now: fixture.now + 10 };
    const mutation = await prepareCustomerUninstallRequest({
      installJournal: fixture.installJournal,
      uninstallPlan: fixture.uninstallPlan,
      approval: { attemptId: UNINSTALL_ATTEMPT_ID, authorizedTarget: target },
      accountWorkersSubdomain: { accountId: ACCOUNT_ID, subdomain: 'example-account' },
      nowMs: ++clock.now,
      randomBytes: (length) => Uint8Array.from({ length }, (_value, index) => index + 151),
    });
    journal = await appendCustomerGatewayRemoveAttempt(journal, {
      expectedRevision: journal.revision,
      attemptId: UNINSTALL_ATTEMPT_ID,
      now: clock.now,
      semantic: mutation.semantic,
    });
    journal = await armCustomerGatewayWorkersDev(journal, {
      expectedRevision: journal.revision,
      attemptId: UNINSTALL_ATTEMPT_ID,
      now: ++clock.now,
      enabled: true,
    });
    if (!journal.lease) throw new TypeError('lease fixture');
    clock.now = journal.lease.expiresAt;
    journal = expireUninstallJournalLease(journal, clock.now);
    clock.now = fixture.uninstallPlan.expiresAt - 4;
    journal = (await rotateUninstallApproval(
      journal,
      fixture.installJournal,
      RECOVERY_ATTEMPT_ID,
      clock,
      fixture.uninstallPlan.expiresAt + 250_000,
    )).journal;
    journal = (await rotateUninstallApproval(
      journal,
      fixture.installJournal,
      RECOVERY_ATTEMPT_TWO,
      clock,
      fixture.uninstallPlan.expiresAt + 500_000,
    )).journal;
    journal = submitCustomerGatewayWorkersDev(journal, {
      expectedRevision: journal.revision,
      attemptId: RECOVERY_ATTEMPT_TWO,
      now: ++clock.now,
      enabled: true,
      locator: { enabled: true, previewsEnabled: false },
    });
    journal = verifyCustomerGatewayWorkersDev(journal, {
      expectedRevision: journal.revision,
      attemptId: RECOVERY_ATTEMPT_TWO,
      now: ++clock.now,
      enabled: true,
    });
    const customer = journal.actions.at(3);
    expect(customer && 'kind' in customer.record && customer.record.kind === 'customer_gateway_remove'
      ? requiredFixture(customer.record.attempts.at(0), 'customer remove attempt').enable
      : null).toMatchObject({
      phase: 'verified',
      approvalAttemptId: UNINSTALL_ATTEMPT_ID,
      submittedByAttemptId: RECOVERY_ATTEMPT_TWO,
      verifiedByAttemptId: RECOVERY_ATTEMPT_TWO,
    });
    await expect(requireUninstallJournal(structuredClone(journal))).resolves.toEqual(journal);

    journal = await prepareCustomerGatewayWorkersDevDisable(journal, {
      expectedRevision: journal.revision,
      attemptId: RECOVERY_ATTEMPT_TWO,
      now: ++clock.now,
    });
    await expect(requireUninstallJournal(structuredClone(journal))).resolves.toEqual(journal);
    const authorityRewind = structuredClone(journal);
    const authorityRewindDisable = firstCustomerRemoveAttempt(authorityRewind).disableAttempts[0];
    if (!authorityRewindDisable) throw new TypeError('workers.dev disable fixture missing');
    Object.defineProperty(authorityRewindDisable, 'approvalAttemptId', {
      value: RECOVERY_ATTEMPT_ID,
    });
    await expect(requireUninstallJournal(authorityRewind)).rejects.toMatchObject({
      code: 'session_invalid',
    });
  });

  it('settles an armed disable under a fresh grant without replaying customer cleanup', async () => {
    const fixture = await customerRemovedBridgeEnabled();
    let { journal } = fixture;
    const { clock } = fixture;
    journal = await prepareCustomerGatewayWorkersDevDisable(journal, {
      expectedRevision: journal.revision,
      attemptId: UNINSTALL_ATTEMPT_ID,
      now: ++clock.now,
    });
    journal = await armCustomerGatewayWorkersDev(journal, {
      expectedRevision: journal.revision,
      attemptId: UNINSTALL_ATTEMPT_ID,
      now: ++clock.now,
      enabled: false,
    });
    if (!journal.lease) throw new TypeError('lease fixture');
    clock.now = journal.lease.expiresAt;
    journal = expireUninstallJournalLease(journal, clock.now);
    clock.now = fixture.uninstallPlan.expiresAt - 4;
    journal = (await rotateUninstallApproval(
      journal,
      fixture.installJournal,
      RECOVERY_ATTEMPT_ID,
      clock,
      fixture.uninstallPlan.expiresAt + 250_000,
    )).journal;
    clock.now = fixture.uninstallPlan.expiresAt;
    journal = submitCustomerGatewayWorkersDev(journal, {
      expectedRevision: journal.revision,
      attemptId: RECOVERY_ATTEMPT_ID,
      now: ++clock.now,
      enabled: false,
      locator: { enabled: false, previewsEnabled: false },
    });
    journal = verifyCustomerGatewayWorkersDev(journal, {
      expectedRevision: journal.revision,
      attemptId: RECOVERY_ATTEMPT_ID,
      now: ++clock.now,
      enabled: false,
    });
    const customer = journal.actions.at(3);
    expect(customer).toMatchObject({ phase: 'verified' });
    expect(customer && 'kind' in customer.record && customer.record.kind === 'customer_gateway_remove'
      ? requiredFixture(
          requiredFixture(customer.record.attempts.at(0), 'customer remove attempt').disableAttempts.at(0),
          'workers.dev disable attempt',
        )
      : null).toMatchObject({
      phase: 'verified',
      approvalAttemptId: UNINSTALL_ATTEMPT_ID,
      submittedByAttemptId: RECOVERY_ATTEMPT_ID,
      verifiedByAttemptId: RECOVERY_ATTEMPT_ID,
    });
    await expect(requireUninstallJournal(structuredClone(journal))).resolves.toEqual(journal);

    const requestOrderRewind = structuredClone(journal);
    const persistedAttempt = firstCustomerRemoveAttempt(requestOrderRewind);
    const persistedDisable = persistedAttempt.disableAttempts[0];
    if (!persistedDisable || persistedAttempt.sendArmedAt === null) {
      throw new TypeError('workers.dev disable ordering fixture missing');
    }
    Object.defineProperty(persistedDisable, 'preparedAt', {
      value: persistedAttempt.sendArmedAt - 1,
    });
    await expect(requireUninstallJournal(requestOrderRewind)).rejects.toMatchObject({
      code: 'session_invalid',
    });
  });

  it('binds cross-grant customer request submission and verification to their exact actors', async () => {
    const { journal } = await customerRequestVerifiedAcrossGrant();
    const request = journal.actions[3];
    expect(request && 'kind' in request.record && request.record.kind === 'customer_gateway_remove'
      ? request.record.attempts[0]
      : null).toMatchObject({
      approvalAttemptId: UNINSTALL_ATTEMPT_ID,
      requestPhase: 'verified',
      submittedByAttemptId: RECOVERY_ATTEMPT_ID,
      verifiedByAttemptId: RECOVERY_ATTEMPT_ID,
    });
    await expect(requireUninstallJournal(structuredClone(journal))).resolves.toEqual(journal);

    const mutations: Array<(value: UninstallJournal) => void> = [
      (value) => Object.defineProperty(firstCustomerRemoveAttempt(value), 'submittedByAttemptId', {
        value: null,
      }),
      (value) => Object.defineProperty(firstCustomerRemoveAttempt(value), 'verifiedByAttemptId', {
        value: null,
      }),
      (value) => Object.defineProperty(firstCustomerRemoveAttempt(value), 'submittedByAttemptId', {
        value: RECOVERY_ATTEMPT_TWO,
      }),
      (value) => Object.defineProperty(firstCustomerRemoveAttempt(value), 'verifiedByAttemptId', {
        value: UNINSTALL_ATTEMPT_ID,
      }),
      (value) => {
        const approval = value.approvalHistory[1];
        if (!approval) throw new TypeError('recovery approval fixture missing');
        Object.defineProperty(firstCustomerRemoveAttempt(value), 'submittedAt', {
          value: approval.recordedAt - 1,
        });
        Object.defineProperty(customerRemoveAction(value), 'submittedAt', {
          value: approval.recordedAt - 1,
        });
      },
    ];
    for (const mutate of mutations) {
      const candidate = structuredClone(journal);
      mutate(candidate);
      await expect(requireUninstallJournal(candidate)).rejects.toMatchObject({ code: 'session_invalid' });
    }
  });

  it('replaces an unarmed customer enable under the current recovery grant only', async () => {
    const fixture = await cleanupReadyUninstall();
    let journal = fixture.journal;
    const clock = { now: fixture.now + 10 };
    const first = await prepareCustomerUninstallRequest({
      installJournal: fixture.installJournal,
      uninstallPlan: fixture.uninstallPlan,
      approval: { attemptId: UNINSTALL_ATTEMPT_ID, authorizedTarget: target },
      accountWorkersSubdomain: { accountId: ACCOUNT_ID, subdomain: 'example-account' },
      nowMs: ++clock.now,
      randomBytes: (length) => Uint8Array.from({ length }, (_value, index) => index + 221),
    });
    journal = await appendCustomerGatewayRemoveAttempt(journal, {
      expectedRevision: journal.revision, attemptId: UNINSTALL_ATTEMPT_ID,
      now: clock.now, semantic: first.semantic,
    });
    if (!journal.lease) throw new TypeError('lease fixture');
    clock.now = journal.lease.expiresAt;
    journal = expireUninstallJournalLease(journal, clock.now);
    const rotated = await rotateUninstallApproval(
      journal,
      fixture.installJournal,
      RECOVERY_ATTEMPT_ID,
      clock,
      fixture.uninstallPlan.expiresAt + 250_000,
    );
    const replacement = await prepareCustomerUninstallRequest({
      installJournal: fixture.installJournal,
      uninstallPlan: rotated.plan,
      approval: { attemptId: RECOVERY_ATTEMPT_ID, authorizedTarget: target },
      accountWorkersSubdomain: { accountId: ACCOUNT_ID, subdomain: 'example-account' },
      nowMs: ++clock.now,
      randomBytes: (length) => Uint8Array.from({ length }, (_value, index) => index + 231),
    });
    journal = await replacePreparedCustomerGatewayRemoveAttempt(rotated.journal, {
      expectedRevision: rotated.journal.revision,
      attemptId: RECOVERY_ATTEMPT_ID,
      now: clock.now,
      semantic: replacement.semantic,
    });
    const action = journal.actions[3];
    expect(action && 'kind' in action.record && action.record.kind === 'customer_gateway_remove'
      ? action.record.attempts.map((entry) => [entry.approvalAttemptId, entry.semantic.requestId])
      : []).toEqual([[RECOVERY_ATTEMPT_ID, replacement.semantic.requestId]]);
    await expect(requireUninstallJournal(structuredClone(journal))).resolves.toEqual(journal);

    const originRewind = structuredClone(journal);
    const persisted = firstCustomerRemoveAttempt(originRewind);
    Object.defineProperties(persisted, {
      approvalAttemptId: { value: UNINSTALL_ATTEMPT_ID },
      semantic: { value: structuredClone(first.semantic) },
    });
    Object.defineProperty(persisted.enable, 'approvalAttemptId', {
      value: UNINSTALL_ATTEMPT_ID,
    });
    await expect(requireUninstallJournal(originRewind)).rejects.toMatchObject({ code: 'session_invalid' });

    journal = await armCustomerGatewayWorkersDev(journal, {
      expectedRevision: journal.revision,
      attemptId: RECOVERY_ATTEMPT_ID,
      now: ++clock.now,
      enabled: true,
    });
    await expect(replacePreparedCustomerGatewayRemoveAttempt(journal, {
      expectedRevision: journal.revision,
      attemptId: RECOVERY_ATTEMPT_ID,
      now: ++clock.now,
      semantic: replacement.semantic,
    })).rejects.toMatchObject({ code: 'session_conflict' });
    journal = submitCustomerGatewayWorkersDev(journal, {
      expectedRevision: journal.revision,
      attemptId: RECOVERY_ATTEMPT_ID,
      now: ++clock.now,
      enabled: true,
      locator: { enabled: true, previewsEnabled: false },
    });
    journal = verifyCustomerGatewayWorkersDev(journal, {
      expectedRevision: journal.revision,
      attemptId: RECOVERY_ATTEMPT_ID,
      now: ++clock.now,
      enabled: true,
    });
    await expect(prepareCustomerGatewayWorkersDevDisable(journal, {
      expectedRevision: journal.revision,
      attemptId: RECOVERY_ATTEMPT_ID,
      now: ++clock.now,
    })).rejects.toMatchObject({ code: 'session_conflict' });

    const prematureDisable = structuredClone(journal);
    const persistedAction = customerRemoveAction(prematureDisable);
    const persistedAttempt = firstCustomerRemoveAttempt(prematureDisable);
    const preparedAt = ++clock.now;
    const unexpectedDisable: UninstallWorkersDevMutation = {
      schemaVersion: 1,
      kind: 'uninstall_workers_dev',
      approvalAttemptId: RECOVERY_ATTEMPT_ID,
      accountId: ACCOUNT_ID,
      workerName,
      uninstallCycleId: UNINSTALL_CYCLE_ID,
      enabled: false,
      previewsEnabled: false,
      requestHash: await hash({ enabled: false, previews_enabled: false }),
      phase: 'prepared',
      locator: null,
      preparedAt,
      sendArmedAt: null,
      submittedAt: null,
      submittedByAttemptId: null,
      verifiedAt: null,
      verifiedByAttemptId: null,
    };
    Object.defineProperty(persistedAttempt, 'disableAttempts', {
      value: [...persistedAttempt.disableAttempts, unexpectedDisable],
    });
    Object.defineProperties(persistedAction, {
      phase: { value: 'send_armed' },
      sendArmedAt: { value: persistedAttempt.enable.sendArmedAt },
    });
    Object.defineProperty(prematureDisable, 'updatedAt', { value: preparedAt });
    await expect(requireUninstallJournal(prematureDisable)).rejects.toMatchObject({
      code: 'session_invalid',
    });
  });

  it('replaces an unarmed workers.dev disable without replaying an armed mutation', async () => {
    const fixture = await customerRemovedBridgeEnabled();
    let { journal } = fixture;
    const { clock } = fixture;
    journal = await prepareCustomerGatewayWorkersDevDisable(journal, {
      expectedRevision: journal.revision,
      attemptId: UNINSTALL_ATTEMPT_ID,
      now: ++clock.now,
    });
    if (!journal.lease) throw new TypeError('lease fixture');
    clock.now = journal.lease.expiresAt;
    journal = expireUninstallJournalLease(journal, clock.now);
    const rotated = await rotateUninstallApproval(
      journal,
      fixture.installJournal,
      RECOVERY_ATTEMPT_ID,
      clock,
      fixture.uninstallPlan.expiresAt + 250_000,
    );
    journal = await replacePreparedCustomerGatewayWorkersDevDisable(rotated.journal, {
      expectedRevision: rotated.journal.revision,
      attemptId: RECOVERY_ATTEMPT_ID,
      now: ++clock.now,
    });
    const action = journal.actions.at(3);
    expect(action && 'kind' in action.record && action.record.kind === 'customer_gateway_remove'
      ? requiredFixture(action.record.attempts.at(0), 'customer remove attempt').disableAttempts
        .map((entry) => [entry.approvalAttemptId, entry.phase])
      : []).toEqual([[RECOVERY_ATTEMPT_ID, 'prepared']]);
    await expect(requireUninstallJournal(structuredClone(journal))).resolves.toEqual(journal);

    const originRewind = structuredClone(journal);
    const originRewindDisable = firstCustomerRemoveAttempt(originRewind).disableAttempts[0];
    if (!originRewindDisable) throw new TypeError('workers.dev disable fixture missing');
    Object.defineProperty(originRewindDisable, 'approvalAttemptId', {
      value: UNINSTALL_ATTEMPT_ID,
    });
    await expect(requireUninstallJournal(originRewind)).rejects.toMatchObject({ code: 'session_invalid' });

    journal = await armCustomerGatewayWorkersDev(journal, {
      expectedRevision: journal.revision,
      attemptId: RECOVERY_ATTEMPT_ID,
      now: ++clock.now,
      enabled: false,
    });
    await expect(replacePreparedCustomerGatewayWorkersDevDisable(journal, {
      expectedRevision: journal.revision,
      attemptId: RECOVERY_ATTEMPT_ID,
      now: ++clock.now,
    })).rejects.toMatchObject({ code: 'session_conflict' });
  });

  it('rejects a customer request armed at signed expiry in every downstream phase', async () => {
    const { journal } = await customerRequestVerifiedAcrossGrant();
    for (const requestPhase of ['send_armed', 'submitted', 'verified'] as const) {
      const candidate = structuredClone(journal);
      const action = customerRemoveAction(candidate);
      const attempt = firstCustomerRemoveAttempt(candidate);
      const expiry = attempt.semantic.expiresAt * 1_000;
      const submitted = requestPhase !== 'send_armed';
      Object.defineProperties(attempt, {
        requestPhase: { value: requestPhase },
        sendArmedAt: { value: expiry },
        submittedAt: { value: submitted ? expiry + 1 : null },
        submittedByAttemptId: { value: submitted ? RECOVERY_ATTEMPT_ID : null },
        verifiedAt: { value: requestPhase === 'verified' ? expiry + 2 : null },
        verifiedByAttemptId: {
          value: requestPhase === 'verified' ? RECOVERY_ATTEMPT_ID : null,
        },
        locator: { value: submitted ? attempt.locator : null },
      });
      Object.defineProperties(action, {
        phase: { value: submitted ? 'submitted' : 'send_armed' },
        locator: { value: submitted ? attempt.locator : null },
        submittedAt: { value: submitted ? expiry + 1 : null },
        verifiedAt: { value: null },
      });
      Object.defineProperty(candidate, 'updatedAt', {
        value: requestPhase === 'verified' ? expiry + 2 : submitted ? expiry + 1 : expiry,
      });
      await expect(requireUninstallJournal(candidate)).rejects.toMatchObject({ code: 'session_invalid' });
    }
  });

  it('never starts a fresh customer cycle after an unknown or nonretryable request outcome', async () => {
    const runCase = async (
      recovery: null | { readonly reason: CustomerUninstallRecoveryReason; readonly retryable: boolean },
    ) => {
      const fixture = await cleanupReadyUninstall();
      let journal = fixture.journal;
      const clock = { now: fixture.now + 10 };
      const first = await prepareCustomerUninstallRequest({
        installJournal: fixture.installJournal,
        uninstallPlan: fixture.uninstallPlan,
        approval: { attemptId: UNINSTALL_ATTEMPT_ID, authorizedTarget: target },
        accountWorkersSubdomain: { accountId: ACCOUNT_ID, subdomain: 'example-account' },
        nowMs: ++clock.now,
        randomBytes: (length) => Uint8Array.from({ length }, (_value, index) => index + 171),
      });
      journal = await appendCustomerGatewayRemoveAttempt(journal, {
        expectedRevision: journal.revision, attemptId: UNINSTALL_ATTEMPT_ID,
        now: clock.now, semantic: first.semantic,
      });
      journal = await armCustomerGatewayWorkersDev(journal, {
        expectedRevision: journal.revision, attemptId: UNINSTALL_ATTEMPT_ID,
        now: ++clock.now, enabled: true,
      });
      journal = submitCustomerGatewayWorkersDev(journal, {
        expectedRevision: journal.revision, attemptId: UNINSTALL_ATTEMPT_ID,
        now: ++clock.now, enabled: true, locator: { enabled: true, previewsEnabled: false },
      });
      journal = verifyCustomerGatewayWorkersDev(journal, {
        expectedRevision: journal.revision, attemptId: UNINSTALL_ATTEMPT_ID,
        now: ++clock.now, enabled: true,
      });
      journal = armCustomerGatewayRemoveRequest(journal, {
        expectedRevision: journal.revision, attemptId: UNINSTALL_ATTEMPT_ID, now: ++clock.now,
      });
      if (recovery) {
        journal = await submitCustomerGatewayRemoveRequest(journal, {
          expectedRevision: journal.revision,
          attemptId: UNINSTALL_ATTEMPT_ID,
          now: ++clock.now,
          locator: recoveryLocator(first, recovery.reason, recovery.retryable),
        });
      }
      journal = await prepareCustomerGatewayWorkersDevDisable(journal, {
        expectedRevision: journal.revision, attemptId: UNINSTALL_ATTEMPT_ID, now: ++clock.now,
      });
      journal = await armCustomerGatewayWorkersDev(journal, {
        expectedRevision: journal.revision, attemptId: UNINSTALL_ATTEMPT_ID,
        now: ++clock.now, enabled: false,
      });
      journal = submitCustomerGatewayWorkersDev(journal, {
        expectedRevision: journal.revision, attemptId: UNINSTALL_ATTEMPT_ID,
        now: ++clock.now, enabled: false, locator: { enabled: false, previewsEnabled: false },
      });
      journal = verifyCustomerGatewayWorkersDev(journal, {
        expectedRevision: journal.revision, attemptId: UNINSTALL_ATTEMPT_ID,
        now: ++clock.now, enabled: false,
      });
      const rotated = await rotateUninstallApproval(
        journal,
        fixture.installJournal,
        RECOVERY_ATTEMPT_ID,
        clock,
        fixture.uninstallPlan.expiresAt + 100_000,
      );
      const second = await prepareCustomerUninstallRequest({
        installJournal: fixture.installJournal,
        uninstallPlan: rotated.plan,
        approval: { attemptId: RECOVERY_ATTEMPT_ID, authorizedTarget: target },
        accountWorkersSubdomain: { accountId: ACCOUNT_ID, subdomain: 'example-account' },
        nowMs: ++clock.now,
        randomBytes: (length) => Uint8Array.from({ length }, (_value, index) => index + 191),
      });
      return {
        journal: rotated.journal,
        input: {
          expectedRevision: rotated.journal.revision,
          attemptId: RECOVERY_ATTEMPT_ID,
          now: clock.now,
          semantic: second.semantic,
        },
      };
    };

    for (const recovery of [
      null,
      { reason: 'uninstall_requires_repair' as const, retryable: false },
    ]) {
      const testCase = await runCase(recovery);
      await expect(appendCustomerGatewayRemoveAttempt(testCase.journal, testCase.input))
        .rejects.toMatchObject({ code: 'session_conflict' });
    }

    const retryable = await runCase({ reason: 'uninstall_recovery_required', retryable: true });
    await expect(appendCustomerGatewayRemoveAttempt(retryable.journal, retryable.input))
      .resolves.toMatchObject({ actions: expect.any(Array) });
  });

  it('rejects binding, plan, install convergence, cycle, extra-key, and credential tampering', async () => {
    const { journal } = await initializedUninstall();
    const mutations: Array<(value: UninstallJournal) => void> = [
      (value) => Object.defineProperty(value, 'bindingHash', {
        value: `sha256:${'f'.repeat(64)}`,
      }),
      (value) => Object.defineProperty(value, 'uninstallCycleId', {
        value: `uninstall-${'f'.repeat(24)}`,
      }),
      (value) => Object.defineProperty(value.uninstallPlan, 'authorityHash', {
        value: `sha256:${'f'.repeat(64)}`,
      }),
      (value) => {
        const finalInstallAction = value.installJournal.actions.at(-1);
        if (!finalInstallAction?.locator || !('convergenceHash' in finalInstallAction.locator)) {
          throw new TypeError('install convergence fixture missing');
        }
        Object.defineProperty(finalInstallAction.locator, 'convergenceHash', {
          value: `sha256:${'f'.repeat(64)}`,
        });
      },
      (value) => {
        const firstAction = value.actions[0];
        if (!firstAction) throw new TypeError('uninstall action fixture missing');
        Object.defineProperty(firstAction.record, 'extra', { value: true, enumerable: true });
      },
      (value) => Object.defineProperty(value, 'cloudflareAccessToken', {
        value: 'must-never-persist',
        enumerable: true,
      }),
    ];
    for (const mutate of mutations) {
      const candidate = structuredClone(journal);
      mutate(candidate);
      await expect(requireUninstallJournal(candidate)).rejects.toMatchObject({ code: 'session_invalid' });
    }
  });

  it('rejects prototype, accessor, symbol, sparse-array, and secret-bearing persistence attacks without invoking code', async () => {
    const { journal } = await initializedUninstall();
    const nullPrototype = Object.assign(Object.create(null), structuredClone(journal));
    await expect(requireUninstallJournal(nullPrototype)).rejects.toMatchObject({ code: 'session_invalid' });

    let getterReads = 0;
    const accessor = structuredClone(journal);
    Object.defineProperty(accessor, 'bindingHash', {
      enumerable: true,
      get() {
        getterReads += 1;
        return journal.bindingHash;
      },
    });
    await expect(requireUninstallJournal(accessor)).rejects.toMatchObject({ code: 'session_invalid' });
    expect(getterReads).toBe(0);

    const symbol = structuredClone(journal);
    Object.defineProperty(symbol, Symbol('hidden'), { value: true, enumerable: true });
    await expect(requireUninstallJournal(symbol)).rejects.toMatchObject({ code: 'session_invalid' });

    const sparse = structuredClone(journal);
    Object.defineProperty(sparse.actions, 'length', { value: sparse.actions.length + 1 });
    await expect(requireUninstallJournal(sparse)).rejects.toMatchObject({ code: 'session_invalid' });

    const credential = structuredClone(journal);
    const firstCredentialAction = credential.actions[0];
    if (!firstCredentialAction) throw new TypeError('uninstall action fixture missing');
    Object.defineProperty(firstCredentialAction.record, 'nested', {
      value: { cloudflareAccessToken: 'must-never-be-read-or-stored' },
      enumerable: true,
    });
    await expect(requireUninstallJournal(credential)).rejects.toMatchObject({ code: 'session_invalid' });
  });

  it('enforces revision CAS, one live lease, current approval, lease limits, and parseable expiry', async () => {
    const fixture = await initializedUninstall();
    let journal = acquireUninstallJournalLease(fixture.journal, {
      expectedRevision: fixture.journal.revision,
      attemptId: UNINSTALL_ATTEMPT_ID,
      now: fixture.now + 1,
      leaseExpiresAt: fixture.now + 120_000,
    });
    expect(() => acquireUninstallJournalLease(journal, {
      expectedRevision: fixture.journal.revision,
      attemptId: UNINSTALL_ATTEMPT_ID,
      now: fixture.now + 2,
      leaseExpiresAt: fixture.now + 100_000,
    })).toThrowError(expect.objectContaining({ code: 'session_conflict' }));
    journal = releaseUninstallJournalLease(journal, {
      expectedRevision: journal.revision,
      attemptId: UNINSTALL_ATTEMPT_ID,
      now: fixture.now + 2,
    });
    expect(journal.lease).toBeNull();

    const renewed = await buildStaticUninstallPlan(
      fixture.installJournal,
      fixture.now + 3,
      fixture.now + 303_000,
    );
    journal = await appendUninstallJournalApproval(journal, renewed, {
      expectedRevision: journal.revision,
      attemptId: RECOVERY_ATTEMPT_ID,
      now: fixture.now + 4,
      approvedAt: fixture.now + 3,
      authorizedTarget: target,
    });
    journal = acquireUninstallJournalLease(journal, {
      expectedRevision: journal.revision,
      attemptId: RECOVERY_ATTEMPT_ID,
      now: fixture.now + 5,
      leaseExpiresAt: fixture.now + 100_000,
    });
    const expired = expireUninstallJournalLease(journal, fixture.now + 100_000);
    expect(expired.lease).toBeNull();
    await expect(requireUninstallJournal(structuredClone(expired))).resolves.toEqual(expired);

    const authorityRewind = structuredClone(expired);
    const rewoundApproval = authorityRewind.approvalHistory[1];
    if (!rewoundApproval) throw new TypeError('recovery approval fixture missing');
    Object.defineProperty(rewoundApproval, 'plan', { value: await buildStaticUninstallPlan(
      fixture.installJournal,
      fixture.uninstallPlan.createdAt,
      renewed.expiresAt,
    ) });
    Object.defineProperty(rewoundApproval, 'approvedAt', {
      value: fixture.uninstallPlan.createdAt,
    });
    await expect(requireUninstallJournal(authorityRewind)).rejects.toMatchObject({ code: 'session_invalid' });

    const reorderedLeases = structuredClone(expired);
    Object.defineProperty(reorderedLeases, 'leaseAttemptIds', {
      value: [...reorderedLeases.leaseAttemptIds].reverse(),
    });
    await expect(requireUninstallJournal(reorderedLeases)).rejects.toMatchObject({ code: 'session_invalid' });
  });

  it('accepts only recovery-equivalent plan renewal for the exact install-authorized target', async () => {
    const fixture = await initializedUninstall();
    const renewed = await buildStaticUninstallPlan(
      fixture.installJournal,
      fixture.now + 3,
      fixture.now + 303_000,
    );
    await expect(appendUninstallJournalApproval(fixture.journal, {
      ...renewed,
      authorityHash: `sha256:${'f'.repeat(64)}`,
    }, {
      expectedRevision: fixture.journal.revision,
      attemptId: RECOVERY_ATTEMPT_ID,
      now: fixture.now + 4,
      approvedAt: fixture.now + 3,
      authorizedTarget: target,
    })).rejects.toBeDefined();
    await expect(appendUninstallJournalApproval(fixture.journal, renewed, {
      expectedRevision: fixture.journal.revision,
      attemptId: RECOVERY_ATTEMPT_ID,
      now: fixture.now + 4,
      approvedAt: fixture.now + 3,
      authorizedTarget: { ...target, account: { ...target.account, id: 'f'.repeat(32) } },
    })).rejects.toMatchObject({ code: 'session_conflict' });
  });

  it('refreshes or discards only a preflight-only journal and rejects stale destructive arming', async () => {
    const fixture = await initializedUninstall();
    let journal = acquireUninstallJournalLease(fixture.journal, {
      expectedRevision: fixture.journal.revision,
      attemptId: UNINSTALL_ATTEMPT_ID,
      now: fixture.now + 1,
      leaseExpiresAt: fixture.now + 240_000,
    });
    journal = await refreshUninstallJournalPreflight(journal,
      await preflight(fixture.installJournal, fixture.uninstallPlan, UNINSTALL_ATTEMPT_ID, fixture.now + 2), {
        expectedRevision: journal.revision,
        attemptId: UNINSTALL_ATTEMPT_ID,
        now: fixture.now + 3,
      });
    expect(requiredFixture(journal.actions.at(0), 'uninstall preflight action').preparedAt).toBe(fixture.now + 3);
    expect(discardPreflightOnlyUninstallJournal(journal, {
      expectedRevision: journal.revision,
      attemptId: UNINSTALL_ATTEMPT_ID,
      now: fixture.now + 4,
    })).toBeNull();

    const stale = structuredClone(journal);
    const presence = {
      kind: 'admin_state_namespace_presence', accountId: ACCOUNT_ID, workerName, workerId: WORKER_ID,
      uninstallCycleId: UNINSTALL_CYCLE_ID, namespaceId: NAMESPACE_ID, namespaceName: 'namespace',
      className: 'AdminState', storage: 'sqlite', accountNamespaceCount: 1, snapshotSha256: '1'.repeat(64),
    } as const;
    const prepared = await import('../src/uninstall-journal').then(({ prepareUninstallJournalAction }) =>
      prepareUninstallJournalAction(stale, {
        expectedRevision: stale.revision,
        attemptId: UNINSTALL_ATTEMPT_ID,
        now: fixture.now + 5,
        action: 'cleanup_worker_version_create',
        record: { schemaVersion: 1, kind: 'uninstall_worker_version_create', stage: 'cleanup',
          accountId: ACCOUNT_ID, workerName, workerId: WORKER_ID, uninstallCycleId: UNINSTALL_CYCLE_ID,
          namespacePresence: presence, release: manifest.release, artifactSha256: manifest.artifact.treeSha256,
          componentSha256: manifest.components.workerCleanup.treeSha256, recovery: null },
      }));
    await expect(armUninstallJournalAction(prepared, {
      expectedRevision: prepared.revision,
      attemptId: UNINSTALL_ATTEMPT_ID,
      now: fixture.now + 61_000,
      action: 'cleanup_worker_version_create',
    })).rejects.toMatchObject({ code: 'session_conflict' });
    await expect(refreshUninstallJournalPreflight(prepared,
      await preflight(fixture.installJournal, fixture.uninstallPlan, UNINSTALL_ATTEMPT_ID, fixture.now + 6), {
        expectedRevision: prepared.revision,
        attemptId: UNINSTALL_ATTEMPT_ID,
        now: fixture.now + 7,
      })).rejects.toMatchObject({ code: 'session_conflict' });
  });

  it('keeps the successful install immutable while a purpose-bound uninstall starts in the same DO', async () => {
    const installJournal = await completeInstallJournal();
    const csrfHash = await sha256('c'.repeat(43));
    const state = new FakeState();
    const storedInstall = {
      schemaVersion: 1 as const,
      status: 'succeeded' as const,
      csrfHash,
      createdAt: NOW,
      updatedAt: installJournal.updatedAt,
      expiresAt: installJournal.sessionExpiresAt,
      selection: installJournal.selection,
      plan: installJournal.plan,
      oauthAttempt: null,
      result: {
        code: 'install_complete' as const,
        completedAt: installJournal.updatedAt,
        installationId: installJournal.installationId,
        grantRevocation: 'confirmed' as const,
      },
    };
    state.storage.values.set('deploy-session-v1', structuredClone(storedInstall));
    state.storage.values.set('install-journal-v1', structuredClone(installJournal));
    let serverNow = installJournal.updatedAt + 1;
    const object = new GatewayDeploySession(state, undefined, () => serverNow);
    const releasePin = {
      verification: 'ed25519' as const,
      keyId: verifiedRelease.keyId,
      release: manifest.release,
      artifactSha256: manifest.artifact.treeSha256,
    };
    const planResponse = await object.fetch(internalRequest('/uninstall/plan', 'POST', {
      csrfHash,
      releasePin,
      planExpiresAt: serverNow + 300_000,
      now: serverNow,
    }));
    expect(planResponse.status).toBe(200);
    const planBody = await parseResponseObject(planResponse);
    const uninstallPlan = await parseStaticUninstallPlan(
      requireResponseObject(planBody, 'uninstall').plan,
    );
    expect(uninstallPlan.installationId).toBe(installJournal.installationId);
    expect(state.storage.values.get('deploy-session-v1')).toEqual(storedInstall);

    const stateHash = await sha256('s'.repeat(43));
    const verifierHash = await sha256('v'.repeat(43));
    serverNow += 1;
    const authorized = await object.fetch(internalRequest('/uninstall/authorize', 'POST', {
      csrfHash,
      releasePin,
      approvedPlanId: uninstallPlan.planId,
      approvedPlanHash: uninstallPlan.planHash,
      attemptId: UNINSTALL_ATTEMPT_ID,
      stateHash,
      verifierHash,
      attemptExpiresAt: uninstallPlan.expiresAt,
      now: serverNow,
    }));
    expect(authorized.status).toBe(200);

    serverNow += 1;
    const wrongPurpose = await object.fetch(internalRequest('/uninstall/consume', 'POST', {
      purpose: 'install',
      attemptId: UNINSTALL_ATTEMPT_ID,
      stateHash,
      verifierHash,
      now: serverNow,
    }));
    expect(wrongPurpose.status).toBe(400);
    expect(await wrongPurpose.json()).toEqual({ error: { code: 'bad_request' } });

    const consumed = await object.fetch(internalRequest('/uninstall/consume', 'POST', {
      purpose: 'uninstall',
      attemptId: UNINSTALL_ATTEMPT_ID,
      stateHash,
      verifierHash,
      now: serverNow,
    }));
    expect(consumed.status).toBe(200);
    expect(state.storage.values.get('deploy-session-v1')).toEqual(storedInstall);

    const cycleId = `uninstall-${'6'.repeat(24)}`;
    const bindingHash = await computeUninstallJournalBindingHash({
      installJournal,
      uninstallPlan,
      uninstallCycleId: cycleId,
    });
    const initialized = await object.fetch(internalRequest('/uninstall-journal/initialize', 'POST', {
      initialization: {
        schemaVersion: 1,
        now: serverNow,
        recoverUntil: installJournal.recoverUntil,
        installJournal,
        uninstallPlan,
        uninstallCycleId: cycleId,
        bindingHash,
        freshPreflight: await preflight(installJournal, uninstallPlan, UNINSTALL_ATTEMPT_ID, serverNow),
      },
      approval: {
        attemptId: UNINSTALL_ATTEMPT_ID,
        approvedAt: serverNow,
        authorizedTarget: target,
      },
    }));
    expect(initialized.status).toBe(201);
    const publicBody = await parseResponseObject(
      await object.fetch(internalRequest('/public', 'GET')),
    );
    expect(requireResponseObject(publicBody, 'session').result).toEqual(storedInstall.result);
    expect(requireResponseObject(publicBody, 'uninstall')).toMatchObject({ status: 'uninstalling', plan: {
      planId: uninstallPlan.planId,
      planHash: uninstallPlan.planHash,
    } });
    expect(JSON.stringify(publicBody)).not.toMatch(/bindingHash|approvalHistory|leaseAttemptIds|namespaceId/iu);

    serverNow = installJournal.recoverUntil - 1;
    const tMinusOne = await object.fetch(internalRequest('/uninstall/plan', 'POST', {
      csrfHash,
      releasePin,
      planExpiresAt: installJournal.recoverUntil,
      now: serverNow,
    }));
    expect(tMinusOne.status).toBe(200);
    const renewedBody = await parseResponseObject(tMinusOne.clone());
    const renewedUninstall = requireResponseObject(renewedBody, 'uninstall');
    const renewedPlan = await parseStaticUninstallPlan(renewedUninstall.plan);
    const sessionId = 'S'.repeat(43);
    const namespace = new ForwardingDeploySessionNamespace(sessionId, {
      fetch: (request) => object.fetch(request),
    });
    const providerCalls: string[] = [];
    const transport: FetchTransport = async (input, init) => {
      const url = new URL(input instanceof Request ? input.url : input.toString());
      providerCalls.push(url.pathname);
      if (url.pathname === '/oauth2/token') return new Response(JSON.stringify({
        token_type: 'Bearer',
        access_token: 'uninstall-access-token-never-persisted',
        refresh_token: 'uninstall-refresh-token-never-persisted',
        scope: REQUIRED_OAUTH_SCOPES.join(' '),
      }));
      if (url.pathname.endsWith('/user')) return new Response(JSON.stringify({ success: true, result: {
        id: target.actor.id,
        email: target.actor.email,
      } }));
      if (url.pathname.endsWith('/accounts')) return new Response(JSON.stringify({ success: true, result: [{
        id: target.account.id,
        name: target.account.name,
      }] }));
      if (url.pathname.endsWith('/zones')) return new Response(JSON.stringify({ success: true, result: [{
        id: target.zone.id,
        name: target.zone.name,
        status: target.zone.status,
        account: { id: target.account.id },
      }] }));
      if (url.pathname === '/oauth2/revoke') {
        expect(String(init?.body ?? '')).toContain('token=');
        return new Response('{}');
      }
      return new Response('{}', { status: 404 });
    };
    let executorCalled = false;
    const executor: UninstallExecutor = {
      execute: async (input) => {
        executorCalled = true;
        expect(input.installJournal).toEqual(installJournal);
        expect(input.uninstallPlan).toEqual(renewedPlan);
        expect(input.target).toEqual(target);
        expect(input.accessToken).toBe('uninstall-access-token-never-persisted');
        expect(input.approvedAt).toBe(serverNow);
        throw new DeployError(503, 'uninstall_mutations_disabled');
      },
    };
    const worker = createGatewayDeployWorker({
      now: () => serverNow,
      releaseProvider,
      transport,
      uninstallExecutor: executor,
      capabilityPolicy: { deploy: false, uninstall: true, events: false },
    });
    const workerEnv = { ...env(), GATEWAY_DEPLOY_SESSION: namespace };
    const sessionPair = `${SESSION_COOKIE}=${sessionId}`;
    const mutationHeaders = {
      origin: PUBLIC_ORIGIN,
      'sec-fetch-site': 'same-origin',
      'content-type': 'application/json',
      'x-csrf-token': 'c'.repeat(43),
      cookie: sessionPair,
    };
    const apiPlan = await worker.fetch(new Request(`${PUBLIC_ORIGIN}/api/uninstall/plan`, {
      method: 'POST',
      headers: mutationHeaders,
    }), workerEnv, undefined);
    expect(apiPlan.status).toBe(200);
    expect(await apiPlan.json()).toMatchObject({
      capabilities: { uninstall: true },
      removal: {
        status: 'planned',
        plan: {
          planId: renewedPlan.planId,
          planHash: renewedPlan.planHash,
          writesPerformed: false,
        },
      },
    });
    const started = await worker.fetch(new Request(`${PUBLIC_ORIGIN}/api/uninstall`, {
      method: 'POST',
      headers: mutationHeaders,
      body: JSON.stringify({
        planId: renewedPlan.planId,
        planHash: renewedPlan.planHash,
      }),
    }), workerEnv, undefined);
    expect(started.status).toBe(200);
    const authorizationUrl = new URL(requireResponseString(
      await parseResponseObject(started),
      'authorizationUrl',
    ));
    const oauthPair = requiredFixture(
      (started.headers.get('set-cookie') ?? '').split(';', 1).at(0),
      'OAuth cookie pair',
    );
    expect(oauthPair.startsWith(`${OAUTH_COOKIE}=`)).toBe(true);
    const callback = await worker.fetch(new Request(
      `${PUBLIC_ORIGIN}/oauth/callback?code=authorization-code-value&state=${authorizationUrl.searchParams.get('state')}`,
      { headers: { cookie: `${sessionPair}; ${oauthPair}` } },
    ), workerEnv, undefined);
    expect(callback.status).toBe(303);
    expect(await callback.text()).toBe('');
    expect(executorCalled).toBe(true);
    expect(state.storage.values.get('deploy-session-v1')).toEqual(storedInstall);
    expect(state.storage.values.get('install-journal-v1')).toEqual(installJournal);
    expect(providerCalls.filter((path) => path === '/oauth2/revoke')).toHaveLength(2);
    expect(JSON.stringify([...state.storage.values.values()])).not.toMatch(
      /uninstall-(?:access|refresh)-token|authorization-code-value/iu,
    );
    const providerCallCount = providerCalls.length;
    const replay = await worker.fetch(new Request(
      `${PUBLIC_ORIGIN}/oauth/callback?code=authorization-code-value&state=${authorizationUrl.searchParams.get('state')}`,
      { headers: { cookie: `${sessionPair}; ${oauthPair}` } },
    ), workerEnv, undefined);
    expect(replay.status).toBe(400);
    expect(await replay.json()).toEqual({ code: 'oauth_state_invalid' });
    expect(providerCalls).toHaveLength(providerCallCount);
    const failedPublic = await parseResponseObject(
      await object.fetch(internalRequest('/public', 'GET')),
    );
    expect(requireResponseObject(failedPublic, 'uninstall').result).toEqual({
      code: 'uninstall_mutations_disabled',
      completedAt: serverNow,
    });
    serverNow = installJournal.recoverUntil;
    const atBoundary = await object.fetch(internalRequest('/uninstall/plan', 'POST', {
      csrfHash,
      releasePin,
      planExpiresAt: installJournal.recoverUntil + 1,
      now: serverNow,
    }));
    expect(atBoundary.status).toBe(410);
    expect(await atBoundary.json()).toEqual({ error: { code: 'session_expired' } });
  });
});

import { describe, expect, it, vi } from 'vitest';
import * as v from 'valibot';

import {
  CustomerUninstallNonceDerivationError,
  CustomerUninstallRequestError,
  canonicalCustomerUninstallJson,
  deriveCustomerUninstallNonce,
  parseCustomerUninstallLocator,
  parseCustomerUninstallSemanticRecord,
  prepareCustomerUninstallRequest,
  submitCustomerUninstallRequest,
  type CustomerUninstallMutationPlan,
  type RemovedInstallationReceipt,
} from '../src/customer-uninstall-request';
import {
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
  type WorkerDeploymentCreateRecord,
  type WorkerDeploymentLocator,
  type WorkerVersionCreateRecord,
  type WorkerVersionLocator,
} from '../src/install-journal';
import { boundaryObjectSchema, type BoundaryObject, type BoundaryValue } from '../src/boundary';
import { canonicalJson } from '../src/canonical-json';
import { sha256Hex } from '../src/crypto';
import { buildStaticDeployPlan, parseDeploySelection, type StaticDeployPlan } from '../src/schema';
import type { AuthorizedTarget } from '../src/cloudflare-target';
import {
  buildStaticUninstallPlan,
  parseStaticUninstallPlan,
  type StaticUninstallPlan,
} from '../src/uninstall-plan';
import { manifest, NOW, selectionInput, verifiedRelease } from './fixtures';
import { readyInstallationReceiptFixture } from './provider-neutral-installation-receipt-fixture';

const SESSION_EXPIRES_AT = NOW + 30 * 60 * 1_000;
const RECOVER_UNTIL = SESSION_EXPIRES_AT + 24 * 60 * 60 * 1_000;
const PLAN_EXPIRES_AT = NOW + 20 * 60 * 1_000;
const ATTEMPT_ID = `att_${'a'.repeat(32)}`;
const UNINSTALL_APPROVAL_ATTEMPT_ID = `att_${'b'.repeat(32)}`;
const ACCOUNT_SUBDOMAIN = Object.freeze({
  accountId: '1'.repeat(32),
  subdomain: 'example-account',
});
const TARGET: AuthorizedTarget = Object.freeze({
  actor: Object.freeze({ id: 'actor-test', email: 'owner@example.com' }),
  account: Object.freeze({ id: ACCOUNT_SUBDOMAIN.accountId, name: 'Example account' }),
  zone: Object.freeze({ id: '2'.repeat(32), name: 'example.com', status: 'active' }),
});
const WORKER_ID = '3'.repeat(32);
const APPLICATION_ID = '4'.repeat(32);
const POLICY_ID = '5'.repeat(32);
const PROVISION_VERSION_ID = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
const PROVISION_DEPLOYMENT_ID = 'cccccccc-cccc-4ccc-8ccc-cccccccccccc';
const BOOTSTRAP_VERSION_ID = '66666666-6666-4666-8666-666666666666';
const BOOTSTRAP_DEPLOYMENT_ID = '77777777-7777-4777-8777-777777777777';
const CLEAN_VERSION_ID = '88888888-8888-4888-8888-888888888888';
const CLEAN_DEPLOYMENT_ID = '99999999-9999-4999-8999-999999999999';
const DOMAIN_ID = 'a'.repeat(32);
const NAMESPACE_ID = 'e'.repeat(32);
const CUSTOMER_PLAN_ID = `plan-${'7'.repeat(24)}`;
const NONCE_KEY = base64url(Uint8Array.from({ length: 32 }, (_value, index) => index + 31));
const OAUTH_TOKEN = 'fresh-uninstall-oauth-token-never-persist';

async function hash<Value>(value: Value): Promise<string> {
  return sha256Hex(canonicalJson(value));
}

function base64url(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes))
    .replaceAll('+', '-')
    .replaceAll('/', '_')
    .replace(/=+$/u, '');
}

function boundaryObject(value: BoundaryValue): BoundaryObject {
  return v.parse(boundaryObjectSchema, value);
}

async function responseObject(response: Response): Promise<BoundaryObject> {
  return v.parse(boundaryObjectSchema, await response.json());
}

interface CapturedRequest {
  request: Request | null;
}

function workerName(plan: StaticDeployPlan): string {
  const worker = plan.managementResources.find((resource) => resource.kind === 'management_worker');
  if (!worker) throw new Error('missing worker');
  return worker.name;
}

const PLAIN_BINDING_NAMES = Object.freeze([
  'ADMIN_EMAILS',
  'ANKKA_INSTALL_ID',
  'ANKKA_GATEWAY_RELEASE',
  'ANKKA_GATEWAY_RELEASE_SHA256',
  'ANKKA_MANAGEMENT_HOSTNAME',
  'ANKKA_UPDATE_CHANNEL',
  'ANKKA_UPDATE_KEY_ID',
  'ANKKA_UPDATE_PUBLIC_KEY',
  'ANKKA_WORKERS_SUBDOMAIN',
  'ANKKA_WORKER_NAME',
  'CF_ACCESS_AUD',
  'CF_ACCESS_ISSUER',
  'CLOUDFLARE_ACCOUNT_ID',
  'CLOUDFLARE_ZONE_ID',
  'CLOUDFLARE_ZONE_NAME',
  'ZERO_TRUST_READY',
] as const);
const PLAIN_BINDINGS: WorkerVersionCreateRecord['plainTextBindingHashes'] = Object.freeze(
  PLAIN_BINDING_NAMES.map((name, index) => Object.freeze({
    name,
    valueSha256: String(index % 10).repeat(64),
  })),
);

async function workerRecord(plan: StaticDeployPlan): Promise<InstallActionRecord> {
  const requestHash = await hash({
    logpush: false,
    name: workerName(plan),
    observability: { enabled: false },
    subdomain: { enabled: false, previews_enabled: false },
    tags: ['ankka-mcp-gateway'],
    tail_consumers: [],
  });
  return {
    schemaVersion: 1,
    kind: 'worker_create',
    accountId: TARGET.account.id,
    workerName: workerName(plan),
    requestHash,
    correlationTag: `ankka-worker-sha256:${requestHash}`,
  };
}

async function applicationRecord(plan: StaticDeployPlan): Promise<InstallActionRecord> {
  const allowedIdentityProviderIds = Object.freeze(['b'.repeat(32)]);
  const intent = prepareManagementAccessApplicationIntent({
    accountId: TARGET.account.id,
    zoneId: TARGET.zone.id,
    plan,
    allowedIdentityProviderIds,
  });
  return {
    schemaVersion: 1,
    kind: 'management_access_application_create',
    accountId: TARGET.account.id,
    planId: plan.planId,
    planHash: plan.planHash,
    ownershipMarker: managementOwnershipMarker(plan),
    allowedIdentityProviderIds,
    intentHash: await hash(intent),
  };
}

async function policyRecord(plan: StaticDeployPlan): Promise<InstallActionRecord> {
  const intent = prepareManagementAdminPolicyIntent({
    accountId: TARGET.account.id,
    zoneId: TARGET.zone.id,
    applicationId: APPLICATION_ID,
    plan,
  });
  return {
    schemaVersion: 1,
    kind: 'management_admin_policy_create',
    accountId: TARGET.account.id,
    planId: plan.planId,
    planHash: plan.planHash,
    ownershipMarker: managementOwnershipMarker(plan),
    applicationId: APPLICATION_ID,
    intentHash: await hash(intent),
  };
}

async function versionRecord(
  plan: StaticDeployPlan,
  phase: 'provision' | 'bootstrap' | 'clean',
): Promise<WorkerVersionCreateRecord> {
  const releaseContract = {
    assetBinding: 'ASSETS' as const,
    assetConfig: {
      notFoundHandling: 'single-page-application' as const,
      runWorkerFirst: ['/__ankka/*', '/api/*'] as const,
    },
    bootstrapBinding: phase === 'bootstrap' ? 'present' as const : 'absent' as const,
    compatibilityDate: '2026-08-08' as const,
    compatibilityFlags: [] as const,
    durableObject: {
      binding: 'ADMIN_STATE' as const,
      className: 'AdminState' as const,
      storage: 'sqlite' as const,
    },
    exports: { AdminState: { type: 'durable-object' as const, storage: 'sqlite' as const } },
    mainModule: 'index.js' as const,
  };
  const assets = [{
    path: '/index.html',
    uploadHash: 'f'.repeat(32),
    contentType: 'text/html; charset=utf-8',
    byteLength: 1,
  }];
  const modules = [{
    name: 'index.js',
    contentType: 'application/javascript+module',
    contentSha256: 'e'.repeat(64),
    byteLength: 1,
  }];
  const requestHash = await hash({
    accountId: TARGET.account.id,
    assets: {
      binding: releaseContract.assetBinding,
      config: {
        notFoundHandling: releaseContract.assetConfig.notFoundHandling,
        runWorkerFirst: [...releaseContract.assetConfig.runWorkerFirst],
      },
      files: assets,
    },
    bindings: {
      bootstrap: releaseContract.bootstrapBinding,
      durableObject: releaseContract.durableObject,
      plainText: PLAIN_BINDINGS,
    },
    compatibilityDate: releaseContract.compatibilityDate,
    compatibilityFlags: [],
    exports: releaseContract.exports,
    mainModule: releaseContract.mainModule,
    modules,
    phase,
    workerId: WORKER_ID,
    workerName: workerName(plan),
  });
  return {
    schemaVersion: 1,
    kind: 'worker_version_create',
    phase,
    accountId: TARGET.account.id,
    workerName: workerName(plan),
    workerId: WORKER_ID,
    requestHash,
    correlationTag: `ankka-version-${phase}-sha256:${requestHash}`,
    releaseContract,
    assets,
    plainTextBindingHashes: PLAIN_BINDINGS,
    modules,
  };
}

async function versionLocator(
  plan: StaticDeployPlan,
  phase: 'provision' | 'bootstrap' | 'clean',
): Promise<WorkerVersionLocator> {
  const record = await versionRecord(plan, phase);
  const locator: WorkerVersionLocator = {
    kind: 'version',
    phase,
    accountId: TARGET.account.id,
    workerName: workerName(plan),
    workerId: WORKER_ID,
    versionId: phase === 'provision' ? PROVISION_VERSION_ID : phase === 'bootstrap' ? BOOTSTRAP_VERSION_ID : CLEAN_VERSION_ID,
    requestHash: record.requestHash,
    correlationTag: record.correlationTag,
  };
  // The provision version precedes the deployment that creates the namespace.
  return phase === 'provision' ? locator : { ...locator, namespaceId: NAMESPACE_ID };
}

async function deploymentRecord(
  plan: StaticDeployPlan,
  phase: 'provision' | 'bootstrap' | 'clean',
): Promise<WorkerDeploymentCreateRecord> {
  const versionId = phase === 'provision' ? PROVISION_VERSION_ID : phase === 'bootstrap' ? BOOTSTRAP_VERSION_ID : CLEAN_VERSION_ID;
  const requestHash = await hash({
    strategy: 'percentage',
    versions: [{ percentage: 100, version_id: versionId }],
  });
  return {
    schemaVersion: 1,
    kind: 'worker_deployment_create',
    phase,
    accountId: TARGET.account.id,
    workerName: workerName(plan),
    workerId: WORKER_ID,
    versionId,
    requestHash,
    correlationTag: `ankka-deploy-${phase}-sha256:${requestHash}`,
  };
}

async function deploymentLocator(
  plan: StaticDeployPlan,
  phase: 'provision' | 'bootstrap' | 'clean',
): Promise<WorkerDeploymentLocator> {
  const record = await deploymentRecord(plan, phase);
  return {
    kind: 'deployment',
    phase,
    accountId: TARGET.account.id,
    workerName: workerName(plan),
    workerId: WORKER_ID,
    versionId: record.versionId,
    deploymentId: phase === 'provision' ? PROVISION_DEPLOYMENT_ID : phase === 'bootstrap' ? BOOTSTRAP_DEPLOYMENT_ID : CLEAN_DEPLOYMENT_ID,
    requestHash: record.requestHash,
    correlationTag: record.correlationTag,
  };
}

async function subdomainRecord(plan: StaticDeployPlan, enabled: boolean): Promise<InstallActionRecord> {
  return {
    schemaVersion: 1,
    kind: 'bootstrap_subdomain',
    accountId: TARGET.account.id,
    workerName: workerName(plan),
    enabled,
    requestHash: await hash({ enabled, previews_enabled: false }),
  };
}

async function domainRecord(plan: StaticDeployPlan): Promise<InstallActionRecord> {
  const intent = prepareManagementCustomDomainIntent({
    accountId: TARGET.account.id,
    zoneId: TARGET.zone.id,
    plan,
  });
  return {
    schemaVersion: 1,
    kind: 'management_custom_domain_attach',
    accountId: TARGET.account.id,
    zoneId: TARGET.zone.id,
    planId: plan.planId,
    planHash: plan.planHash,
    ownershipMarker: managementOwnershipMarker(plan),
    intentHash: await hash(intent),
  };
}

async function advance(
  journal: InstallJournal,
  action: InstallActionName,
  record: InstallActionRecord,
  locator: InstallActionLocator,
  clock: { now: number },
): Promise<InstallJournal> {
  journal = await prepareInstallJournalAction(journal, {
    expectedRevision: journal.revision,
    attemptId: ATTEMPT_ID,
    now: ++clock.now,
    action,
    record,
  });
  journal = armInstallJournalAction(journal, {
    expectedRevision: journal.revision,
    attemptId: ATTEMPT_ID,
    now: ++clock.now,
    action,
  });
  journal = await submitInstallJournalAction(journal, {
    expectedRevision: journal.revision,
    attemptId: ATTEMPT_ID,
    now: ++clock.now,
    action,
    locator,
  });
  return verifyInstallJournalAction(journal, {
    expectedRevision: journal.revision,
    attemptId: ATTEMPT_ID,
    now: ++clock.now,
    action,
  });
}

async function completedInstallJournal(): Promise<InstallJournal> {
  const selection = parseDeploySelection(selectionInput);
  const plan = await buildStaticDeployPlan(selection, manifest, PLAN_EXPIRES_AT);
  const claim = await prepareCustomerBootstrapClaim({
    selection,
    target: TARGET,
    release: verifiedRelease,
    plan,
    nowMs: NOW,
    randomBytes: (length) => Uint8Array.from({ length }, (_value, index) => index + 1),
  });
  const releasePin = Object.freeze({
    verification: 'ed25519' as const,
    keyId: verifiedRelease.keyId,
    release: manifest.release,
    artifactSha256: manifest.artifact.treeSha256,
  });
  const bindingHash = await computeInstallJournalBindingHash({
    selection,
    plan,
    releasePin,
    target: TARGET,
    installationId: claim.expected.installationId,
  });
  const projection = await deriveCustomerGatewayExpectedProjection({
    selection,
    target: TARGET,
    plan,
    release: { id: manifest.release, artifactSha256: manifest.artifact.treeSha256 },
  });
  const preflightUnsigned = {
    schemaVersion: 1 as const,
    kind: 'customer_gateway_fresh_preflight' as const,
    accountId: TARGET.account.id,
    zoneId: TARGET.zone.id,
    planId: plan.planId,
    planHash: plan.planHash,
    installationId: claim.expected.installationId,
    configurationHash: projection.expected.configurationHash,
    desiredHash: projection.expected.desiredHash,
    releaseId: manifest.release,
    releaseArtifactSha256: manifest.artifact.treeSha256,
    zeroCandidateKinds: projection.resourceKinds,
    checkedAt: NOW,
    expiresAt: NOW + 30_000,
  };
  let journal = await createInstallJournal({
    schemaVersion: 1,
    now: NOW,
    recoverUntil: RECOVER_UNTIL,
    selection,
    plan,
    releasePin,
    target: TARGET,
    installationId: claim.expected.installationId,
    bindingHash,
    gatewayFreshPreflight: {
      ...preflightUnsigned,
      attestationHash: `sha256:${await hash(preflightUnsigned)}`,
    },
  }, selection, plan, SESSION_EXPIRES_AT, { attemptId: ATTEMPT_ID, approvedAt: NOW });
  const clock = { now: NOW };
  journal = acquireInstallJournalLease(journal, {
    expectedRevision: journal.revision,
    attemptId: ATTEMPT_ID,
    now: ++clock.now,
    leaseExpiresAt: clock.now + (5 * 60 * 1_000),
  });
  journal = await advance(journal, 'worker_create', await workerRecord(plan), {
    kind: 'worker',
    accountId: TARGET.account.id,
    workerName: workerName(plan),
    workerId: WORKER_ID,
  }, clock);
  journal = await advance(journal, 'management_access_application_create', await applicationRecord(plan), {
    applicationId: APPLICATION_ID,
    aud: 'audience-abcdefghijklmnop',
  }, clock);
  journal = await advance(journal, 'management_admin_policy_create', await policyRecord(plan), {
    policyId: POLICY_ID,
  }, clock);
  journal = await advance(
    journal,
    'provision_worker_version_create',
    await versionRecord(plan, 'provision'),
    await versionLocator(plan, 'provision'),
    clock,
  );
  journal = await advance(
    journal,
    'provision_worker_deployment_create',
    await deploymentRecord(plan, 'provision'),
    await deploymentLocator(plan, 'provision'),
    clock,
  );
  journal = await advance(
    journal,
    'bootstrap_worker_version_create',
    await versionRecord(plan, 'bootstrap'),
    await versionLocator(plan, 'bootstrap'),
    clock,
  );
  journal = await advance(
    journal,
    'bootstrap_worker_deployment_create',
    await deploymentRecord(plan, 'bootstrap'),
    await deploymentLocator(plan, 'bootstrap'),
    clock,
  );
  journal = await advance(
    journal,
    'bootstrap_subdomain_enable',
    await subdomainRecord(plan, true),
    { enabled: true, previewsEnabled: false },
    clock,
  );

  const enable = journal.actions.find((action) => action.name === 'bootstrap_subdomain_enable');
  if (!enable || enable.record.kind !== 'bootstrap_subdomain' || !enable.locator || !('enabled' in enable.locator)) {
    throw new Error('enable missing');
  }
  const bootstrapClaim = await prepareCustomerBootstrapClaim({
    selection,
    target: TARGET,
    release: verifiedRelease,
    plan,
    nowMs: ++clock.now,
    randomBytes: (length) => Uint8Array.from({ length }, (_value, index) => index + 11),
  });
  const compactClaim = {
    schemaVersion: 1 as const,
    requestId: bootstrapClaim.requestId,
    issuedAt: bootstrapClaim.issuedAt,
    expiresAt: bootstrapClaim.expiresAt,
    accountId: TARGET.account.id,
    zoneId: TARGET.zone.id,
    zoneName: TARGET.zone.name,
    accountWorkersSubdomain: ACCOUNT_SUBDOMAIN.subdomain,
    installationId: journal.installationId,
    configurationHash: bootstrapClaim.expected.configurationHash,
    desiredHash: bootstrapClaim.expected.desiredHash,
  };
  const bootstrapRecord: InstallActionRecord = {
    schemaVersion: 1,
    kind: 'customer_bootstrap_submit',
    accountId: TARGET.account.id,
    zoneId: TARGET.zone.id,
    zoneName: TARGET.zone.name,
    accountWorkersSubdomain: ACCOUNT_SUBDOMAIN.subdomain,
    installationId: journal.installationId,
    configurationHash: bootstrapClaim.expected.configurationHash,
    desiredHash: bootstrapClaim.expected.desiredHash,
    attempts: [{
      schemaVersion: 1,
      approvalAttemptId: ATTEMPT_ID,
      requestId: bootstrapClaim.requestId,
      issuedAt: bootstrapClaim.issuedAt,
      expiresAt: bootstrapClaim.expiresAt,
      claimHash: `sha256:${await hash(compactClaim)}`,
      enable: {
        schemaVersion: 1,
        approvalAttemptId: ATTEMPT_ID,
        enabled: true,
        requestHash: enable.record.requestHash,
        phase: 'verified',
        locator: enable.locator,
        preparedAt: enable.preparedAt,
        sendArmedAt: enable.sendArmedAt,
        submittedAt: enable.submittedAt,
        verifiedAt: enable.verifiedAt,
      },
      disable: null,
      phase: 'prepared',
      locator: null,
      preparedAt: clock.now,
      sendArmedAt: null,
      submittedAt: null,
      verifiedAt: null,
    }],
  };
  journal = await prepareInstallJournalAction(journal, {
    expectedRevision: journal.revision,
    attemptId: ATTEMPT_ID,
    now: clock.now,
    action: 'customer_bootstrap_submit',
    record: bootstrapRecord,
  });
  journal = armInstallJournalAction(journal, {
    expectedRevision: journal.revision,
    attemptId: ATTEMPT_ID,
    now: ++clock.now,
    action: 'customer_bootstrap_submit',
  });
  const receiptExpectation = await deriveCustomerGatewayInstallationReceiptExpectation({
    selection,
    target: TARGET,
    plan,
    release: { id: manifest.release, artifactSha256: manifest.artifact.treeSha256 },
  });
  const readyReceipt = await readyInstallationReceiptFixture(receiptExpectation, 14);
  const bootstrapLocator: InstallActionLocator = {
    schemaVersion: 1,
    status: 'ready',
    installationId: journal.installationId,
    approvedPlanId: CUSTOMER_PLAN_ID,
    configurationHash: bootstrapClaim.expected.configurationHash,
    desiredHash: bootstrapClaim.expected.desiredHash,
    settingsRevision: 1,
    release: { id: manifest.release, artifactSha256: `sha256:${manifest.artifact.treeSha256}` },
    gateway: { hostname: selection.basics.portalHostname, mcpUrl: `https://${selection.basics.portalHostname}/mcp` },
    receipt: { revision: 14, resourceCount: 7, evidence: readyReceipt },
    applyInvoked: true,
    resumed: false,
  };
  journal = await submitInstallJournalAction(journal, {
    expectedRevision: journal.revision,
    attemptId: ATTEMPT_ID,
    now: ++clock.now,
    action: 'customer_bootstrap_submit',
    locator: bootstrapLocator,
  });
  journal = verifyInstallJournalAction(journal, {
    expectedRevision: journal.revision,
    attemptId: ATTEMPT_ID,
    now: ++clock.now,
    action: 'customer_bootstrap_submit',
  });
  journal = await advance(
    journal,
    'bootstrap_subdomain_disable',
    await subdomainRecord(plan, false),
    { enabled: false, previewsEnabled: false },
    clock,
  );
  journal = await advance(
    journal,
    'clean_worker_version_create',
    await versionRecord(plan, 'clean'),
    await versionLocator(plan, 'clean'),
    clock,
  );
  journal = await advance(
    journal,
    'clean_worker_deployment_create',
    await deploymentRecord(plan, 'clean'),
    await deploymentLocator(plan, 'clean'),
    clock,
  );
  journal = await advance(journal, 'management_custom_domain_attach', await domainRecord(plan), {
    domainId: DOMAIN_ID,
  }, clock);
  const final = await prepareFinalConvergenceRecordAndLocator(journal);
  journal = await advance(journal, 'final_convergence', final.record, final.locator, clock);
  return journal;
}

async function reviewedUninstall(
  journal: InstallJournal,
  createdAt = NOW + 90_000,
  expiresAt = NOW + 690_000,
): Promise<{
  readonly uninstallPlan: Awaited<ReturnType<typeof buildStaticUninstallPlan>>;
  readonly approval: { readonly attemptId: string; readonly authorizedTarget: AuthorizedTarget };
}> {
  return {
    uninstallPlan: await buildStaticUninstallPlan(journal, createdAt, expiresAt),
    approval: {
      attemptId: UNINSTALL_APPROVAL_ATTEMPT_ID,
      authorizedTarget: TARGET,
    },
  };
}

async function rehashUninstallPlan(
  plan: StaticUninstallPlan,
  semanticPatch: Partial<StaticUninstallPlan>,
): Promise<StaticUninstallPlan> {
  const mutable = { ...structuredClone(plan), ...semanticPatch };
  const {
    planId: _planId,
    planHash: _planHash,
    createdAt,
    expiresAt,
    ...semantic
  } = mutable;
  const digest = await hash(semantic);
  return await parseStaticUninstallPlan({
    ...semantic,
    planId: `uninstall-plan-${digest.slice(0, 24)}`,
    planHash: `sha256:${digest}`,
    createdAt,
    expiresAt,
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
  return {
    ...unsigned,
    checksum: `sha256:${await hash(unsigned)}`,
  };
}

async function removedResponse(mutation: CustomerUninstallMutationPlan): Promise<Response> {
  const evidence = await removedReceipt(mutation);
  return Response.json({
    schemaVersion: 1,
    status: 'removed',
    installationId: mutation.semantic.installationId,
    configurationHash: mutation.semantic.configurationHash,
    uninstallId: `uninstall-${'d'.repeat(24)}`,
    release: mutation.semantic.release,
    receipt: { revision: evidence.revision, resourceCount: 0, evidence },
    uninstallInvoked: true,
    resumed: false,
  }, { headers: { 'cache-control': 'no-store' } });
}

describe('private customer cleanup request primitive', () => {
  it('derives a domain-separated nonce and submits one exact HMAC request to the provider-bound Worker URL', async () => {
    const journal = await completedInstallJournal();
    const review = await reviewedUninstall(journal);
    const nonce = await deriveCustomerUninstallNonce(NONCE_KEY, journal);
    await expect(deriveCustomerUninstallNonce(NONCE_KEY, structuredClone(journal))).resolves.toBe(nonce);
    const rotatedKey = base64url(Uint8Array.from({ length: 32 }, (_value, index) => 255 - index));
    await expect(deriveCustomerUninstallNonce(rotatedKey, journal)).resolves.not.toBe(nonce);
    expect(nonce).toMatch(/^[A-Za-z0-9_-]{43}$/u);
    const mutation = await prepareCustomerUninstallRequest({
      installJournal: journal,
      ...review,
      accountWorkersSubdomain: ACCOUNT_SUBDOMAIN,
      nowMs: NOW + 100_000,
      randomBytes: (length) => Uint8Array.from({ length }, (_value, index) => index + 51),
    });
    expect(mutation.semantic.requestId).toMatch(/^[A-Za-z0-9_-]{22}$/u);
    expect(mutation.semantic.expiresAt - mutation.semantic.issuedAt).toBe(300);
    expect(mutation.semantic).toMatchObject({
      uninstallPlanId: review.uninstallPlan.planId,
      uninstallPlanHash: review.uninstallPlan.planHash,
      authorityHash: review.uninstallPlan.authorityHash,
      approvalAttemptId: UNINSTALL_APPROVAL_ATTEMPT_ID,
    });
    const parsedSemantic = parseCustomerUninstallSemanticRecord(structuredClone(mutation.semantic));
    expect(parsedSemantic).toEqual(mutation.semantic);
    expect(parsedSemantic).not.toBe(mutation.semantic);
    expect(Object.isFrozen(parsedSemantic)).toBe(true);
    expect(Object.isFrozen(parsedSemantic?.release)).toBe(true);
    const serializedSemantic = JSON.stringify(mutation.semantic);
    expect(serializedSemantic).not.toContain(nonce);
    expect(serializedSemantic).not.toContain(OAUTH_TOKEN);
    expect(serializedSemantic).not.toContain(TARGET.actor.email);
    expect(serializedSemantic).not.toMatch(/"(?:body|token|nonce|signature|request|response)"/iu);

    const captured: CapturedRequest = { request: null };
    const result = await submitCustomerUninstallRequest({
      installJournal: journal,
      ...review,
      mutation,
      accountWorkersSubdomain: ACCOUNT_SUBDOMAIN,
      uninstallNonce: nonce,
      cloudflareAccessToken: OAUTH_TOKEN,
      nowMs: NOW + 100_001,
      transport: async (request) => {
        captured.request = request;
        return removedResponse(mutation);
      },
    });
    expect(result).toMatchObject({
      schemaVersion: 1,
      status: 'removed',
      requestId: mutation.semantic.requestId,
      installationId: mutation.semantic.installationId,
      configurationHash: mutation.semantic.configurationHash,
      desiredHash: mutation.semantic.desiredHash,
      installBindingHash: journal.bindingHash,
      adminStateNamespaceId: NAMESPACE_ID,
      uninstallPlanId: review.uninstallPlan.planId,
      uninstallPlanHash: review.uninstallPlan.planHash,
      authorityHash: review.uninstallPlan.authorityHash,
      approvalAttemptId: UNINSTALL_APPROVAL_ATTEMPT_ID,
      receipt: { resourceCount: 0, evidence: { state: 'removed', resources: [], pending: null } },
      uninstallInvoked: true,
      resumed: false,
    });
    expect(JSON.stringify(result)).not.toContain(OAUTH_TOKEN);
    expect(JSON.stringify(result)).not.toContain(nonce);
    const parsedLocator = await parseCustomerUninstallLocator(
      structuredClone(result),
      structuredClone(mutation.semantic),
      journal,
    );
    expect(parsedLocator).toEqual(result);
    expect(parsedLocator).not.toBe(result);
    expect(Object.isFrozen(parsedLocator)).toBe(true);
    await expect(parseCustomerUninstallLocator({ ...result, extra: true }, mutation.semantic, journal))
      .resolves.toBeNull();
    const sent = captured.request;
    if (!sent) throw new TypeError('expected captured uninstall request');
    expect(sent.url).toBe(`https://${workerName(journal.plan)}.${ACCOUNT_SUBDOMAIN.subdomain}.workers.dev/__ankka/uninstall`);
    expect(sent.method).toBe('POST');
    expect(sent.redirect).toBe('manual');
    expect(sent.credentials).toBe('omit');
    expect(sent.referrerPolicy).toBe('no-referrer');
    expect(sent.headers.get('authorization')).toBeNull();
    expect([...sent.headers.keys()].sort()).toEqual([
      'accept', 'content-type', 'x-ankka-uninstall-signature',
    ]);
    const raw = await sent.clone().text();
    const body = v.parse(boundaryObjectSchema, JSON.parse(raw));
    expect(Object.keys(body).sort()).toEqual([
      'cloudflareAccessToken', 'expected', 'expiresAt', 'issuedAt', 'release',
      'requestId', 'schemaVersion', 'target',
    ]);
    expect(body.cloudflareAccessToken).toBe(OAUTH_TOKEN);
    expect(raw).toBe(canonicalCustomerUninstallJson(body));
    const key = await crypto.subtle.importKey(
      'raw',
      Uint8Array.from(atob(`${nonce.replaceAll('-', '+').replaceAll('_', '/')}=`), (value) => value.charCodeAt(0)),
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['verify'],
    );
    const signature = v.parse(
      v.pipe(v.string(), v.regex(/^sha256=[a-f0-9]{64}$/u)),
      sent.headers.get('x-ankka-uninstall-signature'),
    );
    expect(await crypto.subtle.verify(
      'HMAC',
      key,
      Uint8Array.from(signature.slice('sha256='.length).match(/../gu) ?? [], (hex) => Number.parseInt(hex, 16)),
      new TextEncoder().encode(raw),
    )).toBe(true);
  });

  it('rejects incomplete/forged install authority, namespace drift, origin injection, and mutation tampering before transport', async () => {
    const journal = await completedInstallJournal();
    const review = await reviewedUninstall(journal);
    const nonce = await deriveCustomerUninstallNonce(NONCE_KEY, journal);
    const mutation = await prepareCustomerUninstallRequest({
      installJournal: journal,
      ...review,
      accountWorkersSubdomain: ACCOUNT_SUBDOMAIN,
      nowMs: NOW + 100_000,
      randomBytes: (length) => new Uint8Array(length).fill(9),
    });
    const transport = vi.fn();
    const incomplete = { ...structuredClone(journal), actions: journal.actions.slice(0, -1) };
    await expect(prepareCustomerUninstallRequest({
      installJournal: incomplete,
      ...review,
      accountWorkersSubdomain: ACCOUNT_SUBDOMAIN,
      nowMs: NOW + 100_000,
    })).rejects.toMatchObject({ code: 'install_authority_invalid', outcome: 'not_sent' });
    const namespaceDrift = structuredClone(journal);
    const finalAction = namespaceDrift.actions.at(-1);
    if (!finalAction?.locator) throw new TypeError('expected final install locator');
    Object.defineProperty(finalAction.locator, 'adminStateNamespaceId', {
      configurable: true,
      enumerable: true,
      value: 'f'.repeat(32),
    });
    await expect(deriveCustomerUninstallNonce(NONCE_KEY, namespaceDrift)).rejects.toBeInstanceOf(
      CustomerUninstallNonceDerivationError,
    );
    await expect(prepareCustomerUninstallRequest({
      installJournal: journal,
      ...review,
      accountWorkersSubdomain: {
        accountId: ACCOUNT_SUBDOMAIN.accountId,
        subdomain: 'evil.example.com/path',
      },
      nowMs: NOW + 100_000,
    })).rejects.toMatchObject({ code: 'origin_invalid', outcome: 'not_sent' });
    const tampered = structuredClone(mutation);
    Object.defineProperty(tampered.ephemeral.claim.expected.readyReceipt.target, 'accountId', {
      configurable: true,
      enumerable: true,
      value: 'f'.repeat(32),
    });
    await expect(submitCustomerUninstallRequest({
      installJournal: journal,
      ...review,
      mutation: tampered,
      accountWorkersSubdomain: ACCOUNT_SUBDOMAIN,
      uninstallNonce: nonce,
      cloudflareAccessToken: OAUTH_TOKEN,
      nowMs: NOW + 100_001,
      transport,
    })).rejects.toMatchObject({ code: 'install_authority_invalid', outcome: 'not_sent' });
    await expect(submitCustomerUninstallRequest({
      installJournal: journal,
      ...review,
      mutation,
      accountWorkersSubdomain: { ...ACCOUNT_SUBDOMAIN, subdomain: 'different-account' },
      uninstallNonce: nonce,
      cloudflareAccessToken: OAUTH_TOKEN,
      nowMs: NOW + 100_001,
      transport,
    })).rejects.toMatchObject({ code: 'install_authority_invalid', outcome: 'not_sent' });
    expect(transport).not.toHaveBeenCalled();
  });

  it('rejects swapped review authority, wrong grants, and semantic tampering before transport', async () => {
    const journal = await completedInstallJournal();
    const review = await reviewedUninstall(journal);
    const nonce = await deriveCustomerUninstallNonce(NONCE_KEY, journal);
    const mutation = await prepareCustomerUninstallRequest({
      installJournal: journal,
      ...review,
      accountWorkersSubdomain: ACCOUNT_SUBDOMAIN,
      nowMs: NOW + 100_000,
      randomBytes: (length) => new Uint8Array(length).fill(11),
    });
    const swappedAuthorityPlan = await rehashUninstallPlan(review.uninstallPlan, {
      authorityHash: `sha256:${'0'.repeat(64)}`,
    });
    await expect(parseStaticUninstallPlan(swappedAuthorityPlan)).resolves.toEqual(swappedAuthorityPlan);
    await expect(prepareCustomerUninstallRequest({
      installJournal: journal,
      uninstallPlan: swappedAuthorityPlan,
      approval: review.approval,
      accountWorkersSubdomain: ACCOUNT_SUBDOMAIN,
      nowMs: NOW + 100_000,
    })).rejects.toMatchObject({ code: 'install_authority_invalid', outcome: 'not_sent' });

    const actorDrift = structuredClone(TARGET);
    Object.defineProperty(actorDrift.actor, 'id', { value: 'different-actor' });
    const accountDrift = structuredClone(TARGET);
    Object.defineProperty(accountDrift.account, 'id', { value: 'f'.repeat(32) });
    const zoneDrift = structuredClone(TARGET);
    Object.defineProperty(zoneDrift.zone, 'id', { value: 'f'.repeat(32) });
    const wrongApprovals: readonly { readonly attemptId: string; readonly authorizedTarget: unknown }[] = [
      { attemptId: UNINSTALL_APPROVAL_ATTEMPT_ID, authorizedTarget: actorDrift },
      { attemptId: UNINSTALL_APPROVAL_ATTEMPT_ID, authorizedTarget: accountDrift },
      { attemptId: UNINSTALL_APPROVAL_ATTEMPT_ID, authorizedTarget: zoneDrift },
      { attemptId: `att_${'c'.repeat(32)}`, authorizedTarget: TARGET },
      { attemptId: ATTEMPT_ID, authorizedTarget: TARGET },
    ];
    const transport = vi.fn();
    for (const approval of wrongApprovals) {
      await expect(submitCustomerUninstallRequest({
        installJournal: journal,
        uninstallPlan: review.uninstallPlan,
        approval,
        mutation,
        accountWorkersSubdomain: ACCOUNT_SUBDOMAIN,
        uninstallNonce: nonce,
        cloudflareAccessToken: OAUTH_TOKEN,
        nowMs: NOW + 100_001,
        transport,
      })).rejects.toMatchObject({ code: 'install_authority_invalid', outcome: 'not_sent' });
    }
    await expect(submitCustomerUninstallRequest({
      installJournal: journal,
      uninstallPlan: swappedAuthorityPlan,
      approval: review.approval,
      mutation,
      accountWorkersSubdomain: ACCOUNT_SUBDOMAIN,
      uninstallNonce: nonce,
      cloudflareAccessToken: OAUTH_TOKEN,
      nowMs: NOW + 100_001,
      transport,
    })).rejects.toMatchObject({ code: 'install_authority_invalid', outcome: 'not_sent' });

    for (const [field, value] of [
      ['uninstallPlanId', `uninstall-plan-${'d'.repeat(24)}`],
      ['uninstallPlanHash', `sha256:${'d'.repeat(64)}`],
      ['authorityHash', `sha256:${'d'.repeat(64)}`],
      ['approvalAttemptId', `att_${'d'.repeat(32)}`],
    ] as const) {
      const tampered = structuredClone(mutation);
      Object.defineProperty(tampered.semantic, field, {
        configurable: true,
        enumerable: true,
        value,
      });
      await expect(submitCustomerUninstallRequest({
        installJournal: journal,
        ...review,
        mutation: tampered,
        accountWorkersSubdomain: ACCOUNT_SUBDOMAIN,
        uninstallNonce: nonce,
        cloudflareAccessToken: OAUTH_TOKEN,
        nowMs: NOW + 100_001,
        transport,
      })).rejects.toMatchObject({ code: 'install_authority_invalid', outcome: 'not_sent' });
    }
    const semanticWithExtra = { ...mutation.semantic, unknown: true };
    expect(parseCustomerUninstallSemanticRecord(semanticWithExtra)).toBeNull();
    const prototypeSemantic = Object.assign(Object.create({ inherited: true }), mutation.semantic);
    expect(parseCustomerUninstallSemanticRecord(prototypeSemantic)).toBeNull();
    let getterCalls = 0;
    const getterSemantic = { ...mutation.semantic };
    Object.defineProperty(getterSemantic, 'authorityHash', {
      enumerable: true,
      get: () => {
        getterCalls += 1;
        return mutation.semantic.authorityHash;
      },
    });
    expect(parseCustomerUninstallSemanticRecord(getterSemantic)).toBeNull();
    expect(getterCalls).toBe(0);
    expect(transport).not.toHaveBeenCalled();
  });

  it('accepts an equivalent renewed review and enforces the uninstall-plan T-1/T boundary', async () => {
    const journal = await completedInstallJournal();
    const review = await reviewedUninstall(journal);
    const nonce = await deriveCustomerUninstallNonce(NONCE_KEY, journal);
    const mutation = await prepareCustomerUninstallRequest({
      installJournal: journal,
      ...review,
      accountWorkersSubdomain: ACCOUNT_SUBDOMAIN,
      nowMs: NOW + 100_000,
      randomBytes: (length) => new Uint8Array(length).fill(13),
    });
    const renewed = await reviewedUninstall(journal, NOW + 110_000, NOW + 710_000);
    expect(renewed.uninstallPlan.planId).toBe(review.uninstallPlan.planId);
    expect(renewed.uninstallPlan.planHash).toBe(review.uninstallPlan.planHash);
    await expect(submitCustomerUninstallRequest({
      installJournal: journal,
      ...renewed,
      mutation,
      accountWorkersSubdomain: ACCOUNT_SUBDOMAIN,
      uninstallNonce: nonce,
      cloudflareAccessToken: OAUTH_TOKEN,
      nowMs: NOW + 110_000,
      transport: async () => removedResponse(mutation),
    })).resolves.toMatchObject({ status: 'removed' });

    const boundary = NOW + 200_000;
    const boundedReview = await reviewedUninstall(journal, NOW + 90_000, boundary);
    const boundedMutation = await prepareCustomerUninstallRequest({
      installJournal: journal,
      ...boundedReview,
      accountWorkersSubdomain: ACCOUNT_SUBDOMAIN,
      nowMs: boundary - 1,
      randomBytes: (length) => new Uint8Array(length).fill(15),
    });
    expect(boundedMutation.semantic.expiresAt * 1_000).toBe(boundary);
    await expect(prepareCustomerUninstallRequest({
      installJournal: journal,
      ...boundedReview,
      accountWorkersSubdomain: ACCOUNT_SUBDOMAIN,
      nowMs: boundary,
    })).rejects.toMatchObject({ code: 'request_expired', outcome: 'not_sent' });
    const staleTransport = vi.fn();
    await expect(submitCustomerUninstallRequest({
      installJournal: journal,
      ...boundedReview,
      mutation: boundedMutation,
      accountWorkersSubdomain: ACCOUNT_SUBDOMAIN,
      uninstallNonce: nonce,
      cloudflareAccessToken: OAUTH_TOKEN,
      nowMs: boundary,
      transport: staleTransport,
    })).rejects.toMatchObject({ code: 'request_expired', outcome: 'not_sent' });
    expect(staleTransport).not.toHaveBeenCalled();
  });

  it('accepts only exact recovery envelopes and exact checksum-bound zero-resource tombstones', async () => {
    const journal = await completedInstallJournal();
    const review = await reviewedUninstall(journal);
    const nonce = await deriveCustomerUninstallNonce(NONCE_KEY, journal);
    const mutation = await prepareCustomerUninstallRequest({
      installJournal: journal,
      ...review,
      accountWorkersSubdomain: ACCOUNT_SUBDOMAIN,
      nowMs: NOW + 100_000,
      randomBytes: (length) => new Uint8Array(length).fill(7),
    });
    const recovery = await submitCustomerUninstallRequest({
      installJournal: journal,
      ...review,
      mutation,
      accountWorkersSubdomain: ACCOUNT_SUBDOMAIN,
      uninstallNonce: nonce,
      cloudflareAccessToken: OAUTH_TOKEN,
      nowMs: NOW + 100_001,
      transport: async () => Response.json({
        schemaVersion: 1,
        error: 'uninstall_recovery_required',
        retryable: true,
      }, { status: 409 }),
    });
    expect(recovery).toMatchObject({
      status: 'recovery_required',
      reason: 'uninstall_recovery_required',
      freshGrantRequired: true,
      requestId: mutation.semantic.requestId,
      adminStateNamespaceId: NAMESPACE_ID,
    });
    await expect(parseCustomerUninstallLocator(
      structuredClone(recovery),
      mutation.semantic,
      journal,
    )).resolves.toEqual(recovery);

    const invalidRecovery = async () => submitCustomerUninstallRequest({
      installJournal: journal,
      ...review,
      mutation,
      accountWorkersSubdomain: ACCOUNT_SUBDOMAIN,
      uninstallNonce: nonce,
      cloudflareAccessToken: OAUTH_TOKEN,
      nowMs: NOW + 100_001,
      transport: async () => Response.json({
        schemaVersion: 1,
        error: 'uninstall_recovery_required',
        retryable: false,
      }, { status: 409 }),
    });
    await expect(invalidRecovery()).rejects.toMatchObject({
      code: 'uninstall_rejected', stage: 'response', outcome: 'rejected',
    });

    for (const flags of [
      { uninstallInvoked: true, resumed: true },
      { uninstallInvoked: false, resumed: true },
    ]) {
      const coherent = await removedResponse(mutation);
      const coherentBody = await responseObject(coherent);
      Object.assign(coherentBody, flags);
      await expect(submitCustomerUninstallRequest({
        installJournal: journal,
        ...review,
        mutation,
        accountWorkersSubdomain: ACCOUNT_SUBDOMAIN,
        uninstallNonce: nonce,
        cloudflareAccessToken: OAUTH_TOKEN,
        nowMs: NOW + 100_001,
        transport: async () => Response.json(coherentBody),
      })).resolves.toMatchObject({ status: 'removed', ...flags });
    }
    const impossible = await removedResponse(mutation);
    const impossibleBody = await responseObject(impossible);
    Object.assign(impossibleBody, { uninstallInvoked: false, resumed: false });
    await expect(submitCustomerUninstallRequest({
      installJournal: journal,
      ...review,
      mutation,
      accountWorkersSubdomain: ACCOUNT_SUBDOMAIN,
      uninstallNonce: nonce,
      cloudflareAccessToken: OAUTH_TOKEN,
      nowMs: NOW + 100_001,
      transport: async () => Response.json(impossibleBody),
    })).rejects.toMatchObject({ code: 'response_invalid', outcome: 'unknown' });

    const valid = await removedResponse(mutation);
    const body = await responseObject(valid);
    const receipt = boundaryObject(body.receipt);
    const evidence = boundaryObject(receipt.evidence);
    const receiptTarget = boundaryObject(evidence.target);
    const forgedTargetBody = {
      ...body,
      receipt: {
        ...receipt,
        evidence: {
          ...evidence,
          target: { ...receiptTarget, accountId: 'f'.repeat(32) },
        },
      },
    };
    const forgedTarget = async () => submitCustomerUninstallRequest({
      installJournal: journal,
      ...review,
      mutation,
      accountWorkersSubdomain: ACCOUNT_SUBDOMAIN,
      uninstallNonce: nonce,
      cloudflareAccessToken: OAUTH_TOKEN,
      nowMs: NOW + 100_001,
      transport: async () => Response.json(forgedTargetBody),
    });
    await expect(forgedTarget()).rejects.toMatchObject({ code: 'response_invalid', outcome: 'unknown' });

    const validAgain = await removedResponse(mutation);
    const revisionBody = await responseObject(validAgain);
    const revisionReceipt = boundaryObject(revisionBody.receipt);
    const revisionEvidence = boundaryObject(revisionReceipt.evidence);
    const forgedRevisionBody = {
      ...revisionBody,
      receipt: {
        ...revisionReceipt,
        evidence: {
          ...revisionEvidence,
          revision: v.parse(v.number(), revisionEvidence.revision) + 1,
        },
        revision: v.parse(v.number(), revisionReceipt.revision) + 1,
      },
    };
    const forgedRevision = async () => submitCustomerUninstallRequest({
      installJournal: journal,
      ...review,
      mutation,
      accountWorkersSubdomain: ACCOUNT_SUBDOMAIN,
      uninstallNonce: nonce,
      cloudflareAccessToken: OAUTH_TOKEN,
      nowMs: NOW + 100_001,
      transport: async () => Response.json(forgedRevisionBody),
    });
    await expect(forgedRevision()).rejects.toMatchObject({ code: 'response_invalid', outcome: 'unknown' });
  });

  it('treats redirects, oversized streaming bodies, transport faults, and the exact 90-second timeout as unknown outcomes', async () => {
    const journal = await completedInstallJournal();
    const review = await reviewedUninstall(journal);
    const nonce = await deriveCustomerUninstallNonce(NONCE_KEY, journal);
    const mutation = await prepareCustomerUninstallRequest({
      installJournal: journal,
      ...review,
      accountWorkersSubdomain: ACCOUNT_SUBDOMAIN,
      nowMs: NOW + 100_000,
      randomBytes: (length) => new Uint8Array(length).fill(5),
    });
    const submit = (transport: (request: Request) => Promise<Response>) => submitCustomerUninstallRequest({
      installJournal: journal,
      ...review,
      mutation,
      accountWorkersSubdomain: ACCOUNT_SUBDOMAIN,
      uninstallNonce: nonce,
      cloudflareAccessToken: OAUTH_TOKEN,
      nowMs: NOW + 100_001,
      transport,
    });
    const staleTransport = vi.fn();
    await expect(submitCustomerUninstallRequest({
      installJournal: journal,
      ...review,
      mutation,
      accountWorkersSubdomain: ACCOUNT_SUBDOMAIN,
      uninstallNonce: nonce,
      cloudflareAccessToken: OAUTH_TOKEN,
      nowMs: (mutation.semantic.expiresAt + 1) * 1_000,
      transport: staleTransport,
    })).rejects.toMatchObject({ code: 'request_expired', stage: 'validate', outcome: 'not_sent' });
    expect(staleTransport).not.toHaveBeenCalled();
    await expect(submit(async () => new Response('{}', {
      status: 302,
      headers: { location: 'https://attacker.example/' },
    }))).rejects.toMatchObject({ code: 'outcome_unknown', stage: 'response', outcome: 'unknown' });

    const oversized = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(new Uint8Array((96 * 1024) + 1));
        controller.close();
      },
    });
    await expect(submit(async () => new Response(oversized, {
      status: 200,
      headers: { 'content-type': 'application/json' },
    }))).rejects.toMatchObject({ code: 'response_invalid', outcome: 'unknown' });
    await expect(submit(async () => { throw new Error(`provider leaked ${OAUTH_TOKEN}`); }))
      .rejects.toEqual(expect.objectContaining({
        name: 'CustomerUninstallRequestError', code: 'outcome_unknown', stage: 'submit', outcome: 'unknown',
      }));

    vi.useFakeTimers();
    try {
      const observedSignals: AbortSignal[] = [];
      let markStarted: (() => void) | null = null;
      const started = new Promise<void>((resolve) => { markStarted = resolve; });
      const pending = submit(async (request) => {
        observedSignals.push(request.signal);
        markStarted?.();
        return new Promise<Response>(() => undefined);
      });
      const rejected = pending.catch((error) => error);
      await started;
      await vi.advanceTimersByTimeAsync(89_999);
      expect(observedSignals[0]?.aborted).toBe(false);
      await vi.advanceTimersByTimeAsync(1);
      await expect(rejected).resolves.toMatchObject({
        code: 'outcome_unknown', stage: 'submit', outcome: 'unknown',
      });
      expect(observedSignals[0]?.aborted).toBe(true);
    } finally {
      vi.useRealTimers();
    }
  });

  it('uses stable value-free errors for rejected nonce keys and request inputs', async () => {
    const journal = await completedInstallJournal();
    const review = await reviewedUninstall(journal);
    const secretKey = `not-a-key-${'sensitive'.repeat(20)}`;
    let caught: unknown;
    try {
      await deriveCustomerUninstallNonce(secretKey, journal);
    } catch (error) {
      caught = error;
    }
    expect(caught).toBeInstanceOf(CustomerUninstallNonceDerivationError);
    expect(JSON.stringify(caught)).not.toContain(secretKey);
    await expect(deriveCustomerUninstallNonce(base64url(new Uint8Array(32)), journal))
      .rejects.toBeInstanceOf(CustomerUninstallNonceDerivationError);
    const mutation = await prepareCustomerUninstallRequest({
      installJournal: journal,
      ...review,
      accountWorkersSubdomain: ACCOUNT_SUBDOMAIN,
      nowMs: NOW + 100_000,
      randomBytes: (length) => new Uint8Array(length).fill(3),
    });
    let requestError: unknown;
    try {
      await submitCustomerUninstallRequest({
        installJournal: journal,
        ...review,
        mutation,
        accountWorkersSubdomain: ACCOUNT_SUBDOMAIN,
        uninstallNonce: 'secret-invalid-nonce',
        cloudflareAccessToken: OAUTH_TOKEN,
        nowMs: NOW + 100_001,
        transport: vi.fn(),
      });
    } catch (error) {
      requestError = error;
    }
    expect(requestError).toBeInstanceOf(CustomerUninstallRequestError);
    expect(JSON.stringify(requestError)).not.toContain(OAUTH_TOKEN);
  });
});

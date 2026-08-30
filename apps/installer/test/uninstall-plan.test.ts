import { describe, expect, it } from 'vitest';
import * as v from 'valibot';

import {
  managementOwnershipMarker,
  prepareManagementAccessApplicationIntent,
  prepareManagementAdminPolicyIntent,
  prepareManagementCustomDomainIntent,
} from '../src/cloudflare-management-surface';
import type { AuthorizedTarget } from '../src/cloudflare-target';
import {
  deriveCustomerGatewayExpectedProjection,
  deriveCustomerGatewayInstallationReceiptExpectation,
  prepareCustomerBootstrapClaim,
} from '../src/customer-bootstrap-request';
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
  type WorkerDeploymentCreateRecord,
  type WorkerDeploymentLocator,
  type WorkerVersionCreateRecord,
  type WorkerVersionLocator,
} from '../src/install-journal';
import { canonicalJson } from '../src/canonical-json';
import { buildStaticDeployPlan, parseDeploySelection, type StaticDeployPlan } from '../src/schema';
import {
  MAX_STATIC_UNINSTALL_PLAN_TTL_MS,
  STATIC_UNINSTALL_GATEWAY_RESOURCE_ORDER,
  STATIC_UNINSTALL_OAUTH_SCOPES,
  STATIC_UNINSTALL_PROVIDER_NOTICE,
  STATIC_UNINSTALL_RESIDUE_SCOPE,
  STATIC_UNINSTALL_RETIREMENT_LIFECYCLE,
  STATIC_UNINSTALL_STEP_ORDER,
  STATIC_UNINSTALL_STEP_SUMMARIES,
  STATIC_UNINSTALL_TEMPORARY_WORKER_LIFECYCLE,
  buildStaticUninstallPlan,
  isRecoveryEquivalentUninstallPlan,
  parseStaticUninstallPlan,
  type StaticUninstallPlan,
} from '../src/uninstall-plan';
import { manifest, NOW, requiredFixture, selectionInput, verifiedRelease } from './fixtures';
import { readyInstallationReceiptFixture } from './provider-neutral-installation-receipt-fixture';

const SESSION_EXPIRES_AT = NOW + 30 * 60 * 1_000;
const RECOVER_UNTIL = SESSION_EXPIRES_AT + 24 * 60 * 60 * 1_000;
const PLAN_EXPIRES_AT = NOW + 20 * 60 * 1_000;
const ATTEMPT_ID = `att_${'a'.repeat(32)}`;
const ACCOUNT_ID = '1'.repeat(32);
const ZONE_ID = '2'.repeat(32);
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
const AUD = 'audience-abcdefghijklmnop';
const ACCOUNT_SUBDOMAIN = 'example-account';
const TARGET: AuthorizedTarget = Object.freeze({
  actor: Object.freeze({ id: 'actor-test', email: 'owner@example.com' }),
  account: Object.freeze({ id: ACCOUNT_ID, name: 'Example account' }),
  zone: Object.freeze({ id: ZONE_ID, name: 'example.com', status: 'active' }),
});

async function hash<Value>(value: Value): Promise<string> {
  return sha256Hex(canonicalJson(value));
}

function workerName(plan: StaticDeployPlan): string {
  const worker = plan.managementResources.find((resource) => resource.kind === 'management_worker');
  if (!worker) throw new TypeError('worker fixture');
  return worker.name;
}

const PLAIN_BINDING_NAMES = Object.freeze([
  'ADMIN_EMAILS',
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
    accountId: ACCOUNT_ID,
    workerName: workerName(plan),
    requestHash,
    correlationTag: `ankka-worker-sha256:${requestHash}`,
  };
}

async function applicationRecord(plan: StaticDeployPlan): Promise<InstallActionRecord> {
  const allowedIdentityProviderIds = Object.freeze(['b'.repeat(32)]);
  const intent = prepareManagementAccessApplicationIntent({
    accountId: ACCOUNT_ID,
    plan,
    allowedIdentityProviderIds,
  });
  return {
    schemaVersion: 1,
    kind: 'management_access_application_create',
    accountId: ACCOUNT_ID,
    planId: plan.planId,
    planHash: plan.planHash,
    ownershipMarker: managementOwnershipMarker(plan),
    allowedIdentityProviderIds,
    intentHash: await hash(intent),
  };
}

async function policyRecord(plan: StaticDeployPlan): Promise<InstallActionRecord> {
  const intent = prepareManagementAdminPolicyIntent({
    accountId: ACCOUNT_ID,
    applicationId: APPLICATION_ID,
    plan,
  });
  return {
    schemaVersion: 1,
    kind: 'management_admin_policy_create',
    accountId: ACCOUNT_ID,
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
    accountId: ACCOUNT_ID,
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
    accountId: ACCOUNT_ID,
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
    accountId: ACCOUNT_ID,
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
    accountId: ACCOUNT_ID,
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
    accountId: ACCOUNT_ID,
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
    accountId: ACCOUNT_ID,
    workerName: workerName(plan),
    enabled,
    requestHash: await hash({ enabled, previews_enabled: false }),
  };
}

async function domainRecord(plan: StaticDeployPlan): Promise<InstallActionRecord> {
  const intent = prepareManagementCustomDomainIntent({ accountId: ACCOUNT_ID, zoneId: ZONE_ID, plan });
  return {
    schemaVersion: 1,
    kind: 'management_custom_domain_attach',
    accountId: ACCOUNT_ID,
    zoneId: ZONE_ID,
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

async function completedInstallJournal<SelectionCandidate>(
  selectionValue: SelectionCandidate,
): Promise<InstallJournal> {
  const selection = parseDeploySelection(selectionValue);
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
    accountId: ACCOUNT_ID,
    zoneId: ZONE_ID,
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
    kind: 'worker', accountId: ACCOUNT_ID, workerName: workerName(plan), workerId: WORKER_ID,
  }, clock);
  journal = await advance(journal, 'management_access_application_create', await applicationRecord(plan), {
    applicationId: APPLICATION_ID, aud: AUD,
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
  journal = await advance(journal, 'bootstrap_subdomain_enable', await subdomainRecord(plan, true), {
    enabled: true, previewsEnabled: false,
  }, clock);

  const enable = journal.actions.find((action) => action.name === 'bootstrap_subdomain_enable');
  if (!enable || enable.record.kind !== 'bootstrap_subdomain' || !enable.locator || !('enabled' in enable.locator)) {
    throw new TypeError('enable fixture');
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
    accountId: ACCOUNT_ID,
    zoneId: ZONE_ID,
    zoneName: TARGET.zone.name,
    accountWorkersSubdomain: ACCOUNT_SUBDOMAIN,
    installationId: journal.installationId,
    configurationHash: bootstrapClaim.expected.configurationHash,
    desiredHash: bootstrapClaim.expected.desiredHash,
  };
  const bootstrapRecord: InstallActionRecord = {
    schemaVersion: 1,
    kind: 'customer_bootstrap_submit',
    accountId: ACCOUNT_ID,
    zoneId: ZONE_ID,
    zoneName: TARGET.zone.name,
    accountWorkersSubdomain: ACCOUNT_SUBDOMAIN,
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
  const resourceCount = receiptExpectation.resources.length;
  if (resourceCount !== 4 && resourceCount !== 7) {
    throw new TypeError('unexpected receipt resource count');
  }
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
    receipt: { revision: 14, resourceCount, evidence: readyReceipt },
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
  journal = await advance(journal, 'bootstrap_subdomain_disable', await subdomainRecord(plan, false), {
    enabled: false, previewsEnabled: false,
  }, clock);
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
  return advance(journal, 'final_convergence', final.record, final.locator, clock);
}

const scalarBoundarySchema = v.union([
  v.boolean(),
  v.null(),
  v.number(),
  v.string(),
  v.undefined(),
]);
const containerSchema = v.union([v.array(v.unknown()), v.object({})]);

function allFrozen<Value>(value: Value): boolean {
  if (v.is(scalarBoundarySchema, value)) return true;
  if (!v.is(containerSchema, value)) return false;
  if (!Object.isFrozen(value)) return false;
  return Object.values(value).every(allFrozen);
}

async function expectRejected(operation: Promise<unknown>, code?: string): Promise<void> {
  try {
    await operation;
    expect.fail('expected rejection');
  } catch (error) {
    if (code) expect(error).toMatchObject({ code });
  }
}

const completed = await completedInstallJournal(selectionInput);
const CREATED_AT = completed.updatedAt;

describe('provider-ID-free reviewed static uninstall plan', () => {
  it('preserves the published schema-v1 static plan identity across display-copy updates', async () => {
    const current = await buildStaticUninstallPlan(completed, CREATED_AT, CREATED_AT + 60_000);
    const semantic = {
      schemaVersion: current.schemaVersion,
      writesPerformed: current.writesPerformed,
      installationId: current.installationId,
      authorityHash: current.authorityHash,
      requiredScopes: current.requiredScopes,
      gateway: current.gateway,
      source: current.source,
      release: current.release,
      steps: current.steps.map((step) => step.kind === 'gateway_resources_remove' ? {
        ...step,
        summary: 'Remove the customer gateway resources while the reviewed temporary cleanup bridge is active.',
      } : step),
      providerNotice: current.providerNotice,
    };
    const digest = await hash(semantic);
    const legacy = {
      ...semantic,
      planId: `uninstall-plan-${digest.slice(0, 24)}`,
      planHash: `sha256:${digest}`,
      createdAt: current.createdAt,
      expiresAt: current.expiresAt,
    };
    expect(current).toEqual(legacy);
    await expect(parseStaticUninstallPlan(structuredClone(legacy))).resolves.toEqual(current);
    await expect(isRecoveryEquivalentUninstallPlan(legacy, current)).resolves.toBe(true);
  });

  it('projects a complete journal into the exact ordered public no-write contract', async () => {
    const plan = await buildStaticUninstallPlan(
      completed,
      CREATED_AT,
      CREATED_AT + MAX_STATIC_UNINSTALL_PLAN_TTL_MS,
    );
    expect(plan).toMatchObject({
      schemaVersion: 1,
      writesPerformed: false,
      installationId: completed.installationId,
      authorityHash: expect.stringMatching(/^sha256:[a-f0-9]{64}$/u),
      requiredScopes: STATIC_UNINSTALL_OAUTH_SCOPES,
      gateway: {
        name: 'Example Gateway',
        zoneName: 'example.com',
        managementHostname: 'manage.example.com',
        portalHostname: 'mcp.example.com',
        workerName: workerName(completed.plan),
      },
      source: {
        name: 'Company context',
        hostname: 'source.example.net',
        enabledTools: ['company_prepare', 'company_search'],
      },
      release: { id: manifest.release, aggregateSha256: manifest.artifact.treeSha256 },
      providerNotice: STATIC_UNINSTALL_PROVIDER_NOTICE,
    });
    expect(plan.planId).toMatch(/^uninstall-plan-[a-f0-9]{24}$/u);
    expect(plan.planHash).toMatch(/^sha256:[a-f0-9]{64}$/u);
    expect(plan.steps.map((step) => step.kind)).toEqual(STATIC_UNINSTALL_STEP_ORDER);
    expect(plan.steps.map((step) => step.order)).toEqual([1, 2, 3, 4, 5, 6, 7, 8]);
    expect(plan.steps.map((step) => step.summary)).toEqual(
      STATIC_UNINSTALL_STEP_ORDER.map((kind) => STATIC_UNINSTALL_STEP_SUMMARIES[kind]),
    );
    const cleanupStep = requiredFixture(plan.steps.at(0), 'cleanup step');
    expect(cleanupStep).toMatchObject({
      kind: 'temporary_cleanup_workers_dev_bridge',
      temporaryWorkerLifecycle: STATIC_UNINSTALL_TEMPORARY_WORKER_LIFECYCLE,
      workersDev: {
        enabledOnlyDuringCleanup: true,
        previewUrlsEnabled: false,
        disabledBeforeManagementRemoval: true,
      },
    });
    const gatewayStep = requiredFixture(plan.steps.at(1), 'gateway step');
    expect(gatewayStep.kind).toBe('gateway_resources_remove');
    if (gatewayStep.kind !== 'gateway_resources_remove') throw new TypeError('gateway step');
    expect(gatewayStep.resources).toHaveLength(7);
    expect(gatewayStep.resources.map((resource) => resource.kind)).toEqual(STATIC_UNINSTALL_GATEWAY_RESOURCE_ORDER);
    const retirementStep = requiredFixture(plan.steps.at(5), 'retirement step');
    expect(retirementStep).toMatchObject({
      kind: 'admin_state_retire',
      retirementLifecycle: STATIC_UNINSTALL_RETIREMENT_LIFECYCLE,
    });
    const finalStep = requiredFixture(plan.steps.at(7), 'final step');
    expect(finalStep).toMatchObject({
      kind: 'no_ankka_managed_residue_verify',
      scope: STATIC_UNINSTALL_RESIDUE_SCOPE,
      advancedCertificate: 'provider_retained_out_of_scope_manual',
    });
    expect(STATIC_UNINSTALL_OAUTH_SCOPES).toHaveLength(10);
    expect(allFrozen(plan)).toBe(true);
  });

  it('projects a portal-only wizard install without inventing a source', async () => {
    const portalJournal = await completedInstallJournal({ ...selectionInput, firstSource: null });
    const plan = await buildStaticUninstallPlan(
      portalJournal,
      portalJournal.updatedAt,
      portalJournal.updatedAt + MAX_STATIC_UNINSTALL_PLAN_TTL_MS,
    );
    const gatewayStep = plan.steps.find((step) => step.kind === 'gateway_resources_remove');

    expect(plan.source).toBeNull();
    expect(gatewayStep?.kind === 'gateway_resources_remove' ? gatewayStep.resources.map(({ kind }) => kind) : null)
      .toEqual(['portal', 'portal_access_application', 'portal_access_policy', 'dns_record']);
    await expect(parseStaticUninstallPlan(plan)).resolves.toEqual(plan);
  });

  it.each([228, 224])('preserves the exact %i-tool source through install authority and uninstall review', async (toolCount) => {
    const largeToolNames = Array.from(
      { length: toolCount },
      (_value, index) => `synthetic_read_${String(index + 1).padStart(3, '0')}`,
    );
    const largeJournal = await completedInstallJournal({
      ...selectionInput,
      firstSource: { ...selectionInput.firstSource, enabledTools: largeToolNames },
    });
    const plan = await buildStaticUninstallPlan(
      largeJournal,
      largeJournal.updatedAt,
      largeJournal.updatedAt + MAX_STATIC_UNINSTALL_PLAN_TTL_MS,
    );

    expect(plan.source?.enabledTools).toEqual(largeToolNames);
    await expect(parseStaticUninstallPlan(JSON.parse(JSON.stringify(plan))))
      .resolves.toEqual(plan);
  });

  it('commits the exact private install authority behind one public opaque hash', async () => {
    const plan = await buildStaticUninstallPlan(completed, CREATED_AT, CREATED_AT + 60_000);
    const final = completed.actions.at(-1)?.locator;
    if (!final || !('status' in final) || final.status !== 'converged') throw new TypeError('final fixture');
    expect(plan.authorityHash).toBe(`sha256:${await hash({
      adminStateNamespaceId: final.adminStateNamespaceId,
      installBindingHash: completed.bindingHash,
      installConvergenceHash: final.convergenceHash,
      readyReceiptChecksum: final.customerReceiptEvidence.checksum,
    })}`);
    expect(plan.authorityHash).not.toContain(ACCOUNT_ID);
    expect(plan.authorityHash).not.toContain(ZONE_ID);
    expect(plan.authorityHash).not.toContain(NAMESPACE_ID);
  });

  it('exposes no provider locator, receipt, namespace, private journal state, or email', async () => {
    const plan = await buildStaticUninstallPlan(completed, CREATED_AT, CREATED_AT + 60_000);
    const serialized = JSON.stringify(plan);
    for (const forbidden of [
      ACCOUNT_ID,
      ZONE_ID,
      WORKER_ID,
      APPLICATION_ID,
      POLICY_ID,
      BOOTSTRAP_VERSION_ID,
      BOOTSTRAP_DEPLOYMENT_ID,
      CLEAN_VERSION_ID,
      CLEAN_DEPLOYMENT_ID,
      DOMAIN_ID,
      NAMESPACE_ID,
      AUD,
      'owner@example.com',
      'admin@example.com',
      'member@example.com',
      'provider-0',
    ]) expect(serialized).not.toContain(forbidden);
    expect(serialized).not.toMatch(/accountId|zoneId|workerId|applicationId|policyId|domainId|namespace|receipt|bindingHash|approvalHistory|leaseAttemptIds/iu);
    expect(serialized).not.toMatch(/[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/u);
    expect(serialized).toContain(completed.installationId);
  });

  it('round-trips through an exact deep-freezing parser', async () => {
    const built = await buildStaticUninstallPlan(completed, CREATED_AT, CREATED_AT + 60_000);
    const parsed = await parseStaticUninstallPlan(JSON.parse(JSON.stringify(built)));
    expect(parsed).toEqual(built);
    expect(parsed).not.toBe(built);
    expect(allFrozen(parsed)).toBe(true);

    await expectRejected(parseStaticUninstallPlan({ ...built, extra: true }), 'bad_request');
    await expectRejected(parseStaticUninstallPlan({
      ...built,
      gateway: { ...built.gateway, extra: true },
    }), 'bad_request');
    await expectRejected(parseStaticUninstallPlan({
      ...built,
      steps: built.steps.map((step, index) => index === 1 ? { ...step, extra: true } : step),
    }), 'bad_request');
  });

  it('enforces T-1/T recovery boundaries and the exact ten-minute cap', async () => {
    await expect(buildStaticUninstallPlan(
      completed,
      CREATED_AT,
      CREATED_AT + MAX_STATIC_UNINSTALL_PLAN_TTL_MS,
    )).resolves.toMatchObject({ expiresAt: CREATED_AT + MAX_STATIC_UNINSTALL_PLAN_TTL_MS });
    await expectRejected(buildStaticUninstallPlan(
      completed,
      CREATED_AT,
      CREATED_AT + MAX_STATIC_UNINSTALL_PLAN_TTL_MS + 1,
    ), 'session_conflict');
    await expect(buildStaticUninstallPlan(
      completed,
      completed.recoverUntil - 1,
      completed.recoverUntil,
    )).resolves.toMatchObject({ createdAt: completed.recoverUntil - 1, expiresAt: completed.recoverUntil });
    await expectRejected(buildStaticUninstallPlan(
      completed,
      completed.recoverUntil,
      completed.recoverUntil + 1,
    ), 'session_conflict');
    await expectRejected(buildStaticUninstallPlan(
      completed,
      completed.recoverUntil - 1,
      completed.recoverUntil + 1,
    ), 'session_conflict');
    await expectRejected(buildStaticUninstallPlan(completed, CREATED_AT, CREATED_AT), 'session_conflict');
    await expectRejected(buildStaticUninstallPlan(completed, CREATED_AT - 1, CREATED_AT + 1), 'session_conflict');
  });

  it('keeps plan identity invariant across an authorized timestamp renewal', async () => {
    const first = await buildStaticUninstallPlan(completed, CREATED_AT, CREATED_AT + 60_000);
    const renewed = await buildStaticUninstallPlan(completed, CREATED_AT + 120_000, CREATED_AT + 180_000);
    expect(renewed.planId).toBe(first.planId);
    expect(renewed.planHash).toBe(first.planHash);
    expect(renewed.createdAt).not.toBe(first.createdAt);
    expect(await isRecoveryEquivalentUninstallPlan(first, renewed)).toBe(true);
  });

  it.each([
    ['writesPerformed', (plan: StaticUninstallPlan) => ({ ...plan, writesPerformed: true })],
    ['authority', (plan: StaticUninstallPlan) => ({ ...plan, authorityHash: `sha256:${'0'.repeat(64)}` })],
    ['scope', (plan: StaticUninstallPlan) => ({ ...plan, requiredScopes: plan.requiredScopes.slice(1) })],
    ['provider notice', (plan: StaticUninstallPlan) => ({ ...plan, providerNotice: 'Certificate removed.' })],
    ['source', (plan: StaticUninstallPlan) => ({ ...plan, source: { ...plan.source, name: 'Foreign source' } })],
    ['step order', (plan: StaticUninstallPlan) => ({ ...plan, steps: [plan.steps[1], plan.steps[0], ...plan.steps.slice(2)] })],
    ['summary', (plan: StaticUninstallPlan) => ({
      ...plan,
      steps: plan.steps.map((step, index) => index === 0 ? { ...step, summary: 'Delete everything.' } : step),
    })],
    ['resource', (plan: StaticUninstallPlan) => ({
      ...plan,
      steps: plan.steps.map((step, index) => index === 1 && step.kind === 'gateway_resources_remove'
        ? { ...step, resources: step.resources.slice(1) }
        : step),
    })],
  ] as const)('rejects semantic drift in %s even when the old hash is retained', async (_name, mutate) => {
    const plan = await buildStaticUninstallPlan(completed, CREATED_AT, CREATED_AT + 60_000);
    const drifted = mutate(plan);
    await expectRejected(parseStaticUninstallPlan(drifted), 'bad_request');
    expect(await isRecoveryEquivalentUninstallPlan(plan, drifted)).toBe(false);
  });

  it('rejects an incomplete or corrupted journal and rebuilds exact final convergence authority', async () => {
    const incomplete = {
      ...structuredClone(completed),
      actions: completed.actions.slice(0, -1),
    };
    await expectRejected(buildStaticUninstallPlan(incomplete, CREATED_AT, CREATED_AT + 60_000), 'session_conflict');

    const corrupt = structuredClone(completed);
    const final = corrupt.actions.at(-1);
    if (!final?.locator) throw new TypeError('final fixture');
    Object.defineProperty(final.locator, 'workerId', { value: 'f'.repeat(32) });
    await expectRejected(buildStaticUninstallPlan(corrupt, CREATED_AT, CREATED_AT + 60_000), 'session_invalid');

    const corruptHash = structuredClone(completed);
    const finalHash = corruptHash.actions.at(-1);
    if (!finalHash || finalHash.record.kind !== 'final_convergence') throw new TypeError('final fixture');
    Object.defineProperty(finalHash.record, 'convergenceHash', {
      value: `sha256:${'0'.repeat(64)}`,
    });
    await expectRejected(buildStaticUninstallPlan(corruptHash, CREATED_AT, CREATED_AT + 60_000), 'session_invalid');
  });

  it.each([
    ['install binding', (journal: InstallJournal) => {
      Object.defineProperty(journal, 'bindingHash', { value: `sha256:${'0'.repeat(64)}` });
    }],
    ['install convergence', (journal: InstallJournal) => {
      const locator = journal.actions.at(-1)?.locator;
      if (!locator) throw new TypeError('final fixture');
      Object.defineProperty(locator, 'convergenceHash', { value: `sha256:${'0'.repeat(64)}` });
    }],
    ['ready receipt checksum', (journal: InstallJournal) => {
      const locator = journal.actions.at(-1)?.locator;
      if (!locator || !('customerReceiptEvidence' in locator)) throw new TypeError('receipt fixture');
      Object.defineProperty(locator.customerReceiptEvidence, 'checksum', {
        value: `sha256:${'0'.repeat(64)}`,
      });
    }],
    ['AdminState namespace authority', (journal: InstallJournal) => {
      const locator = journal.actions.at(-1)?.locator;
      if (!locator) throw new TypeError('namespace fixture');
      Object.defineProperty(locator, 'adminStateNamespaceId', { value: 'f'.repeat(32) });
    }],
  ] as const)('rejects mutated private %s instead of issuing a misleading review', async (_name, mutate) => {
    const journal = structuredClone(completed);
    mutate(journal);
    await expectRejected(buildStaticUninstallPlan(journal, CREATED_AT, CREATED_AT + 60_000));
  });

  it('rejects unknown prototypes, getters, cycles, and sparse arrays without invoking accessors', async () => {
    let journalGetterCalls = 0;
    const getterJournal = {};
    Object.defineProperty(getterJournal, 'schemaVersion', {
      enumerable: true,
      get: () => {
        journalGetterCalls += 1;
        return 1;
      },
    });
    await expectRejected(buildStaticUninstallPlan(getterJournal, CREATED_AT, CREATED_AT + 60_000), 'bad_request');
    expect(journalGetterCalls).toBe(0);

    const plan = await buildStaticUninstallPlan(completed, CREATED_AT, CREATED_AT + 60_000);
    const prototypePlan = Object.assign(Object.create({ inherited: true }), structuredClone(plan));
    await expectRejected(parseStaticUninstallPlan(prototypePlan), 'bad_request');

    let nestedGetterCalls = 0;
    const getterPlan = structuredClone(plan);
    Object.defineProperty(getterPlan, 'providerNotice', {
      enumerable: true,
      get: () => {
        nestedGetterCalls += 1;
        return STATIC_UNINSTALL_PROVIDER_NOTICE;
      },
    });
    await expectRejected(parseStaticUninstallPlan(getterPlan), 'bad_request');
    expect(nestedGetterCalls).toBe(0);

    const cyclic = structuredClone(plan);
    Object.defineProperty(cyclic, 'cycle', { enumerable: true, value: cyclic });
    await expectRejected(parseStaticUninstallPlan(cyclic), 'bad_request');

    const sparse = structuredClone(plan);
    const sparseSteps: (typeof plan.steps)[number][] = [];
    sparseSteps.length = 8;
    sparseSteps[0] = requiredFixture(plan.steps.at(0), 'first uninstall step');
    Object.defineProperty(sparse, 'steps', { value: sparseSteps });
    await expectRejected(parseStaticUninstallPlan(sparse), 'bad_request');
  });

  it('keeps the exact scope, notice, executor lifecycle order, and no-managed-residue boundary frozen', () => {
    expect(STATIC_UNINSTALL_OAUTH_SCOPES).toEqual([
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
    ]);
    expect(STATIC_UNINSTALL_STEP_ORDER).toEqual([
      'temporary_cleanup_workers_dev_bridge',
      'gateway_resources_remove',
      'management_custom_domain_remove',
      'management_admin_policy_remove',
      'management_access_application_remove',
      'admin_state_retire',
      'management_worker_remove',
      'no_ankka_managed_residue_verify',
    ]);
    expect(STATIC_UNINSTALL_TEMPORARY_WORKER_LIFECYCLE).toEqual([
      'cleanup_worker_version_create',
      'cleanup_worker_deployment_create',
      'workers_dev_enable',
      'gateway_resources_remove',
      'workers_dev_disable',
      'restore_clean_worker_deployment',
    ]);
    expect(STATIC_UNINSTALL_RETIREMENT_LIFECYCLE).toEqual([
      'retirement_worker_version_create',
      'retirement_worker_deployment_create',
      'admin_state_absence_prove',
    ]);
    expect(STATIC_UNINSTALL_RESIDUE_SCOPE).not.toContain('advanced_certificate');
    expect(STATIC_UNINSTALL_PROVIDER_NOTICE).toBe(
      'Cloudflare retains the Advanced Certificate after the Custom Domain is removed. It is outside Ankka\'s reviewed OAuth scope and must be reviewed or removed manually in Cloudflare.',
    );
    expect(Object.isFrozen(STATIC_UNINSTALL_OAUTH_SCOPES)).toBe(true);
    expect(Object.isFrozen(STATIC_UNINSTALL_STEP_ORDER)).toBe(true);
    expect(Object.isFrozen(STATIC_UNINSTALL_TEMPORARY_WORKER_LIFECYCLE)).toBe(true);
    expect(Object.isFrozen(STATIC_UNINSTALL_RETIREMENT_LIFECYCLE)).toBe(true);
    expect(Object.isFrozen(STATIC_UNINSTALL_RESIDUE_SCOPE)).toBe(true);
  });
});

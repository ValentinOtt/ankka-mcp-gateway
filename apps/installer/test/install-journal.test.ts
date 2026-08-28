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
import { sha256, sha256Hex } from '../src/crypto';
import { GatewayDeploySession } from '../src/durable/gateway-deploy-session';
import {
  acquireInstallJournalLease,
  appendCustomerBootstrapAttempt,
  appendInstallJournalApproval,
  armInstallJournalAction,
  computeInstallJournalBindingHash,
  createInstallJournal,
  isPartialInstallJournal,
  isRecoveryEquivalentInstallPlan,
  parsePublicInstallProgress,
  prepareFinalConvergenceRecordAndLocator,
  prepareInstallJournalAction,
  releaseInstallJournalLease,
  requireInstallJournal,
  submitInstallJournalAction,
  verifyInstallJournalAction,
  type InstallActionLocator,
  type InstallActionName,
  type InstallActionRecord,
  type InstallJournal,
} from '../src/install-journal';
import { buildStaticDeployPlan, parseDeploySelection, type StaticDeployPlan } from '../src/schema';
import type { AuthorizedTarget } from '../src/cloudflare-target';
import {
  FakeState,
  internalRequest,
  manifest,
  NOW,
  selectionInput,
  verifiedRelease,
} from './fixtures';
import { readyInstallationReceiptFixture } from './provider-neutral-installation-receipt-fixture';

const SESSION_EXPIRES_AT = NOW + 1_800_000;
const RECOVER_UNTIL = SESSION_EXPIRES_AT + 24 * 60 * 60 * 1_000;
const INITIAL_ATTEMPT = `att_${'a'.repeat(32)}`;
const RECOVERY_ATTEMPT = `att_${'b'.repeat(32)}`;
const SECOND_RECOVERY_ATTEMPT = `att_${'c'.repeat(32)}`;
const CSRF = 'c'.repeat(43);
const STATE = 's'.repeat(43);
const VERIFIER = 'v'.repeat(43);
const PROVISION_VERSION_ID = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
const PROVISION_DEPLOYMENT_ID = 'cccccccc-cccc-4ccc-8ccc-cccccccccccc';
const BOOTSTRAP_VERSION_ID = '66666666-6666-4666-8666-666666666666';
const BOOTSTRAP_DEPLOYMENT_ID = '77777777-7777-4777-8777-777777777777';
const CLEAN_VERSION_ID = '88888888-8888-4888-8888-888888888888';
const CLEAN_DEPLOYMENT_ID = '99999999-9999-4999-8999-999999999999';
const CUSTOMER_APPROVED_PLAN_ID = `plan-${'7'.repeat(24)}`;
const ADMIN_STATE_NAMESPACE_ID = 'e'.repeat(32);
const TARGET: AuthorizedTarget = Object.freeze({
  actor: Object.freeze({ id: 'actor-test', email: 'owner@example.com' }),
  account: Object.freeze({ id: '1'.repeat(32), name: 'Example account' }),
  zone: Object.freeze({ id: '2'.repeat(32), name: 'example.com', status: 'active' }),
});
const RELEASE_PIN = Object.freeze({
  verification: 'ed25519' as const,
  keyId: verifiedRelease.keyId,
  release: manifest.release,
  artifactSha256: manifest.artifact.treeSha256,
});

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function canonicalJson(value: unknown): string {
  if (value === null || typeof value === 'boolean' || typeof value === 'string' || typeof value === 'number') {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (isRecord(value)) {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(',')}}`;
  }
  throw new TypeError('not canonical');
}

async function hash(value: unknown): Promise<string> {
  return sha256Hex(canonicalJson(value));
}

async function body(response: Response): Promise<Record<string, any>> {
  return response.json() as Promise<Record<string, any>>;
}

interface InstalledFixture {
  state: FakeState;
  object: GatewayDeploySession;
  csrfHash: string;
  plan: StaticDeployPlan;
  journal: InstallJournal;
  initialization: Record<string, unknown>;
  setServerNow(value: number): void;
}

async function initializedJournal(): Promise<InstalledFixture> {
  const state = new FakeState();
  let serverNow = NOW;
  const object = new GatewayDeploySession(
    state as unknown as DurableObjectState,
    undefined,
    () => serverNow,
  );
  const csrfHash = await sha256(CSRF);
  await object.fetch(internalRequest('/initialize', 'POST', {
    csrfHash,
    createdAt: NOW,
    expiresAt: SESSION_EXPIRES_AT,
  }));
  await object.fetch(internalRequest('/selection', 'PUT', {
    csrfHash,
    selection: selectionInput,
    now: NOW + 1,
  }));
  const planResponse = await object.fetch(internalRequest('/plan', 'POST', {
    csrfHash,
    releaseManifest: manifest,
    planExpiresAt: NOW + 600_000,
    now: NOW + 2,
  }));
  const plan = (await body(planResponse)).session.plan as StaticDeployPlan;
  await object.fetch(internalRequest('/authorize', 'POST', {
    csrfHash,
    releaseManifest: manifest,
    approvedPlanId: plan.planId,
    approvedPlanHash: plan.planHash,
    attemptId: INITIAL_ATTEMPT,
    stateHash: await sha256(STATE),
    verifierHash: await sha256(VERIFIER),
    attemptExpiresAt: plan.expiresAt,
    now: NOW + 3,
  }));
  await object.fetch(internalRequest('/consume', 'POST', {
    attemptId: INITIAL_ATTEMPT,
    stateHash: await sha256(STATE),
    verifierHash: await sha256(VERIFIER),
    now: NOW + 4,
  }));
  const claim = await prepareCustomerBootstrapClaim({
    selection: parseDeploySelection(selectionInput),
    target: TARGET,
    release: verifiedRelease,
    plan,
    nowMs: NOW + 4,
    randomBytes: (length) => Uint8Array.from({ length }, (_value, index) => index + 1),
  });
  const installationId = claim.expected.installationId;
  const bindingHash = await computeInstallJournalBindingHash({
    selection: parseDeploySelection(selectionInput),
    plan,
    releasePin: RELEASE_PIN,
    target: TARGET,
    installationId,
  });
  const projection = await deriveCustomerGatewayExpectedProjection({
    selection: parseDeploySelection(selectionInput),
    target: TARGET,
    plan,
    release: { id: manifest.release, artifactSha256: manifest.artifact.treeSha256 },
  });
  const preflightCheckedAt = NOW + 4;
  const preflightUnsigned = {
    schemaVersion: 1 as const,
    kind: 'customer_gateway_fresh_preflight' as const,
    accountId: TARGET.account.id,
    zoneId: TARGET.zone.id,
    planId: plan.planId,
    planHash: plan.planHash,
    installationId,
    configurationHash: projection.expected.configurationHash,
    desiredHash: projection.expected.desiredHash,
    releaseId: manifest.release,
    releaseArtifactSha256: manifest.artifact.treeSha256,
    zeroCandidateKinds: projection.resourceKinds,
    checkedAt: preflightCheckedAt,
    expiresAt: preflightCheckedAt + 30_000,
  };
  const initialization = {
    schemaVersion: 1,
    now: NOW + 5,
    recoverUntil: RECOVER_UNTIL,
    selection: parseDeploySelection(selectionInput),
    plan,
    releasePin: RELEASE_PIN,
    target: TARGET,
    installationId,
    bindingHash,
    gatewayFreshPreflight: {
      ...preflightUnsigned,
      attestationHash: `sha256:${await hash(preflightUnsigned)}`,
    },
  };
  serverNow = NOW + 5;
  const response = await object.fetch(internalRequest('/install-journal/initialize', 'POST', initialization));
  expect(response.status).toBe(201);
  const journal = (await body(response)).journal as InstallJournal;
  return {
    state,
    object,
    csrfHash,
    plan,
    journal,
    initialization,
    setServerNow: (value: number) => { serverNow = value; },
  };
}

function workerName(plan: StaticDeployPlan): string {
  const resource = plan.managementResources.find((candidate) => candidate.kind === 'management_worker');
  if (!resource) throw new Error('worker missing');
  return resource.name;
}

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

function workerLocator(plan: StaticDeployPlan): InstallActionLocator {
  return {
    kind: 'worker',
    accountId: TARGET.account.id,
    workerName: workerName(plan),
    workerId: '3'.repeat(32),
  };
}

async function applicationRecord(plan: StaticDeployPlan): Promise<InstallActionRecord> {
  const allowedIdentityProviderIds = Object.freeze(['b'.repeat(32)]);
  const intent = prepareManagementAccessApplicationIntent({
    accountId: TARGET.account.id,
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
    applicationId: '4'.repeat(32),
    plan,
  });
  return {
    schemaVersion: 1,
    kind: 'management_admin_policy_create',
    accountId: TARGET.account.id,
    planId: plan.planId,
    planHash: plan.planHash,
    ownershipMarker: managementOwnershipMarker(plan),
    applicationId: '4'.repeat(32),
    intentHash: await hash(intent),
  };
}

const PLAIN_BINDINGS = Object.freeze([
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
].map((name, index) => Object.freeze({ name, valueSha256: (index % 10).toString().repeat(64) })));

async function versionRecord(plan: StaticDeployPlan, phase: 'provision' | 'bootstrap' | 'clean'): Promise<InstallActionRecord> {
  const releaseContract = {
    assetBinding: 'ASSETS' as const,
    assetConfig: {
      notFoundHandling: 'single-page-application' as const,
      runWorkerFirst: ['/__ankka/*', '/api/*'] as const,
    },
    bootstrapBinding: phase === 'bootstrap' ? 'present' as const : 'absent' as const,
    compatibilityDate: '2026-08-08' as const,
    compatibilityFlags: [] as const,
    durableObject: { binding: 'ADMIN_STATE' as const, className: 'AdminState' as const, storage: 'sqlite' as const },
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
    workerId: '3'.repeat(32),
    workerName: workerName(plan),
  });
  return {
    schemaVersion: 1,
    kind: 'worker_version_create',
    phase,
    accountId: TARGET.account.id,
    workerName: workerName(plan),
    workerId: '3'.repeat(32),
    requestHash,
    correlationTag: `ankka-version-${phase}-sha256:${requestHash}`,
    releaseContract,
    assets,
    plainTextBindingHashes: PLAIN_BINDINGS as any,
    modules,
  };
}

async function versionLocator(plan: StaticDeployPlan, phase: 'provision' | 'bootstrap' | 'clean'): Promise<InstallActionLocator> {
  const record = await versionRecord(plan, phase) as any;
  return {
    kind: 'version',
    phase,
    accountId: TARGET.account.id,
    workerName: workerName(plan),
    workerId: '3'.repeat(32),
    versionId: phase === 'provision' ? PROVISION_VERSION_ID : phase === 'bootstrap' ? BOOTSTRAP_VERSION_ID : CLEAN_VERSION_ID,
    requestHash: record.requestHash,
    correlationTag: record.correlationTag,
    // The provision version precedes the deployment that creates the namespace.
    ...(phase === 'provision' ? {} : { namespaceId: ADMIN_STATE_NAMESPACE_ID }),
  };
}

async function deploymentRecord(plan: StaticDeployPlan, phase: 'provision' | 'bootstrap' | 'clean'): Promise<InstallActionRecord> {
  const versionId = phase === 'provision' ? PROVISION_VERSION_ID : phase === 'bootstrap' ? BOOTSTRAP_VERSION_ID : CLEAN_VERSION_ID;
  const requestHash = await hash({ strategy: 'percentage', versions: [{ percentage: 100, version_id: versionId }] });
  return {
    schemaVersion: 1,
    kind: 'worker_deployment_create',
    phase,
    accountId: TARGET.account.id,
    workerName: workerName(plan),
    workerId: '3'.repeat(32),
    versionId,
    requestHash,
    correlationTag: `ankka-deploy-${phase}-sha256:${requestHash}`,
  };
}

async function deploymentLocator(plan: StaticDeployPlan, phase: 'provision' | 'bootstrap' | 'clean'): Promise<InstallActionLocator> {
  const record = await deploymentRecord(plan, phase) as any;
  return {
    kind: 'deployment',
    phase,
    accountId: TARGET.account.id,
    workerName: workerName(plan),
    workerId: '3'.repeat(32),
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

async function bootstrapRecord(
  fixture: InstalledFixture,
  preparedAt: number,
  approvalAttemptId = INITIAL_ATTEMPT,
  randomOffset = 1,
  cycleJournal?: InstallJournal,
): Promise<InstallActionRecord> {
  const claim = await prepareCustomerBootstrapClaim({
    selection: fixture.journal.selection,
    target: TARGET,
    release: verifiedRelease,
    plan: fixture.plan,
    nowMs: preparedAt,
    randomBytes: (length) => Uint8Array.from({ length }, (_value, index) => index + randomOffset),
  });
  const compact = {
    schemaVersion: 1 as const,
    requestId: claim.requestId,
    issuedAt: claim.issuedAt,
    expiresAt: claim.expiresAt,
    accountId: TARGET.account.id,
    zoneId: TARGET.zone.id,
    zoneName: TARGET.zone.name,
    accountWorkersSubdomain: 'account-subdomain',
    installationId: fixture.journal.installationId,
    configurationHash: claim.expected.configurationHash,
    desiredHash: claim.expected.desiredHash,
  };
  const topEnable = cycleJournal?.actions.find((action) => action.name === 'bootstrap_subdomain_enable');
  const topEnableLocator = topEnable?.locator;
  if (
    !topEnable || topEnable.record.kind !== 'bootstrap_subdomain' || topEnable.phase !== 'verified' ||
    !topEnableLocator || !('previewsEnabled' in topEnableLocator) || topEnableLocator.enabled !== true
  ) {
    throw new Error('verified cycle enable missing');
  }
  return {
    schemaVersion: 1,
    kind: 'customer_bootstrap_submit',
    accountId: compact.accountId,
    zoneId: compact.zoneId,
    zoneName: compact.zoneName,
    accountWorkersSubdomain: compact.accountWorkersSubdomain,
    installationId: compact.installationId,
    configurationHash: compact.configurationHash,
    desiredHash: compact.desiredHash,
    attempts: [{
      schemaVersion: 1,
      approvalAttemptId,
      requestId: compact.requestId,
      issuedAt: compact.issuedAt,
      expiresAt: compact.expiresAt,
      claimHash: `sha256:${await hash(compact)}`,
      enable: {
        schemaVersion: 1,
        approvalAttemptId,
        enabled: true,
        requestHash: topEnable.record.requestHash,
        phase: 'verified',
        locator: topEnableLocator,
        preparedAt: topEnable.preparedAt,
        sendArmedAt: topEnable.sendArmedAt,
        submittedAt: topEnable.submittedAt,
        verifiedAt: topEnable.verifiedAt,
      },
      disable: null,
      phase: 'prepared',
      locator: null,
      preparedAt,
      sendArmedAt: null,
      submittedAt: null,
      verifiedAt: null,
    }],
  };
}

async function bootstrapLocator(
  fixture: InstalledFixture,
  record: InstallActionRecord,
  applyInvoked = true,
  resumed = false,
): Promise<InstallActionLocator> {
  const bootstrap = record as any;
  const expectation = await deriveCustomerGatewayInstallationReceiptExpectation({
    selection: fixture.journal.selection,
    target: TARGET,
    plan: fixture.plan,
    release: { id: manifest.release, artifactSha256: manifest.artifact.treeSha256 },
  });
  const evidence = await readyInstallationReceiptFixture(expectation, 1);
  return {
    schemaVersion: 1,
    status: 'ready',
    installationId: fixture.journal.installationId,
    approvedPlanId: CUSTOMER_APPROVED_PLAN_ID,
    configurationHash: bootstrap.configurationHash,
    desiredHash: bootstrap.desiredHash,
    settingsRevision: 1,
    release: { id: manifest.release, artifactSha256: `sha256:${manifest.artifact.treeSha256}` },
    gateway: { hostname: 'mcp.example.com', mcpUrl: 'https://mcp.example.com/mcp' },
    receipt: { revision: 1, resourceCount: 7, evidence },
    applyInvoked,
    resumed,
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
  attemptId: string,
  action: InstallActionName,
  record: InstallActionRecord,
  locator: InstallActionLocator,
  clock: { now: number },
): Promise<InstallJournal> {
  journal = await prepareInstallJournalAction(journal, {
    expectedRevision: journal.revision, attemptId, now: ++clock.now, action, record,
  });
  journal = armInstallJournalAction(journal, {
    expectedRevision: journal.revision, attemptId, now: ++clock.now, action,
  });
  journal = await submitInstallJournalAction(journal, {
    expectedRevision: journal.revision, attemptId, now: ++clock.now, action, locator,
  });
  return verifyInstallJournalAction(journal, {
    expectedRevision: journal.revision, attemptId, now: ++clock.now, action,
  });
}

async function throughBootstrapSubdomainEnable(fixture: InstalledFixture): Promise<{
  journal: InstallJournal;
  clock: { now: number };
}> {
  let journal = acquireInstallJournalLease(fixture.journal, {
    expectedRevision: 0,
    attemptId: INITIAL_ATTEMPT,
    now: NOW + 6,
    leaseExpiresAt: NOW + 300_000,
  });
  const clock = { now: NOW + 10 };
  journal = await advance(
    journal,
    INITIAL_ATTEMPT,
    'worker_create',
    await workerRecord(fixture.plan),
    workerLocator(fixture.plan),
    clock,
  );
  journal = await advance(journal, INITIAL_ATTEMPT, 'management_access_application_create', await applicationRecord(fixture.plan), {
    applicationId: '4'.repeat(32), aud: 'audience-abcdefghijklmnop',
  }, clock);
  journal = await advance(journal, INITIAL_ATTEMPT, 'management_admin_policy_create', await policyRecord(fixture.plan), {
    policyId: '5'.repeat(32),
  }, clock);
  journal = await advance(
    journal,
    INITIAL_ATTEMPT,
    'provision_worker_version_create',
    await versionRecord(fixture.plan, 'provision'),
    await versionLocator(fixture.plan, 'provision'),
    clock,
  );
  journal = await advance(
    journal,
    INITIAL_ATTEMPT,
    'provision_worker_deployment_create',
    await deploymentRecord(fixture.plan, 'provision'),
    await deploymentLocator(fixture.plan, 'provision'),
    clock,
  );
  journal = await advance(
    journal,
    INITIAL_ATTEMPT,
    'bootstrap_worker_version_create',
    await versionRecord(fixture.plan, 'bootstrap'),
    await versionLocator(fixture.plan, 'bootstrap'),
    clock,
  );
  journal = await advance(
    journal,
    INITIAL_ATTEMPT,
    'bootstrap_worker_deployment_create',
    await deploymentRecord(fixture.plan, 'bootstrap'),
    await deploymentLocator(fixture.plan, 'bootstrap'),
    clock,
  );
  journal = await advance(journal, INITIAL_ATTEMPT, 'bootstrap_subdomain_enable', await subdomainRecord(fixture.plan, true), {
    enabled: true, previewsEnabled: false,
  }, clock);
  return { journal, clock };
}

describe('secret-free install journal and recovery authority', () => {
  it('rejects extra fields and out-of-order actions in the public progress projection', () => {
    expect(() => parsePublicInstallProgress({
      schemaVersion: 1,
      revision: 1,
      updatedAt: NOW,
      actions: [{
        name: 'worker_create',
        phase: 'prepared',
        updatedAt: NOW,
      }],
    })).toThrowError(/session_invalid/u);
    expect(() => parsePublicInstallProgress({
      schemaVersion: 1,
      revision: 1,
      updatedAt: NOW,
      actions: [{
        name: 'gateway_fresh_preflight',
        phase: 'prepared',
        updatedAt: NOW,
        accountId: 'a'.repeat(32),
      }],
    })).toThrowError(/session_invalid/u);
  });

  it('server-stamps the nested initial bootstrap prepare across transport latency', async () => {
    const fixture = await initializedJournal();
    const { journal, clock } = await throughBootstrapSubdomainEnable(fixture);
    fixture.state.storage.values.set('install-journal-v1', structuredClone(journal));
    const callerNow = ++clock.now;
    const record = await bootstrapRecord(fixture, callerNow, INITIAL_ATTEMPT, 1, journal);
    const serverNow = callerNow + 7;
    fixture.setServerNow(serverNow);

    const response = await fixture.object.fetch(internalRequest('/install-journal/action/prepare', 'POST', {
      expectedRevision: journal.revision,
      attemptId: INITIAL_ATTEMPT,
      now: callerNow,
      action: 'customer_bootstrap_submit',
      record,
    }));

    expect(response.status).toBe(200);
    const prepared = (await body(response)).journal as InstallJournal;
    const bootstrap = prepared.actions.find((entry) => entry.name === 'customer_bootstrap_submit');
    expect(bootstrap?.preparedAt).toBe(serverNow);
    expect(bootstrap?.record.kind === 'customer_bootstrap_submit'
      ? bootstrap.record.attempts[0]?.preparedAt
      : null).toBe(serverNow);
  });

  it('persists exact immutable authority separately and keeps the browser session journal-free', async () => {
    const fixture = await initializedJournal();
    expect(fixture.journal).toMatchObject({
      schemaVersion: 1,
      revision: 0,
      sessionExpiresAt: SESSION_EXPIRES_AT,
      recoverUntil: RECOVER_UNTIL,
      plan: fixture.plan,
      releasePin: RELEASE_PIN,
      target: TARGET,
      installationId: fixture.initialization.installationId,
      bindingHash: fixture.initialization.bindingHash,
      approvalHistory: [{
        attemptId: INITIAL_ATTEMPT,
        planId: fixture.plan.planId,
        planHash: fixture.plan.planHash,
        planExpiresAt: fixture.plan.expiresAt,
        managementOwnershipMarker: fixture.plan.managementOwnershipMarker,
      }],
    });
    const serialized = JSON.stringify(fixture.journal);
    expect(serialized).not.toMatch(/access[_-]?token|refresh[_-]?token|codeVerifier|bootstrapNonce|signature|jwt|providerBody/iu);

    fixture.setServerNow(NOW + 6);
    const publicResponse = await fixture.object.fetch(internalRequest('/public', 'GET'));
    const publicSerialized = JSON.stringify(await body(publicResponse));
    expect(publicSerialized).not.toMatch(/install-journal|approvalHistory|leaseAttemptIds|bindingHash/iu);

    const repeat = await fixture.object.fetch(internalRequest('/install-journal/initialize', 'POST', {
      ...fixture.initialization,
      now: 0,
      recoverUntil: Number.MAX_SAFE_INTEGER,
    }));
    expect(repeat.status).toBe(200);
    const repeatedJournal = (await body(repeat)).journal;
    expect(repeatedJournal.revision).toBe(0);
    expect(repeatedJournal.recoverUntil).toBe(RECOVER_UNTIL);

    const forged = structuredClone(fixture.initialization) as any;
    const { attestationHash: _attestationHash, ...unsigned } = forged.gatewayFreshPreflight;
    unsigned.configurationHash = `sha256:${'0'.repeat(64)}`;
    forged.gatewayFreshPreflight = {
      ...unsigned,
      attestationHash: `sha256:${await hash(unsigned)}`,
    };
    await expect(createInstallJournal(
      forged,
      fixture.journal.selection,
      fixture.plan,
      SESSION_EXPIRES_AT,
      { attemptId: INITIAL_ATTEMPT, approvedAt: NOW + 4 },
    )).rejects.toMatchObject({ code: 'bad_request' });
  });

  it('treats expired preflight-only authority as disposable and never weakens worker-arm freshness', async () => {
    const fixture = await initializedJournal();
    let journal = acquireInstallJournalLease(fixture.journal, {
      expectedRevision: 0,
      attemptId: INITIAL_ATTEMPT,
      now: NOW + 6,
      leaseExpiresAt: NOW + 100_000,
    });
    journal = await prepareInstallJournalAction(journal, {
      expectedRevision: journal.revision,
      attemptId: INITIAL_ATTEMPT,
      now: NOW + 7,
      action: 'worker_create',
      record: await workerRecord(fixture.plan),
    });
    const expiresAt = (journal.actions[0].record as any).expiresAt as number;
    expect(isPartialInstallJournal(journal)).toBe(false);
    expect(() => armInstallJournalAction(journal, {
      expectedRevision: journal.revision,
      attemptId: INITIAL_ATTEMPT,
      now: expiresAt,
      action: 'worker_create',
    })).toThrow(expect.objectContaining({ code: 'session_conflict' }));
    fixture.setServerNow(NOW + 6);
    expect((await fixture.object.fetch(internalRequest('/install-journal/lease/acquire', 'POST', {
      expectedRevision: 0,
      attemptId: INITIAL_ATTEMPT,
      now: 0,
      leaseExpiresAt: Number.MAX_SAFE_INTEGER,
    }))).status).toBe(200);
    expect((await fixture.object.fetch(internalRequest('/install-journal/action/prepare', 'POST', {
      expectedRevision: 1,
      attemptId: INITIAL_ATTEMPT,
      now: 0,
      action: 'worker_create',
      record: await workerRecord(fixture.plan),
    }))).status).toBe(200);
    fixture.setServerNow(expiresAt);
    const staleServerClock = await fixture.object.fetch(internalRequest('/install-journal/action/arm', 'POST', {
      expectedRevision: 2,
      attemptId: INITIAL_ATTEMPT,
      now: NOW + 6,
      action: 'worker_create',
    }));
    expect(staleServerClock.status).toBe(409);
    const destroyed = await fixture.object.fetch(internalRequest('/destroy', 'DELETE', { csrfHash: fixture.csrfHash }));
    expect(destroyed.status).toBe(204);
    expect(fixture.state.storage.values.size).toBe(0);
  });

  it('enforces revision, current consumed grant, one-shot leases, exact records, and write-fault recovery', async () => {
    const fixture = await initializedJournal();
    const write = vi.spyOn(fixture.state.storage, 'put').mockRejectedValueOnce(new Error('disk fault'));
    const fault = await fixture.object.fetch(internalRequest('/install-journal/lease/acquire', 'POST', {
      expectedRevision: 0,
      attemptId: INITIAL_ATTEMPT,
      now: NOW + 6,
      leaseExpiresAt: NOW + 100_000,
    }));
    write.mockRestore();
    expect(fault.status).toBe(500);
    expect((await body(fault)).error.code).toBe('internal_error');
    expect((await body(await fixture.object.fetch(internalRequest('/install-journal', 'GET')))).journal.revision).toBe(0);

    const acquired = await fixture.object.fetch(internalRequest('/install-journal/lease/acquire', 'POST', {
      expectedRevision: 0,
      attemptId: INITIAL_ATTEMPT,
      now: 0,
      leaseExpiresAt: Number.MAX_SAFE_INTEGER,
    }));
    expect(acquired.status).toBe(200);
    expect((await body(acquired)).journal.lease).toEqual({
      attemptId: INITIAL_ATTEMPT,
      acquiredAt: NOW + 5,
      expiresAt: NOW + 300_005,
    });
    const record = await workerRecord(fixture.plan);
    const sentinel = await fixture.object.fetch(internalRequest('/install-journal/action/prepare', 'POST', {
      expectedRevision: 1,
      attemptId: INITIAL_ATTEMPT,
      now: NOW + 7,
      action: 'worker_create',
      record: { ...record, providerBody: { cloudflareAccessToken: 'must-never-persist' } },
    }));
    expect(sentinel.status).toBe(400);
    expect(JSON.stringify([...fixture.state.storage.values.values()])).not.toContain('must-never-persist');

    const storedBeforePoison = structuredClone(fixture.state.storage.values.get('install-journal-v1')) as any;
    const poisonedCandidate = structuredClone(storedBeforePoison) as any;
    poisonedCandidate.revision += 1;
    poisonedCandidate.actions[0].phase = 'prepared';
    const storedSession = structuredClone(fixture.state.storage.values.get('deploy-session-v1')) as any;
    await expect((fixture.object as unknown as {
      putJournal(session: unknown, journal: unknown): Promise<void>;
    }).putJournal(storedSession, poisonedCandidate)).rejects.toMatchObject({ code: 'session_invalid' });
    expect(fixture.state.storage.values.get('install-journal-v1')).toEqual(storedBeforePoison);

    const concurrent = await Promise.all([
      fixture.object.fetch(internalRequest('/install-journal/action/prepare', 'POST', {
        expectedRevision: 1,
        attemptId: INITIAL_ATTEMPT,
        now: 0,
        action: 'worker_create',
        record,
      })),
      fixture.object.fetch(internalRequest('/install-journal/action/prepare', 'POST', {
        expectedRevision: 1,
        attemptId: INITIAL_ATTEMPT,
        now: Number.MAX_SAFE_INTEGER,
        action: 'worker_create',
        record,
      })),
    ]);
    expect(concurrent.map((response) => response.status).sort()).toEqual([200, 409]);
    expect((await body(await fixture.object.fetch(internalRequest('/install-journal', 'GET')))).journal.revision).toBe(2);
    const stale = await fixture.object.fetch(internalRequest('/install-journal/action/arm', 'POST', {
      expectedRevision: 1,
      attemptId: INITIAL_ATTEMPT,
      now: NOW + 8,
      action: 'worker_create',
    }));
    expect(stale.status).toBe(409);
    const wrongGrant = await fixture.object.fetch(internalRequest('/install-journal/action/arm', 'POST', {
      expectedRevision: 2,
      attemptId: RECOVERY_ATTEMPT,
      now: NOW + 8,
      action: 'worker_create',
    }));
    expect(wrongGrant.status).toBe(409);
  });

  it('lets a fresh grant safety-close an enabled cycle whose request was prepared but never armed', async () => {
    const fixture = await initializedJournal();
    let journal = acquireInstallJournalLease(fixture.journal, {
      expectedRevision: 0,
      attemptId: INITIAL_ATTEMPT,
      now: NOW + 6,
      leaseExpiresAt: NOW + 300_000,
    });
    const clock = { now: NOW + 10 };
    journal = await advance(journal, INITIAL_ATTEMPT, 'worker_create', await workerRecord(fixture.plan), workerLocator(fixture.plan), clock);
    journal = await advance(journal, INITIAL_ATTEMPT, 'management_access_application_create', await applicationRecord(fixture.plan), {
      applicationId: '4'.repeat(32), aud: 'audience-abcdefghijklmnop',
    }, clock);
    journal = await advance(journal, INITIAL_ATTEMPT, 'management_admin_policy_create', await policyRecord(fixture.plan), {
      policyId: '5'.repeat(32),
    }, clock);
    journal = await advance(
      journal,
      INITIAL_ATTEMPT,
      'provision_worker_version_create',
      await versionRecord(fixture.plan, 'provision'),
      await versionLocator(fixture.plan, 'provision'),
      clock,
    );
    journal = await advance(journal, INITIAL_ATTEMPT, 'provision_worker_deployment_create', await deploymentRecord(fixture.plan, 'provision'), await deploymentLocator(fixture.plan, 'provision'), clock);
    journal = await advance(
      journal,
      INITIAL_ATTEMPT,
      'bootstrap_worker_version_create',
      await versionRecord(fixture.plan, 'bootstrap'),
      await versionLocator(fixture.plan, 'bootstrap'),
      clock,
    );
    journal = await advance(journal, INITIAL_ATTEMPT, 'bootstrap_worker_deployment_create', await deploymentRecord(fixture.plan, 'bootstrap'), await deploymentLocator(fixture.plan, 'bootstrap'), clock);
    journal = await advance(journal, INITIAL_ATTEMPT, 'bootstrap_subdomain_enable', await subdomainRecord(fixture.plan, true), {
      enabled: true, previewsEnabled: false,
    }, clock);
    journal = await prepareInstallJournalAction(journal, {
      expectedRevision: journal.revision,
      attemptId: INITIAL_ATTEMPT,
      now: ++clock.now,
      action: 'customer_bootstrap_submit',
      record: await bootstrapRecord(fixture, clock.now, INITIAL_ATTEMPT, 1, journal),
    });
    journal = releaseInstallJournalLease(journal, {
      expectedRevision: journal.revision,
      attemptId: INITIAL_ATTEMPT,
      now: ++clock.now,
    });
    const renewedPlan = await buildStaticDeployPlan(fixture.journal.selection, manifest, fixture.plan.expiresAt + 600_000);
    journal = appendInstallJournalApproval(journal, renewedPlan, {
      expectedRevision: journal.revision,
      attemptId: RECOVERY_ATTEMPT,
      approvedAt: ++clock.now,
      now: clock.now,
    });
    journal = acquireInstallJournalLease(journal, {
      expectedRevision: journal.revision,
      attemptId: RECOVERY_ATTEMPT,
      now: ++clock.now,
      leaseExpiresAt: clock.now + 100_000,
    });
    journal = await advance(journal, RECOVERY_ATTEMPT, 'bootstrap_subdomain_disable', await subdomainRecord(fixture.plan, false), {
      enabled: false, previewsEnabled: false,
    }, clock);
    const first = (journal.actions[9].record as any).attempts[0];
    expect(first).toMatchObject({
      phase: 'prepared',
      disable: { phase: 'verified', approvalAttemptId: RECOVERY_ATTEMPT },
    });
    const recovery = await bootstrapRecord(fixture, clock.now + 1, RECOVERY_ATTEMPT, 33, journal) as any;
    const attempt = recovery.attempts[0];
    journal = await appendCustomerBootstrapAttempt(journal, {
      expectedRevision: journal.revision,
      attemptId: RECOVERY_ATTEMPT,
      now: ++clock.now,
      attempt: {
        requestId: attempt.requestId,
        issuedAt: attempt.issuedAt,
        expiresAt: attempt.expiresAt,
        claimHash: attempt.claimHash,
        enableRequestHash: (await subdomainRecord(fixture.plan, true) as any).requestHash,
      },
    });
    expect((journal.actions[9].record as any).attempts).toHaveLength(2);
    await expect(prepareInstallJournalAction(journal, {
      expectedRevision: journal.revision,
      attemptId: RECOVERY_ATTEMPT,
      now: ++clock.now,
      action: 'bootstrap_subdomain_disable',
      record: await subdomainRecord(fixture.plan, false),
    })).rejects.toMatchObject({ code: 'session_conflict' });
    await expect(requireInstallJournal(structuredClone(journal))).resolves.toBeDefined();
  });

  it('lets a current recovery lease settle an older nested enable without rewriting its approval evidence', async () => {
    const fixture = await initializedJournal();
    let journal = acquireInstallJournalLease(fixture.journal, {
      expectedRevision: 0,
      attemptId: INITIAL_ATTEMPT,
      now: NOW + 6,
      leaseExpiresAt: NOW + 300_000,
    });
    const clock = { now: NOW + 10 };
    journal = await advance(journal, INITIAL_ATTEMPT, 'worker_create', await workerRecord(fixture.plan), workerLocator(fixture.plan), clock);
    journal = await advance(journal, INITIAL_ATTEMPT, 'management_access_application_create', await applicationRecord(fixture.plan), {
      applicationId: '4'.repeat(32), aud: 'audience-abcdefghijklmnop',
    }, clock);
    journal = await advance(journal, INITIAL_ATTEMPT, 'management_admin_policy_create', await policyRecord(fixture.plan), {
      policyId: '5'.repeat(32),
    }, clock);
    journal = await advance(
      journal,
      INITIAL_ATTEMPT,
      'provision_worker_version_create',
      await versionRecord(fixture.plan, 'provision'),
      await versionLocator(fixture.plan, 'provision'),
      clock,
    );
    journal = await advance(journal, INITIAL_ATTEMPT, 'provision_worker_deployment_create', await deploymentRecord(fixture.plan, 'provision'), await deploymentLocator(fixture.plan, 'provision'), clock);
    journal = await advance(
      journal,
      INITIAL_ATTEMPT,
      'bootstrap_worker_version_create',
      await versionRecord(fixture.plan, 'bootstrap'),
      await versionLocator(fixture.plan, 'bootstrap'),
      clock,
    );
    journal = await advance(journal, INITIAL_ATTEMPT, 'bootstrap_worker_deployment_create', await deploymentRecord(fixture.plan, 'bootstrap'), await deploymentLocator(fixture.plan, 'bootstrap'), clock);
    journal = await advance(journal, INITIAL_ATTEMPT, 'bootstrap_subdomain_enable', await subdomainRecord(fixture.plan, true), {
      enabled: true, previewsEnabled: false,
    }, clock);
    journal = await prepareInstallJournalAction(journal, {
      expectedRevision: journal.revision,
      attemptId: INITIAL_ATTEMPT,
      now: ++clock.now,
      action: 'customer_bootstrap_submit',
      record: await bootstrapRecord(fixture, clock.now, INITIAL_ATTEMPT, 1, journal),
    });
    journal = armInstallJournalAction(journal, {
      expectedRevision: journal.revision,
      attemptId: INITIAL_ATTEMPT,
      now: ++clock.now,
      action: 'customer_bootstrap_submit',
    });
    journal = releaseInstallJournalLease(journal, {
      expectedRevision: journal.revision,
      attemptId: INITIAL_ATTEMPT,
      now: ++clock.now,
    });

    const firstRecoveryPlan = await buildStaticDeployPlan(
      fixture.journal.selection,
      manifest,
      fixture.plan.expiresAt + 600_000,
    );
    journal = appendInstallJournalApproval(journal, firstRecoveryPlan, {
      expectedRevision: journal.revision,
      attemptId: RECOVERY_ATTEMPT,
      approvedAt: ++clock.now,
      now: clock.now,
    });
    journal = acquireInstallJournalLease(journal, {
      expectedRevision: journal.revision,
      attemptId: RECOVERY_ATTEMPT,
      now: ++clock.now,
      leaseExpiresAt: clock.now + 100_000,
    });
    journal = await advance(journal, RECOVERY_ATTEMPT, 'bootstrap_subdomain_disable', await subdomainRecord(fixture.plan, false), {
      enabled: false, previewsEnabled: false,
    }, clock);
    const recoveryBootstrap = await bootstrapRecord(fixture, clock.now + 1, RECOVERY_ATTEMPT, 33, journal) as any;
    const recoveryAttempt = recoveryBootstrap.attempts[0];
    journal = await appendCustomerBootstrapAttempt(journal, {
      expectedRevision: journal.revision,
      attemptId: RECOVERY_ATTEMPT,
      now: ++clock.now,
      attempt: {
        requestId: recoveryAttempt.requestId,
        issuedAt: recoveryAttempt.issuedAt,
        expiresAt: recoveryAttempt.expiresAt,
        claimHash: recoveryAttempt.claimHash,
        enableRequestHash: (await subdomainRecord(fixture.plan, true) as any).requestHash,
      },
    });
    expect((journal.actions[9].record as any).attempts[1].enable).toMatchObject({
      approvalAttemptId: RECOVERY_ATTEMPT,
      phase: 'prepared',
    });
    journal = releaseInstallJournalLease(journal, {
      expectedRevision: journal.revision,
      attemptId: RECOVERY_ATTEMPT,
      now: ++clock.now,
    });

    clock.now = firstRecoveryPlan.expiresAt + 1;
    const secondRecoveryPlan = await buildStaticDeployPlan(
      fixture.journal.selection,
      manifest,
      firstRecoveryPlan.expiresAt + 600_000,
    );
    journal = appendInstallJournalApproval(journal, secondRecoveryPlan, {
      expectedRevision: journal.revision,
      attemptId: SECOND_RECOVERY_ATTEMPT,
      approvedAt: ++clock.now,
      now: clock.now,
    });
    journal = acquireInstallJournalLease(journal, {
      expectedRevision: journal.revision,
      attemptId: SECOND_RECOVERY_ATTEMPT,
      now: ++clock.now,
      leaseExpiresAt: clock.now + 100_000,
    });
    journal = armInstallJournalAction(journal, {
      expectedRevision: journal.revision,
      attemptId: SECOND_RECOVERY_ATTEMPT,
      now: ++clock.now,
      action: 'bootstrap_subdomain_enable',
    });
    journal = await submitInstallJournalAction(journal, {
      expectedRevision: journal.revision,
      attemptId: SECOND_RECOVERY_ATTEMPT,
      now: ++clock.now,
      action: 'bootstrap_subdomain_enable',
      locator: { enabled: true, previewsEnabled: false },
    });
    journal = verifyInstallJournalAction(journal, {
      expectedRevision: journal.revision,
      attemptId: SECOND_RECOVERY_ATTEMPT,
      now: ++clock.now,
      action: 'bootstrap_subdomain_enable',
    });
    const settled = (journal.actions[9].record as any).attempts[1];
    expect(settled).toMatchObject({
      approvalAttemptId: RECOVERY_ATTEMPT,
      phase: 'prepared',
      enable: { approvalAttemptId: RECOVERY_ATTEMPT, phase: 'verified' },
      disable: null,
    });
    await expect(requireInstallJournal(structuredClone(journal))).resolves.toBeDefined();

    // The active lease may settle the provider mutation, but it may not arm or replay
    // the older signed bootstrap request.
    expect(() => armInstallJournalAction(journal, {
      expectedRevision: journal.revision,
      attemptId: SECOND_RECOVERY_ATTEMPT,
      now: ++clock.now,
      action: 'customer_bootstrap_submit',
    })).toThrowError(expect.objectContaining({ code: 'session_conflict' }));

    journal = await advance(journal, SECOND_RECOVERY_ATTEMPT, 'bootstrap_subdomain_disable', await subdomainRecord(fixture.plan, false), {
      enabled: false, previewsEnabled: false,
    }, clock);
    const closed = (journal.actions[9].record as any).attempts[1];
    expect(closed.enable).toMatchObject({
      approvalAttemptId: RECOVERY_ATTEMPT,
      phase: 'verified',
    });
    expect(closed.disable).toMatchObject({
      approvalAttemptId: SECOND_RECOVERY_ATTEMPT,
      phase: 'verified',
    });
    await expect(requireInstallJournal(structuredClone(journal))).resolves.toBeDefined();
  });

  it('allows the mandatory workers.dev safety close while bootstrap is unknown, then hands off only a converged receipt', async () => {
    const fixture = await initializedJournal();
    let journal = acquireInstallJournalLease(fixture.journal, {
      expectedRevision: 0,
      attemptId: INITIAL_ATTEMPT,
      now: NOW + 6,
      leaseExpiresAt: NOW + 300_000,
    });
    const clock = { now: NOW + 10 };
    journal = await advance(journal, INITIAL_ATTEMPT, 'worker_create', await workerRecord(fixture.plan), workerLocator(fixture.plan), clock);
    journal = await advance(journal, INITIAL_ATTEMPT, 'management_access_application_create', await applicationRecord(fixture.plan), {
      applicationId: '4'.repeat(32), aud: 'audience-abcdefghijklmnop',
    }, clock);
    journal = await advance(journal, INITIAL_ATTEMPT, 'management_admin_policy_create', await policyRecord(fixture.plan), {
      policyId: '5'.repeat(32),
    }, clock);
    journal = await advance(
      journal,
      INITIAL_ATTEMPT,
      'provision_worker_version_create',
      await versionRecord(fixture.plan, 'provision'),
      await versionLocator(fixture.plan, 'provision'),
      clock,
    );
    journal = await advance(journal, INITIAL_ATTEMPT, 'provision_worker_deployment_create', await deploymentRecord(fixture.plan, 'provision'), await deploymentLocator(fixture.plan, 'provision'), clock);
    journal = await advance(
      journal,
      INITIAL_ATTEMPT,
      'bootstrap_worker_version_create',
      await versionRecord(fixture.plan, 'bootstrap'),
      await versionLocator(fixture.plan, 'bootstrap'),
      clock,
    );
    journal = await advance(journal, INITIAL_ATTEMPT, 'bootstrap_worker_deployment_create', await deploymentRecord(fixture.plan, 'bootstrap'), await deploymentLocator(fixture.plan, 'bootstrap'), clock);
    journal = await advance(journal, INITIAL_ATTEMPT, 'bootstrap_subdomain_enable', await subdomainRecord(fixture.plan, true), {
      enabled: true, previewsEnabled: false,
    }, clock);

    const bootstrap = await bootstrapRecord(fixture, clock.now + 1, INITIAL_ATTEMPT, 1, journal);
    journal = await prepareInstallJournalAction(journal, {
      expectedRevision: journal.revision, attemptId: INITIAL_ATTEMPT, now: ++clock.now,
      action: 'customer_bootstrap_submit', record: bootstrap,
    });
    journal = armInstallJournalAction(journal, {
      expectedRevision: journal.revision, attemptId: INITIAL_ATTEMPT, now: ++clock.now,
      action: 'customer_bootstrap_submit',
    });
    expect(journal.actions[9].phase).toBe('send_armed');

    // The first signed bootstrap request may have completed remotely while its response was lost.
    // It is never resent. Release the interrupted grant; a fresh grant must be able to close
    // workers.dev for the old cycle before it starts a new signed recovery request.
    journal = releaseInstallJournalLease(journal, {
      expectedRevision: journal.revision,
      attemptId: INITIAL_ATTEMPT,
      now: ++clock.now,
    });
    const renewedPlan = await buildStaticDeployPlan(
      fixture.journal.selection,
      manifest,
      fixture.plan.expiresAt + 600_000,
    );
    journal = appendInstallJournalApproval(journal, renewedPlan, {
      expectedRevision: journal.revision,
      attemptId: RECOVERY_ATTEMPT,
      approvedAt: ++clock.now,
      now: clock.now,
    });
    journal = acquireInstallJournalLease(journal, {
      expectedRevision: journal.revision,
      attemptId: RECOVERY_ATTEMPT,
      now: ++clock.now,
      leaseExpiresAt: clock.now + 100_000,
    });
    journal = await advance(journal, RECOVERY_ATTEMPT, 'bootstrap_subdomain_disable', await subdomainRecord(fixture.plan, false), {
      enabled: false, previewsEnabled: false,
    }, clock);
    expect((journal.actions[9].record as any).attempts[0].disable.approvalAttemptId).toBe(RECOVERY_ATTEMPT);
    await expect(requireInstallJournal(structuredClone(journal))).resolves.toBeDefined();
    await expect(prepareInstallJournalAction(journal, {
      expectedRevision: journal.revision, attemptId: RECOVERY_ATTEMPT, now: ++clock.now,
      action: 'clean_worker_version_create', record: await versionRecord(fixture.plan, 'clean'),
    })).rejects.toMatchObject({ code: 'session_conflict' });
    const recoveryBootstrap = await bootstrapRecord(
      fixture,
      clock.now + 1,
      RECOVERY_ATTEMPT,
      17,
      journal,
    ) as any;
    const recoveryAttempt = recoveryBootstrap.attempts[0];
    const recoveryEnableRequestHash = (await subdomainRecord(fixture.plan, true) as any).requestHash;
    journal = await appendCustomerBootstrapAttempt(journal, {
      expectedRevision: journal.revision,
      attemptId: RECOVERY_ATTEMPT,
      now: ++clock.now,
      attempt: {
        requestId: recoveryAttempt.requestId,
        issuedAt: recoveryAttempt.issuedAt,
        expiresAt: recoveryAttempt.expiresAt,
        claimHash: recoveryAttempt.claimHash,
        enableRequestHash: recoveryEnableRequestHash,
      },
    });
    await expect(requireInstallJournal(structuredClone(journal))).resolves.toBeDefined();
    expect(journal.actions[9].record).toMatchObject({ attempts: [
      { approvalAttemptId: INITIAL_ATTEMPT, phase: 'send_armed' },
      { approvalAttemptId: RECOVERY_ATTEMPT, phase: 'prepared' },
    ] });
    await expect(appendCustomerBootstrapAttempt(journal, {
      expectedRevision: journal.revision,
      attemptId: RECOVERY_ATTEMPT,
      now: ++clock.now,
      attempt: {
        requestId: 'z'.repeat(22), issuedAt: recoveryAttempt.issuedAt,
        expiresAt: recoveryAttempt.expiresAt, claimHash: recoveryAttempt.claimHash,
        enableRequestHash: recoveryEnableRequestHash,
      },
    })).rejects.toMatchObject({ code: 'session_conflict' });
    journal = armInstallJournalAction(journal, {
      expectedRevision: journal.revision,
      attemptId: RECOVERY_ATTEMPT,
      now: ++clock.now,
      action: 'bootstrap_subdomain_enable',
    });
    journal = await submitInstallJournalAction(journal, {
      expectedRevision: journal.revision,
      attemptId: RECOVERY_ATTEMPT,
      now: ++clock.now,
      action: 'bootstrap_subdomain_enable',
      locator: { enabled: true, previewsEnabled: false },
    });
    journal = verifyInstallJournalAction(journal, {
      expectedRevision: journal.revision,
      attemptId: RECOVERY_ATTEMPT,
      now: ++clock.now,
      action: 'bootstrap_subdomain_enable',
    });
    await expect(requireInstallJournal(structuredClone(journal))).resolves.toBeDefined();
    journal = armInstallJournalAction(journal, {
      expectedRevision: journal.revision,
      attemptId: RECOVERY_ATTEMPT,
      now: ++clock.now,
      action: 'customer_bootstrap_submit',
    });
    expect((journal.actions[9].record as any).attempts[1].phase).toBe('send_armed');
    const ready = await bootstrapLocator(fixture, recoveryBootstrap, false, true) as any;
    expect(ready.approvedPlanId).not.toBe(fixture.plan.planId);
    await expect(submitInstallJournalAction(journal, {
      expectedRevision: journal.revision,
      attemptId: RECOVERY_ATTEMPT,
      now: ++clock.now,
      action: 'customer_bootstrap_submit',
      locator: { ...ready, approvedPlanId: 'not-a-customer-plan' },
    })).rejects.toMatchObject({ code: 'bad_request' });
    for (const artifactSha256 of [
      manifest.artifact.treeSha256,
      `sha256:sha256:${manifest.artifact.treeSha256}`,
      `sha256:${manifest.components.worker.treeSha256}`,
    ]) {
      await expect(submitInstallJournalAction(journal, {
        expectedRevision: journal.revision,
        attemptId: RECOVERY_ATTEMPT,
        now: ++clock.now,
        action: 'customer_bootstrap_submit',
        locator: { ...ready, release: { ...ready.release, artifactSha256 } },
      })).rejects.toMatchObject({ code: 'bad_request' });
    }
    journal = await submitInstallJournalAction(journal, {
      expectedRevision: journal.revision, attemptId: RECOVERY_ATTEMPT, now: ++clock.now,
      action: 'customer_bootstrap_submit', locator: ready,
    });
    journal = verifyInstallJournalAction(journal, {
      expectedRevision: journal.revision, attemptId: RECOVERY_ATTEMPT, now: ++clock.now,
      action: 'customer_bootstrap_submit',
    });
    expect((journal.actions[9].locator as any).approvedPlanId).toBe(CUSTOMER_APPROVED_PLAN_ID);
    await expect(requireInstallJournal(structuredClone(journal))).resolves.toBeDefined();
    journal = await prepareInstallJournalAction(journal, {
      expectedRevision: journal.revision,
      attemptId: RECOVERY_ATTEMPT,
      now: ++clock.now,
      action: 'bootstrap_subdomain_disable',
      record: await subdomainRecord(fixture.plan, false),
    });
    journal = armInstallJournalAction(journal, {
      expectedRevision: journal.revision,
      attemptId: RECOVERY_ATTEMPT,
      now: ++clock.now,
      action: 'bootstrap_subdomain_disable',
    });
    journal = await submitInstallJournalAction(journal, {
      expectedRevision: journal.revision,
      attemptId: RECOVERY_ATTEMPT,
      now: ++clock.now,
      action: 'bootstrap_subdomain_disable',
      locator: { enabled: false, previewsEnabled: false },
    });
    journal = verifyInstallJournalAction(journal, {
      expectedRevision: journal.revision,
      attemptId: RECOVERY_ATTEMPT,
      now: ++clock.now,
      action: 'bootstrap_subdomain_disable',
    });
    await expect(requireInstallJournal(structuredClone(journal))).resolves.toBeDefined();
    journal = await advance(
      journal,
      RECOVERY_ATTEMPT,
      'clean_worker_version_create',
      await versionRecord(fixture.plan, 'clean'),
      await versionLocator(fixture.plan, 'clean'),
      clock,
    );
    journal = await advance(journal, RECOVERY_ATTEMPT, 'clean_worker_deployment_create', await deploymentRecord(fixture.plan, 'clean'), await deploymentLocator(fixture.plan, 'clean'), clock);
    journal = await advance(journal, RECOVERY_ATTEMPT, 'management_custom_domain_attach', await domainRecord(fixture.plan), {
      domainId: 'a'.repeat(32),
    }, clock);

    const projection = {
      adminStateNamespaceId: ADMIN_STATE_NAMESPACE_ID,
      bindingHash: journal.bindingHash,
      bootstrapDeploymentId: BOOTSTRAP_DEPLOYMENT_ID,
      bootstrapVersionId: BOOTSTRAP_VERSION_ID,
      cleanDeploymentId: CLEAN_DEPLOYMENT_ID,
      cleanVersionId: CLEAN_VERSION_ID,
      customerApprovedPlanId: CUSTOMER_APPROVED_PLAN_ID,
      customerReceiptEvidence: ready.receipt.evidence,
      customerReceiptRevision: 1,
      installationId: journal.installationId,
      managementAccessAud: 'audience-abcdefghijklmnop',
      managementApplicationId: '4'.repeat(32),
      managementDomainId: 'a'.repeat(32),
      managementPolicyId: '5'.repeat(32),
      workerId: '3'.repeat(32),
      workersDevEnabled: false as const,
    };
    const convergenceHash = `sha256:${await hash({ schemaVersion: 1, ...projection })}`;
    const final = await prepareFinalConvergenceRecordAndLocator(journal);
    expect(final).toEqual({
      record: { schemaVersion: 1, kind: 'final_convergence', convergenceHash },
      locator: { schemaVersion: 1, status: 'converged', convergenceHash, ...projection },
    });
    journal = await prepareInstallJournalAction(journal, {
      expectedRevision: journal.revision,
      attemptId: RECOVERY_ATTEMPT,
      now: ++clock.now,
      action: 'final_convergence',
      record: final.record,
    });
    await expect(prepareFinalConvergenceRecordAndLocator(journal)).resolves.toEqual(final);
    journal = armInstallJournalAction(journal, {
      expectedRevision: journal.revision,
      attemptId: RECOVERY_ATTEMPT,
      now: ++clock.now,
      action: 'final_convergence',
    });
    await expect(prepareFinalConvergenceRecordAndLocator(journal)).resolves.toEqual(final);
    journal = await submitInstallJournalAction(journal, {
      expectedRevision: journal.revision,
      attemptId: RECOVERY_ATTEMPT,
      now: ++clock.now,
      action: 'final_convergence',
      locator: final.locator,
    });
    await expect(prepareFinalConvergenceRecordAndLocator(journal)).resolves.toEqual(final);
    journal = verifyInstallJournalAction(journal, {
      expectedRevision: journal.revision,
      attemptId: RECOVERY_ATTEMPT,
      now: ++clock.now,
      action: 'final_convergence',
    });
    await expect(prepareFinalConvergenceRecordAndLocator(journal)).resolves.toEqual(final);
    expect(journal.actions).toHaveLength(15);
    expect(journal.actions.every((action) => action.phase === 'verified')).toBe(true);

    const storedSession = structuredClone(fixture.state.storage.values.get('deploy-session-v1')) as any;
    storedSession.oauthAttempt = {
      attemptId: RECOVERY_ATTEMPT,
      stateHash: await sha256('r'.repeat(43)),
      verifierHash: await sha256('w'.repeat(43)),
      expiresAt: renewedPlan.expiresAt,
      usedAt: journal.approvalHistory[1].approvedAt,
    };
    storedSession.plan = renewedPlan;
    storedSession.updatedAt = clock.now;
    fixture.state.storage.values.set('deploy-session-v1', storedSession);
    fixture.state.storage.values.set('install-journal-v1', structuredClone(journal));
    const completedAt = SESSION_EXPIRES_AT + 1;
    fixture.setServerNow(completedAt);
    expect((await fixture.object.fetch(internalRequest('/install-journal', 'GET'))).status).toBe(200);
    const pendingReceipt = await body(await fixture.object.fetch(internalRequest('/public', 'GET')));
    expect(pendingReceipt.recovery).toEqual({ status: 'recovery_required', recoverUntil: RECOVER_UNTIL });
    expect(pendingReceipt.resultRetention).toBeNull();
    expect(pendingReceipt.installProgress).toMatchObject({
      schemaVersion: 1,
      revision: journal.revision,
      actions: expect.arrayContaining([
        { name: 'gateway_fresh_preflight', phase: 'verified', updatedAt: expect.any(Number) },
        { name: 'final_convergence', phase: 'verified', updatedAt: expect.any(Number) },
      ]),
    });
    expect(JSON.stringify(pendingReceipt.installProgress)).not.toMatch(
      /accountId|bindingHash|locator|requestHash|record|token/iu,
    );

    const missingRevocation = await fixture.object.fetch(internalRequest('/complete', 'POST', {
      attemptId: RECOVERY_ATTEMPT,
      code: 'install_complete',
      completedAt: completedAt,
      installationId: journal.installationId,
    }));
    expect(missingRevocation.status).toBe(400);
    expect(await body(missingRevocation)).toEqual({ error: { code: 'bad_request' } });

    const inconsistentSuccess = await fixture.object.fetch(internalRequest('/complete', 'POST', {
      attemptId: RECOVERY_ATTEMPT,
      code: 'install_complete',
      completedAt,
      installationId: journal.installationId,
      grantRevocation: null,
    }));
    expect(inconsistentSuccess.status).toBe(409);
    expect(await body(inconsistentSuccess)).toEqual({ error: { code: 'session_conflict' } });

    const inconsistentFailure = await fixture.object.fetch(internalRequest('/complete', 'POST', {
      attemptId: RECOVERY_ATTEMPT,
      code: 'oauth_revoke_failed',
      completedAt,
      installationId: null,
      grantRevocation: 'unconfirmed',
    }));
    expect(inconsistentFailure.status).toBe(409);
    expect(await body(inconsistentFailure)).toEqual({ error: { code: 'session_conflict' } });

    const completed = await fixture.object.fetch(internalRequest('/complete', 'POST', {
      attemptId: RECOVERY_ATTEMPT,
      code: 'install_complete',
      completedAt: RECOVER_UNTIL + 1,
      installationId: journal.installationId,
      grantRevocation: 'unconfirmed',
    }));
    expect(completed.status).toBe(200);
    expect((await body(completed)).session.result).toEqual({
      code: 'install_complete',
      completedAt,
      installationId: journal.installationId,
      grantRevocation: 'unconfirmed',
    });
    expect(fixture.state.storage.alarmAt).toBe(RECOVER_UNTIL);
    const retained = await body(await fixture.object.fetch(internalRequest('/public', 'GET')));
    expect(retained.recovery).toBeNull();
    expect(retained.resultRetention).toEqual({ status: 'result_available', resultUntil: RECOVER_UNTIL });
    fixture.setServerNow(RECOVER_UNTIL);
    await fixture.object.alarm();
    expect(fixture.state.storage.values.size).toBe(0);
    expect(fixture.state.storage.alarmAt).toBeNull();
  });

  it('retains partial authority, renews only the approval expiry with a fresh grant, and rejects drift', async () => {
    const fixture = await initializedJournal();
    const acquired = await body(await fixture.object.fetch(internalRequest('/install-journal/lease/acquire', 'POST', {
      expectedRevision: 0,
      attemptId: INITIAL_ATTEMPT,
      now: NOW + 6,
      leaseExpiresAt: NOW + 100_000,
    })));
    const record = await workerRecord(fixture.plan);
    await fixture.object.fetch(internalRequest('/install-journal/action/prepare', 'POST', {
      expectedRevision: acquired.journal.revision,
      attemptId: INITIAL_ATTEMPT,
      now: NOW + 7,
      action: 'worker_create',
      record,
    }));
    await fixture.object.fetch(internalRequest('/install-journal/action/arm', 'POST', {
      expectedRevision: 2,
      attemptId: INITIAL_ATTEMPT,
      now: NOW + 8,
      action: 'worker_create',
    }));

    const recoveryNow = SESSION_EXPIRES_AT + 1;
    fixture.setServerNow(recoveryNow);
    await fixture.object.alarm();
    expect(fixture.state.storage.values.size).toBe(2);
    const publicState = await body(await fixture.object.fetch(internalRequest('/public', 'GET')));
    expect(publicState.recovery).toEqual({ status: 'recovery_required', recoverUntil: RECOVER_UNTIL });

    const freshExpiry = recoveryNow + 600_000;
    const renewed = await buildStaticDeployPlan(parseDeploySelection(selectionInput), manifest, freshExpiry);
    expect(renewed.planId).toBe(fixture.plan.planId);
    expect(renewed.planHash).toBe(fixture.plan.planHash);
    expect(renewed.managementOwnershipMarker).toMatch(/^acg-[a-f0-9]{24}$/u);
    expect(isRecoveryEquivalentInstallPlan(fixture.plan, renewed)).toBe(true);
    expect(isRecoveryEquivalentInstallPlan(fixture.plan, { ...renewed, planHash: `sha256:${'f'.repeat(64)}` })).toBe(false);
    expect(isRecoveryEquivalentInstallPlan(fixture.plan, {
      ...renewed,
      managementResources: renewed.managementResources.map((resource, index) => index === 0
        ? { ...resource, name: `${resource.name}-drift` }
        : resource),
    })).toBe(false);
    expect(isRecoveryEquivalentInstallPlan(fixture.plan, {
      ...renewed,
      managementOwnershipMarker: `acg-${'f'.repeat(24)}`,
    })).toBe(false);

    const changedRelease = {
      ...manifest,
      artifact: { ...manifest.artifact, treeSha256: 'f'.repeat(64) },
    };
    const drift = await fixture.object.fetch(internalRequest('/install-journal/recovery-plan', 'POST', {
      csrfHash: fixture.csrfHash,
      releaseManifest: changedRelease,
      planExpiresAt: freshExpiry,
      now: recoveryNow,
    }));
    expect(drift.status).toBe(409);
    const recoveryPlan = await fixture.object.fetch(internalRequest('/install-journal/recovery-plan', 'POST', {
      csrfHash: fixture.csrfHash,
      releaseManifest: manifest,
      planExpiresAt: freshExpiry,
      now: recoveryNow,
    }));
    expect(recoveryPlan.status).toBe(200);
    const recoveredPlan = (await body(recoveryPlan)).session.plan;
    expect(recoveredPlan).toEqual(renewed);

    await fixture.object.fetch(internalRequest('/authorize', 'POST', {
      csrfHash: fixture.csrfHash,
      releaseManifest: manifest,
      approvedPlanId: renewed.planId,
      approvedPlanHash: renewed.planHash,
      attemptId: RECOVERY_ATTEMPT,
      stateHash: await sha256('r'.repeat(43)),
      verifierHash: await sha256('w'.repeat(43)),
      attemptExpiresAt: freshExpiry,
      now: recoveryNow + 1,
    }));
    await fixture.object.fetch(internalRequest('/consume', 'POST', {
      attemptId: RECOVERY_ATTEMPT,
      stateHash: await sha256('r'.repeat(43)),
      verifierHash: await sha256('w'.repeat(43)),
      now: recoveryNow + 2,
    }));
    const beforeAppend = (await body(await fixture.object.fetch(internalRequest('/install-journal', 'GET')))).journal;
    const appended = await fixture.object.fetch(internalRequest('/install-journal/approval/append', 'POST', {
      expectedRevision: beforeAppend.revision,
      attemptId: RECOVERY_ATTEMPT,
      now: recoveryNow + 3,
    }));
    expect(appended.status).toBe(200);
    const recoveredJournal = (await body(appended)).journal;
    expect(recoveredJournal.plan.expiresAt).toBe(fixture.plan.expiresAt);
    expect(recoveredJournal.approvalHistory).toHaveLength(2);
    expect(recoveredJournal.approvalHistory[1]).toMatchObject({
      attemptId: RECOVERY_ATTEMPT,
      planId: fixture.plan.planId,
      planHash: fixture.plan.planHash,
      planExpiresAt: freshExpiry,
      managementOwnershipMarker: fixture.plan.managementOwnershipMarker,
    });
    const freshLease = await fixture.object.fetch(internalRequest('/install-journal/lease/acquire', 'POST', {
      expectedRevision: recoveredJournal.revision,
      attemptId: RECOVERY_ATTEMPT,
      now: recoveryNow + 4,
      leaseExpiresAt: recoveryNow + 100_000,
    }));
    expect(freshLease.status).toBe(200);
    const staleGrant = await fixture.object.fetch(internalRequest('/install-journal/lease/release', 'POST', {
      expectedRevision: (await body(freshLease)).journal.revision,
      attemptId: INITIAL_ATTEMPT,
      now: recoveryNow + 5,
    }));
    expect(staleGrant.status).toBe(409);
  });

  it('purges prepared-only, malformed, and retention-expired state while retaining no arbitrary provider data', async () => {
    const preparedOnly = await initializedJournal();
    let preparedJournal = acquireInstallJournalLease(preparedOnly.journal, {
      expectedRevision: 0,
      attemptId: INITIAL_ATTEMPT,
      now: NOW + 6,
      leaseExpiresAt: NOW + 100_000,
    });
    preparedJournal = await prepareInstallJournalAction(preparedJournal, {
      expectedRevision: preparedJournal.revision,
      attemptId: INITIAL_ATTEMPT,
      now: NOW + 7,
      action: 'worker_create',
      record: await workerRecord(preparedOnly.plan),
    });
    expect(isPartialInstallJournal(preparedJournal)).toBe(false);
    preparedOnly.state.storage.values.set('install-journal-v1', structuredClone(preparedJournal));
    preparedOnly.setServerNow(SESSION_EXPIRES_AT);
    await preparedOnly.object.alarm();
    expect(preparedOnly.state.storage.values.size).toBe(0);

    const retained = await initializedJournal();
    let retainedJournal = acquireInstallJournalLease(retained.journal, {
      expectedRevision: 0,
      attemptId: INITIAL_ATTEMPT,
      now: NOW + 6,
      leaseExpiresAt: NOW + 300_000,
    });
    const retainedClock = { now: NOW + 10 };
    retainedJournal = await advance(
      retainedJournal,
      INITIAL_ATTEMPT,
      'worker_create',
      await workerRecord(retained.plan),
      workerLocator(retained.plan),
      retainedClock,
    );
    retainedJournal = await advance(
      retainedJournal,
      INITIAL_ATTEMPT,
      'management_access_application_create',
      await applicationRecord(retained.plan),
      { applicationId: '4'.repeat(32), aud: 'audience-abcdefghijklmnop' },
      retainedClock,
    );
    retainedJournal = await advance(
      retainedJournal,
      INITIAL_ATTEMPT,
      'management_admin_policy_create',
      await policyRecord(retained.plan),
      { policyId: '5'.repeat(32) },
      retainedClock,
    );
    retainedJournal = await prepareInstallJournalAction(retainedJournal, {
      expectedRevision: retainedJournal.revision,
      attemptId: INITIAL_ATTEMPT,
      now: ++retainedClock.now,
      action: 'provision_worker_version_create',
      record: await versionRecord(retained.plan, 'provision'),
    });
    expect(isPartialInstallJournal(retainedJournal)).toBe(true);
    retained.state.storage.values.set('install-journal-v1', structuredClone(retainedJournal));
    retained.setServerNow(SESSION_EXPIRES_AT);
    await retained.object.alarm();
    expect(retained.state.storage.values.size).toBe(2);
    const retainedPublic = await body(await retained.object.fetch(internalRequest('/public', 'GET')));
    expect(retainedPublic.recovery).toEqual({ status: 'recovery_required', recoverUntil: RECOVER_UNTIL });

    const malformed = await initializedJournal();
    let journal = acquireInstallJournalLease(malformed.journal, {
      expectedRevision: 0,
      attemptId: INITIAL_ATTEMPT,
      now: NOW + 6,
      leaseExpiresAt: NOW + 100_000,
    });
    journal = await prepareInstallJournalAction(journal, {
      expectedRevision: journal.revision,
      attemptId: INITIAL_ATTEMPT,
      now: NOW + 7,
      action: 'worker_create',
      record: await workerRecord(malformed.plan),
    });
    journal = armInstallJournalAction(journal, {
      expectedRevision: journal.revision,
      attemptId: INITIAL_ATTEMPT,
      now: NOW + 8,
      action: 'worker_create',
    });
    const poisoned = structuredClone(journal) as any;
    poisoned.actions[0].record.providerBody = { accessToken: 'secret-sentinel' };
    malformed.state.storage.values.set('install-journal-v1', poisoned);
    malformed.setServerNow(NOW + 9);
    await malformed.object.alarm();
    expect(malformed.state.storage.values.size).toBe(0);
    expect(JSON.stringify([...malformed.state.storage.values.values()])).not.toContain('secret-sentinel');

    const expired = await initializedJournal();
    let partial = acquireInstallJournalLease(expired.journal, {
      expectedRevision: 0,
      attemptId: INITIAL_ATTEMPT,
      now: NOW + 6,
      leaseExpiresAt: NOW + 100_000,
    });
    partial = await prepareInstallJournalAction(partial, {
      expectedRevision: partial.revision,
      attemptId: INITIAL_ATTEMPT,
      now: NOW + 7,
      action: 'worker_create',
      record: await workerRecord(expired.plan),
    });
    partial = armInstallJournalAction(partial, {
      expectedRevision: partial.revision,
      attemptId: INITIAL_ATTEMPT,
      now: NOW + 8,
      action: 'worker_create',
    });
    expired.state.storage.values.set('install-journal-v1', structuredClone(partial));
    expired.setServerNow(RECOVER_UNTIL);
    await expired.object.alarm();
    expect(expired.state.storage.values.size).toBe(0);
    expect(expired.state.storage.alarmAt).toBeNull();
  });
});

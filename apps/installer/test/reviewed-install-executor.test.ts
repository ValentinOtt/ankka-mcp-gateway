import { describe, expect, it } from 'vitest';
import * as v from 'valibot';
import {
  prepareVerifiedWorkerRelease,
  prepareWorkerVersionMutation,
  prepareWorkerVersionRecoveryRecord,
  type DeploymentSubmission,
  type VersionSubmission,
  type WorkerDeploymentMutationIntent,
  type WorkerMutationIntent,
  type WorkerSubmission,
  type WorkerVersionMutationPlan,
  type WorkerVersionPhase,
  type WorkerVersionRecoveryRecord,
} from '../src/cloudflare-worker-direct-upload';
import { CustomerGatewayFreshPreflightError } from '../src/cloudflare-gateway-fresh-preflight';
import type { AuthorizedTarget } from '../src/cloudflare-target';
import {
  deriveCustomerGatewayExpectedProjection,
  deriveCustomerGatewayInstallationReceiptExpectation,
} from '../src/customer-bootstrap-request';
import { sha256Hex } from '../src/crypto';
import { DeployError } from '../src/errors';
import type { InstallJournalPort } from '../src/install-journal-port';
import {
  acquireInstallJournalLease,
  appendCustomerBootstrapAttempt,
  appendInstallJournalApproval,
  armInstallJournalAction,
  createInstallJournal,
  expireInstallJournalLease,
  hasArmedInstallJournalAction,
  isPartialInstallJournal,
  prepareInstallJournalAction,
  releaseInstallJournalLease,
  submitInstallJournalAction,
  verifyInstallJournalAction,
  requireInstallJournal,
  type InstallActionName,
  type InstallJournal,
} from '../src/install-journal';
import {
  createCloudflareReviewedInstallProviderAdapter,
  executeReviewedInstall,
  type ReviewedInstallExecutionInput,
  type ReviewedInstallProviderCall,
  type ReviewedInstallProviderAdapter,
} from '../src/reviewed-install-executor';
import { adaptVerifiedReleaseBundleForWorkerDirectUpload } from '../src/release-direct-upload-adapter';
import type { VerifiedReleaseBundle, VerifiedReleasePayloadBlob } from '../src/release';
import {
  APPROVED_CLOUDFLARE_RELEASE_CONTRACT,
  canonicalJson,
  parseReleaseManifest,
  type ReleaseComponent,
  type ReleaseFileRecord,
} from '../src/release-manifest';
import {
  assertSecretFree,
  buildStaticDeployPlan,
  parseDeploySelection,
  type StaticDeployPlan,
} from '../src/schema';
import { REQUIRED_OAUTH_SCOPES } from '../src/constants';
import { requiredFixture } from './fixtures';
import { readyInstallationReceiptFixture } from './provider-neutral-installation-receipt-fixture';

const NOW = 1_787_444_000_000;
const SESSION_EXPIRES_AT = NOW + 15 * 60_000;
const RECOVER_UNTIL = SESSION_EXPIRES_AT + 24 * 60 * 60_000;
const ATTEMPT_ONE = `att_${'a'.repeat(32)}`;
const ATTEMPT_TWO = `att_${'b'.repeat(32)}`;
const ATTEMPT_THREE = `att_${'c'.repeat(32)}`;
const ACCESS_TOKEN_ONE = `grant-${'a'.repeat(32)}`;
const ACCESS_TOKEN_TWO = `grant-${'b'.repeat(32)}`;
const ACCESS_TOKEN_THREE = `grant-${'c'.repeat(32)}`;
const SESSION_ID = 'BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc';
const BOOTSTRAP_NONCE_KEY = 'CAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg';
const WORKER_ID = '3'.repeat(32);
const APPLICATION_ID = '4'.repeat(32);
const POLICY_ID = '5'.repeat(32);
const DOMAIN_ID = '6'.repeat(32);
const PROVISION_VERSION_ID = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
const PROVISION_DEPLOYMENT_ID = 'cccccccc-cccc-4ccc-8ccc-cccccccccccc';
const BOOTSTRAP_VERSION_ID = '77777777-7777-4777-8777-777777777777';
const BOOTSTRAP_DEPLOYMENT_ID = '88888888-8888-4888-8888-888888888888';
const CLEAN_VERSION_ID = '99999999-9999-4999-8999-999999999999';
const CLEAN_DEPLOYMENT_ID = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const ADMIN_STATE_NAMESPACE_ID = 'e'.repeat(32);

const selection = parseDeploySelection({
  schemaVersion: 1,
  basics: {
    gatewayName: 'Example Gateway',
    zoneName: 'example.com',
    adminEmail: 'owner@example.com',
    additionalAdminEmails: ['admin@example.com'],
    managementHostname: 'manage.example.com',
    portalHostname: 'mcp.example.com',
  },
  firstSource: {
    name: 'Company context',
    url: 'https://source.example.net/mcp',
    enabledTools: ['company_search'],
    portalUserEmails: ['owner@example.com', 'member@example.com'],
  },
});

const target: AuthorizedTarget = Object.freeze({
  actor: Object.freeze({ id: 'actor-test', email: 'owner@example.com' }),
  account: Object.freeze({ id: '1'.repeat(32), name: 'Example account' }),
  zone: Object.freeze({ id: '2'.repeat(32), name: 'example.com', status: 'active' }),
});

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');
}

async function sha256(value: Uint8Array | string): Promise<string> {
  const bytes = v.is(v.string(), value) ? new TextEncoder().encode(value) : value;
  const owned = new Uint8Array(new ArrayBuffer(bytes.byteLength));
  owned.set(bytes);
  return bytesToHex(new Uint8Array(await crypto.subtle.digest('SHA-256', owned)));
}

async function releaseFile(path: string, contentType: string, source: string): Promise<{
  readonly bytes: Uint8Array;
  readonly record: ReleaseFileRecord;
}> {
  const bytes = new TextEncoder().encode(source);
  return {
    bytes,
    record: Object.freeze({ path, contentType, byteSize: bytes.byteLength, sha256: await sha256(bytes) }),
  };
}

async function component(files: readonly ReleaseFileRecord[]): Promise<ReleaseComponent> {
  return Object.freeze({
    files: Object.freeze([...files]),
    fileCount: files.length,
    byteSize: files.reduce((sum, file) => sum + file.byteSize, 0),
    treeSha256: await sha256(canonicalJson(files)),
  });
}

async function releaseBundle(): Promise<VerifiedReleaseBundle> {
  const values = [
    await releaseFile('payload/admin/index.html', 'text/html; charset=utf-8', '<main>admin</main>'),
    await releaseFile('payload/installer/index.html', 'text/html; charset=utf-8', '<main>installer</main>'),
    await releaseFile(
      'payload/worker-cleanup/index.js',
      'application/javascript+module',
      'export class AdminState {}; export default { fetch() { return new Response("cleanup") } };',
    ),
    await releaseFile(
      'payload/worker-retirement/index.js',
      'application/javascript+module',
      'export default { fetch() { return new Response(null, { status: 410 }) } };',
    ),
    await releaseFile(
      'payload/worker/index.js',
      'application/javascript+module',
      "const CONTROL_PLANE_ORIGIN = 'https://deploy.ankka.ai';\nexport class AdminState {}; export default { fetch() { return new Response(\"ok\") } };",
    ),
  ] as const;
  const records = values.map((entry) => entry.record);
  const manifest = parseReleaseManifest({
    schemaVersion: 1,
    release: 'gateway-v1.2.3',
    sourceCommit: '0'.repeat(40),
    oauthScopeIds: REQUIRED_OAUTH_SCOPES,
    cloudflare: APPROVED_CLOUDFLARE_RELEASE_CONTRACT,
    controlPlaneOrigin: 'https://deploy.ankka.ai',
    components: {
      admin: await component([requiredFixture(records.at(0), 'admin release record')]),
      installer: await component([requiredFixture(records.at(1), 'installer release record')]),
      worker: await component([requiredFixture(records.at(4), 'worker release record')]),
      workerCleanup: await component([requiredFixture(records.at(2), 'cleanup release record')]),
      workerRetirement: await component([requiredFixture(records.at(3), 'retirement release record')]),
    },
    artifact: {
      fileCount: records.length,
      byteSize: records.reduce((sum, file) => sum + file.byteSize, 0),
      treeSha256: await sha256(canonicalJson(records)),
    },
  });
  const payload = Object.freeze(values.map((entry): VerifiedReleasePayloadBlob => Object.freeze({
    ...entry.record,
    bytes: new Blob([new Uint8Array(entry.bytes)], { type: entry.record.contentType }),
  })));
  return Object.freeze({
    verification: 'ed25519', channel: 'stable', keyId: 'release-key-1', manifest, payload,
    envelope: Object.freeze({
      schemaVersion: 2, channel: 'stable', keyId: 'release-key-1',
      manifest: canonicalJson(manifest), signature: 'A'.repeat(86),
      signatureContext: 'ankka-mcp-gateway-release-envelope-v2',
    }),
    publicKey: 'A'.repeat(43),
  });
}

class Clock {
  value = NOW + 10;

  now = (): number => this.value++;

  advance(milliseconds: number): void {
    this.value += milliseconds;
  }
}

// Keep the executor fixture behind the same outbound-body boundary as the
// Durable Object port so a new journal field cannot pass tests but fail live.
class FakeJournalPort implements InstallJournalPort {
  value: InstallJournal | null = null;
  activePlan: StaticDeployPlan;
  approvalAttempt = ATTEMPT_ONE;
  approvalTime = NOW + 5;
  readonly events: string[];
  faultAfterArm: InstallActionName | null = null;
  faultAfterFinalTransition: 'prepare' | 'arm' | 'submitted' | 'verified' | null = null;
  faultAfterBootstrapCycle = false;
  faultAfterNestedEnableTransition: 'submitted' | 'verified' | null = null;

  constructor(plan: StaticDeployPlan, events: string[]) {
    this.activePlan = plan;
    this.events = events;
  }

  async initialize(input: Parameters<InstallJournalPort['initialize']>[0]): Promise<InstallJournal> {
    assertSecretFree(input);
    this.value = await createInstallJournal(
      input,
      selection,
      this.activePlan,
      SESSION_EXPIRES_AT,
      { attemptId: this.approvalAttempt, approvedAt: this.approvalTime },
    );
    this.events.push('journal:initialize');
    return this.value;
  }

  async read(): Promise<InstallJournal> {
    if (!this.value) throw new DeployError(404, 'session_invalid');
    return this.value;
  }

  async appendApproval(input: Parameters<InstallJournalPort['appendApproval']>[0]): Promise<InstallJournal> {
    if (!this.value) throw new Error('journal absent');
    assertSecretFree(input);
    this.value = appendInstallJournalApproval(this.value, this.activePlan, {
      ...input,
      approvedAt: this.approvalTime,
    });
    this.events.push('journal:approval');
    return this.value;
  }

  async acquireLease(input: Parameters<InstallJournalPort['acquireLease']>[0]): Promise<InstallJournal> {
    if (!this.value) throw new Error('journal absent');
    assertSecretFree(input);
    this.value = acquireInstallJournalLease(this.value, input);
    this.events.push('journal:lease');
    return this.value;
  }

  async releaseLease(input: Parameters<InstallJournalPort['releaseLease']>[0]): Promise<InstallJournal> {
    if (!this.value) throw new Error('journal absent');
    assertSecretFree(input);
    this.value = releaseInstallJournalLease(this.value, input);
    this.events.push('journal:release');
    return this.value;
  }

  async prepareAction(input: Parameters<InstallJournalPort['prepareAction']>[0]): Promise<InstallJournal> {
    if (!this.value) throw new Error('journal absent');
    assertSecretFree(input);
    this.value = await prepareInstallJournalAction(this.value, input);
    this.events.push(`journal:prepare:${input.action}`);
    if (input.action === 'final_convergence' && this.faultAfterFinalTransition === 'prepare') {
      this.faultAfterFinalTransition = null;
      throw new Error('fault_after_final_prepare');
    }
    return this.value;
  }

  async armAction(input: Parameters<InstallJournalPort['armAction']>[0]): Promise<InstallJournal> {
    if (!this.value) throw new Error('journal absent');
    assertSecretFree(input);
    this.value = armInstallJournalAction(this.value, input);
    this.events.push(`journal:arm:${input.action}`);
    if (this.faultAfterArm === input.action) {
      this.faultAfterArm = null;
      throw new Error(`fault_after_arm_${input.action}`);
    }
    if (input.action === 'final_convergence' && this.faultAfterFinalTransition === 'arm') {
      this.faultAfterFinalTransition = null;
      throw new Error('fault_after_final_arm');
    }
    return this.value;
  }

  async recordSubmitted(input: Parameters<InstallJournalPort['recordSubmitted']>[0]): Promise<InstallJournal> {
    if (!this.value) throw new Error('journal absent');
    assertSecretFree(input);
    this.value = await submitInstallJournalAction(this.value, input);
    this.events.push(`journal:submitted:${input.action}`);
    if (
      input.action === 'bootstrap_subdomain_enable' &&
      this.faultAfterNestedEnableTransition === 'submitted' &&
      this.nestedEnablePhase() === 'submitted'
    ) {
      this.faultAfterNestedEnableTransition = null;
      throw new Error('fault_after_nested_enable_submitted');
    }
    if (input.action === 'final_convergence' && this.faultAfterFinalTransition === 'submitted') {
      this.faultAfterFinalTransition = null;
      throw new Error('fault_after_final_submitted');
    }
    return this.value;
  }

  async verifyAction(input: Parameters<InstallJournalPort['verifyAction']>[0]): Promise<InstallJournal> {
    if (!this.value) throw new Error('journal absent');
    assertSecretFree(input);
    this.value = verifyInstallJournalAction(this.value, input);
    this.events.push(`journal:verified:${input.action}`);
    if (
      input.action === 'bootstrap_subdomain_enable' &&
      this.faultAfterNestedEnableTransition === 'verified' &&
      this.nestedEnablePhase() === 'verified'
    ) {
      this.faultAfterNestedEnableTransition = null;
      throw new Error('fault_after_nested_enable_verified');
    }
    if (input.action === 'final_convergence' && this.faultAfterFinalTransition === 'verified') {
      this.faultAfterFinalTransition = null;
      throw new Error('fault_after_final_verified');
    }
    return this.value;
  }

  async appendCustomerBootstrapCycle(
    input: Parameters<InstallJournalPort['appendCustomerBootstrapCycle']>[0],
  ): Promise<InstallJournal> {
    if (!this.value) throw new Error('journal absent');
    assertSecretFree(input);
    this.value = await appendCustomerBootstrapAttempt(this.value, input);
    this.events.push('journal:bootstrap-cycle');
    if (this.faultAfterBootstrapCycle) {
      this.faultAfterBootstrapCycle = false;
      throw new Error('fault_after_nested_enable_prepared');
    }
    return this.value;
  }

  private nestedEnablePhase(): string | null {
    const bootstrap = this.value?.actions.find((entry) => entry.name === 'customer_bootstrap_submit');
    if (bootstrap?.record.kind !== 'customer_bootstrap_submit' || bootstrap.record.attempts.length < 2) return null;
    return bootstrap.record.attempts.at(-1)?.enable.phase ?? null;
  }

  expireLease(now: number): void {
    if (this.value) this.value = expireInstallJournalLease(this.value, now);
  }
}

class FakeProvider implements ReviewedInstallProviderAdapter {
  readonly events: string[];
  worker: WorkerSubmission | null = null;
  application: { readonly applicationId: string; readonly aud: string } | null = null;
  policy: { readonly policyId: string } | null = null;
  domain: { readonly domainId: string } | null = null;
  readonly versions = new Map<WorkerVersionPhase, VersionSubmission>();
  readonly deployments = new Map<WorkerVersionPhase, DeploymentSubmission>();
  subdomainEnabled = false;
  bootstrapResponses: Array<'ready' | 'recovery_required'> = ['ready'];
  bootstrapRequestIds: string[] = [];
  stageCount = 0;
  issuer = 'https://example.cloudflareaccess.com';
  faultAfterAssetStage: WorkerVersionPhase | null = null;
  faultOnNextEnableSet: 'before_state' | 'after_state' | null = null;
  foreignDeploymentBecomesActiveAfterBootstrapReady = false;
  foreignDeploymentBecomesActiveAfterDomain = false;
  foreignDeploymentActive = false;
  bootstrapActiveProofs = 0;
  historicalCleanDeploymentProofs = 0;
  namespaceProofs = 0;
  adminStateNamespaceId = ADMIN_STATE_NAMESPACE_ID;
  namespaceDriftsAfterDomain = false;
  customerGatewayPreflightError: CustomerGatewayFreshPreflightError | null = null;

  constructor(events: string[]) {
    this.events = events;
  }

  async getZeroTrustOrganization() {
    this.events.push('read:zero-trust-organization');
    return Object.freeze({ name: 'Example', authDomain: 'example.cloudflareaccess.com', issuer: this.issuer });
  }

  async listAccessIdentityProviders() {
    this.events.push('read:identity-providers');
    return Object.freeze([Object.freeze({ id: 'a'.repeat(32), name: 'Google', type: 'google', readOnly: false })]);
  }

  async getAccountWorkersSubdomain() {
    this.events.push('read:workers-subdomain');
    return Object.freeze({ accountId: target.account.id, subdomain: 'example-account' });
  }

  async preflightFreshManagementApplication(): Promise<void> {
    this.events.push('preflight:management-app');
  }

  async preflightFreshManagementDomain(): Promise<void> {
    this.events.push('preflight:management-domain');
  }

  async preflightFreshCustomerGateway(input: Parameters<ReviewedInstallProviderAdapter['preflightFreshCustomerGateway']>[0]) {
    this.events.push('preflight:customer-seven');
    if (this.customerGatewayPreflightError) throw this.customerGatewayPreflightError;
    const projection = await deriveCustomerGatewayExpectedProjection({
      selection: input.selection,
      target: input.target,
      plan: input.plan,
      release: { id: input.release.manifest.release, artifactSha256: input.release.manifest.artifact.treeSha256 },
    });
    const unsigned = {
      schemaVersion: 1 as const,
      kind: 'customer_gateway_fresh_preflight' as const,
      accountId: input.target.account.id,
      zoneId: input.target.zone.id,
      planId: input.plan.planId,
      planHash: input.plan.planHash,
      installationId: projection.expected.installationId,
      configurationHash: projection.expected.configurationHash,
      desiredHash: projection.expected.desiredHash,
      releaseId: input.release.manifest.release,
      releaseArtifactSha256: input.release.manifest.artifact.treeSha256,
      zeroCandidateKinds: projection.resourceKinds,
      checkedAt: input.nowMs,
      expiresAt: input.nowMs + 30_000,
    };
    return Object.freeze({
      ...unsigned,
      attestationHash: `sha256:${await sha256Hex(canonicalJson(unsigned))}`,
    });
  }

  async inspectWorker(): Promise<WorkerSubmission | null> {
    this.events.push('read:worker-inspect');
    return this.worker;
  }

  async submitWorker(intent: WorkerMutationIntent): Promise<WorkerSubmission> {
    this.events.push('provider:worker-create');
    this.worker = Object.freeze({
      kind: 'worker', accountId: intent.accountId, workerName: intent.workerName, workerId: WORKER_ID,
    });
    return this.worker;
  }

  async verifyWorker(_intent: WorkerMutationIntent, locator: WorkerSubmission): Promise<WorkerSubmission> {
    if (!this.worker || this.worker.workerId !== locator.workerId) throw new Error('worker mismatch');
    return locator;
  }

  async submitManagementApplication() {
    this.events.push('provider:app-create');
    this.application = Object.freeze({ applicationId: APPLICATION_ID, aud: 'access-audience-1234' });
    return this.application;
  }

  async recoverManagementApplication() {
    if (!this.application) throw new Error('application missing');
    return this.application;
  }

  async verifyManagementApplication(locator: { readonly applicationId: string; readonly aud: string }) {
    if (!this.application || this.application.applicationId !== locator.applicationId || this.application.aud !== locator.aud) {
      throw new Error('application mismatch');
    }
    return locator;
  }

  async submitManagementPolicy() {
    this.events.push('provider:policy-create');
    this.policy = Object.freeze({ policyId: POLICY_ID });
    return this.policy;
  }

  async recoverManagementPolicy() {
    if (!this.policy) throw new Error('policy missing');
    return this.policy;
  }

  async verifyManagementPolicy(locator: { readonly policyId: string }) {
    if (!this.policy || this.policy.policyId !== locator.policyId) throw new Error('policy mismatch');
    return locator;
  }

  prepareWorkerVersionRecovery = prepareWorkerVersionRecoveryRecord;

  async stageWorkerVersionSubmission(
    prepared: Parameters<ReviewedInstallProviderAdapter['stageWorkerVersionSubmission']>[0],
    worker: WorkerSubmission,
    expected: WorkerVersionRecoveryRecord,
    phase: WorkerVersionPhase,
  ): Promise<WorkerVersionMutationPlan> {
    this.events.push(`provider:assets:${phase}`);
    this.stageCount += 1;
    // The provision version has no ASSETS binding, so no asset completion token.
    const plan = await prepareWorkerVersionMutation(
      prepared,
      worker,
      phase === 'provision' ? null : 'completion-jwt-value',
      phase,
    );
    expect(plan.recovery).toEqual(expected);
    if (this.faultAfterAssetStage === phase) {
      this.faultAfterAssetStage = null;
      throw new Error(`fault_after_asset_stage_${phase}`);
    }
    return plan;
  }

  async inspectWorkerVersion(recovery: WorkerVersionRecoveryRecord): Promise<VersionSubmission | null> {
    return this.versions.get(recovery.phase) ?? null;
  }

  async submitWorkerVersion(plan: WorkerVersionMutationPlan): Promise<VersionSubmission> {
    this.events.push(`provider:version:${plan.recovery.phase}`);
    const id = plan.recovery.phase === 'provision'
      ? PROVISION_VERSION_ID
      : plan.recovery.phase === 'bootstrap' ? BOOTSTRAP_VERSION_ID : CLEAN_VERSION_ID;
    const submission = Object.freeze({
      kind: 'version' as const,
      phase: plan.recovery.phase,
      accountId: plan.recovery.accountId,
      workerName: plan.recovery.workerName,
      workerId: plan.recovery.workerId,
      versionId: id,
      requestHash: plan.recovery.requestHash,
      correlationTag: plan.recovery.correlationTag,
    });
    this.versions.set(plan.recovery.phase, submission);
    return submission;
  }

  async verifyWorkerVersion(
    recovery: WorkerVersionRecoveryRecord,
    locator: VersionSubmission,
    _call?: ReviewedInstallProviderCall,
    expectedNamespaceId?: string,
  ) {
    if (this.versions.get(recovery.phase)?.versionId !== locator.versionId) throw new Error('version mismatch');
    if (expectedNamespaceId !== undefined && expectedNamespaceId !== this.adminStateNamespaceId) {
      throw new Error('namespace mismatch');
    }
    return locator;
  }

  async inspectAdminStateNamespace(
    input: Parameters<ReviewedInstallProviderAdapter['inspectAdminStateNamespace']>[0],
  ) {
    this.namespaceProofs += 1;
    if (input.expectedNamespaceId !== undefined && input.expectedNamespaceId !== ADMIN_STATE_NAMESPACE_ID) {
      throw new Error('namespace mismatch');
    }
    return Object.freeze({
      accountId: input.accountId,
      namespaceId: this.adminStateNamespaceId,
      namespaceName: 'admin-state-namespace',
      workerName: input.workerName,
      className: 'AdminState' as const,
      storage: 'sqlite' as const,
    });
  }

  async inspectWorkerDeployment(intent: WorkerDeploymentMutationIntent): Promise<DeploymentSubmission | null> {
    return this.deployments.get(intent.phase) ?? null;
  }

  async submitWorkerDeployment(intent: WorkerDeploymentMutationIntent): Promise<DeploymentSubmission> {
    this.events.push(`provider:deployment:${intent.phase}`);
    const id = intent.phase === 'provision'
      ? PROVISION_DEPLOYMENT_ID
      : intent.phase === 'bootstrap' ? BOOTSTRAP_DEPLOYMENT_ID : CLEAN_DEPLOYMENT_ID;
    const submission = Object.freeze({
      kind: 'deployment' as const,
      phase: intent.phase,
      accountId: intent.accountId,
      workerName: intent.workerName,
      workerId: intent.workerId,
      versionId: intent.versionId,
      deploymentId: id,
      requestHash: intent.requestHash,
      correlationTag: intent.correlationTag,
    });
    this.deployments.set(intent.phase, submission);
    return submission;
  }

  async verifyWorkerDeployment(intent: WorkerDeploymentMutationIntent, locator: DeploymentSubmission) {
    if (this.deployments.get(intent.phase)?.deploymentId !== locator.deploymentId) {
      throw new Error('deployment mismatch');
    }
    if (intent.phase === 'clean') this.historicalCleanDeploymentProofs += 1;
    return locator;
  }

  async proveActiveWorkerVersion(
    recovery: WorkerVersionRecoveryRecord,
    _call: ReviewedInstallProviderCall,
    expectedNamespaceId: string,
  ) {
    this.events.push(`read:active-version:${recovery.phase}`);
    if (recovery.phase !== 'bootstrap' || expectedNamespaceId !== this.adminStateNamespaceId ||
      this.foreignDeploymentActive) throw new Error('active bootstrap version mismatch');
    const version = this.versions.get('bootstrap');
    const deployment = this.deployments.get('bootstrap');
    if (!version || !deployment || version.requestHash !== recovery.requestHash) {
      throw new Error('active bootstrap version missing');
    }
    this.bootstrapActiveProofs += 1;
    return Object.freeze({ version, deployment });
  }

  async verifyActiveWorkerDeployment(
    intent: WorkerDeploymentMutationIntent,
    locator: DeploymentSubmission,
  ) {
    if (
      intent.phase !== 'clean' ||
      locator.phase !== 'clean' ||
      locator.deploymentId !== CLEAN_DEPLOYMENT_ID ||
      this.foreignDeploymentActive
    ) throw new Error('active deployment mismatch');
    return locator;
  }

  async setWorkerSubdomain(enabled: boolean) {
    this.events.push(`provider:subdomain:${String(enabled)}`);
    if (enabled && this.faultOnNextEnableSet === 'before_state') {
      this.faultOnNextEnableSet = null;
      throw new Error('fault_after_nested_enable_arm_observed_false');
    }
    this.subdomainEnabled = enabled;
    if (enabled && this.faultOnNextEnableSet === 'after_state') {
      this.faultOnNextEnableSet = null;
      throw new Error('fault_after_nested_enable_arm_observed_true');
    }
    return Object.freeze({ enabled, previewsEnabled: false as const });
  }

  async verifyWorkerSubdomain(expectedEnabled: boolean) {
    if (this.subdomainEnabled !== expectedEnabled) throw new Error('subdomain mismatch');
    return Object.freeze({ enabled: expectedEnabled, previewsEnabled: false as const });
  }

  async awaitCustomerBootstrapReady(): Promise<void> {
    this.events.push('provider:bootstrap-ready');
    if (this.foreignDeploymentBecomesActiveAfterBootstrapReady) this.foreignDeploymentActive = true;
  }

  async submitCustomerBootstrap(input: Parameters<ReviewedInstallProviderAdapter['submitCustomerBootstrap']>[0]) {
    this.events.push(`provider:bootstrap:${input.claim.requestId}`);
    this.bootstrapRequestIds.push(input.claim.requestId);
    const response = this.bootstrapResponses.shift() ?? 'ready';
    if (response === 'recovery_required') {
      return Object.freeze({
        schemaVersion: 1 as const,
        status: 'recovery_required' as const,
        reason: 'bootstrap_recovery_required' as const,
        canRetry: false as const,
      });
    }
    const expectation = await deriveCustomerGatewayInstallationReceiptExpectation({
      selection: input.selection,
      target: input.target,
      plan: input.plan,
      release: {
        id: input.release.manifest.release,
        artifactSha256: input.release.manifest.artifact.treeSha256,
      },
    });
    const evidence = await readyInstallationReceiptFixture(expectation, 7);
    return Object.freeze({
      schemaVersion: 1 as const,
      status: 'ready' as const,
      installationId: input.claim.expected.installationId,
      approvedPlanId: `plan-${'7'.repeat(24)}`,
      configurationHash: input.claim.expected.configurationHash,
      desiredHash: input.claim.expected.desiredHash,
      settingsRevision: 1 as const,
      release: input.claim.release,
      gateway: Object.freeze({
        hostname: input.claim.settings.connect.hostname,
        mcpUrl: `https://${input.claim.settings.connect.hostname}/mcp`,
      }),
      receipt: Object.freeze({ revision: 7, resourceCount: 7 as const, evidence }),
      applyInvoked: true,
      resumed: this.bootstrapRequestIds.length > 1,
    });
  }

  async submitManagementDomain() {
    this.events.push('provider:domain-create');
    if (this.foreignDeploymentBecomesActiveAfterDomain) this.foreignDeploymentActive = true;
    if (this.namespaceDriftsAfterDomain) this.adminStateNamespaceId = 'f'.repeat(32);
    this.domain = Object.freeze({ domainId: DOMAIN_ID });
    return this.domain;
  }

  async recoverManagementDomain() {
    if (!this.domain) throw new Error('domain missing');
    return this.domain;
  }

  async verifyManagementDomain(locator: { readonly domainId: string }) {
    if (!this.domain || this.domain.domainId !== locator.domainId) throw new Error('domain mismatch');
    return locator;
  }
}

async function setup() {
  const bundle = await releaseBundle();
  const plan = await buildStaticDeployPlan(selection, bundle.manifest, NOW + 5 * 60_000);
  const events: string[] = [];
  const clock = new Clock();
  const journal = new FakeJournalPort(plan, events);
  const provider = new FakeProvider(events);
  let randomOffset = 0;
  const base: Omit<ReviewedInstallExecutionInput, 'accessToken' | 'attemptId' | 'plan'> = {
    selection,
    target,
    releaseBundle: bundle,
    sessionId: SESSION_ID,
    bootstrapNonceDerivationKey: BOOTSTRAP_NONCE_KEY,
    recoverUntil: RECOVER_UNTIL,
    journal,
    provider,
    transport: async () => new Response(null, { status: 500 }),
    now: clock.now,
    randomBytes: (length) => Uint8Array.from({ length }, (_value, index) => index + 1 + randomOffset++),
  };
  return { base, bundle, clock, events, journal, plan, provider };
}

function input(
  fixture: Awaited<ReturnType<typeof setup>>,
  plan: StaticDeployPlan,
  attemptId: string,
  accessToken: string,
): ReviewedInstallExecutionInput {
  return { ...fixture.base, plan, attemptId, accessToken };
}

async function renew(
  fixture: Awaited<ReturnType<typeof setup>>,
  attemptId: string,
): Promise<StaticDeployPlan> {
  fixture.clock.advance(6 * 60_000);
  fixture.journal.expireLease(fixture.clock.value);
  const nextExpiry = Math.max(fixture.journal.activePlan.expiresAt, fixture.clock.value) + 5 * 60_000;
  const plan = await buildStaticDeployPlan(selection, fixture.bundle.manifest, nextExpiry);
  fixture.journal.activePlan = plan;
  fixture.journal.approvalAttempt = attemptId;
  fixture.journal.approvalTime = fixture.clock.value;
  return plan;
}

describe('isolated reviewed install executor', () => {
  it('uses the asset-session JWT when the exact asset set needs zero buckets', async () => {
    const bundle = await releaseBundle();
    const direct = await adaptVerifiedReleaseBundleForWorkerDirectUpload(bundle);
    const prepared = await prepareVerifiedWorkerRelease({
      accountId: target.account.id,
      workerName: 'ankka-gateway-test',
      release: direct,
      plainTextBindings: {
        ADMIN_EMAILS: 'owner@example.com',
        ANKKA_GATEWAY_RELEASE: bundle.manifest.release,
        ANKKA_GATEWAY_RELEASE_SHA256: `sha256:${bundle.manifest.artifact.treeSha256}`,
        ANKKA_MANAGEMENT_HOSTNAME: 'manage.example.com',
        ANKKA_UPDATE_CHANNEL: 'stable',
        ANKKA_UPDATE_KEY_ID: bundle.keyId,
        ANKKA_UPDATE_PUBLIC_KEY: bundle.publicKey,
        ANKKA_WORKERS_SUBDOMAIN: 'customer-workers',
        ANKKA_WORKER_NAME: 'ankka-gateway-test',
        CF_ACCESS_AUD: 'access-audience-1234',
        CF_ACCESS_ISSUER: 'https://example.cloudflareaccess.com',
        CLOUDFLARE_ACCOUNT_ID: target.account.id,
        CLOUDFLARE_ZONE_ID: target.zone.id,
        CLOUDFLARE_ZONE_NAME: target.zone.name,
        ZERO_TRUST_READY: 'true',
      },
      bootstrapNonce: 'BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc',
    });
    const worker: WorkerSubmission = Object.freeze({
      kind: 'worker', accountId: target.account.id, workerName: prepared.workerName, workerId: WORKER_ID,
    });
    const recovery = await prepareWorkerVersionRecoveryRecord(prepared, worker, 'bootstrap');
    const requests: Request[] = [];
    const adapter = createCloudflareReviewedInstallProviderAdapter();
    const plan = await adapter.stageWorkerVersionSubmission(prepared, worker, recovery, 'bootstrap', {
      accessToken: ACCESS_TOKEN_ONE,
      transport: async (request) => {
        requests.push(request);
        return new Response(JSON.stringify({
          success: true,
          errors: [],
          messages: [],
          result: { jwt: 'asset-session-completion-jwt', buckets: [] },
        }), { status: 201, headers: { 'content-type': 'application/json' } });
      },
    });
    expect(requests).toHaveLength(1);
    expect(requiredFixture(requests.at(0), 'asset upload session request').url).toContain('/assets-upload-session');
    expect(plan.recovery).toEqual(recovery);
    expect(JSON.stringify(plan.recovery)).not.toContain('asset-session-completion-jwt');
  });

  it('journals every durable semantic action, stages assets before Version arm, and converges exactly', async () => {
    const fixture = await setup();
    const result = await executeReviewedInstall(input(fixture, fixture.plan, ATTEMPT_ONE, ACCESS_TOKEN_ONE));

    expect(result.installationId).toMatch(/^acg-[a-f0-9]{24}$/u);
    expect(fixture.events.slice(0, 8)).toEqual([
      'read:zero-trust-organization',
      'read:identity-providers',
      'read:workers-subdomain',
      'preflight:customer-seven',
      'read:worker-inspect',
      'preflight:management-app',
      'preflight:management-domain',
      'journal:initialize',
    ]);
    expect(fixture.journal.value?.actions[0]).toMatchObject({
      name: 'gateway_fresh_preflight',
      phase: 'verified',
      record: { zeroCandidateKinds: expect.any(Array) },
    });
    expect(fixture.journal.value?.actions[0]?.record.kind === 'customer_gateway_fresh_preflight' &&
      fixture.journal.value.actions[0].record.zeroCandidateKinds).toEqual([
      'mcp_server',
      'source_access_application',
      'source_access_policy',
      'portal',
      'portal_access_application',
      'portal_access_policy',
      'dns_record',
    ]);
    expect(fixture.journal.value?.actions.map((entry) => entry.name)).toEqual([
      'gateway_fresh_preflight',
      'worker_create',
      'management_access_application_create',
      'management_admin_policy_create',
      'provision_worker_version_create',
      'provision_worker_deployment_create',
      'bootstrap_worker_version_create',
      'bootstrap_worker_deployment_create',
      'bootstrap_subdomain_enable',
      'customer_bootstrap_submit',
      'bootstrap_subdomain_disable',
      'clean_worker_version_create',
      'clean_worker_deployment_create',
      'management_custom_domain_attach',
      'final_convergence',
    ]);
    expect(fixture.journal.value?.actions.at(-1)).toMatchObject({ name: 'final_convergence', phase: 'verified' });
    // The provision version carries no namespace; bootstrap and clean do.
    expect(fixture.journal.value?.actions[4]?.locator).not.toHaveProperty('namespaceId');
    expect(fixture.journal.value?.actions[6]?.locator).toMatchObject({ namespaceId: ADMIN_STATE_NAMESPACE_ID });
    expect(fixture.journal.value?.actions[11]?.locator).toMatchObject({ namespaceId: ADMIN_STATE_NAMESPACE_ID });
    expect(fixture.journal.value?.actions.at(-1)?.locator).toMatchObject({
      adminStateNamespaceId: ADMIN_STATE_NAMESPACE_ID,
      customerReceiptEvidence: { state: 'ready', resources: expect.any(Array), checksum: expect.any(String) },
    });
    expect(fixture.provider.namespaceProofs).toBeGreaterThanOrEqual(7);
    expect(fixture.journal.value?.lease).toBeNull();
    expect(fixture.events.at(-2)).toBe('journal:verified:final_convergence');
    expect(fixture.events.at(-1)).toBe('journal:release');
    expect(fixture.events.filter((event) => event === 'provider:domain-create')).toHaveLength(1);
    const durableMutations = fixture.events.filter((event) => event.startsWith('provider:'));
    expect(durableMutations.at(-1)).toBe('provider:domain-create');
    for (const phase of ['bootstrap', 'clean']) {
      expect(fixture.events.indexOf(`journal:prepare:${phase}_worker_version_create`))
        .toBeLessThan(fixture.events.indexOf(`provider:assets:${phase}`));
      expect(fixture.events.indexOf(`provider:assets:${phase}`))
        .toBeLessThan(fixture.events.indexOf(`journal:arm:${phase}_worker_version_create`));
      expect(fixture.events.indexOf(`journal:arm:${phase}_worker_version_create`))
        .toBeLessThan(fixture.events.indexOf(`provider:version:${phase}`));
    }
    const serialized = JSON.stringify(fixture.journal.value);
    expect(serialized).not.toContain(ACCESS_TOKEN_ONE);
    expect(serialized).not.toContain(BOOTSTRAP_NONCE_KEY);
    expect(serialized).not.toContain('completion-jwt-value');
    expect(serialized.toLowerCase()).not.toContain('nonce');
  });

  it('reports an existing gateway before inspecting its deterministic Worker', async () => {
    const fixture = await setup();
    const expectedProjection = await deriveCustomerGatewayExpectedProjection({
      selection,
      target,
      plan: fixture.plan,
      release: {
        id: fixture.bundle.manifest.release,
        artifactSha256: fixture.bundle.manifest.artifact.treeSha256,
      },
    });
    fixture.provider.worker = Object.freeze({
      kind: 'worker',
      accountId: target.account.id,
      workerName: `ankka-gateway-example-gateway-${fixture.plan.managementOwnershipMarker}`,
      workerId: WORKER_ID,
    });
    const detected = new CustomerGatewayFreshPreflightError(
      'existing_gateway_detected',
      'portal_list',
      Object.freeze({
        schemaVersion: 1,
        installationId: expectedProjection.expected.installationId,
        name: selection.basics.gatewayName,
        managementHostname: selection.basics.managementHostname,
        portalHostname: selection.basics.portalHostname,
        workerName: fixture.provider.worker.workerName,
      }),
    );
    fixture.provider.customerGatewayPreflightError = detected;

    await expect(executeReviewedInstall(input(
      fixture,
      fixture.plan,
      ATTEMPT_ONE,
      ACCESS_TOKEN_ONE,
    ))).rejects.toBe(detected);
    expect(fixture.events).toEqual([
      'read:zero-trust-organization',
      'read:identity-providers',
      'read:workers-subdomain',
      'preflight:customer-seven',
    ]);
    expect(fixture.journal.value).toBeNull();
  });

  it('rejects a foreign active deployment before exposing workers.dev or sending the grant', async () => {
    const fixture = await setup();
    fixture.provider.foreignDeploymentActive = true;

    await expect(executeReviewedInstall(input(fixture, fixture.plan, ATTEMPT_ONE, ACCESS_TOKEN_ONE)))
      .rejects.toThrow('active bootstrap version mismatch');

    expect(fixture.provider.bootstrapRequestIds).toHaveLength(0);
    expect(fixture.events.filter((event) => event.startsWith('provider:subdomain:'))).toEqual([]);
    expect(fixture.events).not.toContain('provider:bootstrap-ready');
    expect(fixture.journal.value?.actions.at(-1)).toMatchObject({
      name: 'bootstrap_worker_deployment_create',
      phase: 'verified',
    });
  });

  it('closes workers.dev without sending the grant when deployment drifts while the route becomes ready', async () => {
    const fixture = await setup();
    fixture.provider.foreignDeploymentBecomesActiveAfterBootstrapReady = true;

    await expect(executeReviewedInstall(input(fixture, fixture.plan, ATTEMPT_ONE, ACCESS_TOKEN_ONE)))
      .rejects.toThrow('active bootstrap version mismatch');

    expect(fixture.provider.bootstrapRequestIds).toHaveLength(0);
    expect(fixture.provider.bootstrapActiveProofs).toBe(1);
    expect(fixture.events.filter((event) => event.startsWith('provider:subdomain:'))).toEqual([
      'provider:subdomain:true',
      'provider:subdomain:false',
    ]);
    expect(fixture.provider.subdomainEnabled).toBe(false);
    const bootstrap = fixture.journal.value?.actions.find((entry) => entry.name === 'customer_bootstrap_submit');
    expect(bootstrap).toMatchObject({ phase: 'prepared' });
  });

  it('refuses final convergence when a foreign deployment becomes currently active', async () => {
    const fixture = await setup();
    fixture.provider.foreignDeploymentBecomesActiveAfterDomain = true;

    await expect(executeReviewedInstall(input(fixture, fixture.plan, ATTEMPT_ONE, ACCESS_TOKEN_ONE)))
      .rejects.toThrow('active deployment mismatch');

    expect(fixture.provider.historicalCleanDeploymentProofs).toBeGreaterThan(0);
    expect(fixture.events).toContain('provider:domain-create');
    expect(fixture.events).not.toContain('journal:prepare:final_convergence');
    expect(fixture.journal.value?.actions.at(-1)).toMatchObject({
      name: 'management_custom_domain_attach',
      phase: 'verified',
    });
    expect(fixture.journal.value?.lease).not.toBeNull();
  });

  it('refuses final convergence when the fully listed AdminState namespace drifts', async () => {
    const fixture = await setup();
    fixture.provider.namespaceDriftsAfterDomain = true;

    await expect(executeReviewedInstall(input(fixture, fixture.plan, ATTEMPT_ONE, ACCESS_TOKEN_ONE)))
      .rejects.toThrow('namespace mismatch');

    expect(fixture.events).toContain('provider:domain-create');
    expect(fixture.events).not.toContain('journal:prepare:final_convergence');
    expect(fixture.journal.value?.actions.at(-1)).toMatchObject({
      name: 'management_custom_domain_attach', phase: 'verified',
    });
  });

  it.each(['prepare', 'arm', 'submitted', 'verified'] as const)(
    'resumes exact local final convergence after a crash following %s',
    async (transition) => {
      const fixture = await setup();
      fixture.journal.faultAfterFinalTransition = transition;

      await expect(executeReviewedInstall(input(fixture, fixture.plan, ATTEMPT_ONE, ACCESS_TOKEN_ONE)))
        .rejects.toThrow(`fault_after_final_${transition}`);

      const expectedPhase = {
        prepare: 'prepared',
        arm: 'send_armed',
        submitted: 'submitted',
        verified: 'verified',
      } as const;
      expect(fixture.journal.value?.actions.at(-1)).toMatchObject({
        name: 'final_convergence',
        phase: expectedPhase[transition],
      });
      const providerMutationCount = fixture.events.filter((event) => event.startsWith('provider:')).length;

      const renewed = await renew(fixture, ATTEMPT_TWO);
      const result = await executeReviewedInstall(input(fixture, renewed, ATTEMPT_TWO, ACCESS_TOKEN_TWO));

      expect(result.installationId).toMatch(/^acg-/u);
      expect(fixture.events.filter((event) => event.startsWith('provider:')))
        .toHaveLength(providerMutationCount);
      expect(fixture.journal.value?.actions.at(-1)).toMatchObject({
        name: 'final_convergence',
        phase: 'verified',
      });
      expect(fixture.journal.value?.lease).toBeNull();
    },
  );

  it('does not retry an unknown Worker create after a journaled arm', async () => {
    const fixture = await setup();
    fixture.journal.faultAfterArm = 'worker_create';
    await expect(executeReviewedInstall(input(fixture, fixture.plan, ATTEMPT_ONE, ACCESS_TOKEN_ONE)))
      .rejects.toThrow('fault_after_arm_worker_create');
    expect(fixture.provider.worker).toBeNull();

    const renewed = await renew(fixture, ATTEMPT_TWO);
    await expect(executeReviewedInstall(input(fixture, renewed, ATTEMPT_TWO, ACCESS_TOKEN_TWO)))
      .rejects.toMatchObject({ code: 'provider_recovery_missing', canRetry: false });
    expect(fixture.events.filter((event) => event === 'provider:worker-create')).toHaveLength(0);
    expect(fixture.events.filter((event) => event === 'preflight:customer-seven')).toHaveLength(1);
  });

  it.each([
    ['management_access_application_create', 'provider:app-create'],
    ['management_admin_policy_create', 'provider:policy-create'],
    ['bootstrap_worker_version_create', 'provider:version:bootstrap'],
    ['bootstrap_worker_deployment_create', 'provider:deployment:bootstrap'],
    ['clean_worker_version_create', 'provider:version:clean'],
    ['clean_worker_deployment_create', 'provider:deployment:clean'],
    ['management_custom_domain_attach', 'provider:domain-create'],
  ] as const)('never retries an absent create after an unknown armed %s', async (actionName, mutationEvent) => {
    const fixture = await setup();
    fixture.journal.faultAfterArm = actionName;

    await expect(executeReviewedInstall(input(fixture, fixture.plan, ATTEMPT_ONE, ACCESS_TOKEN_ONE)))
      .rejects.toThrow(`fault_after_arm_${actionName}`);
    expect(fixture.events.filter((event) => event === mutationEvent)).toHaveLength(0);

    const renewed = await renew(fixture, ATTEMPT_TWO);
    await expect(executeReviewedInstall(input(fixture, renewed, ATTEMPT_TWO, ACCESS_TOKEN_TWO))).rejects.toThrow();
    expect(fixture.events.filter((event) => event === mutationEvent)).toHaveLength(0);
  });

  it('safety-disables an outcome-unknown bootstrap request and uses a fresh request under a new grant', async () => {
    const fixture = await setup();
    fixture.journal.faultAfterArm = 'customer_bootstrap_submit';

    await expect(executeReviewedInstall(input(fixture, fixture.plan, ATTEMPT_ONE, ACCESS_TOKEN_ONE)))
      .rejects.toThrow('fault_after_arm_customer_bootstrap_submit');
    expect(fixture.provider.bootstrapRequestIds).toHaveLength(0);
    expect(fixture.provider.subdomainEnabled).toBe(true);

    const renewed = await renew(fixture, ATTEMPT_TWO);
    const result = await executeReviewedInstall(input(fixture, renewed, ATTEMPT_TWO, ACCESS_TOKEN_TWO));

    expect(result.installationId).toMatch(/^acg-/u);
    expect(fixture.provider.bootstrapRequestIds).toHaveLength(1);
    expect(fixture.events.filter((event) => event.startsWith('provider:subdomain:'))).toEqual([
      'provider:subdomain:true',
      'provider:subdomain:false',
      'provider:subdomain:true',
      'provider:subdomain:false',
    ]);
    const bootstrap = fixture.journal.value?.actions.find((entry) => entry.name === 'customer_bootstrap_submit');
    if (bootstrap?.record.kind !== 'customer_bootstrap_submit') throw new Error('bootstrap missing');
    expect(bootstrap.record.attempts).toHaveLength(2);
    const initialAttempt = requiredFixture(bootstrap.record.attempts.at(0), 'initial bootstrap attempt');
    expect(initialAttempt).toMatchObject({ phase: 'send_armed', locator: null });
    expect(initialAttempt.disable?.phase).toBe('verified');
    expect(requiredFixture(bootstrap.record.attempts.at(1), 'recovery bootstrap attempt')).toMatchObject({
      approvalAttemptId: ATTEMPT_TWO,
      phase: 'verified',
      locator: { status: 'ready', resumed: false },
    });
  });

  it.each([
    ['prepared', 'prepared', false, 'fault_after_nested_enable_prepared'],
    ['send_armed_observed_true', 'send_armed', true, 'fault_after_nested_enable_arm_observed_true'],
    ['send_armed_observed_false', 'send_armed', false, 'fault_after_nested_enable_arm_observed_false'],
    ['submitted', 'submitted', true, 'fault_after_nested_enable_submitted'],
    ['verified', 'verified', true, 'fault_after_nested_enable_verified'],
  ] as const)(
    'a new grant settles nested enable %s, disables it, then appends a fresh cycle',
    async (fault, storedPhase, observedEnabled, expectedError) => {
      const fixture = await setup();
      fixture.provider.bootstrapResponses = ['recovery_required', 'ready'];

      await expect(executeReviewedInstall(input(fixture, fixture.plan, ATTEMPT_ONE, ACCESS_TOKEN_ONE)))
        .rejects.toMatchObject({ code: 'bootstrap_recovery_required' });
      expect(fixture.provider.subdomainEnabled).toBe(false);
      expect(fixture.provider.bootstrapRequestIds).toHaveLength(1);

      const secondPlan = await renew(fixture, ATTEMPT_TWO);
      if (fault === 'prepared') fixture.journal.faultAfterBootstrapCycle = true;
      if (fault === 'send_armed_observed_true') fixture.provider.faultOnNextEnableSet = 'after_state';
      if (fault === 'send_armed_observed_false') fixture.provider.faultOnNextEnableSet = 'before_state';
      if (fault === 'submitted' || fault === 'verified') {
        fixture.journal.faultAfterNestedEnableTransition = fault;
      }
      await expect(executeReviewedInstall(input(fixture, secondPlan, ATTEMPT_TWO, ACCESS_TOKEN_TWO)))
        .rejects.toThrow(expectedError);

      const interrupted = fixture.journal.value?.actions.find(
        (entry) => entry.name === 'customer_bootstrap_submit',
      );
      if (interrupted?.record.kind !== 'customer_bootstrap_submit') throw new Error('bootstrap missing');
      expect(interrupted.record.attempts).toHaveLength(2);
      const inherited = requiredFixture(interrupted.record.attempts.at(1), 'inherited bootstrap attempt');
      expect(inherited.enable).toMatchObject({
        approvalAttemptId: ATTEMPT_TWO,
        phase: storedPhase,
      });
      expect(inherited.disable).toBeNull();
      expect(fixture.provider.subdomainEnabled).toBe(observedEnabled);
      expect(fixture.provider.bootstrapRequestIds).toHaveLength(1);
      await expect(requireInstallJournal(structuredClone(fixture.journal.value))).resolves.toBeDefined();

      const inheritedRequestId = inherited.requestId;
      const recoveryEventOffset = fixture.events.length;
      const thirdPlan = await renew(fixture, ATTEMPT_THREE);
      const result = await executeReviewedInstall(
        input(fixture, thirdPlan, ATTEMPT_THREE, ACCESS_TOKEN_THREE),
      );

      expect(result.installationId).toMatch(/^acg-/u);
      expect(fixture.provider.subdomainEnabled).toBe(false);
      expect(fixture.provider.bootstrapRequestIds).toHaveLength(2);
      expect(new Set(fixture.provider.bootstrapRequestIds).size).toBe(2);
      expect(fixture.provider.bootstrapRequestIds).not.toContain(inheritedRequestId);
      const recoveryEvents = fixture.events.slice(recoveryEventOffset);
      expect(recoveryEvents.indexOf('journal:verified:bootstrap_subdomain_disable')).toBeGreaterThanOrEqual(0);
      expect(recoveryEvents.indexOf('journal:verified:bootstrap_subdomain_disable'))
        .toBeLessThan(recoveryEvents.indexOf('journal:bootstrap-cycle'));

      const converged = fixture.journal.value?.actions.find(
        (entry) => entry.name === 'customer_bootstrap_submit',
      );
      if (converged?.record.kind !== 'customer_bootstrap_submit') throw new Error('bootstrap missing');
      expect(converged.record.attempts).toHaveLength(3);
      const recoveredAttempt = requiredFixture(converged.record.attempts.at(1), 'recovered bootstrap attempt');
      expect(recoveredAttempt.enable).toMatchObject({
        approvalAttemptId: ATTEMPT_TWO,
        phase: 'verified',
      });
      expect(recoveredAttempt.disable).toMatchObject({
        approvalAttemptId: ATTEMPT_THREE,
        phase: 'verified',
        locator: { enabled: false, previewsEnabled: false },
      });
      expect(requiredFixture(converged.record.attempts.at(2), 'final bootstrap attempt')).toMatchObject({
        approvalAttemptId: ATTEMPT_THREE,
        phase: 'verified',
        locator: { status: 'ready' },
      });
      expect(fixture.journal.value?.lease).toBeNull();
      await expect(requireInstallJournal(structuredClone(fixture.journal.value))).resolves.toBeDefined();
    },
  );

  it('detects current Access issuer drift against a stored version before any recovery write', async () => {
    const fixture = await setup();
    fixture.journal.faultAfterArm = 'bootstrap_worker_deployment_create';
    await expect(executeReviewedInstall(input(fixture, fixture.plan, ATTEMPT_ONE, ACCESS_TOKEN_ONE)))
      .rejects.toThrow('fault_after_arm_bootstrap_worker_deployment_create');
    const mutationCount = fixture.events.filter((event) => event.startsWith('provider:')).length;

    const renewed = await renew(fixture, ATTEMPT_TWO);
    fixture.provider.issuer = 'https://drifted.cloudflareaccess.com';
    await expect(executeReviewedInstall(input(fixture, renewed, ATTEMPT_TWO, ACCESS_TOKEN_TWO)))
      .rejects.toMatchObject({ code: 'journal_recovery_mismatch', canRetry: false });
    expect(fixture.events.filter((event) => event.startsWith('provider:'))).toHaveLength(mutationCount);
  });

  it('retains a prepared semantic version after asset staging because the Worker is already verified', async () => {
    const fixture = await setup();
    fixture.provider.faultAfterAssetStage = 'bootstrap';
    await expect(executeReviewedInstall(input(fixture, fixture.plan, ATTEMPT_ONE, ACCESS_TOKEN_ONE)))
      .rejects.toThrow('fault_after_asset_stage_bootstrap');
    const stored = fixture.journal.value;
    if (!stored) throw new Error('journal missing');
    expect(stored.actions.find((entry) => entry.name === 'worker_create')?.phase).toBe('verified');
    expect(stored.actions.find((entry) => entry.name === 'bootstrap_worker_version_create')?.phase).toBe('prepared');
    expect(hasArmedInstallJournalAction(stored)).toBe(true);
    expect(isPartialInstallJournal(stored)).toBe(true);

    fixture.clock.advance(20 * 60_000);
    fixture.journal.expireLease(fixture.clock.value);
    expect(fixture.journal.value && isPartialInstallJournal(fixture.journal.value)).toBe(true);
  });

  it('uses a new grant and request after recoverable customer receipt state, with disable around both cycles', async () => {
    const fixture = await setup();
    fixture.provider.bootstrapResponses = ['recovery_required', 'ready'];
    await expect(executeReviewedInstall(input(fixture, fixture.plan, ATTEMPT_ONE, ACCESS_TOKEN_ONE)))
      .rejects.toMatchObject({ code: 'bootstrap_recovery_required', canRetry: false });
    expect(fixture.provider.subdomainEnabled).toBe(false);
    expect(fixture.provider.bootstrapRequestIds).toHaveLength(1);

    const renewed = await renew(fixture, ATTEMPT_TWO);
    expect(fixture.clock.value).toBeGreaterThan(fixture.plan.expiresAt);
    const result = await executeReviewedInstall(input(fixture, renewed, ATTEMPT_TWO, ACCESS_TOKEN_TWO));
    expect(result.installationId).toMatch(/^acg-/u);
    expect(fixture.provider.bootstrapRequestIds).toHaveLength(2);
    expect(new Set(fixture.provider.bootstrapRequestIds).size).toBe(2);
    expect(fixture.provider.subdomainEnabled).toBe(false);
    const toggles = fixture.events.filter((event) => event.startsWith('provider:subdomain:'));
    expect(toggles).toEqual([
      'provider:subdomain:true',
      'provider:subdomain:false',
      'provider:subdomain:true',
      'provider:subdomain:false',
    ]);
    const bootstrap = fixture.journal.value?.actions.find((entry) => entry.name === 'customer_bootstrap_submit');
    expect(bootstrap?.record).toMatchObject({ kind: 'customer_bootstrap_submit' });
    if (bootstrap?.record.kind !== 'customer_bootstrap_submit') throw new Error('bootstrap missing');
    expect(bootstrap.record.attempts).toHaveLength(2);
    expect(bootstrap.record.attempts.map((attempt) => attempt.approvalAttemptId)).toEqual([
      ATTEMPT_ONE,
      ATTEMPT_TWO,
    ]);
    expect(requiredFixture(bootstrap.record.attempts.at(1), 'resumed bootstrap attempt').locator)
      .toMatchObject({ status: 'ready', resumed: true });
  });
});

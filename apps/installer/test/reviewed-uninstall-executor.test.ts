import { describe, expect, it, vi } from 'vitest';

import { DeployError } from '../src/errors';
import { DisabledUninstallExecutor } from '../src/uninstall-executor';
import type { UninstallJournalPort } from '../src/uninstall-journal-port';
import type {
  CustomerGatewayRemoveRequestAttempt,
  ManagementDeleteAttempt,
  UninstallJournal,
  UninstallJournalAction,
} from '../src/uninstall-journal';

const fixture = vi.hoisted(() => ({
  now: 1_787_444_500_000,
  finalInstall: {
    schemaVersion: 1,
    status: 'converged',
    convergenceHash: `sha256:${'1'.repeat(64)}`,
    installationId: `acg-${'2'.repeat(24)}`,
    bindingHash: `sha256:${'3'.repeat(64)}`,
    workerId: '4'.repeat(32),
    managementApplicationId: '5'.repeat(32),
    managementAccessAud: 'audience-abcdefghijklmnop',
    managementPolicyId: '6'.repeat(32),
    bootstrapVersionId: '11111111-1111-4111-8111-111111111111',
    bootstrapDeploymentId: '22222222-2222-4222-8222-222222222222',
    cleanVersionId: '33333333-3333-4333-8333-333333333333',
    cleanDeploymentId: '44444444-4444-4444-8444-444444444444',
    managementDomainId: '7'.repeat(32),
    customerApprovedPlanId: `plan-${'8'.repeat(24)}`,
    customerReceiptRevision: 9,
    customerReceiptEvidence: { schemaVersion: 1, checksum: `sha256:${'9'.repeat(64)}` },
    adminStateNamespaceId: 'a'.repeat(32),
    workersDevEnabled: false,
  },
  releaseSet: {
    primary: { release: 'gateway-v1.2.3', artifactSha256: 'b'.repeat(64) },
    cleanup: {
      verification: 'ed25519', release: 'gateway-v1.2.3', artifactSha256: 'b'.repeat(64),
      componentSha256: 'c'.repeat(64), variant: 'cleanup', worker: { contract: {}, modules: [] },
    },
    retirement: {
      verification: 'ed25519', release: 'gateway-v1.2.3', artifactSha256: 'b'.repeat(64),
      componentSha256: 'd'.repeat(64), variant: 'retirement', worker: { contract: {}, modules: [] },
    },
  },
  tombstone: {
    schemaVersion: 1,
    status: 'removed',
    convergenceHash: `sha256:${'e'.repeat(64)}`,
    bindingHash: `sha256:${'f'.repeat(64)}`,
    uninstallCycleId: `uninstall-${'1'.repeat(24)}`,
    installationId: `acg-${'2'.repeat(24)}`,
    target: { accountId: '1'.repeat(32), zoneId: '2'.repeat(32), zoneName: 'example.com' },
    release: { id: 'gateway-v1.2.3', artifactSha256: 'b'.repeat(64) },
    customer: { status: 'removed' },
    lifecycle: {},
    management: {},
    workersDevEnabled: false,
    providerNotice: 'manual',
  },
}));

vi.mock('../src/install-journal', async (importOriginal) => {
  const original = await importOriginal<typeof import('../src/install-journal')>();
  return {
    ...original,
    isCompleteInstallJournal: () => true,
    prepareFinalConvergenceRecordAndLocator: async () => ({
      record: { schemaVersion: 1, kind: 'final_convergence', convergenceHash: fixture.finalInstall.convergenceHash },
      locator: fixture.finalInstall,
    }),
  };
});

vi.mock('../src/uninstall-plan', async (importOriginal) => {
  const original = await importOriginal<typeof import('../src/uninstall-plan')>();
  return {
    ...original,
    parseStaticUninstallPlan: async (value: unknown) => value,
    isRecoveryEquivalentUninstallPlan: async () => true,
  };
});

vi.mock('../src/release-direct-upload-adapter', async (importOriginal) => {
  const original = await importOriginal<typeof import('../src/release-direct-upload-adapter')>();
  return {
    ...original,
    adaptVerifiedReleaseBundleForGatewayDeployments: async () => fixture.releaseSet,
  };
});

vi.mock('../src/customer-uninstall-request', async (importOriginal) => {
  const original = await importOriginal<typeof import('../src/customer-uninstall-request')>();
  return {
    ...original,
    deriveCustomerUninstallNonce: async () => 'n'.repeat(43),
  };
});

vi.mock('../src/uninstall-journal', async (importOriginal) => {
  const original = await importOriginal<typeof import('../src/uninstall-journal')>();
  return {
    ...original,
    computeUninstallJournalBindingHash: async () => `sha256:${'f'.repeat(64)}`,
    prepareUninstallFinalConvergenceRecordAndLocator: async () => ({
      record: {
        schemaVersion: 1,
        kind: 'uninstall_final_convergence',
        convergenceHash: fixture.tombstone.convergenceHash,
      },
      locator: fixture.tombstone,
    }),
  };
});

const { executeReviewedUninstall } = await import('../src/reviewed-uninstall-executor');
type ReviewedUninstallExecutionInput = import('../src/reviewed-uninstall-executor').ReviewedUninstallExecutionInput;
type ReviewedUninstallProviderAdapter = import('../src/reviewed-uninstall-executor').ReviewedUninstallProviderAdapter;

const ATTEMPT_ONE = `att_${'a'.repeat(32)}`;
const ATTEMPT_TWO = `att_${'b'.repeat(32)}`;
const ACCESS_TOKEN = `grant-${'a'.repeat(32)}`;
const NONCE_KEY = 'CAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg';
const ACCOUNT_ID = '1'.repeat(32);
const ZONE_ID = '2'.repeat(32);
const WORKER_NAME = 'ankka-example-gateway';
const UNINSTALL_CYCLE_ID = `uninstall-${'1'.repeat(24)}`;

const target = Object.freeze({
  actor: Object.freeze({ id: 'actor-test', email: 'owner@example.com' }),
  account: Object.freeze({ id: ACCOUNT_ID, name: 'Example account' }),
  zone: Object.freeze({ id: ZONE_ID, name: 'example.com', status: 'active' as const }),
});

const plan = Object.freeze({
  schemaVersion: 1,
  planId: `uninstall-plan-${'1'.repeat(24)}`,
  planHash: `sha256:${'2'.repeat(64)}`,
  createdAt: fixture.now,
  expiresAt: fixture.now + 10 * 60_000,
  writesPerformed: false,
  installationId: fixture.finalInstall.installationId,
  authorityHash: `sha256:${'3'.repeat(64)}`,
  requiredScopes: [],
  gateway: {
    name: 'Example Gateway', zoneName: 'example.com', managementHostname: 'manage.example.com',
    portalHostname: 'mcp.example.com', workerName: WORKER_NAME,
  },
  source: { name: 'Company context', hostname: 'source.example.com', enabledTools: ['search'] },
  release: { id: 'gateway-v1.2.3', aggregateSha256: 'b'.repeat(64) },
  steps: [],
  providerNotice: 'manual',
});

const installJournal = Object.freeze({
  schemaVersion: 1,
  revision: 40,
  createdAt: fixture.now - 1_000,
  updatedAt: fixture.now,
  sessionExpiresAt: fixture.now + 60_000,
  recoverUntil: fixture.now + 24 * 60 * 60_000,
  selection: {},
  plan: {
    gatewayConfiguration: {},
    managementResources: [],
  },
  releasePin: {
    verification: 'ed25519', keyId: 'key-1', release: 'gateway-v1.2.3', artifactSha256: 'b'.repeat(64),
  },
  target,
  installationId: fixture.finalInstall.installationId,
  bindingHash: fixture.finalInstall.bindingHash,
  approvalHistory: [],
  lease: null,
  leaseAttemptIds: [],
  actions: [{
    name: 'final_convergence',
    phase: 'verified',
    record: { schemaVersion: 1, kind: 'final_convergence', convergenceHash: fixture.finalInstall.convergenceHash },
    locator: fixture.finalInstall,
    preparedAt: fixture.now,
    sendArmedAt: fixture.now,
    submittedAt: fixture.now,
    verifiedAt: fixture.now,
  }],
});

function replaceAction(
  journal: UninstallJournal,
  name: string,
  transform: (action: UninstallJournalAction) => UninstallJournalAction,
): UninstallJournal {
  return {
    ...journal,
    revision: journal.revision + 1,
    actions: journal.actions.map((entry) => entry.name === name ? transform(entry) : entry),
  } as UninstallJournal;
}

class MemoryUninstallJournalPort {
  journal: UninstallJournal | null = null;
  readonly prepared: string[] = [];

  async initialize(input: Parameters<UninstallJournalPort['initialize']>[0]): Promise<UninstallJournal> {
    const approval = input.approval;
    this.journal = {
      schemaVersion: 1,
      revision: 0,
      createdAt: input.initialization.now,
      updatedAt: input.initialization.now,
      recoverUntil: input.initialization.recoverUntil,
      installJournal: input.initialization.installJournal,
      uninstallPlan: input.initialization.uninstallPlan,
      uninstallCycleId: input.initialization.uninstallCycleId,
      bindingHash: input.initialization.bindingHash,
      approvalHistory: [{
        schemaVersion: 1,
        attemptId: approval.attemptId,
        approvedAt: approval.approvedAt,
        recordedAt: input.initialization.now,
        plan: input.initialization.uninstallPlan,
        authorizedTarget: approval.authorizedTarget,
      }],
      managementPreflightHistory: [],
      lease: null,
      leaseAttemptIds: [],
      actions: [{
        name: 'uninstall_fresh_preflight',
        phase: 'verified',
        record: input.initialization.freshPreflight,
        locator: { attestationSha256: (input.initialization.freshPreflight as { attestationSha256: string }).attestationSha256 },
        preparedAt: input.initialization.now,
        sendArmedAt: input.initialization.now,
        submittedAt: input.initialization.now,
        verifiedAt: input.initialization.now,
      }],
    } as UninstallJournal;
    return this.journal;
  }

  async read(): Promise<UninstallJournal> {
    if (!this.journal) throw new DeployError(404, 'session_invalid');
    return this.journal;
  }

  async appendApproval(input: Parameters<UninstallJournalPort['appendApproval']>[0]): Promise<UninstallJournal> {
    const journal = this.must();
    this.journal = {
      ...journal,
      revision: journal.revision + 1,
      approvalHistory: [...journal.approvalHistory, {
        schemaVersion: 1,
        attemptId: input.attemptId,
        approvedAt: input.approvedAt,
        recordedAt: input.now,
        plan: input.candidatePlan,
        authorizedTarget: input.authorizedTarget,
      }],
      lease: null,
    } as UninstallJournal;
    return this.journal;
  }

  async acquireLease(input: Parameters<UninstallJournalPort['acquireLease']>[0]): Promise<UninstallJournal> {
    const journal = this.must();
    this.journal = { ...journal, revision: journal.revision + 1,
      lease: { attemptId: input.attemptId, acquiredAt: input.now, expiresAt: input.leaseExpiresAt },
      leaseAttemptIds: [...journal.leaseAttemptIds, input.attemptId] } as UninstallJournal;
    return this.journal;
  }

  async releaseLease(): Promise<UninstallJournal> {
    const journal = this.must();
    this.journal = { ...journal, revision: journal.revision + 1, lease: null } as UninstallJournal;
    return this.journal;
  }

  async refreshPreflight(input: Parameters<UninstallJournalPort['refreshPreflight']>[0]): Promise<UninstallJournal> {
    const journal = this.must();
    this.journal = replaceAction(journal, 'uninstall_fresh_preflight', (entry) => ({
      ...entry, record: input.preflight as never,
    }));
    return this.journal;
  }

  async appendManagementPreflight(
    input: Parameters<UninstallJournalPort['appendManagementPreflight']>[0],
  ): Promise<UninstallJournal> {
    const journal = this.must();
    this.journal = { ...journal, revision: journal.revision + 1,
      managementPreflightHistory: [...journal.managementPreflightHistory, input.preflight] } as UninstallJournal;
    return this.journal;
  }

  async prepareAction(input: Parameters<UninstallJournalPort['prepareAction']>[0]): Promise<UninstallJournal> {
    const journal = this.must();
    this.prepared.push(input.action);
    let record = input.record as Record<string, unknown>;
    if (record.kind === 'uninstall_management_delete') {
      record = {
        schemaVersion: 1,
        kind: 'uninstall_management_delete',
        action: input.action,
        attempts: [this.managementAttempt(record, input.now)],
      };
    } else if (record.kind === 'management_no_managed_residue') {
      record = { ...record, preparedByAttemptId: input.attemptId, armedByAttemptId: null,
        submittedByAttemptId: null, verifiedByAttemptId: null };
    }
    this.journal = {
      ...journal,
      revision: journal.revision + 1,
      actions: [...journal.actions, {
        name: input.action, phase: 'prepared', record, locator: null, preparedAt: input.now,
        sendArmedAt: null, submittedAt: null, verifiedAt: null,
      }],
    } as UninstallJournal;
    return this.journal;
  }

  async replacePreparedAction(
    input: Parameters<UninstallJournalPort['replacePreparedAction']>[0],
  ): Promise<UninstallJournal> {
    const journal = this.must();
    this.journal = replaceAction(journal, input.action, (entry) => ({ ...entry, record: input.record as never }));
    return this.journal;
  }

  async attachWorkerVersionRecovery(
    input: Parameters<UninstallJournalPort['attachWorkerVersionRecovery']>[0],
  ): Promise<UninstallJournal> {
    const journal = this.must();
    this.journal = replaceAction(journal, input.action, (entry) => ({
      ...entry, record: { ...entry.record, recovery: input.recovery } as never,
    }));
    return this.journal;
  }

  async armAction(input: Parameters<UninstallJournalPort['armAction']>[0]): Promise<UninstallJournal> {
    const journal = this.must();
    this.journal = replaceAction(journal, input.action, (entry) => {
      let record = entry.record as unknown as Record<string, unknown>;
      if (record.kind === 'uninstall_management_delete') {
        const attempts = [...record.attempts as ManagementDeleteAttempt[]];
        attempts[attempts.length - 1] = { ...attempts.at(-1)!, phase: 'send_armed',
          arm: input.value, sendArmedAt: input.now } as ManagementDeleteAttempt;
        record = { ...record, attempts };
      }
      return { ...entry, phase: 'send_armed', record: record as never, sendArmedAt: input.now };
    });
    return this.journal;
  }

  async recordActionSubmitted(
    input: Parameters<UninstallJournalPort['recordActionSubmitted']>[0],
  ): Promise<UninstallJournal> {
    const journal = this.must();
    this.journal = replaceAction(journal, input.action, (entry) => {
      let record = entry.record as unknown as Record<string, unknown>;
      let locator: unknown = input.value;
      if (record.kind === 'uninstall_management_delete') {
        const attempts = [...record.attempts as ManagementDeleteAttempt[]];
        attempts[attempts.length - 1] = { ...attempts.at(-1)!, phase: 'submitted',
          submission: input.value, submittedAt: input.now, submittedByAttemptId: input.attemptId } as ManagementDeleteAttempt;
        record = { ...record, attempts };
        locator = null;
      } else if (record.kind === 'management_worker_delete') {
        record = { ...record, submission: input.value };
        locator = null;
      }
      return { ...entry, phase: 'submitted', record: record as never, locator: locator as never,
        submittedAt: input.now };
    });
    return this.journal;
  }

  async verifyAction(input: Parameters<UninstallJournalPort['verifyAction']>[0]): Promise<UninstallJournal> {
    const journal = this.must();
    this.journal = replaceAction(journal, input.action, (entry) => {
      let record = entry.record as unknown as Record<string, unknown>;
      if (record.kind === 'uninstall_management_delete') {
        const attempts = [...record.attempts as ManagementDeleteAttempt[]];
        attempts[attempts.length - 1] = { ...attempts.at(-1)!, phase: 'verified', locator: input.value,
          verifiedAt: input.now, verifiedByAttemptId: input.attemptId } as ManagementDeleteAttempt;
        record = { ...record, attempts };
      }
      return { ...entry, phase: 'verified', record: record as never, locator: input.value as never,
        verifiedAt: input.now };
    });
    return this.journal;
  }

  async appendCustomerRemoveCycle(
    input: Parameters<UninstallJournalPort['appendCustomerRemoveCycle']>[0],
  ): Promise<UninstallJournal> {
    const journal = this.must();
    const attempt = this.customerAttempt(input.attemptId, input.semantic, input.now);
    this.prepared.push('customer_gateway_remove');
    this.journal = { ...journal, revision: journal.revision + 1, actions: [...journal.actions, {
      name: 'customer_gateway_remove', phase: 'prepared', locator: null,
      record: { schemaVersion: 1, kind: 'customer_gateway_remove', accountId: ACCOUNT_ID,
        zoneId: ZONE_ID, zoneName: 'example.com', workerName: WORKER_NAME,
        installationId: fixture.finalInstall.installationId, uninstallCycleId: UNINSTALL_CYCLE_ID,
        attempts: [attempt] },
      preparedAt: input.now, sendArmedAt: null, submittedAt: null, verifiedAt: null,
    }] } as UninstallJournal;
    return this.journal;
  }

  async replacePreparedCustomerRemoveCycle(
    input: Parameters<UninstallJournalPort['replacePreparedCustomerRemoveCycle']>[0],
  ): Promise<UninstallJournal> {
    const journal = this.must();
    const replacement = this.customerAttempt(input.attemptId, input.semantic, input.now);
    this.journal = this.mapCustomer(journal, (record) => ({
      ...record, attempts: [...record.attempts.slice(0, -1), replacement],
    }));
    return this.journal;
  }

  async armCustomerWorkersDev(
    input: Parameters<UninstallJournalPort['armCustomerWorkersDev']>[0],
  ): Promise<UninstallJournal> {
    this.journal = this.mapCustomer(this.must(), (record) => this.mapLatestCustomer(record, (attempt) => input.enabled
      ? { ...attempt, enable: { ...attempt.enable, phase: 'send_armed', sendArmedAt: input.now } }
      : { ...attempt, disableAttempts: attempt.disableAttempts.map((entry: any, index: number) =>
        index === attempt.disableAttempts.length - 1
          ? { ...entry, phase: 'send_armed', sendArmedAt: input.now }
          : entry) }));
    return this.journal;
  }

  async recordCustomerWorkersDevSubmitted(
    input: Parameters<UninstallJournalPort['recordCustomerWorkersDevSubmitted']>[0],
  ): Promise<UninstallJournal> {
    this.journal = this.mapCustomer(this.must(), (record) => this.mapLatestCustomer(record, (attempt) => input.enabled
      ? { ...attempt, enable: { ...attempt.enable, phase: 'submitted', locator: input.locator,
        submittedAt: input.now, submittedByAttemptId: input.attemptId } }
      : { ...attempt, disableAttempts: attempt.disableAttempts.map((entry: any, index: number) =>
        index === attempt.disableAttempts.length - 1
          ? { ...entry, phase: 'submitted', locator: input.locator, submittedAt: input.now,
            submittedByAttemptId: input.attemptId }
          : entry) }));
    return this.journal;
  }

  async verifyCustomerWorkersDev(
    input: Parameters<UninstallJournalPort['verifyCustomerWorkersDev']>[0],
  ): Promise<UninstallJournal> {
    this.journal = this.mapCustomer(this.must(), (record) => this.mapLatestCustomer(record, (attempt) => input.enabled
      ? { ...attempt, enable: { ...attempt.enable, phase: 'verified', verifiedAt: input.now,
        verifiedByAttemptId: input.attemptId } }
      : { ...attempt, disableAttempts: attempt.disableAttempts.map((entry: any, index: number) =>
        index === attempt.disableAttempts.length - 1
          ? { ...entry, phase: 'verified', verifiedAt: input.now, verifiedByAttemptId: input.attemptId }
          : entry) }));
    return this.journal;
  }

  async recordCustomerWorkersDevNotApplied(
    input: Parameters<UninstallJournalPort['recordCustomerWorkersDevNotApplied']>[0],
  ): Promise<UninstallJournal> {
    this.journal = this.mapCustomer(this.must(), (record) => this.mapLatestCustomer(record, (attempt) => input.enabled
      ? { ...attempt, enable: { ...attempt.enable, phase: 'not_applied', locator: input.locator,
        verifiedAt: input.now, verifiedByAttemptId: input.attemptId } }
      : { ...attempt, disableAttempts: attempt.disableAttempts.map((entry: any, index: number) =>
        index === attempt.disableAttempts.length - 1
          ? { ...entry, phase: 'not_applied', locator: input.locator, verifiedAt: input.now,
            verifiedByAttemptId: input.attemptId }
          : entry) }));
    return this.journal;
  }

  async armCustomerRemoveRequest(input: Parameters<UninstallJournalPort['armCustomerRemoveRequest']>[0]): Promise<UninstallJournal> {
    this.journal = this.mapCustomer(this.must(), (record) => this.mapLatestCustomer(record, (attempt) => ({
      ...attempt, requestPhase: 'send_armed', sendArmedAt: input.now,
    })));
    return this.journal;
  }

  async recordCustomerRemoveRequestSubmitted(
    input: Parameters<UninstallJournalPort['recordCustomerRemoveRequestSubmitted']>[0],
  ): Promise<UninstallJournal> {
    this.journal = this.mapCustomer(this.must(), (record) => this.mapLatestCustomer(record, (attempt) => ({
      ...attempt, requestPhase: 'submitted', locator: input.locator, submittedAt: input.now,
      submittedByAttemptId: input.attemptId,
    })));
    return this.journal;
  }

  async verifyCustomerRemoveRequest(
    input: Parameters<UninstallJournalPort['verifyCustomerRemoveRequest']>[0],
  ): Promise<UninstallJournal> {
    this.journal = this.mapCustomer(this.must(), (record) => this.mapLatestCustomer(record, (attempt) => ({
      ...attempt, requestPhase: 'verified', verifiedAt: input.now, verifiedByAttemptId: input.attemptId,
    })));
    return this.journal;
  }

  async prepareCustomerWorkersDevDisable(
    input: Parameters<UninstallJournalPort['prepareCustomerWorkersDevDisable']>[0],
  ): Promise<UninstallJournal> {
    this.journal = this.mapCustomer(this.must(), (record) => this.mapLatestCustomer(record, (attempt) => ({
      ...attempt,
      disableAttempts: [...attempt.disableAttempts, this.workersDev(input.attemptId, false, input.now)],
    })));
    return this.journal;
  }

  async replacePreparedCustomerWorkersDevDisable(
    input: Parameters<UninstallJournalPort['replacePreparedCustomerWorkersDevDisable']>[0],
  ): Promise<UninstallJournal> {
    this.journal = this.mapCustomer(this.must(), (record) => this.mapLatestCustomer(record, (attempt) => ({
      ...attempt,
      disableAttempts: [...attempt.disableAttempts.slice(0, -1), this.workersDev(input.attemptId, false, input.now)],
    })));
    return this.journal;
  }

  async appendManagementDeleteAttempt(
    input: Parameters<UninstallJournalPort['appendManagementDeleteAttempt']>[0],
  ): Promise<UninstallJournal> {
    const journal = this.must();
    this.journal = replaceAction(journal, input.action, (entry) => ({ ...entry,
      record: { ...entry.record, attempts: [
        ...((entry.record as unknown as { attempts: ManagementDeleteAttempt[] }).attempts),
        this.managementAttempt({ prerequisites: input.prerequisites, intent: input.intent }, input.now),
      ] } as never }));
    return this.journal;
  }

  async recordManagementDeleteRecovery(
    input: Parameters<UninstallJournalPort['recordManagementDeleteRecovery']>[0],
  ): Promise<UninstallJournal> {
    const journal = this.must();
    this.journal = replaceAction(journal, input.action, (entry) => {
      const record = entry.record as unknown as { attempts: ManagementDeleteAttempt[] };
      const attempts = [...record.attempts];
      const absent = (input.evidence as { status: string }).status === 'absent';
      attempts[attempts.length - 1] = { ...attempts.at(-1)!, phase: absent ? 'verified' : 'not_applied',
        locator: absent ? input.evidence : null, recovery: absent ? null : input.evidence,
        verifiedAt: input.now, verifiedByAttemptId: input.attemptId } as ManagementDeleteAttempt;
      return { ...entry, phase: absent ? 'verified' : entry.phase, locator: absent ? input.evidence as never : null,
        record: { ...entry.record, attempts } as never, verifiedAt: absent ? input.now : null };
    });
    return this.journal;
  }

  discardPreflight = async () => ({ discarded: true as const });

  private must(): UninstallJournal {
    if (!this.journal) throw new TypeError('missing journal fixture');
    return this.journal;
  }

  private workersDev(attemptId: string, enabled: boolean, now: number) {
    return { schemaVersion: 1, kind: 'uninstall_workers_dev', approvalAttemptId: attemptId,
      accountId: ACCOUNT_ID, workerName: WORKER_NAME, uninstallCycleId: UNINSTALL_CYCLE_ID,
      enabled, previewsEnabled: false, requestHash: '0'.repeat(64), phase: 'prepared', locator: null,
      preparedAt: now, sendArmedAt: null, submittedAt: null, submittedByAttemptId: null,
      verifiedAt: null, verifiedByAttemptId: null } as const;
  }

  private customerAttempt(attemptId: string, semantic: unknown, now: number): CustomerGatewayRemoveRequestAttempt {
    return { schemaVersion: 1, approvalAttemptId: attemptId, semantic, enable: this.workersDev(attemptId, true, now),
      requestPhase: 'prepared', locator: null, disableAttempts: [], preparedAt: now, sendArmedAt: null,
      submittedAt: null, submittedByAttemptId: null, verifiedAt: null, verifiedByAttemptId: null } as CustomerGatewayRemoveRequestAttempt;
  }

  private managementAttempt(record: Record<string, unknown>, now: number): ManagementDeleteAttempt {
    return { schemaVersion: 1, prerequisites: record.prerequisites, intent: record.intent, phase: 'prepared',
      arm: null, submission: null, recovery: null, locator: null, preparedAt: now, sendArmedAt: null,
      submittedAt: null, submittedByAttemptId: null, verifiedAt: null,
      verifiedByAttemptId: null } as ManagementDeleteAttempt;
  }

  private mapCustomer(journal: UninstallJournal, transform: (record: any) => any): UninstallJournal {
    return replaceAction(journal, 'customer_gateway_remove', (entry) => {
      const record = transform(entry.record);
      const attempt = record.attempts.at(-1);
      const disable = attempt?.disableAttempts.at(-1);
      const complete = attempt?.requestPhase === 'verified' && disable?.phase === 'verified';
      return { ...entry,
        record,
        phase: complete ? 'verified' : entry.phase,
        locator: complete ? attempt.locator : entry.locator,
        verifiedAt: complete ? Math.max(attempt.verifiedAt, disable.verifiedAt) : entry.verifiedAt,
      };
    }) as UninstallJournal;
  }

  private mapLatestCustomer(record: any, transform: (attempt: any) => any): any {
    return { ...record, attempts: [...record.attempts.slice(0, -1), transform(record.attempts.at(-1))] };
  }
}

interface ProviderOptions {
  readonly failFirstCleanupSubmit?: boolean;
  readonly failPostReadyCleanupProof?: boolean;
}

function providerHarness(options: ProviderOptions = {}): {
  readonly provider: ReviewedUninstallProviderAdapter;
  readonly mutations: string[];
  readonly inspections: string[];
  allowCleanupRecovery(): void;
} {
  const mutations: string[] = [];
  const inspections: string[] = [];
  let cleanupFailed = false;
  let cleanupRecoverable = !options.failFirstCleanupSubmit;
  const version = (stage: 'cleanup' | 'retirement') => ({
    kind: 'uninstall_worker_version', stage, accountId: ACCOUNT_ID, workerName: WORKER_NAME,
    workerId: fixture.finalInstall.workerId, uninstallCycleId: UNINSTALL_CYCLE_ID,
    versionId: stage === 'cleanup'
      ? '55555555-5555-4555-8555-555555555555'
      : '66666666-6666-4666-8666-666666666666',
    requestHash: stage === 'cleanup' ? '1'.repeat(64) : '2'.repeat(64), correlationTag: `version-${stage}`,
  });
  const deployment = (intent: any) => ({
    kind: 'uninstall_worker_deployment', stage: intent.stage, accountId: ACCOUNT_ID,
    workerName: WORKER_NAME, workerId: fixture.finalInstall.workerId, uninstallCycleId: UNINSTALL_CYCLE_ID,
    versionId: intent.versionId,
    deploymentId: intent.stage === 'cleanup' ? '77777777-7777-4777-8777-777777777777'
      : intent.stage === 'restore_clean' ? '88888888-8888-4888-8888-888888888888'
        : '99999999-9999-4999-8999-999999999999',
    requestHash: intent.requestHash, correlationTag: intent.correlationTag,
  });
  const absence = (action: string) => ({ schemaVersion: 1, status: 'absent', action,
    attemptId: ATTEMPT_ONE, evidenceSha256: '3'.repeat(64) });

  const provider = {
    getAccountWorkersSubdomain: async () => ({ accountId: ACCOUNT_ID, subdomain: 'example-account' }),
    inspectAdminStateNamespace: async () => ({ accountId: ACCOUNT_ID,
      namespaceId: fixture.finalInstall.adminStateNamespaceId, namespaceName: 'ankka-admin-state',
      workerName: WORKER_NAME, className: 'AdminState', storage: 'sqlite' }),
    preflightManagement: async (_context: unknown, _call: unknown, now: number) => ({
      schemaVersion: 1, status: 'ready', attemptId: ATTEMPT_ONE, checkedAt: now,
      expiresAt: now + 60_000, attestationSha256: '4'.repeat(64),
    }),
    prepareCleanupVersion: async () => ({ recovery: { kind: 'uninstall_version_recovery', stage: 'cleanup',
      accountId: ACCOUNT_ID, workerName: WORKER_NAME, workerId: fixture.finalInstall.workerId,
      uninstallCycleId: UNINSTALL_CYCLE_ID, requestHash: '1'.repeat(64) }, ephemeral: {} }),
    prepareRetirementVersion: async () => ({ recovery: { kind: 'uninstall_version_recovery', stage: 'retirement',
      accountId: ACCOUNT_ID, workerName: WORKER_NAME, workerId: fixture.finalInstall.workerId,
      uninstallCycleId: UNINSTALL_CYCLE_ID, requestHash: '2'.repeat(64) }, ephemeral: {} }),
    inspectVersion: async (recovery: any) => {
      inspections.push(`version:${recovery.stage}`);
      return recovery.stage === 'cleanup' && !cleanupRecoverable ? null : version(recovery.stage);
    },
    submitVersion: async (mutation: any) => {
      mutations.push(`version:${mutation.recovery.stage}`);
      if (mutation.recovery.stage === 'cleanup' && options.failFirstCleanupSubmit && !cleanupFailed) {
        cleanupFailed = true;
        throw new Error('unknown');
      }
      return version(mutation.recovery.stage);
    },
    verifyVersion: async (_recovery: unknown, submission: unknown) => submission,
    prepareDeployment: async (input: any) => ({ kind: 'uninstall_deployment', ...input,
      requestHash: input.stage === 'cleanup' ? '5'.repeat(64)
        : input.stage === 'restore_clean' ? '6'.repeat(64) : '7'.repeat(64),
      correlationTag: `deployment-${input.stage}`, body: {} }),
    inspectDeployment: async () => null,
    submitDeployment: async (intent: any) => {
      mutations.push(`deployment:${intent.stage}`);
      return deployment(intent);
    },
    verifyDeployment: async (_intent: unknown, submission: unknown) => submission,
    verifyActiveDeployment: async (_intent: unknown, submission: unknown) => submission,
    proveActiveCleanupWorker: async (
      _recovery: unknown,
      versionSubmission: unknown,
      _deploymentIntent: unknown,
      deploymentSubmission: unknown,
    ) => {
      inspections.push('cleanup-active-proof');
      if (options.failPostReadyCleanupProof) throw new Error('cleanup deployment drift');
      return { version: versionSubmission, deployment: deploymentSubmission };
    },
    setWorkersDev: async (enabled: boolean) => {
      mutations.push(`workers-dev:${String(enabled)}`);
      return { enabled, previewsEnabled: false };
    },
    verifyWorkersDev: async (enabled: boolean) => ({ enabled, previewsEnabled: false }),
    prepareCustomerRequest: async (input: any) => ({ ephemeral: { claim: {} }, semantic: {
      schemaVersion: 1, kind: 'customer_uninstall_submit', approvalAttemptId: input.approval.attemptId,
      requestId: 'request-1', issuedAt: Math.floor(fixture.now / 1_000),
      expiresAt: Math.floor((fixture.now + 60_000) / 1_000),
    } }),
    awaitCustomerRemoveReady: async () => {
      mutations.push('customer-remove-ready');
    },
    submitCustomerRequest: async () => {
      mutations.push('customer-remove');
      return { schemaVersion: 1, status: 'removed', requestId: 'request-1',
        installationId: fixture.finalInstall.installationId, receipt: { revision: 10, resourceCount: 0,
          evidence: {} } };
    },
    prepareManagementDeleteIntent: async (_context: unknown, action: string) => ({
      schemaVersion: 1, kind: action, attemptId: ATTEMPT_ONE, locator: {},
    }),
    prepareManagementDeleteArm: async (_context: unknown, intent: any, _prereq: unknown, armedAt: number) => ({
      schemaVersion: 1, kind: 'management_delete_arm', action: intent.kind,
      attemptId: intent.attemptId, armedAt, intentSha256: '8'.repeat(64),
    }),
    submitManagementDelete: async (_context: unknown, intent: any) => {
      mutations.push(intent.kind);
      return { schemaVersion: 1, status: 'submitted', action: intent.kind,
        attemptId: intent.attemptId, intentSha256: '8'.repeat(64), locator: {} };
    },
    verifyManagementDelete: async (_context: unknown, intent: any) => absence(intent.kind),
    recoverManagementDelete: async (_context: unknown, intent: any) => absence(intent.kind),
    proveNamespacePresent: async () => ({ kind: 'admin_state_namespace_presence', accountId: ACCOUNT_ID,
      workerName: WORKER_NAME, workerId: fixture.finalInstall.workerId, uninstallCycleId: UNINSTALL_CYCLE_ID,
      namespaceId: fixture.finalInstall.adminStateNamespaceId }),
    proveNamespaceRetired: async () => {
      inspections.push('namespace-retired');
      return { kind: 'admin_state_namespace_retirement', accountId: ACCOUNT_ID,
        workerName: WORKER_NAME, workerId: fixture.finalInstall.workerId, uninstallCycleId: UNINSTALL_CYCLE_ID,
        namespaceId: fixture.finalInstall.adminStateNamespaceId,
        retirementVersionId: version('retirement').versionId };
    },
    prepareWorkerDelete: async (_input: unknown) => ({ kind: 'uninstall_worker_delete_intent',
      accountId: ACCOUNT_ID, workerName: WORKER_NAME, workerId: fixture.finalInstall.workerId,
      uninstallCycleId: UNINSTALL_CYCLE_ID, namespaceId: fixture.finalInstall.adminStateNamespaceId,
      retirementVersionId: version('retirement').versionId, retirementProofCommitment: '9'.repeat(64),
      retirementProof: {}, requestHash: 'a'.repeat(64), correlationTag: 'worker-delete', method: 'DELETE', force: 'omitted' }),
    submitWorkerDelete: async (intent: any) => {
      mutations.push('worker-delete');
      return { ...intent, kind: 'uninstall_worker_delete' };
    },
    recoverWorkerDelete: async (intent: any) => ({ ...intent, kind: 'uninstall_worker_deletion_proof' }),
    verifyNoManagedResidue: async () => {
      inspections.push('no-residue');
      return { schemaVersion: 1, status: 'no_ankka_managed_residue', attemptId: ATTEMPT_ONE,
        uninstallCycleId: UNINSTALL_CYCLE_ID };
    },
  } as unknown as ReviewedUninstallProviderAdapter;
  return {
    provider,
    mutations,
    inspections,
    allowCleanupRecovery: () => { cleanupRecoverable = true; },
  };
}

function executionInput(
  port: MemoryUninstallJournalPort,
  provider: ReviewedUninstallProviderAdapter,
  attemptId = ATTEMPT_ONE,
): ReviewedUninstallExecutionInput {
  return {
    installJournal: installJournal as never,
    uninstallPlan: plan as never,
    target,
    releaseBundle: {} as never,
    accessToken: ACCESS_TOKEN,
    uninstallNonceDerivationKey: NONCE_KEY,
    attemptId,
    approvedAt: fixture.now,
    recoverUntil: installJournal.recoverUntil,
    uninstallCycleId: UNINSTALL_CYCLE_ID,
    journal: port as unknown as UninstallJournalPort,
    provider,
    transport: async () => new Response(null, { status: 500 }),
    now: () => fixture.now,
  };
}

describe('reviewed uninstall executor', () => {
  it('keeps the default executor disabled without inspecting dependencies', async () => {
    await expect(new DisabledUninstallExecutor().execute({} as never)).rejects.toMatchObject({
      status: 503,
      code: 'uninstall_mutations_disabled',
    });
  });

  it('durably converges the exact 14-action canary uninstall order', async () => {
    const port = new MemoryUninstallJournalPort();
    const harness = providerHarness();
    await expect(executeReviewedUninstall(executionInput(port, harness.provider))).resolves.toEqual({
      status: 'removed',
      installationId: fixture.finalInstall.installationId,
      convergenceHash: fixture.tombstone.convergenceHash,
    });
    expect(port.journal?.actions.map((entry) => entry.name)).toEqual([
      'uninstall_fresh_preflight',
      'cleanup_worker_version_create',
      'cleanup_worker_deployment_create',
      'customer_gateway_remove',
      'restore_clean_worker_deployment',
      'management_custom_domain_delete',
      'management_admin_policy_delete',
      'management_access_application_delete',
      'retirement_worker_version_create',
      'retirement_worker_deployment_create',
      'admin_state_namespace_retired',
      'management_worker_delete',
      'management_no_managed_residue',
      'uninstall_final_convergence',
    ]);
    expect(port.journal?.actions.every((entry) => entry.phase === 'verified')).toBe(true);
    expect(harness.mutations).toEqual([
      'version:cleanup',
      'deployment:cleanup',
      'workers-dev:true',
      'customer-remove-ready',
      'customer-remove',
      'workers-dev:false',
      'deployment:restore_clean',
      'management_custom_domain_delete',
      'management_admin_policy_delete',
      'management_access_application_delete',
      'version:retirement',
      'deployment:retirement',
      'worker-delete',
    ]);
  });

  it('never replays an armed version mutation and resumes only from two equal inspections', async () => {
    const port = new MemoryUninstallJournalPort();
    const harness = providerHarness({ failFirstCleanupSubmit: true });
    await expect(executeReviewedUninstall(executionInput(port, harness.provider))).rejects.toThrow('unknown');
    expect(harness.mutations).toEqual(['version:cleanup']);
    expect(port.journal?.actions.at(-1)).toMatchObject({
      name: 'cleanup_worker_version_create',
      phase: 'send_armed',
    });
    expect(harness.inspections).toEqual(['version:cleanup', 'version:cleanup']);

    if (port.journal) port.journal = { ...port.journal, lease: null } as UninstallJournal;
    harness.allowCleanupRecovery();
    await expect(executeReviewedUninstall(
      executionInput(port, harness.provider, ATTEMPT_TWO),
    )).resolves.toMatchObject({ status: 'removed' });
    expect(harness.mutations.filter((entry) => entry === 'version:cleanup')).toHaveLength(1);
    expect(harness.inspections.slice(2, 4)).toEqual(['version:cleanup', 'version:cleanup']);
  });

  it('closes workers.dev and sends no grant when cleanup drifts after route readiness', async () => {
    const port = new MemoryUninstallJournalPort();
    const harness = providerHarness({ failPostReadyCleanupProof: true });
    await expect(executeReviewedUninstall(executionInput(port, harness.provider)))
      .rejects.toThrow('cleanup deployment drift');
    expect(harness.mutations).toEqual([
      'version:cleanup',
      'deployment:cleanup',
      'workers-dev:true',
      'customer-remove-ready',
      'workers-dev:false',
    ]);
    expect(harness.mutations).not.toContain('customer-remove');
    expect(harness.inspections).toContain('cleanup-active-proof');
  });
});

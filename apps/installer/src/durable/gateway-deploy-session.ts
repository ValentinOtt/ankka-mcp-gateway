import * as v from 'valibot';

import {
  boundaryObjectSchema,
  boundaryValueSchema,
  type BoundaryObject,
  type BoundaryValue,
} from '../boundary';
import { DeployError, isDeployErrorCode, stableError, type DeployErrorCode, isFailureReason } from '../errors';
import { OAUTH_ATTEMPT_TTL_MS, SESSION_TTL_MS } from '../constants';
import { constantTimeEqual } from '../crypto';
import { parseExistingAnkkaGatewaySummary } from '../cloudflare-gateway-fresh-preflight';
import {
  acquireInstallJournalLease,
  appendCustomerBootstrapAttempt,
  appendInstallJournalApproval,
  armInstallJournalAction,
  createInstallJournal,
  expireInstallJournalLease,
  hasArmedInstallJournalAction,
  isCompleteInstallJournal,
  isPartialInstallJournal,
  isRecoveryEquivalentInstallPlan,
  MAX_INSTALL_LEASE_MS,
  MAX_INSTALL_RECOVERY_RETENTION_MS,
  prepareInstallJournalAction,
  publicInstallProgress,
  releaseInstallJournalLease,
  requireInstallJournal,
  serverTimeInstallJournalPrepare,
  submitInstallJournalAction,
  verifyInstallJournalAction,
  INSTALL_ACTION_ORDER,
  type InstallJournal,
} from '../install-journal';
import {
  buildStaticUninstallPlan,
  isRecoveryEquivalentUninstallPlan,
} from '../uninstall-plan';
import {
  publicUninstallSession,
  requireStoredUninstallControl,
  type StoredUninstallControl,
  type UninstallResult,
} from '../uninstall-session';
import {
  acquireUninstallJournalLease,
  appendCustomerGatewayRemoveAttempt,
  appendUninstallJournalApproval,
  appendUninstallManagementDeleteAttempt,
  appendUninstallManagementPreflight,
  armCustomerGatewayRemoveRequest,
  armCustomerGatewayWorkersDev,
  armUninstallJournalAction,
  attachUninstallWorkerVersionRecovery,
  createUninstallJournal,
  discardPreflightOnlyUninstallJournal,
  expireUninstallJournalLease,
  hasArmedUninstallJournalAction,
  isCompleteUninstallJournal,
  isPartialUninstallJournal,
  MAX_UNINSTALL_LEASE_MS,
  prepareCustomerGatewayWorkersDevDisable,
  prepareUninstallJournalAction,
  recordCustomerGatewayWorkersDevNotApplied,
  recordUninstallManagementDeleteRecovery,
  releaseUninstallJournalLease,
  replacePreparedCustomerGatewayRemoveAttempt,
  replacePreparedCustomerGatewayWorkersDevDisable,
  replacePreparedUninstallJournalAction,
  requireUninstallJournal,
  submitCustomerGatewayRemoveRequest,
  submitCustomerGatewayWorkersDev,
  submitUninstallJournalAction,
  verifyCustomerGatewayRemoveRequest,
  verifyCustomerGatewayWorkersDev,
  verifyUninstallJournalAction,
  refreshUninstallJournalPreflight,
  type UninstallJournal,
} from '../uninstall-journal';
import {
  assertSecretFree,
  buildStaticDeployPlan,
  parseDeploySelection,
  parseReleaseManifest,
} from '../schema';
import {
  publicSession,
  requireStoredSession,
  verifyHash,
  type DeployResult,
  type PublicDeployRecovery,
  type PublicDeployResultRetention,
  type StoredDeploySession,
} from '../session';
import {
  publicReturningUninstall,
  requireStoredReturningUninstall,
  type StoredReturningUninstall,
} from '../returning-uninstall-session';
import { buildReturningUninstallPlan } from '../returning-uninstall-plan';
import { requireReturningUninstallImportedAuthority } from '../returning-uninstall-authority';
import {
  acquireReturningUninstallLease,
  appendReturningUninstallHostedRecoveryApproval,
  appendReturningUninstallApproval,
  armReturningUninstallAction,
  createReturningUninstallJournal,
  MAX_RETURNING_UNINSTALL_RECOVERY_RETENTION_MS,
  prepareReturningUninstallAction,
  releaseReturningUninstallLease,
  requireReturningUninstallJournal,
  submitReturningUninstallAction,
  verifyReturningUninstallAction,
  RETURNING_UNINSTALL_ACTION_ORDER,
  type ReturningUninstallJournal,
} from '../returning-uninstall-journal';
import {
  publicCloudflareDiscovery,
  requireStoredCloudflareDiscovery,
  selectedDiscoveredTarget,
  type CloudflareDiscoveryResult,
  type StoredCloudflareDiscovery,
} from '../cloudflare-discovery';

const STORAGE_KEY = 'deploy-session-v1';
const INSTALL_JOURNAL_STORAGE_KEY = 'install-journal-v1';
const UNINSTALL_CONTROL_STORAGE_KEY = 'uninstall-control-v1';
const UNINSTALL_JOURNAL_STORAGE_KEY = 'uninstall-journal-v1';
const DISCOVERY_STORAGE_KEY = 'cloudflare-discovery-v1';
const RETURNING_UNINSTALL_STORAGE_KEY = 'returning-uninstall-v1';
const RETURNING_UNINSTALL_JOURNAL_STORAGE_KEY = 'returning-uninstall-journal-v1';
type GatewayDeploySessionEnvironment = Readonly<Record<never, never>>;

export interface GatewayDeploySessionTransaction {
  get<Value = unknown>(key: string): Promise<Value | undefined>;
  put<Value>(key: string, value: Value): Promise<void>;
}

export interface GatewayDeploySessionStorage extends GatewayDeploySessionTransaction {
  delete(key: string): Promise<boolean>;
  deleteAll(): Promise<void>;
  transaction<Value>(
    closure: (transaction: GatewayDeploySessionTransaction) => Promise<Value>,
  ): Promise<Value>;
  setAlarm(scheduledTime: number | Date): Promise<void>;
  deleteAlarm(): Promise<void>;
}

export interface GatewayDeploySessionState {
  readonly storage: GatewayDeploySessionStorage;
}

interface RetainedInstallAuthority {
  readonly session: StoredDeploySession;
  readonly journal: InstallJournal;
}
const safeIntegerSchema = v.pipe(v.number(), v.safeInteger());
const csrfHashSchema = v.pipe(v.string(), v.regex(/^[A-Za-z0-9_-]{43}$/u));
const oauthAttemptIdSchema = v.pipe(v.string(), v.regex(/^att_[A-Za-z0-9_-]{32}$/u));
const oauthHashSchema = v.pipe(v.string(), v.regex(/^[A-Za-z0-9_-]{43}$/u));
const targetIdHashSchema = v.pipe(v.string(), v.regex(/^sha256:[a-f0-9]{64}$/u));
const installActionNameSchema = v.picklist(INSTALL_ACTION_ORDER);
const returningUninstallActionNameSchema = v.picklist(RETURNING_UNINSTALL_ACTION_ORDER);
const revisionAttemptNowSchema = {
  expectedRevision: safeIntegerSchema,
  attemptId: oauthAttemptIdSchema,
  now: safeIntegerSchema,
};
const oauthConsumeBodySchema = v.strictObject({
  attemptId: oauthAttemptIdSchema,
  stateHash: oauthHashSchema,
  verifierHash: oauthHashSchema,
  now: safeIntegerSchema,
});
const oauthAuthorizeBodyEntries = {
  csrfHash: csrfHashSchema,
  attemptId: oauthAttemptIdSchema,
  stateHash: oauthHashSchema,
  verifierHash: oauthHashSchema,
  attemptExpiresAt: safeIntegerSchema,
  now: safeIntegerSchema,
};
const cloudflareDiscoveryResultSchema = v.custom<CloudflareDiscoveryResult>(
  (value) => v.is(boundaryObjectSchema, value),
);
const returningActionAuthoritySchema = v.strictObject({
  actionId: v.pipe(v.string(), v.regex(/^action_[A-Za-z0-9_-]{32}$/u)),
  actionKeyHash: oauthHashSchema,
  actorEmail: v.string(),
  accountId: v.pipe(v.string(), v.regex(/^[a-f0-9]{32}$/u)),
  workerName: v.pipe(v.string(), v.regex(/^[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$/u)),
  workersSubdomain: v.string(),
  managementOrigin: v.string(),
  expiresAt: safeIntegerSchema,
});
const reviewedPlanAuthorizationSchema = v.strictObject({
  ...oauthAuthorizeBodyEntries,
  approvedPlanId: v.string(),
  approvedPlanHash: v.string(),
});
const failureReasonSchema = v.custom<string>((value) => isFailureReason(value));
const successfulReturningCompletionSchema = v.strictObject({
  attemptId: oauthAttemptIdSchema,
  code: v.literal('returning_uninstall_complete'),
  completedAt: safeIntegerSchema,
  installationId: v.string(),
  grantRevocation: v.picklist(['confirmed', 'unconfirmed']),
  reason: v.null(),
});
const failedReturningCompletionSchema = v.strictObject({
  attemptId: oauthAttemptIdSchema,
  code: v.string(),
  completedAt: safeIntegerSchema,
  installationId: v.null(),
  grantRevocation: v.null(),
  reason: v.nullable(failureReasonSchema),
});
const returningCompletionBodySchema = v.union([
  successfulReturningCompletionSchema,
  failedReturningCompletionSchema,
]);
const mutableUninstallActionSchema = v.picklist([
  'cleanup_worker_version_create',
  'cleanup_worker_deployment_create',
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
const versionRecoveryActionSchema = v.picklist([
  'cleanup_worker_version_create',
  'retirement_worker_version_create',
]);
const managementDeleteActionSchema = v.picklist([
  'management_custom_domain_delete',
  'management_admin_policy_delete',
  'management_access_application_delete',
]);
const uninstallTransitionBaseEntries = {
  ...revisionAttemptNowSchema,
  action: mutableUninstallActionSchema,
};
const uninstallArmBodySchema = v.union([
  v.strictObject(uninstallTransitionBaseEntries),
  v.strictObject({ ...uninstallTransitionBaseEntries, value: boundaryValueSchema }),
]);
const uninstallValueBodySchema = v.strictObject({
  ...uninstallTransitionBaseEntries,
  value: boundaryValueSchema,
});
type UninstallTransitionInput = v.InferOutput<typeof uninstallArmBodySchema>;
const uninstallCompletionBodySchema = v.union([
  v.strictObject({
    attemptId: oauthAttemptIdSchema,
    code: v.literal('uninstall_complete'),
    completedAt: safeIntegerSchema,
    installationId: v.string(),
    grantRevocation: v.picklist(['confirmed', 'unconfirmed']),
    reason: v.null(),
  }),
  v.strictObject({
    attemptId: oauthAttemptIdSchema,
    code: v.string(),
    completedAt: safeIntegerSchema,
    installationId: v.null(),
    grantRevocation: v.null(),
    reason: v.nullable(failureReasonSchema),
  }),
]);
const successfulInstallCompletionSchema = v.strictObject({
  attemptId: oauthAttemptIdSchema,
  code: v.literal('install_complete'),
  completedAt: safeIntegerSchema,
  installationId: v.nullable(v.string()),
  grantRevocation: v.nullable(v.picklist(['confirmed', 'unconfirmed'])),
  reason: v.null(),
});
const failedInstallCompletionSchema = v.strictObject({
  attemptId: oauthAttemptIdSchema,
  code: v.string(),
  completedAt: safeIntegerSchema,
  installationId: v.null(),
  grantRevocation: v.null(),
  reason: v.nullable(failureReasonSchema),
  existingGateway: v.optional(boundaryValueSchema),
});
const installCompletionBodySchema = v.union([
  successfulInstallCompletionSchema,
  failedInstallCompletionSchema,
]);

async function jsonBody(request: Request): Promise<BoundaryObject> {
  if (!request.headers.get('content-type')?.toLowerCase().startsWith('application/json')) {
    throw new DeployError(400, 'bad_request');
  }
  let input: BoundaryValue;
  try {
    const candidate = v.safeParse(boundaryValueSchema, await request.json());
    if (!candidate.success) throw new DeployError(400, 'bad_request');
    input = candidate.output;
  } catch {
    throw new DeployError(400, 'bad_request');
  }
  const candidate = v.safeParse(boundaryObjectSchema, input);
  if (!candidate.success) throw new DeployError(400, 'bad_request');
  return candidate.output;
}

async function parsedJsonBody<Schema extends v.GenericSchema>(
  request: Request,
  schema: Schema,
): Promise<v.InferOutput<Schema>> {
  const candidate = v.safeParse(schema, await jsonBody(request));
  if (!candidate.success) throw new DeployError(400, 'bad_request');
  return candidate.output;
}

function internalJson<Value>(value: Value, status = 200): Response {
  return new Response(JSON.stringify(value), {
    status,
    headers: { 'content-type': 'application/json', 'cache-control': 'no-store' },
  });
}

function storedRevision<Value>(value: Value): number | null {
  const candidate = v.safeParse(v.object({ revision: v.pipe(v.number(), v.safeInteger()) }), value);
  return candidate.success ? candidate.output.revision : null;
}

function storedObject<Value>(value: Value): BoundaryObject | null {
  const candidate = v.safeParse(boundaryObjectSchema, value);
  return candidate.success ? candidate.output : null;
}

function failureCode<Value>(value: Value): DeployErrorCode {
  const candidate = v.safeParse(v.string(), value);
  if (candidate.success && isDeployErrorCode(candidate.output)) return candidate.output;
  throw new DeployError(400, 'bad_request');
}

function uninstallCompletionCode<Value>(value: Value): 'uninstall_complete' | DeployErrorCode {
  const candidate = v.safeParse(v.string(), value);
  if (candidate.success && candidate.output === 'uninstall_complete') return 'uninstall_complete';
  if (candidate.success && isDeployErrorCode(candidate.output)) return candidate.output;
  throw new DeployError(400, 'bad_request');
}

function hasRecoverableJournal(
  session: StoredDeploySession,
  journal: InstallJournal | null,
): journal is InstallJournal {
  return Boolean(
    journal &&
    (isPartialInstallJournal(journal) || (isCompleteInstallJournal(journal) && session.status !== 'succeeded')),
  );
}

export class GatewayDeploySession {
  private operationTail: Promise<void> = Promise.resolve();
  private readonly clock: () => number;

  constructor(
    private readonly state: GatewayDeploySessionState,
    _environment?: GatewayDeploySessionEnvironment,
    clock: () => number = Date.now,
  ) {
    this.clock = clock;
  }

  private async exclusively<T>(operation: () => Promise<T>): Promise<T> {
    const previous = this.operationTail;
    let release = (): void => undefined;
    this.operationTail = new Promise<void>((resolve) => {
      release = resolve;
    });
    await previous;
    try {
      return await operation();
    } finally {
      release();
    }
  }

  private wallTime(): number {
    const now = this.clock();
    if (!Number.isSafeInteger(now) || now < 0) throw new DeployError(500, 'session_invalid');
    return now;
  }

  async alarm(): Promise<void> {
    await this.exclusively(async () => this.handleAlarm());
  }

  private async handleAlarm(): Promise<void> {
    let session: StoredDeploySession | null;
    let journal: InstallJournal | null;
    let uninstallControl: StoredUninstallControl | null;
    let uninstallJournal: UninstallJournal | null;
    let returningUninstall: StoredReturningUninstall | null;
    let returningUninstallJournal: ReturningUninstallJournal | null;
    try {
      session = await this.stored();
      journal = await this.storedJournal(session);
      uninstallControl = await this.storedUninstallControl(session, journal);
      uninstallJournal = await this.storedUninstallJournal(session, journal, uninstallControl);
      returningUninstall = await this.storedReturningUninstall(session);
      returningUninstallJournal = await this.storedReturningUninstallJournal(session, returningUninstall);
    } catch {
      await this.clearStorage();
      return;
    }
    if (!session) {
      if (journal || uninstallControl || uninstallJournal || returningUninstall || returningUninstallJournal) {
        await this.clearStorage();
      }
      else await this.state.storage.deleteAlarm();
      return;
    }
    const now = this.wallTime();
    if (journal && now >= journal.recoverUntil) {
      await this.clearStorage();
      return;
    }
    if (journal?.lease && !isCompleteInstallJournal(journal) && now >= journal.lease.expiresAt) {
      journal = expireInstallJournalLease(journal, now);
      await this.putJournal(session, journal);
    }
    if (uninstallJournal?.lease && now >= uninstallJournal.lease.expiresAt) {
      if (!journal || !uninstallControl) {
        await this.clearStorage();
        return;
      }
      uninstallJournal = expireUninstallJournalLease(uninstallJournal, now);
      await this.putUninstallJournal(session, journal, uninstallControl, uninstallJournal);
    }
    if (returningUninstallJournal && now >= returningUninstallJournal.recoverUntil) {
      await this.clearStorage();
      return;
    }
    if (returningUninstallJournal?.lease && now >= returningUninstallJournal.lease.expiresAt) {
      if (!returningUninstall) {
        await this.clearStorage();
        return;
      }
      returningUninstallJournal = await releaseReturningUninstallLease(returningUninstallJournal, {
        expectedRevision: returningUninstallJournal.revision,
        attemptId: returningUninstallJournal.lease.attemptId,
        now,
      });
      await this.putReturningUninstallJournal(session, returningUninstall, returningUninstallJournal);
    }
    if (
      now >= session.expiresAt &&
      (!journal || (!isPartialInstallJournal(journal) && !isCompleteInstallJournal(journal))) &&
      (!returningUninstallJournal || now >= returningUninstallJournal.recoverUntil)
    ) {
      await this.clearStorage();
      return;
    }
    await this.scheduleStorage(session, journal, now, uninstallJournal, returningUninstallJournal);
  }

  async fetch(request: Request): Promise<Response> {
    return this.exclusively(async () => {
      try {
        const { pathname } = new URL(request.url);
        if (request.method === 'POST' && pathname === '/initialize') return await this.initialize(request);
        if (request.method === 'POST' && pathname === '/csrf/synchronize') return await this.synchronizeCsrf(request);
        if (request.method === 'GET' && pathname === '/public') return await this.readPublic();
        if (request.method === 'POST' && pathname === '/discover/authorize') return await this.authorizeDiscovery(request);
        if (request.method === 'POST' && pathname === '/discover/consume') return await this.consumeDiscovery(request);
        if (request.method === 'POST' && pathname === '/discover/complete') return await this.completeDiscovery(request);
        if (request.method === 'PUT' && pathname === '/selection') return await this.saveSelection(request);
        if (request.method === 'POST' && pathname === '/plan') return await this.previewPlan(request);
        if (request.method === 'POST' && pathname === '/authorize') return await this.authorize(request);
        if (request.method === 'POST' && pathname === '/consume') return await this.consume(request);
        if (request.method === 'POST' && pathname === '/complete') return await this.complete(request);
        if (request.method === 'POST' && pathname === '/install-journal/initialize') return await this.initializeInstallJournal(request);
        if (request.method === 'POST' && pathname === '/install-journal/recovery-plan') return await this.createRecoveryPlan(request);
        if (request.method === 'POST' && pathname === '/install-journal/approval/append') return await this.appendInstallApproval(request);
        if (request.method === 'GET' && pathname === '/install-journal') return await this.readInstallJournal();
        if (request.method === 'POST' && pathname === '/install-journal/lease/acquire') return await this.acquireInstallLease(request);
        if (request.method === 'POST' && pathname === '/install-journal/lease/release') return await this.releaseInstallLease(request);
        if (request.method === 'POST' && pathname === '/install-journal/action/prepare') return await this.prepareInstallAction(request);
        if (request.method === 'POST' && pathname === '/install-journal/action/arm') return await this.armInstallAction(request);
        if (request.method === 'POST' && pathname === '/install-journal/action/submitted') return await this.submitInstallAction(request);
        if (request.method === 'POST' && pathname === '/install-journal/action/verified') return await this.verifyInstallAction(request);
        if (request.method === 'POST' && pathname === '/install-journal/customer-bootstrap/attempt/append') return await this.appendBootstrapAttempt(request);
        if (request.method === 'POST' && pathname === '/uninstall/plan') return await this.previewUninstallPlan(request);
        if (request.method === 'POST' && pathname === '/uninstall/authorize') return await this.authorizeUninstall(request);
        if (request.method === 'POST' && pathname === '/uninstall/consume') return await this.consumeUninstall(request);
        if (request.method === 'POST' && pathname === '/uninstall/complete') return await this.completeUninstall(request);
        if (request.method === 'POST' && pathname === '/returning-uninstall/plan') return await this.prepareReturningUninstall(request);
        if (request.method === 'POST' && pathname === '/returning-uninstall/authorize') return await this.authorizeReturningUninstall(request);
        if (request.method === 'POST' && pathname === '/returning-uninstall/consume') return await this.consumeReturningUninstall(request);
        if (request.method === 'POST' && pathname === '/returning-uninstall/recovery/plan') return await this.prepareReturningUninstallRecovery(request);
        if (request.method === 'POST' && pathname === '/returning-uninstall/recovery/authorize') return await this.authorizeReturningUninstallRecovery(request);
        if (request.method === 'POST' && pathname === '/returning-uninstall/recovery/consume') return await this.consumeReturningUninstallRecovery(request);
        if (request.method === 'POST' && pathname === '/returning-uninstall/complete') return await this.completeReturningUninstall(request);
        if (request.method === 'POST' && pathname === '/returning-uninstall-journal/initialize') return await this.initializeReturningUninstallJournal(request);
        if (request.method === 'GET' && pathname === '/returning-uninstall-journal') return await this.readReturningUninstallJournal();
        if (request.method === 'POST' && pathname === '/returning-uninstall-journal/approval') return await this.appendReturningUninstallJournalApproval(request);
        if (request.method === 'POST' && pathname === '/returning-uninstall-journal/approval/hosted-recovery') return await this.appendReturningUninstallHostedRecoveryJournalApproval(request);
        if (request.method === 'POST' && pathname === '/returning-uninstall-journal/lease/acquire') return await this.acquireReturningUninstallJournalLease(request);
        if (request.method === 'POST' && pathname === '/returning-uninstall-journal/lease/release') return await this.releaseReturningUninstallJournalLease(request);
        if (request.method === 'POST' && pathname === '/returning-uninstall-journal/action/prepare') return await this.prepareReturningUninstallJournalAction(request);
        if (request.method === 'POST' && pathname === '/returning-uninstall-journal/action/arm') return await this.armReturningUninstallJournalAction(request);
        if (request.method === 'POST' && pathname === '/returning-uninstall-journal/action/submit') return await this.submitReturningUninstallJournalAction(request);
        if (request.method === 'POST' && pathname === '/returning-uninstall-journal/action/verify') return await this.verifyReturningUninstallJournalAction(request);
        if (request.method === 'POST' && pathname === '/uninstall-journal/initialize') return await this.initializeUninstallJournal(request);
        if (request.method === 'GET' && pathname === '/uninstall-journal') return await this.readUninstallJournal();
        if (request.method === 'POST' && pathname === '/uninstall-journal/approval/append') return await this.appendUninstallApproval(request);
        if (request.method === 'POST' && pathname === '/uninstall-journal/lease/acquire') return await this.acquireUninstallLease(request);
        if (request.method === 'POST' && pathname === '/uninstall-journal/lease/release') return await this.releaseUninstallLease(request);
        if (request.method === 'POST' && pathname === '/uninstall-journal/preflight/refresh') return await this.refreshUninstallPreflight(request);
        if (request.method === 'POST' && pathname === '/uninstall-journal/preflight/discard') return await this.discardUninstallPreflight(request);
        if (request.method === 'POST' && pathname === '/uninstall-journal/management-preflight/append') return await this.appendUninstallManagementPreflight(request);
        if (request.method === 'POST' && pathname === '/uninstall-journal/action/prepare') return await this.prepareUninstallAction(request);
        if (request.method === 'POST' && pathname === '/uninstall-journal/action/replace') return await this.replacePreparedUninstallAction(request);
        if (request.method === 'POST' && pathname === '/uninstall-journal/action/version-recovery/attach') return await this.attachUninstallVersionRecovery(request);
        if (request.method === 'POST' && pathname === '/uninstall-journal/action/arm') return await this.armUninstallAction(request);
        if (request.method === 'POST' && pathname === '/uninstall-journal/action/submitted') return await this.submitUninstallAction(request);
        if (request.method === 'POST' && pathname === '/uninstall-journal/action/verified') return await this.verifyUninstallAction(request);
        if (request.method === 'POST' && pathname === '/uninstall-journal/customer-remove/cycle/append') return await this.appendCustomerRemoveCycle(request);
        if (request.method === 'POST' && pathname === '/uninstall-journal/customer-remove/cycle/replace') return await this.replaceCustomerRemoveCycle(request);
        if (request.method === 'POST' && pathname === '/uninstall-journal/customer-remove/workers-dev/disable/prepare') return await this.prepareCustomerWorkersDevDisable(request);
        if (request.method === 'POST' && pathname === '/uninstall-journal/customer-remove/workers-dev/disable/replace') return await this.replaceCustomerWorkersDevDisable(request);
        if (request.method === 'POST' && pathname === '/uninstall-journal/customer-remove/workers-dev/arm') return await this.armCustomerWorkersDev(request);
        if (request.method === 'POST' && pathname === '/uninstall-journal/customer-remove/workers-dev/submitted') return await this.submitCustomerWorkersDev(request);
        if (request.method === 'POST' && pathname === '/uninstall-journal/customer-remove/workers-dev/verified') return await this.verifyCustomerWorkersDev(request);
        if (request.method === 'POST' && pathname === '/uninstall-journal/customer-remove/workers-dev/not-applied') return await this.recordCustomerWorkersDevNotApplied(request);
        if (request.method === 'POST' && pathname === '/uninstall-journal/customer-remove/request/arm') return await this.armCustomerRemoveRequest(request);
        if (request.method === 'POST' && pathname === '/uninstall-journal/customer-remove/request/submitted') return await this.submitCustomerRemoveRequest(request);
        if (request.method === 'POST' && pathname === '/uninstall-journal/customer-remove/request/verified') return await this.verifyCustomerRemoveRequest(request);
        if (request.method === 'POST' && pathname === '/uninstall-journal/management-delete/attempt/append') return await this.appendManagementDeleteAttempt(request);
        if (request.method === 'POST' && pathname === '/uninstall-journal/management-delete/recovery') return await this.recordManagementDeleteRecovery(request);
        if (request.method === 'DELETE' && pathname === '/destroy') return await this.destroy(request);
        return internalJson({ error: { code: 'bad_request' } }, 404);
      } catch (error) {
        const stable = stableError(error instanceof Error ? error : undefined);
        return internalJson({ error: { code: stable.code } }, stable.status);
      }
    });
  }

  private async stored(): Promise<StoredDeploySession | null> {
    const stored = await this.state.storage.get<unknown>(STORAGE_KEY);
    return stored === undefined ? null : requireStoredSession(stored);
  }

  private async storedDiscovery(): Promise<StoredCloudflareDiscovery | null> {
    const stored = await this.state.storage.get<unknown>(DISCOVERY_STORAGE_KEY);
    return stored === undefined ? null : requireStoredCloudflareDiscovery(stored);
  }

  private async putDiscovery(discovery: StoredCloudflareDiscovery): Promise<void> {
    const validated = requireStoredCloudflareDiscovery(discovery);
    assertSecretFree(validated);
    await this.state.storage.put(DISCOVERY_STORAGE_KEY, validated);
  }

  private async storedReturningUninstall(
    session: StoredDeploySession | null,
  ): Promise<StoredReturningUninstall | null> {
    const stored = await this.state.storage.get<unknown>(RETURNING_UNINSTALL_STORAGE_KEY);
    if (stored === undefined) return null;
    const control = await requireStoredReturningUninstall(stored);
    const gateway = session?.result?.code === 'existing_gateway_detected'
      ? parseExistingAnkkaGatewaySummary(session.result.existingGateway)
      : null;
    if (!session || session.status !== 'failed' || !gateway ||
      JSON.stringify(gateway) !== JSON.stringify(control.plan.gateway)) {
      throw new DeployError(500, 'session_invalid');
    }
    return control;
  }

  private async putReturningUninstall(
    session: StoredDeploySession,
    value: StoredReturningUninstall,
  ): Promise<void> {
    const validated = await requireStoredReturningUninstall(value);
    const gateway = session.result?.code === 'existing_gateway_detected'
      ? parseExistingAnkkaGatewaySummary(session.result.existingGateway)
      : null;
    if (session.status !== 'failed' || !gateway ||
      JSON.stringify(gateway) !== JSON.stringify(validated.plan.gateway)) {
      throw new DeployError(500, 'session_invalid');
    }
    assertSecretFree(validated);
    await this.state.storage.put(RETURNING_UNINSTALL_STORAGE_KEY, validated);
    const returningJournal = await this.storedReturningUninstallJournal(session, validated);
    await this.scheduleStorage(session, null, this.wallTime(), null, returningJournal);
  }

  private async storedReturningUninstallJournal(
    session: StoredDeploySession | null,
    control: StoredReturningUninstall | null,
  ): Promise<ReturningUninstallJournal | null> {
    const stored = await this.state.storage.get<unknown>(RETURNING_UNINSTALL_JOURNAL_STORAGE_KEY);
    if (stored === undefined) return null;
    const journal = await requireReturningUninstallJournal(stored);
    if (!session || !control || journal.plan.planId !== control.plan.planId ||
      journal.plan.planHash !== control.plan.planHash ||
      journal.installationId !== control.plan.gateway.installationId ||
      journal.authority.runtime.accountId !== control.action.accountId ||
      journal.authority.runtime.workerName !== control.action.workerName) {
      throw new DeployError(500, 'session_invalid');
    }
    return journal;
  }

  private async putReturningUninstallJournal(
    session: StoredDeploySession,
    control: StoredReturningUninstall,
    value: ReturningUninstallJournal,
  ): Promise<void> {
    const journal = await requireReturningUninstallJournal(value);
    if (journal.plan.planId !== control.plan.planId || journal.plan.planHash !== control.plan.planHash ||
      journal.installationId !== control.plan.gateway.installationId ||
      journal.authority.runtime.accountId !== control.action.accountId ||
      journal.authority.runtime.workerName !== control.action.workerName) throw new DeployError(500, 'session_invalid');
    assertSecretFree(journal);
    await this.state.storage.transaction(async (transaction) => {
      const stored = await transaction.get<unknown>(RETURNING_UNINSTALL_JOURNAL_STORAGE_KEY);
      const retained = storedObject(stored);
      if ((journal.revision === 0 && stored !== undefined) ||
        (journal.revision > 0 && (storedRevision(stored) !== journal.revision - 1 ||
          retained?.bindingHash !== journal.bindingHash))) throw new DeployError(409, 'session_conflict');
      await transaction.put(RETURNING_UNINSTALL_JOURNAL_STORAGE_KEY, journal);
    });
    await this.scheduleStorage(session, null, this.wallTime(), null, journal);
  }

  private async storedJournal(session?: StoredDeploySession | null): Promise<InstallJournal | null> {
    const stored = await this.state.storage.get<unknown>(INSTALL_JOURNAL_STORAGE_KEY);
    if (stored === undefined) return null;
    const journal = await requireInstallJournal(stored);
    if (session && (
      journal.sessionExpiresAt !== session.expiresAt ||
      !session.selection || !session.plan ||
      JSON.stringify(journal.selection) !== JSON.stringify(session.selection) ||
      !isRecoveryEquivalentInstallPlan(journal.plan, session.plan)
    )) throw new DeployError(500, 'session_invalid');
    return journal;
  }

  private async storedUninstallControl(
    session: StoredDeploySession | null,
    installJournal: InstallJournal | null,
  ): Promise<StoredUninstallControl | null> {
    const stored = await this.state.storage.get<unknown>(UNINSTALL_CONTROL_STORAGE_KEY);
    if (stored === undefined) return null;
    const control = await requireStoredUninstallControl(stored);
    if (!session || !installJournal || session.status !== 'succeeded' ||
      session.result?.code !== 'install_complete' || !isCompleteInstallJournal(installJournal) ||
      session.result.installationId !== control.installationId ||
      installJournal.installationId !== control.installationId ||
      installJournal.bindingHash !== control.installBindingHash ||
      installJournal.recoverUntil !== control.recoverUntil) {
      throw new DeployError(500, 'session_invalid');
    }
    const rebuilt = await buildStaticUninstallPlan(
      installJournal,
      control.plan.createdAt,
      control.plan.expiresAt,
    );
    if (JSON.stringify(rebuilt) !== JSON.stringify(control.plan)) {
      throw new DeployError(500, 'session_invalid');
    }
    return control;
  }

  private async storedUninstallJournal(
    session: StoredDeploySession | null,
    installJournal: InstallJournal | null,
    control: StoredUninstallControl | null,
  ): Promise<UninstallJournal | null> {
    const stored = await this.state.storage.get<unknown>(UNINSTALL_JOURNAL_STORAGE_KEY);
    if (stored === undefined) return null;
    const journal = await requireUninstallJournal(stored);
    if (!session || !installJournal || !control || journal.installJournal.installationId !== control.installationId ||
      journal.installJournal.bindingHash !== control.installBindingHash ||
      journal.recoverUntil !== control.recoverUntil ||
      JSON.stringify(journal.installJournal) !== JSON.stringify(installJournal) ||
      !await isRecoveryEquivalentUninstallPlan(journal.uninstallPlan, control.plan)) {
      throw new DeployError(500, 'session_invalid');
    }
    return journal;
  }

  private async scheduleStorage(
    session: StoredDeploySession,
    journal: InstallJournal | null,
    now: number,
    uninstallJournal: UninstallJournal | null = null,
    returningUninstallJournal: ReturningUninstallJournal | null = null,
  ): Promise<void> {
    const deadlines: number[] = [];
    if (session.expiresAt > now) deadlines.push(session.expiresAt);
    else if (
      journal &&
      (isPartialInstallJournal(journal) || isCompleteInstallJournal(journal)) &&
      journal.recoverUntil > now
    ) {
      deadlines.push(journal.recoverUntil);
    }
    // A completed install journal is immutable removal authority. Its final
    // install lease is inert and must never schedule a later journal rewrite.
    if (journal?.lease && !isCompleteInstallJournal(journal) && journal.lease.expiresAt > now) {
      deadlines.push(journal.lease.expiresAt);
    }
    if (uninstallJournal?.lease && uninstallJournal.lease.expiresAt > now) {
      deadlines.push(uninstallJournal.lease.expiresAt);
    }
    if (returningUninstallJournal?.recoverUntil && returningUninstallJournal.recoverUntil > now) {
      deadlines.push(returningUninstallJournal.recoverUntil);
    }
    if (returningUninstallJournal?.lease && returningUninstallJournal.lease.expiresAt > now) {
      deadlines.push(returningUninstallJournal.lease.expiresAt);
    }
    await this.state.storage.setAlarm(deadlines.length > 0 ? Math.min(...deadlines) : now);
  }

  private async put(session: StoredDeploySession, journal: InstallJournal | null = null, now = session.updatedAt): Promise<void> {
    assertSecretFree(session);
    await this.state.storage.put(STORAGE_KEY, session);
    await this.scheduleStorage(session, journal, now);
  }

  private async putJournal(session: StoredDeploySession, journal: InstallJournal): Promise<void> {
    const validated = await requireInstallJournal(journal);
    if (
      validated.sessionExpiresAt !== session.expiresAt || !session.selection || !session.plan ||
      JSON.stringify(validated.selection) !== JSON.stringify(session.selection) ||
      !isRecoveryEquivalentInstallPlan(validated.plan, session.plan)
    ) throw new DeployError(500, 'session_invalid');
    assertSecretFree(validated);
    await this.state.storage.transaction(async (transaction) => {
      const stored = await transaction.get<unknown>(INSTALL_JOURNAL_STORAGE_KEY);
      const storedRecord = storedObject(stored);
      if (
        (validated.revision === 0 && stored !== undefined) ||
        (validated.revision > 0 && (
          storedRevision(stored) !== validated.revision - 1 ||
          storedRecord?.bindingHash !== validated.bindingHash ||
          storedRecord.installationId !== validated.installationId
        ))
      ) throw new DeployError(409, 'session_conflict');
      await transaction.put(INSTALL_JOURNAL_STORAGE_KEY, validated);
    });
    await this.scheduleStorage(session, validated, this.wallTime());
  }

  private async putUninstallControl(
    session: StoredDeploySession,
    installJournal: InstallJournal,
    control: StoredUninstallControl,
    uninstallJournal: UninstallJournal | null = null,
  ): Promise<void> {
    const validated = await requireStoredUninstallControl(control);
    if (session.status !== 'succeeded' || session.result?.code !== 'install_complete' ||
      !isCompleteInstallJournal(installJournal) || session.result.installationId !== validated.installationId ||
      installJournal.installationId !== validated.installationId ||
      installJournal.bindingHash !== validated.installBindingHash ||
      installJournal.recoverUntil !== validated.recoverUntil) throw new DeployError(500, 'session_invalid');
    assertSecretFree(validated);
    await this.state.storage.put(UNINSTALL_CONTROL_STORAGE_KEY, validated);
    await this.scheduleStorage(session, installJournal, this.wallTime(), uninstallJournal);
  }

  private async putUninstallJournal(
    session: StoredDeploySession,
    installJournal: InstallJournal,
    control: StoredUninstallControl,
    journal: UninstallJournal,
  ): Promise<void> {
    const validated = await requireUninstallJournal(journal);
    if (validated.installJournal.installationId !== control.installationId ||
      validated.installJournal.bindingHash !== control.installBindingHash ||
      validated.recoverUntil !== control.recoverUntil ||
      JSON.stringify(validated.installJournal) !== JSON.stringify(installJournal) ||
      !await isRecoveryEquivalentUninstallPlan(validated.uninstallPlan, control.plan)) {
      throw new DeployError(500, 'session_invalid');
    }
    assertSecretFree(validated);
    await this.state.storage.transaction(async (transaction) => {
      const stored = await transaction.get<unknown>(UNINSTALL_JOURNAL_STORAGE_KEY);
      const record = storedObject(stored);
      if ((validated.revision === 0 && stored !== undefined) ||
        (validated.revision > 0 && (storedRevision(stored) !== validated.revision - 1 ||
          record?.bindingHash !== validated.bindingHash ||
          record.uninstallCycleId !== validated.uninstallCycleId))) {
        throw new DeployError(409, 'session_conflict');
      }
      await transaction.put(UNINSTALL_JOURNAL_STORAGE_KEY, validated);
    });
    await this.scheduleStorage(session, installJournal, this.wallTime(), validated);
  }

  private async clearStorage(): Promise<void> {
    await this.state.storage.deleteAll();
    await this.state.storage.deleteAlarm();
  }

  private async initialize(request: Request): Promise<Response> {
    const input = await parsedJsonBody(request, v.strictObject({
      csrfHash: csrfHashSchema,
      createdAt: safeIntegerSchema,
      expiresAt: safeIntegerSchema,
    }));
    if (input.expiresAt <= input.createdAt) {
      throw new DeployError(400, 'bad_request');
    }
    const now = this.wallTime();
    const expiresAt = now + SESSION_TTL_MS;
    if (!Number.isSafeInteger(expiresAt)) throw new DeployError(500, 'session_invalid');
    const existing = await this.stored();
    const existingJournal = await this.storedJournal(existing);
    if (existing) {
      await this.scheduleStorage(existing, existingJournal, now);
      return internalJson({ session: publicSession(existing) });
    }
    if (existingJournal) await this.clearStorage();
    const session: StoredDeploySession = {
      schemaVersion: 1,
      status: 'draft',
      csrfHash: input.csrfHash,
      createdAt: now,
      updatedAt: now,
      expiresAt,
      selection: null,
      plan: null,
      oauthAttempt: null,
      result: null,
    };
    await this.put(session);
    return internalJson({ session: publicSession(session) }, 201);
  }

  private async synchronizeCsrf(request: Request): Promise<Response> {
    const input = await parsedJsonBody(request, v.strictObject({ csrfHash: csrfHashSchema }));
    const session = await this.stored();
    if (!session) throw new DeployError(404, 'session_invalid');
    if (!constantTimeEqual(input.csrfHash, session.csrfHash)) {
      const synchronized = { ...session, csrfHash: input.csrfHash };
      assertSecretFree(synchronized);
      await this.state.storage.put(STORAGE_KEY, synchronized);
    }
    return internalJson({ synchronized: true });
  }

  private async readPublic(): Promise<Response> {
    let session: StoredDeploySession | null;
    let journal: InstallJournal | null;
    let uninstallControl: StoredUninstallControl | null;
    let uninstallJournal: UninstallJournal | null;
    let returningUninstall: StoredReturningUninstall | null;
    let returningUninstallJournal: ReturningUninstallJournal | null;
    try {
      session = await this.stored();
      journal = await this.storedJournal(session);
      uninstallControl = await this.storedUninstallControl(session, journal);
      uninstallJournal = await this.storedUninstallJournal(session, journal, uninstallControl);
      returningUninstall = await this.storedReturningUninstall(session);
      returningUninstallJournal = await this.storedReturningUninstallJournal(session, returningUninstall);
    } catch {
      await this.clearStorage();
      throw new DeployError(404, 'session_invalid');
    }
    if (!session) {
      if (journal || uninstallControl || uninstallJournal || returningUninstall || returningUninstallJournal) {
        await this.clearStorage();
      }
      throw new DeployError(404, 'session_invalid');
    }
    const now = this.wallTime();
    const recoverable = hasRecoverableJournal(session, journal) && now < journal.recoverUntil;
    const resultAvailable = Boolean(
      journal &&
      isCompleteInstallJournal(journal) &&
      session.status === 'succeeded' &&
      session.result?.code === 'install_complete' &&
      session.result.installationId === journal.installationId &&
      now < journal.recoverUntil
    );
    if (uninstallControl && (now >= uninstallControl.recoverUntil ||
      (uninstallJournal && uninstallJournal.recoverUntil !== uninstallControl.recoverUntil))) {
      await this.clearStorage();
      throw new DeployError(404, 'session_invalid');
    }
    if (
      (journal && now >= journal.recoverUntil) ||
      (now >= session.expiresAt && !recoverable && !resultAvailable &&
        (!returningUninstallJournal || now >= returningUninstallJournal.recoverUntil))
    ) {
      if (!journal || !isCompleteInstallJournal(journal)) await this.clearStorage();
      throw new DeployError(404, 'session_invalid');
    }
    const recovery: PublicDeployRecovery | null = now >= session.expiresAt && recoverable && journal
      ? { status: 'recovery_required', recoverUntil: journal.recoverUntil }
      : null;
    const resultRetention: PublicDeployResultRetention | null = now >= session.expiresAt && resultAvailable && journal
      ? { status: 'result_available', resultUntil: journal.recoverUntil }
      : null;
    const discovery = await this.storedDiscovery();
    const returningGatewayRemoval = returningUninstallJournal?.actions.find(
      (action) => action.name === 'customer_gateway_remove',
    );
    const returningRecoveryAvailable = Boolean(
      returningUninstall?.status !== 'removed' && returningGatewayRemoval?.phase === 'verified' &&
      returningUninstallJournal && now < returningUninstallJournal.recoverUntil,
    );
    return internalJson({
      session: publicSession(session),
      installProgress: publicInstallProgress(journal),
      discovery: publicCloudflareDiscovery(discovery),
      recovery,
      resultRetention,
      uninstall: uninstallControl ? publicUninstallSession(uninstallControl) : null,
      uninstallRecovery: uninstallJournal && isPartialUninstallJournal(uninstallJournal)
        ? { status: 'recovery_required', recoverUntil: uninstallJournal.recoverUntil }
        : null,
      returningUninstall: returningUninstall
        ? publicReturningUninstall(returningUninstall, returningRecoveryAvailable)
        : null,
    });
  }

  private async saveSelection(request: Request): Promise<Response> {
    const input = await parsedJsonBody(request, v.strictObject({
      csrfHash: v.string(),
      selection: boundaryValueSchema,
      targetIdHash: v.optional(boundaryValueSchema),
      now: safeIntegerSchema,
    }));
    const targetIdHash = input.targetIdHash ?? null;
    const session = await this.stored();
    if (!session) throw new DeployError(404, 'session_invalid');
    const now = this.wallTime();
    const journal = await this.storedJournal(session);
    if (journal && hasArmedInstallJournalAction(journal)) throw new DeployError(409, 'session_conflict');
    if (now >= session.expiresAt) {
      throw new DeployError(410, 'session_expired');
    }
    if (session.status === 'installing' || session.status === 'succeeded') {
      throw new DeployError(409, 'session_conflict');
    }
    verifyHash(input.csrfHash, session.csrfHash);
    const selection = parseDeploySelection(input.selection);
    const discovery = await this.storedDiscovery();
    if (discovery) {
      if (discovery.status !== 'ready' || !discovery.result ||
        !v.is(targetIdHashSchema, targetIdHash)) {
        throw new DeployError(409, 'session_conflict');
      }
      const target = discovery.result.targets.find((candidate) => candidate.targetIdHash === targetIdHash);
      if (!target || target.zone.name !== selection.basics.zoneName ||
        discovery.result.actor.email !== selection.basics.adminEmail) {
        throw new DeployError(409, 'session_conflict');
      }
      await this.putDiscovery({ ...discovery, selectedTargetIdHash: targetIdHash, updatedAt: now });
    } else if (targetIdHash !== null) {
      throw new DeployError(409, 'session_conflict');
    }
    const next: StoredDeploySession = {
      ...session,
      status: 'draft',
      updatedAt: now,
      selection,
      plan: null,
      oauthAttempt: null,
      result: null,
    };
    if (journal) await this.clearStorage();
    await this.put(next);
    return internalJson({ session: publicSession(next) });
  }

  private async previewPlan(request: Request): Promise<Response> {
    const input = await parsedJsonBody(request, v.strictObject({
      csrfHash: v.string(),
      releaseManifest: boundaryValueSchema,
      planExpiresAt: safeIntegerSchema,
      now: safeIntegerSchema,
    }));
    const session = await this.stored();
    if (!session?.selection) throw new DeployError(409, 'session_conflict');
    const now = this.wallTime();
    const journal = await this.storedJournal(session);
    if (journal && hasArmedInstallJournalAction(journal)) throw new DeployError(409, 'session_conflict');
    if (
      now >= session.expiresAt || input.planExpiresAt <= now ||
      input.planExpiresAt > session.expiresAt
    ) throw new DeployError(410, 'session_expired');
    if (session.status === 'installing' || session.status === 'succeeded') {
      throw new DeployError(409, 'session_conflict');
    }
    verifyHash(input.csrfHash, session.csrfHash);
    const manifest = parseReleaseManifest(input.releaseManifest);
    const plan = await buildStaticDeployPlan(session.selection, manifest, input.planExpiresAt);
    const next: StoredDeploySession = {
      ...session,
      status: 'draft',
      updatedAt: now,
      plan,
      oauthAttempt: null,
      result: null,
    };
    if (journal) await this.clearStorage();
    await this.put(next);
    return internalJson({ session: publicSession(next) });
  }

  private async authorize(request: Request): Promise<Response> {
    const input = await parsedJsonBody(request, v.strictObject({
      ...oauthAuthorizeBodyEntries,
      releaseManifest: boundaryObjectSchema,
      approvedPlanId: v.string(),
      approvedPlanHash: v.string(),
    }));
    const session = await this.stored();
    if (!session?.selection || !session.plan) throw new DeployError(409, 'session_conflict');
    const now = this.wallTime();
    const journal = await this.storedJournal(session);
    const recoveryJournal = hasRecoverableJournal(session, journal) ? journal : null;
    const authorizationDeadline = recoveryJournal
      ? Math.min(recoveryJournal.recoverUntil, session.plan.expiresAt)
      : session.expiresAt;
    if (now >= authorizationDeadline) {
      throw new DeployError(410, 'session_expired');
    }
    if ((session.status === 'installing' && !recoveryJournal) || session.status === 'succeeded') {
      throw new DeployError(409, 'session_conflict');
    }
    verifyHash(input.csrfHash, session.csrfHash);
    if (
      input.attemptExpiresAt <= now ||
      input.attemptExpiresAt > authorizationDeadline || input.attemptExpiresAt > session.plan.expiresAt ||
      !input.releaseManifest
    ) {
      throw new DeployError(400, 'bad_request');
    }
    if (
      input.approvedPlanId !== session.plan.planId ||
      input.approvedPlanHash !== session.plan.planHash || now >= session.plan.expiresAt
    ) throw new DeployError(409, 'session_conflict');
    const selection = parseDeploySelection(session.selection);
    const plan = await buildStaticDeployPlan(
      selection,
      parseReleaseManifest(input.releaseManifest),
      session.plan.expiresAt,
    );
    if (JSON.stringify(plan) !== JSON.stringify(session.plan)) {
      throw new DeployError(409, 'session_conflict');
    }
    assertSecretFree(plan);
    const next: StoredDeploySession = {
      ...session,
      status: 'authorizing',
      updatedAt: Math.min(now, session.expiresAt),
      selection,
      plan,
      oauthAttempt: {
        attemptId: input.attemptId,
        stateHash: input.stateHash,
        verifierHash: input.verifierHash,
        expiresAt: input.attemptExpiresAt,
        usedAt: null,
      },
      result: null,
    };
    await this.put(next, journal, now);
    return internalJson({ accepted: true });
  }

  private async consume(request: Request): Promise<Response> {
    const input = await parsedJsonBody(request, oauthConsumeBodySchema);
    const session = await this.stored();
    if (!session?.oauthAttempt || !session.selection || !session.plan) {
      throw new DeployError(400, 'oauth_state_invalid');
    }
    const journal = await this.storedJournal(session);
    const now = this.wallTime();
    const recoveryJournal = hasRecoverableJournal(session, journal) ? journal : null;
    const attempt = session.oauthAttempt;
    if (
      session.status !== 'authorizing' ||
      attempt.usedAt !== null ||
      now >= attempt.expiresAt ||
      now >= session.plan.expiresAt ||
      (recoveryJournal && now >= recoveryJournal.recoverUntil) ||
      input.attemptId !== attempt.attemptId ||
      !constantHashes(input.stateHash, attempt.stateHash, input.verifierHash, attempt.verifierHash)
    ) {
      throw new DeployError(400, 'oauth_state_invalid');
    }
    const next: StoredDeploySession = {
      ...session,
      status: 'installing',
      updatedAt: Math.min(now, session.expiresAt),
      oauthAttempt: { ...attempt, usedAt: now },
    };
    await this.put(next, journal, now);
    const recoverUntil = journal?.recoverUntil ?? session.expiresAt + MAX_INSTALL_RECOVERY_RETENTION_MS;
    if (!Number.isSafeInteger(recoverUntil) || recoverUntil <= now) {
      throw new DeployError(500, 'session_invalid');
    }
    return internalJson({
      selection: session.selection,
      plan: session.plan,
      recoverUntil,
      discoveredTarget: selectedDiscoveredTarget(await this.storedDiscovery()),
    });
  }

  private async authorizeDiscovery(request: Request): Promise<Response> {
    const input = await parsedJsonBody(request, v.strictObject(oauthAuthorizeBodyEntries));
    const session = await this.stored();
    if (!session) throw new DeployError(404, 'session_invalid');
    const now = this.wallTime();
    if (now >= session.expiresAt || session.status === 'installing' || session.status === 'succeeded' ||
      session.selection !== null || session.plan !== null) {
      throw new DeployError(409, 'session_conflict');
    }
    verifyHash(input.csrfHash, session.csrfHash);
    if (input.attemptExpiresAt <= now || input.attemptExpiresAt > session.expiresAt ||
      input.attemptExpiresAt > now + OAUTH_ATTEMPT_TTL_MS) {
      throw new DeployError(400, 'bad_request');
    }
    await this.putDiscovery({
      schemaVersion: 1,
      status: 'authorizing',
      updatedAt: now,
      expiresAt: session.expiresAt,
      oauthAttempt: {
        attemptId: input.attemptId,
        stateHash: input.stateHash,
        verifierHash: input.verifierHash,
        expiresAt: input.attemptExpiresAt,
        usedAt: null,
      },
      result: null,
      selectedTargetIdHash: null,
      failureCode: null,
      grantRevocation: null,
    });
    return internalJson({ accepted: true });
  }

  private async consumeDiscovery(request: Request): Promise<Response> {
    const input = await parsedJsonBody(request, oauthConsumeBodySchema);
    const discovery = await this.storedDiscovery();
    const now = this.wallTime();
    const attempt = discovery?.oauthAttempt;
    if (!discovery || discovery.status !== 'authorizing' || !attempt || attempt.usedAt !== null ||
      now >= attempt.expiresAt || now >= discovery.expiresAt ||
      input.attemptId !== attempt.attemptId ||
      !constantHashes(input.stateHash, attempt.stateHash, input.verifierHash, attempt.verifierHash)) {
      throw new DeployError(400, 'oauth_state_invalid');
    }
    await this.putDiscovery({
      ...discovery,
      updatedAt: now,
      oauthAttempt: { ...attempt, usedAt: now },
    });
    return internalJson({ accepted: true });
  }

  private async completeDiscovery(request: Request): Promise<Response> {
    const input = await parsedJsonBody(request, v.strictObject({
      attemptId: oauthAttemptIdSchema,
      code: v.string(),
      result: v.nullable(cloudflareDiscoveryResultSchema),
      grantRevocation: v.nullable(v.picklist(['confirmed', 'unconfirmed'])),
      completedAt: safeIntegerSchema,
    }));
    const discovery = await this.storedDiscovery();
    const attempt = discovery?.oauthAttempt;
    const now = this.wallTime();
    if (!discovery || discovery.status !== 'authorizing' || !attempt || attempt.usedAt === null ||
      input.attemptId !== attempt.attemptId ||
      now < attempt.usedAt || now >= discovery.expiresAt) {
      throw new DeployError(409, 'session_conflict');
    }
    if (input.code === 'discovery_complete') {
      if (input.grantRevocation !== 'confirmed' && input.grantRevocation !== 'unconfirmed') {
        throw new DeployError(400, 'bad_request');
      }
      const candidate = requireStoredCloudflareDiscovery({
        ...discovery,
        status: 'ready',
        updatedAt: now,
        result: input.result,
        selectedTargetIdHash: null,
        failureCode: null,
        grantRevocation: input.grantRevocation,
      });
      await this.putDiscovery(candidate);
    } else {
      if (!isDeployErrorCode(input.code) || input.result !== null || input.grantRevocation !== null) {
        throw new DeployError(400, 'bad_request');
      }
      await this.putDiscovery({
        ...discovery,
        status: 'failed',
        updatedAt: now,
        result: null,
        selectedTargetIdHash: null,
        failureCode: input.code,
        grantRevocation: null,
      });
    }
    return internalJson({ accepted: true });
  }

  private requireInstallAttempt<Input>(session: StoredDeploySession, attemptId: Input): string {
    const candidate = v.safeParse(oauthAttemptIdSchema, attemptId);
    if (
      !candidate.success || session.status !== 'installing' ||
      !session.oauthAttempt || session.oauthAttempt.usedAt === null ||
      session.oauthAttempt.attemptId !== candidate.output
    ) throw new DeployError(409, 'session_conflict');
    return candidate.output;
  }

  private async initializeInstallJournal(request: Request): Promise<Response> {
    const input = await parsedJsonBody(request, v.strictObject({
      schemaVersion: v.literal(1),
      now: safeIntegerSchema,
      recoverUntil: safeIntegerSchema,
      selection: boundaryValueSchema,
      plan: boundaryValueSchema,
      releasePin: boundaryValueSchema,
      target: boundaryValueSchema,
      installationId: v.string(),
      bindingHash: v.string(),
      gatewayFreshPreflight: boundaryValueSchema,
    }));
    const session = await this.stored();
    if (!session?.selection || !session.plan || !session.oauthAttempt || session.oauthAttempt.usedAt === null) {
      throw new DeployError(409, 'session_conflict');
    }
    const now = this.wallTime();
    const recoverUntil = session.expiresAt + MAX_INSTALL_RECOVERY_RETENTION_MS;
    if (!Number.isSafeInteger(recoverUntil) || now >= session.expiresAt) {
      throw new DeployError(410, 'session_expired');
    }
    this.requireInstallAttempt(session, session.oauthAttempt.attemptId);
    const existing = await this.storedJournal(session);
    if (existing) {
      if (
        input.schemaVersion !== 1 || now < existing.createdAt || now >= existing.recoverUntil ||
        recoverUntil !== existing.recoverUntil || input.installationId !== existing.installationId ||
        input.bindingHash !== existing.bindingHash ||
        JSON.stringify(input.selection) !== JSON.stringify(existing.selection) ||
        JSON.stringify(input.plan) !== JSON.stringify(existing.plan) ||
        JSON.stringify(input.releasePin) !== JSON.stringify(existing.releasePin) ||
        JSON.stringify(input.target) !== JSON.stringify(existing.target) ||
        JSON.stringify(input.gatewayFreshPreflight) !== JSON.stringify(existing.actions[0]?.record)
      ) throw new DeployError(409, 'session_conflict');
      return internalJson({ journal: existing });
    }
    const canonicalInput = { ...input, now, recoverUntil };
    const journal = await createInstallJournal(
      canonicalInput,
      session.selection,
      session.plan,
      session.expiresAt,
      { attemptId: session.oauthAttempt.attemptId, approvedAt: session.oauthAttempt.usedAt },
    );
    await this.putJournal(session, journal);
    return internalJson({ journal }, 201);
  }

  private async readInstallJournal(): Promise<Response> {
    const session = await this.stored();
    if (!session) throw new DeployError(404, 'session_invalid');
    let journal = await this.storedJournal(session);
    if (!journal) throw new DeployError(404, 'session_invalid');
    const now = this.wallTime();
    if (
      now >= journal.recoverUntil ||
      (now >= session.expiresAt && !isPartialInstallJournal(journal) && !isCompleteInstallJournal(journal))
    ) {
      await this.clearStorage();
      throw new DeployError(404, 'session_invalid');
    }
    if (journal.lease && !isCompleteInstallJournal(journal) && now >= journal.lease.expiresAt) {
      journal = expireInstallJournalLease(journal, now);
      await this.putJournal(session, journal);
    }
    return internalJson({ journal });
  }

  private async createRecoveryPlan(request: Request): Promise<Response> {
    const input = await parsedJsonBody(request, v.strictObject({
      csrfHash: v.string(),
      releaseManifest: boundaryValueSchema,
      planExpiresAt: safeIntegerSchema,
      now: safeIntegerSchema,
    }));
    const session = await this.stored();
    if (!session?.selection || !session.plan) throw new DeployError(409, 'session_conflict');
    let journal = await this.storedJournal(session);
    if (!hasRecoverableJournal(session, journal)) throw new DeployError(409, 'session_conflict');
    const now = this.wallTime();
    verifyHash(input.csrfHash, session.csrfHash);
    if (
      now < journal.updatedAt || now >= journal.recoverUntil || input.planExpiresAt <= now ||
      input.planExpiresAt > now + OAUTH_ATTEMPT_TTL_MS || input.planExpiresAt > journal.recoverUntil
    ) throw new DeployError(410, 'session_expired');
    if (journal.lease) {
      if (now < journal.lease.expiresAt) throw new DeployError(409, 'session_conflict');
      journal = expireInstallJournalLease(journal, now);
      await this.putJournal(session, journal);
    }
    const plan = await buildStaticDeployPlan(
      journal.selection,
      parseReleaseManifest(input.releaseManifest),
      input.planExpiresAt,
    );
    const lastApproval = journal.approvalHistory[journal.approvalHistory.length - 1];
    if (
      !lastApproval || input.planExpiresAt <= lastApproval.planExpiresAt ||
      !isRecoveryEquivalentInstallPlan(journal.plan, plan)
    ) throw new DeployError(409, 'session_conflict');
    const next: StoredDeploySession = {
      ...session,
      status: 'failed',
      updatedAt: Math.min(now, session.expiresAt),
      selection: journal.selection,
      plan,
      oauthAttempt: null,
      result: null,
    };
    await this.put(next, journal, now);
    return internalJson({ session: publicSession(next) });
  }

  private async appendInstallApproval(request: Request): Promise<Response> {
    const input = await parsedJsonBody(request, v.strictObject(revisionAttemptNowSchema));
    const session = await this.stored();
    if (!session?.plan || !session.oauthAttempt || session.oauthAttempt.usedAt === null) {
      throw new DeployError(409, 'session_conflict');
    }
    const attemptId = this.requireInstallAttempt(session, input.attemptId);
    const journal = await this.storedJournal(session);
    if (!journal) throw new DeployError(409, 'session_conflict');
    const now = this.wallTime();
    const next = appendInstallJournalApproval(journal, session.plan, {
      expectedRevision: input.expectedRevision,
      attemptId,
      approvedAt: session.oauthAttempt.usedAt,
      now,
    });
    await this.putJournal(session, next);
    return internalJson({ journal: next });
  }

  private async acquireInstallLease(request: Request): Promise<Response> {
    const input = await parsedJsonBody(request, v.strictObject({
      ...revisionAttemptNowSchema,
      leaseExpiresAt: safeIntegerSchema,
    }));
    const session = await this.stored();
    if (!session) throw new DeployError(409, 'session_conflict');
    const attemptId = this.requireInstallAttempt(session, input.attemptId);
    const journal = await this.storedJournal(session);
    if (!journal) throw new DeployError(409, 'session_conflict');
    const now = this.wallTime();
    const approval = journal.approvalHistory.find((entry) => entry.attemptId === attemptId);
    if (!approval) throw new DeployError(409, 'session_conflict');
    const leaseExpiresAt = Math.min(
      now + MAX_INSTALL_LEASE_MS,
      approval.planExpiresAt,
      journal.recoverUntil,
    );
    const next = acquireInstallJournalLease(journal, {
      expectedRevision: input.expectedRevision,
      attemptId,
      now,
      leaseExpiresAt,
    });
    await this.putJournal(session, next);
    return internalJson({ journal: next });
  }

  private async releaseInstallLease(request: Request): Promise<Response> {
    const input = await parsedJsonBody(request, v.strictObject(revisionAttemptNowSchema));
    const session = await this.stored();
    if (!session) throw new DeployError(409, 'session_conflict');
    const attemptId = this.requireInstallAttempt(session, input.attemptId);
    const journal = await this.storedJournal(session);
    if (!journal) throw new DeployError(409, 'session_conflict');
    const now = this.wallTime();
    const next = releaseInstallJournalLease(journal, {
      expectedRevision: input.expectedRevision,
      attemptId,
      now,
    });
    await this.putJournal(session, next);
    return internalJson({ journal: next });
  }

  private async prepareInstallAction(request: Request): Promise<Response> {
    const input = await parsedJsonBody(request, v.strictObject({
      ...revisionAttemptNowSchema,
      action: installActionNameSchema,
      record: boundaryValueSchema,
    }));
    const session = await this.stored();
    if (!session) throw new DeployError(409, 'session_conflict');
    const attemptId = this.requireInstallAttempt(session, input.attemptId);
    const journal = await this.storedJournal(session);
    if (!journal) throw new DeployError(409, 'session_conflict');
    const now = this.wallTime();
    const next = await prepareInstallJournalAction(journal, serverTimeInstallJournalPrepare({
      expectedRevision: input.expectedRevision,
      attemptId,
      now: input.now,
      action: input.action,
      record: input.record,
    }, now));
    await this.putJournal(session, next);
    return internalJson({ journal: next });
  }

  private async armInstallAction(request: Request): Promise<Response> {
    return this.transitionInstallAction(request, 'arm');
  }

  private async submitInstallAction(request: Request): Promise<Response> {
    const input = await parsedJsonBody(request, v.strictObject({
      ...revisionAttemptNowSchema,
      action: installActionNameSchema,
      locator: boundaryValueSchema,
    }));
    const session = await this.stored();
    if (!session) throw new DeployError(409, 'session_conflict');
    const attemptId = this.requireInstallAttempt(session, input.attemptId);
    const journal = await this.storedJournal(session);
    if (!journal) throw new DeployError(409, 'session_conflict');
    const now = this.wallTime();
    const next = await submitInstallJournalAction(journal, {
      expectedRevision: input.expectedRevision,
      attemptId,
      now,
      action: input.action,
      locator: input.locator,
    });
    await this.putJournal(session, next);
    return internalJson({ journal: next });
  }

  private async verifyInstallAction(request: Request): Promise<Response> {
    return this.transitionInstallAction(request, 'verified');
  }

  private async appendBootstrapAttempt(request: Request): Promise<Response> {
    const input = await parsedJsonBody(request, v.strictObject({
      ...revisionAttemptNowSchema,
      attempt: boundaryValueSchema,
    }));
    const session = await this.stored();
    if (!session) throw new DeployError(409, 'session_conflict');
    const attemptId = this.requireInstallAttempt(session, input.attemptId);
    const journal = await this.storedJournal(session);
    if (!journal) throw new DeployError(409, 'session_conflict');
    const now = this.wallTime();
    const next = await appendCustomerBootstrapAttempt(journal, {
      expectedRevision: input.expectedRevision,
      attemptId,
      now,
      attempt: input.attempt,
    });
    await this.putJournal(session, next);
    return internalJson({ journal: next });
  }

  private async transitionInstallAction(request: Request, transition: 'arm' | 'verified'): Promise<Response> {
    const input = await parsedJsonBody(request, v.strictObject({
      ...revisionAttemptNowSchema,
      action: installActionNameSchema,
    }));
    const session = await this.stored();
    if (!session) throw new DeployError(409, 'session_conflict');
    const attemptId = this.requireInstallAttempt(session, input.attemptId);
    const journal = await this.storedJournal(session);
    if (!journal) throw new DeployError(409, 'session_conflict');
    const now = this.wallTime();
    const transitionInput = {
      expectedRevision: input.expectedRevision,
      attemptId,
      now,
      action: input.action,
    };
    const next = transition === 'arm'
      ? armInstallJournalAction(journal, transitionInput)
      : verifyInstallJournalAction(journal, transitionInput);
    await this.putJournal(session, next);
    return internalJson({ journal: next });
  }

  private requireRetainedInstallAuthority(
    session: StoredDeploySession | null,
    journal: InstallJournal | null,
    now: number,
  ): RetainedInstallAuthority {
    if (!session || !journal || session.status !== 'succeeded' ||
      session.result?.code !== 'install_complete' || !isCompleteInstallJournal(journal) ||
      session.result.installationId !== journal.installationId) {
      throw new DeployError(409, 'session_conflict');
    }
    if (now >= journal.recoverUntil) {
      throw new DeployError(410, 'session_expired');
    }
    return { session, journal };
  }

  private requireExactReleasePin<Input>(input: Input, journal: InstallJournal): void {
    const candidate = v.safeParse(v.strictObject({
      verification: v.string(),
      keyId: v.string(),
      release: v.string(),
      artifactSha256: v.string(),
    }), input);
    if (!candidate.success) throw new DeployError(400, 'bad_request');
    const pin = candidate.output;
    if (pin.verification !== journal.releasePin.verification || pin.keyId !== journal.releasePin.keyId ||
      pin.release !== journal.releasePin.release || pin.artifactSha256 !== journal.releasePin.artifactSha256) {
      throw new DeployError(409, 'session_conflict');
    }
  }

  private async previewUninstallPlan(request: Request): Promise<Response> {
    const input = await parsedJsonBody(request, v.strictObject({
      csrfHash: v.string(),
      releasePin: boundaryValueSchema,
      planExpiresAt: safeIntegerSchema,
      now: safeIntegerSchema,
    }));
    const session = await this.stored();
    const installJournal = await this.storedJournal(session);
    const now = this.wallTime();
    const authority = this.requireRetainedInstallAuthority(session, installJournal, now);
    verifyHash(input.csrfHash, authority.session.csrfHash);
    this.requireExactReleasePin(input.releasePin, authority.journal);
    if (input.planExpiresAt <= now || input.planExpiresAt > now + OAUTH_ATTEMPT_TTL_MS ||
      input.planExpiresAt > authority.journal.recoverUntil) throw new DeployError(410, 'session_expired');

    const existing = await this.storedUninstallControl(authority.session, authority.journal);
    const uninstallJournal = await this.storedUninstallJournal(authority.session, authority.journal, existing);
    if (existing?.status === 'removed' || (uninstallJournal?.lease && now < uninstallJournal.lease.expiresAt) ||
      ((existing?.status === 'authorizing' || existing?.status === 'uninstalling') &&
        existing.oauthAttempt && now < existing.oauthAttempt.expiresAt)) {
      throw new DeployError(409, 'session_conflict');
    }
    const plan = await buildStaticUninstallPlan(authority.journal, now, input.planExpiresAt);
    if (uninstallJournal && !await isRecoveryEquivalentUninstallPlan(uninstallJournal.uninstallPlan, plan)) {
      throw new DeployError(409, 'session_conflict');
    }
    const next: StoredUninstallControl = {
      schemaVersion: 1,
      status: 'planned',
      installationId: authority.journal.installationId,
      installBindingHash: authority.journal.bindingHash,
      createdAt: existing?.createdAt ?? now,
      updatedAt: now,
      recoverUntil: authority.journal.recoverUntil,
      plan,
      oauthAttempt: null,
      result: null,
    };
    await this.putUninstallControl(authority.session, authority.journal, next, uninstallJournal);
    return internalJson({ uninstall: publicUninstallSession(next) });
  }

  private async authorizeUninstall(request: Request): Promise<Response> {
    const input = await parsedJsonBody(request, v.strictObject({
      ...oauthAuthorizeBodyEntries,
      releasePin: boundaryValueSchema,
      approvedPlanId: v.string(),
      approvedPlanHash: v.string(),
    }));
    const session = await this.stored();
    const installJournal = await this.storedJournal(session);
    const now = this.wallTime();
    const authority = this.requireRetainedInstallAuthority(session, installJournal, now);
    const control = await this.storedUninstallControl(authority.session, authority.journal);
    const uninstallJournal = await this.storedUninstallJournal(authority.session, authority.journal, control);
    if (!control || control.status !== 'planned') throw new DeployError(409, 'session_conflict');
    verifyHash(input.csrfHash, authority.session.csrfHash);
    this.requireExactReleasePin(input.releasePin, authority.journal);
    if (input.approvedPlanId !== control.plan.planId || input.approvedPlanHash !== control.plan.planHash ||
      now >= control.plan.expiresAt ||
      input.attemptExpiresAt <= now || input.attemptExpiresAt > control.plan.expiresAt ||
      input.attemptExpiresAt > control.recoverUntil ||
      uninstallJournal?.approvalHistory.some((approval) => approval.attemptId === input.attemptId)) {
      throw new DeployError(409, 'session_conflict');
    }
    const next: StoredUninstallControl = {
      ...control,
      status: 'authorizing',
      updatedAt: now,
      oauthAttempt: {
        purpose: 'uninstall',
        attemptId: input.attemptId,
        stateHash: input.stateHash,
        verifierHash: input.verifierHash,
        expiresAt: input.attemptExpiresAt,
        usedAt: null,
      },
      result: null,
    };
    await this.putUninstallControl(authority.session, authority.journal, next, uninstallJournal);
    return internalJson({ accepted: true });
  }

  private async consumeUninstall(request: Request): Promise<Response> {
    const input = await parsedJsonBody(request, v.strictObject({
      purpose: v.literal('uninstall'),
      ...oauthConsumeBodySchema.entries,
    }));
    const session = await this.stored();
    const installJournal = await this.storedJournal(session);
    const now = this.wallTime();
    const authority = this.requireRetainedInstallAuthority(session, installJournal, now);
    const control = await this.storedUninstallControl(authority.session, authority.journal);
    const uninstallJournal = await this.storedUninstallJournal(authority.session, authority.journal, control);
    const attempt = control?.oauthAttempt;
    if (!control || control.status !== 'authorizing' || !attempt || attempt.purpose !== 'uninstall' ||
      input.purpose !== 'uninstall' || attempt.usedAt !== null || now >= attempt.expiresAt ||
      now >= control.plan.expiresAt || input.attemptId !== attempt.attemptId ||
      !constantHashes(input.stateHash, attempt.stateHash, input.verifierHash, attempt.verifierHash)) {
      throw new DeployError(400, 'oauth_state_invalid');
    }
    const next: StoredUninstallControl = {
      ...control,
      status: 'uninstalling',
      updatedAt: now,
      oauthAttempt: { ...attempt, usedAt: now },
    };
    await this.putUninstallControl(authority.session, authority.journal, next, uninstallJournal);
    return internalJson({
      approvedAt: now,
      installationId: control.installationId,
      plan: control.plan,
      recoverUntil: control.recoverUntil,
    });
  }

  private async prepareReturningUninstall(request: Request): Promise<Response> {
    const input = await parsedJsonBody(request, v.strictObject({
      csrfHash: v.string(),
      action: returningActionAuthoritySchema,
      planExpiresAt: safeIntegerSchema,
      now: safeIntegerSchema,
    }));
    const session = await this.stored();
    const now = this.wallTime();
    const gateway = session?.result?.code === 'existing_gateway_detected'
      ? parseExistingAnkkaGatewaySummary(session.result.existingGateway)
      : null;
    const discovery = await this.storedDiscovery();
    const target = selectedDiscoveredTarget(discovery);
    const existing = await this.storedReturningUninstall(session);
    const existingJournal = await this.storedReturningUninstallJournal(session, existing);
    const recoveryActive = Boolean(existingJournal && now < existingJournal.recoverUntil);
    if (!session || session.status !== 'failed' || !gateway || !discovery?.result || !target ||
      (now >= session.expiresAt && !recoveryActive)) throw new DeployError(409, 'session_conflict');
    verifyHash(input.csrfHash, session.csrfHash);
    const action = input.action;
    if (action.actorEmail !== discovery.result.actor.email || action.accountId !== target.account.id ||
      action.workerName !== gateway.workerName || action.managementOrigin !== `https://${gateway.managementHostname}` ||
      action.expiresAt !== input.planExpiresAt || input.planExpiresAt <= now ||
      input.planExpiresAt > (existingJournal?.recoverUntil ?? existing?.recoverUntil ?? session.expiresAt)) {
      throw new DeployError(409, 'session_conflict');
    }
    const plan = await buildReturningUninstallPlan(gateway, now, input.planExpiresAt);
    if (existing && (existing.status === 'removed' || existing.action.actionId === action.actionId ||
      (existing.status !== 'failed' && existing.status !== 'removing') ||
      (existing.status === 'removing' && now < existing.plan.expiresAt))) {
      throw new DeployError(409, 'session_conflict');
    }
    const recoverUntil = existingJournal?.recoverUntil ?? existing?.recoverUntil ??
      now + MAX_RETURNING_UNINSTALL_RECOVERY_RETENTION_MS;
    if (!Number.isSafeInteger(recoverUntil) || recoverUntil <= input.planExpiresAt) {
      throw new DeployError(409, 'session_conflict');
    }
    const next: StoredReturningUninstall = {
      schemaVersion: 1,
      status: 'planned',
      createdAt: existing?.createdAt ?? now,
      updatedAt: now,
      recoverUntil,
      plan,
      action,
      oauthAttempt: null,
      result: null,
    };
    await this.putReturningUninstall(session, next);
    return internalJson({ returningUninstall: publicReturningUninstall(next) });
  }

  private async authorizeReturningUninstall(request: Request): Promise<Response> {
    const input = await parsedJsonBody(request, reviewedPlanAuthorizationSchema);
    const session = await this.stored();
    const control = await this.storedReturningUninstall(session);
    const now = this.wallTime();
    if (!session || !control || !['planned', 'failed'].includes(control.status) ||
      now >= control.plan.expiresAt) {
      throw new DeployError(409, 'session_conflict');
    }
    verifyHash(input.csrfHash, session.csrfHash);
    if (input.approvedPlanId !== control.plan.planId || input.approvedPlanHash !== control.plan.planHash ||
      input.attemptExpiresAt <= now || input.attemptExpiresAt > control.plan.expiresAt) {
      throw new DeployError(409, 'session_conflict');
    }
    const next: StoredReturningUninstall = {
      ...control,
      status: 'authorizing',
      updatedAt: now,
      oauthAttempt: {
        purpose: 'customer_action',
        attemptId: input.attemptId,
        stateHash: input.stateHash,
        verifierHash: input.verifierHash,
        expiresAt: input.attemptExpiresAt,
        usedAt: null,
      },
      result: null,
    };
    await this.putReturningUninstall(session, next);
    return internalJson({ accepted: true });
  }

  private async consumeReturningUninstall(request: Request): Promise<Response> {
    const input = await parsedJsonBody(request, v.strictObject({
      ...oauthConsumeBodySchema.entries,
      actionKeyHash: oauthHashSchema,
    }));
    const session = await this.stored();
    const control = await this.storedReturningUninstall(session);
    const attempt = control?.oauthAttempt;
    const now = this.wallTime();
    if (!session || !control || control.status !== 'authorizing' || !attempt ||
      attempt.purpose !== 'customer_action' || attempt.usedAt !== null ||
      now >= attempt.expiresAt || now >= control.plan.expiresAt || input.attemptId !== attempt.attemptId ||
      !constantHashes(input.stateHash, attempt.stateHash, input.verifierHash, attempt.verifierHash) ||
      !constantTimeEqual(input.actionKeyHash, control.action.actionKeyHash)) {
      throw new DeployError(400, 'oauth_state_invalid');
    }
    const next: StoredReturningUninstall = {
      ...control,
      status: 'removing',
      updatedAt: now,
      oauthAttempt: { ...attempt, usedAt: now },
    };
    await this.putReturningUninstall(session, next);
    return internalJson({
      approvedAt: now,
      recoverUntil: control.recoverUntil,
      plan: control.plan,
      action: control.action,
      actor: (await this.storedDiscovery())?.result?.actor ?? null,
      discoveredTarget: selectedDiscoveredTarget(await this.storedDiscovery()),
    });
  }

  private async returningUninstallRecoveryAuthority(): Promise<{
    readonly session: StoredDeploySession;
    readonly control: StoredReturningUninstall;
    readonly journal: ReturningUninstallJournal;
    readonly discovery: StoredCloudflareDiscovery;
    readonly target: NonNullable<ReturnType<typeof selectedDiscoveredTarget>>;
  }> {
    const session = await this.stored();
    const control = await this.storedReturningUninstall(session);
    const journal = await this.storedReturningUninstallJournal(session, control);
    const discovery = await this.storedDiscovery();
    const target = selectedDiscoveredTarget(discovery);
    const imported = journal?.actions[0];
    const gatewayRemoval = journal?.actions.find((action) => action.name === 'customer_gateway_remove');
    if (!session || !control || !journal || !discovery?.result || !target || control.status === 'removed' ||
      journal.recoverUntil !== control.recoverUntil || imported?.name !== 'authority_import' ||
      imported.phase !== 'verified' || gatewayRemoval?.phase !== 'verified' ||
      journal.authority.actorEmail !== discovery.result.actor.email ||
      journal.authority.runtime.accountId !== target.account.id ||
      journal.authority.runtime.zoneId !== target.zone.id ||
      journal.authority.runtime.zoneName !== target.zone.name ||
      journal.authority.installationId !== control.plan.gateway.installationId) {
      throw new DeployError(409, 'session_conflict');
    }
    return { session, control, journal, discovery, target };
  }

  private async prepareReturningUninstallRecovery(request: Request): Promise<Response> {
    const input = await parsedJsonBody(request, v.strictObject({
      csrfHash: v.string(),
      planExpiresAt: safeIntegerSchema,
      now: safeIntegerSchema,
    }));
    const authority = await this.returningUninstallRecoveryAuthority();
    const now = this.wallTime();
    verifyHash(input.csrfHash, authority.session.csrfHash);
    const priorAttempt = authority.control.oauthAttempt;
    const retryable = authority.control.status === 'failed' || (
      authority.control.status === 'removing' && Boolean(
        priorAttempt && priorAttempt.usedAt !== null && priorAttempt.expiresAt <= now,
      )
    );
    if (!retryable || now < authority.journal.updatedAt || now >= authority.journal.recoverUntil ||
      input.planExpiresAt <= now || input.planExpiresAt > now + OAUTH_ATTEMPT_TTL_MS ||
      input.planExpiresAt > authority.journal.recoverUntil) {
      throw new DeployError(409, 'session_conflict');
    }
    let journal = authority.journal;
    if (journal.lease) {
      if (journal.lease.expiresAt > now) throw new DeployError(409, 'session_conflict');
      journal = await releaseReturningUninstallLease(journal, {
        expectedRevision: journal.revision,
        attemptId: journal.lease.attemptId,
        now,
      });
      await this.putReturningUninstallJournal(authority.session, authority.control, journal);
    }
    const priorApproval = journal.approvalHistory.at(-1);
    if (!priorApproval || input.planExpiresAt <= priorApproval.planExpiresAt) {
      throw new DeployError(409, 'session_conflict');
    }
    const plan = await buildReturningUninstallPlan(authority.control.plan.gateway, now, input.planExpiresAt);
    if (plan.planId !== journal.plan.planId || plan.planHash !== journal.plan.planHash) {
      throw new DeployError(409, 'session_conflict');
    }
    const next: StoredReturningUninstall = {
      ...authority.control,
      status: 'planned',
      updatedAt: now,
      plan,
      // The customer action endpoint is already durably verified as removed.
      // Retain only its secret-free binding while matching the newly reviewed
      // hosted recovery window required by the stored-state invariant.
      action: { ...authority.control.action, expiresAt: plan.expiresAt },
      oauthAttempt: null,
      result: null,
    };
    await this.putReturningUninstall(authority.session, next);
    return internalJson({ returningUninstall: publicReturningUninstall(next, true) });
  }

  private async authorizeReturningUninstallRecovery(request: Request): Promise<Response> {
    const input = await parsedJsonBody(request, reviewedPlanAuthorizationSchema);
    const authority = await this.returningUninstallRecoveryAuthority();
    const now = this.wallTime();
    if (authority.control.status !== 'planned' || now >= authority.control.plan.expiresAt) {
      throw new DeployError(409, 'session_conflict');
    }
    verifyHash(input.csrfHash, authority.session.csrfHash);
    if (input.approvedPlanId !== authority.control.plan.planId ||
      input.approvedPlanHash !== authority.control.plan.planHash ||
      input.attemptExpiresAt <= now || input.attemptExpiresAt > authority.control.plan.expiresAt ||
      input.attemptExpiresAt > authority.journal.recoverUntil) {
      throw new DeployError(409, 'session_conflict');
    }
    const next: StoredReturningUninstall = {
      ...authority.control,
      status: 'authorizing',
      updatedAt: now,
      oauthAttempt: {
        purpose: 'hosted_recovery',
        attemptId: input.attemptId,
        stateHash: input.stateHash,
        verifierHash: input.verifierHash,
        expiresAt: input.attemptExpiresAt,
        usedAt: null,
      },
      result: null,
    };
    await this.putReturningUninstall(authority.session, next);
    return internalJson({
      accepted: true,
      actorEmail: authority.discovery.result?.actor.email,
      accountId: authority.target.account.id,
      zoneId: authority.target.zone.id,
    });
  }

  private async consumeReturningUninstallRecovery(request: Request): Promise<Response> {
    const input = await parsedJsonBody(request, oauthConsumeBodySchema);
    const authority = await this.returningUninstallRecoveryAuthority();
    const attempt = authority.control.oauthAttempt;
    const now = this.wallTime();
    if (authority.control.status !== 'authorizing' || !attempt || attempt.purpose !== 'hosted_recovery' ||
      attempt.usedAt !== null || now >= attempt.expiresAt || now >= authority.control.plan.expiresAt ||
      now >= authority.journal.recoverUntil || input.attemptId !== attempt.attemptId ||
      !constantHashes(input.stateHash, attempt.stateHash, input.verifierHash, attempt.verifierHash)) {
      throw new DeployError(400, 'oauth_state_invalid');
    }
    const next: StoredReturningUninstall = {
      ...authority.control,
      status: 'removing',
      updatedAt: now,
      oauthAttempt: { ...attempt, usedAt: now },
    };
    await this.putReturningUninstall(authority.session, next);
    return internalJson({
      approvedAt: now,
      recoverUntil: authority.control.recoverUntil,
      plan: authority.control.plan,
      actor: authority.discovery.result?.actor ?? null,
      discoveredTarget: authority.target,
    });
  }

  private async completeReturningUninstall(request: Request): Promise<Response> {
    const input = await parsedJsonBody(request, returningCompletionBodySchema);
    const session = await this.stored();
    const control = await this.storedReturningUninstall(session);
    const now = this.wallTime();
    const attempt = control?.oauthAttempt;
    const successfulInput = v.safeParse(successfulReturningCompletionSchema, input);
    const success = successfulInput.success;
    const journal = await this.storedReturningUninstallJournal(session, control);
    const final = journal?.actions.at(-1);
    if (!session || !control || control.status !== 'removing' || !attempt || attempt.usedAt === null ||
      input.attemptId !== attempt.attemptId || (input.code !== 'returning_uninstall_complete' &&
        !isDeployErrorCode(input.code)) ||
      (success && (input.installationId !== control.plan.gateway.installationId ||
        (input.grantRevocation !== 'confirmed' && input.grantRevocation !== 'unconfirmed') ||
        !journal || journal.lease !== null || final?.name !== 'final_convergence' ||
        final.phase !== 'verified' || !v.is(v.object({ status: v.literal('removed') }), final.locator))) ||
      (!success && (input.installationId !== null || input.grantRevocation !== null))) {
      throw new DeployError(409, 'session_conflict');
    }
    let result: NonNullable<StoredReturningUninstall['result']>;
    if (successfulInput.success) {
      result = {
        code: 'returning_uninstall_complete',
        completedAt: now,
        installationId: successfulInput.output.installationId,
        grantRevocation: successfulInput.output.grantRevocation,
      };
    } else {
      const failedInput = v.parse(failedReturningCompletionSchema, input);
      const code = failureCode(failedInput.code);
      result = failedInput.reason === null
        ? { code, completedAt: now }
        : { code, completedAt: now, reason: failedInput.reason };
    }
    const next: StoredReturningUninstall = {
      ...control,
      status: success ? 'removed' : 'failed',
      updatedAt: now,
      result,
    };
    await this.putReturningUninstall(session, next);
    return internalJson({ returningUninstall: publicReturningUninstall(next) });
  }

  private async activeReturningUninstallOperation<Input>(attemptId: Input): Promise<{
    readonly now: number;
    readonly session: StoredDeploySession;
    readonly control: StoredReturningUninstall;
    readonly journal: ReturningUninstallJournal | null;
    readonly attemptId: string;
  }> {
    const attemptCandidate = v.safeParse(oauthAttemptIdSchema, attemptId);
    const session = await this.stored();
    const control = await this.storedReturningUninstall(session);
    const now = this.wallTime();
    const attempt = control?.oauthAttempt;
    if (!session || !control || control.status !== 'removing' || !attempt || attempt.usedAt === null ||
      !attemptCandidate.success || attempt.attemptId !== attemptCandidate.output || now >= control.plan.expiresAt) {
      throw new DeployError(409, 'session_conflict');
    }
    const journal = await this.storedReturningUninstallJournal(session, control);
    return { now, session, control, journal, attemptId: attemptCandidate.output };
  }

  private async initializeReturningUninstallJournal(request: Request): Promise<Response> {
    const input = await parsedJsonBody(request, v.strictObject({
      now: safeIntegerSchema,
      plan: boundaryValueSchema,
      authority: boundaryValueSchema,
      attemptId: oauthAttemptIdSchema,
      approvedAt: safeIntegerSchema,
      accountId: v.string(),
      zoneId: v.string(),
      recoverUntil: safeIntegerSchema,
    }));
    const context = await this.activeReturningUninstallOperation(input.attemptId);
    const authority = await requireReturningUninstallImportedAuthority(input.authority);
    if (context.journal || context.control.oauthAttempt?.purpose !== 'customer_action' ||
      input.approvedAt !== context.control.oauthAttempt.usedAt ||
      JSON.stringify(input.plan) !== JSON.stringify(context.control.plan) ||
      input.recoverUntil !== context.control.recoverUntil || input.accountId !== context.control.action.accountId ||
      authority.actionId !== context.control.action.actionId ||
      authority.actorEmail !== context.control.action.actorEmail) throw new DeployError(409, 'session_conflict');
    const journal = await createReturningUninstallJournal({
      now: context.now,
      plan: context.control.plan,
      authority,
      attemptId: context.attemptId,
      approvedAt: input.approvedAt,
      accountId: input.accountId,
      zoneId: input.zoneId,
      recoverUntil: context.control.recoverUntil,
    });
    await this.putReturningUninstallJournal(context.session, context.control, journal);
    return internalJson({ journal }, 201);
  }

  private async readReturningUninstallJournal(): Promise<Response> {
    const session = await this.stored();
    const control = await this.storedReturningUninstall(session);
    const journal = await this.storedReturningUninstallJournal(session, control);
    if (!journal) throw new DeployError(404, 'session_invalid');
    return internalJson({ journal });
  }

  private async appendReturningUninstallJournalApproval(request: Request): Promise<Response> {
    const input = await parsedJsonBody(request, v.strictObject({
      ...revisionAttemptNowSchema,
      approvedAt: safeIntegerSchema,
      plan: boundaryValueSchema,
      authority: boundaryValueSchema,
    }));
    const context = await this.activeReturningUninstallOperation(input.attemptId);
    const authority = await requireReturningUninstallImportedAuthority(input.authority);
    if (!context.journal || input.approvedAt !== context.control.oauthAttempt?.usedAt ||
      context.control.oauthAttempt?.purpose !== 'customer_action' ||
      JSON.stringify(input.plan) !== JSON.stringify(context.control.plan) ||
      authority.actionId !== context.control.action.actionId ||
      authority.actorEmail !== context.control.action.actorEmail) {
      throw new DeployError(409, 'session_conflict');
    }
    const journal = await appendReturningUninstallApproval(context.journal, {
      expectedRevision: input.expectedRevision,
      attemptId: context.attemptId,
      approvedAt: input.approvedAt,
      now: context.now,
      plan: context.control.plan,
      authority,
    });
    await this.putReturningUninstallJournal(context.session, context.control, journal);
    return internalJson({ journal });
  }

  private async appendReturningUninstallHostedRecoveryJournalApproval(request: Request): Promise<Response> {
    const input = await parsedJsonBody(request, v.strictObject({
      ...revisionAttemptNowSchema,
      approvedAt: safeIntegerSchema,
      plan: boundaryValueSchema,
      actorEmail: v.string(),
      accountId: v.string(),
      zoneId: v.string(),
    }));
    const context = await this.activeReturningUninstallOperation(input.attemptId);
    const target = selectedDiscoveredTarget(await this.storedDiscovery());
    if (!context.journal || context.control.oauthAttempt?.purpose !== 'hosted_recovery' || !target ||
      input.approvedAt !== context.control.oauthAttempt.usedAt ||
      JSON.stringify(input.plan) !== JSON.stringify(context.control.plan) ||
      input.actorEmail !== context.journal.authority.actorEmail ||
      input.accountId !== target.account.id || input.zoneId !== target.zone.id) {
      throw new DeployError(409, 'session_conflict');
    }
    const journal = await appendReturningUninstallHostedRecoveryApproval(context.journal, {
      expectedRevision: input.expectedRevision,
      attemptId: context.attemptId,
      approvedAt: input.approvedAt,
      now: context.now,
      plan: context.control.plan,
      actorEmail: input.actorEmail,
      accountId: input.accountId,
      zoneId: input.zoneId,
    });
    await this.putReturningUninstallJournal(context.session, context.control, journal);
    return internalJson({ journal });
  }

  private async acquireReturningUninstallJournalLease(request: Request): Promise<Response> {
    const input = await parsedJsonBody(request, v.strictObject({
      ...revisionAttemptNowSchema,
      expiresAt: safeIntegerSchema,
    }));
    const context = await this.activeReturningUninstallOperation(input.attemptId);
    if (!context.journal) throw new DeployError(409, 'session_conflict');
    const journal = await acquireReturningUninstallLease(context.journal, {
      expectedRevision: input.expectedRevision,
      attemptId: context.attemptId,
      now: context.now,
      expiresAt: Math.min(input.expiresAt, context.control.plan.expiresAt),
    });
    await this.putReturningUninstallJournal(context.session, context.control, journal);
    return internalJson({ journal });
  }

  private async releaseReturningUninstallJournalLease(request: Request): Promise<Response> {
    const input = await parsedJsonBody(request, v.strictObject(revisionAttemptNowSchema));
    const context = await this.activeReturningUninstallOperation(input.attemptId);
    if (!context.journal) throw new DeployError(409, 'session_conflict');
    const journal = await releaseReturningUninstallLease(context.journal, {
      expectedRevision: input.expectedRevision,
      attemptId: context.attemptId,
      now: context.now,
    });
    await this.putReturningUninstallJournal(context.session, context.control, journal);
    return internalJson({ journal });
  }

  private async prepareReturningUninstallJournalAction(request: Request): Promise<Response> {
    const input = await parsedJsonBody(request, v.strictObject({
      ...revisionAttemptNowSchema,
      name: returningUninstallActionNameSchema,
      record: boundaryValueSchema,
    }));
    const context = await this.activeReturningUninstallOperation(input.attemptId);
    if (!context.journal) throw new DeployError(409, 'session_conflict');
    const journal = await prepareReturningUninstallAction(context.journal, {
      expectedRevision: input.expectedRevision,
      attemptId: context.attemptId,
      now: context.now,
      name: input.name,
      record: input.record,
    });
    await this.putReturningUninstallJournal(context.session, context.control, journal);
    return internalJson({ journal });
  }

  private async transitionReturningUninstallJournalAction(
    request: Request,
    phase: 'arm' | 'submit' | 'verify',
  ): Promise<Response> {
    const input = phase === 'arm'
      ? await parsedJsonBody(request, v.strictObject({
          ...revisionAttemptNowSchema,
          name: returningUninstallActionNameSchema,
        }))
      : await parsedJsonBody(request, v.strictObject({
          ...revisionAttemptNowSchema,
          name: returningUninstallActionNameSchema,
          locator: boundaryValueSchema,
        }));
    const context = await this.activeReturningUninstallOperation(input.attemptId);
    if (!context.journal) throw new DeployError(409, 'session_conflict');
    const base = {
      expectedRevision: input.expectedRevision,
      attemptId: context.attemptId,
      now: context.now,
      name: input.name,
    };
    let journal: ReturningUninstallJournal;
    if (phase === 'arm') {
      journal = await armReturningUninstallAction(context.journal, base);
    } else {
      const locator = v.parse(boundaryValueSchema, 'locator' in input ? input.locator : null);
      journal = phase === 'submit'
        ? await submitReturningUninstallAction(context.journal, { ...base, locator })
        : await verifyReturningUninstallAction(context.journal, { ...base, locator });
    }
    await this.putReturningUninstallJournal(context.session, context.control, journal);
    return internalJson({ journal });
  }

  private armReturningUninstallJournalAction(request: Request): Promise<Response> {
    return this.transitionReturningUninstallJournalAction(request, 'arm');
  }

  private submitReturningUninstallJournalAction(request: Request): Promise<Response> {
    return this.transitionReturningUninstallJournalAction(request, 'submit');
  }

  private verifyReturningUninstallJournalAction(request: Request): Promise<Response> {
    return this.transitionReturningUninstallJournalAction(request, 'verify');
  }

  private requireUninstallAttempt<Input>(control: StoredUninstallControl, attemptId: Input): string {
    const candidate = v.safeParse(oauthAttemptIdSchema, attemptId);
    if (!candidate.success || control.status !== 'uninstalling' ||
      !control.oauthAttempt || control.oauthAttempt.purpose !== 'uninstall' ||
      control.oauthAttempt.usedAt === null || control.oauthAttempt.attemptId !== candidate.output) {
      throw new DeployError(409, 'session_conflict');
    }
    return candidate.output;
  }

  private async activeUninstallOperation<Input>(attemptId: Input): Promise<{
    readonly now: number;
    readonly session: StoredDeploySession;
    readonly installJournal: InstallJournal;
    readonly control: StoredUninstallControl;
    readonly journal: UninstallJournal | null;
    readonly attemptId: string;
  }> {
    const session = await this.stored();
    const installJournal = await this.storedJournal(session);
    const now = this.wallTime();
    const authority = this.requireRetainedInstallAuthority(session, installJournal, now);
    const control = await this.storedUninstallControl(authority.session, authority.journal);
    if (!control) throw new DeployError(409, 'session_conflict');
    const activeAttemptId = this.requireUninstallAttempt(control, attemptId);
    const journal = await this.storedUninstallJournal(authority.session, authority.journal, control);
    return {
      now,
      session: authority.session,
      installJournal: authority.journal,
      control,
      journal,
      attemptId: activeAttemptId,
    };
  }

  private async initializeUninstallJournal(request: Request): Promise<Response> {
    const input = await parsedJsonBody(request, v.strictObject({
      initialization: v.strictObject({
        schemaVersion: v.literal(1),
        now: safeIntegerSchema,
        recoverUntil: safeIntegerSchema,
        installJournal: boundaryValueSchema,
        uninstallPlan: boundaryValueSchema,
        uninstallCycleId: v.string(),
        bindingHash: v.string(),
        freshPreflight: boundaryValueSchema,
      }),
      approval: v.strictObject({
        attemptId: oauthAttemptIdSchema,
        approvedAt: safeIntegerSchema,
        authorizedTarget: boundaryValueSchema,
      }),
    }));
    const approval = input.approval;
    const context = await this.activeUninstallOperation(approval.attemptId);
    if (context.journal) throw new DeployError(409, 'session_conflict');
    const initialization = input.initialization;
    const approvedAt = context.control.oauthAttempt?.usedAt;
    if (approvedAt === null || approvedAt === undefined || approval.approvedAt !== approvedAt) {
      throw new DeployError(409, 'session_conflict');
    }
    const journal = await createUninstallJournal({
      ...initialization,
      now: context.now,
      recoverUntil: context.control.recoverUntil,
      installJournal: context.installJournal,
      uninstallPlan: context.control.plan,
    }, {
      attemptId: context.attemptId,
      approvedAt,
      authorizedTarget: approval.authorizedTarget,
    });
    await this.putUninstallJournal(
      context.session,
      context.installJournal,
      context.control,
      journal,
    );
    return internalJson({ journal }, 201);
  }

  private async readUninstallJournal(): Promise<Response> {
    const session = await this.stored();
    const installJournal = await this.storedJournal(session);
    const now = this.wallTime();
    const authority = this.requireRetainedInstallAuthority(session, installJournal, now);
    const control = await this.storedUninstallControl(authority.session, authority.journal);
    let journal = await this.storedUninstallJournal(authority.session, authority.journal, control);
    if (!control || !journal || now >= journal.recoverUntil) throw new DeployError(404, 'session_invalid');
    if (journal.lease && now >= journal.lease.expiresAt) {
      journal = expireUninstallJournalLease(journal, now);
      await this.putUninstallJournal(authority.session, authority.journal, control, journal);
    }
    return internalJson({ journal });
  }

  private async appendUninstallApproval(request: Request): Promise<Response> {
    const input = await parsedJsonBody(request, v.strictObject({
      ...revisionAttemptNowSchema,
      approvedAt: safeIntegerSchema,
      authorizedTarget: boundaryValueSchema,
      candidatePlan: boundaryValueSchema,
    }));
    const context = await this.activeUninstallOperation(input.attemptId);
    const approvedAt = context.control.oauthAttempt?.usedAt;
    if (!context.journal || approvedAt === null || approvedAt === undefined || input.approvedAt !== approvedAt ||
      JSON.stringify(input.candidatePlan) !== JSON.stringify(context.control.plan)) {
      throw new DeployError(409, 'session_conflict');
    }
    const journal = await appendUninstallJournalApproval(context.journal, context.control.plan, {
      expectedRevision: input.expectedRevision,
      attemptId: context.attemptId,
      approvedAt,
      authorizedTarget: input.authorizedTarget,
      now: context.now,
    });
    await this.putUninstallJournal(context.session, context.installJournal, context.control, journal);
    return internalJson({ journal });
  }

  private async acquireUninstallLease(request: Request): Promise<Response> {
    const input = await parsedJsonBody(request, v.strictObject({
      ...revisionAttemptNowSchema,
      leaseExpiresAt: safeIntegerSchema,
    }));
    const context = await this.activeUninstallOperation(input.attemptId);
    if (!context.journal) throw new DeployError(409, 'session_conflict');
    const leaseExpiresAt = Math.min(
      context.now + MAX_UNINSTALL_LEASE_MS,
      context.control.plan.expiresAt,
      context.control.recoverUntil,
    );
    const journal = acquireUninstallJournalLease(context.journal, {
      expectedRevision: input.expectedRevision,
      attemptId: context.attemptId,
      now: context.now,
      leaseExpiresAt,
    });
    await this.putUninstallJournal(context.session, context.installJournal, context.control, journal);
    return internalJson({ journal });
  }

  private async releaseUninstallLease(request: Request): Promise<Response> {
    return this.casUninstallJournal(request, (journal, input, context) =>
      releaseUninstallJournalLease(journal, { ...input, now: context.now }));
  }

  private async refreshUninstallPreflight(request: Request): Promise<Response> {
    const input = await parsedJsonBody(request, v.strictObject({
      ...revisionAttemptNowSchema,
      preflight: boundaryValueSchema,
    }));
    const context = await this.activeUninstallOperation(input.attemptId);
    if (!context.journal) throw new DeployError(409, 'session_conflict');
    const journal = await refreshUninstallJournalPreflight(context.journal, input.preflight, {
      expectedRevision: input.expectedRevision,
      attemptId: context.attemptId,
      now: context.now,
    });
    await this.putUninstallJournal(context.session, context.installJournal, context.control, journal);
    return internalJson({ journal });
  }

  private async discardUninstallPreflight(request: Request): Promise<Response> {
    const input = await parsedJsonBody(request, v.strictObject(revisionAttemptNowSchema));
    const context = await this.activeUninstallOperation(input.attemptId);
    if (!context.journal) throw new DeployError(409, 'session_conflict');
    discardPreflightOnlyUninstallJournal(context.journal, {
      expectedRevision: input.expectedRevision,
      attemptId: context.attemptId,
      now: context.now,
    });
    await this.state.storage.delete(UNINSTALL_JOURNAL_STORAGE_KEY);
    await this.scheduleStorage(context.session, context.installJournal, context.now);
    return internalJson({ discarded: true });
  }

  private async appendUninstallManagementPreflight(request: Request): Promise<Response> {
    const input = await parsedJsonBody(request, v.strictObject({
      ...revisionAttemptNowSchema,
      preflight: boundaryValueSchema,
    }));
    const context = await this.activeUninstallOperation(input.attemptId);
    if (!context.journal) throw new DeployError(409, 'session_conflict');
    const journal = await appendUninstallManagementPreflight(context.journal, {
      expectedRevision: input.expectedRevision,
      attemptId: context.attemptId,
      now: context.now,
      preflight: input.preflight,
    });
    await this.putUninstallJournal(context.session, context.installJournal, context.control, journal);
    return internalJson({ journal });
  }

  private async prepareUninstallAction(request: Request): Promise<Response> {
    return this.writePreparedUninstallAction(request, false);
  }

  private async replacePreparedUninstallAction(request: Request): Promise<Response> {
    return this.writePreparedUninstallAction(request, true);
  }

  private async writePreparedUninstallAction(request: Request, replace: boolean): Promise<Response> {
    const input = await parsedJsonBody(request, v.strictObject({
      ...revisionAttemptNowSchema,
      action: mutableUninstallActionSchema,
      record: boundaryValueSchema,
    }));
    const context = await this.activeUninstallOperation(input.attemptId);
    if (!context.journal) throw new DeployError(409, 'session_conflict');
    const transition = {
      expectedRevision: input.expectedRevision,
      attemptId: context.attemptId,
      now: context.now,
      action: input.action,
      record: input.record,
    };
    const journal = replace
      ? await replacePreparedUninstallJournalAction(context.journal, transition)
      : await prepareUninstallJournalAction(context.journal, transition);
    await this.putUninstallJournal(context.session, context.installJournal, context.control, journal);
    return internalJson({ journal });
  }

  private async attachUninstallVersionRecovery(request: Request): Promise<Response> {
    const input = await parsedJsonBody(request, v.strictObject({
      ...revisionAttemptNowSchema,
      action: versionRecoveryActionSchema,
      recovery: boundaryValueSchema,
    }));
    const context = await this.activeUninstallOperation(input.attemptId);
    if (!context.journal) throw new DeployError(409, 'session_conflict');
    const journal = await attachUninstallWorkerVersionRecovery(context.journal, {
      expectedRevision: input.expectedRevision,
      attemptId: context.attemptId,
      now: context.now,
      action: input.action,
      recovery: input.recovery,
    });
    await this.putUninstallJournal(context.session, context.installJournal, context.control, journal);
    return internalJson({ journal });
  }

  private async armUninstallAction(request: Request): Promise<Response> {
    const input = await parsedJsonBody(request, uninstallArmBodySchema);
    return this.transitionUninstallAction(input, 'arm');
  }

  private async submitUninstallAction(request: Request): Promise<Response> {
    const input = await parsedJsonBody(request, uninstallValueBodySchema);
    return this.transitionUninstallAction(input, 'submitted');
  }

  private async verifyUninstallAction(request: Request): Promise<Response> {
    const input = await parsedJsonBody(request, uninstallValueBodySchema);
    return this.transitionUninstallAction(input, 'verified');
  }

  private async transitionUninstallAction(
    input: UninstallTransitionInput,
    transition: 'arm' | 'submitted' | 'verified',
  ): Promise<Response> {
    const context = await this.activeUninstallOperation(input.attemptId);
    if (!context.journal) throw new DeployError(409, 'session_conflict');
    const base = {
      expectedRevision: input.expectedRevision,
      attemptId: context.attemptId,
      now: context.now,
      action: input.action,
    };
    let journal: UninstallJournal;
    if (transition === 'arm') {
      journal = 'value' in input
        ? await armUninstallJournalAction(context.journal, { ...base, value: input.value })
        : await armUninstallJournalAction(context.journal, base);
    } else {
      if (!('value' in input)) throw new DeployError(400, 'bad_request');
      const value = { ...base, value: input.value };
      journal = transition === 'submitted'
        ? await submitUninstallJournalAction(context.journal, value)
        : await verifyUninstallJournalAction(context.journal, value);
    }
    await this.putUninstallJournal(context.session, context.installJournal, context.control, journal);
    return internalJson({ journal });
  }

  private async appendCustomerRemoveCycle(request: Request): Promise<Response> {
    return this.writeCustomerRemoveCycle(request, false);
  }

  private async replaceCustomerRemoveCycle(request: Request): Promise<Response> {
    return this.writeCustomerRemoveCycle(request, true);
  }

  private async writeCustomerRemoveCycle(request: Request, replace: boolean): Promise<Response> {
    const input = await parsedJsonBody(request, v.strictObject({
      ...revisionAttemptNowSchema,
      semantic: boundaryValueSchema,
    }));
    const context = await this.activeUninstallOperation(input.attemptId);
    if (!context.journal) throw new DeployError(409, 'session_conflict');
    const change = {
      expectedRevision: input.expectedRevision,
      attemptId: context.attemptId,
      now: context.now,
      semantic: input.semantic,
    };
    const journal = replace
      ? await replacePreparedCustomerGatewayRemoveAttempt(context.journal, change)
      : await appendCustomerGatewayRemoveAttempt(context.journal, change);
    await this.putUninstallJournal(context.session, context.installJournal, context.control, journal);
    return internalJson({ journal });
  }

  private async prepareCustomerWorkersDevDisable(request: Request): Promise<Response> {
    return this.writeCustomerWorkersDevDisable(request, false);
  }

  private async replaceCustomerWorkersDevDisable(request: Request): Promise<Response> {
    return this.writeCustomerWorkersDevDisable(request, true);
  }

  private async writeCustomerWorkersDevDisable(request: Request, replace: boolean): Promise<Response> {
    const input = await parsedJsonBody(request, v.strictObject(revisionAttemptNowSchema));
    const context = await this.activeUninstallOperation(input.attemptId);
    if (!context.journal) throw new DeployError(409, 'session_conflict');
    const change = {
      expectedRevision: input.expectedRevision,
      attemptId: context.attemptId,
      now: context.now,
    };
    const journal = replace
      ? await replacePreparedCustomerGatewayWorkersDevDisable(context.journal, change)
      : await prepareCustomerGatewayWorkersDevDisable(context.journal, change);
    await this.putUninstallJournal(context.session, context.installJournal, context.control, journal);
    return internalJson({ journal });
  }

  private async armCustomerWorkersDev(request: Request): Promise<Response> {
    return this.transitionCustomerWorkersDev(request, 'arm');
  }

  private async submitCustomerWorkersDev(request: Request): Promise<Response> {
    return this.transitionCustomerWorkersDev(request, 'submitted');
  }

  private async verifyCustomerWorkersDev(request: Request): Promise<Response> {
    return this.transitionCustomerWorkersDev(request, 'verified');
  }

  private async recordCustomerWorkersDevNotApplied(request: Request): Promise<Response> {
    return this.transitionCustomerWorkersDev(request, 'not_applied');
  }

  private async transitionCustomerWorkersDev(
    request: Request,
    transition: 'arm' | 'submitted' | 'verified' | 'not_applied',
  ): Promise<Response> {
    const needsLocator = transition === 'submitted' || transition === 'not_applied';
    const input = needsLocator
      ? await parsedJsonBody(request, v.strictObject({
          ...revisionAttemptNowSchema,
          enabled: v.boolean(),
          locator: boundaryValueSchema,
        }))
      : await parsedJsonBody(request, v.strictObject({
          ...revisionAttemptNowSchema,
          enabled: v.boolean(),
        }));
    const context = await this.activeUninstallOperation(input.attemptId);
    if (!context.journal) throw new DeployError(409, 'session_conflict');
    const base = {
      expectedRevision: input.expectedRevision,
      attemptId: context.attemptId,
      now: context.now,
      enabled: input.enabled,
    };
    let journal: UninstallJournal;
    if (transition === 'arm') {
      journal = await armCustomerGatewayWorkersDev(context.journal, base);
    } else if (transition === 'verified') {
      journal = verifyCustomerGatewayWorkersDev(context.journal, base);
    } else {
      if (!('locator' in input)) throw new DeployError(400, 'bad_request');
      const change = { ...base, locator: input.locator };
      journal = transition === 'submitted'
        ? submitCustomerGatewayWorkersDev(context.journal, change)
        : recordCustomerGatewayWorkersDevNotApplied(context.journal, change);
    }
    await this.putUninstallJournal(context.session, context.installJournal, context.control, journal);
    return internalJson({ journal });
  }

  private async armCustomerRemoveRequest(request: Request): Promise<Response> {
    return this.transitionCustomerRemoveRequest(request, 'arm');
  }

  private async submitCustomerRemoveRequest(request: Request): Promise<Response> {
    return this.transitionCustomerRemoveRequest(request, 'submitted');
  }

  private async verifyCustomerRemoveRequest(request: Request): Promise<Response> {
    return this.transitionCustomerRemoveRequest(request, 'verified');
  }

  private async transitionCustomerRemoveRequest(
    request: Request,
    transition: 'arm' | 'submitted' | 'verified',
  ): Promise<Response> {
    const input = transition === 'submitted'
      ? await parsedJsonBody(request, v.strictObject({
          ...revisionAttemptNowSchema,
          locator: boundaryValueSchema,
        }))
      : await parsedJsonBody(request, v.strictObject(revisionAttemptNowSchema));
    const context = await this.activeUninstallOperation(input.attemptId);
    if (!context.journal) throw new DeployError(409, 'session_conflict');
    const base = {
      expectedRevision: input.expectedRevision,
      attemptId: context.attemptId,
      now: context.now,
    };
    let journal: UninstallJournal;
    if (transition === 'arm') {
      journal = armCustomerGatewayRemoveRequest(context.journal, base);
    } else if (transition === 'verified') {
      journal = verifyCustomerGatewayRemoveRequest(context.journal, base);
    } else {
      if (!('locator' in input)) throw new DeployError(400, 'bad_request');
      journal = await submitCustomerGatewayRemoveRequest(context.journal, {
        ...base,
        locator: input.locator,
      });
    }
    await this.putUninstallJournal(context.session, context.installJournal, context.control, journal);
    return internalJson({ journal });
  }

  private async appendManagementDeleteAttempt(request: Request): Promise<Response> {
    const input = await parsedJsonBody(request, v.strictObject({
      ...revisionAttemptNowSchema,
      action: managementDeleteActionSchema,
      prerequisites: boundaryValueSchema,
      intent: boundaryValueSchema,
    }));
    const context = await this.activeUninstallOperation(input.attemptId);
    if (!context.journal) throw new DeployError(409, 'session_conflict');
    const journal = await appendUninstallManagementDeleteAttempt(context.journal, {
      expectedRevision: input.expectedRevision,
      attemptId: context.attemptId,
      now: context.now,
      action: input.action,
      prerequisites: input.prerequisites,
      intent: input.intent,
    });
    await this.putUninstallJournal(context.session, context.installJournal, context.control, journal);
    return internalJson({ journal });
  }

  private async recordManagementDeleteRecovery(request: Request): Promise<Response> {
    const input = await parsedJsonBody(request, v.strictObject({
      ...revisionAttemptNowSchema,
      action: managementDeleteActionSchema,
      evidence: boundaryValueSchema,
    }));
    const context = await this.activeUninstallOperation(input.attemptId);
    if (!context.journal) throw new DeployError(409, 'session_conflict');
    const journal = await recordUninstallManagementDeleteRecovery(context.journal, {
      expectedRevision: input.expectedRevision,
      attemptId: context.attemptId,
      now: context.now,
      action: input.action,
      evidence: input.evidence,
    });
    await this.putUninstallJournal(context.session, context.installJournal, context.control, journal);
    return internalJson({ journal });
  }

  private async casUninstallJournal(
    request: Request,
    transition: (
      journal: UninstallJournal,
      input: { expectedRevision: number; attemptId: string; now: number },
      context: Awaited<ReturnType<GatewayDeploySession['activeUninstallOperation']>>,
    ) => UninstallJournal,
  ): Promise<Response> {
    const input = await parsedJsonBody(request, v.strictObject(revisionAttemptNowSchema));
    const context = await this.activeUninstallOperation(input.attemptId);
    if (!context.journal) throw new DeployError(409, 'session_conflict');
    const journal = transition(context.journal, {
      expectedRevision: input.expectedRevision,
      attemptId: context.attemptId,
      now: context.now,
    }, context);
    await this.putUninstallJournal(context.session, context.installJournal, context.control, journal);
    return internalJson({ journal });
  }

  private async completeUninstall(request: Request): Promise<Response> {
    const input = await parsedJsonBody(request, uninstallCompletionBodySchema);
    const session = await this.stored();
    const installJournal = await this.storedJournal(session);
    const now = this.wallTime();
    const authority = this.requireRetainedInstallAuthority(session, installJournal, now);
    const control = await this.storedUninstallControl(authority.session, authority.journal);
    const uninstallJournal = await this.storedUninstallJournal(authority.session, authority.journal, control);
    if (!control) throw new DeployError(409, 'session_conflict');
    this.requireUninstallAttempt(control, input.attemptId);
    const code = uninstallCompletionCode(input.code);
    if (now < (control.oauthAttempt?.usedAt ?? now + 1) || now >= control.recoverUntil) {
      throw new DeployError(409, 'session_conflict');
    }
    let result: UninstallResult;
    if (code === 'uninstall_complete') {
      const final = uninstallJournal?.actions.at(-1);
      if (!uninstallJournal || !isCompleteUninstallJournal(uninstallJournal) ||
        final?.name !== 'uninstall_final_convergence' || final.phase !== 'verified' ||
        !final.locator || !('status' in final.locator) || final.locator.status !== 'removed' ||
        final.locator.installationId !== control.installationId || input.installationId !== control.installationId ||
        (input.grantRevocation !== 'confirmed' && input.grantRevocation !== 'unconfirmed')) {
        throw new DeployError(409, 'session_conflict');
      }
      result = {
        code,
        completedAt: now,
        installationId: control.installationId,
        grantRevocation: input.grantRevocation,
      };
    } else {
      if (input.installationId !== null || input.grantRevocation !== null) {
        throw new DeployError(409, 'session_conflict');
      }
      result = isFailureReason(input.reason) ? { code, completedAt: now, reason: input.reason } : { code, completedAt: now };
    }
    const next: StoredUninstallControl = {
      ...control,
      status: code === 'uninstall_complete' ? 'removed' : 'failed',
      updatedAt: now,
      result,
    };
    await this.putUninstallControl(authority.session, authority.journal, next, uninstallJournal);
    return internalJson({ uninstall: publicUninstallSession(next) });
  }

  private async complete(request: Request): Promise<Response> {
    const input = await parsedJsonBody(request, installCompletionBodySchema);
    const successfulInput = v.safeParse(successfulInstallCompletionSchema, input);
    const failedInput = v.safeParse(failedInstallCompletionSchema, input);
    const existingGateway = failedInput.success && failedInput.output.existingGateway !== undefined
      ? parseExistingAnkkaGatewaySummary(failedInput.output.existingGateway)
      : null;
    const session = await this.stored();
    const journal = await this.storedJournal(session);
    const code = successfulInput.success ? 'install_complete' : failureCode(input.code);
    const completedAt = this.wallTime();
    const completionDeadline = journal && (isPartialInstallJournal(journal) || isCompleteInstallJournal(journal))
      ? journal.recoverUntil
      : session?.expiresAt;
    if (
      !session?.oauthAttempt ||
      session.status !== 'installing' ||
      session.oauthAttempt.usedAt === null ||
      input.attemptId !== session.oauthAttempt.attemptId ||
      completedAt < session.oauthAttempt.usedAt ||
      completionDeadline === undefined || completedAt >= completionDeadline
    ) {
      throw new DeployError(409, 'session_conflict');
    }
    let result: DeployResult;
    if (successfulInput.success) {
      if (
        !journal || !isCompleteInstallJournal(journal) ||
        successfulInput.output.installationId !== journal.installationId ||
        (successfulInput.output.grantRevocation !== 'confirmed' &&
          successfulInput.output.grantRevocation !== 'unconfirmed')
      ) throw new DeployError(409, 'session_conflict');
      result = {
        code,
        completedAt,
        installationId: successfulInput.output.installationId,
        grantRevocation: successfulInput.output.grantRevocation,
      };
    } else {
      if (!failedInput.success) throw new DeployError(400, 'bad_request');
      const errorCode = failureCode(failedInput.output.code);
      if ((code === 'existing_gateway_detected') !== (existingGateway !== null)) {
        throw new DeployError(409, 'session_conflict');
      }
      if (failedInput.output.reason !== null && existingGateway) {
        result = { code: errorCode, completedAt, reason: failedInput.output.reason, existingGateway };
      } else if (failedInput.output.reason !== null) {
        result = { code: errorCode, completedAt, reason: failedInput.output.reason };
      } else if (existingGateway) {
        result = { code: errorCode, completedAt, existingGateway };
      } else {
        result = { code: errorCode, completedAt };
      }
    }
    const next: StoredDeploySession = {
      ...session,
      status: code === 'install_complete' ? 'succeeded' : 'failed',
      updatedAt: Math.min(completedAt, session.expiresAt),
      result,
    };
    await this.put(next, journal, completedAt);
    return internalJson({ session: publicSession(next) });
  }

  private async destroy(request: Request): Promise<Response> {
    const input = await parsedJsonBody(request, v.strictObject({ csrfHash: v.string() }));
    const session = await this.stored();
    if (!session) return new Response(null, { status: 204 });
    verifyHash(input.csrfHash, session.csrfHash);
    const journal = await this.storedJournal(session);
    if (journal && hasArmedInstallJournalAction(journal)) throw new DeployError(409, 'session_conflict');
    const uninstallControl = await this.storedUninstallControl(session, journal);
    const uninstallJournal = await this.storedUninstallJournal(session, journal, uninstallControl);
    if (uninstallJournal && hasArmedUninstallJournalAction(uninstallJournal)) {
      throw new DeployError(409, 'session_conflict');
    }
    await this.clearStorage();
    return new Response(null, { status: 204 });
  }
}

function constantHashes(leftState: string, rightState: string, leftVerifier: string, rightVerifier: string): boolean {
  try {
    verifyHash(leftState, rightState);
    verifyHash(leftVerifier, rightVerifier);
    return true;
  } catch {
    return false;
  }
}

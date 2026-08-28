import * as v from 'valibot';

import { boundaryValueSchema, jsonValueSchema, type BoundaryValue, type JsonValue } from './boundary';
import { sha256Hex } from './crypto';
import { DeployError } from './errors';
import {
  requireReturningUninstallImportedAuthority,
  returningUninstallAuthorityCanonicalJson as canonicalJson,
  type ReturningUninstallImportedAuthority,
} from './returning-uninstall-authority';
import { parseReturningUninstallPlan, type ReturningUninstallPlan } from './returning-uninstall-plan';
import { assertSecretFree } from './schema';

const ATTEMPT_ID = /^att_[A-Za-z0-9_-]{32}$/u;
const HASH = /^sha256:[a-f0-9]{64}$/u;
const MAX_ACTION_BYTES = 512 * 1024;
export const MAX_RETURNING_UNINSTALL_LEASE_MS = 5 * 60 * 1_000;
export const MAX_RETURNING_UNINSTALL_RECOVERY_RETENTION_MS = 24 * 60 * 60 * 1_000;

export const RETURNING_UNINSTALL_ACTION_ORDER = Object.freeze([
  'authority_import',
  'surface_preflight',
  'customer_gateway_remove',
  'management_custom_domain_delete',
  'management_admin_policy_delete',
  'management_access_application_delete',
  'retirement_worker_version_create',
  'retirement_worker_deployment_create',
  'admin_state_namespace_retired',
  'management_worker_delete',
  'no_managed_residue_verify',
  'final_convergence',
] as const);

export type ReturningUninstallActionName = (typeof RETURNING_UNINSTALL_ACTION_ORDER)[number];
export type ReturningUninstallActionPhase = 'prepared' | 'send_armed' | 'submitted' | 'verified';

const safeIntegerSchema = v.pipe(v.number(), v.safeInteger(), v.minValue(0));
const actionNameSchema = v.picklist(RETURNING_UNINSTALL_ACTION_ORDER);
const actionPhaseSchema = v.picklist(['prepared', 'send_armed', 'submitted', 'verified']);
const storedActionSchema = v.strictObject({
  name: actionNameSchema,
  phase: actionPhaseSchema,
  record: jsonValueSchema,
  locator: v.nullable(jsonValueSchema),
  preparedAt: safeIntegerSchema,
  sendArmedAt: v.nullable(safeIntegerSchema),
  submittedAt: v.nullable(safeIntegerSchema),
  verifiedAt: v.nullable(safeIntegerSchema),
});
const storedApprovalSchema = v.strictObject({
  authorization: v.picklist(['customer_action', 'hosted_recovery']),
  attemptId: v.string(),
  approvedAt: safeIntegerSchema,
  actionId: v.string(),
  actorEmail: v.string(),
  actionProofHash: v.string(),
  planCreatedAt: safeIntegerSchema,
  planExpiresAt: safeIntegerSchema,
  accountId: v.string(),
  zoneId: v.string(),
});
const storedLeaseSchema = v.strictObject({
  attemptId: v.string(),
  acquiredAt: safeIntegerSchema,
  expiresAt: safeIntegerSchema,
});
const storedJournalSchema = v.strictObject({
  schemaVersion: v.literal(1),
  revision: safeIntegerSchema,
  createdAt: safeIntegerSchema,
  updatedAt: safeIntegerSchema,
  recoverUntil: safeIntegerSchema,
  installationId: v.string(),
  plan: boundaryValueSchema,
  authority: boundaryValueSchema,
  bindingHash: v.string(),
  approvalHistory: v.array(storedApprovalSchema),
  lease: v.nullable(storedLeaseSchema),
  actions: v.array(storedActionSchema),
});

type StoredReturningUninstallAction = v.InferOutput<typeof storedActionSchema>;

export interface ReturningUninstallJournalAction {
  readonly name: ReturningUninstallActionName;
  readonly phase: ReturningUninstallActionPhase;
  readonly record: JsonValue;
  readonly locator: JsonValue | null;
  readonly preparedAt: number;
  readonly sendArmedAt: number | null;
  readonly submittedAt: number | null;
  readonly verifiedAt: number | null;
}

export interface ReturningUninstallJournalApproval {
  readonly authorization: 'customer_action' | 'hosted_recovery';
  readonly attemptId: string;
  readonly approvedAt: number;
  readonly actionId: string;
  readonly actorEmail: string;
  readonly actionProofHash: string;
  readonly planCreatedAt: number;
  readonly planExpiresAt: number;
  readonly accountId: string;
  readonly zoneId: string;
}

export interface ReturningUninstallJournal {
  readonly schemaVersion: 1;
  readonly revision: number;
  readonly createdAt: number;
  readonly updatedAt: number;
  readonly recoverUntil: number;
  readonly installationId: string;
  readonly plan: ReturningUninstallPlan;
  readonly authority: ReturningUninstallImportedAuthority;
  readonly bindingHash: string;
  readonly approvalHistory: readonly ReturningUninstallJournalApproval[];
  readonly lease: null | {
    readonly attemptId: string;
    readonly acquiredAt: number;
    readonly expiresAt: number;
  };
  readonly actions: readonly ReturningUninstallJournalAction[];
}

function parseSafePayload<Input>(value: Input): JsonValue | undefined {
  try {
    const parsed = v.safeParse(jsonValueSchema, value);
    if (!parsed.success) return undefined;
    assertSecretFree(parsed.output);
    if (new TextEncoder().encode(canonicalJson(parsed.output)).byteLength > MAX_ACTION_BYTES) return undefined;
    return parsed.output;
  } catch {
    return undefined;
  }
}

async function bindingHash(plan: ReturningUninstallPlan, authority: ReturningUninstallImportedAuthority): Promise<string> {
  return `sha256:${await sha256Hex(canonicalJson({
    schemaVersion: 1,
    planId: plan.planId,
    planHash: plan.planHash,
    installationId: authority.installationId,
    authorityHash: authority.authorityHash,
  }))}`;
}

function stableAuthority(value: ReturningUninstallImportedAuthority) {
  return {
    schemaVersion: value.schemaVersion,
    installationId: value.installationId,
    receipt: value.receipt,
    control: value.control,
    sources: value.sources,
    runtime: value.runtime,
    authorityHash: value.authorityHash,
  };
}

function invalid(code: 'session_invalid' | 'session_conflict' = 'session_invalid', status = 500): never {
  throw new DeployError(status, code);
}

async function parseAction(
  value: StoredReturningUninstallAction,
  index: number,
  updatedAt: number,
): Promise<ReturningUninstallJournalAction> {
  const actionRecord = parseSafePayload(value.record);
  const locator = value.locator === null ? null : parseSafePayload(value.locator);
  if (value.name !== RETURNING_UNINSTALL_ACTION_ORDER[index] || actionRecord === undefined ||
    locator === undefined || value.preparedAt > updatedAt ||
    (value.sendArmedAt !== null && (value.sendArmedAt < value.preparedAt || value.sendArmedAt > updatedAt)) ||
    (value.submittedAt !== null && (value.sendArmedAt === null ||
      value.submittedAt < value.sendArmedAt || value.submittedAt > updatedAt)) ||
    (value.verifiedAt !== null && (value.submittedAt === null ||
      value.verifiedAt < value.submittedAt || value.verifiedAt > updatedAt))) invalid();
  if ((value.phase === 'prepared' && (value.sendArmedAt !== null || value.submittedAt !== null ||
      value.verifiedAt !== null || value.locator !== null)) ||
    (value.phase === 'send_armed' && (value.sendArmedAt === null || value.submittedAt !== null ||
      value.verifiedAt !== null || value.locator !== null)) ||
    (value.phase === 'submitted' && (value.sendArmedAt === null || value.submittedAt === null ||
      value.verifiedAt !== null || value.locator === null)) ||
    (value.phase === 'verified' && (value.sendArmedAt === null || value.submittedAt === null ||
      value.verifiedAt === null || value.locator === null))) invalid();
  return Object.freeze({
    name: value.name,
    phase: value.phase,
    record: structuredClone(actionRecord),
    locator: locator === null ? null : structuredClone(locator),
    preparedAt: value.preparedAt,
    sendArmedAt: value.sendArmedAt,
    submittedAt: value.submittedAt,
    verifiedAt: value.verifiedAt,
  });
}

export async function requireReturningUninstallJournal<Input>(input: Input): Promise<ReturningUninstallJournal> {
  const parsed = v.safeParse(storedJournalSchema, input);
  if (!parsed.success) invalid();
  const value = parsed.output;
  if (value.updatedAt < value.createdAt ||
    value.recoverUntil <= value.createdAt ||
    value.recoverUntil - value.createdAt > MAX_RETURNING_UNINSTALL_RECOVERY_RETENTION_MS ||
    !HASH.test(value.bindingHash) ||
    value.approvalHistory.length < 1 || value.approvalHistory.length > 16 ||
    value.actions.length < 1 ||
    value.actions.length > RETURNING_UNINSTALL_ACTION_ORDER.length) invalid();
  const plan = await parseReturningUninstallPlan(value.plan).catch(() => null);
  const authority = await requireReturningUninstallImportedAuthority(value.authority).catch(() => null);
  if (!plan || !authority || value.installationId !== authority.installationId ||
    plan.expiresAt > value.recoverUntil || canonicalJson(plan.gateway) !== canonicalJson({
      schemaVersion: 1,
      installationId: authority.installationId,
      name: authority.control.portal.name,
      managementHostname: authority.runtime.managementHostname,
      portalHostname: authority.control.portal.hostname,
      workerName: authority.runtime.workerName,
    }) || value.bindingHash !== await bindingHash(plan, authority)) invalid();
  const approvals: ReturningUninstallJournalApproval[] = [];
  for (const raw of value.approvalHistory) {
    if (!ATTEMPT_ID.test(raw.attemptId) || !HASH.test(raw.actionProofHash) ||
      raw.planExpiresAt <= raw.planCreatedAt || raw.planExpiresAt > value.recoverUntil ||
      raw.approvedAt < raw.planCreatedAt || raw.approvedAt >= raw.planExpiresAt ||
      raw.accountId !== authority.runtime.accountId || raw.zoneId !== authority.runtime.zoneId) invalid();
    approvals.push(Object.freeze({
      authorization: raw.authorization,
      attemptId: raw.attemptId,
      approvedAt: raw.approvedAt,
      actionId: raw.actionId,
      actorEmail: raw.actorEmail,
      actionProofHash: raw.actionProofHash,
      planCreatedAt: raw.planCreatedAt,
      planExpiresAt: raw.planExpiresAt,
      accountId: raw.accountId,
      zoneId: raw.zoneId,
    }));
  }
  if (new Set(approvals.map((approval) => approval.attemptId)).size !== approvals.length) invalid();
  const activeApproval = approvals.at(-1);
  if (!activeApproval || activeApproval.actionId !== authority.actionId ||
    activeApproval.actorEmail !== authority.actorEmail || activeApproval.actionProofHash !== authority.actionProofHash ||
    activeApproval.planCreatedAt !== plan.createdAt || activeApproval.planExpiresAt !== plan.expiresAt) invalid();
  let lease: ReturningUninstallJournal['lease'] = null;
  if (value.lease !== null) {
    const rawLease = value.lease;
    if (!approvals.some((approval) => approval.attemptId === rawLease.attemptId) ||
      rawLease.expiresAt <= rawLease.acquiredAt || rawLease.expiresAt > value.recoverUntil ||
      rawLease.expiresAt > (approvals.find((approval) => approval.attemptId === rawLease.attemptId)?.planExpiresAt ?? 0) ||
      rawLease.expiresAt - rawLease.acquiredAt > MAX_RETURNING_UNINSTALL_LEASE_MS) invalid();
    lease = Object.freeze({
      attemptId: rawLease.attemptId,
      acquiredAt: rawLease.acquiredAt,
      expiresAt: rawLease.expiresAt,
    });
  }
  const actions = await Promise.all(value.actions.map((action, index) => parseAction(action, index, value.updatedAt)));
  if (actions.slice(0, -1).some((action) => action.phase !== 'verified')) invalid();
  const imported = actions[0];
  if (imported === undefined || imported.name !== 'authority_import' || imported.phase !== 'verified' ||
    canonicalJson(imported.record) !== canonicalJson({
      schemaVersion: 1,
      authorityHash: authority.authorityHash,
      installationId: authority.installationId,
    }) || canonicalJson(imported.locator) !== canonicalJson({
      schemaVersion: 1,
      status: 'imported',
      authorityHash: authority.authorityHash,
    })) invalid();
  const journal = Object.freeze({
    schemaVersion: 1 as const,
    revision: value.revision,
    createdAt: value.createdAt,
    updatedAt: value.updatedAt,
    recoverUntil: value.recoverUntil,
    installationId: authority.installationId,
    plan,
    authority,
    bindingHash: value.bindingHash,
    approvalHistory: Object.freeze(approvals),
    lease,
    actions: Object.freeze(actions),
  });
  assertSecretFree(journal);
  return journal;
}

export async function createReturningUninstallJournal(input: {
  readonly now: number;
  readonly plan: ReturningUninstallPlan;
  readonly authority: ReturningUninstallImportedAuthority;
  readonly attemptId: string;
  readonly approvedAt: number;
  readonly accountId: string;
  readonly zoneId: string;
  readonly recoverUntil: number;
}): Promise<ReturningUninstallJournal> {
  if (!v.is(safeIntegerSchema, input.now) || !ATTEMPT_ID.test(input.attemptId) || input.accountId !== input.authority.runtime.accountId ||
    input.zoneId !== input.authority.runtime.zoneId || input.approvedAt > input.now || input.now >= input.plan.expiresAt ||
    !v.is(safeIntegerSchema, input.recoverUntil) || input.recoverUntil <= input.plan.expiresAt ||
    input.recoverUntil - input.now > MAX_RETURNING_UNINSTALL_RECOVERY_RETENTION_MS) {
    invalid('session_conflict', 409);
  }
  const action = Object.freeze({
    name: 'authority_import' as const,
    phase: 'verified' as const,
    record: Object.freeze({
      schemaVersion: 1,
      authorityHash: input.authority.authorityHash,
      installationId: input.authority.installationId,
    }),
    locator: Object.freeze({
      schemaVersion: 1,
      status: 'imported' as const,
      authorityHash: input.authority.authorityHash,
    }),
    preparedAt: input.now,
    sendArmedAt: input.now,
    submittedAt: input.now,
    verifiedAt: input.now,
  });
  return requireReturningUninstallJournal({
    schemaVersion: 1,
    revision: 0,
    createdAt: input.now,
    updatedAt: input.now,
    recoverUntil: input.recoverUntil,
    installationId: input.authority.installationId,
    plan: input.plan,
    authority: input.authority,
    bindingHash: await bindingHash(input.plan, input.authority),
    approvalHistory: [{
      authorization: 'customer_action',
      attemptId: input.attemptId,
      approvedAt: input.approvedAt,
      actionId: input.authority.actionId,
      actorEmail: input.authority.actorEmail,
      actionProofHash: input.authority.actionProofHash,
      planCreatedAt: input.plan.createdAt,
      planExpiresAt: input.plan.expiresAt,
      accountId: input.accountId,
      zoneId: input.zoneId,
    }],
    lease: null,
    actions: [action],
  });
}

function cas(journal: ReturningUninstallJournal, expectedRevision: number, attemptId: string, now: number): void {
  if (journal.revision !== expectedRevision || !ATTEMPT_ID.test(attemptId) || !v.is(safeIntegerSchema, now) ||
    now < journal.updatedAt || now >= journal.recoverUntil ||
    !journal.approvalHistory.some((approval) => approval.attemptId === attemptId)) {
    invalid('session_conflict', 409);
  }
}

function updated(journal: ReturningUninstallJournal, patch: Partial<ReturningUninstallJournal>) {
  return { ...journal, revision: journal.revision + 1, ...patch };
}

export async function appendReturningUninstallApproval(
  journal: ReturningUninstallJournal,
  input: {
    readonly expectedRevision: number;
    readonly attemptId: string;
    readonly approvedAt: number;
    readonly now: number;
    readonly plan: ReturningUninstallPlan;
    readonly authority: ReturningUninstallImportedAuthority;
  },
): Promise<ReturningUninstallJournal> {
  if (journal.revision !== input.expectedRevision || !ATTEMPT_ID.test(input.attemptId) ||
    journal.approvalHistory.some((approval) => approval.attemptId === input.attemptId) ||
    !v.is(safeIntegerSchema, input.approvedAt) || !v.is(safeIntegerSchema, input.now) || input.approvedAt > input.now ||
    input.now < journal.updatedAt || input.now >= journal.recoverUntil || input.now >= input.plan.expiresAt ||
    input.approvedAt < input.plan.createdAt || input.approvedAt >= input.plan.expiresAt ||
    input.plan.planId !== journal.plan.planId || input.plan.planHash !== journal.plan.planHash ||
    canonicalJson(input.plan.gateway) !== canonicalJson(journal.plan.gateway) ||
    input.authority.authorityHash !== journal.authority.authorityHash ||
    canonicalJson(stableAuthority(input.authority)) !== canonicalJson(stableAuthority(journal.authority))) {
    invalid('session_conflict', 409);
  }
  return requireReturningUninstallJournal(updated(journal, {
    updatedAt: input.now,
    plan: input.plan,
    authority: input.authority,
    approvalHistory: Object.freeze([...journal.approvalHistory, Object.freeze({
      authorization: 'customer_action' as const,
      attemptId: input.attemptId,
      approvedAt: input.approvedAt,
      actionId: input.authority.actionId,
      actorEmail: input.authority.actorEmail,
      actionProofHash: input.authority.actionProofHash,
      planCreatedAt: input.plan.createdAt,
      planExpiresAt: input.plan.expiresAt,
      accountId: input.authority.runtime.accountId,
      zoneId: input.authority.runtime.zoneId,
    })]),
  }));
}

export async function appendReturningUninstallHostedRecoveryApproval(
  journal: ReturningUninstallJournal,
  input: {
    readonly expectedRevision: number;
    readonly attemptId: string;
    readonly approvedAt: number;
    readonly now: number;
    readonly plan: ReturningUninstallPlan;
    readonly actorEmail: string;
    readonly accountId: string;
    readonly zoneId: string;
  },
): Promise<ReturningUninstallJournal> {
  const gatewayRemoval = journal.actions.find((action) => action.name === 'customer_gateway_remove');
  if (journal.revision !== input.expectedRevision || !ATTEMPT_ID.test(input.attemptId) ||
    journal.approvalHistory.some((approval) => approval.attemptId === input.attemptId) ||
    !v.is(safeIntegerSchema, input.approvedAt) || !v.is(safeIntegerSchema, input.now) || input.approvedAt > input.now ||
    input.now < journal.updatedAt || input.now >= journal.recoverUntil || input.now >= input.plan.expiresAt ||
    input.approvedAt < input.plan.createdAt || input.approvedAt >= input.plan.expiresAt ||
    input.plan.planId !== journal.plan.planId || input.plan.planHash !== journal.plan.planHash ||
    canonicalJson(input.plan.gateway) !== canonicalJson(journal.plan.gateway) ||
    input.actorEmail !== journal.authority.actorEmail || input.accountId !== journal.authority.runtime.accountId ||
    input.zoneId !== journal.authority.runtime.zoneId || gatewayRemoval?.phase !== 'verified') {
    invalid('session_conflict', 409);
  }
  return requireReturningUninstallJournal(updated(journal, {
    updatedAt: input.now,
    plan: input.plan,
    approvalHistory: Object.freeze([...journal.approvalHistory, Object.freeze({
      authorization: 'hosted_recovery' as const,
      attemptId: input.attemptId,
      approvedAt: input.approvedAt,
      actionId: journal.authority.actionId,
      actorEmail: input.actorEmail,
      actionProofHash: journal.authority.actionProofHash,
      planCreatedAt: input.plan.createdAt,
      planExpiresAt: input.plan.expiresAt,
      accountId: input.accountId,
      zoneId: input.zoneId,
    })]),
  }));
}

export async function acquireReturningUninstallLease(
  journal: ReturningUninstallJournal,
  input: { readonly expectedRevision: number; readonly attemptId: string; readonly now: number; readonly expiresAt: number },
): Promise<ReturningUninstallJournal> {
  cas(journal, input.expectedRevision, input.attemptId, input.now);
  const approval = journal.approvalHistory.find((candidate) => candidate.attemptId === input.attemptId);
  if (!approval || !v.is(safeIntegerSchema, input.expiresAt) || input.expiresAt <= input.now ||
    input.expiresAt > journal.recoverUntil || input.expiresAt > approval.planExpiresAt ||
    input.expiresAt - input.now > MAX_RETURNING_UNINSTALL_LEASE_MS ||
    (journal.lease && journal.lease.expiresAt > input.now && journal.lease.attemptId !== input.attemptId)) {
    invalid('session_conflict', 409);
  }
  return requireReturningUninstallJournal(updated(journal, {
    updatedAt: input.now,
    lease: Object.freeze({ attemptId: input.attemptId, acquiredAt: input.now, expiresAt: input.expiresAt }),
  }));
}

export async function releaseReturningUninstallLease(
  journal: ReturningUninstallJournal,
  input: { readonly expectedRevision: number; readonly attemptId: string; readonly now: number },
): Promise<ReturningUninstallJournal> {
  cas(journal, input.expectedRevision, input.attemptId, input.now);
  if (journal.lease?.attemptId !== input.attemptId) invalid('session_conflict', 409);
  return requireReturningUninstallJournal(updated(journal, { updatedAt: input.now, lease: null }));
}

function active(journal: ReturningUninstallJournal, attemptId: string, now: number): void {
  if (journal.lease?.attemptId !== attemptId || journal.lease.expiresAt <= now) invalid('session_conflict', 409);
}

export async function prepareReturningUninstallAction(
  journal: ReturningUninstallJournal,
  input: {
    readonly expectedRevision: number; readonly attemptId: string; readonly now: number;
    readonly name: ReturningUninstallActionName; readonly record: BoundaryValue;
  },
): Promise<ReturningUninstallJournal> {
  cas(journal, input.expectedRevision, input.attemptId, input.now);
  active(journal, input.attemptId, input.now);
  const actionRecord = parseSafePayload(input.record);
  if (input.name !== RETURNING_UNINSTALL_ACTION_ORDER[journal.actions.length] || actionRecord === undefined) {
    invalid('session_conflict', 409);
  }
  return requireReturningUninstallJournal(updated(journal, {
    updatedAt: input.now,
    actions: Object.freeze([...journal.actions, Object.freeze({
      name: input.name,
      phase: 'prepared' as const,
      record: structuredClone(actionRecord),
      locator: null,
      preparedAt: input.now,
      sendArmedAt: null,
      submittedAt: null,
      verifiedAt: null,
    })]),
  }));
}

async function transition(
  journal: ReturningUninstallJournal,
  input: {
    readonly expectedRevision: number; readonly attemptId: string; readonly now: number;
    readonly name: ReturningUninstallActionName; readonly locator?: BoundaryValue;
  },
  from: ReturningUninstallActionPhase,
  to: ReturningUninstallActionPhase,
): Promise<ReturningUninstallJournal> {
  cas(journal, input.expectedRevision, input.attemptId, input.now);
  active(journal, input.attemptId, input.now);
  const current = journal.actions.at(-1);
  const locator = input.locator === undefined ? undefined : parseSafePayload(input.locator);
  if (!current || current.name !== input.name || current.phase !== from ||
    ((to === 'submitted' || to === 'verified') && locator === undefined) ||
    (to === 'verified' && canonicalJson(current.locator) !== canonicalJson(locator))) {
    invalid('session_conflict', 409);
  }
  let sendArmedAt = current.sendArmedAt;
  let submittedAt = current.submittedAt;
  let verifiedAt = current.verifiedAt;
  let actionLocator = current.locator;
  if (to === 'send_armed') sendArmedAt = input.now;
  if (to === 'submitted') {
    if (locator === undefined) invalid('session_conflict', 409);
    submittedAt = input.now;
    actionLocator = structuredClone(locator);
  }
  if (to === 'verified') verifiedAt = input.now;
  const action = Object.freeze({
    ...current,
    phase: to,
    locator: actionLocator,
    sendArmedAt,
    submittedAt,
    verifiedAt,
  });
  return requireReturningUninstallJournal(updated(journal, {
    updatedAt: input.now,
    actions: Object.freeze([...journal.actions.slice(0, -1), action]),
  }));
}

export const armReturningUninstallAction = (
  journal: ReturningUninstallJournal,
  input: { readonly expectedRevision: number; readonly attemptId: string; readonly now: number; readonly name: ReturningUninstallActionName },
): Promise<ReturningUninstallJournal> => transition(journal, input, 'prepared', 'send_armed');

export const submitReturningUninstallAction = (
  journal: ReturningUninstallJournal,
  input: { readonly expectedRevision: number; readonly attemptId: string; readonly now: number; readonly name: ReturningUninstallActionName; readonly locator: BoundaryValue },
): Promise<ReturningUninstallJournal> => transition(journal, input, 'send_armed', 'submitted');

export const verifyReturningUninstallAction = (
  journal: ReturningUninstallJournal,
  input: { readonly expectedRevision: number; readonly attemptId: string; readonly now: number; readonly name: ReturningUninstallActionName; readonly locator: BoundaryValue },
): Promise<ReturningUninstallJournal> => transition(journal, input, 'submitted', 'verified');

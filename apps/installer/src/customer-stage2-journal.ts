import * as v from 'valibot';

import { canonicalJson } from './canonical-json';
import type { CustomerGatewayFreshPreflightAttestation } from
  './cloudflare-gateway-fresh-preflight';
import { assertSecretFree } from './schema';
import { deepFreezePlainData } from './plain-data';
import { jsonValueSchema, type JsonObject, type JsonValue } from './boundary';

export const CUSTOMER_STAGE2_JOURNAL_KEY = 'ankka-mcp-gateway/stage2-journal/v1';
// The final runtime comes last: its upload restarts the Durable Object on the
// new code and refuses storage to the pass that uploaded it, so everything
// that must be journaled happens before it.
export const CUSTOMER_STAGE2_ACTION_ORDER = Object.freeze([
  'management_access_application',
  'management_admin_policy',
  'gateway_resources',
  'management_custom_domain',
  'workers_dev_disable',
  'terminal_verify',
  'final_runtime',
] as const);

export type CustomerStage2ActionName = (typeof CUSTOMER_STAGE2_ACTION_ORDER)[number];
export type CustomerStage2ActionPhase = 'prepared' | 'send_armed' | 'submitted' | 'verified';

const SAFE_ID = /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$/u;
const ACCOUNT_ID = /^[a-f0-9]{32}$/u;
const INSTALL_ID = /^acg-[a-f0-9]{24}$/u;
const PLAN_ID = /^plan-[a-f0-9]{24}$/u;
const SHA256 = /^sha256:[a-f0-9]{64}$/u;
const BARE_SHA256 = /^[a-f0-9]{64}$/u;
const WORKER_NAME = /^[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$/u;
const VERSION_ID = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/u;
const ATTEMPT_ID = /^attempt_[A-Za-z0-9_-]{24}$/u;
const HOST_LABEL = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/u;
const RELEASE = /^gateway-v(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)$/u;
const MAX_JOURNAL_BYTES = 256 * 1024;

const safeInteger = v.pipe(v.number(), v.safeInteger(), v.minValue(0));
const identitySchema = v.strictObject({
  accountId: v.pipe(v.string(), v.regex(ACCOUNT_ID)),
  zoneId: v.pipe(v.string(), v.regex(ACCOUNT_ID)),
  zoneName: v.string(),
  installId: v.pipe(v.string(), v.regex(INSTALL_ID)),
  planId: v.pipe(v.string(), v.regex(PLAN_ID)),
  planHash: v.pipe(v.string(), v.regex(SHA256)),
  configurationHash: v.pipe(v.string(), v.regex(SHA256)),
  desiredHash: v.pipe(v.string(), v.regex(SHA256)),
  workerName: v.pipe(v.string(), v.regex(WORKER_NAME)),
  workerId: v.pipe(v.string(), v.regex(ACCOUNT_ID)),
  namespaceId: v.pipe(v.string(), v.regex(ACCOUNT_ID)),
  bootstrapVersionId: v.pipe(v.string(), v.regex(VERSION_ID)),
  releaseId: v.pipe(v.string(), v.regex(RELEASE)),
  releaseArtifactSha256: v.pipe(v.string(), v.regex(BARE_SHA256)),
  finalRuntimeSha256: v.pipe(v.string(), v.regex(BARE_SHA256)),
  updateChannel: v.picklist(['canary', 'stable']),
  updateKeyId: v.pipe(v.string(), v.regex(/^[a-z0-9](?:[a-z0-9._-]{0,62}[a-z0-9])?$/u)),
  updatePublicKey: v.pipe(v.string(), v.regex(/^[A-Za-z0-9_-]{43}$/u)),
  ownershipReceiptSha256: v.pipe(v.string(), v.regex(SHA256)),
});
const organizationSchema = v.strictObject({
  name: v.pipe(v.string(), v.minLength(1), v.maxLength(256)),
  authDomain: v.pipe(v.string(), v.minLength(3), v.maxLength(253)),
  issuer: v.pipe(v.string(), v.url()),
});
const leaseSchema = v.strictObject({
  attemptId: v.pipe(v.string(), v.regex(ATTEMPT_ID)),
  acquiredAt: safeInteger,
  expiresAt: safeInteger,
});
const actionSchema = v.strictObject({
  name: v.picklist(CUSTOMER_STAGE2_ACTION_ORDER),
  phase: v.picklist(['prepared', 'send_armed', 'submitted', 'verified']),
  record: v.record(v.string(), jsonValueSchema),
  locator: v.union([jsonValueSchema, v.null()]),
  preparedAt: safeInteger,
  sendArmedAt: v.union([safeInteger, v.null()]),
  submittedAt: v.union([safeInteger, v.null()]),
  verifiedAt: v.union([safeInteger, v.null()]),
});
const journalSchema = v.strictObject({
  schemaVersion: v.literal(1),
  revision: v.pipe(v.number(), v.safeInteger(), v.minValue(1)),
  createdAt: safeInteger,
  updatedAt: safeInteger,
  identity: identitySchema,
  organization: organizationSchema,
  identityProviderIds: v.pipe(v.array(v.pipe(v.string(), v.regex(SAFE_ID))), v.minLength(1)),
  workersSubdomain: v.pipe(v.string(), v.regex(HOST_LABEL)),
  preflight: v.strictObject({
    attestationHash: v.pipe(v.string(), v.regex(SHA256)),
    checkedAt: safeInteger,
    expiresAt: safeInteger,
  }),
  lease: v.union([leaseSchema, v.null()]),
  actions: v.pipe(v.array(actionSchema), v.maxLength(CUSTOMER_STAGE2_ACTION_ORDER.length)),
  completedAt: v.union([safeInteger, v.null()]),
});

export type CustomerStage2Identity = v.InferOutput<typeof identitySchema>;
export type CustomerStage2Organization = v.InferOutput<typeof organizationSchema>;
export type CustomerStage2Lease = v.InferOutput<typeof leaseSchema>;
export type CustomerStage2Action = v.InferOutput<typeof actionSchema>;
export type CustomerStage2Journal = v.InferOutput<typeof journalSchema>;

export class CustomerStage2JournalError extends Error {
  constructor(readonly code: 'invalid' | 'conflict' | 'lease_expired' | 'complete') {
    super(code);
    this.name = 'CustomerStage2JournalError';
  }
}

function fail(code: CustomerStage2JournalError['code']): never {
  throw new CustomerStage2JournalError(code);
}

function validTime(value: number): void {
  if (!Number.isSafeInteger(value) || value < 0) fail('invalid');
}

function validateAction(action: CustomerStage2Action, index: number, updatedAt: number): void {
  if (action.name !== CUSTOMER_STAGE2_ACTION_ORDER[index] || action.preparedAt > updatedAt) fail('invalid');
  const armed = action.sendArmedAt;
  const submitted = action.submittedAt;
  const verified = action.verifiedAt;
  if (
    (action.phase === 'prepared' && (action.locator !== null || armed !== null || submitted !== null || verified !== null)) ||
    (action.phase === 'send_armed' && (action.locator !== null || armed === null || submitted !== null || verified !== null)) ||
    (action.phase === 'submitted' && (action.locator === null || armed === null || submitted === null || verified !== null)) ||
    (action.phase === 'verified' && (action.locator === null || armed === null || submitted === null || verified === null)) ||
    (armed !== null && (armed < action.preparedAt || armed > updatedAt)) ||
    (submitted !== null && (armed === null || submitted < armed || submitted > updatedAt)) ||
    (verified !== null && (submitted === null || verified < submitted || verified > updatedAt))
  ) fail('invalid');
  try {
    assertSecretFree(action.record);
    if (action.locator !== null) assertSecretFree(action.locator);
  } catch {
    fail('invalid');
  }
}

export function parseCustomerStage2Journal<Input>(value: Input): CustomerStage2Journal | null {
  const parsed = v.safeParse(journalSchema, value);
  if (!parsed.success) return null;
  const journal = parsed.output;
  try {
    if (journal.createdAt > journal.updatedAt ||
        journal.preflight.checkedAt > journal.createdAt ||
        journal.preflight.expiresAt <= journal.preflight.checkedAt ||
        new Set(journal.identityProviderIds).size !== journal.identityProviderIds.length ||
        [...journal.identityProviderIds].sort().some((id, index) => id !== journal.identityProviderIds[index]) ||
        (journal.lease !== null && (
          journal.lease.acquiredAt > journal.updatedAt ||
          journal.lease.expiresAt <= journal.lease.acquiredAt
        )) ||
        (journal.completedAt !== null && (
          journal.lease !== null || journal.completedAt > journal.updatedAt ||
            journal.actions.length !== CUSTOMER_STAGE2_ACTION_ORDER.length ||
            journal.actions.some((action) => action.phase !== 'verified')))) return null;
    journal.actions.forEach((action, index) => validateAction(action, index, journal.updatedAt));
    assertSecretFree(journal);
    const serialized = canonicalJson(journal);
    if (new TextEncoder().encode(serialized).byteLength > MAX_JOURNAL_BYTES) return null;
    return deepFreezePlainData(journal);
  } catch {
    return null;
  }
}

function requireJournal(value: CustomerStage2Journal): CustomerStage2Journal {
  const parsed = parseCustomerStage2Journal(value);
  if (parsed === null) fail('invalid');
  return parsed;
}

function next(journal: CustomerStage2Journal, update: Partial<CustomerStage2Journal>, now: number) {
  validTime(now);
  if (now < journal.updatedAt) fail('conflict');
  const candidate = requireJournal({
    ...journal,
    ...update,
    revision: journal.revision + 1,
    updatedAt: now,
  });
  return candidate;
}

function assertLease(journal: CustomerStage2Journal, attemptId: string, now: number): void {
  validTime(now);
  if (!ATTEMPT_ID.test(attemptId)) fail('invalid');
  if (journal.completedAt !== null) fail('complete');
  if (journal.lease?.attemptId !== attemptId) fail('conflict');
  if (journal.lease.expiresAt <= now) fail('lease_expired');
}

export function createCustomerStage2Journal(input: {
  readonly now: number;
  readonly leaseExpiresAt: number;
  readonly attemptId: string;
  readonly identity: CustomerStage2Identity;
  readonly organization: CustomerStage2Organization;
  readonly identityProviderIds: readonly string[];
  readonly workersSubdomain: string;
  readonly preflight: CustomerGatewayFreshPreflightAttestation;
}): CustomerStage2Journal {
  validTime(input.now);
  validTime(input.leaseExpiresAt);
  if (!ATTEMPT_ID.test(input.attemptId) || input.leaseExpiresAt <= input.now ||
      input.preflight.checkedAt > input.now || input.preflight.expiresAt <= input.now ||
      input.preflight.accountId !== input.identity.accountId ||
      input.preflight.zoneId !== input.identity.zoneId ||
      input.preflight.planId !== input.identity.planId ||
      input.preflight.planHash !== input.identity.planHash ||
      input.preflight.installationId !== input.identity.installId ||
      input.preflight.configurationHash !== input.identity.configurationHash ||
      input.preflight.desiredHash !== input.identity.desiredHash ||
      input.preflight.releaseId !== input.identity.releaseId ||
      input.preflight.releaseArtifactSha256 !== input.identity.releaseArtifactSha256) fail('invalid');
  const ids = [...input.identityProviderIds].sort();
  const candidate = {
    schemaVersion: 1 as const,
    revision: 1,
    createdAt: input.now,
    updatedAt: input.now,
    identity: { ...input.identity },
    organization: { ...input.organization },
    identityProviderIds: ids,
    workersSubdomain: input.workersSubdomain,
    preflight: {
      attestationHash: input.preflight.attestationHash,
      checkedAt: input.preflight.checkedAt,
      expiresAt: input.preflight.expiresAt,
    },
    lease: { attemptId: input.attemptId, acquiredAt: input.now, expiresAt: input.leaseExpiresAt },
    actions: [],
    completedAt: null,
  };
  return requireJournal(candidate);
}

export function acquireCustomerStage2Lease(
  value: CustomerStage2Journal,
  input: { readonly attemptId: string; readonly now: number; readonly leaseExpiresAt: number },
): CustomerStage2Journal {
  const journal = requireJournal(value);
  validTime(input.now);
  validTime(input.leaseExpiresAt);
  if (!ATTEMPT_ID.test(input.attemptId) || input.leaseExpiresAt <= input.now ||
      journal.completedAt !== null) fail(journal.completedAt === null ? 'invalid' : 'complete');
  if (journal.lease !== null && journal.lease.attemptId !== input.attemptId &&
      journal.lease.expiresAt > input.now) fail('conflict');
  if (journal.lease?.attemptId === input.attemptId && journal.lease.expiresAt > input.now) return journal;
  return next(journal, {
    lease: { attemptId: input.attemptId, acquiredAt: input.now, expiresAt: input.leaseExpiresAt },
  }, input.now);
}

export function renewCustomerStage2Lease(
  value: CustomerStage2Journal,
  input: { readonly attemptId: string; readonly now: number; readonly leaseExpiresAt: number },
): CustomerStage2Journal {
  const journal = requireJournal(value);
  assertLease(journal, input.attemptId, input.now);
  const lease = journal.lease;
  if (lease === null || !Number.isSafeInteger(input.leaseExpiresAt) ||
      input.leaseExpiresAt <= lease.expiresAt) {
    fail('invalid');
  }
  return next(journal, {
    lease: { ...lease, expiresAt: input.leaseExpiresAt },
  }, input.now);
}

export function releaseCustomerStage2Lease(
  value: CustomerStage2Journal,
  input: { readonly attemptId: string; readonly now: number },
): CustomerStage2Journal {
  const journal = requireJournal(value);
  assertLease(journal, input.attemptId, input.now);
  return next(journal, { lease: null }, input.now);
}

export function customerStage2Action(
  journal: CustomerStage2Journal,
  name: CustomerStage2ActionName,
): CustomerStage2Action | null {
  const parsed = requireJournal(journal);
  return parsed.actions.find((action) => action.name === name) ?? null;
}

export function prepareCustomerStage2Action(
  value: CustomerStage2Journal,
  input: { readonly attemptId: string; readonly now: number; readonly name: CustomerStage2ActionName; readonly record: JsonObject },
): CustomerStage2Journal {
  const journal = requireJournal(value);
  assertLease(journal, input.attemptId, input.now);
  if (input.name !== CUSTOMER_STAGE2_ACTION_ORDER[journal.actions.length]) fail('conflict');
  try {
    assertSecretFree(input.record);
  } catch {
    fail('invalid');
  }
  const action: CustomerStage2Action = {
    name: input.name,
    phase: 'prepared',
    record: input.record,
    locator: null,
    preparedAt: input.now,
    sendArmedAt: null,
    submittedAt: null,
    verifiedAt: null,
  };
  return next(journal, { actions: [...journal.actions, action] }, input.now);
}

function replaceAction(
  journal: CustomerStage2Journal,
  index: number,
  action: CustomerStage2Action,
  now: number,
): CustomerStage2Journal {
  const actions = [...journal.actions];
  actions[index] = action;
  return next(journal, { actions }, now);
}

export function armCustomerStage2Action(
  value: CustomerStage2Journal,
  input: { readonly attemptId: string; readonly now: number; readonly name: CustomerStage2ActionName },
): CustomerStage2Journal {
  const journal = requireJournal(value);
  assertLease(journal, input.attemptId, input.now);
  const index = CUSTOMER_STAGE2_ACTION_ORDER.indexOf(input.name);
  const action = journal.actions[index];
  if (!action || action.phase !== 'prepared' ||
      journal.actions.slice(0, index).some((item) => item.phase !== 'verified')) fail('conflict');
  return replaceAction(journal, index, {
    ...action,
    phase: 'send_armed',
    sendArmedAt: input.now,
  }, input.now);
}

export function submitCustomerStage2Action(
  value: CustomerStage2Journal,
  input: {
    readonly attemptId: string;
    readonly now: number;
    readonly name: CustomerStage2ActionName;
    readonly locator: JsonValue;
  },
): CustomerStage2Journal {
  const journal = requireJournal(value);
  assertLease(journal, input.attemptId, input.now);
  const index = CUSTOMER_STAGE2_ACTION_ORDER.indexOf(input.name);
  const action = journal.actions[index];
  if (!action || action.phase !== 'send_armed' || input.locator === null) fail('conflict');
  try {
    assertSecretFree(input.locator);
  } catch {
    fail('invalid');
  }
  return replaceAction(journal, index, {
    ...action,
    phase: 'submitted',
    locator: input.locator,
    submittedAt: input.now,
  }, input.now);
}

export function verifyCustomerStage2Action(
  value: CustomerStage2Journal,
  input: { readonly attemptId: string; readonly now: number; readonly name: CustomerStage2ActionName },
): CustomerStage2Journal {
  const journal = requireJournal(value);
  assertLease(journal, input.attemptId, input.now);
  const index = CUSTOMER_STAGE2_ACTION_ORDER.indexOf(input.name);
  const action = journal.actions[index];
  if (!action || action.phase !== 'submitted' || action.locator === null) fail('conflict');
  return replaceAction(journal, index, {
    ...action,
    phase: 'verified',
    verifiedAt: input.now,
  }, input.now);
}

export function completeCustomerStage2Journal(
  value: CustomerStage2Journal,
  input: { readonly attemptId: string; readonly now: number },
): CustomerStage2Journal {
  const journal = requireJournal(value);
  assertLease(journal, input.attemptId, input.now);
  if (journal.actions.length !== CUSTOMER_STAGE2_ACTION_ORDER.length ||
      journal.actions.some((action) => action.phase !== 'verified')) fail('conflict');
  return next(journal, { lease: null, completedAt: input.now }, input.now);
}

import * as v from 'valibot';

import { deepFreezePlainData } from './plain-data';
import { exactReleaseBundleIdentitySchema, type ExactReleaseBundleIdentity } from './exact-release-bundle';
import {
  verifyGatewayTeardownHandoff,
  type GatewayTeardownTrust,
} from './gateway-teardown-handoff';

/** The hosted job survives retirement of the customer's Worker and namespace. */
export const GATEWAY_ROOT_REMOVAL_STEPS = Object.freeze([
  'retire_namespace', 'management_domain', 'management_policy', 'management_application', 'worker',
] as const);
export type GatewayRootRemovalStep = (typeof GATEWAY_ROOT_REMOVAL_STEPS)[number];
const ATTEMPT_TTL_MS = 10 * 60 * 1_000;
const TOKEN = /^[A-Za-z0-9_-]{43}$/u;
const HASH = /^sha256:[a-f0-9]{64}$/u;
const time = v.pipe(v.number(), v.safeInteger(), v.minValue(0));
const attemptSchema = v.strictObject({
  id: v.pipe(v.string(), v.regex(/^attempt_[A-Za-z0-9_-]{24}$/u)),
  stateHash: v.pipe(v.string(), v.regex(TOKEN)),
  verifierHash: v.pipe(v.string(), v.regex(TOKEN)),
  issuedAt: time,
  expiresAt: time,
});
const jobSchema = v.strictObject({
  schemaVersion: v.literal(1),
  revision: v.pipe(v.number(), v.safeInteger(), v.minValue(1)),
  handoff: v.pipe(v.string(), v.minLength(1), v.maxLength(32 * 1024)),
  handoffSha256: v.pipe(v.string(), v.regex(HASH)),
  release: exactReleaseBundleIdentitySchema,
  retirementModuleSha256: v.pipe(v.string(), v.regex(/^[a-f0-9]{64}$/u)),
  acceptedAt: time,
  updatedAt: time,
  phase: v.picklist(['review', 'authorizing', 'exchanging', 'recovery_required', 'removed', 'removed_revocation_unconfirmed']),
  attempt: v.union([attemptSchema, v.null()]),
  verifiedSteps: v.pipe(v.array(v.picklist(GATEWAY_ROOT_REMOVAL_STEPS)), v.maxLength(GATEWAY_ROOT_REMOVAL_STEPS.length)),
  pendingStep: v.union([v.picklist(GATEWAY_ROOT_REMOVAL_STEPS), v.null()]),
  pendingAttemptId: v.union([v.pipe(v.string(), v.regex(/^attempt_[A-Za-z0-9_-]{24}$/u)), v.null()]),
  revocation: v.picklist(['not_attempted', 'confirmed', 'unconfirmed']),
  failureReason: v.nullable(v.pipe(v.string(), v.regex(/^[a-z][a-z0-9_]{0,95}$/u))),
});
export type GatewayTeardownJob = v.InferOutput<typeof jobSchema>;
export type GatewayTeardownAttempt = v.InferOutput<typeof attemptSchema>;

function conflict(): never { throw new Error('teardown_job_conflict'); }

/** Stored authority is secret-free; raw OAuth state, verifier, code, and grant are not fields. */
export function parseGatewayTeardownJob<Input>(value: Input): GatewayTeardownJob {
  const job = v.parse(jobSchema, value);
  const terminal = ['removed', 'removed_revocation_unconfirmed'].includes(job.phase);
  if (job.acceptedAt > job.updatedAt ||
      job.verifiedSteps.some((step, index) => step !== GATEWAY_ROOT_REMOVAL_STEPS[index]) ||
      (job.pendingStep !== null && job.pendingStep !== GATEWAY_ROOT_REMOVAL_STEPS[job.verifiedSteps.length]) ||
      (terminal && (job.verifiedSteps.length !== GATEWAY_ROOT_REMOVAL_STEPS.length ||
        job.pendingStep !== null || job.attempt !== null ||
        job.revocation !== (job.phase === 'removed' ? 'confirmed' : 'unconfirmed'))) ||
      ((job.pendingStep === null) !== (job.pendingAttemptId === null)) ||
      (['authorizing', 'exchanging'].includes(job.phase) !== (job.attempt !== null)) ||
      (job.phase === 'review' && (job.verifiedSteps.length !== 0 || job.pendingStep !== null)) ||
      (job.attempt !== null && (job.attempt.issuedAt < job.acceptedAt ||
        job.attempt.issuedAt > job.updatedAt || job.attempt.expiresAt - job.attempt.issuedAt !== ATTEMPT_TTL_MS))) conflict();
  return deepFreezePlainData(job);
}

export async function createGatewayTeardownJob(input: {
  readonly handoff: string;
  readonly trust: GatewayTeardownTrust;
  readonly release: ExactReleaseBundleIdentity;
  readonly retirementModuleSha256: string;
  readonly now: number;
}): Promise<GatewayTeardownJob> {
  const verified = await verifyGatewayTeardownHandoff(input);
  return parseGatewayTeardownJob({
    schemaVersion: 1, revision: 1,
    handoff: input.handoff, handoffSha256: verified.handoffSha256,
    release: input.release, retirementModuleSha256: input.retirementModuleSha256,
    acceptedAt: input.now, updatedAt: input.now, phase: 'review', attempt: null,
    verifiedSteps: [], pendingStep: null, pendingAttemptId: null,
    revocation: verified.statement.priorGrantRevocationUnconfirmed ? 'unconfirmed' : 'not_attempted', failureReason: null,
  });
}

/**
 * A retry re-verifies the exact accepted handoff at its original import time.
 * Expiry prevents a new import; it does not strand an already authorized job
 * after the customer's management surface has gone. Every retry still needs
 * a fresh provider grant and exact resource read-back.
 */
export async function verifyGatewayTeardownJobAuthority(input: {
  readonly job: GatewayTeardownJob;
  readonly trust: GatewayTeardownTrust;
}) {
  const job = parseGatewayTeardownJob(input.job);
  const verified = await verifyGatewayTeardownHandoff({
    handoff: job.handoff, trust: input.trust, now: job.acceptedAt,
  });
  if (verified.handoffSha256 !== job.handoffSha256) conflict();
  return verified;
}

function next(job: GatewayTeardownJob, change: Partial<GatewayTeardownJob>, now: number): GatewayTeardownJob {
  parseGatewayTeardownJob(job);
  if (!Number.isSafeInteger(now) || now < job.updatedAt) conflict();
  return parseGatewayTeardownJob({ ...job, ...change, revision: job.revision + 1, updatedAt: now });
}

export function authorizeGatewayTeardownJob(input: {
  readonly job: GatewayTeardownJob;
  readonly attemptId: string;
  readonly stateHash: string;
  readonly verifierHash: string;
  readonly now: number;
}): GatewayTeardownJob {
  const { job, now } = input;
  if (['removed', 'removed_revocation_unconfirmed'].includes(job.phase) ||
      (job.attempt !== null && (job.attempt.expiresAt > now || job.attempt.id === input.attemptId)) ||
      job.pendingAttemptId === input.attemptId) conflict();
  // An interrupted exchange may already have received a grant. A new consent
  // cannot establish that the previous request revoked it.
  const revocationUnconfirmed = job.revocation === 'unconfirmed' || job.phase === 'exchanging';
  return next(job, {
    phase: 'authorizing', failureReason: null, revocation: revocationUnconfirmed ? 'unconfirmed' : 'not_attempted',
    attempt: { id: input.attemptId, stateHash: input.stateHash, verifierHash: input.verifierHash,
      issuedAt: now, expiresAt: now + ATTEMPT_TTL_MS },
  }, now);
}

export function consumeGatewayTeardownCallback(input: {
  readonly job: GatewayTeardownJob;
  readonly attemptId: string;
  readonly stateHash: string;
  readonly verifierHash: string;
  readonly now: number;
}): GatewayTeardownJob {
  const { job, now } = input;
  if (job.phase !== 'authorizing' || job.attempt === null || job.attempt.id !== input.attemptId ||
      job.attempt.stateHash !== input.stateHash || job.attempt.verifierHash !== input.verifierHash ||
      job.attempt.expiresAt <= now) conflict();
  // Persist this transition before exchanging a code; a callback cannot run twice.
  return next(job, { phase: 'exchanging' }, now);
}

function active(job: GatewayTeardownJob, attemptId: string, now: number): void {
  if (job.phase !== 'exchanging' || job.attempt?.id !== attemptId || job.attempt.expiresAt <= now) conflict();
}

export function armGatewayRootRemoval(input: {
  readonly job: GatewayTeardownJob;
  readonly attemptId: string;
  readonly step: GatewayRootRemovalStep;
  readonly now: number;
}): GatewayTeardownJob {
  active(input.job, input.attemptId, input.now);
  if ((input.job.pendingStep !== null && input.job.pendingAttemptId === input.attemptId) ||
      input.step !== GATEWAY_ROOT_REMOVAL_STEPS[input.job.verifiedSteps.length]) conflict();
  return next(input.job, { pendingStep: input.step, pendingAttemptId: input.attemptId }, input.now);
}

/** Called only after exact provider absence (or verified signed namespace retirement). */
export function verifyGatewayRootRemoval(input: {
  readonly job: GatewayTeardownJob;
  readonly attemptId: string;
  readonly step: GatewayRootRemovalStep;
  readonly now: number;
}): GatewayTeardownJob {
  active(input.job, input.attemptId, input.now);
  if (input.job.pendingStep !== input.step) conflict();
  return next(input.job, { verifiedSteps: [...input.job.verifiedSteps, input.step], pendingStep: null, pendingAttemptId: null }, input.now);
}

/** A failed or expired request retains the ambiguous boundary for the next consent. */
export function settleGatewayTeardownAttempt(input: {
  readonly job: GatewayTeardownJob;
  readonly attemptId: string;
  readonly revocation: 'confirmed' | 'unconfirmed';
  readonly reason?: string | null;
  readonly now: number;
}): GatewayTeardownJob {
  const { job } = input;
  if (job.attempt?.id !== input.attemptId) conflict();
  const complete = job.phase === 'exchanging' && job.pendingStep === null &&
    job.verifiedSteps.length === GATEWAY_ROOT_REMOVAL_STEPS.length;
  const revocation = job.revocation === 'unconfirmed' ? 'unconfirmed' : input.revocation;
  let phase: GatewayTeardownJob['phase'] = 'recovery_required';
  if (complete) phase = revocation === 'confirmed' ? 'removed' : 'removed_revocation_unconfirmed';
  return next(job, { phase, attempt: null, revocation, failureReason: complete ? null : input.reason ?? null }, input.now);
}

/** A fresh, equivalent gateway proof may carry an earlier unconfirmed revocation. */
export function retainGatewayTeardownRevocationWarning(job: GatewayTeardownJob, now: number): GatewayTeardownJob {
  if (job.phase.startsWith('removed')) conflict();
  return next(job, { revocation: 'unconfirmed' }, now);
}

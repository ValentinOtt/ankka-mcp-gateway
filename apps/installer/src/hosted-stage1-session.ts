import * as v from 'valibot';

import { boundaryObjectSchema, type BoundaryObject } from './boundary';
import { canonicalJson } from './canonical-json';
import {
  base64UrlEncode,
  constantTimeEqual,
  pkceChallenge,
  randomBase64Url,
  sha256,
  sha256Hex,
  type SealedBootstrapCookie,
} from './crypto';
import type { BootstrapRandomBytes } from './customer-bootstrap-state';
import {
  parseHostedStage1Provision,
  type HostedStage1Provision,
} from './hosted-stage1-bootstrap';
import {
  deploySelectionFromStaticPlan,
  forbiddenStoredKeyPath,
  parseDeploySelection,
  parseStaticDeployPlan,
  verifyStaticDeployPlanIntegrity,
  type DeploySelection,
  type StaticDeployPlan,
} from './schema';

/**
 * Secret-free hosted Stage 1 session model.
 *
 * Everything recoverable about one deploy.ankka.ai install lives here: the
 * normalized customer selection, the frozen static plan, exact attempt
 * commitments (hashes only), the provider identities read back after the
 * Stage 1 grant was revoked, and the deterministic cleanup marker when the
 * browser lost the one-time capability. The raw OAuth state, PKCE verifier,
 * authorization code, access token, capability secret, bootstrap nonce, and
 * ownership wrapping key never enter this state; they travel only inside the
 * encrypted short-lived bootstrap cookie.
 */

const SESSION_ID = /^s1s_[A-Za-z0-9_-]{24}$/u;
const ATTEMPT_ID = /^attempt_[A-Za-z0-9_-]{24}$/u;
const TOKEN = /^[A-Za-z0-9_-]{43}$/u;
const COMMITMENT = /^sha256:[a-f0-9]{64}$/u;
const BOOTSTRAP_ID = /^boot_[A-Za-z0-9_-]{24}$/u;

/** A draft session may be edited for this long before it must be started over. */
export const HOSTED_STAGE1_SESSION_TTL_MS = 60 * 60 * 1_000;
/** A fresh cleanup authorization must complete within this window. */
export const HOSTED_STAGE1_CLEANUP_ATTEMPT_TTL_MS = 10 * 60 * 1_000;
/** Upper bound for one canonical serialized session, enforced by the durable port too. */
export const MAX_HOSTED_STAGE1_SESSION_BYTES = 64 * 1_024;

const timestampSchema = v.pipe(v.number(), v.safeInteger(), v.minValue(0));
const phaseSchema = v.picklist([
  'draft',
  'authorizing',
  'provisioned',
  'handed_off',
  'failed',
  'cleanup_required',
]);
const failureCodeSchema = v.picklist([
  'attempt_expired',
  'authorization_rejected',
  'callback_invalid',
  'cleanup_failed',
  'grant_invalid',
  'provision_failed',
  'revocation_unconfirmed',
  'session_expired',
]);
const cleanupReasonSchema = v.picklist([
  'capability_expired',
  'cookie_lost',
  'handoff_rejected',
]);
const capabilityCommitmentSchema = v.strictObject({
  bootstrapId: v.pipe(v.string(), v.regex(BOOTSTRAP_ID)),
  secretCommitment: v.pipe(v.string(), v.regex(COMMITMENT)),
  expiresAt: timestampSchema,
});
const attemptSchema = v.strictObject({
  attemptId: v.pipe(v.string(), v.regex(ATTEMPT_ID)),
  kind: v.picklist(['bootstrap', 'cleanup']),
  status: v.picklist(['authorizing', 'exchanging']),
  stateHash: v.pipe(v.string(), v.regex(TOKEN)),
  verifierHash: v.pipe(v.string(), v.regex(TOKEN)),
  startedAt: timestampSchema,
  expiresAt: timestampSchema,
  capability: v.union([capabilityCommitmentSchema, v.null()]),
});
const failureSchema = v.strictObject({
  code: failureCodeSchema,
  attemptId: v.union([v.pipe(v.string(), v.regex(ATTEMPT_ID)), v.null()]),
  at: timestampSchema,
});
const cleanupSchema = v.strictObject({
  reason: cleanupReasonSchema,
  requiredAt: timestampSchema,
  completedAt: v.union([timestampSchema, v.null()]),
});
const sessionSchema = v.strictObject({
  schemaVersion: v.literal(1),
  revision: v.pipe(v.number(), v.safeInteger(), v.minValue(1)),
  sessionId: v.pipe(v.string(), v.regex(SESSION_ID)),
  phase: phaseSchema,
  createdAt: timestampSchema,
  updatedAt: timestampSchema,
  expiresAt: timestampSchema,
  selection: v.union([boundaryObjectSchema, v.null()]),
  plan: v.union([boundaryObjectSchema, v.null()]),
  provision: v.union([boundaryObjectSchema, v.null()]),
  attempt: v.union([attemptSchema, v.null()]),
  provisionedAttemptId: v.union([v.pipe(v.string(), v.regex(ATTEMPT_ID)), v.null()]),
  handedOffAt: v.union([timestampSchema, v.null()]),
  failure: v.union([failureSchema, v.null()]),
  cleanup: v.union([cleanupSchema, v.null()]),
});

type ParsedSession = v.InferOutput<typeof sessionSchema>;

export type HostedStage1Phase = v.InferOutput<typeof phaseSchema>;
export type HostedStage1FailureCode = v.InferOutput<typeof failureCodeSchema>;
export type HostedStage1CleanupReason = v.InferOutput<typeof cleanupReasonSchema>;
export type HostedStage1Attempt = v.InferOutput<typeof attemptSchema>;
export type HostedStage1Failure = v.InferOutput<typeof failureSchema>;
export type HostedStage1Cleanup = v.InferOutput<typeof cleanupSchema>;

export const HOSTED_STAGE1_FAILURE_CODES: readonly HostedStage1FailureCode[] = Object.freeze(
  [...failureCodeSchema.options],
);
export const HOSTED_STAGE1_CLEANUP_REASONS: readonly HostedStage1CleanupReason[] = Object.freeze(
  [...cleanupReasonSchema.options],
);

export interface HostedStage1Session {
  readonly schemaVersion: 1;
  readonly revision: number;
  readonly sessionId: string;
  readonly phase: HostedStage1Phase;
  readonly createdAt: number;
  readonly updatedAt: number;
  readonly expiresAt: number;
  readonly selection: DeploySelection | null;
  readonly plan: StaticDeployPlan | null;
  readonly provision: HostedStage1Provision | null;
  readonly attempt: HostedStage1Attempt | null;
  readonly provisionedAttemptId: string | null;
  readonly handedOffAt: number | null;
  readonly failure: HostedStage1Failure | null;
  readonly cleanup: HostedStage1Cleanup | null;
}

/** The only capability facts the durable session ever sees; the secret stays in the cookie. */
export interface HostedStage1CapabilityCommitment {
  readonly bootstrapId: string;
  readonly secretCommitment: string;
  readonly expiresAt: number;
}

/** Request-local authorization material; the runtime seals it into the bootstrap cookie at once. */
export interface HostedStage1AuthorizationStart {
  readonly attemptId: string;
  readonly kind: 'bootstrap' | 'cleanup';
  readonly state: string;
  readonly verifier: string;
  readonly challenge: string;
  readonly expiresAt: number;
  readonly next: HostedStage1Session;
}

export type HostedStage1Reap =
  | { readonly action: 'erase' }
  | { readonly action: 'retain' }
  | { readonly action: 'replace'; readonly next: HostedStage1Session };

export interface HostedStage1PublicSession {
  readonly schemaVersion: 1;
  readonly sessionId: string;
  readonly phase: HostedStage1Phase;
  readonly revision: number;
  readonly expiresAt: number;
  readonly selection: DeploySelection | null;
  readonly plan: Readonly<{
    planId: string;
    releaseId: string;
    expiresAt: number;
    managementHostname: string;
    portalHostname: string;
  }> | null;
  readonly attempt: Readonly<{ attemptId: string; kind: 'bootstrap' | 'cleanup'; expiresAt: number }> | null;
  readonly provision: Readonly<{
    installId: string;
    workerName: string;
    bootstrapOrigin: string;
    capabilityExpiresAt: number;
  }> | null;
  readonly failure: HostedStage1Failure | null;
  readonly cleanup: HostedStage1Cleanup | null;
}

export class HostedStage1SessionError extends Error {
  constructor(readonly code: 'invalid' | 'expired' | 'consumed' | 'phase' | 'conflict') {
    super(code);
    this.name = 'HostedStage1SessionError';
  }
}

function invalid(): never {
  throw new HostedStage1SessionError('invalid');
}

function wrongPhase(): never {
  throw new HostedStage1SessionError('phase');
}

function validNow(now: number): void {
  if (!Number.isSafeInteger(now) || now < 0) invalid();
}

function randomToken(randomBytes?: BootstrapRandomBytes): string {
  if (randomBytes === undefined) return randomBase64Url(32);
  const bytes = randomBytes(32);
  if (!(bytes instanceof Uint8Array) || bytes.byteLength !== 32) invalid();
  const encoded = base64UrlEncode(bytes);
  bytes.fill(0);
  return encoded;
}

function randomShortToken(randomBytes?: BootstrapRandomBytes): string {
  if (randomBytes === undefined) return randomBase64Url(18);
  const bytes = randomBytes(18);
  if (!(bytes instanceof Uint8Array) || bytes.byteLength !== 18) invalid();
  const encoded = base64UrlEncode(bytes);
  bytes.fill(0);
  return encoded;
}

function exactSelection(value: BoundaryObject | null): DeploySelection | null {
  if (value === null) return null;
  let parsed: DeploySelection;
  try {
    parsed = parseDeploySelection(value);
  } catch {
    invalid();
  }
  if (canonicalJson(parsed) !== canonicalJson(value)) invalid();
  return parsed;
}

function exactPlan(value: BoundaryObject | null): StaticDeployPlan | null {
  if (value === null) return null;
  let parsed: StaticDeployPlan;
  try {
    parsed = parseStaticDeployPlan(value);
  } catch {
    invalid();
  }
  if (canonicalJson(parsed) !== canonicalJson(value)) invalid();
  return parsed;
}

function exactProvision(value: BoundaryObject | null): HostedStage1Provision | null {
  if (value === null) return null;
  let parsed: HostedStage1Provision;
  try {
    parsed = parseHostedStage1Provision(value);
  } catch {
    invalid();
  }
  if (canonicalJson(parsed) !== canonicalJson(value)) invalid();
  return parsed;
}

function provisionMatchesPlan(provision: HostedStage1Provision, plan: StaticDeployPlan): boolean {
  return provision.plan.id === plan.planId &&
    provision.plan.hash === plan.planHash &&
    provision.release.id === plan.releaseId &&
    provision.release.artifactSha256 === plan.releaseArtifactSha256 &&
    provision.installId === plan.managementOwnershipMarker;
}

function phaseInvariantsHold(session: HostedStage1Session): boolean {
  const {
    phase, selection, plan, provision, attempt, provisionedAttemptId, handedOffAt, failure, cleanup,
  } = session;
  const planMatchesSelection = plan === null || (selection !== null &&
    canonicalJson(deploySelectionFromStaticPlan(plan)) === canonicalJson(selection));
  const provisionConsistent = provision === null ||
    (plan !== null && provisionMatchesPlan(provision, plan));
  if (!planMatchesSelection || !provisionConsistent) return false;
  if (session.updatedAt < session.createdAt || session.expiresAt <= session.createdAt) return false;
  switch (phase) {
    case 'draft':
      return attempt === null && provision === null && provisionedAttemptId === null &&
        handedOffAt === null && failure === null &&
        (cleanup === null || cleanup.completedAt !== null);
    case 'authorizing':
      return selection !== null && plan !== null && provision === null &&
        provisionedAttemptId === null && handedOffAt === null && failure === null &&
        attempt !== null && attempt.kind === 'bootstrap' && attempt.capability !== null &&
        attempt.capability.expiresAt === attempt.expiresAt &&
        attempt.expiresAt <= plan.expiresAt &&
        (cleanup === null || cleanup.completedAt !== null);
    case 'provisioned':
      return plan !== null && provision !== null && attempt === null &&
        provisionedAttemptId !== null && handedOffAt === null && failure === null &&
        (cleanup === null || cleanup.completedAt !== null);
    case 'handed_off':
      return plan !== null && provision !== null && attempt === null &&
        provisionedAttemptId !== null && handedOffAt !== null && failure === null &&
        (cleanup === null || cleanup.completedAt !== null);
    case 'failed':
      return attempt === null && provision === null && provisionedAttemptId === null &&
        handedOffAt === null && failure !== null &&
        (cleanup === null || cleanup.completedAt !== null);
    case 'cleanup_required':
      return plan !== null && provision !== null && provisionedAttemptId !== null &&
        handedOffAt === null && cleanup !== null && cleanup.completedAt === null &&
        (attempt === null || (attempt.kind === 'cleanup' && attempt.capability === null));
    default:
      return false;
  }
}

function frozen(input: ParsedSession): HostedStage1Session {
  if (forbiddenStoredKeyPath(input) !== null) invalid();
  const session: HostedStage1Session = Object.freeze({
    schemaVersion: input.schemaVersion,
    revision: input.revision,
    sessionId: input.sessionId,
    phase: input.phase,
    createdAt: input.createdAt,
    updatedAt: input.updatedAt,
    expiresAt: input.expiresAt,
    selection: exactSelection(input.selection),
    plan: exactPlan(input.plan),
    provision: exactProvision(input.provision),
    attempt: input.attempt === null ? null : Object.freeze({
      ...input.attempt,
      capability: input.attempt.capability === null ? null : Object.freeze(input.attempt.capability),
    }),
    provisionedAttemptId: input.provisionedAttemptId,
    handedOffAt: input.handedOffAt,
    failure: input.failure === null ? null : Object.freeze(input.failure),
    cleanup: input.cleanup === null ? null : Object.freeze(input.cleanup),
  });
  if (!phaseInvariantsHold(session)) invalid();
  if (new TextEncoder().encode(canonicalJson(session)).byteLength > MAX_HOSTED_STAGE1_SESSION_BYTES) {
    invalid();
  }
  return session;
}

function validated(candidate: HostedStage1Session): HostedStage1Session {
  const parsed = v.safeParse(sessionSchema, candidate);
  if (!parsed.success) invalid();
  return frozen(parsed.output);
}

function advance(current: HostedStage1Session, now: number, patch: Partial<HostedStage1Session>): HostedStage1Session {
  return validated({ ...current, ...patch, revision: current.revision + 1, updatedAt: now });
}

/** Parses durable or transported state; returns null for anything not exactly this contract. */
export function parseHostedStage1Session<Input>(input: Input): HostedStage1Session | null {
  const parsed = v.safeParse(sessionSchema, input);
  if (!parsed.success) return null;
  try {
    return frozen(parsed.output);
  } catch (error) {
    if (error instanceof HostedStage1SessionError) return null;
    throw error;
  }
}

function currentSession(input: HostedStage1Session, now: number): HostedStage1Session {
  validNow(now);
  const current = parseHostedStage1Session(input);
  if (current === null) invalid();
  return current;
}

function requireLive(current: HostedStage1Session, now: number): void {
  if (current.expiresAt <= now) throw new HostedStage1SessionError('expired');
}

export function initializeHostedStage1Session(input: {
  readonly now: number;
  readonly randomBytes?: BootstrapRandomBytes | undefined;
}): HostedStage1Session {
  validNow(input.now);
  return validated({
    schemaVersion: 1,
    revision: 1,
    sessionId: `s1s_${randomShortToken(input.randomBytes)}`,
    phase: 'draft',
    createdAt: input.now,
    updatedAt: input.now,
    expiresAt: input.now + HOSTED_STAGE1_SESSION_TTL_MS,
    selection: null,
    plan: null,
    provision: null,
    attempt: null,
    provisionedAttemptId: null,
    handedOffAt: null,
    failure: null,
    cleanup: null,
  });
}

/** Stores the normalized nontechnical selection and discards any plan derived from an older one. */
export function saveHostedStage1Selection(input: {
  readonly current: HostedStage1Session;
  readonly selection: DeploySelection;
  readonly now: number;
}): HostedStage1Session {
  const current = currentSession(input.current, input.now);
  requireLive(current, input.now);
  if (current.phase !== 'draft' && current.phase !== 'failed') wrongPhase();
  const selection = parseDeploySelection(input.selection);
  return advance(current, input.now, {
    phase: 'draft',
    selection,
    plan: null,
    failure: null,
  });
}

/** Freezes the exact static plan for the stored selection after recomputing both plan commitments. */
export async function freezeHostedStage1Plan(input: {
  readonly current: HostedStage1Session;
  readonly plan: StaticDeployPlan;
  readonly now: number;
}): Promise<HostedStage1Session> {
  const current = currentSession(input.current, input.now);
  requireLive(current, input.now);
  if (current.phase !== 'draft' && current.phase !== 'failed') wrongPhase();
  if (current.selection === null) wrongPhase();
  const plan = await verifyStaticDeployPlanIntegrity(input.plan);
  if (plan.expiresAt <= input.now ||
      canonicalJson(deploySelectionFromStaticPlan(plan)) !== canonicalJson(current.selection)) invalid();
  return advance(current, input.now, { phase: 'draft', plan, failure: null });
}

async function startAttempt(input: {
  readonly current: HostedStage1Session;
  readonly now: number;
  readonly kind: 'bootstrap' | 'cleanup';
  readonly expiresAt: number;
  readonly capability: HostedStage1Attempt['capability'];
  readonly phase: HostedStage1Phase;
  readonly randomBytes: BootstrapRandomBytes | undefined;
}): Promise<HostedStage1AuthorizationStart> {
  const state = randomToken(input.randomBytes);
  const verifier = randomToken(input.randomBytes);
  const attemptId = `attempt_${randomShortToken(input.randomBytes)}`;
  const attempt: HostedStage1Attempt = Object.freeze({
    attemptId,
    kind: input.kind,
    status: 'authorizing',
    stateHash: await sha256(state),
    verifierHash: await sha256(verifier),
    startedAt: input.now,
    expiresAt: input.expiresAt,
    capability: input.capability,
  });
  const next = advance(input.current, input.now, { phase: input.phase, attempt, failure: null });
  return Object.freeze({
    attemptId,
    kind: input.kind,
    state,
    verifier,
    challenge: await pkceChallenge(verifier),
    expiresAt: input.expiresAt,
    next,
  });
}

/**
 * Opens exactly one Stage 1 authorization for the frozen plan. Only hashes of
 * the OAuth state and PKCE verifier and the capability commitment are kept;
 * the raw values are returned once for the encrypted bootstrap cookie.
 */
export async function authorizeHostedStage1Bootstrap(input: {
  readonly current: HostedStage1Session;
  readonly capability: HostedStage1CapabilityCommitment;
  readonly now: number;
  readonly randomBytes?: BootstrapRandomBytes | undefined;
}): Promise<HostedStage1AuthorizationStart> {
  const current = currentSession(input.current, input.now);
  requireLive(current, input.now);
  if (current.phase !== 'draft' && current.phase !== 'failed') wrongPhase();
  if (current.plan === null) wrongPhase();
  const capability = input.capability;
  if (!BOOTSTRAP_ID.test(capability.bootstrapId) || !COMMITMENT.test(capability.secretCommitment) ||
      !Number.isSafeInteger(capability.expiresAt) || capability.expiresAt <= input.now ||
      capability.expiresAt > current.plan.expiresAt || current.plan.expiresAt <= input.now) invalid();
  return startAttempt({
    current,
    now: input.now,
    kind: 'bootstrap',
    expiresAt: capability.expiresAt,
    capability: Object.freeze({
      bootstrapId: capability.bootstrapId,
      secretCommitment: capability.secretCommitment,
      expiresAt: capability.expiresAt,
    }),
    phase: 'authorizing',
    randomBytes: input.randomBytes,
  });
}

/**
 * Atomically claims the provider callback before any code exchange. A second
 * callback for the same attempt, a stale attempt, or a mismatched state or
 * verifier fails here and never reaches the token endpoint.
 */
export async function consumeHostedStage1Callback(input: {
  readonly current: HostedStage1Session;
  readonly attemptId: string;
  readonly state: string;
  readonly verifier: string;
  readonly now: number;
}): Promise<HostedStage1Session> {
  const current = currentSession(input.current, input.now);
  if (!ATTEMPT_ID.test(input.attemptId) || !TOKEN.test(input.state) || !TOKEN.test(input.verifier)) invalid();
  if (current.phase !== 'authorizing' && current.phase !== 'cleanup_required') wrongPhase();
  const attempt = current.attempt;
  if (attempt === null || attempt.attemptId !== input.attemptId) invalid();
  if (attempt.status !== 'authorizing') throw new HostedStage1SessionError('consumed');
  if (attempt.expiresAt <= input.now) throw new HostedStage1SessionError('expired');
  const stateMatches = constantTimeEqual(await sha256(input.state), attempt.stateHash);
  const verifierMatches = constantTimeEqual(await sha256(input.verifier), attempt.verifierHash);
  if (!stateMatches || !verifierMatches) invalid();
  return advance(current, input.now, {
    attempt: Object.freeze({ ...attempt, status: 'exchanging' }),
  });
}

/** Records a terminal attempt failure without retaining any provider text. */
export function failHostedStage1Attempt(input: {
  readonly current: HostedStage1Session;
  readonly attemptId: string;
  readonly code: HostedStage1FailureCode;
  readonly now: number;
}): HostedStage1Session {
  const current = currentSession(input.current, input.now);
  if (!ATTEMPT_ID.test(input.attemptId) || !v.is(failureCodeSchema, input.code)) invalid();
  const attempt = current.attempt;
  if (attempt === null || attempt.attemptId !== input.attemptId) invalid();
  const failure: HostedStage1Failure = Object.freeze({
    code: input.code,
    attemptId: attempt.attemptId,
    at: input.now,
  });
  if (attempt.kind === 'cleanup') {
    if (current.phase !== 'cleanup_required') wrongPhase();
    return advance(current, input.now, { attempt: null, failure });
  }
  if (current.phase !== 'authorizing') wrongPhase();
  return advance(current, input.now, { phase: 'failed', attempt: null, failure });
}

/**
 * Persists the secret-free provision exactly once, and only when the
 * coordinator has already confirmed revocation of the Stage 1 grant.
 */
export function recordHostedStage1Provision(input: {
  readonly current: HostedStage1Session;
  readonly attemptId: string;
  readonly provision: HostedStage1Provision;
  readonly now: number;
}): HostedStage1Session {
  const current = currentSession(input.current, input.now);
  if (!ATTEMPT_ID.test(input.attemptId)) invalid();
  if (current.phase !== 'authorizing' || current.plan === null) wrongPhase();
  const attempt = current.attempt;
  if (attempt === null || attempt.attemptId !== input.attemptId || attempt.capability === null) invalid();
  if (attempt.status !== 'exchanging') wrongPhase();
  const provision = parseHostedStage1Provision(input.provision);
  if (provision.grantRevocation !== 'confirmed' ||
      provision.bootstrapId !== attempt.capability.bootstrapId ||
      provision.bootstrapSecretCommitment !== attempt.capability.secretCommitment ||
      provision.capabilityExpiresAt !== attempt.capability.expiresAt ||
      !provisionMatchesPlan(provision, current.plan)) invalid();
  return advance(current, input.now, {
    phase: 'provisioned',
    attempt: null,
    provisionedAttemptId: attempt.attemptId,
    provision,
  });
}

/** Marks the same-browser fragment handoff as released to the customer Worker origin. */
export function markHostedStage1HandedOff(input: {
  readonly current: HostedStage1Session;
  readonly bootstrapId: string;
  readonly secretCommitment: string;
  readonly now: number;
}): HostedStage1Session {
  const current = currentSession(input.current, input.now);
  if (current.phase !== 'provisioned' || current.provision === null) wrongPhase();
  if (!BOOTSTRAP_ID.test(input.bootstrapId) || !COMMITMENT.test(input.secretCommitment) ||
      current.provision.bootstrapId !== input.bootstrapId ||
      !constantTimeEqual(current.provision.bootstrapSecretCommitment, input.secretCommitment)) invalid();
  if (current.provision.capabilityExpiresAt <= input.now) throw new HostedStage1SessionError('expired');
  return advance(current, input.now, { phase: 'handed_off', handedOffAt: input.now });
}

/**
 * The capability cannot be reconstructed once the browser loses the cookie or
 * the window closes. Only exact provider identities are retained so a fresh
 * Stage 1 grant can remove precisely the recorded Worker and namespace.
 */
export function markHostedStage1CleanupRequired(input: {
  readonly current: HostedStage1Session;
  readonly reason: HostedStage1CleanupReason;
  readonly now: number;
}): HostedStage1Session {
  const current = currentSession(input.current, input.now);
  if (!v.is(cleanupReasonSchema, input.reason)) invalid();
  if (current.phase !== 'provisioned') wrongPhase();
  return advance(current, input.now, {
    phase: 'cleanup_required',
    cleanup: Object.freeze({ reason: input.reason, requiredAt: input.now, completedAt: null }),
  });
}

/** Opens one fresh cleanup authorization bound to the recorded Stage 1 root. */
export async function authorizeHostedStage1Cleanup(input: {
  readonly current: HostedStage1Session;
  readonly now: number;
  readonly randomBytes?: BootstrapRandomBytes | undefined;
}): Promise<HostedStage1AuthorizationStart> {
  const current = currentSession(input.current, input.now);
  if (current.phase !== 'cleanup_required') wrongPhase();
  if (current.attempt !== null && current.attempt.expiresAt > input.now) {
    throw new HostedStage1SessionError('conflict');
  }
  return startAttempt({
    current,
    now: input.now,
    kind: 'cleanup',
    expiresAt: input.now + HOSTED_STAGE1_CLEANUP_ATTEMPT_TTL_MS,
    capability: null,
    phase: 'cleanup_required',
    randomBytes: input.randomBytes,
  });
}

/**
 * Completes exact cleanup: the recorded root is gone and the fresh grant was
 * revoked. The install marker was consumed by the removed Worker, so the plan
 * is discarded and a new one must be frozen for the retained selection.
 */
export function completeHostedStage1Cleanup(input: {
  readonly current: HostedStage1Session;
  readonly attemptId: string;
  readonly now: number;
}): HostedStage1Session {
  const current = currentSession(input.current, input.now);
  if (!ATTEMPT_ID.test(input.attemptId)) invalid();
  if (current.phase !== 'cleanup_required' || current.cleanup === null) wrongPhase();
  const attempt = current.attempt;
  if (attempt === null || attempt.attemptId !== input.attemptId || attempt.kind !== 'cleanup') invalid();
  if (attempt.status !== 'exchanging') wrongPhase();
  return advance(current, input.now, {
    phase: 'draft',
    plan: null,
    provision: null,
    attempt: null,
    provisionedAttemptId: null,
    failure: null,
    cleanup: Object.freeze({ ...current.cleanup, completedAt: input.now }),
    expiresAt: input.now + HOSTED_STAGE1_SESSION_TTL_MS,
  });
}

/**
 * Alarm-driven housekeeping. Sessions that hold nothing recoverable are erased;
 * a provisioned session whose capability lapsed before handoff becomes a
 * cleanup obligation; cleanup obligations are never dropped automatically.
 */
export function reapHostedStage1Session(input: {
  readonly current: HostedStage1Session;
  readonly now: number;
}): HostedStage1Reap {
  const current = currentSession(input.current, input.now);
  switch (current.phase) {
    case 'cleanup_required':
      return Object.freeze({ action: 'retain' });
    case 'provisioned':
      if (current.provision !== null && current.provision.capabilityExpiresAt <= input.now) {
        return Object.freeze({
          action: 'replace',
          next: markHostedStage1CleanupRequired({ current, reason: 'capability_expired', now: input.now }),
        });
      }
      return Object.freeze({ action: 'retain' });
    case 'authorizing':
      if (current.attempt !== null && current.attempt.expiresAt <= input.now) {
        return Object.freeze({
          action: 'replace',
          next: failHostedStage1Attempt({
            current,
            attemptId: current.attempt.attemptId,
            code: 'attempt_expired',
            now: input.now,
          }),
        });
      }
      return Object.freeze({ action: current.expiresAt <= input.now ? 'erase' : 'retain' });
    default:
      return Object.freeze({ action: current.expiresAt <= input.now ? 'erase' : 'retain' });
  }
}

/** Browser-facing projection: no hashes, no handoff material, no provider metadata beyond identity. */
export function publicHostedStage1Session(state: HostedStage1Session): HostedStage1PublicSession {
  const session = parseHostedStage1Session(state);
  if (session === null) invalid();
  return Object.freeze({
    schemaVersion: 1,
    sessionId: session.sessionId,
    phase: session.phase,
    revision: session.revision,
    expiresAt: session.expiresAt,
    selection: session.selection,
    plan: session.plan === null ? null : Object.freeze({
      planId: session.plan.planId,
      releaseId: session.plan.releaseId,
      expiresAt: session.plan.expiresAt,
      managementHostname: session.plan.gatewayConfiguration.managementHostname,
      portalHostname: session.plan.gatewayConfiguration.portalHostname,
    }),
    attempt: session.attempt === null ? null : Object.freeze({
      attemptId: session.attempt.attemptId,
      kind: session.attempt.kind,
      expiresAt: session.attempt.expiresAt,
    }),
    provision: session.provision === null ? null : Object.freeze({
      installId: session.provision.installId,
      workerName: session.provision.deployment.workerName,
      bootstrapOrigin: session.provision.bootstrapOrigin,
      capabilityExpiresAt: session.provision.capabilityExpiresAt,
    }),
    failure: session.failure,
    cleanup: session.cleanup,
  });
}

export interface HostedStage1CookieMatch {
  readonly phase: 'authorizing' | 'provisioned' | 'cleanup_required';
  readonly attemptId: string;
}

/**
 * Exact-matches an opened bootstrap cookie against the session's durable
 * commitments: session, attempt, plan identity, and (for a bootstrap attempt)
 * the capability commitment. Nothing from the cookie is written back.
 */
export async function matchHostedStage1Cookie(input: {
  readonly current: HostedStage1Session;
  readonly cookie: SealedBootstrapCookie;
  readonly now: number;
}): Promise<HostedStage1CookieMatch> {
  const current = currentSession(input.current, input.now);
  const cookie = input.cookie;
  if (cookie.schemaVersion !== 10 || cookie.purpose !== 'bootstrap' ||
      !SESSION_ID.test(cookie.sessionId) || !ATTEMPT_ID.test(cookie.attemptId) ||
      !TOKEN.test(cookie.state) || !TOKEN.test(cookie.verifier)) invalid();
  if (cookie.expiresAt <= input.now) throw new HostedStage1SessionError('expired');
  if (!constantTimeEqual(cookie.sessionId, current.sessionId) || current.plan === null ||
      cookie.planId !== current.plan.planId || cookie.planHash !== current.plan.planHash) invalid();

  const capabilityMatches = async (
    expected: Readonly<{ bootstrapId: string; secretCommitment: string; expiresAt: number }>,
  ): Promise<boolean> => {
    const capability = cookie.capability;
    if (cookie.kind !== 'bootstrap' || capability === null) return false;
    const presented = `sha256:${await sha256Hex(capability.capabilitySecret)}`;
    return capability.bootstrapId === expected.bootstrapId &&
      capability.capabilityExpiresAt === expected.expiresAt &&
      cookie.expiresAt === expected.expiresAt &&
      constantTimeEqual(presented, expected.secretCommitment);
  };

  switch (current.phase) {
    case 'authorizing': {
      const attempt = current.attempt;
      if (attempt === null || attempt.capability === null ||
          !constantTimeEqual(cookie.attemptId, attempt.attemptId) ||
          !await capabilityMatches(attempt.capability)) invalid();
      return Object.freeze({ phase: 'authorizing', attemptId: attempt.attemptId });
    }
    case 'provisioned': {
      const provision = current.provision;
      if (provision === null || current.provisionedAttemptId === null ||
          !constantTimeEqual(cookie.attemptId, current.provisionedAttemptId) ||
          !await capabilityMatches({
            bootstrapId: provision.bootstrapId,
            secretCommitment: provision.bootstrapSecretCommitment,
            expiresAt: provision.capabilityExpiresAt,
          })) invalid();
      return Object.freeze({ phase: 'provisioned', attemptId: current.provisionedAttemptId });
    }
    case 'cleanup_required': {
      const attempt = current.attempt;
      if (attempt === null || attempt.kind !== 'cleanup' || cookie.kind !== 'cleanup' ||
          cookie.capability !== null || cookie.expiresAt !== attempt.expiresAt ||
          !constantTimeEqual(cookie.attemptId, attempt.attemptId)) invalid();
      return Object.freeze({ phase: 'cleanup_required', attemptId: attempt.attemptId });
    }
    default:
      wrongPhase();
  }
}

import * as v from 'valibot';

import {
  base64UrlEncode,
  constantTimeEqual,
  pkceChallenge,
  randomBase64Url,
  sha256,
  sha256Hex,
} from './crypto';

const BOOTSTRAP_ID = /^boot_[A-Za-z0-9_-]{24}$/u;
const INSTALLATION_ID = /^acg-[a-f0-9]{24}$/u;
const ATTEMPT_ID = /^attempt_[A-Za-z0-9_-]{24}$/u;
const TOKEN = /^[A-Za-z0-9_-]{43}$/u;
const COMMITMENT = /^sha256:[a-f0-9]{64}$/u;

export const CUSTOMER_BOOTSTRAP_TTL_MS = 10 * 60 * 1_000;
export const CUSTOMER_BOOTSTRAP_OAUTH_TTL_MS = 5 * 60 * 1_000;
export const CUSTOMER_BOOTSTRAP_STATE_KEY = 'ankka-mcp-gateway/bootstrap-state/v1';

const bootstrapFailureCodeSchema = v.picklist([
  'authorization_rejected',
  'grant_invalid',
  'provider_recovery_required',
  'revocation_unconfirmed',
]);

const bootstrapOauthAttemptSchema = v.strictObject({
  attemptId: v.pipe(v.string(), v.regex(ATTEMPT_ID)),
  stateHash: v.pipe(v.string(), v.regex(TOKEN)),
  phase: v.picklist(['authorizing', 'exchanging']),
  expiresAt: v.pipe(v.number(), v.safeInteger()),
});

const failureReasonSchema = v.pipe(v.string(), v.regex(/^[a-z][a-z0-9_]{0,159}$/u));

const customerBootstrapStateSchema = v.strictObject({
  schemaVersion: v.literal(1),
  revision: v.pipe(v.number(), v.safeInteger(), v.minValue(1)),
  status: v.picklist(['INCOMPLETE', 'CONVERGING', 'READY']),
  installId: v.pipe(v.string(), v.regex(INSTALLATION_ID)),
  bootstrapId: v.pipe(v.string(), v.regex(BOOTSTRAP_ID)),
  secretCommitment: v.pipe(v.string(), v.regex(COMMITMENT)),
  capabilityUnused: v.boolean(),
  capabilityExpiresAt: v.pipe(v.number(), v.safeInteger()),
  session: v.union([
    v.strictObject({
      secretHash: v.pipe(v.string(), v.regex(TOKEN)),
      expiresAt: v.pipe(v.number(), v.safeInteger()),
    }),
    v.null(),
  ]),
  oauth: v.union([bootstrapOauthAttemptSchema, v.null()]),
  failureCode: v.union([bootstrapFailureCodeSchema, v.null()]),
  /** Secret-free detail behind failureCode; absent in states stored before it existed. */
  failureReason: v.optional(v.union([failureReasonSchema, v.null()]), null),
  readyAt: v.union([v.pipe(v.number(), v.safeInteger()), v.null()]),
});

export type CustomerBootstrapFailureCode = v.InferOutput<typeof bootstrapFailureCodeSchema>;
export type CustomerBootstrapOauthAttempt = v.InferOutput<typeof bootstrapOauthAttemptSchema>;
export type CustomerBootstrapState = v.InferOutput<typeof customerBootstrapStateSchema>;

export interface CustomerBootstrapCapability {
  readonly bootstrapId: string;
  readonly secret: string;
  readonly secretCommitment: string;
  readonly expiresAt: number;
}

export interface CustomerBootstrapSession {
  readonly sessionSecret: string;
  readonly expiresAt: number;
  readonly state: CustomerBootstrapState;
}

export interface CustomerBootstrapOauthStart {
  readonly attemptId: string;
  readonly state: string;
  /** Request-local only; the router immediately moves this into an HttpOnly cookie. */
  readonly verifier: string;
  readonly challenge: string;
  readonly expiresAt: number;
  readonly next: CustomerBootstrapState;
}

export interface CustomerBootstrapOauthCallback {
  readonly attemptId: string;
  readonly next: CustomerBootstrapState;
}

export type BootstrapRandomBytes = (length: number) => Uint8Array;

export class CustomerBootstrapStateError extends Error {
  constructor(readonly code: 'invalid' | 'expired' | 'consumed' | 'conflict' | 'final') {
    super(code);
    this.name = 'CustomerBootstrapStateError';
  }
}

function invalid(): never {
  throw new CustomerBootstrapStateError('invalid');
}

function frozen(state: CustomerBootstrapState): CustomerBootstrapState {
  const parsed = v.safeParse(customerBootstrapStateSchema, state);
  if (!parsed.success) invalid();
  const session = parsed.output.session === null ? null : Object.freeze(parsed.output.session);
  const oauth = parsed.output.oauth === null ? null : Object.freeze(parsed.output.oauth);
  return Object.freeze({ ...parsed.output, session, oauth });
}

function randomToken(randomBytes?: BootstrapRandomBytes): string {
  if (randomBytes === undefined) return randomBase64Url(32);
  const bytes = randomBytes(32);
  if (!(bytes instanceof Uint8Array) || bytes.byteLength !== 32) invalid();
  return base64UrlEncode(bytes);
}

function randomShortToken(randomBytes?: BootstrapRandomBytes): string {
  if (randomBytes === undefined) return randomBase64Url(18);
  const bytes = randomBytes(18);
  if (!(bytes instanceof Uint8Array) || bytes.byteLength !== 18) invalid();
  return base64UrlEncode(bytes);
}

function validNow(now: number): void {
  if (!Number.isSafeInteger(now) || now < 0) invalid();
}

export function parseCustomerBootstrapState<Input>(input: Input): CustomerBootstrapState | null {
  const parsed = v.safeParse(customerBootstrapStateSchema, input);
  return parsed.success ? frozen(parsed.output) : null;
}

export async function createCustomerBootstrapCapability(input: {
  readonly now: number;
  readonly randomBytes?: BootstrapRandomBytes | undefined;
}): Promise<CustomerBootstrapCapability> {
  validNow(input.now);
  const secret = randomToken(input.randomBytes);
  return Object.freeze({
    bootstrapId: `boot_${randomShortToken(input.randomBytes)}`,
    secret,
    secretCommitment: `sha256:${await sha256Hex(secret)}`,
    expiresAt: input.now + CUSTOMER_BOOTSTRAP_TTL_MS,
  });
}

/** Creates the only state that may be seeded by a Stage 1 Worker binding. */
export function initialCustomerBootstrapState(input: {
  readonly installId: string;
  readonly bootstrapId: string;
  readonly secretCommitment: string;
  readonly expiresAt: number;
}): CustomerBootstrapState {
  return frozen({
    schemaVersion: 1,
    revision: 1,
    status: 'INCOMPLETE',
    installId: input.installId,
    bootstrapId: input.bootstrapId,
    secretCommitment: input.secretCommitment,
    capabilityUnused: true,
    capabilityExpiresAt: input.expiresAt,
    session: null,
    oauth: null,
    failureCode: null,
    failureReason: null,
    readyAt: null,
  });
}

/**
 * Consumes the installation capability once and replaces it with a bounded,
 * browser-held bootstrap session. Only the hash of either secret is retained.
 */
export async function consumeCustomerBootstrapCapability(input: {
  readonly current: CustomerBootstrapState;
  readonly bootstrapId: string;
  readonly secret: string;
  readonly now: number;
  readonly randomBytes?: BootstrapRandomBytes;
}): Promise<CustomerBootstrapSession> {
  validNow(input.now);
  const current = parseCustomerBootstrapState(input.current);
  if (!current || !BOOTSTRAP_ID.test(input.bootstrapId) || !TOKEN.test(input.secret)) invalid();
  if (current.status === 'READY') throw new CustomerBootstrapStateError('final');
  if (current.bootstrapId !== input.bootstrapId) invalid();
  if (!current.capabilityUnused) throw new CustomerBootstrapStateError('consumed');
  if (current.capabilityExpiresAt <= input.now) throw new CustomerBootstrapStateError('expired');
  const presented = `sha256:${await sha256Hex(input.secret)}`;
  if (!constantTimeEqual(presented, current.secretCommitment)) invalid();

  const sessionSecret = randomToken(input.randomBytes);
  const expiresAt = Math.min(input.now + CUSTOMER_BOOTSTRAP_TTL_MS, current.capabilityExpiresAt);
  const state = frozen({
    ...current,
    revision: current.revision + 1,
    capabilityUnused: false,
    session: { secretHash: await sha256(sessionSecret), expiresAt },
    oauth: null,
    failureCode: null,
    failureReason: null,
  });
  return Object.freeze({ sessionSecret, expiresAt, state });
}

/**
 * Rotate a browser session for an Access-protected recovery page after the
 * initial one-use capability has been consumed. This grants no Cloudflare
 * authority: a new ownership proof and OAuth authorization are still required.
 */
export async function createCustomerBootstrapRecoverySession(input: {
  readonly current: CustomerBootstrapState;
  readonly now: number;
  readonly randomBytes?: BootstrapRandomBytes;
}): Promise<CustomerBootstrapSession> {
  validNow(input.now);
  const current = parseCustomerBootstrapState(input.current);
  if (!current || current.capabilityUnused) invalid();
  if (current.status === 'READY') throw new CustomerBootstrapStateError('final');
  if (current.oauth !== null && current.oauth.expiresAt > input.now) {
    throw new CustomerBootstrapStateError('conflict');
  }
  const sessionSecret = randomToken(input.randomBytes);
  const expiresAt = input.now + CUSTOMER_BOOTSTRAP_TTL_MS;
  if (!Number.isSafeInteger(expiresAt)) invalid();
  const state = frozen({
    ...current,
    revision: current.revision + 1,
    status: 'INCOMPLETE',
    session: { secretHash: await sha256(sessionSecret), expiresAt },
    oauth: null,
    failureCode: current.status === 'CONVERGING' || current.oauth !== null
      ? 'provider_recovery_required'
      : current.failureCode,
  });
  return Object.freeze({ sessionSecret, expiresAt, state });
}

async function authenticatedSession(
  current: CustomerBootstrapState,
  sessionSecret: string,
  now: number,
): Promise<void> {
  if (!TOKEN.test(sessionSecret)) invalid();
  if (!current.session || current.session.expiresAt <= now) {
    throw new CustomerBootstrapStateError('expired');
  }
  if (!constantTimeEqual(await sha256(sessionSecret), current.session.secretHash)) invalid();
}

/** Starts a fresh PKCE S256 authorization generated inside the customer Worker. */
export async function startCustomerBootstrapOauth(input: {
  readonly current: CustomerBootstrapState;
  readonly sessionSecret: string;
  readonly now: number;
  readonly randomBytes?: BootstrapRandomBytes;
}): Promise<CustomerBootstrapOauthStart> {
  validNow(input.now);
  let current = parseCustomerBootstrapState(input.current);
  if (!current) invalid();
  if (current.status === 'READY') throw new CustomerBootstrapStateError('final');
  await authenticatedSession(current, input.sessionSecret, input.now);

  // A dead invocation cannot strand authority. Once its bounded attempt has
  // expired, only a fresh OAuth authorization may continue convergence.
  if (current.oauth !== null && current.oauth.expiresAt <= input.now) {
    current = frozen({
      ...current,
      status: 'INCOMPLETE',
      oauth: null,
      failureCode: 'provider_recovery_required',
      failureReason: null,
    });
  }
  if (current.status !== 'INCOMPLETE' || current.oauth !== null) {
    throw new CustomerBootstrapStateError('conflict');
  }

  const verifier = randomToken(input.randomBytes);
  const state = randomToken(input.randomBytes);
  const attemptId = `attempt_${randomShortToken(input.randomBytes)}`;
  const expiresAt = Math.min(input.now + CUSTOMER_BOOTSTRAP_OAUTH_TTL_MS, current.session?.expiresAt ?? 0);
  const next = frozen({
    ...current,
    revision: current.revision + 1,
    oauth: {
      attemptId,
      stateHash: await sha256(state),
      phase: 'authorizing',
      expiresAt,
    },
    failureCode: null,
    failureReason: null,
  });
  return Object.freeze({
    attemptId,
    state,
    verifier,
    challenge: await pkceChallenge(verifier),
    expiresAt,
    next,
  });
}

/**
 * Atomically consumes the matching OAuth state and attempt before any token
 * exchange. The verifier is deliberately absent from durable state.
 */
export async function consumeCustomerBootstrapOauthCallback(input: {
  readonly current: CustomerBootstrapState;
  readonly sessionSecret: string;
  readonly attemptId: string;
  readonly state: string;
  readonly now: number;
}): Promise<CustomerBootstrapOauthCallback> {
  validNow(input.now);
  const current = parseCustomerBootstrapState(input.current);
  if (!current || !ATTEMPT_ID.test(input.attemptId) || !TOKEN.test(input.state)) invalid();
  if (current.status === 'READY') throw new CustomerBootstrapStateError('final');
  await authenticatedSession(current, input.sessionSecret, input.now);
  const oauth = current.oauth;
  if (!oauth || oauth.phase !== 'authorizing') throw new CustomerBootstrapStateError('conflict');
  if (oauth.expiresAt <= input.now) throw new CustomerBootstrapStateError('expired');
  if (oauth.attemptId !== input.attemptId) invalid();
  if (!constantTimeEqual(await sha256(input.state), oauth.stateHash)) invalid();
  const next = frozen({
    ...current,
    revision: current.revision + 1,
    status: 'CONVERGING',
    oauth: { ...oauth, phase: 'exchanging' },
    failureCode: null,
    failureReason: null,
  });
  return Object.freeze({ attemptId: oauth.attemptId, next });
}

/** Returns a failed relay start to retryable state before any OAuth redirect. */
export function rejectCustomerBootstrapOauthStart(input: {
  readonly current: CustomerBootstrapState;
  readonly attemptId: string;
}): CustomerBootstrapState {
  const current = parseCustomerBootstrapState(input.current);
  if (!current || !ATTEMPT_ID.test(input.attemptId)) invalid();
  if (current.status === 'READY') throw new CustomerBootstrapStateError('final');
  if (current.status !== 'INCOMPLETE' || current.oauth?.phase !== 'authorizing' ||
      current.oauth.attemptId !== input.attemptId) {
    throw new CustomerBootstrapStateError('conflict');
  }
  return frozen({
    ...current,
    revision: current.revision + 1,
    oauth: null,
    failureCode: 'authorization_rejected',
    failureReason: null,
  });
}

/** Consumes an authenticated OAuth denial without ever receiving a code. */
export async function rejectCustomerBootstrapOauthCallback(input: {
  readonly current: CustomerBootstrapState;
  readonly sessionSecret: string;
  readonly attemptId: string;
  readonly state: string;
  readonly now: number;
}): Promise<CustomerBootstrapState> {
  validNow(input.now);
  const current = parseCustomerBootstrapState(input.current);
  if (!current || !ATTEMPT_ID.test(input.attemptId) || !TOKEN.test(input.state)) invalid();
  if (current.status === 'READY') throw new CustomerBootstrapStateError('final');
  await authenticatedSession(current, input.sessionSecret, input.now);
  const oauth = current.oauth;
  if (current.status !== 'INCOMPLETE' || !oauth || oauth.phase !== 'authorizing') {
    throw new CustomerBootstrapStateError('conflict');
  }
  if (oauth.expiresAt <= input.now) throw new CustomerBootstrapStateError('expired');
  if (oauth.attemptId !== input.attemptId) invalid();
  if (!constantTimeEqual(await sha256(input.state), oauth.stateHash)) invalid();
  return frozen({
    ...current,
    revision: current.revision + 1,
    oauth: null,
    failureCode: 'authorization_rejected',
    failureReason: null,
  });
}

export function markCustomerBootstrapIncomplete(input: {
  readonly current: CustomerBootstrapState;
  readonly attemptId: string;
  readonly failureCode: CustomerBootstrapFailureCode;
  readonly failureReason?: string | null;
}): CustomerBootstrapState {
  const current = parseCustomerBootstrapState(input.current);
  if (!current || !ATTEMPT_ID.test(input.attemptId)) invalid();
  if (current.status === 'READY') throw new CustomerBootstrapStateError('final');
  if (current.status !== 'CONVERGING' || current.oauth?.attemptId !== input.attemptId) {
    throw new CustomerBootstrapStateError('conflict');
  }
  return frozen({
    ...current,
    revision: current.revision + 1,
    status: 'INCOMPLETE',
    oauth: null,
    failureCode: input.failureCode,
    failureReason: v.is(failureReasonSchema, input.failureReason) ? input.failureReason : null,
  });
}

/** One-way terminal transition; all bootstrap credentials are erased. */
export function markCustomerBootstrapReady(input: {
  readonly current: CustomerBootstrapState;
  readonly attemptId: string;
  readonly now: number;
}): CustomerBootstrapState {
  validNow(input.now);
  const current = parseCustomerBootstrapState(input.current);
  if (!current || !ATTEMPT_ID.test(input.attemptId)) invalid();
  if (current.status === 'READY') throw new CustomerBootstrapStateError('final');
  if (current.status !== 'CONVERGING' || current.oauth?.attemptId !== input.attemptId) {
    throw new CustomerBootstrapStateError('conflict');
  }
  return frozen({
    ...current,
    revision: current.revision + 1,
    status: 'READY',
    capabilityUnused: false,
    session: null,
    oauth: null,
    failureCode: null,
    failureReason: null,
    readyAt: input.now,
  });
}

export function publicCustomerBootstrapStatus(state: CustomerBootstrapState): Readonly<{
  schemaVersion: 1;
  status: 'INCOMPLETE' | 'CONVERGING' | 'READY';
  canRetry: boolean;
}> {
  const parsed = parseCustomerBootstrapState(state);
  if (!parsed) invalid();
  return Object.freeze({
    schemaVersion: 1,
    status: parsed.status,
    canRetry: parsed.status === 'INCOMPLETE' && parsed.session !== null,
  });
}

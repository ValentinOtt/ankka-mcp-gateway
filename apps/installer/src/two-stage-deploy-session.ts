import * as v from 'valibot';

import { boundaryObjectSchema, type BoundaryObject } from './boundary';
import type { BootstrapRandomBytes } from './customer-bootstrap-state';
import { DeployError, isDeployErrorCode, type DeployErrorCode, FAILURE_REASON_PATTERN } from './errors';
import { parseHostedStage1Provision, type HostedStage1Provision } from './hosted-stage1-bootstrap';
import {
  HOSTED_STAGE1_CLEANUP_REASONS,
  HOSTED_STAGE1_FAILURE_CODES,
  HostedStage1SessionError,
  authorizeHostedStage1Bootstrap,
  authorizeHostedStage1Cleanup,
  completeHostedStage1Cleanup,
  consumeHostedStage1Callback,
  failHostedStage1Attempt,
  freezeHostedStage1Plan,
  initializeHostedStage1Session,
  markHostedStage1CleanupRequired,
  markHostedStage1HandedOff,
  parseHostedStage1Session,
  reapHostedStage1Session,
  recordHostedStage1Provision,
  saveHostedStage1Selection,
  type HostedStage1AuthorizationStart,
  type HostedStage1CapabilityCommitment,
  type HostedStage1CleanupReason,
  type HostedStage1FailureCode,
  type HostedStage1Session,
} from './hosted-stage1-session';
import {
  HostedStage1SessionDurableStatePort,
  initializeHostedStage1SessionSql,
  type HostedStage1SessionPort,
  type HostedStage1SessionSqlStorage,
} from './hosted-stage1-session-durable-state';
import { parseDeploySelection, parseStaticDeployPlan, type DeploySelection, type StaticDeployPlan } from './schema';

/**
 * Clean hosted two-stage Durable Object.
 *
 * One instance owns exactly one secret-free hosted Stage 1 session. It is a
 * revision-checked RPC over the pure session model and nothing more: no
 * provider I/O, no OAuth exchange, no cookie handling, and no capability
 * secret ever reaches it. The hosted Worker runtime performs Cloudflare calls
 * in the request that owns the encrypted cookie and asks this object only to
 * claim, record, and reap state atomically.
 */

export const TWO_STAGE_SESSION_INTERNAL_ORIGIN = 'https://two-stage-deploy-session.invalid';
const MAX_BODY_BYTES = 256 * 1_024;
const ALARM_MIN_DELAY_MS = 60_000;

const ATTEMPT_ID = /^attempt_[A-Za-z0-9_-]{24}$/u;
const TOKEN = /^[A-Za-z0-9_-]{43}$/u;
const COMMITMENT = /^sha256:[a-f0-9]{64}$/u;
const BOOTSTRAP_ID = /^boot_[A-Za-z0-9_-]{24}$/u;

const attemptIdSchema = v.pipe(v.string(), v.regex(ATTEMPT_ID));
const capabilitySchema = v.strictObject({
  bootstrapId: v.pipe(v.string(), v.regex(BOOTSTRAP_ID)),
  secretCommitment: v.pipe(v.string(), v.regex(COMMITMENT)),
  expiresAt: v.pipe(v.number(), v.safeInteger(), v.minValue(0)),
});
const emptyBodySchema = v.strictObject({});
const bodySchemas = Object.freeze({
  '/initialize': emptyBodySchema,
  '/selection': v.strictObject({ selection: boundaryObjectSchema }),
  '/plan': v.strictObject({ plan: boundaryObjectSchema }),
  '/bootstrap/authorize': v.strictObject({ capability: capabilitySchema }),
  '/bootstrap/consume': v.strictObject({
    attemptId: attemptIdSchema,
    state: v.pipe(v.string(), v.regex(TOKEN)),
    verifier: v.pipe(v.string(), v.regex(TOKEN)),
  }),
  '/attempt/fail': v.strictObject({
    attemptId: attemptIdSchema,
    code: v.picklist(HOSTED_STAGE1_FAILURE_CODES),
    reason: v.union([v.pipe(v.string(), v.regex(FAILURE_REASON_PATTERN)), v.null()]),
  }),
  '/bootstrap/provision': v.strictObject({ attemptId: attemptIdSchema, provision: boundaryObjectSchema }),
  '/bootstrap/handed-off': v.strictObject({
    bootstrapId: v.pipe(v.string(), v.regex(BOOTSTRAP_ID)),
    secretCommitment: v.pipe(v.string(), v.regex(COMMITMENT)),
  }),
  '/cleanup/require': v.strictObject({ reason: v.picklist(HOSTED_STAGE1_CLEANUP_REASONS) }),
  '/cleanup/authorize': emptyBodySchema,
  '/cleanup/complete': v.strictObject({ attemptId: attemptIdSchema }),
});
type MutationPath = keyof typeof bodySchemas;
const MUTATION_PATHS: readonly MutationPath[] = Object.freeze(
  Object.keys(bodySchemas).filter((path): path is MutationPath => Object.hasOwn(bodySchemas, path)),
);

const startSchema = v.strictObject({
  attemptId: attemptIdSchema,
  kind: v.picklist(['bootstrap', 'cleanup']),
  state: v.pipe(v.string(), v.regex(TOKEN)),
  verifier: v.pipe(v.string(), v.regex(TOKEN)),
  challenge: v.pipe(v.string(), v.regex(TOKEN)),
  expiresAt: v.pipe(v.number(), v.safeInteger(), v.minValue(0)),
});
const errorBodySchema = v.object({ error: v.object({ code: v.string() }) });
const sessionBodySchema = v.object({ session: v.union([boundaryObjectSchema, v.null()]) });
const startBodySchema = v.object({ session: boundaryObjectSchema, start: startSchema });

export interface TwoStageDeploySessionStorage extends HostedStage1SessionSqlStorage {
  setAlarm(scheduledTime: number | Date): Promise<void>;
  deleteAlarm(): Promise<void>;
  deleteAll(): Promise<void>;
}

export interface TwoStageDeploySessionState {
  readonly storage: TwoStageDeploySessionStorage;
  blockConcurrencyWhile<T>(callback: () => Promise<T>): Promise<T>;
}

export interface TwoStageDeploySessionStub {
  fetch(request: Request): Promise<Response>;
}

export interface TwoStageDeploySessionNamespace {
  idFromName(name: string): DurableObjectId;
  get(id: DurableObjectId): TwoStageDeploySessionStub;
}

/** The object reads no bindings; the Worker environment only carries its own namespace. */
export interface TwoStageDeploySessionEnv {
  readonly TWO_STAGE_DEPLOY_SESSION?: TwoStageDeploySessionNamespace;
}

export interface TwoStageDeploySessionClock {
  readonly now?: () => number;
  readonly randomBytes?: BootstrapRandomBytes;
}

interface SessionResult {
  readonly session: HostedStage1Session;
}

interface StartResult extends SessionResult {
  readonly start: Omit<HostedStage1AuthorizationStart, 'next'>;
}

function nextDeadline(session: HostedStage1Session): number | null {
  switch (session.phase) {
    case 'cleanup_required':
      return null;
    case 'provisioned':
      return session.provision === null ? session.expiresAt : session.provision.capabilityExpiresAt;
    case 'authorizing':
      return session.attempt === null ? session.expiresAt : session.attempt.expiresAt;
    default:
      return session.expiresAt;
  }
}

function sessionErrorToDeployError(error: HostedStage1SessionError): DeployError {
  switch (error.code) {
    case 'expired':
      return new DeployError(410, 'session_expired');
    case 'consumed':
      return new DeployError(409, 'callback_invalid');
    case 'phase':
    case 'conflict':
      return new DeployError(409, 'session_conflict');
    default:
      return new DeployError(400, 'session_invalid');
  }
}

function errorResponse<Thrown>(error: Thrown): Response {
  const deployError = error instanceof HostedStage1SessionError
    ? sessionErrorToDeployError(error)
    : error instanceof DeployError ? error : new DeployError(500, 'internal_error');
  return Response.json({ error: { code: deployError.code } }, { status: deployError.status });
}

function withoutNext(start: HostedStage1AuthorizationStart): Omit<HostedStage1AuthorizationStart, 'next'> {
  return Object.freeze({
    attemptId: start.attemptId,
    kind: start.kind,
    state: start.state,
    verifier: start.verifier,
    challenge: start.challenge,
    expiresAt: start.expiresAt,
  });
}

export class TwoStageDeploySession {
  private readonly ready: Promise<void>;
  private readonly port: HostedStage1SessionPort;
  private readonly now: () => number;
  private readonly randomBytes: BootstrapRandomBytes | undefined;

  constructor(
    private readonly state: TwoStageDeploySessionState,
    _env?: TwoStageDeploySessionEnv,
    clock: TwoStageDeploySessionClock = {},
  ) {
    this.now = clock.now ?? Date.now;
    this.randomBytes = clock.randomBytes;
    this.port = new HostedStage1SessionDurableStatePort(state.storage);
    this.ready = state.blockConcurrencyWhile(async () => {
      initializeHostedStage1SessionSql(state.storage);
    });
  }

  async fetch(request: Request): Promise<Response> {
    try {
      await this.ready;
      const url = new URL(request.url);
      if (url.origin !== TWO_STAGE_SESSION_INTERNAL_ORIGIN || url.search !== '' || url.hash !== '') {
        throw new DeployError(404, 'bad_request');
      }
      if (url.pathname === '/session') {
        if (request.method !== 'GET') throw new DeployError(405, 'bad_request');
        return Response.json({ session: await this.port.read() });
      }
      const path = MUTATION_PATHS.find((candidate) => candidate === url.pathname);
      if (path === undefined) throw new DeployError(404, 'bad_request');
      if (request.method !== 'POST') throw new DeployError(405, 'bad_request');
      const body = await this.readBody(request, path);
      const result = await this.apply(path, body);
      return Response.json(result);
    } catch (error) {
      return errorResponse(error);
    }
  }

  /** Alarm-driven housekeeping: erase, escalate to cleanup, or fail an expired attempt. */
  async alarm(): Promise<void> {
    await this.ready;
    const current = await this.port.read();
    if (current === null) {
      await this.state.storage.deleteAlarm();
      return;
    }
    const now = this.currentTime();
    const reap = reapHostedStage1Session({ current, now });
    if (reap.action === 'erase') {
      if (await this.port.erase(current.revision)) {
        await this.state.storage.deleteAll();
        initializeHostedStage1SessionSql(this.state.storage);
      }
      await this.state.storage.deleteAlarm();
      return;
    }
    if (reap.action === 'replace') {
      if (!await this.port.compareAndSet(current.revision, reap.next)) return;
      await this.schedule(reap.next, now);
      return;
    }
    await this.schedule(current, now, ALARM_MIN_DELAY_MS);
  }

  private currentTime(): number {
    const now = this.now();
    if (!Number.isSafeInteger(now) || now < 0) throw new DeployError(500, 'internal_error');
    return now;
  }

  private async schedule(session: HostedStage1Session, now: number, minDelayMs = 1_000): Promise<void> {
    const deadline = nextDeadline(session);
    if (deadline === null) {
      await this.state.storage.deleteAlarm();
      return;
    }
    await this.state.storage.setAlarm(Math.max(deadline, now + minDelayMs));
  }

  private async readBody<Path extends MutationPath>(
    request: Request,
    path: Path,
  ): Promise<v.InferOutput<(typeof bodySchemas)[Path]>> {
    if (!request.headers.get('content-type')?.toLowerCase().startsWith('application/json')) {
      throw new DeployError(400, 'bad_request');
    }
    const declared = Number(request.headers.get('content-length'));
    if (Number.isFinite(declared) && declared > MAX_BODY_BYTES) throw new DeployError(413, 'bad_request');
    let decoded: unknown;
    try {
      const text = await request.text();
      if (text.length > MAX_BODY_BYTES) throw new DeployError(413, 'bad_request');
      decoded = JSON.parse(text);
    } catch (error) {
      if (error instanceof DeployError) throw error;
      throw new DeployError(400, 'bad_request');
    }
    const parsed = v.safeParse(bodySchemas[path], decoded);
    if (!parsed.success) throw new DeployError(400, 'bad_request');
    return parsed.output;
  }

  private async existing(): Promise<HostedStage1Session> {
    const current = await this.port.read();
    if (current === null) throw new DeployError(404, 'session_invalid');
    return current;
  }

  private async commit(current: HostedStage1Session | null, next: HostedStage1Session, now: number): Promise<void> {
    const expectedRevision = current === null ? null : current.revision;
    if (!await this.port.compareAndSet(expectedRevision, next)) {
      throw new DeployError(409, 'session_conflict');
    }
    await this.schedule(next, now);
  }

  private async apply<Path extends MutationPath>(
    path: Path,
    body: v.InferOutput<(typeof bodySchemas)[Path]>,
  ): Promise<SessionResult | StartResult> {
    const now = this.currentTime();
    switch (path) {
      case '/initialize': {
        if (await this.port.read() !== null) throw new DeployError(409, 'session_conflict');
        const session = initializeHostedStage1Session({ now, randomBytes: this.randomBytes });
        await this.commit(null, session, now);
        return { session };
      }
      case '/selection': {
        const input = v.parse(bodySchemas['/selection'], body);
        const current = await this.existing();
        const session = saveHostedStage1Selection({
          current, selection: parseDeploySelection(input.selection), now,
        });
        await this.commit(current, session, now);
        return { session };
      }
      case '/plan': {
        const input = v.parse(bodySchemas['/plan'], body);
        const current = await this.existing();
        const session = await freezeHostedStage1Plan({
          current, plan: parseStaticDeployPlan(input.plan), now,
        });
        await this.commit(current, session, now);
        return { session };
      }
      case '/bootstrap/authorize': {
        const input = v.parse(bodySchemas['/bootstrap/authorize'], body);
        const current = await this.existing();
        const start = await authorizeHostedStage1Bootstrap({
          current, capability: input.capability, now, randomBytes: this.randomBytes,
        });
        await this.commit(current, start.next, now);
        return { session: start.next, start: withoutNext(start) };
      }
      case '/bootstrap/consume': {
        const input = v.parse(bodySchemas['/bootstrap/consume'], body);
        const current = await this.existing();
        const session = await consumeHostedStage1Callback({ current, ...input, now });
        await this.commit(current, session, now);
        return { session };
      }
      case '/attempt/fail': {
        const input = v.parse(bodySchemas['/attempt/fail'], body);
        const current = await this.existing();
        const session = failHostedStage1Attempt({ current, ...input, now });
        await this.commit(current, session, now);
        return { session };
      }
      case '/bootstrap/provision': {
        const input = v.parse(bodySchemas['/bootstrap/provision'], body);
        const current = await this.existing();
        const session = recordHostedStage1Provision({
          current, attemptId: input.attemptId, provision: parseHostedStage1Provision(input.provision), now,
        });
        await this.commit(current, session, now);
        return { session };
      }
      case '/bootstrap/handed-off': {
        const input = v.parse(bodySchemas['/bootstrap/handed-off'], body);
        const current = await this.existing();
        const session = markHostedStage1HandedOff({ current, ...input, now });
        await this.commit(current, session, now);
        return { session };
      }
      case '/cleanup/require': {
        const input = v.parse(bodySchemas['/cleanup/require'], body);
        const current = await this.existing();
        const session = markHostedStage1CleanupRequired({ current, reason: input.reason, now });
        await this.commit(current, session, now);
        return { session };
      }
      case '/cleanup/authorize': {
        const current = await this.existing();
        const start = await authorizeHostedStage1Cleanup({ current, now, randomBytes: this.randomBytes });
        await this.commit(current, start.next, now);
        return { session: start.next, start: withoutNext(start) };
      }
      case '/cleanup/complete': {
        const input = v.parse(bodySchemas['/cleanup/complete'], body);
        const current = await this.existing();
        const session = completeHostedStage1Cleanup({ current, attemptId: input.attemptId, now });
        await this.commit(current, session, now);
        return { session };
      }
      default:
        throw new DeployError(404, 'bad_request');
    }
  }
}

function internalErrorCode<Input>(input: Input): DeployErrorCode | null {
  const result = v.safeParse(errorBodySchema, input);
  const code = result.success ? result.output.error.code : null;
  return isDeployErrorCode(code) ? code : null;
}

/** Typed same-release client for the hosted Worker runtime; every response is re-parsed by its owner. */
export class TwoStageDeploySessionClient {
  constructor(private readonly stub: TwoStageDeploySessionStub) {}

  private async call<Input>(path: string, body: Input | null): Promise<BoundaryObject> {
    const request = new Request(`${TWO_STAGE_SESSION_INTERNAL_ORIGIN}${path}`, body === null
      ? { method: 'GET' }
      : {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(body),
      });
    const response = await this.stub.fetch(request);
    let decoded: unknown;
    try {
      decoded = await response.json();
    } catch {
      throw new DeployError(500, 'session_invalid');
    }
    if (!response.ok) throw new DeployError(response.status, internalErrorCode(decoded) ?? 'session_invalid');
    const parsed = v.safeParse(boundaryObjectSchema, decoded);
    if (!parsed.success) throw new DeployError(500, 'session_invalid');
    return parsed.output;
  }

  private sessionOf(decoded: BoundaryObject): HostedStage1Session {
    const parsed = v.safeParse(sessionBodySchema, decoded);
    const session = parsed.success ? parseHostedStage1Session(parsed.output.session) : null;
    if (session === null) throw new DeployError(500, 'session_invalid');
    return session;
  }

  private startOf(decoded: BoundaryObject): HostedStage1AuthorizationStart {
    const parsed = v.safeParse(startBodySchema, decoded);
    if (!parsed.success) throw new DeployError(500, 'session_invalid');
    const next = parseHostedStage1Session(parsed.output.session);
    if (next === null) throw new DeployError(500, 'session_invalid');
    return Object.freeze({ ...parsed.output.start, next });
  }

  async read(): Promise<HostedStage1Session | null> {
    const decoded = await this.call('/session', null);
    const parsed = v.safeParse(sessionBodySchema, decoded);
    if (!parsed.success) throw new DeployError(500, 'session_invalid');
    if (parsed.output.session === null) return null;
    return this.sessionOf(decoded);
  }

  async initialize(): Promise<HostedStage1Session> {
    return this.sessionOf(await this.call('/initialize', {}));
  }

  async saveSelection(selection: DeploySelection): Promise<HostedStage1Session> {
    return this.sessionOf(await this.call('/selection', { selection }));
  }

  async freezePlan(plan: StaticDeployPlan): Promise<HostedStage1Session> {
    return this.sessionOf(await this.call('/plan', { plan }));
  }

  async authorizeBootstrap(capability: HostedStage1CapabilityCommitment): Promise<HostedStage1AuthorizationStart> {
    return this.startOf(await this.call('/bootstrap/authorize', {
      capability: {
        bootstrapId: capability.bootstrapId,
        secretCommitment: capability.secretCommitment,
        expiresAt: capability.expiresAt,
      },
    }));
  }

  async consumeCallback(input: {
    readonly attemptId: string;
    readonly state: string;
    readonly verifier: string;
  }): Promise<HostedStage1Session> {
    return this.sessionOf(await this.call('/bootstrap/consume', {
      attemptId: input.attemptId, state: input.state, verifier: input.verifier,
    }));
  }

  async failAttempt(input: {
    readonly attemptId: string;
    readonly code: HostedStage1FailureCode;
    readonly reason?: string | null | undefined;
  }): Promise<HostedStage1Session> {
    return this.sessionOf(await this.call('/attempt/fail', {
      attemptId: input.attemptId,
      code: input.code,
      reason: input.reason ?? null,
    }));
  }

  async recordProvision(input: {
    readonly attemptId: string;
    readonly provision: HostedStage1Provision;
  }): Promise<HostedStage1Session> {
    return this.sessionOf(await this.call('/bootstrap/provision', {
      attemptId: input.attemptId, provision: input.provision,
    }));
  }

  async markHandedOff(input: {
    readonly bootstrapId: string;
    readonly secretCommitment: string;
  }): Promise<HostedStage1Session> {
    return this.sessionOf(await this.call('/bootstrap/handed-off', {
      bootstrapId: input.bootstrapId, secretCommitment: input.secretCommitment,
    }));
  }

  async requireCleanup(reason: HostedStage1CleanupReason): Promise<HostedStage1Session> {
    return this.sessionOf(await this.call('/cleanup/require', { reason }));
  }

  async authorizeCleanup(): Promise<HostedStage1AuthorizationStart> {
    return this.startOf(await this.call('/cleanup/authorize', {}));
  }

  async completeCleanup(attemptId: string): Promise<HostedStage1Session> {
    return this.sessionOf(await this.call('/cleanup/complete', { attemptId }));
  }
}

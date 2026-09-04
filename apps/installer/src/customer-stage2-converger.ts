import * as v from 'valibot';

import { jsonValueSchema, type JsonObject, type JsonValue } from './boundary';
import { canonicalJson } from './canonical-json';
import {
  preflightFreshCustomerGatewayProjection,
} from './cloudflare-gateway-fresh-preflight';
import {
  attachManagementCustomDomain,
  createManagementAccessApplication,
  createManagementAdminAllowPolicy,
  getAccountWorkersSubdomain,
  getZeroTrustOrganization,
  listAccessIdentityProviders,
  preflightFreshManagementAccessApplication,
  preflightFreshManagementCustomDomain,
  prepareManagementAccessApplicationIntent,
  prepareManagementAdminPolicyIntent,
  prepareManagementCustomDomainIntent,
  recoverManagementAccessApplication,
  recoverManagementAdminAllowPolicy,
  recoverManagementCustomDomain,
  setWorkerBootstrapSubdomain,
  verifyManagementAccessApplicationGet,
  verifyManagementAccessApplicationList,
  verifyManagementAdminAllowPolicyGet,
  verifyManagementAdminAllowPolicyList,
  verifyManagementCustomDomainGet,
  verifyManagementCustomDomainList,
  verifyWorkerBootstrapSubdomain,
  type ManagementAccessApplicationLocator,
  type ManagementAdminPolicyLocator,
  type ManagementCustomDomainLocator,
  type ZeroTrustOrganization,
} from './cloudflare-management-surface';
import type { CustomerBootstrapConvergenceResult } from './customer-bootstrap-callback';
import {
  prepareCustomerGatewayDesiredProjectionFromPlan,
  submitCustomerBootstrapFromPlan,
  type CustomerBootstrapReadyResult,
  type CustomerBootstrapTarget,
} from './customer-bootstrap-request';
import {
  CUSTOMER_BOOTSTRAP_PLAIN_BINDINGS,
  readCustomerBootstrapWorkerOwnership,
} from './customer-bootstrap-worker-readback';
import {
  resolveAuthorizedCloudflareZone,
  type CustomerCloudflareTransport,
} from './customer-cloudflare-grant';
import {
  adoptCustomerGatewayOwnership,
  readCustomerGatewayOwnershipState,
  verifyCustomerGatewayOwnershipAdoption,
  type CustomerGatewayOwnershipStorage,
} from './customer-gateway-ownership-state';
import {
  acquireCustomerStage2Lease,
  armCustomerStage2Action,
  completeCustomerStage2Journal,
  createCustomerStage2Journal,
  customerStage2Action,
  prepareCustomerStage2Action,
  releaseCustomerStage2Lease,
  renewCustomerStage2Lease,
  submitCustomerStage2Action,
  verifyCustomerStage2Action,
  type CustomerStage2ActionName,
  type CustomerStage2Identity,
  type CustomerStage2Journal,
} from './customer-stage2-journal';
import type { CustomerStage2JournalPort } from './customer-stage2-durable-state';
import {
  inspectCustomerWorkerFinalRuntime,
  publishCustomerWorkerFinalRuntime,
  uploadCustomerWorkerFinalRuntime,
  type CustomerWorkerActiveRelease,
} from './customer-worker-self-update';
import { sha256Hex } from './crypto';
import { PUBLIC_ORIGIN } from './constants';
import type { GatewayWorkerPlainTextBindings } from './cloudflare-worker-direct-upload';
import { isPlainDataTree } from './plain-data';
import {
  verifyCloudflareBootstrapOwnershipHandoff,
  type CloudflareBootstrapOwnershipAdoptionReceipt,
} from './cloudflare-bootstrap-ownership-handoff';
import {
  verifyStaticDeployPlanIntegrity,
  type StaticDeployPlan,
} from './schema';

const LEASE_TTL_MS = 5 * 60 * 1_000;
const PLAN_RENEWAL_MS = 30 * 60 * 1_000;
const ATTEMPT_ID = /^attempt_[A-Za-z0-9_-]{24}$/u;
const SHA256 = /^[a-f0-9]{64}$/u;
const PROVIDER_ID = /^(?:[a-f0-9]{32}|[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12})$/u;
const CUSTOM_DOMAIN_ID = /^(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12})$/u;
const ACCESS_AUD = /^[A-Za-z0-9._~-]{16,512}$/u;

const applicationLocatorSchema = v.strictObject({
  applicationId: v.pipe(v.string(), v.regex(PROVIDER_ID)),
  aud: v.pipe(v.string(), v.regex(ACCESS_AUD)),
});
const policyLocatorSchema = v.strictObject({
  policyId: v.pipe(v.string(), v.regex(PROVIDER_ID)),
});
const domainLocatorSchema = v.strictObject({
  domainId: v.pipe(v.string(), v.regex(CUSTOM_DOMAIN_ID)),
});
const workerReleaseLocatorSchema = v.strictObject({
  workerId: v.pipe(v.string(), v.regex(/^[a-f0-9]{32}$/u)),
  deploymentId: v.pipe(v.string(), v.regex(PROVIDER_ID)),
  versionId: v.pipe(v.string(), v.regex(PROVIDER_ID)),
  finalRuntimeSha256: v.pipe(v.string(), v.regex(SHA256)),
});
const gatewayLocatorSchema = v.strictObject({
  schemaVersion: v.literal(1),
  kind: v.literal('gateway_resources_ready'),
  installationId: v.pipe(v.string(), v.regex(/^acg-[a-f0-9]{24}$/u)),
  approvedPlanId: v.pipe(v.string(), v.regex(/^plan-[a-f0-9]{24}$/u)),
  configurationHash: v.pipe(v.string(), v.regex(/^sha256:[a-f0-9]{64}$/u)),
  desiredHash: v.pipe(v.string(), v.regex(/^sha256:[a-f0-9]{64}$/u)),
  gatewayHostname: v.string(),
  receiptRevision: v.pipe(v.number(), v.safeInteger(), v.minValue(1)),
  resourceCount: v.union([v.literal(4), v.literal(7)]),
  receiptChecksum: v.pipe(v.string(), v.regex(/^sha256:[a-f0-9]{64}$/u)),
});

type BootstrapBindingName = (typeof CUSTOMER_BOOTSTRAP_PLAIN_BINDINGS)[number];
export type CustomerStage2BootstrapBindings = Readonly<Record<BootstrapBindingName, string>>;

export interface CustomerStage2BootstrapRuntime {
  /** Request-local HMAC key inherited only by the restricted bootstrap runtime. */
  readonly nonce: string;
  /** Exact Stage 1 plain-text binding surface used for independent provider readback. */
  readonly expectedBindings: CustomerStage2BootstrapBindings;
}

export interface CustomerStage2RuntimeIdentity {
  readonly updateChannel: 'canary' | 'stable';
  readonly updateKeyId: string;
  readonly updatePublicKey: string;
}

export interface CustomerStage2PayloadAdapter {
  /**
   * Delivers the one signed bootstrap request directly to the co-resident
   * payload, with the plan and target it was derived from so the host can
   * complete the payload's runtime environment.
   */
  readonly bootstrap: (request: Request, context: {
    readonly plan: StaticDeployPlan;
    readonly target: CustomerBootstrapTarget;
  }) => Promise<Response>;
  /**
   * Re-reads every receipt-owned Gateway resource with the request-local
   * grant and names the first disagreement with fixed words when it fails.
   */
  readonly verifyReady: (input: {
    readonly accessToken: string;
    readonly plan: StaticDeployPlan;
    readonly target: CustomerBootstrapTarget;
  }) => Promise<CustomerStage2ReadinessVerdict>;
}

export interface CustomerStage2ReadinessVerdict {
  readonly verified: boolean;
  /** Fixed words only, for example `dns_record_absent`; null when verified. */
  readonly reason: string | null;
}

const VERIFY_REASON = /^[a-z][a-z0-9_]{0,120}$/u;

/**
 * A journal transition after which a chunked run returns instead of going on.
 * The next run resumes from the journal under the same attempt and lease.
 */
export interface CustomerStage2Checkpoint {
  readonly action: CustomerStage2ActionName;
  readonly phase: 'submitted' | 'verified';
}

/**
 * Chunk boundaries that keep every run inside the Workers Free plan budget
 * of 50 subrequests per invocation. Measured against the real provider: the
 * bootstrap creates and the receipt re-verification are the two largest
 * blocks, and the final runtime upload stays in the same run as everything
 * that follows it so the object never resumes on new code without its grant.
 */
export const CUSTOMER_STAGE2_CHUNK_CHECKPOINTS: readonly CustomerStage2Checkpoint[] = Object.freeze([
  Object.freeze({ action: 'management_admin_policy', phase: 'verified' } as const),
  Object.freeze({ action: 'gateway_resources', phase: 'submitted' } as const),
  Object.freeze({ action: 'management_custom_domain', phase: 'verified' } as const),
]);

/** The run stopped at a checkpoint; the journal holds the progress and the lease. */
export interface CustomerStage2ConvergerPause {
  readonly verified: false;
  readonly paused: true;
  readonly checkpoint: CustomerStage2Checkpoint;
}

/**
 * The final runtime is uploaded and the object may restart on it at any
 * moment; the journal keeps `final_runtime` armed and the final runtime
 * itself moves the install to READY.
 */
export interface CustomerStage2ConvergerHandover {
  readonly verified: false;
  readonly handedOver: true;
}

export type CustomerStage2ConvergerResult =
  | CustomerBootstrapConvergenceResult
  | CustomerStage2ConvergerPause
  | CustomerStage2ConvergerHandover;

export interface CustomerStage2ConvergerInput {
  readonly accessToken: string;
  readonly attemptId: string;
  readonly storage: CustomerGatewayOwnershipStorage;
  readonly journal: CustomerStage2JournalPort;
  readonly runtime: CustomerStage2RuntimeIdentity;
  readonly bootstrap?: CustomerStage2BootstrapRuntime;
  /** Present in the restricted runtime; absent after the strict final self-update. */
  readonly finalRuntimeSource?: string;
  readonly payload: CustomerStage2PayloadAdapter;
  readonly transport: CustomerCloudflareTransport;
  readonly now: () => number;
  /** Absent: one run completes the install. Present: the run returns at the first checkpoint it crosses. */
  readonly checkpoints?: readonly CustomerStage2Checkpoint[];
  /**
   * Present in the bootstrap shell: called after every journal write and
   * right before the final runtime upload. The upload restarts the Durable
   * Object on the new code and refuses storage to this pass afterwards, so
   * the run returns a handover instead of journaling the upload. Absent
   * where no restart follows the upload (recovery, tests, harnesses).
   */
  readonly handover?: (() => Promise<void>) | undefined;
}

export type CustomerStage2ConvergerErrorCode =
  | 'invalid'
  | 'ownership_invalid'
  | 'journal_conflict'
  | 'journal_mismatch'
  | 'payload_recovery_required'
  | 'runtime_source_unavailable'
  | 'provider_mismatch';

const CONVERGER_REASON = /^[a-z][a-z0-9_]{0,159}$/u;

export class CustomerStage2ConvergerError extends Error {
  readonly canRetry = false;
  /** Secret-free detail naming the step or provider outcome behind the code. */
  readonly reason: string | null;

  constructor(readonly code: CustomerStage2ConvergerErrorCode, reason: string | null = null) {
    super(code);
    this.name = 'CustomerStage2ConvergerError';
    this.reason = reason !== null && CONVERGER_REASON.test(reason) ? reason : null;
  }
}

interface Context {
  readonly input: CustomerStage2ConvergerInput;
  readonly plan: StaticDeployPlan;
  readonly target: CustomerBootstrapTarget;
  readonly organization: ZeroTrustOrganization;
  readonly identityProviderIds: readonly string[];
  readonly workersSubdomain: string;
  journal: CustomerStage2Journal;
  /**
   * Resources this run has already re-read from the provider, keyed by kind
   * and locator. A run proves each resource once; a new run proves it again.
   */
  readonly proofs: Map<string, CustomerWorkerActiveRelease | true>;
}

function fail(code: CustomerStage2ConvergerErrorCode, reason: string | null = null): never {
  throw new CustomerStage2ConvergerError(code, reason);
}

/** Unwinds the step sequence at a checkpoint; never leaves the converger. */
class CustomerStage2Pause {
  constructor(readonly checkpoint: CustomerStage2Checkpoint) {}
}

function pauseAtCheckpoint(
  context: Context,
  action: CustomerStage2ActionName,
  phase: CustomerStage2Checkpoint['phase'],
): void {
  const reached = (context.input.checkpoints ?? []).find((checkpoint) =>
    checkpoint.action === action && checkpoint.phase === phase);
  if (reached !== undefined) throw new CustomerStage2Pause(reached);
}

function exact<Left, Right>(left: Left, right: Right): boolean {
  try {
    return canonicalJson(left) === canonicalJson(right);
  } catch {
    return false;
  }
}

const jsonObjectSchema = v.record(v.string(), jsonValueSchema);
const callableSchema = v.function();

function jsonObject<Value>(value: Value): JsonObject {
  if (!isPlainDataTree(value) || Array.isArray(value)) fail('invalid');
  const parsed = v.safeParse(jsonObjectSchema, JSON.parse(canonicalJson(value)));
  if (!parsed.success) fail('invalid');
  return parsed.output;
}

function jsonValue<Value>(value: Value): JsonValue {
  if (!isPlainDataTree(value)) fail('invalid');
  const parsed = v.safeParse(jsonValueSchema, JSON.parse(canonicalJson(value)));
  if (!parsed.success) fail('invalid');
  return parsed.output;
}

function clock(input: CustomerStage2ConvergerInput, floor = 0): number {
  const value = input.now();
  if (!Number.isSafeInteger(value) || value < 0) fail('invalid');
  return Math.max(value, floor);
}

async function renewedPlan(plan: StaticDeployPlan, now: number): Promise<StaticDeployPlan> {
  const expiresAt = Math.max(plan.expiresAt, now + PLAN_RENEWAL_MS);
  if (!Number.isSafeInteger(expiresAt)) fail('invalid');
  return verifyStaticDeployPlanIntegrity(Object.freeze({ ...plan, expiresAt })).catch(() =>
    fail('ownership_invalid'));
}

function managementWorkerName(plan: StaticDeployPlan): string {
  const workers = plan.managementResources.filter((resource) =>
    resource.kind === 'management_worker');
  const worker = workers.length === 1 ? workers[0] : undefined;
  if (worker === undefined) fail('ownership_invalid');
  return worker.name;
}

function gatewayReadyLocator(result: CustomerBootstrapReadyResult): JsonObject {
  return jsonObject({
    schemaVersion: 1,
    kind: 'gateway_resources_ready',
    installationId: result.installationId,
    approvedPlanId: result.approvedPlanId,
    configurationHash: result.configurationHash,
    desiredHash: result.desiredHash,
    gatewayHostname: result.gateway.hostname,
    receiptRevision: result.receipt.revision,
    resourceCount: result.receipt.resourceCount,
    receiptChecksum: result.receipt.evidence.checksum,
  });
}

function applicationLocator(value: JsonValue | null): ManagementAccessApplicationLocator {
  const parsed = v.safeParse(applicationLocatorSchema, value);
  if (!parsed.success) fail('journal_mismatch');
  return Object.freeze(parsed.output);
}

function policyLocator(value: JsonValue | null): ManagementAdminPolicyLocator {
  const parsed = v.safeParse(policyLocatorSchema, value);
  if (!parsed.success) fail('journal_mismatch');
  return Object.freeze(parsed.output);
}

function domainLocator(value: JsonValue | null): ManagementCustomDomainLocator {
  const parsed = v.safeParse(domainLocatorSchema, value);
  if (!parsed.success) fail('journal_mismatch');
  return Object.freeze(parsed.output);
}

function workerReleaseLocator(value: JsonValue | null): CustomerWorkerActiveRelease {
  const parsed = v.safeParse(workerReleaseLocatorSchema, value);
  if (!parsed.success) fail('journal_mismatch');
  return Object.freeze(parsed.output);
}

function gatewayLocator(value: JsonValue | null): v.InferOutput<typeof gatewayLocatorSchema> {
  const parsed = v.safeParse(gatewayLocatorSchema, value);
  if (!parsed.success) fail('journal_mismatch');
  return Object.freeze(parsed.output);
}

async function persistTransition(context: Context, next: CustomerStage2Journal): Promise<void> {
  const previous = context.journal;
  if (next.revision === previous.revision) {
    if (!exact(next, previous)) fail('journal_mismatch');
    return;
  }
  if (next.revision !== previous.revision + 1 ||
      !await context.input.journal.compareAndSet(previous.revision, next)) {
    fail('journal_conflict');
  }
  context.journal = next;
}

async function ensureLease(context: Context): Promise<void> {
  const now = clock(context.input, context.journal.updatedAt);
  const lease = context.journal.lease;
  if (lease === null || lease.attemptId !== context.input.attemptId || lease.expiresAt <= now) {
    fail('journal_conflict');
  }
  if (lease.expiresAt - now >= LEASE_TTL_MS / 2) return;
  await persistTransition(context, renewCustomerStage2Lease(context.journal, {
    attemptId: context.input.attemptId,
    now,
    leaseExpiresAt: now + LEASE_TTL_MS,
  }));
}

async function prepareAction(
  context: Context,
  name: CustomerStage2ActionName,
  record: JsonObject,
): Promise<void> {
  await ensureLease(context);
  const existing = customerStage2Action(context.journal, name);
  if (existing !== null) {
    if (!exact(existing.record, record)) fail('journal_mismatch');
    return;
  }
  await persistTransition(context, prepareCustomerStage2Action(context.journal, {
    attemptId: context.input.attemptId,
    now: clock(context.input, context.journal.updatedAt),
    name,
    record,
  }));
}

async function armAction(context: Context, name: CustomerStage2ActionName): Promise<void> {
  await ensureLease(context);
  await persistTransition(context, armCustomerStage2Action(context.journal, {
    attemptId: context.input.attemptId,
    now: clock(context.input, context.journal.updatedAt),
    name,
  }));
}

async function submitAction(
  context: Context,
  name: CustomerStage2ActionName,
  locator: JsonValue,
): Promise<void> {
  await ensureLease(context);
  await persistTransition(context, submitCustomerStage2Action(context.journal, {
    attemptId: context.input.attemptId,
    now: clock(context.input, context.journal.updatedAt),
    name,
    locator,
  }));
  pauseAtCheckpoint(context, name, 'submitted');
}

async function verifyAction(context: Context, name: CustomerStage2ActionName): Promise<void> {
  await ensureLease(context);
  await persistTransition(context, verifyCustomerStage2Action(context.journal, {
    attemptId: context.input.attemptId,
    now: clock(context.input, context.journal.updatedAt),
    name,
  }));
  pauseAtCheckpoint(context, name, 'verified');
}

async function adoptOwnership(input: CustomerStage2ConvergerInput): Promise<Readonly<{
  receipt: CloudflareBootstrapOwnershipAdoptionReceipt;
  bootstrapVersionId: string;
  plan: StaticDeployPlan;
}>> {
  const state = await readCustomerGatewayOwnershipState(input.storage).catch(() =>
    fail('ownership_invalid'));
  if (state.serializedPlan === null || state.serializedHandoff === null || state.trust === null) {
    fail('ownership_invalid');
  }
  let decodedPlan: unknown;
  try {
    decodedPlan = JSON.parse(state.serializedPlan);
    if (canonicalJson(decodedPlan) !== state.serializedPlan) fail('ownership_invalid');
  } catch {
    fail('ownership_invalid');
  }
  const plan = await verifyStaticDeployPlanIntegrity(decodedPlan).catch(() =>
    fail('ownership_invalid'));
  if (state.adoptionReceipt !== null) {
    const adopted = await verifyCustomerGatewayOwnershipAdoption({
      storage: input.storage,
      pinnedIssuerPublicKey: state.trust.pinnedIssuerPublicKey,
    }).catch(() => fail('ownership_invalid'));
    return Object.freeze({ receipt: adopted.receipt, bootstrapVersionId: adopted.bootstrapVersionId, plan });
  }
  const bootstrap = input.bootstrap;
  if (bootstrap === undefined) fail('runtime_source_unavailable');
  const now = clock(input);
  const handoff = await verifyCloudflareBootstrapOwnershipHandoff({
    now,
    pinnedPublicKey: state.trust.pinnedIssuerPublicKey,
    serializedHandoff: state.serializedHandoff,
  }).catch(() => fail('ownership_invalid'));
  const statement = handoff.statement;
  const expected = bootstrap.expectedBindings;
  const workerName = managementWorkerName(plan);
  const expectedValues: CustomerStage2BootstrapBindings = Object.freeze({
    ANKKA_BOOTSTRAP_CALLBACK: state.trust.bootstrapCallback,
    ANKKA_BOOTSTRAP_EXPIRES_AT: String(statement.bootstrapSecret.expiresAt),
    ANKKA_BOOTSTRAP_ID: expected.ANKKA_BOOTSTRAP_ID,
    ANKKA_BOOTSTRAP_SECRET_SHA256: statement.bootstrapSecret.commitment,
    ANKKA_GATEWAY_RELEASE: plan.releaseId,
    ANKKA_GATEWAY_RELEASE_SHA256: `sha256:${plan.releaseArtifactSha256}`,
    ANKKA_INSTALL_ID: plan.managementOwnershipMarker,
    ANKKA_INSTALLER_ORIGIN: PUBLIC_ORIGIN,
    ANKKA_MANAGEMENT_HOSTNAME: plan.gatewayConfiguration.managementHostname,
    ANKKA_PLAN_HASH: plan.planHash,
    ANKKA_PLAN_ID: plan.planId,
    ANKKA_UPDATE_CHANNEL: input.runtime.updateChannel,
    ANKKA_UPDATE_KEY_ID: input.runtime.updateKeyId,
    ANKKA_UPDATE_PUBLIC_KEY: input.runtime.updatePublicKey,
    ANKKA_WORKER_NAME: workerName,
    CLOUDFLARE_ACCOUNT_ID: statement.accountId,
    CLOUDFLARE_CUSTOMER_OAUTH_CLIENT_ID: state.trust.publicClientId,
    CLOUDFLARE_OWNERSHIP_ISSUER_KEY_ID: state.trust.issuerKeyId,
    CLOUDFLARE_OWNERSHIP_ISSUER_PUBLIC_KEY: state.trust.pinnedIssuerPublicKey,
  });
  if (!/^boot_[A-Za-z0-9_-]{24}$/u.test(expected.ANKKA_BOOTSTRAP_ID) ||
      !exact(expected, expectedValues) || statement.plan.id !== plan.planId ||
      statement.plan.hash !== plan.planHash || statement.release.id !== plan.releaseId ||
      statement.release.artifactSha256 !== plan.releaseArtifactSha256 ||
      statement.installId !== plan.managementOwnershipMarker || statement.worker.name !== workerName) {
    fail('ownership_invalid');
  }
  const readback = await readCustomerBootstrapWorkerOwnership({
    accessToken: input.accessToken,
    accountId: statement.accountId,
    workerName,
    serializedHandoff: state.serializedHandoff,
    pinnedIssuerPublicKey: state.trust.pinnedIssuerPublicKey,
    expectedBootstrapSourceSha256: plan.bootstrapWorkerSourceSha256,
    expectedBindings: expected,
    transport: input.transport,
    now: () => clock(input),
  });
  const receipt = await adoptCustomerGatewayOwnership({
    storage: input.storage,
    pinnedIssuerPublicKey: state.trust.pinnedIssuerPublicKey,
    providerReadback: readback.providerReadback,
    activeVersionId: readback.activeVersionId,
    now: clock(input),
  }).catch(() => fail('ownership_invalid'));
  return Object.freeze({ receipt, bootstrapVersionId: readback.activeVersionId, plan });
}

async function ownershipReceiptHash(receipt: CloudflareBootstrapOwnershipAdoptionReceipt): Promise<string> {
  return `sha256:${await sha256Hex(canonicalJson(receipt))}`;
}

async function finalRuntimeHash(source: string): Promise<string> {
  const size = new TextEncoder().encode(source).byteLength;
  if (size < 1 || size > 8 * 1024 * 1024) fail('invalid');
  return sha256Hex(source);
}

function finalBindings(
  context: Context,
  application: ManagementAccessApplicationLocator,
): GatewayWorkerPlainTextBindings {
  return Object.freeze({
    ADMIN_EMAILS: context.plan.managementAdminEmails.join(','),
    ANKKA_INSTALL_ID: context.journal.identity.installId,
    ANKKA_GATEWAY_RELEASE: context.plan.releaseId,
    ANKKA_GATEWAY_RELEASE_SHA256: `sha256:${context.plan.releaseArtifactSha256}`,
    ANKKA_MANAGEMENT_HOSTNAME: context.plan.gatewayConfiguration.managementHostname,
    ANKKA_UPDATE_CHANNEL: context.journal.identity.updateChannel,
    ANKKA_UPDATE_KEY_ID: context.journal.identity.updateKeyId,
    ANKKA_UPDATE_PUBLIC_KEY: context.journal.identity.updatePublicKey,
    ANKKA_WORKERS_SUBDOMAIN: context.workersSubdomain,
    ANKKA_WORKER_NAME: context.journal.identity.workerName,
    CF_ACCESS_AUD: application.aud,
    CF_ACCESS_ISSUER: context.organization.issuer,
    CLOUDFLARE_ACCOUNT_ID: context.target.accountId,
    CLOUDFLARE_ZONE_ID: context.target.zoneId,
    CLOUDFLARE_ZONE_NAME: context.target.zoneName,
    ZERO_TRUST_READY: 'true',
  });
}

function providerCall(context: Context) {
  return {
    accessToken: context.input.accessToken,
    transport: (request: Request) => context.input.transport(request),
  };
}

function applicationOperation(context: Context) {
  return {
    ...providerCall(context),
    accountId: context.target.accountId,
    zoneId: context.target.zoneId,
    plan: context.plan,
    allowedIdentityProviderIds: context.identityProviderIds,
  };
}

function policyOperation(context: Context, application: ManagementAccessApplicationLocator) {
  return {
    ...providerCall(context),
    accountId: context.target.accountId,
    zoneId: context.target.zoneId,
    applicationId: application.applicationId,
    plan: context.plan,
  };
}

function domainOperation(context: Context) {
  return {
    ...providerCall(context),
    accountId: context.target.accountId,
    zoneId: context.target.zoneId,
    plan: context.plan,
  };
}

function runtimeInspection(context: Context, application: ManagementAccessApplicationLocator) {
  return {
    accessToken: context.input.accessToken,
    accountId: context.target.accountId,
    workerName: context.journal.identity.workerName,
    expectedWorkerId: context.journal.identity.workerId,
    finalRuntimeSha256: context.journal.identity.finalRuntimeSha256,
    bindings: finalBindings(context, application),
    transport: context.input.transport,
  };
}

function workersDevOperation(context: Context) {
  return {
    ...providerCall(context),
    accountId: context.target.accountId,
    plan: context.plan,
  };
}

// Each proof re-reads the provider once per run. The post-submit read of a
// step is always the first proof of its resource in that run; the trailing
// re-checks and the terminal proof then cost nothing more, which is what
// keeps a chunked run inside the per-invocation subrequest budget.
async function proveApplication(
  context: Context,
  locator: ManagementAccessApplicationLocator,
): Promise<void> {
  const key = `application:${canonicalJson(locator)}`;
  if (context.proofs.has(key)) return;
  const operation = applicationOperation(context);
  await verifyManagementAccessApplicationGet({ ...operation, ...locator });
  await verifyManagementAccessApplicationList({ ...operation, ...locator });
  context.proofs.set(key, true);
}

async function provePolicy(
  context: Context,
  application: ManagementAccessApplicationLocator,
  locator: ManagementAdminPolicyLocator,
): Promise<void> {
  const key = `policy:${canonicalJson({ application, locator })}`;
  if (context.proofs.has(key)) return;
  const operation = policyOperation(context, application);
  await verifyManagementAdminAllowPolicyGet({ ...operation, ...locator });
  await verifyManagementAdminAllowPolicyList({ ...operation, ...locator });
  context.proofs.set(key, true);
}

async function proveGatewayResources(context: Context): Promise<void> {
  const key = 'gateway_resources';
  if (context.proofs.has(key)) return;
  await verifyGatewayResources(context);
  context.proofs.set(key, true);
}

async function proveDomain(context: Context, locator: ManagementCustomDomainLocator): Promise<void> {
  const key = `domain:${canonicalJson(locator)}`;
  if (context.proofs.has(key)) return;
  const operation = domainOperation(context);
  await verifyManagementCustomDomainGet({ ...operation, ...locator });
  await verifyManagementCustomDomainList({ ...operation, ...locator });
  context.proofs.set(key, true);
}

async function proveFinalRuntime(
  context: Context,
  application: ManagementAccessApplicationLocator,
): Promise<CustomerWorkerActiveRelease | null> {
  const key = `runtime:${canonicalJson(application)}`;
  const proven = context.proofs.get(key);
  if (proven !== undefined && proven !== true) return proven;
  const observed = await inspectCustomerWorkerFinalRuntime(runtimeInspection(context, application));
  if (observed !== null) context.proofs.set(key, observed);
  return observed;
}

async function proveWorkersDevDisabled(context: Context): Promise<void> {
  const key = 'workers_dev_disabled';
  if (context.proofs.has(key)) return;
  await verifyWorkerBootstrapSubdomain({ ...workersDevOperation(context), expectedEnabled: false });
  context.proofs.set(key, true);
}

async function convergeApplication(context: Context): Promise<ManagementAccessApplicationLocator> {
  const name = 'management_access_application' as const;
  const operation = applicationOperation(context);
  const intent = prepareManagementAccessApplicationIntent(operation);
  await prepareAction(context, name, jsonObject(intent));
  let action = customerStage2Action(context.journal, name);
  let armedHere = false;
  if (action?.phase === 'prepared') {
    if (clock(context.input, context.journal.updatedAt) >= context.journal.preflight.expiresAt) {
      fail('provider_mismatch');
    }
    await armAction(context, name);
    action = customerStage2Action(context.journal, name);
    armedHere = true;
  }
  if (action?.phase === 'send_armed') {
    const locator = armedHere
      ? await createManagementAccessApplication({ ...operation, intent })
      : (await recoverManagementAccessApplication({ ...operation, intent })).locator;
    await submitAction(context, name, jsonValue(locator));
    action = customerStage2Action(context.journal, name);
  }
  if (action?.phase === 'submitted') {
    await proveApplication(context, applicationLocator(action.locator));
    await verifyAction(context, name);
    action = customerStage2Action(context.journal, name);
  }
  const locator = applicationLocator(action?.locator ?? null);
  await proveApplication(context, locator);
  return locator;
}

async function convergePolicy(
  context: Context,
  application: ManagementAccessApplicationLocator,
): Promise<ManagementAdminPolicyLocator> {
  const name = 'management_admin_policy' as const;
  const operation = policyOperation(context, application);
  const intent = prepareManagementAdminPolicyIntent(operation);
  await prepareAction(context, name, jsonObject(intent));
  let action = customerStage2Action(context.journal, name);
  let armedHere = false;
  if (action?.phase === 'prepared') {
    await armAction(context, name);
    action = customerStage2Action(context.journal, name);
    armedHere = true;
  }
  if (action?.phase === 'send_armed') {
    const locator = armedHere
      ? await createManagementAdminAllowPolicy({ ...operation, intent })
      : (await recoverManagementAdminAllowPolicy({ ...operation, intent })).locator;
    await submitAction(context, name, jsonValue(locator));
    action = customerStage2Action(context.journal, name);
  }
  if (action?.phase === 'submitted') {
    await provePolicy(context, application, policyLocator(action.locator));
    await verifyAction(context, name);
    action = customerStage2Action(context.journal, name);
  }
  const locator = policyLocator(action?.locator ?? null);
  await provePolicy(context, application, locator);
  return locator;
}

function gatewayActionRecord(context: Context, projectionHash: string): JsonObject {
  return jsonObject({
    schemaVersion: 1,
    kind: 'gateway_resources',
    accountId: context.target.accountId,
    zoneId: context.target.zoneId,
    planId: context.plan.planId,
    planHash: context.plan.planHash,
    installationId: context.journal.identity.installId,
    configurationHash: context.journal.identity.configurationHash,
    desiredHash: context.journal.identity.desiredHash,
    projectionHash,
  });
}

async function verifyGatewayResources(context: Context): Promise<void> {
  const plan = await renewedPlan(context.plan, clock(context.input, context.journal.updatedAt));
  const verdict = await context.input.payload.verifyReady({
    accessToken: context.input.accessToken,
    plan,
    target: context.target,
  });
  if (verdict.verified !== true) {
    const reason = v.is(v.string(), verdict.reason) && VERIFY_REASON.test(verdict.reason)
      ? `verify_${verdict.reason}`
      : 'verify_unknown';
    fail('payload_recovery_required', reason);
  }
}

async function convergeGatewayResources(context: Context): Promise<v.InferOutput<typeof gatewayLocatorSchema>> {
  const name = 'gateway_resources' as const;
  const projection = await prepareCustomerGatewayDesiredProjectionFromPlan({
    plan: context.plan,
    target: context.target,
  });
  const projectionHash = `sha256:${await sha256Hex(canonicalJson({
    ...projection,
    plan: { planId: projection.plan.planId, planHash: projection.plan.planHash },
  }))}`;
  await prepareAction(context, name, gatewayActionRecord(context, projectionHash));
  let action = customerStage2Action(context.journal, name);
  if (action?.phase === 'prepared') {
    await armAction(context, name);
    action = customerStage2Action(context.journal, name);
  }
  if (action?.phase === 'send_armed') {
    const bootstrap = context.input.bootstrap;
    if (bootstrap === undefined) fail('runtime_source_unavailable');
    const plan = await renewedPlan(context.plan, clock(context.input, context.journal.updatedAt));
    const result = await submitCustomerBootstrapFromPlan({
      plan,
      target: context.target,
      accountWorkersSubdomain: {
        accountId: context.target.accountId,
        subdomain: context.workersSubdomain,
      },
      bootstrapNonce: bootstrap.nonce,
      cloudflareAccessToken: context.input.accessToken,
      transport: (request) => context.input.payload.bootstrap(request, { plan, target: context.target }),
      timeoutMs: 120_000,
      nowMs: clock(context.input, context.journal.updatedAt),
    });
    if (result.status !== 'ready') fail('payload_recovery_required', result.detail ?? result.reason);
    await submitAction(context, name, gatewayReadyLocator(result));
    action = customerStage2Action(context.journal, name);
  }
  if (action?.phase === 'submitted') {
    const locator = gatewayLocator(action.locator);
    if (locator.configurationHash !== context.journal.identity.configurationHash ||
        locator.desiredHash !== context.journal.identity.desiredHash ||
        locator.installationId !== context.journal.identity.installId ||
        locator.gatewayHostname !== context.plan.gatewayConfiguration.portalHostname) {
      fail('journal_mismatch');
    }
    await proveGatewayResources(context);
    await verifyAction(context, name);
    action = customerStage2Action(context.journal, name);
  }
  const locator = gatewayLocator(action?.locator ?? null);
  if (locator.resourceCount !== projection.resourceKinds.length ||
      locator.configurationHash !== projection.expected.configurationHash ||
      locator.desiredHash !== projection.expected.desiredHash ||
      locator.installationId !== projection.expected.installationId) fail('journal_mismatch');
  await proveGatewayResources(context);
  return locator;
}

async function convergeDomain(context: Context): Promise<ManagementCustomDomainLocator> {
  const name = 'management_custom_domain' as const;
  const operation = domainOperation(context);
  const intent = prepareManagementCustomDomainIntent(operation);
  await prepareAction(context, name, jsonObject(intent));
  let action = customerStage2Action(context.journal, name);
  let armedHere = false;
  if (action?.phase === 'prepared') {
    await armAction(context, name);
    action = customerStage2Action(context.journal, name);
    armedHere = true;
  }
  if (action?.phase === 'send_armed') {
    const locator = armedHere
      ? await attachManagementCustomDomain({ ...operation, intent })
      : (await recoverManagementCustomDomain({ ...operation, intent })).locator;
    await submitAction(context, name, jsonValue(locator));
    action = customerStage2Action(context.journal, name);
  }
  if (action?.phase === 'submitted') {
    await proveDomain(context, domainLocator(action.locator));
    await verifyAction(context, name);
    action = customerStage2Action(context.journal, name);
  }
  const locator = domainLocator(action?.locator ?? null);
  await proveDomain(context, locator);
  return locator;
}

/** Returns true when the upload was handed over to the final runtime. */
async function convergeFinalRuntime(
  context: Context,
  application: ManagementAccessApplicationLocator,
): Promise<boolean> {
  const name = 'final_runtime' as const;
  const bindings = finalBindings(context, application);
  const record = jsonObject({
    schemaVersion: 1,
    kind: 'final_runtime',
    workerId: context.journal.identity.workerId,
    previousVersionId: context.journal.identity.bootstrapVersionId,
    finalRuntimeSha256: context.journal.identity.finalRuntimeSha256,
    bindings,
  });
  await prepareAction(context, name, record);
  let action = customerStage2Action(context.journal, name);
  if (action?.phase === 'prepared') {
    await armAction(context, name);
    action = customerStage2Action(context.journal, name);
  }
  const inspection = runtimeInspection(context, application);
  if (action?.phase === 'send_armed') {
    const source = context.input.finalRuntimeSource;
    const handover = context.input.handover;
    if (source !== undefined && handover !== undefined) {
      // Last durable word from this code: the state is marked finalizing and
      // an alarm is armed for the final runtime before anything is uploaded.
      await handover();
      await uploadCustomerWorkerFinalRuntime({
        ...inspection,
        finalRuntimeSource: source,
        previousVersionId: context.journal.identity.bootstrapVersionId,
      });
      return true;
    }
    const locator = source === undefined
      ? await inspectCustomerWorkerFinalRuntime(inspection)
      : await publishCustomerWorkerFinalRuntime({
        ...inspection,
        finalRuntimeSource: source,
        previousVersionId: context.journal.identity.bootstrapVersionId,
      });
    if (locator === null) fail('runtime_source_unavailable');
    await submitAction(context, name, jsonValue(locator));
    action = customerStage2Action(context.journal, name);
  }
  const persisted = workerReleaseLocator(action?.locator ?? null);
  if (action?.phase === 'submitted') {
    const observed = await proveFinalRuntime(context, application);
    if (observed === null || !exact(observed, persisted)) fail('provider_mismatch');
    await verifyAction(context, name);
    action = customerStage2Action(context.journal, name);
  }
  const observed = await proveFinalRuntime(context, application);
  if (observed === null || !exact(observed, workerReleaseLocator(action?.locator ?? null))) {
    fail('provider_mismatch');
  }
  await persistTransition(context, completeCustomerStage2Journal(context.journal, {
    attemptId: context.input.attemptId,
    now: clock(context.input, context.journal.updatedAt),
  }));
  return false;
}

async function convergeWorkersDev(context: Context): Promise<void> {
  const name = 'workers_dev_disable' as const;
  const operation = workersDevOperation(context);
  await prepareAction(context, name, jsonObject({
    schemaVersion: 1,
    kind: 'workers_dev_disable',
    workerName: context.journal.identity.workerName,
    enabled: false,
    previewsEnabled: false,
  }));
  let action = customerStage2Action(context.journal, name);
  if (action?.phase === 'prepared') {
    await armAction(context, name);
    action = customerStage2Action(context.journal, name);
  }
  if (action?.phase === 'send_armed') {
    let state;
    try {
      state = await verifyWorkerBootstrapSubdomain({ ...operation, expectedEnabled: false });
    } catch (firstError) {
      try {
        await verifyWorkerBootstrapSubdomain({ ...operation, expectedEnabled: true });
      } catch {
        throw firstError;
      }
      state = await setWorkerBootstrapSubdomain({ ...operation, enabled: false });
    }
    await submitAction(context, name, jsonValue(state));
    action = customerStage2Action(context.journal, name);
  }
  if (action?.phase === 'submitted') {
    await proveWorkersDevDisabled(context);
    await verifyAction(context, name);
  }
  await proveWorkersDevDisabled(context);
}

async function terminalProof(
  context: Context,
  application: ManagementAccessApplicationLocator,
  policy: ManagementAdminPolicyLocator,
  domain: ManagementCustomDomainLocator,
  runtime: boolean,
): Promise<void> {
  await proveApplication(context, application);
  await provePolicy(context, application, policy);
  await proveGatewayResources(context);
  await proveDomain(context, domain);
  await proveWorkersDevDisabled(context);
  if (!runtime) return;
  const release = await proveFinalRuntime(context, application);
  if (release === null) fail('provider_mismatch');
}

async function convergeTerminal(
  context: Context,
  application: ManagementAccessApplicationLocator,
  policy: ManagementAdminPolicyLocator,
  domain: ManagementCustomDomainLocator,
): Promise<void> {
  const name = 'terminal_verify' as const;
  await terminalProof(context, application, policy, domain, false);
  const prerequisiteHash = `sha256:${await sha256Hex(canonicalJson(
    context.journal.actions.slice(0, 5),
  ))}`;
  const record = jsonObject({
    schemaVersion: 1,
    kind: 'terminal_verify',
    prerequisiteHash,
    postconditions: [
      'ownership-receipt-complete',
      'management-access-enforced',
      'portal-converged',
      'source-set-converged',
      'bootstrap-surface-dead',
      'workers-dev-disabled',
    ],
  });
  await prepareAction(context, name, record);
  let action = customerStage2Action(context.journal, name);
  if (action?.phase === 'prepared') {
    await armAction(context, name);
    action = customerStage2Action(context.journal, name);
  }
  if (action?.phase === 'send_armed') {
    await submitAction(context, name, jsonValue({
      schemaVersion: 1,
      kind: 'terminal_verification',
      prerequisiteHash,
      verified: true,
    }));
    action = customerStage2Action(context.journal, name);
  }
  if (action?.phase === 'submitted') {
    await terminalProof(context, application, policy, domain, false);
    await verifyAction(context, name);
  }
}

function success(): CustomerBootstrapConvergenceResult {
  return Object.freeze({
    verified: true,
    ownershipReceipt: 'complete',
    managementAccess: 'enforced',
    portal: 'converged',
    sourceSet: 'converged',
    finalRuntime: 'active-recovery-capable',
    workersDev: 'disabled',
  });
}

function identityMatches(left: CustomerStage2Identity, right: CustomerStage2Identity): boolean {
  return exact(left, right);
}

/**
 * Complete the fixed Stage 2 install inside the customer Durable Object. The
 * Cloudflare token is passed only to direct provider calls and the co-resident
 * payload adapter; every durable transition is schema-limited and secret-free.
 */
export async function convergeCustomerStage2(
  input: CustomerStage2ConvergerInput,
): Promise<CustomerStage2ConvergerResult> {
  if (!ATTEMPT_ID.test(input.attemptId) || !v.is(callableSchema, input.now) ||
      !v.is(callableSchema, input.transport) || !v.is(callableSchema, input.payload.bootstrap) ||
      !v.is(callableSchema, input.payload.verifyReady)) fail('invalid');
  const adopted = await adoptOwnership(input);
  const startedAt = clock(input);
  const plan = await renewedPlan(adopted.plan, startedAt);
  const workerName = managementWorkerName(plan);
  const zone = await resolveAuthorizedCloudflareZone({
    accessToken: input.accessToken,
    accountId: adopted.receipt.accountId,
    zoneName: plan.gatewayConfiguration.zoneName,
    transport: input.transport,
  });
  const target: CustomerBootstrapTarget = Object.freeze({
    accountId: adopted.receipt.accountId,
    zoneId: zone.id,
    zoneName: zone.name,
  });
  const projection = await prepareCustomerGatewayDesiredProjectionFromPlan({ plan, target });
  const call = {
    accessToken: input.accessToken,
    transport: (request: Request) => input.transport(request),
  };
  const organization = await getZeroTrustOrganization({ ...call, accountId: target.accountId });
  const identityProviderIds = (await listAccessIdentityProviders({
    ...call,
    accountId: target.accountId,
  })).map((provider) => provider.id);
  const workers = await getAccountWorkersSubdomain({ ...call, accountId: target.accountId });
  const receiptSha256 = await ownershipReceiptHash(adopted.receipt);
  let journal = await input.journal.read();
  let runtimeSha256: string;
  if (journal === null) {
    if (input.finalRuntimeSource === undefined) fail('runtime_source_unavailable');
    runtimeSha256 = await finalRuntimeHash(input.finalRuntimeSource);
  } else {
    runtimeSha256 = journal.identity.finalRuntimeSha256;
    if (input.finalRuntimeSource !== undefined &&
        await finalRuntimeHash(input.finalRuntimeSource) !== runtimeSha256) fail('journal_mismatch');
  }
  const identity: CustomerStage2Identity = Object.freeze({
    accountId: target.accountId,
    zoneId: target.zoneId,
    zoneName: target.zoneName,
    installId: plan.managementOwnershipMarker,
    planId: plan.planId,
    planHash: plan.planHash,
    configurationHash: projection.expected.configurationHash,
    desiredHash: projection.expected.desiredHash,
    workerName,
    workerId: adopted.receipt.ownership.worker.providerId,
    namespaceId: adopted.receipt.ownership.adminStateNamespace.providerId,
    bootstrapVersionId: adopted.bootstrapVersionId,
    releaseId: plan.releaseId,
    releaseArtifactSha256: plan.releaseArtifactSha256,
    finalRuntimeSha256: runtimeSha256,
    updateChannel: input.runtime.updateChannel,
    updateKeyId: input.runtime.updateKeyId,
    updatePublicKey: input.runtime.updatePublicKey,
    ownershipReceiptSha256: receiptSha256,
  });
  if (journal === null) {
    await preflightFreshManagementAccessApplication({
      ...call,
      accountId: target.accountId,
      zoneId: target.zoneId,
      plan,
    });
    await preflightFreshManagementCustomDomain({
      ...call,
      accountId: target.accountId,
      zoneId: target.zoneId,
      plan,
    });
    // Finish with the broad customer-resource scan so its short attestation
    // window covers the first mutation rather than the earlier prerequisites.
    const preflight = await preflightFreshCustomerGatewayProjection({
      ...call,
      projection,
      managementHostname: plan.gatewayConfiguration.managementHostname,
      nowMs: clock(input),
    });
    const now = clock(input, preflight.checkedAt);
    journal = createCustomerStage2Journal({
      now,
      leaseExpiresAt: now + LEASE_TTL_MS,
      attemptId: input.attemptId,
      identity,
      organization,
      identityProviderIds,
      workersSubdomain: workers.subdomain,
      preflight,
    });
    if (!await input.journal.compareAndSet(null, journal)) fail('journal_conflict');
  } else {
    if (!identityMatches(journal.identity, identity) || !exact(journal.organization, organization) ||
        !exact(journal.identityProviderIds, identityProviderIds) ||
        journal.workersSubdomain !== workers.subdomain) fail('journal_mismatch');
    if (journal.completedAt !== null) {
      const completed: Context = {
        input,
        plan,
        target,
        organization,
        identityProviderIds,
        workersSubdomain: workers.subdomain,
        journal,
        proofs: new Map(),
      };
      const application = applicationLocator(
        customerStage2Action(journal, 'management_access_application')?.locator ?? null,
      );
      const policy = policyLocator(
        customerStage2Action(journal, 'management_admin_policy')?.locator ?? null,
      );
      const domain = domainLocator(
        customerStage2Action(journal, 'management_custom_domain')?.locator ?? null,
      );
      await terminalProof(completed, application, policy, domain, true);
      return success();
    }
    const acquiredAt = clock(input, journal.updatedAt);
    const acquired = acquireCustomerStage2Lease(journal, {
      attemptId: input.attemptId,
      now: acquiredAt,
      leaseExpiresAt: acquiredAt + LEASE_TTL_MS,
    });
    if (acquired.revision !== journal.revision) {
      if (!await input.journal.compareAndSet(journal.revision, acquired)) fail('journal_conflict');
      journal = acquired;
    }
  }
  const context: Context = {
    input,
    plan,
    target,
    organization,
    identityProviderIds,
    workersSubdomain: workers.subdomain,
    journal,
    proofs: new Map(),
  };
  try {
    const application = await convergeApplication(context);
    const policy = await convergePolicy(context, application);
    await convergeGatewayResources(context);
    const domain = await convergeDomain(context);
    await convergeWorkersDev(context);
    await convergeTerminal(context, application, policy, domain);
    const handedOver = await convergeFinalRuntime(context, application);
    return handedOver ? Object.freeze({ verified: false, handedOver: true }) : success();
  } catch (error) {
    if (error instanceof CustomerStage2Pause) {
      // The lease stays with this attempt: the next run continues it.
      return Object.freeze({ verified: false, paused: true, checkpoint: error.checkpoint });
    }
    const lease = context.journal.lease;
    if (context.journal.completedAt === null && lease?.attemptId === input.attemptId) {
      try {
        const releasedAt = clock(input, context.journal.updatedAt);
        if (lease.expiresAt <= releasedAt) throw new Error('lease_expired');
        await persistTransition(context, releaseCustomerStage2Lease(context.journal, {
          attemptId: input.attemptId,
          now: releasedAt,
        }));
      } catch {
        // The original fixed failure remains authoritative; a CAS race is
        // visible to the next fresh authorization.
      }
    }
    throw error;
  }
}

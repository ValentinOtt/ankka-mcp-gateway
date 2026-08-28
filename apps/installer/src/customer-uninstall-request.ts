import type { AccountWorkersSubdomain } from './cloudflare-management-surface';
import {
  isCompleteInstallJournal,
  prepareFinalConvergenceRecordAndLocator,
  requireInstallJournal,
  type FinalConvergenceLocator,
  type InstallJournal,
} from './install-journal';
import type {
  InstallationReceiptAccessPolicy,
  InstallationReceiptTarget,
  ReadyInstallationReceipt,
} from './provider-neutral-installation-receipt';
import { base64UrlEncode } from './crypto';
import {
  buildStaticUninstallPlan,
  parseStaticUninstallPlan,
  type StaticUninstallPlan,
} from './uninstall-plan';

const UNINSTALL_PATH = '/__ankka/uninstall';
const NONCE_DERIVATION_DOMAIN = 'ankka-mcp-gateway/customer-uninstall-nonce/v1';
const REQUEST_LIFETIME_SECONDS = 5 * 60;
const MAX_CLOCK_SKEW_SECONDS = 30;
const REQUEST_LIMIT_BYTES = 96 * 1024;
const RESPONSE_LIMIT_BYTES = 96 * 1024;
/**
 * The public cleanup contract has no retry: an unknown outcome cannot be
 * replayed. The Worker removes every gateway resource inside this one request,
 * so the ceiling matches the install-side bootstrap submit rather than a
 * typical API call (live 2026-08-23: 15s aborted a request that was in flight).
 */
const REQUEST_TIMEOUT_MS = 90_000;
const REQUEST_ID_BYTES = 16;
const NONCE_BYTES = 32;
const MAX_ACCESS_TOKEN_LENGTH = 16 * 1024;
const REQUEST_ID = /^[A-Za-z0-9_-]{22}$/u;
const NONCE = /^[A-Za-z0-9_-]{43}$/u;
const ACCOUNT_ID = /^[a-f0-9]{32}$/u;
const WORKER_NAME = /^[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$/u;
const HOST_LABEL = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/u;
const HASH = /^sha256:[a-f0-9]{64}$/u;
const INSTALLATION_ID = /^acg-[a-f0-9]{24}$/u;
const UNINSTALL_ID = /^uninstall-[a-f0-9]{24}$/u;
const RELEASE = /^[A-Za-z0-9][A-Za-z0-9._+-]{0,79}$/u;
const CONTROL_CHARACTER = /[\u0000-\u001f\u007f]/u;
const STANDARD_BASE64_KEY = /^[A-Za-z0-9+/]{43}=$/u;
const BASE64URL_KEY = /^[A-Za-z0-9_-]{43}$/u;
const ATTEMPT_ID = /^att_[A-Za-z0-9_-]{32}$/u;

export type CustomerUninstallStage =
  | 'validate'
  | 'claim'
  | 'sign'
  | 'submit'
  | 'response';

export type CustomerUninstallOutcome = 'not_sent' | 'rejected' | 'unknown';

export type CustomerUninstallErrorCode =
  | 'invalid_input'
  | 'install_authority_invalid'
  | 'request_expired'
  | 'origin_invalid'
  | 'sign_failed'
  | 'outcome_unknown'
  | 'uninstall_rejected'
  | 'response_invalid';

/** Value-free failure surface; no provider body, nonce, token, or request body is retained. */
export class CustomerUninstallRequestError extends Error {
  readonly canRetry = false;

  constructor(
    readonly code: CustomerUninstallErrorCode,
    readonly stage: CustomerUninstallStage,
    readonly outcome: CustomerUninstallOutcome,
  ) {
    super(code);
    this.name = 'CustomerUninstallRequestError';
  }
}

/** Value-free derivation failure; the source key and derived nonce are never reflected. */
export class CustomerUninstallNonceDerivationError extends Error {
  readonly code = 'customer_uninstall_nonce_derivation_invalid';

  constructor() {
    super('customer_uninstall_nonce_derivation_invalid');
    this.name = 'CustomerUninstallNonceDerivationError';
  }
}

export interface CustomerUninstallTarget {
  readonly accountId: string;
  readonly zoneId: string;
  readonly zoneName: string;
}

export interface CustomerUninstallReleaseEvidence {
  readonly id: string;
  readonly artifactSha256: string;
}

export interface CustomerUninstallExpectedEvidence {
  readonly configurationHash: string;
  readonly installationId: string;
  readonly desiredHash: string;
  readonly readyReceipt: ReadyInstallationReceipt;
}

/** Exact credential-free portion of the public cleanup Worker's request body. */
export interface PreparedCustomerUninstallClaim {
  readonly schemaVersion: 1;
  readonly requestId: string;
  readonly issuedAt: number;
  readonly expiresAt: number;
  readonly target: CustomerUninstallTarget;
  readonly release: CustomerUninstallReleaseEvidence;
  readonly expected: CustomerUninstallExpectedEvidence;
}

/**
 * Persist this before the one POST. It deliberately excludes the nonce, OAuth
 * grant, raw/canonical body, signature, Request, and Response.
 */
export interface CustomerUninstallSemanticRecord {
  readonly schemaVersion: 1;
  readonly kind: 'customer_uninstall_submit';
  readonly accountId: string;
  readonly zoneId: string;
  readonly zoneName: string;
  readonly accountWorkersSubdomain: string;
  readonly workerName: string;
  readonly requestId: string;
  readonly issuedAt: number;
  readonly expiresAt: number;
  readonly installationId: string;
  readonly configurationHash: string;
  readonly desiredHash: string;
  readonly release: CustomerUninstallReleaseEvidence;
  readonly rootReceiptRevision: number;
  readonly rootReceiptChecksum: string;
  readonly installBindingHash: string;
  readonly installConvergenceHash: string;
  readonly adminStateNamespaceId: string;
  readonly uninstallPlanId: string;
  readonly uninstallPlanHash: string;
  readonly authorityHash: string;
  readonly approvalAttemptId: string;
  readonly claimHash: string;
}

/** Only `ephemeral.claim` stays in the live call stack; `semantic` is journal-safe. */
export interface CustomerUninstallMutationPlan {
  readonly ephemeral: {
    readonly claim: PreparedCustomerUninstallClaim;
  };
  readonly semantic: CustomerUninstallSemanticRecord;
}

export interface RemovedInstallationReceipt {
  readonly schemaVersion: 1;
  readonly manager: 'ankka-mcp-gateway';
  readonly installationId: string;
  readonly state: 'removed';
  readonly revision: number;
  readonly release: string;
  readonly target: InstallationReceiptTarget;
  readonly accessPolicy: InstallationReceiptAccessPolicy;
  readonly desiredHash: string;
  readonly resources: readonly [];
  readonly pending: null;
  readonly checksum: string;
}

interface CustomerUninstallLocatorAuthority {
  readonly requestId: string;
  readonly accountId: string;
  readonly zoneId: string;
  readonly zoneName: string;
  readonly accountWorkersSubdomain: string;
  readonly workerName: string;
  readonly installationId: string;
  readonly configurationHash: string;
  readonly desiredHash: string;
  readonly release: CustomerUninstallReleaseEvidence;
  readonly installBindingHash: string;
  readonly installConvergenceHash: string;
  readonly adminStateNamespaceId: string;
  readonly uninstallPlanId: string;
  readonly uninstallPlanHash: string;
  readonly authorityHash: string;
  readonly approvalAttemptId: string;
}

export interface CustomerUninstallRemovedLocator extends CustomerUninstallLocatorAuthority {
  readonly schemaVersion: 1;
  readonly status: 'removed';
  readonly uninstallId: string;
  readonly receipt: {
    readonly revision: number;
    readonly resourceCount: 0;
    readonly evidence: RemovedInstallationReceipt;
  };
  readonly uninstallInvoked: boolean;
  readonly resumed: boolean;
}

export type CustomerUninstallRecoveryReason =
  | 'uninstall_recovery_required'
  | 'uninstall_fresh_grant_required'
  | 'uninstall_requires_repair'
  | 'uninstall_request_mismatch'
  | 'uninstall_blocked';

export interface CustomerUninstallRecoveryLocator extends CustomerUninstallLocatorAuthority {
  readonly schemaVersion: 1;
  readonly status: 'recovery_required';
  readonly reason: CustomerUninstallRecoveryReason;
  readonly freshGrantRequired: boolean;
}

export type CustomerUninstallLocator =
  | CustomerUninstallRemovedLocator
  | CustomerUninstallRecoveryLocator;

export type CustomerUninstallTransport = (request: Request) => Promise<Response>;

export interface PrepareCustomerUninstallRequestInput {
  /** Exact persisted install journal; it is parsed again rather than trusted by type. */
  readonly installJournal: unknown;
  /** Exact frozen reviewed uninstall plan; provider locators remain private. */
  readonly uninstallPlan: unknown;
  /** Fresh operation approval bound to the exact provider-authorized install target. */
  readonly approval: {
    readonly attemptId: string;
    readonly authorizedTarget: unknown;
  };
  /** Pass the authorized provider result directly; never pass a caller-composed origin. */
  readonly accountWorkersSubdomain: AccountWorkersSubdomain;
  readonly nowMs?: number;
  readonly randomBytes?: (length: number) => Uint8Array;
}

export interface SubmitCustomerUninstallRequestInput {
  /** Exact persisted install journal used during preparation. */
  readonly installJournal: unknown;
  /** Revalidated reviewed plan; an equivalent timestamp renewal is accepted. */
  readonly uninstallPlan: unknown;
  /** Revalidated fresh operation approval. */
  readonly approval: {
    readonly attemptId: string;
    readonly authorizedTarget: unknown;
  };
  /** Previously prepared and journaled one-attempt plan. */
  readonly mutation: CustomerUninstallMutationPlan;
  /** Pass the authorized provider result directly; it must match the prepared record. */
  readonly accountWorkersSubdomain: AccountWorkersSubdomain;
  /** Deterministic 32-byte base64url nonce already installed in the cleanup Worker. */
  readonly uninstallNonce: string;
  /** Fresh OAuth grant; used only as the exact body field required by the public contract. */
  readonly cloudflareAccessToken: string;
  readonly transport: CustomerUninstallTransport;
  /** Server clock captured for this one send; stale prepared claims are not submitted. */
  readonly nowMs: number;
}

interface InstallAuthority {
  readonly journal: InstallJournal;
  readonly final: FinalConvergenceLocator;
  readonly workerName: string;
  readonly target: CustomerUninstallTarget;
  readonly release: CustomerUninstallReleaseEvidence;
  readonly configurationHash: string;
  readonly desiredHash: string;
  readonly readyReceipt: ReadyInstallationReceipt;
}

interface ReviewedUninstallAuthority {
  readonly plan: StaticUninstallPlan;
  readonly approvalAttemptId: string;
}

class CustomerUninstallTimeout extends Error {}

function fail(
  code: CustomerUninstallErrorCode,
  stage: CustomerUninstallStage,
  outcome: CustomerUninstallOutcome,
): never {
  throw new CustomerUninstallRequestError(code, stage, outcome);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  try {
    if (Object.getPrototypeOf(value) !== Object.prototype) return false;
    if (Reflect.ownKeys(value).some((key) => typeof key !== 'string')) return false;
    return Object.values(Object.getOwnPropertyDescriptors(value)).every(
      (descriptor) => descriptor.enumerable === true && 'value' in descriptor,
    );
  } catch {
    return false;
  }
}

function exactKeys(value: Record<string, unknown>, expected: readonly string[]): boolean {
  const actual = Object.keys(value).sort(compareText);
  const sortedExpected = [...expected].sort(compareText);
  return actual.length === sortedExpected.length &&
    actual.every((key, index) => key === sortedExpected[index]);
}

function exactDataKeys(value: unknown, expected: readonly string[]): value is Record<string, unknown> {
  return isRecord(value) && exactKeys(value, expected);
}

function compareText(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function isPlainDataTree(
  value: unknown,
  budget = { remaining: 20_000 },
  depth = 0,
): boolean {
  if (
    value === null || typeof value === 'string' || typeof value === 'boolean' ||
    (typeof value === 'number' && Number.isFinite(value))
  ) return true;
  if (typeof value !== 'object' || depth > 64 || --budget.remaining < 0) return false;
  let prototype: object | null;
  let descriptors: PropertyDescriptorMap;
  let keys: readonly PropertyKey[];
  try {
    prototype = Object.getPrototypeOf(value);
    descriptors = Object.getOwnPropertyDescriptors(value);
    keys = Reflect.ownKeys(value);
  } catch {
    return false;
  }
  if (keys.some((key) => typeof key !== 'string')) return false;
  if (Array.isArray(value)) {
    if (prototype !== Array.prototype || value.length > 10_000 || keys.length !== value.length + 1) return false;
    const length = descriptors.length;
    if (!length || !('value' in length) || length.value !== value.length) return false;
    for (let index = 0; index < value.length; index += 1) {
      const descriptor = descriptors[String(index)];
      if (!descriptor || descriptor.enumerable !== true || !('value' in descriptor) ||
          !isPlainDataTree(descriptor.value, budget, depth + 1)) return false;
    }
    return true;
  }
  if (prototype !== Object.prototype) return false;
  return keys.every((key) => {
    const descriptor = descriptors[key as string];
    return Boolean(
      descriptor && descriptor.enumerable === true && 'value' in descriptor &&
      isPlainDataTree(descriptor.value, budget, depth + 1),
    );
  });
}

function canonicalJson(value: unknown): string {
  if (value === null || typeof value === 'boolean' || typeof value === 'string') {
    return JSON.stringify(value);
  }
  if (typeof value === 'number' && Number.isFinite(value)) return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (isRecord(value)) {
    return `{${Object.keys(value)
      .sort(compareText)
      .map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`)
      .join(',')}}`;
  }
  throw new TypeError('canonical_json_invalid');
}

function exactJson(left: unknown, right: unknown): boolean {
  try {
    return canonicalJson(left) === canonicalJson(right);
  } catch {
    return false;
  }
}

async function prefixedSha256(value: string): Promise<string> {
  const digest = new Uint8Array(await crypto.subtle.digest(
    'SHA-256',
    new TextEncoder().encode(value),
  ));
  const result = `sha256:${bytesToHex(digest)}`;
  digest.fill(0);
  return result;
}

function managementWorkerName(journal: InstallJournal): string | null {
  const matches = journal.plan.managementResources.filter(
    (resource) => resource.kind === 'management_worker',
  );
  return matches.length === 1 && WORKER_NAME.test(matches[0].name) ? matches[0].name : null;
}

async function requireInstallAuthority(value: unknown): Promise<InstallAuthority> {
  if (!isPlainDataTree(value)) fail('install_authority_invalid', 'validate', 'not_sent');
  let journal: InstallJournal;
  try {
    journal = await requireInstallJournal(value);
  } catch {
    fail('install_authority_invalid', 'validate', 'not_sent');
  }
  if (!isCompleteInstallJournal(journal)) {
    fail('install_authority_invalid', 'validate', 'not_sent');
  }
  const finalAction = journal.actions.at(-1);
  const workerName = managementWorkerName(journal);
  if (
    !finalAction || finalAction.name !== 'final_convergence' || finalAction.phase !== 'verified' ||
    !finalAction.locator || !workerName
  ) fail('install_authority_invalid', 'validate', 'not_sent');

  let rebuilt: Awaited<ReturnType<typeof prepareFinalConvergenceRecordAndLocator>>;
  try {
    rebuilt = await prepareFinalConvergenceRecordAndLocator(journal);
  } catch {
    fail('install_authority_invalid', 'validate', 'not_sent');
  }
  if (
    !exactJson(finalAction.record, rebuilt.record) ||
    !exactJson(finalAction.locator, rebuilt.locator)
  ) fail('install_authority_invalid', 'validate', 'not_sent');

  const final = rebuilt.locator;
  const bootstrap = journal.actions.find((action) => action.name === 'customer_bootstrap_submit');
  const bootstrapLocator = bootstrap?.phase === 'verified' ? bootstrap.locator : null;
  if (
    !bootstrapLocator || !('status' in bootstrapLocator) || bootstrapLocator.status !== 'ready' ||
    final.customerReceiptRevision !== bootstrapLocator.receipt.revision ||
    !exactJson(final.customerReceiptEvidence, bootstrapLocator.receipt.evidence) ||
    final.customerReceiptRevision !== final.customerReceiptEvidence.revision ||
    final.installationId !== journal.installationId ||
    final.installationId !== final.customerReceiptEvidence.installationId ||
    final.bindingHash !== journal.bindingHash ||
    !ACCOUNT_ID.test(final.adminStateNamespaceId) ||
    final.customerReceiptEvidence.target.accountId !== journal.target.account.id ||
    final.customerReceiptEvidence.target.zoneId !== journal.target.zone.id ||
    final.customerReceiptEvidence.target.zoneName !== journal.target.zone.name ||
    final.customerReceiptEvidence.release !== journal.releasePin.release ||
    final.customerReceiptEvidence.desiredHash !== bootstrapLocator.desiredHash ||
    bootstrapLocator.configurationHash.length === 0 || !HASH.test(bootstrapLocator.configurationHash)
  ) fail('install_authority_invalid', 'validate', 'not_sent');

  return Object.freeze({
    journal,
    final,
    workerName,
    target: Object.freeze({
      accountId: journal.target.account.id,
      zoneId: journal.target.zone.id,
      zoneName: journal.target.zone.name,
    }),
    release: Object.freeze({
      id: journal.releasePin.release,
      artifactSha256: `sha256:${journal.releasePin.artifactSha256}`,
    }),
    configurationHash: bootstrapLocator.configurationHash,
    desiredHash: bootstrapLocator.desiredHash,
    readyReceipt: final.customerReceiptEvidence,
  });
}

function requireProviderSubdomain(
  value: unknown,
  expectedAccountId: string,
): { readonly accountId: string; readonly subdomain: string } {
  if (!exactDataKeys(value, ['accountId', 'subdomain'])) {
    fail('origin_invalid', 'validate', 'not_sent');
  }
  const descriptors = Object.getOwnPropertyDescriptors(value);
  const accountId = descriptors.accountId.value as unknown;
  const subdomain = descriptors.subdomain.value as unknown;
  if (
    accountId !== expectedAccountId || typeof accountId !== 'string' || !ACCOUNT_ID.test(accountId) ||
    typeof subdomain !== 'string' || !HOST_LABEL.test(subdomain)
  ) fail('origin_invalid', 'validate', 'not_sent');
  return Object.freeze({ accountId, subdomain });
}

/** The exact removal endpoint, for a readiness probe before the one-shot POST. */
export function customerUninstallUrl(input: {
  readonly workerName: string;
  readonly accountWorkersSubdomain: { readonly subdomain: string };
}): string {
  return uninstallUrl(input.workerName, input.accountWorkersSubdomain).toString();
}

function uninstallUrl(workerName: string, provider: { readonly subdomain: string }): URL {
  if (!WORKER_NAME.test(workerName) || !HOST_LABEL.test(provider.subdomain)) {
    fail('origin_invalid', 'validate', 'not_sent');
  }
  return new URL(`https://${workerName}.${provider.subdomain}.workers.dev${UNINSTALL_PATH}`);
}

function freshRequestId(generator: ((length: number) => Uint8Array) | undefined): string {
  let generated: Uint8Array;
  try {
    generated = (generator ?? ((length) => {
      const bytes = new Uint8Array(length);
      crypto.getRandomValues(bytes);
      return bytes;
    }))(REQUEST_ID_BYTES);
  } catch {
    fail('invalid_input', 'claim', 'not_sent');
  }
  if (!(generated instanceof Uint8Array) || generated.byteLength !== REQUEST_ID_BYTES) {
    fail('invalid_input', 'claim', 'not_sent');
  }
  const owned = new Uint8Array(generated.byteLength);
  owned.set(generated);
  if (owned.every((byte) => byte === 0)) {
    owned.fill(0);
    fail('invalid_input', 'claim', 'not_sent');
  }
  const requestId = base64UrlEncode(owned);
  owned.fill(0);
  if (!REQUEST_ID.test(requestId)) fail('invalid_input', 'claim', 'not_sent');
  return requestId;
}

function safeNow(value: unknown): number {
  const now = value === undefined ? Date.now() : value;
  if (!Number.isSafeInteger(now) || (now as number) < 0) {
    fail('invalid_input', 'validate', 'not_sent');
  }
  return now as number;
}

async function expectedReviewedAuthorityHash(authority: InstallAuthority): Promise<string> {
  return prefixedSha256(canonicalJson({
    adminStateNamespaceId: authority.final.adminStateNamespaceId,
    installBindingHash: authority.journal.bindingHash,
    installConvergenceHash: authority.final.convergenceHash,
    readyReceiptChecksum: authority.readyReceipt.checksum,
  }));
}

async function requireReviewedUninstallAuthority(
  uninstallPlanValue: unknown,
  approvalValue: unknown,
  authority: InstallAuthority,
  nowMs: number,
): Promise<ReviewedUninstallAuthority> {
  if (!isPlainDataTree(approvalValue) || !exactDataKeys(approvalValue, [
    'attemptId', 'authorizedTarget',
  ]) || typeof approvalValue.attemptId !== 'string' || !ATTEMPT_ID.test(approvalValue.attemptId) ||
    !exactJson(approvalValue.authorizedTarget, authority.journal.target) ||
    authority.journal.approvalHistory.some((entry) => entry.attemptId === approvalValue.attemptId) ||
    authority.journal.leaseAttemptIds.includes(approvalValue.attemptId)) {
    fail('install_authority_invalid', 'validate', 'not_sent');
  }
  let plan: StaticUninstallPlan;
  try {
    plan = await parseStaticUninstallPlan(uninstallPlanValue);
  } catch {
    fail('install_authority_invalid', 'validate', 'not_sent');
  }
  let rebuiltPlan: StaticUninstallPlan;
  try {
    rebuiltPlan = await buildStaticUninstallPlan(
      authority.journal,
      plan.createdAt,
      plan.expiresAt,
    );
  } catch {
    fail('install_authority_invalid', 'validate', 'not_sent');
  }
  if (
    !exactJson(plan, rebuiltPlan) ||
    plan.authorityHash !== await expectedReviewedAuthorityHash(authority) ||
    plan.installationId !== authority.journal.installationId ||
    plan.release.id !== authority.journal.releasePin.release ||
    plan.release.aggregateSha256 !== authority.journal.releasePin.artifactSha256 ||
    plan.createdAt < authority.journal.updatedAt || plan.expiresAt > authority.journal.recoverUntil
  ) fail('install_authority_invalid', 'validate', 'not_sent');
  if (nowMs < plan.createdAt || nowMs >= plan.expiresAt || nowMs >= authority.journal.recoverUntil) {
    fail('request_expired', 'validate', 'not_sent');
  }
  return Object.freeze({ plan, approvalAttemptId: approvalValue.attemptId });
}

function reviewedClaimCommitment(
  claim: PreparedCustomerUninstallClaim,
  review: Pick<ReviewedUninstallAuthority, 'approvalAttemptId' | 'plan'>,
): Record<string, unknown> {
  return {
    schemaVersion: 1,
    approvalAttemptId: review.approvalAttemptId,
    authorityHash: review.plan.authorityHash,
    claim,
    uninstallPlanHash: review.plan.planHash,
    uninstallPlanId: review.plan.planId,
  };
}

function locatorAuthority(
  semantic: CustomerUninstallSemanticRecord,
): CustomerUninstallLocatorAuthority {
  return Object.freeze({
    requestId: semantic.requestId,
    accountId: semantic.accountId,
    zoneId: semantic.zoneId,
    zoneName: semantic.zoneName,
    accountWorkersSubdomain: semantic.accountWorkersSubdomain,
    workerName: semantic.workerName,
    installationId: semantic.installationId,
    configurationHash: semantic.configurationHash,
    desiredHash: semantic.desiredHash,
    release: semantic.release,
    installBindingHash: semantic.installBindingHash,
    installConvergenceHash: semantic.installConvergenceHash,
    adminStateNamespaceId: semantic.adminStateNamespaceId,
    uninstallPlanId: semantic.uninstallPlanId,
    uninstallPlanHash: semantic.uninstallPlanHash,
    authorityHash: semantic.authorityHash,
    approvalAttemptId: semantic.approvalAttemptId,
  });
}

/**
 * Build a fresh exact claim and its credential-free recovery record. No
 * provider request, HMAC, nonce access, or OAuth token access occurs here.
 */
export async function prepareCustomerUninstallRequest(
  input: PrepareCustomerUninstallRequestInput,
): Promise<CustomerUninstallMutationPlan> {
  if (!exactDataKeys(input, [
    'installJournal', 'uninstallPlan', 'approval', 'accountWorkersSubdomain', 'nowMs', 'randomBytes',
  ]) && !exactDataKeys(input, [
    'installJournal', 'uninstallPlan', 'approval', 'accountWorkersSubdomain', 'nowMs',
  ]) && !exactDataKeys(input, [
    'installJournal', 'uninstallPlan', 'approval', 'accountWorkersSubdomain', 'randomBytes',
  ]) && !exactDataKeys(input, [
    'installJournal', 'uninstallPlan', 'approval', 'accountWorkersSubdomain',
  ])) {
    fail('invalid_input', 'validate', 'not_sent');
  }
  const authority = await requireInstallAuthority(input.installJournal);
  const nowMs = safeNow(input.nowMs);
  const review = await requireReviewedUninstallAuthority(
    input.uninstallPlan,
    input.approval,
    authority,
    nowMs,
  );
  const provider = requireProviderSubdomain(
    input.accountWorkersSubdomain,
    authority.target.accountId,
  );
  uninstallUrl(authority.workerName, provider);
  const issuedAt = Math.floor(nowMs / 1_000);
  const expiresAt = Math.min(
    issuedAt + REQUEST_LIFETIME_SECONDS,
    Math.floor(review.plan.expiresAt / 1_000),
    Math.floor(authority.journal.recoverUntil / 1_000),
  );
  if (expiresAt <= issuedAt || expiresAt - issuedAt > REQUEST_LIFETIME_SECONDS) {
    fail('request_expired', 'claim', 'not_sent');
  }
  const claim: PreparedCustomerUninstallClaim = Object.freeze({
    schemaVersion: 1,
    requestId: freshRequestId(input.randomBytes),
    issuedAt,
    expiresAt,
    target: authority.target,
    release: authority.release,
    expected: Object.freeze({
      configurationHash: authority.configurationHash,
      installationId: authority.journal.installationId,
      desiredHash: authority.desiredHash,
      readyReceipt: authority.readyReceipt,
    }),
  });
  const semantic: CustomerUninstallSemanticRecord = Object.freeze({
    schemaVersion: 1,
    kind: 'customer_uninstall_submit',
    accountId: authority.target.accountId,
    zoneId: authority.target.zoneId,
    zoneName: authority.target.zoneName,
    accountWorkersSubdomain: provider.subdomain,
    workerName: authority.workerName,
    requestId: claim.requestId,
    issuedAt,
    expiresAt,
    installationId: authority.journal.installationId,
    configurationHash: authority.configurationHash,
    desiredHash: authority.desiredHash,
    release: authority.release,
    rootReceiptRevision: authority.readyReceipt.revision,
    rootReceiptChecksum: authority.readyReceipt.checksum,
    installBindingHash: authority.journal.bindingHash,
    installConvergenceHash: authority.final.convergenceHash,
    adminStateNamespaceId: authority.final.adminStateNamespaceId,
    uninstallPlanId: review.plan.planId,
    uninstallPlanHash: review.plan.planHash,
    authorityHash: review.plan.authorityHash,
    approvalAttemptId: review.approvalAttemptId,
    claimHash: await prefixedSha256(canonicalJson(reviewedClaimCommitment(claim, review))),
  });
  return Object.freeze({
    ephemeral: Object.freeze({ claim }),
    semantic,
  });
}

function parseClaim(value: unknown): PreparedCustomerUninstallClaim | null {
  if (!exactDataKeys(value, [
    'schemaVersion', 'requestId', 'issuedAt', 'expiresAt', 'target', 'release', 'expected',
  ])) return null;
  if (
    value.schemaVersion !== 1 || typeof value.requestId !== 'string' || !REQUEST_ID.test(value.requestId) ||
    !Number.isSafeInteger(value.issuedAt) || !Number.isSafeInteger(value.expiresAt) ||
    (value.expiresAt as number) <= (value.issuedAt as number) ||
    (value.expiresAt as number) - (value.issuedAt as number) > REQUEST_LIFETIME_SECONDS ||
    !exactDataKeys(value.target, ['accountId', 'zoneId', 'zoneName']) ||
    !exactDataKeys(value.release, ['id', 'artifactSha256']) ||
    !exactDataKeys(value.expected, ['configurationHash', 'installationId', 'desiredHash', 'readyReceipt'])
  ) return null;
  return value as unknown as PreparedCustomerUninstallClaim;
}

export function parseCustomerUninstallSemanticRecord(
  value: unknown,
): CustomerUninstallSemanticRecord | null {
  if (!exactDataKeys(value, [
    'schemaVersion', 'kind', 'accountId', 'zoneId', 'zoneName', 'accountWorkersSubdomain',
    'workerName', 'requestId', 'issuedAt', 'expiresAt', 'installationId', 'configurationHash',
    'desiredHash', 'release', 'rootReceiptRevision', 'rootReceiptChecksum', 'installBindingHash',
    'installConvergenceHash', 'adminStateNamespaceId', 'uninstallPlanId', 'uninstallPlanHash',
    'authorityHash', 'approvalAttemptId', 'claimHash',
  ])) return null;
  if (
    value.schemaVersion !== 1 || value.kind !== 'customer_uninstall_submit' ||
    typeof value.accountId !== 'string' || !ACCOUNT_ID.test(value.accountId) ||
    typeof value.zoneId !== 'string' || !ACCOUNT_ID.test(value.zoneId) ||
    typeof value.zoneName !== 'string' || typeof value.accountWorkersSubdomain !== 'string' ||
    !HOST_LABEL.test(value.accountWorkersSubdomain) || typeof value.workerName !== 'string' ||
    !WORKER_NAME.test(value.workerName) || typeof value.requestId !== 'string' || !REQUEST_ID.test(value.requestId) ||
    !Number.isSafeInteger(value.issuedAt) || !Number.isSafeInteger(value.expiresAt) ||
    (value.expiresAt as number) <= (value.issuedAt as number) ||
    (value.expiresAt as number) - (value.issuedAt as number) > REQUEST_LIFETIME_SECONDS ||
    typeof value.installationId !== 'string' || !INSTALLATION_ID.test(value.installationId) ||
    typeof value.configurationHash !== 'string' || !HASH.test(value.configurationHash) ||
    typeof value.desiredHash !== 'string' || !HASH.test(value.desiredHash) ||
    !exactDataKeys(value.release, ['id', 'artifactSha256']) ||
    typeof value.release.id !== 'string' || !RELEASE.test(value.release.id) ||
    typeof value.release.artifactSha256 !== 'string' || !HASH.test(value.release.artifactSha256) ||
    !Number.isSafeInteger(value.rootReceiptRevision) || (value.rootReceiptRevision as number) < 0 ||
    typeof value.rootReceiptChecksum !== 'string' || !HASH.test(value.rootReceiptChecksum) ||
    typeof value.installBindingHash !== 'string' || !HASH.test(value.installBindingHash) ||
    typeof value.installConvergenceHash !== 'string' || !HASH.test(value.installConvergenceHash) ||
    typeof value.adminStateNamespaceId !== 'string' || !ACCOUNT_ID.test(value.adminStateNamespaceId) ||
    typeof value.uninstallPlanId !== 'string' || !/^uninstall-plan-[a-f0-9]{24}$/u.test(value.uninstallPlanId) ||
    typeof value.uninstallPlanHash !== 'string' || !HASH.test(value.uninstallPlanHash) ||
    typeof value.authorityHash !== 'string' || !HASH.test(value.authorityHash) ||
    typeof value.approvalAttemptId !== 'string' || !ATTEMPT_ID.test(value.approvalAttemptId) ||
    typeof value.claimHash !== 'string' || !HASH.test(value.claimHash)
  ) return null;
  return Object.freeze({
    schemaVersion: 1,
    kind: 'customer_uninstall_submit',
    accountId: value.accountId,
    zoneId: value.zoneId,
    zoneName: value.zoneName,
    accountWorkersSubdomain: value.accountWorkersSubdomain,
    workerName: value.workerName,
    requestId: value.requestId,
    issuedAt: value.issuedAt,
    expiresAt: value.expiresAt,
    installationId: value.installationId,
    configurationHash: value.configurationHash,
    desiredHash: value.desiredHash,
    release: Object.freeze({
      id: value.release.id,
      artifactSha256: value.release.artifactSha256,
    }),
    rootReceiptRevision: value.rootReceiptRevision,
    rootReceiptChecksum: value.rootReceiptChecksum,
    installBindingHash: value.installBindingHash,
    installConvergenceHash: value.installConvergenceHash,
    adminStateNamespaceId: value.adminStateNamespaceId,
    uninstallPlanId: value.uninstallPlanId,
    uninstallPlanHash: value.uninstallPlanHash,
    authorityHash: value.authorityHash,
    approvalAttemptId: value.approvalAttemptId,
    claimHash: value.claimHash,
  } as CustomerUninstallSemanticRecord);
}

async function requireMutation(
  value: unknown,
  authority: InstallAuthority,
  provider: { readonly subdomain: string },
  review: ReviewedUninstallAuthority,
): Promise<CustomerUninstallMutationPlan> {
  if (!isPlainDataTree(value) || !exactDataKeys(value, ['ephemeral', 'semantic']) ||
      !exactDataKeys(value.ephemeral, ['claim'])) {
    fail('invalid_input', 'validate', 'not_sent');
  }
  const claim = parseClaim(value.ephemeral.claim);
  const semantic = parseCustomerUninstallSemanticRecord(value.semantic);
  if (!claim || !semantic) fail('invalid_input', 'validate', 'not_sent');
  const expectedClaim: PreparedCustomerUninstallClaim = {
    schemaVersion: 1,
    requestId: semantic.requestId,
    issuedAt: semantic.issuedAt,
    expiresAt: semantic.expiresAt,
    target: authority.target,
    release: authority.release,
    expected: {
      configurationHash: authority.configurationHash,
      installationId: authority.journal.installationId,
      desiredHash: authority.desiredHash,
      readyReceipt: authority.readyReceipt,
    },
  };
  const expectedSemantic = {
    schemaVersion: 1,
    kind: 'customer_uninstall_submit',
    accountId: authority.target.accountId,
    zoneId: authority.target.zoneId,
    zoneName: authority.target.zoneName,
    accountWorkersSubdomain: provider.subdomain,
    workerName: authority.workerName,
    requestId: semantic.requestId,
    issuedAt: semantic.issuedAt,
    expiresAt: semantic.expiresAt,
    installationId: authority.journal.installationId,
    configurationHash: authority.configurationHash,
    desiredHash: authority.desiredHash,
    release: authority.release,
    rootReceiptRevision: authority.readyReceipt.revision,
    rootReceiptChecksum: authority.readyReceipt.checksum,
    installBindingHash: authority.journal.bindingHash,
    installConvergenceHash: authority.final.convergenceHash,
    adminStateNamespaceId: authority.final.adminStateNamespaceId,
    uninstallPlanId: review.plan.planId,
    uninstallPlanHash: review.plan.planHash,
    authorityHash: review.plan.authorityHash,
    approvalAttemptId: review.approvalAttemptId,
    claimHash: await prefixedSha256(canonicalJson(reviewedClaimCommitment(expectedClaim, review))),
  };
  if (
    semantic.expiresAt <= semantic.issuedAt ||
    semantic.expiresAt - semantic.issuedAt > REQUEST_LIFETIME_SECONDS ||
    semantic.expiresAt * 1_000 > review.plan.expiresAt ||
    semantic.expiresAt * 1_000 > authority.journal.recoverUntil ||
    !exactJson(claim, expectedClaim) || !exactJson(semantic, expectedSemantic)
  ) fail('install_authority_invalid', 'validate', 'not_sent');
  return Object.freeze({
    ephemeral: Object.freeze({ claim }),
    semantic,
  });
}

function decodeCanonicalBase64(value: string, variant: 'base64' | 'base64url'): Uint8Array<ArrayBuffer> {
  const encoded = variant === 'base64url'
    ? `${value.replaceAll('-', '+').replaceAll('_', '/')}=`
    : value;
  let decoded: string;
  try {
    decoded = atob(encoded);
  } catch {
    throw new CustomerUninstallNonceDerivationError();
  }
  const bytes = Uint8Array.from(decoded, (character) => character.charCodeAt(0));
  const canonical = variant === 'base64url'
    ? base64UrlEncode(bytes)
    : btoa(String.fromCharCode(...bytes));
  if (bytes.byteLength !== NONCE_BYTES || canonical !== value) {
    bytes.fill(0);
    throw new CustomerUninstallNonceDerivationError();
  }
  return bytes;
}

function decodeDerivationKey(value: unknown): Uint8Array<ArrayBuffer> {
  if (typeof value !== 'string') throw new CustomerUninstallNonceDerivationError();
  let bytes: Uint8Array<ArrayBuffer>;
  if (STANDARD_BASE64_KEY.test(value)) bytes = decodeCanonicalBase64(value, 'base64');
  else if (BASE64URL_KEY.test(value)) bytes = decodeCanonicalBase64(value, 'base64url');
  else throw new CustomerUninstallNonceDerivationError();
  if (bytes.every((byte) => byte === 0)) {
    bytes.fill(0);
    throw new CustomerUninstallNonceDerivationError();
  }
  return bytes;
}

/**
 * Deterministically derive the cleanup-only HMAC nonce from a separate root
 * key and the complete namespace-bound install authority. Nothing is stored.
 */
export async function deriveCustomerUninstallNonce(
  encodedKey: unknown,
  installJournal: unknown,
): Promise<string> {
  let authority: InstallAuthority;
  try {
    authority = await requireInstallAuthority(installJournal);
  } catch {
    throw new CustomerUninstallNonceDerivationError();
  }
  const keyBytes = decodeDerivationKey(encodedKey);
  let signature: Uint8Array<ArrayBuffer> | null = null;
  try {
    const key = await crypto.subtle.importKey(
      'raw',
      keyBytes,
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['sign'],
    );
    signature = new Uint8Array(await crypto.subtle.sign(
      'HMAC',
      key,
      new TextEncoder().encode(canonicalJson({
        adminStateNamespaceId: authority.final.adminStateNamespaceId,
        domain: NONCE_DERIVATION_DOMAIN,
        installBindingHash: authority.journal.bindingHash,
        installConvergenceHash: authority.final.convergenceHash,
        installationId: authority.journal.installationId,
        releaseArtifactSha256: authority.journal.releasePin.artifactSha256,
        schemaVersion: 1,
      })),
    ));
    if (signature.every((byte) => byte === 0)) {
      throw new CustomerUninstallNonceDerivationError();
    }
    return base64UrlEncode(signature);
  } catch {
    throw new CustomerUninstallNonceDerivationError();
  } finally {
    signature?.fill(0);
    keyBytes.fill(0);
  }
}

function requireNonce(value: unknown): Uint8Array<ArrayBuffer> {
  if (typeof value !== 'string' || !NONCE.test(value)) {
    fail('invalid_input', 'validate', 'not_sent');
  }
  let bytes: Uint8Array<ArrayBuffer>;
  try {
    bytes = decodeCanonicalBase64(value, 'base64url');
  } catch {
    fail('invalid_input', 'validate', 'not_sent');
  }
  if (bytes.every((byte) => byte === 0)) {
    bytes.fill(0);
    fail('invalid_input', 'validate', 'not_sent');
  }
  return bytes;
}

function requireAccessToken(value: unknown): string {
  if (
    typeof value !== 'string' || value.length === 0 || value.length > MAX_ACCESS_TOKEN_LENGTH ||
    value.trim() !== value || CONTROL_CHARACTER.test(value)
  ) fail('invalid_input', 'validate', 'not_sent');
  return value;
}

async function signRawBody(rawBody: string, nonceBytes: Uint8Array): Promise<string> {
  const owned = new Uint8Array(nonceBytes.byteLength);
  owned.set(nonceBytes);
  let signature: Uint8Array<ArrayBuffer> | null = null;
  try {
    const key = await crypto.subtle.importKey(
      'raw',
      owned,
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['sign'],
    );
    signature = new Uint8Array(await crypto.subtle.sign(
      'HMAC',
      key,
      new TextEncoder().encode(rawBody),
    ));
    return `sha256=${bytesToHex(signature)}`;
  } catch {
    fail('sign_failed', 'sign', 'not_sent');
  } finally {
    signature?.fill(0);
    owned.fill(0);
  }
  return fail('sign_failed', 'sign', 'not_sent');
}

async function parseRemovedReceipt(
  value: unknown,
  root: ReadyInstallationReceipt,
): Promise<RemovedInstallationReceipt | null> {
  if (!exactDataKeys(value, [
    'schemaVersion', 'manager', 'installationId', 'state', 'revision', 'release',
    'target', 'accessPolicy', 'desiredHash', 'resources', 'pending', 'checksum',
  ])) return null;
  const expectedRevision = root.revision + (root.resources.length * 2) + 1;
  if (
    !Number.isSafeInteger(expectedRevision) || value.schemaVersion !== 1 ||
    value.manager !== 'ankka-mcp-gateway' || value.installationId !== root.installationId ||
    value.state !== 'removed' || value.revision !== expectedRevision || value.release !== root.release ||
    !exactJson(value.target, root.target) || !exactJson(value.accessPolicy, root.accessPolicy) ||
    value.desiredHash !== root.desiredHash || !Array.isArray(value.resources) || value.resources.length !== 0 ||
    value.pending !== null || typeof value.checksum !== 'string' || !HASH.test(value.checksum)
  ) return null;
  const unsigned = {
    schemaVersion: 1 as const,
    manager: 'ankka-mcp-gateway' as const,
    installationId: root.installationId,
    state: 'removed' as const,
    revision: expectedRevision,
    release: root.release,
    target: value.target,
    accessPolicy: value.accessPolicy,
    desiredHash: root.desiredHash,
    resources: [],
    pending: null,
  };
  if (await prefixedSha256(canonicalJson(unsigned)) !== value.checksum) return null;
  return Object.freeze({
    ...unsigned,
    manager: 'ankka-mcp-gateway' as const,
    state: 'removed' as const,
    target: Object.freeze({ ...root.target }),
    accessPolicy: Object.freeze({ ...root.accessPolicy }),
    resources: Object.freeze([]) as readonly [],
    checksum: value.checksum,
  });
}

async function parseRemovedResult(
  value: unknown,
  mutation: CustomerUninstallMutationPlan,
): Promise<CustomerUninstallRemovedLocator | null> {
  const claim = mutation.ephemeral.claim;
  if (!exactDataKeys(value, [
    'schemaVersion', 'status', 'installationId', 'configurationHash', 'uninstallId',
    'release', 'receipt', 'uninstallInvoked', 'resumed',
  ])) return null;
  if (
    value.schemaVersion !== 1 || value.status !== 'removed' ||
    value.installationId !== claim.expected.installationId ||
    value.configurationHash !== claim.expected.configurationHash ||
    typeof value.uninstallId !== 'string' || !UNINSTALL_ID.test(value.uninstallId) ||
    !exactJson(value.release, claim.release) ||
    !exactDataKeys(value.receipt, ['revision', 'resourceCount', 'evidence']) ||
    value.receipt.resourceCount !== 0 || typeof value.uninstallInvoked !== 'boolean' ||
    typeof value.resumed !== 'boolean' ||
    (value.uninstallInvoked === false && value.resumed === false)
  ) return null;
  const evidence = await parseRemovedReceipt(value.receipt.evidence, claim.expected.readyReceipt);
  if (!evidence || value.receipt.revision !== evidence.revision) return null;
  return Object.freeze({
    schemaVersion: 1,
    status: 'removed',
    ...locatorAuthority(mutation.semantic),
    uninstallId: value.uninstallId,
    receipt: Object.freeze({ revision: evidence.revision, resourceCount: 0, evidence }),
    uninstallInvoked: value.uninstallInvoked,
    resumed: value.resumed,
  });
}

const RECOVERY_RETRYABILITY = Object.freeze({
  uninstall_recovery_required: true,
  uninstall_fresh_grant_required: true,
  uninstall_requires_repair: false,
  uninstall_request_mismatch: false,
  uninstall_blocked: true,
} satisfies Readonly<Record<CustomerUninstallRecoveryReason, boolean>>);

function parseRecoveryResult(
  value: unknown,
  status: number,
  semantic: CustomerUninstallSemanticRecord,
): CustomerUninstallRecoveryLocator | null {
  if (
    status !== 409 || !exactDataKeys(value, ['schemaVersion', 'error', 'retryable']) ||
    value.schemaVersion !== 1 || typeof value.error !== 'string' ||
    !Object.hasOwn(RECOVERY_RETRYABILITY, value.error)
  ) return null;
  const reason = value.error as CustomerUninstallRecoveryReason;
  const retryable = RECOVERY_RETRYABILITY[reason];
  if (value.retryable !== retryable) return null;
  return Object.freeze({
    schemaVersion: 1,
    status: 'recovery_required',
    ...locatorAuthority(semantic),
    reason,
    freshGrantRequired: retryable,
  });
}

async function semanticMatchesInstallAuthority(
  semantic: CustomerUninstallSemanticRecord,
  authority: InstallAuthority,
): Promise<boolean> {
  const expectedClaim: PreparedCustomerUninstallClaim = {
    schemaVersion: 1,
    requestId: semantic.requestId,
    issuedAt: semantic.issuedAt,
    expiresAt: semantic.expiresAt,
    target: authority.target,
    release: authority.release,
    expected: {
      configurationHash: authority.configurationHash,
      installationId: authority.journal.installationId,
      desiredHash: authority.desiredHash,
      readyReceipt: authority.readyReceipt,
    },
  };
  const expectedClaimHash = await prefixedSha256(canonicalJson({
    schemaVersion: 1,
    approvalAttemptId: semantic.approvalAttemptId,
    authorityHash: semantic.authorityHash,
    claim: expectedClaim,
    uninstallPlanHash: semantic.uninstallPlanHash,
    uninstallPlanId: semantic.uninstallPlanId,
  }));
  return semantic.accountId === authority.target.accountId &&
    semantic.zoneId === authority.target.zoneId && semantic.zoneName === authority.target.zoneName &&
    semantic.workerName === authority.workerName && semantic.installationId === authority.journal.installationId &&
    semantic.configurationHash === authority.configurationHash && semantic.desiredHash === authority.desiredHash &&
    exactJson(semantic.release, authority.release) &&
    semantic.rootReceiptRevision === authority.readyReceipt.revision &&
    semantic.rootReceiptChecksum === authority.readyReceipt.checksum &&
    semantic.installBindingHash === authority.journal.bindingHash &&
    semantic.installConvergenceHash === authority.final.convergenceHash &&
    semantic.adminStateNamespaceId === authority.final.adminStateNamespaceId &&
    semantic.authorityHash === await expectedReviewedAuthorityHash(authority) &&
    semantic.claimHash === expectedClaimHash;
}

/**
 * Parse a persisted removed/recovery locator against its immutable semantic
 * record and exact completed install authority. This never needs the ephemeral
 * claim, OAuth grant, uninstall nonce, request body, or provider response.
 */
export async function parseCustomerUninstallLocator(
  value: unknown,
  semanticInput: unknown,
  installJournal: unknown,
): Promise<CustomerUninstallLocator | null> {
  if (!isPlainDataTree(value) || !isRecord(value)) return null;
  const semantic = parseCustomerUninstallSemanticRecord(semanticInput);
  if (!semantic) return null;
  let authority: InstallAuthority;
  try {
    authority = await requireInstallAuthority(installJournal);
  } catch {
    return null;
  }
  if (!await semanticMatchesInstallAuthority(semantic, authority)) return null;
  const commonKeys = [
    'requestId', 'accountId', 'zoneId', 'zoneName', 'accountWorkersSubdomain', 'workerName',
    'installationId', 'configurationHash', 'desiredHash', 'release', 'installBindingHash',
    'installConvergenceHash', 'adminStateNamespaceId', 'uninstallPlanId', 'uninstallPlanHash',
    'authorityHash', 'approvalAttemptId',
  ] as const;
  if (!exactDataKeys(value, ['schemaVersion', 'status', ...commonKeys,
    ...(value.status === 'removed'
      ? ['uninstallId', 'receipt', 'uninstallInvoked', 'resumed']
      : ['reason', 'freshGrantRequired']),
  ])) return null;
  const expectedAuthority = locatorAuthority(semantic);
  if (!Object.entries(expectedAuthority).every(([key, expected]) => exactJson(value[key], expected))) return null;
  if (value.schemaVersion !== 1) return null;
  if (value.status === 'removed') {
    if (typeof value.uninstallId !== 'string' || !UNINSTALL_ID.test(value.uninstallId) ||
      !exactDataKeys(value.receipt, ['revision', 'resourceCount', 'evidence']) ||
      value.receipt.resourceCount !== 0 || typeof value.uninstallInvoked !== 'boolean' ||
      typeof value.resumed !== 'boolean' || (value.uninstallInvoked === false && value.resumed === false)) return null;
    const evidence = await parseRemovedReceipt(value.receipt.evidence, authority.readyReceipt);
    if (!evidence || value.receipt.revision !== evidence.revision) return null;
    return Object.freeze({
      schemaVersion: 1,
      status: 'removed',
      ...expectedAuthority,
      uninstallId: value.uninstallId,
      receipt: Object.freeze({ revision: evidence.revision, resourceCount: 0, evidence }),
      uninstallInvoked: value.uninstallInvoked,
      resumed: value.resumed,
    });
  }
  if (value.status !== 'recovery_required' || typeof value.reason !== 'string' ||
    !Object.hasOwn(RECOVERY_RETRYABILITY, value.reason)) return null;
  const reason = value.reason as CustomerUninstallRecoveryReason;
  const freshGrantRequired = RECOVERY_RETRYABILITY[reason];
  if (value.freshGrantRequired !== freshGrantRequired) return null;
  return Object.freeze({
    schemaVersion: 1,
    status: 'recovery_required',
    ...expectedAuthority,
    reason,
    freshGrantRequired,
  });
}

async function readBoundedJson(response: Response): Promise<unknown> {
  const contentType = response.headers.get('content-type')?.split(';', 1)[0]?.trim().toLowerCase();
  if (contentType !== 'application/json') fail('response_invalid', 'response', 'unknown');
  const declared = response.headers.get('content-length');
  if (declared !== null) {
    const length = Number(declared);
    if (!Number.isSafeInteger(length) || length < 0 || length > RESPONSE_LIMIT_BYTES) {
      fail('response_invalid', 'response', 'unknown');
    }
  }
  if (!response.body) fail('response_invalid', 'response', 'unknown');
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      if (value.byteLength > RESPONSE_LIMIT_BYTES - total) {
        try {
          await reader.cancel();
        } catch {
          // The bounded-response violation remains authoritative.
        }
        fail('response_invalid', 'response', 'unknown');
      }
      if (value.byteLength > 0) {
        chunks.push(value.slice());
        total += value.byteLength;
      }
    }
    const bytes = new Uint8Array(total);
    let offset = 0;
    for (const chunk of chunks) {
      bytes.set(chunk, offset);
      offset += chunk.byteLength;
    }
    try {
      return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)) as unknown;
    } catch {
      fail('response_invalid', 'response', 'unknown');
    } finally {
      bytes.fill(0);
    }
  } finally {
    for (const chunk of chunks) chunk.fill(0);
    reader.releaseLock();
  }
}

async function parseUninstallResponse(
  response: Response,
  requestUrl: URL,
  mutation: CustomerUninstallMutationPlan,
): Promise<CustomerUninstallLocator> {
  if (
    response.type === 'opaqueredirect' || response.redirected ||
    (response.url !== '' && response.url !== requestUrl.href) ||
    (response.status >= 300 && response.status < 400)
  ) fail('outcome_unknown', 'response', 'unknown');
  const value = await readBoundedJson(response);
  if (response.status === 200) {
    const removed = await parseRemovedResult(value, mutation);
    if (removed) return removed;
    fail('response_invalid', 'response', 'unknown');
  }
  const recovery = parseRecoveryResult(value, response.status, mutation.semantic);
  if (recovery) return recovery;
  if (response.status >= 500) fail('outcome_unknown', 'response', 'unknown');
  fail('uninstall_rejected', 'response', 'rejected');
}

/**
 * Submit exactly one cleanup request. There is no retry loop, persistence hook,
 * logger, runtime fetch default, environment read, or Authorization header.
 */
export async function submitCustomerUninstallRequest(
  input: SubmitCustomerUninstallRequestInput,
): Promise<CustomerUninstallLocator> {
  if (!exactDataKeys(input, [
    'installJournal', 'uninstallPlan', 'approval', 'mutation', 'accountWorkersSubdomain',
    'uninstallNonce', 'cloudflareAccessToken', 'transport', 'nowMs',
  ]) || typeof input.transport !== 'function') {
    fail('invalid_input', 'validate', 'not_sent');
  }
  const authority = await requireInstallAuthority(input.installJournal);
  const nowMs = safeNow(input.nowMs);
  const review = await requireReviewedUninstallAuthority(
    input.uninstallPlan,
    input.approval,
    authority,
    nowMs,
  );
  const provider = requireProviderSubdomain(
    input.accountWorkersSubdomain,
    authority.target.accountId,
  );
  const requestUrl = uninstallUrl(authority.workerName, provider);
  const mutation = await requireMutation(input.mutation, authority, provider, review);
  const now = Math.floor(nowMs / 1_000);
  if (
    mutation.semantic.issuedAt > now + MAX_CLOCK_SKEW_SECONDS ||
    mutation.semantic.expiresAt < now ||
    now - mutation.semantic.issuedAt > REQUEST_LIFETIME_SECONDS
  ) fail('request_expired', 'validate', 'not_sent');
  const nonceBytes = requireNonce(input.uninstallNonce);
  const accessToken = requireAccessToken(input.cloudflareAccessToken);
  let rawBody = '';
  try {
    rawBody = canonicalJson({
      ...mutation.ephemeral.claim,
      cloudflareAccessToken: accessToken,
    });
    if (new TextEncoder().encode(rawBody).byteLength > REQUEST_LIMIT_BYTES) {
      fail('invalid_input', 'validate', 'not_sent');
    }
    const signature = await signRawBody(rawBody, nonceBytes);
    const controller = new AbortController();
    const request = new Request(requestUrl, {
      method: 'POST',
      headers: {
        accept: 'application/json',
        'content-type': 'application/json',
        'x-ankka-uninstall-signature': signature,
      },
      body: rawBody,
      redirect: 'manual',
      credentials: 'omit',
      referrerPolicy: 'no-referrer',
      signal: controller.signal,
    });
    let timer: ReturnType<typeof setTimeout> | undefined;
    const timeout = new Promise<never>((_resolve, reject) => {
      timer = setTimeout(() => {
        controller.abort();
        reject(new CustomerUninstallTimeout());
      }, REQUEST_TIMEOUT_MS);
    });
    try {
      const operation = (async () => {
        const response = await input.transport(request);
        if (!(response instanceof Response)) fail('outcome_unknown', 'submit', 'unknown');
        return parseUninstallResponse(response, requestUrl, mutation);
      })();
      return await Promise.race([operation, timeout]);
    } catch (error) {
      if (error instanceof CustomerUninstallRequestError) throw error;
      if (error instanceof CustomerUninstallTimeout) fail('outcome_unknown', 'submit', 'unknown');
      fail('outcome_unknown', 'submit', 'unknown');
    } finally {
      if (timer !== undefined) clearTimeout(timer);
      controller.abort();
    }
  } finally {
    nonceBytes.fill(0);
    rawBody = '';
  }
  return fail('outcome_unknown', 'submit', 'unknown');
}

export function canonicalCustomerUninstallJson(value: unknown): string {
  return canonicalJson(value);
}

function bytesToHex(bytes: Uint8Array): string {
  return [...bytes].map((byte) => byte.toString(16).padStart(2, '0')).join('');
}

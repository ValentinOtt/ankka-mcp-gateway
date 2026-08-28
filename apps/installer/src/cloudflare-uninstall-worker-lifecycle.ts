import { CLOUDFLARE_API_ORIGIN } from './constants';
import type {
  AdminStateDurableObjectNamespaceLocator,
  CloudflareDirectUploadCall,
} from './cloudflare-worker-direct-upload';
import type {
  VerifiedGatewayWorkerReleaseSet,
} from './release-direct-upload-adapter';
import { APPROVED_CLOUDFLARE_RELEASE_CONTRACT } from './release-manifest';

const ACCOUNT_ID = /^[a-f0-9]{32}$/u;
const WORKER_ID = /^[a-f0-9]{32}$/u;
const WORKER_NAME = /^[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$/u;
const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/u;
const SHA256 = /^[a-f0-9]{64}$/u;
const RELEASE = /^gateway-v(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)$/u;
const UNINSTALL_CYCLE_ID = /^uninstall-[a-f0-9]{24}$/u;
const SAFE_TOKEN = /^[A-Za-z0-9._~-]+$/u;
const CONTROL_CHARACTER = /[\u0000-\u001f\u007f]/u;
const HOSTNAME = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/u;

const EXACT_COMPATIBILITY_DATE: '2026-08-08' = '2026-08-08';
const MAX_FILE_BYTES = 8 * 1024 * 1024;
const MAX_RELEASE_BYTES = 32 * 1024 * 1024;
const MAX_RESPONSE_BYTES = 256 * 1024;
const MAX_VERSION_RESPONSE_BYTES = 64 * 1024 * 1024;
const DEFAULT_TIMEOUT_MS = 10_000;
const VERSION_PAGE_SIZE = 100;
const MAX_VERSION_PAGES = 100;
const NAMESPACE_PAGE_SIZE = 1_000;
const MAX_NAMESPACE_PAGES = 100;
const MAX_NAMESPACE_COUNT = NAMESPACE_PAGE_SIZE * MAX_NAMESPACE_PAGES;
const MAX_NAMESPACE_RESPONSE_BYTES = 512 * 1024;
const MAX_DEPLOYMENTS = 1_000;
const MAX_SCRIPTS = 10_000;
const SCRIPT_PAGE_SIZE = 100;
const MAX_SCRIPT_PAGES = MAX_SCRIPTS / SCRIPT_PAGE_SIZE;

const MODULE_CONTENT_TYPES: Readonly<Record<string, string>> = Object.freeze({
  '.js': 'application/javascript+module',
  '.mjs': 'application/javascript+module',
  '.wasm': 'application/wasm',
});

export const UNINSTALL_CLEANUP_VARIABLE_NAMES = Object.freeze([
  'ANKKA_GATEWAY_RELEASE',
  'ANKKA_GATEWAY_RELEASE_SHA256',
  'CLOUDFLARE_ACCOUNT_ID',
  'CLOUDFLARE_ZONE_ID',
  'CLOUDFLARE_ZONE_NAME',
  'ZERO_TRUST_READY',
] as const);

export type UninstallCleanupVariableName = (typeof UNINSTALL_CLEANUP_VARIABLE_NAMES)[number];
export type UninstallCleanupVariables = Readonly<Record<UninstallCleanupVariableName, string>>;
export type UninstallWorkerVersionStage = 'cleanup' | 'retirement';
export type UninstallWorkerDeploymentStage = 'cleanup' | 'retirement' | 'restore_clean';

export type CloudflareUninstallWorkerLifecycleStage =
  | 'validate'
  | 'version_submit'
  | 'version_verify'
  | 'version_recovery'
  | 'deployment_submit'
  | 'deployment_verify'
  | 'deployment_active_verify'
  | 'deployment_recovery'
  | 'namespace_present'
  | 'namespace_absent'
  | 'worker_delete'
  | 'worker_delete_recovery';

export type CloudflareUninstallWorkerLifecycleOutcome =
  | 'not_sent'
  | 'rejected'
  | 'unknown'
  | 'submitted';

export type CloudflareUninstallWorkerLifecycleErrorCode =
  | 'invalid_input'
  | 'provider_rejected'
  | 'provider_unknown'
  | 'provider_mismatch'
  | 'recovery_ambiguous'
  | 'deletion_not_proven';

export interface UninstallWorkerVersionSubmission {
  readonly kind: 'uninstall_worker_version';
  readonly stage: UninstallWorkerVersionStage;
  readonly accountId: string;
  readonly workerName: string;
  readonly workerId: string;
  readonly uninstallCycleId: string;
  readonly versionId: string;
  readonly requestHash: string;
  readonly correlationTag: string;
}

export interface UninstallWorkerDeploymentSubmission {
  readonly kind: 'uninstall_worker_deployment';
  readonly stage: UninstallWorkerDeploymentStage;
  readonly accountId: string;
  readonly workerName: string;
  readonly workerId: string;
  readonly uninstallCycleId: string;
  readonly versionId: string;
  readonly deploymentId: string;
  readonly requestHash: string;
  readonly correlationTag: string;
}

export interface WorkerDeleteSubmission {
  readonly kind: 'uninstall_worker_delete';
  readonly accountId: string;
  readonly workerName: string;
  readonly workerId: string;
  readonly uninstallCycleId: string;
  readonly namespaceId: string;
  readonly retirementVersionId: string;
  readonly retirementProofCommitment: string;
  readonly requestHash: string;
  readonly correlationTag: string;
}

export type CloudflareUninstallWorkerLifecycleSubmission =
  | UninstallWorkerVersionSubmission
  | UninstallWorkerDeploymentSubmission
  | WorkerDeleteSubmission;

/**
 * Safe error surface. Provider bodies, access tokens, nonces, and module bytes
 * are deliberately never attached. A mutation-stage `unknown` outcome must be
 * resolved by the corresponding recovery API; callers must not replay it.
 */
export class CloudflareUninstallWorkerLifecycleError extends Error {
  readonly code: CloudflareUninstallWorkerLifecycleErrorCode;
  readonly stage: CloudflareUninstallWorkerLifecycleStage;
  readonly outcome: CloudflareUninstallWorkerLifecycleOutcome;
  readonly submissions: readonly CloudflareUninstallWorkerLifecycleSubmission[];
  readonly canRetry: false;

  constructor(
    code: CloudflareUninstallWorkerLifecycleErrorCode,
    stage: CloudflareUninstallWorkerLifecycleStage,
    outcome: CloudflareUninstallWorkerLifecycleOutcome,
    submissions: readonly unknown[] = [],
  ) {
    const validCode = (['invalid_input', 'provider_rejected', 'provider_unknown', 'provider_mismatch',
      'recovery_ambiguous', 'deletion_not_proven'] as const).includes(code);
    const validStage = (['validate', 'version_submit', 'version_verify', 'version_recovery',
      'deployment_submit', 'deployment_verify', 'deployment_active_verify', 'deployment_recovery',
      'namespace_present', 'namespace_absent', 'worker_delete', 'worker_delete_recovery'] as const).includes(stage);
    const validOutcome = (['not_sent', 'rejected', 'unknown', 'submitted'] as const).includes(outcome);
    const safeCode: CloudflareUninstallWorkerLifecycleErrorCode =
      validCode && validStage && validOutcome ? code : 'invalid_input';
    const safeStage: CloudflareUninstallWorkerLifecycleStage = safeCode === 'invalid_input' ? 'validate' : stage;
    const safeOutcome: CloudflareUninstallWorkerLifecycleOutcome =
      safeCode === 'invalid_input' ? 'not_sent' : outcome;
    super(safeCode);
    this.name = 'CloudflareUninstallWorkerLifecycleError';
    this.code = safeCode;
    this.stage = safeStage;
    this.outcome = safeOutcome;
    const projected: CloudflareUninstallWorkerLifecycleSubmission[] = [];
    if (safeCode !== 'invalid_input' && Array.isArray(submissions)) {
      try {
        const count = Math.min(submissions.length, 16);
        for (let index = 0; index < count; index += 1) {
          const parsed = parseCloudflareUninstallWorkerLifecycleSubmission(submissions[index]);
          if (parsed !== null) projected.push(parsed);
        }
      } catch {
        projected.length = 0;
      }
    }
    this.submissions = Object.freeze(projected);
    this.canRetry = false;
  }
}

export interface UninstallWorkerModuleCommitment {
  readonly name: string;
  readonly contentType: string;
  readonly contentSha256: string;
  readonly byteLength: number;
}

export interface CleanupWorkerVersionRecoveryRecord {
  readonly kind: 'uninstall_version_recovery';
  readonly stage: 'cleanup';
  readonly accountId: string;
  readonly workerName: string;
  readonly workerId: string;
  readonly namespaceId: string;
  readonly uninstallCycleId: string;
  readonly release: string;
  readonly artifactSha256: string;
  readonly componentSha256: string;
  readonly requestHash: string;
  readonly correlationTag: string;
  readonly compatibilityDate: '2026-08-08';
  readonly compatibilityFlags: readonly [];
  readonly mainModule: 'index.js';
  readonly contract: {
    readonly assets: 'absent';
    readonly defaultApplication: 'absent';
    readonly durableObject: {
      readonly binding: 'ADMIN_STATE';
      readonly className: 'AdminState';
      readonly namespaceId: string;
      readonly storage: 'sqlite';
    };
    readonly exports: {
      readonly AdminState: { readonly type: 'durable-object'; readonly storage: 'sqlite' };
    };
    readonly uninstallNonceBinding: 'present';
    readonly variableValueHashes: readonly {
      readonly name: UninstallCleanupVariableName;
      readonly valueSha256: string;
    }[];
  };
  readonly modules: readonly UninstallWorkerModuleCommitment[];
}

export interface RetirementWorkerVersionRecoveryRecord {
  readonly kind: 'uninstall_version_recovery';
  readonly stage: 'retirement';
  readonly accountId: string;
  readonly workerName: string;
  readonly workerId: string;
  readonly uninstallCycleId: string;
  readonly release: string;
  readonly artifactSha256: string;
  readonly componentSha256: string;
  readonly requestHash: string;
  readonly correlationTag: string;
  readonly compatibilityDate: '2026-08-08';
  readonly compatibilityFlags: readonly [];
  readonly mainModule: 'index.js';
  readonly contract: {
    readonly assets: 'absent';
    readonly bindings: readonly [];
    readonly defaultApplication: 'absent';
    readonly exports: {
      readonly AdminState: { readonly type: 'durable-object'; readonly state: 'deleted' };
    };
  };
  readonly modules: readonly UninstallWorkerModuleCommitment[];
}

export type UninstallWorkerVersionRecoveryRecord =
  | CleanupWorkerVersionRecoveryRecord
  | RetirementWorkerVersionRecoveryRecord;

/** Contains nonce/module bytes and is never journal-safe or a replay-control record. */
export interface UninstallWorkerVersionSubmitIntent {
  readonly kind: 'uninstall_version_submit';
  readonly stage: UninstallWorkerVersionStage;
  readonly accountId: string;
  readonly workerName: string;
  readonly workerId: string;
  readonly uninstallCycleId: string;
  readonly requestHash: string;
  readonly correlationTag: string;
  readonly semanticCommitment: Readonly<Record<string, unknown>>;
  readonly body: Readonly<Record<string, unknown>>;
}

export interface UninstallWorkerVersionMutationPlan {
  /** Ephemeral payload. The outer durable journal must CAS before submission, then discard it. */
  readonly ephemeral: UninstallWorkerVersionSubmitIntent;
  /** Persist before POST. Exact, semantic, credential-free recovery input. */
  readonly recovery: UninstallWorkerVersionRecoveryRecord;
}

/**
 * Ephemeral proof used immediately before forwarding a Cloudflare grant to the
 * customer cleanup Worker. It is deliberately not a journal record: the
 * caller must consume it in the same request that performs the relay.
 */
export interface ActiveCleanupWorkerVersionProof {
  readonly version: UninstallWorkerVersionSubmission;
  readonly deployment: UninstallWorkerDeploymentSubmission;
}

export interface PrepareCleanupWorkerVersionInput {
  readonly accountId: string;
  readonly workerName: string;
  readonly workerId: string;
  readonly namespaceId: string;
  readonly uninstallCycleId: string;
  readonly releaseSet: VerifiedGatewayWorkerReleaseSet;
  readonly variables: UninstallCleanupVariables;
  readonly uninstallNonce: string;
}

export interface PrepareRetirementWorkerVersionInput {
  readonly accountId: string;
  readonly workerName: string;
  readonly workerId: string;
  readonly uninstallCycleId: string;
  readonly releaseSet: VerifiedGatewayWorkerReleaseSet;
}

export interface UninstallWorkerDeploymentMutationIntent {
  readonly kind: 'uninstall_deployment';
  readonly stage: UninstallWorkerDeploymentStage;
  readonly accountId: string;
  readonly workerName: string;
  readonly workerId: string;
  readonly uninstallCycleId: string;
  readonly versionId: string;
  readonly requestHash: string;
  readonly correlationTag: string;
  readonly body: {
    readonly annotations: { readonly 'workers/message': string };
    readonly strategy: 'percentage';
    readonly versions: readonly [{ readonly percentage: 100; readonly version_id: string }];
  };
}

export interface PrepareUninstallWorkerDeploymentInput {
  readonly stage: UninstallWorkerDeploymentStage;
  readonly accountId: string;
  readonly workerName: string;
  readonly workerId: string;
  readonly uninstallCycleId: string;
  readonly versionId: string;
}

export interface AdminStateNamespacePresenceProof {
  readonly kind: 'admin_state_namespace_presence';
  readonly accountId: string;
  readonly workerName: string;
  readonly workerId: string;
  readonly uninstallCycleId: string;
  readonly namespaceId: string;
  readonly namespaceName: string;
  readonly className: 'AdminState';
  readonly storage: 'sqlite';
  readonly accountNamespaceCount: number;
  readonly snapshotSha256: string;
}

export interface AdminStateNamespaceRetirementProof {
  readonly kind: 'admin_state_namespace_retirement';
  readonly accountId: string;
  readonly workerName: string;
  readonly workerId: string;
  readonly uninstallCycleId: string;
  readonly namespaceId: string;
  readonly retirementVersionId: string;
  readonly accountNamespaceCount: number;
  readonly firstSnapshotSha256: string;
  readonly secondSnapshotSha256: string;
}

export type PrepareWorkerDeleteInput = ProveAdminStateNamespaceRetiredInput;

export interface WorkerDeleteMutationIntent {
  readonly kind: 'uninstall_worker_delete_intent';
  readonly accountId: string;
  readonly workerName: string;
  readonly workerId: string;
  readonly uninstallCycleId: string;
  readonly namespaceId: string;
  readonly retirementVersionId: string;
  /** SHA-256 of the canonical, exact ProveAdminStateNamespaceRetiredInput. */
  readonly retirementProofCommitment: string;
  /** First complete proof; submit must reproduce it exactly before DELETE. */
  readonly retirementProof: AdminStateNamespaceRetirementProof;
  readonly requestHash: string;
  readonly correlationTag: string;
  readonly method: 'DELETE';
  /** Auditable proof that the optional destructive query flag is not sent. */
  readonly force: 'omitted';
}

export interface WorkerDeletionProof {
  readonly kind: 'uninstall_worker_deletion_proof';
  readonly accountId: string;
  readonly workerName: string;
  readonly workerId: string;
  readonly uninstallCycleId: string;
  readonly requestHash: string;
  readonly firstScriptListSha256: string;
  readonly secondScriptListSha256: string;
  readonly scriptCount: number;
}

/** Exact proof returned by this lifecycle's namespace-bound recovery API. */
export interface WorkerDeletionRecoveryProof extends WorkerDeletionProof {
  readonly namespaceId: string;
  readonly retirementVersionId: string;
  readonly retirementProofCommitment: string;
}

/**
 * The complete persistence allowlist for this module. Submit intents for
 * versions are intentionally excluded because they carry module bytes and, for
 * cleanup, ANKKA_UNINSTALL_NONCE. Cloudflare access tokens live only in calls.
 */
export type CloudflareUninstallWorkerLifecycleJournalRecord =
  | UninstallWorkerVersionRecoveryRecord
  | UninstallWorkerVersionSubmission
  | UninstallWorkerDeploymentMutationIntent
  | UninstallWorkerDeploymentSubmission
  | AdminStateNamespacePresenceProof
  | AdminStateNamespaceRetirementProof
  | WorkerDeleteMutationIntent
  | WorkerDeleteSubmission
  | WorkerDeletionRecoveryProof;

interface PreparedCall {
  readonly accessToken: string;
  readonly transport: (request: Request) => Promise<Response>;
  readonly timeoutMs: number;
}

interface CloudflareEnvelope {
  readonly errors: null | readonly unknown[];
  readonly messages: null | readonly unknown[];
  readonly result: unknown;
  readonly success: boolean;
}

interface VersionModuleBytes extends UninstallWorkerModuleCommitment {
  readonly bytes: Uint8Array;
}

interface DurableObjectNamespaceItem {
  readonly id: string;
  readonly className: string;
  readonly name: string;
  readonly script: string;
  readonly useSqlite: boolean;
}

interface DurableObjectNamespaceSnapshot {
  readonly items: readonly DurableObjectNamespaceItem[];
  readonly sha256: string;
}

function fail(
  code: CloudflareUninstallWorkerLifecycleErrorCode,
  stage: CloudflareUninstallWorkerLifecycleStage,
  outcome: CloudflareUninstallWorkerLifecycleOutcome,
  submissions: readonly CloudflareUninstallWorkerLifecycleSubmission[] = [],
): never {
  throw new CloudflareUninstallWorkerLifecycleError(code, stage, outcome, submissions);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
}

function isJournalObject(value: unknown): value is Record<string, unknown> {
  if (!isRecord(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function exactKeys(value: Record<string, unknown>, expected: readonly string[]): boolean {
  const actual = Object.keys(value).sort();
  const sortedExpected = [...expected].sort();
  return actual.length === sortedExpected.length && actual.every((key, index) => key === sortedExpected[index]);
}

function exactSubmissionIdentity(value: Record<string, unknown>): value is Record<string, unknown> & {
  readonly accountId: string;
  readonly workerName: string;
  readonly workerId: string;
  readonly uninstallCycleId: string;
} {
  return typeof value.accountId === 'string' && ACCOUNT_ID.test(value.accountId) &&
    typeof value.workerName === 'string' && WORKER_NAME.test(value.workerName) &&
    typeof value.workerId === 'string' && WORKER_ID.test(value.workerId) &&
    typeof value.uninstallCycleId === 'string' && UNINSTALL_CYCLE_ID.test(value.uninstallCycleId);
}

/**
 * Pure journal/error-boundary parser. It accepts only an exact known kind and
 * returns a fresh allowlisted locator; extra provider or credential fields
 * reject the whole value instead of being copied into an error.
 */
export function parseCloudflareUninstallWorkerLifecycleSubmission(
  value: unknown,
): CloudflareUninstallWorkerLifecycleSubmission | null {
  try {
    if (!isJournalObject(value) || !exactSubmissionIdentity(value)) return null;
    if (
      value.kind === 'uninstall_worker_version' &&
      exactKeys(value, [
        'accountId', 'correlationTag', 'kind', 'requestHash', 'stage', 'uninstallCycleId', 'versionId',
        'workerId', 'workerName',
      ]) && (value.stage === 'cleanup' || value.stage === 'retirement') &&
      typeof value.versionId === 'string' && UUID.test(value.versionId) &&
      typeof value.requestHash === 'string' && SHA256.test(value.requestHash) &&
      value.correlationTag === versionCorrelationTag(value.stage, value.requestHash)
    ) {
      return Object.freeze({
        kind: 'uninstall_worker_version',
        stage: value.stage,
        accountId: value.accountId,
        workerName: value.workerName,
        workerId: value.workerId,
        uninstallCycleId: value.uninstallCycleId,
        versionId: value.versionId,
        requestHash: value.requestHash,
        correlationTag: value.correlationTag,
      });
    }
    if (
      value.kind === 'uninstall_worker_deployment' &&
      exactKeys(value, [
        'accountId', 'correlationTag', 'deploymentId', 'kind', 'requestHash', 'stage',
        'uninstallCycleId', 'versionId', 'workerId', 'workerName',
      ]) && (value.stage === 'cleanup' || value.stage === 'retirement' || value.stage === 'restore_clean') &&
      typeof value.versionId === 'string' && UUID.test(value.versionId) &&
      typeof value.deploymentId === 'string' && UUID.test(value.deploymentId) &&
      typeof value.requestHash === 'string' && SHA256.test(value.requestHash) &&
      value.correlationTag === deploymentCorrelationTag(value.stage, value.requestHash)
    ) {
      return Object.freeze({
        kind: 'uninstall_worker_deployment',
        stage: value.stage,
        accountId: value.accountId,
        workerName: value.workerName,
        workerId: value.workerId,
        uninstallCycleId: value.uninstallCycleId,
        versionId: value.versionId,
        deploymentId: value.deploymentId,
        requestHash: value.requestHash,
        correlationTag: value.correlationTag,
      });
    }
    if (
      value.kind === 'uninstall_worker_delete' &&
      exactKeys(value, [
        'accountId', 'correlationTag', 'kind', 'namespaceId', 'requestHash',
        'retirementProofCommitment', 'retirementVersionId', 'uninstallCycleId', 'workerId', 'workerName',
      ]) && typeof value.namespaceId === 'string' && ACCOUNT_ID.test(value.namespaceId) &&
      typeof value.retirementVersionId === 'string' && UUID.test(value.retirementVersionId) &&
      typeof value.retirementProofCommitment === 'string' && SHA256.test(value.retirementProofCommitment) &&
      typeof value.requestHash === 'string' && SHA256.test(value.requestHash) &&
      value.correlationTag === `ankka-un-w-delete-sha256:${value.requestHash}`
    ) {
      return Object.freeze({
        kind: 'uninstall_worker_delete',
        accountId: value.accountId,
        workerName: value.workerName,
        workerId: value.workerId,
        uninstallCycleId: value.uninstallCycleId,
        namespaceId: value.namespaceId,
        retirementVersionId: value.retirementVersionId,
        retirementProofCommitment: value.retirementProofCommitment,
        requestHash: value.requestHash,
        correlationTag: value.correlationTag,
      });
    }
    return null;
  } catch {
    return null;
  }
}

function canonicalJson(value: unknown): string {
  if (value === null || typeof value === 'string' || typeof value === 'boolean') return JSON.stringify(value);
  if (typeof value === 'number' && Number.isFinite(value)) return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map((entry) => canonicalJson(entry)).join(',')}]`;
  if (isRecord(value)) {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(',')}}`;
  }
  throw new TypeError('canonical');
}

function canonicalEqual(left: unknown, right: unknown): boolean {
  try {
    return canonicalJson(left) === canonicalJson(right);
  } catch {
    return false;
  }
}

function lexicalCompare(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');
}

async function sha256(value: Uint8Array | string): Promise<string> {
  const source = typeof value === 'string' ? new TextEncoder().encode(value) : value;
  const owned = new Uint8Array(source.byteLength);
  owned.set(source);
  return bytesToHex(new Uint8Array(await crypto.subtle.digest('SHA-256', owned)));
}

function bytesToBase64(bytes: Uint8Array): string {
  let binary = '';
  for (let offset = 0; offset < bytes.byteLength; offset += 0x8000) {
    binary += String.fromCharCode(...bytes.subarray(offset, Math.min(offset + 0x8000, bytes.byteLength)));
  }
  return btoa(binary);
}

function strictBase64Bytes(value: unknown, byteLength: number): Uint8Array | null {
  if (
    typeof value !== 'string' ||
    value.length !== 4 * Math.ceil(byteLength / 3) ||
    !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/u.test(value)
  ) return null;
  try {
    const decoded = atob(value);
    if (decoded.length !== byteLength) return null;
    const bytes = Uint8Array.from(decoded, (character) => character.charCodeAt(0));
    return bytesToBase64(bytes) === value ? bytes : null;
  } catch {
    return null;
  }
}

function extension(path: string): string {
  const slash = path.lastIndexOf('/');
  const dot = path.lastIndexOf('.');
  return dot > slash ? path.slice(dot).toLowerCase() : '';
}

function safeModuleName(value: unknown): value is string {
  return typeof value === 'string' && value.length > 0 && value.length <= 256 &&
    !value.startsWith('/') && !value.includes('\\') && !CONTROL_CHARACTER.test(value) &&
    value.split('/').every((segment) => segment !== '' && segment !== '.' && segment !== '..');
}

function safeToken(value: unknown, minimum = 20): value is string {
  return typeof value === 'string' && value.length >= minimum && value.length <= 8192 && SAFE_TOKEN.test(value);
}

function validIdentity(input: Record<string, unknown>): boolean {
  return ACCOUNT_ID.test(String(input.accountId)) &&
    WORKER_NAME.test(String(input.workerName)) &&
    WORKER_ID.test(String(input.workerId)) &&
    UNINSTALL_CYCLE_ID.test(String(input.uninstallCycleId));
}

function validCleanupVariables(
  value: unknown,
  accountId: string,
  release: string,
  artifactSha256: string,
): value is UninstallCleanupVariables {
  if (!isRecord(value) || !exactKeys(value, UNINSTALL_CLEANUP_VARIABLE_NAMES)) return false;
  for (const name of UNINSTALL_CLEANUP_VARIABLE_NAMES) {
    const entry = value[name];
    if (typeof entry !== 'string' || entry.length === 0 || entry.length > 4096 || CONTROL_CHARACTER.test(entry)) {
      return false;
    }
  }
  return value.ANKKA_GATEWAY_RELEASE === release &&
    value.ANKKA_GATEWAY_RELEASE_SHA256 === `sha256:${artifactSha256}` &&
    value.CLOUDFLARE_ACCOUNT_ID === accountId &&
    typeof value.CLOUDFLARE_ZONE_ID === 'string' && ACCOUNT_ID.test(value.CLOUDFLARE_ZONE_ID) &&
    typeof value.CLOUDFLARE_ZONE_NAME === 'string' && HOSTNAME.test(value.CLOUDFLARE_ZONE_NAME) &&
    value.ZERO_TRUST_READY === 'true';
}

async function verifiedModules(
  modules: VerifiedGatewayWorkerReleaseSet['cleanup']['worker']['modules'],
): Promise<readonly VersionModuleBytes[]> {
  if (!Array.isArray(modules) || modules.length === 0 || modules.length > 1_000) {
    fail('invalid_input', 'validate', 'not_sent');
  }
  const result: VersionModuleBytes[] = [];
  const names = new Set<string>();
  let totalBytes = 0;
  for (const module of modules) {
    if (
      !isRecord(module) || !exactKeys(module, ['bytes', 'contentType', 'name', 'sha256']) ||
      !safeModuleName(module.name) || names.has(module.name) ||
      module.contentType !== MODULE_CONTENT_TYPES[extension(module.name)] ||
      typeof module.sha256 !== 'string' || !SHA256.test(module.sha256) ||
      !(module.bytes instanceof Uint8Array) || module.bytes.byteLength === 0 ||
      module.bytes.byteLength > MAX_FILE_BYTES
    ) fail('invalid_input', 'validate', 'not_sent');
    const bytes = new Uint8Array(module.bytes);
    if (await sha256(bytes) !== module.sha256) fail('invalid_input', 'validate', 'not_sent');
    names.add(module.name);
    totalBytes += bytes.byteLength;
    if (!Number.isSafeInteger(totalBytes) || totalBytes > MAX_RELEASE_BYTES) {
      fail('invalid_input', 'validate', 'not_sent');
    }
    result.push(Object.freeze({
      name: module.name,
      contentType: module.contentType,
      contentSha256: module.sha256,
      byteLength: bytes.byteLength,
      bytes,
    }));
  }
  if (!names.has('index.js')) fail('invalid_input', 'validate', 'not_sent');
  result.sort((left, right) => lexicalCompare(left.name, right.name));
  return Object.freeze(result);
}

function releaseSetIdentityValid(releaseSet: VerifiedGatewayWorkerReleaseSet): boolean {
  if (!isRecord(releaseSet) || !exactKeys(releaseSet, ['cleanup', 'primary', 'retirement'])) return false;
  const { primary, cleanup, retirement } = releaseSet;
  if (!isRecord(primary) || !isRecord(cleanup) || !isRecord(retirement)) return false;
  if (
    primary.verification !== 'ed25519' || cleanup.verification !== 'ed25519' || retirement.verification !== 'ed25519' ||
    !RELEASE.test(primary.release) || cleanup.release !== primary.release || retirement.release !== primary.release ||
    !SHA256.test(primary.artifactSha256) || cleanup.artifactSha256 !== primary.artifactSha256 ||
    retirement.artifactSha256 !== primary.artifactSha256 ||
    !SHA256.test(cleanup.componentSha256) || !SHA256.test(retirement.componentSha256) ||
    cleanup.variant !== 'cleanup' || retirement.variant !== 'retirement' ||
    !isRecord(cleanup.worker) || !isRecord(retirement.worker)
  ) return false;
  return canonicalEqual(
    cleanup.worker.contract,
    APPROVED_CLOUDFLARE_RELEASE_CONTRACT.workerVariants.cleanup,
  ) && canonicalEqual(
    retirement.worker.contract,
    APPROVED_CLOUDFLARE_RELEASE_CONTRACT.workerVariants.retirement,
  );
}

function moduleCommitments(modules: readonly VersionModuleBytes[]): readonly UninstallWorkerModuleCommitment[] {
  return Object.freeze(modules.map((module) => Object.freeze({
    name: module.name,
    contentType: module.contentType,
    contentSha256: module.contentSha256,
    byteLength: module.byteLength,
  })));
}

function versionSemanticCommitment(recovery: UninstallWorkerVersionRecoveryRecord): Record<string, unknown> {
  return {
    accountId: recovery.accountId,
    artifactSha256: recovery.artifactSha256,
    compatibilityDate: recovery.compatibilityDate,
    compatibilityFlags: [...recovery.compatibilityFlags],
    componentSha256: recovery.componentSha256,
    contract: recovery.contract,
    mainModule: recovery.mainModule,
    modules: recovery.modules.map((module) => ({ ...module })),
    release: recovery.release,
    stage: recovery.stage,
    uninstallCycleId: recovery.uninstallCycleId,
    workerId: recovery.workerId,
    workerName: recovery.workerName,
  };
}

/**
 * Version annotations are bounded: Cloudflare rejects a `workers/tag` longer
 * than 100 characters (live 2026-08-23), and stage plus a 64-character digest
 * already spends most of that, so the fixed prefix stays short.
 */
function versionCorrelationTag(stage: UninstallWorkerVersionStage, requestHash: string): string {
  return `ankka-un-v-${stage}-sha256:${requestHash}`;
}

async function createCleanupRecovery(
  input: Omit<PrepareCleanupWorkerVersionInput, 'uninstallNonce'>,
  modules: readonly VersionModuleBytes[],
): Promise<CleanupWorkerVersionRecoveryRecord> {
  const hashes = await Promise.all(UNINSTALL_CLEANUP_VARIABLE_NAMES.map(async (name) => Object.freeze({
    name,
    valueSha256: await sha256(input.variables[name]),
  })));
  const base = {
    kind: 'uninstall_version_recovery' as const,
    stage: 'cleanup' as const,
    accountId: input.accountId,
    workerName: input.workerName,
    workerId: input.workerId,
    namespaceId: input.namespaceId,
    uninstallCycleId: input.uninstallCycleId,
    release: input.releaseSet.cleanup.release,
    artifactSha256: input.releaseSet.cleanup.artifactSha256,
    componentSha256: input.releaseSet.cleanup.componentSha256,
    compatibilityDate: EXACT_COMPATIBILITY_DATE,
    compatibilityFlags: Object.freeze([]) as readonly [],
    mainModule: 'index.js' as const,
    contract: Object.freeze({
      assets: 'absent' as const,
      defaultApplication: 'absent' as const,
      durableObject: Object.freeze({
        binding: 'ADMIN_STATE' as const,
        className: 'AdminState' as const,
        namespaceId: input.namespaceId,
        storage: 'sqlite' as const,
      }),
      exports: Object.freeze({
        AdminState: Object.freeze({ type: 'durable-object' as const, storage: 'sqlite' as const }),
      }),
      uninstallNonceBinding: 'present' as const,
      variableValueHashes: Object.freeze(hashes),
    }),
    modules: moduleCommitments(modules),
  };
  const requestHash = await sha256(canonicalJson(versionSemanticCommitment({
    ...base,
    requestHash: '0'.repeat(64),
    correlationTag: '',
  })));
  return Object.freeze({
    ...base,
    requestHash,
    correlationTag: versionCorrelationTag('cleanup', requestHash),
  });
}

async function createRetirementRecovery(
  input: PrepareRetirementWorkerVersionInput,
  modules: readonly VersionModuleBytes[],
): Promise<RetirementWorkerVersionRecoveryRecord> {
  const base = {
    kind: 'uninstall_version_recovery' as const,
    stage: 'retirement' as const,
    accountId: input.accountId,
    workerName: input.workerName,
    workerId: input.workerId,
    uninstallCycleId: input.uninstallCycleId,
    release: input.releaseSet.retirement.release,
    artifactSha256: input.releaseSet.retirement.artifactSha256,
    componentSha256: input.releaseSet.retirement.componentSha256,
    compatibilityDate: EXACT_COMPATIBILITY_DATE,
    compatibilityFlags: Object.freeze([]) as readonly [],
    mainModule: 'index.js' as const,
    contract: Object.freeze({
      assets: 'absent' as const,
      bindings: Object.freeze([]) as readonly [],
      defaultApplication: 'absent' as const,
      exports: Object.freeze({
        AdminState: Object.freeze({ type: 'durable-object' as const, state: 'deleted' as const }),
      }),
    }),
    modules: moduleCommitments(modules),
  };
  const requestHash = await sha256(canonicalJson(versionSemanticCommitment({
    ...base,
    requestHash: '0'.repeat(64),
    correlationTag: '',
  })));
  return Object.freeze({
    ...base,
    requestHash,
    correlationTag: versionCorrelationTag('retirement', requestHash),
  });
}

function versionBody(
  recovery: UninstallWorkerVersionRecoveryRecord,
  modules: readonly VersionModuleBytes[],
  variables?: UninstallCleanupVariables,
  uninstallNonce?: string,
): Readonly<Record<string, unknown>> {
  const bindings: Record<string, unknown>[] = [];
  if (recovery.stage === 'cleanup') {
    if (!variables || !uninstallNonce) fail('invalid_input', 'validate', 'not_sent');
    bindings.push({
      name: 'ADMIN_STATE',
      type: 'durable_object_namespace',
      class_name: 'AdminState',
      namespace_id: recovery.namespaceId,
    });
    for (const name of UNINSTALL_CLEANUP_VARIABLE_NAMES) {
      bindings.push({ name, type: 'plain_text', text: variables[name] });
    }
    bindings.push({ name: 'ANKKA_UNINSTALL_NONCE', type: 'secret_text', text: uninstallNonce });
  }
  bindings.sort((left, right) => lexicalCompare(String(left.name), String(right.name)));
  return Object.freeze({
    annotations: Object.freeze({ 'workers/tag': recovery.correlationTag }),
    bindings: Object.freeze(bindings.map((binding) => Object.freeze(binding))),
    compatibility_date: recovery.compatibilityDate,
    compatibility_flags: Object.freeze([]),
    exports: recovery.contract.exports,
    main_module: recovery.mainModule,
    modules: Object.freeze(modules.map((module) => Object.freeze({
      name: module.name,
      content_type: module.contentType,
      content_base64: bytesToBase64(module.bytes),
    }))),
  });
}

export async function prepareCleanupWorkerVersionMutation(
  input: PrepareCleanupWorkerVersionInput,
): Promise<UninstallWorkerVersionMutationPlan> {
  if (
    !isRecord(input) || !exactKeys(input, [
      'accountId', 'namespaceId', 'releaseSet', 'uninstallCycleId', 'uninstallNonce', 'variables',
      'workerId', 'workerName',
    ]) || !validIdentity(input) || !ACCOUNT_ID.test(input.namespaceId) ||
    !safeToken(input.uninstallNonce, 32) || !releaseSetIdentityValid(input.releaseSet) ||
    !validCleanupVariables(
      input.variables,
      input.accountId,
      input.releaseSet.cleanup.release,
      input.releaseSet.cleanup.artifactSha256,
    )
  ) fail('invalid_input', 'validate', 'not_sent');
  const modules = await verifiedModules(input.releaseSet.cleanup.worker.modules);
  const recovery = await createCleanupRecovery(input, modules);
  const body = versionBody(recovery, modules, input.variables, input.uninstallNonce);
  return Object.freeze({
    recovery,
    ephemeral: Object.freeze({
      kind: 'uninstall_version_submit',
      stage: 'cleanup',
      accountId: input.accountId,
      workerName: input.workerName,
      workerId: input.workerId,
      uninstallCycleId: input.uninstallCycleId,
      requestHash: recovery.requestHash,
      correlationTag: recovery.correlationTag,
      semanticCommitment: Object.freeze(versionSemanticCommitment(recovery)),
      body,
    }),
  });
}

export async function prepareRetirementWorkerVersionMutation(
  input: PrepareRetirementWorkerVersionInput,
): Promise<UninstallWorkerVersionMutationPlan> {
  if (
    !isRecord(input) || !exactKeys(input, [
      'accountId', 'releaseSet', 'uninstallCycleId', 'workerId', 'workerName',
    ]) || !validIdentity(input) || !releaseSetIdentityValid(input.releaseSet)
  ) fail('invalid_input', 'validate', 'not_sent');
  const modules = await verifiedModules(input.releaseSet.retirement.worker.modules);
  const recovery = await createRetirementRecovery(input, modules);
  const body = versionBody(recovery, modules);
  return Object.freeze({
    recovery,
    ephemeral: Object.freeze({
      kind: 'uninstall_version_submit',
      stage: 'retirement',
      accountId: input.accountId,
      workerName: input.workerName,
      workerId: input.workerId,
      uninstallCycleId: input.uninstallCycleId,
      requestHash: recovery.requestHash,
      correlationTag: recovery.correlationTag,
      semanticCommitment: Object.freeze(versionSemanticCommitment(recovery)),
      body,
    }),
  });
}

function validModuleCommitments(value: unknown): value is readonly UninstallWorkerModuleCommitment[] {
  if (!Array.isArray(value) || value.length === 0 || value.length > 1_000) return false;
  const names = new Set<string>();
  let previous = '';
  let total = 0;
  for (const module of value) {
    if (
      !isRecord(module) || !exactKeys(module, ['byteLength', 'contentSha256', 'contentType', 'name']) ||
      !safeModuleName(module.name) || names.has(module.name) || (previous !== '' && previous >= module.name) ||
      module.contentType !== MODULE_CONTENT_TYPES[extension(module.name)] ||
      typeof module.contentSha256 !== 'string' || !SHA256.test(module.contentSha256) ||
      typeof module.byteLength !== 'number' || !Number.isSafeInteger(module.byteLength) ||
      module.byteLength <= 0 || module.byteLength > MAX_FILE_BYTES
    ) return false;
    names.add(module.name);
    previous = module.name;
    total += module.byteLength;
    if (!Number.isSafeInteger(total) || total > MAX_RELEASE_BYTES) return false;
  }
  return names.has('index.js');
}

function exactCleanupContract(value: unknown, namespaceId: string): value is CleanupWorkerVersionRecoveryRecord['contract'] {
  if (!isRecord(value) || !exactKeys(value, [
    'assets', 'defaultApplication', 'durableObject', 'exports', 'uninstallNonceBinding',
    'variableValueHashes',
  ])) return false;
  if (
    value.assets !== 'absent' || value.defaultApplication !== 'absent' ||
    value.uninstallNonceBinding !== 'present' ||
    !canonicalEqual(value.durableObject, {
      binding: 'ADMIN_STATE', className: 'AdminState', namespaceId, storage: 'sqlite',
    }) ||
    !canonicalEqual(value.exports, {
      AdminState: { storage: 'sqlite', type: 'durable-object' },
    }) ||
    !Array.isArray(value.variableValueHashes) ||
    value.variableValueHashes.length !== UNINSTALL_CLEANUP_VARIABLE_NAMES.length
  ) return false;
  return value.variableValueHashes.every((binding, index) => (
    isRecord(binding) && exactKeys(binding, ['name', 'valueSha256']) &&
    binding.name === UNINSTALL_CLEANUP_VARIABLE_NAMES[index] &&
    typeof binding.valueSha256 === 'string' && SHA256.test(binding.valueSha256)
  ));
}

function exactRetirementContract(value: unknown): value is RetirementWorkerVersionRecoveryRecord['contract'] {
  return isRecord(value) && exactKeys(value, ['assets', 'bindings', 'defaultApplication', 'exports']) &&
    value.assets === 'absent' && value.defaultApplication === 'absent' &&
    Array.isArray(value.bindings) && value.bindings.length === 0 &&
    canonicalEqual(value.exports, {
      AdminState: { state: 'deleted', type: 'durable-object' },
    });
}

async function validVersionRecoveryRecord(value: unknown): Promise<boolean> {
  if (!isRecord(value)) return false;
  const cleanup = value.stage === 'cleanup';
  const expected = cleanup
    ? [
        'accountId', 'artifactSha256', 'compatibilityDate', 'compatibilityFlags', 'componentSha256',
        'contract', 'correlationTag', 'kind', 'mainModule', 'modules', 'namespaceId', 'release',
        'requestHash', 'stage', 'uninstallCycleId', 'workerId', 'workerName',
      ]
    : [
        'accountId', 'artifactSha256', 'compatibilityDate', 'compatibilityFlags', 'componentSha256',
        'contract', 'correlationTag', 'kind', 'mainModule', 'modules', 'release', 'requestHash',
        'stage', 'uninstallCycleId', 'workerId', 'workerName',
      ];
  if (
    !exactKeys(value, expected) || value.kind !== 'uninstall_version_recovery' ||
    (value.stage !== 'cleanup' && value.stage !== 'retirement') || !validIdentity(value) ||
    typeof value.release !== 'string' || !RELEASE.test(value.release) ||
    typeof value.artifactSha256 !== 'string' || !SHA256.test(value.artifactSha256) ||
    typeof value.componentSha256 !== 'string' || !SHA256.test(value.componentSha256) ||
    typeof value.requestHash !== 'string' || !SHA256.test(value.requestHash) ||
    value.correlationTag !== versionCorrelationTag(value.stage, value.requestHash) ||
    value.compatibilityDate !== EXACT_COMPATIBILITY_DATE ||
    !Array.isArray(value.compatibilityFlags) || value.compatibilityFlags.length !== 0 ||
    value.mainModule !== 'index.js' || !validModuleCommitments(value.modules)
  ) return false;
  if (cleanup) {
    if (typeof value.namespaceId !== 'string' || !ACCOUNT_ID.test(value.namespaceId) ||
      !exactCleanupContract(value.contract, value.namespaceId)) return false;
  } else if (!exactRetirementContract(value.contract)) return false;
  try {
    const expectedHash = await sha256(canonicalJson(versionSemanticCommitment(
      value as unknown as UninstallWorkerVersionRecoveryRecord,
    )));
    return expectedHash === value.requestHash;
  } catch {
    return false;
  }
}

/** Parse an exact, credential-free record at the uninstall journal boundary. */
export async function parseUninstallWorkerVersionRecoveryRecord(
  value: unknown,
): Promise<UninstallWorkerVersionRecoveryRecord | null> {
  try {
    if (!isJournalObject(value) || !await validVersionRecoveryRecord(value)) return null;
    const input = value as unknown as UninstallWorkerVersionRecoveryRecord;
    const modules: UninstallWorkerModuleCommitment[] = [];
    for (let index = 0; index < input.modules.length; index += 1) {
      const module = input.modules[index];
      modules.push(Object.freeze({
        name: module.name,
        contentType: module.contentType,
        contentSha256: module.contentSha256,
        byteLength: module.byteLength,
      }));
    }
    const common = {
      kind: 'uninstall_version_recovery' as const,
      accountId: input.accountId,
      workerName: input.workerName,
      workerId: input.workerId,
      uninstallCycleId: input.uninstallCycleId,
      release: input.release,
      artifactSha256: input.artifactSha256,
      componentSha256: input.componentSha256,
      requestHash: input.requestHash,
      correlationTag: input.correlationTag,
      compatibilityDate: EXACT_COMPATIBILITY_DATE,
      compatibilityFlags: Object.freeze([]) as readonly [],
      mainModule: 'index.js' as const,
      modules: Object.freeze(modules),
    };
    if (input.stage === 'cleanup') {
      const variableValueHashes: Array<{
        readonly name: UninstallCleanupVariableName;
        readonly valueSha256: string;
      }> = [];
      for (let index = 0; index < input.contract.variableValueHashes.length; index += 1) {
        const binding = input.contract.variableValueHashes[index];
        variableValueHashes.push(Object.freeze({
          name: binding.name,
          valueSha256: binding.valueSha256,
        }));
      }
      const parsed = Object.freeze({
        ...common,
        stage: 'cleanup',
        namespaceId: input.namespaceId,
        contract: Object.freeze({
          assets: 'absent',
          defaultApplication: 'absent',
          durableObject: Object.freeze({
            binding: 'ADMIN_STATE',
            className: 'AdminState',
            namespaceId: input.namespaceId,
            storage: 'sqlite',
          }),
          exports: Object.freeze({
            AdminState: Object.freeze({ type: 'durable-object', storage: 'sqlite' }),
          }),
          uninstallNonceBinding: 'present',
          variableValueHashes: Object.freeze(variableValueHashes),
        }),
      });
      return await validVersionRecoveryRecord(parsed) ? parsed : null;
    }
    const parsed = Object.freeze({
      ...common,
      stage: 'retirement',
      contract: Object.freeze({
        assets: 'absent',
        bindings: Object.freeze([]) as readonly [],
        defaultApplication: 'absent',
        exports: Object.freeze({
          AdminState: Object.freeze({ type: 'durable-object', state: 'deleted' }),
        }),
      }),
    });
    return await validVersionRecoveryRecord(parsed) ? parsed : null;
  } catch {
    return null;
  }
}

async function validVersionSubmitIntent(
  intent: UninstallWorkerVersionSubmitIntent,
  recovery: UninstallWorkerVersionRecoveryRecord,
): Promise<boolean> {
  if (
    !await validVersionRecoveryRecord(recovery) || !isRecord(intent) || !exactKeys(intent, [
      'accountId', 'body', 'correlationTag', 'kind', 'requestHash', 'semanticCommitment', 'stage',
      'uninstallCycleId', 'workerId', 'workerName',
    ]) || intent.kind !== 'uninstall_version_submit' || intent.stage !== recovery.stage ||
    intent.accountId !== recovery.accountId || intent.workerName !== recovery.workerName ||
    intent.workerId !== recovery.workerId || intent.uninstallCycleId !== recovery.uninstallCycleId ||
    intent.requestHash !== recovery.requestHash || intent.correlationTag !== recovery.correlationTag ||
    !canonicalEqual(intent.semanticCommitment, versionSemanticCommitment(recovery)) ||
    !isRecord(intent.body) || !exactKeys(intent.body, [
      'annotations', 'bindings', 'compatibility_date', 'compatibility_flags', 'exports',
      'main_module', 'modules',
    ]) || Object.hasOwn(intent.body, 'assets') || Object.hasOwn(intent.body, 'migrations') ||
    Object.hasOwn(intent.body, 'migration_tag') ||
    !canonicalEqual(intent.body.annotations, { 'workers/tag': recovery.correlationTag }) ||
    intent.body.compatibility_date !== EXACT_COMPATIBILITY_DATE ||
    !Array.isArray(intent.body.compatibility_flags) || intent.body.compatibility_flags.length !== 0 ||
    intent.body.main_module !== 'index.js' ||
    !canonicalEqual(intent.body.exports, recovery.contract.exports) ||
    !Array.isArray(intent.body.bindings) || !Array.isArray(intent.body.modules) ||
    intent.body.modules.length !== recovery.modules.length
  ) return false;

  const bindingMap = new Map<string, Record<string, unknown>>();
  for (const binding of intent.body.bindings) {
    if (!isRecord(binding) || typeof binding.name !== 'string' || bindingMap.has(binding.name)) return false;
    bindingMap.set(binding.name, binding);
  }
  if (recovery.stage === 'cleanup') {
    if (bindingMap.size !== UNINSTALL_CLEANUP_VARIABLE_NAMES.length + 2) return false;
    if (!canonicalEqual(bindingMap.get('ADMIN_STATE'), {
      name: 'ADMIN_STATE', type: 'durable_object_namespace', class_name: 'AdminState',
      namespace_id: recovery.namespaceId,
    })) return false;
    for (const expected of recovery.contract.variableValueHashes) {
      const binding = bindingMap.get(expected.name);
      if (
        !binding || !exactKeys(binding, ['name', 'text', 'type']) || binding.type !== 'plain_text' ||
        typeof binding.text !== 'string' || await sha256(binding.text) !== expected.valueSha256
      ) return false;
    }
    const nonce = bindingMap.get('ANKKA_UNINSTALL_NONCE');
    if (
      !nonce || !exactKeys(nonce, ['name', 'text', 'type']) || nonce.type !== 'secret_text' ||
      !safeToken(nonce.text, 32)
    ) return false;
  } else if (bindingMap.size !== 0) return false;

  for (let index = 0; index < recovery.modules.length; index += 1) {
    const expected = recovery.modules[index];
    const module = intent.body.modules[index];
    if (
      !isRecord(module) || !exactKeys(module, ['content_base64', 'content_type', 'name']) ||
      module.name !== expected.name || module.content_type !== expected.contentType
    ) return false;
    const bytes = strictBase64Bytes(module.content_base64, expected.byteLength);
    if (!bytes || await sha256(bytes) !== expected.contentSha256) return false;
  }
  return await sha256(canonicalJson(intent.semanticCommitment)) === recovery.requestHash;
}

function prepareCall(value: CloudflareDirectUploadCall): PreparedCall {
  if (!isRecord(value)) fail('invalid_input', 'validate', 'not_sent');
  const timeoutMs = value.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  if (
    !safeToken(value.accessToken) || typeof value.transport !== 'function' ||
    !Number.isSafeInteger(timeoutMs) || timeoutMs < 100 || timeoutMs > 60_000
  ) fail('invalid_input', 'validate', 'not_sent');
  return { accessToken: value.accessToken, transport: value.transport, timeoutMs };
}

function authHeaders(accessToken: string): Headers {
  const headers = new Headers();
  headers.set('accept', 'application/json');
  headers.set('authorization', `Bearer ${accessToken}`);
  return headers;
}

function jsonHeaders(accessToken: string): Headers {
  const headers = authHeaders(accessToken);
  headers.set('content-type', 'application/json');
  return headers;
}

async function readBoundedJson(response: Response, maximum = MAX_RESPONSE_BYTES): Promise<unknown> {
  const contentType = response.headers.get('content-type')?.toLowerCase() ?? '';
  if (!contentType.startsWith('application/json') || !response.body) throw new TypeError('response');
  const declared = response.headers.get('content-length');
  if (declared !== null) {
    const parsed = Number(declared);
    if (!Number.isSafeInteger(parsed) || parsed < 0 || parsed > maximum) throw new TypeError('response');
  }
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > maximum) {
      await reader.cancel();
      throw new TypeError('response');
    }
    chunks.push(value);
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
    throw new TypeError('response');
  }
}

async function requestJson(
  call: PreparedCall,
  stage: CloudflareUninstallWorkerLifecycleStage,
  url: string,
  init: RequestInit,
  maximum = MAX_RESPONSE_BYTES,
  submissions: readonly CloudflareUninstallWorkerLifecycleSubmission[] = [],
): Promise<{ readonly status: number; readonly value: unknown }> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), call.timeoutMs);
  const mutation = init.method === 'POST' || init.method === 'DELETE';
  try {
    const response = await call.transport(new Request(url, { ...init, signal: controller.signal }));
    const value = await readBoundedJson(response, maximum);
    return { status: response.status, value };
  } catch {
    fail('provider_unknown', stage, mutation ? 'unknown' : 'unknown', submissions);
  } finally {
    clearTimeout(timeout);
  }
}

function isEmptyProviderList(value: unknown): value is null | readonly [] {
  return value === null || (Array.isArray(value) && value.length === 0);
}

function providerErrors(value: unknown): boolean {
  return Array.isArray(value) && value.length > 0 && value.length <= 16 && value.every((error) => (
    isRecord(error) && typeof error.code === 'number' && Number.isSafeInteger(error.code) &&
    typeof error.message === 'string' && error.message.length > 0 && error.message.length <= 2_048 &&
    Object.keys(error).every((key) => ['code', 'documentation_url', 'message', 'source'].includes(key))
  ));
}

function parseEnvelope(value: unknown): CloudflareEnvelope | null {
  if (!isRecord(value) || !exactKeys(value, ['errors', 'messages', 'result', 'success']) ||
    typeof value.success !== 'boolean' || !(value.errors === null || Array.isArray(value.errors)) ||
    !(value.messages === null || Array.isArray(value.messages))) return null;
  return {
    errors: value.errors,
    messages: value.messages,
    result: value.result,
    success: value.success,
  };
}

function successResult(value: unknown): unknown | null {
  const envelope = parseEnvelope(value);
  return envelope && envelope.success && isEmptyProviderList(envelope.errors) &&
    isEmptyProviderList(envelope.messages) ? envelope.result : null;
}

function absentEnvelope(value: unknown): boolean {
  const envelope = parseEnvelope(value);
  return Boolean(envelope && !envelope.success && providerErrors(envelope.errors) &&
    isEmptyProviderList(envelope.messages) && envelope.result === null);
}

function rejectStatus(
  status: number,
  value: unknown,
  stage: CloudflareUninstallWorkerLifecycleStage,
  submissions: readonly CloudflareUninstallWorkerLifecycleSubmission[] = [],
): never {
  const envelope = parseEnvelope(value);
  if (status >= 400 && status < 500 && envelope && !envelope.success && providerErrors(envelope.errors)) {
    fail('provider_rejected', stage, 'rejected', submissions);
  }
  fail('provider_unknown', stage, 'unknown', submissions);
}

function rawResultId(value: unknown, pattern: RegExp): string | null {
  if (!isRecord(value) || !isRecord(value.result) || typeof value.result.id !== 'string') return null;
  return pattern.test(value.result.id) ? value.result.id : null;
}

function versionResponseMaximum(recovery: UninstallWorkerVersionRecoveryRecord): number {
  const moduleBytes = recovery.modules.reduce(
    (total, module) => total + 4 * Math.ceil(module.byteLength / 3),
    0,
  );
  return Math.min(MAX_VERSION_RESPONSE_BYTES, Math.max(MAX_RESPONSE_BYTES, moduleBytes + 1024 * 1024));
}

function versionSubmission(
  recovery: UninstallWorkerVersionRecoveryRecord,
  versionId: string,
): UninstallWorkerVersionSubmission {
  return Object.freeze({
    kind: 'uninstall_worker_version',
    stage: recovery.stage,
    accountId: recovery.accountId,
    workerName: recovery.workerName,
    workerId: recovery.workerId,
    uninstallCycleId: recovery.uninstallCycleId,
    versionId,
    requestHash: recovery.requestHash,
    correlationTag: recovery.correlationTag,
  });
}

function validVersionSubmission(
  recovery: UninstallWorkerVersionRecoveryRecord,
  submission: UninstallWorkerVersionSubmission,
): boolean {
  return isRecord(submission) && exactKeys(submission, [
    'accountId', 'correlationTag', 'kind', 'requestHash', 'stage', 'uninstallCycleId', 'versionId',
    'workerId', 'workerName',
  ]) && submission.kind === 'uninstall_worker_version' && submission.stage === recovery.stage &&
    submission.accountId === recovery.accountId && submission.workerName === recovery.workerName &&
    submission.workerId === recovery.workerId && submission.uninstallCycleId === recovery.uninstallCycleId &&
    submission.requestHash === recovery.requestHash && submission.correlationTag === recovery.correlationTag &&
    UUID.test(submission.versionId);
}

/**
 * The outer durable journal owns one-shot CAS/replay control. This module has
 * no process-local replay lock. A returned ID is not a validation proof.
 */
export async function submitUninstallWorkerVersionMutation(
  intent: UninstallWorkerVersionSubmitIntent,
  recovery: UninstallWorkerVersionRecoveryRecord,
  callInput: CloudflareDirectUploadCall,
): Promise<UninstallWorkerVersionSubmission> {
  if (!await validVersionSubmitIntent(intent, recovery)) fail('invalid_input', 'validate', 'not_sent');
  const call = prepareCall(callInput);
  const response = await requestJson(
    call,
    'version_submit',
    `${CLOUDFLARE_API_ORIGIN}/client/v4/accounts/${intent.accountId}/workers/workers/${intent.workerId}/versions`,
    { method: 'POST', headers: jsonHeaders(call.accessToken), body: JSON.stringify(intent.body) },
    versionResponseMaximum(recovery),
  );
  const versionId = rawResultId(response.value, UUID);
  const surfaced = versionId === null ? [] : [versionSubmission(recovery, versionId)];
  if (![200, 201].includes(response.status)) rejectStatus(response.status, response.value, 'version_submit', surfaced);
  if (versionId === null) fail('provider_mismatch', 'version_submit', 'unknown');
  const submission = surfaced[0];
  const result = successResult(response.value);
  if (!isRecord(result) || result.id !== versionId) {
    fail('provider_mismatch', 'version_submit', 'submitted', [submission]);
  }
  return submission;
}

function safeIsoDate(value: unknown): value is string {
  return typeof value === 'string' && value.length >= 20 && value.length <= 40 && Number.isFinite(Date.parse(value));
}

function exactVersionAnnotations(value: unknown, correlationTag: string): boolean {
  if (!isRecord(value)) return false;
  if (Object.keys(value).some((key) => !['workers/message', 'workers/tag', 'workers/triggered_by'].includes(key))) {
    return false;
  }
  return value['workers/tag'] === correlationTag && ['workers/message', 'workers/triggered_by'].every((key) => (
    value[key] === undefined || (
      typeof value[key] === 'string' && value[key].length > 0 && value[key].length <= 256
    )
  ));
}

function exactDefaultWorkerExport(value: unknown): boolean {
  if (!isRecord(value) || value.type !== 'worker') return false;
  if (Object.keys(value).some((key) => !['cache', 'state', 'type'].includes(key))) return false;
  if (!(value.state === undefined || value.state === 'created')) return false;
  return value.cache === undefined || (
    isRecord(value.cache) && exactKeys(value.cache, ['enabled']) && value.cache.enabled === false
  );
}

function exactActiveExports(value: unknown): boolean {
  if (!isRecord(value)) return false;
  const keys = Object.keys(value).sort();
  if (!(keys.length === 1 || (keys.length === 2 && keys[0] === 'AdminState' && keys[1] === 'default'))) {
    return false;
  }
  const adminState = value.AdminState;
  if (
    !isRecord(adminState) ||
    !(
      exactKeys(adminState, ['storage', 'type']) ||
      exactKeys(adminState, ['state', 'storage', 'type'])
    ) ||
    adminState.type !== 'durable-object' || adminState.storage !== 'sqlite' ||
    !(adminState.state === undefined || adminState.state === 'created')
  ) return false;
  return value.default === undefined || exactDefaultWorkerExport(value.default);
}

/**
 * Live (2026-08-23): a retired Durable Object export is not dropped from the
 * version's export map — it stays and is marked `state: 'deleted'`, which is a
 * stronger retirement proof than absence. Either shape is accepted; a live
 * `AdminState` export is not.
 */
function exactRetiredExports(value: unknown): boolean {
  if (!isRecord(value)) return false;
  if (Object.keys(value).some((key) => !['AdminState', 'default'].includes(key))) return false;
  if (Object.hasOwn(value, 'AdminState')) {
    const adminState = value.AdminState;
    if (!isRecord(adminState) || !exactKeys(adminState, ['state', 'type']) ||
      adminState.type !== 'durable-object' || adminState.state !== 'deleted') return false;
  }
  return !Object.hasOwn(value, 'default') || exactDefaultWorkerExport(value.default);
}

const EXPORT_RECONCILIATION_KEYS = Object.freeze([
  'created',
  'deleted',
  'info',
  'removable_entries',
  'renamed',
  'transfer_pending',
  'transferred',
  'updated',
  'warnings',
] as const);

function validExportReconciliation(value: unknown, stage: UninstallWorkerVersionStage): boolean {
  if (!isRecord(value) || !exactKeys(value, EXPORT_RECONCILIATION_KEYS)) return false;
  for (const key of EXPORT_RECONCILIATION_KEYS) {
    if (!Array.isArray(value[key])) return false;
  }
  if (stage === 'retirement') {
    return canonicalEqual(value.deleted, ['AdminState']) &&
      EXPORT_RECONCILIATION_KEYS.filter((key) => key !== 'deleted').every(
        (key) => (value[key] as unknown[]).length === 0,
      );
  }
  if ((value.deleted as unknown[]).length !== 0) return false;
  const allowedAdminState = (entry: unknown): boolean => entry === 'AdminState';
  return ['created', 'updated'].every((key) => (
    (value[key] as unknown[]).length <= 1 && (value[key] as unknown[]).every(allowedAdminState)
  )) && EXPORT_RECONCILIATION_KEYS.filter(
    (key) => !['created', 'deleted', 'updated'].includes(key),
  ).every((key) => (value[key] as unknown[]).length === 0);
}

async function exactVersionResult(
  result: unknown,
  recovery: UninstallWorkerVersionRecoveryRecord,
  versionId: string,
  requireModuleContent = false,
): Promise<boolean> {
  // Live version read-back (2026-08-23) also carries env, source, and urls, and
  // omits compatibility_flags and exports_reconciliation when they are empty or
  // not yet reconciled. The uninstall Workers carry no assets at any stage.
  if (!isRecord(result) || Object.keys(result).some((key) => ![
    'annotations', 'bindings', 'compatibility_date', 'compatibility_flags', 'created_on', 'env', 'exports',
    'exports_reconciliation', 'id', 'limits', 'main_module', 'modules', 'number', 'placement', 'source',
    'startup_time_ms', 'urls', 'usage_model',
  ].includes(key))) return false;
  if (
    Object.hasOwn(result, 'assets') || Object.hasOwn(result, 'migrations') ||
    Object.hasOwn(result, 'migration_tag') || result.id !== versionId || !safeIsoDate(result.created_on) ||
    typeof result.number !== 'number' || !Number.isSafeInteger(result.number) || result.number < 1 ||
    result.compatibility_date !== recovery.compatibilityDate ||
    !(result.compatibility_flags === undefined ||
      (Array.isArray(result.compatibility_flags) && result.compatibility_flags.length === 0)) ||
    result.main_module !== recovery.mainModule ||
    !exactVersionAnnotations(result.annotations, recovery.correlationTag) ||
    // Declarative exports are reconciled by the deployment, so the field is
    // absent on a version that has not been deployed yet. The exact `exports`
    // assertion below carries the same evidence and is always present.
    !(result.exports_reconciliation === undefined ||
      validExportReconciliation(result.exports_reconciliation, recovery.stage)) ||
    // A version with no bindings omits the field entirely (live 2026-08-23).
    !(result.bindings === undefined || Array.isArray(result.bindings)) ||
    !Array.isArray(result.modules) || result.modules.length !== recovery.modules.length
  ) return false;
  if (result.source !== undefined && result.source !== 'api') return false;
  if (result.urls !== undefined && !Array.isArray(result.urls)) return false;
  if (result.env !== undefined && !isRecord(result.env)) return false;
  if (recovery.stage === 'cleanup' ? !exactActiveExports(result.exports) : !exactRetiredExports(result.exports)) {
    return false;
  }
  if (result.usage_model !== undefined && !(
    typeof result.usage_model === 'string' && result.usage_model.length > 0 && result.usage_model.length <= 128
  )) return false;
  if (result.startup_time_ms !== undefined && !(
    typeof result.startup_time_ms === 'number' && Number.isFinite(result.startup_time_ms) &&
    result.startup_time_ms >= 0
  )) return false;
  if (result.limits !== undefined && !(
    isRecord(result.limits) && Object.keys(result.limits).every((key) => key === 'cpu_ms') &&
    (result.limits.cpu_ms === undefined || (
      typeof result.limits.cpu_ms === 'number' && Number.isSafeInteger(result.limits.cpu_ms) &&
      result.limits.cpu_ms >= 0
    ))
  )) return false;
  if (result.placement !== undefined && !(
    isRecord(result.placement) && Object.keys(result.placement).every((key) => ['hint', 'mode'].includes(key)) &&
    (result.placement.mode === undefined || typeof result.placement.mode === 'string') &&
    (result.placement.hint === undefined || typeof result.placement.hint === 'string')
  )) return false;

  const bindings = new Map<string, Record<string, unknown>>();
  for (const binding of (result.bindings ?? []) as readonly unknown[]) {
    if (!isRecord(binding) || typeof binding.name !== 'string' || bindings.has(binding.name)) return false;
    bindings.set(binding.name, binding);
  }
  if (recovery.stage === 'retirement') {
    if (bindings.size !== 0) return false;
  } else {
    if (bindings.size !== UNINSTALL_CLEANUP_VARIABLE_NAMES.length + 2) return false;
    const adminState = bindings.get('ADMIN_STATE');
    if (
      !adminState || adminState.type !== 'durable_object_namespace' || adminState.class_name !== 'AdminState' ||
      Object.keys(adminState).some((key) => !['class_name', 'name', 'namespace_id', 'type'].includes(key)) ||
      (adminState.namespace_id !== undefined && adminState.namespace_id !== recovery.namespaceId)
    ) return false;
    const nonce = bindings.get('ANKKA_UNINSTALL_NONCE');
    if (!nonce || !exactKeys(nonce, ['name', 'type']) || nonce.type !== 'secret_text') return false;
    for (const expected of recovery.contract.variableValueHashes) {
      const binding = bindings.get(expected.name);
      if (
        !binding || !exactKeys(binding, ['name', 'text', 'type']) || binding.type !== 'plain_text' ||
        typeof binding.text !== 'string' || await sha256(binding.text) !== expected.valueSha256
      ) return false;
    }
  }

  const returnedModules = new Map<string, Record<string, unknown>>();
  for (const module of result.modules) {
    if (!isRecord(module) || typeof module.name !== 'string' || returnedModules.has(module.name)) return false;
    returnedModules.set(module.name, module);
  }
  if (returnedModules.size !== recovery.modules.length) return false;
  for (const expected of recovery.modules) {
    const module = returnedModules.get(expected.name);
    if (
      !module || Object.keys(module).some((key) => !['content_base64', 'content_type', 'name'].includes(key)) ||
      !Object.hasOwn(module, 'content_type') || module.content_type !== expected.contentType ||
      (requireModuleContent && typeof module.content_base64 !== 'string')
    ) return false;
    if (module.content_base64 !== undefined) {
      const bytes = strictBase64Bytes(module.content_base64, expected.byteLength);
      if (!bytes || await sha256(bytes) !== expected.contentSha256) return false;
    }
  }
  return true;
}

async function verifyUninstallWorkerVersionSubmissionWithMode(
  recovery: UninstallWorkerVersionRecoveryRecord,
  submission: UninstallWorkerVersionSubmission,
  callInput: CloudflareDirectUploadCall,
  requireModuleContent: boolean,
): Promise<UninstallWorkerVersionSubmission> {
  if (!await validVersionRecoveryRecord(recovery) || !validVersionSubmission(recovery, submission)) {
    fail('invalid_input', 'validate', 'not_sent', [submission]);
  }
  const call = prepareCall(callInput);
  const response = await requestJson(
    call,
    'version_verify',
    // Modules are returned only when explicitly included (live 2026-08-23).
    `${CLOUDFLARE_API_ORIGIN}/client/v4/accounts/${recovery.accountId}/workers/workers/${recovery.workerId}/versions/${submission.versionId}?include=modules`,
    { method: 'GET', headers: authHeaders(call.accessToken) },
    versionResponseMaximum(recovery),
    [submission],
  );
  if (response.status !== 200) rejectStatus(response.status, response.value, 'version_verify', [submission]);
  const result = successResult(response.value);
  if (!await exactVersionResult(result, recovery, submission.versionId, requireModuleContent)) {
    fail('provider_mismatch', 'version_verify', 'submitted', [submission]);
  }
  return submission;
}

/** Validate the exact provider version. Returned module bytes are optional, but exact when present. */
export async function verifyUninstallWorkerVersionSubmission(
  recovery: UninstallWorkerVersionRecoveryRecord,
  submission: UninstallWorkerVersionSubmission,
  callInput: CloudflareDirectUploadCall,
): Promise<UninstallWorkerVersionSubmission> {
  return verifyUninstallWorkerVersionSubmissionWithMode(recovery, submission, callInput, false);
}

function parseVersionListPage(
  value: unknown,
  expectedPage: number,
): { readonly items: readonly unknown[]; readonly totalCount: number; readonly totalPages: number } | null {
  if (!isRecord(value) || !exactKeys(value, ['errors', 'messages', 'result', 'result_info', 'success']) ||
    value.success !== true || !isEmptyProviderList(value.errors) || !isEmptyProviderList(value.messages) ||
    !Array.isArray(value.result) || !isRecord(value.result_info) ||
    // Live (2026-08-23): the version list omits total_pages entirely. When it
    // is absent the page count is derived from the totals actually reported.
    !exactKeys(value.result_info, Object.hasOwn(value.result_info, 'total_pages')
      ? ['count', 'page', 'per_page', 'total_count', 'total_pages']
      : ['count', 'page', 'per_page', 'total_count'])) return null;
  const info = value.result_info;
  if (
    info.page !== expectedPage || info.per_page !== VERSION_PAGE_SIZE || info.count !== value.result.length ||
    typeof info.count !== 'number' || !Number.isSafeInteger(info.count) || info.count < 0 ||
    info.count > VERSION_PAGE_SIZE || typeof info.total_count !== 'number' ||
    !Number.isSafeInteger(info.total_count) || info.total_count < 0 ||
    info.total_count > VERSION_PAGE_SIZE * MAX_VERSION_PAGES ||
    (info.total_pages !== undefined && (typeof info.total_pages !== 'number' ||
      !Number.isSafeInteger(info.total_pages) || info.total_pages < 0 || info.total_pages > MAX_VERSION_PAGES))
  ) return null;
  const calculated = info.total_count === 0 ? 0 : Math.ceil(info.total_count / VERSION_PAGE_SIZE);
  const totalPages = info.total_pages === undefined ? calculated : info.total_pages as number;
  if (!(
    (info.total_count === 0 && (totalPages === 0 || totalPages === 1) && expectedPage === 1) ||
    (info.total_count > 0 && totalPages === calculated)
  )) return null;
  return { items: value.result, totalCount: info.total_count, totalPages };
}

function versionListItem(value: unknown): { readonly id: string; readonly tag: string | null } | null {
  if (!isRecord(value) || typeof value.id !== 'string' || !UUID.test(value.id)) return null;
  if (Object.keys(value).some((key) => ![
    'annotations', 'assets', 'bindings', 'compatibility_date', 'compatibility_flags', 'created_on',
    'exports', 'exports_reconciliation', 'id', 'limits', 'main_module', 'modules', 'number',
    'placement', 'startup_time_ms', 'usage_model',
  ].includes(key))) return null;
  if (value.annotations === undefined) return { id: value.id, tag: null };
  if (!isRecord(value.annotations) || Object.keys(value.annotations).some(
    (key) => !['workers/message', 'workers/tag', 'workers/triggered_by'].includes(key),
  )) return null;
  const tag = value.annotations['workers/tag'];
  return tag === undefined || typeof tag === 'string' ? { id: value.id, tag: tag ?? null } : null;
}

/** Fully paginate versions and recover only one exact correlation match. */
export async function inspectUninstallWorkerVersionRecovery(
  recovery: UninstallWorkerVersionRecoveryRecord,
  callInput: CloudflareDirectUploadCall,
): Promise<UninstallWorkerVersionSubmission | null> {
  if (!await validVersionRecoveryRecord(recovery)) fail('invalid_input', 'validate', 'not_sent');
  const call = prepareCall(callInput);
  const seenIds = new Set<string>();
  const matches: string[] = [];
  let totalCount: number | null = null;
  let totalPages: number | null = null;
  let observed = 0;
  for (let page = 1; page <= MAX_VERSION_PAGES; page += 1) {
    const response = await requestJson(
      call,
      'version_recovery',
      `${CLOUDFLARE_API_ORIGIN}/client/v4/accounts/${recovery.accountId}/workers/workers/${recovery.workerId}/versions?page=${page}&per_page=${VERSION_PAGE_SIZE}`,
      { method: 'GET', headers: authHeaders(call.accessToken) },
      versionResponseMaximum(recovery),
    );
    if (response.status !== 200) rejectStatus(response.status, response.value, 'version_recovery');
    const parsed = parseVersionListPage(response.value, page);
    if (!parsed) fail('provider_mismatch', 'version_recovery', 'unknown');
    if (page === 1) {
      totalCount = parsed.totalCount;
      totalPages = parsed.totalPages;
    } else if (parsed.totalCount !== totalCount || parsed.totalPages !== totalPages) {
      fail('provider_mismatch', 'version_recovery', 'unknown');
    }
    for (const raw of parsed.items) {
      const item = versionListItem(raw);
      if (!item) fail('provider_mismatch', 'version_recovery', 'unknown');
      if (seenIds.has(item.id)) fail('recovery_ambiguous', 'version_recovery', 'unknown');
      seenIds.add(item.id);
      if (item.tag === recovery.correlationTag) matches.push(item.id);
    }
    observed += parsed.items.length;
    const last = (totalPages ?? 0) === 0 ? 1 : totalPages as number;
    if (page === last) break;
  }
  if (totalCount === null || observed !== totalCount) fail('provider_mismatch', 'version_recovery', 'unknown');
  if (matches.length === 0) return null;
  if (matches.length !== 1) fail('recovery_ambiguous', 'version_recovery', 'unknown');
  const submission = versionSubmission(recovery, matches[0]);
  return await verifyUninstallWorkerVersionSubmission(recovery, submission, callInput);
}

function deploymentSemanticCommitment(input: PrepareUninstallWorkerDeploymentInput): Record<string, unknown> {
  return {
    accountId: input.accountId,
    stage: input.stage,
    uninstallCycleId: input.uninstallCycleId,
    versionId: input.versionId,
    workerId: input.workerId,
    workerName: input.workerName,
  };
}

function deploymentCorrelationTag(stage: UninstallWorkerDeploymentStage, requestHash: string): string {
  return `ankka-un-d-${stage}-sha256:${requestHash}`;
}

/**
 * Prepare a journal-safe deployment intent. `restore_clean` uses the persisted
 * pre-uninstall clean version ID, but its correlation is unique to this exact
 * uninstall cycle rather than adopting the original installation deployment.
 */
export async function prepareUninstallWorkerDeploymentMutation(
  input: PrepareUninstallWorkerDeploymentInput,
): Promise<UninstallWorkerDeploymentMutationIntent> {
  if (
    !isRecord(input) || !exactKeys(input, [
      'accountId', 'stage', 'uninstallCycleId', 'versionId', 'workerId', 'workerName',
    ]) || !validIdentity(input) ||
    !['cleanup', 'retirement', 'restore_clean'].includes(input.stage) || !UUID.test(input.versionId)
  ) fail('invalid_input', 'validate', 'not_sent');
  const requestHash = await sha256(canonicalJson(deploymentSemanticCommitment(input)));
  const correlationTag = deploymentCorrelationTag(input.stage, requestHash);
  return Object.freeze({
    kind: 'uninstall_deployment',
    stage: input.stage,
    accountId: input.accountId,
    workerName: input.workerName,
    workerId: input.workerId,
    uninstallCycleId: input.uninstallCycleId,
    versionId: input.versionId,
    requestHash,
    correlationTag,
    body: Object.freeze({
      annotations: Object.freeze({ 'workers/message': correlationTag }),
      strategy: 'percentage',
      versions: Object.freeze([
        Object.freeze({ percentage: 100 as const, version_id: input.versionId }),
      ]) as readonly [{ readonly percentage: 100; readonly version_id: string }],
    }),
  });
}

async function validDeploymentIntent(intent: UninstallWorkerDeploymentMutationIntent): Promise<boolean> {
  if (
    !isRecord(intent) || !exactKeys(intent, [
      'accountId', 'body', 'correlationTag', 'kind', 'requestHash', 'stage', 'uninstallCycleId',
      'versionId', 'workerId', 'workerName',
    ]) || intent.kind !== 'uninstall_deployment' || !validIdentity(intent) ||
    !['cleanup', 'retirement', 'restore_clean'].includes(intent.stage) || !UUID.test(intent.versionId) ||
    !SHA256.test(intent.requestHash) ||
    intent.correlationTag !== deploymentCorrelationTag(intent.stage, intent.requestHash) ||
    !canonicalEqual(intent.body, {
      annotations: { 'workers/message': intent.correlationTag },
      strategy: 'percentage',
      versions: [{ percentage: 100, version_id: intent.versionId }],
    })
  ) return false;
  return await sha256(canonicalJson(deploymentSemanticCommitment(intent))) === intent.requestHash;
}

/** Pure, exact journal parser for a semantic deployment mutation intent. */
export async function parseUninstallWorkerDeploymentMutationIntent(
  value: unknown,
): Promise<UninstallWorkerDeploymentMutationIntent | null> {
  try {
    if (!isJournalObject(value) || !exactKeys(value, [
      'accountId', 'body', 'correlationTag', 'kind', 'requestHash', 'stage', 'uninstallCycleId',
      'versionId', 'workerId', 'workerName',
    ]) || value.kind !== 'uninstall_deployment' || !exactSubmissionIdentity(value) ||
      (value.stage !== 'cleanup' && value.stage !== 'retirement' && value.stage !== 'restore_clean') ||
      typeof value.versionId !== 'string' || !UUID.test(value.versionId) ||
      typeof value.requestHash !== 'string' || !SHA256.test(value.requestHash) ||
      value.correlationTag !== deploymentCorrelationTag(value.stage, value.requestHash) ||
      !isJournalObject(value.body) || !exactKeys(value.body, ['annotations', 'strategy', 'versions']) ||
      !isJournalObject(value.body.annotations) ||
      !exactKeys(value.body.annotations, ['workers/message']) ||
      value.body.annotations['workers/message'] !== value.correlationTag ||
      value.body.strategy !== 'percentage' || !Array.isArray(value.body.versions) ||
      value.body.versions.length !== 1 || !isJournalObject(value.body.versions[0]) ||
      !exactKeys(value.body.versions[0], ['percentage', 'version_id']) ||
      value.body.versions[0].percentage !== 100 || value.body.versions[0].version_id !== value.versionId ||
      !await validDeploymentIntent(value as unknown as UninstallWorkerDeploymentMutationIntent)
    ) return null;
    const parsed = Object.freeze({
      kind: 'uninstall_deployment',
      stage: value.stage,
      accountId: value.accountId,
      workerName: value.workerName,
      workerId: value.workerId,
      uninstallCycleId: value.uninstallCycleId,
      versionId: value.versionId,
      requestHash: value.requestHash,
      correlationTag: value.correlationTag,
      body: Object.freeze({
        annotations: Object.freeze({ 'workers/message': value.correlationTag }),
        strategy: 'percentage',
        versions: Object.freeze([Object.freeze({
          percentage: 100 as const,
          version_id: value.versionId,
        })]) as readonly [{ readonly percentage: 100; readonly version_id: string }],
      }),
    });
    return await validDeploymentIntent(parsed) ? parsed : null;
  } catch {
    return null;
  }
}

function deploymentSubmission(
  intent: UninstallWorkerDeploymentMutationIntent,
  deploymentId: string,
): UninstallWorkerDeploymentSubmission {
  return Object.freeze({
    kind: 'uninstall_worker_deployment',
    stage: intent.stage,
    accountId: intent.accountId,
    workerName: intent.workerName,
    workerId: intent.workerId,
    uninstallCycleId: intent.uninstallCycleId,
    versionId: intent.versionId,
    deploymentId,
    requestHash: intent.requestHash,
    correlationTag: intent.correlationTag,
  });
}

function validDeploymentSubmission(
  intent: UninstallWorkerDeploymentMutationIntent,
  submission: UninstallWorkerDeploymentSubmission,
): boolean {
  return isRecord(submission) && exactKeys(submission, [
    'accountId', 'correlationTag', 'deploymentId', 'kind', 'requestHash', 'stage',
    'uninstallCycleId', 'versionId', 'workerId', 'workerName',
  ]) && submission.kind === 'uninstall_worker_deployment' && submission.stage === intent.stage &&
    submission.accountId === intent.accountId && submission.workerName === intent.workerName &&
    submission.workerId === intent.workerId && submission.uninstallCycleId === intent.uninstallCycleId &&
    submission.versionId === intent.versionId && submission.requestHash === intent.requestHash &&
    submission.correlationTag === intent.correlationTag && UUID.test(submission.deploymentId);
}

export async function submitUninstallWorkerDeploymentMutation(
  intent: UninstallWorkerDeploymentMutationIntent,
  callInput: CloudflareDirectUploadCall,
): Promise<UninstallWorkerDeploymentSubmission> {
  if (!await validDeploymentIntent(intent)) fail('invalid_input', 'validate', 'not_sent');
  const call = prepareCall(callInput);
  const response = await requestJson(
    call,
    'deployment_submit',
    `${CLOUDFLARE_API_ORIGIN}/client/v4/accounts/${intent.accountId}/workers/scripts/${encodeURIComponent(intent.workerName)}/deployments`,
    { method: 'POST', headers: jsonHeaders(call.accessToken), body: JSON.stringify(intent.body) },
  );
  const deploymentId = rawResultId(response.value, UUID);
  const surfaced = deploymentId === null ? [] : [deploymentSubmission(intent, deploymentId)];
  if (![200, 201].includes(response.status)) {
    rejectStatus(response.status, response.value, 'deployment_submit', surfaced);
  }
  if (deploymentId === null) fail('provider_mismatch', 'deployment_submit', 'unknown');
  const submission = surfaced[0];
  const result = successResult(response.value);
  if (!isRecord(result) || result.id !== deploymentId) {
    fail('provider_mismatch', 'deployment_submit', 'submitted', [submission]);
  }
  return submission;
}

function deploymentAnnotations(value: unknown): Record<string, unknown> | null {
  if (!isRecord(value) || Object.keys(value).some(
    (key) => !['workers/message', 'workers/triggered_by'].includes(key),
  )) return null;
  for (const entry of Object.values(value)) {
    if (!(typeof entry === 'string' && entry.length > 0 && entry.length <= 256)) return null;
  }
  return value;
}

function validDeploymentShape(value: unknown): value is Record<string, unknown> {
  if (!isRecord(value) || Object.keys(value).some((key) => ![
    'annotations', 'author_email', 'created_on', 'id', 'source', 'strategy', 'versions',
  ].includes(key))) return false;
  if (
    typeof value.id !== 'string' || !UUID.test(value.id) || !safeIsoDate(value.created_on) ||
    value.source !== 'api' || value.strategy !== 'percentage' ||
    (value.author_email !== undefined && !(
      typeof value.author_email === 'string' && value.author_email.length > 0 && value.author_email.length <= 320
    )) ||
    (value.annotations !== undefined && deploymentAnnotations(value.annotations) === null) ||
    !Array.isArray(value.versions) || value.versions.length === 0 || value.versions.length > 100
  ) return false;
  let percentage = 0;
  const versions = new Set<string>();
  for (const version of value.versions) {
    if (
      !isRecord(version) || !exactKeys(version, ['percentage', 'version_id']) ||
      typeof version.version_id !== 'string' || !UUID.test(version.version_id) || versions.has(version.version_id) ||
      typeof version.percentage !== 'number' || !Number.isFinite(version.percentage) ||
      version.percentage <= 0 || version.percentage > 100
    ) return false;
    versions.add(version.version_id);
    percentage += version.percentage;
  }
  return percentage === 100;
}

function exactDeployment(
  value: unknown,
  intent: UninstallWorkerDeploymentMutationIntent,
  deploymentId: string,
): boolean {
  if (!validDeploymentShape(value) || value.id !== deploymentId) return false;
  const annotations = deploymentAnnotations(value.annotations);
  if (!annotations || annotations['workers/message'] !== intent.correlationTag) return false;
  return canonicalEqual(value.versions, [{ percentage: 100, version_id: intent.versionId }]);
}

export async function verifyUninstallWorkerDeploymentSubmission(
  intent: UninstallWorkerDeploymentMutationIntent,
  submission: UninstallWorkerDeploymentSubmission,
  callInput: CloudflareDirectUploadCall,
): Promise<UninstallWorkerDeploymentSubmission> {
  if (!await validDeploymentIntent(intent) || !validDeploymentSubmission(intent, submission)) {
    fail('invalid_input', 'validate', 'not_sent', [submission]);
  }
  const call = prepareCall(callInput);
  const response = await requestJson(
    call,
    'deployment_verify',
    `${CLOUDFLARE_API_ORIGIN}/client/v4/accounts/${intent.accountId}/workers/scripts/${encodeURIComponent(intent.workerName)}/deployments/${submission.deploymentId}`,
    { method: 'GET', headers: authHeaders(call.accessToken) },
    MAX_RESPONSE_BYTES,
    [submission],
  );
  if (response.status !== 200) rejectStatus(response.status, response.value, 'deployment_verify', [submission]);
  if (!exactDeployment(successResult(response.value), intent, submission.deploymentId)) {
    fail('provider_mismatch', 'deployment_verify', 'submitted', [submission]);
  }
  return submission;
}

function deploymentList(value: unknown): readonly unknown[] | null {
  const result = successResult(value);
  return isRecord(result) && exactKeys(result, ['deployments']) && Array.isArray(result.deployments) &&
    result.deployments.length <= MAX_DEPLOYMENTS ? result.deployments : null;
}

async function readDeploymentList(
  intent: UninstallWorkerDeploymentMutationIntent,
  call: PreparedCall,
  stage: 'deployment_recovery' | 'deployment_active_verify',
  submissions: readonly CloudflareUninstallWorkerLifecycleSubmission[] = [],
): Promise<readonly unknown[]> {
  const response = await requestJson(
    call,
    stage,
    `${CLOUDFLARE_API_ORIGIN}/client/v4/accounts/${intent.accountId}/workers/scripts/${encodeURIComponent(intent.workerName)}/deployments`,
    { method: 'GET', headers: authHeaders(call.accessToken) },
    2 * 1024 * 1024,
    submissions,
  );
  if (response.status !== 200) rejectStatus(response.status, response.value, stage, submissions);
  const deployments = deploymentList(response.value);
  if (!deployments) fail('provider_mismatch', stage, 'unknown', submissions);
  const seen = new Set<string>();
  for (const deployment of deployments) {
    if (!validDeploymentShape(deployment)) fail('provider_mismatch', stage, 'unknown', submissions);
    const id = String(deployment.id);
    if (seen.has(id)) fail('recovery_ambiguous', stage, 'unknown', submissions);
    seen.add(id);
  }
  return deployments;
}

export async function inspectUninstallWorkerDeploymentRecovery(
  intent: UninstallWorkerDeploymentMutationIntent,
  callInput: CloudflareDirectUploadCall,
): Promise<UninstallWorkerDeploymentSubmission | null> {
  if (!await validDeploymentIntent(intent)) fail('invalid_input', 'validate', 'not_sent');
  const call = prepareCall(callInput);
  const deployments = await readDeploymentList(intent, call, 'deployment_recovery');
  const matches = deployments.filter((deployment) => (
    deploymentAnnotations((deployment as Record<string, unknown>).annotations)?.['workers/message'] ===
      intent.correlationTag
  ));
  if (matches.length === 0) return null;
  if (matches.length !== 1) fail('recovery_ambiguous', 'deployment_recovery', 'unknown');
  const submission = deploymentSubmission(intent, String((matches[0] as Record<string, unknown>).id));
  return await verifyUninstallWorkerDeploymentSubmission(intent, submission, callInput);
}

/**
 * Exact latest-active proof for every uninstall lifecycle deployment. Cleanup
 * must be current before workers.dev is enabled; retirement must be current
 * before namespace retirement is accepted; restore_clean must be current
 * before the attempt can exit. A foreign/newer item fails closed.
 */
export async function verifyUninstallWorkerDeploymentIsActive(
  intent: UninstallWorkerDeploymentMutationIntent,
  submission: UninstallWorkerDeploymentSubmission,
  callInput: CloudflareDirectUploadCall,
): Promise<UninstallWorkerDeploymentSubmission> {
  if (
    !await validDeploymentIntent(intent) || !validDeploymentSubmission(intent, submission)
  ) fail('invalid_input', 'validate', 'not_sent', [submission]);
  const call = prepareCall(callInput);
  const deployments = await readDeploymentList(
    intent,
    call,
    'deployment_active_verify',
    [submission],
  );
  if (deployments.length === 0) {
    fail('provider_mismatch', 'deployment_active_verify', 'submitted', [submission]);
  }
  const matches = deployments.filter((deployment) => (
    deploymentAnnotations((deployment as Record<string, unknown>).annotations)?.['workers/message'] ===
      intent.correlationTag
  ));
  if (matches.length !== 1) {
    fail(
      matches.length > 1 ? 'recovery_ambiguous' : 'provider_mismatch',
      'deployment_active_verify',
      'submitted',
      [submission],
    );
  }
  if (!exactDeployment(deployments[0], intent, submission.deploymentId)) {
    fail('provider_mismatch', 'deployment_active_verify', 'submitted', [submission]);
  }
  return submission;
}

/**
 * Prove that the exact signed cleanup module and binding set are still the
 * sole actively serving deployment. The deployment/version/deployment read
 * sequence closes the edge-readiness race as far as Cloudflare's API permits;
 * callers must run it immediately before arming the credential-bearing POST.
 */
export async function proveActiveCleanupWorkerVersion(
  recovery: CleanupWorkerVersionRecoveryRecord,
  version: UninstallWorkerVersionSubmission,
  deploymentIntent: UninstallWorkerDeploymentMutationIntent,
  deployment: UninstallWorkerDeploymentSubmission,
  callInput: CloudflareDirectUploadCall,
): Promise<ActiveCleanupWorkerVersionProof> {
  if (
    recovery.stage !== 'cleanup' ||
    version.stage !== 'cleanup' ||
    deploymentIntent.stage !== 'cleanup' ||
    deployment.stage !== 'cleanup' ||
    version.versionId !== deploymentIntent.versionId ||
    version.versionId !== deployment.versionId ||
    version.accountId !== deploymentIntent.accountId ||
    version.workerName !== deploymentIntent.workerName ||
    version.workerId !== deploymentIntent.workerId ||
    version.uninstallCycleId !== deploymentIntent.uninstallCycleId
  ) fail('invalid_input', 'validate', 'not_sent', [version, deployment]);
  await verifyUninstallWorkerDeploymentIsActive(deploymentIntent, deployment, callInput);
  await verifyUninstallWorkerVersionSubmissionWithMode(recovery, version, callInput, true);
  await verifyUninstallWorkerDeploymentIsActive(deploymentIntent, deployment, callInput);
  return Object.freeze({ version, deployment });
}

/** Backward-compatible, stage-restricted name for the restore-specific call site. */
export async function verifyRestoredCleanWorkerDeploymentIsActive(
  intent: UninstallWorkerDeploymentMutationIntent,
  submission: UninstallWorkerDeploymentSubmission,
  callInput: CloudflareDirectUploadCall,
): Promise<UninstallWorkerDeploymentSubmission> {
  if (intent.stage !== 'restore_clean') fail('invalid_input', 'validate', 'not_sent', [submission]);
  return await verifyUninstallWorkerDeploymentIsActive(intent, submission, callInput);
}

export interface ProveAdminStateNamespacePresentInput {
  readonly namespace: AdminStateDurableObjectNamespaceLocator;
  readonly workerId: string;
  readonly uninstallCycleId: string;
}

export interface ProveAdminStateNamespaceRetiredInput {
  readonly namespace: AdminStateDurableObjectNamespaceLocator;
  readonly workerId: string;
  readonly uninstallCycleId: string;
  readonly retirementRecovery: RetirementWorkerVersionRecoveryRecord;
  readonly retirementSubmission: UninstallWorkerVersionSubmission;
  readonly retirementDeploymentIntent: UninstallWorkerDeploymentMutationIntent;
  readonly retirementDeploymentSubmission: UninstallWorkerDeploymentSubmission;
}

function boundedNamespaceText(value: unknown, maximum: number): value is string {
  return typeof value === 'string' && value.length > 0 && value.length <= maximum && !CONTROL_CHARACTER.test(value);
}

function validNamespaceLocator(value: unknown): value is AdminStateDurableObjectNamespaceLocator {
  return isRecord(value) && exactKeys(value, [
    'accountId', 'className', 'namespaceId', 'namespaceName', 'storage', 'workerName',
  ]) && typeof value.accountId === 'string' && ACCOUNT_ID.test(value.accountId) &&
    typeof value.namespaceId === 'string' && ACCOUNT_ID.test(value.namespaceId) &&
    boundedNamespaceText(value.namespaceName, 256) && typeof value.workerName === 'string' &&
    WORKER_NAME.test(value.workerName) && value.className === 'AdminState' && value.storage === 'sqlite';
}

/** Pure, exact journal parser for the pre-retirement namespace presence proof. */
export function parseAdminStateNamespacePresenceProof(
  value: unknown,
): AdminStateNamespacePresenceProof | null {
  try {
    if (!isJournalObject(value) || !exactKeys(value, [
      'accountId', 'accountNamespaceCount', 'className', 'kind', 'namespaceId', 'namespaceName',
      'snapshotSha256', 'storage', 'uninstallCycleId', 'workerId', 'workerName',
    ]) || value.kind !== 'admin_state_namespace_presence' || !exactSubmissionIdentity(value) ||
      typeof value.namespaceId !== 'string' || !ACCOUNT_ID.test(value.namespaceId) ||
      !boundedNamespaceText(value.namespaceName, 256) || value.className !== 'AdminState' ||
      value.storage !== 'sqlite' || typeof value.accountNamespaceCount !== 'number' ||
      !Number.isSafeInteger(value.accountNamespaceCount) || value.accountNamespaceCount <= 0 ||
      value.accountNamespaceCount > MAX_NAMESPACE_COUNT ||
      typeof value.snapshotSha256 !== 'string' || !SHA256.test(value.snapshotSha256)
    ) return null;
    return Object.freeze({
      kind: 'admin_state_namespace_presence',
      accountId: value.accountId,
      workerName: value.workerName,
      workerId: value.workerId,
      uninstallCycleId: value.uninstallCycleId,
      namespaceId: value.namespaceId,
      namespaceName: value.namespaceName,
      className: 'AdminState',
      storage: 'sqlite',
      accountNamespaceCount: value.accountNamespaceCount,
      snapshotSha256: value.snapshotSha256,
    });
  } catch {
    return null;
  }
}

export function parseAdminStateNamespaceRetirementProof(
  value: unknown,
): AdminStateNamespaceRetirementProof | null {
  try {
    if (
      !isJournalObject(value) || !exactKeys(value, [
        'accountId', 'accountNamespaceCount', 'firstSnapshotSha256', 'kind', 'namespaceId',
        'retirementVersionId', 'secondSnapshotSha256', 'uninstallCycleId', 'workerId', 'workerName',
      ]) || value.kind !== 'admin_state_namespace_retirement' || !exactSubmissionIdentity(value) ||
      typeof value.namespaceId !== 'string' || !ACCOUNT_ID.test(value.namespaceId) ||
      typeof value.retirementVersionId !== 'string' || !UUID.test(value.retirementVersionId) ||
      typeof value.accountNamespaceCount !== 'number' || !Number.isSafeInteger(value.accountNamespaceCount) ||
      value.accountNamespaceCount < 0 || value.accountNamespaceCount > MAX_NAMESPACE_COUNT ||
      typeof value.firstSnapshotSha256 !== 'string' || !SHA256.test(value.firstSnapshotSha256) ||
      typeof value.secondSnapshotSha256 !== 'string' || !SHA256.test(value.secondSnapshotSha256) ||
      value.firstSnapshotSha256 !== value.secondSnapshotSha256
    ) return null;
    return Object.freeze({
      kind: 'admin_state_namespace_retirement',
      accountId: value.accountId,
      workerName: value.workerName,
      workerId: value.workerId,
      uninstallCycleId: value.uninstallCycleId,
      namespaceId: value.namespaceId,
      retirementVersionId: value.retirementVersionId,
      accountNamespaceCount: value.accountNamespaceCount,
      firstSnapshotSha256: value.firstSnapshotSha256,
      secondSnapshotSha256: value.secondSnapshotSha256,
    });
  } catch {
    return null;
  }
}

async function validAdminStateNamespaceRetiredInput(
  input: ProveAdminStateNamespaceRetiredInput,
): Promise<boolean> {
  if (
    !isRecord(input) || !exactKeys(input, [
      'namespace', 'retirementDeploymentIntent', 'retirementDeploymentSubmission',
      'retirementRecovery', 'retirementSubmission', 'uninstallCycleId', 'workerId',
    ]) || !validNamespaceLocator(input.namespace) || typeof input.workerId !== 'string' ||
    !WORKER_ID.test(input.workerId) || typeof input.uninstallCycleId !== 'string' ||
    !UNINSTALL_CYCLE_ID.test(input.uninstallCycleId) ||
    !isRecord(input.retirementRecovery) || !isRecord(input.retirementSubmission) ||
    !isRecord(input.retirementDeploymentIntent) || !isRecord(input.retirementDeploymentSubmission) ||
    input.retirementRecovery.stage !== 'retirement' ||
    input.retirementRecovery.accountId !== input.namespace.accountId ||
    input.retirementRecovery.workerName !== input.namespace.workerName ||
    input.retirementRecovery.workerId !== input.workerId ||
    input.retirementRecovery.uninstallCycleId !== input.uninstallCycleId ||
    input.retirementDeploymentIntent.stage !== 'retirement' ||
    input.retirementDeploymentIntent.accountId !== input.namespace.accountId ||
    input.retirementDeploymentIntent.workerName !== input.namespace.workerName ||
    input.retirementDeploymentIntent.workerId !== input.workerId ||
    input.retirementDeploymentIntent.uninstallCycleId !== input.uninstallCycleId ||
    input.retirementDeploymentIntent.versionId !== input.retirementSubmission.versionId
  ) return false;
  return await validVersionRecoveryRecord(input.retirementRecovery) &&
    validVersionSubmission(input.retirementRecovery, input.retirementSubmission) &&
    await validDeploymentIntent(input.retirementDeploymentIntent) &&
    validDeploymentSubmission(input.retirementDeploymentIntent, input.retirementDeploymentSubmission);
}

async function parseAdminStateNamespaceRetiredInput(
  value: unknown,
): Promise<ProveAdminStateNamespaceRetiredInput | null> {
  try {
    if (!isRecord(value) || !await validAdminStateNamespaceRetiredInput(
      value as unknown as ProveAdminStateNamespaceRetiredInput,
    )) return null;
    const input = value as unknown as ProveAdminStateNamespaceRetiredInput;
    const retirementRecovery = await parseUninstallWorkerVersionRecoveryRecord(input.retirementRecovery);
    const retirementSubmission = parseCloudflareUninstallWorkerLifecycleSubmission(input.retirementSubmission);
    const retirementDeploymentIntent = await parseUninstallWorkerDeploymentMutationIntent(
      input.retirementDeploymentIntent,
    );
    const retirementDeploymentSubmission = parseCloudflareUninstallWorkerLifecycleSubmission(
      input.retirementDeploymentSubmission,
    );
    if (retirementRecovery?.stage !== 'retirement' ||
      retirementSubmission?.kind !== 'uninstall_worker_version' || retirementSubmission.stage !== 'retirement' ||
      retirementDeploymentIntent?.stage !== 'retirement' ||
      retirementDeploymentSubmission?.kind !== 'uninstall_worker_deployment' ||
      retirementDeploymentSubmission.stage !== 'retirement') return null;
    const parsed = Object.freeze({
      namespace: Object.freeze({
        accountId: input.namespace.accountId,
        namespaceId: input.namespace.namespaceId,
        namespaceName: input.namespace.namespaceName,
        workerName: input.namespace.workerName,
        className: 'AdminState' as const,
        storage: 'sqlite' as const,
      }),
      workerId: input.workerId,
      uninstallCycleId: input.uninstallCycleId,
      retirementRecovery,
      retirementSubmission,
      retirementDeploymentIntent,
      retirementDeploymentSubmission,
    });
    return await validAdminStateNamespaceRetiredInput(parsed) ? parsed : null;
  } catch {
    return null;
  }
}

async function adminStateNamespaceRetirementProofCommitment(
  input: ProveAdminStateNamespaceRetiredInput,
): Promise<string> {
  return await sha256(canonicalJson(input));
}

function retirementProofMatchesInput(
  proof: AdminStateNamespaceRetirementProof,
  input: ProveAdminStateNamespaceRetiredInput,
): boolean {
  return proof.accountId === input.namespace.accountId && proof.workerName === input.namespace.workerName &&
    proof.workerId === input.workerId && proof.uninstallCycleId === input.uninstallCycleId &&
    proof.namespaceId === input.namespace.namespaceId &&
    proof.retirementVersionId === input.retirementSubmission.versionId;
}

function parseNamespacePage(
  value: unknown,
  expectedPage: number,
): {
  readonly items: readonly DurableObjectNamespaceItem[];
  readonly totalCount: number;
  readonly totalPages: number;
} | null {
  if (!isRecord(value) || !exactKeys(value, ['errors', 'messages', 'result', 'result_info', 'success']) ||
    value.success !== true || !isEmptyProviderList(value.errors) || !isEmptyProviderList(value.messages) ||
    !Array.isArray(value.result) || !isRecord(value.result_info) ||
    // Live (2026-08-23): the namespace list omits total_pages entirely. When it
    // is absent the page count is derived from the totals actually reported.
    !exactKeys(value.result_info, Object.hasOwn(value.result_info, 'total_pages')
      ? ['count', 'page', 'per_page', 'total_count', 'total_pages']
      : ['count', 'page', 'per_page', 'total_count'])) return null;
  const info = value.result_info;
  if (
    info.page !== expectedPage || info.per_page !== NAMESPACE_PAGE_SIZE || info.count !== value.result.length ||
    typeof info.count !== 'number' || !Number.isSafeInteger(info.count) || info.count < 0 ||
    info.count > NAMESPACE_PAGE_SIZE || typeof info.total_count !== 'number' ||
    !Number.isSafeInteger(info.total_count) || info.total_count < 0 || info.total_count > MAX_NAMESPACE_COUNT ||
    (info.total_pages !== undefined && (typeof info.total_pages !== 'number' ||
      !Number.isSafeInteger(info.total_pages) ||
      info.total_pages < 0 || info.total_pages > MAX_NAMESPACE_PAGES))
  ) return null;
  const calculated = info.total_count === 0 ? 0 : Math.ceil(info.total_count / NAMESPACE_PAGE_SIZE);
  const totalPages = info.total_pages === undefined ? calculated : info.total_pages as number;
  if (!(
    (info.total_count === 0 && (totalPages === 0 || totalPages === 1) && expectedPage === 1) ||
    (info.total_count > 0 && totalPages === calculated)
  )) return null;
  const items: DurableObjectNamespaceItem[] = [];
  for (const item of value.result) {
    if (!isRecord(item) || !exactKeys(item, ['class', 'id', 'name', 'script', 'use_sqlite']) ||
      typeof item.id !== 'string' || !ACCOUNT_ID.test(item.id) || !boundedNamespaceText(item.class, 128) ||
      !boundedNamespaceText(item.name, 256) || !boundedNamespaceText(item.script, 128) ||
      typeof item.use_sqlite !== 'boolean') return null;
    items.push(Object.freeze({
      id: item.id,
      className: item.class,
      name: item.name,
      script: item.script,
      useSqlite: item.use_sqlite,
    }));
  }
  return { items: Object.freeze(items), totalCount: info.total_count, totalPages };
}

async function readNamespaceSnapshot(
  accountId: string,
  call: PreparedCall,
  stage: 'namespace_present' | 'namespace_absent',
): Promise<DurableObjectNamespaceSnapshot> {
  const seenIds = new Set<string>();
  const items: DurableObjectNamespaceItem[] = [];
  let totalCount: number | null = null;
  let totalPages: number | null = null;
  for (let page = 1; page <= MAX_NAMESPACE_PAGES; page += 1) {
    const response = await requestJson(
      call,
      stage,
      `${CLOUDFLARE_API_ORIGIN}/client/v4/accounts/${accountId}/workers/durable_objects/namespaces?page=${page}&per_page=${NAMESPACE_PAGE_SIZE}`,
      { method: 'GET', headers: authHeaders(call.accessToken) },
      MAX_NAMESPACE_RESPONSE_BYTES,
    );
    if (response.status !== 200) rejectStatus(response.status, response.value, stage);
    const parsed = parseNamespacePage(response.value, page);
    if (!parsed) fail('provider_mismatch', stage, 'unknown');
    if (page === 1) {
      totalCount = parsed.totalCount;
      totalPages = parsed.totalPages;
    } else if (parsed.totalCount !== totalCount || parsed.totalPages !== totalPages) {
      fail('provider_mismatch', stage, 'unknown');
    }
    for (const item of parsed.items) {
      if (seenIds.has(item.id)) fail('recovery_ambiguous', stage, 'unknown');
      seenIds.add(item.id);
      items.push(item);
    }
    const lastPage = (totalPages ?? 0) === 0 ? 1 : totalPages as number;
    if (page === lastPage) break;
  }
  if (totalCount === null || items.length !== totalCount) fail('provider_mismatch', stage, 'unknown');
  items.sort((left, right) => lexicalCompare(left.id, right.id));
  const frozenItems = Object.freeze(items.map((item) => Object.freeze({ ...item })));
  return Object.freeze({ items: frozenItems, sha256: await sha256(canonicalJson(frozenItems)) });
}

/** Full-account, exact ownership proof required before creating retirement. */
export async function provePersistedAdminStateNamespacePresent(
  input: ProveAdminStateNamespacePresentInput,
  callInput: CloudflareDirectUploadCall,
): Promise<AdminStateNamespacePresenceProof> {
  if (
    !isRecord(input) || !exactKeys(input, ['namespace', 'uninstallCycleId', 'workerId']) ||
    !validNamespaceLocator(input.namespace) || !WORKER_ID.test(input.workerId) ||
    !UNINSTALL_CYCLE_ID.test(input.uninstallCycleId)
  ) fail('invalid_input', 'validate', 'not_sent');
  const call = prepareCall(callInput);
  const snapshot = await readNamespaceSnapshot(input.namespace.accountId, call, 'namespace_present');
  const identityMatches = snapshot.items.filter((item) => (
    item.script === input.namespace.workerName && item.className === 'AdminState'
  ));
  if (identityMatches.length !== 1) {
    fail(identityMatches.length > 1 ? 'recovery_ambiguous' : 'provider_mismatch', 'namespace_present', 'unknown');
  }
  const match = identityMatches[0];
  if (
    match.id !== input.namespace.namespaceId || match.name !== input.namespace.namespaceName || !match.useSqlite
  ) fail('provider_mismatch', 'namespace_present', 'unknown');
  return Object.freeze({
    kind: 'admin_state_namespace_presence',
    accountId: input.namespace.accountId,
    workerName: input.namespace.workerName,
    workerId: input.workerId,
    uninstallCycleId: input.uninstallCycleId,
    namespaceId: input.namespace.namespaceId,
    namespaceName: input.namespace.namespaceName,
    className: 'AdminState',
    storage: 'sqlite',
    accountNamespaceCount: snapshot.items.length,
    snapshotSha256: snapshot.sha256,
  });
}

/**
 * Prove the first retirement version deleted the declarative class, then prove
 * two complete, byte-stable account namespace catalogues contain neither the
 * persisted namespace ID nor another AdminState namespace for this script.
 */
export async function proveAdminStateNamespaceRetired(
  input: ProveAdminStateNamespaceRetiredInput,
  callInput: CloudflareDirectUploadCall,
): Promise<AdminStateNamespaceRetirementProof> {
  const parsedInput = await parseAdminStateNamespaceRetiredInput(input);
  if (!parsedInput) fail('invalid_input', 'validate', 'not_sent');
  input = parsedInput;
  const call = prepareCall(callInput);
  await verifyUninstallWorkerDeploymentIsActive(
    input.retirementDeploymentIntent,
    input.retirementDeploymentSubmission,
    call,
  );
  await verifyUninstallWorkerVersionSubmission(
    input.retirementRecovery,
    input.retirementSubmission,
    call,
  );
  const first = await readNamespaceSnapshot(input.namespace.accountId, call, 'namespace_absent');
  const second = await readNamespaceSnapshot(input.namespace.accountId, call, 'namespace_absent');
  const hasResidue = (snapshot: DurableObjectNamespaceSnapshot): boolean => snapshot.items.some((item) => (
    item.id === input.namespace.namespaceId ||
    (item.script === input.namespace.workerName && item.className === 'AdminState')
  ));
  if (hasResidue(first) || hasResidue(second) || first.sha256 !== second.sha256 ||
    !canonicalEqual(first.items, second.items)) {
    fail('provider_mismatch', 'namespace_absent', 'unknown', [input.retirementSubmission]);
  }
  return Object.freeze({
    kind: 'admin_state_namespace_retirement',
    accountId: input.namespace.accountId,
    workerName: input.namespace.workerName,
    workerId: input.workerId,
    uninstallCycleId: input.uninstallCycleId,
    namespaceId: input.namespace.namespaceId,
    retirementVersionId: input.retirementSubmission.versionId,
    accountNamespaceCount: first.items.length,
    firstSnapshotSha256: first.sha256,
    secondSnapshotSha256: second.sha256,
  });
}

function workerDeleteSemanticCommitment(input: WorkerDeleteMutationIntent): Record<string, unknown> {
  return {
    accountId: input.accountId,
    force: 'omitted',
    method: 'DELETE',
    namespaceId: input.namespaceId,
    retirementProof: input.retirementProof,
    retirementProofCommitment: input.retirementProofCommitment,
    retirementVersionId: input.retirementVersionId,
    uninstallCycleId: input.uninstallCycleId,
    workerId: input.workerId,
    workerName: input.workerName,
  };
}

export async function prepareWorkerDeleteMutation(
  input: PrepareWorkerDeleteInput,
  callInput: CloudflareDirectUploadCall,
): Promise<WorkerDeleteMutationIntent> {
  const parsedInput = await parseAdminStateNamespaceRetiredInput(input);
  if (!parsedInput) fail('invalid_input', 'validate', 'not_sent');
  input = parsedInput;
  const proved = parseAdminStateNamespaceRetirementProof(
    await proveAdminStateNamespaceRetired(input, callInput),
  );
  if (!proved || !retirementProofMatchesInput(proved, input)) {
    fail('provider_mismatch', 'namespace_absent', 'unknown', [input.retirementSubmission]);
  }
  const retirementProofCommitment = await adminStateNamespaceRetirementProofCommitment(input);
  const base = {
    kind: 'uninstall_worker_delete_intent',
    accountId: input.namespace.accountId,
    workerName: input.namespace.workerName,
    workerId: input.workerId,
    uninstallCycleId: input.uninstallCycleId,
    namespaceId: input.namespace.namespaceId,
    retirementVersionId: input.retirementSubmission.versionId,
    retirementProofCommitment,
    retirementProof: proved,
    requestHash: '0'.repeat(64),
    correlationTag: '',
    method: 'DELETE',
    force: 'omitted',
  } as const;
  const requestHash = await sha256(canonicalJson(workerDeleteSemanticCommitment(base)));
  return Object.freeze({
    ...base,
    requestHash,
    correlationTag: `ankka-un-w-delete-sha256:${requestHash}`,
  });
}

export async function parseWorkerDeleteMutationIntent(
  value: unknown,
): Promise<WorkerDeleteMutationIntent | null> {
  try {
    if (!isJournalObject(value) || !exactKeys(value, [
      'accountId', 'correlationTag', 'force', 'kind', 'method', 'namespaceId', 'requestHash',
      'retirementProof', 'retirementProofCommitment', 'retirementVersionId', 'uninstallCycleId',
      'workerId', 'workerName',
    ]) || value.kind !== 'uninstall_worker_delete_intent' || !exactSubmissionIdentity(value) ||
      typeof value.namespaceId !== 'string' || !ACCOUNT_ID.test(value.namespaceId) ||
      typeof value.retirementVersionId !== 'string' || !UUID.test(value.retirementVersionId) ||
      typeof value.retirementProofCommitment !== 'string' || !SHA256.test(value.retirementProofCommitment) ||
      typeof value.requestHash !== 'string' || !SHA256.test(value.requestHash) ||
      value.correlationTag !== `ankka-un-w-delete-sha256:${value.requestHash}` ||
      value.method !== 'DELETE' || value.force !== 'omitted') return null;
    const retirementProof = parseAdminStateNamespaceRetirementProof(value.retirementProof);
    if (!retirementProof || retirementProof.accountId !== value.accountId ||
      retirementProof.workerName !== value.workerName || retirementProof.workerId !== value.workerId ||
      retirementProof.uninstallCycleId !== value.uninstallCycleId ||
      retirementProof.namespaceId !== value.namespaceId ||
      retirementProof.retirementVersionId !== value.retirementVersionId) return null;
    const parsed = Object.freeze({
      kind: 'uninstall_worker_delete_intent' as const,
      accountId: value.accountId,
      workerName: value.workerName,
      workerId: value.workerId,
      uninstallCycleId: value.uninstallCycleId,
      namespaceId: value.namespaceId,
      retirementVersionId: value.retirementVersionId,
      retirementProofCommitment: value.retirementProofCommitment,
      retirementProof,
      requestHash: value.requestHash,
      correlationTag: value.correlationTag,
      method: 'DELETE' as const,
      force: 'omitted' as const,
    });
    return await sha256(canonicalJson(workerDeleteSemanticCommitment(parsed))) === parsed.requestHash
      ? parsed
      : null;
  } catch {
    return null;
  }
}

function workerDeleteSubmission(intent: WorkerDeleteMutationIntent): WorkerDeleteSubmission {
  return Object.freeze({
    kind: 'uninstall_worker_delete',
    accountId: intent.accountId,
    workerName: intent.workerName,
    workerId: intent.workerId,
    uninstallCycleId: intent.uninstallCycleId,
    namespaceId: intent.namespaceId,
    retirementVersionId: intent.retirementVersionId,
    retirementProofCommitment: intent.retirementProofCommitment,
    requestHash: intent.requestHash,
    correlationTag: intent.correlationTag,
  });
}

async function requestDelete(
  call: PreparedCall,
  intent: WorkerDeleteMutationIntent,
): Promise<{ readonly status: number; readonly value: unknown | undefined }> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), call.timeoutMs);
  try {
    const url = `${CLOUDFLARE_API_ORIGIN}/client/v4/accounts/${intent.accountId}/workers/workers/${intent.workerId}`;
    const request = new Request(url, {
      method: 'DELETE',
      headers: authHeaders(call.accessToken),
      signal: controller.signal,
    });
    // `force` is intentionally absent from both the URL and RequestInit.
    if (new URL(request.url).search !== '' || request.body !== null) {
      fail('invalid_input', 'validate', 'not_sent');
    }
    const response = await call.transport(request);
    if (response.status === 204) {
      if (response.body) await response.body.cancel();
      return { status: 204, value: undefined };
    }
    return { status: response.status, value: await readBoundedJson(response) };
  } catch (error) {
    if (error instanceof CloudflareUninstallWorkerLifecycleError) throw error;
    fail('provider_unknown', 'worker_delete', 'unknown');
  } finally {
    clearTimeout(timeout);
  }
}

/**
 * The outer durable journal must CAS this mutation to its submitting state.
 * This module has no process-local replay lock. After an unknown outcome,
 * recoverWorkerDeletionOutcome is read-only and must replace any replay.
 */
export async function submitWorkerDeleteMutation(
  intent: WorkerDeleteMutationIntent,
  retirementProofInput: ProveAdminStateNamespaceRetiredInput,
  callInput: CloudflareDirectUploadCall,
): Promise<WorkerDeleteSubmission> {
  const parsedIntent = await parseWorkerDeleteMutationIntent(intent);
  const parsedProofInput = await parseAdminStateNamespaceRetiredInput(retirementProofInput);
  if (!parsedIntent || !parsedProofInput) {
    fail('invalid_input', 'validate', 'not_sent');
  }
  retirementProofInput = parsedProofInput;
  const commitment = await adminStateNamespaceRetirementProofCommitment(retirementProofInput);
  if (commitment !== parsedIntent.retirementProofCommitment ||
    !retirementProofMatchesInput(parsedIntent.retirementProof, retirementProofInput)) {
    fail('invalid_input', 'validate', 'not_sent');
  }
  const call = prepareCall(callInput);
  const freshProof = parseAdminStateNamespaceRetirementProof(
    await proveAdminStateNamespaceRetired(retirementProofInput, call),
  );
  if (!freshProof || !canonicalEqual(freshProof, parsedIntent.retirementProof)) {
    fail('provider_mismatch', 'namespace_absent', 'unknown', [retirementProofInput.retirementSubmission]);
  }
  const response = await requestDelete(call, parsedIntent);
  const submission = workerDeleteSubmission(parsedIntent);
  if (![200, 202, 204].includes(response.status)) {
    if (response.value === undefined) fail('provider_unknown', 'worker_delete', 'unknown');
    rejectStatus(response.status, response.value, 'worker_delete');
  }
  if (response.status !== 204) {
    const envelope = parseEnvelope(response.value);
    if (!envelope || !envelope.success || !isEmptyProviderList(envelope.errors) ||
      !isEmptyProviderList(envelope.messages)) {
      fail('provider_mismatch', 'worker_delete', 'submitted', [submission]);
    }
    const result = envelope.result;
    if (!(result === null || (isRecord(result) && (
      exactKeys(result, []) || (exactKeys(result, ['id']) && result.id === parsedIntent.workerId)
    )))) {
      fail('provider_mismatch', 'worker_delete', 'submitted', [submission]);
    }
  }
  return submission;
}

async function requestAbsenceStatus(
  call: PreparedCall,
  url: string,
): Promise<{ readonly status: number; readonly value?: unknown }> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), call.timeoutMs);
  try {
    const response = await call.transport(new Request(url, {
      method: 'GET',
      headers: authHeaders(call.accessToken),
      signal: controller.signal,
    }));
    if (response.status >= 200 && response.status < 300) {
      if (response.body) await response.body.cancel();
      return { status: response.status };
    }
    return { status: response.status, value: await readBoundedJson(response) };
  } catch {
    fail('provider_unknown', 'worker_delete_recovery', 'unknown');
  } finally {
    clearTimeout(timeout);
  }
}

interface ScriptListPage {
  readonly ids: readonly string[];
  readonly pagination: null | {
    readonly totalCount: number;
    readonly totalPages: number;
  };
}

function parseScriptListPage(value: unknown, expectedPage: number): ScriptListPage | null {
  if (!isRecord(value)) return null;
  const allowedEnvelopeKeys = new Set(['errors', 'messages', 'result', 'result_info', 'success']);
  if (Object.keys(value).some((key) => !allowedEnvelopeKeys.has(key)) ||
    value.success !== true || !isEmptyProviderList(value.errors) || !isEmptyProviderList(value.messages) ||
    !Array.isArray(value.result) || value.result.length > MAX_SCRIPTS) return null;
  const ids: string[] = [];
  const seen = new Set<string>();
  for (const script of value.result) {
    if (!isRecord(script) || typeof script.id !== 'string' || !WORKER_NAME.test(script.id) || seen.has(script.id)) {
      return null;
    }
    seen.add(script.id);
    ids.push(script.id);
  }
  ids.sort(lexicalCompare);
  if (value.result_info === undefined || value.result_info === null) {
    return expectedPage === 1 ? Object.freeze({ ids: Object.freeze(ids), pagination: null }) : null;
  }
  if (!isRecord(value.result_info) || !exactKeys(value.result_info, [
    'count', 'page', 'per_page', 'total_count', 'total_pages',
  ])) return null;
  const info = value.result_info;
  if (
    ids.length > SCRIPT_PAGE_SIZE ||
    info.page !== expectedPage || info.per_page !== SCRIPT_PAGE_SIZE || info.count !== ids.length ||
    typeof info.count !== 'number' || !Number.isSafeInteger(info.count) || info.count < 0 ||
    typeof info.total_count !== 'number' || !Number.isSafeInteger(info.total_count) ||
    info.total_count < 0 || info.total_count > MAX_SCRIPTS ||
    typeof info.total_pages !== 'number' || !Number.isSafeInteger(info.total_pages) ||
    info.total_pages < 0 || info.total_pages > MAX_SCRIPT_PAGES
  ) return null;
  const calculated = info.total_count === 0 ? 0 : Math.ceil(info.total_count / SCRIPT_PAGE_SIZE);
  if (!(
    (info.total_count === 0 && (info.total_pages === 0 || info.total_pages === 1) && expectedPage === 1) ||
    (info.total_count > 0 && info.total_pages === calculated)
  )) return null;
  return Object.freeze({
    ids: Object.freeze(ids),
    pagination: Object.freeze({ totalCount: info.total_count, totalPages: info.total_pages }),
  });
}

async function readFullScriptList(
  intent: WorkerDeleteMutationIntent,
  call: PreparedCall,
): Promise<readonly string[]> {
  const ids: string[] = [];
  const seen = new Set<string>();
  let totalCount: number | null = null;
  let totalPages: number | null = null;
  for (let page = 1; page <= MAX_SCRIPT_PAGES; page += 1) {
    const list = await requestJson(
      call,
      'worker_delete_recovery',
      `${CLOUDFLARE_API_ORIGIN}/client/v4/accounts/${intent.accountId}/workers/scripts?page=${page}&per_page=${SCRIPT_PAGE_SIZE}`,
      { method: 'GET', headers: authHeaders(call.accessToken) },
      4 * 1024 * 1024,
    );
    if (list.status !== 200) rejectStatus(list.status, list.value, 'worker_delete_recovery');
    const parsed = parseScriptListPage(list.value, page);
    if (!parsed) fail('provider_mismatch', 'worker_delete_recovery', 'unknown');
    if (parsed.pagination === null) {
      if (page !== 1) fail('provider_mismatch', 'worker_delete_recovery', 'unknown');
      for (const id of parsed.ids) {
        if (seen.has(id)) fail('recovery_ambiguous', 'worker_delete_recovery', 'unknown');
        seen.add(id);
        ids.push(id);
      }
      totalCount = ids.length;
      totalPages = 1;
      break;
    }
    if (page === 1) {
      totalCount = parsed.pagination.totalCount;
      totalPages = parsed.pagination.totalPages;
    } else if (
      parsed.pagination.totalCount !== totalCount || parsed.pagination.totalPages !== totalPages
    ) fail('provider_mismatch', 'worker_delete_recovery', 'unknown');
    const remaining = (totalCount as number) - ids.length;
    const expectedCount = Math.max(0, Math.min(SCRIPT_PAGE_SIZE, remaining));
    if (parsed.ids.length !== expectedCount) fail('provider_mismatch', 'worker_delete_recovery', 'unknown');
    for (const id of parsed.ids) {
      if (seen.has(id)) fail('recovery_ambiguous', 'worker_delete_recovery', 'unknown');
      seen.add(id);
      ids.push(id);
    }
    const lastPage = (totalPages ?? 0) === 0 ? 1 : totalPages as number;
    if (page === lastPage) break;
  }
  if (totalCount === null || totalPages === null || ids.length !== totalCount) {
    fail('provider_mismatch', 'worker_delete_recovery', 'unknown');
  }
  ids.sort(lexicalCompare);
  return Object.freeze(ids);
}

async function proveOneWorkerAbsenceObservation(
  intent: WorkerDeleteMutationIntent,
  call: PreparedCall,
): Promise<{ readonly scriptIds: readonly string[]; readonly sha256: string }> {
  const beta = await requestAbsenceStatus(
    call,
    `${CLOUDFLARE_API_ORIGIN}/client/v4/accounts/${intent.accountId}/workers/workers/${intent.workerId}`,
  );
  if (beta.status !== 404) {
    if (beta.status >= 200 && beta.status < 300) {
      fail('deletion_not_proven', 'worker_delete_recovery', 'unknown');
    }
    rejectStatus(beta.status, beta.value, 'worker_delete_recovery');
  }
  if (!absentEnvelope(beta.value)) fail('provider_mismatch', 'worker_delete_recovery', 'unknown');

  const script = await requestAbsenceStatus(
    call,
    `${CLOUDFLARE_API_ORIGIN}/client/v4/accounts/${intent.accountId}/workers/scripts/${encodeURIComponent(intent.workerName)}`,
  );
  if (script.status !== 404) {
    if (script.status >= 200 && script.status < 300) {
      fail('deletion_not_proven', 'worker_delete_recovery', 'unknown');
    }
    rejectStatus(script.status, script.value, 'worker_delete_recovery');
  }
  if (!absentEnvelope(script.value)) fail('provider_mismatch', 'worker_delete_recovery', 'unknown');

  const scriptIds = await readFullScriptList(intent, call);
  if (scriptIds.includes(intent.workerName)) fail('deletion_not_proven', 'worker_delete_recovery', 'unknown');
  return Object.freeze({ scriptIds, sha256: await sha256(canonicalJson(scriptIds)) });
}

/** Pure, exact journal parser for the namespace-bound Worker absence proof. */
export function parseWorkerDeletionRecoveryProof(
  value: unknown,
): WorkerDeletionRecoveryProof | null {
  try {
    if (!isJournalObject(value) || !exactKeys(value, [
      'accountId', 'firstScriptListSha256', 'kind', 'namespaceId', 'requestHash',
      'retirementProofCommitment', 'retirementVersionId', 'scriptCount', 'secondScriptListSha256',
      'uninstallCycleId', 'workerId', 'workerName',
    ]) || value.kind !== 'uninstall_worker_deletion_proof' || !exactSubmissionIdentity(value) ||
      typeof value.namespaceId !== 'string' || !ACCOUNT_ID.test(value.namespaceId) ||
      typeof value.retirementVersionId !== 'string' || !UUID.test(value.retirementVersionId) ||
      typeof value.retirementProofCommitment !== 'string' || !SHA256.test(value.retirementProofCommitment) ||
      typeof value.requestHash !== 'string' || !SHA256.test(value.requestHash) ||
      typeof value.firstScriptListSha256 !== 'string' || !SHA256.test(value.firstScriptListSha256) ||
      typeof value.secondScriptListSha256 !== 'string' || !SHA256.test(value.secondScriptListSha256) ||
      value.firstScriptListSha256 !== value.secondScriptListSha256 ||
      typeof value.scriptCount !== 'number' || !Number.isSafeInteger(value.scriptCount) ||
      value.scriptCount < 0 || value.scriptCount > MAX_SCRIPTS
    ) return null;
    return Object.freeze({
      kind: 'uninstall_worker_deletion_proof',
      accountId: value.accountId,
      workerName: value.workerName,
      workerId: value.workerId,
      uninstallCycleId: value.uninstallCycleId,
      namespaceId: value.namespaceId,
      retirementVersionId: value.retirementVersionId,
      retirementProofCommitment: value.retirementProofCommitment,
      requestHash: value.requestHash,
      firstScriptListSha256: value.firstScriptListSha256,
      secondScriptListSha256: value.secondScriptListSha256,
      scriptCount: value.scriptCount,
    });
  } catch {
    return null;
  }
}

/** Pure aggregate parser for every credential-free lifecycle journal kind. */
export async function parseCloudflareUninstallWorkerLifecycleJournalRecord(
  value: unknown,
): Promise<CloudflareUninstallWorkerLifecycleJournalRecord | null> {
  try {
    if (!isJournalObject(value) || typeof value.kind !== 'string') return null;
    switch (value.kind) {
      case 'uninstall_version_recovery':
        return await parseUninstallWorkerVersionRecoveryRecord(value);
      case 'uninstall_worker_version':
      case 'uninstall_worker_deployment':
      case 'uninstall_worker_delete':
        return parseCloudflareUninstallWorkerLifecycleSubmission(value);
      case 'uninstall_deployment':
        return await parseUninstallWorkerDeploymentMutationIntent(value);
      case 'admin_state_namespace_presence':
        return parseAdminStateNamespacePresenceProof(value);
      case 'admin_state_namespace_retirement':
        return parseAdminStateNamespaceRetirementProof(value);
      case 'uninstall_worker_delete_intent':
        return await parseWorkerDeleteMutationIntent(value);
      case 'uninstall_worker_deletion_proof':
        return parseWorkerDeletionRecoveryProof(value);
      default:
        return null;
    }
  } catch {
    return null;
  }
}

/**
 * Outcome-unknown recovery. This never replays DELETE and never adopts a
 * same-named Worker: exact beta-ID absence and same-name Script GET/list
 * absence must hold across two identical full list observations.
 */
export async function recoverWorkerDeletionOutcome(
  intent: WorkerDeleteMutationIntent,
  callInput: CloudflareDirectUploadCall,
): Promise<WorkerDeletionRecoveryProof> {
  const parsedIntent = await parseWorkerDeleteMutationIntent(intent);
  if (!parsedIntent) fail('invalid_input', 'validate', 'not_sent');
  const call = prepareCall(callInput);
  const first = await proveOneWorkerAbsenceObservation(parsedIntent, call);
  const second = await proveOneWorkerAbsenceObservation(parsedIntent, call);
  if (first.sha256 !== second.sha256 || !canonicalEqual(first.scriptIds, second.scriptIds)) {
    fail('deletion_not_proven', 'worker_delete_recovery', 'unknown');
  }
  return Object.freeze({
    kind: 'uninstall_worker_deletion_proof',
    accountId: parsedIntent.accountId,
    workerName: parsedIntent.workerName,
    workerId: parsedIntent.workerId,
    uninstallCycleId: parsedIntent.uninstallCycleId,
    namespaceId: parsedIntent.namespaceId,
    retirementVersionId: parsedIntent.retirementVersionId,
    retirementProofCommitment: parsedIntent.retirementProofCommitment,
    requestHash: parsedIntent.requestHash,
    firstScriptListSha256: first.sha256,
    secondScriptListSha256: second.sha256,
    scriptCount: first.scriptIds.length,
  });
}

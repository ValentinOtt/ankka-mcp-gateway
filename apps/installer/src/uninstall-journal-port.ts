import { DeployError, isDeployErrorCode } from './errors';
import { assertSecretFree } from './schema';
import {
  requireUninstallJournal,
  type AcquireUninstallJournalLeaseInput,
  type AppendCustomerGatewayRemoveAttemptInput,
  type AppendUninstallManagementDeleteAttemptInput,
  type AppendUninstallManagementPreflightInput,
  type AppendUninstallJournalApprovalInput,
  type CreateUninstallJournalApprovalInput,
  type CreateUninstallJournalInput,
  type PrepareUninstallJournalActionInput,
  type RecordUninstallManagementDeleteRecoveryInput,
  type TransitionUninstallJournalActionInput,
  type UninstallJournal,
  type UninstallJournalCasInput,
} from './uninstall-journal';

const INTERNAL_ORIGIN = 'https://gateway-deploy-session.internal';
const MAX_INTERNAL_RESPONSE_BYTES = 4 * 1024 * 1024;

export interface UninstallJournalFetcher {
  fetch(request: Request): Promise<Response>;
}

export interface InitializeUninstallJournalPortInput {
  readonly initialization: CreateUninstallJournalInput;
  readonly approval: CreateUninstallJournalApprovalInput;
}

export interface AppendUninstallJournalApprovalPortInput extends AppendUninstallJournalApprovalInput {
  readonly candidatePlan: unknown;
}

export interface RefreshUninstallJournalPreflightPortInput extends UninstallJournalCasInput {
  readonly preflight: unknown;
}

export interface AttachUninstallWorkerVersionRecoveryPortInput extends UninstallJournalCasInput {
  readonly action: 'cleanup_worker_version_create' | 'retirement_worker_version_create';
  readonly recovery: unknown;
}

export type SubmitUninstallJournalActionPortInput = TransitionUninstallJournalActionInput & {
  readonly value: unknown;
};

export interface CustomerGatewayWorkersDevTransitionPortInput extends UninstallJournalCasInput {
  readonly enabled: boolean;
}

export interface CustomerGatewayWorkersDevSubmissionPortInput
  extends CustomerGatewayWorkersDevTransitionPortInput {
  readonly locator: unknown;
}

export interface CustomerGatewayRemoveRequestSubmissionPortInput extends UninstallJournalCasInput {
  readonly locator: unknown;
}

export interface UninstallJournalDiscardAcknowledgement {
  readonly discarded: true;
}

export interface UninstallJournalPort {
  initialize(input: InitializeUninstallJournalPortInput): Promise<UninstallJournal>;
  read(): Promise<UninstallJournal>;
  appendApproval(input: AppendUninstallJournalApprovalPortInput): Promise<UninstallJournal>;
  acquireLease(input: AcquireUninstallJournalLeaseInput): Promise<UninstallJournal>;
  releaseLease(input: UninstallJournalCasInput): Promise<UninstallJournal>;
  refreshPreflight(input: RefreshUninstallJournalPreflightPortInput): Promise<UninstallJournal>;
  discardPreflight(input: UninstallJournalCasInput): Promise<UninstallJournalDiscardAcknowledgement>;
  appendManagementPreflight(input: AppendUninstallManagementPreflightInput): Promise<UninstallJournal>;
  appendManagementDeleteAttempt(input: AppendUninstallManagementDeleteAttemptInput): Promise<UninstallJournal>;
  recordManagementDeleteRecovery(
    input: RecordUninstallManagementDeleteRecoveryInput,
  ): Promise<UninstallJournal>;
  prepareAction(input: PrepareUninstallJournalActionInput): Promise<UninstallJournal>;
  replacePreparedAction(input: PrepareUninstallJournalActionInput): Promise<UninstallJournal>;
  attachWorkerVersionRecovery(input: AttachUninstallWorkerVersionRecoveryPortInput): Promise<UninstallJournal>;
  armAction(input: TransitionUninstallJournalActionInput): Promise<UninstallJournal>;
  recordActionSubmitted(input: SubmitUninstallJournalActionPortInput): Promise<UninstallJournal>;
  verifyAction(input: SubmitUninstallJournalActionPortInput): Promise<UninstallJournal>;
  appendCustomerRemoveCycle(input: AppendCustomerGatewayRemoveAttemptInput): Promise<UninstallJournal>;
  replacePreparedCustomerRemoveCycle(
    input: AppendCustomerGatewayRemoveAttemptInput,
  ): Promise<UninstallJournal>;
  prepareCustomerWorkersDevDisable(input: UninstallJournalCasInput): Promise<UninstallJournal>;
  replacePreparedCustomerWorkersDevDisable(input: UninstallJournalCasInput): Promise<UninstallJournal>;
  armCustomerWorkersDev(input: CustomerGatewayWorkersDevTransitionPortInput): Promise<UninstallJournal>;
  recordCustomerWorkersDevSubmitted(
    input: CustomerGatewayWorkersDevSubmissionPortInput,
  ): Promise<UninstallJournal>;
  verifyCustomerWorkersDev(input: CustomerGatewayWorkersDevTransitionPortInput): Promise<UninstallJournal>;
  recordCustomerWorkersDevNotApplied(
    input: CustomerGatewayWorkersDevSubmissionPortInput,
  ): Promise<UninstallJournal>;
  armCustomerRemoveRequest(input: UninstallJournalCasInput): Promise<UninstallJournal>;
  recordCustomerRemoveRequestSubmitted(
    input: CustomerGatewayRemoveRequestSubmissionPortInput,
  ): Promise<UninstallJournal>;
  verifyCustomerRemoveRequest(input: UninstallJournalCasInput): Promise<UninstallJournal>;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function exactKeys(value: Record<string, unknown>, expected: readonly string[]): boolean {
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  return actual.length === wanted.length && actual.every((key, index) => key === wanted[index]);
}

function invalidInternalResponse(status = 500): never {
  throw new DeployError(status, 'session_invalid');
}

function assertResponseSecretFree(value: unknown): void {
  try {
    assertSecretFree(value);
  } catch {
    invalidInternalResponse();
  }
}

async function boundedJson(response: Response): Promise<unknown> {
  const contentType = response.headers.get('content-type')?.split(';', 1)[0]?.trim().toLowerCase() ?? '';
  if (contentType !== 'application/json') invalidInternalResponse();

  const declared = response.headers.get('content-length');
  let declaredSize: number | null = null;
  if (declared !== null) {
    if (!/^(?:0|[1-9][0-9]*)$/u.test(declared)) invalidInternalResponse();
    const size = Number(declared);
    if (!Number.isSafeInteger(size) || size > MAX_INTERNAL_RESPONSE_BYTES) invalidInternalResponse();
    declaredSize = size;
  }
  if (!response.body) invalidInternalResponse();

  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  while (true) {
    let read: ReadableStreamReadResult<Uint8Array>;
    try {
      read = await reader.read();
    } catch {
      invalidInternalResponse();
    }
    if (read.done) break;
    total += read.value.byteLength;
    if (total > MAX_INTERNAL_RESPONSE_BYTES) {
      try {
        await reader.cancel();
      } catch {
        // Cancellation is best-effort; the response is already rejected.
      }
      invalidInternalResponse();
    }
    chunks.push(read.value);
  }
  if (declaredSize !== null && total !== declaredSize) invalidInternalResponse();

  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)) as unknown;
  } catch {
    invalidInternalResponse();
  }
  assertResponseSecretFree(parsed);
  return parsed;
}

function errorFromResponse(response: Response, body: unknown): DeployError {
  if (
    isRecord(body) && exactKeys(body, ['error']) && isRecord(body.error) &&
    exactKeys(body.error, ['code']) && isDeployErrorCode(body.error.code)
  ) {
    return new DeployError(response.status, body.error.code);
  }
  return new DeployError(response.status, 'session_invalid');
}

async function journalResponse(response: Response): Promise<UninstallJournal> {
  const body = await boundedJson(response);
  if (!response.ok) throw errorFromResponse(response, body);
  if (!isRecord(body) || !exactKeys(body, ['journal'])) invalidInternalResponse();
  try {
    return await requireUninstallJournal(body.journal);
  } catch {
    invalidInternalResponse();
  }
}

async function discardResponse(response: Response): Promise<UninstallJournalDiscardAcknowledgement> {
  const body = await boundedJson(response);
  if (!response.ok) throw errorFromResponse(response, body);
  if (!isRecord(body) || !exactKeys(body, ['discarded']) || body.discarded !== true) {
    invalidInternalResponse();
  }
  return Object.freeze({ discarded: true });
}

function internalRequest(path: string, method: 'GET' | 'POST', body?: unknown): Request {
  let encoded: string | undefined;
  if (body !== undefined) {
    try {
      assertSecretFree(body);
      const candidate = JSON.stringify(body);
      if (typeof candidate !== 'string') throw new TypeError('body_not_serializable');
      // JSON serialization can invoke user-defined toJSON methods or getters.
      // Re-scan the exact bytes crossing the same-DO boundary so those hooks
      // cannot introduce a credential-shaped field after the first scan.
      assertSecretFree(JSON.parse(candidate) as unknown);
      encoded = candidate;
    } catch {
      throw new DeployError(400, 'bad_request');
    }
  }
  return new Request(new URL(path, INTERNAL_ORIGIN), {
    method,
    headers: encoded === undefined ? undefined : { 'content-type': 'application/json' },
    body: encoded,
  });
}

export function createUninstallJournalPort(fetcher: UninstallJournalFetcher): UninstallJournalPort {
  const response = async (path: string, method: 'GET' | 'POST', body?: unknown): Promise<Response> => {
    try {
      return await fetcher.fetch(internalRequest(path, method, body));
    } catch (error) {
      if (error instanceof DeployError) throw new DeployError(error.status, error.code);
      throw new DeployError(500, 'session_invalid');
    }
  };
  const journal = async (path: string, method: 'GET' | 'POST', body?: unknown): Promise<UninstallJournal> => {
    return journalResponse(await response(path, method, body));
  };

  return Object.freeze({
    initialize: (input: InitializeUninstallJournalPortInput) =>
      journal('/uninstall-journal/initialize', 'POST', input),
    read: () => journal('/uninstall-journal', 'GET'),
    appendApproval: (input: AppendUninstallJournalApprovalPortInput) =>
      journal('/uninstall-journal/approval/append', 'POST', input),
    acquireLease: (input: AcquireUninstallJournalLeaseInput) =>
      journal('/uninstall-journal/lease/acquire', 'POST', input),
    releaseLease: (input: UninstallJournalCasInput) =>
      journal('/uninstall-journal/lease/release', 'POST', input),
    refreshPreflight: (input: RefreshUninstallJournalPreflightPortInput) =>
      journal('/uninstall-journal/preflight/refresh', 'POST', input),
    discardPreflight: async (input: UninstallJournalCasInput) =>
      discardResponse(await response('/uninstall-journal/preflight/discard', 'POST', input)),
    appendManagementPreflight: (input: AppendUninstallManagementPreflightInput) =>
      journal('/uninstall-journal/management-preflight/append', 'POST', input),
    appendManagementDeleteAttempt: (input: AppendUninstallManagementDeleteAttemptInput) =>
      journal('/uninstall-journal/management-delete/attempt/append', 'POST', input),
    recordManagementDeleteRecovery: (input: RecordUninstallManagementDeleteRecoveryInput) =>
      journal('/uninstall-journal/management-delete/recovery', 'POST', input),
    prepareAction: (input: PrepareUninstallJournalActionInput) =>
      journal('/uninstall-journal/action/prepare', 'POST', input),
    replacePreparedAction: (input: PrepareUninstallJournalActionInput) =>
      journal('/uninstall-journal/action/replace', 'POST', input),
    attachWorkerVersionRecovery: (input: AttachUninstallWorkerVersionRecoveryPortInput) =>
      journal('/uninstall-journal/action/version-recovery/attach', 'POST', input),
    armAction: (input: TransitionUninstallJournalActionInput) =>
      journal('/uninstall-journal/action/arm', 'POST', input),
    recordActionSubmitted: (input: SubmitUninstallJournalActionPortInput) =>
      journal('/uninstall-journal/action/submitted', 'POST', input),
    verifyAction: (input: SubmitUninstallJournalActionPortInput) =>
      journal('/uninstall-journal/action/verified', 'POST', input),
    appendCustomerRemoveCycle: (input: AppendCustomerGatewayRemoveAttemptInput) =>
      journal('/uninstall-journal/customer-remove/cycle/append', 'POST', input),
    replacePreparedCustomerRemoveCycle: (input: AppendCustomerGatewayRemoveAttemptInput) =>
      journal('/uninstall-journal/customer-remove/cycle/replace', 'POST', input),
    prepareCustomerWorkersDevDisable: (input: UninstallJournalCasInput) =>
      journal('/uninstall-journal/customer-remove/workers-dev/disable/prepare', 'POST', input),
    replacePreparedCustomerWorkersDevDisable: (input: UninstallJournalCasInput) =>
      journal('/uninstall-journal/customer-remove/workers-dev/disable/replace', 'POST', input),
    armCustomerWorkersDev: (input: CustomerGatewayWorkersDevTransitionPortInput) =>
      journal('/uninstall-journal/customer-remove/workers-dev/arm', 'POST', input),
    recordCustomerWorkersDevSubmitted: (input: CustomerGatewayWorkersDevSubmissionPortInput) =>
      journal('/uninstall-journal/customer-remove/workers-dev/submitted', 'POST', input),
    verifyCustomerWorkersDev: (input: CustomerGatewayWorkersDevTransitionPortInput) =>
      journal('/uninstall-journal/customer-remove/workers-dev/verified', 'POST', input),
    recordCustomerWorkersDevNotApplied: (input: CustomerGatewayWorkersDevSubmissionPortInput) =>
      journal('/uninstall-journal/customer-remove/workers-dev/not-applied', 'POST', input),
    armCustomerRemoveRequest: (input: UninstallJournalCasInput) =>
      journal('/uninstall-journal/customer-remove/request/arm', 'POST', input),
    recordCustomerRemoveRequestSubmitted: (input: CustomerGatewayRemoveRequestSubmissionPortInput) =>
      journal('/uninstall-journal/customer-remove/request/submitted', 'POST', input),
    verifyCustomerRemoveRequest: (input: UninstallJournalCasInput) =>
      journal('/uninstall-journal/customer-remove/request/verified', 'POST', input),
  });
}

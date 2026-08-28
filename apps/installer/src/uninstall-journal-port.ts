import * as v from 'valibot';

import {
  boundaryValueSchema,
  type BoundaryValue,
} from './boundary';
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
const errorResponseSchema = v.strictObject({
  error: v.strictObject({ code: v.string() }),
});
const journalResponseSchema = v.strictObject({ journal: boundaryValueSchema });
const discardResponseSchema = v.strictObject({ discarded: v.literal(true) });

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

export interface UninstallJournalPort<Journal = UninstallJournal> {
  initialize(input: InitializeUninstallJournalPortInput): Promise<Journal>;
  read(): Promise<Journal>;
  appendApproval(input: AppendUninstallJournalApprovalPortInput): Promise<Journal>;
  acquireLease(input: AcquireUninstallJournalLeaseInput): Promise<Journal>;
  releaseLease(input: UninstallJournalCasInput): Promise<Journal>;
  refreshPreflight(input: RefreshUninstallJournalPreflightPortInput): Promise<Journal>;
  discardPreflight(input: UninstallJournalCasInput): Promise<UninstallJournalDiscardAcknowledgement>;
  appendManagementPreflight(input: AppendUninstallManagementPreflightInput): Promise<Journal>;
  appendManagementDeleteAttempt(input: AppendUninstallManagementDeleteAttemptInput): Promise<Journal>;
  recordManagementDeleteRecovery(
    input: RecordUninstallManagementDeleteRecoveryInput,
  ): Promise<Journal>;
  prepareAction(input: PrepareUninstallJournalActionInput): Promise<Journal>;
  replacePreparedAction(input: PrepareUninstallJournalActionInput): Promise<Journal>;
  attachWorkerVersionRecovery(input: AttachUninstallWorkerVersionRecoveryPortInput): Promise<Journal>;
  armAction(input: TransitionUninstallJournalActionInput): Promise<Journal>;
  recordActionSubmitted(input: SubmitUninstallJournalActionPortInput): Promise<Journal>;
  verifyAction(input: SubmitUninstallJournalActionPortInput): Promise<Journal>;
  appendCustomerRemoveCycle(input: AppendCustomerGatewayRemoveAttemptInput): Promise<Journal>;
  replacePreparedCustomerRemoveCycle(
    input: AppendCustomerGatewayRemoveAttemptInput,
  ): Promise<Journal>;
  prepareCustomerWorkersDevDisable(input: UninstallJournalCasInput): Promise<Journal>;
  replacePreparedCustomerWorkersDevDisable(input: UninstallJournalCasInput): Promise<Journal>;
  armCustomerWorkersDev(input: CustomerGatewayWorkersDevTransitionPortInput): Promise<Journal>;
  recordCustomerWorkersDevSubmitted(
    input: CustomerGatewayWorkersDevSubmissionPortInput,
  ): Promise<Journal>;
  verifyCustomerWorkersDev(input: CustomerGatewayWorkersDevTransitionPortInput): Promise<Journal>;
  recordCustomerWorkersDevNotApplied(
    input: CustomerGatewayWorkersDevSubmissionPortInput,
  ): Promise<Journal>;
  armCustomerRemoveRequest(input: UninstallJournalCasInput): Promise<Journal>;
  recordCustomerRemoveRequestSubmitted(
    input: CustomerGatewayRemoveRequestSubmissionPortInput,
  ): Promise<Journal>;
  verifyCustomerRemoveRequest(input: UninstallJournalCasInput): Promise<Journal>;
}

export interface UninstallJournalPortDependencies<Journal> {
  parseJournal(value: BoundaryValue): Promise<Journal>;
}

function invalidInternalResponse(status = 500): never {
  throw new DeployError(status, 'session_invalid');
}

function assertResponseSecretFree(value: BoundaryValue): void {
  try {
    assertSecretFree(value);
  } catch {
    invalidInternalResponse();
  }
}

async function boundedJson(response: Response): Promise<BoundaryValue> {
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
  let parsed: BoundaryValue;
  try {
    const result = v.safeParse(
      boundaryValueSchema,
      JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)),
    );
    if (!result.success) invalidInternalResponse();
    parsed = result.output;
  } catch {
    invalidInternalResponse();
  }
  assertResponseSecretFree(parsed);
  return parsed;
}

function errorFromResponse(response: Response, body: BoundaryValue): DeployError {
  const result = v.safeParse(errorResponseSchema, body);
  if (result.success && isDeployErrorCode(result.output.error.code)) {
    return new DeployError(response.status, result.output.error.code);
  }
  return new DeployError(response.status, 'session_invalid');
}

async function journalResponse<Journal>(
  response: Response,
  dependencies: UninstallJournalPortDependencies<Journal>,
): Promise<Journal> {
  const body = await boundedJson(response);
  if (!response.ok) throw errorFromResponse(response, body);
  const result = v.safeParse(journalResponseSchema, body);
  if (!result.success) invalidInternalResponse();
  try {
    return await dependencies.parseJournal(result.output.journal);
  } catch {
    invalidInternalResponse();
  }
}

async function discardResponse(response: Response): Promise<UninstallJournalDiscardAcknowledgement> {
  const body = await boundedJson(response);
  if (!response.ok) throw errorFromResponse(response, body);
  if (!v.safeParse(discardResponseSchema, body).success) invalidInternalResponse();
  return Object.freeze({ discarded: true });
}

function internalRequest<Body>(path: string, method: 'GET' | 'POST', body?: Body): Request {
  let encoded: string | undefined;
  if (body !== undefined) {
    try {
      assertSecretFree(body);
      const candidate = JSON.stringify(body);
      if (candidate === undefined) throw new TypeError('body_not_serializable');
      // JSON serialization can invoke user-defined toJSON methods or getters.
      // Re-scan the exact bytes crossing the same-DO boundary so those hooks
      // cannot introduce a credential-shaped field after the first scan.
      const rescanned = v.safeParse(boundaryValueSchema, JSON.parse(candidate));
      if (!rescanned.success) throw new TypeError('body_not_serializable');
      assertSecretFree(rescanned.output);
      encoded = candidate;
    } catch {
      throw new DeployError(400, 'bad_request');
    }
  }
  const requestInit: RequestInit = { method };
  if (encoded !== undefined) {
    requestInit.headers = { 'content-type': 'application/json' };
    requestInit.body = encoded;
  }
  return new Request(new URL(path, INTERNAL_ORIGIN), requestInit);
}

export function createUninstallJournalPortWithDependencies<Journal>(
  fetcher: UninstallJournalFetcher,
  dependencies: UninstallJournalPortDependencies<Journal>,
): UninstallJournalPort<Journal> {
  const response = async <Body>(
    path: string,
    method: 'GET' | 'POST',
    body?: Body,
  ): Promise<Response> => {
    try {
      return await fetcher.fetch(internalRequest(path, method, body));
    } catch (error) {
      if (error instanceof DeployError) throw new DeployError(error.status, error.code);
      throw new DeployError(500, 'session_invalid');
    }
  };
  const journal = async <Body>(
    path: string,
    method: 'GET' | 'POST',
    body?: Body,
  ): Promise<Journal> => {
    return journalResponse(await response(path, method, body), dependencies);
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

export function createUninstallJournalPort(fetcher: UninstallJournalFetcher): UninstallJournalPort {
  return createUninstallJournalPortWithDependencies(fetcher, {
    parseJournal: requireUninstallJournal,
  });
}

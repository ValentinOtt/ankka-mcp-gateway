import { DeployError, isDeployErrorCode } from './errors';
import { assertSecretFree, forbiddenStoredKeyPath } from './schema';
import {
  requireInstallJournal,
  type AcquireInstallJournalLeaseInput,
  type AppendCustomerBootstrapAttemptInput,
  type CreateInstallJournalInput,
  type InstallJournal,
  type InstallJournalCasInput,
  type PrepareInstallJournalActionInput,
  type SubmitInstallJournalActionInput,
  type TransitionInstallJournalActionInput,
} from './install-journal';

const INTERNAL_ORIGIN = 'https://gateway-deploy-session.internal';
const MAX_INTERNAL_RESPONSE_BYTES = 4 * 1024 * 1024;

export interface InstallJournalFetcher {
  fetch(request: Request): Promise<Response>;
}

export interface InstallJournalPort {
  initialize(input: CreateInstallJournalInput): Promise<InstallJournal>;
  read(): Promise<InstallJournal>;
  appendApproval(input: InstallJournalCasInput): Promise<InstallJournal>;
  acquireLease(input: AcquireInstallJournalLeaseInput): Promise<InstallJournal>;
  releaseLease(input: InstallJournalCasInput): Promise<InstallJournal>;
  prepareAction(input: PrepareInstallJournalActionInput): Promise<InstallJournal>;
  armAction(input: TransitionInstallJournalActionInput): Promise<InstallJournal>;
  recordSubmitted(input: SubmitInstallJournalActionInput): Promise<InstallJournal>;
  verifyAction(input: TransitionInstallJournalActionInput): Promise<InstallJournal>;
  appendCustomerBootstrapCycle(input: AppendCustomerBootstrapAttemptInput): Promise<InstallJournal>;
}

type InstallJournalRequestBody =
  | AcquireInstallJournalLeaseInput
  | AppendCustomerBootstrapAttemptInput
  | CreateInstallJournalInput
  | InstallJournalCasInput
  | PrepareInstallJournalActionInput
  | SubmitInstallJournalActionInput
  | TransitionInstallJournalActionInput;

function isRecord(value: BoundaryValue): value is BoundaryObject {
  return v.is(boundaryObjectSchema, value);
}

async function boundedJson(response: Response): Promise<BoundaryValue> {
  const contentType = response.headers.get('content-type')?.toLowerCase() ?? '';
  if (!contentType.startsWith('application/json')) throw new DeployError(500, 'session_invalid');
  const declared = response.headers.get('content-length');
  if (declared !== null) {
    const size = Number(declared);
    if (!Number.isSafeInteger(size) || size < 0 || size > MAX_INTERNAL_RESPONSE_BYTES) {
      throw new DeployError(500, 'session_invalid');
    }
  }
  if (!response.body) throw new DeployError(500, 'session_invalid');
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > MAX_INTERNAL_RESPONSE_BYTES) {
      await reader.cancel();
      throw new DeployError(500, 'session_invalid');
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
    return v.parse(
      boundaryValueSchema,
      JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)),
    );
  } catch {
    throw new DeployError(500, 'session_invalid');
  }
}

async function journalResponse(response: Response): Promise<InstallJournal> {
  const body = await boundedJson(response);
  if (!response.ok) {
    const code = isRecord(body) && isRecord(body.error) && isDeployErrorCode(body.error.code)
      ? body.error.code
      : 'session_invalid';
    throw new DeployError(response.status, code);
  }
  if (!isRecord(body) || Object.keys(body).length !== 1 || !Object.hasOwn(body, 'journal')) {
    throw new DeployError(500, 'session_invalid');
  }
  return requireInstallJournal(body.journal);
}

function request(
  path: string,
  method: 'GET' | 'POST',
  body?: InstallJournalRequestBody,
): Request {
  if (body !== undefined) {
    try {
      assertSecretFree(body);
    } catch {
      const keyPath = forbiddenStoredKeyPath(body);
      const reason = keyPath
        ? `journal_body_rejected_at_${keyPath}`
          .toLowerCase()
          .replace(/[^a-z0-9_]+/gu, '_')
          .replace(/^_+|_+$/gu, '')
          .slice(0, 160)
        : null;
      throw new DeployError(400, 'bad_request', reason);
    }
  }
  const init: RequestInit = { method };
  if (body !== undefined) {
    init.headers = { 'content-type': 'application/json' };
    init.body = JSON.stringify(body);
  }
  return new Request(new URL(path, INTERNAL_ORIGIN), init);
}

export function createInstallJournalPort(fetcher: InstallJournalFetcher): InstallJournalPort {
  const call = async (
    path: string,
    method: 'GET' | 'POST',
    body?: InstallJournalRequestBody,
  ): Promise<InstallJournal> => {
    return journalResponse(await fetcher.fetch(request(path, method, body)));
  };
  return Object.freeze({
    initialize: (input: CreateInstallJournalInput) => call('/install-journal/initialize', 'POST', input),
    read: () => call('/install-journal', 'GET'),
    appendApproval: (input: InstallJournalCasInput) => call('/install-journal/approval/append', 'POST', input),
    acquireLease: (input: AcquireInstallJournalLeaseInput) => call('/install-journal/lease/acquire', 'POST', input),
    releaseLease: (input: InstallJournalCasInput) => call('/install-journal/lease/release', 'POST', input),
    prepareAction: (input: PrepareInstallJournalActionInput) => call('/install-journal/action/prepare', 'POST', input),
    armAction: (input: TransitionInstallJournalActionInput) => call('/install-journal/action/arm', 'POST', input),
    recordSubmitted: (input: SubmitInstallJournalActionInput) => call('/install-journal/action/submitted', 'POST', input),
    verifyAction: (input: TransitionInstallJournalActionInput) => call('/install-journal/action/verified', 'POST', input),
    appendCustomerBootstrapCycle: (input: AppendCustomerBootstrapAttemptInput) => call(
      '/install-journal/customer-bootstrap/attempt/append',
      'POST',
      input,
    ),
  });
}
import * as v from 'valibot';

import {
  boundaryObjectSchema,
  boundaryValueSchema,
  type BoundaryObject,
  type BoundaryValue,
} from './boundary';

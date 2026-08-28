import { DeployError, isDeployErrorCode } from './errors';
import {
  requireReturningUninstallJournal,
  type ReturningUninstallActionName,
  type ReturningUninstallJournal,
} from './returning-uninstall-journal';
import type { ReturningUninstallImportedAuthority } from './returning-uninstall-authority';
import type { ReturningUninstallPlan } from './returning-uninstall-plan';
import { assertSecretFree } from './schema';

const ORIGIN = 'https://gateway-deploy-session.internal';
const MAX_BYTES = 4 * 1024 * 1024;

export interface ReturningUninstallJournalFetcher { fetch(request: Request): Promise<Response> }

interface Cas { readonly expectedRevision: number; readonly attemptId: string; readonly now: number }

export interface ReturningUninstallJournalPort {
  initialize(input: {
    readonly now: number;
    readonly plan: ReturningUninstallPlan;
    readonly authority: ReturningUninstallImportedAuthority;
    readonly attemptId: string;
    readonly approvedAt: number;
    readonly accountId: string;
    readonly zoneId: string;
    readonly recoverUntil: number;
  }): Promise<ReturningUninstallJournal>;
  read(): Promise<ReturningUninstallJournal>;
  appendApproval(input: Cas & {
    readonly approvedAt: number;
    readonly plan: ReturningUninstallPlan;
    readonly authority: ReturningUninstallImportedAuthority;
  }): Promise<ReturningUninstallJournal>;
  appendHostedRecoveryApproval(input: Cas & {
    readonly approvedAt: number;
    readonly plan: ReturningUninstallPlan;
    readonly actorEmail: string;
    readonly accountId: string;
    readonly zoneId: string;
  }): Promise<ReturningUninstallJournal>;
  acquireLease(input: Cas & { readonly expiresAt: number }): Promise<ReturningUninstallJournal>;
  releaseLease(input: Cas): Promise<ReturningUninstallJournal>;
  prepare(input: Cas & { readonly name: ReturningUninstallActionName; readonly record: unknown }): Promise<ReturningUninstallJournal>;
  arm(input: Cas & { readonly name: ReturningUninstallActionName }): Promise<ReturningUninstallJournal>;
  submit(input: Cas & { readonly name: ReturningUninstallActionName; readonly locator: unknown }): Promise<ReturningUninstallJournal>;
  verify(input: Cas & { readonly name: ReturningUninstallActionName; readonly locator: unknown }): Promise<ReturningUninstallJournal>;
}

function record(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

async function json(response: Response): Promise<unknown> {
  const declared = Number(response.headers.get('content-length') ?? '0');
  if (declared > MAX_BYTES) throw new DeployError(500, 'session_invalid');
  const text = await response.text();
  if (new TextEncoder().encode(text).byteLength > MAX_BYTES) throw new DeployError(500, 'session_invalid');
  try {
    const value = JSON.parse(text) as unknown;
    assertSecretFree(value);
    return value;
  } catch { throw new DeployError(500, 'session_invalid'); }
}

async function journal(response: Response): Promise<ReturningUninstallJournal> {
  const body = await json(response);
  if (!response.ok) {
    const code = record(body) && record(body.error) && isDeployErrorCode(body.error.code)
      ? body.error.code
      : 'session_invalid';
    throw new DeployError(response.status, code);
  }
  if (!record(body) || Object.keys(body).join(',') !== 'journal') throw new DeployError(500, 'session_invalid');
  return requireReturningUninstallJournal(body.journal);
}

function request(path: string, method: 'GET' | 'POST', body?: unknown): Request {
  let encoded: string | undefined;
  if (body !== undefined) {
    try { assertSecretFree(body); encoded = JSON.stringify(body); }
    catch { throw new DeployError(400, 'bad_request'); }
  }
  return new Request(new URL(path, ORIGIN), {
    method,
    headers: encoded === undefined ? undefined : { 'content-type': 'application/json' },
    body: encoded,
  });
}

export function createReturningUninstallJournalPort(
  fetcher: ReturningUninstallJournalFetcher,
): ReturningUninstallJournalPort {
  const call = async (path: string, method: 'GET' | 'POST', body?: unknown): Promise<ReturningUninstallJournal> => {
    let response: Response;
    try { response = await fetcher.fetch(request(path, method, body)); }
    catch (error) {
      if (error instanceof DeployError) throw error;
      throw new DeployError(500, 'session_invalid');
    }
    return journal(response);
  };
  const port: ReturningUninstallJournalPort = {
    initialize: (input) => call('/returning-uninstall-journal/initialize', 'POST', input),
    read: () => call('/returning-uninstall-journal', 'GET'),
    appendApproval: (input) => call('/returning-uninstall-journal/approval', 'POST', input),
    appendHostedRecoveryApproval: (input) => call(
      '/returning-uninstall-journal/approval/hosted-recovery', 'POST', input,
    ),
    acquireLease: (input) => call('/returning-uninstall-journal/lease/acquire', 'POST', input),
    releaseLease: (input) => call('/returning-uninstall-journal/lease/release', 'POST', input),
    prepare: (input) => call('/returning-uninstall-journal/action/prepare', 'POST', input),
    arm: (input) => call('/returning-uninstall-journal/action/arm', 'POST', input),
    submit: (input) => call('/returning-uninstall-journal/action/submit', 'POST', input),
    verify: (input) => call('/returning-uninstall-journal/action/verify', 'POST', input),
  };
  return Object.freeze(port);
}

import type { AuthorizedTarget } from './cloudflare-target';
import { DeployError } from './errors';
import type { ExactReleaseBundleIdentity } from './exact-release-bundle';
import type { FetchTransport } from './oauth';
import type { VerifiedReleaseBundle } from './release';
import type { ReturningUninstallPlan } from './returning-uninstall-plan';
import type { ReturningUninstallJournalPort } from './returning-uninstall-journal-port';

export interface ReturningUninstallExecutionInput {
  readonly plan: ReturningUninstallPlan;
  readonly target: AuthorizedTarget;
  /** Loads only the immutable installed release identity imported from customer authority. */
  readonly loadExactReleaseBundle: (
    identity: ExactReleaseBundleIdentity,
  ) => Promise<VerifiedReleaseBundle>;
  readonly accessToken: string;
  readonly transport: FetchTransport;
  readonly attemptId: string;
  readonly approvedAt: number;
  readonly recoverUntil: number;
  readonly journal: ReturningUninstallJournalPort;
  readonly action: {
    readonly actionId: string;
    readonly actionKey: string;
    readonly actorEmail: string;
    readonly accountId: string;
    readonly installationId: string;
    readonly workerName: string;
    readonly workersSubdomain: string;
    readonly managementOrigin: string;
    readonly expiresAt: number;
  };
}

export interface ReturningUninstallRecoveryExecutionInput {
  readonly plan: ReturningUninstallPlan;
  readonly target: AuthorizedTarget;
  /** Loads only the immutable installed release identity retained in the teardown journal. */
  readonly loadExactReleaseBundle: (
    identity: ExactReleaseBundleIdentity,
  ) => Promise<VerifiedReleaseBundle>;
  readonly accessToken: string;
  readonly transport: FetchTransport;
  readonly attemptId: string;
  readonly approvedAt: number;
  readonly recoverUntil: number;
  readonly journal: ReturningUninstallJournalPort;
}

export interface ReturningUninstallExecutionResult {
  readonly status: 'removed';
  readonly installationId: string;
  readonly convergenceHash: string;
}

export interface ReturningUninstallExecutor {
  execute(input: ReturningUninstallExecutionInput): Promise<ReturningUninstallExecutionResult>;
  resume(input: ReturningUninstallRecoveryExecutionInput): Promise<ReturningUninstallExecutionResult>;
}

/** Fail closed until the receipt-import teardown implementation is explicitly injected. */
export class DisabledReturningUninstallExecutor implements ReturningUninstallExecutor {
  async execute(_input: ReturningUninstallExecutionInput): Promise<ReturningUninstallExecutionResult> {
    throw new DeployError(503, 'uninstall_mutations_disabled');
  }

  async resume(_input: ReturningUninstallRecoveryExecutionInput): Promise<ReturningUninstallExecutionResult> {
    throw new DeployError(503, 'uninstall_mutations_disabled');
  }
}

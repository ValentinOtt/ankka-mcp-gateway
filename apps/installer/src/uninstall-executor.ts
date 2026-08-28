import type { AuthorizedTarget } from './cloudflare-target';
import { DeployError } from './errors';
import type { InstallJournal } from './install-journal';
import type { VerifiedReleaseBundle } from './release';
import type { UninstallJournalPort } from './uninstall-journal-port';
import type { StaticUninstallPlan } from './uninstall-plan';

export interface UninstallExecutionInput {
  readonly installJournal: InstallJournal;
  readonly uninstallPlan: StaticUninstallPlan;
  readonly target: AuthorizedTarget;
  readonly releaseBundle: VerifiedReleaseBundle;
  readonly accessToken: string;
  /** A key used only to derive the namespace-bound cleanup HMAC nonce. */
  readonly uninstallNonceDerivationKey: string;
  readonly attemptId: string;
  readonly approvedAt: number;
  readonly recoverUntil: number;
  readonly uninstallCycleId: string;
  readonly journal: UninstallJournalPort;
}

export interface UninstallExecutionResult {
  readonly status: 'removed';
  readonly installationId: string;
  readonly convergenceHash: string;
}

export interface UninstallExecutor {
  execute(input: UninstallExecutionInput): Promise<UninstallExecutionResult>;
}

/**
 * Fail closed unless a reviewed uninstall implementation is explicitly
 * injected. No environment flag can activate destructive provider calls.
 */
export class DisabledUninstallExecutor implements UninstallExecutor {
  async execute(_input: UninstallExecutionInput): Promise<UninstallExecutionResult> {
    throw new DeployError(503, 'uninstall_mutations_disabled');
  }
}

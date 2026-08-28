import type { AuthorizedTarget } from './cloudflare-target';
import { DeployError } from './errors';
import type { InstallJournalPort } from './install-journal-port';
import type { VerifiedReleaseBundle } from './release';
import type { DeploySelection, StaticDeployPlan } from './schema';

export interface InstallExecutionInput {
  selection: DeploySelection;
  plan: StaticDeployPlan;
  target: AuthorizedTarget;
  releaseBundle: VerifiedReleaseBundle;
  accessToken: string;
  sessionId: string;
  bootstrapNonceDerivationKey: string;
  attemptId: string;
  recoverUntil: number;
  journal: InstallJournalPort;
}

export interface InstallExecutionResult {
  installationId: string;
}

export interface InstallExecutor {
  execute(input: InstallExecutionInput): Promise<InstallExecutionResult>;
}

// No environment flag can turn this on accidentally. A reviewed executor must
// be injected explicitly when the mutation implementation exists.
export class DisabledInstallExecutor implements InstallExecutor {
  async execute(_input: InstallExecutionInput): Promise<InstallExecutionResult> {
    throw new DeployError(503, 'install_mutations_disabled');
  }
}

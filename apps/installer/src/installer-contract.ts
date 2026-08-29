import { isFailureReason } from './errors';
import type { DeploySelection, StaticDeployPlan } from './schema';
import type { DeployErrorCode } from './errors';
import type { PublicDeployRecovery, PublicDeploySession } from './session';
import type {
  PublicUninstallPlan,
  PublicUninstallRecovery,
  PublicUninstallSession,
} from './uninstall-session';
import type { ExistingAnkkaGatewaySummary } from './cloudflare-gateway-fresh-preflight';
import type { PublicReturningUninstall } from './returning-uninstall-session';
import {
  INSTALL_ACTION_ORDER,
  type InstallActionName,
  type InstallActionPhase,
  type PublicInstallProgress,
} from './install-journal';

export type AuthorizationStatus = 'anonymous' | 'authorized' | 'expired';
export type DeploymentStatus = 'idle' | 'queued' | 'running' | 'failed' | 'succeeded';
export type OperationStatus = 'pending' | 'running' | 'succeeded' | 'failed' | 'blocked';
export type RepairTarget = 'account-home' | 'zero-trust' | 'domain-setup' | 'workers';

export const UNCONFIRMED_GRANT_REVOCATION_DETAIL =
  'Automatic Cloudflare OAuth revocation could not be confirmed. Manually revoke Ankka MCP Gateway in Cloudflare Connected Applications.';

export interface InstallerPlan {
  schemaVersion: 1;
  planId: string;
  planHash: string;
  writesPerformed: false;
  release: { version: string; sha256: string };
  resourceGroups: Array<{ id: string; label: string; detail: string; operations: string[] }>;
  blockers: Array<{
    code: string;
    title: string;
    detail: string;
    severity: 'warning' | 'error';
    repairTarget: RepairTarget | null;
  }>;
  expiresAt: string;
}

export interface InstallerDeployment {
  deploymentId: string;
  status: DeploymentStatus;
  operations: Array<{
    id: string;
    label: string;
    detail: string | null;
    status: OperationStatus;
  }>;
  failure: {
    code: string;
    title: string;
    detail: string;
    repairTarget: RepairTarget | null;
  } | null;
  canRetry: boolean;
  existingGateway: ExistingAnkkaGatewaySummary | null;
  receipt: {
    receiptId: string;
    planId: string;
    planHash: string;
    release: string;
    releaseSha256: string;
    appliedAt: string;
    managementUrl: string | null;
    portalUrl: string | null;
  } | null;
}

export interface InstallerSession {
  schemaVersion: 1;
  recovery: {
    status: 'recovery_required';
    expiresAt: string;
  } | null;
  authorization: {
    status: AuthorizationStatus;
    email: string | null;
    expiresAt: string | null;
  };
  capabilities: {
    selection: boolean;
    plan: boolean;
    deploy: boolean;
    uninstall: boolean;
    events: boolean;
    signedRelease: boolean;
  };
  selection: DeploySelection | null;
  plan: InstallerPlan | null;
  deployment: InstallerDeployment | null;
  removal: InstallerRemoval | null;
  updatedAt: string;
}

export interface InstallerCapabilityPolicy {
  readonly deploy: boolean;
  readonly uninstall: boolean;
  readonly events: boolean;
}

/** Default and reviewed-disabled entrypoints both advertise zero mutation capability. */
export const DISABLED_INSTALLER_CAPABILITY_POLICY: InstallerCapabilityPolicy = Object.freeze({
  deploy: false,
  uninstall: false,
  events: false,
});

export interface InstallerRemoval {
  readonly status: 'planned' | 'authorizing' | 'running' | 'failed' | 'removed';
  readonly recovery: { readonly status: 'recovery_required'; readonly expiresAt: string } | null;
  readonly plan: {
    readonly schemaVersion: 1;
    readonly planId: string;
    readonly planHash: string;
    readonly writesPerformed: false;
    readonly installationId: string;
    readonly release: { readonly version: string; readonly sha256: string } | null;
    readonly operations: readonly { readonly id: string; readonly label: string }[];
    readonly providerNotice: string;
    readonly expiresAt: string;
  };
  readonly failure: {
    readonly code: string;
    readonly title: string;
    readonly detail: string;
    readonly repairTarget: RepairTarget | null;
  } | null;
  readonly canRetry: boolean;
  readonly receipt: {
    readonly receiptId: string;
    readonly installationId: string;
    readonly removedAt: string;
    readonly grantRevocation: 'confirmed' | 'unconfirmed';
    readonly providerNotice: string;
  } | null;
}

/** Appends the stored secret-free diagnostic reason, when one was recorded. */
interface DiagnosticResult {
  readonly code: string;
  readonly reason?: string;
}

function withDiagnostic(detail: string, result: DiagnosticResult | null | undefined): string {
  const candidate = result?.reason ?? null;
  const reason = isFailureReason(candidate) ? candidate : null;
  return reason ? `${detail} Diagnostic: ${reason}.` : detail;
}

function publicPlan(plan: StaticDeployPlan | null): InstallerPlan | null {
  if (!plan) return null;
  const includesInitialSource = plan.gatewayConfiguration.firstSource !== null;
  return {
    schemaVersion: 1,
    planId: plan.planId,
    planHash: plan.planHash,
    writesPerformed: false,
    release: { version: plan.releaseId, sha256: plan.releaseArtifactSha256 },
    resourceGroups: [
      {
        id: 'runtime',
        label: 'Customer-owned runtime',
        detail: 'Management Worker, dashboard assets, and SQLite durable state.',
        operations: [
          'Management Worker',
          'SQLite Durable Object',
          'Dashboard assets',
        ],
      },
      {
        id: 'management-access',
        label: 'Management access',
        detail: 'An explicit Access application and administrator allow policy.',
        operations: ['Management Access application', 'Management Access policy'],
      },
      {
        id: 'gateway',
        label: 'Read-only MCP gateway',
        detail: includesInitialSource
          ? 'First source, Portal, explicit Access applications and policies, and Portal DNS.'
          : 'An empty Portal, explicit administrator access policy, and Portal DNS. Add sources after installation.',
        operations: [
          ...(includesInitialSource ? [
            'MCP server',
            'Source Access application',
            'Source Access policy',
          ] : []),
          'MCP Portal',
          'Portal Access application',
          'Portal Access policy',
          'Portal DNS record',
        ],
      },
    ],
    blockers: [],
    expiresAt: new Date(plan.expiresAt).toISOString(),
  };
}

const FAILURE_COPY: Readonly<Record<DeployErrorCode, {
  title: string;
  detail: string;
  repairTarget: RepairTarget | null;
}>> = Object.freeze({
  abuse_controls_unavailable: {
    title: 'Installer protection unavailable',
    detail: 'Wait until the hosted installer protection is restored before retrying.',
    repairTarget: null,
  },
  bad_request: { title: 'Deployment request rejected', detail: 'Review the installer inputs and create a new plan.', repairTarget: null },
  callback_invalid: { title: 'Cloudflare callback rejected', detail: 'Restart authorization from the exact approved plan.', repairTarget: null },
  csrf_invalid: { title: 'Installer session expired', detail: 'Reload the installer and create a new plan.', repairTarget: null },
  existing_gateway_detected: {
    title: 'Ankka MCP Gateway already detected',
    detail: 'No Cloudflare writes were performed. Open the customer-owned management page to prove the stored receipt before reviewing teardown.',
    repairTarget: null,
  },
  install_mutations_disabled: { title: 'Installer writes are not enabled', detail: 'This private scaffold is intentionally running in zero-write mode.', repairTarget: null },
  uninstall_mutations_disabled: { title: 'Removal writes are not enabled', detail: 'This build keeps the reviewed removal executors intentionally disabled.', repairTarget: null },
  internal_error: { title: 'Deployment could not finish', detail: 'Restart from a new static plan.', repairTarget: null },
  oauth_denied: { title: 'Cloudflare authorization was cancelled', detail: 'Authorize the exact plan when you are ready.', repairTarget: null },
  oauth_exchange_failed: { title: 'Cloudflare authorization failed', detail: 'Restart authorization from a new static plan.', repairTarget: null },
  oauth_grant_invalid: { title: 'Cloudflare permission grant did not match', detail: 'Approve the exact requested permissions with the primary administrator.', repairTarget: 'account-home' },
  oauth_revoke_failed: { title: 'Cloudflare grant revocation needs attention', detail: 'Revoke Ankka MCP Gateway from Cloudflare connected applications before retrying.', repairTarget: 'account-home' },
  oauth_state_invalid: { title: 'Authorization attempt expired', detail: 'Create and authorize a new static plan.', repairTarget: null },
  origin_invalid: { title: 'Installer request rejected', detail: 'Reload this page from the signed installer origin.', repairTarget: null },
  rate_limited: { title: 'Installer request limit reached', detail: 'Wait briefly, then retry the same reviewed action.', repairTarget: null },
  release_invalid: { title: 'Gateway release verification failed', detail: 'Wait for a verified gateway release before retrying.', repairTarget: null },
  release_unavailable: { title: 'Verified gateway release unavailable', detail: 'The zero-write installer cannot deploy until release signing is enabled.', repairTarget: null },
  session_conflict: { title: 'Static plan changed', detail: 'Review and approve a fresh plan.', repairTarget: null },
  session_expired: { title: 'Installer session expired', detail: 'Reload the installer and create a new plan.', repairTarget: null },
  session_invalid: { title: 'Installer session invalid', detail: 'Reload the installer and create a new plan.', repairTarget: null },
  target_account_ambiguous: { title: 'Cloudflare account selection is ambiguous', detail: 'Authorize exactly one Cloudflare account.', repairTarget: 'account-home' },
  target_zone_invalid: { title: 'Active Cloudflare zone not found', detail: 'Check the typed active zone in the authorized account.', repairTarget: 'domain-setup' },
});

const INSTALL_ACTION_COPY: Readonly<Record<InstallActionName, {
  readonly label: string;
  readonly detail: string;
}>> = Object.freeze({
  gateway_fresh_preflight: {
    label: 'Checking requested Cloudflare names',
    detail: 'Verifies that the requested Worker, Access, and hostname resources are unused.',
  },
  worker_create: {
    label: 'Creating the management Worker',
    detail: 'Creates the customer-owned Worker resource.',
  },
  management_access_application_create: {
    label: 'Creating the management Access application',
    detail: 'Protects the administrator interface with Cloudflare Access.',
  },
  management_admin_policy_create: {
    label: 'Creating the administrator Access policy',
    detail: 'Allows only the reviewed administrator identities.',
  },
  provision_worker_version_create: {
    label: 'Uploading the provisioning Worker version',
    detail: 'Uploads the reviewed customer-resident runtime and dashboard assets.',
  },
  provision_worker_deployment_create: {
    label: 'Deploying the provisioning Worker',
    detail: 'Activates the provisioning version in the customer account.',
  },
  bootstrap_worker_version_create: {
    label: 'Uploading the bootstrap Worker version',
    detail: 'Prepares the one-time customer-owned bootstrap endpoint.',
  },
  bootstrap_worker_deployment_create: {
    label: 'Deploying the bootstrap Worker',
    detail: 'Activates the reviewed bootstrap version.',
  },
  bootstrap_subdomain_enable: {
    label: 'Enabling the temporary bootstrap URL',
    detail: 'Temporarily enables workers.dev for the signed bootstrap request.',
  },
  customer_bootstrap_submit: {
    label: 'Bootstrapping customer-owned gateway state',
    detail: 'Creates the initial source, Portal, Access, and DNS configuration.',
  },
  bootstrap_subdomain_disable: {
    label: 'Disabling the temporary bootstrap URL',
    detail: 'Closes the one-time workers.dev bootstrap surface.',
  },
  clean_worker_version_create: {
    label: 'Uploading the final Worker version',
    detail: 'Uploads the runtime without the bootstrap endpoint.',
  },
  clean_worker_deployment_create: {
    label: 'Deploying the final Worker version',
    detail: 'Replaces the temporary bootstrap deployment.',
  },
  management_custom_domain_attach: {
    label: 'Attaching the management custom domain',
    detail: 'Connects the reviewed administrator hostname.',
  },
  final_convergence: {
    label: 'Verifying final gateway convergence',
    detail: 'Confirms the exact reviewed resources and customer-owned receipt.',
  },
});

function phaseDetail(phase: InstallActionPhase, base: string): string {
  if (phase === 'prepared') return `${base} The request is prepared.`;
  if (phase === 'send_armed') return `${base} The provider write is armed.`;
  if (phase === 'submitted') return `${base} Cloudflare accepted the request; verification is running.`;
  return base;
}

function installOperations(
  session: PublicDeploySession,
  progress: PublicInstallProgress | null,
): InstallerDeployment['operations'] {
  const byName = new Map(progress?.actions.map((action) => [action.name, action]) ?? []);
  let failedAction: InstallActionName | null = null;
  if (session.status === 'failed' && progress) {
    const incomplete = progress.actions.find((action) => action.phase !== 'verified');
    failedAction = incomplete?.name ?? INSTALL_ACTION_ORDER[progress.actions.length] ?? null;
  }
  return INSTALL_ACTION_ORDER.map((name) => {
    const copy = INSTALL_ACTION_COPY[name];
    const action = byName.get(name);
    const status: OperationStatus = name === failedAction
      ? 'failed'
      : action?.phase === 'verified' || session.status === 'succeeded'
        ? 'succeeded'
        : action
          ? 'running'
          : 'pending';
    return {
      id: name,
      label: copy.label,
      detail: action ? phaseDetail(action.phase, copy.detail) : copy.detail,
      status,
    };
  });
}

function deployment(
  session: PublicDeploySession,
  progress: PublicInstallProgress | null,
): InstallerDeployment | null {
  const plan = session.plan;
  if (!plan || (session.status === 'draft' && !session.result)) return null;
  const status: DeploymentStatus = session.status === 'authorizing'
    ? 'queued'
    : session.status === 'installing'
      ? 'running'
      : session.status === 'succeeded'
        ? 'succeeded'
        : session.status === 'failed'
          ? 'failed'
          : 'idle';
  const failed = status === 'failed';
  const succeeded = status === 'succeeded';
  const resultCode = session.result?.code;
  const grantRevocationUnconfirmed = succeeded &&
    session.result?.code === 'install_complete' &&
    session.result.grantRevocation === 'unconfirmed';
  const failureCode = failed && resultCode && resultCode !== 'install_complete'
    ? resultCode
    : null;
  const failureCopy = failureCode ? FAILURE_COPY[failureCode] : null;
  return {
    deploymentId: `deploy-${plan.planId.slice('plan-'.length)}`,
    status,
    operations: [
      {
        id: 'connect',
        label: 'Connecting to your Cloudflare account',
        detail: null,
        status: session.status === 'authorizing' ? 'running' : 'succeeded',
      },
      {
        id: 'verify',
        label: 'Checking the authorized account and active zone',
        detail: null,
        status: session.status === 'authorizing'
          ? 'pending'
          : failed && progress === null
            ? 'failed'
            : succeeded || progress !== null
              ? 'succeeded'
              : 'running',
      },
      ...installOperations(session, progress),
      {
        id: 'revoke',
        label: 'Revoking the short-lived Cloudflare grant',
        detail: grantRevocationUnconfirmed ? UNCONFIRMED_GRANT_REVOCATION_DETAIL : null,
        status: succeeded
          ? grantRevocationUnconfirmed ? 'blocked' : 'succeeded'
          : failed ? 'failed' : 'pending',
      },
    ],
    failure: failureCode && failureCopy
      ? { code: failureCode, ...failureCopy, detail: withDiagnostic(failureCopy.detail, session.result) }
      : null,
    canRetry: failed && resultCode !== 'existing_gateway_detected',
    existingGateway: failed && session.result?.code === 'existing_gateway_detected'
      ? session.result.existingGateway ?? null
      : null,
    receipt: succeeded && session.result?.code === 'install_complete'
      ? {
          receiptId: `receipt-${session.result.installationId.slice('acg-'.length)}`,
          planId: plan.planId,
          planHash: plan.planHash,
          release: plan.releaseId,
          releaseSha256: plan.releaseArtifactSha256,
          appliedAt: new Date(session.result.completedAt).toISOString(),
          managementUrl: `https://${plan.gatewayConfiguration.managementHostname}/`,
          portalUrl: `https://${plan.gatewayConfiguration.portalHostname}/mcp`,
        }
      : null,
  };
}

function removal(
  uninstall: InstallerUninstallSession | null,
  recovery: PublicUninstallRecovery | null,
): InstallerRemoval | null {
  if (!uninstall) return null;
  const failed = uninstall.status === 'failed';
  const removed = uninstall.status === 'removed';
  const failureCode = failed && uninstall.result?.code !== 'uninstall_complete'
    ? uninstall.result?.code ?? null
    : null;
  const failureCopy = failureCode ? FAILURE_COPY[failureCode] : null;
  const result = removed && uninstall.result?.code === 'uninstall_complete'
    ? uninstall.result
    : null;
  return {
    status: uninstall.status === 'uninstalling' ? 'running' : uninstall.status,
    recovery: recovery
      ? { status: 'recovery_required', expiresAt: new Date(recovery.recoverUntil).toISOString() }
      : null,
    plan: {
      schemaVersion: 1,
      planId: uninstall.plan.planId,
      planHash: uninstall.plan.planHash,
      writesPerformed: false,
      installationId: uninstall.plan.installationId,
      release: {
        version: uninstall.plan.release.id,
        sha256: uninstall.plan.release.aggregateSha256,
      },
      operations: uninstall.plan.steps.map((step) => ({ id: step.kind, label: step.summary })),
      providerNotice: uninstall.plan.providerNotice,
      expiresAt: new Date(uninstall.plan.expiresAt).toISOString(),
    },
    failure: failureCode && failureCopy
      ? { code: failureCode, ...failureCopy, detail: withDiagnostic(failureCopy.detail, uninstall.result) }
      : null,
    canRetry: failed || recovery !== null,
    receipt: result
      ? {
          receiptId: `removal-${result.installationId.slice('acg-'.length)}`,
          installationId: result.installationId,
          removedAt: new Date(result.completedAt).toISOString(),
          grantRevocation: result.grantRevocation,
          providerNotice: uninstall.plan.providerNotice,
        }
      : null,
  };
}

type InstallerUninstallSession = Omit<PublicUninstallSession, 'plan'> & {
  readonly plan: PublicUninstallPlan;
};

const RETURNING_REMOVAL_NOTICE =
  'Removal is authorized by the checksum-verified receipt held in the customer-owned Worker. Cloudflare retains any Advanced Certificate for manual review.';

function returningRemoval(value: PublicReturningUninstall | null): InstallerRemoval | null {
  if (!value) return null;
  const failed = value.status === 'failed';
  const removed = value.status === 'removed';
  const failureCode = failed && value.result?.code !== 'returning_uninstall_complete'
    ? value.result?.code ?? null
    : null;
  const failureCopy = failureCode ? FAILURE_COPY[failureCode] : null;
  const result = removed && value.result?.code === 'returning_uninstall_complete' ? value.result : null;
  return {
    status: value.status === 'removing' ? 'running' : value.status,
    recovery: value.recoveryAvailable
      ? { status: 'recovery_required', expiresAt: new Date(value.recoverUntil).toISOString() }
      : null,
    plan: {
      schemaVersion: 1,
      planId: value.plan.planId,
      planHash: value.plan.planHash,
      writesPerformed: false,
      installationId: value.plan.gateway.installationId,
      release: null,
      operations: value.plan.steps.map((label, index) => ({ id: `returning_teardown_${index + 1}`, label })),
      providerNotice: RETURNING_REMOVAL_NOTICE,
      expiresAt: new Date(value.plan.expiresAt).toISOString(),
    },
    failure: failureCode && failureCopy
      ? { code: failureCode, ...failureCopy, detail: withDiagnostic(failureCopy.detail, value.result) }
      : null,
    canRetry: failed || value.recoveryAvailable,
    receipt: result
      ? {
          receiptId: `removal-${result.installationId.slice('acg-'.length)}`,
          installationId: result.installationId,
          removedAt: new Date(result.completedAt).toISOString(),
          grantRevocation: result.grantRevocation,
          providerNotice: RETURNING_REMOVAL_NOTICE,
        }
      : null,
  };
}

export function installerSession(
  session: PublicDeploySession,
  recovery: PublicDeployRecovery | null = null,
  capabilityPolicy: InstallerCapabilityPolicy = DISABLED_INSTALLER_CAPABILITY_POLICY,
  uninstall: InstallerUninstallSession | null = null,
  uninstallRecovery: PublicUninstallRecovery | null = null,
  installProgress: PublicInstallProgress | null = null,
  returningUninstall: PublicReturningUninstall | null = null,
): InstallerSession {
  const hasPlan = session.plan !== null;
  const completed = session.status === 'failed' || session.status === 'succeeded';
  const authorized = session.status === 'installing' && recovery === null;
  const email = session.selection?.basics.adminEmail ?? null;
  return {
    schemaVersion: 1,
    recovery: recovery
      ? { status: 'recovery_required', expiresAt: new Date(recovery.recoverUntil).toISOString() }
      : null,
    authorization: {
      status: completed ? 'expired' : authorized ? 'authorized' : 'anonymous',
      email: completed || authorized ? email : null,
      expiresAt: completed
        ? (session.result ? new Date(session.result.completedAt).toISOString() : null)
        : authorized
          ? new Date(session.expiresAt).toISOString()
          : null,
    },
    capabilities: {
      selection: recovery === null && session.status !== 'installing' && session.status !== 'succeeded',
      plan: recovery !== null
        ? session.selection !== null
        : session.selection !== null && session.status !== 'installing' && session.status !== 'succeeded',
      deploy: capabilityPolicy.deploy,
      uninstall: capabilityPolicy.uninstall && (
        (session.status === 'succeeded' && uninstall?.status !== 'removed') ||
        (session.status === 'failed' && session.result?.code === 'existing_gateway_detected' &&
          returningUninstall !== null && returningUninstall.status !== 'removed')
      ),
      events: capabilityPolicy.events,
      signedRelease: hasPlan,
    },
    selection: session.selection,
    plan: publicPlan(session.plan),
    deployment: deployment(session, installProgress),
    removal: removal(uninstall, uninstallRecovery) ?? returningRemoval(returningUninstall),
    updatedAt: new Date(Math.max(
      session.updatedAt,
      uninstall?.updatedAt ?? 0,
      returningUninstall?.updatedAt ?? 0,
      installProgress?.updatedAt ?? 0,
    )).toISOString(),
  };
}

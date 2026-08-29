import {
  JOURNALED_INSTALL_RECOVERY_DETAIL,
  installerSession,
  UNCONFIRMED_GRANT_REVOCATION_DETAIL,
} from '../src/installer-contract';
import { buildStaticDeployPlan, parseDeploySelection } from '../src/schema';
import type { PublicDeploySession } from '../src/session';
import type { PublicUninstallPlan } from '../src/uninstall-session';
import {
  STATIC_UNINSTALL_PROVIDER_NOTICE,
  STATIC_UNINSTALL_STEP_SUMMARIES,
} from '../src/uninstall-plan';
import type { PublicInstallProgress } from '../src/install-journal';
import { buildReturningUninstallPlan, RETURNING_UNINSTALL_STEPS } from '../src/returning-uninstall-plan';
import { manifest, NOW, selectionInput } from './fixtures';

describe('installer UI/server cross-contract', () => {
  it('returns the exact stable top-level InstallerSession and InstallerPlan shapes', async () => {
    const selection = parseDeploySelection(selectionInput);
    const plan = await buildStaticDeployPlan(selection, manifest, NOW + 600_000);
    const internal: PublicDeploySession = {
      schemaVersion: 1,
      status: 'draft',
      expiresAt: NOW + 1_800_000,
      updatedAt: NOW,
      selection,
      plan,
      result: null,
    };
    const response = { ...installerSession(internal), csrf: 'c'.repeat(43) };
    expect(Object.keys(response).sort()).toEqual([
      'authorization',
      'capabilities',
      'csrf',
      'deployment',
      'plan',
      'recovery',
      'removal',
      'schemaVersion',
      'selection',
      'updatedAt',
    ]);
    expect(Object.keys(response.plan ?? {}).sort()).toEqual([
      'blockers',
      'expiresAt',
      'planHash',
      'planId',
      'release',
      'resourceGroups',
      'schemaVersion',
      'writesPerformed',
    ]);
    expect(response.plan).toMatchObject({
      schemaVersion: 1,
      planId: plan.planId,
      planHash: plan.planHash,
      writesPerformed: false,
      release: { version: manifest.release, sha256: manifest.artifact.treeSha256 },
      blockers: [],
    });
    expect(response.capabilities).toEqual({
      selection: true,
      plan: true,
      deploy: false,
      uninstall: false,
      events: false,
      signedRelease: true,
    });
    expect(response.authorization).toEqual({ status: 'anonymous', email: null, expiresAt: null });
    expect(response.recovery).toBeNull();
    expect(response.deployment).toBeNull();
  });

  it('shows the portal-only wizard plan without source operations', async () => {
    const selection = parseDeploySelection({ ...selectionInput, firstSource: null });
    const plan = await buildStaticDeployPlan(selection, manifest, NOW + 600_000);
    const response = installerSession({
      schemaVersion: 1,
      status: 'draft',
      expiresAt: NOW + 1_800_000,
      updatedAt: NOW,
      selection,
      plan,
      result: null,
    });
    const gatewayGroup = response.plan?.resourceGroups.find(({ id }) => id === 'gateway');

    expect(gatewayGroup?.operations).toEqual([
      'MCP Portal',
      'Portal Access application',
      'Portal Access policy',
      'Portal DNS record',
    ]);
    expect(gatewayGroup?.detail).toContain('Add sources after installation');
  });

  it('exposes only a fixed recovery signal and disables selection mutation', async () => {
    const selection = parseDeploySelection(selectionInput);
    const plan = await buildStaticDeployPlan(selection, manifest, NOW + 600_000);
    const response = installerSession({
      schemaVersion: 1,
      status: 'installing',
      expiresAt: NOW + 1_800_000,
      updatedAt: NOW + 1_800_000,
      selection,
      plan,
      result: null,
    }, {
      status: 'recovery_required',
      recoverUntil: NOW + 1_800_000 + 86_400_000,
    });

    expect(response.recovery).toEqual({
      status: 'recovery_required',
      expiresAt: new Date(NOW + 1_800_000 + 86_400_000).toISOString(),
    });
    expect(response.capabilities).toMatchObject({ selection: false, plan: true, deploy: false, uninstall: false, events: false });
    expect(response.authorization).toEqual({ status: 'anonymous', email: null, expiresAt: null });
    expect(JSON.stringify(response)).not.toMatch(/journal|bindingHash|approvalHistory|leaseAttemptIds/iu);
  });

  it('maps a code-only failed result to fixed UI copy without leaking internal state fields', async () => {
    const selection = parseDeploySelection(selectionInput);
    const plan = await buildStaticDeployPlan(selection, manifest, NOW + 600_000);
    const response = installerSession({
      schemaVersion: 1,
      status: 'failed',
      expiresAt: NOW + 1_800_000,
      updatedAt: NOW + 50,
      selection,
      plan,
      result: { code: 'install_mutations_disabled', completedAt: NOW + 50 },
    });
    expect(response.deployment).toMatchObject({
      status: 'failed',
      canRetry: true,
      failure: {
        code: 'install_mutations_disabled',
        title: 'Installer writes are not enabled',
      },
      receipt: null,
    });
    expect(response.authorization.status).toBe('expired');
    expect(Object.hasOwn(response, 'status')).toBe(false);
    expect(Object.hasOwn(response, 'result')).toBe(false);
  });

  it('binds a success receipt to the reviewed plan, release, and exact configured origins', async () => {
    const selection = parseDeploySelection(selectionInput);
    const plan = await buildStaticDeployPlan(selection, manifest, NOW + 600_000);
    const response = installerSession({
      schemaVersion: 1,
      status: 'succeeded',
      expiresAt: NOW + 1_800_000,
      updatedAt: NOW + 50,
      selection,
      plan,
      result: {
        code: 'install_complete',
        completedAt: NOW + 50,
        installationId: `acg-${'d'.repeat(24)}`,
        grantRevocation: 'confirmed',
      },
    });
    expect(response.deployment?.receipt).toEqual({
      receiptId: `receipt-${'d'.repeat(24)}`,
      planId: plan.planId,
      planHash: plan.planHash,
      release: manifest.release,
      releaseSha256: manifest.artifact.treeSha256,
      appliedAt: new Date(NOW + 50).toISOString(),
      managementUrl: 'https://manage.example.com/',
      portalUrl: 'https://mcp.example.com/mcp',
    });
    expect(Object.keys(response.deployment?.receipt ?? {}).sort()).toEqual([
      'appliedAt',
      'managementUrl',
      'planHash',
      'planId',
      'portalUrl',
      'receiptId',
      'release',
      'releaseSha256',
    ]);
  });

  it('retains a converged receipt and blocks only the revocation operation when revocation is unconfirmed', async () => {
    const selection = parseDeploySelection(selectionInput);
    const plan = await buildStaticDeployPlan(selection, manifest, NOW + 600_000);
    const response = installerSession({
      schemaVersion: 1,
      status: 'succeeded',
      expiresAt: NOW + 1_800_000,
      updatedAt: NOW + 50,
      selection,
      plan,
      result: {
        code: 'install_complete',
        completedAt: NOW + 50,
        installationId: `acg-${'e'.repeat(24)}`,
        grantRevocation: 'unconfirmed',
      },
    });

    expect(response.deployment).toMatchObject({
      status: 'succeeded',
      failure: null,
      canRetry: false,
      receipt: {
        receiptId: `receipt-${'e'.repeat(24)}`,
        managementUrl: 'https://manage.example.com/',
        portalUrl: 'https://mcp.example.com/mcp',
      },
    });
    expect(response.deployment?.operations
      .filter(({ id }) => id !== 'revoke')
      .map(({ status }) => status))
      .toEqual(Array(17).fill('succeeded'));
    expect(response.deployment?.operations.find(({ id }) => id === 'revoke')).toEqual({
      id: 'revoke',
      label: 'Revoking the short-lived Cloudflare grant',
      detail: UNCONFIRMED_GRANT_REVOCATION_DETAIL,
      status: 'blocked',
    });
  });

  it('projects exact journal action phases as provider-ID-free live progress', async () => {
    const selection = parseDeploySelection(selectionInput);
    const plan = await buildStaticDeployPlan(selection, manifest, NOW + 600_000);
    const progress: PublicInstallProgress = {
      schemaVersion: 1,
      revision: 9,
      updatedAt: NOW + 30,
      actions: [
        { name: 'gateway_fresh_preflight', phase: 'verified', updatedAt: NOW + 10 },
        { name: 'worker_create', phase: 'verified', updatedAt: NOW + 20 },
        { name: 'management_access_application_create', phase: 'submitted', updatedAt: NOW + 30 },
      ],
    };
    const response = installerSession({
      schemaVersion: 1,
      status: 'installing',
      expiresAt: NOW + 1_800_000,
      updatedAt: NOW + 5,
      selection,
      plan,
      result: null,
    }, null, undefined, null, null, progress);

    expect(response.updatedAt).toBe(new Date(progress.updatedAt).toISOString());
    expect(response.deployment?.operations.slice(0, 6)).toEqual([
      expect.objectContaining({ id: 'connect', status: 'succeeded' }),
      expect.objectContaining({ id: 'verify', status: 'succeeded' }),
      expect.objectContaining({ id: 'gateway_fresh_preflight', status: 'succeeded' }),
      expect.objectContaining({ id: 'worker_create', status: 'succeeded' }),
      expect.objectContaining({
        id: 'management_access_application_create',
        status: 'running',
        detail: expect.stringContaining('Cloudflare accepted the request'),
      }),
      expect.objectContaining({ id: 'management_admin_policy_create', status: 'pending' }),
    ]);
    expect(JSON.stringify(response)).not.toMatch(
      /accountId|applicationId|bindingHash|locator|requestHash|token/iu,
    );
  });

  it('explains receipt-bound recovery only after a journaled write may have started', async () => {
    const selection = parseDeploySelection(selectionInput);
    const plan = await buildStaticDeployPlan(selection, manifest, NOW + 600_000);
    const session: PublicDeploySession = {
      schemaVersion: 1,
      status: 'failed',
      expiresAt: NOW + 1_800_000,
      updatedAt: NOW + 50,
      selection,
      plan,
      result: {
        code: 'internal_error',
        completedAt: NOW + 50,
      },
    };
    const progress = (workerPhase: 'prepared' | 'send_armed'): PublicInstallProgress => ({
      schemaVersion: 1,
      revision: 2,
      updatedAt: NOW + 40,
      actions: [
        { name: 'gateway_fresh_preflight', phase: 'verified', updatedAt: NOW + 20 },
        { name: 'worker_create', phase: workerPhase, updatedAt: NOW + 40 },
      ],
    });

    const afterWriteArmed = installerSession(
      session,
      null,
      undefined,
      null,
      null,
      progress('send_armed'),
    );
    expect(afterWriteArmed.deployment?.failure?.detail).toContain(JOURNALED_INSTALL_RECOVERY_DETAIL);
    const recoveryDetail = afterWriteArmed.deployment?.failure?.detail ?? '';
    expect(recoveryDetail).toContain('Exact journaled resources may remain');
    expect(recoveryDetail).toContain('resume or reconciliation');
    expect(recoveryDetail).toContain('not blindly auto-deleted');
    expect(recoveryDetail).toContain('reviewed recovery flow');
    expect(recoveryDetail).toContain('receipt-bound uninstall path for full cleanup');
    expect(afterWriteArmed.deployment?.operations.find(({ id }) => id === 'worker_create')?.status)
      .toBe('failed');
    expect(afterWriteArmed.deployment?.operations.find(({ id }) => id === 'revoke')?.status)
      .toBe('succeeded');
    expect(JSON.stringify(afterWriteArmed)).not.toMatch(
      /accountId|applicationId|bindingHash|locator|requestHash|recordContent|token/iu,
    );

    const preparedOnly = installerSession(session, null, undefined, null, null, progress('prepared'));
    expect(preparedOnly.deployment?.failure?.detail).not.toContain(JOURNALED_INSTALL_RECOVERY_DETAIL);
  });

  it('projects a canary removal plan and recovery without journal or provider locators', async () => {
    const selection = parseDeploySelection(selectionInput);
    const plan = await buildStaticDeployPlan(selection, manifest, NOW + 600_000);
    const installationId = `acg-${'f'.repeat(24)}`;
    const providerNotice = STATIC_UNINSTALL_PROVIDER_NOTICE;
    const uninstallPlan: PublicUninstallPlan = {
      schemaVersion: 1,
      writesPerformed: false,
      installationId,
      release: { id: manifest.release, aggregateSha256: manifest.artifact.treeSha256 },
      steps: [{
        order: 2,
        kind: 'gateway_resources_remove',
        summary: STATIC_UNINSTALL_STEP_SUMMARIES.gateway_resources_remove,
        resources: [],
      }],
      providerNotice,
      planId: `uninstall-plan-${'a'.repeat(24)}`,
      planHash: `sha256:${'b'.repeat(64)}`,
      expiresAt: NOW + 300_000,
    };
    const response = installerSession({
      schemaVersion: 1,
      status: 'succeeded',
      expiresAt: NOW + 1_800_000,
      updatedAt: NOW + 50,
      selection,
      plan,
      result: {
        code: 'install_complete',
        completedAt: NOW + 50,
        installationId,
        grantRevocation: 'confirmed',
      },
    }, null, { deploy: true, uninstall: true, events: false }, {
      schemaVersion: 1,
      status: 'failed',
      recoverUntil: NOW + 86_400_000,
      updatedAt: NOW + 100,
      plan: uninstallPlan,
      result: { code: 'internal_error', completedAt: NOW + 100 },
    }, { status: 'recovery_required', recoverUntil: NOW + 86_400_000 });

    expect(response.capabilities.uninstall).toBe(true);
    expect(response.removal).toMatchObject({
      status: 'failed',
      canRetry: true,
      recovery: {
        status: 'recovery_required',
        expiresAt: new Date(NOW + 86_400_000).toISOString(),
      },
      plan: {
        planId: uninstallPlan.planId,
        planHash: uninstallPlan.planHash,
        writesPerformed: false,
        providerNotice,
        operations: [{
          id: 'gateway_resources_remove',
          label: STATIC_UNINSTALL_STEP_SUMMARIES.gateway_resources_remove,
        }],
      },
      failure: { code: 'internal_error' },
      receipt: null,
    });
    expect(JSON.stringify(response.removal)).not.toMatch(
      /bindingHash|approvalHistory|leaseAttemptIds|namespaceId|applicationId|policyId/iu,
    );
  });

  it('keeps a removed receipt when grant revocation is unconfirmed and disables another removal', async () => {
    const selection = parseDeploySelection(selectionInput);
    const plan = await buildStaticDeployPlan(selection, manifest, NOW + 600_000);
    const installationId = `acg-${'1'.repeat(24)}`;
    const providerNotice = STATIC_UNINSTALL_PROVIDER_NOTICE;
    const uninstallPlan: PublicUninstallPlan = {
      schemaVersion: 1,
      writesPerformed: false,
      installationId,
      release: { id: manifest.release, aggregateSha256: manifest.artifact.treeSha256 },
      steps: [],
      providerNotice,
      planId: `uninstall-plan-${'2'.repeat(24)}`,
      planHash: `sha256:${'3'.repeat(64)}`,
      expiresAt: NOW + 300_000,
    };
    const response = installerSession({
      schemaVersion: 1,
      status: 'succeeded',
      expiresAt: NOW + 1_800_000,
      updatedAt: NOW + 50,
      selection,
      plan,
      result: {
        code: 'install_complete',
        completedAt: NOW + 50,
        installationId,
        grantRevocation: 'confirmed',
      },
    }, null, { deploy: true, uninstall: true, events: false }, {
      schemaVersion: 1,
      status: 'removed',
      recoverUntil: NOW + 86_400_000,
      updatedAt: NOW + 150,
      plan: uninstallPlan,
      result: {
        code: 'uninstall_complete',
        completedAt: NOW + 150,
        installationId,
        grantRevocation: 'unconfirmed',
      },
    }, null);

    expect(response.capabilities.uninstall).toBe(false);
    expect(response.removal).toMatchObject({
      status: 'removed',
      failure: null,
      canRetry: false,
      receipt: {
        receiptId: `removal-${'1'.repeat(24)}`,
        installationId,
        removedAt: new Date(NOW + 150).toISOString(),
        grantRevocation: 'unconfirmed',
        providerNotice,
      },
    });
  });

  it('projects a returning customer teardown plan and terminal receipt without action authority', async () => {
    const selection = parseDeploySelection(selectionInput);
    const existingGateway = {
      schemaVersion: 1 as const,
      installationId: `acg-${'4'.repeat(24)}`,
      name: selection.basics.gatewayName,
      managementHostname: selection.basics.managementHostname,
      portalHostname: selection.basics.portalHostname,
      workerName: 'ankka-gateway-example',
    };
    const plan = await buildReturningUninstallPlan(existingGateway, NOW, NOW + 300_000);
    const failedSession: PublicDeploySession = {
      schemaVersion: 1,
      status: 'failed',
      expiresAt: NOW + 1_800_000,
      updatedAt: NOW,
      selection,
      plan: null,
      result: { code: 'existing_gateway_detected', completedAt: NOW, existingGateway },
    };
    const planned = installerSession(
      failedSession,
      null,
      { deploy: false, uninstall: true, events: false },
      null,
      null,
      null,
      {
        schemaVersion: 1, status: 'planned', updatedAt: NOW + 1,
        recoverUntil: NOW + 86_400_000, recoveryAvailable: false, plan, result: null,
      },
    );

    expect(planned.capabilities.uninstall).toBe(true);
    expect(planned.removal).toMatchObject({
      status: 'planned',
      recovery: null,
      failure: null,
      canRetry: false,
      receipt: null,
      plan: {
        planId: plan.planId,
        planHash: plan.planHash,
        writesPerformed: false,
        installationId: existingGateway.installationId,
        release: null,
        operations: RETURNING_UNINSTALL_STEPS.map((label, index) => ({
          id: `returning_teardown_${index + 1}`,
          label,
        })),
      },
    });
    expect(JSON.stringify(planned.removal)).not.toMatch(
      /actionId|actionKey|actorEmail|accountId|stateHash|verifierHash|attemptId|workersSubdomain/iu,
    );

    const recoverable = installerSession(
      failedSession,
      null,
      { deploy: false, uninstall: true, events: false },
      null,
      null,
      null,
      {
        schemaVersion: 1,
        status: 'removing',
        updatedAt: NOW + 2,
        recoverUntil: NOW + 86_400_000,
        recoveryAvailable: true,
        plan,
        result: null,
      },
    );
    expect(recoverable.removal).toMatchObject({
      status: 'running',
      canRetry: true,
      recovery: {
        status: 'recovery_required',
        expiresAt: new Date(NOW + 86_400_000).toISOString(),
      },
    });

    const removedAt = NOW + 20;
    const removed = installerSession(
      failedSession,
      null,
      { deploy: false, uninstall: true, events: false },
      null,
      null,
      null,
      {
        schemaVersion: 1,
        status: 'removed',
        updatedAt: removedAt,
        recoverUntil: NOW + 86_400_000,
        recoveryAvailable: false,
        plan,
        result: {
          code: 'returning_uninstall_complete',
          completedAt: removedAt,
          installationId: existingGateway.installationId,
          grantRevocation: 'unconfirmed',
        },
      },
    );
    expect(removed.capabilities.uninstall).toBe(false);
    expect(removed.removal).toMatchObject({
      status: 'removed',
      canRetry: false,
      receipt: {
        receiptId: `removal-${'4'.repeat(24)}`,
        installationId: existingGateway.installationId,
        removedAt: new Date(removedAt).toISOString(),
        grantRevocation: 'unconfirmed',
      },
    });
  });
});

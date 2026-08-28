import { sha256 } from '../src/crypto';
import { deriveCustomerGatewayInstallationReceiptExpectation } from '../src/customer-bootstrap-request';
import { GatewayDeploySession } from '../src/durable/gateway-deploy-session';
import { parseReturningUninstallImportedAuthority } from '../src/returning-uninstall-authority';
import { loadInstalledReturningUninstallReleaseBundle } from '../src/reviewed-returning-uninstall-executor';
import {
  acquireReturningUninstallLease,
  armReturningUninstallAction,
  createReturningUninstallJournal,
  prepareReturningUninstallAction,
  submitReturningUninstallAction,
  verifyReturningUninstallAction,
} from '../src/returning-uninstall-journal';
import { parseDeploySelection } from '../src/schema';
import {
  FakeState,
  internalRequest,
  manifest,
  NOW,
  selectionInput,
  verifiedReleaseBundle,
} from './fixtures';
import { readyInstallationReceiptFixture } from './provider-neutral-installation-receipt-fixture';

const CSRF = 'c'.repeat(43);
const DISCOVERY_ATTEMPT = `att_${'D'.repeat(32)}`;
const INSTALL_ATTEMPT = `att_${'I'.repeat(32)}`;
const RETURNING_ATTEMPT = `att_${'R'.repeat(32)}`;
const TARGET_ID_HASH = `sha256:${'1'.repeat(64)}`;
const ACCOUNT_ID = 'a'.repeat(32);
const ZONE_ID = 'b'.repeat(32);
const GATEWAY = Object.freeze({
  schemaVersion: 1 as const,
  installationId: `acg-${'d'.repeat(24)}`,
  name: selectionInput.basics.gatewayName,
  managementHostname: selectionInput.basics.managementHostname,
  portalHostname: selectionInput.basics.portalHostname,
  workerName: 'ankka-gateway-example',
});

async function responseBody(response: Response): Promise<Record<string, any>> {
  return response.json() as Promise<Record<string, any>>;
}

async function returningReady(planExpiresAt = NOW + 500_000) {
  const state = new FakeState();
  let currentTime = NOW;
  const object = new GatewayDeploySession(
    state as unknown as DurableObjectState,
    undefined,
    () => currentTime,
  );
  const csrfHash = await sha256(CSRF);
  const discoveryState = 'd'.repeat(43);
  const discoveryVerifier = 'e'.repeat(43);

  expect((await object.fetch(internalRequest('/initialize', 'POST', {
    csrfHash,
    createdAt: NOW,
    expiresAt: NOW + 1_800_000,
  }))).status).toBe(201);
  currentTime = NOW + 1;
  expect((await object.fetch(internalRequest('/discover/authorize', 'POST', {
    csrfHash,
    attemptId: DISCOVERY_ATTEMPT,
    stateHash: await sha256(discoveryState),
    verifierHash: await sha256(discoveryVerifier),
    attemptExpiresAt: NOW + 100_000,
    now: currentTime,
  }))).status).toBe(200);
  currentTime = NOW + 2;
  expect((await object.fetch(internalRequest('/discover/consume', 'POST', {
    attemptId: DISCOVERY_ATTEMPT,
    stateHash: await sha256(discoveryState),
    verifierHash: await sha256(discoveryVerifier),
    now: currentTime,
  }))).status).toBe(200);
  currentTime = NOW + 3;
  expect((await object.fetch(internalRequest('/discover/complete', 'POST', {
    attemptId: DISCOVERY_ATTEMPT,
    code: 'discovery_complete',
    result: {
      actor: { id: 'user-12345678', email: 'owner@example.com' },
      targets: [{
        targetIdHash: TARGET_ID_HASH,
        account: { id: ACCOUNT_ID, name: 'Primary account' },
        zone: { id: ZONE_ID, name: 'example.com', status: 'active' },
      }],
    },
    grantRevocation: 'confirmed',
    completedAt: currentTime,
  }))).status).toBe(200);
  currentTime = NOW + 4;
  expect((await object.fetch(internalRequest('/selection', 'PUT', {
    csrfHash,
    selection: selectionInput,
    targetIdHash: TARGET_ID_HASH,
    now: currentTime,
  }))).status).toBe(200);
  const deployPlan = (await responseBody(await object.fetch(internalRequest('/plan', 'POST', {
    csrfHash,
    releaseManifest: manifest,
    planExpiresAt: NOW + 600_000,
    now: currentTime,
  })))).session.plan;
  currentTime = NOW + 5;
  expect((await object.fetch(internalRequest('/authorize', 'POST', {
    csrfHash,
    releaseManifest: manifest,
    approvedPlanId: deployPlan.planId,
    approvedPlanHash: deployPlan.planHash,
    attemptId: INSTALL_ATTEMPT,
    stateHash: await sha256('i'.repeat(43)),
    verifierHash: await sha256('j'.repeat(43)),
    attemptExpiresAt: NOW + 400_000,
    now: currentTime,
  }))).status).toBe(200);
  currentTime = NOW + 6;
  expect((await object.fetch(internalRequest('/consume', 'POST', {
    attemptId: INSTALL_ATTEMPT,
    stateHash: await sha256('i'.repeat(43)),
    verifierHash: await sha256('j'.repeat(43)),
    now: currentTime,
  }))).status).toBe(200);
  currentTime = NOW + 7;
  expect((await object.fetch(internalRequest('/complete', 'POST', {
    attemptId: INSTALL_ATTEMPT,
    code: 'existing_gateway_detected',
    completedAt: currentTime,
    installationId: null,
    grantRevocation: null,
    existingGateway: GATEWAY,
  }))).status).toBe(200);

  const rawActionKey = 'customer-action-key-never-store';
  const action = {
    actionId: `action_${'A'.repeat(32)}`,
    actionKeyHash: await sha256(rawActionKey),
    actorEmail: 'owner@example.com',
    accountId: ACCOUNT_ID,
    workerName: GATEWAY.workerName,
    workersSubdomain: 'customer-workers',
    managementOrigin: `https://${GATEWAY.managementHostname}`,
    expiresAt: planExpiresAt,
  };
  return {
    state,
    object,
    csrfHash,
    action,
    rawActionKey,
    deployPlan,
    planExpiresAt,
    setNow(value: number) { currentTime = value; },
  };
}

async function importedAuthority(input: Awaited<ReturnType<typeof returningReady>>) {
  const selection = parseDeploySelection(selectionInput);
  const target = {
    actor: { id: 'user-12345678', email: 'owner@example.com' },
    account: { id: ACCOUNT_ID, name: 'Primary account' },
    zone: { id: ZONE_ID, name: 'example.com', status: 'active' as const },
  };
  const derivedExpectation = await deriveCustomerGatewayInstallationReceiptExpectation({
    selection,
    target,
    plan: input.deployPlan,
    release: { id: manifest.release, artifactSha256: manifest.artifact.treeSha256 },
  });
  const expectation = {
    ...derivedExpectation,
    installationId: GATEWAY.installationId,
    resources: derivedExpectation.resources.map((resource) => ({
      ...resource,
      marker: `acg:v1:${GATEWAY.installationId}:${resource.key}`,
    })),
  };
  const receipt = await readyInstallationReceiptFixture(expectation);
  const portal = receipt.resources.find((resource) => resource.kind === 'portal');
  const sourceResources = receipt.resources.filter((resource) => [
    'mcp_server', 'source_access_application', 'source_access_policy',
  ].includes(resource.kind));
  if (!portal || sourceResources.length !== 3) throw new Error('returning authority fixture');
  return parseReturningUninstallImportedAuthority({
    schemaVersion: 1,
    actionId: input.action.actionId,
    status: 'authorized',
    authority: {
      schemaVersion: 1,
      installationId: GATEWAY.installationId,
      root: { receipt },
      control: {
        schemaVersion: 1,
        installationId: GATEWAY.installationId,
        accountId: ACCOUNT_ID,
        portal: {
          id: portal.provider.id,
          name: GATEWAY.name,
          hostname: GATEWAY.portalHostname,
          marker: portal.marker,
        },
        audienceEmails: ['owner@example.com'],
        sourceOwnership: [{ sourceId: `source-${'1'.repeat(16)}`, resources: sourceResources }],
      },
      sources: {
        schemaVersion: 1,
        revision: 1,
        applyMode: 'oauth_per_action',
        sources: [{
          id: `source-${'1'.repeat(16)}`,
          label: 'Company context',
          url: 'https://source.example.net/mcp',
          authMode: 'none',
          enabledTools: ['company_search', 'company_prepare'],
          status: 'installed',
        }],
      },
      runtime: {
        release: manifest.release,
        artifactSha256: `sha256:${manifest.artifact.treeSha256}`,
        updateChannel: 'stable',
        updateKeyId: 'test-key',
        updatePublicKey: 'A'.repeat(43),
        accountId: ACCOUNT_ID,
        zoneId: ZONE_ID,
        zoneName: 'example.com',
        workerName: GATEWAY.workerName,
        workersSubdomain: input.action.workersSubdomain,
        managementHostname: GATEWAY.managementHostname,
      },
    },
  }, {
    actionId: input.action.actionId,
    actorEmail: input.action.actorEmail,
    installationId: GATEWAY.installationId,
    accountId: ACCOUNT_ID,
    workerName: GATEWAY.workerName,
    workersSubdomain: input.action.workersSubdomain,
    managementOrigin: input.action.managementOrigin,
    portalHostname: GATEWAY.portalHostname,
    gatewayName: GATEWAY.name,
  });
}

async function prepareReturning(input: Awaited<ReturnType<typeof returningReady>>) {
  const response = await input.object.fetch(internalRequest('/returning-uninstall/plan', 'POST', {
    csrfHash: input.csrfHash,
    action: input.action,
    planExpiresAt: input.planExpiresAt,
    now: NOW + 8,
  }));
  return { response, payload: await responseBody(response) };
}

describe('GatewayDeploySession returning-customer uninstall lifecycle', () => {
  it('loads only the exact installed release identity and rejects an injected cross-channel bundle', async () => {
    const prepared = await returningReady();
    const authority = await importedAuthority(prepared);
    let requested: unknown = null;
    await expect(loadInstalledReturningUninstallReleaseBundle(async (identity) => {
      requested = identity;
      return verifiedReleaseBundle;
    }, authority)).resolves.toBe(verifiedReleaseBundle);
    expect(requested).toEqual({
      schemaVersion: 1,
      channel: 'stable',
      release: manifest.release,
      keyId: 'test-key',
      publicKey: 'A'.repeat(43),
      artifactSha256: manifest.artifact.treeSha256,
    });

    const replay = Object.freeze({
      ...verifiedReleaseBundle,
      channel: 'canary',
      envelope: Object.freeze({ ...verifiedReleaseBundle.envelope, channel: 'canary' }),
    });
    await expect(loadInstalledReturningUninstallReleaseBundle(
      async () => replay,
      authority,
    )).rejects.toMatchObject({ code: 'release_invalid', status: 503 });
  });

  it('plans, authorizes, consumes, records a failed completion, and rejects every replay while retaining no raw proof', async () => {
    const prepared = await returningReady();
    prepared.setNow(NOW + 8);
    const planned = await prepareReturning(prepared);
    expect(planned.response.status).toBe(200);
    expect(planned.payload.returningUninstall).toMatchObject({
      schemaVersion: 1,
      status: 'planned',
      result: null,
      plan: {
        gateway: GATEWAY,
        writesPerformed: false,
        authority: 'customer_receipt_one_time_action',
      },
    });

    const serializedPlanned = JSON.stringify([...prepared.state.storage.values.values()]);
    expect(serializedPlanned).not.toContain(prepared.rawActionKey);
    expect(serializedPlanned).not.toMatch(/access[_-]?token|refresh[_-]?token|client[_-]?secret/iu);
    const publicPlanned = await responseBody(await prepared.object.fetch(internalRequest('/public', 'GET')));
    expect(JSON.stringify(publicPlanned.returningUninstall)).not.toMatch(
      /actionId|actionKey|actorEmail|accountId|stateHash|verifierHash|attemptId|workersSubdomain/iu,
    );

    const plan = planned.payload.returningUninstall.plan;
    const stateValue = 's'.repeat(43);
    const verifier = 'v'.repeat(43);
    prepared.setNow(NOW + 9);
    const authorizeInput = {
      csrfHash: prepared.csrfHash,
      approvedPlanId: plan.planId,
      approvedPlanHash: plan.planHash,
      attemptId: RETURNING_ATTEMPT,
      stateHash: await sha256(stateValue),
      verifierHash: await sha256(verifier),
      attemptExpiresAt: prepared.planExpiresAt,
      now: NOW + 9,
    };
    expect((await prepared.object.fetch(internalRequest(
      '/returning-uninstall/authorize', 'POST', authorizeInput,
    ))).status).toBe(200);
    expect((await prepared.object.fetch(internalRequest(
      '/returning-uninstall/authorize', 'POST', authorizeInput,
    ))).status).toBe(409);

    const consumeInput = {
      attemptId: RETURNING_ATTEMPT,
      stateHash: await sha256(stateValue),
      verifierHash: await sha256(verifier),
      actionKeyHash: prepared.action.actionKeyHash,
      now: NOW + 10,
    };
    prepared.setNow(NOW + 10);
    const consumed = await prepared.object.fetch(internalRequest(
      '/returning-uninstall/consume', 'POST', consumeInput,
    ));
    expect(consumed.status).toBe(200);
    expect(await responseBody(consumed)).toMatchObject({
      plan,
      action: { actionId: prepared.action.actionId, actionKeyHash: prepared.action.actionKeyHash },
      actor: { id: 'user-12345678', email: 'owner@example.com' },
      discoveredTarget: { account: { id: ACCOUNT_ID }, zone: { id: ZONE_ID } },
    });
    const replay = await prepared.object.fetch(internalRequest(
      '/returning-uninstall/consume', 'POST', consumeInput,
    ));
    expect(replay.status).toBe(400);
    expect(await responseBody(replay)).toEqual({ error: { code: 'oauth_state_invalid' } });

    prepared.setNow(NOW + 11);
    const prematureSuccess = await prepared.object.fetch(internalRequest('/returning-uninstall/complete', 'POST', {
      attemptId: RETURNING_ATTEMPT,
      code: 'returning_uninstall_complete',
      completedAt: NOW + 11,
      installationId: GATEWAY.installationId,
      grantRevocation: 'confirmed',
    }));
    expect(prematureSuccess.status).toBe(409);
    const completed = await prepared.object.fetch(internalRequest('/returning-uninstall/complete', 'POST', {
      attemptId: RETURNING_ATTEMPT,
      code: 'internal_error',
      completedAt: NOW + 11,
      installationId: null,
      grantRevocation: null,
      reason: 'provider_unavailable',
    }));
    expect(completed.status).toBe(200);
    expect(await responseBody(completed)).toMatchObject({
      returningUninstall: {
        status: 'failed',
        result: {
          code: 'internal_error',
          reason: 'provider_unavailable',
        },
      },
    });
    expect((await prepared.object.fetch(internalRequest('/returning-uninstall/complete', 'POST', {
      attemptId: RETURNING_ATTEMPT,
      code: 'internal_error',
      completedAt: NOW + 12,
      installationId: null,
      grantRevocation: null,
    }))).status).toBe(409);
  });

  it('binds the plan to CSRF, actor, account, gateway, exact approval, and one-time action proof', async () => {
    const cases: Array<(prepared: Awaited<ReturnType<typeof returningReady>>) => unknown> = [
      (prepared) => ({ ...prepared.action, actorEmail: 'other@example.com' }),
      (prepared) => ({ ...prepared.action, accountId: 'f'.repeat(32) }),
      (prepared) => ({ ...prepared.action, workerName: 'another-worker' }),
      (prepared) => ({ ...prepared.action, managementOrigin: 'https://other.example.com' }),
    ];
    for (const mutate of cases) {
      const prepared = await returningReady();
      prepared.setNow(NOW + 8);
      const rejected = await prepared.object.fetch(internalRequest('/returning-uninstall/plan', 'POST', {
        csrfHash: prepared.csrfHash,
        action: mutate(prepared),
        planExpiresAt: prepared.planExpiresAt,
        now: NOW + 8,
      }));
      expect(rejected.status).toBe(409);
    }

    const prepared = await returningReady();
    prepared.setNow(NOW + 8);
    const planned = await prepareReturning(prepared);
    const plan = planned.payload.returningUninstall.plan;
    const forgedCsrf = await prepared.object.fetch(internalRequest('/returning-uninstall/authorize', 'POST', {
      csrfHash: await sha256('x'.repeat(43)),
      approvedPlanId: plan.planId,
      approvedPlanHash: plan.planHash,
      attemptId: RETURNING_ATTEMPT,
      stateHash: await sha256('s'.repeat(43)),
      verifierHash: await sha256('v'.repeat(43)),
      attemptExpiresAt: prepared.planExpiresAt,
      now: NOW + 9,
    }));
    expect(forgedCsrf.status).toBe(403);

    const changedApproval = await prepared.object.fetch(internalRequest('/returning-uninstall/authorize', 'POST', {
      csrfHash: prepared.csrfHash,
      approvedPlanId: plan.planId,
      approvedPlanHash: `sha256:${'0'.repeat(64)}`,
      attemptId: RETURNING_ATTEMPT,
      stateHash: await sha256('s'.repeat(43)),
      verifierHash: await sha256('v'.repeat(43)),
      attemptExpiresAt: prepared.planExpiresAt,
      now: NOW + 9,
    }));
    expect(changedApproval.status).toBe(409);

    expect((await prepared.object.fetch(internalRequest('/returning-uninstall/authorize', 'POST', {
      csrfHash: prepared.csrfHash,
      approvedPlanId: plan.planId,
      approvedPlanHash: plan.planHash,
      attemptId: RETURNING_ATTEMPT,
      stateHash: await sha256('s'.repeat(43)),
      verifierHash: await sha256('v'.repeat(43)),
      attemptExpiresAt: prepared.planExpiresAt,
      now: NOW + 9,
    }))).status).toBe(200);
    prepared.setNow(NOW + 10);
    const wrongProof = await prepared.object.fetch(internalRequest('/returning-uninstall/consume', 'POST', {
      attemptId: RETURNING_ATTEMPT,
      stateHash: await sha256('s'.repeat(43)),
      verifierHash: await sha256('v'.repeat(43)),
      actionKeyHash: await sha256('forged-action-key'),
      now: NOW + 10,
    }));
    expect(wrongProof.status).toBe(400);
    expect(await responseBody(wrongProof)).toEqual({ error: { code: 'oauth_state_invalid' } });
  });

  it('rejects authorization and consumption at expiry, and allows a new action only after a failed attempt', async () => {
    const expiring = await returningReady(NOW + 20);
    expiring.setNow(NOW + 8);
    const planned = await prepareReturning(expiring);
    const plan = planned.payload.returningUninstall.plan;
    expect((await expiring.object.fetch(internalRequest('/returning-uninstall/authorize', 'POST', {
      csrfHash: expiring.csrfHash,
      approvedPlanId: plan.planId,
      approvedPlanHash: plan.planHash,
      attemptId: RETURNING_ATTEMPT,
      stateHash: await sha256('s'.repeat(43)),
      verifierHash: await sha256('v'.repeat(43)),
      attemptExpiresAt: expiring.planExpiresAt,
      now: NOW + 9,
    }))).status).toBe(200);
    expiring.setNow(expiring.planExpiresAt);
    expect((await expiring.object.fetch(internalRequest('/returning-uninstall/consume', 'POST', {
      attemptId: RETURNING_ATTEMPT,
      stateHash: await sha256('s'.repeat(43)),
      verifierHash: await sha256('v'.repeat(43)),
      actionKeyHash: expiring.action.actionKeyHash,
      now: expiring.planExpiresAt,
    }))).status).toBe(400);

    const retryable = await returningReady();
    retryable.setNow(NOW + 8);
    const retryPlan = (await prepareReturning(retryable)).payload.returningUninstall.plan;
    expect((await retryable.object.fetch(internalRequest('/returning-uninstall/authorize', 'POST', {
      csrfHash: retryable.csrfHash,
      approvedPlanId: retryPlan.planId,
      approvedPlanHash: retryPlan.planHash,
      attemptId: RETURNING_ATTEMPT,
      stateHash: await sha256('s'.repeat(43)),
      verifierHash: await sha256('v'.repeat(43)),
      attemptExpiresAt: retryable.planExpiresAt,
      now: NOW + 9,
    }))).status).toBe(200);
    retryable.setNow(NOW + 10);
    expect((await retryable.object.fetch(internalRequest('/returning-uninstall/consume', 'POST', {
      attemptId: RETURNING_ATTEMPT,
      stateHash: await sha256('s'.repeat(43)),
      verifierHash: await sha256('v'.repeat(43)),
      actionKeyHash: retryable.action.actionKeyHash,
      now: NOW + 10,
    }))).status).toBe(200);
    retryable.setNow(NOW + 11);
    expect((await retryable.object.fetch(internalRequest('/returning-uninstall/complete', 'POST', {
      attemptId: RETURNING_ATTEMPT,
      code: 'internal_error',
      completedAt: NOW + 11,
      installationId: null,
      grantRevocation: null,
      reason: 'provider_unavailable',
    }))).status).toBe(200);

    retryable.setNow(NOW + 12);
    const sameAction = await prepareReturning(retryable);
    expect(sameAction.response.status).toBe(409);
    const nextAction = {
      ...retryable.action,
      actionId: `action_${'N'.repeat(32)}`,
      actionKeyHash: await sha256('new-one-time-action-key'),
    };
    const replanned = await retryable.object.fetch(internalRequest('/returning-uninstall/plan', 'POST', {
      csrfHash: retryable.csrfHash,
      action: nextAction,
      planExpiresAt: retryable.planExpiresAt,
      now: NOW + 12,
    }));
    expect(replanned.status).toBe(200);
    expect(await responseBody(replanned)).toMatchObject({ returningUninstall: { status: 'planned' } });
  });

  it('mints hosted recovery authority only after customer gateway removal is durably verified', async () => {
    const prepared = await returningReady();
    prepared.setNow(NOW + 8);
    const plan = (await prepareReturning(prepared)).payload.returningUninstall.plan;
    const state = 's'.repeat(43);
    const verifier = 'v'.repeat(43);
    expect((await prepared.object.fetch(internalRequest('/returning-uninstall/authorize', 'POST', {
      csrfHash: prepared.csrfHash,
      approvedPlanId: plan.planId,
      approvedPlanHash: plan.planHash,
      attemptId: RETURNING_ATTEMPT,
      stateHash: await sha256(state),
      verifierHash: await sha256(verifier),
      attemptExpiresAt: prepared.planExpiresAt,
      now: NOW + 9,
    }))).status).toBe(200);
    prepared.setNow(NOW + 10);
    const consumed = await responseBody(await prepared.object.fetch(internalRequest(
      '/returning-uninstall/consume', 'POST', {
        attemptId: RETURNING_ATTEMPT,
        stateHash: await sha256(state),
        verifierHash: await sha256(verifier),
        actionKeyHash: prepared.action.actionKeyHash,
        now: NOW + 10,
      },
    )));
    const authority = await importedAuthority(prepared);
    expect({
      schemaVersion: 1,
      installationId: authority.installationId,
      name: authority.control.portal.name,
      managementHostname: authority.runtime.managementHostname,
      portalHostname: authority.control.portal.hostname,
      workerName: authority.runtime.workerName,
    }).toEqual(plan.gateway);
    let journal = await createReturningUninstallJournal({
      now: NOW + 11,
      plan,
      authority,
      attemptId: RETURNING_ATTEMPT,
      approvedAt: consumed.approvedAt,
      accountId: ACCOUNT_ID,
      zoneId: ZONE_ID,
      recoverUntil: plan.createdAt + 86_400_000,
    });
    journal = await acquireReturningUninstallLease(journal, {
      expectedRevision: journal.revision,
      attemptId: RETURNING_ATTEMPT,
      now: NOW + 11,
      expiresAt: NOW + 100,
    });
    let clock = NOW + 12;
    const appendVerified = async (name: 'surface_preflight' | 'customer_gateway_remove') => {
      const record = { schemaVersion: 1, name };
      const locator = { schemaVersion: 1, status: 'verified', name };
      journal = await prepareReturningUninstallAction(journal, {
        expectedRevision: journal.revision, attemptId: RETURNING_ATTEMPT, now: clock++, name, record,
      });
      journal = await armReturningUninstallAction(journal, {
        expectedRevision: journal.revision, attemptId: RETURNING_ATTEMPT, now: clock++, name,
      });
      journal = await submitReturningUninstallAction(journal, {
        expectedRevision: journal.revision, attemptId: RETURNING_ATTEMPT, now: clock++, name, locator,
      });
      journal = await verifyReturningUninstallAction(journal, {
        expectedRevision: journal.revision, attemptId: RETURNING_ATTEMPT, now: clock++, name, locator,
      });
    };
    await appendVerified('surface_preflight');
    prepared.state.storage.values.set('returning-uninstall-journal-v1', structuredClone(journal));
    prepared.setNow(clock);
    expect((await prepared.object.fetch(internalRequest('/returning-uninstall/complete', 'POST', {
      attemptId: RETURNING_ATTEMPT,
      code: 'internal_error',
      completedAt: clock,
      installationId: null,
      grantRevocation: null,
      reason: 'provider_unavailable',
    }))).status).toBe(200);

    const recoveryNow = prepared.planExpiresAt + 1;
    prepared.setNow(recoveryNow);
    const preBoundary = await prepared.object.fetch(internalRequest(
      '/returning-uninstall/recovery/plan', 'POST', {
        csrfHash: prepared.csrfHash,
        planExpiresAt: recoveryNow + 300_000,
        now: recoveryNow,
      },
    ));
    expect(preBoundary.status).toBe(409);

    await appendVerified('customer_gateway_remove');
    prepared.state.storage.values.set('returning-uninstall-journal-v1', structuredClone(journal));
    const retainedJournal = await prepared.object.fetch(internalRequest('/returning-uninstall-journal', 'GET'));
    expect({ status: retainedJournal.status, body: await responseBody(retainedJournal) }).toEqual({
      status: 200,
      body: expect.any(Object),
    });
    const recoveryPlanResponse = await prepared.object.fetch(internalRequest(
      '/returning-uninstall/recovery/plan', 'POST', {
        csrfHash: prepared.csrfHash,
        planExpiresAt: recoveryNow + 300_000,
        now: recoveryNow,
      },
    ));
    const recoveryPlanBody = await responseBody(recoveryPlanResponse);
    expect({ status: recoveryPlanResponse.status, body: recoveryPlanBody }).toEqual({
      status: 200,
      body: expect.any(Object),
    });
    const recoveryPlan = recoveryPlanBody.returningUninstall;
    expect(recoveryPlan).toMatchObject({ status: 'planned', recoveryAvailable: true });

    const recoveryAttempt = `att_${'H'.repeat(32)}`;
    const recoveryState = 'h'.repeat(43);
    const recoveryVerifier = 'k'.repeat(43);
    prepared.setNow(recoveryNow + 1);
    const originalDiscovery = structuredClone(
      prepared.state.storage.values.get('cloudflare-discovery-v1'),
    ) as Record<string, any>;
    const wrongActor = structuredClone(originalDiscovery);
    wrongActor.result.actor.email = 'other@example.com';
    prepared.state.storage.values.set('cloudflare-discovery-v1', wrongActor);
    expect((await prepared.object.fetch(internalRequest(
      '/returning-uninstall/recovery/authorize', 'POST', {
        csrfHash: prepared.csrfHash,
        approvedPlanId: recoveryPlan.plan.planId,
        approvedPlanHash: recoveryPlan.plan.planHash,
        attemptId: recoveryAttempt,
        stateHash: await sha256(recoveryState),
        verifierHash: await sha256(recoveryVerifier),
        attemptExpiresAt: recoveryPlan.plan.expiresAt,
        now: recoveryNow + 1,
      },
    ))).status).toBe(409);
    const wrongAccount = structuredClone(originalDiscovery);
    wrongAccount.result.targets[0].account.id = 'f'.repeat(32);
    prepared.state.storage.values.set('cloudflare-discovery-v1', wrongAccount);
    expect((await prepared.object.fetch(internalRequest(
      '/returning-uninstall/recovery/authorize', 'POST', {
        csrfHash: prepared.csrfHash,
        approvedPlanId: recoveryPlan.plan.planId,
        approvedPlanHash: recoveryPlan.plan.planHash,
        attemptId: recoveryAttempt,
        stateHash: await sha256(recoveryState),
        verifierHash: await sha256(recoveryVerifier),
        attemptExpiresAt: recoveryPlan.plan.expiresAt,
        now: recoveryNow + 1,
      },
    ))).status).toBe(409);
    prepared.state.storage.values.set('cloudflare-discovery-v1', originalDiscovery);
    expect((await prepared.object.fetch(internalRequest(
      '/returning-uninstall/recovery/authorize', 'POST', {
        csrfHash: await sha256('x'.repeat(43)),
        approvedPlanId: recoveryPlan.plan.planId,
        approvedPlanHash: recoveryPlan.plan.planHash,
        attemptId: recoveryAttempt,
        stateHash: await sha256(recoveryState),
        verifierHash: await sha256(recoveryVerifier),
        attemptExpiresAt: recoveryPlan.plan.expiresAt,
        now: recoveryNow + 1,
      },
    ))).status).toBe(403);
    const authorized = await prepared.object.fetch(internalRequest(
      '/returning-uninstall/recovery/authorize', 'POST', {
        csrfHash: prepared.csrfHash,
        approvedPlanId: recoveryPlan.plan.planId,
        approvedPlanHash: recoveryPlan.plan.planHash,
        attemptId: recoveryAttempt,
        stateHash: await sha256(recoveryState),
        verifierHash: await sha256(recoveryVerifier),
        attemptExpiresAt: recoveryPlan.plan.expiresAt,
        now: recoveryNow + 1,
      },
    ));
    expect(await responseBody(authorized)).toEqual({
      accepted: true,
      actorEmail: 'owner@example.com',
      accountId: ACCOUNT_ID,
      zoneId: ZONE_ID,
    });
    prepared.setNow(recoveryNow + 2);
    expect((await prepared.object.fetch(internalRequest(
      '/returning-uninstall/recovery/consume', 'POST', {
        attemptId: recoveryAttempt,
        stateHash: await sha256('z'.repeat(43)),
        verifierHash: await sha256(recoveryVerifier),
        now: recoveryNow + 2,
      },
    ))).status).toBe(400);
    const recovered = await prepared.object.fetch(internalRequest(
      '/returning-uninstall/recovery/consume', 'POST', {
        attemptId: recoveryAttempt,
        stateHash: await sha256(recoveryState),
        verifierHash: await sha256(recoveryVerifier),
        now: recoveryNow + 2,
      },
    ));
    expect(recovered.status).toBe(200);
    const recoveredBody = await responseBody(recovered);
    expect(JSON.stringify(recoveredBody)).not.toMatch(/actionKey|actionKeyHash|workersSubdomain/iu);
    expect((await prepared.object.fetch(internalRequest(
      '/returning-uninstall/recovery/consume', 'POST', {
        attemptId: recoveryAttempt,
        stateHash: await sha256(recoveryState),
        verifierHash: await sha256(recoveryVerifier),
        now: recoveryNow + 2,
      },
    ))).status).toBe(400);
    const currentJournal = (await responseBody(await prepared.object.fetch(internalRequest(
      '/returning-uninstall-journal', 'GET',
    )))).journal;
    prepared.setNow(recoveryNow + 3);
    const approvedRecovery = await prepared.object.fetch(internalRequest(
      '/returning-uninstall-journal/approval/hosted-recovery', 'POST', {
        expectedRevision: currentJournal.revision,
        attemptId: recoveryAttempt,
        approvedAt: recoveredBody.approvedAt,
        now: recoveryNow + 3,
        plan: recoveredBody.plan,
        actorEmail: 'owner@example.com',
        accountId: ACCOUNT_ID,
        zoneId: ZONE_ID,
      },
    ));
    expect((await responseBody(approvedRecovery)).journal.approvalHistory.at(-1)).toMatchObject({
      authorization: 'hosted_recovery',
      attemptId: recoveryAttempt,
      actionId: prepared.action.actionId,
      actorEmail: 'owner@example.com',
    });
    prepared.setNow(journal.recoverUntil);
    expect((await prepared.object.fetch(internalRequest(
      '/returning-uninstall/recovery/plan', 'POST', {
        csrfHash: prepared.csrfHash,
        planExpiresAt: journal.recoverUntil + 1,
        now: journal.recoverUntil,
      },
    ))).status).toBe(409);
    expect(JSON.stringify([...prepared.state.storage.values.values()])).not.toMatch(
      /customer-action-key-never-store|access[_-]?token|refresh[_-]?token|client[_-]?secret/iu,
    );
  });
});

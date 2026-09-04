import { describe, expect, it } from 'vitest';

import { PUBLIC_ORIGIN } from '../src/constants';
import { base64UrlEncode } from '../src/crypto';
import {
  CustomerBootstrapRequestError,
  prepareCustomerBootstrapClaimFromPlan,
  submitCustomerBootstrapFromPlan,
} from '../src/customer-bootstrap-request';
import { customerPayloadEnvironment } from '../src/customer-payload-environment';
import { buildStaticDeployPlan, parseDeploySelection } from '../src/schema';
import type { StaticDeployPlan } from '../src/schema';
import { manifest, selectionInput } from './fixtures';
// The real customer payload, exactly as shipped in the release. The shell
// runs it in-process, so its bootstrap must verify the shell's own request
// under the environment the shell gives it, not under a fixture.
// @ts-expect-error The payload is validated as a release input, not a TS package.
import { processBootstrap } from '../../../payload/worker/index.js';

const TOKEN = 'ephemeral-cloudflare-oauth-grant-never-store';
const KEY = base64UrlEncode(Uint8Array.from({ length: 32 }, (_, index) => index + 1));
const NONCE = base64UrlEncode(Uint8Array.from({ length: 32 }, (_, index) => index + 33));
// The converger's target: the account and zone the plan was approved for.
const target = Object.freeze({ accountId: '1'.repeat(32), zoneId: '2'.repeat(32), zoneName: 'example.com' });
// Storage that is not reachable: the payload then answers with a recovery
// result right after verification, which proves verification passed
// without reaching any provider.
const offlineStorage = { get: async () => { throw new Error('storage offline'); } };

async function approvedPlan(nowMs: number): Promise<StaticDeployPlan> {
  return buildStaticDeployPlan(parseDeploySelection(selectionInput), manifest, nowMs + 30 * 60_000);
}

/** The bindings the hosted Stage 1 deploy gives the shell: nothing about the zone. */
function stageOneEnvironment(plan: StaticDeployPlan) {
  const worker = plan.managementResources.find((resource) => resource.kind === 'management_worker');
  if (!worker) throw new TypeError('plan fixture has no management worker');
  return Object.freeze({
    CLOUDFLARE_ACCOUNT_ID: target.accountId,
    ANKKA_INSTALL_ID: plan.managementOwnershipMarker,
    ANKKA_WORKER_NAME: worker.name,
    ANKKA_GATEWAY_RELEASE: plan.releaseId,
    ANKKA_GATEWAY_RELEASE_SHA256: `sha256:${plan.releaseArtifactSha256}`,
    ANKKA_PLAN_ID: plan.planId,
    ANKKA_PLAN_HASH: plan.planHash,
    ANKKA_BOOTSTRAP_ID: `boot_${'a'.repeat(24)}`,
    ANKKA_BOOTSTRAP_SECRET_SHA256: `sha256:${'b'.repeat(64)}`,
    ANKKA_BOOTSTRAP_EXPIRES_AT: '1900000000000',
    ANKKA_BOOTSTRAP_CALLBACK: `https://${worker.name}.tenant.workers.dev/__ankka/install/oauth/callback`,
    ANKKA_INSTALLER_ORIGIN: PUBLIC_ORIGIN,
    ANKKA_MANAGEMENT_HOSTNAME: plan.gatewayConfiguration.managementHostname,
    ANKKA_UPDATE_CHANNEL: 'canary',
    ANKKA_UPDATE_KEY_ID: 'release-2026-09-dev1',
    ANKKA_UPDATE_PUBLIC_KEY: KEY,
    CLOUDFLARE_CUSTOMER_OAUTH_CLIENT_ID: 'c'.repeat(32),
    CLOUDFLARE_OWNERSHIP_ISSUER_PUBLIC_KEY: KEY,
    CLOUDFLARE_OWNERSHIP_ISSUER_KEY_ID: 'issuer-2026-09',
    ANKKA_GATEWAY_OWNERSHIP_WRAP_KEY: KEY,
    ANKKA_BOOTSTRAP_NONCE: NONCE,
  });
}

type StageOneEnvironment = ReturnType<typeof stageOneEnvironment>;
type PayloadEnvironment = StageOneEnvironment | ReturnType<typeof customerPayloadEnvironment<StageOneEnvironment>>;

function converge(plan: StaticDeployPlan, nowMs: number, environment: PayloadEnvironment) {
  // Exactly the converger's call in convergeGatewayResources, with the
  // adapter the shell entrypoint wires: processBootstrap in-process.
  return submitCustomerBootstrapFromPlan({
    plan,
    target,
    accountWorkersSubdomain: { accountId: target.accountId, subdomain: 'tenant' },
    bootstrapNonce: NONCE,
    cloudflareAccessToken: TOKEN,
    transport: async (request: Request) => {
      const response = await processBootstrap(request, environment, offlineStorage);
      Object.defineProperty(response, 'url', { configurable: true, value: request.url });
      return response;
    },
    timeoutMs: 120_000,
    nowMs,
  });
}

describe('the shell bootstrap request against the shipped payload', () => {
  it('identifies the install the same way on both sides', async () => {
    const nowMs = Date.now();
    const plan = await approvedPlan(nowMs);
    const claim = await prepareCustomerBootstrapClaimFromPlan({ plan, target, nowMs });
    expect(claim.expected.installationId).toBe(plan.managementOwnershipMarker);
  });

  it('is rejected under the bare Stage 1 bindings, which is the live failure of 2026-09-04', async () => {
    const nowMs = Date.now();
    const plan = await approvedPlan(nowMs);
    await expect(converge(plan, nowMs, stageOneEnvironment(plan)))
      .rejects.toSatisfy((error: CustomerBootstrapRequestError) => {
        expect(error).toBeInstanceOf(CustomerBootstrapRequestError);
        expect(error.code).toBe('bootstrap_rejected');
        return true;
      });
  });

  it('verifies once the shell completes the payload environment with the zone and readiness', async () => {
    const nowMs = Date.now();
    const plan = await approvedPlan(nowMs);
    await expect(converge(plan, nowMs, customerPayloadEnvironment(stageOneEnvironment(plan), target)))
      .resolves.toMatchObject({ status: 'recovery_required', reason: 'bootstrap_recovery_required' });
  });
});

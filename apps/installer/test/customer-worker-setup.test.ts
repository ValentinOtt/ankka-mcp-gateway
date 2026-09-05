import { buildBootstrapDeployPlan } from '../src/bootstrap-plan';
import { issueCloudflareBootstrapOwnershipHandoff } from '../src/cloudflare-bootstrap-ownership-handoff';
import { verifyCloudflareGatewayOwnershipCertificate } from '../src/cloudflare-gateway-ownership-proof';
import { base64UrlEncode } from '../src/crypto';
import { acceptCustomerGatewayOwnershipHandoff, initializeCustomerGatewayOwnershipState, openCustomerGatewayOwnershipPrivateKey, type CustomerGatewayOwnershipStorage } from '../src/customer-gateway-ownership-state';
import { createCustomerWorkerSetup } from '../src/customer-worker-setup';
import type { SetupZone } from '../src/hosted-account-setup';
import { parseDeploySelection, verifyStaticDeployPlanIntegrity } from '../src/schema';
import { certifyWorkerSetup, issueWorkerSetupPermit, setupConfigurationRequestSchema, signWorkerSetupConfiguration, verifyWorkerSetupPermit } from '../src/worker-setup-permit';
import * as v from 'valibot';
import { CLIENT_ID, ENCRYPTION_KEY, manifest, NOW, selectionInput } from './fixtures';

class MemoryStorage implements CustomerGatewayOwnershipStorage {
  readonly values = new Map<string, unknown>();
  async get<Value = unknown>(key: string): Promise<Value | undefined> {
    // SAFETY: mirrors the Durable Object storage contract; readers validate stored values.
    return structuredClone(this.values.get(key)) as Value | undefined;
  }
  async put<Value>(key: string, value: Value): Promise<void> { this.values.set(key, structuredClone(value)); }
}

async function fixture(availableZones: readonly SetupZone[] = [{ id: 'e'.repeat(32), name: 'example.com' }]) {
  const issuer = await crypto.subtle.generateKey('Ed25519', true, ['sign', 'verify']);
  const issuerPublicKey = base64UrlEncode(new Uint8Array(await crypto.subtle.exportKey('raw', issuer.publicKey)));
  const bootstrapPlan = await buildBootstrapDeployPlan(manifest, NOW + 600_000, 'd'.repeat(32));
  const storage = new MemoryStorage();
  const ownership = await initializeCustomerGatewayOwnershipState({ storage, wrappingKey: ENCRYPTION_KEY });
  const config = {
    accountId: 'a'.repeat(32), installId: bootstrapPlan.managementOwnershipMarker,
    workerName: bootstrapPlan.workerName, planId: bootstrapPlan.planId, planHash: bootstrapPlan.planHash,
    bootstrapCallback: `https://${bootstrapPlan.workerName}.team.workers.dev/__ankka/install/oauth/callback`,
    secretCommitment: `sha256:${'9'.repeat(64)}`, expiresAt: NOW + 600_000,
    issuerPublicKey, issuerKeyId: 'ownership-key-v1', publicClientId: CLIENT_ID, wrappingKey: ENCRYPTION_KEY,
  };
  const serializedHandoff = await issueCloudflareBootstrapOwnershipHandoff({
    accountId: config.accountId, installId: config.installId, worker: { name: config.workerName, providerId: 'b'.repeat(32) },
    adminState: { binding: 'ADMIN_STATE', className: 'AdminState', storage: 'sqlite', namespaceId: 'c'.repeat(32), workerProviderId: 'b'.repeat(32) },
    bootstrapSecret: { commitment: config.secretCommitment, expiresAt: config.expiresAt },
    issuedAt: NOW, expiresAt: config.expiresAt,
    plan: { id: config.planId, hash: config.planHash }, release: { id: manifest.release, artifactSha256: manifest.artifact.treeSha256 },
  }, issuer.privateKey);
  const permit = await issueWorkerSetupPermit({
    bootstrapPlan, serializedHandoff, availableZones,
    ownershipPublicKey: ownership.publicKey, bootstrapCallback: config.bootstrapCallback,
    publicClientId: CLIENT_ID, issuerKeyId: config.issuerKeyId,
  }, issuer.privateKey);
  const calls: string[] = [];
  const certify = (request: v.InferOutput<typeof setupConfigurationRequestSchema>, now = NOW + 1) => certifyWorkerSetup({
    request, now, manifest, issuerPublicKey, issuerPrivateKey: issuer.privateKey, issuerKeyId: config.issuerKeyId, publicClientId: CLIENT_ID,
  });
  const setup = createCustomerWorkerSetup({ storage, config, now: () => NOW + 1, transport: async (input, init) => {
    const request = new Request(input, init);
    calls.push(request.url);
    expect(request.url).toBe('https://deploy.ankka.ai/api/bootstrap/configure');
    expect(request.headers.get('authorization')).toBeNull();
    expect(request.headers.get('cookie')).toBeNull();
    return Response.json(await certify(v.parse(setupConfigurationRequestSchema, await request.json())));
  } });
  const selection = parseDeploySelection({ ...selectionInput, firstSource: null });
  return { issuer, bootstrapPlan, storage, config, permit, setup, calls, selection, certify };
}

describe('configuration in the customer Worker', () => {
  it('accepts a setup permit without domains but cannot configure or certify a gateway', async () => {
    const f = await fixture([]);
    await f.setup.accept(f.permit);
    expect(await f.setup.read()).toMatchObject({ availableZones: [], selection: null, plan: null });
    await expect(f.setup.configure(f.selection)).rejects.toMatchObject({ reason: 'active_zone_required' });
    expect(f.calls).toHaveLength(0);
    expect(await f.setup.configured()).toBeNull();
    const key = await openCustomerGatewayOwnershipPrivateKey({ storage: f.storage, wrappingKey: ENCRYPTION_KEY });
    const request = await signWorkerSetupConfiguration(f.permit, f.selection, key);
    await expect(f.certify(request)).rejects.toMatchObject({ reason: 'worker_setup_invalid' });
  });

  it('reviews and edits details while preserving the deployed Worker, then binds the exact callback', async () => {
    const f = await fixture();
    await f.setup.accept(f.permit);
    expect(await f.setup.read()).toMatchObject({ availableZones: [{ name: 'example.com' }], selection: null, plan: null });
    const first = await f.setup.configure(f.selection);
    const edited = parseDeploySelection({ ...f.selection, basics: { ...f.selection.basics, gatewayName: 'Renamed Gateway', managementHostname: 'gateway.example.com' } });
    const second = await f.setup.configure(edited);
    expect(second.plan?.planHash).not.toBe(first.plan?.planHash);
    expect(second.plan?.managementOwnershipMarker).toBe(f.config.installId);
    expect(second.plan?.managementResources.find((resource) => resource.kind === 'management_worker')?.name).toBe(f.config.workerName);
    const configured = await f.setup.configured();
    if (configured === null) throw new Error('configuration missing');
    const plan = await verifyStaticDeployPlanIntegrity(JSON.parse(configured.serializedPlan));
    const certificate = await verifyCloudflareGatewayOwnershipCertificate({
      certificate: configured.ownershipCertificate, pinnedIssuerPublicKey: f.config.issuerPublicKey,
      expectedKeyId: f.config.issuerKeyId, expectedPublicClientId: CLIENT_ID,
    });
    const gatewayCallback = 'https://gateway.example.com/__ankka/install/oauth/callback';
    expect(certificate.statement.gatewayCallback).toBe(gatewayCallback);
    await acceptCustomerGatewayOwnershipHandoff({
      storage: f.storage, config: {
        accountId: f.config.accountId, installId: f.config.installId, workerName: f.config.workerName,
        plan: { id: f.config.planId, hash: f.config.planHash }, release: { id: plan.releaseId, artifactSha256: plan.releaseArtifactSha256 },
        bootstrapSecretCommitment: f.config.secretCommitment, bootstrapExpiresAt: f.config.expiresAt,
        bootstrapCallback: f.config.bootstrapCallback, gatewayCallback, publicClientId: CLIENT_ID,
        pinnedIssuerPublicKey: f.config.issuerPublicKey, issuerKeyId: f.config.issuerKeyId,
      }, ...configured, now: NOW + 2,
    });
    await expect(f.setup.configure(f.selection)).rejects.toThrow();
    expect(f.calls).toHaveLength(2);
  });

  it('refuses a domain outside the discovered account and an expired permit', async () => {
    const f = await fixture();
    await f.setup.accept(f.permit);
    const foreign = parseDeploySelection({ ...f.selection, basics: { ...f.selection.basics, zoneName: 'elsewhere.com', managementHostname: 'manage.elsewhere.com', portalHostname: 'mcp.elsewhere.com' } });
    await expect(f.setup.configure(foreign)).rejects.toThrow();
    expect(f.calls).toHaveLength(0);
    await expect(verifyWorkerSetupPermit(f.permit, f.config.issuerPublicKey, f.config.expiresAt)).rejects.toThrow();
  });

  it('requires proof from the exact deployed Worker, even with a valid permit', async () => {
    const f = await fixture();
    const other = await crypto.subtle.generateKey('Ed25519', true, ['sign', 'verify']);
    const request = await signWorkerSetupConfiguration(f.permit, f.selection, other.privateKey);
    await expect(f.certify(request)).rejects.toThrow();
    const altered = JSON.parse(f.permit);
    altered.statement = altered.statement.replace('example.com', 'another.com');
    await expect(f.setup.accept(JSON.stringify(altered))).rejects.toThrow();
    expect(await f.setup.configured()).toBeNull();
  });
});

import { canonicalJson } from '../src/canonical-json';
import { generateCloudflareGatewayOwnershipKeyPair, issueCloudflareGatewayOwnershipCertificate } from '../src/cloudflare-gateway-ownership-proof';
import { base64UrlEncode, sha256Hex } from '../src/crypto';
import { GATEWAY_TEARDOWN_HANDOFF_CONTEXT, type GatewayTeardownStatement } from '../src/gateway-teardown-handoff';
import { createGatewayTeardownJob } from '../src/gateway-teardown-job';
import { releaseSignatureCanonicalJson, type VerifiedReleaseBundle } from '../src/release';
import { sourceActionRuntimeFixture } from './source-action-runtime-fixture';

export const ROOT_TEST = Object.freeze({
  accountId: '1'.repeat(32), zoneId: '2'.repeat(32), workerId: '3'.repeat(32), namespaceId: '4'.repeat(32),
  workerName: 'ankka-gateway-removal-fixture', hostname: 'manage.example.com',
  installId: `acg-${'5'.repeat(24)}`, applicationId: '6'.repeat(32), policyId: '7'.repeat(32), domainId: '8'.repeat(32),
  now: 1_800_000_000_000,
});

export async function gatewayTeardownFixture() {
  const root = ROOT_TEST;
  const runtime = await sourceActionRuntimeFixture({ ...root, actorEmail: 'admin@example.com',
    managementHostname: root.hostname, workersSubdomain: 'customer' });
  const releaseKeys = await crypto.subtle.generateKey('Ed25519', true, ['sign', 'verify']);
  const releasePublic = base64UrlEncode(new Uint8Array(await crypto.subtle.exportKey('raw', releaseKeys.publicKey)));
  const signature = base64UrlEncode(new Uint8Array(await crypto.subtle.sign('Ed25519', releaseKeys.privateKey,
    new TextEncoder().encode(releaseSignatureCanonicalJson(runtime.bundle.channel, runtime.bundle.keyId, runtime.bundle.envelope.manifest)))));
  const bundle: VerifiedReleaseBundle = Object.freeze({ ...runtime.bundle, publicKey: releasePublic,
    envelope: Object.freeze({ ...runtime.bundle.envelope, signature }) });
  const identity = { ...runtime.identity, publicKey: releasePublic };
  const issuer = await crypto.subtle.generateKey('Ed25519', true, ['sign', 'verify']);
  const ownership = await generateCloudflareGatewayOwnershipKeyPair();
  const trust = {
    expectedKeyId: 'test-issuer', expectedPublicClientId: 'test_customer_client_id',
    pinnedIssuerPublicKey: base64UrlEncode(new Uint8Array(await crypto.subtle.exportKey('raw', issuer.publicKey))),
  };
  const certificate = await issueCloudflareGatewayOwnershipCertificate({
    accountId: root.accountId, installId: root.installId, worker: { name: root.workerName, providerId: root.workerId },
    adminStateNamespaceId: root.namespaceId,
    bootstrapCallback: `https://${root.workerName}.customer.workers.dev/__ankka/install/oauth/callback`,
    gatewayCallback: `https://${root.hostname}/__ankka/install/oauth/callback`, publicClientId: trust.expectedPublicClientId,
    ownershipPublicKey: ownership.publicKey, handoffSha256: `sha256:${'9'.repeat(64)}`, issuedAt: root.now, keyId: trust.expectedKeyId,
  }, issuer.privateKey);
  const statement: GatewayTeardownStatement = {
    schemaVersion: 1, purpose: 'gateway_teardown_handoff', certificateSha256: `sha256:${await sha256Hex(certificate)}`,
    actionId: `action_${'a'.repeat(32)}`, nonce: 'A'.repeat(43), issuedAt: root.now, expiresAt: root.now + 600_000,
    readyReceiptChecksum: `sha256:${'b'.repeat(64)}`, dependencyResourcesHash: `sha256:${'c'.repeat(64)}`,
    customerGrantRevocation: 'confirmed', priorGrantRevocationUnconfirmed: false, dependentResourcesAbsent: true,
    management: { zoneId: root.zoneId, hostname: root.hostname, applicationId: root.applicationId,
      applicationName: `Fixture management [${root.installId}]`, applicationAud: 'fixture-management-audience',
      policyId: root.policyId, policyName: `Fixture administrators [${root.installId}]`, domainId: root.domainId },
  };
  const sign = async (value: GatewayTeardownStatement) => {
    const serialized = canonicalJson(value);
    return canonicalJson({ schemaVersion: 1, purpose: 'gateway_teardown_handoff_envelope',
    signatureContext: GATEWAY_TEARDOWN_HANDOFF_CONTEXT, certificate, statement: serialized,
    signature: base64UrlEncode(new Uint8Array(await crypto.subtle.sign('Ed25519', ownership.privateKey,
      new TextEncoder().encode(`${GATEWAY_TEARDOWN_HANDOFF_CONTEXT}\n${serialized}`)))),
    });
  };
  const handoff = await sign(statement);
  const retirement = bundle.payload.find((entry) => entry.path === 'payload/worker-retirement/index.js');
  if (retirement === undefined) throw new Error('fixture_retirement_missing');
  const job = await createGatewayTeardownJob({ handoff, trust, release: identity, retirementModuleSha256: retirement.sha256, now: root.now });
  return { job, bundle, trust, handoff, statement, retirement, sign };
}

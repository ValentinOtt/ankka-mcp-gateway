import * as v from 'valibot';

import { buildBootstrapDeployPlan, isBootstrapPlan, verifyHostedDeployPlan, type BootstrapDeployPlan } from './bootstrap-plan';
import { canonicalJson } from './canonical-json';
import { issueCloudflareBootstrapOwnershipHandoff, verifyCloudflareBootstrapOwnershipHandoff } from './cloudflare-bootstrap-ownership-handoff';
import { issueCloudflareGatewayOwnershipCertificate } from './cloudflare-gateway-ownership-proof';
import { base64UrlEncode, sha256Hex } from './crypto';
import { CUSTOMER_INSTALL_OAUTH_CALLBACK_PATH } from './customer-install-paths';
import { DeployError } from './errors';
import { setupZonesSchema, type SetupZone } from './hosted-account-setup';
import type { ReleaseManifest } from './release-manifest';
import { buildStaticDeployPlan, parseDeploySelection, type DeploySelection } from './schema';

export const WORKER_SETUP_CERTIFY_PATH = '/api/bootstrap/configure';
const CONTEXT = 'ankka-worker-setup-permit-v1';
const REQUEST_CONTEXT = 'ankka-worker-setup-configuration-v1';
const keySchema = v.pipe(v.string(), v.regex(/^[A-Za-z0-9_-]{43}$/u));
const envelopeSchema = v.strictObject({ statement: v.pipe(v.string(), v.maxLength(48 * 1024)), signature: v.pipe(v.string(), v.regex(/^[A-Za-z0-9_-]{86}$/u)) });
const permitSchema = v.strictObject({
  purpose: v.literal(CONTEXT),
  bootstrapPlan: v.unknown(),
  serializedHandoff: v.pipe(v.string(), v.maxLength(8192)),
  availableZones: setupZonesSchema,
  ownershipPublicKey: keySchema,
  bootstrapCallback: v.pipe(v.string(), v.url()),
  publicClientId: v.pipe(v.string(), v.minLength(16), v.maxLength(128)),
  issuerKeyId: v.pipe(v.string(), v.regex(/^[a-z0-9][a-z0-9._-]{0,62}$/u)),
});
export const setupConfigurationRequestSchema = v.strictObject({
  permit: v.pipe(v.string(), v.maxLength(56 * 1024)),
  selection: v.unknown(),
  signature: v.pipe(v.string(), v.regex(/^[A-Za-z0-9_-]{86}$/u)),
});
export const configuredSetupSchema = v.strictObject({
  serializedPlan: v.pipe(v.string(), v.maxLength(32 * 1024)),
  serializedHandoff: v.pipe(v.string(), v.maxLength(8192)),
  ownershipCertificate: v.pipe(v.string(), v.maxLength(8192)),
});
export type ConfiguredSetup = v.InferOutput<typeof configuredSetupSchema>;

function invalid(): never { throw new DeployError(400, 'session_invalid', 'worker_setup_invalid'); }
function bytes(value: string): Uint8Array<ArrayBuffer> {
  try {
    const result = Uint8Array.from(atob(value.replaceAll('-', '+').replaceAll('_', '/')), (c) => c.charCodeAt(0));
    if (base64UrlEncode(result) !== value) invalid();
    return result;
  } catch { return invalid(); }
}
async function verify(publicKey: string, signature: string, message: string): Promise<void> {
  if (!v.is(keySchema, publicKey)) invalid();
  const key = await crypto.subtle.importKey('raw', bytes(publicKey), 'Ed25519', false, ['verify']);
  if (!await crypto.subtle.verify('Ed25519', key, bytes(signature), new TextEncoder().encode(message))) invalid();
}
async function sign(key: CryptoKey, message: string): Promise<string> {
  return base64UrlEncode(new Uint8Array(await crypto.subtle.sign('Ed25519', key, new TextEncoder().encode(message))));
}

export async function issueWorkerSetupPermit(input: {
  bootstrapPlan: BootstrapDeployPlan;
  serializedHandoff: string;
  availableZones: readonly SetupZone[];
  ownershipPublicKey: string;
  bootstrapCallback: string;
  publicClientId: string;
  issuerKeyId: string;
}, signingKey: CryptoKey): Promise<string> {
  const statement = canonicalJson(v.parse(permitSchema, { purpose: CONTEXT, ...input }));
  if (statement.length > 48 * 1024) invalid();
  return canonicalJson({ statement, signature: await sign(signingKey, statement) });
}

export async function verifyWorkerSetupPermit(permit: string, publicKey: string, now: number) {
  if (permit.length > 56 * 1024) invalid();
  const envelope = v.parse(envelopeSchema, JSON.parse(permit));
  if (canonicalJson(envelope) !== permit) invalid();
  await verify(publicKey, envelope.signature, envelope.statement);
  const parsed = v.parse(permitSchema, JSON.parse(envelope.statement));
  if (canonicalJson(parsed) !== envelope.statement) invalid();
  const plan = await verifyHostedDeployPlan(parsed.bootstrapPlan);
  if (!isBootstrapPlan(plan) || plan.expiresAt <= now) invalid();
  const handoff = await verifyCloudflareBootstrapOwnershipHandoff({ now, pinnedPublicKey: publicKey, serializedHandoff: parsed.serializedHandoff });
  const statement = handoff.statement;
  const callback = new URL(parsed.bootstrapCallback);
  if (statement.plan.id !== plan.planId || statement.plan.hash !== plan.planHash ||
      statement.installId !== plan.managementOwnershipMarker || statement.worker.name !== plan.workerName ||
      statement.release.id !== plan.releaseId || statement.release.artifactSha256 !== plan.releaseArtifactSha256 ||
      callback.protocol !== 'https:' || callback.username || callback.password || callback.port || callback.search || callback.hash ||
      callback.pathname !== CUSTOMER_INSTALL_OAUTH_CALLBACK_PATH ||
      !callback.hostname.startsWith(`${plan.workerName}.`) || !callback.hostname.endsWith('.workers.dev') ||
      new Set(parsed.availableZones.map((zone) => zone.id)).size !== parsed.availableZones.length) invalid();
  return { ...parsed, bootstrapPlan: plan, handoff: statement };
}

async function configurationMessage(permit: string, selection: DeploySelection): Promise<string> {
  return canonicalJson({ purpose: REQUEST_CONTEXT, permitSha256: await sha256Hex(permit), selection });
}
export async function signWorkerSetupConfiguration(permit: string, selection: DeploySelection, key: CryptoKey) {
  return { permit, selection, signature: await sign(key, await configurationMessage(permit, selection)) };
}

/** Token-free issuer: only the certified Worker key can bind its bootstrap to one eligible domain. */
export async function certifyWorkerSetup(input: {
  request: v.InferOutput<typeof setupConfigurationRequestSchema>;
  manifest: ReleaseManifest;
  issuerPublicKey: string;
  issuerPrivateKey: CryptoKey;
  issuerKeyId: string;
  publicClientId: string;
  now: number;
}): Promise<ConfiguredSetup> {
  const permit = await verifyWorkerSetupPermit(input.request.permit, input.issuerPublicKey, input.now);
  const selection = parseDeploySelection(input.request.selection);
  if (selection.firstSource !== null || !permit.availableZones.some((zone) => zone.name === selection.basics.zoneName) ||
      permit.publicClientId !== input.publicClientId || permit.issuerKeyId !== input.issuerKeyId) invalid();
  await verify(permit.ownershipPublicKey, input.request.signature, await configurationMessage(input.request.permit, selection));
  const bootstrap = permit.bootstrapPlan;
  const rebuilt = await buildBootstrapDeployPlan(input.manifest, bootstrap.expiresAt, bootstrap.installSeed);
  if (canonicalJson(rebuilt) !== canonicalJson(bootstrap)) invalid();
  const plan = await buildStaticDeployPlan(selection, input.manifest, bootstrap.expiresAt, {
    planId: bootstrap.planId, planHash: bootstrap.planHash,
    installId: bootstrap.managementOwnershipMarker, workerName: bootstrap.workerName,
  });
  const prior = permit.handoff;
  const serializedHandoff = await issueCloudflareBootstrapOwnershipHandoff({
    accountId: prior.accountId, adminState: prior.adminState, bootstrapSecret: prior.bootstrapSecret,
    expiresAt: prior.expiresAt, installId: prior.installId, issuedAt: input.now,
    plan: { id: plan.planId, hash: plan.planHash }, release: prior.release, worker: prior.worker,
  }, input.issuerPrivateKey);
  const ownershipCertificate = await issueCloudflareGatewayOwnershipCertificate({
    accountId: prior.accountId, installId: prior.installId, worker: prior.worker,
    adminStateNamespaceId: prior.adminState.namespaceId,
    bootstrapCallback: permit.bootstrapCallback,
    gatewayCallback: `https://${selection.basics.managementHostname}${CUSTOMER_INSTALL_OAUTH_CALLBACK_PATH}`,
    publicClientId: input.publicClientId, ownershipPublicKey: permit.ownershipPublicKey,
    handoffSha256: `sha256:${await sha256Hex(serializedHandoff)}`, issuedAt: input.now, keyId: input.issuerKeyId,
  }, input.issuerPrivateKey);
  return { serializedPlan: canonicalJson(plan), serializedHandoff, ownershipCertificate };
}

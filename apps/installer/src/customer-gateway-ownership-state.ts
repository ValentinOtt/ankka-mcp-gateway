import * as v from 'valibot';

import {
  proveCloudflareBootstrapOwnershipAdoption,
  verifyCloudflareBootstrapOwnershipHandoff,
  verifyCloudflareBootstrapOwnershipHistory,
  type CloudflareBootstrapOwnershipAdoptionReceipt,
} from './cloudflare-bootstrap-ownership-handoff';
import {
  generateSealedCloudflareGatewayOwnershipKeyPair,
  openSealedCloudflareGatewayOwnershipPrivateKey,
  verifyCloudflareGatewayOwnershipCertificate,
} from './cloudflare-gateway-ownership-proof';
import { canonicalJson } from './canonical-json';
import { sha256Hex } from './crypto';
import { verifyStaticDeployPlanIntegrity } from './schema';

export const CUSTOMER_GATEWAY_OWNERSHIP_STATE_KEY =
  'ankka-mcp-gateway/ownership-state/v2';

const TOKEN = /^[A-Za-z0-9_-]{43}$/u;
const SHA256 = /^sha256:[a-f0-9]{64}$/u;
const VERSION_ID = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/u;
const stateSchema = v.strictObject({
  schemaVersion: v.literal(1),
  publicKey: v.pipe(v.string(), v.regex(TOKEN)),
  sealedPrivateKey: v.pipe(v.string(), v.minLength(1), v.maxLength(4096)),
  serializedPlan: v.union([v.pipe(v.string(), v.minLength(1), v.maxLength(128 * 1024)), v.null()]),
  serializedHandoff: v.union([v.pipe(v.string(), v.minLength(1), v.maxLength(60 * 1024)), v.null()]),
  ownershipCertificate: v.union([v.pipe(v.string(), v.minLength(1), v.maxLength(60 * 1024)), v.null()]),
  certificateSha256: v.union([v.pipe(v.string(), v.regex(SHA256)), v.null()]),
  adoptionReceipt: v.union([v.record(v.string(), v.unknown()), v.null()]),
  bootstrapVersionId: v.union([v.pipe(v.string(), v.regex(VERSION_ID)), v.null()]),
  trust: v.union([v.strictObject({
    publicClientId: v.pipe(v.string(), v.minLength(16), v.maxLength(128)),
    pinnedIssuerPublicKey: v.pipe(v.string(), v.regex(TOKEN)),
    issuerKeyId: v.pipe(v.string(), v.minLength(1), v.maxLength(64)),
    bootstrapCallback: v.pipe(v.string(), v.url()),
    gatewayCallback: v.pipe(v.string(), v.url()),
  }), v.null()]),
});

export type CustomerGatewayOwnershipState = v.InferOutput<typeof stateSchema>;

export interface CustomerGatewayOwnershipStorage {
  get<Value = unknown>(key: string): Promise<Value | undefined>;
  put<Value>(key: string, value: Value): Promise<void>;
}

export interface CustomerGatewayOwnershipConfig {
  readonly accountId: string;
  readonly installId: string;
  readonly plan: { readonly id: string; readonly hash: string };
  readonly workerName: string;
  readonly release: { readonly id: string; readonly artifactSha256: string };
  readonly bootstrapSecretCommitment: string;
  readonly bootstrapExpiresAt: number;
  readonly bootstrapCallback: string;
  readonly gatewayCallback: string;
  readonly publicClientId: string;
  readonly pinnedIssuerPublicKey: string;
  readonly issuerKeyId: string;
}

function invalid(): never {
  throw new Error('customer_gateway_ownership_invalid');
}

function parseState<Value>(value: Value): CustomerGatewayOwnershipState {
  const parsed = v.safeParse(stateSchema, value);
  if (!parsed.success) invalid();
  return Object.freeze(parsed.output);
}

function exact<Left, Right>(left: Left, right: Right): boolean {
  try {
    return canonicalJson(left) === canonicalJson(right);
  } catch {
    return false;
  }
}

/** Generate the proof key in the customer Durable Object and persist ciphertext only. */
export async function initializeCustomerGatewayOwnershipState(input: {
  readonly storage: CustomerGatewayOwnershipStorage;
  readonly wrappingKey: string;
}): Promise<CustomerGatewayOwnershipState> {
  const existing = await input.storage.get(CUSTOMER_GATEWAY_OWNERSHIP_STATE_KEY);
  if (existing !== undefined) return parseState(existing);
  const generated = await generateSealedCloudflareGatewayOwnershipKeyPair(input.wrappingKey);
  const state = parseState({
    schemaVersion: 1,
    publicKey: generated.publicKey,
    sealedPrivateKey: generated.sealedPrivateKey,
    serializedPlan: null,
    serializedHandoff: null,
    ownershipCertificate: null,
    certificateSha256: null,
    adoptionReceipt: null,
    bootstrapVersionId: null,
    trust: null,
  });
  await input.storage.put(CUSTOMER_GATEWAY_OWNERSHIP_STATE_KEY, state);
  return state;
}

export async function readCustomerGatewayOwnershipState(
  storage: CustomerGatewayOwnershipStorage,
): Promise<CustomerGatewayOwnershipState> {
  const value = await storage.get(CUSTOMER_GATEWAY_OWNERSHIP_STATE_KEY);
  if (value === undefined) invalid();
  return parseState(value);
}

/**
 * Accept only one exact deploy-signed handoff/certificate pair. A retry with
 * byte-identical evidence is harmless; substitution is terminal.
 */
export async function acceptCustomerGatewayOwnershipHandoff(input: {
  readonly storage: CustomerGatewayOwnershipStorage;
  readonly config: CustomerGatewayOwnershipConfig;
  readonly serializedHandoff: string;
  readonly serializedPlan: string;
  readonly ownershipCertificate: string;
  readonly now: number;
}): Promise<CustomerGatewayOwnershipState> {
  const current = await readCustomerGatewayOwnershipState(input.storage);
  if (current.serializedHandoff !== null || current.ownershipCertificate !== null) {
    if (current.serializedHandoff !== input.serializedHandoff ||
        current.serializedPlan !== input.serializedPlan ||
        current.ownershipCertificate !== input.ownershipCertificate) invalid();
    return current;
  }
  let decodedPlan: unknown;
  try {
    decodedPlan = JSON.parse(input.serializedPlan);
    if (canonicalJson(decodedPlan) !== input.serializedPlan) invalid();
  } catch {
    invalid();
  }
  const plan = await verifyStaticDeployPlanIntegrity(decodedPlan).catch(invalid);
  const handoff = await verifyCloudflareBootstrapOwnershipHandoff({
    now: input.now,
    pinnedPublicKey: input.config.pinnedIssuerPublicKey,
    serializedHandoff: input.serializedHandoff,
  });
  const certificate = await verifyCloudflareGatewayOwnershipCertificate({
    certificate: input.ownershipCertificate,
    pinnedIssuerPublicKey: input.config.pinnedIssuerPublicKey,
    expectedKeyId: input.config.issuerKeyId,
    expectedPublicClientId: input.config.publicClientId,
  });
  const statement = handoff.statement;
  const certified = certificate.statement;
  const handoffSha256 = `sha256:${await sha256Hex(input.serializedHandoff)}`;
  if (
    statement.accountId !== input.config.accountId ||
    statement.installId !== input.config.installId ||
    (plan.bootstrapIdentity?.planId ?? statement.plan.id) !== input.config.plan.id ||
    (plan.bootstrapIdentity?.planHash ?? statement.plan.hash) !== input.config.plan.hash ||
    plan.planId !== statement.plan.id ||
    plan.planHash !== statement.plan.hash ||
    plan.managementOwnershipMarker !== statement.installId ||
    plan.releaseId !== statement.release.id ||
    plan.releaseArtifactSha256 !== statement.release.artifactSha256 ||
    plan.expiresAt <= input.now ||
    plan.managementResources.filter((resource) =>
      resource.kind === 'management_worker' && resource.name === statement.worker.name).length !== 1 ||
    statement.worker.name !== input.config.workerName ||
    statement.release.id !== input.config.release.id ||
    statement.release.artifactSha256 !== input.config.release.artifactSha256 ||
    statement.bootstrapSecret.commitment !== input.config.bootstrapSecretCommitment ||
    statement.bootstrapSecret.expiresAt !== input.config.bootstrapExpiresAt ||
    certified.accountId !== statement.accountId ||
    certified.installId !== statement.installId ||
    certified.worker.name !== statement.worker.name ||
    certified.worker.providerId !== statement.worker.providerId ||
    certified.adminStateNamespaceId !== statement.adminState.namespaceId ||
    statement.adminState.workerProviderId !== statement.worker.providerId ||
    certified.bootstrapCallback !== input.config.bootstrapCallback ||
    certified.gatewayCallback !== input.config.gatewayCallback ||
    certified.publicClientId !== input.config.publicClientId ||
    certified.ownershipKey.publicKey !== current.publicKey ||
    certified.handoffSha256 !== handoffSha256 ||
    certified.issuedAt < statement.issuedAt ||
    certified.issuedAt >= statement.expiresAt
  ) invalid();
  const next = parseState({
    ...current,
    serializedPlan: input.serializedPlan,
    serializedHandoff: input.serializedHandoff,
    ownershipCertificate: input.ownershipCertificate,
    certificateSha256: certificate.certificateSha256,
    trust: {
      publicClientId: input.config.publicClientId,
      pinnedIssuerPublicKey: input.config.pinnedIssuerPublicKey,
      issuerKeyId: input.config.issuerKeyId,
      bootstrapCallback: input.config.bootstrapCallback,
      gatewayCallback: input.config.gatewayCallback,
    },
  });
  const latest = await readCustomerGatewayOwnershipState(input.storage);
  if (!exact(latest, current)) {
    if (exact(latest, next)) return latest;
    invalid();
  }
  await input.storage.put(CUSTOMER_GATEWAY_OWNERSHIP_STATE_KEY, next);
  return next;
}

export async function adoptCustomerGatewayOwnership(input: {
  readonly storage: CustomerGatewayOwnershipStorage;
  readonly pinnedIssuerPublicKey: string;
  readonly providerReadback: unknown;
  readonly activeVersionId: string;
  readonly now: number;
}): Promise<CloudflareBootstrapOwnershipAdoptionReceipt> {
  const current = await readCustomerGatewayOwnershipState(input.storage);
  if (current.serializedHandoff === null) invalid();
  if (current.adoptionReceipt !== null) {
    if (current.bootstrapVersionId !== input.activeVersionId) invalid();
    return verifyCloudflareBootstrapOwnershipHistory({
      adoptionReceipt: current.adoptionReceipt,
      pinnedPublicKey: input.pinnedIssuerPublicKey,
      serializedHandoff: current.serializedHandoff,
    });
  }
  if (!VERSION_ID.test(input.activeVersionId) || current.bootstrapVersionId !== null) invalid();
  const receipt = await proveCloudflareBootstrapOwnershipAdoption({
    now: input.now,
    pinnedPublicKey: input.pinnedIssuerPublicKey,
    providerReadback: input.providerReadback,
    serializedHandoff: current.serializedHandoff,
  });
  const next = parseState({
    ...current,
    adoptionReceipt: receipt,
    bootstrapVersionId: input.activeVersionId,
  });
  await input.storage.put(CUSTOMER_GATEWAY_OWNERSHIP_STATE_KEY, next);
  return receipt;
}

/** Re-authenticate already-adopted ownership history without an expiring handoff check. */
export async function verifyCustomerGatewayOwnershipAdoption(input: {
  readonly storage: CustomerGatewayOwnershipStorage;
  readonly pinnedIssuerPublicKey: string;
}): Promise<Readonly<{
  receipt: CloudflareBootstrapOwnershipAdoptionReceipt;
  bootstrapVersionId: string;
}>> {
  const current = await readCustomerGatewayOwnershipState(input.storage);
  if (current.serializedHandoff === null || current.adoptionReceipt === null ||
      current.bootstrapVersionId === null) invalid();
  const receipt = await verifyCloudflareBootstrapOwnershipHistory({
    adoptionReceipt: current.adoptionReceipt,
    pinnedPublicKey: input.pinnedIssuerPublicKey,
    serializedHandoff: current.serializedHandoff,
  });
  return Object.freeze({ receipt, bootstrapVersionId: current.bootstrapVersionId });
}

export async function openCustomerGatewayOwnershipPrivateKey(input: {
  readonly storage: CustomerGatewayOwnershipStorage;
  readonly wrappingKey: string;
}): Promise<CryptoKey> {
  const current = await readCustomerGatewayOwnershipState(input.storage);
  return openSealedCloudflareGatewayOwnershipPrivateKey({
    sealedPrivateKey: current.sealedPrivateKey,
    wrappingKey: input.wrappingKey,
    expectedPublicKey: current.publicKey,
  });
}

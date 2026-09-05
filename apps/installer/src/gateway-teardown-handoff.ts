import * as v from 'valibot';

import { canonicalJson } from './canonical-json';
import {
  verifyCloudflareGatewayOwnershipCertificate,
  type VerifiedCloudflareGatewayOwnershipCertificate,
} from './cloudflare-gateway-ownership-proof';
import { base64UrlDecode, base64UrlEncode, sha256Hex } from './crypto';
import { deepFreezePlainData } from './plain-data';
import { CUSTOMER_STAGE2_ACTION_ORDER, parseCustomerStage2Journal, type CustomerStage2Journal } from './customer-stage2-journal';
import { verifyStaticDeployPlanIntegrity, type StaticDeployPlan } from './schema';

/** A separate purpose prevents a relay proof or the retired tombstone authorizing deletion. */
export const GATEWAY_TEARDOWN_HANDOFF_CONTEXT = 'ankka-gateway-teardown-handoff-v1';
export const GATEWAY_TEARDOWN_HANDOFF_TTL_MS = 10 * 60 * 1_000;
const HASH = /^sha256:[a-f0-9]{64}$/u;
const ID = /^[A-Za-z0-9_-]{1,128}$/u;
const TOKEN = /^[A-Za-z0-9_-]{43}$/u;
const time = v.pipe(v.number(), v.safeInteger(), v.minValue(0));
const digest = v.pipe(v.string(), v.regex(HASH));
const identifier = v.pipe(v.string(), v.regex(ID));
const name = v.pipe(v.string(), v.minLength(1), v.maxLength(256));

const statementSchema = v.strictObject({
  schemaVersion: v.literal(1),
  purpose: v.literal('gateway_teardown_handoff'),
  certificateSha256: digest,
  actionId: v.pipe(v.string(), v.regex(/^action_[A-Za-z0-9_-]{32}$/u)),
  nonce: v.pipe(v.string(), v.regex(TOKEN)),
  issuedAt: time,
  expiresAt: time,
  readyReceiptChecksum: digest,
  dependencyResourcesHash: digest,
  customerGrantRevocation: v.literal('confirmed'),
  dependentResourcesAbsent: v.literal(true),
  management: v.strictObject({
    zoneId: v.pipe(v.string(), v.regex(/^[a-f0-9]{32}$/u)),
    hostname: v.pipe(v.string(), v.minLength(3), v.maxLength(253)),
    applicationId: identifier,
    applicationName: name,
    applicationAud: v.pipe(v.string(), v.regex(/^[A-Za-z0-9._~-]{16,512}$/u)),
    policyId: identifier,
    policyName: name,
    domainId: identifier,
  }),
});
const envelopeSchema = v.strictObject({
  schemaVersion: v.literal(1),
  purpose: v.literal('gateway_teardown_handoff_envelope'),
  signatureContext: v.literal(GATEWAY_TEARDOWN_HANDOFF_CONTEXT),
  certificate: v.pipe(v.string(), v.minLength(1), v.maxLength(16 * 1024)),
  statement: v.pipe(v.string(), v.minLength(1), v.maxLength(8 * 1024)),
  signature: v.pipe(v.string(), v.regex(/^[A-Za-z0-9_-]{86}$/u)),
});
export type GatewayTeardownStatement = v.InferOutput<typeof statementSchema>;
export interface VerifiedGatewayTeardownHandoff {
  readonly certificate: VerifiedCloudflareGatewayOwnershipCertificate;
  readonly statement: GatewayTeardownStatement;
  readonly handoffSha256: string;
}
export interface GatewayTeardownTrust {
  readonly pinnedIssuerPublicKey: string;
  readonly expectedKeyId: string;
  readonly expectedPublicClientId: string;
}

function invalid(): never { throw new Error('teardown_handoff_invalid'); }
function payload(statement: string): Uint8Array<ArrayBuffer> {
  return new TextEncoder().encode(`${GATEWAY_TEARDOWN_HANDOFF_CONTEXT}\n${statement}`);
}

function matchCertificate(
  statement: GatewayTeardownStatement,
  certificate: VerifiedCloudflareGatewayOwnershipCertificate,
): void {
  const owner = certificate.statement;
  const management = statement.management;
  const hostname = new URL(owner.gatewayCallback).hostname;
  if (statement.certificateSha256 !== certificate.certificateSha256 ||
      management.hostname !== hostname ||
      !management.applicationName.endsWith(` management [${owner.installId}]`) ||
      !management.policyName.endsWith(` administrators [${owner.installId}]`) ||
      management.applicationName.slice(0, -` management [${owner.installId}]`.length) !==
        management.policyName.slice(0, -` administrators [${owner.installId}]`.length)) invalid();
}

/**
 * Called only after the gateway verified dependent-resource absence and revoked
 * its uninstall grant. The existing installation journal supplies management
 * locators; the browser never supplies a resource list. Management stays live
 * until the hosted finalizer has its own fresh consent and recovery journal.
 */
export async function createGatewayTeardownHandoff(input: {
  readonly certificate: string;
  readonly privateKey: CryptoKey;
  readonly trust: GatewayTeardownTrust;
  readonly plan: StaticDeployPlan;
  readonly journal: CustomerStage2Journal;
  readonly actionId: string;
  readonly nonce: string;
  readonly readyReceiptChecksum: string;
  readonly dependencyResourcesHash: string;
  readonly now: number;
  readonly customerGrantRevocation: 'confirmed';
}): Promise<string> {
  const certificate = await verifyCloudflareGatewayOwnershipCertificate({ certificate: input.certificate, ...input.trust });
  const owner = certificate.statement;
  const plan = await verifyStaticDeployPlanIntegrity(input.plan);
  const journal = parseCustomerStage2Journal(input.journal);
  if (journal === null || journal.identity.accountId !== owner.accountId ||
      journal.identity.installId !== owner.installId || journal.identity.workerName !== owner.worker.name ||
      journal.identity.workerId !== owner.worker.providerId || journal.identity.namespaceId !== owner.adminStateNamespaceId ||
      journal.identity.planId !== plan.planId || journal.identity.planHash !== plan.planHash ||
      plan.managementOwnershipMarker !== owner.installId ||
      plan.gatewayConfiguration.managementHostname !== new URL(owner.gatewayCallback).hostname) invalid();
  const resources = journal.actions.find((action) => action.name === 'gateway_resources');
  const resourcesLocator = v.parse(v.looseObject({ receiptChecksum: digest }), resources?.locator);
  if (resources?.phase !== 'verified' || resourcesLocator.receiptChecksum !== input.readyReceiptChecksum ||
      journal.actions.length !== CUSTOMER_STAGE2_ACTION_ORDER.length || journal.actions.slice(0, -1).some((action) => action.phase !== 'verified') ||
      !['send_armed', 'submitted', 'verified'].includes(journal.actions.at(-1)?.phase ?? '')) invalid();
  const application = journal.actions.find((action) => action.name === 'management_access_application');
  const policy = journal.actions.find((action) => action.name === 'management_admin_policy');
  const domain = journal.actions.find((action) => action.name === 'management_custom_domain');
  if (application?.phase !== 'verified' || policy?.phase !== 'verified' || domain?.phase !== 'verified') invalid();
  const applicationLocator = v.parse(v.strictObject({ applicationId: identifier, aud: v.string() }), application.locator);
  const policyLocator = v.parse(v.strictObject({ policyId: identifier }), policy.locator);
  const domainLocator = v.parse(v.strictObject({ domainId: identifier }), domain.locator);
  const applicationResource = plan.managementResources.find((resource) => resource.kind === 'management_access_application');
  const policyResource = plan.managementResources.find((resource) => resource.kind === 'management_access_policy');
  if (applicationResource === undefined || policyResource === undefined) invalid();
  const statement = v.parse(statementSchema, {
    schemaVersion: 1, purpose: 'gateway_teardown_handoff',
    certificateSha256: certificate.certificateSha256,
    actionId: input.actionId, nonce: input.nonce,
    issuedAt: input.now, expiresAt: input.now + GATEWAY_TEARDOWN_HANDOFF_TTL_MS,
    readyReceiptChecksum: input.readyReceiptChecksum,
    dependencyResourcesHash: input.dependencyResourcesHash,
    customerGrantRevocation: input.customerGrantRevocation, dependentResourcesAbsent: true,
    management: {
      zoneId: journal.identity.zoneId, hostname: plan.gatewayConfiguration.managementHostname,
      applicationId: applicationLocator.applicationId, applicationAud: applicationLocator.aud,
      applicationName: applicationResource.name, policyId: policyLocator.policyId,
      policyName: policyResource.name, domainId: domainLocator.domainId,
    },
  });
  matchCertificate(statement, certificate);
  const serialized = canonicalJson(statement);
  if (input.privateKey.type !== 'private' || input.privateKey.algorithm.name !== 'Ed25519' ||
      input.privateKey.extractable) invalid();
  const signature = base64UrlEncode(new Uint8Array(await crypto.subtle.sign('Ed25519', input.privateKey, payload(serialized))));
  const envelope = canonicalJson({
    schemaVersion: 1, purpose: 'gateway_teardown_handoff_envelope',
    signatureContext: GATEWAY_TEARDOWN_HANDOFF_CONTEXT,
    certificate: input.certificate, statement: serialized, signature,
  });
  // A wrong private key must fail here, before the browser leaves the gateway.
  await verifyGatewayTeardownHandoff({ handoff: envelope, trust: input.trust, now: input.now });
  return envelope;
}

/** Verify once on import; a durable finalizer job retains this exact accepted authority for recovery. */
export async function verifyGatewayTeardownHandoff(input: {
  readonly handoff: string;
  readonly trust: GatewayTeardownTrust;
  readonly now: number;
}): Promise<VerifiedGatewayTeardownHandoff> {
  if (input.handoff.length > 32 * 1024) invalid();
  const envelope = v.parse(envelopeSchema, JSON.parse(input.handoff));
  if (canonicalJson(envelope) !== input.handoff) invalid();
  const statement = v.parse(statementSchema, JSON.parse(envelope.statement));
  if (canonicalJson(statement) !== envelope.statement || !Number.isSafeInteger(input.now) ||
      statement.issuedAt > input.now || statement.expiresAt <= input.now ||
      statement.expiresAt - statement.issuedAt !== GATEWAY_TEARDOWN_HANDOFF_TTL_MS) invalid();
  const certificate = await verifyCloudflareGatewayOwnershipCertificate({ certificate: envelope.certificate, ...input.trust });
  matchCertificate(statement, certificate);
  const key = await crypto.subtle.importKey('raw', new Uint8Array(base64UrlDecode(certificate.statement.ownershipKey.publicKey)), 'Ed25519', false, ['verify']);
  if (!await crypto.subtle.verify('Ed25519', key, new Uint8Array(base64UrlDecode(envelope.signature)), payload(envelope.statement))) invalid();
  return deepFreezePlainData({ certificate, statement, handoffSha256: `sha256:${await sha256Hex(input.handoff)}` });
}

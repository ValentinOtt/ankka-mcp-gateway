import * as v from 'valibot';

import { canonicalJson } from './canonical-json';
import {
  issueCloudflareBootstrapOwnershipHandoff,
  verifyCloudflareBootstrapOwnershipHandoff,
} from './cloudflare-bootstrap-ownership-handoff';
import {
  CloudflareGatewayOwnershipProofError,
  issueCloudflareGatewayOwnershipCertificate,
} from './cloudflare-gateway-ownership-proof';
import {
  getAccountWorkersSubdomain,
  setWorkerBootstrapSubdomain,
  verifyWorkerBootstrapSubdomain,
  type CloudflareManagementTransport,
} from './cloudflare-management-surface';
import { PUBLIC_ORIGIN } from './constants';
import {
  createCustomerBootstrapCapability,
  type BootstrapRandomBytes,
  type CustomerBootstrapCapability,
} from './customer-bootstrap-state';
import {
  deployCustomerBootstrapWorker,
  type CustomerBootstrapPlainBindings,
} from './customer-bootstrap-worker-deployment';
import {
  CUSTOMER_INSTALL_OAUTH_CALLBACK_PATH,
  CUSTOMER_INSTALL_ROOT_PATH,
  CUSTOMER_INSTALL_STATUS_PATH,
} from './customer-install-paths';
import { customerInstallStatusSchema } from './customer-install-status';
import { base64UrlEncode, sha256Hex } from './crypto';
import { DeployError } from './errors';
import {
  executeHostedBootstrapGrant,
} from './hosted-bootstrap-grant';
import { type BoundedRead, fetchBoundedText } from './http';
import type { CloudflareOauthConfig, FetchTransport } from './oauth';
import {
  adaptVerifiedReleaseBundleForGatewayDeployments,
} from './release-direct-upload-adapter';
import type { VerifiedReleaseBundle } from './release';
import {
  verifyStaticDeployPlanIntegrity,
  type StaticDeployPlan,
} from './schema';
import { parseVerifiedReleaseBundle } from './verified-release-bundle';

const ACCOUNT_ID = /^[a-f0-9]{32}$/u;
const PROVIDER_ID = /^[a-f0-9]{32}$/u;
const VERSION_ID = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/u;
const WORKER_NAME = /^[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$/u;
const DNS_LABEL = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/u;
const TOKEN = /^[A-Za-z0-9_-]{43}$/u;
const BOOTSTRAP_ID = /^boot_[A-Za-z0-9_-]{24}$/u;
const INSTALL_ID = /^acg-[a-f0-9]{24}$/u;
const PLAN_ID = /^plan-[a-f0-9]{24}$/u;
const RELEASE_ID = /^gateway-v(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)$/u;
const SHA256 = /^[a-f0-9]{64}$/u;
const SHA256_COMMITMENT = /^sha256:[a-f0-9]{64}$/u;
const CLIENT_ID = /^[A-Za-z0-9_-]{16,128}$/u;
const KEY_ID = /^[a-z0-9](?:[a-z0-9._-]{0,62}[a-z0-9])?$/u;
const MAX_HEALTH_BYTES = 16 * 1024;
const MAX_HANDOFF_FRAGMENT_BYTES = 64 * 1024;

const safeTimestamp = v.pipe(v.number(), v.safeInteger(), v.minValue(0));
const deploymentSchema = v.strictObject({
  workerId: v.pipe(v.string(), v.regex(PROVIDER_ID)),
  workerName: v.pipe(v.string(), v.regex(WORKER_NAME)),
  namespaceId: v.pipe(v.string(), v.regex(PROVIDER_ID)),
  namespaceName: v.pipe(v.string(), v.minLength(1), v.maxLength(256)),
  deploymentId: v.pipe(v.string(), v.regex(VERSION_ID)),
  versionId: v.pipe(v.string(), v.regex(VERSION_ID)),
  release: v.pipe(v.string(), v.regex(RELEASE_ID)),
  artifactSha256: v.pipe(v.string(), v.regex(SHA256)),
  bootstrapComponentSha256: v.pipe(v.string(), v.regex(SHA256)),
  sourceSha256: v.pipe(v.string(), v.regex(SHA256)),
  recovery: v.picklist(['created', 'recovered']),
});
const provisionSchema = v.strictObject({
  schemaVersion: v.literal(1),
  accountId: v.pipe(v.string(), v.regex(ACCOUNT_ID)),
  bootstrapId: v.pipe(v.string(), v.regex(BOOTSTRAP_ID)),
  bootstrapSecretCommitment: v.pipe(v.string(), v.regex(SHA256_COMMITMENT)),
  capabilityExpiresAt: safeTimestamp,
  bootstrapOrigin: v.pipe(v.string(), v.url()),
  bootstrapCallback: v.pipe(v.string(), v.url()),
  deployment: deploymentSchema,
  grantRevocation: v.literal('confirmed'),
  handoff: v.pipe(v.string(), v.minLength(1), v.maxLength(8_192)),
  installId: v.pipe(v.string(), v.regex(INSTALL_ID)),
  plan: v.strictObject({
    id: v.pipe(v.string(), v.regex(PLAN_ID)),
    hash: v.pipe(v.string(), v.regex(SHA256_COMMITMENT)),
  }),
  release: v.strictObject({
    id: v.pipe(v.string(), v.regex(RELEASE_ID)),
    artifactSha256: v.pipe(v.string(), v.regex(SHA256)),
  }),
  workersSubdomain: v.pipe(v.string(), v.regex(DNS_LABEL)),
});

/** Optional propagation wait forwarded only when a caller supplied one. */
interface DeploymentWaitOverride {
  wait?: (milliseconds: number) => Promise<void>;
}

export interface HostedStage1Secrets {
  readonly capability: CustomerBootstrapCapability;
  readonly bootstrapNonce: string;
  readonly ownershipWrapKey: string;
}

export type HostedStage1Provision = v.InferOutput<typeof provisionSchema>;

export interface HostedStage1Handoff {
  /** Contains the one-time capability in the URL fragment and must never be persisted. */
  readonly handoffUrl: string;
  readonly bootstrapOrigin: string;
  readonly expiresAt: number;
}

export interface HostedStage1Provider {
  readonly getAccountWorkersSubdomain: typeof getAccountWorkersSubdomain;
  readonly deployCustomerBootstrapWorker: typeof deployCustomerBootstrapWorker;
  readonly setWorkerBootstrapSubdomain: typeof setWorkerBootstrapSubdomain;
  readonly verifyWorkerBootstrapSubdomain: typeof verifyWorkerBootstrapSubdomain;
}

const DEFAULT_PROVIDER: HostedStage1Provider = Object.freeze({
  getAccountWorkersSubdomain,
  deployCustomerBootstrapWorker,
  setWorkerBootstrapSubdomain,
  verifyWorkerBootstrapSubdomain,
});

function invalid(code: 'session_invalid' | 'release_invalid' = 'session_invalid'): never {
  throw new DeployError(code === 'release_invalid' ? 503 : 400, code);
}

function randomToken(randomBytes?: BootstrapRandomBytes): string {
  const bytes = randomBytes === undefined
    ? crypto.getRandomValues(new Uint8Array(32))
    : randomBytes(32);
  if (!(bytes instanceof Uint8Array) || bytes.byteLength !== 32) invalid();
  return base64UrlEncode(bytes);
}

function managementTransport(transport: FetchTransport): CloudflareManagementTransport {
  return (request) => transport(request);
}

function managementWorkerName(plan: StaticDeployPlan): string {
  const matches = plan.managementResources.filter((resource) =>
    resource.kind === 'management_worker');
  const workerName = matches[0]?.name;
  if (matches.length !== 1 || workerName === undefined || !WORKER_NAME.test(workerName)) {
    invalid('release_invalid');
  }
  return workerName;
}

function exactBootstrapOrigin(value: string, workerName: string, subdomain: string): boolean {
  try {
    const url = new URL(value);
    return url.protocol === 'https:' && url.username === '' && url.password === '' &&
      url.port === '' && url.pathname === '/' && url.search === '' && url.hash === '' &&
      url.hostname === `${workerName}.${subdomain}.workers.dev`;
  } catch {
    return false;
  }
}

export function parseHostedStage1Provision<Input>(input: Input): HostedStage1Provision {
  const parsed = v.safeParse(provisionSchema, input);
  if (!parsed.success ||
      !exactBootstrapOrigin(
        parsed.output.bootstrapOrigin,
        parsed.output.deployment.workerName,
        parsed.output.workersSubdomain,
      ) ||
      parsed.output.bootstrapCallback !==
        `${parsed.output.bootstrapOrigin.slice(0, -1)}${CUSTOMER_INSTALL_OAUTH_CALLBACK_PATH}` ||
      !parsed.output.deployment.workerName.endsWith(`-${parsed.output.installId}`) ||
      parsed.output.deployment.release !== parsed.output.release.id ||
      parsed.output.deployment.artifactSha256 !== parsed.output.release.artifactSha256) {
    invalid();
  }
  return Object.freeze({
    ...parsed.output,
    deployment: Object.freeze(parsed.output.deployment),
    plan: Object.freeze(parsed.output.plan),
    release: Object.freeze(parsed.output.release),
  });
}

/** Generates every raw Stage 1 secret together, for one encrypted browser cookie. */
export async function createHostedStage1Secrets(input: {
  readonly now: number;
  readonly randomBytes?: BootstrapRandomBytes | undefined;
}): Promise<HostedStage1Secrets> {
  if (!Number.isSafeInteger(input.now) || input.now < 0) invalid();
  const capability = await createCustomerBootstrapCapability(input);
  return Object.freeze({
    capability,
    bootstrapNonce: randomToken(input.randomBytes),
    ownershipWrapKey: randomToken(input.randomBytes),
  });
}

function validateSecrets(input: HostedStage1Secrets, now: number, plan: StaticDeployPlan): void {
  if (!BOOTSTRAP_ID.test(input.capability.bootstrapId) ||
      !TOKEN.test(input.capability.secret) ||
      !SHA256_COMMITMENT.test(input.capability.secretCommitment) ||
      !TOKEN.test(input.bootstrapNonce) || !TOKEN.test(input.ownershipWrapKey) ||
      input.capability.expiresAt <= now || input.capability.expiresAt > plan.expiresAt) invalid();
}

/** The exact plain-text binding set the restricted bootstrap Worker is deployed with. */
export function expectedCustomerBootstrapBindings(input: {
  readonly accountId: string;
  readonly bootstrapCallback: string;
  readonly customerOauthClientId: string;
  readonly issuerKeyId: string;
  readonly issuerPublicKey: string;
  readonly plan: StaticDeployPlan;
  readonly release: ReturnType<typeof parseVerifiedReleaseBundle>;
  readonly capability: CustomerBootstrapCapability;
  readonly workerName: string;
}): CustomerBootstrapPlainBindings {
  return Object.freeze({
    ANKKA_BOOTSTRAP_CALLBACK: input.bootstrapCallback,
    ANKKA_BOOTSTRAP_EXPIRES_AT: String(input.capability.expiresAt),
    ANKKA_BOOTSTRAP_ID: input.capability.bootstrapId,
    ANKKA_BOOTSTRAP_SECRET_SHA256: input.capability.secretCommitment,
    ANKKA_GATEWAY_RELEASE: input.plan.releaseId,
    ANKKA_GATEWAY_RELEASE_SHA256: `sha256:${input.plan.releaseArtifactSha256}`,
    ANKKA_INSTALL_ID: input.plan.managementOwnershipMarker,
    ANKKA_INSTALLER_ORIGIN: PUBLIC_ORIGIN,
    ANKKA_MANAGEMENT_HOSTNAME: input.plan.gatewayConfiguration.managementHostname,
    ANKKA_PLAN_HASH: input.plan.planHash,
    ANKKA_PLAN_ID: input.plan.planId,
    ANKKA_UPDATE_CHANNEL: input.release.channel,
    ANKKA_UPDATE_KEY_ID: input.release.keyId,
    ANKKA_UPDATE_PUBLIC_KEY: input.release.publicKey,
    ANKKA_WORKER_NAME: input.workerName,
    CLOUDFLARE_ACCOUNT_ID: input.accountId,
    CLOUDFLARE_CUSTOMER_OAUTH_CLIENT_ID: input.customerOauthClientId,
    CLOUDFLARE_OWNERSHIP_ISSUER_KEY_ID: input.issuerKeyId,
    CLOUDFLARE_OWNERSHIP_ISSUER_PUBLIC_KEY: input.issuerPublicKey,
  });
}

/**
 * Runs the exact account-wide Worker bootstrap while the narrow grant is in
 * callback-local memory. The returned value exists only after revocation.
 */
export async function provisionHostedStage1(input: {
  readonly code: string;
  readonly verifier: string;
  readonly oauth: CloudflareOauthConfig;
  readonly transport: FetchTransport;
  readonly bundle: VerifiedReleaseBundle;
  readonly plan: StaticDeployPlan;
  readonly secrets: HostedStage1Secrets;
  readonly customerOauthClientId: string;
  readonly issuerKeyId: string;
  readonly issuerPublicKey: string;
  readonly issuerPrivateKey: CryptoKey;
  readonly now: () => number;
  readonly wait?: (milliseconds: number) => Promise<void>;
  /** Test seam only; production always uses the fixed reviewed provider primitives. */
  readonly provider?: HostedStage1Provider;
}): Promise<HostedStage1Provision> {
  const startedAt = input.now();
  if (!Number.isSafeInteger(startedAt) || startedAt < 0 ||
      !CLIENT_ID.test(input.customerOauthClientId) ||
      !KEY_ID.test(input.issuerKeyId) || !TOKEN.test(input.issuerPublicKey)) invalid();
  const plan = await verifyStaticDeployPlanIntegrity(input.plan);
  validateSecrets(input.secrets, startedAt, plan);
  if (`sha256:${await sha256Hex(input.secrets.capability.secret)}` !==
      input.secrets.capability.secretCommitment) invalid();
  const parsedRelease = parseVerifiedReleaseBundle(input.bundle);
  if ((parsedRelease.channel !== 'canary' && parsedRelease.channel !== 'stable') ||
      parsedRelease.manifest.release !== plan.releaseId ||
      parsedRelease.manifest.artifact.treeSha256 !== plan.releaseArtifactSha256 ||
      parsedRelease.manifest.components.workerBootstrap.files.length !== 1 ||
      parsedRelease.manifest.components.workerBootstrap.files[0]?.sha256 !==
        plan.bootstrapWorkerSourceSha256) invalid('release_invalid');
  const releases = await adaptVerifiedReleaseBundleForGatewayDeployments(input.bundle);
  const workerName = managementWorkerName(plan);
  const fixedTransport = managementTransport(input.transport);
  const provider = input.provider ?? DEFAULT_PROVIDER;

  const result = await executeHostedBootstrapGrant({
    code: input.code,
    verifier: input.verifier,
    config: input.oauth,
    transport: input.transport,
    deploy: async ({ accessToken, accountId }) => {
      const workersSubdomain = await provider.getAccountWorkersSubdomain({
        accessToken,
        accountId,
        transport: fixedTransport,
      });
      if (workersSubdomain.accountId !== accountId) invalid();
      const bootstrapOrigin = `https://${workerName}.${workersSubdomain.subdomain}.workers.dev/`;
      const bootstrapCallback =
        `${bootstrapOrigin.slice(0, -1)}${CUSTOMER_INSTALL_OAUTH_CALLBACK_PATH}`;
      const plainTextBindings = expectedCustomerBootstrapBindings({
        accountId,
        bootstrapCallback,
        customerOauthClientId: input.customerOauthClientId,
        issuerKeyId: input.issuerKeyId,
        issuerPublicKey: input.issuerPublicKey,
        plan,
        release: parsedRelease,
        capability: input.secrets.capability,
        workerName,
      });
      const waitOverride: DeploymentWaitOverride = {};
      if (input.wait !== undefined) waitOverride.wait = input.wait;
      const deployment = await provider.deployCustomerBootstrapWorker({
        accessToken,
        accountId,
        workerName,
        bootstrapId: input.secrets.capability.bootstrapId,
        release: releases.bootstrap,
        plainTextBindings,
        bootstrapNonce: input.secrets.bootstrapNonce,
        ownershipWrapKey: input.secrets.ownershipWrapKey,
        transport: input.transport,
        ...waitOverride,
      });
      await provider.setWorkerBootstrapSubdomain({
        accessToken,
        accountId,
        plan,
        enabled: true,
        transport: fixedTransport,
      });
      await provider.verifyWorkerBootstrapSubdomain({
        accessToken,
        accountId,
        plan,
        expectedEnabled: true,
        transport: fixedTransport,
      });
      const issuedAt = input.now();
      if (!Number.isSafeInteger(issuedAt) || issuedAt < startedAt ||
          issuedAt >= input.secrets.capability.expiresAt) invalid();
      const handoff = await issueCloudflareBootstrapOwnershipHandoff({
        accountId,
        adminState: {
          binding: 'ADMIN_STATE',
          className: 'AdminState',
          namespaceId: deployment.namespaceId,
          storage: 'sqlite',
          workerProviderId: deployment.workerId,
        },
        bootstrapSecret: {
          commitment: input.secrets.capability.secretCommitment,
          expiresAt: input.secrets.capability.expiresAt,
        },
        expiresAt: input.secrets.capability.expiresAt,
        installId: plan.managementOwnershipMarker,
        issuedAt,
        plan: { id: plan.planId, hash: plan.planHash },
        release: { id: plan.releaseId, artifactSha256: plan.releaseArtifactSha256 },
        worker: { name: workerName, providerId: deployment.workerId },
      }, input.issuerPrivateKey);
      await verifyCloudflareBootstrapOwnershipHandoff({
        now: issuedAt,
        pinnedPublicKey: input.issuerPublicKey,
        serializedHandoff: handoff,
      });
      return Object.freeze({
        bootstrapCallback,
        bootstrapOrigin,
        deployment,
        handoff,
        workersSubdomain: workersSubdomain.subdomain,
      });
    },
  });

  return parseHostedStage1Provision({
    schemaVersion: 1,
    accountId: result.accountId,
    bootstrapId: input.secrets.capability.bootstrapId,
    bootstrapSecretCommitment: input.secrets.capability.secretCommitment,
    capabilityExpiresAt: input.secrets.capability.expiresAt,
    bootstrapOrigin: result.deployment.bootstrapOrigin,
    bootstrapCallback: result.deployment.bootstrapCallback,
    deployment: result.deployment.deployment,
    grantRevocation: result.grantRevocation,
    handoff: result.deployment.handoff,
    installId: plan.managementOwnershipMarker,
    plan: { id: plan.planId, hash: plan.planHash },
    release: { id: plan.releaseId, artifactSha256: plan.releaseArtifactSha256 },
    workersSubdomain: result.deployment.workersSubdomain,
  });
}

/** Names a certificate issuance failure by the proof library's own code, never its message. */
function certificateReason<Thrown>(error: Thrown): string {
  if (error instanceof DeployError) return error.reason ?? error.code;
  if (error instanceof CloudflareGatewayOwnershipProofError) return `handoff_certificate_${error.code}`;
  return 'handoff_certificate_unexpected';
}

/** Names why the readiness fetch settled without a response: expiry, body, or transport. */
function readinessReadReason<Thrown>(error: Thrown): string {
  if (error instanceof DeployError) {
    if (error.status === 504) return 'readiness_deadline_expired';
    if (error.reason === 'body_read_failed') return 'readiness_body_read_failed';
  }
  return 'readiness_transport_failed';
}

function readinessStatusReason(response: Response): string {
  const { status } = response;
  return Number.isInteger(status) && status >= 100 && status <= 599
    ? `readiness_http_${status}`
    : 'readiness_http_unknown';
}

/**
 * Token-free readiness read of the freshly deployed shell.
 *
 * It asks the shell's install status route, not /health: the shell serves its
 * admin assets with a single-page-application fallback and only /__ankka/*
 * and /api/* run the Worker first, so from outside /health answers with the
 * admin page. The request uses redirect: 'manual' because workerd rejects
 * redirect: 'error' when the request is built; a redirect is refused by its
 * status instead. Every outcome carries a secret-free reason so the operator
 * can read why a handoff is still waiting.
 */
async function readBootstrapHealth(input: {
  readonly provision: HostedStage1Provision;
  readonly transport: FetchTransport;
}): Promise<v.InferOutput<typeof customerInstallStatusSchema>> {
  let read: BoundedRead;
  try {
    read = await fetchBoundedText(
      input.transport,
      new URL(CUSTOMER_INSTALL_STATUS_PATH, input.provision.bootstrapOrigin),
      {
        method: 'GET',
        headers: { accept: 'application/json' },
        cache: 'no-store',
        redirect: 'manual',
      },
      'bootstrap_not_ready',
      { maxBytes: MAX_HEALTH_BYTES, timeoutMs: 5_000 },
    );
  } catch (error) {
    throw new DeployError(503, 'bootstrap_not_ready', readinessReadReason(error));
  }
  const { response } = read;
  if (response.status !== 200) throw new DeployError(503, 'bootstrap_not_ready', readinessStatusReason(response));
  let decoded: unknown;
  try {
    decoded = JSON.parse(read.text);
  } catch {
    throw new DeployError(502, 'bootstrap_failed', 'readiness_not_json');
  }
  const parsed = v.safeParse(customerInstallStatusSchema, decoded);
  if (!parsed.success) throw new DeployError(502, 'bootstrap_failed', 'readiness_schema_invalid');
  // A shell that was just deployed has nothing to converge yet; any other
  // status means the readiness read reached a different install.
  if (parsed.output.status !== 'INCOMPLETE') {
    throw new DeployError(502, 'bootstrap_failed', 'readiness_status_unexpected');
  }
  if (parsed.output.installId !== input.provision.installId) {
    throw new DeployError(502, 'bootstrap_failed', 'readiness_install_id_mismatch');
  }
  if (parsed.output.release !== input.provision.release.id) {
    throw new DeployError(502, 'bootstrap_failed', 'readiness_release_mismatch');
  }
  return parsed.output;
}

/**
 * Completes the token-free readiness check and releases the one-time secret
 * only as a same-browser URL fragment destined for the customer Worker.
 */
export async function completeHostedStage1Handoff(input: {
  readonly provision: HostedStage1Provision;
  readonly plan: StaticDeployPlan;
  readonly capabilitySecret: string;
  readonly customerOauthClientId: string;
  readonly issuerKeyId: string;
  readonly issuerPublicKey: string;
  readonly issuerPrivateKey: CryptoKey;
  readonly transport: FetchTransport;
  readonly now: () => number;
}): Promise<HostedStage1Handoff> {
  const provision = parseHostedStage1Provision(input.provision);
  const plan = await verifyStaticDeployPlanIntegrity(input.plan);
  const now = input.now();
  if (!Number.isSafeInteger(now) || now < 0 || now >= provision.capabilityExpiresAt ||
      !TOKEN.test(input.capabilitySecret) || !CLIENT_ID.test(input.customerOauthClientId) ||
      !KEY_ID.test(input.issuerKeyId) || !TOKEN.test(input.issuerPublicKey) ||
      provision.plan.id !== plan.planId || provision.plan.hash !== plan.planHash ||
      provision.release.id !== plan.releaseId ||
      provision.release.artifactSha256 !== plan.releaseArtifactSha256 ||
      provision.installId !== plan.managementOwnershipMarker ||
      provision.bootstrapSecretCommitment !== `sha256:${await sha256Hex(input.capabilitySecret)}`) {
    invalid();
  }
  const verifiedHandoff = await verifyCloudflareBootstrapOwnershipHandoff({
    now,
    pinnedPublicKey: input.issuerPublicKey,
    serializedHandoff: provision.handoff,
  }).catch(() => invalid());
  const statement = verifiedHandoff.statement;
  if (statement.accountId !== provision.accountId ||
      statement.worker.name !== provision.deployment.workerName ||
      statement.worker.providerId !== provision.deployment.workerId ||
      statement.adminState.namespaceId !== provision.deployment.namespaceId ||
      statement.bootstrapSecret.commitment !== provision.bootstrapSecretCommitment ||
      statement.bootstrapSecret.expiresAt !== provision.capabilityExpiresAt) invalid();
  const health = await readBootstrapHealth({ provision, transport: input.transport });
  if (health.installId !== plan.managementOwnershipMarker) {
    throw new DeployError(502, 'bootstrap_failed', 'handoff_install_id_mismatch');
  }
  let ownershipCertificate: string;
  try {
    ownershipCertificate = await issueCloudflareGatewayOwnershipCertificate({
    accountId: provision.accountId,
    installId: plan.managementOwnershipMarker,
    worker: {
      name: provision.deployment.workerName,
      providerId: provision.deployment.workerId,
    },
    adminStateNamespaceId: provision.deployment.namespaceId,
    bootstrapCallback: provision.bootstrapCallback,
    gatewayCallback:
      `https://${plan.gatewayConfiguration.managementHostname}${CUSTOMER_INSTALL_OAUTH_CALLBACK_PATH}`,
    publicClientId: input.customerOauthClientId,
    ownershipPublicKey: health.ownershipPublicKey,
    handoffSha256: `sha256:${await sha256Hex(provision.handoff)}`,
    issuedAt: now,
    keyId: input.issuerKeyId,
  }, input.issuerPrivateKey);
  } catch (error) {
    throw new DeployError(500, 'internal_error', certificateReason(error));
  }
  const payload = canonicalJson({
    bootstrapId: provision.bootstrapId,
    ownershipCertificate,
    secret: input.capabilitySecret,
    serializedHandoff: provision.handoff,
    serializedPlan: canonicalJson(plan),
  });
  const bytes = new TextEncoder().encode(payload);
  if (bytes.byteLength > MAX_HANDOFF_FRAGMENT_BYTES) invalid();
  const handoffUrl = new URL(CUSTOMER_INSTALL_ROOT_PATH, provision.bootstrapOrigin);
  handoffUrl.hash = base64UrlEncode(bytes);
  return Object.freeze({
    handoffUrl: handoffUrl.toString(),
    bootstrapOrigin: provision.bootstrapOrigin,
    expiresAt: provision.capabilityExpiresAt,
  });
}

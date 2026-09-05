import * as v from 'valibot';
import { createBigQuerySetup } from './customer-bigquery-setup';
import { bigQuerySetupAvailable } from './customer-bigquery-deployment';
import { createBigQueryTeardown } from './customer-bigquery-teardown';

// @ts-expect-error The payload is validated as a release input, not a TS package.
import gatewayRuntime, { AdminState as RuntimeAdminState, verifyBootstrapReceiptProviderStateWithReason, prepareCurrentGatewayTeardown, gatewayControlPlaneOrigin, verifyAccess } from '../../../payload/worker/index.js';
import { CustomerBootstrapConvergenceDriver } from './customer-bootstrap-convergence-driver';
import { finalizeCustomerBootstrapHandover } from './customer-bootstrap-handover';
import { customerInstallProgressPage } from './customer-install-progress-page';
import {
  customerInstallationObjectName,
  handleCustomerInstallationObjectRequest,
  verifyReceiptInInstallationObject,
} from './customer-installation-object';
import { beginCustomerBootstrapRelay } from './customer-bootstrap-relay-client';
import {
  CustomerBootstrapDurableStatePort,
  initializeCustomerBootstrapSql,
} from './customer-bootstrap-durable-state';
import { prepareCustomerBootstrapClaimFromPlan } from './customer-bootstrap-request';
import {
  openCustomerGatewayOwnershipPrivateKey,
  readCustomerGatewayOwnershipState,
  type CustomerGatewayOwnershipState,
} from './customer-gateway-ownership-state';
import { requestCustomerGatewayRelayTicket } from './customer-gateway-relay-ticket-client';
import {
  CUSTOMER_INSTALL_CONTINUE_PATH,
  CUSTOMER_INSTALL_OAUTH_CALLBACK_PATH,
  CUSTOMER_INSTALL_OAUTH_START_PATH,
  CUSTOMER_INSTALL_ROOT_PATH,
  CUSTOMER_INSTALL_STATUS_PATH,
  CUSTOMER_OPERATION_ROOT_PATH,
} from './customer-install-paths';
import type { ReceiptOwnedCloudflareResourceKind, CustomerCloudflareOperation } from './cloudflare-operation-authority';
import { canonicalJson } from './canonical-json';
import { randomBase64Url } from './crypto';
import { verifyStaticDeployPlanIntegrity } from './schema';
import { createGatewayTeardownHandoff } from './gateway-teardown-handoff';
import { DurableCustomerTeardownAttemptPort } from './customer-teardown-attempt';
import { createCustomerTeardownRouter, customerTeardownCookiePresent, CUSTOMER_TEARDOWN_PATH } from './customer-teardown-router';
import {
  createCustomerOperationRouter,
  customerOperationAttemptSchema,
  customerOperationCookiePresent,
  type CustomerOperationAttempt,
  type CustomerOperationAttemptPort,
  type CustomerOperationResult,
  type CustomerOperationRuntimeUpdateInput,
} from './customer-operation-router';
import {
  openOperationSecret,
  operationSignature,
  sealOperationSecret,
} from './customer-operation-secrets';
import {
  runCustomerRuntimeUpdate,
  type CustomerRuntimeControlCommand,
} from './customer-runtime-update';
import {
  CUSTOMER_STAGE2_CHUNK_CHECKPOINTS,
  convergeCustomerStage2,
  type CustomerStage2ConvergerResult,
} from './customer-stage2-converger';
import {
  CustomerStage2DurableStatePort,
  initializeCustomerStage2Sql,
} from './customer-stage2-durable-state';
import {
  customerStage2Action,
  type CustomerStage2Journal,
} from './customer-stage2-journal';
import { createCustomerStage2RecoveryRouter } from './customer-stage2-recovery-router';

const TOKEN = /^[A-Za-z0-9_-]{43}$/u;
const envSchema = v.object({
  ADMIN_EMAILS: v.pipe(v.string(), v.minLength(3), v.maxLength(8_192)),
  ANKKA_INSTALL_ID: v.pipe(v.string(), v.regex(/^acg-[a-f0-9]{24}$/u)),
  ANKKA_GATEWAY_RELEASE: v.pipe(v.string(), v.regex(/^gateway-v(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)$/u)),
  ANKKA_GATEWAY_RELEASE_SHA256: v.pipe(v.string(), v.regex(/^sha256:[a-f0-9]{64}$/u)),
  ANKKA_MANAGEMENT_HOSTNAME: v.pipe(v.string(), v.minLength(3), v.maxLength(253)),
  ANKKA_UPDATE_CHANNEL: v.picklist(['canary', 'stable']),
  ANKKA_UPDATE_KEY_ID: v.pipe(v.string(), v.regex(/^[a-z0-9](?:[a-z0-9._-]{0,62}[a-z0-9])?$/u)),
  ANKKA_UPDATE_PUBLIC_KEY: v.pipe(v.string(), v.regex(TOKEN)),
  ANKKA_WORKERS_SUBDOMAIN: v.pipe(v.string(), v.regex(/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/u)),
  ANKKA_WORKER_NAME: v.pipe(v.string(), v.regex(/^[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$/u)),
  CF_ACCESS_AUD: v.pipe(v.string(), v.minLength(16), v.maxLength(512)),
  CF_ACCESS_ISSUER: v.pipe(v.string(), v.url()),
  CLOUDFLARE_ACCOUNT_ID: v.pipe(v.string(), v.regex(/^[a-f0-9]{32}$/u)),
  CLOUDFLARE_ZONE_ID: v.pipe(v.string(), v.regex(/^[a-f0-9]{32}$/u)),
  CLOUDFLARE_ZONE_NAME: v.pipe(v.string(), v.minLength(3), v.maxLength(253)),
  ZERO_TRUST_READY: v.literal('true'),
  ANKKA_GATEWAY_OWNERSHIP_WRAP_KEY: v.pipe(v.string(), v.regex(TOKEN)),
});

const OPERATION_ATTEMPT_KEY = 'ankka-mcp-gateway/customer-operation-attempt/v1';
/** The payload's public view of one prepared action; other fields stay untouched. */
const sourceActionViewSchema = v.looseObject({
  schemaVersion: v.literal(1),
  actionId: v.string(),
  status: v.string(),
  expiresAt: v.string(),
});

const RUNTIME_HANDOVER_KEY = 'ankka-mcp-gateway/customer-runtime-handover/v1';
/** How long the version that started an update waits for the new one before it reports failure. */
const RUNTIME_HANDOVER_DEADLINE_MS = 5 * 60 * 1_000;
const RUNTIME_HANDOVER_ALARM_DELAY_MS = 8_000;
/**
 * What the new version needs to finish an update's journal: the action, the
 * target it must find itself running, and the action key sealed under the
 * ownership wrap key it inherits. Written right before the upload.
 */
const runtimeHandoverSchema = v.strictObject({
  schemaVersion: v.literal(1),
  actionId: v.pipe(v.string(), v.regex(/^action_[A-Za-z0-9_-]{32}$/u)),
  operation: v.picklist(['update', 'rollback']),
  actionExpiresAt: v.pipe(v.number(), v.safeInteger()),
  target: v.strictObject({
    release: v.pipe(v.string(), v.regex(/^gateway-v(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)$/u)),
    artifactSha256: v.pipe(v.string(), v.regex(/^sha256:[a-f0-9]{64}$/u)),
  }),
  fromVersionId: v.pipe(v.string(), v.regex(/^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/u)),
  sealedActionKey: v.pipe(v.string(), v.maxLength(4_096)),
  armedAt: v.pipe(v.number(), v.safeInteger()),
  deadline: v.pipe(v.number(), v.safeInteger()),
});
type RuntimeHandover = v.InferOutput<typeof runtimeHandoverSchema>;

/** The one in-flight operation attempt, kept in the object's own storage without secrets. */
class DurableCustomerOperationAttemptPort implements CustomerOperationAttemptPort {
  constructor(private readonly storage: DurableObjectStorage) {}

  async read(): Promise<CustomerOperationAttempt | null> {
    const parsed = v.safeParse(customerOperationAttemptSchema, await this.storage.get(OPERATION_ATTEMPT_KEY));
    return parsed.success ? parsed.output : null;
  }

  async write(attempt: CustomerOperationAttempt): Promise<void> {
    await this.storage.put(OPERATION_ATTEMPT_KEY, attempt);
  }

  async clear(): Promise<void> {
    await this.storage.delete(OPERATION_ATTEMPT_KEY);
  }
}

interface FinalGatewayEnv extends Record<string, unknown> {
  ADMIN_STATE: DurableObjectNamespace;
  ADMIN_EMAILS: string;
  ANKKA_INSTALL_ID: string;
  ANKKA_GATEWAY_RELEASE: string;
  ANKKA_GATEWAY_RELEASE_SHA256: string;
  ANKKA_MANAGEMENT_HOSTNAME: string;
  ANKKA_UPDATE_CHANNEL: 'canary' | 'stable';
  ANKKA_UPDATE_KEY_ID: string;
  ANKKA_UPDATE_PUBLIC_KEY: string;
  ANKKA_WORKERS_SUBDOMAIN: string;
  ANKKA_WORKER_NAME: string;
  CF_ACCESS_AUD: string;
  CF_ACCESS_ISSUER: string;
  CLOUDFLARE_ACCOUNT_ID: string;
  CLOUDFLARE_ZONE_ID: string;
  CLOUDFLARE_ZONE_NAME: string;
  ZERO_TRUST_READY: 'true';
  ANKKA_GATEWAY_OWNERSHIP_WRAP_KEY: string;
}

interface FinalDurableObjectState extends DurableObjectState {
  blockConcurrencyWhile<Value>(callback: () => Promise<Value>): Promise<Value>;
}

type ParsedFinalEnv = v.InferOutput<typeof envSchema>;

const namespaceSchema = v.object({ idFromName: v.function(), get: v.function() });

function parsedEnv(env: FinalGatewayEnv): ParsedFinalEnv {
  const parsed = v.safeParse(envSchema, env);
  if (!parsed.success || !v.is(namespaceSchema, env.ADMIN_STATE)) throw new Error('gateway_config_invalid');
  const managementHostname = parsed.output.ANKKA_MANAGEMENT_HOSTNAME;
  const issuer = new URL(parsed.output.CF_ACCESS_ISSUER);
  if (managementHostname !== managementHostname.toLowerCase() || !managementHostname.includes('.') ||
      issuer.protocol !== 'https:' || issuer.username !== '' || issuer.password !== '' ||
      issuer.port !== '' || issuer.search !== '' || issuer.hash !== '') {
    throw new Error('gateway_config_invalid');
  }
  return Object.freeze(parsed.output);
}

function secureHeaders(contentType: string): Headers {
  return new Headers({
    'cache-control': 'no-store',
    'content-security-policy': "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
    'content-type': contentType,
    'cross-origin-opener-policy': 'same-origin',
    'referrer-policy': 'no-referrer',
    'x-content-type-options': 'nosniff',
  });
}

function notFound(): Response {
  return new Response(JSON.stringify({ schemaVersion: 1, error: 'not_found' }), {
    status: 404,
    headers: secureHeaders('application/json; charset=utf-8'),
  });
}

function unavailable(): Response {
  return new Response(JSON.stringify({ schemaVersion: 1, error: 'recovery_unavailable' }), {
    status: 503,
    headers: secureHeaders('application/json; charset=utf-8'),
  });
}

function recoveryPage(): Response {
  const nonce = crypto.randomUUID().replaceAll('-', '');
  const headers = secureHeaders('text/html; charset=utf-8');
  headers.set('content-security-policy', `default-src 'none'; script-src 'nonce-${nonce}'; connect-src 'self'; style-src 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'`);
  return new Response(`<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><meta name="referrer" content="no-referrer"><title>Finish Ankka Gateway setup</title><style>body{font:16px/1.5 system-ui,sans-serif;max-width:42rem;margin:5rem auto;padding:0 1.25rem;color:#171713}button{font:inherit;padding:.75rem 1rem}</style><h1>Finish your Ankka Gateway</h1><p id="message">Preparing a fresh, temporary Cloudflare approval…</p><button id="retry" hidden>Try again</button><script nonce="${nonce}">(()=>{const message=document.querySelector('#message');const retry=document.querySelector('#retry');const run=async()=>{retry.hidden=true;try{const response=await fetch('${CUSTOMER_INSTALL_OAUTH_START_PATH}',{method:'POST',headers:{'content-type':'application/json'},body:'{}',credentials:'same-origin',cache:'no-store'});const value=await response.json();if(!response.ok||typeof value.authorizationUrl!=='string')throw new Error();location.assign(value.authorizationUrl)}catch{message.textContent='Setup is still finishing or needs a fresh attempt. Wait a moment, then try again.';retry.hidden=false}};retry.addEventListener('click',run);run()})();</script></html>`, {
    status: 200,
    headers,
  });
}

function exactRecoveryJournal(journal: CustomerStage2Journal, config: ParsedFinalEnv): boolean {
  if (journal.identity.accountId !== config.CLOUDFLARE_ACCOUNT_ID ||
      journal.identity.zoneId !== config.CLOUDFLARE_ZONE_ID ||
      journal.identity.zoneName !== config.CLOUDFLARE_ZONE_NAME ||
      journal.identity.installId !== config.ANKKA_INSTALL_ID ||
      journal.identity.workerName !== config.ANKKA_WORKER_NAME ||
      journal.identity.releaseId !== config.ANKKA_GATEWAY_RELEASE ||
      `sha256:${journal.identity.releaseArtifactSha256}` !== config.ANKKA_GATEWAY_RELEASE_SHA256 ||
      journal.identity.updateChannel !== config.ANKKA_UPDATE_CHANNEL ||
      journal.identity.updateKeyId !== config.ANKKA_UPDATE_KEY_ID ||
      journal.identity.updatePublicKey !== config.ANKKA_UPDATE_PUBLIC_KEY) return false;
  const prerequisites = [
    'management_access_application',
    'management_admin_policy',
    'gateway_resources',
    'management_custom_domain',
  ] as const;
  if (prerequisites.some((name) => customerStage2Action(journal, name)?.phase !== 'verified')) {
    return false;
  }
  const finalRuntime = customerStage2Action(journal, 'final_runtime');
  return finalRuntime !== null && ['send_armed', 'submitted', 'verified'].includes(finalRuntime.phase);
}

export class AdminState extends RuntimeAdminState {
  private readonly recoveryReady: Promise<void>;
  /** Grant and pass count of a running recovery attempt, in memory only. */
  private recovery: CustomerBootstrapConvergenceDriver | null = null;

  constructor(
    private readonly finalState: FinalDurableObjectState,
    private readonly finalEnv: FinalGatewayEnv,
  ) {
    const config = parsedEnv(finalEnv);
    super(finalState, finalEnv, createBigQueryTeardown({
      accountId: config.CLOUDFLARE_ACCOUNT_ID, zoneId: config.CLOUDFLARE_ZONE_ID,
      zoneName: config.CLOUDFLARE_ZONE_NAME, installationId: config.ANKKA_INSTALL_ID,
      accessIssuer: new URL(config.CF_ACCESS_ISSUER).origin,
    }, { storage: finalState.storage, fetch: (target, init) => fetch(target, init) }));
    this.recoveryReady = finalState.blockConcurrencyWhile(async () => {
      const config = parsedEnv(finalEnv);
      initializeCustomerBootstrapSql(finalState.storage);
      initializeCustomerStage2Sql(finalState.storage);
      // Bootstrap keeps only the receipt in the installation object. The
      // ownership key belongs to the separate management object.
      if (finalState.id.name !== customerInstallationObjectName(config.ANKKA_INSTALL_ID)) {
        await readCustomerGatewayOwnershipState(finalState.storage);
      }
    });
  }

  /** One driver per object, bound to the public client the ownership trust names. */
  private async recoveryDriver(): Promise<CustomerBootstrapConvergenceDriver | null> {
    if (this.recovery !== null) return this.recovery;
    const ownership = await readCustomerGatewayOwnershipState(this.finalState.storage);
    if (ownership.trust === null) return null;
    this.recovery = new CustomerBootstrapConvergenceDriver({
      state: new CustomerBootstrapDurableStatePort(this.finalState.storage),
      transport: (target, init) => fetch(target, init),
      publicClientId: ownership.trust.publicClientId,
      converge: (accessToken, attemptId, handover) => this.converge(accessToken, attemptId, handover),
      now: Date.now,
      // Every alarm is its own invocation with its own subrequest budget.
      schedule: (delayMs) => this.finalState.storage.setAlarm(Date.now() + delayMs),
    });
    return this.recovery;
  }

  /** The recovery converger: no runtime source to upload, so it never hands over. */
  private async converge(
    accessToken: string,
    attemptId: string,
    handover: (() => Promise<void>) | undefined,
  ): Promise<CustomerStage2ConvergerResult> {
    const config = parsedEnv(this.finalEnv);
    return convergeCustomerStage2({
      accessToken,
      attemptId,
      handover,
      storage: this.finalState.storage,
      journal: new CustomerStage2DurableStatePort(this.finalState.storage),
      runtime: {
        updateChannel: config.ANKKA_UPDATE_CHANNEL,
        updateKeyId: config.ANKKA_UPDATE_KEY_ID,
        updatePublicKey: config.ANKKA_UPDATE_PUBLIC_KEY,
      },
      payload: {
        bootstrap: async () => notFound(),
        verifyReady: async ({ accessToken: token, plan, target }) => {
          const claim = await prepareCustomerBootstrapClaimFromPlan({
            plan,
            target,
            nowMs: Date.now(),
          });
          return verifyReceiptInInstallationObject(this.installationObject(), {
            claim: { ...claim, cloudflareAccessToken: token },
            target,
          });
        },
      },
      transport: (target, init) => fetch(target, init),
      now: Date.now,
      checkpoints: CUSTOMER_STAGE2_CHUNK_CHECKPOINTS,
    });
  }

  private async assertRecoverable(config: ParsedFinalEnv): Promise<CustomerGatewayOwnershipState> {
    const ownership = await readCustomerGatewayOwnershipState(this.finalState.storage);
    const bootstrap = await new CustomerBootstrapDurableStatePort(this.finalState.storage).read();
    const journal = await new CustomerStage2DurableStatePort(this.finalState.storage).read();
    const callback = `https://${config.ANKKA_MANAGEMENT_HOSTNAME}${CUSTOMER_INSTALL_OAUTH_CALLBACK_PATH}`;
    if (bootstrap === null || bootstrap.installId !== config.ANKKA_INSTALL_ID ||
        bootstrap.capabilityUnused || journal === null || !exactRecoveryJournal(journal, config) ||
        ownership.ownershipCertificate === null || ownership.certificateSha256 === null ||
        ownership.trust === null || ownership.trust.gatewayCallback !== callback) {
      throw new Error('recovery_unavailable');
    }
    return ownership;
  }

  private async issueInstallRelayTicket(config: ParsedFinalEnv) {
    const ownership = await this.assertRecoverable(config);
    if (ownership.ownershipCertificate === null || ownership.certificateSha256 === null ||
        ownership.trust === null) throw new Error('recovery_unavailable');
    const privateKey = await openCustomerGatewayOwnershipPrivateKey({
      storage: this.finalState.storage,
      wrappingKey: config.ANKKA_GATEWAY_OWNERSHIP_WRAP_KEY,
    });
    return requestCustomerGatewayRelayTicket({
      certificate: ownership.ownershipCertificate,
      certificateSha256: ownership.certificateSha256,
      gatewayCallback: ownership.trust.gatewayCallback,
      operation: 'install',
      ownershipPrivateKey: privateKey,
      transport: (input, init) => fetch(input, init),
    });
  }

  /** A finished install whose ownership trust still names the certified callback. */
  private async assertOperational(config: ParsedFinalEnv): Promise<CustomerGatewayOwnershipState> {
    const ownership = await readCustomerGatewayOwnershipState(this.finalState.storage);
    const bootstrap = await new CustomerBootstrapDurableStatePort(this.finalState.storage).read();
    const callback = `https://${config.ANKKA_MANAGEMENT_HOSTNAME}${CUSTOMER_INSTALL_OAUTH_CALLBACK_PATH}`;
    if (bootstrap === null || bootstrap.installId !== config.ANKKA_INSTALL_ID ||
        bootstrap.status !== 'READY' || ownership.ownershipCertificate === null ||
        ownership.certificateSha256 === null || ownership.trust === null ||
        ownership.trust.gatewayCallback !== callback) {
      throw new Error('operation_unavailable');
    }
    return ownership;
  }

  private async issueOperationRelayTicket(config: ParsedFinalEnv, operation: CustomerCloudflareOperation, receiptResourceKinds?: readonly ReceiptOwnedCloudflareResourceKind[]) {
    const ownership = await this.assertOperational(config);
    if (ownership.ownershipCertificate === null || ownership.certificateSha256 === null ||
        ownership.trust === null) throw new Error('operation_unavailable');
    const privateKey = await openCustomerGatewayOwnershipPrivateKey({
      storage: this.finalState.storage,
      wrappingKey: config.ANKKA_GATEWAY_OWNERSHIP_WRAP_KEY,
    });
    const input: Parameters<typeof requestCustomerGatewayRelayTicket>[0] = {
      certificate: ownership.ownershipCertificate,
      certificateSha256: ownership.certificateSha256,
      gatewayCallback: ownership.trust.gatewayCallback,
      operation,
      ownershipPrivateKey: privateKey,
      transport: (input, init) => fetch(input, init),
    };
    return receiptResourceKinds === undefined ? requestCustomerGatewayRelayTicket(input)
      : requestCustomerGatewayRelayTicket({ ...input, receiptResourceKinds });
  }

  /** Reads one prepared action through the payload's own internal route. */
  private async readSourceAction(actionId: string) {
    const response = await super.fetch(new Request(`https://admin-state.invalid/source-actions/${actionId}`));
    if (response.status !== 200) return null;
    const parsed = v.safeParse(sourceActionViewSchema, await response.json());
    if (!parsed.success || parsed.output.actionId !== actionId) return null;
    const expiresAt = Date.parse(parsed.output.expiresAt);
    return Number.isSafeInteger(expiresAt) ? { status: parsed.output.status, expiresAt } : null;
  }

  /** Submits the signed claim to the payload's apply route without leaving the object. */
  private applySourceAction(input: { readonly body: string; readonly signature: string }): Promise<Response> {
    return super.fetch(new Request('https://admin-state.invalid/source-actions/apply', {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-ankka-source-action-signature': input.signature },
      body: input.body,
    }));
  }

  /** Reads one prepared update through the payload's own internal route. */
  private async readRuntimeAction(actionId: string) {
    const response = await super.fetch(new Request(`https://admin-state.invalid/runtime-updates/${actionId}`));
    if (response.status !== 200) return null;
    const parsed = v.safeParse(sourceActionViewSchema, await response.json());
    if (!parsed.success || parsed.output.actionId !== actionId) return null;
    const expiresAt = Date.parse(parsed.output.expiresAt);
    return Number.isSafeInteger(expiresAt) ? { status: parsed.output.status, expiresAt } : null;
  }

  /** One HMAC-signed control command to the payload's update journal, in process. */
  private async signedRuntimeControl(input: {
    readonly actionId: string;
    readonly actionKey: string;
    readonly operation: 'update' | 'rollback';
    readonly actionExpiresAt: number;
  }, command: CustomerRuntimeControlCommand | { readonly command: 'finalize'; readonly fromVersionId: string }): Promise<boolean> {
    const body = canonicalJson({
      schemaVersion: 1,
      actionId: input.actionId,
      actionKey: input.actionKey,
      operation: input.operation,
      issuedAt: Date.now(),
      expiresAt: input.actionExpiresAt,
      ...command,
    });
    const response = await super.fetch(new Request('https://admin-state.invalid/runtime-updates/control', {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'x-ankka-runtime-action-signature': await operationSignature(input.actionKey, body),
      },
      body,
    }));
    await response.body?.cancel();
    return response.status === 200;
  }

  /**
   * The gateway updates itself with the customer's own grant. The upload
   * replaces this Worker, so the handover record and an alarm are written
   * first; the new version's alarm finishes the journal.
   */
  private async runRuntimeUpdate(
    config: ParsedFinalEnv,
    input: CustomerOperationRuntimeUpdateInput,
  ): Promise<CustomerOperationResult> {
    const control = (command: CustomerRuntimeControlCommand) => this.signedRuntimeControl(input, command);
    try {
      await runCustomerRuntimeUpdate({
        accessToken: input.accessToken,
        accountId: config.CLOUDFLARE_ACCOUNT_ID,
        workerName: config.ANKKA_WORKER_NAME,
        controlPlaneOrigin: input.controlPlaneOrigin,
        channel: config.ANKKA_UPDATE_CHANNEL,
        updateKeyId: config.ANKKA_UPDATE_KEY_ID,
        updatePublicKey: config.ANKKA_UPDATE_PUBLIC_KEY,
        target: input.target,
        transport: (target, init) => fetch(target, init),
        control,
        armHandover: async ({ fromVersionId }) => {
          const armedAt = Date.now();
          const handover: RuntimeHandover = {
            schemaVersion: 1,
            actionId: input.actionId,
            operation: input.operation,
            actionExpiresAt: input.actionExpiresAt,
            target: input.target,
            fromVersionId,
            sealedActionKey: await sealOperationSecret(config.ANKKA_GATEWAY_OWNERSHIP_WRAP_KEY, input.actionKey),
            armedAt,
            deadline: armedAt + RUNTIME_HANDOVER_DEADLINE_MS,
          };
          await this.finalState.storage.put(RUNTIME_HANDOVER_KEY, handover);
          await this.finalState.storage.setAlarm(armedAt + RUNTIME_HANDOVER_ALARM_DELAY_MS);
        },
      });
      return 'applied';
    } catch {
      return 'failed';
    }
  }

  /**
   * Runs in whichever version owns the object when the alarm fires: the new
   * one proves the update by its own release bindings and completes the
   * journal; the old one keeps waiting until the deadline, then fails it.
   */
  private async finishRuntimeHandover(config: ParsedFinalEnv): Promise<void> {
    const stored = await this.finalState.storage.get(RUNTIME_HANDOVER_KEY);
    if (stored === undefined || stored === null) return;
    const parsed = v.safeParse(runtimeHandoverSchema, stored);
    if (!parsed.success) {
      await this.finalState.storage.delete(RUNTIME_HANDOVER_KEY);
      return;
    }
    const handover = parsed.output;
    const now = Date.now();
    const running = config.ANKKA_GATEWAY_RELEASE === handover.target.release &&
      config.ANKKA_GATEWAY_RELEASE_SHA256 === handover.target.artifactSha256;
    if (!running && now < handover.deadline) {
      await this.finalState.storage.setAlarm(now + RUNTIME_HANDOVER_ALARM_DELAY_MS);
      return;
    }
    let actionKey: string;
    try {
      actionKey = await openOperationSecret(config.ANKKA_GATEWAY_OWNERSHIP_WRAP_KEY, handover.sealedActionKey);
    } catch {
      await this.finalState.storage.delete(RUNTIME_HANDOVER_KEY);
      return;
    }
    const identity = {
      actionId: handover.actionId,
      actionKey,
      operation: handover.operation,
      actionExpiresAt: handover.actionExpiresAt,
    };
    try {
      await this.signedRuntimeControl(identity, running
        ? { command: 'finalize', fromVersionId: handover.fromVersionId }
        : { command: 'fail', failureCode: 'runtime_update_unconfirmed', recoveryRequired: true });
    } finally {
      await this.finalState.storage.delete(RUNTIME_HANDOVER_KEY);
    }
  }

  private async teardownRouter(config: ParsedFinalEnv, managementOrigin: string) {
    const ownership = await this.assertOperational(config);
    if (ownership.trust === null || ownership.ownershipCertificate === null || ownership.serializedPlan === null) {
      throw new Error('teardown_unavailable');
    }
    const trust = ownership.trust;
    const certificate = ownership.ownershipCertificate;
    const serializedPlan = ownership.serializedPlan;
    return createCustomerTeardownRouter({
      accountId: config.CLOUDFLARE_ACCOUNT_ID, installId: config.ANKKA_INSTALL_ID,
      managementOrigin, controlPlaneOrigin: gatewayControlPlaneOrigin(),
      workerName: config.ANKKA_WORKER_NAME, workersSubdomain: config.ANKKA_WORKERS_SUBDOMAIN,
      publicClientId: trust.publicClientId, encryptionKey: config.ANKKA_GATEWAY_OWNERSHIP_WRAP_KEY,
    }, {
      attempts: new DurableCustomerTeardownAttemptPort(this.finalState.storage),
      transport: (target, init) => fetch(target, init),
      assertOperational: () => this.assertOperational(config).then(() => undefined),
      command: (command, body, signature) => super.fetch(new Request(`https://admin-state.invalid/teardown-actions/${command}-current`, {
        method: 'POST', headers: { 'content-type': 'application/json', 'x-ankka-teardown-action-signature': signature }, body,
      })),
      issueRelayTicket: (kinds) => this.issueOperationRelayTicket(config, 'uninstall', kinds),
      signHandoff: async (completion, priorGrantRevocationUnconfirmed) => {
        const journal = await new CustomerStage2DurableStatePort(this.finalState.storage).read();
        if (journal === null) throw new Error('teardown_unavailable');
        return createGatewayTeardownHandoff({
          certificate, privateKey: await openCustomerGatewayOwnershipPrivateKey({ storage: this.finalState.storage,
            wrappingKey: config.ANKKA_GATEWAY_OWNERSHIP_WRAP_KEY }),
          trust: { pinnedIssuerPublicKey: trust.pinnedIssuerPublicKey, expectedKeyId: trust.issuerKeyId,
            expectedPublicClientId: trust.publicClientId },
          plan: await verifyStaticDeployPlanIntegrity(JSON.parse(serializedPlan)), journal,
          actionId: completion.actionId, nonce: randomBase64Url(32),
          readyReceiptChecksum: completion.readyReceiptChecksum, dependencyResourcesHash: completion.dependencyResourcesHash,
          customerGrantRevocation: 'confirmed', priorGrantRevocationUnconfirmed, now: Date.now(),
        });
      },
    });
  }

  private bigQuerySetup(config: ParsedFinalEnv) {
    return createBigQuerySetup({
      accountId: config.CLOUDFLARE_ACCOUNT_ID, zoneId: config.CLOUDFLARE_ZONE_ID,
      zoneName: config.CLOUDFLARE_ZONE_NAME, installationId: config.ANKKA_INSTALL_ID,
      accessIssuer: new URL(config.CF_ACCESS_ISSUER).origin,
      managementOrigin: `https://${config.ANKKA_MANAGEMENT_HOSTNAME}`,
      workerName: config.ANKKA_WORKER_NAME, workersSubdomain: config.ANKKA_WORKERS_SUBDOMAIN,
      controlPlaneOrigin: v.parse(v.string(), gatewayControlPlaneOrigin()),
      releaseIdentity: { schemaVersion: 1, channel: config.ANKKA_UPDATE_CHANNEL,
        controlPlaneOrigin: v.parse(v.string(), gatewayControlPlaneOrigin()), release: config.ANKKA_GATEWAY_RELEASE, keyId: config.ANKKA_UPDATE_KEY_ID,
        publicKey: config.ANKKA_UPDATE_PUBLIC_KEY, artifactSha256: config.ANKKA_GATEWAY_RELEASE_SHA256.slice('sha256:'.length) },
    }, { storage: this.finalState.storage, runtime: (request) => super.fetch(request),
      fetch: (input, init) => fetch(input, init) });

  }

  /** Authorizes and applies a later operation with the public client the trust names. */
  private async operationRouter(config: ParsedFinalEnv, managementOrigin: string) {
    const ownership = await this.assertOperational(config);
    if (ownership.trust === null) throw new Error('operation_unavailable');
    const publicClientId = ownership.trust.publicClientId;
    return createCustomerOperationRouter({
      accountId: config.CLOUDFLARE_ACCOUNT_ID,
      installId: config.ANKKA_INSTALL_ID,
      publicClientId,
      managementOrigin,
      workerName: config.ANKKA_WORKER_NAME,
      workersSubdomain: config.ANKKA_WORKERS_SUBDOMAIN,
      release: config.ANKKA_GATEWAY_RELEASE,
      artifactSha256: config.ANKKA_GATEWAY_RELEASE_SHA256.slice('sha256:'.length),
    }, {
      attempts: new DurableCustomerOperationAttemptPort(this.finalState.storage),
      transport: (target, init) => fetch(target, init),
      assertOperational: () => this.assertOperational(config).then(() => undefined),
      readSourceAction: (actionId) => this.readSourceAction(actionId),
      readBigQueryAction: async (actionId) => {
        if (!bigQuerySetupAvailable()) return null;
        const current = await this.bigQuerySetup(config).readSourceAction(actionId);
        return current === null ? null : { status: current.action.status, expiresAt: Date.parse(current.action.expiresAt) };
      },
      runBigQuerySetup: (input) => this.bigQuerySetup(config).run(input),
      readRuntimeAction: (actionId) => this.readRuntimeAction(actionId),
      runRuntimeUpdate: (input) => this.runRuntimeUpdate(config, input),
      issueRelayTicket: (operation) => this.issueOperationRelayTicket(config, operation),
      beginRelay: (input) => beginCustomerBootstrapRelay({
        ...input,
        publicClientId,
        transport: (target, init) => fetch(target, init),
      }),
      applySourceAction: (input) => this.applySourceAction(input),
    });
  }

  /**
   * The bootstrap shell arms this alarm right before it uploads this runtime;
   * the pass that uploaded it cannot reach storage once the object restarts
   * here, so this is where a finalizing install becomes READY.
   */
  async alarm(): Promise<void> {
    await this.recoveryReady;
    // An update this object started, or the update that put this version here.
    try {
      await this.finishRuntimeHandover(parsedEnv(this.finalEnv));
    } catch {
      // A refused journal write leaves the action for the dashboard to show; the record is gone.
    }
    try {
      await finalizeCustomerBootstrapHandover(
        new CustomerBootstrapDurableStatePort(this.finalState.storage),
        Date.now(),
      );
    } catch {
      // A conflicting write means another pass already settled the attempt.
    }
    // A recovery attempt runs its passes here too, one alarm each.
    try {
      const driver = await this.recoveryDriver();
      if (driver !== null) await driver.continue();
    } catch {
      // The driver settles what it can; a thrown port leaves the next look to the deadline.
    }
  }

  private installationObject(): DurableObjectStub {
    const namespace = this.finalEnv.ADMIN_STATE;
    return namespace.get(namespace.idFromName(customerInstallationObjectName(parsedEnv(this.finalEnv).ANKKA_INSTALL_ID)));
  }

  async fetch(request: Request): Promise<Response> {
    await this.recoveryReady;
    const config = parsedEnv(this.finalEnv);
    const url = new URL(request.url);
    const managementOrigin = `https://${config.ANKKA_MANAGEMENT_HOSTNAME}`;
    // The receipt verification runs in the installation object, where the
    // bootstrap wrote the receipt; internal only, the entry never forwards it.
    const installation = await handleCustomerInstallationObjectRequest(request, {
      bootstrapEnv: this.finalEnv,
      storage: this.finalState.storage,
      payload: { processBootstrap: async () => notFound(), verifyReceipt: verifyBootstrapReceiptProviderStateWithReason },
      now: Date.now,
    });
    if (installation !== null) return installation;
    const teardownRoute = url.pathname === CUSTOMER_TEARDOWN_PATH || url.pathname.startsWith(`${CUSTOMER_TEARDOWN_PATH}/`) ||
      (url.pathname === CUSTOMER_INSTALL_OAUTH_CALLBACK_PATH && customerTeardownCookiePresent(request));
    if (url.origin === managementOrigin && teardownRoute) {
      try { return await (await this.teardownRouter(config, managementOrigin)).fetch(request); }
      catch { return unavailable(); }
    }
    if (url.origin === managementOrigin && ['/api/bigquery', '/api/bigquery/resume'].includes(url.pathname) && url.search === '') {
      const actor = v.safeParse(v.string(), await verifyAccess(request, this.finalEnv));
      if (!actor.success) return new Response(null, { status: 401, headers: secureHeaders('application/json') });
      if (!bigQuerySetupAvailable()) return new Response(JSON.stringify({ schemaVersion: 1, available: false, setups: [] }), {
        status: request.method === 'GET' ? 200 : 409, headers: secureHeaders('application/json'),
      });
      const setup = this.bigQuerySetup(config);
      try {
        await this.assertOperational(config);
        if (request.method === 'GET' && url.pathname === '/api/bigquery') return setup.list();
        if (request.method !== 'POST' || request.headers.get('origin') !== managementOrigin ||
            request.headers.get('content-type')?.split(';')[0]?.trim() !== 'application/json' ||
            ![null, 'same-origin'].includes(request.headers.get('sec-fetch-site'))) return notFound();
        return await setup.prepare(request, actor.output, url.pathname.endsWith('/resume'));
      } catch { return new Response(JSON.stringify({ error: 'bigquery_setup_invalid' }), { status: 400, headers: secureHeaders('application/json') }); }
    }
    // A later operation owns its page and start route; it also claims the
    // certified callback while the browser carries an operation attempt.
    const operationRoute = url.pathname.startsWith(CUSTOMER_OPERATION_ROOT_PATH) ||
      (url.pathname === CUSTOMER_INSTALL_OAUTH_CALLBACK_PATH && customerOperationCookiePresent(request));
    if (url.origin === managementOrigin && operationRoute) {
      try {
        const router = await this.operationRouter(config, managementOrigin);
        return await router.fetch(request);
      } catch {
        return unavailable();
      }
    }
    if (url.origin !== managementOrigin || !url.pathname.startsWith(CUSTOMER_INSTALL_ROOT_PATH)) {
      return super.fetch(request);
    }
    if (request.method === 'GET' && url.pathname === CUSTOMER_INSTALL_ROOT_PATH &&
        url.search === '') {
      try {
        const ownership = await this.assertRecoverable(config);
        const bootstrap = await new CustomerBootstrapDurableStatePort(this.finalState.storage).read();
        return ownership.trust !== null && bootstrap?.status !== 'READY' ? recoveryPage() : notFound();
      } catch {
        return unavailable();
      }
    }
    if (request.method === 'GET' && url.pathname === CUSTOMER_INSTALL_STATUS_PATH &&
        url.search === '') {
      try {
        await this.assertRecoverable(config);
        const bootstrap = await new CustomerBootstrapDurableStatePort(this.finalState.storage).read();
        return new Response(JSON.stringify({
          schemaVersion: 1,
          status: bootstrap?.status ?? 'INCOMPLETE',
        }), { status: 200, headers: secureHeaders('application/json; charset=utf-8') });
      } catch {
        return unavailable();
      }
    }
    if (url.pathname !== CUSTOMER_INSTALL_OAUTH_START_PATH &&
        url.pathname !== CUSTOMER_INSTALL_OAUTH_CALLBACK_PATH) return notFound();
    try {
      const ownership = await this.assertRecoverable(config);
      if (ownership.trust === null) return unavailable();
      const publicClientId = ownership.trust.publicClientId;
      const state = new CustomerBootstrapDurableStatePort(this.finalState.storage);
      const router = createCustomerStage2RecoveryRouter({
        accountId: config.CLOUDFLARE_ACCOUNT_ID,
        installId: config.ANKKA_INSTALL_ID,
        publicClientId,
        managementOrigin,
      }, {
        state,
        assertRecoverable: () => this.assertRecoverable(config).then(() => undefined),
        issueRelayTicket: () => this.issueInstallRelayTicket(config),
        beginRelay: (input) => beginCustomerBootstrapRelay({
          ...input,
          publicClientId,
          transport: (target, init) => fetch(target, init),
        }),
        transport: (target, init) => fetch(target, init),
        startConvergence: async (input) => {
          const driver = await this.recoveryDriver();
          if (driver === null) throw new Error('recovery_unavailable');
          await driver.start(input);
        },
        callbackResponse: (outcome, cookies) =>
          customerInstallProgressPage(config.ANKKA_MANAGEMENT_HOSTNAME, outcome, cookies),
      });
      return router.fetch(request);
    } catch {
      return unavailable();
    }
  }
}

export default {
  async fetch(request: Request, env: FinalGatewayEnv, context: ExecutionContext): Promise<Response> {
    try {
      const config = parsedEnv(env);
      const url = new URL(request.url);
      if (url.pathname === CUSTOMER_INSTALL_CONTINUE_PATH) return notFound();
      if (url.pathname.startsWith(CUSTOMER_INSTALL_ROOT_PATH) ||
          url.pathname.startsWith(CUSTOMER_OPERATION_ROOT_PATH) ||
          ['/api/bigquery', '/api/bigquery/resume'].includes(url.pathname)) {
        if (url.origin !== `https://${config.ANKKA_MANAGEMENT_HOSTNAME}`) return notFound();
        return env.ADMIN_STATE.get(env.ADMIN_STATE.idFromName('v1:management')).fetch(request);
      }
      if (request.method === 'POST' && url.pathname === '/api/teardown-actions') {
        return prepareCurrentGatewayTeardown(request, env);
      }
      return gatewayRuntime.fetch(request, env, context);
    } catch {
      return unavailable();
    }
  },
};

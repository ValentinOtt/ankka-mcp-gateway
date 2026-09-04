import * as v from 'valibot';

// @ts-expect-error The payload is validated as a release input, not a TS package.
import gatewayRuntime, { AdminState as RuntimeAdminState, verifyBootstrapReceiptProviderStateWithReason } from '../../../payload/worker/index.js';
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
} from './customer-install-paths';
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
    super(finalState, finalEnv);
    this.recoveryReady = finalState.blockConcurrencyWhile(async () => {
      initializeCustomerBootstrapSql(finalState.storage);
      initializeCustomerStage2Sql(finalState.storage);
      await readCustomerGatewayOwnershipState(finalState.storage);
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

  /**
   * The bootstrap shell arms this alarm right before it uploads this runtime;
   * the pass that uploaded it cannot reach storage once the object restarts
   * here, so this is where a finalizing install becomes READY.
   */
  async alarm(): Promise<void> {
    await this.recoveryReady;
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
      if (url.pathname.startsWith(CUSTOMER_INSTALL_ROOT_PATH)) {
        if (url.origin !== `https://${config.ANKKA_MANAGEMENT_HOSTNAME}`) return notFound();
        return env.ADMIN_STATE.get(env.ADMIN_STATE.idFromName('v1:management')).fetch(request);
      }
      return gatewayRuntime.fetch(request, env, context);
    } catch {
      return unavailable();
    }
  },
};

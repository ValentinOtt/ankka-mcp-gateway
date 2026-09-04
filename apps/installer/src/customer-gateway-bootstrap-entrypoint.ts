import * as v from 'valibot';

// @ts-expect-error The payload is validated as a release input, not a TS package.
import { AdminState as RuntimeAdminState, processBootstrap, publishBootstrapCompletion, verifyBootstrapReceiptProviderStateWithReason } from '../../../payload/worker/index.js';
import { PUBLIC_ORIGIN } from './constants';
import { CustomerBootstrapConvergenceDriver } from './customer-bootstrap-convergence-driver';
import { beginCustomerBootstrapRelay } from './customer-bootstrap-relay-client';
import {
  CustomerBootstrapDurableStatePort,
  initializeCustomerBootstrapSql,
} from './customer-bootstrap-durable-state';
import {
  createCustomerBootstrapRouter,
  type CustomerBootstrapCallbackOutcome,
} from './customer-bootstrap-router';
import {
  acceptCustomerGatewayOwnershipHandoff,
  initializeCustomerGatewayOwnershipState,
  openCustomerGatewayOwnershipPrivateKey,
  readCustomerGatewayOwnershipState,
} from './customer-gateway-ownership-state';
import { requestCustomerGatewayRelayTicket } from './customer-gateway-relay-ticket-client';
import {
  CUSTOMER_STAGE2_CHUNK_CHECKPOINTS,
  convergeCustomerStage2,
  type CustomerStage2ConvergerResult,
} from './customer-stage2-converger';
import {
  CustomerStage2DurableStatePort,
  initializeCustomerStage2Sql,
} from './customer-stage2-durable-state';
import { prepareCustomerBootstrapClaimFromPlan } from './customer-bootstrap-request';
import {
  customerInstallationObjectName,
  handleCustomerInstallationObjectRequest,
  verifyReceiptInInstallationObject,
} from './customer-installation-object';
import {
  CUSTOMER_INSTALL_CONTINUE_PATH,
  CUSTOMER_INSTALL_OAUTH_CALLBACK_PATH,
  CUSTOMER_INSTALL_OAUTH_START_PATH,
  CUSTOMER_INSTALL_ROOT_PATH,
  CUSTOMER_INSTALL_STATUS_PATH,
} from './customer-install-paths';
import type { CustomerInstallStatus } from './customer-install-status';
import { customerPayloadEnvironment } from './customer-payload-environment';

declare const __ANKKA_FINAL_RUNTIME_SOURCE__: string;

const TOKEN = /^[A-Za-z0-9_-]{43}$/u;
const envSchema = v.object({
  CLOUDFLARE_ACCOUNT_ID: v.pipe(v.string(), v.regex(/^[a-f0-9]{32}$/u)),
  ANKKA_INSTALL_ID: v.pipe(v.string(), v.regex(/^acg-[a-f0-9]{24}$/u)),
  ANKKA_WORKER_NAME: v.pipe(v.string(), v.regex(/^[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$/u)),
  ANKKA_GATEWAY_RELEASE: v.pipe(v.string(), v.regex(/^gateway-v(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)$/u)),
  ANKKA_GATEWAY_RELEASE_SHA256: v.pipe(v.string(), v.regex(/^sha256:[a-f0-9]{64}$/u)),
  ANKKA_PLAN_ID: v.pipe(v.string(), v.regex(/^plan-[a-f0-9]{24}$/u)),
  ANKKA_PLAN_HASH: v.pipe(v.string(), v.regex(/^sha256:[a-f0-9]{64}$/u)),
  ANKKA_BOOTSTRAP_ID: v.pipe(v.string(), v.regex(/^boot_[A-Za-z0-9_-]{24}$/u)),
  ANKKA_BOOTSTRAP_SECRET_SHA256: v.pipe(v.string(), v.regex(/^sha256:[a-f0-9]{64}$/u)),
  ANKKA_BOOTSTRAP_EXPIRES_AT: v.pipe(v.string(), v.regex(/^\d{10,16}$/u)),
  ANKKA_BOOTSTRAP_CALLBACK: v.pipe(v.string(), v.url()),
  ANKKA_INSTALLER_ORIGIN: v.literal(PUBLIC_ORIGIN),
  ANKKA_MANAGEMENT_HOSTNAME: v.string(),
  ANKKA_UPDATE_CHANNEL: v.picklist(['canary', 'stable']),
  ANKKA_UPDATE_KEY_ID: v.pipe(v.string(), v.regex(/^[a-z0-9](?:[a-z0-9._-]{0,62}[a-z0-9])?$/u)),
  ANKKA_UPDATE_PUBLIC_KEY: v.pipe(v.string(), v.regex(TOKEN)),
  CLOUDFLARE_CUSTOMER_OAUTH_CLIENT_ID: v.pipe(v.string(), v.regex(/^[A-Za-z0-9_-]{16,128}$/u)),
  CLOUDFLARE_OWNERSHIP_ISSUER_PUBLIC_KEY: v.pipe(v.string(), v.regex(TOKEN)),
  CLOUDFLARE_OWNERSHIP_ISSUER_KEY_ID: v.pipe(v.string(), v.regex(/^[a-z0-9](?:[a-z0-9._-]{0,62}[a-z0-9])?$/u)),
  ANKKA_GATEWAY_OWNERSHIP_WRAP_KEY: v.pipe(v.string(), v.regex(TOKEN)),
  ANKKA_BOOTSTRAP_NONCE: v.pipe(v.string(), v.regex(TOKEN)),
});

interface BootstrapEnv extends Record<string, unknown> {
  ADMIN_STATE: DurableObjectNamespace;
  CLOUDFLARE_ACCOUNT_ID: string;
  ANKKA_INSTALL_ID: string;
  ANKKA_WORKER_NAME: string;
  ANKKA_GATEWAY_RELEASE: string;
  ANKKA_GATEWAY_RELEASE_SHA256: string;
  ANKKA_INSTALLER_ORIGIN: typeof PUBLIC_ORIGIN;
  ANKKA_PLAN_ID: string;
  ANKKA_PLAN_HASH: string;
  ANKKA_BOOTSTRAP_ID: string;
  ANKKA_BOOTSTRAP_SECRET_SHA256: string;
  ANKKA_BOOTSTRAP_EXPIRES_AT: string;
  ANKKA_BOOTSTRAP_CALLBACK: string;
  ANKKA_MANAGEMENT_HOSTNAME: string;
  ANKKA_UPDATE_CHANNEL: 'canary' | 'stable';
  ANKKA_UPDATE_KEY_ID: string;
  ANKKA_UPDATE_PUBLIC_KEY: string;
  CLOUDFLARE_CUSTOMER_OAUTH_CLIENT_ID: string;
  CLOUDFLARE_OWNERSHIP_ISSUER_PUBLIC_KEY: string;
  CLOUDFLARE_OWNERSHIP_ISSUER_KEY_ID: string;
  ANKKA_GATEWAY_OWNERSHIP_WRAP_KEY: string;
  ANKKA_BOOTSTRAP_NONCE: string;
}

const namespaceSchema = v.object({ idFromName: v.function(), get: v.function() });

function parsedEnv(env: BootstrapEnv) {
  const parsed = v.safeParse(envSchema, env);
  if (!parsed.success || !v.is(namespaceSchema, env.ADMIN_STATE)) throw new Error('bootstrap_config_invalid');
  const expiresAt = Number(parsed.output.ANKKA_BOOTSTRAP_EXPIRES_AT);
  const callback = new URL(parsed.output.ANKKA_BOOTSTRAP_CALLBACK);
  const managementHostname = parsed.output.ANKKA_MANAGEMENT_HOSTNAME;
  if (!Number.isSafeInteger(expiresAt) || expiresAt <= 0 ||
      callback.pathname !== CUSTOMER_INSTALL_OAUTH_CALLBACK_PATH ||
      callback.search !== '' || callback.hash !== '' ||
      managementHostname !== managementHostname.toLowerCase() || !managementHostname.includes('.')) {
    throw new Error('bootstrap_config_invalid');
  }
  return Object.freeze({ ...parsed.output, expiresAt });
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

function unavailable(): Response {
  return new Response(JSON.stringify({ schemaVersion: 1, error: 'bootstrap_unavailable' }), {
    status: 503,
    headers: secureHeaders('application/json; charset=utf-8'),
  });
}

function handoffPage(): Response {
  const nonce = crypto.randomUUID().replaceAll('-', '');
  const headers = secureHeaders('text/html; charset=utf-8');
  headers.set('content-security-policy', `default-src 'none'; script-src 'nonce-${nonce}'; connect-src 'self'; style-src 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'`);
  return new Response(`<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><meta name="referrer" content="no-referrer"><title>Install Ankka Gateway</title><style>body{font:16px/1.5 system-ui,sans-serif;max-width:42rem;margin:5rem auto;padding:0 1.25rem;color:#171713}button{font:inherit;padding:.75rem 1rem}pre{white-space:pre-wrap}</style><h1>Finishing your Ankka Gateway</h1><p id="message">Checking the secure handoff…</p><button id="retry" hidden>Try again</button><script nonce="${nonce}">(()=>{const message=document.querySelector('#message');const retry=document.querySelector('#retry');let handoff=null;const decode=()=>{const raw=location.hash.slice(1);if(!raw)return null;const normalized=raw.replace(/-/g,'+').replace(/_/g,'/');return JSON.parse(new TextDecoder().decode(Uint8Array.from(atob(normalized.padEnd(Math.ceil(normalized.length/4)*4,'=')),c=>c.charCodeAt(0))))};const run=async()=>{retry.hidden=true;try{handoff=handoff??decode();history.replaceState(null,'','${CUSTOMER_INSTALL_ROOT_PATH}');if(!handoff)throw new Error();let response=await fetch('${CUSTOMER_INSTALL_CONTINUE_PATH}',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(handoff),credentials:'same-origin',cache:'no-store'});if(!response.ok)throw new Error();message.textContent='One more Cloudflare approval will finish setup.';response=await fetch('${CUSTOMER_INSTALL_OAUTH_START_PATH}',{method:'POST',headers:{'content-type':'application/json'},body:'{}',credentials:'same-origin',cache:'no-store'});const value=await response.json();if(!response.ok||typeof value.authorizationUrl!=='string')throw new Error();location.assign(value.authorizationUrl)}catch{message.textContent='The setup link expired or could not be verified. Return to deploy.ankka.ai and try again.';retry.hidden=false}};retry.addEventListener('click',run);run()})();</script></html>`, {
    status: 200,
    headers,
  });
}

function scriptLiteral<Value>(value: Value): string {
  return JSON.stringify(value).replaceAll('<', '\\u003c');
}

/**
 * Where the second Cloudflare approval lands. The passes run behind alarms,
 * so the page follows the status route until the attempt settles; the
 * temporary workers.dev address closes as the last step of a successful
 * install, which the page reads as "open your Gateway" rather than an error.
 */
function convergencePage(
  managementHostname: string,
  outcome: CustomerBootstrapCallbackOutcome,
  cookies: readonly string[],
): Response {
  const nonce = crypto.randomUUID().replaceAll('-', '');
  const headers = secureHeaders('text/html; charset=utf-8');
  headers.set('content-security-policy', `default-src 'none'; script-src 'nonce-${nonce}'; connect-src 'self'; style-src 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'`);
  for (const cookie of cookies) headers.append('set-cookie', cookie);
  const initial = scriptLiteral({
    status: outcome.status,
    failure: outcome.failureCode === null ? null : { code: outcome.failureCode, reason: outcome.failureReason },
  });
  return new Response(`<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><meta name="referrer" content="no-referrer"><title>Install Ankka Gateway</title><style>body{font:16px/1.5 system-ui,sans-serif;max-width:42rem;margin:5rem auto;padding:0 1.25rem;color:#171713}code{font:.9375em ui-monospace,monospace}a{color:#1d4ed8}</style><h1 id="title">Finishing your Ankka Gateway</h1><p id="message">Cloudflare approved the install. Setting up the Gateway takes a few minutes; this page updates itself.</p><p id="detail"></p><script nonce="${nonce}">(()=>{const management=${scriptLiteral(`https://${managementHostname}/`)};const title=document.querySelector('#title');const message=document.querySelector('#message');const detail=document.querySelector('#detail');let misses=0;let sawConverging=false;const show=(state)=>{if(state.status==='READY'){title.textContent='Your Ankka Gateway is ready';message.textContent='';const link=document.createElement('a');link.href=management;link.textContent='Open your management page';message.append(link);detail.textContent='';return true}if(state.status==='INCOMPLETE'){title.textContent='Setup did not complete';message.textContent='The Gateway stopped before it was ready. Return to deploy.ankka.ai to remove this install and try again.';const failure=state.failure;detail.textContent=failure?'Reason: '+failure.code+(failure.reason?' / '+failure.reason:''):'';return true}sawConverging=true;return false};const closed=()=>{title.textContent='Setup finished';message.textContent='This temporary setup address has closed, which happens when the Gateway is ready. Open your management page; if it does not answer, return to deploy.ankka.ai.';const link=document.createElement('a');link.href=management;link.textContent=management;detail.textContent='';detail.append(link)};const poll=async()=>{try{const response=await fetch(${scriptLiteral(CUSTOMER_INSTALL_STATUS_PATH)},{credentials:'omit',cache:'no-store'});if(!response.ok)throw new Error();misses=0;if(show(await response.json()))return}catch{misses+=1;if(sawConverging&&misses>=3){closed();return}}setTimeout(poll,3000)};if(!show(${initial}))setTimeout(poll,3000)})();</script></html>`, {
    status: 200,
    headers,
  });
}

interface BootstrapDurableObjectState extends DurableObjectState {
  blockConcurrencyWhile<T>(callback: () => Promise<T>): Promise<T>;
}

export class AdminState extends RuntimeAdminState {
  private readonly bootstrapReady: Promise<void>;
  /** Grant and pass count of the running attempt, in memory only. */
  private readonly convergence: CustomerBootstrapConvergenceDriver;

  constructor(
    private readonly bootstrapState: BootstrapDurableObjectState,
    private readonly bootstrapEnv: BootstrapEnv,
  ) {
    super(bootstrapState, bootstrapEnv);
    this.bootstrapReady = bootstrapState.blockConcurrencyWhile(async () => {
      const config = parsedEnv(bootstrapEnv);
      initializeCustomerBootstrapSql(bootstrapState.storage);
      initializeCustomerStage2Sql(bootstrapState.storage);
      // The installation object only holds the payload's receipt; the
      // ownership key and the install state live in the management object.
      if (bootstrapState.id.name !== customerInstallationObjectName(config.ANKKA_INSTALL_ID)) {
        await initializeCustomerGatewayOwnershipState({
          storage: bootstrapState.storage,
          wrappingKey: config.ANKKA_GATEWAY_OWNERSHIP_WRAP_KEY,
        });
      }
    });
    this.convergence = new CustomerBootstrapConvergenceDriver({
      state: new CustomerBootstrapDurableStatePort(bootstrapState.storage),
      transport: (target, init) => fetch(target, init),
      publicClientId: parsedEnv(bootstrapEnv).CLOUDFLARE_CUSTOMER_OAUTH_CLIENT_ID,
      converge: (accessToken, attemptId, handover) => this.converge(accessToken, attemptId, handover),
      now: Date.now,
      // Every alarm is its own invocation with its own subrequest budget; the
      // delayed one fires on the final runtime after the handover.
      schedule: (delayMs) => bootstrapState.storage.setAlarm(Date.now() + delayMs),
    });
  }

  /** One converger pass per alarm; the driver re-arms until the attempt settles. */
  async alarm(): Promise<void> {
    await this.bootstrapReady;
    await this.convergence.continue();
  }

  private converge(
    accessToken: string,
    attemptId: string,
    handover: (() => Promise<void>) | undefined,
  ): Promise<CustomerStage2ConvergerResult> {
    const config = parsedEnv(this.bootstrapEnv);
    return convergeCustomerStage2({
      accessToken,
      attemptId,
      handover,
      storage: this.bootstrapState.storage,
      journal: new CustomerStage2DurableStatePort(this.bootstrapState.storage),
      runtime: {
        updateChannel: config.ANKKA_UPDATE_CHANNEL,
        updateKeyId: config.ANKKA_UPDATE_KEY_ID,
        updatePublicKey: config.ANKKA_UPDATE_PUBLIC_KEY,
      },
      bootstrap: {
        nonce: config.ANKKA_BOOTSTRAP_NONCE,
        expectedBindings: {
          ANKKA_BOOTSTRAP_CALLBACK: config.ANKKA_BOOTSTRAP_CALLBACK,
          ANKKA_BOOTSTRAP_EXPIRES_AT: config.ANKKA_BOOTSTRAP_EXPIRES_AT,
          ANKKA_BOOTSTRAP_ID: config.ANKKA_BOOTSTRAP_ID,
          ANKKA_BOOTSTRAP_SECRET_SHA256: config.ANKKA_BOOTSTRAP_SECRET_SHA256,
          ANKKA_GATEWAY_RELEASE: config.ANKKA_GATEWAY_RELEASE,
          ANKKA_GATEWAY_RELEASE_SHA256: config.ANKKA_GATEWAY_RELEASE_SHA256,
          ANKKA_INSTALL_ID: config.ANKKA_INSTALL_ID,
          ANKKA_INSTALLER_ORIGIN: config.ANKKA_INSTALLER_ORIGIN,
          ANKKA_MANAGEMENT_HOSTNAME: config.ANKKA_MANAGEMENT_HOSTNAME,
          ANKKA_PLAN_HASH: config.ANKKA_PLAN_HASH,
          ANKKA_PLAN_ID: config.ANKKA_PLAN_ID,
          ANKKA_UPDATE_CHANNEL: config.ANKKA_UPDATE_CHANNEL,
          ANKKA_UPDATE_KEY_ID: config.ANKKA_UPDATE_KEY_ID,
          ANKKA_UPDATE_PUBLIC_KEY: config.ANKKA_UPDATE_PUBLIC_KEY,
          ANKKA_WORKER_NAME: config.ANKKA_WORKER_NAME,
          CLOUDFLARE_ACCOUNT_ID: config.CLOUDFLARE_ACCOUNT_ID,
          CLOUDFLARE_CUSTOMER_OAUTH_CLIENT_ID: config.CLOUDFLARE_CUSTOMER_OAUTH_CLIENT_ID,
          CLOUDFLARE_OWNERSHIP_ISSUER_KEY_ID: config.CLOUDFLARE_OWNERSHIP_ISSUER_KEY_ID,
          CLOUDFLARE_OWNERSHIP_ISSUER_PUBLIC_KEY: config.CLOUDFLARE_OWNERSHIP_ISSUER_PUBLIC_KEY,
        },
      },
      finalRuntimeSource: __ANKKA_FINAL_RUNTIME_SOURCE__,
      payload: {
        // The bootstrap runs in the installation object, where the payload
        // keeps the receipt for verification and teardown; the public status
        // and the management control it publishes afterwards land in this,
        // the management object, exactly as the payload's own route writes
        // them. Without them the management API answers "unavailable".
        bootstrap: async (request, { target }) => {
          const claimText = await request.clone().text();
          const response = await this.installationObject().fetch(request);
          if (response.status !== 200) return response;
          const published = await publishBootstrapCompletion(
            JSON.parse(claimText),
            JSON.parse(await response.clone().text()),
            customerPayloadEnvironment(this.bootstrapEnv, target),
            Date.now(),
            (internal: Request) => super.fetch(internal),
          );
          if (published !== true) {
            return new Response(JSON.stringify({
              schemaVersion: 1,
              error: 'management_publication_failed',
              retryable: false,
            }), { status: 409, headers: { 'content-type': 'application/json; charset=utf-8' } });
          }
          return response;
        },
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

  private installationObject(): DurableObjectStub {
    const namespace = this.bootstrapEnv.ADMIN_STATE;
    return namespace.get(namespace.idFromName(customerInstallationObjectName(parsedEnv(this.bootstrapEnv).ANKKA_INSTALL_ID)));
  }

  async fetch(request: Request): Promise<Response> {
    await this.bootstrapReady;
    const config = parsedEnv(this.bootstrapEnv);
    const url = new URL(request.url);
    // Internal only: the Worker entry never forwards these two requests.
    const installation = await handleCustomerInstallationObjectRequest(request, {
      bootstrapEnv: this.bootstrapEnv,
      storage: this.bootstrapState.storage,
      payload: { processBootstrap, verifyReceipt: verifyBootstrapReceiptProviderStateWithReason },
      now: Date.now,
    });
    if (installation !== null) return installation;
    if (request.method === 'GET' && url.pathname === CUSTOMER_INSTALL_STATUS_PATH) {
      const ownership = await readCustomerGatewayOwnershipState(this.bootstrapState.storage);
      const state = await new CustomerBootstrapDurableStatePort(this.bootstrapState.storage).read();
      // Typed against the schema the hosted readiness check parses with, so
      // the shell cannot answer in a shape the hosted runtime rejects.
      const body: CustomerInstallStatus = {
        schemaVersion: 1,
        role: 'customer-gateway-bootstrap',
        status: state?.status ?? 'INCOMPLETE',
        installId: config.ANKKA_INSTALL_ID,
        release: config.ANKKA_GATEWAY_RELEASE,
        ownershipPublicKey: ownership.publicKey,
        // Secret-free: a fixed code plus numbers and fixed words naming the step.
        failure: state?.failureCode
          ? { code: state.failureCode, reason: state.failureReason ?? null }
          : null,
      };
      return new Response(JSON.stringify(body), {
        status: 200,
        headers: secureHeaders('application/json; charset=utf-8'),
      });
    }
    if (request.method === 'GET' && url.pathname === '/health' && url.search === '') {
      const ownership = await readCustomerGatewayOwnershipState(this.bootstrapState.storage);
      const state = await new CustomerBootstrapDurableStatePort(this.bootstrapState.storage).read();
      const headers = secureHeaders('application/json; charset=utf-8');
      headers.set('access-control-allow-origin', config.ANKKA_INSTALLER_ORIGIN);
      headers.set('vary', 'Origin');
      return new Response(JSON.stringify({
        schemaVersion: 1,
        role: 'customer-gateway-bootstrap',
        status: state?.status ?? 'INCOMPLETE',
        installId: config.ANKKA_INSTALL_ID,
        release: config.ANKKA_GATEWAY_RELEASE,
        ownershipPublicKey: ownership.publicKey,
      }), { status: 200, headers });
    }
    if (url.pathname !== CUSTOMER_INSTALL_CONTINUE_PATH &&
        url.pathname !== CUSTOMER_INSTALL_OAUTH_START_PATH &&
        url.pathname !== CUSTOMER_INSTALL_OAUTH_CALLBACK_PATH) {
      return super.fetch(request);
    }
    const router = createCustomerBootstrapRouter({
      accountId: config.CLOUDFLARE_ACCOUNT_ID,
      installId: config.ANKKA_INSTALL_ID,
      bootstrapId: config.ANKKA_BOOTSTRAP_ID,
      secretCommitment: config.ANKKA_BOOTSTRAP_SECRET_SHA256,
      capabilityExpiresAt: config.expiresAt,
      publicClientId: config.CLOUDFLARE_CUSTOMER_OAUTH_CLIENT_ID,
    }, {
      state: new CustomerBootstrapDurableStatePort(this.bootstrapState.storage),
      transport: (input, init) => fetch(input, init),
      acceptHandoff: ({ serializedHandoff, serializedPlan, ownershipCertificate }) =>
        acceptCustomerGatewayOwnershipHandoff({
          storage: this.bootstrapState.storage,
          config: {
            accountId: config.CLOUDFLARE_ACCOUNT_ID,
            installId: config.ANKKA_INSTALL_ID,
            workerName: config.ANKKA_WORKER_NAME,
            plan: { id: config.ANKKA_PLAN_ID, hash: config.ANKKA_PLAN_HASH },
            release: {
              id: config.ANKKA_GATEWAY_RELEASE,
              artifactSha256: config.ANKKA_GATEWAY_RELEASE_SHA256.slice('sha256:'.length),
            },
            bootstrapSecretCommitment: config.ANKKA_BOOTSTRAP_SECRET_SHA256,
            bootstrapExpiresAt: config.expiresAt,
            bootstrapCallback: config.ANKKA_BOOTSTRAP_CALLBACK,
            gatewayCallback: `https://${config.ANKKA_MANAGEMENT_HOSTNAME}${CUSTOMER_INSTALL_OAUTH_CALLBACK_PATH}`,
            publicClientId: config.CLOUDFLARE_CUSTOMER_OAUTH_CLIENT_ID,
            pinnedIssuerPublicKey: config.CLOUDFLARE_OWNERSHIP_ISSUER_PUBLIC_KEY,
            issuerKeyId: config.CLOUDFLARE_OWNERSHIP_ISSUER_KEY_ID,
          },
          serializedHandoff,
          serializedPlan,
          ownershipCertificate,
          now: Date.now(),
        }).then(() => undefined),
      beginRelay: (input) => beginCustomerBootstrapRelay({
        ...input,
        publicClientId: config.CLOUDFLARE_CUSTOMER_OAUTH_CLIENT_ID,
        transport: (target, init) => fetch(target, init),
      }),
      issueRelayTicket: async () => {
        const ownership = await readCustomerGatewayOwnershipState(this.bootstrapState.storage);
        if (ownership.ownershipCertificate === null || ownership.certificateSha256 === null ||
            ownership.trust === null ||
            ownership.trust.publicClientId !== config.CLOUDFLARE_CUSTOMER_OAUTH_CLIENT_ID ||
            ownership.trust.gatewayCallback !==
              `https://${config.ANKKA_MANAGEMENT_HOSTNAME}${CUSTOMER_INSTALL_OAUTH_CALLBACK_PATH}`) {
          throw new Error('customer_gateway_ownership_invalid');
        }
        const privateKey = await openCustomerGatewayOwnershipPrivateKey({
          storage: this.bootstrapState.storage,
          wrappingKey: config.ANKKA_GATEWAY_OWNERSHIP_WRAP_KEY,
        });
        return requestCustomerGatewayRelayTicket({
          certificate: ownership.ownershipCertificate,
          certificateSha256: ownership.certificateSha256,
          gatewayCallback: ownership.trust.gatewayCallback,
          operation: 'install',
          ownershipPrivateKey: privateKey,
          transport: (target, init) => fetch(target, init),
        });
      },
      startConvergence: (input) => this.convergence.start(input),
      callbackResponse: (outcome, cookies) => convergencePage(config.ANKKA_MANAGEMENT_HOSTNAME, outcome, cookies),
    });
    return router.fetch(request);
  }
}

export default {
  async fetch(request: Request, env: BootstrapEnv): Promise<Response> {
    try {
      const config = parsedEnv(env);
      const url = new URL(request.url);
      if (url.origin !== new URL(config.ANKKA_BOOTSTRAP_CALLBACK).origin) return unavailable();
      if (request.method === 'GET' && url.pathname === CUSTOMER_INSTALL_ROOT_PATH &&
          url.search === '') return handoffPage();
      if (!(
        request.method === 'GET' && (url.pathname === '/health' ||
          url.pathname === CUSTOMER_INSTALL_STATUS_PATH ||
          url.pathname === CUSTOMER_INSTALL_OAUTH_CALLBACK_PATH) ||
        request.method === 'POST' && (url.pathname === CUSTOMER_INSTALL_CONTINUE_PATH ||
          url.pathname === CUSTOMER_INSTALL_OAUTH_START_PATH)
      )) return new Response(null, { status: 404, headers: secureHeaders('text/plain; charset=utf-8') });
      return env.ADMIN_STATE.get(env.ADMIN_STATE.idFromName('v1:management')).fetch(request);
    } catch {
      return unavailable();
    }
  },
};

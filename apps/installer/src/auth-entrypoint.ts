import * as v from 'valibot';

import { CLOUDFLARE_CODE_RELAY_ORIGIN } from './cloudflare-code-relay';
import { createCloudflareCodeRelayHttpHandler } from './cloudflare-code-relay-http';
import {
  CloudflareGatewayOwnershipChallengeDurableState,
  initializeCloudflareGatewayOwnershipChallengeSql,
} from './cloudflare-gateway-ownership-challenge-durable-state';
import { CLOUDFLARE_GATEWAY_OWNERSHIP_CHALLENGE_TTL_MS } from
  './cloudflare-gateway-ownership-proof';
import { createCloudflareGatewayOwnershipProofHttpHandler } from
  './cloudflare-gateway-ownership-proof-http';
import type { CustomerCloudflareOperation } from './cloudflare-operation-authority';

const CLIENT_ID = /^[A-Za-z0-9_-]{16,128}$/u;
const KEY_ID = /^[a-z0-9](?:[a-z0-9._-]{0,62}[a-z0-9])?$/u;
const TOKEN = /^[A-Za-z0-9_-]{43}$/u;
const OWNERSHIP_ROUTE = /^\/oauth\/relay-ticket\/(?:challenge|issue)\/(install|upgrade|rollback|source-add|source-update|source-remove|uninstall)$/u;

const authConfigSchema = v.object({
  CLOUDFLARE_CUSTOMER_OAUTH_CLIENT_ID: v.pipe(v.string(), v.regex(CLIENT_ID)),
  CLOUDFLARE_RELAY_STATE_KEY: v.pipe(v.string(), v.regex(TOKEN)),
  CLOUDFLARE_RELAY_TICKET_KEY: v.pipe(v.string(), v.regex(TOKEN)),
  CLOUDFLARE_OWNERSHIP_ISSUER_PUBLIC_KEY: v.pipe(v.string(), v.regex(TOKEN)),
  CLOUDFLARE_OWNERSHIP_ISSUER_KEY_ID: v.pipe(v.string(), v.regex(KEY_ID)),
});

export interface CloudflareAuthDurableObjectStub {
  fetch(request: Request): Promise<Response>;
}

export interface CloudflareAuthDurableObjectNamespace {
  idFromName(name: string): DurableObjectId;
  get(id: DurableObjectId): CloudflareAuthDurableObjectStub;
}

export interface CloudflareAuthEnv {
  /** Public PKCE-only OAuth client identifier. It is not a credential. */
  CLOUDFLARE_CUSTOMER_OAUTH_CLIENT_ID: string;
  /** HMAC secrets. They exist only on auth.ankka.ai. */
  CLOUDFLARE_RELAY_STATE_KEY: string;
  CLOUDFLARE_RELAY_TICKET_KEY: string;
  /** Public verifier and identifier for certificates issued by deploy.ankka.ai. */
  CLOUDFLARE_OWNERSHIP_ISSUER_PUBLIC_KEY: string;
  CLOUDFLARE_OWNERSHIP_ISSUER_KEY_ID: string;
  GATEWAY_OWNERSHIP_CHALLENGE: CloudflareAuthDurableObjectNamespace;
}

interface ParsedCloudflareAuthConfig {
  readonly publicClientId: string;
  readonly relayStateKey: string;
  readonly relayTicketKey: string;
  readonly pinnedIssuerPublicKey: string;
  readonly issuerKeyId: string;
}

const namespaceSchema = v.object({ idFromName: v.function(), get: v.function() });

function parseConfig(env: CloudflareAuthEnv): ParsedCloudflareAuthConfig | null {
  const parsed = v.safeParse(authConfigSchema, env);
  if (!parsed.success || !v.is(namespaceSchema, env.GATEWAY_OWNERSHIP_CHALLENGE)) return null;
  return Object.freeze({
    publicClientId: parsed.output.CLOUDFLARE_CUSTOMER_OAUTH_CLIENT_ID,
    relayStateKey: parsed.output.CLOUDFLARE_RELAY_STATE_KEY,
    relayTicketKey: parsed.output.CLOUDFLARE_RELAY_TICKET_KEY,
    pinnedIssuerPublicKey: parsed.output.CLOUDFLARE_OWNERSHIP_ISSUER_PUBLIC_KEY,
    issuerKeyId: parsed.output.CLOUDFLARE_OWNERSHIP_ISSUER_KEY_ID,
  });
}

function headers(): Headers {
  return new Headers({
    'cache-control': 'no-store',
    'content-security-policy': "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
    'content-type': 'application/json; charset=utf-8',
    'referrer-policy': 'no-referrer',
    'x-content-type-options': 'nosniff',
  });
}

function unavailable(): Response {
  return new Response(JSON.stringify({ schemaVersion: 1, error: 'relay_unavailable' }), {
    status: 503,
    headers: headers(),
  });
}

function health(): Response {
  return new Response(JSON.stringify({
    schemaVersion: 1,
    ok: true,
    role: 'cloudflare-code-relay',
    tokenExchange: false,
  }), { status: 200, headers: headers() });
}

function exactAuthUrl(request: Request): URL | null {
  try {
    const url = new URL(request.url);
    return url.origin === CLOUDFLARE_CODE_RELAY_ORIGIN && url.username === '' &&
      url.password === '' && url.port === '' && url.hash === '' ? url : null;
  } catch {
    return null;
  }
}

function ownershipOperation(pathname: string): CustomerCloudflareOperation | null {
  const operation = OWNERSHIP_ROUTE.exec(pathname)?.[1];
  return operation === 'install' || operation === 'upgrade' || operation === 'rollback' ||
    operation === 'source-add' ||
    operation === 'source-update' || operation === 'source-remove' || operation === 'uninstall'
    ? operation
    : null;
}

export interface CloudflareAuthWorkerDependencies {
  readonly now?: () => number;
}

/**
 * Public auth.ankka.ai runtime. This deployment has no OAuth client secret,
 * release bucket, Cloudflare management transport, or customer credential
 * binding; it can authenticate fixed operations and relay codes only.
 */
export function createCloudflareAuthWorker(
  dependencies: CloudflareAuthWorkerDependencies = {},
): Readonly<{ fetch(request: Request, env: CloudflareAuthEnv): Promise<Response> }> {
  const now = dependencies.now ?? Date.now;
  return Object.freeze({
    async fetch(request: Request, env: CloudflareAuthEnv): Promise<Response> {
      const url = exactAuthUrl(request);
      if (url === null) return unavailable();
      const config = parseConfig(env);
      if (config === null) return unavailable();
      if (request.method === 'GET' && url.pathname === '/health' && url.search === '') {
        return health();
      }
      const operation = ownershipOperation(url.pathname);
      if (request.method === 'POST' && operation !== null && url.search === '') {
        try {
          const id = env.GATEWAY_OWNERSHIP_CHALLENGE.idFromName(`v1:${operation}`);
          return await env.GATEWAY_OWNERSHIP_CHALLENGE.get(id).fetch(request);
        } catch {
          return unavailable();
        }
      }
      return createCloudflareCodeRelayHttpHandler({
        publicClientId: config.publicClientId,
        relayStateKey: config.relayStateKey,
        relayTicketKey: config.relayTicketKey,
      }, { now }).fetch(request);
    },
  });
}

interface ChallengeDurableObjectState {
  readonly storage: DurableObjectStorage;
  blockConcurrencyWhile<T>(callback: () => Promise<T>): Promise<T>;
}

/** Hash-only, operation-sharded state used by ownership proof issuance. */
export class CloudflareGatewayOwnershipChallenge {
  private readonly ready: Promise<void>;

  constructor(
    private readonly state: ChallengeDurableObjectState,
    private readonly env: CloudflareAuthEnv,
  ) {
    this.ready = state.blockConcurrencyWhile(async () => {
      initializeCloudflareGatewayOwnershipChallengeSql(state.storage);
    });
  }

  async fetch(request: Request): Promise<Response> {
    await this.ready;
    const config = parseConfig(this.env);
    if (config === null) return unavailable();
    const response = await createCloudflareGatewayOwnershipProofHttpHandler({
      publicClientId: config.publicClientId,
      pinnedIssuerPublicKey: config.pinnedIssuerPublicKey,
      issuerKeyId: config.issuerKeyId,
      relayTicketKey: config.relayTicketKey,
    }, {
      store: new CloudflareGatewayOwnershipChallengeDurableState(this.state.storage),
    }).fetch(request);
    let challengeIssued = false;
    try {
      const url = new URL(request.url);
      challengeIssued = response.status === 200 &&
        url.pathname.startsWith('/oauth/relay-ticket/challenge/');
    } catch {
      challengeIssued = false;
    }
    if (challengeIssued) {
      try {
        await this.state.storage.setAlarm(
          Date.now() + CLOUDFLARE_GATEWAY_OWNERSHIP_CHALLENGE_TTL_MS,
        );
      } catch {
        return unavailable();
      }
    }
    return response;
  }

  async alarm(): Promise<void> {
    await this.ready;
    new CloudflareGatewayOwnershipChallengeDurableState(this.state.storage).pruneExpired(Date.now());
    await this.state.storage.deleteAlarm();
  }
}

export default createCloudflareAuthWorker();

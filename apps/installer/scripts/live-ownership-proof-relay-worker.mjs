/**
 * Disposable relay used only to qualify later-operation ownership proof on
 * the Cloudflare Workers runtime. Production remains disabled and unwired.
 */

import { DurableObject } from 'cloudflare:workers';

import {
  CloudflareGatewayOwnershipChallengeDurableState,
  initializeCloudflareGatewayOwnershipChallengeSql,
} from '../src/cloudflare-gateway-ownership-challenge-durable-state.ts';
import { createCloudflareGatewayOwnershipProofHttpHandler } from
  '../src/cloudflare-gateway-ownership-proof-http.ts';
import { verifyCloudflareGatewayRelayTicket } from
  '../src/cloudflare-gateway-relay-ticket.ts';

const INTERNAL_ORIGIN = 'https://auth.ankka.ai';
const TOKEN = /^[A-Za-z0-9_-]{43}$/u;
const RELAY_TICKET = /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]{43}$/u;
const MAX_BODY_BYTES = 16 * 1024;

function secureJson(value, status = 200) {
  return Response.json(value, {
    status,
    headers: {
      'cache-control': 'no-store',
      'content-security-policy': "default-src 'none'; frame-ancestors 'none'; base-uri 'none'",
      'referrer-policy': 'no-referrer',
      'x-content-type-options': 'nosniff',
    },
  });
}

function validConfig(env) {
  try {
    const origin = new URL(env.CANARY_PUBLIC_ORIGIN);
    const callback = new URL(env.CANARY_GATEWAY_CALLBACK);
    return origin.protocol === 'https:' && origin.pathname === '/' && origin.search === '' &&
      origin.hash === '' && callback.protocol === 'https:' &&
      callback.pathname === '/__ankka/install/oauth/callback' &&
      callback.search === '' && callback.hash === '' && TOKEN.test(env.CANARY_CONTROL_KEY ?? '');
  } catch {
    return false;
  }
}

async function boundedJson(request) {
  const declared = request.headers.get('content-length');
  if (declared !== null && (!Number.isSafeInteger(Number(declared)) ||
      Number(declared) > MAX_BODY_BYTES)) throw new Error('invalid');
  const serialized = await request.text();
  if (serialized.length > MAX_BODY_BYTES) throw new Error('invalid');
  return JSON.parse(serialized);
}

export class OwnershipChallengeState extends DurableObject {
  constructor(ctx, env) {
    super(ctx, env);
    this.ctx = ctx;
    initializeCloudflareGatewayOwnershipChallengeSql(ctx.storage);
    this.store = new CloudflareGatewayOwnershipChallengeDurableState(ctx.storage);
  }

  async updateAudit(update) {
    const current = await this.ctx.storage.get('canary-audit') ?? {
      writes: 0,
      consumes: 0,
      successfulConsumes: 0,
      consumeFailures: 0,
      hashOnly: true,
    };
    await this.ctx.storage.put('canary-audit', Object.freeze({ ...current, ...update(current) }));
  }

  async put(record) {
    const keys = Object.keys(record).sort().join(',');
    const hashOnly = keys === 'certificateSha256,challengeSha256,expiresAt,operation' &&
      /^sha256:[a-f0-9]{64}$/u.test(record.certificateSha256 ?? '') &&
      /^sha256:[a-f0-9]{64}$/u.test(record.challengeSha256 ?? '');
    const stored = await this.store.put(record);
    await this.updateAudit((current) => ({
      writes: current.writes + 1,
      hashOnly: current.hashOnly && hashOnly,
    }));
    return stored;
  }

  async consume(record) {
    await this.updateAudit((current) => ({
      consumes: current.consumes + 1,
    }));
    let consumed;
    try {
      consumed = await this.store.consume(record);
    } catch (error) {
      await this.updateAudit((current) => ({
        consumeFailures: (current.consumeFailures ?? 0) + 1,
      }));
      throw error;
    }
    if (consumed) {
      await this.updateAudit((current) => ({
        successfulConsumes: current.successfulConsumes + 1,
      }));
    }
    return consumed;
  }

  async summary() {
    const audit = await this.ctx.storage.get('canary-audit') ?? {
      writes: 0,
      consumes: 0,
      successfulConsumes: 0,
      consumeFailures: 0,
      hashOnly: true,
    };
    const remaining = [...this.ctx.storage.sql.exec(
      'SELECT COUNT(*) AS count FROM ankka_gateway_ownership_challenges',
    )][0]?.count ?? -1;
    return Object.freeze({ ...audit, remaining });
  }
}

function challengeStore(env) {
  const stub = env.CHALLENGE_STATE.get(env.CHALLENGE_STATE.idFromName('canary'));
  return Object.freeze({
    put: (record) => stub.put(record),
    consume: (record) => stub.consume(record),
  });
}

async function verifyTicket(request, env) {
  let body;
  try {
    body = await boundedJson(request);
  } catch {
    return secureJson({ schemaVersion: 1, accepted: false }, 400);
  }
  if (Object.keys(body).sort().join(',') !== 'relayTicket' ||
      !RELAY_TICKET.test(body.relayTicket ?? '')) {
    return secureJson({ schemaVersion: 1, accepted: false }, 400);
  }
  try {
    const claims = await verifyCloudflareGatewayRelayTicket({
      ticket: body.relayTicket,
      signingKey: env.RELAY_TICKET_KEY,
      expectedClientId: env.PUBLIC_CLIENT_ID,
      expectedOperation: 'upgrade',
      expectedGatewayCallback: env.CANARY_GATEWAY_CALLBACK,
      now: Date.now(),
    });
    return secureJson({
      schemaVersion: 1,
      accepted: true,
      exactOperation: claims.operation === 'upgrade',
      exactCallback: claims.gatewayCallback === env.CANARY_GATEWAY_CALLBACK,
      exactClient: claims.publicClientId === env.PUBLIC_CLIENT_ID,
    });
  } catch {
    return secureJson({ schemaVersion: 1, accepted: false }, 400);
  }
}

export default {
  async fetch(request, env) {
    if (!validConfig(env)) return secureJson({ schemaVersion: 1, error: 'unavailable' }, 503);
    const url = new URL(request.url);
    if (url.origin !== env.CANARY_PUBLIC_ORIGIN) return new Response(null, { status: 404 });
    if (request.method === 'POST' && url.pathname === '/canary/verify-ticket' &&
        url.search === '' && url.hash === '') return verifyTicket(request, env);
    if (request.method === 'GET' && url.pathname === '/canary/audit' &&
        request.headers.get('x-ankka-canary-control') === env.CANARY_CONTROL_KEY) {
      const stub = env.CHALLENGE_STATE.get(env.CHALLENGE_STATE.idFromName('canary'));
      return secureJson({ schemaVersion: 1, ...await stub.summary() });
    }
    const internal = new URL(url.pathname + url.search, INTERNAL_ORIGIN);
    const handler = createCloudflareGatewayOwnershipProofHttpHandler({
      publicClientId: env.PUBLIC_CLIENT_ID,
      pinnedIssuerPublicKey: env.ISSUER_PUBLIC_KEY,
      issuerKeyId: env.ISSUER_KEY_ID,
      relayTicketKey: env.RELAY_TICKET_KEY,
    }, { store: challengeStore(env) });
    return handler.fetch(new Request(internal, request));
  },
};

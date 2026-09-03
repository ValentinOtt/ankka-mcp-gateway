/**
 * Disposable customer Gateway used only to prove that an AES-GCM-sealed
 * Ed25519 private key survives customer Durable Object storage, is reopened
 * non-extractably, and can obtain one fixed later-operation relay ticket.
 * Production remains disabled and unwired.
 */

import { DurableObject } from 'cloudflare:workers';

import { CLOUDFLARE_CODE_RELAY_ORIGIN } from '../src/cloudflare-code-relay.ts';
import {
  createCloudflareGatewayOwnershipChallengeRequest,
  generateCloudflareGatewayOwnershipKeyPair,
  generateSealedCloudflareGatewayOwnershipKeyPair,
  openSealedCloudflareGatewayOwnershipPrivateKey,
  verifyCloudflareGatewayOwnershipCertificate,
} from '../src/cloudflare-gateway-ownership-proof.ts';
import { requestCustomerGatewayRelayTicket } from
  '../src/customer-gateway-relay-ticket-client.ts';

const TOKEN = /^[A-Za-z0-9_-]{43}$/u;
const SHA256 = /^sha256:[a-f0-9]{64}$/u;
const MAX_BODY_BYTES = 16 * 1024;

function isString(value) {
  return Object.prototype.toString.call(value) === '[object String]';
}

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

function fixedFailure(error) {
  return error instanceof Error && /^[a-z0-9_]{1,64}$/u.test(error.message)
    ? error.message
    : 'internal_failure';
}

function validConfig(env) {
  try {
    const origin = new URL(env.CANARY_PUBLIC_ORIGIN);
    const relay = new URL(env.CANARY_RELAY_ORIGIN);
    const callback = new URL(env.CANARY_GATEWAY_CALLBACK);
    return origin.protocol === 'https:' && relay.protocol === 'https:' &&
      callback.origin === origin.origin &&
      callback.pathname === '/__ankka/install/oauth/callback' &&
      TOKEN.test(env.CANARY_CONTROL_KEY ?? '') && TOKEN.test(env.OWNERSHIP_WRAP_KEY ?? '') &&
      env.RELAY_SERVICE !== undefined;
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

async function relayFetch(env, path, init) {
  return env.RELAY_SERVICE.fetch(new Request(new URL(path, env.CANARY_RELAY_ORIGIN), {
    ...init,
    redirect: 'manual',
    signal: AbortSignal.timeout(10_000),
  }));
}

export class CustomerOwnershipState extends DurableObject {
  constructor(ctx, env) {
    super(ctx, env);
    this.ctx = ctx;
    this.env = env;
  }

  async ownershipKey() {
    let sealedPrivateKey;
    let publicKey;
    try {
      sealedPrivateKey = await this.ctx.storage.get('ownership-sealed-private-key');
      publicKey = await this.ctx.storage.get('ownership-public-key');
    } catch {
      throw new Error('key_storage_read_failed');
    }
    if (sealedPrivateKey === undefined && publicKey === undefined) {
      let generated;
      try {
        generated = await generateSealedCloudflareGatewayOwnershipKeyPair(
          this.env.OWNERSHIP_WRAP_KEY,
        );
      } catch {
        throw new Error('key_generation_failed');
      }
      try {
        await this.ctx.storage.put({
          'ownership-sealed-private-key': generated.sealedPrivateKey,
          'ownership-public-key': generated.publicKey,
        });
      } catch {
        throw new Error('key_storage_write_failed');
      }
      try {
        sealedPrivateKey = await this.ctx.storage.get('ownership-sealed-private-key');
        publicKey = await this.ctx.storage.get('ownership-public-key');
      } catch {
        throw new Error('key_storage_readback_failed');
      }
    }
    if (!TOKEN.test(publicKey ?? '') || !sealedPrivateKey) {
      throw new Error('key_storage_roundtrip_invalid');
    }
    let privateKey;
    try {
      privateKey = await openSealedCloudflareGatewayOwnershipPrivateKey({
        sealedPrivateKey,
        wrappingKey: this.env.OWNERSHIP_WRAP_KEY,
        expectedPublicKey: publicKey,
      });
    } catch {
      throw new Error('key_unseal_failed');
    }
    return { privateKey, publicKey };
  }

  async publicKey() {
    try {
      const ownership = await this.ownershipKey();
      return {
        publicKey: ownership.publicKey,
        privateExtractable: ownership.privateKey.extractable,
      };
    } catch (error) {
      return { failure: fixedFailure(error) };
    }
  }

  async adopt(certificate, certificateSha256) {
    const ownership = await this.ownershipKey();
    const verified = await verifyCloudflareGatewayOwnershipCertificate({
      certificate,
      pinnedIssuerPublicKey: this.env.ISSUER_PUBLIC_KEY,
      expectedKeyId: this.env.ISSUER_KEY_ID,
      expectedPublicClientId: this.env.PUBLIC_CLIENT_ID,
    });
    if (verified.certificateSha256 !== certificateSha256 ||
        verified.statement.ownershipKey.publicKey !== ownership.publicKey ||
        verified.statement.gatewayCallback !== this.env.CANARY_GATEWAY_CALLBACK) {
      throw new Error('adoption_rejected');
    }
    await this.ctx.storage.put({ certificate, certificateSha256 });
    return Object.freeze({ adopted: true });
  }

  async run() {
    const ownership = await this.ownershipKey();
    const certificate = await this.ctx.storage.get('certificate');
    const certificateSha256 = await this.ctx.storage.get('certificateSha256');
    if (!SHA256.test(certificateSha256 ?? '') || !certificate) throw new Error('not_adopted');

    const wrongOwnership = await generateCloudflareGatewayOwnershipKeyPair();
    const wrongRequest = await createCloudflareGatewayOwnershipChallengeRequest({
      certificate,
      certificateSha256,
      operation: 'upgrade',
      now: Date.now(),
      ownershipPrivateKey: wrongOwnership.privateKey,
    });
    const wrongKeyResponse = await relayFetch(this.env, '/oauth/relay-ticket/challenge/upgrade', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ request: wrongRequest }),
    });
    await wrongKeyResponse.body?.cancel();
    if (wrongKeyResponse.status !== 400) throw new Error('wrong_key_accepted');

    let issueBody = null;
    const transport = async (input, init) => {
      if (!isString(input)) throw new Error('relay_request_invalid');
      const requestedUrl = new URL(input);
      if (requestedUrl.origin !== CLOUDFLARE_CODE_RELAY_ORIGIN) {
        throw new Error('relay_origin_substituted');
      }
      if (requestedUrl.pathname === '/oauth/relay-ticket/issue/upgrade') {
        if (!isString(init?.body)) throw new Error('proof_not_observed');
        issueBody = init.body;
      }
      const mapped = new URL(requestedUrl.pathname + requestedUrl.search, this.env.CANARY_RELAY_ORIGIN);
      return this.env.RELAY_SERVICE.fetch(mapped.toString(), init);
    };
    const ticket = await requestCustomerGatewayRelayTicket({
      certificate,
      certificateSha256,
      gatewayCallback: this.env.CANARY_GATEWAY_CALLBACK,
      operation: 'upgrade',
      ownershipPrivateKey: ownership.privateKey,
      transport,
    });
    if (issueBody === null) throw new Error('proof_not_observed');

    const replay = await relayFetch(this.env, '/oauth/relay-ticket/issue/upgrade', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: issueBody,
    });
    await replay.body?.cancel();
    if (replay.status !== 409) throw new Error('proof_replay_accepted');

    const accepted = await relayFetch(this.env, '/canary/verify-ticket', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ relayTicket: ticket.relayTicket }),
    });
    const acceptedValue = await accepted.json();
    if (accepted.status !== 200 || acceptedValue.accepted !== true ||
        acceptedValue.exactOperation !== true || acceptedValue.exactCallback !== true ||
        acceptedValue.exactClient !== true) throw new Error('ticket_rejected');

    return Object.freeze({
      outcome: 'passed',
      privateKeyExtractable: ownership.privateKey.extractable,
      wrongKeyRejectedBeforeAllocation: true,
      proofReplayRejected: true,
      exactTicketAccepted: true,
    });
  }
}

export default {
  async fetch(request, env) {
    if (!validConfig(env)) return secureJson({ schemaVersion: 1, error: 'unavailable' }, 503);
    const url = new URL(request.url);
    if (url.origin !== env.CANARY_PUBLIC_ORIGIN ||
        request.headers.get('x-ankka-canary-control') !== env.CANARY_CONTROL_KEY) {
      return new Response(null, { status: 404 });
    }
    const stub = env.CUSTOMER_STATE.get(env.CUSTOMER_STATE.idFromName('customer'));
    try {
      if (request.method === 'GET' && url.pathname === '/public-key') {
        return secureJson({ schemaVersion: 1, ...await stub.publicKey() });
      }
      if (request.method === 'POST' && url.pathname === '/adopt') {
        const body = await boundedJson(request);
        if (Object.keys(body).sort().join(',') !== 'certificate,certificateSha256') {
          throw new Error('adoption_rejected');
        }
        return secureJson({ schemaVersion: 1, ...await stub.adopt(
          body.certificate,
          body.certificateSha256,
        ) });
      }
      if (request.method === 'POST' && url.pathname === '/run') {
        return secureJson({ schemaVersion: 1, ...await stub.run() });
      }
    } catch (error) {
      return secureJson({
        schemaVersion: 1,
        outcome: 'failed',
        failure: fixedFailure(error),
      }, 500);
    }
    return new Response(null, { status: 404 });
  },
};

import * as v from 'valibot';

import { CLOUDFLARE_CODE_RELAY_ORIGIN } from '../src/cloudflare-code-relay';
import {
  createCloudflareGatewayOwnershipChallengeRequest,
  createCloudflareGatewayOwnershipProof,
  generateCloudflareGatewayOwnershipKeyPair,
  issueCloudflareGatewayOwnershipCertificate,
  verifyCloudflareGatewayOwnershipCertificate,
  type CloudflareGatewayOwnershipChallengeRecord,
  type CloudflareGatewayOwnershipChallengeStore,
} from '../src/cloudflare-gateway-ownership-proof';
import { createCloudflareGatewayOwnershipProofHttpHandler } from
  '../src/cloudflare-gateway-ownership-proof-http';
import { verifyCloudflareGatewayRelayTicket } from '../src/cloudflare-gateway-relay-ticket';
import { requestCustomerGatewayRelayTicket } from '../src/customer-gateway-relay-ticket-client';
import type { CustomerCloudflareTransport } from '../src/customer-cloudflare-grant';
import { base64UrlEncode, randomBase64Url } from '../src/crypto';
import { CUSTOMER_INSTALL_OAUTH_CALLBACK_PATH } from '../src/customer-install-paths';

const ACCOUNT_ID = 'a'.repeat(32);
const WORKER_PROVIDER_ID = 'b'.repeat(32);
const NAMESPACE_ID = 'c'.repeat(32);
const INSTALL_ID = `acg-${'d'.repeat(24)}`;
const WORKER_NAME = 'ankka-gateway-proof-http';
const BOOTSTRAP_CALLBACK = `https://${WORKER_NAME}.customer.workers.dev${CUSTOMER_INSTALL_OAUTH_CALLBACK_PATH}`;
const GATEWAY_CALLBACK = `https://manage.example.com${CUSTOMER_INSTALL_OAUTH_CALLBACK_PATH}`;
const CLIENT_ID = 'client_ownership_http_1234567890';
const ISSUER_KEY_ID = 'ownership-http-issuer-v1';
const HANDOFF_SHA256 = `sha256:${'e'.repeat(64)}`;
const NOW = 1_788_192_000_000;
const challengeResponseSchema = v.strictObject({
  schemaVersion: v.literal(1),
  challenge: v.pipe(v.string(), v.regex(/^[A-Za-z0-9_-]{43}$/u)),
  certificateSha256: v.pipe(v.string(), v.regex(/^sha256:[a-f0-9]{64}$/u)),
  expiresAt: v.pipe(v.number(), v.safeInteger()),
});

class MemoryChallengeStore implements CloudflareGatewayOwnershipChallengeStore {
  readonly records = new Map<string, CloudflareGatewayOwnershipChallengeRecord>();
  writes = 0;

  private key(record: CloudflareGatewayOwnershipChallengeRecord): string {
    return `${record.certificateSha256}.${record.operation}`;
  }

  async put(record: CloudflareGatewayOwnershipChallengeRecord): Promise<boolean> {
    this.records.set(this.key(record), Object.freeze({ ...record }));
    this.writes += 1;
    return true;
  }

  async consume(record: CloudflareGatewayOwnershipChallengeRecord): Promise<boolean> {
    const key = this.key(record);
    const stored = this.records.get(key);
    if (stored?.challengeSha256 !== record.challengeSha256 ||
        stored.expiresAt !== record.expiresAt) return false;
    this.records.delete(key);
    return true;
  }
}

async function exportPublicKey(key: CryptoKey): Promise<string> {
  return base64UrlEncode(new Uint8Array(await crypto.subtle.exportKey('raw', key)));
}

async function fixture() {
  const issuer = await crypto.subtle.generateKey('Ed25519', true, ['sign', 'verify']);
  const ownership = await generateCloudflareGatewayOwnershipKeyPair();
  const issuerPublicKey = await exportPublicKey(issuer.publicKey);
  const certificate = await issueCloudflareGatewayOwnershipCertificate({
    accountId: ACCOUNT_ID,
    installId: INSTALL_ID,
    worker: { name: WORKER_NAME, providerId: WORKER_PROVIDER_ID },
    adminStateNamespaceId: NAMESPACE_ID,
    bootstrapCallback: BOOTSTRAP_CALLBACK,
    gatewayCallback: GATEWAY_CALLBACK,
    publicClientId: CLIENT_ID,
    ownershipPublicKey: ownership.publicKey,
    handoffSha256: HANDOFF_SHA256,
    issuedAt: NOW,
    keyId: ISSUER_KEY_ID,
  }, issuer.privateKey);
  const verified = await verifyCloudflareGatewayOwnershipCertificate({
    certificate,
    pinnedIssuerPublicKey: issuerPublicKey,
    expectedKeyId: ISSUER_KEY_ID,
    expectedPublicClientId: CLIENT_ID,
  });
  const relayTicketKey = randomBase64Url(32);
  const store = new MemoryChallengeStore();
  const handler = createCloudflareGatewayOwnershipProofHttpHandler({
    publicClientId: CLIENT_ID,
    pinnedIssuerPublicKey: issuerPublicKey,
    issuerKeyId: ISSUER_KEY_ID,
    relayTicketKey,
  }, { now: () => NOW, store });
  return {
    certificate,
    handler,
    issuerPublicKey,
    ownership,
    relayTicketKey,
    store,
    verified,
  };
}

function post(handler: Readonly<{ fetch(request: Request): Promise<Response> }>, path: string, body: string) {
  return handler.fetch(new Request(`${CLOUDFLARE_CODE_RELAY_ORIGIN}${path}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body,
  }));
}

describe('ownership-proof HTTP boundary', () => {
  it('lets the customer Gateway obtain one exact install-recovery ticket end to end', async () => {
    const value = await fixture();
    const calls: Array<Readonly<{
      body: string;
      contentType: string | undefined;
      method: string | undefined;
      redirect: RequestRedirect | undefined;
      url: string;
    }>> = [];
    const responseHeaders: Headers[] = [];
    const transport: CustomerCloudflareTransport = async (input, init) => {
      const request = new Request(input, init);
      const body = await request.clone().text();
      calls.push(Object.freeze({
        body,
        contentType: request.headers.get('content-type') ?? undefined,
        method: request.method,
        redirect: request.redirect,
        url: request.url,
      }));
      const response = await value.handler.fetch(request);
      responseHeaders.push(response.headers);
      return response;
    };

    const ticket = await requestCustomerGatewayRelayTicket({
      certificate: value.certificate,
      certificateSha256: value.verified.certificateSha256,
      gatewayCallback: GATEWAY_CALLBACK,
      operation: 'install',
      ownershipPrivateKey: value.ownership.privateKey,
      transport,
      now: () => NOW,
    });
    // The install ticket is bound to the certified bootstrap origin, where the
    // shell is served during the install; the proof itself still names the
    // certified management callback.
    await expect(verifyCloudflareGatewayRelayTicket({
      ticket: ticket.relayTicket,
      signingKey: value.relayTicketKey,
      expectedClientId: CLIENT_ID,
      expectedOperation: 'install',
      expectedGatewayCallback: BOOTSTRAP_CALLBACK,
      now: NOW + 1,
    })).resolves.toMatchObject({
      accountId: ACCOUNT_ID,
      installId: INSTALL_ID,
      workerName: WORKER_NAME,
      gatewayCallback: BOOTSTRAP_CALLBACK,
      operation: 'install',
      receiptResourceKinds: null,
    });

    expect(calls.map((call) => call.url)).toEqual([
      `${CLOUDFLARE_CODE_RELAY_ORIGIN}/oauth/relay-ticket/challenge/install`,
      `${CLOUDFLARE_CODE_RELAY_ORIGIN}/oauth/relay-ticket/issue/install`,
    ]);
    for (const call of calls) {
      expect(call).toMatchObject({
        contentType: 'application/json',
        method: 'POST',
        redirect: 'manual',
      });
      expect(call.body).not.toContain(value.relayTicketKey);
      expect(call.body).not.toContain('ownershipPrivateKey');
      expect(call.body).not.toContain('relayTicketKey');
      expect(call.body).not.toContain('"scope"');
      expect(call.body).not.toContain('"destination"');
    }
    expect(value.store.writes).toBe(1);
    expect(value.store.records.size).toBe(0);
    for (const headers of responseHeaders) {
      expect(headers.get('cache-control')).toBe('no-store');
      expect(headers.get('referrer-policy')).toBe('no-referrer');
      expect(headers.get('x-content-type-options')).toBe('nosniff');
      expect(headers.get('access-control-allow-origin')).toBeNull();
    }
  });

  it('requires the certified customer key before allocating challenge state', async () => {
    const value = await fixture();
    const otherOwnership = await generateCloudflareGatewayOwnershipKeyPair();
    const request = await createCloudflareGatewayOwnershipChallengeRequest({
      certificate: value.certificate,
      certificateSha256: value.verified.certificateSha256,
      operation: 'rollback',
      now: NOW,
      ownershipPrivateKey: otherOwnership.privateKey,
    });
    const response = await post(
      value.handler,
      '/oauth/relay-ticket/challenge/rollback',
      JSON.stringify({ request }),
    );
    expect(response.status).toBe(400);
    await expect(response.json()).resolves.toEqual({
      schemaVersion: 1,
      error: 'ownership_proof_rejected',
    });
    expect(value.store.writes).toBe(0);
    expect(value.store.records.size).toBe(0);
  });

  it('atomically consumes one proof and rejects operation substitution and replay', async () => {
    const value = await fixture();
    const challengeRequest = await createCloudflareGatewayOwnershipChallengeRequest({
      certificate: value.certificate,
      certificateSha256: value.verified.certificateSha256,
      operation: 'upgrade',
      now: NOW,
      ownershipPrivateKey: value.ownership.privateKey,
    });
    const challengeResponse = await post(
      value.handler,
      '/oauth/relay-ticket/challenge/upgrade',
      JSON.stringify({ request: challengeRequest }),
    );
    const challenge = v.parse(challengeResponseSchema, await challengeResponse.json());
    const proof = await createCloudflareGatewayOwnershipProof({
      certificate: value.certificate,
      certificateSha256: challenge.certificateSha256,
      gatewayCallback: GATEWAY_CALLBACK,
      operation: 'upgrade',
      challenge: challenge.challenge,
      challengeExpiresAt: challenge.expiresAt,
      now: NOW,
      ownershipPrivateKey: value.ownership.privateKey,
    });

    const substituted = await post(
      value.handler,
      '/oauth/relay-ticket/issue/rollback',
      JSON.stringify({ proof }),
    );
    expect(substituted.status).toBe(400);
    expect(value.store.records.size).toBe(1);

    const attempts = await Promise.all([
      post(value.handler, '/oauth/relay-ticket/issue/upgrade', JSON.stringify({ proof })),
      post(value.handler, '/oauth/relay-ticket/issue/upgrade', JSON.stringify({ proof })),
    ]);
    expect(attempts.map((response) => response.status).sort()).toEqual([200, 409]);
    expect(value.store.records.size).toBe(0);
  });

  it('exposes no CORS surface, query variant, loose body schema, or preflight', async () => {
    const value = await fixture();
    const responses = await Promise.all([
      value.handler.fetch(new Request(
        `${CLOUDFLARE_CODE_RELAY_ORIGIN}/oauth/relay-ticket/challenge/upgrade?operation=install`,
        { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{}' },
      )),
      post(value.handler, '/oauth/relay-ticket/challenge/upgrade', JSON.stringify({
        request: 'invalid',
        extra: true,
      })),
      post(value.handler, '/oauth/relay-ticket/challenge/upgrade', 'x'.repeat(16 * 1024 + 1)),
      value.handler.fetch(new Request(
        `${CLOUDFLARE_CODE_RELAY_ORIGIN}/oauth/relay-ticket/challenge/upgrade`,
        { method: 'OPTIONS' },
      )),
    ]);
    expect(responses.map((response) => response.status)).toEqual([404, 400, 400, 404]);
    for (const response of responses) {
      expect(response.headers.get('access-control-allow-origin')).toBeNull();
      expect(response.headers.get('cache-control')).toBe('no-store');
    }
    expect(value.store.writes).toBe(0);
  });
});

import * as v from 'valibot';

import { CLOUDFLARE_CODE_RELAY_ORIGIN } from './cloudflare-code-relay';
import {
  CLOUDFLARE_GATEWAY_OWNERSHIP_CHALLENGE_TTL_MS,
  CLOUDFLARE_GATEWAY_OWNERSHIP_CLOCK_SKEW_MS,
  CLOUDFLARE_GATEWAY_RELAY_TICKET_ISSUER_TTL_MS,
  createCloudflareGatewayOwnershipChallengeRequest,
  createCloudflareGatewayOwnershipProof,
} from './cloudflare-gateway-ownership-proof';
import {
  CUSTOMER_CLOUDFLARE_OPERATIONS,
  RECEIPT_OWNED_CLOUDFLARE_RESOURCE_KINDS,
  type CustomerCloudflareOperation,
  type ReceiptOwnedCloudflareResourceKind,
} from './cloudflare-operation-authority';
import { readBoundedText } from './http';
import type { CustomerCloudflareTransport } from './customer-cloudflare-grant';
import { CUSTOMER_INSTALL_OAUTH_CALLBACK_PATH } from './customer-install-paths';

const SHA256 = /^sha256:[a-f0-9]{64}$/u;
const TOKEN = /^[A-Za-z0-9_-]{43}$/u;
const RELAY_TICKET = /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]{43}$/u;
const MAX_RESPONSE_BYTES = 16 * 1024;
const REQUEST_TIMEOUT_MS = 10_000;

const challengeResponseSchema = v.strictObject({
  schemaVersion: v.literal(1),
  challenge: v.pipe(v.string(), v.regex(TOKEN)),
  certificateSha256: v.pipe(v.string(), v.regex(SHA256)),
  expiresAt: v.pipe(v.number(), v.safeInteger()),
});
const ticketResponseSchema = v.strictObject({
  schemaVersion: v.literal(1),
  relayTicket: v.pipe(v.string(), v.regex(RELAY_TICKET), v.maxLength(4096)),
  expiresAt: v.pipe(v.number(), v.safeInteger()),
});

export interface CustomerGatewayRelayTicket {
  readonly relayTicket: string;
  readonly expiresAt: number;
}

export class CustomerGatewayRelayTicketClientError extends Error {
  constructor(readonly code: 'invalid' | 'relay_rejected' | 'relay_unavailable') {
    super(code);
    this.name = 'CustomerGatewayRelayTicketClientError';
  }
}

function fail(code: CustomerGatewayRelayTicketClientError['code'] = 'invalid'): never {
  throw new CustomerGatewayRelayTicketClientError(code);
}

function ownershipProofOperation(value: CustomerCloudflareOperation): boolean {
  return CUSTOMER_CLOUDFLARE_OPERATIONS.includes(value);
}

function validGatewayCallback(value: string): boolean {
  try {
    const url = new URL(value);
    return url.protocol === 'https:' && url.username === '' && url.password === '' &&
      url.port === '' && url.pathname === CUSTOMER_INSTALL_OAUTH_CALLBACK_PATH && url.search === '' &&
      url.hash === '' && url.hostname === url.hostname.toLowerCase() && url.hostname.includes('.');
  } catch {
    return false;
  }
}

function validReceiptKinds(
  operation: CustomerCloudflareOperation,
  kinds: readonly ReceiptOwnedCloudflareResourceKind[] | undefined,
): boolean {
  if (operation !== 'uninstall') return kinds === undefined;
  return kinds !== undefined && kinds.length >= 1 &&
    kinds.length <= RECEIPT_OWNED_CLOUDFLARE_RESOURCE_KINDS.length &&
    new Set(kinds).size === kinds.length &&
    kinds.every((kind) => RECEIPT_OWNED_CLOUDFLARE_RESOURCE_KINDS.includes(kind));
}

function applicationJson(value: string | null): boolean {
  return value?.split(';', 1)[0]?.trim().toLowerCase() === 'application/json';
}

async function postJson<Schema extends v.GenericSchema>(
  transport: CustomerCloudflareTransport,
  path: string,
  body: string,
  schema: Schema,
): Promise<v.InferOutput<Schema>> {
  const controller = new AbortController();
  let timeout: ReturnType<typeof setTimeout> | undefined;
  const expired = new Promise<never>((_resolve, reject) => {
    timeout = setTimeout(() => {
      controller.abort();
      reject(new CustomerGatewayRelayTicketClientError('relay_unavailable'));
    }, REQUEST_TIMEOUT_MS);
  });
  try {
    return await Promise.race([
      (async () => {
        let response: Response;
        try {
          response = await transport(`${CLOUDFLARE_CODE_RELAY_ORIGIN}${path}`, {
            method: 'POST',
            headers: { accept: 'application/json', 'content-type': 'application/json' },
            body,
            redirect: 'manual',
            signal: controller.signal,
          });
        } catch {
          return fail('relay_unavailable');
        }
        if (response.redirected || response.status !== 200 ||
            !applicationJson(response.headers.get('content-type'))) {
          await response.body?.cancel().catch(() => undefined);
          return fail(response.status >= 500 ? 'relay_unavailable' : 'relay_rejected');
        }
        let serialized: string;
        try {
          serialized = await readBoundedText(response, 'oauth_exchange_failed', MAX_RESPONSE_BYTES);
        } catch {
          return fail('relay_rejected');
        }
        try {
          return v.parse(schema, JSON.parse(serialized));
        } catch {
          return fail('relay_rejected');
        }
      })(),
      expired,
    ]);
  } catch (error) {
    if (error instanceof CustomerGatewayRelayTicketClientError) throw error;
    return fail('relay_unavailable');
  } finally {
    if (timeout !== undefined) clearTimeout(timeout);
    controller.abort();
  }
}

function validExpiry(expiresAt: number, now: number, ttl: number): boolean {
  return Number.isSafeInteger(expiresAt) && expiresAt > now - CLOUDFLARE_GATEWAY_OWNERSHIP_CLOCK_SKEW_MS &&
    expiresAt <= now + ttl + CLOUDFLARE_GATEWAY_OWNERSHIP_CLOCK_SKEW_MS;
}

/**
 * Runs entirely inside the customer Gateway. The ownership private key signs
 * both requests and is never serialized; the returned ticket is short-lived
 * and accepted only by the fixed operation relay.
 */
export async function requestCustomerGatewayRelayTicket(input: {
  readonly certificate: string;
  readonly certificateSha256: string;
  readonly gatewayCallback: string;
  readonly operation: CustomerCloudflareOperation;
  readonly receiptResourceKinds?: readonly ReceiptOwnedCloudflareResourceKind[];
  readonly ownershipPrivateKey: CryptoKey;
  readonly transport: CustomerCloudflareTransport;
  readonly now?: () => number;
}): Promise<CustomerGatewayRelayTicket> {
  const now = input.now ?? Date.now;
  const startedAt = now();
  if (!Number.isSafeInteger(startedAt) || startedAt < 0 || !SHA256.test(input.certificateSha256) ||
      input.certificate.length < 1 || input.certificate.length > 8192 ||
      !validGatewayCallback(input.gatewayCallback) || !ownershipProofOperation(input.operation) ||
      !validReceiptKinds(input.operation, input.receiptResourceKinds)) fail();

  let challengeRequest: string;
  try {
    challengeRequest = await createCloudflareGatewayOwnershipChallengeRequest({
      certificate: input.certificate,
      certificateSha256: input.certificateSha256,
      operation: input.operation,
      now: startedAt,
      ownershipPrivateKey: input.ownershipPrivateKey,
    });
  } catch {
    fail();
  }
  const challenge = await postJson(
    input.transport,
    `/oauth/relay-ticket/challenge/${input.operation}`,
    JSON.stringify({ request: challengeRequest }),
    challengeResponseSchema,
  );
  const challengeReceivedAt = now();
  if (challenge.certificateSha256 !== input.certificateSha256 ||
      !validExpiry(
        challenge.expiresAt,
        challengeReceivedAt,
        CLOUDFLARE_GATEWAY_OWNERSHIP_CHALLENGE_TTL_MS,
      )) fail('relay_rejected');

  let proof: string;
  try {
    const proofInput = {
      certificate: input.certificate,
      certificateSha256: input.certificateSha256,
      gatewayCallback: input.gatewayCallback,
      operation: input.operation,
      challenge: challenge.challenge,
      challengeExpiresAt: challenge.expiresAt,
      now: challengeReceivedAt,
      ownershipPrivateKey: input.ownershipPrivateKey,
    };
    proof = input.receiptResourceKinds === undefined
      ? await createCloudflareGatewayOwnershipProof(proofInput)
      : await createCloudflareGatewayOwnershipProof({
        ...proofInput,
        receiptResourceKinds: input.receiptResourceKinds,
      });
  } catch {
    fail();
  }
  const ticket = await postJson(
    input.transport,
    `/oauth/relay-ticket/issue/${input.operation}`,
    JSON.stringify({ proof }),
    ticketResponseSchema,
  );
  const ticketReceivedAt = now();
  if (!validExpiry(
    ticket.expiresAt,
    ticketReceivedAt,
    CLOUDFLARE_GATEWAY_RELAY_TICKET_ISSUER_TTL_MS,
  )) fail('relay_rejected');
  return Object.freeze(ticket);
}

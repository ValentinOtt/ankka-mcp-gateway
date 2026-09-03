import * as v from 'valibot';

import { boundaryValueSchema } from './boundary';
import { canonicalJson } from './canonical-json';
import { CUSTOMER_INSTALL_OAUTH_CALLBACK_PATH } from './customer-install-paths';
import {
  RECEIPT_OWNED_CLOUDFLARE_RESOURCE_KINDS,
  type CustomerCloudflareOperation,
  type ReceiptOwnedCloudflareResourceKind,
} from './cloudflare-operation-authority';
import { base64UrlDecode, base64UrlEncode, constantTimeEqual } from './crypto';

const ACCOUNT_ID = /^[a-f0-9]{32}$/u;
const INSTALLATION_ID = /^acg-[a-f0-9]{24}$/u;
const WORKER_NAME = /^[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$/u;
const CLIENT_ID = /^[A-Za-z0-9_-]{16,128}$/u;
const TOKEN = /^[A-Za-z0-9_-]{43}$/u;
const MAX_TICKET_BYTES = 4096;
const SIGNING_CONTEXT = 'ankka-cloudflare-gateway-relay-ticket-v1';

export const CLOUDFLARE_GATEWAY_RELAY_TICKET_TTL_MS = 15 * 60 * 1_000;

const relayTicketSchema = v.strictObject({
  schemaVersion: v.literal(1),
  purpose: v.literal('cloudflare-code-relay'),
  accountId: v.pipe(v.string(), v.regex(ACCOUNT_ID)),
  installId: v.pipe(v.string(), v.regex(INSTALLATION_ID)),
  workerName: v.pipe(v.string(), v.regex(WORKER_NAME)),
  gatewayCallback: v.pipe(v.string(), v.url()),
  publicClientId: v.pipe(v.string(), v.regex(CLIENT_ID)),
  operation: v.picklist([
    'install', 'upgrade', 'rollback', 'source-add', 'source-update', 'source-remove', 'uninstall',
  ]),
  receiptResourceKinds: v.union([
    v.array(v.picklist(RECEIPT_OWNED_CLOUDFLARE_RESOURCE_KINDS)),
    v.null(),
  ]),
  nonce: v.pipe(v.string(), v.regex(TOKEN)),
  issuedAt: v.pipe(v.number(), v.safeInteger()),
  expiresAt: v.pipe(v.number(), v.safeInteger()),
});

type ParsedCloudflareGatewayRelayTicketClaims = v.InferOutput<typeof relayTicketSchema>;
export type CloudflareGatewayRelayTicketClaims = Omit<
  ParsedCloudflareGatewayRelayTicketClaims,
  'receiptResourceKinds'
> & {
  readonly receiptResourceKinds: readonly ReceiptOwnedCloudflareResourceKind[] | null;
};

export class CloudflareGatewayRelayTicketError extends Error {
  constructor(readonly code: 'invalid' | 'expired' | 'operation_mismatch') {
    super(code);
    this.name = 'CloudflareGatewayRelayTicketError';
  }
}

function invalid(): never {
  throw new CloudflareGatewayRelayTicketError('invalid');
}

function validGatewayCallback(value: string): boolean {
  try {
    const url = new URL(value);
    return url.protocol === 'https:' && url.username === '' && url.password === '' && url.port === '' &&
      url.pathname === CUSTOMER_INSTALL_OAUTH_CALLBACK_PATH && url.search === '' && url.hash === '' &&
      url.hostname === url.hostname.toLowerCase() && url.hostname.includes('.');
  } catch {
    return false;
  }
}

function keyBytes(value: string): Uint8Array<ArrayBuffer> {
  let decoded: Uint8Array;
  try {
    decoded = base64UrlDecode(value);
  } catch {
    invalid();
  }
  if (decoded.byteLength !== 32) invalid();
  const owned = new Uint8Array(new ArrayBuffer(32));
  owned.set(decoded);
  decoded.fill(0);
  return owned;
}

async function signature(payload: string, encodedKey: string): Promise<string> {
  const bytes = keyBytes(encodedKey);
  try {
    const key = await crypto.subtle.importKey(
      'raw', bytes, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign'],
    );
    const signed = new TextEncoder().encode(`${SIGNING_CONTEXT}.${payload}`);
    return base64UrlEncode(new Uint8Array(await crypto.subtle.sign('HMAC', key, signed)));
  } finally {
    bytes.fill(0);
  }
}

function validReceiptKinds(
  operation: CustomerCloudflareOperation,
  kinds: readonly ReceiptOwnedCloudflareResourceKind[] | null,
): boolean {
  if (operation !== 'uninstall') return kinds === null;
  return kinds !== null && kinds.length >= 1 && kinds.length <= RECEIPT_OWNED_CLOUDFLARE_RESOURCE_KINDS.length &&
    new Set(kinds).size === kinds.length;
}

function validateClaims(claims: ParsedCloudflareGatewayRelayTicketClaims): void {
  if (!validGatewayCallback(claims.gatewayCallback) || claims.issuedAt < 0 ||
      claims.expiresAt <= claims.issuedAt ||
      claims.expiresAt - claims.issuedAt > CLOUDFLARE_GATEWAY_RELAY_TICKET_TTL_MS ||
      !validReceiptKinds(claims.operation, claims.receiptResourceKinds)) invalid();
}

/**
 * Issuer-side only. Every identity field must come from the verified Stage 1
 * provider readback/ownership handoff (or an equally strong later receipt),
 * never from a browser or an unauthenticated Gateway request. The HMAC key is
 * held only by the relay issuer and verifier and is never deployed to a
 * customer Worker.
 */
export async function createCloudflareGatewayRelayTicket(input: {
  readonly accountId: string;
  readonly installId: string;
  readonly workerName: string;
  readonly gatewayCallback: string;
  readonly publicClientId: string;
  readonly operation: CustomerCloudflareOperation;
  readonly receiptResourceKinds?: readonly ReceiptOwnedCloudflareResourceKind[];
  readonly nonce: string;
  readonly now: number;
  readonly expiresAt: number;
  readonly signingKey: string;
}): Promise<string> {
  const candidate = v.safeParse(relayTicketSchema, {
    schemaVersion: 1,
    purpose: 'cloudflare-code-relay',
    accountId: input.accountId,
    installId: input.installId,
    workerName: input.workerName,
    gatewayCallback: input.gatewayCallback,
    publicClientId: input.publicClientId,
    operation: input.operation,
    receiptResourceKinds: input.receiptResourceKinds ?? null,
    nonce: input.nonce,
    issuedAt: input.now,
    expiresAt: input.expiresAt,
  });
  if (!candidate.success) invalid();
  validateClaims(candidate.output);
  const serialized = canonicalJson(candidate.output);
  const payload = base64UrlEncode(new TextEncoder().encode(serialized));
  if (payload.length > MAX_TICKET_BYTES) invalid();
  return `${payload}.${await signature(payload, input.signingKey)}`;
}

export async function verifyCloudflareGatewayRelayTicket(input: {
  readonly ticket: string;
  readonly signingKey: string;
  readonly expectedClientId: string;
  readonly expectedOperation: CustomerCloudflareOperation;
  readonly expectedGatewayCallback: string;
  readonly now: number;
}): Promise<CloudflareGatewayRelayTicketClaims> {
  if (!Number.isSafeInteger(input.now) || input.now < 0 || !CLIENT_ID.test(input.expectedClientId) ||
      !validGatewayCallback(input.expectedGatewayCallback)) invalid();
  const segments = input.ticket.split('.');
  const payload = segments[0];
  const suppliedSignature = segments[1];
  if (segments.length !== 2 || payload === undefined || suppliedSignature === undefined ||
      payload.length > MAX_TICKET_BYTES || !/^[A-Za-z0-9_-]+$/u.test(payload) ||
      !TOKEN.test(suppliedSignature)) invalid();
  const expectedSignature = await signature(payload, input.signingKey);
  if (!constantTimeEqual(suppliedSignature, expectedSignature)) invalid();

  let decoded: unknown;
  try {
    const bytes = base64UrlDecode(payload);
    try {
      decoded = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
    } finally {
      bytes.fill(0);
    }
  } catch {
    invalid();
  }
  const boundary = v.safeParse(boundaryValueSchema, decoded);
  const parsed = boundary.success ? v.safeParse(relayTicketSchema, boundary.output) : null;
  if (!parsed?.success || canonicalJson(parsed.output) !== canonicalJson(decoded)) invalid();
  validateClaims(parsed.output);
  if (parsed.output.expiresAt <= input.now) throw new CloudflareGatewayRelayTicketError('expired');
  if (parsed.output.operation !== input.expectedOperation ||
      parsed.output.publicClientId !== input.expectedClientId ||
      parsed.output.gatewayCallback !== input.expectedGatewayCallback) {
    throw new CloudflareGatewayRelayTicketError('operation_mismatch');
  }
  return Object.freeze({
    ...parsed.output,
    receiptResourceKinds: parsed.output.receiptResourceKinds === null
      ? null
      : Object.freeze([...parsed.output.receiptResourceKinds]),
  });
}

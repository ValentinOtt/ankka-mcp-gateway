import * as v from 'valibot';

import { CLOUDFLARE_CODE_RELAY_ORIGIN } from './cloudflare-code-relay';
import {
  CLOUDFLARE_GATEWAY_OWNERSHIP_CHALLENGE_TTL_MS,
  CLOUDFLARE_GATEWAY_RELAY_TICKET_ISSUER_TTL_MS,
  CloudflareGatewayOwnershipProofError,
  issueCloudflareGatewayOwnershipChallenge,
  issueCloudflareGatewayRelayTicketFromOwnershipProof,
  type CloudflareGatewayOwnershipChallengeStore,
} from './cloudflare-gateway-ownership-proof';
import type { CustomerCloudflareOperation } from './cloudflare-operation-authority';

const CLIENT_ID = /^[A-Za-z0-9_-]{16,128}$/u;
const KEY_ID = /^[a-z0-9](?:[a-z0-9._-]{0,62}[a-z0-9])?$/u;
const TOKEN = /^[A-Za-z0-9_-]{43}$/u;
const MAX_BODY_BYTES = 16 * 1024;
const CUSTOMER_OPERATION =
  '(install|upgrade|rollback|source-add|source-update|source-remove|uninstall)';
const CHALLENGE_PATH = new RegExp(`^/oauth/relay-ticket/challenge/${CUSTOMER_OPERATION}$`, 'u');
const ISSUE_PATH = new RegExp(`^/oauth/relay-ticket/issue/${CUSTOMER_OPERATION}$`, 'u');

const configSchema = v.strictObject({
  publicClientId: v.pipe(v.string(), v.regex(CLIENT_ID)),
  pinnedIssuerPublicKey: v.pipe(v.string(), v.regex(TOKEN)),
  issuerKeyId: v.pipe(v.string(), v.regex(KEY_ID)),
  relayTicketKey: v.pipe(v.string(), v.regex(TOKEN)),
});
const challengeBodySchema = v.strictObject({
  request: v.pipe(v.string(), v.minLength(1), v.maxLength(MAX_BODY_BYTES)),
});
const proofBodySchema = v.strictObject({
  proof: v.pipe(v.string(), v.minLength(1), v.maxLength(MAX_BODY_BYTES)),
});

export interface CloudflareGatewayOwnershipProofHttpConfig {
  readonly publicClientId: string;
  readonly pinnedIssuerPublicKey: string;
  readonly issuerKeyId: string;
  readonly relayTicketKey: string;
}

export interface CloudflareGatewayOwnershipProofHttpDependencies {
  readonly now?: () => number;
  /** Strongly consistent adapter; records contain hashes only. */
  readonly store: CloudflareGatewayOwnershipChallengeStore;
}

type OwnershipProofHttpJson =
  | {
    readonly schemaVersion: 1;
    readonly challenge: string;
    readonly certificateSha256: string;
    readonly expiresAt: number;
  }
  | {
    readonly schemaVersion: 1;
    readonly relayTicket: string;
    readonly expiresAt: number;
  }
  | {
    readonly schemaVersion: 1;
    readonly error: 'not_found' | 'ownership_proof_rejected' | 'ownership_proof_unavailable';
  };

function responseHeaders(): Headers {
  return new Headers({
    'cache-control': 'no-store',
    'content-security-policy': "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
    'content-type': 'application/json; charset=utf-8',
    'referrer-policy': 'no-referrer',
    'x-content-type-options': 'nosniff',
  });
}

function json(value: OwnershipProofHttpJson, status = 200): Response {
  return new Response(JSON.stringify(value), { status, headers: responseHeaders() });
}

function notFound(): Response {
  return json({ schemaVersion: 1, error: 'not_found' }, 404);
}

function applicationJson(value: string | null): boolean {
  return value?.split(';', 1)[0]?.trim().toLowerCase() === 'application/json';
}

async function readBoundedRequestText(request: Request): Promise<string> {
  const declaredHeader = request.headers.get('content-length');
  if (declaredHeader !== null) {
    const declared = Number(declaredHeader);
    if (!Number.isSafeInteger(declared) || declared < 0 || declared > MAX_BODY_BYTES) {
      await request.body?.cancel().catch(() => undefined);
      throw new CloudflareGatewayOwnershipProofError('invalid');
    }
  }
  if (request.body === null) throw new CloudflareGatewayOwnershipProofError('invalid');
  const reader = request.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > MAX_BODY_BYTES) {
      await reader.cancel();
      throw new CloudflareGatewayOwnershipProofError('invalid');
    }
    chunks.push(value);
  }
  const combined = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    combined.set(chunk, offset);
    offset += chunk.byteLength;
  }
  try {
    return new TextDecoder('utf-8', { fatal: true }).decode(combined);
  } catch {
    throw new CloudflareGatewayOwnershipProofError('invalid');
  } finally {
    combined.fill(0);
    for (const chunk of chunks) chunk.fill(0);
  }
}

async function readBody<Schema extends v.GenericSchema>(
  request: Request,
  schema: Schema,
): Promise<v.InferOutput<Schema>> {
  if (!applicationJson(request.headers.get('content-type'))) {
    throw new CloudflareGatewayOwnershipProofError('invalid');
  }
  try {
    return v.parse(schema, JSON.parse(await readBoundedRequestText(request)));
  } catch (error) {
    if (error instanceof CloudflareGatewayOwnershipProofError) throw error;
    throw new CloudflareGatewayOwnershipProofError('invalid');
  }
}

function operationFromPath(
  pattern: RegExp,
  pathname: string,
): CustomerCloudflareOperation | null {
  const operation = pattern.exec(pathname)?.[1];
  return operation === 'install' || operation === 'upgrade' || operation === 'rollback' ||
    operation === 'source-add' ||
    operation === 'source-update' || operation === 'source-remove' || operation === 'uninstall'
    ? operation
    : null;
}

function rejected(error: CloudflareGatewayOwnershipProofError | null): Response {
  if (error?.code === 'store_unavailable') {
    return json({ schemaVersion: 1, error: 'ownership_proof_unavailable' }, 503);
  }
  const status = error?.code === 'expired'
    ? 410
    : error?.code === 'replayed'
      ? 409
      : 400;
  return json({ schemaVersion: 1, error: 'ownership_proof_rejected' }, status);
}

/**
 * Feature-disabled auth.ankka.ai boundary for issuing a fresh relay ticket to
 * a Gateway that proves possession of its customer-owned Ed25519 key.
 */
export function createCloudflareGatewayOwnershipProofHttpHandler(
  rawConfig: CloudflareGatewayOwnershipProofHttpConfig,
  dependencies: CloudflareGatewayOwnershipProofHttpDependencies,
): Readonly<{ fetch(request: Request): Promise<Response> }> {
  const parsedConfig = v.safeParse(configSchema, rawConfig);
  if (!parsedConfig.success) throw new Error('ownership_proof_config_invalid');
  const config = Object.freeze(parsedConfig.output);
  const now = dependencies.now ?? Date.now;

  return Object.freeze({
    async fetch(request: Request): Promise<Response> {
      let url: URL;
      try {
        url = new URL(request.url);
      } catch {
        return notFound();
      }
      if (url.origin !== CLOUDFLARE_CODE_RELAY_ORIGIN || url.username !== '' ||
          url.password !== '' || url.port !== '' || url.search !== '' || url.hash !== '') {
        return notFound();
      }
      if (request.method !== 'POST') return notFound();

      try {
        const challengeOperation = operationFromPath(CHALLENGE_PATH, url.pathname);
        if (challengeOperation !== null) {
          const body = await readBody(request, challengeBodySchema);
          const issuedAt = now();
          const challenge = await issueCloudflareGatewayOwnershipChallenge({
            request: body.request,
            pinnedIssuerPublicKey: config.pinnedIssuerPublicKey,
            expectedKeyId: config.issuerKeyId,
            expectedPublicClientId: config.publicClientId,
            expectedOperation: challengeOperation,
            now: issuedAt,
            store: dependencies.store,
          });
          if (challenge.expiresAt !== issuedAt + CLOUDFLARE_GATEWAY_OWNERSHIP_CHALLENGE_TTL_MS) {
            throw new CloudflareGatewayOwnershipProofError('invalid');
          }
          return json({ schemaVersion: 1, ...challenge });
        }

        const issueOperation = operationFromPath(ISSUE_PATH, url.pathname);
        if (issueOperation !== null) {
          const body = await readBody(request, proofBodySchema);
          const issuedAt = now();
          const expiresAt = issuedAt + CLOUDFLARE_GATEWAY_RELAY_TICKET_ISSUER_TTL_MS;
          const relayTicket = await issueCloudflareGatewayRelayTicketFromOwnershipProof({
            proof: body.proof,
            pinnedIssuerPublicKey: config.pinnedIssuerPublicKey,
            expectedKeyId: config.issuerKeyId,
            expectedPublicClientId: config.publicClientId,
            expectedOperation: issueOperation,
            now: issuedAt,
            ticketExpiresAt: expiresAt,
            relayTicketSigningKey: config.relayTicketKey,
            store: dependencies.store,
          });
          return json({ schemaVersion: 1, relayTicket, expiresAt });
        }
        return notFound();
      } catch (error) {
        return rejected(error instanceof CloudflareGatewayOwnershipProofError ? error : null);
      }
    },
  });
}

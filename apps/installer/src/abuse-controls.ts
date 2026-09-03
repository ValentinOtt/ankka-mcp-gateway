import { base64UrlDecode, base64UrlEncode } from './crypto';
import type { GatewayDeployEnv } from './env';
import { DeployError } from './errors';
import * as v from 'valibot';

export const ANONYMOUS_SESSION_RATE_LIMIT_BINDING = 'ANONYMOUS_SESSION_RATE_LIMIT' as const;
export const SESSION_READ_RATE_LIMIT_BINDING = 'SESSION_READ_RATE_LIMIT' as const;
export const SESSION_MUTATION_RATE_LIMIT_BINDING = 'SESSION_MUTATION_RATE_LIMIT' as const;

// Stable, project-specific namespace identifiers. These are configuration
// identities, not Cloudflare account or resource IDs.
export const ANONYMOUS_SESSION_RATE_LIMIT_NAMESPACE_ID = '588230349' as const;
export const SESSION_READ_RATE_LIMIT_NAMESPACE_ID = '913742685' as const;
export const SESSION_MUTATION_RATE_LIMIT_NAMESPACE_ID = '74228090' as const;

export const ANONYMOUS_SESSION_RATE_LIMIT = Object.freeze({ limit: 6, period: 60 } as const);
export const SESSION_READ_RATE_LIMIT = Object.freeze({ limit: 120, period: 60 } as const);
export const SESSION_MUTATION_RATE_LIMIT = Object.freeze({ limit: 30, period: 60 } as const);

export type HostedAbuseControlPolicy = 'disabled' | 'required';

/** The exact bindings the abuse controls read; any hosted runtime env satisfies it structurally. */
export type AbuseControlEnv = Pick<
  GatewayDeployEnv,
  | 'DEPLOY_SESSION_ENCRYPTION_KEY'
  | 'ANONYMOUS_SESSION_RATE_LIMIT'
  | 'SESSION_READ_RATE_LIMIT'
  | 'SESSION_MUTATION_RATE_LIMIT'
>;

type RateLimitPurpose =
  | 'anonymous-mutation-v1'
  | 'anonymous-session-v1'
  | 'session-read-v1'
  | 'session-mutation-v1';

const encoder = new TextEncoder();
const DOMAIN = 'ankka-gateway-deploy-abuse-control-v1';
const SESSION_ID_DOMAIN = 'ankka-gateway-deploy-session-id-v1';
const SESSION_ID_PATTERN = /^[A-Za-z0-9_-]{43}$/u;
const CLIENT_ADDRESS_PATTERN = /^[0-9a-f:.]{2,64}$/u;
const functionSchema = v.function();
const rateLimitOutcomeSchema = v.object({ success: v.boolean() });

function unavailable(): never {
  throw new DeployError(503, 'abuse_controls_unavailable');
}

function decodeDeploymentKey(value: string): Uint8Array<ArrayBuffer> {
  const compact = value.trim();
  let decoded: Uint8Array;
  try {
    if (/^[A-Za-z0-9_-]{43}$/u.test(compact)) {
      decoded = base64UrlDecode(compact);
    } else {
      const binary = atob(compact);
      decoded = Uint8Array.from(binary, (character) => character.charCodeAt(0));
    }
  } catch {
    unavailable();
  }
  if (decoded.byteLength !== 32) {
    decoded.fill(0);
    unavailable();
  }
  const owned = new Uint8Array(decoded.byteLength);
  owned.set(decoded);
  decoded.fill(0);
  return owned;
}

async function keyedDigest(
  encodedDeploymentKey: string,
  domain: string,
  purpose: string,
  subject: Uint8Array,
): Promise<Uint8Array<ArrayBuffer>> {
  const rawKey = decodeDeploymentKey(encodedDeploymentKey);
  const prefix = encoder.encode(`${domain}\0${purpose}\0`);
  const message = new Uint8Array(prefix.byteLength + subject.byteLength);
  message.set(prefix);
  message.set(subject, prefix.byteLength);
  try {
    const key = await crypto.subtle.importKey(
      'raw',
      rawKey,
      { hash: 'SHA-256', name: 'HMAC' },
      false,
      ['sign'],
    );
    const digest = await crypto.subtle.sign('HMAC', key, message);
    return new Uint8Array(digest);
  } catch {
    unavailable();
  } finally {
    rawKey.fill(0);
    prefix.fill(0);
    message.fill(0);
  }
}

async function opaqueKey(
  encodedDeploymentKey: string,
  purpose: RateLimitPurpose,
  subject: string,
): Promise<string> {
  const subjectBytes = encoder.encode(subject);
  try {
    const digest = await keyedDigest(encodedDeploymentKey, DOMAIN, purpose, subjectBytes);
    try {
      return base64UrlEncode(digest);
    } finally {
      digest.fill(0);
    }
  } finally {
    subjectBytes.fill(0);
  }
}

/**
 * Preserve the 43-character cookie contract while making the DO name
 * self-authenticating: 16 random bytes followed by a 16-byte HMAC tag.
 */
export async function mintAuthenticatedSessionId(encodedDeploymentKey: string): Promise<string> {
  const nonce = new Uint8Array(16);
  crypto.getRandomValues(nonce);
  const digest = await keyedDigest(encodedDeploymentKey, SESSION_ID_DOMAIN, 'cookie-v1', nonce);
  const token = new Uint8Array(32);
  token.set(nonce);
  token.set(digest.subarray(0, 16), 16);
  try {
    return base64UrlEncode(token);
  } finally {
    nonce.fill(0);
    digest.fill(0);
    token.fill(0);
  }
}

export async function isAuthenticatedSessionId(
  encodedDeploymentKey: string,
  sessionId: string,
): Promise<boolean> {
  if (!SESSION_ID_PATTERN.test(sessionId)) return false;
  let token: Uint8Array;
  try {
    token = base64UrlDecode(sessionId);
  } catch {
    return false;
  }
  if (token.byteLength !== 32) {
    token.fill(0);
    return false;
  }
  const nonce = token.slice(0, 16);
  const expected = await keyedDigest(encodedDeploymentKey, SESSION_ID_DOMAIN, 'cookie-v1', nonce);
  let mismatch = 0;
  for (let index = 0; index < 16; index += 1) {
    const tokenByte = token.at(index + 16);
    const expectedByte = expected.at(index);
    if (tokenByte === undefined || expectedByte === undefined) {
      token.fill(0);
      nonce.fill(0);
      expected.fill(0);
      return false;
    }
    mismatch |= tokenByte ^ expectedByte;
  }
  token.fill(0);
  nonce.fill(0);
  expected.fill(0);
  return mismatch === 0;
}

function clientAddress(request: Request): string {
  const raw = request.headers.get('cf-connecting-ip');
  if (raw === null || raw !== raw.trim()) unavailable();
  const normalized = raw.toLowerCase();
  if (
    !CLIENT_ADDRESS_PATTERN.test(normalized) ||
    (!normalized.includes('.') && !normalized.includes(':'))
  ) unavailable();
  return normalized;
}

async function consume(
  binding: RateLimit | undefined,
  key: string,
): Promise<void> {
  let outcome: RateLimitOutcome;
  try {
    if (!binding || !v.is(functionSchema, binding.limit)) unavailable();
    outcome = await binding.limit({ key });
  } catch (error) {
    if (error instanceof DeployError) throw error;
    unavailable();
  }
  if (!v.is(rateLimitOutcomeSchema, outcome)) unavailable();
  if (!outcome.success) throw new DeployError(429, 'rate_limited');
}

export async function enforceAnonymousSessionRateLimit(
  request: Request,
  env: AbuseControlEnv,
): Promise<void> {
  const key = await opaqueKey(
    env.DEPLOY_SESSION_ENCRYPTION_KEY,
    'anonymous-session-v1',
    clientAddress(request),
  );
  await consume(env.ANONYMOUS_SESSION_RATE_LIMIT, key);
}

export async function enforceSessionMutationRateLimit(
  request: Request,
  env: AbuseControlEnv,
  sessionId: string | null,
): Promise<void> {
  const hasSession = sessionId !== null && SESSION_ID_PATTERN.test(sessionId);
  const key = await opaqueKey(
    env.DEPLOY_SESSION_ENCRYPTION_KEY,
    hasSession ? 'session-mutation-v1' : 'anonymous-mutation-v1',
    hasSession ? sessionId : clientAddress(request),
  );
  await consume(env.SESSION_MUTATION_RATE_LIMIT, key);
}

export async function enforceSessionReadRateLimit(
  env: AbuseControlEnv,
  sessionId: string,
): Promise<void> {
  const key = await opaqueKey(
    env.DEPLOY_SESSION_ENCRYPTION_KEY,
    'session-read-v1',
    sessionId,
  );
  await consume(env.SESSION_READ_RATE_LIMIT, key);
}

import * as v from 'valibot';

import { DeployError } from './errors';
import {
  exactReleaseBundleIdentitySchema,
  type ExactReleaseBundleIdentity,
} from './exact-release-bundle';
import { isPlainDataTree } from './plain-data';

const encoder = new TextEncoder();
const decoder = new TextDecoder('utf-8', { fatal: true });
const OAUTH_COOKIE_AAD = encoder.encode('ankka-gateway-deploy-oauth-cookie-v2');
const BOOTSTRAP_COOKIE_AAD = encoder.encode('ankka-gateway-deploy-bootstrap-cookie-v1');
const TEARDOWN_COOKIE_AAD = encoder.encode('ankka-gateway-teardown-cookie-v1');
const BASE64_TOKEN = /^[A-Za-z0-9_-]{43}$/u;
const HOSTED_STAGE1_SESSION_ID = /^s1s_[A-Za-z0-9_-]{24}$/u;
const HOSTED_STAGE1_ATTEMPT_ID = /^attempt_[A-Za-z0-9_-]{24}$/u;
const BOOTSTRAP_ID = /^boot_[A-Za-z0-9_-]{24}$/u;
const PLAN_ID = /^plan-[a-f0-9]{24}$/u;

/** The bootstrap cookie can never outlive one Stage 1 authorization and capability window. */
export const HOSTED_STAGE1_COOKIE_TTL_MS = 10 * 60 * 1_000;
const ATTEMPT_ID = /^att_[A-Za-z0-9_-]{32}$/u;
const ACTION_ID = /^action_[A-Za-z0-9_-]{32}$/u;
const EMAIL = /^[^\s@]{1,64}@[A-Za-z0-9.-]{1,190}$/u;
const ACCOUNT_ID = /^[a-f0-9]{32}$/u;
const INSTALLATION_ID = /^acg-[a-f0-9]{24}$/u;
const WORKER_NAME = /^[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$/u;
const DNS_LABEL = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/u;
const RELEASE = /^gateway-v(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)$/u;
const HASH = /^sha256:[a-f0-9]{64}$/u;
const VERSION_ID = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/u;
const RETURNING_UNINSTALL_PLAN_ID = /^returning-uninstall-plan-[a-f0-9]{24}$/u;

function validManagementOrigin(value: string): boolean {
  try {
    const url = new URL(value);
    return url.protocol === 'https:' && !url.username && !url.password && !url.port &&
      url.pathname === '/' && !url.search && !url.hash;
  } catch {
    return false;
  }
}

function validHostname(value: string): boolean {
  const labels = value.split('.');
  return value.length <= 253 && value === value.toLowerCase() && labels.length >= 2 &&
    labels.every((label) => DNS_LABEL.test(label));
}

function validSafeName(value: string): boolean {
  return ![...value].some((character) => {
    const codePoint = character.codePointAt(0) ?? 0;
    return codePoint <= 31 || codePoint === 127 || '<>{}\\'.includes(character);
  });
}

const base64TokenSchema = v.pipe(v.string(), v.regex(BASE64_TOKEN));
const attemptIdSchema = v.pipe(v.string(), v.regex(ATTEMPT_ID));
const actionIdSchema = v.pipe(v.string(), v.regex(ACTION_ID));
const emailSchema = v.pipe(
  v.string(),
  v.regex(EMAIL),
  v.check((email) => email === email.toLowerCase()),
);
const accountIdSchema = v.pipe(v.string(), v.regex(ACCOUNT_ID));
const installationIdSchema = v.pipe(v.string(), v.regex(INSTALLATION_ID));
const workerNameSchema = v.pipe(v.string(), v.regex(WORKER_NAME));
const workersSubdomainSchema = v.pipe(v.string(), v.regex(DNS_LABEL));
const managementOriginSchema = v.pipe(v.string(), v.check(validManagementOrigin));
const hostnameSchema = v.pipe(v.string(), v.check(validHostname));
const safeNameSchema = v.pipe(
  v.string(),
  v.minLength(1),
  v.maxLength(128),
  v.check(validSafeName),
);
const expiresAtSchema = v.pipe(v.number(), v.safeInteger());
const runtimeVersionSchema = v.strictObject({
  release: v.pipe(v.string(), v.regex(RELEASE)),
  artifactSha256: v.pipe(v.string(), v.regex(HASH)),
  versionId: v.union([v.pipe(v.string(), v.regex(VERSION_ID)), v.null()]),
});

const sealedOauthCookieV2Schema = v.strictObject({
  schemaVersion: v.literal(2),
  purpose: v.picklist(['install', 'uninstall']),
  sessionId: base64TokenSchema,
  attemptId: attemptIdSchema,
  verifier: base64TokenSchema,
  expiresAt: expiresAtSchema,
});
const sealedOauthCookieV3Schema = v.strictObject({
  schemaVersion: v.literal(3),
  purpose: v.picklist(['discover', 'install', 'uninstall']),
  sessionId: base64TokenSchema,
  attemptId: attemptIdSchema,
  state: base64TokenSchema,
  verifier: base64TokenSchema,
  expiresAt: expiresAtSchema,
});
const sealedOauthCookieV4Schema = v.strictObject({
  schemaVersion: v.literal(4),
  purpose: v.literal('source_apply'),
  action: v.exactOptional(v.literal('access')),
  state: base64TokenSchema,
  verifier: base64TokenSchema,
  expiresAt: expiresAtSchema,
  actionId: actionIdSchema,
  actionKey: base64TokenSchema,
  actorEmail: emailSchema,
  accountId: accountIdSchema,
  workerName: workerNameSchema,
  workersSubdomain: workersSubdomainSchema,
  managementOrigin: managementOriginSchema,
  releaseIdentity: exactReleaseBundleIdentitySchema,
});
const sealedOauthCookieV5Schema = v.strictObject({
  schemaVersion: v.literal(5),
  purpose: v.literal('runtime_update'),
  state: base64TokenSchema,
  verifier: base64TokenSchema,
  expiresAt: expiresAtSchema,
  actionId: actionIdSchema,
  actionKey: base64TokenSchema,
  actorEmail: emailSchema,
  accountId: accountIdSchema,
  workerName: workerNameSchema,
  workersSubdomain: workersSubdomainSchema,
  managementOrigin: managementOriginSchema,
  operation: v.picklist(['update', 'rollback']),
  from: runtimeVersionSchema,
  to: runtimeVersionSchema,
});
const sealedOauthCookieV6Schema = v.strictObject({
  schemaVersion: v.literal(6),
  purpose: v.literal('gateway_teardown_review'),
  sessionId: base64TokenSchema,
  expiresAt: expiresAtSchema,
  actionId: actionIdSchema,
  actionKey: base64TokenSchema,
  actorEmail: emailSchema,
  accountId: accountIdSchema,
  installationId: installationIdSchema,
  gatewayName: safeNameSchema,
  portalHostname: hostnameSchema,
  workerName: workerNameSchema,
  workersSubdomain: workersSubdomainSchema,
  managementOrigin: managementOriginSchema,
});
const sealedOauthCookieV7Schema = v.strictObject({
  schemaVersion: v.literal(7),
  purpose: v.literal('gateway_teardown'),
  sessionId: base64TokenSchema,
  attemptId: attemptIdSchema,
  state: base64TokenSchema,
  verifier: base64TokenSchema,
  expiresAt: expiresAtSchema,
  actionId: actionIdSchema,
  actionKey: base64TokenSchema,
  actorEmail: emailSchema,
  accountId: accountIdSchema,
  installationId: installationIdSchema,
  gatewayName: safeNameSchema,
  portalHostname: hostnameSchema,
  workerName: workerNameSchema,
  workersSubdomain: workersSubdomainSchema,
  managementOrigin: managementOriginSchema,
});
const sealedOauthCookieV8Schema = v.strictObject({
  schemaVersion: v.literal(8),
  purpose: v.literal('gateway_teardown_recovery'),
  sessionId: base64TokenSchema,
  attemptId: attemptIdSchema,
  state: base64TokenSchema,
  verifier: base64TokenSchema,
  expiresAt: expiresAtSchema,
  planId: v.pipe(v.string(), v.regex(RETURNING_UNINSTALL_PLAN_ID)),
  planHash: v.pipe(v.string(), v.regex(HASH)),
  actorEmail: emailSchema,
  accountId: accountIdSchema,
  zoneId: accountIdSchema,
  installationId: installationIdSchema,
});
const sealedOauthCookieV9Schema = v.strictObject({
  schemaVersion: v.literal(9),
  purpose: v.literal('management_action_result'),
  actionType: v.picklist(['source_apply', 'access_apply', 'runtime_update']),
  actionId: actionIdSchema,
  managementOrigin: managementOriginSchema,
  expiresAt: expiresAtSchema,
});
const sealedOauthCookieSchema = v.variant('schemaVersion', [
  sealedOauthCookieV2Schema,
  sealedOauthCookieV3Schema,
  sealedOauthCookieV4Schema,
  sealedOauthCookieV5Schema,
  sealedOauthCookieV6Schema,
  sealedOauthCookieV7Schema,
  sealedOauthCookieV8Schema,
  sealedOauthCookieV9Schema,
]);

const sealedBootstrapCapabilitySchema = v.strictObject({
  bootstrapId: v.pipe(v.string(), v.regex(BOOTSTRAP_ID)),
  capabilitySecret: base64TokenSchema,
  capabilityExpiresAt: expiresAtSchema,
  bootstrapNonce: base64TokenSchema,
  ownershipWrapKey: base64TokenSchema,
});
/**
 * Schema 10: the only browser-side holder of the raw Stage 1 redirect secrets.
 * It is sealed under its own additional data so neither the legacy OAuth
 * cookie nor this one can be opened by the other path. A `bootstrap` attempt
 * carries the one-time capability material; a `cleanup` attempt carries none.
 */
const sealedBootstrapCookieSchema = v.pipe(
  v.strictObject({
    schemaVersion: v.literal(10),
    purpose: v.literal('bootstrap'),
    kind: v.picklist(['bootstrap', 'cleanup']),
    sessionId: v.pipe(v.string(), v.regex(HOSTED_STAGE1_SESSION_ID)),
    attemptId: v.pipe(v.string(), v.regex(HOSTED_STAGE1_ATTEMPT_ID)),
    state: base64TokenSchema,
    verifier: base64TokenSchema,
    expiresAt: v.pipe(expiresAtSchema, v.minValue(0)),
    planId: v.pipe(v.string(), v.regex(PLAN_ID)),
    planHash: v.pipe(v.string(), v.regex(HASH)),
    capability: v.union([sealedBootstrapCapabilitySchema, v.null()]),
  }),
  v.check((cookie) => cookie.kind === 'bootstrap'
    ? cookie.capability !== null && cookie.capability.capabilityExpiresAt === cookie.expiresAt
    : cookie.capability === null),
  v.check((cookie) => cookie.state !== cookie.verifier),
);

export function base64UrlEncode(bytes: Uint8Array): string {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/u, '');
}

export function base64UrlDecode(value: string): Uint8Array {
  if (!/^[A-Za-z0-9_-]+$/u.test(value)) throw new DeployError(400, 'session_invalid');
  const padded = value.replaceAll('-', '+').replaceAll('_', '/') + '='.repeat((4 - (value.length % 4)) % 4);
  try {
    const binary = atob(padded);
    const bytes = new Uint8Array(binary.length);
    for (let index = 0; index < binary.length; index += 1) bytes[index] = binary.charCodeAt(index);
    // Reject alternate spellings created by non-zero unused base64 padding
    // bits. An authenticated cookie has one canonical wire representation.
    if (base64UrlEncode(bytes) !== value) throw new DeployError(400, 'session_invalid');
    return bytes;
  } catch {
    throw new DeployError(400, 'session_invalid');
  }
}

export function randomBase64Url(byteLength: number): string {
  const bytes = new Uint8Array(byteLength);
  crypto.getRandomValues(bytes);
  return base64UrlEncode(bytes);
}

export async function sha256(value: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', encoder.encode(value));
  return base64UrlEncode(new Uint8Array(digest));
}

export async function sha256Hex(value: string): Promise<string> {
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', encoder.encode(value)));
  return [...digest].map((byte) => byte.toString(16).padStart(2, '0')).join('');
}

export async function pkceChallenge(verifier: string): Promise<string> {
  return sha256(verifier);
}

export function constantTimeEqual(left: string, right: string): boolean {
  const leftBytes = encoder.encode(left);
  const rightBytes = encoder.encode(right);
  let mismatch = leftBytes.length ^ rightBytes.length;
  const length = Math.max(leftBytes.length, rightBytes.length);
  for (let index = 0; index < length; index += 1) {
    mismatch |= (leftBytes[index] ?? 0) ^ (rightBytes[index] ?? 0);
  }
  return mismatch === 0;
}

function decodeEncryptionKey(value: string): Uint8Array<ArrayBuffer> {
  const compact = value.trim();
  let bytes: Uint8Array;
  try {
    if (/^[A-Za-z0-9_-]{43}$/u.test(compact)) {
      bytes = base64UrlDecode(compact);
    } else {
      const binary = atob(compact);
      bytes = Uint8Array.from(binary, (character) => character.charCodeAt(0));
    }
  } catch {
    throw new DeployError(500, 'session_invalid');
  }
  if (bytes.byteLength !== 32) throw new DeployError(500, 'session_invalid');
  const owned = new Uint8Array(bytes.byteLength);
  owned.set(bytes);
  return owned;
}

async function aesKey(encodedKey: string): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    'raw',
    decodeEncryptionKey(encodedKey),
    { name: 'AES-GCM' },
    false,
    ['encrypt', 'decrypt'],
  );
}

export interface SealedOauthCookieV2 {
  schemaVersion: 2;
  purpose: 'install' | 'uninstall';
  sessionId: string;
  attemptId: string;
  verifier: string;
  expiresAt: number;
}

export interface SealedOauthCookieV3 {
  schemaVersion: 3;
  purpose: 'discover' | 'install' | 'uninstall';
  sessionId: string;
  attemptId: string;
  state: string;
  verifier: string;
  expiresAt: number;
}

export interface SealedOauthCookieV4 {
  schemaVersion: 4;
  purpose: 'source_apply';
  action?: 'access';
  state: string;
  verifier: string;
  expiresAt: number;
  actionId: string;
  actionKey: string;
  actorEmail: string;
  accountId: string;
  workerName: string;
  workersSubdomain: string;
  managementOrigin: string;
  releaseIdentity: ExactReleaseBundleIdentity;
}

export interface SealedOauthCookieV5 {
  schemaVersion: 5;
  purpose: 'runtime_update';
  state: string;
  verifier: string;
  expiresAt: number;
  actionId: string;
  actionKey: string;
  actorEmail: string;
  accountId: string;
  workerName: string;
  workersSubdomain: string;
  managementOrigin: string;
  operation: 'update' | 'rollback';
  from: { readonly release: string; readonly artifactSha256: string; readonly versionId: string | null };
  to: { readonly release: string; readonly artifactSha256: string; readonly versionId: string | null };
}

export interface SealedOauthCookieV6 {
  schemaVersion: 6;
  purpose: 'gateway_teardown_review';
  sessionId: string;
  expiresAt: number;
  actionId: string;
  actionKey: string;
  actorEmail: string;
  accountId: string;
  installationId: string;
  gatewayName: string;
  portalHostname: string;
  workerName: string;
  workersSubdomain: string;
  managementOrigin: string;
}

export interface SealedOauthCookieV7 {
  schemaVersion: 7;
  purpose: 'gateway_teardown';
  sessionId: string;
  attemptId: string;
  state: string;
  verifier: string;
  expiresAt: number;
  actionId: string;
  actionKey: string;
  actorEmail: string;
  accountId: string;
  installationId: string;
  gatewayName: string;
  portalHostname: string;
  workerName: string;
  workersSubdomain: string;
  managementOrigin: string;
}

export interface SealedOauthCookieV8 {
  schemaVersion: 8;
  purpose: 'gateway_teardown_recovery';
  sessionId: string;
  attemptId: string;
  state: string;
  verifier: string;
  expiresAt: number;
  planId: string;
  planHash: string;
  actorEmail: string;
  accountId: string;
  zoneId: string;
  installationId: string;
}

/**
 * Short-lived redirect authority minted only after a management action has
 * completed through the verified customer Worker relay. The untrusted handoff
 * cookie (schemas 4/5) is deliberately not accepted by the context endpoint.
 */
export interface SealedOauthCookieV9 {
  schemaVersion: 9;
  purpose: 'management_action_result';
  actionType: 'source_apply' | 'access_apply' | 'runtime_update';
  actionId: string;
  managementOrigin: string;
  expiresAt: number;
}

export type SealedOauthCookie =
  | SealedOauthCookieV2
  | SealedOauthCookieV3
  | SealedOauthCookieV4
  | SealedOauthCookieV5
  | SealedOauthCookieV6
  | SealedOauthCookieV7
  | SealedOauthCookieV8
  | SealedOauthCookieV9;

function parseSealedPayload<Input>(input: Input): SealedOauthCookie {
  if (!isPlainDataTree(input)) throw new DeployError(400, 'session_invalid');
  const result = v.safeParse(sealedOauthCookieSchema, input);
  if (!result.success) throw new DeployError(400, 'session_invalid');
  return result.output;
}

async function sealSerialized(encodedKey: string, aad: Uint8Array<ArrayBuffer>, serialized: string): Promise<string> {
  const iv = new Uint8Array(12);
  crypto.getRandomValues(iv);
  const plaintext = encoder.encode(serialized);
  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv, additionalData: aad },
    await aesKey(encodedKey),
    plaintext,
  );
  plaintext.fill(0);
  const combined = new Uint8Array(iv.byteLength + ciphertext.byteLength);
  combined.set(iv);
  combined.set(new Uint8Array(ciphertext), iv.byteLength);
  return base64UrlEncode(combined);
}

async function openSerialized(encodedKey: string, aad: Uint8Array<ArrayBuffer>, sealed: string): Promise<string> {
  try {
    const bytes = base64UrlDecode(sealed);
    if (bytes.byteLength < 12 + 16) throw new DeployError(400, 'session_invalid');
    const plaintext = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: bytes.slice(0, 12), additionalData: aad },
      await aesKey(encodedKey),
      bytes.slice(12),
    );
    return decoder.decode(plaintext);
  } catch (error) {
    if (error instanceof DeployError) throw error;
    throw new DeployError(400, 'session_invalid');
  }
}

function parseSerializedJson(serialized: string): SealedOauthCookie {
  let decoded: unknown;
  try {
    decoded = JSON.parse(serialized);
  } catch {
    throw new DeployError(400, 'session_invalid');
  }
  return parseSealedPayload(decoded);
}

export async function sealOauthCookie<Input>(
  encodedKey: string,
  payload: Input,
): Promise<string> {
  const parsed = parseSealedPayload(payload);
  return sealSerialized(encodedKey, OAUTH_COOKIE_AAD, JSON.stringify(parsed));
}

export async function openOauthCookie(
  encodedKey: string,
  sealed: string,
): Promise<SealedOauthCookie> {
  return parseSerializedJson(await openSerialized(encodedKey, OAUTH_COOKIE_AAD, sealed));
}

export interface SealedBootstrapCapability {
  readonly bootstrapId: string;
  readonly capabilitySecret: string;
  readonly capabilityExpiresAt: number;
  readonly bootstrapNonce: string;
  readonly ownershipWrapKey: string;
}

/**
 * Raw Stage 1 redirect material for exactly one attempt. It exists only inside
 * the encrypted `__Host-` bootstrap cookie and in request-local memory; the
 * durable session stores hashes and commitments for every field here.
 */
export interface SealedBootstrapCookie {
  readonly schemaVersion: 10;
  readonly purpose: 'bootstrap';
  readonly kind: 'bootstrap' | 'cleanup';
  readonly sessionId: string;
  readonly attemptId: string;
  readonly state: string;
  readonly verifier: string;
  readonly expiresAt: number;
  readonly planId: string;
  readonly planHash: string;
  readonly capability: SealedBootstrapCapability | null;
}

function parseSealedBootstrapPayload<Input>(input: Input, now: number): SealedBootstrapCookie {
  if (!Number.isSafeInteger(now) || now < 0 || !isPlainDataTree(input)) {
    throw new DeployError(400, 'session_invalid');
  }
  const result = v.safeParse(sealedBootstrapCookieSchema, input);
  if (!result.success) throw new DeployError(400, 'session_invalid');
  const cookie = result.output;
  if (cookie.expiresAt > now + HOSTED_STAGE1_COOKIE_TTL_MS) throw new DeployError(400, 'session_invalid');
  if (cookie.expiresAt <= now) throw new DeployError(400, 'session_expired');
  return Object.freeze({
    ...cookie,
    capability: cookie.capability === null ? null : Object.freeze(cookie.capability),
  });
}

/** Seals the bootstrap cookie; the payload must already be within its ten-minute window. */
export async function sealHostedStage1Cookie<Input>(
  encodedKey: string,
  payload: Input,
  now: number,
): Promise<string> {
  const parsed = parseSealedBootstrapPayload(payload, now);
  return sealSerialized(encodedKey, BOOTSTRAP_COOKIE_AAD, JSON.stringify(parsed));
}

/** Opens the bootstrap cookie and rejects anything expired, foreign, or not schema 10. */
export async function openHostedStage1Cookie(
  encodedKey: string,
  sealed: string,
  now: number,
): Promise<SealedBootstrapCookie> {
  const serialized = await openSerialized(encodedKey, BOOTSTRAP_COOKIE_AAD, sealed);
  let decoded: unknown;
  try {
    decoded = JSON.parse(serialized);
  } catch {
    throw new DeployError(400, 'session_invalid');
  }
  return parseSealedBootstrapPayload(decoded, now);
}

export async function deriveCsrfToken(encodedKey: string, sessionId: string): Promise<string> {
  const key = await crypto.subtle.importKey(
    'raw',
    decodeEncryptionKey(encodedKey),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  );
  const signature = await crypto.subtle.sign(
    'HMAC',
    key,
    encoder.encode(`ankka-gateway-deploy-csrf-v1:${sessionId}`),
  );
  return base64UrlEncode(new Uint8Array(signature));
}

const teardownCookieSchema = v.strictObject({
  purpose: v.literal('gateway_teardown'), schemaVersion: v.literal(1),
  jobId: v.pipe(v.string(), v.regex(/^[a-f0-9]{64}$/u)),
  expiresAt: v.pipe(v.number(), v.safeInteger(), v.minValue(0)),
  attempt: v.nullable(v.strictObject({
    id: v.pipe(v.string(), v.regex(HOSTED_STAGE1_ATTEMPT_ID)),
    state: v.pipe(v.string(), v.regex(BASE64_TOKEN)), verifier: v.pipe(v.string(), v.regex(BASE64_TOKEN)),
    expiresAt: v.pipe(v.number(), v.safeInteger(), v.minValue(0)),
  })),
});
export type GatewayTeardownCookie = v.InferOutput<typeof teardownCookieSchema>;
export async function sealGatewayTeardownCookie(encodedKey: string, value: GatewayTeardownCookie): Promise<string> {
  const parsed = v.safeParse(teardownCookieSchema, value);
  if (!parsed.success) throw new DeployError(400, 'session_invalid');
  return sealSerialized(encodedKey, TEARDOWN_COOKIE_AAD, JSON.stringify(parsed.output));
}
export async function openGatewayTeardownCookie(encodedKey: string, sealed: string, now: number): Promise<GatewayTeardownCookie> {
  try {
    const cookie = v.parse(teardownCookieSchema, JSON.parse(await openSerialized(encodedKey, TEARDOWN_COOKIE_AAD, sealed)));
    if (cookie.expiresAt <= now || cookie.expiresAt > now + 24 * 60 * 60 * 1000) throw new Error();
    return cookie;
  } catch { throw new DeployError(400, 'session_invalid'); }
}

const CUSTOMER_TEARDOWN_COOKIE_AAD = new TextEncoder().encode('ankka-customer-teardown-cookie-v1');
const customerTeardownCookieSchema = v.strictObject({
  purpose: v.literal('customer_teardown'), schemaVersion: v.literal(1),
  attemptId: v.pipe(v.string(), v.regex(HOSTED_STAGE1_ATTEMPT_ID)),
  expiresAt: v.pipe(v.number(), v.safeInteger(), v.minValue(0)),
  verifier: v.pipe(v.string(), v.regex(BASE64_TOKEN)),
  actionKey: v.pipe(v.string(), v.regex(BASE64_TOKEN)),
});
export type CustomerTeardownCookie = v.InferOutput<typeof customerTeardownCookieSchema>;
export async function sealCustomerTeardownCookie(key: string, value: CustomerTeardownCookie): Promise<string> {
  return sealSerialized(key, CUSTOMER_TEARDOWN_COOKIE_AAD, JSON.stringify(v.parse(customerTeardownCookieSchema, value)));
}
export async function openCustomerTeardownCookie(key: string, sealed: string, now: number): Promise<CustomerTeardownCookie> {
  const cookie = v.parse(customerTeardownCookieSchema, JSON.parse(await openSerialized(key, CUSTOMER_TEARDOWN_COOKIE_AAD, sealed)));
  if (cookie.expiresAt <= now || cookie.expiresAt > now + 10 * 60 * 1000) throw new Error('teardown_cookie_invalid');
  return cookie;
}

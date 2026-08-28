import { DeployError } from './errors';
import type { ExactReleaseBundleIdentity } from './exact-release-bundle';

const encoder = new TextEncoder();
const decoder = new TextDecoder('utf-8', { fatal: true });
const OAUTH_COOKIE_AAD = encoder.encode('ankka-gateway-deploy-oauth-cookie-v2');

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
  actionType: 'source_apply' | 'runtime_update';
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

function parseSealedPayload(input: unknown): SealedOauthCookie {
  if (!input || typeof input !== 'object' || Array.isArray(input)) {
    throw new DeployError(400, 'session_invalid');
  }
  const value = input as Record<string, unknown>;
  const expectedKeys = value.schemaVersion === 2
    ? ['attemptId', 'expiresAt', 'purpose', 'schemaVersion', 'sessionId', 'verifier']
    : value.schemaVersion === 3
      ? ['attemptId', 'expiresAt', 'purpose', 'schemaVersion', 'sessionId', 'state', 'verifier']
      : value.schemaVersion === 4 ? [
        'accountId', 'actionId', 'actionKey', 'actorEmail', 'expiresAt', 'managementOrigin',
        'purpose', 'releaseIdentity', 'schemaVersion', 'state', 'verifier', 'workerName',
        'workersSubdomain',
      ] : value.schemaVersion === 5 ? [
        'accountId', 'actionId', 'actionKey', 'actorEmail', 'expiresAt', 'from', 'managementOrigin',
        'operation', 'purpose', 'schemaVersion', 'state', 'to', 'verifier', 'workerName', 'workersSubdomain',
      ] : value.schemaVersion === 6 ? [
        'accountId', 'actionId', 'actionKey', 'actorEmail', 'expiresAt', 'gatewayName', 'installationId',
        'managementOrigin', 'portalHostname', 'purpose', 'schemaVersion', 'sessionId', 'workerName',
        'workersSubdomain',
      ] : value.schemaVersion === 7 ? [
        'accountId', 'actionId', 'actionKey', 'actorEmail', 'attemptId', 'expiresAt', 'gatewayName',
        'installationId', 'managementOrigin', 'portalHostname', 'purpose', 'schemaVersion', 'sessionId',
        'state', 'verifier', 'workerName', 'workersSubdomain',
      ] : value.schemaVersion === 8 ? [
        'accountId', 'actorEmail', 'attemptId', 'expiresAt', 'installationId', 'planHash', 'planId',
        'purpose', 'schemaVersion', 'sessionId', 'state', 'verifier', 'zoneId',
      ] : value.schemaVersion === 9 ? [
        'actionId', 'actionType', 'expiresAt', 'managementOrigin', 'purpose', 'schemaVersion',
      ] : [
      ];
  if (value.schemaVersion === 4) {
    let management: URL;
    try { management = new URL(String(value.managementOrigin)); } catch {
      throw new DeployError(400, 'session_invalid');
    }
    const releaseIdentity = value.releaseIdentity;
    if (
      Object.keys(value).sort().join(',') !== expectedKeys.sort().join(',') ||
      value.purpose !== 'source_apply' ||
      typeof value.state !== 'string' || !/^[A-Za-z0-9_-]{43}$/u.test(value.state) ||
      typeof value.verifier !== 'string' || !/^[A-Za-z0-9_-]{43}$/u.test(value.verifier) ||
      typeof value.expiresAt !== 'number' || !Number.isSafeInteger(value.expiresAt) ||
      typeof value.actionId !== 'string' || !/^action_[A-Za-z0-9_-]{32}$/u.test(value.actionId) ||
      typeof value.actionKey !== 'string' || !/^[A-Za-z0-9_-]{43}$/u.test(value.actionKey) ||
      typeof value.actorEmail !== 'string' || value.actorEmail !== value.actorEmail.toLowerCase() ||
      !/^[^\s@]{1,64}@[A-Za-z0-9.-]{1,190}$/u.test(value.actorEmail) ||
      typeof value.accountId !== 'string' || !/^[a-f0-9]{32}$/u.test(value.accountId) ||
      typeof value.workerName !== 'string' || !/^[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$/u.test(value.workerName) ||
      typeof value.workersSubdomain !== 'string' || !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/u.test(value.workersSubdomain) ||
      !releaseIdentity || typeof releaseIdentity !== 'object' || Array.isArray(releaseIdentity) ||
      Object.keys(releaseIdentity).sort().join(',') !==
        'artifactSha256,channel,keyId,publicKey,release,schemaVersion' ||
      (releaseIdentity as Record<string, unknown>).schemaVersion !== 1 ||
      ((releaseIdentity as Record<string, unknown>).channel !== 'canary' &&
        (releaseIdentity as Record<string, unknown>).channel !== 'stable') ||
      typeof (releaseIdentity as Record<string, unknown>).release !== 'string' ||
      !/^gateway-v(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)$/u.test(
        (releaseIdentity as Record<string, unknown>).release as string,
      ) || typeof (releaseIdentity as Record<string, unknown>).keyId !== 'string' ||
      !/^[a-z0-9][a-z0-9._-]{0,63}$/u.test((releaseIdentity as Record<string, unknown>).keyId as string) ||
      typeof (releaseIdentity as Record<string, unknown>).publicKey !== 'string' ||
      !/^[A-Za-z0-9_-]{43}$/u.test((releaseIdentity as Record<string, unknown>).publicKey as string) ||
      typeof (releaseIdentity as Record<string, unknown>).artifactSha256 !== 'string' ||
      !/^[a-f0-9]{64}$/u.test((releaseIdentity as Record<string, unknown>).artifactSha256 as string) ||
      management.protocol !== 'https:' || management.username !== '' || management.password !== '' ||
      management.port !== '' || management.pathname !== '/' || management.search !== '' || management.hash !== ''
    ) throw new DeployError(400, 'session_invalid');
    return value as unknown as SealedOauthCookieV4;
  }
  if (value.schemaVersion === 5) {
    let management: URL;
    try { management = new URL(String(value.managementOrigin)); } catch {
      throw new DeployError(400, 'session_invalid');
    }
    const runtimeVersion = (input: unknown): boolean => Boolean(input) && typeof input === 'object' &&
      !Array.isArray(input) && Object.keys(input as Record<string, unknown>).sort().join(',') ===
        'artifactSha256,release,versionId' &&
      typeof (input as Record<string, unknown>).release === 'string' &&
      /^gateway-v(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)$/u.test(
        (input as Record<string, unknown>).release as string,
      ) && typeof (input as Record<string, unknown>).artifactSha256 === 'string' &&
      /^sha256:[a-f0-9]{64}$/u.test((input as Record<string, unknown>).artifactSha256 as string) &&
      ((input as Record<string, unknown>).versionId === null || (
        typeof (input as Record<string, unknown>).versionId === 'string' &&
        /^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/u.test(
          (input as Record<string, unknown>).versionId as string,
        )
      ));
    if (
      Object.keys(value).sort().join(',') !== expectedKeys.sort().join(',') ||
      value.purpose !== 'runtime_update' ||
      typeof value.state !== 'string' || !/^[A-Za-z0-9_-]{43}$/u.test(value.state) ||
      typeof value.verifier !== 'string' || !/^[A-Za-z0-9_-]{43}$/u.test(value.verifier) ||
      typeof value.expiresAt !== 'number' || !Number.isSafeInteger(value.expiresAt) ||
      typeof value.actionId !== 'string' || !/^action_[A-Za-z0-9_-]{32}$/u.test(value.actionId) ||
      typeof value.actionKey !== 'string' || !/^[A-Za-z0-9_-]{43}$/u.test(value.actionKey) ||
      typeof value.actorEmail !== 'string' || value.actorEmail !== value.actorEmail.toLowerCase() ||
      !/^[^\s@]{1,64}@[A-Za-z0-9.-]{1,190}$/u.test(value.actorEmail) ||
      typeof value.accountId !== 'string' || !/^[a-f0-9]{32}$/u.test(value.accountId) ||
      typeof value.workerName !== 'string' || !/^[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$/u.test(value.workerName) ||
      typeof value.workersSubdomain !== 'string' || !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/u.test(value.workersSubdomain) ||
      management.protocol !== 'https:' || management.username !== '' || management.password !== '' ||
      management.port !== '' || management.pathname !== '/' || management.search !== '' || management.hash !== '' ||
      (value.operation !== 'update' && value.operation !== 'rollback') || !runtimeVersion(value.from) ||
      !runtimeVersion(value.to)
    ) throw new DeployError(400, 'session_invalid');
    return value as unknown as SealedOauthCookieV5;
  }
  if (value.schemaVersion === 6 || value.schemaVersion === 7) {
    let management: URL;
    try { management = new URL(String(value.managementOrigin)); } catch {
      throw new DeployError(400, 'session_invalid');
    }
    const hostname = (input: unknown): boolean => typeof input === 'string' && input.length <= 253 &&
      input === input.toLowerCase() && input.split('.').length >= 2 && input.split('.').every((label) =>
        /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/u.test(label));
    const attemptValid = value.schemaVersion === 6 || (
      typeof value.attemptId === 'string' && /^att_[A-Za-z0-9_-]{32}$/u.test(value.attemptId) &&
      typeof value.state === 'string' && /^[A-Za-z0-9_-]{43}$/u.test(value.state) &&
      typeof value.verifier === 'string' && /^[A-Za-z0-9_-]{43}$/u.test(value.verifier)
    );
    if (Object.keys(value).sort().join(',') !== expectedKeys.sort().join(',') ||
      value.purpose !== (value.schemaVersion === 6 ? 'gateway_teardown_review' : 'gateway_teardown') ||
      typeof value.sessionId !== 'string' || !/^[A-Za-z0-9_-]{43}$/u.test(value.sessionId) ||
      !attemptValid || typeof value.expiresAt !== 'number' || !Number.isSafeInteger(value.expiresAt) ||
      typeof value.actionId !== 'string' || !/^action_[A-Za-z0-9_-]{32}$/u.test(value.actionId) ||
      typeof value.actionKey !== 'string' || !/^[A-Za-z0-9_-]{43}$/u.test(value.actionKey) ||
      typeof value.actorEmail !== 'string' || value.actorEmail !== value.actorEmail.toLowerCase() ||
      !/^[^\s@]{1,64}@[A-Za-z0-9.-]{1,190}$/u.test(value.actorEmail) ||
      typeof value.accountId !== 'string' || !/^[a-f0-9]{32}$/u.test(value.accountId) ||
      typeof value.installationId !== 'string' || !/^acg-[a-f0-9]{24}$/u.test(value.installationId) ||
      typeof value.gatewayName !== 'string' || value.gatewayName.length < 1 || value.gatewayName.length > 128 ||
      /[\u0000-\u001f\u007f<>{}\\]/u.test(value.gatewayName) || !hostname(value.portalHostname) ||
      typeof value.workerName !== 'string' || !/^[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$/u.test(value.workerName) ||
      typeof value.workersSubdomain !== 'string' || !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/u.test(value.workersSubdomain) ||
      management.protocol !== 'https:' || management.username !== '' || management.password !== '' ||
      management.port !== '' || management.pathname !== '/' || management.search !== '' || management.hash !== '') {
      throw new DeployError(400, 'session_invalid');
    }
    return value as unknown as SealedOauthCookieV6 | SealedOauthCookieV7;
  }
  if (value.schemaVersion === 8) {
    if (Object.keys(value).sort().join(',') !== expectedKeys.sort().join(',') ||
      value.purpose !== 'gateway_teardown_recovery' ||
      typeof value.sessionId !== 'string' || !/^[A-Za-z0-9_-]{43}$/u.test(value.sessionId) ||
      typeof value.attemptId !== 'string' || !/^att_[A-Za-z0-9_-]{32}$/u.test(value.attemptId) ||
      typeof value.state !== 'string' || !/^[A-Za-z0-9_-]{43}$/u.test(value.state) ||
      typeof value.verifier !== 'string' || !/^[A-Za-z0-9_-]{43}$/u.test(value.verifier) ||
      typeof value.expiresAt !== 'number' || !Number.isSafeInteger(value.expiresAt) ||
      typeof value.planId !== 'string' || !/^returning-uninstall-plan-[a-f0-9]{24}$/u.test(value.planId) ||
      typeof value.planHash !== 'string' || !/^sha256:[a-f0-9]{64}$/u.test(value.planHash) ||
      typeof value.actorEmail !== 'string' || value.actorEmail !== value.actorEmail.toLowerCase() ||
      !/^[^\s@]{1,64}@[A-Za-z0-9.-]{1,190}$/u.test(value.actorEmail) ||
      typeof value.accountId !== 'string' || !/^[a-f0-9]{32}$/u.test(value.accountId) ||
      typeof value.zoneId !== 'string' || !/^[a-f0-9]{32}$/u.test(value.zoneId) ||
      typeof value.installationId !== 'string' || !/^acg-[a-f0-9]{24}$/u.test(value.installationId)) {
      throw new DeployError(400, 'session_invalid');
    }
    return value as unknown as SealedOauthCookieV8;
  }
  if (value.schemaVersion === 9) {
    let management: URL;
    try { management = new URL(String(value.managementOrigin)); } catch {
      throw new DeployError(400, 'session_invalid');
    }
    if (Object.keys(value).sort().join(',') !== expectedKeys.sort().join(',') ||
      value.purpose !== 'management_action_result' ||
      (value.actionType !== 'source_apply' && value.actionType !== 'runtime_update') ||
      typeof value.actionId !== 'string' || !/^action_[A-Za-z0-9_-]{32}$/u.test(value.actionId) ||
      typeof value.expiresAt !== 'number' || !Number.isSafeInteger(value.expiresAt) ||
      management.protocol !== 'https:' || management.username !== '' || management.password !== '' ||
      management.port !== '' || management.pathname !== '/' || management.search !== '' || management.hash !== '') {
      throw new DeployError(400, 'session_invalid');
    }
    return value as unknown as SealedOauthCookieV9;
  }
  if (
    Object.keys(value).sort().join(',') !== expectedKeys.sort().join(',') ||
    (value.schemaVersion !== 2 && value.schemaVersion !== 3) ||
    (value.purpose !== 'discover' && value.purpose !== 'install' && value.purpose !== 'uninstall') ||
    typeof value.sessionId !== 'string' ||
    !/^[A-Za-z0-9_-]{43}$/u.test(value.sessionId) ||
    typeof value.attemptId !== 'string' ||
    !/^att_[A-Za-z0-9_-]{32}$/u.test(value.attemptId) ||
    (value.schemaVersion === 3 && (
      typeof value.state !== 'string' || !/^[A-Za-z0-9_-]{43}$/u.test(value.state)
    )) ||
    typeof value.verifier !== 'string' ||
    !/^[A-Za-z0-9_-]{43}$/u.test(value.verifier) ||
    typeof value.expiresAt !== 'number' ||
    !Number.isSafeInteger(value.expiresAt)
  ) {
    throw new DeployError(400, 'session_invalid');
  }
  return value as unknown as SealedOauthCookie;
}

export async function sealOauthCookie(
  encodedKey: string,
  payload: SealedOauthCookie,
): Promise<string> {
  const iv = new Uint8Array(12);
  crypto.getRandomValues(iv);
  const plaintext = encoder.encode(JSON.stringify(payload));
  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv, additionalData: OAUTH_COOKIE_AAD },
    await aesKey(encodedKey),
    plaintext,
  );
  const combined = new Uint8Array(iv.byteLength + ciphertext.byteLength);
  combined.set(iv);
  combined.set(new Uint8Array(ciphertext), iv.byteLength);
  return base64UrlEncode(combined);
}

export async function openOauthCookie(
  encodedKey: string,
  sealed: string,
): Promise<SealedOauthCookie> {
  try {
    const bytes = base64UrlDecode(sealed);
    if (bytes.byteLength < 12 + 16) throw new DeployError(400, 'session_invalid');
    const plaintext = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: bytes.slice(0, 12), additionalData: OAUTH_COOKIE_AAD },
      await aesKey(encodedKey),
      bytes.slice(12),
    );
    return parseSealedPayload(JSON.parse(decoder.decode(plaintext)));
  } catch (error) {
    if (error instanceof DeployError) throw error;
    throw new DeployError(400, 'session_invalid');
  }
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

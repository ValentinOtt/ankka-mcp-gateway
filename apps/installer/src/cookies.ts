import { BOOTSTRAP_COOKIE, OAUTH_COOKIE, SESSION_COOKIE } from './constants';
import { DeployError } from './errors';

const SESSION_ID_PATTERN = /^[A-Za-z0-9_-]{43}$/u;
const SEALED_VALUE_PATTERN = /^[A-Za-z0-9_-]{40,4096}$/u;

/** Reads the sealed hosted Stage 1 bootstrap cookie value, or null when absent or malformed. */
export function readBootstrapCookie(request: Request): string | null {
  const value = parseCookies(request.headers.get('cookie')).get(BOOTSTRAP_COOKIE) ?? null;
  return value !== null && SEALED_VALUE_PATTERN.test(value) ? value : null;
}

export function bootstrapCookie(value: string, maxAgeSeconds: number): string {
  if (!SEALED_VALUE_PATTERN.test(value) || !Number.isSafeInteger(maxAgeSeconds) ||
      maxAgeSeconds < 1 || maxAgeSeconds > 600) {
    throw new DeployError(500, 'session_invalid');
  }
  return `${BOOTSTRAP_COOKIE}=${value}; Path=/; Max-Age=${maxAgeSeconds}; HttpOnly; Secure; SameSite=Lax`;
}

export function clearBootstrapCookie(): string {
  return `${BOOTSTRAP_COOKIE}=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax`;
}

export function parseCookies(header: string | null): ReadonlyMap<string, string> {
  const result = new Map<string, string>();
  for (const part of (header ?? '').split(';')) {
    const separator = part.indexOf('=');
    if (separator <= 0) continue;
    const name = part.slice(0, separator).trim();
    const value = part.slice(separator + 1).trim();
    if (name !== '' && !result.has(name)) result.set(name, value);
  }
  return result;
}

export function readSessionId(request: Request): string | null {
  const value = parseCookies(request.headers.get('cookie')).get(SESSION_COOKIE) ?? null;
  if (value === null) return null;
  if (!SESSION_ID_PATTERN.test(value)) throw new DeployError(401, 'session_invalid');
  return value;
}

export function readOauthCookie(request: Request): string | null {
  const value = parseCookies(request.headers.get('cookie')).get(OAUTH_COOKIE) ?? null;
  return value && /^[A-Za-z0-9_-]{40,4096}$/u.test(value) ? value : null;
}

export function sessionCookie(value: string, maxAgeSeconds: number): string {
  return `${SESSION_COOKIE}=${value}; Path=/; Max-Age=${maxAgeSeconds}; HttpOnly; Secure; SameSite=Lax`;
}

export function oauthCookie(value: string, maxAgeSeconds: number): string {
  return `${OAUTH_COOKIE}=${value}; Path=/; Max-Age=${maxAgeSeconds}; HttpOnly; Secure; SameSite=Lax`;
}

export function clearOauthCookie(): string {
  return `${OAUTH_COOKIE}=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax`;
}

export function clearSessionCookie(): string {
  return `${SESSION_COOKIE}=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax`;
}

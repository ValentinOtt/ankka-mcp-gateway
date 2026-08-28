import { CLOUDFLARE_API_ORIGIN } from './constants';
import { sha256Hex } from './crypto';
import { DeployError, isDeployErrorCode, type DeployErrorCode } from './errors';
import { readBoundedText, withDeadline } from './http';
import type { FetchTransport } from './oauth';
import type { StoredOauthAttempt } from './session';

const ACCOUNT_ID = /^[a-f0-9]{32}$/u;
const TARGET_ID_HASH = /^sha256:[a-f0-9]{64}$/u;

export interface DiscoveredCloudflareTarget {
  targetIdHash: string;
  account: { id: string; name: string };
  zone: { id: string; name: string; status: 'active' };
}

export interface CloudflareDiscoveryResult {
  actor: { id: string; email: string };
  targets: readonly DiscoveredCloudflareTarget[];
}

export interface StoredCloudflareDiscovery {
  schemaVersion: 1;
  status: 'authorizing' | 'ready' | 'failed';
  updatedAt: number;
  expiresAt: number;
  oauthAttempt: StoredOauthAttempt;
  result: CloudflareDiscoveryResult | null;
  selectedTargetIdHash: string | null;
  failureCode: DeployErrorCode | null;
  grantRevocation: 'confirmed' | 'unconfirmed' | null;
}

export interface PublicCloudflareDiscovery {
  schemaVersion: 1;
  status: 'not_started' | 'authorizing' | 'ready' | 'failed';
  actorEmail: string | null;
  targets: readonly {
    targetIdHash: string;
    accountName: string;
    zoneName: string;
  }[];
  selectedTargetIdHash: string | null;
  failureCode: DeployErrorCode | null;
  grantRevocation: 'confirmed' | 'unconfirmed' | null;
  updatedAt: string | null;
}

function record(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
}

function exact(value: Record<string, unknown>, keys: readonly string[]): boolean {
  return Object.keys(value).sort().join(',') === [...keys].sort().join(',');
}

function validName(value: unknown): value is string {
  return typeof value === 'string' && value.length >= 1 && value.length <= 256 &&
    !/[\u0000-\u001f\u007f]/u.test(value);
}

function validEmail(value: unknown): value is string {
  return typeof value === 'string' && value.length <= 254 &&
    /^[^\s@]{1,64}@[A-Za-z0-9.-]{1,190}$/u.test(value);
}

function validAttempt(value: unknown): value is StoredOauthAttempt {
  if (!record(value) || !exact(value, ['attemptId', 'stateHash', 'verifierHash', 'expiresAt', 'usedAt'])) return false;
  return typeof value.attemptId === 'string' && /^att_[A-Za-z0-9_-]{32}$/u.test(value.attemptId) &&
    typeof value.stateHash === 'string' && /^[A-Za-z0-9_-]{43}$/u.test(value.stateHash) &&
    typeof value.verifierHash === 'string' && /^[A-Za-z0-9_-]{43}$/u.test(value.verifierHash) &&
    typeof value.expiresAt === 'number' && Number.isSafeInteger(value.expiresAt) &&
    (value.usedAt === null || (typeof value.usedAt === 'number' && Number.isSafeInteger(value.usedAt)));
}

export function requireStoredCloudflareDiscovery(value: unknown): StoredCloudflareDiscovery {
  if (!record(value) || !exact(value, [
    'schemaVersion', 'status', 'updatedAt', 'expiresAt', 'oauthAttempt', 'result',
    'selectedTargetIdHash', 'failureCode', 'grantRevocation',
  ]) || value.schemaVersion !== 1 ||
    (value.status !== 'authorizing' && value.status !== 'ready' && value.status !== 'failed') ||
    typeof value.updatedAt !== 'number' || !Number.isSafeInteger(value.updatedAt) ||
    typeof value.expiresAt !== 'number' || !Number.isSafeInteger(value.expiresAt) ||
    value.updatedAt > value.expiresAt || !validAttempt(value.oauthAttempt) ||
    (value.selectedTargetIdHash !== null &&
      (typeof value.selectedTargetIdHash !== 'string' || !TARGET_ID_HASH.test(value.selectedTargetIdHash))) ||
    (value.failureCode !== null && !isDeployErrorCode(value.failureCode)) ||
    (value.grantRevocation !== null && value.grantRevocation !== 'confirmed' && value.grantRevocation !== 'unconfirmed')) {
    throw new DeployError(500, 'session_invalid');
  }
  let resultTargets: readonly unknown[] = [];
  if (value.result !== null) {
    if (!record(value.result) || !exact(value.result, ['actor', 'targets']) ||
      !record(value.result.actor) || !exact(value.result.actor, ['id', 'email']) ||
      !validName(value.result.actor.id) || !validEmail(value.result.actor.email) ||
      !Array.isArray(value.result.targets) || value.result.targets.length > 1000) {
      throw new DeployError(500, 'session_invalid');
    }
    resultTargets = value.result.targets;
    for (const target of resultTargets) {
      if (!record(target) || !exact(target, ['targetIdHash', 'account', 'zone']) ||
        typeof target.targetIdHash !== 'string' || !TARGET_ID_HASH.test(target.targetIdHash) ||
        !record(target.account) || !exact(target.account, ['id', 'name']) ||
        typeof target.account.id !== 'string' || !ACCOUNT_ID.test(target.account.id) || !validName(target.account.name) ||
        !record(target.zone) || !exact(target.zone, ['id', 'name', 'status']) ||
        typeof target.zone.id !== 'string' || !ACCOUNT_ID.test(target.zone.id) ||
        !validName(target.zone.name) || target.zone.status !== 'active') {
        throw new DeployError(500, 'session_invalid');
      }
    }
  }
  if ((value.status === 'ready') !== (value.result !== null) ||
    (value.status === 'failed') !== (value.failureCode !== null) ||
    (value.selectedTargetIdHash !== null && !resultTargets.some(
      (target) => record(target) && target.targetIdHash === value.selectedTargetIdHash,
    ))) {
    throw new DeployError(500, 'session_invalid');
  }
  return value as unknown as StoredCloudflareDiscovery;
}

export function publicCloudflareDiscovery(
  discovery: StoredCloudflareDiscovery | null,
): PublicCloudflareDiscovery {
  if (!discovery) return Object.freeze({
    schemaVersion: 1,
    status: 'not_started',
    actorEmail: null,
    targets: Object.freeze([]),
    selectedTargetIdHash: null,
    failureCode: null,
    grantRevocation: null,
    updatedAt: null,
  });
  return Object.freeze({
    schemaVersion: 1,
    status: discovery.status,
    actorEmail: discovery.result?.actor.email ?? null,
    targets: Object.freeze((discovery.result?.targets ?? []).map((target) => Object.freeze({
      targetIdHash: target.targetIdHash,
      accountName: target.account.name,
      zoneName: target.zone.name,
    }))),
    selectedTargetIdHash: discovery.selectedTargetIdHash,
    failureCode: discovery.failureCode,
    grantRevocation: discovery.grantRevocation,
    updatedAt: new Date(discovery.updatedAt).toISOString(),
  });
}

async function api(
  transport: FetchTransport,
  accessToken: string,
  url: URL,
): Promise<unknown> {
  return withDeadline(async (signal) => {
    const response = await transport(url, {
      headers: { authorization: `Bearer ${accessToken}`, accept: 'application/json' },
      signal,
    });
    if (!response.ok) throw new DeployError(403, 'oauth_grant_invalid');
    let body: unknown;
    try {
      body = JSON.parse(await readBoundedText(response, 'oauth_grant_invalid'));
    } catch (error) {
      if (error instanceof DeployError) throw error;
      throw new DeployError(502, 'oauth_grant_invalid');
    }
    if (!record(body) || body.success !== true || !Object.hasOwn(body, 'result')) {
      throw new DeployError(403, 'oauth_grant_invalid');
    }
    return body.result;
  }, 'oauth_grant_invalid');
}

export async function discoverCloudflareTargets(input: {
  accessToken: string;
  transport: FetchTransport;
}): Promise<CloudflareDiscoveryResult> {
  const user = await api(
    input.transport,
    input.accessToken,
    new URL('/client/v4/user', CLOUDFLARE_API_ORIGIN),
  );
  if (!record(user) || !validName(user.id) || !validEmail(user.email)) {
    throw new DeployError(403, 'oauth_grant_invalid');
  }
  const accountsUrl = new URL('/client/v4/accounts', CLOUDFLARE_API_ORIGIN);
  accountsUrl.searchParams.set('per_page', '50');
  const accounts = await api(input.transport, input.accessToken, accountsUrl);
  if (!Array.isArray(accounts) || accounts.length > 50) {
    throw new DeployError(502, 'target_account_ambiguous');
  }
  const targets: DiscoveredCloudflareTarget[] = [];
  for (const account of accounts) {
    if (!record(account) || typeof account.id !== 'string' || !ACCOUNT_ID.test(account.id) || !validName(account.name)) {
      throw new DeployError(502, 'target_account_ambiguous');
    }
    const zonesUrl = new URL('/client/v4/zones', CLOUDFLARE_API_ORIGIN);
    zonesUrl.searchParams.set('account.id', account.id);
    zonesUrl.searchParams.set('status', 'active');
    zonesUrl.searchParams.set('per_page', '50');
    const zones = await api(input.transport, input.accessToken, zonesUrl);
    if (!Array.isArray(zones) || zones.length > 50) throw new DeployError(502, 'target_zone_invalid');
    for (const zone of zones) {
      if (!record(zone) || typeof zone.id !== 'string' || !ACCOUNT_ID.test(zone.id) ||
        !validName(zone.name) || zone.status !== 'active' || !record(zone.account) || zone.account.id !== account.id) {
        throw new DeployError(502, 'target_zone_invalid');
      }
      const targetIdHash = `sha256:${await sha256Hex(
        `ankka-cloudflare-target-v1\n${account.id}\n${zone.id}`,
      )}`;
      targets.push({
        targetIdHash,
        account: { id: account.id, name: account.name },
        zone: { id: zone.id, name: zone.name, status: 'active' },
      });
    }
  }
  targets.sort((left, right) => left.zone.name.localeCompare(right.zone.name) ||
    left.account.name.localeCompare(right.account.name));
  return Object.freeze({
    actor: Object.freeze({ id: user.id, email: user.email.toLowerCase() }),
    targets: Object.freeze(targets.map((target) => Object.freeze({
      targetIdHash: target.targetIdHash,
      account: Object.freeze(target.account),
      zone: Object.freeze(target.zone),
    }))),
  });
}

export function selectedDiscoveredTarget(
  discovery: StoredCloudflareDiscovery | null,
): DiscoveredCloudflareTarget | null {
  if (!discovery?.result || !discovery.selectedTargetIdHash) return null;
  return discovery.result.targets.find(
    (target) => target.targetIdHash === discovery.selectedTargetIdHash,
  ) ?? null;
}

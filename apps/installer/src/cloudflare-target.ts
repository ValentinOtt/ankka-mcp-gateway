import { CLOUDFLARE_API_ORIGIN } from './constants';
import { DeployError } from './errors';
import type { FetchTransport } from './oauth';
import { readBoundedText, withDeadline } from './http';

export interface AuthorizedTarget {
  actor: { id: string; email: string };
  account: { id: string; name: string };
  zone: { id: string; name: string; status: 'active' };
}

export interface AuthorizedAccount {
  actor: { id: string; email: string };
  account: { id: string; name: string };
}

async function readApiEnvelope(
  response: Response,
  errorCode: 'oauth_grant_invalid' | 'target_account_ambiguous' | 'target_zone_invalid',
): Promise<unknown> {
  if (!response.ok) throw new DeployError(403, errorCode);
  let body: unknown;
  try {
    const text = await readBoundedText(response, errorCode);
    body = JSON.parse(text);
  } catch (error) {
    if (error instanceof DeployError) throw error;
    throw new DeployError(502, errorCode);
  }
  if (!body || typeof body !== 'object' || Array.isArray(body)) throw new DeployError(502, errorCode);
  const envelope = body as Record<string, unknown>;
  if (envelope.success !== true || !Object.hasOwn(envelope, 'result')) {
    throw new DeployError(403, errorCode);
  }
  return envelope.result;
}

function bearerHeaders(accessToken: string): HeadersInit {
  return { authorization: `Bearer ${accessToken}`, accept: 'application/json' };
}

async function cloudflareApi(
  transport: FetchTransport,
  url: URL,
  accessToken: string,
  errorCode: 'oauth_grant_invalid' | 'target_account_ambiguous' | 'target_zone_invalid',
): Promise<unknown> {
  return withDeadline(async (signal) => {
    const response = await transport(url, { headers: bearerHeaders(accessToken), signal });
    return readApiEnvelope(response, errorCode);
  }, errorCode);
}

export async function resolveAuthorizedTarget(input: {
  accessToken: string;
  typedZoneName: string;
  expectedAdminEmail: string;
  expectedAccountId?: string;
  expectedZoneId?: string;
  transport: FetchTransport;
}): Promise<AuthorizedTarget> {
  const userUrl = new URL('/client/v4/user', CLOUDFLARE_API_ORIGIN);
  const actor = await cloudflareApi(input.transport, userUrl, input.accessToken, 'oauth_grant_invalid');
  if (!actor || typeof actor !== 'object' || Array.isArray(actor)) {
    throw new DeployError(403, 'oauth_grant_invalid');
  }
  const actorRecord = actor as Record<string, unknown>;
  if (
    typeof actorRecord.id !== 'string' || actorRecord.id.length < 8 || actorRecord.id.length > 128 ||
    typeof actorRecord.email !== 'string' || actorRecord.email.toLowerCase() !== input.expectedAdminEmail
  ) {
    throw new DeployError(403, 'oauth_grant_invalid');
  }
  const accountsUrl = new URL('/client/v4/accounts', CLOUDFLARE_API_ORIGIN);
  accountsUrl.searchParams.set('per_page', input.expectedAccountId ? '50' : '2');
  const accountResult = await cloudflareApi(
    input.transport,
    accountsUrl,
    input.accessToken,
    'target_account_ambiguous',
  );
  if (!Array.isArray(accountResult)) throw new DeployError(502, 'target_account_ambiguous');
  const accounts = accountResult;
  const matchingAccounts = input.expectedAccountId
    ? accounts.filter((candidate) => candidate && typeof candidate === 'object' && !Array.isArray(candidate) &&
      (candidate as Record<string, unknown>).id === input.expectedAccountId)
    : accounts;
  if (matchingAccounts.length !== 1) throw new DeployError(409, 'target_account_ambiguous');
  const account = matchingAccounts[0];
  if (!account || typeof account !== 'object' || Array.isArray(account)) {
    throw new DeployError(502, 'target_account_ambiguous');
  }
  const accountRecord = account as Record<string, unknown>;
  if (
    typeof accountRecord.id !== 'string' || !/^[a-f0-9]{32}$/u.test(accountRecord.id) ||
    (input.expectedAccountId !== undefined && accountRecord.id !== input.expectedAccountId) ||
    typeof accountRecord.name !== 'string' || accountRecord.name.length < 1 || accountRecord.name.length > 256
  ) {
    throw new DeployError(502, 'target_account_ambiguous');
  }

  const zonesUrl = new URL('/client/v4/zones', CLOUDFLARE_API_ORIGIN);
  zonesUrl.searchParams.set('name', input.typedZoneName);
  zonesUrl.searchParams.set('account.id', accountRecord.id);
  zonesUrl.searchParams.set('status', 'active');
  zonesUrl.searchParams.set('per_page', '2');
  const zoneResult = await cloudflareApi(
    input.transport,
    zonesUrl,
    input.accessToken,
    'target_zone_invalid',
  );
  if (!Array.isArray(zoneResult)) throw new DeployError(502, 'target_zone_invalid');
  const zones = zoneResult;
  if (zones.length !== 1) throw new DeployError(409, 'target_zone_invalid');
  const zone = zones[0];
  if (!zone || typeof zone !== 'object' || Array.isArray(zone)) {
    throw new DeployError(502, 'target_zone_invalid');
  }
  const zoneRecord = zone as Record<string, unknown>;
  if (
    typeof zoneRecord.id !== 'string' || !/^[a-f0-9]{32}$/u.test(zoneRecord.id) ||
    (input.expectedZoneId !== undefined && zoneRecord.id !== input.expectedZoneId) ||
    zoneRecord.name !== input.typedZoneName ||
    zoneRecord.status !== 'active' ||
    !zoneRecord.account || typeof zoneRecord.account !== 'object' || Array.isArray(zoneRecord.account) ||
    (zoneRecord.account as Record<string, unknown>).id !== accountRecord.id
  ) {
    throw new DeployError(409, 'target_zone_invalid');
  }
  return {
    actor: { id: actorRecord.id, email: input.expectedAdminEmail },
    account: { id: accountRecord.id, name: accountRecord.name },
    zone: { id: zoneRecord.id, name: input.typedZoneName, status: 'active' },
  };
}

export async function resolveAuthorizedAccount(input: {
  accessToken: string;
  expectedActorEmail: string;
  expectedAccountId: string;
  transport: FetchTransport;
}): Promise<AuthorizedAccount> {
  if (!/^[a-f0-9]{32}$/u.test(input.expectedAccountId) ||
      input.expectedActorEmail !== input.expectedActorEmail.toLowerCase()) {
    throw new DeployError(403, 'oauth_grant_invalid');
  }
  const userUrl = new URL('/client/v4/user', CLOUDFLARE_API_ORIGIN);
  const actor = await cloudflareApi(input.transport, userUrl, input.accessToken, 'oauth_grant_invalid');
  if (!actor || typeof actor !== 'object' || Array.isArray(actor)) {
    throw new DeployError(403, 'oauth_grant_invalid');
  }
  const actorRecord = actor as Record<string, unknown>;
  if (typeof actorRecord.id !== 'string' || actorRecord.id.length < 8 || actorRecord.id.length > 128 ||
      typeof actorRecord.email !== 'string' || actorRecord.email.toLowerCase() !== input.expectedActorEmail) {
    throw new DeployError(403, 'oauth_grant_invalid');
  }
  const accountsUrl = new URL('/client/v4/accounts', CLOUDFLARE_API_ORIGIN);
  accountsUrl.searchParams.set('per_page', '50');
  const result = await cloudflareApi(
    input.transport,
    accountsUrl,
    input.accessToken,
    'target_account_ambiguous',
  );
  if (!Array.isArray(result)) throw new DeployError(502, 'target_account_ambiguous');
  const matches = result.filter((candidate) => candidate && typeof candidate === 'object' &&
    !Array.isArray(candidate) && (candidate as Record<string, unknown>).id === input.expectedAccountId);
  if (matches.length !== 1) throw new DeployError(409, 'target_account_ambiguous');
  const account = matches[0] as Record<string, unknown>;
  if (typeof account.name !== 'string' || account.name.length < 1 || account.name.length > 256) {
    throw new DeployError(502, 'target_account_ambiguous');
  }
  return Object.freeze({
    actor: Object.freeze({ id: actorRecord.id, email: input.expectedActorEmail }),
    account: Object.freeze({ id: input.expectedAccountId, name: account.name }),
  });
}

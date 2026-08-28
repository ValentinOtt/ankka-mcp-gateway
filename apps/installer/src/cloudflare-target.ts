import * as v from 'valibot';

import { boundaryValueSchema, type BoundaryValue } from './boundary';
import { CLOUDFLARE_API_ORIGIN } from './constants';
import { DeployError } from './errors';
import type { FetchTransport } from './oauth';
import { readBoundedText, withDeadline } from './http';

type TargetResolutionErrorCode =
  | 'oauth_grant_invalid'
  | 'target_account_ambiguous'
  | 'target_zone_invalid';

const apiEnvelopeSchema = v.looseObject({
  result: boundaryValueSchema,
  success: v.literal(true),
});
const actorSchema = v.looseObject({ email: v.string(), id: v.string() });
const accountSchema = v.looseObject({ id: v.string(), name: v.string() });
const zoneSchema = v.looseObject({
  account: v.looseObject({ id: v.string() }),
  id: v.string(),
  name: v.string(),
  status: v.literal('active'),
});

export interface AuthorizedTarget {
  actor: { id: string; email: string };
  account: { id: string; name: string };
  zone: { id: string; name: string; status: 'active' };
}

export interface AuthorizedAccount {
  actor: { id: string; email: string };
  account: { id: string; name: string };
}

export interface AuthorizedTargetResolutionInput {
  accessToken: string;
  typedZoneName: string;
  expectedAdminEmail: string;
  expectedAccountId?: string;
  expectedZoneId?: string;
  transport: FetchTransport;
}

async function readApiEnvelope(
  response: Response,
  errorCode: TargetResolutionErrorCode,
): Promise<BoundaryValue> {
  if (!response.ok) throw new DeployError(403, errorCode);
  let body: BoundaryValue;
  try {
    const text = await readBoundedText(response, errorCode);
    const result = v.safeParse(boundaryValueSchema, JSON.parse(text));
    if (!result.success) throw new DeployError(502, errorCode);
    body = result.output;
  } catch (error) {
    if (error instanceof DeployError) throw error;
    throw new DeployError(502, errorCode);
  }
  const envelope = v.safeParse(apiEnvelopeSchema, body);
  if (!envelope.success) {
    throw new DeployError(403, errorCode);
  }
  return envelope.output.result;
}

function bearerHeaders(accessToken: string): HeadersInit {
  return { authorization: `Bearer ${accessToken}`, accept: 'application/json' };
}

async function cloudflareApi(
  transport: FetchTransport,
  url: URL,
  accessToken: string,
  errorCode: TargetResolutionErrorCode,
): Promise<BoundaryValue> {
  return withDeadline(async (signal) => {
    const response = await transport(url, { headers: bearerHeaders(accessToken), signal });
    return readApiEnvelope(response, errorCode);
  }, errorCode);
}

export async function resolveAuthorizedTarget(
  input: AuthorizedTargetResolutionInput,
): Promise<AuthorizedTarget> {
  const userUrl = new URL('/client/v4/user', CLOUDFLARE_API_ORIGIN);
  const actor = v.safeParse(
    actorSchema,
    await cloudflareApi(input.transport, userUrl, input.accessToken, 'oauth_grant_invalid'),
  );
  if (
    !actor.success || actor.output.id.length < 8 || actor.output.id.length > 128 ||
    actor.output.email.toLowerCase() !== input.expectedAdminEmail
  ) {
    throw new DeployError(403, 'oauth_grant_invalid');
  }
  const accountsUrl = new URL('/client/v4/accounts', CLOUDFLARE_API_ORIGIN);
  accountsUrl.searchParams.set('per_page', input.expectedAccountId ? '50' : '2');
  const accountResult = v.safeParse(v.array(accountSchema), await cloudflareApi(
    input.transport,
    accountsUrl,
    input.accessToken,
    'target_account_ambiguous',
  ));
  if (!accountResult.success) throw new DeployError(502, 'target_account_ambiguous');
  const accounts = accountResult.output;
  const matchingAccounts = input.expectedAccountId
    ? accounts.filter((candidate) => candidate.id === input.expectedAccountId)
    : accounts;
  if (matchingAccounts.length !== 1) throw new DeployError(409, 'target_account_ambiguous');
  const account = matchingAccounts.at(0);
  if (account === undefined) throw new DeployError(409, 'target_account_ambiguous');
  if (
    !/^[a-f0-9]{32}$/u.test(account.id) ||
    (input.expectedAccountId !== undefined && account.id !== input.expectedAccountId) ||
    account.name.length < 1 || account.name.length > 256
  ) {
    throw new DeployError(502, 'target_account_ambiguous');
  }

  const zonesUrl = new URL('/client/v4/zones', CLOUDFLARE_API_ORIGIN);
  zonesUrl.searchParams.set('name', input.typedZoneName);
  zonesUrl.searchParams.set('account.id', account.id);
  zonesUrl.searchParams.set('status', 'active');
  zonesUrl.searchParams.set('per_page', '2');
  const zoneResult = v.safeParse(v.array(zoneSchema), await cloudflareApi(
    input.transport,
    zonesUrl,
    input.accessToken,
    'target_zone_invalid',
  ));
  if (!zoneResult.success) throw new DeployError(502, 'target_zone_invalid');
  const zones = zoneResult.output;
  if (zones.length !== 1) throw new DeployError(409, 'target_zone_invalid');
  const zone = zones.at(0);
  if (zone === undefined) throw new DeployError(409, 'target_zone_invalid');
  if (
    !/^[a-f0-9]{32}$/u.test(zone.id) ||
    (input.expectedZoneId !== undefined && zone.id !== input.expectedZoneId) ||
    zone.name !== input.typedZoneName || zone.account.id !== account.id
  ) {
    throw new DeployError(409, 'target_zone_invalid');
  }
  return {
    actor: { id: actor.output.id, email: input.expectedAdminEmail },
    account: { id: account.id, name: account.name },
    zone: { id: zone.id, name: input.typedZoneName, status: 'active' },
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
  const actor = v.safeParse(
    actorSchema,
    await cloudflareApi(input.transport, userUrl, input.accessToken, 'oauth_grant_invalid'),
  );
  if (!actor.success || actor.output.id.length < 8 || actor.output.id.length > 128 ||
      actor.output.email.toLowerCase() !== input.expectedActorEmail) {
    throw new DeployError(403, 'oauth_grant_invalid');
  }
  const accountsUrl = new URL('/client/v4/accounts', CLOUDFLARE_API_ORIGIN);
  accountsUrl.searchParams.set('per_page', '50');
  const result = v.safeParse(v.array(accountSchema), await cloudflareApi(
    input.transport,
    accountsUrl,
    input.accessToken,
    'target_account_ambiguous',
  ));
  if (!result.success) throw new DeployError(502, 'target_account_ambiguous');
  const matches = result.output.filter((candidate) => candidate.id === input.expectedAccountId);
  if (matches.length !== 1) throw new DeployError(409, 'target_account_ambiguous');
  const account = matches.at(0);
  if (account === undefined) throw new DeployError(409, 'target_account_ambiguous');
  if (account.name.length < 1 || account.name.length > 256) {
    throw new DeployError(502, 'target_account_ambiguous');
  }
  return Object.freeze({
    actor: Object.freeze({ id: actor.output.id, email: input.expectedActorEmail }),
    account: Object.freeze({ id: input.expectedAccountId, name: account.name }),
  });
}

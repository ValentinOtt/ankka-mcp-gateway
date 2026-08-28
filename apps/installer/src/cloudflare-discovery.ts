import * as v from 'valibot';

import {
  boundaryValueSchema,
  type BoundaryValue,
} from './boundary';
import { CLOUDFLARE_API_ORIGIN } from './constants';
import { sha256Hex } from './crypto';
import { DeployError, isDeployErrorCode, type DeployErrorCode } from './errors';
import { readBoundedText, withDeadline } from './http';
import type { FetchTransport } from './oauth';
import type { StoredOauthAttempt } from './session';

const ACCOUNT_ID = /^[a-f0-9]{32}$/u;
const TARGET_ID_HASH = /^sha256:[a-f0-9]{64}$/u;
const safeIntegerSchema = v.pipe(v.number(), v.safeInteger());
const oauthAttemptSchema = v.strictObject({
  attemptId: v.string(),
  expiresAt: safeIntegerSchema,
  stateHash: v.string(),
  usedAt: v.nullable(safeIntegerSchema),
  verifierHash: v.string(),
});
const discoveredTargetSchema = v.strictObject({
  account: v.strictObject({ id: v.string(), name: v.string() }),
  targetIdHash: v.string(),
  zone: v.strictObject({ id: v.string(), name: v.string(), status: v.literal('active') }),
});
const discoveryResultSchema = v.strictObject({
  actor: v.strictObject({ email: v.string(), id: v.string() }),
  targets: v.array(discoveredTargetSchema),
});
const storedDiscoverySchema = v.strictObject({
  expiresAt: safeIntegerSchema,
  failureCode: v.nullable(v.string()),
  grantRevocation: v.nullable(v.picklist(['confirmed', 'unconfirmed'])),
  oauthAttempt: oauthAttemptSchema,
  result: v.nullable(discoveryResultSchema),
  schemaVersion: v.literal(1),
  selectedTargetIdHash: v.nullable(v.string()),
  status: v.picklist(['authorizing', 'ready', 'failed']),
  updatedAt: safeIntegerSchema,
});
const providerResponseSchema = v.looseObject({
  result: boundaryValueSchema,
  success: v.literal(true),
});
const providerUserSchema = v.looseObject({ email: v.string(), id: v.string() });
const providerAccountSchema = v.looseObject({ id: v.string(), name: v.string() });
const providerZoneSchema = v.looseObject({
  account: v.looseObject({ id: v.string() }),
  id: v.string(),
  name: v.string(),
  status: v.literal('active'),
});

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

function validName(value: string): boolean {
  return value.length >= 1 && value.length <= 256 &&
    !Array.from(value).some((character) => {
      const code = character.charCodeAt(0);
      return code <= 31 || code === 127;
    });
}

function validEmail(value: string): boolean {
  return value.length <= 254 &&
    /^[^\s@]{1,64}@[A-Za-z0-9.-]{1,190}$/u.test(value);
}

function validAttempt(value: v.InferOutput<typeof oauthAttemptSchema>): boolean {
  return /^att_[A-Za-z0-9_-]{32}$/u.test(value.attemptId) &&
    /^[A-Za-z0-9_-]{43}$/u.test(value.stateHash) &&
    /^[A-Za-z0-9_-]{43}$/u.test(value.verifierHash);
}

export function requireStoredCloudflareDiscovery<Input>(value: Input): StoredCloudflareDiscovery {
  const result = v.safeParse(storedDiscoverySchema, value);
  if (!result.success) throw new DeployError(500, 'session_invalid');
  const input = result.output;
  const failureCode = input.failureCode;
  if (input.updatedAt > input.expiresAt || !validAttempt(input.oauthAttempt) ||
    (input.selectedTargetIdHash !== null && !TARGET_ID_HASH.test(input.selectedTargetIdHash)) ||
    (failureCode !== null && !isDeployErrorCode(failureCode))) {
    throw new DeployError(500, 'session_invalid');
  }
  const resultTargets = input.result?.targets ?? Object.freeze([]);
  if (input.result !== null) {
    if (!validName(input.result.actor.id) || !validEmail(input.result.actor.email) ||
      input.result.targets.length > 1000) {
      throw new DeployError(500, 'session_invalid');
    }
    for (const target of resultTargets) {
      if (!TARGET_ID_HASH.test(target.targetIdHash) ||
        !ACCOUNT_ID.test(target.account.id) || !validName(target.account.name) ||
        !ACCOUNT_ID.test(target.zone.id) ||
        !validName(target.zone.name) || target.zone.status !== 'active') {
        throw new DeployError(500, 'session_invalid');
      }
    }
  }
  if ((input.status === 'ready') !== (input.result !== null) ||
    (input.status === 'failed') !== (input.failureCode !== null) ||
    (input.selectedTargetIdHash !== null && !resultTargets.some(
      (target) => target.targetIdHash === input.selectedTargetIdHash,
    ))) {
    throw new DeployError(500, 'session_invalid');
  }
  return Object.freeze({
    schemaVersion: 1,
    status: input.status,
    updatedAt: input.updatedAt,
    expiresAt: input.expiresAt,
    oauthAttempt: Object.freeze({ ...input.oauthAttempt }),
    result: input.result === null ? null : Object.freeze({
      actor: Object.freeze({ ...input.result.actor }),
      targets: Object.freeze(input.result.targets.map((target) => Object.freeze({
        targetIdHash: target.targetIdHash,
        account: Object.freeze({ ...target.account }),
        zone: Object.freeze({ ...target.zone }),
      }))),
    }),
    selectedTargetIdHash: input.selectedTargetIdHash,
    failureCode,
    grantRevocation: input.grantRevocation,
  });
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
): Promise<BoundaryValue> {
  return withDeadline(async (signal) => {
    const response = await transport(url, {
      headers: { authorization: `Bearer ${accessToken}`, accept: 'application/json' },
      signal,
    });
    if (!response.ok) throw new DeployError(403, 'oauth_grant_invalid');
    let body: BoundaryValue;
    try {
      const result = v.safeParse(
        boundaryValueSchema,
        JSON.parse(await readBoundedText(response, 'oauth_grant_invalid')),
      );
      if (!result.success) throw new DeployError(502, 'oauth_grant_invalid');
      body = result.output;
    } catch (error) {
      if (error instanceof DeployError) throw error;
      throw new DeployError(502, 'oauth_grant_invalid');
    }
    const result = v.safeParse(providerResponseSchema, body);
    if (!result.success) {
      throw new DeployError(403, 'oauth_grant_invalid');
    }
    return result.output.result;
  }, 'oauth_grant_invalid');
}

export async function discoverCloudflareTargets(input: {
  accessToken: string;
  transport: FetchTransport;
}): Promise<CloudflareDiscoveryResult> {
  const userResult = v.safeParse(providerUserSchema, await api(
    input.transport,
    input.accessToken,
    new URL('/client/v4/user', CLOUDFLARE_API_ORIGIN),
  ));
  if (!userResult.success || !validName(userResult.output.id) || !validEmail(userResult.output.email)) {
    throw new DeployError(403, 'oauth_grant_invalid');
  }
  const user = userResult.output;
  const accountsUrl = new URL('/client/v4/accounts', CLOUDFLARE_API_ORIGIN);
  accountsUrl.searchParams.set('per_page', '50');
  const accountsResult = v.safeParse(
    v.array(providerAccountSchema),
    await api(input.transport, input.accessToken, accountsUrl),
  );
  if (!accountsResult.success || accountsResult.output.length > 50) {
    throw new DeployError(502, 'target_account_ambiguous');
  }
  const accounts = accountsResult.output;
  const targets: DiscoveredCloudflareTarget[] = [];
  for (const account of accounts) {
    if (!ACCOUNT_ID.test(account.id) || !validName(account.name)) {
      throw new DeployError(502, 'target_account_ambiguous');
    }
    const zonesUrl = new URL('/client/v4/zones', CLOUDFLARE_API_ORIGIN);
    zonesUrl.searchParams.set('account.id', account.id);
    zonesUrl.searchParams.set('status', 'active');
    zonesUrl.searchParams.set('per_page', '50');
    const zonesResult = v.safeParse(
      v.array(providerZoneSchema),
      await api(input.transport, input.accessToken, zonesUrl),
    );
    if (!zonesResult.success || zonesResult.output.length > 50) {
      throw new DeployError(502, 'target_zone_invalid');
    }
    const zones = zonesResult.output;
    for (const zone of zones) {
      if (!ACCOUNT_ID.test(zone.id) || !validName(zone.name) || zone.account.id !== account.id) {
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

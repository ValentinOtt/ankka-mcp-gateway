import * as v from 'valibot';

import { CLOUDFLARE_API_ORIGIN } from './constants';
import { DeployError } from './errors';
import { fetchBoundedText } from './http';
import type { FetchTransport } from './oauth';

const label = v.pipe(v.string(), v.regex(/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/u));
const id = v.pipe(v.string(), v.regex(/^[a-f0-9]{32}$/u));
export const setupZoneSchema = v.strictObject({
  id,
  name: v.pipe(v.string(), v.maxLength(253), v.regex(/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/u)),
});
export const setupZonesSchema = v.pipe(v.array(setupZoneSchema), v.maxLength(100));
export type SetupZone = v.InferOutput<typeof setupZoneSchema>;
const envelope = v.object({
  success: v.boolean(),
  errors: v.array(v.object({ code: v.number() })),
  result: v.unknown(),
  result_info: v.optional(v.object({ total_pages: v.optional(v.pipe(v.number(), v.safeInteger(), v.minValue(0))) })),
});
interface Call {
  readonly accessToken: string;
  readonly accountId: string;
  readonly transport: FetchTransport;
}

async function request(call: Call, path: string, subdomain?: string) {
  if (!v.is(id, call.accountId)) throw new DeployError(400, 'session_invalid');
  const init: RequestInit = {
    method: subdomain === undefined ? 'GET' : 'PUT',
    headers: { authorization: `Bearer ${call.accessToken}`, 'content-type': 'application/json' },
    redirect: 'manual',
  };
  if (subdomain !== undefined) init.body = JSON.stringify({ subdomain });
  const read = await fetchBoundedText(call.transport, new URL(`/client/v4${path}`, CLOUDFLARE_API_ORIGIN), init, 'oauth_exchange_failed', { maxBytes: 512 * 1024 });
  let value: unknown;
  try { value = JSON.parse(read.text); } catch { throw new DeployError(502, 'oauth_exchange_failed', 'account_setup_invalid_response'); }
  const parsed = v.safeParse(envelope, value);
  if (!parsed.success) throw new DeployError(502, 'oauth_exchange_failed', 'account_setup_invalid_response');
  return { status: read.response.status, ok: read.response.ok, ...parsed.output };
}

/** Returns display choices only. Stage 2 revalidates the selected zone with its fresh grant. */
export async function discoverHostedAccountZones(call: Call): Promise<readonly SetupZone[]> {
  const zones: SetupZone[] = [];
  const pageSchema = v.pipe(v.array(v.object({ id, name: setupZoneSchema.entries.name, status: v.string(), account: v.object({ id }) })), v.maxLength(50));
  // A third empty page can prove completion when pagination metadata is absent.
  for (let page = 1; page <= 3; page += 1) {
    const result = await request(call, `/zones?account.id=${call.accountId}&status=active&per_page=50&page=${page}`);
    const parsed = v.safeParse(pageSchema, result.result);
    if (!result.ok || !result.success || result.errors.length !== 0 || !parsed.success) {
      throw new DeployError(502, 'oauth_exchange_failed', 'zone_discovery_rejected');
    }
    for (const zone of parsed.output) {
      if (zone.account.id !== call.accountId || zone.status !== 'active' || zones.some((other) => other.id === zone.id || other.name === zone.name)) {
        throw new DeployError(502, 'oauth_exchange_failed', 'zone_discovery_mismatch');
      }
      zones.push({ id: zone.id, name: zone.name });
    }
    const pages = result.result_info?.total_pages;
    if (zones.length > 100 || (pages !== undefined && pages > 2)) {
      throw new DeployError(502, 'oauth_exchange_failed', 'zone_discovery_limit');
    }
    if (pages !== undefined && ((pages === 0 && zones.length !== 0) || (pages > page && parsed.output.length === 0))) {
      throw new DeployError(502, 'oauth_exchange_failed', 'zone_discovery_mismatch');
    }
    if (pages === undefined ? parsed.output.length < 50 : page >= pages) {
      return Object.freeze(zones.sort((a, b) => a.name.localeCompare(b.name)));
    }
  }
  throw new DeployError(502, 'oauth_exchange_failed', 'zone_discovery_limit');
}

async function readSubdomain(call: Call): Promise<string | null> {
  const result = await request(call, `/accounts/${call.accountId}/workers/subdomain`);
  if (result.status === 404 && !result.success && result.errors.length === 1 && result.errors[0]?.code === 10007) return null;
  const parsed = v.safeParse(v.object({ subdomain: label }), result.result);
  if (!result.ok || !result.success || result.errors.length !== 0 || !parsed.success) {
    throw new DeployError(502, 'oauth_exchange_failed', 'account_worker_subdomain_get_rejected');
  }
  return parsed.output.subdomain;
}

/** Register only after explicit absence; existing account subdomains are never intentionally renamed or deleted. */
export async function ensureHostedWorkersSubdomain(call: Call & { readonly suggestedSubdomain: string }) {
  if (!v.is(label, call.suggestedSubdomain)) throw new DeployError(400, 'session_invalid');
  const existing = await readSubdomain(call);
  if (existing !== null) return Object.freeze({ accountId: call.accountId, subdomain: existing });
  // Another setup may have completed since discovery. Reuse its account setting.
  const latest = await readSubdomain(call);
  if (latest !== null) return Object.freeze({ accountId: call.accountId, subdomain: latest });
  const result = await request(call, `/accounts/${call.accountId}/workers/subdomain`, call.suggestedSubdomain);
  if (!result.ok || !result.success || result.errors.length !== 0) {
    throw new DeployError(502, 'oauth_exchange_failed', 'account_worker_subdomain_create_rejected');
  }
  const actual = await readSubdomain(call);
  if (actual !== call.suggestedSubdomain) throw new DeployError(502, 'oauth_exchange_failed', 'account_worker_subdomain_create_mismatch');
  return Object.freeze({ accountId: call.accountId, subdomain: actual });
}

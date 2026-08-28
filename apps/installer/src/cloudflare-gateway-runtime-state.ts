import * as v from 'valibot';

import { boundaryObjectSchema, type BoundaryObject, type BoundaryValue } from './boundary';
import type { GatewayWorkerPlainTextBindings } from './cloudflare-worker-direct-upload';

const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/u;
const WORKER_ID = /^[a-f0-9]{32}$/u;
export const GATEWAY_RUNTIME_BINDING_NAMES = Object.freeze([
  'ADMIN_EMAILS',
  'ANKKA_GATEWAY_RELEASE',
  'ANKKA_GATEWAY_RELEASE_SHA256',
  'ANKKA_MANAGEMENT_HOSTNAME',
  'ANKKA_UPDATE_CHANNEL',
  'ANKKA_UPDATE_KEY_ID',
  'ANKKA_UPDATE_PUBLIC_KEY',
  'ANKKA_WORKERS_SUBDOMAIN',
  'ANKKA_WORKER_NAME',
  'CF_ACCESS_AUD',
  'CF_ACCESS_ISSUER',
  'CLOUDFLARE_ACCOUNT_ID',
  'CLOUDFLARE_ZONE_ID',
  'CLOUDFLARE_ZONE_NAME',
  'ZERO_TRUST_READY',
] as const);

type BindingName = (typeof GATEWAY_RUNTIME_BINDING_NAMES)[number];

const activeRuntimeSchema = v.strictObject({
  deployments: v.pipe(v.array(v.looseObject({
    id: v.pipe(v.string(), v.regex(UUID)),
    versions: v.array(v.looseObject({
      percentage: v.number(),
      version_id: v.pipe(v.string(), v.regex(UUID)),
    })),
  })), v.minLength(1), v.maxLength(1_000)),
});
const currentRuntimeSchema = v.looseObject({
  bindings: v.array(boundaryObjectSchema),
  compatibility_date: v.literal('2026-08-08'),
  main_module: v.literal('index.js'),
});
const namedBindingSchema = v.looseObject({ name: v.string() });
const adminBindingSchema = v.looseObject({
  class_name: v.literal('AdminState'),
  name: v.literal('ADMIN_STATE'),
  type: v.literal('durable_object_namespace'),
});
const assetsBindingSchema = v.strictObject({
  name: v.literal('ASSETS'),
  type: v.literal('assets'),
});
const plainTextBindingSchema = v.strictObject({
  name: v.string(),
  text: v.pipe(v.string(), v.minLength(1), v.maxLength(4_096)),
  type: v.literal('plain_text'),
});
const currentWorkerSchema = v.looseObject({
  id: v.pipe(v.string(), v.regex(WORKER_ID)),
  name: v.string(),
  tags: v.array(v.string()),
});
const currentVersionSchema = v.looseObject({ id: v.pipe(v.string(), v.regex(UUID)) });
const subdomainStateSchema = v.strictObject({
  enabled: v.boolean(),
  previews_enabled: v.literal(false),
});
const accountSubdomainSchema = v.strictObject({ subdomain: v.string() });
const workerDomainsSchema = v.array(v.looseObject({
  environment: v.optional(v.string()),
  hostname: v.string(),
  service: v.string(),
}));

export interface ActiveGatewayRuntime {
  readonly deploymentId: string;
  readonly versionId: string;
}

export interface CurrentGatewayWorker {
  readonly id: string;
  readonly name: string;
  readonly tags: readonly string[];
}

export interface CurrentGatewayVersion {
  readonly id: string;
}

export interface GatewayWorkerDomain {
  readonly environment?: string;
  readonly hostname: string;
  readonly service: string;
}

export interface GatewayWorkerSubdomainState {
  readonly enabled: boolean;
  readonly previewsEnabled: false;
}

export function parseActiveGatewayRuntime(value: BoundaryValue): ActiveGatewayRuntime | null {
  const result = v.safeParse(activeRuntimeSchema, value);
  if (!result.success) return null;
  const active = result.output.deployments[0];
  const version = active?.versions[0];
  if (!active || active.versions.length !== 1 || !version || version.percentage !== 100) return null;
  return Object.freeze({ deploymentId: active.id, versionId: version.version_id });
}

function plainTextBinding(bindings: ReadonlyMap<string, BoundaryObject>, name: BindingName): string | null {
  const result = v.safeParse(plainTextBindingSchema, bindings.get(name));
  return result.success && result.output.name === name ? result.output.text : null;
}

export function parseGatewayRuntimeBindings(value: BoundaryValue): GatewayWorkerPlainTextBindings | null {
  const result = v.safeParse(currentRuntimeSchema, value);
  if (!result.success || result.output.bindings.length !== GATEWAY_RUNTIME_BINDING_NAMES.length + 2 ||
      Object.hasOwn(result.output, 'migrations') || Object.hasOwn(result.output, 'migration_tag')) return null;
  const bindings = new Map<string, BoundaryObject>();
  for (const binding of result.output.bindings) {
    const named = v.safeParse(namedBindingSchema, binding);
    if (!named.success || bindings.has(named.output.name)) return null;
    bindings.set(named.output.name, binding);
  }
  if (!v.safeParse(adminBindingSchema, bindings.get('ADMIN_STATE')).success ||
      !v.safeParse(assetsBindingSchema, bindings.get('ASSETS')).success) return null;

  const ADMIN_EMAILS = plainTextBinding(bindings, 'ADMIN_EMAILS');
  const ANKKA_GATEWAY_RELEASE = plainTextBinding(bindings, 'ANKKA_GATEWAY_RELEASE');
  const ANKKA_GATEWAY_RELEASE_SHA256 = plainTextBinding(bindings, 'ANKKA_GATEWAY_RELEASE_SHA256');
  const ANKKA_MANAGEMENT_HOSTNAME = plainTextBinding(bindings, 'ANKKA_MANAGEMENT_HOSTNAME');
  const ANKKA_UPDATE_CHANNEL = plainTextBinding(bindings, 'ANKKA_UPDATE_CHANNEL');
  const ANKKA_UPDATE_KEY_ID = plainTextBinding(bindings, 'ANKKA_UPDATE_KEY_ID');
  const ANKKA_UPDATE_PUBLIC_KEY = plainTextBinding(bindings, 'ANKKA_UPDATE_PUBLIC_KEY');
  const ANKKA_WORKERS_SUBDOMAIN = plainTextBinding(bindings, 'ANKKA_WORKERS_SUBDOMAIN');
  const ANKKA_WORKER_NAME = plainTextBinding(bindings, 'ANKKA_WORKER_NAME');
  const CF_ACCESS_AUD = plainTextBinding(bindings, 'CF_ACCESS_AUD');
  const CF_ACCESS_ISSUER = plainTextBinding(bindings, 'CF_ACCESS_ISSUER');
  const CLOUDFLARE_ACCOUNT_ID = plainTextBinding(bindings, 'CLOUDFLARE_ACCOUNT_ID');
  const CLOUDFLARE_ZONE_ID = plainTextBinding(bindings, 'CLOUDFLARE_ZONE_ID');
  const CLOUDFLARE_ZONE_NAME = plainTextBinding(bindings, 'CLOUDFLARE_ZONE_NAME');
  const ZERO_TRUST_READY = plainTextBinding(bindings, 'ZERO_TRUST_READY');
  if (ADMIN_EMAILS === null || ANKKA_GATEWAY_RELEASE === null || ANKKA_GATEWAY_RELEASE_SHA256 === null ||
      ANKKA_MANAGEMENT_HOSTNAME === null || ANKKA_UPDATE_CHANNEL === null || ANKKA_UPDATE_KEY_ID === null ||
      ANKKA_UPDATE_PUBLIC_KEY === null || ANKKA_WORKERS_SUBDOMAIN === null || ANKKA_WORKER_NAME === null ||
      CF_ACCESS_AUD === null || CF_ACCESS_ISSUER === null || CLOUDFLARE_ACCOUNT_ID === null ||
      CLOUDFLARE_ZONE_ID === null || CLOUDFLARE_ZONE_NAME === null || ZERO_TRUST_READY === null) return null;
  return Object.freeze({
    ADMIN_EMAILS,
    ANKKA_GATEWAY_RELEASE,
    ANKKA_GATEWAY_RELEASE_SHA256,
    ANKKA_MANAGEMENT_HOSTNAME,
    ANKKA_UPDATE_CHANNEL,
    ANKKA_UPDATE_KEY_ID,
    ANKKA_UPDATE_PUBLIC_KEY,
    ANKKA_WORKERS_SUBDOMAIN,
    ANKKA_WORKER_NAME,
    CF_ACCESS_AUD,
    CF_ACCESS_ISSUER,
    CLOUDFLARE_ACCOUNT_ID,
    CLOUDFLARE_ZONE_ID,
    CLOUDFLARE_ZONE_NAME,
    ZERO_TRUST_READY,
  });
}

export function parseCurrentGatewayWorker(value: BoundaryValue): CurrentGatewayWorker | null {
  const result = v.safeParse(currentWorkerSchema, value);
  return result.success ? Object.freeze(result.output) : null;
}

export function parseCurrentGatewayVersion(value: BoundaryValue): CurrentGatewayVersion | null {
  const result = v.safeParse(currentVersionSchema, value);
  return result.success ? Object.freeze(result.output) : null;
}

export function parseGatewayWorkerSubdomainState(value: BoundaryValue): GatewayWorkerSubdomainState | null {
  const result = v.safeParse(subdomainStateSchema, value);
  return result.success
    ? Object.freeze({ enabled: result.output.enabled, previewsEnabled: false })
    : null;
}

export function parseAccountWorkersSubdomain(value: BoundaryValue): string | null {
  const result = v.safeParse(accountSubdomainSchema, value);
  return result.success ? result.output.subdomain : null;
}

export function parseGatewayWorkerDomains(value: BoundaryValue): readonly GatewayWorkerDomain[] | null {
  const result = v.safeParse(workerDomainsSchema, value);
  if (!result.success) return null;
  return Object.freeze(result.output.map((domain): GatewayWorkerDomain => (
    domain.environment === undefined
      ? Object.freeze({ hostname: domain.hostname, service: domain.service })
      : Object.freeze({
        environment: domain.environment,
        hostname: domain.hostname,
        service: domain.service,
      })
  )));
}

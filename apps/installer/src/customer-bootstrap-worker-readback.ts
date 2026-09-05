import * as v from 'valibot';

import {
  boundaryObjectSchema,
  boundaryValueSchema,
  type BoundaryObject,
  type BoundaryValue,
} from './boundary';
import {
  verifyCloudflareBootstrapOwnershipHandoff,
  type CloudflareBootstrapOwnershipProviderReadback,
} from './cloudflare-bootstrap-ownership-handoff';
import { CLOUDFLARE_API_ORIGIN } from './constants';
import {
  CloudflareDirectUploadError,
  inspectAdminStateDurableObjectNamespace,
} from './cloudflare-worker-direct-upload';
import type { CustomerCloudflareTransport } from './customer-cloudflare-grant';
import { readBoundedText, withDeadline } from './http';
import { decodeWorkerModuleBase64 } from './worker-module-base64';

const VERSION_ID = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/u;
const MAX_RESPONSE_BYTES = 16 * 1024 * 1024;
const SHA256 = /^[a-f0-9]{64}$/u;

export const CUSTOMER_BOOTSTRAP_PLAIN_BINDINGS = Object.freeze([
  'ANKKA_BOOTSTRAP_CALLBACK',
  'ANKKA_BOOTSTRAP_EXPIRES_AT',
  'ANKKA_BOOTSTRAP_ID',
  'ANKKA_BOOTSTRAP_SECRET_SHA256',
  'ANKKA_GATEWAY_RELEASE',
  'ANKKA_GATEWAY_RELEASE_SHA256',
  'ANKKA_INSTALL_ID',
  'ANKKA_INSTALLER_ORIGIN',
  'ANKKA_MANAGEMENT_HOSTNAME',
  'ANKKA_PLAN_HASH',
  'ANKKA_PLAN_ID',
  'ANKKA_UPDATE_CHANNEL',
  'ANKKA_UPDATE_KEY_ID',
  'ANKKA_UPDATE_PUBLIC_KEY',
  'ANKKA_WORKER_NAME',
  'CLOUDFLARE_ACCOUNT_ID',
  'CLOUDFLARE_CUSTOMER_OAUTH_CLIENT_ID',
  'CLOUDFLARE_OWNERSHIP_ISSUER_KEY_ID',
  'CLOUDFLARE_OWNERSHIP_ISSUER_PUBLIC_KEY',
] as const);

const REQUIRED_SECRET_BINDINGS = Object.freeze([
  'ANKKA_BOOTSTRAP_NONCE',
  'ANKKA_GATEWAY_OWNERSHIP_WRAP_KEY',
] as const);

const envelopeSchema = v.looseObject({
  success: v.literal(true),
  errors: v.array(boundaryValueSchema),
  messages: v.array(boundaryValueSchema),
  result: boundaryValueSchema,
});
const workerSchema = v.looseObject({
  id: v.string(),
  name: v.string(),
  logpush: v.literal(false),
  observability: v.looseObject({ enabled: v.literal(false) }),
  subdomain: v.looseObject({
    enabled: v.literal(true),
    previews_enabled: v.literal(false),
  }),
  tags: v.array(v.string()),
  tail_consumers: v.array(boundaryValueSchema),
});
const deploymentsSchema = v.looseObject({
  deployments: v.array(v.looseObject({
    id: v.pipe(v.string(), v.regex(VERSION_ID)),
    versions: v.array(v.looseObject({
      version_id: v.pipe(v.string(), v.regex(VERSION_ID)),
      percentage: v.number(),
    })),
  })),
});
const versionSchema = v.looseObject({
  id: v.pipe(v.string(), v.regex(VERSION_ID)),
  main_module: v.literal('index.js'),
  compatibility_date: v.literal('2026-08-08'),
  compatibility_flags: v.optional(v.array(v.string())),
  bindings: v.array(boundaryValueSchema),
  assets: v.looseObject({
    config: v.looseObject({
      not_found_handling: v.literal('single-page-application'),
      run_worker_first: v.tuple([v.literal('/__ankka/*'), v.literal('/api/*')]),
    }),
  }),
  exports: v.looseObject({
    AdminState: v.looseObject({
      type: v.literal('durable-object'),
      storage: v.literal('sqlite'),
    }),
  }),
  modules: v.array(v.looseObject({
    name: v.string(),
    content_type: v.string(),
    content_base64: v.string(),
  })),
});
const namedBindingSchema = v.looseObject({ name: v.string(), type: v.string() });

export class CustomerBootstrapWorkerReadbackError extends Error {
  constructor(readonly code: 'invalid' | 'provider_unknown' | 'provider_rejected' | 'identity_mismatch') {
    super(code);
    this.name = 'CustomerBootstrapWorkerReadbackError';
  }
}

function fail(code: CustomerBootstrapWorkerReadbackError['code']): never {
  throw new CustomerBootstrapWorkerReadbackError(code);
}

async function providerResult(
  input: {
    readonly accessToken: string;
    readonly transport: CustomerCloudflareTransport;
  },
  url: URL,
): Promise<BoundaryValue> {
  try {
    return await withDeadline(async (signal) => {
      const response = await input.transport(url, {
        method: 'GET',
        headers: { accept: 'application/json', authorization: `Bearer ${input.accessToken}` },
        redirect: 'manual',
        signal,
      });
      const serialized = await readBoundedText(response, 'internal_error', MAX_RESPONSE_BYTES);
      let decoded: unknown;
      try {
        decoded = JSON.parse(serialized);
      } catch {
        fail('provider_unknown');
      }
      const envelope = v.safeParse(envelopeSchema, decoded);
      if (!response.ok || !envelope.success || envelope.output.errors.length !== 0 ||
          envelope.output.messages.length !== 0) {
        fail(response.status >= 500 ? 'provider_unknown' : 'provider_rejected');
      }
      return envelope.output.result;
    }, 'internal_error');
  } catch (error) {
    if (error instanceof CustomerBootstrapWorkerReadbackError) throw error;
    fail('provider_unknown');
  }
}

function accountUrl(accountId: string, path: string): URL {
  return new URL(`/client/v4/accounts/${accountId}${path}`, CLOUDFLARE_API_ORIGIN);
}

/** Exact Stage 1 binding set: every plain binding, both secret bindings, ADMIN_STATE, and ASSETS, nothing else. */
export function exactCustomerBootstrapVersionBindings(
  values: readonly BoundaryValue[],
  expected: Readonly<Record<string, string>>,
  namespaceId: string,
): boolean {
  const bindings = new Map<string, BoundaryObject>();
  for (const value of values) {
    const named = v.safeParse(namedBindingSchema, value);
    const object = v.safeParse(boundaryObjectSchema, value);
    if (!named.success || !object.success || bindings.has(named.output.name)) return false;
    bindings.set(named.output.name, object.output);
  }
  const exactCount = CUSTOMER_BOOTSTRAP_PLAIN_BINDINGS.length +
    REQUIRED_SECRET_BINDINGS.length + 2;
  if (bindings.size !== exactCount) return false;
  const admin = bindings.get('ADMIN_STATE');
  const assets = bindings.get('ASSETS');
  if (admin?.type !== 'durable_object_namespace' || admin.name !== 'ADMIN_STATE' ||
      admin.class_name !== 'AdminState' ||
      (admin.namespace_id !== undefined && admin.namespace_id !== namespaceId) ||
      assets?.type !== 'assets' || assets.name !== 'ASSETS') return false;
  for (const name of REQUIRED_SECRET_BINDINGS) {
    const binding = bindings.get(name);
    if (binding?.type !== 'secret_text' || binding.name !== name) return false;
  }
  for (const name of CUSTOMER_BOOTSTRAP_PLAIN_BINDINGS) {
    const binding = bindings.get(name);
    if (binding?.type !== 'plain_text' || binding.name !== name || binding.text !== expected[name]) {
      return false;
    }
  }
  return true;
}

export interface CustomerBootstrapVersionModule {
  readonly name: string;
  readonly content_type: string;
  readonly content_base64: string;
}

/** True only for exactly one `index.js` module whose bytes hash to the signed bootstrap source. */
export async function exactCustomerBootstrapModule(
  modules: readonly CustomerBootstrapVersionModule[],
  expectedSha256: string,
): Promise<boolean> {
  if (!SHA256.test(expectedSha256) || modules.length !== 1) return false;
  const module = modules[0];
  if (module === undefined || module.name !== 'index.js' ||
      module.content_type !== 'application/javascript+module') return false;
  const bytes = decodeWorkerModuleBase64(module.content_base64, 8 * 1024 * 1024);
  if (bytes === null || bytes.byteLength < 1) return false;
  const owned = new Uint8Array(new ArrayBuffer(bytes.byteLength));
  owned.set(bytes);
  try {
    const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', owned));
    const actual = Array.from(digest, (byte) => byte.toString(16).padStart(2, '0')).join('');
    digest.fill(0);
    return actual === expectedSha256;
  } finally {
    owned.fill(0);
    bytes.fill(0);
  }
}

function exactStringSet(actual: readonly string[], expected: readonly string[]): boolean {
  const left = [...actual].sort();
  const right = [...expected].sort();
  return left.length === right.length && left.every((value, index) => value === right[index]);
}

/**
 * Independently read the exact Stage 1 Worker, active version, and SQLite
 * namespace before customer-owned state adopts the deploy-signed handoff.
 */
export async function readCustomerBootstrapWorkerOwnership(input: {
  readonly accessToken: string;
  readonly accountId: string;
  readonly workerName: string;
  readonly serializedHandoff: string;
  readonly pinnedIssuerPublicKey: string;
  readonly expectedBootstrapSourceSha256: string;
  readonly expectedBindings: Readonly<Record<(typeof CUSTOMER_BOOTSTRAP_PLAIN_BINDINGS)[number], string>>;
  readonly transport: CustomerCloudflareTransport;
  readonly now: () => number;
}): Promise<Readonly<{
  providerReadback: CloudflareBootstrapOwnershipProviderReadback;
  activeVersionId: string;
}>> {
  const startedAt = input.now();
  if (!Number.isSafeInteger(startedAt) || startedAt < 0 ||
      !SHA256.test(input.expectedBootstrapSourceSha256) ||
      Object.keys(input.expectedBindings).length !== CUSTOMER_BOOTSTRAP_PLAIN_BINDINGS.length ||
      CUSTOMER_BOOTSTRAP_PLAIN_BINDINGS.some((name) =>
        !Object.hasOwn(input.expectedBindings, name) || input.expectedBindings[name].length === 0)) {
    fail('invalid');
  }
  const handoff = await verifyCloudflareBootstrapOwnershipHandoff({
    now: startedAt,
    pinnedPublicKey: input.pinnedIssuerPublicKey,
    serializedHandoff: input.serializedHandoff,
  }).catch(() => fail('identity_mismatch'));
  const statement = handoff.statement;
  if (statement.accountId !== input.accountId || statement.worker.name !== input.workerName) {
    fail('identity_mismatch');
  }
  const common = { accessToken: input.accessToken, transport: input.transport };
  const workerValue = await providerResult(common, accountUrl(
    input.accountId,
    `/workers/workers/${encodeURIComponent(input.workerName)}`,
  ));
  const worker = v.safeParse(workerSchema, workerValue);
  if (!worker.success || worker.output.id !== statement.worker.providerId ||
      worker.output.name !== statement.worker.name || worker.output.tail_consumers.length !== 0 ||
      !exactStringSet(worker.output.tags, [
        'ankka-mcp-gateway',
        'ankka-stage1-bootstrap',
        `ankka-bootstrap-id:${input.expectedBindings.ANKKA_BOOTSTRAP_ID}`,
      ])) {
    fail('identity_mismatch');
  }
  const deploymentValue = await providerResult(common, accountUrl(
    input.accountId,
    `/workers/scripts/${encodeURIComponent(input.workerName)}/deployments`,
  ));
  const deployments = v.safeParse(deploymentsSchema, deploymentValue);
  const active = deployments.success ? deployments.output.deployments.at(0) : undefined;
  const version = active?.versions.at(0);
  if (!deployments.success || !active || active.versions.length !== 1 || !version ||
      version.percentage !== 100) fail('identity_mismatch');
  const versionValue = await providerResult(common, accountUrl(
    input.accountId,
    `/workers/workers/${statement.worker.providerId}/versions/${version.version_id}?include=modules`,
  ));
  const parsedVersion = v.safeParse(versionSchema, versionValue);
  if (!parsedVersion.success || parsedVersion.output.id !== version.version_id ||
      (parsedVersion.output.compatibility_flags ?? []).length !== 0 ||
      !await exactCustomerBootstrapModule(
        parsedVersion.output.modules,
        input.expectedBootstrapSourceSha256,
      ) ||
      !exactCustomerBootstrapVersionBindings(
        parsedVersion.output.bindings,
        input.expectedBindings,
        statement.adminState.namespaceId,
      )) fail('identity_mismatch');
  try {
    await inspectAdminStateDurableObjectNamespace({
      accountId: input.accountId,
      workerName: input.workerName,
      className: 'AdminState',
      storage: 'sqlite',
      expectedNamespaceId: statement.adminState.namespaceId,
    }, { accessToken: input.accessToken, transport: input.transport });
  } catch (error) {
    if (error instanceof CloudflareDirectUploadError &&
        (error.code === 'provider_mismatch' || error.code === 'recovery_ambiguous')) {
      fail('identity_mismatch');
    }
    fail('provider_unknown');
  }
  const finalDeploymentValue = await providerResult(common, accountUrl(
    input.accountId,
    `/workers/scripts/${encodeURIComponent(input.workerName)}/deployments`,
  ));
  const finalDeployments = v.safeParse(deploymentsSchema, finalDeploymentValue);
  const finalActive = finalDeployments.success ? finalDeployments.output.deployments.at(0) : undefined;
  const finalVersion = finalActive?.versions.at(0);
  if (!finalDeployments.success || !finalActive || finalActive.id !== active.id ||
      finalActive.versions.length !== 1 || !finalVersion ||
      finalVersion.version_id !== version.version_id || finalVersion.percentage !== 100) {
    fail('identity_mismatch');
  }
  const observedAt = input.now();
  if (!Number.isSafeInteger(observedAt) || observedAt < startedAt) fail('invalid');
  const providerReadback: CloudflareBootstrapOwnershipProviderReadback = Object.freeze({
    accountId: statement.accountId,
    adminState: statement.adminState,
    bootstrapSecret: statement.bootstrapSecret,
    handoff: Object.freeze({
      expiresAt: statement.expiresAt,
      issuedAt: statement.issuedAt,
      nonce: statement.nonce,
    }),
    installId: statement.installId,
    observedAt,
    purpose: 'cloudflare_bootstrap_ownership_provider_readback',
    plan: statement.plan,
    release: statement.release,
    schemaVersion: statement.schemaVersion,
    worker: statement.worker,
  });
  return Object.freeze({ providerReadback, activeVersionId: version.version_id });
}

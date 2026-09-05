import * as v from 'valibot';

import { boundaryObjectSchema, boundaryValueSchema, type BoundaryObject, type BoundaryValue } from './boundary';
import { canonicalJson } from './canonical-json';
import { CLOUDFLARE_API_ORIGIN } from './constants';
import type {
  CustomerCloudflareTransport,
} from './customer-cloudflare-grant';
import {
  EXACT_PLAIN_TEXT_BINDINGS,
  type GatewayWorkerPlainTextBindings,
} from './cloudflare-worker-direct-upload';
import { readBoundedText, withDeadline } from './http';
import { decodeWorkerModuleBase64 } from './worker-module-base64';

const ACCOUNT_ID = /^[a-f0-9]{32}$/u;
const WORKER_ID = /^[a-f0-9]{32}$/u;
const WORKER_NAME = /^[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$/u;
const VERSION_ID = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/u;
const TOKEN = /^[A-Za-z0-9._~+/-]+=*$/u;
const SOURCE_SHA256 = /^[a-f0-9]{64}$/u;
const MAX_SOURCE_BYTES = 8 * 1024 * 1024;
// Allow the bounded source as base64 plus version metadata.
const MAX_RESPONSE_BYTES = 16 * 1024 * 1024;
const COMPATIBILITY_DATE = '2026-08-08';
const MAIN_MODULE = 'index.js';
const INHERITED_BINDINGS = Object.freeze([
  'ADMIN_STATE',
  'ASSETS',
  'ANKKA_GATEWAY_OWNERSHIP_WRAP_KEY',
] as const);

const envelopeSchema = v.looseObject({
  success: v.literal(true),
  errors: v.array(boundaryValueSchema),
  messages: v.array(boundaryValueSchema),
  result: boundaryValueSchema,
});
const workerSchema = v.looseObject({
  id: v.pipe(v.string(), v.regex(WORKER_ID)),
  name: v.pipe(v.string(), v.regex(WORKER_NAME)),
  tags: v.array(v.string()),
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
const namedBindingSchema = v.looseObject({ name: v.string(), type: v.string() });
const plainTextBindingValueSchema = v.pipe(v.string(), v.minLength(1), v.maxLength(4096));
const moduleSchema = v.looseObject({
  name: v.string(),
  content_type: v.string(),
  content_base64: v.string(),
});
const versionSchema = v.looseObject({
  id: v.pipe(v.string(), v.regex(VERSION_ID)),
  main_module: v.literal(MAIN_MODULE),
  compatibility_date: v.literal(COMPATIBILITY_DATE),
  compatibility_flags: v.optional(v.array(v.string())),
  modules: v.array(moduleSchema),
  bindings: v.array(boundaryValueSchema),
  exports: v.looseObject({
    AdminState: v.looseObject({
      type: v.literal('durable-object'),
      storage: v.literal('sqlite'),
    }),
  }),
});

export type CustomerWorkerSelfUpdateStage =
  | 'validate'
  | 'worker_read'
  | 'deployment_read'
  | 'version_read'
  | 'script_upload'
  | 'secret_delete';

export class CustomerWorkerSelfUpdateError extends Error {
  readonly canRetry = false;

  constructor(
    readonly code: 'invalid' | 'provider_rejected' | 'provider_unknown' | 'provider_mismatch',
    readonly stage: CustomerWorkerSelfUpdateStage,
    readonly outcome: 'not_sent' | 'rejected' | 'unknown' | 'submitted',
  ) {
    super(code);
    this.name = 'CustomerWorkerSelfUpdateError';
  }
}

export interface CustomerWorkerFinalRuntimeInspectionInput {
  readonly accessToken: string;
  readonly accountId: string;
  readonly workerName: string;
  readonly expectedWorkerId: string;
  readonly finalRuntimeSha256: string;
  readonly bindings: GatewayWorkerPlainTextBindings;
  readonly transport: CustomerCloudflareTransport;
  readonly wait?: (milliseconds: number) => Promise<void>;
}

export interface CustomerWorkerSelfUpdateInput
  extends CustomerWorkerFinalRuntimeInspectionInput {
  readonly finalRuntimeSource: string;
}

export interface CustomerWorkerActiveRelease {
  readonly workerId: string;
  readonly deploymentId: string;
  readonly versionId: string;
  readonly finalRuntimeSha256: string;
}

function fail(
  code: CustomerWorkerSelfUpdateError['code'],
  stage: CustomerWorkerSelfUpdateStage,
  outcome: CustomerWorkerSelfUpdateError['outcome'],
): never {
  throw new CustomerWorkerSelfUpdateError(code, stage, outcome);
}

function validToken(value: string): boolean {
  return value.length >= 16 && value.length <= 8192 && TOKEN.test(value) &&
    ![...value].some((character) => {
      const point = character.codePointAt(0) ?? 0;
      return point <= 31 || point === 127;
    });
}

function validateInspection(input: CustomerWorkerFinalRuntimeInspectionInput): void {
  const bindingNames = Object.keys(input.bindings);
  const bindingValues = Object.values(input.bindings);
  if (!validToken(input.accessToken) || !ACCOUNT_ID.test(input.accountId) ||
      !WORKER_NAME.test(input.workerName) || !WORKER_ID.test(input.expectedWorkerId) ||
      !SOURCE_SHA256.test(input.finalRuntimeSha256) ||
      bindingNames.length !== EXACT_PLAIN_TEXT_BINDINGS.length ||
      EXACT_PLAIN_TEXT_BINDINGS.some((name) => !Object.hasOwn(input.bindings, name)) ||
      bindingValues.some((value) => !v.is(plainTextBindingValueSchema, value))) {
    fail('invalid', 'validate', 'not_sent');
  }
}

async function validateUpdate(input: CustomerWorkerSelfUpdateInput): Promise<void> {
  validateInspection(input);
  const sourceBytes = new TextEncoder().encode(input.finalRuntimeSource);
  if (sourceBytes.byteLength < 1 || sourceBytes.byteLength > MAX_SOURCE_BYTES ||
      await sha256BytesHex(sourceBytes) !== input.finalRuntimeSha256) {
    sourceBytes.fill(0);
    fail('invalid', 'validate', 'not_sent');
  }
  sourceBytes.fill(0);
}

function accountUrl(accountId: string, path: string): URL {
  return new URL(`/client/v4/accounts/${accountId}${path}`, CLOUDFLARE_API_ORIGIN);
}

async function responseValue(
  response: Response,
  stage: CustomerWorkerSelfUpdateStage,
  outcome: CustomerWorkerSelfUpdateError['outcome'],
): Promise<BoundaryValue> {
  let serialized: string;
  try {
    serialized = await readBoundedText(response, 'internal_error', MAX_RESPONSE_BYTES);
  } catch {
    fail('provider_unknown', stage, outcome);
  }
  let decoded: unknown;
  try {
    decoded = JSON.parse(serialized);
  } catch {
    fail('provider_unknown', stage, outcome);
  }
  const parsed = v.safeParse(envelopeSchema, decoded);
  if (!response.ok || !parsed.success || parsed.output.errors.length !== 0 ||
      parsed.output.messages.length !== 0) {
    fail(response.status >= 500 ? 'provider_unknown' : 'provider_rejected', stage, outcome);
  }
  return parsed.output.result;
}

async function providerRead(
  input: CustomerWorkerFinalRuntimeInspectionInput,
  stage: CustomerWorkerSelfUpdateStage,
  url: URL,
): Promise<BoundaryValue> {
  try {
    return await withDeadline(async (signal) => responseValue(await input.transport(url, {
      method: 'GET',
      headers: { accept: 'application/json', authorization: `Bearer ${input.accessToken}` },
      redirect: 'manual',
      signal,
    }), stage, 'unknown'), 'internal_error');
  } catch (error) {
    if (error instanceof CustomerWorkerSelfUpdateError) throw error;
    fail('provider_unknown', stage, 'unknown');
  }
}

async function currentWorker(input: CustomerWorkerFinalRuntimeInspectionInput): Promise<string> {
  const value = await providerRead(input, 'worker_read', accountUrl(
    input.accountId,
    `/workers/workers/${encodeURIComponent(input.workerName)}`,
  ));
  const worker = v.safeParse(workerSchema, value);
  if (!worker.success || worker.output.id !== input.expectedWorkerId ||
      worker.output.name !== input.workerName || !worker.output.tags.includes('ankka-mcp-gateway')) {
    fail('provider_mismatch', 'worker_read', 'rejected');
  }
  return worker.output.id;
}

async function activeRelease(input: CustomerWorkerFinalRuntimeInspectionInput): Promise<{
  deploymentId: string;
  versionId: string;
}> {
  const value = await providerRead(input, 'deployment_read', accountUrl(
    input.accountId,
    `/workers/scripts/${encodeURIComponent(input.workerName)}/deployments`,
  ));
  const parsed = v.safeParse(deploymentsSchema, value);
  const deployments = parsed.success ? parsed.output.deployments : [];
  const deployment = deployments[0];
  const version = deployment?.versions[0];
  if (!parsed.success || !deployment || deployment.versions.length !== 1 || !version ||
      version.percentage !== 100) fail('provider_mismatch', 'deployment_read', 'rejected');
  return Object.freeze({ deploymentId: deployment.id, versionId: version.version_id });
}

async function sha256BytesHex(bytes: Uint8Array): Promise<string> {
  const input = new Uint8Array(bytes.byteLength);
  input.set(bytes);
  try {
    const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', input));
    return [...digest].map((byte) => byte.toString(16).padStart(2, '0')).join('');
  } finally {
    input.fill(0);
  }
}

function exactBindings(
  values: readonly BoundaryValue[],
  expected: GatewayWorkerPlainTextBindings,
): boolean {
  const bindings = new Map<string, BoundaryObject>();
  for (const value of values) {
    const named = v.safeParse(namedBindingSchema, value);
    const object = v.safeParse(boundaryObjectSchema, value);
    if (!named.success || !object.success || Array.isArray(value) ||
        bindings.has(named.output.name)) return false;
    bindings.set(named.output.name, object.output);
  }
  if (bindings.size !== Object.keys(expected).length + INHERITED_BINDINGS.length) return false;
  const admin = bindings.get('ADMIN_STATE');
  const assets = bindings.get('ASSETS');
  const ownershipKey = bindings.get('ANKKA_GATEWAY_OWNERSHIP_WRAP_KEY');
  if (admin?.type !== 'durable_object_namespace' || admin.name !== 'ADMIN_STATE' ||
      admin.class_name !== 'AdminState' || assets?.type !== 'assets' || assets.name !== 'ASSETS' ||
      ownershipKey?.type !== 'secret_text' || ownershipKey.name !== 'ANKKA_GATEWAY_OWNERSHIP_WRAP_KEY' ||
      bindings.has('ANKKA_BOOTSTRAP_NONCE')) return false;
  for (const [name, text] of Object.entries(expected)) {
    const binding = bindings.get(name);
    if (binding?.type !== 'plain_text' || binding.name !== name || binding.text !== text) return false;
  }
  return true;
}

async function exactFinalVersion(
  input: CustomerWorkerFinalRuntimeInspectionInput,
  workerId: string,
  versionId: string,
): Promise<boolean> {
  const value = await providerRead(input, 'version_read', accountUrl(
    input.accountId,
    `/workers/workers/${workerId}/versions/${versionId}?include=modules`,
  ));
  const parsed = v.safeParse(versionSchema, value);
  if (!parsed.success || parsed.output.id !== versionId ||
      (parsed.output.compatibility_flags ?? []).length !== 0 ||
      parsed.output.modules.length !== 1 || !exactBindings(parsed.output.bindings, input.bindings)) return false;
  const module = parsed.output.modules[0];
  if (!module || module.name !== MAIN_MODULE ||
      module.content_type !== 'application/javascript+module') return false;
  const bytes = decodeWorkerModuleBase64(module.content_base64, MAX_SOURCE_BYTES);
  if (bytes === null) return false;
  try {
    return await sha256BytesHex(bytes) === input.finalRuntimeSha256;
  } finally {
    bytes.fill(0);
  }
}

/** Read back the exact active source and binding boundary; never infer from PUT success. */
export async function inspectCustomerWorkerFinalRuntime(
  input: CustomerWorkerFinalRuntimeInspectionInput,
): Promise<CustomerWorkerActiveRelease | null> {
  validateInspection(input);
  const workerId = await currentWorker(input);
  const active = await activeRelease(input);
  if (!await exactFinalVersion(input, workerId, active.versionId)) return null;
  return Object.freeze({
    workerId,
    deploymentId: active.deploymentId,
    versionId: active.versionId,
    finalRuntimeSha256: input.finalRuntimeSha256,
  });
}

function uploadMetadata(input: CustomerWorkerSelfUpdateInput): BoundaryObject {
  // The script upload API inherits only from the latest version (it refuses
  // an exact version id with code 10057). The caller has just proven that the
  // latest version is the verified bootstrap version, and the active version
  // is read back and matched exactly after the upload.
  const inherited = INHERITED_BINDINGS.map((name) => Object.freeze({
    name,
    type: 'inherit' as const,
    version_id: 'latest',
  }));
  const plain = Object.entries(input.bindings).map(([name, text]) => Object.freeze({
    name,
    type: 'plain_text' as const,
    text,
  }));
  return Object.freeze({
    annotations: Object.freeze({
      'workers/message': `Ankka final runtime ${input.finalRuntimeSha256.slice(0, 16)}`,
      'workers/tag': `ankka-final-${input.finalRuntimeSha256.slice(0, 64)}`,
    }),
    bindings: Object.freeze([...inherited, ...plain].sort((left, right) =>
      left.name < right.name ? -1 : left.name > right.name ? 1 : 0)),
    compatibility_date: COMPATIBILITY_DATE,
    compatibility_flags: Object.freeze([]),
    exports: Object.freeze({
      AdminState: Object.freeze({ type: 'durable-object', storage: 'sqlite' }),
    }),
    keep_assets: true,
    main_module: MAIN_MODULE,
  });
}

/**
 * Secrets survive script uploads by design, so the bootstrap nonce is removed
 * from the Worker explicitly; the readback afterwards refuses any version
 * that still carries it. A nonce that is already gone is fine.
 */
async function deleteBootstrapNonceSecret(input: CustomerWorkerSelfUpdateInput): Promise<void> {
  const url = accountUrl(
    input.accountId,
    `/workers/scripts/${encodeURIComponent(input.workerName)}/secrets/ANKKA_BOOTSTRAP_NONCE`,
  );
  try {
    await withDeadline(async (signal) => {
      const response = await input.transport(url, {
        method: 'DELETE',
        headers: { accept: 'application/json', authorization: `Bearer ${input.accessToken}` },
        redirect: 'manual',
        signal,
      });
      if (response.status === 404) {
        await readBoundedText(response, 'internal_error', MAX_RESPONSE_BYTES);
        return;
      }
      await responseValue(response, 'secret_delete', 'submitted');
    }, 'internal_error');
  } catch (error) {
    if (error instanceof CustomerWorkerSelfUpdateError) throw error;
    fail('provider_unknown', 'secret_delete', 'unknown');
  }
}

interface FinalRuntimeUpload {
  readonly workerId: string;
  readonly previousVersionId: string;
}

/**
 * Upload the final runtime over the verified bootstrap version and drop the
 * bootstrap nonce. Returns the already-active release when the bootstrap
 * version is no longer active, else the upload's identifiers for a readback.
 */
async function uploadFinalRuntime(input: CustomerWorkerSelfUpdateInput & {
  readonly previousVersionId: string;
}): Promise<FinalRuntimeUpload | CustomerWorkerActiveRelease> {
  await validateUpdate(input);
  if (!VERSION_ID.test(input.previousVersionId)) fail('invalid', 'validate', 'not_sent');
  const workerId = await currentWorker(input);
  const before = await activeRelease(input);
  if (before.versionId !== input.previousVersionId) {
    const recovered = await inspectCustomerWorkerFinalRuntime(input);
    if (recovered !== null) return recovered;
    fail('provider_mismatch', 'deployment_read', 'rejected');
  }
  const form = new FormData();
  form.append('metadata', new Blob([canonicalJson(uploadMetadata(input))], {
    type: 'application/json',
  }), 'metadata.json');
  const sourceBytes = new TextEncoder().encode(input.finalRuntimeSource);
  form.append(MAIN_MODULE, new Blob([sourceBytes], {
    type: 'application/javascript+module',
  }), MAIN_MODULE);
  sourceBytes.fill(0);
  const url = accountUrl(
    input.accountId,
    `/workers/scripts/${encodeURIComponent(input.workerName)}`,
  );
  url.searchParams.set('bindings_inherit', 'strict');
  try {
    await withDeadline(async (signal) => {
      const response = await input.transport(url, {
        method: 'PUT',
        headers: { accept: 'application/json', authorization: `Bearer ${input.accessToken}` },
        body: form,
        redirect: 'manual',
        signal,
      });
      await responseValue(response, 'script_upload', 'submitted');
    }, 'internal_error');
  } catch (error) {
    if (error instanceof CustomerWorkerSelfUpdateError) throw error;
    fail('provider_unknown', 'script_upload', 'unknown');
  }
  await deleteBootstrapNonceSecret(input);
  return Object.freeze({ workerId, previousVersionId: before.versionId });
}

/**
 * Upload the final runtime without reading the result back, for a caller
 * whose own runtime is replaced by the upload and cannot record a readback.
 */
export async function uploadCustomerWorkerFinalRuntime(input: CustomerWorkerSelfUpdateInput & {
  readonly previousVersionId: string;
}): Promise<void> {
  await uploadFinalRuntime(input);
}

/**
 * Publish the final runtime while inheriting only the exact customer-owned DO,
 * assets, and ownership-key secret from one verified active version, and
 * read the activated release back exactly.
 */
export async function publishCustomerWorkerFinalRuntime(input: CustomerWorkerSelfUpdateInput & {
  readonly previousVersionId: string;
}): Promise<CustomerWorkerActiveRelease> {
  const uploaded = await uploadFinalRuntime(input);
  if ('deploymentId' in uploaded) return uploaded;
  const wait = input.wait ?? ((milliseconds: number) =>
    new Promise<void>((resolve) => setTimeout(resolve, milliseconds)));
  for (let attempt = 0; attempt < 8; attempt += 1) {
    const active = await activeRelease(input);
    if (active.versionId !== uploaded.previousVersionId &&
        await exactFinalVersion(input, uploaded.workerId, active.versionId)) {
      return Object.freeze({
        workerId: uploaded.workerId,
        deploymentId: active.deploymentId,
        versionId: active.versionId,
        finalRuntimeSha256: input.finalRuntimeSha256,
      });
    }
    await wait(100 * (attempt + 1));
  }
  fail('provider_unknown', 'version_read', 'submitted');
}

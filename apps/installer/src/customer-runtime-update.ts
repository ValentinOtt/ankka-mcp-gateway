import * as v from 'valibot';

import { boundaryObjectSchema, type BoundaryObject, type BoundaryValue } from './boundary';
import { canonicalJson } from './canonical-json';
import {
  parseActiveGatewayRuntime,
  parseCurrentGatewayWorker,
} from './cloudflare-gateway-runtime-state';
import {
  EXACT_PLAIN_TEXT_BINDINGS,
  prepareAssetBucketMutation,
  prepareAssetUploadSessionMutation,
  prepareVerifiedWorkerRelease,
  submitAssetBucketMutation,
  submitAssetUploadSessionMutation,
  type GatewayWorkerPlainTextBindingName,
  type GatewayWorkerPlainTextBindings,
  type PreparedVerifiedWorkerRelease,
} from './cloudflare-worker-direct-upload';
import { CLOUDFLARE_API_ORIGIN } from './constants';
import type { CustomerCloudflareTransport } from './customer-cloudflare-grant';
import { withDeadline } from './http';
import { adaptVerifiedReleaseBundleForWorkerDirectUpload } from './release-direct-upload-adapter';
import {
  RELEASE_ENVELOPE_SCHEMA_VERSION,
  RELEASE_SIGNATURE_CONTEXT,
  verifySignedReleaseEnvelope,
  type ReleasePayloadFile,
  type VerifiedReleaseBundle,
  type VerifiedReleasePayloadBlob,
} from './release';
import { parseCanonicalReleaseManifest, type ReleaseManifest } from './release-manifest';
import { parsePublicUpdateChannel } from './update-channel';

/**
 * A gateway updating itself. The grant is the customer's own `upgrade`
 * consent; the bytes come from the control plane's exact signed bundle and are
 * verified against the signed manifest with the update key this runtime was
 * installed with before anything is uploaded. The upload replaces the very
 * Worker that runs this code, so the caller arms a handover first and the new
 * version's alarm finishes the journal; nothing after the upload may rely on
 * this object's storage.
 */
export type CustomerRuntimeUpdateStage =
  | 'begin'
  | 'current_read'
  | 'release_read'
  | 'release_verify'
  | 'release_prepare'
  | 'assets_upload'
  | 'handover'
  | 'script_upload';

export class CustomerRuntimeUpdateError extends Error {
  constructor(
    readonly code: 'invalid' | 'control_rejected' | 'provider_rejected' | 'provider_unknown' |
      'release_unavailable' | 'release_invalid' | 'upload_unknown',
    readonly stage: CustomerRuntimeUpdateStage,
  ) {
    super(code);
    this.name = 'CustomerRuntimeUpdateError';
  }
}

export type CustomerRuntimeControlCommand =
  | { readonly command: 'begin' }
  | {
    readonly command: 'progress';
    readonly stage: 'current_verified' | 'assets_uploaded' | 'candidate_created';
    readonly fromVersionId: string;
    readonly toVersionId: null;
  }
  | { readonly command: 'fail'; readonly failureCode: string; readonly recoveryRequired: boolean };

export interface CustomerRuntimeUpdateTarget {
  readonly release: string;
  /** With its `sha256:` prefix, as the bindings and the public channel carry it. */
  readonly artifactSha256: string;
}

export interface CustomerRuntimeUpdateInput {
  readonly accessToken: string;
  readonly accountId: string;
  readonly workerName: string;
  readonly controlPlaneOrigin: string;
  readonly channel: 'canary' | 'stable';
  readonly updateKeyId: string;
  readonly updatePublicKey: string;
  readonly target: CustomerRuntimeUpdateTarget;
  readonly transport: CustomerCloudflareTransport;
  /** One HMAC-signed control command to the gateway's own journal; true on 200. */
  readonly control: (command: CustomerRuntimeControlCommand) => Promise<boolean>;
  /** Persists what the new version needs to finish, and arms its alarm; right before the upload. */
  readonly armHandover: (input: { readonly fromVersionId: string }) => Promise<void>;
}

export interface CustomerRuntimeUpdateResult {
  readonly status: 'uploaded';
  readonly fromVersionId: string;
}

const ACCOUNT_ID = /^[a-f0-9]{32}$/u;
const WORKER_NAME = /^[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$/u;
const RELEASE = /^gateway-v(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)$/u;
const ARTIFACT = /^sha256:[a-f0-9]{64}$/u;
const TOKEN = /^[A-Za-z0-9_-]{43}$/u;
const KEY_ID = /^[a-z0-9][a-z0-9._-]{0,63}$/u;
const FILE_PATH = /^payload\/[A-Za-z0-9][A-Za-z0-9._/-]{0,200}$/u;
const MAX_DESCRIPTOR_BYTES = 8 * 1024 * 1024;
const MAX_RESPONSE_BYTES = 4 * 1024 * 1024;
/** The whole bundle must fit the same bound the hosted installer applies. */
const MAX_BUNDLE_BYTES = 24 * 1024 * 1024;
const COMPATIBILITY_DATE = '2026-08-08';
const MAIN_MODULE = 'index.js';
const RUN_WORKER_FIRST = Object.freeze(['/__ankka/*', '/api/*'] as const);
/** The nonce input is required by the shared preparer; a clean version carries none. */
const NO_BOOTSTRAP_NONCE = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';

const envelopeSchema = v.looseObject({
  success: v.literal(true),
  result: v.union([boundaryObjectSchema, v.null()]),
});

function fail(code: CustomerRuntimeUpdateError['code'], stage: CustomerRuntimeUpdateStage): never {
  throw new CustomerRuntimeUpdateError(code, stage);
}

function accountUrl(accountId: string, path: string): URL {
  return new URL(`/client/v4/accounts/${accountId}${path}`, CLOUDFLARE_API_ORIGIN);
}

async function readBoundedBytes(response: Response, maxBytes: number): Promise<Uint8Array> {
  const declared = response.headers.get('content-length');
  if (declared !== null && (!/^\d{1,9}$/u.test(declared) || Number(declared) > maxBytes)) {
    await response.body?.cancel();
    throw new TypeError('response');
  }
  if (!response.body) throw new TypeError('response');
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > maxBytes) {
      await reader.cancel();
      throw new TypeError('response');
    }
    chunks.push(value);
  }
  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return bytes;
}

async function providerJson(
  input: CustomerRuntimeUpdateInput,
  stage: CustomerRuntimeUpdateStage,
  url: URL,
): Promise<BoundaryValue> {
  let bytes: Uint8Array;
  let status = 0;
  try {
    bytes = await withDeadline(async (signal) => {
      const response = await input.transport(url, {
        method: 'GET',
        headers: { accept: 'application/json', authorization: `Bearer ${input.accessToken}` },
        redirect: 'manual',
        signal,
      });
      status = response.status;
      return readBoundedBytes(response, MAX_RESPONSE_BYTES);
    }, 'internal_error');
  } catch {
    fail('provider_unknown', stage);
  }
  if (status !== 200) fail('provider_rejected', stage);
  let parsed: v.SafeParseResult<typeof envelopeSchema>;
  try {
    parsed = v.safeParse(envelopeSchema, JSON.parse(new TextDecoder().decode(bytes)));
  } catch {
    fail('provider_rejected', stage);
  }
  if (!parsed.success || parsed.output.result === null) fail('provider_rejected', stage);
  return parsed.output.result;
}

interface CurrentRuntime {
  readonly workerId: string;
  readonly versionId: string;
  readonly bindings: GatewayWorkerPlainTextBindings;
}

const finalVersionSchema = v.looseObject({
  bindings: v.array(boundaryObjectSchema),
  compatibility_date: v.literal(COMPATIBILITY_DATE),
  main_module: v.literal(MAIN_MODULE),
});
const namedBindingSchema = v.looseObject({ name: v.string(), type: v.string() });
const plainTextBindingSchema = v.strictObject({
  name: v.string(),
  text: v.pipe(v.string(), v.minLength(1), v.maxLength(4_096)),
  type: v.literal('plain_text'),
});

/**
 * The final runtime's exact binding set: the object namespace, the assets,
 * the ownership wrap-key secret, and the sixteen plain-text bindings. The
 * shared parser knows the bootstrap shape without the secret; an update
 * starts from the version that already carries it and inherits it forward.
 */
function parseFinalRuntimeBindings(value: BoundaryValue): GatewayWorkerPlainTextBindings | null {
  const parsed = v.safeParse(finalVersionSchema, value);
  if (!parsed.success || parsed.output.bindings.length !== EXACT_PLAIN_TEXT_BINDINGS.length + 3 ||
      Object.hasOwn(parsed.output, 'migrations') || Object.hasOwn(parsed.output, 'migration_tag')) return null;
  const byName = new Map<string, BoundaryObject>();
  for (const binding of parsed.output.bindings) {
    const named = v.safeParse(namedBindingSchema, binding);
    if (!named.success || byName.has(named.output.name)) return null;
    byName.set(named.output.name, binding);
  }
  const admin = byName.get('ADMIN_STATE');
  const assets = byName.get('ASSETS');
  const wrapKey = byName.get('ANKKA_GATEWAY_OWNERSHIP_WRAP_KEY');
  if (admin?.type !== 'durable_object_namespace' || admin.class_name !== 'AdminState' ||
      assets?.type !== 'assets' || wrapKey?.type !== 'secret_text') return null;
  const text = (name: GatewayWorkerPlainTextBindingName): string | null => {
    const plain = v.safeParse(plainTextBindingSchema, byName.get(name));
    return plain.success && plain.output.name === name ? plain.output.text : null;
  };
  const ADMIN_EMAILS = text('ADMIN_EMAILS');
  const ANKKA_INSTALL_ID = text('ANKKA_INSTALL_ID');
  const ANKKA_GATEWAY_RELEASE = text('ANKKA_GATEWAY_RELEASE');
  const ANKKA_GATEWAY_RELEASE_SHA256 = text('ANKKA_GATEWAY_RELEASE_SHA256');
  const ANKKA_MANAGEMENT_HOSTNAME = text('ANKKA_MANAGEMENT_HOSTNAME');
  const ANKKA_UPDATE_CHANNEL = text('ANKKA_UPDATE_CHANNEL');
  const ANKKA_UPDATE_KEY_ID = text('ANKKA_UPDATE_KEY_ID');
  const ANKKA_UPDATE_PUBLIC_KEY = text('ANKKA_UPDATE_PUBLIC_KEY');
  const ANKKA_WORKERS_SUBDOMAIN = text('ANKKA_WORKERS_SUBDOMAIN');
  const ANKKA_WORKER_NAME = text('ANKKA_WORKER_NAME');
  const CF_ACCESS_AUD = text('CF_ACCESS_AUD');
  const CF_ACCESS_ISSUER = text('CF_ACCESS_ISSUER');
  const CLOUDFLARE_ACCOUNT_ID = text('CLOUDFLARE_ACCOUNT_ID');
  const CLOUDFLARE_ZONE_ID = text('CLOUDFLARE_ZONE_ID');
  const CLOUDFLARE_ZONE_NAME = text('CLOUDFLARE_ZONE_NAME');
  const ZERO_TRUST_READY = text('ZERO_TRUST_READY');
  if (ADMIN_EMAILS === null || ANKKA_INSTALL_ID === null || ANKKA_GATEWAY_RELEASE === null ||
      ANKKA_GATEWAY_RELEASE_SHA256 === null || ANKKA_MANAGEMENT_HOSTNAME === null ||
      ANKKA_UPDATE_CHANNEL === null || ANKKA_UPDATE_KEY_ID === null || ANKKA_UPDATE_PUBLIC_KEY === null ||
      ANKKA_WORKERS_SUBDOMAIN === null || ANKKA_WORKER_NAME === null || CF_ACCESS_AUD === null ||
      CF_ACCESS_ISSUER === null || CLOUDFLARE_ACCOUNT_ID === null || CLOUDFLARE_ZONE_ID === null ||
      CLOUDFLARE_ZONE_NAME === null || ZERO_TRUST_READY === null) return null;
  return Object.freeze({
    ADMIN_EMAILS,
    ANKKA_INSTALL_ID,
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

async function readCurrentRuntime(input: CustomerRuntimeUpdateInput): Promise<CurrentRuntime> {
  const worker = parseCurrentGatewayWorker(await providerJson(
    input, 'current_read', accountUrl(input.accountId, `/workers/workers/${encodeURIComponent(input.workerName)}`),
  ));
  if (worker === null || worker.name !== input.workerName || !worker.tags.includes('ankka-mcp-gateway')) {
    fail('provider_rejected', 'current_read');
  }
  const active = parseActiveGatewayRuntime(await providerJson(
    input, 'current_read', accountUrl(input.accountId, `/workers/scripts/${encodeURIComponent(input.workerName)}/deployments`),
  ));
  if (active === null) fail('provider_rejected', 'current_read');
  const version = await providerJson(
    input, 'current_read', accountUrl(input.accountId, `/workers/workers/${worker.id}/versions/${active.versionId}`),
  );
  const bindings = parseFinalRuntimeBindings(version);
  if (bindings === null || bindings.ANKKA_WORKER_NAME !== input.workerName ||
      bindings.CLOUDFLARE_ACCOUNT_ID !== input.accountId ||
      bindings.ANKKA_UPDATE_KEY_ID !== input.updateKeyId ||
      bindings.ANKKA_UPDATE_PUBLIC_KEY !== input.updatePublicKey ||
      bindings.ANKKA_UPDATE_CHANNEL !== input.channel ||
      bindings.ANKKA_GATEWAY_RELEASE === input.target.release) {
    fail('provider_rejected', 'current_read');
  }
  return Object.freeze({ workerId: worker.id, versionId: active.versionId, bindings });
}

async function controlPlaneBytes(
  input: CustomerRuntimeUpdateInput,
  path: string,
  maxBytes: number,
): Promise<Uint8Array> {
  let status = 0;
  try {
    const bytes = await withDeadline(async (signal) => {
      const response = await input.transport(`${input.controlPlaneOrigin}${path}`, {
        method: 'GET',
        headers: { accept: '*/*' },
        redirect: 'manual',
        signal,
      });
      status = response.status;
      return readBoundedBytes(response, maxBytes);
    }, 'internal_error');
    if (status !== 200) fail('release_unavailable', 'release_read');
    return bytes;
  } catch (error) {
    if (error instanceof CustomerRuntimeUpdateError) throw error;
    fail('release_unavailable', 'release_read');
  }
}

function manifestFiles(manifest: ReleaseManifest) {
  return [
    ...manifest.components.admin.files,
    ...manifest.components.installer.files,
    ...manifest.components.worker.files,
    ...manifest.components.workerBootstrap.files,
    ...manifest.components.workerCleanup.files,
    ...manifest.components.workerRetirement.files,
  ];
}

/** Fetches the approved bundle independently of the mutable channel selection. */
async function loadTargetBundle(input: CustomerRuntimeUpdateInput): Promise<VerifiedReleaseBundle> {
  const releasePath = `/api/releases/${input.channel}/by-id/${input.target.release}/${input.target.artifactSha256.slice('sha256:'.length)}`;
  let channel: ReturnType<typeof parsePublicUpdateChannel>;
  try {
    channel = parsePublicUpdateChannel(JSON.parse(new TextDecoder().decode(
      await controlPlaneBytes(input, releasePath, MAX_DESCRIPTOR_BYTES),
    )));
  } catch (error) {
    if (error instanceof CustomerRuntimeUpdateError) throw error;
    fail('release_invalid', 'release_read');
  }
  if (channel.channel !== input.channel || channel.release.id !== input.target.release ||
      channel.release.artifactSha256 !== input.target.artifactSha256 ||
      channel.verification.keyId !== input.updateKeyId) {
    fail('release_unavailable', 'release_read');
  }
  let manifest: ReleaseManifest;
  try {
    manifest = parseCanonicalReleaseManifest(channel.verification.manifest);
  } catch {
    fail('release_invalid', 'release_read');
  }
  if (manifest.controlPlaneOrigin !== input.controlPlaneOrigin ||
      manifest.artifact.byteSize > MAX_BUNDLE_BYTES) fail('release_invalid', 'release_read');
  const files: ReleasePayloadFile[] = [];
  const blobs: VerifiedReleasePayloadBlob[] = [];
  for (const record of manifestFiles(manifest)) {
    if (!FILE_PATH.test(record.path)) fail('release_invalid', 'release_read');
    const bytes = await controlPlaneBytes(
      input, `${releasePath}/files/${record.path}`, record.byteSize,
    );
    if (bytes.byteLength !== record.byteSize) fail('release_invalid', 'release_read');
    files.push({ path: record.path, bytes });
    const owned = new Uint8Array(bytes.byteLength);
    owned.set(bytes);
    blobs.push(Object.freeze({
      path: record.path,
      byteSize: record.byteSize,
      contentType: record.contentType,
      sha256: record.sha256,
      bytes: new Blob([owned], { type: record.contentType }),
    }));
  }
  const envelope = Object.freeze({
    schemaVersion: RELEASE_ENVELOPE_SCHEMA_VERSION,
    channel: channel.channel,
    keyId: channel.verification.keyId,
    manifest: channel.verification.manifest,
    signature: channel.verification.signature,
    signatureContext: RELEASE_SIGNATURE_CONTEXT,
  });
  try {
    await verifySignedReleaseEnvelope(
      canonicalJson(envelope),
      input.channel,
      Object.freeze({ [input.updateKeyId]: input.updatePublicKey }),
      files,
    );
  } catch {
    fail('release_invalid', 'release_verify');
  } finally {
    for (const file of files) file.bytes.fill(0);
  }
  return Object.freeze({
    verification: 'ed25519',
    keyId: channel.verification.keyId,
    manifest,
    channel: channel.channel,
    envelope,
    payload: Object.freeze(blobs),
    publicKey: input.updatePublicKey,
  });
}

async function uploadAssets(
  input: CustomerRuntimeUpdateInput,
  prepared: PreparedVerifiedWorkerRelease,
): Promise<string> {
  const call = {
    accessToken: input.accessToken,
    transport: (request: Request) => input.transport(request),
  };
  try {
    const sessionIntent = await prepareAssetUploadSessionMutation(prepared);
    const session = await submitAssetUploadSessionMutation(sessionIntent, call);
    let completionJwt = session.uploadJwt;
    for (let index = 0; index < session.buckets.length; index += 1) {
      const intent = await prepareAssetBucketMutation(session, index);
      const submitted = await submitAssetBucketMutation(intent, session, prepared, call);
      if (submitted.isFinal) completionJwt = submitted.completionJwt;
    }
    return completionJwt;
  } catch {
    fail('provider_rejected', 'assets_upload');
  }
}

function uploadMetadata(
  prepared: PreparedVerifiedWorkerRelease,
  completionJwt: string,
  target: CustomerRuntimeUpdateTarget,
): BoundaryObject {
  const inherited = ['ADMIN_STATE', 'ANKKA_GATEWAY_OWNERSHIP_WRAP_KEY'].map((name) => Object.freeze({
    name,
    type: 'inherit' as const,
    version_id: 'latest',
  }));
  const plain = EXACT_PLAIN_TEXT_BINDINGS.map((name) => Object.freeze({
    name,
    type: 'plain_text' as const,
    text: prepared.plainTextBindings[name],
  }));
  return Object.freeze({
    annotations: Object.freeze({
      'workers/message': `Ankka runtime ${target.release}`,
      'workers/tag': `ankka-runtime-${target.release}`,
    }),
    assets: Object.freeze({
      config: Object.freeze({
        not_found_handling: 'single-page-application',
        run_worker_first: [...RUN_WORKER_FIRST],
      }),
      jwt: completionJwt,
    }),
    bindings: Object.freeze([...inherited, { name: 'ASSETS', type: 'assets' as const }, ...plain].sort((left, right) =>
      left.name < right.name ? -1 : left.name > right.name ? 1 : 0)),
    compatibility_date: COMPATIBILITY_DATE,
    compatibility_flags: Object.freeze([]),
    exports: Object.freeze({
      AdminState: Object.freeze({ type: 'durable-object', storage: 'sqlite' }),
    }),
    main_module: MAIN_MODULE,
  });
}

/**
 * The script upload that replaces this Worker. It activates on return; the
 * caller must already have handed over, and must not touch its own storage
 * afterwards. Secrets and the object namespace are inherited explicitly.
 */
async function uploadScript(
  input: CustomerRuntimeUpdateInput,
  prepared: PreparedVerifiedWorkerRelease,
  completionJwt: string,
): Promise<void> {
  const form = new FormData();
  form.append('metadata', new Blob([canonicalJson(uploadMetadata(prepared, completionJwt, input.target))], {
    type: 'application/json',
  }), 'metadata.json');
  for (const module of prepared.modules) {
    const owned = new Uint8Array(module.bytes.byteLength);
    owned.set(module.bytes);
    form.append(module.name, new Blob([owned], { type: module.contentType }), module.name);
  }
  const url = accountUrl(input.accountId, `/workers/scripts/${encodeURIComponent(input.workerName)}`);
  url.searchParams.set('bindings_inherit', 'strict');
  let status = 0;
  let accepted = false;
  try {
    await withDeadline(async (signal) => {
      const response = await input.transport(url, {
        method: 'PUT',
        headers: { accept: 'application/json', authorization: `Bearer ${input.accessToken}` },
        body: form,
        redirect: 'manual',
        signal,
      });
      status = response.status;
      const bytes = await readBoundedBytes(response, MAX_RESPONSE_BYTES);
      const parsed = v.safeParse(envelopeSchema, JSON.parse(new TextDecoder().decode(bytes)));
      accepted = status === 200 && parsed.success;
    }, 'internal_error');
  } catch {
    fail('upload_unknown', 'script_upload');
  }
  if (!accepted) fail(status === 0 ? 'upload_unknown' : 'provider_rejected', 'script_upload');
}

function validate(input: CustomerRuntimeUpdateInput): void {
  let origin: URL;
  try {
    origin = new URL(input.controlPlaneOrigin);
  } catch {
    fail('invalid', 'begin');
  }
  if (!ACCOUNT_ID.test(input.accountId) || !WORKER_NAME.test(input.workerName) ||
      origin.origin !== input.controlPlaneOrigin || origin.protocol !== 'https:' ||
      !RELEASE.test(input.target.release) || !ARTIFACT.test(input.target.artifactSha256) ||
      !KEY_ID.test(input.updateKeyId) || !TOKEN.test(input.updatePublicKey) ||
      input.accessToken.length < 16 || input.accessToken.length > 8192) {
    fail('invalid', 'begin');
  }
}

async function require(input: CustomerRuntimeUpdateInput, command: CustomerRuntimeControlCommand, stage: CustomerRuntimeUpdateStage): Promise<void> {
  let accepted = false;
  try {
    accepted = await input.control(command);
  } catch {
    accepted = false;
  }
  if (!accepted) fail('control_rejected', stage);
}

export async function runCustomerRuntimeUpdate(
  input: CustomerRuntimeUpdateInput,
): Promise<CustomerRuntimeUpdateResult> {
  validate(input);
  await require(input, { command: 'begin' }, 'begin');
  let uploaded = false;
  try {
    const current = await readCurrentRuntime(input);
    await require(input, {
      command: 'progress', stage: 'current_verified', fromVersionId: current.versionId, toVersionId: null,
    }, 'current_read');
    const bundle = await loadTargetBundle(input);
    let prepared: PreparedVerifiedWorkerRelease;
    try {
      const direct = await adaptVerifiedReleaseBundleForWorkerDirectUpload(bundle);
      if (direct.release !== input.target.release ||
          `sha256:${direct.artifactSha256}` !== input.target.artifactSha256) fail('release_invalid', 'release_prepare');
      prepared = await prepareVerifiedWorkerRelease({
        accountId: input.accountId,
        workerName: input.workerName,
        release: direct,
        plainTextBindings: Object.freeze({
          ...current.bindings,
          ANKKA_GATEWAY_RELEASE: input.target.release,
          ANKKA_GATEWAY_RELEASE_SHA256: input.target.artifactSha256,
        }),
        bootstrapNonce: NO_BOOTSTRAP_NONCE,
      });
    } catch (error) {
      if (error instanceof CustomerRuntimeUpdateError) throw error;
      fail('release_invalid', 'release_prepare');
    }
    const completionJwt = await uploadAssets(input, prepared);
    await require(input, {
      command: 'progress', stage: 'assets_uploaded', fromVersionId: current.versionId, toVersionId: null,
    }, 'assets_upload');
    try {
      await input.armHandover({ fromVersionId: current.versionId });
    } catch {
      fail('invalid', 'handover');
    }
    // From here on this object may restart on the new version at any moment.
    uploaded = true;
    await uploadScript(input, prepared, completionJwt);
    return Object.freeze({ status: 'uploaded', fromVersionId: current.versionId });
  } catch (error) {
    const failure = error instanceof CustomerRuntimeUpdateError
      ? error
      : new CustomerRuntimeUpdateError('invalid', 'begin');
    if (!uploaded) {
      try {
        await input.control({
          command: 'fail', failureCode: `runtime_${failure.stage}_${failure.code}`, recoveryRequired: false,
        });
      } catch {
        // The provider failure is what the caller reports; the journal keeps its last stage.
      }
    }
    throw failure;
  }
}

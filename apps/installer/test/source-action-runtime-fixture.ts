import * as v from 'valibot';

import type { JsonObject } from '../src/boundary';
import {
  prepareVerifiedWorkerRelease,
  prepareWorkerDeploymentMutation,
  prepareWorkerVersionRecoveryRecord,
  type GatewayWorkerPlainTextBindings,
} from '../src/cloudflare-worker-direct-upload';
import { REQUIRED_OAUTH_SCOPES } from '../src/constants';
import type { ExactReleaseBundleIdentity } from '../src/exact-release-bundle';
import { adaptVerifiedReleaseBundleForWorkerDirectUpload } from '../src/release-direct-upload-adapter';
import type { VerifiedReleaseBundle, VerifiedReleasePayloadBlob } from '../src/release';
import {
  APPROVED_CLOUDFLARE_RELEASE_CONTRACT,
  canonicalJson,
  parseReleaseManifest,
} from '../src/release-manifest';

interface FileInput {
  readonly component: 'admin' | 'installer' | 'worker' | 'workerCleanup' | 'workerRetirement';
  readonly path: string;
  readonly contentType: string;
  readonly bytes: Uint8Array;
}

async function sha256(value: Uint8Array | string): Promise<string> {
  const bytes = v.is(v.string(), value) ? new TextEncoder().encode(value) : value;
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', new Uint8Array(bytes)));
  return [...digest].map((byte) => byte.toString(16).padStart(2, '0')).join('');
}

function base64(bytes: Uint8Array): string {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

export interface SourceActionRuntimeFixture {
  readonly bundle: VerifiedReleaseBundle;
  readonly identity: ExactReleaseBundleIdentity;
  readonly bindings: GatewayWorkerPlainTextBindings;
  readonly versionResult: (versionId: string, moduleBytes?: Uint8Array) => JsonObject;
  readonly deploymentResult: (
    deploymentId: string,
    versionId: string,
  ) => Promise<JsonObject>;
}

export async function sourceActionRuntimeFixture(input: Readonly<{
  accountId: string;
  actorEmail: string;
  managementHostname: string;
  workerId: string;
  workerName: string;
  workersSubdomain: string;
}>): Promise<SourceActionRuntimeFixture> {
  const encoder = new TextEncoder();
  const files: readonly FileInput[] = [
    { component: 'admin', path: 'payload/admin/index.html', contentType: 'text/html; charset=utf-8', bytes: encoder.encode('<!doctype html><title>Gateway</title>') },
    { component: 'installer', path: 'payload/installer/index.html', contentType: 'text/html; charset=utf-8', bytes: encoder.encode('<!doctype html><title>Installer</title>') },
    { component: 'worker', path: 'payload/worker/index.js', contentType: 'application/javascript+module', bytes: encoder.encode('export default { fetch() { return new Response("ok") } };') },
    { component: 'workerCleanup', path: 'payload/worker-cleanup/index.js', contentType: 'application/javascript+module', bytes: encoder.encode('export default { fetch() { return new Response("cleanup") } };') },
    { component: 'workerRetirement', path: 'payload/worker-retirement/index.js', contentType: 'application/javascript+module', bytes: encoder.encode('export default { fetch() { return new Response("retired") } };') },
  ];
  const snapshots = await Promise.all(files.map(async (file) => Object.freeze({
    ...file,
    record: Object.freeze({
      byteSize: file.bytes.byteLength,
      contentType: file.contentType,
      path: file.path,
      sha256: await sha256(file.bytes),
    }),
  })));
  const component = async (name: FileInput['component']) => {
    const selected = snapshots.filter((file) => file.component === name);
    const records = selected.map((file) => file.record);
    return Object.freeze({
      byteSize: selected.reduce((sum, file) => sum + file.bytes.byteLength, 0),
      fileCount: selected.length,
      files: Object.freeze(records),
      treeSha256: await sha256(canonicalJson(records)),
    });
  };
  const records = snapshots.map((file) => file.record).sort((left, right) => (
    left.path < right.path ? -1 : left.path > right.path ? 1 : 0
  ));
  const manifest = parseReleaseManifest({
    artifact: {
      byteSize: snapshots.reduce((sum, file) => sum + file.bytes.byteLength, 0),
      fileCount: snapshots.length,
      treeSha256: await sha256(canonicalJson(records)),
    },
    cloudflare: APPROVED_CLOUDFLARE_RELEASE_CONTRACT,
    components: {
      admin: await component('admin'),
      installer: await component('installer'),
      worker: await component('worker'),
      workerCleanup: await component('workerCleanup'),
      workerRetirement: await component('workerRetirement'),
    },
    oauthScopeIds: REQUIRED_OAUTH_SCOPES,
    release: 'gateway-v1.0.0',
    schemaVersion: 1,
    sourceCommit: '0123456789abcdef0123456789abcdef01234567',
  });
  const payload = Object.freeze(snapshots.map((file): VerifiedReleasePayloadBlob => Object.freeze({
    ...file.record,
    bytes: new Blob([new Uint8Array(file.bytes)], { type: file.contentType }),
  })));
  const channel = 'canary';
  const bundle: VerifiedReleaseBundle = Object.freeze({
    verification: 'ed25519',
    channel,
    keyId: 'source-action-test-key',
    envelope: Object.freeze({
      schemaVersion: 2,
      channel,
      keyId: 'source-action-test-key',
      manifest: canonicalJson(manifest),
      signature: 'A'.repeat(86),
      signatureContext: 'ankka-mcp-gateway-release-envelope-v2',
    }),
    manifest,
    payload,
    publicKey: 'A'.repeat(43),
  });
  const identity: ExactReleaseBundleIdentity = Object.freeze({
    schemaVersion: 1,
    channel,
    release: manifest.release,
    keyId: bundle.keyId,
    publicKey: bundle.publicKey,
    artifactSha256: manifest.artifact.treeSha256,
  });
  const bindings: GatewayWorkerPlainTextBindings = Object.freeze({
    ADMIN_EMAILS: input.actorEmail,
    ANKKA_GATEWAY_RELEASE: identity.release,
    ANKKA_GATEWAY_RELEASE_SHA256: `sha256:${identity.artifactSha256}`,
    ANKKA_MANAGEMENT_HOSTNAME: input.managementHostname,
    ANKKA_UPDATE_CHANNEL: identity.channel,
    ANKKA_UPDATE_KEY_ID: identity.keyId,
    ANKKA_UPDATE_PUBLIC_KEY: identity.publicKey,
    ANKKA_WORKERS_SUBDOMAIN: input.workersSubdomain,
    ANKKA_WORKER_NAME: input.workerName,
    CF_ACCESS_AUD: 'access-audience-tag',
    CF_ACCESS_ISSUER: 'https://customer.cloudflareaccess.com',
    CLOUDFLARE_ACCOUNT_ID: input.accountId,
    CLOUDFLARE_ZONE_ID: 'c'.repeat(32),
    CLOUDFLARE_ZONE_NAME: 'example.com',
    ZERO_TRUST_READY: 'true',
  });
  const direct = await adaptVerifiedReleaseBundleForWorkerDirectUpload(bundle);
  const prepared = await prepareVerifiedWorkerRelease({
    accountId: input.accountId,
    workerName: input.workerName,
    release: direct,
    plainTextBindings: bindings,
    bootstrapNonce: 'A'.repeat(43),
  });
  const recovery = await prepareWorkerVersionRecoveryRecord(prepared, Object.freeze({
    kind: 'worker' as const,
    accountId: input.accountId,
    workerName: input.workerName,
    workerId: input.workerId,
  }), 'clean');
  const workerModule = direct.worker.modules.find((module) => module.name === 'index.js');
  if (!workerModule) throw new TypeError('source_action_runtime_fixture');

  return Object.freeze({
    bundle,
    identity,
    bindings,
    versionResult: (versionId: string, moduleBytes = workerModule.bytes) => Object.freeze({
      annotations: Object.freeze({ 'workers/tag': recovery.correlationTag }),
      assets: Object.freeze({
        config: Object.freeze({
          not_found_handling: 'single-page-application',
          run_worker_first: Object.freeze(['/__ankka/*', '/api/*']),
        }),
      }),
      bindings: Object.freeze([
        Object.freeze({ name: 'ADMIN_STATE', type: 'durable_object_namespace', class_name: 'AdminState' }),
        Object.freeze({ name: 'ASSETS', type: 'assets' }),
        ...Object.entries(bindings).map(([name, text]) => Object.freeze({ name, text, type: 'plain_text' })),
      ]),
      compatibility_date: '2026-08-08',
      created_on: '2026-08-26T00:00:00.000Z',
      exports: Object.freeze({ AdminState: Object.freeze({ type: 'durable-object', storage: 'sqlite' }) }),
      id: versionId,
      main_module: 'index.js',
      modules: Object.freeze([Object.freeze({
        name: workerModule.name,
        content_type: workerModule.contentType,
        content_base64: base64(moduleBytes),
      })]),
      number: 1,
    }),
    deploymentResult: async (deploymentId: string, versionId: string) => {
      const intent = await prepareWorkerDeploymentMutation(Object.freeze({
        kind: 'version' as const,
        phase: 'clean' as const,
        accountId: input.accountId,
        workerName: input.workerName,
        workerId: input.workerId,
        versionId,
        requestHash: recovery.requestHash,
        correlationTag: recovery.correlationTag,
      }));
      return Object.freeze({
        annotations: Object.freeze({ 'workers/message': intent.correlationTag }),
        created_on: '2026-08-26T00:00:00.000Z',
        id: deploymentId,
        source: 'api',
        strategy: 'percentage',
        versions: Object.freeze([Object.freeze({ percentage: 100, version_id: versionId })]),
      });
    },
  });
}

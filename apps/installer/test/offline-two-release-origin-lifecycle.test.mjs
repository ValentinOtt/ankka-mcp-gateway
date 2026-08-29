import { generateKeyPairSync } from 'node:crypto';
import { readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

import { describe, expect, it } from 'vitest';

import {
  buildReleaseCandidate,
  writeReleaseCandidate,
} from '../scripts/build-gateway-release-candidate.mjs';
import { generateReviewedIsolatedCanaryArtifacts } from '../scripts/generate-reviewed-canary.mjs';
import {
  prepareSignedReleasePublishPlan,
  writeSignedReleasePublishDirectory,
} from '../scripts/sign-gateway-release.mjs';
import { createR2PublicationOperator } from '../src/r2-publication-operator';
import {
  ExactR2ReleaseBundleProvider,
  PinnedR2ReleaseBundleProvider,
} from '../src/r2-release-provider';
import { publishCreateOnlyR2Release } from '../src/r2-release-publisher';
import { parseCanonicalReleaseManifest } from '../src/release-manifest';
import { parsePublicUpdateChannel } from '../src/update-channel';
import { durableNamespace } from '../../../test/payload-lifecycle.mjs';
import {
  FIXTURE_PAYLOAD,
  fixtureGit,
  releaseCandidateCheckout,
} from './release-candidate-fixture.mjs';

const RELEASE_A = 'gateway-v9.8.0';
const RELEASE_B = 'gateway-v9.8.1';
const CHANNEL = 'canary';
const KEY_ID = 'offline-lifecycle-key-1';
const ACCOUNT_ID = '1'.repeat(32);
const ZONE_ID = '2'.repeat(32);
const BUCKET_NAME = 'ankka-gateway-release-offline-proof';
const HOSTNAME = 'installer-lifecycle.canary.example.net';
const CONTROL_PLANE_ORIGIN = `https://${HOSTNAME}`;
const MANAGEMENT_ORIGIN = 'https://manage.example.com';
const JSON_CONTENT_TYPE = 'application/json; charset=utf-8';

function copyBytes(value) {
  const copy = new Uint8Array(value.byteLength);
  copy.set(value);
  return copy;
}

class SharedCreateOnlyR2Bucket {
  constructor() {
    this.objects = new Map();
    this.putCalls = [];
  }

  async put(key, value, options) {
    this.putCalls.push({ key, options });
    if (options.onlyIf.get('if-none-match') !== '*') {
      throw new Error('offline bucket requires create-only writes');
    }
    if (this.objects.has(key)) return null;
    this.objects.set(key, {
      bytes: copyBytes(value),
      contentType: options.httpMetadata.contentType,
      customMetadata: { ...options.customMetadata },
    });
    const stored = this.objects.get(key);
    return {
      key,
      size: stored.bytes.byteLength,
      httpMetadata: { contentType: stored.contentType },
      customMetadata: { ...stored.customMetadata },
    };
  }

  async get(key) {
    const stored = this.objects.get(key);
    if (!stored) return null;
    const bytes = copyBytes(stored.bytes);
    return {
      key,
      size: bytes.byteLength,
      httpMetadata: { contentType: stored.contentType },
      customMetadata: { ...stored.customMetadata },
      async arrayBuffer() {
        return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength);
      },
    };
  }

  async list(options) {
    const offset = options.cursor ? Number(options.cursor) : 0;
    const keys = [...this.objects.keys()]
      .filter((key) => key.startsWith(options.prefix))
      .sort();
    const selected = keys.slice(offset, offset + options.limit);
    const next = offset + selected.length;
    const objects = selected.map((key) => ({
      key,
      size: this.objects.get(key).bytes.byteLength,
    }));
    return next < keys.length
      ? { objects, truncated: true, cursor: String(next) }
      : { objects, truncated: false };
  }
}

function signingMaterial() {
  const pair = generateKeyPairSync('ed25519');
  const privateDer = pair.privateKey.export({ format: 'der', type: 'pkcs8' });
  const publicDer = pair.publicKey.export({ format: 'der', type: 'spki' });
  const seed = Buffer.from(privateDer.subarray(privateDer.byteLength - 32));
  const publicKey = Buffer.from(publicDer.subarray(publicDer.byteLength - 32)).toString('base64url');
  privateDer.fill(0);
  publicDer.fill(0);
  return Object.freeze({ seed, publicKey });
}

async function signedRelease(checkout, release, candidateDirectory, publishDirectory, material) {
  const candidate = await buildReleaseCandidate({
    controlPlaneOrigin: CONTROL_PLANE_ORIGIN,
    release,
    sourceCommit: fixtureGit(checkout.source, 'rev-parse', 'HEAD'),
    sourceDirectory: checkout.source,
  });
  const releaseDirectory = await writeReleaseCandidate(candidate, candidateDirectory);
  const prepared = await prepareSignedReleasePublishPlan({
    channel: CHANNEL,
    keyId: KEY_ID,
    privateKeySeed: Buffer.from(material.seed),
    publicKey: material.publicKey,
    release,
    releaseDirectory,
  });
  await writeSignedReleasePublishDirectory(prepared, publishDirectory);
  return Object.freeze({ candidate, prepared, publishDirectory });
}

async function publicationBlobs(release) {
  return Object.freeze(await Promise.all(release.prepared.objectPlan.objects.map(async (object) => (
    Object.freeze({
      key: object.key,
      bytes: new Blob(
        [await readFile(path.join(release.publishDirectory, ...object.sourcePath.split('/')))],
        { type: object.contentType },
      ),
    })
  ))));
}

function publicationIdentity(release, publicKey) {
  return Object.freeze({
    schemaVersion: 1,
    accountId: ACCOUNT_ID,
    artifactSha256: release.prepared.artifactSha256,
    bucketName: BUCKET_NAME,
    channel: CHANNEL,
    controlPlaneOrigin: CONTROL_PLANE_ORIGIN,
    keyId: KEY_ID,
    objectPlanSha256: release.prepared.objectPlanSha256,
    prefix: release.prepared.objectPlan.prefix,
    publicKey,
    release: release.prepared.release,
    releaseEnvelopeSha256: release.prepared.releaseEnvelopeSha256,
  });
}

async function publishThroughOperator(release, publicKey, bucket) {
  const identity = publicationIdentity(release, publicKey);
  const operator = createR2PublicationOperator({
    blobs: await publicationBlobs(release),
    objectPlan: release.prepared.objectPlan,
    objectPlanSha256: release.prepared.objectPlanSha256,
    publicationIdentity: identity,
    publish: publishCreateOnlyR2Release,
  });
  const response = await operator.fetch(new Request(
    `http://127.0.0.1/__ankka/publish/${release.prepared.objectPlanSha256}`,
    { method: 'POST' },
  ), { RELEASE_BUCKET: bucket });
  expect(response.status).toBe(200);
  return Object.freeze(await response.json());
}

function pin(release, publicKey) {
  return Object.freeze({
    schemaVersion: 1,
    channel: CHANNEL,
    controlPlaneOrigin: CONTROL_PLANE_ORIGIN,
    release: release.prepared.release,
    keyId: KEY_ID,
    publicKey,
    artifactSha256: release.prepared.artifactSha256,
  });
}

async function generatedWorker(outputDirectory) {
  const moduleUrl = pathToFileURL(path.join(outputDirectory, 'reviewed-canary-worker.mjs'));
  return (await import(`${moduleUrl.href}?offline-lifecycle=${path.basename(outputDirectory)}`)).default;
}

function reviewedEnvironment(bucket) {
  const rateLimit = Object.freeze({ async limit() { return { success: true }; } });
  return {
    GATEWAY_RELEASE_BUCKET: bucket,
    GATEWAY_DEPLOY_SESSION: {
      idFromName() { throw new Error('offline lifecycle did not create a hosted session'); },
      get() { throw new Error('offline lifecycle did not create a hosted session'); },
    },
    ANONYMOUS_SESSION_RATE_LIMIT: rateLimit,
    SESSION_READ_RATE_LIMIT: rateLimit,
    SESSION_MUTATION_RATE_LIMIT: rateLimit,
    CLOUDFLARE_OAUTH_CLIENT_ID: '3'.repeat(32),
    CLOUDFLARE_OAUTH_CLIENT_SECRET: 'synthetic-test-only',
    DEPLOY_SESSION_ENCRYPTION_KEY: Buffer.alloc(32, 7).toString('base64url'),
    BOOTSTRAP_NONCE_DERIVATION_KEY: Buffer.alloc(32, 8).toString('base64url'),
  };
}

function managementRequest(claim) {
  return new Request(`${CONTROL_PLANE_ORIGIN}/api/management/authorize`, {
    method: 'POST',
    headers: {
      'cf-connecting-ip': '192.0.2.10',
      'content-type': JSON_CONTENT_TYPE,
      origin: CONTROL_PLANE_ORIGIN,
      'sec-fetch-site': 'same-origin',
    },
    body: JSON.stringify({
      handoff: Buffer.from(JSON.stringify(claim)).toString('base64url'),
    }),
  });
}

function sharedManagementClaim(actionCharacter) {
  return {
    actionId: `action_${actionCharacter.repeat(32)}`,
    actionKey: Buffer.alloc(32, actionCharacter.charCodeAt(0)).toString('base64url'),
    actorEmail: 'admin@example.com',
    accountId: ACCOUNT_ID,
    controlPlaneOrigin: CONTROL_PLANE_ORIGIN,
    workerName: 'ankka-gateway-offline',
    workersSubdomain: 'offline-tenant',
    managementOrigin: MANAGEMENT_ORIGIN,
    expiresAt: Date.now() + 5 * 60 * 1000,
  };
}

function base64UrlJson(value) {
  return Buffer.from(JSON.stringify(value)).toString('base64url');
}

async function accessAssertion(privateKey, kid) {
  const header = base64UrlJson({ alg: 'RS256', kid, typ: 'JWT' });
  const payload = base64UrlJson({
    aud: 'offline-access-audience',
    email: 'admin@example.com',
    exp: Math.floor(Date.now() / 1000) + 300,
    iss: 'https://offline-tenant.cloudflareaccess.com',
  });
  const message = `${header}.${payload}`;
  const signature = await crypto.subtle.sign(
    'RSASSA-PKCS1-v1_5',
    privateKey,
    new TextEncoder().encode(message),
  );
  return `${message}.${Buffer.from(signature).toString('base64url')}`;
}

describe('offline two-release signed origin lifecycle', () => {
  it('publishes A/B create-only, repins to B, discovers B from A, retains exact A rollback, and origin-binds handoffs', async () => {
    const checkout = await releaseCandidateCheckout({
      ...FIXTURE_PAYLOAD,
      'payload/worker/index.js': await readFile(new URL('../../../payload/worker/index.js', import.meta.url), 'utf8'),
    });
    const material = signingMaterial();
    const bucket = new SharedCreateOnlyR2Bucket();
    const originalFetch = globalThis.fetch;
    try {
      const releaseA = await signedRelease(
        checkout,
        RELEASE_A,
        path.join(checkout.sandbox, 'candidate-a'),
        path.join(checkout.sandbox, 'publish-a'),
        material,
      );
      await writeFile(
        path.join(checkout.source, 'payload/installer/index.html'),
        '<main>installer release B</main>',
      );
      fixtureGit(checkout.source, 'add', 'payload/installer/index.html');
      fixtureGit(checkout.source, 'commit', '-q', '-m', 'release B payload');
      const releaseB = await signedRelease(
        checkout,
        RELEASE_B,
        path.join(checkout.sandbox, 'candidate-b'),
        path.join(checkout.sandbox, 'publish-b'),
        material,
      );
      expect(releaseA.prepared.artifactSha256).not.toBe(releaseB.prepared.artifactSha256);

      const receiptA = await publishThroughOperator(releaseA, material.publicKey, bucket);
      const aKeys = new Set(bucket.objects.keys());
      const receiptB = await publishThroughOperator(releaseB, material.publicKey, bucket);
      expect([...aKeys].every((key) => bucket.objects.has(key))).toBe(true);
      expect(bucket.putCalls.every(
        ({ options }) => options.onlyIf.get('if-none-match') === '*',
      )).toBe(true);
      expect([receiptA, receiptB]).toEqual([
        expect.objectContaining({
          accountId: ACCOUNT_ID,
          bucketName: BUCKET_NAME,
          channel: CHANNEL,
          controlPlaneOrigin: CONTROL_PLANE_ORIGIN,
          keyId: KEY_ID,
          publicKey: material.publicKey,
          release: RELEASE_A,
          status: 'published',
        }),
        expect.objectContaining({
          accountId: ACCOUNT_ID,
          bucketName: BUCKET_NAME,
          channel: CHANNEL,
          controlPlaneOrigin: CONTROL_PLANE_ORIGIN,
          keyId: KEY_ID,
          publicKey: material.publicKey,
          release: RELEASE_B,
          status: 'published',
        }),
      ]);

      const pinA = pin(releaseA, material.publicKey);
      const pinB = pin(releaseB, material.publicKey);
      const bundleA = await new PinnedR2ReleaseBundleProvider(pinA)
        .loadVerifiedReleaseBundle(bucket);
      const bundleB = await new PinnedR2ReleaseBundleProvider(pinB)
        .loadVerifiedReleaseBundle(bucket);
      expect(bundleA.manifest.controlPlaneOrigin).toBe(CONTROL_PLANE_ORIGIN);
      expect(bundleB.manifest.controlPlaneOrigin).toBe(CONTROL_PLANE_ORIGIN);
      expect(bundleA.publicKey).toBe(bundleB.publicKey);

      await expect(new PinnedR2ReleaseBundleProvider({
        ...pinA,
        controlPlaneOrigin: 'https://foreign-control.example',
      }).loadVerifiedReleaseBundle(bucket)).rejects.toMatchObject({ code: 'release_invalid' });
      await expect(new PinnedR2ReleaseBundleProvider({
        ...pinA,
        channel: 'stable',
      }).loadVerifiedReleaseBundle(bucket)).rejects.toMatchObject({ code: 'release_unavailable' });
      await expect(new PinnedR2ReleaseBundleProvider({
        ...pinA,
        keyId: 'foreign-key',
      }).loadVerifiedReleaseBundle(bucket)).rejects.toMatchObject({ code: 'release_invalid' });
      await expect(new PinnedR2ReleaseBundleProvider(pinA)
        .loadVerifiedReleaseBundle(new SharedCreateOnlyR2Bucket()))
        .rejects.toMatchObject({ code: 'release_unavailable' });

      const isolatedTarget = Object.freeze({
        accountId: ACCOUNT_ID,
        hostname: HOSTNAME,
        kind: 'ankka-gateway-deploy-isolated-target',
        oauthClientId: '3'.repeat(32),
        schemaVersion: 1,
        workerName: 'ankka-gateway-deploy-isolated-lifecycle-proof',
      });
      const reviewedA = path.join(checkout.sandbox, 'reviewed-a');
      const reviewedB = path.join(checkout.sandbox, 'reviewed-b');
      await generateReviewedIsolatedCanaryArtifacts({
        isolatedTarget,
        outputDirectory: reviewedA,
        pin: pinA,
        publicationResult: receiptA,
      });
      await generateReviewedIsolatedCanaryArtifacts({
        isolatedTarget,
        outputDirectory: reviewedB,
        pin: pinB,
        publicationResult: receiptB,
      });
      const workerA = await generatedWorker(reviewedA);
      const workerB = await generatedWorker(reviewedB);
      const reviewedEnv = reviewedEnvironment(bucket);
      const descriptorAResponse = await workerA.fetch(
        new Request(`${CONTROL_PLANE_ORIGIN}/api/releases/${CHANNEL}`), reviewedEnv,
      );
      const descriptorBResponse = await workerB.fetch(
        new Request(`${CONTROL_PLANE_ORIGIN}/api/releases/${CHANNEL}`), reviewedEnv,
      );
      expect(descriptorAResponse.status).toBe(200);
      expect(descriptorBResponse.status).toBe(200);
      expect(parsePublicUpdateChannel(await descriptorAResponse.json()).release.id).toBe(RELEASE_A);
      const descriptorB = parsePublicUpdateChannel(await descriptorBResponse.json());
      expect(descriptorB.release.id).toBe(RELEASE_B);
      expect(parseCanonicalReleaseManifest(descriptorB.verification.manifest).controlPlaneOrigin)
        .toBe(CONTROL_PLANE_ORIGIN);

      const workerPayloadA = bundleA.payload.find(({ path: payloadPath }) => (
        payloadPath === 'payload/worker/index.js'
      ));
      if (!workerPayloadA) throw new Error('signed release A worker missing');
      const customerWorkerPath = path.join(checkout.sandbox, 'customer-release-a.mjs');
      await writeFile(customerWorkerPath, await workerPayloadA.bytes.text(), { flag: 'wx' });
      const customerA = await import(`${pathToFileURL(customerWorkerPath).href}?release=a`);
      const accessKeys = await crypto.subtle.generateKey(
        {
          name: 'RSASSA-PKCS1-v1_5',
          modulusLength: 2048,
          publicExponent: new Uint8Array([1, 0, 1]),
          hash: 'SHA-256',
        },
        true,
        ['sign', 'verify'],
      );
      const accessKid = 'offline-access-key';
      const accessJwk = await crypto.subtle.exportKey('jwk', accessKeys.publicKey);
      const assertion = await accessAssertion(accessKeys.privateKey, accessKid);
      const customerEnv = {
        CLOUDFLARE_ACCOUNT_ID: ACCOUNT_ID,
        CLOUDFLARE_ZONE_ID: ZONE_ID,
        CLOUDFLARE_ZONE_NAME: 'example.com',
        ANKKA_GATEWAY_RELEASE: RELEASE_A,
        ANKKA_GATEWAY_RELEASE_SHA256: `sha256:${pinA.artifactSha256}`,
        ANKKA_MANAGEMENT_HOSTNAME: 'manage.example.com',
        ANKKA_UPDATE_CHANNEL: CHANNEL,
        ANKKA_UPDATE_KEY_ID: KEY_ID,
        ANKKA_UPDATE_PUBLIC_KEY: material.publicKey,
        ANKKA_WORKERS_SUBDOMAIN: 'offline-tenant',
        ANKKA_WORKER_NAME: 'ankka-gateway-offline',
        ZERO_TRUST_READY: 'true',
        ADMIN_EMAILS: 'admin@example.com',
        CF_ACCESS_AUD: 'offline-access-audience',
        CF_ACCESS_ISSUER: 'https://offline-tenant.cloudflareaccess.com',
      };
      customerEnv.ADMIN_STATE = durableNamespace(customerEnv, customerA.AdminState);
      globalThis.fetch = async (input, init) => {
        const request = input instanceof Request ? input : new Request(input, init);
        if (request.url === 'https://offline-tenant.cloudflareaccess.com/cdn-cgi/access/certs') {
          return new Response(JSON.stringify({
            keys: [{ ...accessJwk, kid: accessKid, alg: 'RS256', use: 'sig' }],
          }), { headers: { 'content-type': JSON_CONTENT_TYPE } });
        }
        if (request.url === `${CONTROL_PLANE_ORIGIN}/api/releases/${CHANNEL}`) {
          return workerB.fetch(request, reviewedEnv);
        }
        throw new Error(`offline lifecycle blocked unexpected fetch ${request.url}`);
      };
      const updateResponse = await customerA.default.fetch(new Request(`${MANAGEMENT_ORIGIN}/api/update`, {
        headers: {
          'cf-access-authenticated-user-email': 'admin@example.com',
          'cf-access-jwt-assertion': assertion,
        },
      }), customerEnv);
      expect(updateResponse.status).toBe(200);
      expect(await updateResponse.json()).toMatchObject({
        schemaVersion: 1,
        channel: CHANNEL,
        status: 'available',
        current: { release: RELEASE_A, artifactSha256: `sha256:${pinA.artifactSha256}` },
        available: { release: RELEASE_B, artifactSha256: `sha256:${pinB.artifactSha256}` },
      });
      globalThis.fetch = originalFetch;

      const historicalA = await new ExactR2ReleaseBundleProvider()
        .loadVerifiedReleaseBundleForIdentity(bucket, pinA);
      expect(historicalA.manifest.release).toBe(RELEASE_A);
      expect(historicalA.manifest.controlPlaneOrigin).toBe(CONTROL_PLANE_ORIGIN);
      expect([...bucket.objects.keys()].some((key) => key.startsWith(
        `ankka-mcp-gateway/releases/${CHANNEL}/${RELEASE_A}/`,
      ))).toBe(true);

      const rollback = await workerB.fetch(managementRequest({
        schemaVersion: 2,
        actionType: 'runtime_update',
        ...sharedManagementClaim('R'),
        operation: 'rollback',
        from: {
          release: RELEASE_B,
          artifactSha256: `sha256:${pinB.artifactSha256}`,
          versionId: null,
        },
        to: {
          release: RELEASE_A,
          artifactSha256: `sha256:${pinA.artifactSha256}`,
          versionId: null,
        },
      }), reviewedEnv);
      expect(rollback.status).toBe(200);

      const sourceClaim = {
        schemaVersion: 1,
        ...sharedManagementClaim('S'),
        releaseIdentity: pinA,
      };
      const source = await workerB.fetch(managementRequest(sourceClaim), reviewedEnv);
      expect(source.status).toBe(200);
      expect(new URL((await source.json()).authorizationUrl).origin).toBe('https://dash.cloudflare.com');
      const crossedSourceIdentity = await workerB.fetch(managementRequest({
        ...sourceClaim,
        releaseIdentity: { ...pinA, controlPlaneOrigin: 'https://foreign-control.example' },
      }), reviewedEnv);
      expect(crossedSourceIdentity.status).toBe(400);
      expect(await crossedSourceIdentity.json()).toEqual({ code: 'bad_request' });

      const removalClaim = {
        schemaVersion: 3,
        actionType: 'gateway_teardown',
        ...sharedManagementClaim('T'),
        installationId: `acg-${'d'.repeat(24)}`,
        gatewayName: 'Offline gateway',
        portalHostname: 'mcp.example.com',
      };
      const boundRemoval = await workerB.fetch(managementRequest(removalClaim), reviewedEnv);
      expect(boundRemoval.status).toBe(401);
      expect(await boundRemoval.json()).toEqual({ code: 'session_invalid' });
      const crossedRemoval = await workerB.fetch(managementRequest({
        ...removalClaim,
        controlPlaneOrigin: 'https://foreign-control.example',
      }), reviewedEnv);
      expect(crossedRemoval.status).toBe(400);
      expect(await crossedRemoval.json()).toEqual({ code: 'bad_request' });
    } finally {
      globalThis.fetch = originalFetch;
      material.seed.fill(0);
      await checkout.cleanup();
    }
  });
});

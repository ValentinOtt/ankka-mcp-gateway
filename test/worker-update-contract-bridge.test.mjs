import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

import {
  APPROVED_CLOUDFLARE_CONTRACT,
  RELEASE_ENVELOPE_SCHEMA_VERSION,
  RELEASE_SIGNATURE_CONTEXT,
  REQUIRED_OAUTH_SCOPES,
  canonicalJson,
  releaseSignatureCanonicalJson,
} from '../apps/installer/scripts/sign-gateway-release.mjs';

const workerSource = await readFile(new URL('../payload/worker/index.js', import.meta.url), 'utf8');
assert.doesNotMatch(workerSource, /REVIEWED_TEAM_UPDATE_CLOUDFLARE_CONTRACT/u);
const verifier = await import(`data:text/javascript;base64,${Buffer.from(
  `${workerSource}\nexport { APPROVED_UPDATE_CLOUDFLARE_CONTRACT, parseSignedUpdateManifest, verifyUpdateEnvelope };\n`,
).toString('base64')}`);
const runtimeContract = verifier.APPROVED_UPDATE_CLOUDFLARE_CONTRACT;
const retiredTeamContract = structuredClone(runtimeContract);
retiredTeamContract.publicBindings.secrets.push({
  lifecycle: 'customer-managed-optional', name: 'ANKKA_TEAM_MANAGEMENT_TOKEN',
});
const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');

function manifestFor(cloudflare = runtimeContract) {
  const components = {};
  for (const [name, directory] of [
    ['admin', 'admin'], ['installer', 'installer'], ['worker', 'worker'],
    ['workerBootstrap', 'worker-bootstrap'],
    ['workerCleanup', 'worker-cleanup'], ['workerRetirement', 'worker-retirement'],
  ]) {
    const body = `// synthetic ${directory}\n`;
    const files = [{
      byteSize: Buffer.byteLength(body), contentType: 'application/javascript+module',
      path: `payload/${directory}/index.js`, sha256: sha256(body),
    }];
    components[name] = {
      byteSize: files[0].byteSize, fileCount: 1, files, treeSha256: sha256(canonicalJson(files)),
    };
  }
  const files = Object.values(components).flatMap((component) => component.files)
    .sort((left, right) => left.path < right.path ? -1 : left.path > right.path ? 1 : 0);
  return {
    artifact: {
      byteSize: files.reduce((total, file) => total + file.byteSize, 0),
      fileCount: files.length, treeSha256: sha256(canonicalJson(files)),
    },
    cloudflare, components, controlPlaneOrigin: 'https://deploy.ankka.ai',
    oauthScopeIds: REQUIRED_OAUTH_SCOPES, release: 'gateway-v0.1.20',
    schemaVersion: 1, sourceCommit: 'b'.repeat(40),
  };
}

function signedManifest(manifest) {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const serialized = canonicalJson(manifest);
  const environment = {
    updateChannel: 'canary', updateKeyId: 'test-v1-key',
    updatePublicKey: publicKey.export({ format: 'der', type: 'spki' }).subarray(-32).toString('base64url'),
  };
  return {
    environment,
    envelope: {
      algorithm: 'ed25519', channel: environment.updateChannel, keyId: environment.updateKeyId,
      manifest: serialized, schemaVersion: RELEASE_ENVELOPE_SCHEMA_VERSION,
      signatureContext: RELEASE_SIGNATURE_CONTEXT,
      signature: sign(null, Buffer.from(releaseSignatureCanonicalJson(
        environment.updateChannel, environment.updateKeyId, serialized,
      )), privateKey).toString('base64url'),
    },
  };
}

test('the signer and runtime accept one exact V1 contract without a standing Team secret', async () => {
  assert.deepEqual(APPROVED_CLOUDFLARE_CONTRACT, runtimeContract);
  assert.deepEqual(APPROVED_CLOUDFLARE_CONTRACT.publicBindings.secrets, [
    { lifecycle: 'customer-worker', name: 'ANKKA_GATEWAY_OWNERSHIP_WRAP_KEY' },
  ]);
  const manifest = manifestFor();
  const { envelope, environment } = signedManifest(manifest);
  assert.deepEqual(await verifier.verifyUpdateEnvelope(envelope, environment), manifest);
});

test('the runtime rejects the retired optional Team-secret contract', async () => {
  const manifest = manifestFor(retiredTeamContract);
  const { envelope, environment } = signedManifest(manifest);
  assert.equal(await verifier.verifyUpdateEnvelope(envelope, environment), null);
});

test('the runtime rejects every unreviewed contract change', async () => {
  const changes = [
    ['unknown contract field', (value) => { value.unreviewed = true; }],
    ['unknown binding field', (value) => { value.publicBindings.unreviewed = []; }],
    ['extra secret', (value) => { value.publicBindings.secrets.push({ lifecycle: 'customer-managed-optional', name: 'OTHER_TOKEN' }); }],
    ['missing ownership secret', (value) => { value.publicBindings.secrets.shift(); }],
    ['extra variable', (value) => { value.publicBindings.variables.push('UNREVIEWED'); }],
    ['different DO class', (value) => { value.durableObjects.bindings[0].className = 'OtherState'; }],
    ['different compatibility date', (value) => { value.compatibilityDate = '2026-08-09'; }],
    ['enabled observability', (value) => { value.observability.enabled = true; }],
    ['bootstrap change', (value) => { value.workerVariants.bootstrap.workersDev = true; }],
    ['cleanup change', (value) => { value.workerVariants.cleanup.workersDev = true; }],
  ];
  for (const [label, change] of changes) {
    const contract = structuredClone(runtimeContract);
    change(contract);
    const { envelope, environment } = signedManifest(manifestFor(contract));
    assert.equal(await verifier.verifyUpdateEnvelope(envelope, environment), null, label);
  }
});

test('an alternate contract cannot replace the signed contract without a new signature', async () => {
  const manifest = manifestFor();
  const { envelope, environment } = signedManifest(manifest);
  assert.equal(await verifier.verifyUpdateEnvelope({
    ...envelope, manifest: canonicalJson({ ...manifest, cloudflare: retiredTeamContract }),
  }, environment), null);
  for (const change of [
    { channel: 'stable' }, { keyId: 'other-key' }, { signatureContext: 'unreviewed' },
  ]) {
    assert.equal(await verifier.verifyUpdateEnvelope({ ...envelope, ...change }, environment), null);
  }
});

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
const legacyCondition = 'canonicalJson(value.cloudflare) !== canonicalJson(APPROVED_UPDATE_CLOUDFLARE_CONTRACT)';
const bridgeCondition = `(${legacyCondition} &&
       canonicalJson(value.cloudflare) !== canonicalJson(REVIEWED_TEAM_UPDATE_CLOUDFLARE_CONTRACT))`;
assert.equal(workerSource.split(bridgeCondition).length, 2);
const legacySource = workerSource.replace(bridgeCondition, legacyCondition);
const parserStart = legacySource.indexOf('async function parseSignedUpdateManifest(');
const parserEnd = legacySource.indexOf('\nasync function verifyUpdateEnvelope(', parserStart);
const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');

// Pin the restored parser to the actual published v16 function, not a permissive mock.
assert.equal(sha256(legacySource.slice(parserStart, parserEnd)),
  '227281610ef0289c75ae2871c7116860cd2e35c5cc204d34bdb500f0e7b301ae');
const importVerifier = (source) => import(`data:text/javascript;base64,${Buffer.from(
  `${source}\nexport { APPROVED_UPDATE_CLOUDFLARE_CONTRACT, parseSignedUpdateManifest, verifyUpdateEnvelope };\n`,
).toString('base64')}`);
const [bridge, legacy] = await Promise.all([importVerifier(workerSource), importVerifier(legacySource)]);
const legacyContract = bridge.APPROVED_UPDATE_CLOUDFLARE_CONTRACT;
const teamContract = structuredClone(legacyContract);
teamContract.publicBindings.secrets.push({
  lifecycle: 'customer-managed-optional', name: 'ANKKA_TEAM_MANAGEMENT_TOKEN',
});

function manifestFor(cloudflare = legacyContract) {
  const components = {};
  for (const [name, directory] of [
    ['admin', 'admin'], ['installer', 'installer'], ['worker', 'worker'],
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
    oauthScopeIds: REQUIRED_OAUTH_SCOPES, release: 'gateway-v0.1.17',
    schemaVersion: 1, sourceCommit: 'b'.repeat(40),
  };
}

function signedManifest(manifest) {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const serialized = canonicalJson(manifest);
  const environment = {
    updateChannel: 'canary', updateKeyId: 'test-bridge-key',
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

test('v16 and bridge verifiers accept the unchanged legacy bridge signing contract', async () => {
  assert.deepEqual(legacyContract.publicBindings.secrets, [
    { lifecycle: 'bootstrap-only', name: 'ANKKA_BOOTSTRAP_NONCE' },
  ]);
  const manifest = manifestFor();
  const { envelope, environment } = signedManifest(manifest);
  for (const verifier of [legacy, bridge]) {
    assert.deepEqual(await verifier.verifyUpdateEnvelope(envelope, environment), manifest);
  }
});

test('only bridge accepts the reviewed Team contract and preserves its signed identity', async () => {
  const manifest = { ...manifestFor(teamContract), release: 'gateway-v0.1.18' };
  const { envelope, environment } = signedManifest(manifest);
  assert.equal(await legacy.verifyUpdateEnvelope(envelope, environment), null);
  const parsed = await bridge.verifyUpdateEnvelope(envelope, environment);
  assert.deepEqual(parsed, manifest);
  assert.equal(canonicalJson(parsed.cloudflare), canonicalJson(teamContract));
  assert.notEqual(canonicalJson(parsed.cloudflare), canonicalJson(legacyContract));
});

test('bridge rejects unreviewed contract changes, including secret lifecycle and extra bindings', async () => {
  const changes = [
    ['unknown contract field', (value) => { value.unreviewed = true; }],
    ['unknown binding field', (value) => { value.publicBindings.unreviewed = []; }],
    ['extra secret', (value) => { value.publicBindings.secrets.push({ lifecycle: 'customer-managed-optional', name: 'OTHER_TOKEN' }); }],
    ['wrong secret name', (value) => { value.publicBindings.secrets[1].name = 'OTHER_TOKEN'; }],
    ['required secret', (value) => { value.publicBindings.secrets[1].lifecycle = 'customer-managed'; }],
    ['secret extra field', (value) => { value.publicBindings.secrets[1].required = false; }],
    ['duplicate secret', (value) => { value.publicBindings.secrets.push(value.publicBindings.secrets[1]); }],
    ['missing bootstrap secret', (value) => { value.publicBindings.secrets.shift(); }],
    ['reordered secrets', (value) => { value.publicBindings.secrets.reverse(); }],
    ['extra variable', (value) => { value.publicBindings.variables.push('UNREVIEWED'); }],
    ['different DO class', (value) => { value.durableObjects.bindings[0].className = 'OtherState'; }],
    ['different compatibility date', (value) => { value.compatibilityDate = '2026-08-09'; }],
    ['enabled observability', (value) => { value.observability.enabled = true; }],
    ['cleanup change', (value) => { value.workerVariants.cleanup.workersDev = true; }],
  ];
  for (const [label, change] of changes) {
    const contract = structuredClone(teamContract);
    change(contract);
    const { envelope, environment } = signedManifest(manifestFor(contract));
    assert.equal(await bridge.verifyUpdateEnvelope(envelope, environment), null, label);
    assert.equal(await legacy.verifyUpdateEnvelope(envelope, environment), null, label);
  }
});

test('an alternate reviewed contract cannot replace the signed contract without a new signature', async () => {
  const manifest = manifestFor();
  const { envelope, environment } = signedManifest(manifest);
  assert.equal(await bridge.verifyUpdateEnvelope({
    ...envelope, manifest: canonicalJson({ ...manifest, cloudflare: teamContract }),
  }, environment), null);
  for (const change of [
    { channel: 'stable' }, { keyId: 'other-key' }, { signatureContext: 'unreviewed' },
  ]) {
    assert.equal(await bridge.verifyUpdateEnvelope({ ...envelope, ...change }, environment), null);
  }
});

test('bridge declares compatibility without provisioning or activating the Team credential', () => {
  assert.equal(workerSource.split('ANKKA_TEAM_MANAGEMENT_TOKEN').length, 2);
  assert.match(workerSource, /lifecycle: 'customer-managed-optional', name: 'ANKKA_TEAM_MANAGEMENT_TOKEN'/u);
  assert.doesNotMatch(workerSource, /env(?:\.|\[['"])ANKKA_TEAM_MANAGEMENT_TOKEN/u);
  assert.deepEqual(APPROVED_CLOUDFLARE_CONTRACT.publicBindings.secrets, [
    { lifecycle: 'bootstrap-only', name: 'ANKKA_BOOTSTRAP_NONCE' },
  ]);
});

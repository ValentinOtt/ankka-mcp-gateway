import { createHash, generateKeyPairSync, verify as ed25519Verify } from 'node:crypto';
import { Readable, Writable } from 'node:stream';
import {
  chmod,
  link,
  lstat,
  mkdir,
  mkdtemp,
  readFile,
  rm,
  symlink,
  writeFile,
} from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import {
  APPROVED_CLOUDFLARE_CONTRACT,
  REQUIRED_OAUTH_SCOPES,
  RELEASE_ENVELOPE_SCHEMA_VERSION,
  RELEASE_SIGNATURE_CONTEXT,
  canonicalJson,
  prepareSignedReleasePublishPlan,
  releaseSignatureCanonicalJson,
  runReleaseSigningCli,
  writeSignedReleasePublishDirectory,
} from '../scripts/sign-gateway-release.mjs';

const RELEASE = 'gateway-v1.2.3';
const CHANNEL = 'canary';
const KEY_ID = 'gateway-release-canary-1';

const EXPECTED_CLOUDFLARE_SCOPE_IDS = REQUIRED_OAUTH_SCOPES;
const CLOUDFLARE = APPROVED_CLOUDFLARE_CONTRACT;

function sha256(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

async function file(relativePath, contentType, contents) {
  const bytes = Buffer.from(contents);
  return {
    bytes,
    record: Object.freeze({
      byteSize: bytes.byteLength,
      contentType,
      path: relativePath,
      sha256: sha256(bytes),
    }),
  };
}

function component(files) {
  const records = files.map((entry) => entry.record);
  return Object.freeze({
    byteSize: records.reduce((total, record) => total + record.byteSize, 0),
    fileCount: records.length,
    files: Object.freeze(records),
    treeSha256: sha256(Buffer.from(canonicalJson(records))),
  });
}

function signingKey() {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const pkcs8 = privateKey.export({ format: 'der', type: 'pkcs8' });
  const spki = publicKey.export({ format: 'der', type: 'spki' });
  const seed = Buffer.from(pkcs8.subarray(pkcs8.byteLength - 32));
  const rawPublic = Buffer.from(spki.subarray(spki.byteLength - 32));
  pkcs8.fill(0);
  spki.fill(0);
  return {
    privateKey,
    publicKeyObject: publicKey,
    publicKey: rawPublic.toString('base64url'),
    seed,
  };
}

async function releaseFixture(overrides = {}) {
  const sandbox = await mkdtemp(path.join(os.tmpdir(), 'gateway-sign-test-'));
  const releaseDirectory = path.join(sandbox, 'public-release');
  await mkdir(releaseDirectory);
  const source = [
    await file('payload/admin/assets/app-A1b2C3d4.js', 'text/javascript; charset=utf-8', 'admin'),
    await file('payload/admin/index.html', 'text/html; charset=utf-8', '<main>admin</main>'),
    await file('payload/installer/assets/app-E5f6G7h8.js', 'text/javascript; charset=utf-8', 'installer'),
    await file('payload/installer/index.html', 'text/html; charset=utf-8', '<main>installer</main>'),
    await file(
      'payload/worker-bootstrap/index.js',
      'application/javascript+module',
      'export class AdminState {}; export default {}',
    ),
    await file(
      'payload/worker-cleanup/index.js',
      'application/javascript+module',
      'export class AdminState {}; export default {}',
    ),
    await file(
      'payload/worker-retirement/index.js',
      'application/javascript+module',
      'export default {}',
    ),
    await file('payload/worker/index.js', 'application/javascript+module', '// ankka-control-plane-origin:https://deploy.ankka.ai\nexport default {}'),
  ];
  const components = {
    admin: component(source.slice(0, 2)),
    installer: component(source.slice(2, 4)),
    worker: component(source.slice(7, 8)),
    workerBootstrap: component(source.slice(4, 5)),
    workerCleanup: component(source.slice(5, 6)),
    workerRetirement: component(source.slice(6, 7)),
  };
  const records = source.map((entry) => entry.record);
  const manifestObject = {
    artifact: {
      byteSize: records.reduce((total, record) => total + record.byteSize, 0),
      fileCount: records.length,
      treeSha256: sha256(Buffer.from(canonicalJson(records))),
    },
    cloudflare: CLOUDFLARE,
    controlPlaneOrigin: 'https://deploy.ankka.ai',
    components,
    oauthScopeIds: EXPECTED_CLOUDFLARE_SCOPE_IDS,
    release: RELEASE,
    schemaVersion: 1,
    sourceCommit: '0123456789abcdef0123456789abcdef01234567',
  };
  const manifest = canonicalJson(manifestObject);
  await writeFile(path.join(releaseDirectory, 'manifest.json'), overrides.manifest ?? manifest);
  for (const entry of source) {
    const target = path.join(releaseDirectory, ...entry.record.path.split('/'));
    await mkdir(path.dirname(target), { recursive: true });
    await writeFile(target, entry.bytes);
  }
  return {
    sandbox,
    releaseDirectory,
    manifest,
    manifestObject,
    source,
    async cleanup() {
      await chmod(sandbox, 0o700).catch(() => {});
      await rm(sandbox, { recursive: true, force: true });
    },
  };
}

async function prepare(input, key = signingKey()) {
  const seed = Buffer.from(key.seed);
  const prepared = await prepareSignedReleasePublishPlan({
    channel: CHANNEL,
    keyId: KEY_ID,
    privateKeySeed: seed,
    publicKey: key.publicKey,
    release: RELEASE,
    releaseDirectory: input.releaseDirectory,
  });
  return { prepared, seed, key };
}

async function replacePayloadAndRebuildManifest(input, targetPath, contents) {
  const bytes = Buffer.from(contents);
  const raw = JSON.parse(input.manifest);
  let replaced = false;
  for (const componentName of [
    'admin',
    'installer',
    'worker',
    'workerBootstrap',
    'workerCleanup',
    'workerRetirement',
  ]) {
    const componentValue = raw.components[componentName];
    for (const record of componentValue.files) {
      if (record.path !== targetPath) continue;
      record.byteSize = bytes.byteLength;
      record.sha256 = sha256(bytes);
      replaced = true;
    }
    componentValue.byteSize = componentValue.files.reduce((total, record) => total + record.byteSize, 0);
    componentValue.treeSha256 = sha256(Buffer.from(canonicalJson(componentValue.files)));
  }
  if (!replaced) throw new Error('fixture target missing');
  const records = [
    ...raw.components.admin.files,
    ...raw.components.installer.files,
    ...raw.components.workerBootstrap.files,
    ...raw.components.workerCleanup.files,
    ...raw.components.workerRetirement.files,
    ...raw.components.worker.files,
  ];
  raw.artifact.byteSize = records.reduce((total, record) => total + record.byteSize, 0);
  raw.artifact.treeSha256 = sha256(Buffer.from(canonicalJson(records)));
  const serialized = canonicalJson(raw);
  await writeFile(path.join(input.releaseDirectory, 'manifest.json'), serialized);
  await writeFile(path.join(input.releaseDirectory, ...targetPath.split('/')), bytes);
  return serialized;
}

function captureWritable() {
  let value = '';
  const stream = new Writable({
    write(chunk, _encoding, callback) {
      value += chunk.toString();
      callback();
    },
  });
  return { stream, read: () => value };
}

describe('offline gateway release signing and R2 object plan', () => {
  it('signs the exact canonical manifest and consumes the caller seed', async () => {
    const input = await releaseFixture();
    try {
      const { prepared, seed, key } = await prepare(input);
      expect([...seed]).toEqual(Array.from({ length: 32 }, () => 0));
      expect(prepared).toMatchObject({
        schemaVersion: 1,
        release: RELEASE,
        channel: CHANNEL,
        keyId: KEY_ID,
        artifactSha256: input.manifestObject.artifact.treeSha256,
      });
      expect(Object.isFrozen(prepared)).toBe(true);
      expect(Object.isFrozen(prepared.objectPlan)).toBe(true);
      expect(prepared.objectPlan).toMatchObject({
        prefix: `ankka-mcp-gateway/releases/${CHANNEL}/${RELEASE}/`,
        objectCount: input.source.length + 1,
        immutability: {
          externalAtomicCreateOnlyRequired: true,
          overwriteAllowed: false,
        },
      });
      const envelope = JSON.parse(prepared.releaseEnvelopeCanonicalJson);
      expect(canonicalJson(envelope)).toBe(prepared.releaseEnvelopeCanonicalJson);
      expect(envelope).toEqual({
        channel: CHANNEL,
        keyId: KEY_ID,
        manifest: input.manifest,
        schemaVersion: RELEASE_ENVELOPE_SCHEMA_VERSION,
        signature: expect.stringMatching(/^[A-Za-z0-9_-]{86}$/u),
        signatureContext: RELEASE_SIGNATURE_CONTEXT,
      });
      expect(ed25519Verify(
        null,
        Buffer.from(releaseSignatureCanonicalJson(
          envelope.channel,
          envelope.keyId,
          envelope.manifest,
        )),
        key.publicKeyObject,
        Buffer.from(envelope.signature, 'base64url'),
      )).toBe(true);
      expect(ed25519Verify(
        null,
        Buffer.from(envelope.manifest),
        key.publicKeyObject,
        Buffer.from(envelope.signature, 'base64url'),
      )).toBe(false);
      // Verify using the exact public key derived alongside the consumed seed.
      const derivedPublic = Buffer.concat([
        Buffer.from('302a300506032b6570032100', 'hex'),
        Buffer.from(key.publicKey, 'base64url'),
      ]);
      expect(ed25519Verify(
        null,
        Buffer.from(releaseSignatureCanonicalJson(
          envelope.channel,
          envelope.keyId,
          envelope.manifest,
        )),
        { key: derivedPublic, format: 'der', type: 'spki' },
        Buffer.from(envelope.signature, 'base64url'),
      )).toBe(true);
    } finally {
      await input.cleanup();
    }
  });

  it('emits a fresh verified local publish tree and writes the canonical plan last', async () => {
    const input = await releaseFixture();
    try {
      const { prepared } = await prepare(input);
      const output = path.join(input.sandbox, 'publish-ready');
      const result = await writeSignedReleasePublishDirectory(prepared, output);
      expect(result.objectCount).toBe(input.source.length + 1);
      expect(await readFile(result.objectPlanPath, 'utf8')).toBe(prepared.objectPlanCanonicalJson);
      const envelopeObject = prepared.objectPlan.objects.find((entry) => entry.key.endsWith('/release-envelope.json'));
      expect(await readFile(path.join(output, ...envelopeObject.sourcePath.split('/')), 'utf8'))
        .toBe(prepared.releaseEnvelopeCanonicalJson);
      for (const object of prepared.objectPlan.objects) {
        const bytes = await readFile(path.join(output, ...object.sourcePath.split('/')));
        expect(bytes.byteLength).toBe(object.byteSize);
        expect(sha256(bytes)).toBe(object.sha256);
      }
      await expect(writeSignedReleasePublishDirectory(prepared, output)).rejects.toMatchObject({
        code: 'release_signing_failed',
      });
    } finally {
      await input.cleanup();
    }
  });

  it('does not include the local plan itself in the immutable R2 object set', async () => {
    const input = await releaseFixture();
    try {
      const { prepared } = await prepare(input);
      expect(prepared.objectPlan.objects.every((entry) => entry.key !== 'r2-object-plan.json')).toBe(true);
      expect(prepared.objectPlan.objects.every((entry) => entry.sourcePath.startsWith('objects/ankka-mcp-gateway/releases/'))).toBe(true);
      expect(prepared.objectPlan.objects.map((entry) => entry.key)).toEqual(
        prepared.objectPlan.objects.map((entry) => entry.key).sort(),
      );
      expect(canonicalJson(prepared.objectPlan)).toBe(prepared.objectPlanCanonicalJson);
    } finally {
      await input.cleanup();
    }
  });

  it('rejects the wrong private key and still wipes the supplied seed', async () => {
    const input = await releaseFixture();
    const expected = signingKey();
    const wrong = signingKey();
    const seed = Buffer.from(wrong.seed);
    try {
      await expect(prepareSignedReleasePublishPlan({
        channel: CHANNEL,
        keyId: KEY_ID,
        privateKeySeed: seed,
        publicKey: expected.publicKey,
        release: RELEASE,
        releaseDirectory: input.releaseDirectory,
      })).rejects.toMatchObject({ code: 'release_signing_failed', message: 'Release signing failed' });
      expect([...seed]).toEqual(Array.from({ length: 32 }, () => 0));
    } finally {
      await input.cleanup();
    }
  });

  it.each([
    ['tampered payload', async (input) => {
      await writeFile(path.join(input.releaseDirectory, 'payload/installer/index.html'), 'tampered');
    }],
    ['extra payload file', async (input) => {
      await writeFile(path.join(input.releaseDirectory, 'payload/installer/extra.js'), 'extra');
    }],
    ['payload symlink', async (input) => {
      await symlink(
        path.join(input.releaseDirectory, 'payload/installer/index.html'),
        path.join(input.releaseDirectory, 'payload/installer/linked.html'),
      );
    }],
    ['extra empty directory', async (input) => {
      await mkdir(path.join(input.releaseDirectory, 'payload/installer/extra'));
    }],
    ['extra release-root file', async (input) => {
      await writeFile(path.join(input.releaseDirectory, 'unexpected.txt'), 'extra');
    }],
  ])('rejects an inexact or unsafe public tree: %s', async (_label, mutate) => {
    const input = await releaseFixture();
    try {
      await mutate(input);
      const key = signingKey();
      const seed = Buffer.from(key.seed);
      await expect(prepareSignedReleasePublishPlan({
        channel: CHANNEL,
        keyId: KEY_ID,
        privateKeySeed: seed,
        publicKey: key.publicKey,
        release: RELEASE,
        releaseDirectory: input.releaseDirectory,
      })).rejects.toMatchObject({ code: 'release_signing_failed' });
      expect([...seed]).toEqual(Array.from({ length: 32 }, () => 0));
    } finally {
      await input.cleanup();
    }
  });

  it('rejects a noncanonical or mismatched rich manifest before signing', async () => {
    const input = await releaseFixture();
    try {
      await writeFile(path.join(input.releaseDirectory, 'manifest.json'), `${input.manifest}\n`);
      const key = signingKey();
      await expect(prepareSignedReleasePublishPlan({
        channel: CHANNEL,
        keyId: KEY_ID,
        privateKeySeed: Buffer.from(key.seed),
        publicKey: key.publicKey,
        release: RELEASE,
        releaseDirectory: input.releaseDirectory,
      })).rejects.toMatchObject({ code: 'release_signing_failed' });
    } finally {
      await input.cleanup();
    }
  });

  it('independently rejects a manifest origin that differs from the embedded Worker origin', async () => {
    const input = await releaseFixture();
    try {
      const manifest = JSON.parse(input.manifest);
      manifest.controlPlaneOrigin = 'https://foreign-control.example';
      await writeFile(
        path.join(input.releaseDirectory, 'manifest.json'),
        canonicalJson(manifest),
      );
      const key = signingKey();
      const seed = Buffer.from(key.seed);
      await expect(prepareSignedReleasePublishPlan({
        channel: CHANNEL,
        keyId: KEY_ID,
        privateKeySeed: seed,
        publicKey: key.publicKey,
        release: RELEASE,
        releaseDirectory: input.releaseDirectory,
      })).rejects.toMatchObject({ code: 'release_signing_failed' });
      expect([...seed]).toEqual(Array.from({ length: 32 }, () => 0));
    } finally {
      await input.cleanup();
    }
  });

  it('independently rejects credential-like payload content even when every signed digest is self-consistent', async () => {
    const input = await releaseFixture();
    try {
      const secret = 'sk_test_value_that_must_not_be_signed';
      await replacePayloadAndRebuildManifest(
        input,
        'payload/installer/assets/app-E5f6G7h8.js',
        `const clientSecret = "${secret}";`,
      );
      const key = signingKey();
      const seed = Buffer.from(key.seed);
      const error = await prepareSignedReleasePublishPlan({
        channel: CHANNEL,
        keyId: KEY_ID,
        privateKeySeed: seed,
        publicKey: key.publicKey,
        release: RELEASE,
        releaseDirectory: input.releaseDirectory,
      }).catch((caught) => caught);
      expect(error).toMatchObject({ code: 'release_signing_failed', message: 'Release signing failed' });
      expect(error.message).not.toContain(secret);
      expect([...seed]).toEqual(Array.from({ length: 32 }, () => 0));
    } finally {
      await input.cleanup();
    }
  });

  it('rejects a hard-linked payload file rather than signing mutable aliasing', async () => {
    const input = await releaseFixture();
    try {
      const target = path.join(input.releaseDirectory, 'payload/admin/index.html');
      await link(target, path.join(input.sandbox, 'outside-hardlink'));
      const key = signingKey();
      await expect(prepareSignedReleasePublishPlan({
        channel: CHANNEL,
        keyId: KEY_ID,
        privateKeySeed: Buffer.from(key.seed),
        publicKey: key.publicKey,
        release: RELEASE,
        releaseDirectory: input.releaseDirectory,
      })).rejects.toMatchObject({ code: 'release_signing_failed' });
    } finally {
      await input.cleanup();
    }
  });

  it('rejects unknown call fields and malformed release/channel/key bindings while consuming a supplied seed', async () => {
    const input = await releaseFixture();
    try {
      const key = signingKey();
      const unsupportedChannelSeed = Buffer.from(key.seed);
      await expect(prepareSignedReleasePublishPlan({
        channel: 'preview',
        keyId: KEY_ID,
        privateKeySeed: unsupportedChannelSeed,
        publicKey: key.publicKey,
        release: RELEASE,
        releaseDirectory: input.releaseDirectory,
      })).rejects.toMatchObject({ code: 'release_signing_failed' });
      expect([...unsupportedChannelSeed]).toEqual(Array.from({ length: 32 }, () => 0));

      const seed = Buffer.from(key.seed);
      await expect(prepareSignedReleasePublishPlan({
        channel: '../canary',
        keyId: KEY_ID,
        privateKeySeed: seed,
        publicKey: key.publicKey,
        release: RELEASE,
        releaseDirectory: input.releaseDirectory,
        upload: true,
      })).rejects.toMatchObject({ code: 'release_signing_failed' });
      expect([...seed]).toEqual(Array.from({ length: 32 }, () => 0));
    } finally {
      await input.cleanup();
    }
  });

  it('keeps the default CLI offline/dry-run and emits no local directory', async () => {
    const input = await releaseFixture();
    try {
      const key = signingKey();
      const stdinSeed = Buffer.from(key.seed);
      const stdout = captureWritable();
      const stderr = captureWritable();
      const output = path.join(input.sandbox, 'must-not-exist');
      const exitCode = await runReleaseSigningCli({
        argv: [
          '--release-dir', input.releaseDirectory,
          '--release', RELEASE,
          '--channel', CHANNEL,
          '--key-id', KEY_ID,
          '--public-key', key.publicKey,
          '--private-key-stdin',
        ],
        stdin: Readable.from([stdinSeed]),
        stdout: stdout.stream,
        stderr: stderr.stream,
      });
      expect(exitCode).toBe(0);
      expect(stderr.read()).toBe('');
      expect(canonicalJson(JSON.parse(stdout.read().trim()))).toBe(stdout.read().trim());
      await expect(lstat(output)).rejects.toMatchObject({ code: 'ENOENT' });
      expect([...stdinSeed]).toEqual(Array.from({ length: 32 }, () => 0));
    } finally {
      await input.cleanup();
    }
  });

  it('does not echo an argv-injected private value or create an output on CLI failure', async () => {
    const input = await releaseFixture();
    const secret = 'private-seed-must-never-echo';
    try {
      const stdout = captureWritable();
      const stderr = captureWritable();
      const exitCode = await runReleaseSigningCli({
        argv: ['--private-key', secret],
        stdin: Readable.from([]),
        stdout: stdout.stream,
        stderr: stderr.stream,
      });
      expect(exitCode).toBe(1);
      expect(stdout.read()).toBe('');
      expect(stderr.read()).toBe('Release signing failed. No live upload was attempted.\n');
      expect(stderr.read()).not.toContain(secret);
    } finally {
      await input.cleanup();
    }
  });

  it('refuses an existing output root and never offers a live upload mode', async () => {
    const input = await releaseFixture();
    try {
      const { prepared } = await prepare(input);
      const output = path.join(input.sandbox, 'existing');
      await mkdir(output);
      await writeFile(path.join(output, 'sentinel'), 'keep');
      await expect(writeSignedReleasePublishDirectory(prepared, output)).rejects.toMatchObject({
        code: 'release_signing_failed',
      });
      expect(await readFile(path.join(output, 'sentinel'), 'utf8')).toBe('keep');

      const stdout = captureWritable();
      const stderr = captureWritable();
      const exitCode = await runReleaseSigningCli({
        argv: ['--upload-live'],
        stdin: Readable.from([]),
        stdout: stdout.stream,
        stderr: stderr.stream,
      });
      expect(exitCode).toBe(1);
      expect(stderr.read()).toContain('No live upload was attempted');
    } finally {
      await input.cleanup();
    }
  });
});


describe('embedded Google authorization protocol metadata', () => {
  it('accepts only the fixed public Google token endpoint assignment', async () => {
    const input = await releaseFixture();
    try {
      await replacePayloadAndRebuildManifest(input, 'payload/worker/index.js',
        '// ankka-control-plane-origin:https://deploy.ankka.ai\nconst GOOGLE_TOKEN_ENDPOINT = "https://oauth2.googleapis.com/token"; export default {}');
      await expect(prepare(input)).resolves.toBeDefined();
    } finally { await input.cleanup(); }
  });
  it.each([
    'https://oauth2.googleapis.com/token?credential=synthetic-credential',
    'https://foreign.example.com/token',
    'synthetic-credential-value',
  ])('still rejects a credential-like assignment disguised as an endpoint: %s', async (value) => {
    const input = await releaseFixture();
    try {
      await replacePayloadAndRebuildManifest(input, 'payload/worker/index.js',
        `// ankka-control-plane-origin:https://deploy.ankka.ai\nconst GOOGLE_TOKEN_ENDPOINT = ${JSON.stringify(value)}; export default {}`);
      await expect(prepare(input)).rejects.toMatchObject({ code: 'release_signing_failed' });
    } finally { await input.cleanup(); }
  });
});

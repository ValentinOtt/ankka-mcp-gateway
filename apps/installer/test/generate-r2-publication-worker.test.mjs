import { createHash, generateKeyPairSync } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import {
  mkdir,
  mkdtemp,
  readFile,
  realpath,
  rm,
  unlink,
  writeFile,
} from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import {
  R2PublicationWorkerGenerationError,
  generateR2PublicationWorker,
  runR2PublicationWorkerGeneratorCli,
} from '../scripts/generate-r2-publication-worker.mjs';
import {
  canonicalJson,
  prepareSignedReleasePublishPlan,
  writeSignedReleasePublishDirectory,
} from '../scripts/sign-gateway-release.mjs';

const RELEASE = 'gateway-v1.2.3';
const CHANNEL = 'canary';
const KEY_ID = 'gateway-release-canary-1';
const BUCKET = 'ankka-gateway-releases';
const ACCOUNT_ID = '0123456789abcdef0123456789abcdef';

const REQUIRED_OAUTH_SCOPES = Object.freeze([
  'access-acct.write',
  'access.write',
  'account-settings.read',
  'dns.write',
  'mcp-portals.write',
  'memberships.read',
  'user-details.read',
  'workers-routes.read',
  'workers-scripts.write',
  'zone.read',
]);

const CLOUDFLARE = Object.freeze({
  assets: Object.freeze({
    binding: 'ASSETS',
    notFoundHandling: 'single-page-application',
    payloadDirectory: 'payload/admin',
    runWorkerFirst: Object.freeze(['/__ankka/*', '/api/*']),
  }),
  compatibilityDate: '2026-08-08',
  compatibilityFlags: Object.freeze([]),
  dependenciesInstrumentation: Object.freeze({ enabled: false }),
  durableObjects: Object.freeze({
    bindings: Object.freeze([Object.freeze({ binding: 'ADMIN_STATE', className: 'AdminState' })]),
    exports: Object.freeze({
      AdminState: Object.freeze({ storage: 'sqlite', type: 'durable-object' }),
    }),
  }),
  mainModule: 'index.js',
  observability: Object.freeze({ enabled: false }),
  previewUrls: false,
  publicBindings: Object.freeze({
    secrets: Object.freeze([
      Object.freeze({ lifecycle: 'bootstrap-only', name: 'ANKKA_BOOTSTRAP_NONCE' }),
      Object.freeze({ lifecycle: 'customer-managed-optional', name: 'ANKKA_TEAM_MANAGEMENT_TOKEN' }),
    ]),
    variables: Object.freeze([
      'ADMIN_EMAILS',
      'ANKKA_GATEWAY_RELEASE',
      'ANKKA_GATEWAY_RELEASE_SHA256',
      'CF_ACCESS_AUD',
      'CF_ACCESS_ISSUER',
      'CLOUDFLARE_ACCOUNT_ID',
      'CLOUDFLARE_ZONE_ID',
      'CLOUDFLARE_ZONE_NAME',
      'ANKKA_UPDATE_CHANNEL',
      'ANKKA_UPDATE_KEY_ID',
      'ANKKA_UPDATE_PUBLIC_KEY',
      'ZERO_TRUST_READY',
    ]),
  }),
  sendMetrics: false,
  workersDev: false,
  workerVariants: Object.freeze({
    cleanup: Object.freeze({
      component: 'workerCleanup',
      compatibilityDate: '2026-08-08',
      compatibilityFlags: Object.freeze([]),
      dependenciesInstrumentation: Object.freeze({ enabled: false }),
      durableObjects: Object.freeze({
        bindings: Object.freeze([Object.freeze({ binding: 'ADMIN_STATE', className: 'AdminState' })]),
        exports: Object.freeze({
          AdminState: Object.freeze({ storage: 'sqlite', type: 'durable-object' }),
        }),
      }),
      mainModule: 'index.js',
      observability: Object.freeze({ enabled: false }),
      payloadDirectory: 'payload/worker-cleanup',
      previewUrls: false,
      publicBindings: Object.freeze({
        secrets: Object.freeze([
          Object.freeze({ lifecycle: 'uninstall-attempt', name: 'ANKKA_UNINSTALL_NONCE' }),
        ]),
        variables: Object.freeze([
          'ANKKA_GATEWAY_RELEASE',
          'ANKKA_GATEWAY_RELEASE_SHA256',
          'CLOUDFLARE_ACCOUNT_ID',
          'CLOUDFLARE_ZONE_ID',
          'CLOUDFLARE_ZONE_NAME',
          'ZERO_TRUST_READY',
        ]),
      }),
      publicPath: '/__ankka/uninstall',
      sendMetrics: false,
      workersDev: false,
    }),
    retirement: Object.freeze({
      component: 'workerRetirement',
      compatibilityDate: '2026-08-08',
      compatibilityFlags: Object.freeze([]),
      dependenciesInstrumentation: Object.freeze({ enabled: false }),
      durableObjects: Object.freeze({
        bindings: Object.freeze([]),
        exports: Object.freeze({
          AdminState: Object.freeze({ state: 'deleted', type: 'durable-object' }),
        }),
      }),
      mainModule: 'index.js',
      observability: Object.freeze({ enabled: false }),
      payloadDirectory: 'payload/worker-retirement',
      previewUrls: false,
      publicBindings: Object.freeze({ secrets: Object.freeze([]), variables: Object.freeze([]) }),
      sendMetrics: false,
      workersDev: false,
    }),
  }),
});

function sha256(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

function signingKey() {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const pkcs8 = privateKey.export({ format: 'der', type: 'pkcs8' });
  const spki = publicKey.export({ format: 'der', type: 'spki' });
  const seed = Buffer.from(pkcs8.subarray(pkcs8.byteLength - 32));
  const rawPublic = Buffer.from(spki.subarray(spki.byteLength - 32));
  pkcs8.fill(0);
  spki.fill(0);
  return { seed, publicKey: rawPublic.toString('base64url') };
}

async function sourceFile(relativePath, contentType, contents) {
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

async function fixture() {
  const sandbox = await mkdtemp(path.join(os.tmpdir(), 'gateway-r2-operator-'));
  const releaseDirectory = path.join(sandbox, 'release');
  const publishDirectory = path.join(sandbox, 'publish');
  await mkdir(releaseDirectory);
  const files = [
    await sourceFile('payload/admin/index.html', 'text/html; charset=utf-8', '<main>admin</main>'),
    await sourceFile('payload/installer/index.html', 'text/html; charset=utf-8', '<main>install</main>'),
    await sourceFile(
      'payload/worker-cleanup/index.js',
      'application/javascript+module',
      'export class AdminState {}; export default {}',
    ),
    await sourceFile(
      'payload/worker-retirement/index.js',
      'application/javascript+module',
      'export default {}',
    ),
    await sourceFile('payload/worker/index.js', 'application/javascript+module', "const CONTROL_PLANE_ORIGIN = 'https://deploy.ankka.ai';\nexport default {}"),
  ];
  const records = files.map((entry) => entry.record);
  const manifest = canonicalJson({
    artifact: {
      byteSize: records.reduce((total, record) => total + record.byteSize, 0),
      fileCount: records.length,
      treeSha256: sha256(Buffer.from(canonicalJson(records))),
    },
    cloudflare: CLOUDFLARE,
    controlPlaneOrigin: 'https://deploy.ankka.ai',
    components: {
      admin: component(files.slice(0, 1)),
      installer: component(files.slice(1, 2)),
      worker: component(files.slice(4, 5)),
      workerCleanup: component(files.slice(2, 3)),
      workerRetirement: component(files.slice(3, 4)),
    },
    oauthScopeIds: REQUIRED_OAUTH_SCOPES,
    release: RELEASE,
    schemaVersion: 1,
    sourceCommit: '0123456789abcdef0123456789abcdef01234567',
  });
  await writeFile(path.join(releaseDirectory, 'manifest.json'), manifest);
  for (const entry of files) {
    const target = path.join(releaseDirectory, ...entry.record.path.split('/'));
    await mkdir(path.dirname(target), { recursive: true });
    await writeFile(target, entry.bytes);
  }
  const key = signingKey();
  const prepared = await prepareSignedReleasePublishPlan({
    channel: CHANNEL,
    keyId: KEY_ID,
    privateKeySeed: key.seed,
    publicKey: key.publicKey,
    release: RELEASE,
    releaseDirectory,
  });
  await writeSignedReleasePublishDirectory(prepared, publishDirectory);
  return {
    sandbox,
    publishDirectory,
    publicKey: key.publicKey,
    objectPlanSha256: prepared.objectPlanSha256,
    envelopeSha256: prepared.releaseEnvelopeSha256,
    async cleanup() {
      await rm(sandbox, { recursive: true, force: true });
    },
  };
}

async function readPlan(input) {
  return JSON.parse(await readFile(path.join(input.publishDirectory, 'r2-object-plan.json'), 'utf8'));
}

async function writePlan(input, plan) {
  await writeFile(path.join(input.publishDirectory, 'r2-object-plan.json'), canonicalJson(plan));
}

function generationArgs(input, outputDirectory) {
  return {
    accountId: ACCOUNT_ID,
    bucketName: BUCKET,
    inputDirectory: input.publishDirectory,
    outputDirectory,
    publicKey: input.publicKey,
  };
}

function expectGenerationFailure(promise) {
  return expect(promise).rejects.toBeInstanceOf(R2PublicationWorkerGenerationError);
}

function captureWriter() {
  let value = '';
  return {
    stream: { write: (chunk) => { value += String(chunk); } },
    read: () => value,
  };
}

describe('release-specific R2 publication Worker generator', () => {
  it('revalidates the signed tree and emits only the one remote R2 capability', async () => {
    const input = await fixture();
    try {
      const output = path.join(input.sandbox, 'operator');
      const generated = await generateR2PublicationWorker(generationArgs(input, output));
      expect(generated).toMatchObject({
        schemaVersion: 1,
        outputDirectory: await realpath(output),
        objectPlanSha256: input.objectPlanSha256,
        publicationPath: `/__ankka/publish/${input.objectPlanSha256}`,
        port: 5732,
        bucketBinding: 'RELEASE_BUCKET',
        publicationIdentity: {
          accountId: ACCOUNT_ID,
          artifactSha256: expect.stringMatching(/^[a-f0-9]{64}$/u),
          bucketName: BUCKET,
          channel: CHANNEL,
          keyId: KEY_ID,
          objectPlanSha256: input.objectPlanSha256,
          prefix: `ankka-mcp-gateway/releases/${CHANNEL}/${RELEASE}/`,
          publicKey: input.publicKey,
          release: RELEASE,
          releaseEnvelopeSha256: input.envelopeSha256,
          schemaVersion: 1,
        },
      });

      const config = await readFile(path.join(output, 'wrangler.toml'), 'utf8');
      expect(config).toContain(`account_id = "${ACCOUNT_ID}"`);
      expect(config.match(/(?:^|\n)account_id\s*=/gu)).toHaveLength(1);
      expect(config.match(/\[\[r2_buckets\]\]/gu)).toHaveLength(1);
      expect(config).toContain('binding = "RELEASE_BUCKET"');
      expect(config).toContain(`bucket_name = "${BUCKET}"`);
      expect(config).toContain('remote = true');
      expect(config).toContain('workers_dev = false');
      expect(config).toContain('preview_urls = false');
      expect(config).toContain('send_metrics = false');
      expect(config).toContain('port = 5732');
      expect(config).not.toMatch(/(?:^|\n)routes?\s*=/u);
      expect(config).not.toMatch(/oauth|secret|token/iu);
      const generatorSource = await readFile(
        new URL('../scripts/generate-r2-publication-worker.mjs', import.meta.url),
        'utf8',
      );
      expect(generatorSource).not.toMatch(/process\.env|CLOUDFLARE_ACCOUNT_ID|CF_ACCOUNT_ID/u);

      const invocation = await readFile(path.join(output, 'INVOCATION.txt'), 'utf8');
      expect(invocation).toContain("wrangler.js' dev --config wrangler.toml --ip 127.0.0.1 --port 5732");
      expect(invocation).not.toContain('npx');
      expect(invocation).not.toContain('wrangler dev --remote');
      expect(invocation).not.toContain('wrangler deploy');
      expect(invocation).toContain(`/__ankka/publish/${input.objectPlanSha256}`);

      const index = await readFile(path.join(output, 'src/index.ts'), 'utf8');
      expect(index.match(/publishCreateOnlyR2Release/gu)).toHaveLength(2);
      expect(index).not.toMatch(/Request|searchParams|request\.json|request\.text/gu);
      const publisher = await readFile(path.join(output, 'src/r2-release-publisher.ts'), 'utf8');
      expect(publisher.match(/bucket\.put\(/gu)).toHaveLength(1);
      expect(publisher).toContain("new Headers({ 'If-None-Match': '*' })");
      expect(publisher).not.toMatch(/bucket\.(?:delete|createMultipartUpload|resumeMultipartUpload)\(/gu);

      const dryRun = spawnSync(generated.wranglerExecutable, [
        'deploy',
        '--dry-run',
        '--config',
        'wrangler.toml',
        '--outdir',
        path.join(input.sandbox, 'bundle'),
      ], {
        cwd: output,
        encoding: 'utf8',
        env: {
          ...process.env,
          CF_ACCOUNT_ID: 'f'.repeat(32),
          CLOUDFLARE_ACCOUNT_ID: 'e'.repeat(32),
          WRANGLER_LOG_PATH: path.join(input.sandbox, 'wrangler-dry-run.log'),
          WRANGLER_SEND_METRICS: 'false',
        },
      });
      expect(dryRun.status, dryRun.stderr).toBe(0);
    } finally {
      await input.cleanup();
    }
  });

  it('rejects output reuse and invalid explicit bucket or public-key arguments', async () => {
    const input = await fixture();
    try {
      const output = path.join(input.sandbox, 'operator');
      await generateR2PublicationWorker(generationArgs(input, output));
      await expectGenerationFailure(generateR2PublicationWorker(generationArgs(input, output)));
      await expectGenerationFailure(generateR2PublicationWorker({
        ...generationArgs(input, path.join(input.sandbox, 'bad-bucket')),
        bucketName: '../bucket',
      }));
      await expectGenerationFailure(generateR2PublicationWorker({
        ...generationArgs(input, path.join(input.sandbox, 'bad-account-uppercase')),
        accountId: ACCOUNT_ID.toUpperCase(),
      }));
      await expectGenerationFailure(generateR2PublicationWorker({
        ...generationArgs(input, path.join(input.sandbox, 'bad-account-short')),
        accountId: ACCOUNT_ID.slice(1),
      }));
      await expectGenerationFailure(generateR2PublicationWorker({
        ...generationArgs(input, path.join(input.sandbox, 'bad-key')),
        publicKey: 'A'.repeat(43),
      }));
    } finally {
      await input.cleanup();
    }
  });

  it('requires the explicit account ID at the CLI boundary without consulting ambient account state', async () => {
    const input = await fixture();
    try {
      const stdout = captureWriter();
      const stderr = captureWriter();
      const output = path.join(input.sandbox, 'operator-cli');
      const code = await runR2PublicationWorkerGeneratorCli({
        argv: [
          '--publish-dir', input.publishDirectory,
          '--account-id', ACCOUNT_ID,
          '--bucket', BUCKET,
          '--public-key', input.publicKey,
          '--out', output,
        ],
        stdout: stdout.stream,
        stderr: stderr.stream,
      });
      expect(code).toBe(0);
      expect(stderr.read()).toBe('');
      expect(stdout.read()).toContain(input.objectPlanSha256);
      expect(await readFile(path.join(output, 'wrangler.toml'), 'utf8'))
        .toContain(`account_id = "${ACCOUNT_ID}"`);

      const missingStdout = captureWriter();
      const missingStderr = captureWriter();
      const missingCode = await runR2PublicationWorkerGeneratorCli({
        argv: [
          '--publish-dir', input.publishDirectory,
          '--bucket', BUCKET,
          '--public-key', input.publicKey,
          '--out', path.join(input.sandbox, 'operator-cli-missing-account'),
        ],
        stdout: missingStdout.stream,
        stderr: missingStderr.stream,
      });
      expect(missingCode).toBe(1);
      expect(missingStdout.read()).toBe('');
      expect(missingStderr.read()).toBe(
        'R2 publication Worker generation failed. No live call was attempted.\n',
      );
    } finally {
      await input.cleanup();
    }
  });

  it.each(['missing', 'extra', 'tampered'])('rejects a %s local object tree', async (mode) => {
    const input = await fixture();
    try {
      const plan = await readPlan(input);
      const objectPath = path.join(input.publishDirectory, ...plan.objects[0].sourcePath.split('/'));
      if (mode === 'missing') await unlink(objectPath);
      if (mode === 'extra') await writeFile(path.join(input.publishDirectory, 'objects', 'extra.txt'), 'extra');
      if (mode === 'tampered') await writeFile(objectPath, 'tampered');
      await expectGenerationFailure(generateR2PublicationWorker(
        generationArgs(input, path.join(input.sandbox, `operator-${mode}`)),
      ));
    } finally {
      await input.cleanup();
    }
  });

  it.each(['missing', 'extra', 'tampered'])('rejects a %s object-plan completion marker', async (mode) => {
    const input = await fixture();
    try {
      const planPath = path.join(input.publishDirectory, 'r2-object-plan.json');
      if (mode === 'missing') await unlink(planPath);
      if (mode === 'extra') {
        await writeFile(
          path.join(input.publishDirectory, 'r2-object-plan.copy.json'),
          await readFile(planPath),
        );
      }
      if (mode === 'tampered') {
        await writeFile(planPath, `${await readFile(planPath, 'utf8')}\n`);
      }
      await expectGenerationFailure(generateR2PublicationWorker(
        generationArgs(input, path.join(input.sandbox, `operator-plan-${mode}`)),
      ));
    } finally {
      await input.cleanup();
    }
  });

  it.each(['hash', 'path'])('rejects a canonical plan with the wrong object %s', async (mode) => {
    const input = await fixture();
    try {
      const plan = await readPlan(input);
      if (mode === 'hash') plan.objects[0].sha256 = '0'.repeat(64);
      if (mode === 'path') plan.objects[0].sourcePath = `${plan.objects[0].sourcePath}.other`;
      await writePlan(input, plan);
      await expectGenerationFailure(generateR2PublicationWorker(
        generationArgs(input, path.join(input.sandbox, `operator-${mode}`)),
      ));
    } finally {
      await input.cleanup();
    }
  });

  it('rejects a tampered envelope even when its file hash and canonical plan are updated', async () => {
    const input = await fixture();
    try {
      const plan = await readPlan(input);
      const envelope = plan.objects.find((object) => object.key.endsWith('/release-envelope.json'));
      const envelopePath = path.join(input.publishDirectory, ...envelope.sourcePath.split('/'));
      const parsed = JSON.parse(await readFile(envelopePath, 'utf8'));
      parsed.signature = `${parsed.signature.slice(0, -1)}${parsed.signature.endsWith('A') ? 'B' : 'A'}`;
      const bytes = Buffer.from(canonicalJson(parsed));
      await writeFile(envelopePath, bytes);
      envelope.byteSize = bytes.byteLength;
      envelope.sha256 = sha256(bytes);
      plan.totalByteSize = plan.objects.reduce((total, object) => total + object.byteSize, 0);
      await writePlan(input, plan);
      await expectGenerationFailure(generateR2PublicationWorker(
        generationArgs(input, path.join(input.sandbox, 'operator-signature')),
      ));
    } finally {
      await input.cleanup();
    }
  });

  it('rejects a canonical plan above the deliberately small embedded-Worker byte bound', async () => {
    const input = await fixture();
    try {
      const plan = await readPlan(input);
      const excess = 1_500_001 - plan.totalByteSize;
      plan.objects[0].byteSize += excess;
      plan.totalByteSize += excess;
      await writePlan(input, plan);
      await expectGenerationFailure(generateR2PublicationWorker(
        generationArgs(input, path.join(input.sandbox, 'operator-oversize')),
      ));
    } finally {
      await input.cleanup();
    }
  });
});

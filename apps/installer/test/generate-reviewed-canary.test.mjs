import { execFile } from 'node:child_process';
import { createHash } from 'node:crypto';
import {
  mkdtemp,
  readFile,
  readdir,
  realpath,
  rm,
  writeFile,
} from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { promisify } from 'node:util';
import { fileURLToPath } from 'node:url';
import * as v from 'valibot';
import { describe, expect, it } from 'vitest';
import {
  ReviewedCanaryGenerationError,
  generateReviewedCanaryArtifacts,
  generateReviewedIsolatedCanaryArtifacts,
  runReviewedCanaryGeneratorCli,
  validateGeneratedReviewedCanaryDirectory,
} from '../scripts/generate-reviewed-canary.mjs';
import { runReviewedIsolatedCanaryGeneratorCli } from
  '../scripts/generate-reviewed-isolated-canary.mjs';

const execFileAsync = promisify(execFile);
const APP_ROOT = fileURLToPath(new URL('../', import.meta.url));
const REPOSITORY_ROOT = fileURLToPath(new URL('../../../', import.meta.url));
const ACCOUNT_ID = '1'.repeat(32);
const GENERATED_FILES = Object.freeze([
  'reviewed-canary-record.json',
  'reviewed-canary-worker.mjs',
  'reviewed-rollback-worker.mjs',
  'wrangler.canary.toml',
  'wrangler.rollback.toml',
]);

const PIN = Object.freeze({
  schemaVersion: 1,
  channel: 'canary',
  controlPlaneOrigin: 'https://deploy.ankka.ai',
  release: 'gateway-v1.2.3',
  keyId: 'gateway-canary-key-1',
  publicKey: 'A'.repeat(43),
  artifactSha256: 'a'.repeat(64),
});

const PUBLICATION = Object.freeze({
  schemaVersion: 1,
  status: 'published',
  accountId: ACCOUNT_ID,
  bucketName: 'ankka-gateway-release-canary',
  channel: PIN.channel,
  controlPlaneOrigin: PIN.controlPlaneOrigin,
  release: PIN.release,
  prefix: `ankka-mcp-gateway/releases/${PIN.channel}/${PIN.release}/`,
  keyId: PIN.keyId,
  publicKey: PIN.publicKey,
  artifactSha256: PIN.artifactSha256,
  releaseEnvelopeSha256: 'c'.repeat(64),
  objectPlanSha256: 'b'.repeat(64),
});

const ISOLATED_TARGET = Object.freeze({
  accountId: ACCOUNT_ID,
  hostname: 'installer-proof.canary.example.net',
  kind: 'ankka-gateway-deploy-isolated-target',
  oauthClientId: '2'.repeat(32),
  schemaVersion: 1,
  workerName: 'ankka-gateway-deploy-isolated-proof',
  zoneId: '3'.repeat(32),
});
const ISOLATED_PIN = Object.freeze({
  ...PIN,
  controlPlaneOrigin: `https://${ISOLATED_TARGET.hostname}`,
});
const ISOLATED_PUBLICATION = Object.freeze({
  ...PUBLICATION,
  controlPlaneOrigin: ISOLATED_PIN.controlPlaneOrigin,
});

const canonicalRecordSchema = v.record(v.string(), v.unknown());

function canonicalJson(value) {
  if (!v.is(canonicalRecordSchema, value) && !Array.isArray(value)) return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  return `{${Object.keys(value).sort().map(
    (key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`,
  ).join(',')}}`;
}

function sha256Hex(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

function sink() {
  let value = '';
  return {
    write(chunk) {
      value += String(chunk);
    },
    value() {
      return value;
    },
  };
}

async function sandbox() {
  const root = await mkdtemp(path.join(os.tmpdir(), 'gateway-canary-test-'));
  return {
    root,
    output: path.join(root, 'new-reviewed-canary'),
    async cleanup() {
      await rm(root, { recursive: true, force: true });
    },
  };
}

async function generated(input = {}) {
  const test = await sandbox();
  const pin = input.pin ?? PIN;
  const publicationResult = input.publicationResult ?? PUBLICATION;
  try {
    const result = await generateReviewedCanaryArtifacts({
      outputDirectory: test.output,
      pin,
      publicationResult,
    });
    return { ...test, result };
  } catch (error) {
    await test.cleanup();
    throw error;
  }
}

describe('offline reviewed canary artifact generator', () => {
  it('emits self-contained pinned active and false/null rollback modules with exact configs', async () => {
    const fixture = await generated();
    try {
      const [active, canary, rollbackModule, rollback, recordText] = await Promise.all([
        readFile(path.join(fixture.output, 'reviewed-canary-worker.mjs'), 'utf8'),
        readFile(path.join(fixture.output, 'wrangler.canary.toml'), 'utf8'),
        readFile(path.join(fixture.output, 'reviewed-rollback-worker.mjs'), 'utf8'),
        readFile(path.join(fixture.output, 'wrangler.rollback.toml'), 'utf8'),
        readFile(path.join(fixture.output, 'reviewed-canary-record.json'), 'utf8'),
      ]);
      const record = JSON.parse(recordText);

      expect(fixture.result).toEqual({
        schemaVersion: 1,
        accountId: ACCOUNT_ID,
        outputDirectory: await realpath(fixture.output),
        objectPlanSha256: PUBLICATION.objectPlanSha256,
        release: PIN.release,
      });
      expect(active).toContain('TwoStageDeploySession');
      expect(active).not.toContain('GatewayDeploySession');
      expect(active).not.toContain('HOSTED_INSTALLER_ANALYTICS');
      expect(active).toContain(PIN.release);
      expect(active).toContain(PIN.publicKey);
      expect(active).toContain(PIN.artifactSha256);
      expect(active).not.toMatch(/(?:^|\n)\s*import(?:\s|\()/mu);
      expect(active).not.toContain('sourceMappingURL=');

      expect(rollbackModule).toContain('TwoStageDeploySession');
      expect(rollbackModule).not.toContain('GatewayDeploySession');
      expect(rollbackModule).toContain('enabled: false');
      expect(rollbackModule).toContain('pin: null');
      expect(rollbackModule).not.toMatch(/(?:^|\n)\s*import(?:\s|\()/mu);
      expect(rollbackModule).not.toContain('sourceMappingURL=');

      for (const config of [canary, rollback]) {
        expect(config).toMatch(/^name = "ankka-gateway-deploy"$/mu);
        expect(config).toContain(`account_id = "${ACCOUNT_ID}"`);
        expect(config).toMatch(/^no_bundle = true$/mu);
        expect(config).toMatch(/^find_additional_modules = false$/mu);
        expect(config).toMatch(/^workers_dev = false$/mu);
        expect(config).toMatch(/^preview_urls = false$/mu);
        expect(config).toContain('pattern = "deploy.ankka.ai"');
        expect(config).toContain('custom_domain = true');
        expect(config).toContain('name = "TWO_STAGE_DEPLOY_SESSION"');
        expect(config).toContain('class_name = "TwoStageDeploySession"');
        expect(config).toContain('new_sqlite_classes = ["TwoStageDeploySession"]');
        expect(config).not.toContain('GatewayDeploySession');
        expect(config).not.toContain('analytics_engine_datasets');
        expect(config.match(/^enabled = false$/gmu)).toHaveLength(3);
        expect(config).toContain('invocation_logs = false');
        expect(config.match(/^persist = false$/gmu)).toHaveLength(2);
      }
      expect(canary).toMatch(/^main = "reviewed-canary-worker\.mjs"$/mu);
      expect(canary).toContain('binding = "GATEWAY_RELEASE_BUCKET"');
      expect(canary).toContain(`bucket_name = "${PUBLICATION.bucketName}"`);
      expect(canary).toContain('CLOUDFLARE_OAUTH_CLIENT_ID = "6ace98c3cfe05f58a7fbe18f88390bfc"');
      expect(canary).not.toContain('HOSTED_INSTALLER_ANALYTICS');
      // The request-time bindings are provisioned with `wrangler secret put`;
      // the config names them in a comment only and assigns none of them.
      for (const binding of [
        'CLOUDFLARE_OAUTH_CLIENT_SECRET',
        'DEPLOY_SESSION_ENCRYPTION_KEY',
        'CLOUDFLARE_CUSTOMER_OAUTH_CLIENT_ID',
        'CLOUDFLARE_OWNERSHIP_ISSUER_PRIVATE_KEY',
        'CLOUDFLARE_OWNERSHIP_ISSUER_PUBLIC_KEY',
        'CLOUDFLARE_OWNERSHIP_ISSUER_KEY_ID',
      ]) {
        expect(canary).toMatch(new RegExp(`^# ${binding}$`, 'mu'));
        expect(canary).not.toMatch(new RegExp(`^${binding}\\s*=`, 'mu'));
      }
      expect(canary.match(/^\[\[ratelimits\]\]$/gmu)).toHaveLength(3);
      expect(canary).toContain('name = "ANONYMOUS_SESSION_RATE_LIMIT"');
      expect(canary).toContain('namespace_id = "588230349"');
      expect(canary).toContain('simple = { limit = 6, period = 60 }');
      expect(canary).toContain('name = "SESSION_READ_RATE_LIMIT"');
      expect(canary).toContain('namespace_id = "913742685"');
      expect(canary).toContain('simple = { limit = 120, period = 60 }');
      expect(canary).toContain('name = "SESSION_MUTATION_RATE_LIMIT"');
      expect(canary).toContain('namespace_id = "74228090"');
      expect(canary).toContain('simple = { limit = 30, period = 60 }');
      expect(rollback).toMatch(/^main = "reviewed-rollback-worker\.mjs"$/mu);
      expect(rollback).not.toContain('GATEWAY_RELEASE_BUCKET');
      expect(rollback).not.toContain('CLOUDFLARE_OAUTH_CLIENT_ID');
      expect(rollback).not.toContain('CLOUDFLARE_CUSTOMER_OAUTH_CLIENT_ID');
      expect(rollback).not.toContain('CLOUDFLARE_OWNERSHIP_ISSUER');
      expect(rollback).not.toContain('[[ratelimits]]');

      for (const contents of [canary, rollback, recordText]) {
        expect(contents).not.toMatch(
          /^(?:CLOUDFLARE_OAUTH_CLIENT_SECRET|DEPLOY_SESSION_ENCRYPTION_KEY|BOOTSTRAP_NONCE_DERIVATION_KEY|CLOUDFLARE_OWNERSHIP_ISSUER_PRIVATE_KEY)\s*=/mu,
        );
      }
      for (const contents of [rollback, recordText]) {
        expect(contents).not.toMatch(/CLOUDFLARE_OAUTH_CLIENT_SECRET|DEPLOY_SESSION_ENCRYPTION_KEY|OWNERSHIP_ISSUER/u);
      }
      expect(record).toMatchObject({
        kind: 'ankka-gateway-deploy-reviewed-canary',
        objectPlanSha256: PUBLICATION.objectPlanSha256,
        pin: PIN,
        publication: PUBLICATION,
        schemaVersion: 1,
        buildProvenance: {
          schemaVersion: 1,
          toolchain: {
            schemaVersion: 1,
            packageLock: { path: 'package-lock.json' },
            bundler: {
              name: 'esbuild', version: '0.28.1',
              packageFile: { path: 'node_modules/esbuild/package.json' },
              runtimeFile: { path: 'node_modules/esbuild/lib/main.js' },
              launcherFile: { path: 'node_modules/esbuild/bin/esbuild' },
              nativeBinaryFile: { path: `node_modules/@esbuild/${process.platform}-${process.arch}/bin/esbuild` },
            },
            wrangler: {
              name: 'wrangler', version: '4.127.0',
              packageFile: { path: 'node_modules/wrangler/package.json' },
              cliFile: { path: 'node_modules/wrangler/bin/wrangler.js' },
              runtimeFile: { path: 'node_modules/wrangler/wrangler-dist/cli.js' },
              schemaFile: { path: 'node_modules/wrangler/config-schema.json' },
            },
          },
        },
      });
      expect(record.buildProvenance.bundles.map((entry) => entry.kind)).toEqual(['active', 'rollback']);
      for (const bundle of record.buildProvenance.bundles) {
        expect(bundle.sourceInputs.map((entry) => entry.path)).toContain(
          'node_modules/valibot/dist/index.mjs',
        );
        const sourcePaths = bundle.sourceInputs.map((entry) => entry.path);
        expect(sourcePaths).toContain('src/two-stage-runtime.ts');
        expect(sourcePaths).toContain('src/two-stage-deploy-session.ts');
        for (const legacy of [
          'src/r2-publication-operator.ts',
          'src/reviewed-runtime.ts',
          'src/durable/gateway-deploy-session.ts',
          'src/hosted-installer-analytics.ts',
          'src/index.ts',
        ]) {
          expect(sourcePaths).not.toContain(legacy);
        }
      }
      await expect(validateGeneratedReviewedCanaryDirectory(fixture.output)).resolves.toMatchObject({
        accountId: ACCOUNT_ID,
        release: PIN.release,
      });
    } finally {
      await fixture.cleanup();
    }
  });

  it('never overwrites an existing output directory, including an identical completed output', async () => {
    const fixture = await generated();
    try {
      const before = await readFile(path.join(fixture.output, 'reviewed-canary-record.json'), 'utf8');
      await expect(generateReviewedCanaryArtifacts({
        outputDirectory: fixture.output,
        pin: PIN,
        publicationResult: PUBLICATION,
      })).rejects.toBeInstanceOf(ReviewedCanaryGenerationError);
      expect(await readFile(path.join(fixture.output, 'reviewed-canary-record.json'), 'utf8')).toBe(before);
    } finally {
      await fixture.cleanup();
    }
  });

  it('binds an exact non-live hostname, worker, and publication account into isolated output', async () => {
    const fixture = await sandbox();
    try {
      await expect(generateReviewedIsolatedCanaryArtifacts({
        isolatedTarget: ISOLATED_TARGET,
        outputDirectory: fixture.output,
        pin: ISOLATED_PIN,
        publicationResult: ISOLATED_PUBLICATION,
      })).resolves.toMatchObject({ accountId: ACCOUNT_ID, release: PIN.release, schemaVersion: 2 });
      const [canary, rollback, recordText, activeModule, rollbackModule] = await Promise.all([
        readFile(path.join(fixture.output, 'wrangler.canary.toml'), 'utf8'),
        readFile(path.join(fixture.output, 'wrangler.rollback.toml'), 'utf8'),
        readFile(path.join(fixture.output, 'reviewed-canary-record.json'), 'utf8'),
        readFile(path.join(fixture.output, 'reviewed-canary-worker.mjs'), 'utf8'),
        readFile(path.join(fixture.output, 'reviewed-rollback-worker.mjs'), 'utf8'),
      ]);
      for (const config of [canary, rollback]) {
        expect(config).toMatch(/^name = "ankka-gateway-deploy-isolated-proof"$/mu);
        expect(config).toContain('pattern = "installer-proof.canary.example.net"');
        expect(config).not.toContain('name = "ankka-gateway-deploy"');
        expect(config).not.toContain('pattern = "deploy.ankka.ai"');
      }
      const record = JSON.parse(recordText);
      expect(record).toMatchObject({
        deploymentTarget: ISOLATED_TARGET,
        kind: 'ankka-gateway-deploy-reviewed-isolated-canary',
        schemaVersion: 2,
      });
      expect(record.buildProvenance.bundles.map((bundle) => bundle.publicOrigin)).toEqual([
        `https://${ISOLATED_TARGET.hostname}`,
        `https://${ISOLATED_TARGET.hostname}`,
      ]);
      expect(canary).toContain(`CLOUDFLARE_OAUTH_CLIENT_ID = "${ISOLATED_TARGET.oauthClientId}"`);
      expect(canary).not.toContain('6ace98c3cfe05f58a7fbe18f88390bfc');
      for (const module of [activeModule, rollbackModule]) {
        expect(module).toContain(`https://${ISOLATED_TARGET.hostname}`);
        expect(module).not.toContain('https://deploy.ankka.ai');
        expect(module).toContain('/oauth/callback');
        expect(module).toContain('__Host-ankka_gateway_deploy');
      }
      await expect(validateGeneratedReviewedCanaryDirectory(fixture.output)).resolves.toMatchObject({
        accountId: ACCOUNT_ID,
        release: PIN.release,
        schemaVersion: 2,
      });
    } finally {
      await fixture.cleanup();
    }
  });

  it('refuses live identities and account drift in the isolated generation path', async () => {
    for (const [pin, publicationResult] of [
      [{ ...ISOLATED_PIN, controlPlaneOrigin: 'https://foreign-control.example' }, ISOLATED_PUBLICATION],
      [ISOLATED_PIN, { ...ISOLATED_PUBLICATION, controlPlaneOrigin: 'https://foreign-control.example' }],
      [
        { ...ISOLATED_PIN, controlPlaneOrigin: 'https://foreign-control.example' },
        { ...ISOLATED_PUBLICATION, controlPlaneOrigin: 'https://foreign-control.example' },
      ],
    ]) {
      const fixture = await sandbox();
      try {
        await expect(generateReviewedIsolatedCanaryArtifacts({
          isolatedTarget: ISOLATED_TARGET,
          outputDirectory: fixture.output,
          pin,
          publicationResult,
        })).rejects.toBeInstanceOf(ReviewedCanaryGenerationError);
      } finally {
        await fixture.cleanup();
      }
    }
    const invalidTargets = [
      { ...ISOLATED_TARGET, hostname: 'deploy.ankka.ai' },
      { ...ISOLATED_TARGET, workerName: 'ankka-gateway-deploy' },
      { ...ISOLATED_TARGET, accountId: '2'.repeat(32) },
      { ...ISOLATED_TARGET, oauthClientId: '6ace98c3cfe05f58a7fbe18f88390bfc' },
      { ...ISOLATED_TARGET, hostname: '*.canary.example.net' },
      { ...ISOLATED_TARGET, hostname: 'installer-proof.workers.dev' },
      { ...ISOLATED_TARGET, extra: true },
    ];
    for (const isolatedTarget of invalidTargets) {
      const fixture = await sandbox();
      try {
        await expect(generateReviewedIsolatedCanaryArtifacts({
          isolatedTarget,
          outputDirectory: fixture.output,
          pin: PIN,
          publicationResult: PUBLICATION,
        })).rejects.toBeInstanceOf(ReviewedCanaryGenerationError);
        await expect(readFile(path.join(fixture.output, 'reviewed-canary-record.json'))).rejects.toThrow();
      } finally {
        await fixture.cleanup();
      }
    }
  });

  it('refuses to materialize schema-2 isolated output anywhere inside the repository', async () => {
    const outputDirectory = path.resolve(
      APP_ROOT,
      '..',
      `.isolated-reviewed-output-test-${process.pid}`,
    );
    try {
      await expect(generateReviewedIsolatedCanaryArtifacts({
        isolatedTarget: ISOLATED_TARGET,
        outputDirectory,
        pin: PIN,
        publicationResult: PUBLICATION,
      })).rejects.toBeInstanceOf(ReviewedCanaryGenerationError);
      await expect(readFile(path.join(outputDirectory, 'reviewed-canary-record.json'))).rejects.toThrow();
    } finally {
      await rm(outputDirectory, { force: true, recursive: true });
    }
  });

  it('dry-runs exact no-bundle module bytes despite a hostile ambient account', async () => {
    const fixture = await generated();
    try {
      const wrangler = path.join(REPOSITORY_ROOT, 'node_modules', 'wrangler', 'bin', 'wrangler.js');
      for (const [configName, moduleName] of [
        ['wrangler.rollback.toml', 'reviewed-rollback-worker.mjs'],
        ['wrangler.canary.toml', 'reviewed-canary-worker.mjs'],
      ]) {
        const outdir = path.join(fixture.root, `${configName}-dry-run`);
        const { stdout, stderr } = await execFileAsync(process.execPath, [
          wrangler,
          'deploy',
          '--dry-run',
          '--cwd', fixture.root,
          '--config', path.join(fixture.output, configName),
          '--outdir', outdir,
        ], {
          cwd: APP_ROOT,
          env: {
            ...process.env,
            CLOUDFLARE_ACCOUNT_ID: 'f'.repeat(32),
            CLOUDFLARE_API_KEY: '',
            CLOUDFLARE_API_TOKEN: '',
            CLOUDFLARE_EMAIL: '',
            CLOUDFLARE_OAUTH_TOKEN: '',
            NO_COLOR: '1',
            WRANGLER_HIDE_BANNER: 'true',
            WRANGLER_LOG_PATH: path.join(fixture.root, 'wrangler-logs'),
          },
          timeout: 30_000,
          maxBuffer: 2 * 1024 * 1024,
        });
        expect(`${stdout}\n${stderr}`).toContain('Total Upload:');
        expect((await readdir(outdir)).sort()).toEqual(['README.md', moduleName]);
        expect(await readFile(path.join(outdir, moduleName))).toEqual(
          await readFile(path.join(fixture.output, moduleName)),
        );
      }
      expect((await readdir(fixture.output)).filter((name) => name !== '.wrangler').sort())
        .toEqual(GENERATED_FILES);
      await expect(validateGeneratedReviewedCanaryDirectory(fixture.output)).resolves.toMatchObject({
        accountId: ACCOUNT_ID,
        release: PIN.release,
      });
    } finally {
      await fixture.cleanup();
    }
  }, 60_000);

  it('rejects every unbound identity, malformed account, and unknown field before output exists', async () => {
    const { accountId: _removedAccountId, ...publicationWithoutAccount } = PUBLICATION;
    const mutations = [
      [{ ...PIN, channel: 'other' }, PUBLICATION],
      [{ ...PIN, release: 'gateway-v1.2.4' }, PUBLICATION],
      [{ ...PIN, keyId: 'other-key' }, PUBLICATION],
      [{ ...PIN, publicKey: 'B'.repeat(43) }, PUBLICATION],
      [{ ...PIN, artifactSha256: 'd'.repeat(64) }, PUBLICATION],
      [{ ...PIN, controlPlaneOrigin: 'https://foreign-control.example' }, PUBLICATION],
      [PIN, { ...PUBLICATION, controlPlaneOrigin: 'https://foreign-control.example' }],
      [
        { ...PIN, controlPlaneOrigin: 'https://foreign-control.example' },
        { ...PUBLICATION, controlPlaneOrigin: 'https://foreign-control.example' },
      ],
      [PIN, { ...PUBLICATION, accountId: 'F'.repeat(32) }],
      [PIN, { ...PUBLICATION, accountId: '1'.repeat(31) }],
      [PIN, publicationWithoutAccount],
      [PIN, { ...PUBLICATION, prefix: 'ankka-mcp-gateway/releases/canary/wrong/' }],
      [PIN, { ...PUBLICATION, status: 'failed' }],
      [PIN, { ...PUBLICATION, extra: true }],
      [{ ...PIN, extra: true }, PUBLICATION],
    ];
    for (const [pin, publicationResult] of mutations) {
      const fixture = await sandbox();
      try {
        await expect(generateReviewedCanaryArtifacts({
          outputDirectory: fixture.output,
          pin,
          publicationResult,
        })).rejects.toBeInstanceOf(ReviewedCanaryGenerationError);
        await expect(readFile(path.join(fixture.output, 'reviewed-canary-record.json'))).rejects.toThrow();
      } finally {
        await fixture.cleanup();
      }
    }
  });

  it('rejects module tampering, extra output, and coordinated config-account tampering', async () => {
    const modified = await generated();
    try {
      await writeFile(path.join(modified.output, 'reviewed-canary-worker.mjs'), 'changed\n');
      await expect(validateGeneratedReviewedCanaryDirectory(modified.output))
        .rejects.toBeInstanceOf(ReviewedCanaryGenerationError);
    } finally {
      await modified.cleanup();
    }

    const extra = await generated();
    try {
      await writeFile(path.join(extra.output, 'extra.txt'), 'unexpected');
      await expect(validateGeneratedReviewedCanaryDirectory(extra.output))
        .rejects.toBeInstanceOf(ReviewedCanaryGenerationError);
    } finally {
      await extra.cleanup();
    }

    const accountTamper = await generated();
    try {
      const configPath = path.join(accountTamper.output, 'wrangler.canary.toml');
      const recordPath = path.join(accountTamper.output, 'reviewed-canary-record.json');
      const tamperedConfig = (await readFile(configPath, 'utf8'))
        .replace(`account_id = "${ACCOUNT_ID}"`, `account_id = "${'e'.repeat(32)}"`);
      const record = JSON.parse(await readFile(recordPath, 'utf8'));
      const bytes = Buffer.from(tamperedConfig, 'utf8');
      const fileRecord = record.outputFiles.find((entry) => entry.path === 'wrangler.canary.toml');
      fileRecord.byteSize = bytes.byteLength;
      fileRecord.sha256 = sha256Hex(bytes);
      await writeFile(configPath, bytes);
      await writeFile(recordPath, `${canonicalJson(record)}\n`);
      await expect(validateGeneratedReviewedCanaryDirectory(accountTamper.output))
        .rejects.toBeInstanceOf(ReviewedCanaryGenerationError);
    } finally {
      await accountTamper.cleanup();
    }
  });

  it('CLI accepts only exact regular JSON inputs and emits no release identity or secret data', async () => {
    const fixture = await sandbox();
    try {
      const pinFile = path.join(fixture.root, 'pin.json');
      const publicationFile = path.join(fixture.root, 'publication.json');
      await writeFile(pinFile, JSON.stringify(PIN));
      await writeFile(publicationFile, JSON.stringify(PUBLICATION));
      const stdout = sink();
      const stderr = sink();
      await expect(runReviewedCanaryGeneratorCli({
        argv: [
          '--pin', pinFile,
          '--publication-result', publicationFile,
          '--output-dir', fixture.output,
        ],
        stderr,
        stdout,
      })).resolves.toBe(0);
      expect(stderr.value()).toBe('');
      expect(stdout.value()).toBe(
        'Reviewed canary artifacts generated and validated. No live call was attempted.\n',
      );
      expect(stdout.value()).not.toContain(PIN.publicKey);
      expect(stdout.value()).not.toContain(PIN.artifactSha256);
      expect(stdout.value()).not.toContain(ACCOUNT_ID);

      const validationStdout = sink();
      await expect(runReviewedCanaryGeneratorCli({
        argv: ['--validate-output-dir', fixture.output],
        stderr: sink(),
        stdout: validationStdout,
      })).resolves.toBe(0);
      expect(validationStdout.value()).toBe('Reviewed canary artifacts are exact and secret-free.\n');
      const isolatedValidationStderr = sink();
      await expect(runReviewedIsolatedCanaryGeneratorCli({
        argv: ['--validate-output-dir', fixture.output],
        stderr: isolatedValidationStderr,
        stdout: sink(),
      })).resolves.toBe(1);
      expect(isolatedValidationStderr.value()).toBe(
        'Reviewed isolated canary validation failed. No deploy or live call was attempted.\n',
      );
    } finally {
      await fixture.cleanup();
    }
  });

  it('CLI isolated mode binds the external target and rejects the live hostname', async () => {
    const fixture = await sandbox();
    try {
      const pinFile = path.join(fixture.root, 'pin.json');
      const publicationFile = path.join(fixture.root, 'publication.json');
      const targetFile = path.join(fixture.root, 'target.json');
      await Promise.all([
        writeFile(pinFile, JSON.stringify(ISOLATED_PIN)),
        writeFile(publicationFile, JSON.stringify(ISOLATED_PUBLICATION)),
        writeFile(targetFile, JSON.stringify(ISOLATED_TARGET)),
      ]);
      const stdout = sink();
      await expect(runReviewedIsolatedCanaryGeneratorCli({
        argv: [
          '--pin', pinFile,
          '--publication-result', publicationFile,
          '--isolated-target', targetFile,
          '--output-dir', fixture.output,
        ],
        stderr: sink(),
        stdout,
      })).resolves.toBe(0);
      expect(stdout.value()).not.toContain(ISOLATED_TARGET.hostname);
      const config = await readFile(path.join(fixture.output, 'wrangler.canary.toml'), 'utf8');
      expect(config).toContain(`pattern = "${ISOLATED_TARGET.hostname}"`);
      expect(config).not.toContain('deploy.ankka.ai');
      const validationOutput = sink();
      await expect(runReviewedIsolatedCanaryGeneratorCli({
        argv: ['--validate-output-dir', fixture.output],
        stderr: sink(),
        stdout: validationOutput,
      })).resolves.toBe(0);
      expect(validationOutput.value()).toBe(
        'Reviewed isolated canary artifacts are exact and secret-free.\n',
      );
    } finally {
      await fixture.cleanup();
    }

    const rejected = await sandbox();
    try {
      const pinFile = path.join(rejected.root, 'pin.json');
      const publicationFile = path.join(rejected.root, 'publication.json');
      const targetFile = path.join(rejected.root, 'target.json');
      await Promise.all([
        writeFile(pinFile, JSON.stringify(PIN)),
        writeFile(publicationFile, JSON.stringify(PUBLICATION)),
        writeFile(targetFile, JSON.stringify({ ...ISOLATED_TARGET, hostname: 'deploy.ankka.ai' })),
      ]);
      const stderr = sink();
      await expect(runReviewedIsolatedCanaryGeneratorCli({
        argv: [
          '--pin', pinFile,
          '--publication-result', publicationFile,
          '--isolated-target', targetFile,
          '--output-dir', rejected.output,
        ],
        stderr,
        stdout: sink(),
      })).resolves.toBe(1);
      expect(stderr.value()).toBe(
        'Reviewed canary artifact operation failed. No deploy or live call was attempted.\n',
      );
    } finally {
      await rejected.cleanup();
    }
  });
});

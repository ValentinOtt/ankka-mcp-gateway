import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { createHash } from 'node:crypto';
import { copyFile, mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import { after, before, test } from 'node:test';

import { canonicalJson } from '../apps/installer/scripts/sign-gateway-release.mjs';
import {
  ReleaseSbomError,
  generateReleaseSbom,
  loadReleaseSbom,
} from '../scripts/generate-release-sbom.mjs';

const execFileAsync = promisify(execFile);
const REPOSITORY_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const RELEASE = 'gateway-v9.9.9';

async function sourceFixture() {
  const root = await mkdtemp(path.join(tmpdir(), 'ankka-release-sbom-'));
  const source = path.join(root, 'source');
  await Promise.all([
    mkdir(path.join(source, 'scripts'), { recursive: true }),
    mkdir(path.join(source, 'apps/admin'), { recursive: true }),
    mkdir(path.join(source, 'apps/installer/scripts'), { recursive: true }),
  ]);
  for (const relative of [
    '.nvmrc',
    'package.json',
    'package-lock.json',
    'scripts/generate-release-sbom.mjs',
    'apps/admin/package.json',
    'apps/installer/package.json',
    'apps/installer/scripts/sign-gateway-release.mjs',
  ]) {
    await copyFile(path.join(REPOSITORY_ROOT, relative), path.join(source, relative));
  }
  await execFileAsync('git', ['init', '--quiet'], { cwd: source });
  await execFileAsync('git', ['add', '.'], { cwd: source });
  await execFileAsync('git', [
    '-c', 'user.name=Release SBOM Test',
    '-c', 'user.email=release-sbom@example.invalid',
    'commit', '--quiet', '-m', 'fixture',
  ], { cwd: source });
  const { stdout } = await execFileAsync('git', ['rev-parse', 'HEAD'], { cwd: source, encoding: 'utf8' });
  return Object.freeze({
    root,
    source,
    sourceCommit: stdout.trim(),
    packageLockSha256: createHash('sha256')
      .update(await readFile(path.join(source, 'package-lock.json'))).digest('hex'),
  });
}

let fixture;

before(async () => {
  fixture = await sourceFixture();
});

after(async () => {
  if (fixture?.root) await rm(fixture.root, { recursive: true, force: true });
});

test('generates deterministic create-only CycloneDX bytes from the exact clean source tree', async () => {
  const first = path.join(fixture.root, 'first.cdx.json');
  const second = path.join(fixture.root, 'second.cdx.json');
  await generateReleaseSbom({
    output: first,
    release: RELEASE,
    source: fixture.source,
    sourceCommit: fixture.sourceCommit,
  });
  await generateReleaseSbom({
    output: second,
    release: RELEASE,
    source: fixture.source,
    sourceCommit: fixture.sourceCommit,
  });
  const [firstBytes, secondBytes] = await Promise.all([readFile(first), readFile(second)]);
  assert.deepEqual(firstBytes, secondBytes);
  const parsed = loadReleaseSbom(firstBytes, {
    packageLockSha256: fixture.packageLockSha256,
    release: RELEASE,
    sourceCommit: fixture.sourceCommit,
  });
  assert.equal(parsed.metadata.timestamp, undefined);
  assert.equal(parsed.metadata.component.properties.find(
    (entry) => entry.name === 'ai.ankka.packageLockSha256',
  ).value, fixture.packageLockSha256);
  assert.equal(parsed.metadata.component.properties.find(
    (entry) => entry.name === 'ai.ankka.sbom.devDependencies',
  ).value, 'omitted');
  assert.equal(parsed.components.some((component) => component.scope === 'optional' ||
    component.properties?.some((entry) =>
      entry.name === 'cdx:npm:package:development' && entry.value === 'true')), false);
  assert.deepEqual(
    parsed.components.map((component) => component['bom-ref']),
    parsed.components.map((component) => component['bom-ref']).sort(),
  );
  await assert.rejects(
    generateReleaseSbom({
      output: first,
      release: RELEASE,
      source: fixture.source,
      sourceCommit: fixture.sourceCommit,
    }),
    (error) => error instanceof ReleaseSbomError && error.code === 'release_sbom_output_exists',
  );
});

test('rejects local locators, sensitive fields, and a generator not bound to the source commit', async () => {
  const validBytes = await readFile(path.join(fixture.root, 'first.cdx.json'));
  const withLocator = JSON.parse(validBytes.toString('utf8'));
  withLocator.components[0].properties = [
    ...(withLocator.components[0].properties ?? []),
    { name: 'fixture', value: '/Users/example/private/release' },
  ];
  assert.throws(
    () => loadReleaseSbom(Buffer.from(canonicalJson(withLocator), 'utf8'), {
      release: RELEASE,
      sourceCommit: fixture.sourceCommit,
    }),
    (error) => error instanceof ReleaseSbomError,
  );
  const withSecretField = JSON.parse(validBytes.toString('utf8'));
  withSecretField.components[0].accountId = 'a'.repeat(32);
  assert.throws(
    () => loadReleaseSbom(Buffer.from(canonicalJson(withSecretField), 'utf8'), {
      release: RELEASE,
      sourceCommit: fixture.sourceCommit,
    }),
    (error) => error instanceof ReleaseSbomError,
  );
  const withDuplicateRootProperty = JSON.parse(validBytes.toString('utf8'));
  withDuplicateRootProperty.metadata.component.properties.push(
    { ...withDuplicateRootProperty.metadata.component.properties[0] },
  );
  assert.throws(
    () => loadReleaseSbom(Buffer.from(canonicalJson(withDuplicateRootProperty), 'utf8'), {
      release: RELEASE,
      sourceCommit: fixture.sourceCommit,
    }),
    (error) => error instanceof ReleaseSbomError,
  );

  const mismatch = await sourceFixture();
  try {
    const tool = path.join(mismatch.source, 'scripts/generate-release-sbom.mjs');
    await writeFile(tool, `${await readFile(tool, 'utf8')}\n// changed generator\n`);
    await execFileAsync('git', ['add', tool], { cwd: mismatch.source });
    await execFileAsync('git', [
      '-c', 'user.name=Release SBOM Test',
      '-c', 'user.email=release-sbom@example.invalid',
      'commit', '--quiet', '-m', 'change tool',
    ], { cwd: mismatch.source });
    const { stdout } = await execFileAsync('git', ['rev-parse', 'HEAD'], {
      cwd: mismatch.source,
      encoding: 'utf8',
    });
    await assert.rejects(
      generateReleaseSbom({
        output: path.join(mismatch.root, 'mismatch.cdx.json'),
        release: RELEASE,
        source: mismatch.source,
        sourceCommit: stdout.trim(),
      }),
      (error) => error instanceof ReleaseSbomError &&
        error.code === 'release_sbom_source_tool_mismatch',
    );
  } finally {
    await rm(mismatch.root, { recursive: true, force: true });
  }
});

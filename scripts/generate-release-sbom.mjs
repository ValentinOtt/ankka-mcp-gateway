import { execFile } from 'node:child_process';
import { createHash } from 'node:crypto';
import { lstat, readFile, realpath, writeFile } from 'node:fs/promises';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { promisify } from 'node:util';
import * as v from 'valibot';

import { canonicalJson } from '../apps/installer/scripts/sign-gateway-release.mjs';

const execFileAsync = promisify(execFile);
const RELEASE_PATTERN = /^gateway-v(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)$/u;
const COMMIT_PATTERN = /^[a-f0-9]{40}$/u;
const SHA256_PATTERN = /^[a-f0-9]{64}$/u;
const CYCLONEDX_SCHEMA = 'http://cyclonedx.org/schema/bom-1.5.schema.json';
const MAX_SBOM_BYTES = 2 * 1024 * 1024;
const RELEASE_TOOL_PATHS = Object.freeze([
  'scripts/generate-release-sbom.mjs',
  'apps/installer/scripts/sign-gateway-release.mjs',
]);
const SENSITIVE_FIELD = /^(?:accountId|apiKey|bucketName|clientSecret|credential|credentials|password|privateKey|resourceId|secret|token|zoneId)$/iu;
const LOCAL_LOCATOR = /(?:^|[\s"'])(?:\/Users\/|\/home\/|[A-Za-z]:\\)/u;
const CLOUDFLARE_LOCATOR = /(?:api\.cloudflare\.com\/client\/v4\/accounts\/|r2\.cloudflarestorage\.com)/iu;
const PRIVATE_MATERIAL = /-----BEGIN [^-\r\n]*PRIVATE KEY-----|(?:CLOUDFLARE_API_TOKEN|GITHUB_TOKEN|NPM_TOKEN)\s*=/iu;
const NPM_PACKAGE_PATH = /^(?:apps|node_modules)\/[A-Za-z0-9@._/-]+$/u;
const BOOLEAN_SCHEMA = v.boolean();
const NUMBER_SCHEMA = v.number();
const OBJECT_SCHEMA = v.object({});
const STRING_SCHEMA = v.string();

export class ReleaseSbomError extends Error {
  constructor(code) {
    super(code);
    this.name = 'ReleaseSbomError';
    this.code = code;
  }
}

function fail(code = 'release_sbom_invalid') {
  throw new ReleaseSbomError(code);
}

function isRecord(value) {
  return v.is(OBJECT_SCHEMA, value) && !Array.isArray(value);
}

function exactKeys(value, expected) {
  if (!isRecord(value)) return false;
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  return actual.length === wanted.length && actual.every((key, index) => key === wanted[index]);
}

function lexicalCompare(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
}

function decodeUtf8(bytes) {
  try {
    return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch {
    fail();
  }
}

function assertPublicSbomValue(value, seen = new Set()) {
  if (value === null || v.is(BOOLEAN_SCHEMA, value) || v.is(NUMBER_SCHEMA, value)) return;
  if (v.is(STRING_SCHEMA, value)) {
    if (LOCAL_LOCATOR.test(value) || CLOUDFLARE_LOCATOR.test(value) || PRIVATE_MATERIAL.test(value)) fail();
    try {
      const locator = new URL(value);
      if (locator.username || locator.password || locator.protocol === 'file:') fail();
    } catch (error) {
      if (error instanceof ReleaseSbomError) throw error;
    }
    return;
  }
  if (!v.is(OBJECT_SCHEMA, value) || seen.has(value)) fail();
  seen.add(value);
  if (Array.isArray(value)) {
    for (const entry of value) assertPublicSbomValue(entry, seen);
  } else {
    if (v.is(STRING_SCHEMA, value.name) && Object.hasOwn(value, 'value') &&
        SENSITIVE_FIELD.test(value.name)) fail();
    for (const [key, entry] of Object.entries(value)) {
      if (SENSITIVE_FIELD.test(key)) fail();
      assertPublicSbomValue(entry, seen);
    }
  }
  seen.delete(value);
}

function normalizeComponents(input) {
  const byReference = new Map();
  for (const component of structuredClone(input)) {
    if (!isRecord(component) || !v.is(STRING_SCHEMA, component['bom-ref']) || component['bom-ref'].length === 0) fail();
    if (component.scope === 'optional' || (Array.isArray(component.properties) &&
        component.properties.some((entry) => isRecord(entry) &&
          entry.name === 'cdx:npm:package:development' && entry.value === 'true'))) fail();
    const npmPaths = [];
    const otherProperties = [];
    for (const property of Array.isArray(component.properties) ? component.properties : []) {
      if (isRecord(property) && property.name === 'cdx:npm:package:path') {
        if (!exactKeys(property, ['name', 'value']) || !v.is(STRING_SCHEMA, property.value) ||
            !NPM_PACKAGE_PATH.test(property.value) ||
            property.value.split('/').some((segment) => segment === '.' || segment === '..')) fail();
        npmPaths.push(property.value);
      } else {
        otherProperties.push(property);
      }
    }
    const identity = structuredClone(component);
    if (otherProperties.length === 0) delete identity.properties;
    else identity.properties = otherProperties;
    const fingerprint = canonicalJson(identity);
    const existing = byReference.get(component['bom-ref']);
    if (existing) {
      if (existing.fingerprint !== fingerprint) fail();
      for (const npmPath of npmPaths) existing.npmPaths.add(npmPath);
      continue;
    }
    byReference.set(component['bom-ref'], {
      component,
      fingerprint,
      npmPaths: new Set(npmPaths),
      otherProperties,
    });
  }
  const components = [...byReference.values()].map((entry) => {
    if (entry.npmPaths.size > 0) {
      entry.component.properties = [
        ...entry.otherProperties,
        ...[...entry.npmPaths].sort(lexicalCompare)
          .map((value) => ({ name: 'cdx:npm:package:path', value })),
      ];
    } else if (entry.otherProperties.length === 0) {
      delete entry.component.properties;
    } else {
      entry.component.properties = entry.otherProperties;
    }
    return entry.component;
  });
  components.sort((left, right) => lexicalCompare(left['bom-ref'], right['bom-ref']));
  return { components, references: new Set(byReference.keys()) };
}

function normalizeDependencies(input, oldRootReference, rootReference, componentReferences) {
  const byReference = new Map();
  for (const dependency of structuredClone(input)) {
    if (!isRecord(dependency) || !exactKeys(dependency, ['dependsOn', 'ref']) ||
        !v.is(STRING_SCHEMA, dependency.ref) || !Array.isArray(dependency.dependsOn)) fail();
    const ref = dependency.ref === oldRootReference ? rootReference : dependency.ref;
    const dependsOn = dependency.dependsOn.map((entry) =>
      entry === oldRootReference ? rootReference : entry);
    if (dependsOn.some((entry) => !v.is(STRING_SCHEMA, entry)) || new Set(dependsOn).size !== dependsOn.length) fail();
    const existing = byReference.get(ref);
    if (existing) {
      for (const reference of dependsOn) existing.add(reference);
    } else {
      byReference.set(ref, new Set(dependsOn));
    }
  }
  const references = new Set(byReference.keys());
  const dependencies = [...byReference].map(([ref, dependsOn]) => ({
    dependsOn: [...dependsOn].sort(lexicalCompare),
    ref,
  }));
  if (!references.has(rootReference) || references.size !== componentReferences.size + 1 ||
      [...componentReferences].some((reference) => !references.has(reference)) ||
      dependencies.some((dependency) => dependency.dependsOn.some((reference) => !references.has(reference)))) fail();
  dependencies.sort((left, right) => lexicalCompare(left.ref, right.ref));
  return dependencies;
}

function deterministicUuid(sourceCommit, release) {
  const bytes = createHash('sha256').update(`ankka-mcp-gateway-sbom\0${sourceCommit}\0${release}`).digest().subarray(0, 16);
  bytes[6] = (bytes[6] & 0x0f) | 0x50;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = bytes.toString('hex');
  return `urn:uuid:${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

export function prepareReleaseSbom({ npmSbom, packageLockSha256, release, sourceCommit }) {
  if (!RELEASE_PATTERN.test(release) || !COMMIT_PATTERN.test(sourceCommit) ||
      !SHA256_PATTERN.test(packageLockSha256) || !isRecord(npmSbom)) fail();
  if (
    npmSbom.$schema !== CYCLONEDX_SCHEMA ||
    npmSbom.bomFormat !== 'CycloneDX' ||
    npmSbom.specVersion !== '1.5' ||
    npmSbom.version !== 1 ||
    !isRecord(npmSbom.metadata) ||
    !exactKeys(npmSbom.metadata, ['component', 'lifecycles', 'timestamp', 'tools']) ||
    !Array.isArray(npmSbom.metadata.lifecycles) || npmSbom.metadata.lifecycles.length !== 1 ||
    !exactKeys(npmSbom.metadata.lifecycles[0], ['phase']) ||
    npmSbom.metadata.lifecycles[0].phase !== 'pre-build' ||
    !Array.isArray(npmSbom.metadata.tools) || npmSbom.metadata.tools.length !== 1 ||
    !exactKeys(npmSbom.metadata.tools[0], ['name', 'vendor', 'version']) ||
    npmSbom.metadata.tools[0].name !== 'cli' || npmSbom.metadata.tools[0].vendor !== 'npm' ||
    !v.is(STRING_SCHEMA, npmSbom.metadata.tools[0].version) ||
    !/^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)$/u.test(npmSbom.metadata.tools[0].version) ||
    !isRecord(npmSbom.metadata.component) ||
    !Array.isArray(npmSbom.components) || npmSbom.components.length === 0 ||
    !Array.isArray(npmSbom.dependencies) || npmSbom.dependencies.length === 0
  ) fail();

  const root = structuredClone(npmSbom.metadata.component);
  const oldRootReference = root['bom-ref'];
  if (!v.is(STRING_SCHEMA, oldRootReference) || oldRootReference.length === 0) fail();
  const rootReference = `urn:ankka:mcp-gateway:${release}:${sourceCommit}`;
  const version = release.slice('gateway-v'.length);
  root['bom-ref'] = rootReference;
  root.name = '@ankka/mcp-gateway';
  root.purl = `pkg:npm/%40ankka/mcp-gateway@${version}`;
  root.version = version;
  root.properties = [
    { name: 'ai.ankka.packageLockSha256', value: packageLockSha256 },
    { name: 'ai.ankka.release', value: release },
    { name: 'ai.ankka.sourceCommit', value: sourceCommit },
    { name: 'ai.ankka.sbom.devDependencies', value: 'omitted' },
    { name: 'ai.ankka.sbom.optionalDependencies', value: 'omitted' },
  ];

  const metadata = structuredClone(npmSbom.metadata);
  delete metadata.timestamp;
  metadata.component = root;
  const { components, references } = normalizeComponents(npmSbom.components);
  const dependencies = normalizeDependencies(
    npmSbom.dependencies,
    oldRootReference,
    rootReference,
    references,
  );

  const output = {
    $schema: CYCLONEDX_SCHEMA,
    bomFormat: 'CycloneDX',
    components,
    dependencies,
    metadata,
    serialNumber: deterministicUuid(sourceCommit, release),
    specVersion: '1.5',
    version: 1,
  };
  assertPublicSbomValue(output);
  const bytes = Buffer.from(canonicalJson(output), 'utf8');
  if (bytes.byteLength === 0 || bytes.byteLength > MAX_SBOM_BYTES) fail();
  loadReleaseSbom(bytes, { packageLockSha256, release, sourceCommit });
  return bytes;
}

export function loadReleaseSbom(bytes, { packageLockSha256, release, sourceCommit }) {
  if (!Buffer.isBuffer(bytes) || bytes.byteLength === 0 || bytes.byteLength > MAX_SBOM_BYTES) fail();
  let parsed;
  let serialized;
  try {
    serialized = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
    parsed = JSON.parse(serialized);
  } catch {
    fail();
  }
  if (
    canonicalJson(parsed) !== serialized ||
    !exactKeys(parsed, [
      '$schema', 'bomFormat', 'components', 'dependencies', 'metadata',
      'serialNumber', 'specVersion', 'version',
    ]) ||
    parsed.$schema !== CYCLONEDX_SCHEMA ||
    parsed.bomFormat !== 'CycloneDX' ||
    parsed.specVersion !== '1.5' ||
    parsed.version !== 1 ||
    parsed.serialNumber !== deterministicUuid(sourceCommit, release) ||
    !Array.isArray(parsed.components) || parsed.components.length === 0 ||
    !Array.isArray(parsed.dependencies) || parsed.dependencies.length === 0 ||
    !isRecord(parsed.metadata) || 'timestamp' in parsed.metadata ||
    !exactKeys(parsed.metadata, ['component', 'lifecycles', 'tools']) ||
    !Array.isArray(parsed.metadata.lifecycles) || parsed.metadata.lifecycles.length !== 1 ||
    !exactKeys(parsed.metadata.lifecycles[0], ['phase']) ||
    parsed.metadata.lifecycles[0].phase !== 'pre-build' ||
    !Array.isArray(parsed.metadata.tools) || parsed.metadata.tools.length !== 1 ||
    !exactKeys(parsed.metadata.tools[0], ['name', 'vendor', 'version']) ||
    parsed.metadata.tools[0].name !== 'cli' || parsed.metadata.tools[0].vendor !== 'npm' ||
    !v.is(STRING_SCHEMA, parsed.metadata.tools[0].version) ||
    !/^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)$/u.test(parsed.metadata.tools[0].version) ||
    !isRecord(parsed.metadata.component) ||
    parsed.metadata.component['bom-ref'] !== `urn:ankka:mcp-gateway:${release}:${sourceCommit}` ||
    parsed.metadata.component.name !== '@ankka/mcp-gateway' ||
    parsed.metadata.component.purl !== `pkg:npm/%40ankka/mcp-gateway@${release.slice('gateway-v'.length)}` ||
    parsed.metadata.component.version !== release.slice('gateway-v'.length) ||
    !Array.isArray(parsed.metadata.component.properties) ||
    parsed.metadata.component.properties.length !== 5
  ) fail();
  const normalized = normalizeComponents(parsed.components);
  const normalizedDependencies = normalizeDependencies(
    parsed.dependencies,
    parsed.metadata.component['bom-ref'],
    parsed.metadata.component['bom-ref'],
    normalized.references,
  );
  if (canonicalJson(normalized.components) !== canonicalJson(parsed.components) ||
      canonicalJson(normalizedDependencies) !== canonicalJson(parsed.dependencies)) fail();
  assertPublicSbomValue(parsed);
  const expectedProperties = [
    ['ai.ankka.packageLockSha256', parsed.metadata.component.properties[0]?.value],
    ['ai.ankka.release', release],
    ['ai.ankka.sourceCommit', sourceCommit],
    ['ai.ankka.sbom.devDependencies', 'omitted'],
    ['ai.ankka.sbom.optionalDependencies', 'omitted'],
  ];
  if (parsed.metadata.component.properties.some((entry, index) =>
    !exactKeys(entry, ['name', 'value']) ||
    entry.name !== expectedProperties[index][0] ||
    entry.value !== expectedProperties[index][1])) fail();
  const properties = new Map(parsed.metadata.component.properties.map((entry) => [entry.name, entry.value]));
  if (
    properties.size !== 5 ||
    !v.is(STRING_SCHEMA, properties.get('ai.ankka.packageLockSha256')) ||
    !SHA256_PATTERN.test(properties.get('ai.ankka.packageLockSha256')) ||
    (packageLockSha256 !== undefined && properties.get('ai.ankka.packageLockSha256') !== packageLockSha256) ||
    properties.get('ai.ankka.release') !== release ||
    properties.get('ai.ankka.sourceCommit') !== sourceCommit ||
    properties.get('ai.ankka.sbom.devDependencies') !== 'omitted' ||
    properties.get('ai.ankka.sbom.optionalDependencies') !== 'omitted'
  ) fail();
  return Object.freeze(parsed);
}

async function assertReleaseToolingMatchesSource(root) {
  for (const relative of RELEASE_TOOL_PATHS) {
    let running;
    let committed;
    try {
      const runningUrl = relative === RELEASE_TOOL_PATHS[0]
        ? import.meta.url
        : new URL('../apps/installer/scripts/sign-gateway-release.mjs', import.meta.url);
      [running, committed] = await Promise.all([
        readFile(fileURLToPath(runningUrl)),
        readFile(path.join(root, ...relative.split('/'))),
      ]);
      if (!running.equals(committed)) fail('release_sbom_source_tool_mismatch');
    } catch (error) {
      if (error instanceof ReleaseSbomError) throw error;
      fail('release_sbom_source_tool_mismatch');
    } finally {
      running?.fill(0);
      committed?.fill(0);
    }
  }
}

async function assertExactSource(root, sourceCommit) {
  const { stdout: head } = await execFileAsync('git', ['-C', root, 'rev-parse', '--verify', 'HEAD^{commit}'], {
    encoding: 'utf8',
  });
  const { stdout: status } = await execFileAsync(
    'git',
    ['-C', root, 'status', '--porcelain=v1', '--untracked-files=all'],
    { encoding: 'utf8' },
  );
  if (head.trim() !== sourceCommit || status !== '') fail('release_sbom_source_mismatch');
  await assertReleaseToolingMatchesSource(root);
}

async function pinnedSourceToolchain(root) {
  let packageBytes;
  let nodeBytes;
  let lockBytes;
  try {
    [packageBytes, nodeBytes, lockBytes] = await Promise.all([
      readFile(path.join(root, 'package.json')),
      readFile(path.join(root, '.nvmrc')),
      readFile(path.join(root, 'package-lock.json')),
    ]);
    const packageManifest = JSON.parse(decodeUtf8(packageBytes));
    const expectedNpm = /^npm@((?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*))$/u
      .exec(packageManifest.packageManager)?.[1];
    const expectedNode = decodeUtf8(nodeBytes).trim();
    if (!expectedNpm || !/^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)$/u.test(expectedNode) ||
        process.version !== `v${expectedNode}`) fail('release_sbom_toolchain_mismatch');
    const { stdout: actualNpm } = await execFileAsync('npm', ['--version'], { cwd: root, encoding: 'utf8' });
    if (actualNpm.trim() !== expectedNpm) fail('release_sbom_toolchain_mismatch');
    return Object.freeze({ packageLockSha256: createHash('sha256').update(lockBytes).digest('hex') });
  } catch (error) {
    if (error instanceof ReleaseSbomError) throw error;
    fail('release_sbom_toolchain_mismatch');
  } finally {
    packageBytes?.fill(0);
    nodeBytes?.fill(0);
    lockBytes?.fill(0);
  }
}

export async function generateReleaseSbom({ output, release, source, sourceCommit }) {
  const root = await realpath(path.resolve(source)).catch(() => fail());
  const metadata = await lstat(root).catch(() => fail());
  if (!metadata.isDirectory() || metadata.isSymbolicLink()) fail();
  await assertExactSource(root, sourceCommit);
  const { packageLockSha256 } = await pinnedSourceToolchain(root);

  let npmSbom;
  try {
    const { stdout } = await execFileAsync('npm', [
      'sbom', '--package-lock-only', '--omit', 'dev', '--omit', 'optional',
      '--sbom-format', 'cyclonedx', '--sbom-type', 'application',
    ], { cwd: root, encoding: 'utf8', maxBuffer: MAX_SBOM_BYTES });
    npmSbom = JSON.parse(stdout);
  } catch {
    fail('release_sbom_generation_failed');
  }
  await assertExactSource(root, sourceCommit);
  const after = await pinnedSourceToolchain(root);
  if (after.packageLockSha256 !== packageLockSha256) fail('release_sbom_source_mismatch');
  const bytes = prepareReleaseSbom({ npmSbom, packageLockSha256, release, sourceCommit });
  try {
    await writeFile(path.resolve(output), bytes, { flag: 'wx', mode: 0o600 });
  } catch {
    fail('release_sbom_output_exists');
  } finally {
    bytes.fill(0);
  }
}

function parseCli(argv) {
  const allowed = new Set(['--out', '--release', '--source', '--source-commit']);
  const values = {};
  for (let index = 0; index < argv.length; index += 2) {
    const flag = argv[index];
    if (!allowed.has(flag) || !argv[index + 1] || argv[index + 1].startsWith('--') || flag in values) fail();
    values[flag] = argv[index + 1];
  }
  if ([...allowed].some((flag) => !v.is(STRING_SCHEMA, values[flag]))) fail();
  return {
    output: values['--out'],
    release: values['--release'],
    source: values['--source'],
    sourceCommit: values['--source-commit'],
  };
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  generateReleaseSbom(parseCli(process.argv.slice(2)))
    .then(() => process.stdout.write('{"schemaVersion":1,"status":"written"}\n'))
    .catch((error) => {
      const code = error instanceof ReleaseSbomError ? error.code : 'release_sbom_internal_error';
      process.stderr.write(`Release SBOM generation failed: ${code}.\n`);
      process.exitCode = 1;
    });
}

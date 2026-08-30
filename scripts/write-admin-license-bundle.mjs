import { readFile, readdir, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import * as v from 'valibot';

const repositoryRoot = path.dirname(fileURLToPath(import.meta.url));
const projectRoot = path.dirname(repositoryRoot);
const OBJECT_SCHEMA = v.object({});
const STRING_SCHEMA = v.string();

function lexicalCompare(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
}

function canonicalLf(text) {
  return text.replace(/\r\n?/gu, '\n');
}

async function readUtf8(filename, errorCode) {
  let bytes;
  try {
    bytes = await readFile(filename);
    return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch {
    throw new Error(errorCode);
  } finally {
    bytes?.fill(0);
  }
}

let lock;
try {
  lock = JSON.parse(await readUtf8(
    path.join(projectRoot, 'package-lock.json'),
    'license_bundle_lock_invalid',
  ));
} catch {
  throw new Error('license_bundle_lock_invalid');
}
if (lock.lockfileVersion !== 3 || !v.is(OBJECT_SCHEMA, lock.packages)) {
  throw new Error('license_bundle_lock_invalid');
}

const external = Object.entries(lock.packages)
  .filter(([relative, value]) => relative.startsWith('node_modules/') && value.dev !== true && value.link !== true)
  .sort(([left], [right]) => lexicalCompare(left, right));
if (external.length === 0) throw new Error('license_bundle_empty');

const licenseName = /^(?:license|licence|copying|notice)(?:[-._].*)?$/iu;

async function familyLicenseInputs(packageName, expectedVersion) {
  const directory = path.join(projectRoot, 'node_modules', packageName);
  let manifest;
  try {
    manifest = JSON.parse(await readUtf8(
      path.join(directory, 'package.json'),
      'license_bundle_fallback_invalid',
    ));
  } catch {
    throw new Error('license_bundle_fallback_invalid');
  }
  if (manifest.name !== packageName || manifest.version !== expectedVersion) {
    throw new Error('license_bundle_fallback_invalid');
  }
  const filenames = (await readdir(directory, { withFileTypes: true }))
    .filter((entry) => entry.isFile() && licenseName.test(entry.name))
    .map((entry) => entry.name)
    .sort(lexicalCompare);
  if (filenames.length === 0) throw new Error('license_bundle_fallback_invalid');
  return filenames.map((filename) => ({
    label: `${packageName}/${filename}`,
    filename: path.join(directory, filename),
  }));
}

async function reviewedLicenseFallback(manifest) {
  if (manifest.name === '@cfworker/json-schema' && manifest.version === '4.1.1') {
    return [{
      label: 'cfworker-json-schema-4.1.1-LICENSE.md',
      filename: path.join(
        projectRoot,
        'third_party',
        'licenses',
        'cfworker-json-schema-4.1.1-LICENSE.md',
      ),
    }];
  }
  if (manifest.name.startsWith('@esbuild/')) {
    return familyLicenseInputs('esbuild', manifest.version);
  }
  if (manifest.name.startsWith('@rolldown/binding-')) {
    return familyLicenseInputs('rolldown', manifest.version);
  }
  throw new Error('license_bundle_text_missing');
}

function optionalFamilyManifest(relative, locked) {
  if (locked.optional !== true) return null;
  const name = relative.slice('node_modules/'.length);
  if (!name.startsWith('@esbuild/') && !name.startsWith('@rolldown/binding-')) return null;
  return { name, version: locked.version };
}

const sections = [];
for (const [relative, locked] of external) {
  const directory = path.join(projectRoot, relative);
  let manifest;
  try {
    manifest = JSON.parse(await readUtf8(
      path.join(directory, 'package.json'),
      'license_bundle_package_invalid',
    ));
  } catch {
    manifest = optionalFamilyManifest(relative, locked);
    if (manifest === null) throw new Error('license_bundle_package_invalid');
  }
  if (!v.is(STRING_SCHEMA, manifest.name) || !v.is(STRING_SCHEMA, manifest.version) ||
      manifest.version !== locked.version || !v.is(STRING_SCHEMA, locked.resolved) ||
      !locked.resolved.startsWith('https://registry.npmjs.org/') || !v.is(STRING_SCHEMA, locked.integrity)) {
    throw new Error('license_bundle_package_invalid');
  }
  let filenames = [];
  try {
    filenames = (await readdir(directory, { withFileTypes: true }))
      .filter((entry) => entry.isFile() && licenseName.test(entry.name))
      .map((entry) => entry.name)
      .sort(lexicalCompare);
  } catch {
    if (locked.optional !== true) throw new Error('license_bundle_package_invalid');
  }
  const licenseInputs = filenames.length === 0
    ? await reviewedLicenseFallback(manifest)
    : filenames.map((filename) => ({ label: filename, filename: path.join(directory, filename) }));
  const texts = [];
  for (const input of licenseInputs) {
    const text = await readUtf8(input.filename, 'license_bundle_text_invalid');
    if (text.length === 0 || text.length > 2 * 1024 * 1024 || text.includes('\0')) {
      throw new Error('license_bundle_text_invalid');
    }
    texts.push(`--- ${input.label} ---\n${canonicalLf(text).trim()}\n`);
  }
  sections.push([
    `Package: ${manifest.name}@${manifest.version}`,
    `License metadata: ${String(manifest.license ?? locked.license ?? 'UNSPECIFIED')}`,
    `Registry origin: ${locked.resolved}`,
    '',
    texts.join('\n'),
  ].join('\n'));
}

const heading = [
  'THIRD-PARTY LICENSE TEXTS FOR ANKKA GATEWAY ADMIN',
  '',
  'Generated deterministically from the production dependency graph in package-lock.json.',
  'Package integrity values remain recorded in package-lock.json and the release SBOM.',
  '',
].join('\n');
const bundle = `${heading}${sections.join('\n============================================================\n\n')}\n`;
if (Buffer.byteLength(bundle) > 8 * 1024 * 1024) throw new Error('license_bundle_too_large');

const output = path.join(projectRoot, 'apps', 'admin', 'dist');
const projectLicense = canonicalLf(await readUtf8(
  path.join(projectRoot, 'LICENSE'),
  'license_bundle_project_license_invalid',
));
await Promise.all([
  writeFile(path.join(output, 'LICENSE.txt'), projectLicense, { encoding: 'utf8' }),
  writeFile(path.join(output, 'THIRD_PARTY_LICENSES.txt'), bundle, { encoding: 'utf8' }),
]);

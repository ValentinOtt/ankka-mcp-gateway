import { readFile, readdir, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const repositoryRoot = path.dirname(fileURLToPath(import.meta.url));
const projectRoot = path.dirname(repositoryRoot);

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
if (lock.lockfileVersion !== 3 || !lock.packages || typeof lock.packages !== 'object') {
  throw new Error('license_bundle_lock_invalid');
}

const external = Object.entries(lock.packages)
  .filter(([relative, value]) => relative.startsWith('node_modules/') && value.dev !== true && value.link !== true)
  .sort(([left], [right]) => lexicalCompare(left, right));
if (external.length === 0) throw new Error('license_bundle_empty');

const licenseName = /^(?:license|licence|copying|notice)(?:[-._].*)?$/iu;
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
    throw new Error('license_bundle_package_invalid');
  }
  if (typeof manifest.name !== 'string' || typeof manifest.version !== 'string' ||
      manifest.version !== locked.version || typeof locked.resolved !== 'string' ||
      !locked.resolved.startsWith('https://registry.npmjs.org/') || typeof locked.integrity !== 'string') {
    throw new Error('license_bundle_package_invalid');
  }
  const filenames = (await readdir(directory, { withFileTypes: true }))
    .filter((entry) => entry.isFile() && licenseName.test(entry.name))
    .map((entry) => entry.name)
    .sort(lexicalCompare);
  if (filenames.length === 0) throw new Error('license_bundle_text_missing');
  const texts = [];
  for (const filename of filenames) {
    const text = await readUtf8(path.join(directory, filename), 'license_bundle_text_invalid');
    if (text.length === 0 || text.length > 2 * 1024 * 1024 || text.includes('\0')) {
      throw new Error('license_bundle_text_invalid');
    }
    texts.push(`--- ${filename} ---\n${canonicalLf(text).trim()}\n`);
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

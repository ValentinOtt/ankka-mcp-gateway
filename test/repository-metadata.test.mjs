import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

const ROOT = new URL('../', import.meta.url);

function contentTypeMap(source, constantName) {
  const block = new RegExp(
    `const ${constantName} = Object\\.freeze\\(\\{([\\s\\S]*?)\\n\\}\\);`,
    'u',
  ).exec(source)?.[1];
  assert.ok(block, `${constantName} must remain an explicit frozen mapping`);
  return new Map([...block.matchAll(/^\s+'(\.[a-z0-9]+)': '([^']+)',?\s*$/gmu)]
    .map((match) => [match[1], match[2]]));
}

function isTextContentType(contentType) {
  return contentType.startsWith('text/') ||
    contentType.startsWith('application/json') ||
    contentType.startsWith('application/javascript') ||
    contentType === 'image/svg+xml';
}

test('every accepted non-text signed payload extension is explicitly binary', async () => {
  const [attributes, signer] = await Promise.all([
    readFile(new URL('.gitattributes', ROOT), 'utf8'),
    readFile(new URL('apps/installer/scripts/sign-gateway-release.mjs', ROOT), 'utf8'),
  ]);
  const accepted = new Map([
    ...contentTypeMap(signer, 'WORKER_CONTENT_TYPES'),
    ...contentTypeMap(signer, 'WEB_CONTENT_TYPES'),
  ]);
  const binaryExtensions = [...accepted]
    .filter(([, contentType]) => !isTextContentType(contentType))
    .map(([extension]) => extension)
    .sort();
  assert.deepEqual(binaryExtensions, [
    '.avif', '.gif', '.ico', '.jpeg', '.jpg', '.otf', '.png', '.ttf', '.wasm',
    '.webp', '.woff', '.woff2',
  ]);
  const attributedBinary = new Set(
    [...attributes.matchAll(/^\*(\.[a-z0-9]+) binary$/gmu)].map((match) => match[1]),
  );
  for (const extension of binaryExtensions) {
    assert.ok(attributedBinary.has(extension), `${extension} must be marked binary`);
  }
});

test('contributor pins stay exact without narrowing the runtime engine floor', async () => {
  const [contributing, nodePin, manifest] = await Promise.all([
    readFile(new URL('CONTRIBUTING.md', ROOT), 'utf8'),
    readFile(new URL('.nvmrc', ROOT), 'utf8'),
    readFile(new URL('package.json', ROOT), 'utf8').then(JSON.parse),
  ]);
  assert.equal(nodePin.trim(), '22.23.2');
  assert.equal(manifest.engines?.node, '>=22');
  // Local drift warns so development continues; check:toolchain (run in CI
  // and in the full check gate) still enforces the exact pinned toolchain.
  assert.deepEqual(manifest.devEngines, {
    runtime: { name: 'node', version: '22.23.2', onFail: 'warn' },
    packageManager: { name: 'npm', version: '10.9.8', onFail: 'warn' },
  });
  assert.equal(manifest.packageManager, 'npm@10.9.8');
  assert.match(contributing, /Node\.js `22\.23\.2`/u);
  assert.match(contributing, /npm `10\.9\.8`/u);
  assert.match(contributing, /npm ci/u);
});

test('the protocol-v2 development envelope declares its required channel', async () => {
  const example = await readFile(new URL('apps/installer/.dev.vars.example', ROOT), 'utf8');
  assert.match(example, /^GATEWAY_RELEASE_CHANNEL=canary$/mu);
  assert.ok(
    example.indexOf('GATEWAY_RELEASE_CHANNEL=canary') <
      example.indexOf('GATEWAY_RELEASE_ENVELOPE_JSON='),
  );
});

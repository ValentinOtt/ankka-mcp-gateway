import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import process from 'node:process';

const root = new URL('../', import.meta.url);
const [nodePin, packageManifest] = await Promise.all([
  readFile(new URL('.nvmrc', root), 'utf8'),
  readFile(new URL('package.json', root), 'utf8').then(JSON.parse),
]);

const expectedNode = nodePin.trim();
const expectedNpm = /^npm@(.+)$/u.exec(packageManifest.packageManager)?.[1] ?? null;
assert.match(expectedNode, /^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)$/u);
assert.match(expectedNpm, /^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)$/u);
assert.equal(process.version, `v${expectedNode}`, `expected Node v${expectedNode}, received ${process.version}`);
assert.equal(process.env.npm_config_user_agent?.split(' ', 1)[0], `npm/${expectedNpm}`,
  `expected npm ${expectedNpm}`);

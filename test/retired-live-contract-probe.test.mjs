import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { readdir, readFile } from 'node:fs/promises';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';

const execFileAsync = promisify(execFile);
const runner = new URL(
  '../apps/installer/scripts/live-contract-probe/run.mjs',
  import.meta.url,
);

test('the legacy account-wide live probe fails before credentials or network access', async () => {
  assert.deepEqual(
    (await readdir(new URL('../apps/installer/scripts/live-contract-probe/', import.meta.url))).sort(),
    ['README.md', 'run.mjs'],
  );
  const source = await readFile(runner, 'utf8');
  assert.doesNotMatch(
    source,
    /(?:CLOUDFLARE_API_TOKEN|\bfetch\s*\(|client\/v4|\bsweep\s*\(|method:\s*['"]DELETE['"])/u,
  );

  await assert.rejects(
    execFileAsync(process.execPath, [fileURLToPath(runner), 'install'], {
      env: { PATH: process.env.PATH ?? '' },
      encoding: 'utf8',
    }),
    (error) => {
      assert.equal(error.code, 1);
      assert.match(error.stderr, /^Retired: /u);
      assert.equal(error.stdout, '');
      return true;
    },
  );
});

import { execFile } from 'node:child_process';
import { readdir, readFile } from 'node:fs/promises';
import { describe, expect, it } from 'vitest';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';

const execFileAsync = promisify(execFile);
const runner = new URL('../scripts/exact-payload-canary/run.mjs', import.meta.url);

describe('retired exact-payload canary', () => {
  it('fails before credentials, provider output, or network access', async () => {
    expect(
      (await readdir(new URL('../scripts/exact-payload-canary/', import.meta.url))).sort(),
    ).toEqual(['run.mjs']);
    const source = await readFile(runner, 'utf8');
    expect(source).not.toMatch(
      /(?:CLOUDFLARE_API_TOKEN|\bfetch\s*\(|client\/v4|\bspawn\s*\(|method:\s*['"](?:PUT|POST|DELETE)['"])/u,
    );

    await expect(execFileAsync(process.execPath, [fileURLToPath(runner), 'install'], {
      env: { PATH: process.env.PATH ?? '' },
      encoding: 'utf8',
    })).rejects.toMatchObject({
      code: 1,
      stdout: '',
      stderr: expect.stringMatching(/^Retired: /u),
    });
  });
});

import { readdirSync, readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const sourceRoot = fileURLToPath(new URL('../src/', import.meta.url));

/** Comments may name the option in order to warn against it; only code counts. */
function withoutComments(text: string): string {
  return text
    .replace(/\/\*[\s\S]*?\*\//gu, '')
    .split('\n')
    .map((line) => line.replace(/\/\/.*$/u, ''))
    .join('\n');
}

/**
 * workerd refuses `redirect: 'error'` when a Request is built ("won't be
 * implemented since it does not make sense at the edge"). Node accepts it, so
 * a call site using it passes every test and fails on every real fetch in
 * production, as the Stage 1 readiness read did on 2026-09-03. Use
 * `redirect: 'manual'` and refuse redirects by status instead.
 */
describe('fetch options the Workers runtime rejects', () => {
  it('no source file asks fetch for redirect: error', () => {
    const offenders: string[] = [];
    for (const name of readdirSync(sourceRoot)) {
      if (!name.endsWith('.ts')) continue;
      const code = withoutComments(readFileSync(path.join(sourceRoot, name), 'utf8'));
      if (/redirect:\s*['"]error['"]/u.test(code)) offenders.push(name);
    }
    expect(offenders).toEqual([]);
  });
});

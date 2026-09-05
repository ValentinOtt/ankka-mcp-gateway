import { describe, expect, it } from 'vitest';

import { decodeWorkerModuleBase64 } from '../src/worker-module-base64';

const MAXIMUM = 8 * 1024 * 1024;

describe('canonical Worker module base64', () => {
  it.each([
    ['YQ==', [97]],
    ['YWI=', [97, 98]],
    ['YWJj', [97, 98, 99]],
    ['+/8=', [251, 255]],
  ])('decodes canonical padding and alphabet: %s', (value, bytes) => {
    expect(decodeWorkerModuleBase64(value, MAXIMUM)).toEqual(new Uint8Array(bytes));
  });

  it.each([
    '', 'Y', 'YQ', 'YQ=', 'YQ===', 'Y===', '====', '=YQ=', 'Y=Q=',
    'YQ==YQ==', 'YQ==\n', 'Y Q==', 'YQ\t=', 'YQ\r=', 'YQ\0=', 'YQ\u00a0=',
    '-_8=', '????', 'éé==', 'YR==', 'YWJ=',
  ])('rejects malformed or noncanonical content: %j', (value) => {
    expect(decodeWorkerModuleBase64(value, MAXIMUM)).toBeNull();
  });

  it.each([4 * 1024 * 1024, MAXIMUM])('decodes %i bytes within the declared bound', (size) => {
    const bytes = decodeWorkerModuleBase64(btoa('a'.repeat(size)), size);
    expect(bytes?.byteLength).toBe(size);
    expect(bytes?.every((byte) => byte === 97)).toBe(true);
  });

  it('rejects byte and encoded length overflow, including within a padded quartet', () => {
    expect(decodeWorkerModuleBase64('YWI=', 1)).toBeNull();
    expect(decodeWorkerModuleBase64('YWJj', 2)).toBeNull();
    expect(decodeWorkerModuleBase64('YWJjYQ==', 3)).toBeNull();
    expect(decodeWorkerModuleBase64(btoa('a'.repeat(MAXIMUM + 1)), MAXIMUM)).toBeNull();
  });

  it('rejects long malformed input and partial-quartet truncation without throwing', () => {
    const value = btoa('a'.repeat(4 * 1024 * 1024));
    for (const malformed of [
      value.slice(0, -1), value.slice(0, -2), value.slice(0, -3),
      `${value.slice(0, -4)}Y===`, `${value.slice(0, -4)}YR==`,
      `${value.slice(0, -4)}Y Q=`, `${value.slice(0, -4)}Y?==`,
      `=${value.slice(1)}`, `${value.slice(0, -4)}éé==`,
    ]) {
      expect(decodeWorkerModuleBase64(malformed, MAXIMUM)).toBeNull();
    }
  });
});

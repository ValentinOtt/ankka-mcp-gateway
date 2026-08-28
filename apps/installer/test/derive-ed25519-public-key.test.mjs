import assert from 'node:assert/strict';
import { createPrivateKey, createPublicKey } from 'node:crypto';
import { describe, it } from 'vitest';

import {
  deriveEd25519PublicKey,
  PublicKeyDerivationError,
} from '../scripts/derive-ed25519-public-key.mjs';

const PKCS8_SEED_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');

describe('stdin-only Ed25519 public-key derivation', () => {
  it('returns the standard raw public key without mutating the caller seed', () => {
    const seed = Buffer.alloc(32, 7);
    const before = Buffer.from(seed);
    const publicKey = deriveEd25519PublicKey(seed);
    const privateKey = createPrivateKey({
      key: Buffer.concat([PKCS8_SEED_PREFIX, seed]),
      format: 'der',
      type: 'pkcs8',
    });
    const expected = Buffer.from(
      createPublicKey(privateKey).export({ format: 'der', type: 'spki' }),
    ).subarray(-32).toString('base64url');
    assert.equal(publicKey, expected);
    assert.deepEqual(seed, before);
  });

  it('rejects every non-32-byte input with one fixed error', () => {
    for (const seed of [Buffer.alloc(0), Buffer.alloc(31), Buffer.alloc(33)]) {
      assert.throws(
        () => deriveEd25519PublicKey(seed),
        (error) => error instanceof PublicKeyDerivationError &&
          error.code === 'public_key_derivation_invalid',
      );
    }
  });
});

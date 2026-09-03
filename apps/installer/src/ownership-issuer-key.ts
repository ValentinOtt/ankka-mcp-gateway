import * as v from 'valibot';

import { base64UrlDecode, base64UrlEncode, constantTimeEqual } from './crypto';
import { DeployError } from './errors';

/**
 * Strict importer for the hosted ownership issuer key.
 *
 * The private key is provisioned as an encrypted Worker secret holding only
 * the 32-byte Ed25519 seed (base64url, 43 characters). The importer rebuilds
 * the PKCS#8 document, derives the public key, verifies it against the
 * separately configured public key and key id, and returns a non-extractable
 * signing key. A mismatch fails before any OAuth exchange or provider write.
 */

const TOKEN = /^[A-Za-z0-9_-]{43}$/u;
const KEY_ID = /^[a-z0-9](?:[a-z0-9._-]{0,62}[a-z0-9])?$/u;
const publicJwkSchema = v.object({
  kty: v.literal('OKP'),
  crv: v.literal('Ed25519'),
  x: v.pipe(v.string(), v.regex(TOKEN)),
});
/** RFC 8410 PrivateKeyInfo prefix for an Ed25519 seed: SEQUENCE, version 0, OID 1.3.101.112, OCTET STRING. */
const ED25519_PKCS8_PREFIX = Uint8Array.from([
  0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
]);

export interface OwnershipIssuerKeyInput {
  /** Base64url-encoded 32-byte Ed25519 seed from the Worker secret binding. */
  readonly privateKeySeed: string;
  /** Base64url-encoded 32-byte Ed25519 public key from the plain binding. */
  readonly publicKey: string;
  readonly keyId: string;
}

export interface OwnershipIssuerKey {
  readonly keyId: string;
  readonly publicKey: string;
  /** Non-extractable signing key; never leaves this isolate. */
  readonly privateKey: CryptoKey;
}

function invalid(): never {
  throw new DeployError(500, 'session_invalid', 'ownership_issuer_key_invalid');
}

function pkcs8(seed: Uint8Array): Uint8Array<ArrayBuffer> {
  const document = new Uint8Array(ED25519_PKCS8_PREFIX.byteLength + seed.byteLength);
  document.set(ED25519_PKCS8_PREFIX);
  document.set(seed, ED25519_PKCS8_PREFIX.byteLength);
  return document;
}

export async function importOwnershipIssuerKey(input: OwnershipIssuerKeyInput): Promise<OwnershipIssuerKey> {
  if (!TOKEN.test(input.privateKeySeed) || !TOKEN.test(input.publicKey) || !KEY_ID.test(input.keyId)) invalid();
  let seed: Uint8Array;
  try {
    seed = base64UrlDecode(input.privateKeySeed);
  } catch {
    invalid();
  }
  if (seed.byteLength !== 32) {
    seed.fill(0);
    invalid();
  }
  const document = pkcs8(seed);
  seed.fill(0);
  try {
    let derivedPublicKey: string;
    try {
      const extractable = await crypto.subtle.importKey('pkcs8', document, { name: 'Ed25519' }, true, ['sign']);
      const jwk = v.safeParse(publicJwkSchema, await crypto.subtle.exportKey('jwk', extractable));
      if (!jwk.success) invalid();
      derivedPublicKey = base64UrlEncode(base64UrlDecode(jwk.output.x));
    } catch (error) {
      if (error instanceof DeployError) throw error;
      invalid();
    }
    if (!constantTimeEqual(derivedPublicKey, input.publicKey)) invalid();
    let privateKey: CryptoKey;
    try {
      privateKey = await crypto.subtle.importKey('pkcs8', document, { name: 'Ed25519' }, false, ['sign']);
    } catch {
      invalid();
    }
    return Object.freeze({ keyId: input.keyId, publicKey: input.publicKey, privateKey });
  } finally {
    document.fill(0);
  }
}

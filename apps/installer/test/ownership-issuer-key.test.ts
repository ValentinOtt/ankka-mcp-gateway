import { base64UrlEncode } from '../src/crypto';
import { importOwnershipIssuerKey } from '../src/ownership-issuer-key';

async function issuerMaterial() {
  // SAFETY: Ed25519 generateKey always yields a key pair; the union only exists for symmetric algorithms.
  const keys = await crypto.subtle.generateKey('Ed25519', true, ['sign', 'verify']) as CryptoKeyPair;
  const pkcs8 = new Uint8Array(await crypto.subtle.exportKey('pkcs8', keys.privateKey));
  const seed = base64UrlEncode(pkcs8.subarray(pkcs8.byteLength - 32));
  const publicKey = base64UrlEncode(new Uint8Array(await crypto.subtle.exportKey('raw', keys.publicKey)));
  return { keys, seed, publicKey };
}

describe('ownership issuer key importer', () => {
  it('rebuilds a non-extractable signing key from the seed and proves it matches the pinned public key', async () => {
    const material = await issuerMaterial();
    const issuer = await importOwnershipIssuerKey({
      privateKeySeed: material.seed,
      publicKey: material.publicKey,
      keyId: 'ownership-key-v1',
    });
    expect(issuer.keyId).toBe('ownership-key-v1');
    expect(issuer.publicKey).toBe(material.publicKey);
    expect(issuer.privateKey.extractable).toBe(false);
    expect(issuer.privateKey.usages).toEqual(['sign']);
    const message = new TextEncoder().encode('ownership statement');
    const signature = await crypto.subtle.sign('Ed25519', issuer.privateKey, message);
    expect(await crypto.subtle.verify('Ed25519', material.keys.publicKey, signature, message)).toBe(true);
    await expect(crypto.subtle.exportKey('pkcs8', issuer.privateKey)).rejects.toThrow();
  });

  it('rejects a public key, key id, or seed that does not belong together before any use', async () => {
    const material = await issuerMaterial();
    const other = await issuerMaterial();
    const valid = { privateKeySeed: material.seed, publicKey: material.publicKey, keyId: 'ownership-key-v1' };
    const rejected = [
      { name: 'foreignPublicKey', input: { ...valid, publicKey: other.publicKey } },
      { name: 'foreignSeed', input: { ...valid, privateKeySeed: other.seed } },
      { name: 'shortSeed', input: { ...valid, privateKeySeed: material.seed.slice(1) } },
      { name: 'paddedSeed', input: { ...valid, privateKeySeed: `${material.seed}=` } },
      { name: 'shortPublicKey', input: { ...valid, publicKey: material.publicKey.slice(1) } },
      { name: 'badKeyId', input: { ...valid, keyId: 'Ownership Key' } },
      { name: 'emptyKeyId', input: { ...valid, keyId: '' } },
    ];
    for (const { name, input } of rejected) {
      await expect(importOwnershipIssuerKey(input), name)
        .rejects.toMatchObject({ status: 500, code: 'session_invalid', reason: 'ownership_issuer_key_invalid' });
    }
  });
});

import {
  BootstrapNonceDerivationError,
  deriveBootstrapNonce,
  type BootstrapNonceDerivationInput,
} from '../src/bootstrap-nonce';

function base64(bytes: Uint8Array): string {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function base64url(bytes: Uint8Array): string {
  return base64(bytes).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/u, '');
}

const KEY_BYTES = Uint8Array.from({ length: 32 }, (_value, index) => (index * 17 + 3) % 256);
const KEY_BASE64 = base64(KEY_BYTES);
const KEY_BASE64URL = base64url(KEY_BYTES);
const INPUT: BootstrapNonceDerivationInput = Object.freeze({
  sessionId: base64url(Uint8Array.from({ length: 32 }, (_value, index) => index + 1)),
  journalBindingHash: `sha256:${'1a'.repeat(32)}`,
  installationId: `acg-${'2b'.repeat(12)}`,
  releaseArtifactSha256: '3c'.repeat(32),
});

function serializedError(error: BootstrapNonceDerivationError): string {
  return JSON.stringify({
    name: error.name,
    message: error.message,
    code: error.code,
  });
}

describe('bootstrap nonce derivation', () => {
  it('locks the domain-separated canonical HMAC commitment to a stable vector', async () => {
    const nonce = await deriveBootstrapNonce(KEY_BASE64URL, INPUT);
    expect(nonce).toBe('b3E6b_VChagV9U7HCFCczjo42Ucl7DpHxRWvcS-KwkA');
    expect(nonce).toMatch(/^[A-Za-z0-9_-]{43}$/u);
    await expect(deriveBootstrapNonce(KEY_BASE64URL, { ...INPUT })).resolves.toBe(nonce);
  });

  it('accepts only the canonical base64 and base64url spellings of the same 32-byte key', async () => {
    const fromBase64 = await deriveBootstrapNonce(KEY_BASE64, INPUT);
    const fromBase64Url = await deriveBootstrapNonce(KEY_BASE64URL, INPUT);
    expect(fromBase64).toBe(fromBase64Url);
  });

  it('binds the nonce to every commitment field', async () => {
    const original = await deriveBootstrapNonce(KEY_BASE64URL, INPUT);
    const variants: BootstrapNonceDerivationInput[] = [
      { ...INPUT, sessionId: base64url(new Uint8Array(32).fill(8)) },
      { ...INPUT, journalBindingHash: `sha256:${'4d'.repeat(32)}` },
      { ...INPUT, installationId: `acg-${'5e'.repeat(12)}` },
      { ...INPUT, releaseArtifactSha256: '6f'.repeat(32) },
    ];
    for (const variant of variants) {
      await expect(deriveBootstrapNonce(KEY_BASE64URL, variant)).resolves.not.toBe(original);
    }
  });

  it('makes key rotation intentionally invalidate pending bootstrap recovery', async () => {
    const rotatedKey = base64url(Uint8Array.from(KEY_BYTES, (byte) => byte ^ 0xff));
    const beforeRotation = await deriveBootstrapNonce(KEY_BASE64URL, INPUT);
    const afterRotation = await deriveBootstrapNonce(rotatedKey, INPUT);
    expect(afterRotation).not.toBe(beforeRotation);
  });

  it.each([
    ['31 bytes', base64url(new Uint8Array(31).fill(1))],
    ['33 bytes', base64url(new Uint8Array(33).fill(1))],
    ['standard base64 without padding', KEY_BASE64.slice(0, -1)],
    ['base64url with padding', `${KEY_BASE64URL}=`],
    ['leading whitespace', ` ${KEY_BASE64URL}`],
    ['trailing whitespace', `${KEY_BASE64URL} `],
    ['non-canonical base64 pad bits', `${base64(new Uint8Array(32)).slice(0, 42)}B=`],
    ['non-canonical base64url pad bits', `${base64url(new Uint8Array(32)).slice(0, 42)}B`],
    ['malformed text', 'not-a-key'],
  ])('rejects a non-canonical or non-32-byte key: %s', async (_label, key) => {
    await expect(deriveBootstrapNonce(key, INPUT)).rejects.toBeInstanceOf(BootstrapNonceDerivationError);
  });

  it.each([
    ['session length', { ...INPUT, sessionId: 'x'.repeat(42) }],
    ['session alphabet', { ...INPUT, sessionId: `${INPUT.sessionId.slice(0, -1)}+` }],
    ['session pad bits', { ...INPUT, sessionId: `${base64url(new Uint8Array(32)).slice(0, 42)}B` }],
    ['binding prefix', { ...INPUT, journalBindingHash: '1a'.repeat(32) }],
    ['binding case', { ...INPUT, journalBindingHash: `sha256:${'A1'.repeat(32)}` }],
    ['installation prefix', { ...INPUT, installationId: `gateway-${'2b'.repeat(12)}` }],
    ['installation case', { ...INPUT, installationId: `acg-${'AB'.repeat(12)}` }],
    ['release prefix', { ...INPUT, releaseArtifactSha256: `sha256:${INPUT.releaseArtifactSha256}` }],
    ['release case', { ...INPUT, releaseArtifactSha256: 'CD'.repeat(32) }],
    ['extra field', { ...INPUT, extra: true }],
    ['missing field', {
      sessionId: INPUT.sessionId,
      journalBindingHash: INPUT.journalBindingHash,
      installationId: INPUT.installationId,
    }],
  ])('rejects an inexact commitment without reflecting values: %s', async (_label, value) => {
    let caught: BootstrapNonceDerivationError | null = null;
    try {
      await deriveBootstrapNonce(KEY_BASE64URL, value);
    } catch (error) {
      if (error instanceof BootstrapNonceDerivationError) caught = error;
    }
    expect(caught).toBeInstanceOf(BootstrapNonceDerivationError);
    if (!caught) throw new TypeError('expected bootstrap nonce derivation error');
    const serialized = serializedError(caught);
    expect(serialized).toBe(JSON.stringify({
      name: 'BootstrapNonceDerivationError',
      message: 'bootstrap_nonce_derivation_invalid',
      code: 'bootstrap_nonce_derivation_invalid',
    }));
    for (const secretOrField of [KEY_BASE64URL, INPUT.sessionId, INPUT.journalBindingHash, INPUT.installationId]) {
      expect(serialized).not.toContain(secretOrField);
    }
  });

  it('rejects accessors and non-plain commitment containers without invoking them', async () => {
    let invoked = false;
    const accessor = {
      ...INPUT,
      get sessionId() {
        invoked = true;
        return INPUT.sessionId;
      },
    };
    await expect(deriveBootstrapNonce(KEY_BASE64URL, accessor)).rejects.toBeInstanceOf(BootstrapNonceDerivationError);
    await expect(deriveBootstrapNonce(KEY_BASE64URL, Object.create(null))).rejects.toBeInstanceOf(BootstrapNonceDerivationError);
    expect(invoked).toBe(false);
  });

  it('never reflects a rejected source key in the stable error', async () => {
    const rejectedKey = `sensitive-${'x'.repeat(80)}`;
    let caught: BootstrapNonceDerivationError | null = null;
    try {
      await deriveBootstrapNonce(rejectedKey, INPUT);
    } catch (error) {
      if (error instanceof BootstrapNonceDerivationError) caught = error;
    }
    if (!caught) throw new TypeError('expected bootstrap nonce derivation error');
    expect(serializedError(caught)).not.toContain(rejectedKey);
  });
});

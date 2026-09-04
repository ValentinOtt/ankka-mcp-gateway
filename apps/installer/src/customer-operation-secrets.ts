import { base64UrlDecode, base64UrlEncode } from './crypto';

/**
 * Request-local material a gateway-local operation must carry across its own
 * restart: the runtime update uploads a new version of the Worker that runs
 * it, and only the new version can finish the journal. The one-time action
 * key is sealed under the deployment's ownership wrap key (an env secret the
 * new version inherits) and deleted right after it is used. Nothing here
 * derives a key for anything else.
 */
const AAD = new TextEncoder().encode('ankka-runtime-handover-v1');
const IV_BYTES = 12;
const KEY_BYTES = 32;
const MAX_SEALED_CHARS = 4_096;

function invalid(): never {
  throw new Error('operation_seal_invalid');
}

async function aesKey(wrapKey: string, usage: 'encrypt' | 'decrypt'): Promise<CryptoKey> {
  const decoded = base64UrlDecode(wrapKey);
  const owned = new Uint8Array(decoded.byteLength);
  owned.set(decoded);
  decoded.fill(0);
  if (owned.byteLength !== KEY_BYTES) {
    owned.fill(0);
    invalid();
  }
  try {
    return await crypto.subtle.importKey('raw', owned.buffer, { name: 'AES-GCM' }, false, [usage]);
  } finally {
    owned.fill(0);
  }
}

export async function sealOperationSecret(wrapKey: string, plaintext: string): Promise<string> {
  const key = await aesKey(wrapKey, 'encrypt');
  const iv = crypto.getRandomValues(new Uint8Array(IV_BYTES));
  const encoded = new TextEncoder().encode(plaintext);
  try {
    const sealed = new Uint8Array(await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv, additionalData: AAD }, key, encoded,
    ));
    return `${base64UrlEncode(iv)}.${base64UrlEncode(sealed)}`;
  } finally {
    encoded.fill(0);
  }
}

export async function openOperationSecret(wrapKey: string, sealed: string): Promise<string> {
  if (sealed.length > MAX_SEALED_CHARS) invalid();
  const parts = sealed.split('.');
  if (parts.length !== 2) invalid();
  const [encodedIv = '', encodedBody = ''] = parts;
  const key = await aesKey(wrapKey, 'decrypt');
  let iv: Uint8Array;
  let body: Uint8Array;
  try {
    iv = base64UrlDecode(encodedIv);
    body = base64UrlDecode(encodedBody);
  } catch {
    invalid();
  }
  if (iv.byteLength !== IV_BYTES) invalid();
  const ownedIv = new Uint8Array(iv.byteLength);
  ownedIv.set(iv);
  const ownedBody = new Uint8Array(body.byteLength);
  ownedBody.set(body);
  try {
    const plaintext = new Uint8Array(await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: ownedIv, additionalData: AAD }, key, ownedBody,
    ));
    try {
      return new TextDecoder('utf-8', { fatal: true }).decode(plaintext);
    } finally {
      plaintext.fill(0);
    }
  } catch {
    invalid();
  } finally {
    ownedIv.fill(0);
    ownedBody.fill(0);
  }
}

/** The gateway's HMAC over one canonical control body, in the header form the payload verifies. */
export async function operationSignature(actionKey: string, body: string): Promise<string> {
  const keyBytes = base64UrlDecode(actionKey);
  const ownedKey = new Uint8Array(keyBytes.byteLength);
  ownedKey.set(keyBytes);
  try {
    const key = await crypto.subtle.importKey(
      'raw', ownedKey.buffer, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign'],
    );
    const digest = new Uint8Array(await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(body)));
    try {
      return `sha256=${[...digest].map((byte) => byte.toString(16).padStart(2, '0')).join('')}`;
    } finally {
      digest.fill(0);
    }
  } finally {
    keyBytes.fill(0);
    ownedKey.fill(0);
  }
}

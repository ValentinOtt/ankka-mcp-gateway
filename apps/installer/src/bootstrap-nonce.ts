import * as v from 'valibot';

const encoder = new TextEncoder();

const DERIVATION_DOMAIN = 'ankka-mcp-gateway/bootstrap-nonce/v1';
const STANDARD_BASE64_KEY = /^[A-Za-z0-9+/]{43}=$/u;
const BASE64URL_KEY = /^[A-Za-z0-9_-]{43}$/u;
const SESSION_ID = /^[A-Za-z0-9_-]{43}$/u;
const JOURNAL_BINDING_HASH = /^sha256:[a-f0-9]{64}$/u;
const INSTALLATION_ID = /^acg-[a-f0-9]{24}$/u;
const RELEASE_ARTIFACT_SHA256 = /^[a-f0-9]{64}$/u;

const INPUT_KEYS = Object.freeze([
  'installationId',
  'journalBindingHash',
  'releaseArtifactSha256',
  'sessionId',
] as const);
const INPUT_KEY_SET = new Set<string>(INPUT_KEYS);
const nonceInputContainerSchema = v.object({});
const bootstrapNonceInputSchema = v.strictObject({
  installationId: v.pipe(v.string(), v.regex(INSTALLATION_ID)),
  journalBindingHash: v.pipe(v.string(), v.regex(JOURNAL_BINDING_HASH)),
  releaseArtifactSha256: v.pipe(v.string(), v.regex(RELEASE_ARTIFACT_SHA256)),
  sessionId: v.pipe(v.string(), v.regex(SESSION_ID)),
});

export interface BootstrapNonceDerivationInput {
  readonly sessionId: string;
  readonly journalBindingHash: string;
  readonly installationId: string;
  readonly releaseArtifactSha256: string;
}

/** A deliberately value-free failure safe to pass through a stable error boundary. */
export class BootstrapNonceDerivationError extends Error {
  readonly code = 'bootstrap_nonce_derivation_invalid';

  constructor() {
    super('bootstrap_nonce_derivation_invalid');
    this.name = 'BootstrapNonceDerivationError';
  }
}

function invalid(): never {
  throw new BootstrapNonceDerivationError();
}

function encodeBase64(bytes: Uint8Array): string {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function encodeBase64Url(bytes: Uint8Array): string {
  return encodeBase64(bytes)
    .replaceAll('+', '-')
    .replaceAll('/', '_')
    .replace(/=+$/u, '');
}

function decodeCanonicalBase64(value: string, variant: 'base64' | 'base64url'): Uint8Array<ArrayBuffer> {
  const encoded = variant === 'base64url'
    ? `${value.replaceAll('-', '+').replaceAll('_', '/')}=`
    : value;
  let decoded: string;
  try {
    decoded = atob(encoded);
  } catch {
    invalid();
  }
  const bytes = new Uint8Array(decoded.length);
  for (let index = 0; index < decoded.length; index += 1) {
    bytes[index] = decoded.charCodeAt(index);
  }
  if (
    bytes.byteLength !== 32 ||
    (variant === 'base64' ? encodeBase64(bytes) : encodeBase64Url(bytes)) !== value
  ) {
    bytes.fill(0);
    invalid();
  }
  return bytes;
}

function decodeDerivationKey<Value>(value: Value): Uint8Array<ArrayBuffer> {
  const result = v.safeParse(v.string(), value);
  if (!result.success) invalid();
  if (STANDARD_BASE64_KEY.test(result.output)) return decodeCanonicalBase64(result.output, 'base64');
  if (BASE64URL_KEY.test(result.output)) return decodeCanonicalBase64(result.output, 'base64url');
  invalid();
}

function canonicalSessionId(value: string): boolean {
  if (!SESSION_ID.test(value)) return false;
  try {
    const bytes = decodeCanonicalBase64(value, 'base64url');
    bytes.fill(0);
    return true;
  } catch {
    return false;
  }
}

function parseInput<Value>(value: Value): BootstrapNonceDerivationInput {
  try {
    if (!v.is(nonceInputContainerSchema, value)) invalid();
    if (Object.getPrototypeOf(value) !== Object.prototype) invalid();
    const ownKeys = Reflect.ownKeys(value);
    if (
      ownKeys.length !== INPUT_KEYS.length ||
      ownKeys.some((key) => !v.is(v.string(), key) || !INPUT_KEY_SET.has(key))
    ) invalid();
    const descriptors = Object.getOwnPropertyDescriptors(value);
    const installationId = descriptors.installationId;
    const journalBindingHash = descriptors.journalBindingHash;
    const releaseArtifactSha256 = descriptors.releaseArtifactSha256;
    const sessionId = descriptors.sessionId;
    if (
      installationId === undefined || installationId.enumerable !== true || !('value' in installationId) ||
      journalBindingHash === undefined || journalBindingHash.enumerable !== true || !('value' in journalBindingHash) ||
      releaseArtifactSha256 === undefined || releaseArtifactSha256.enumerable !== true ||
        !('value' in releaseArtifactSha256) ||
      sessionId === undefined || sessionId.enumerable !== true || !('value' in sessionId)
    ) invalid();

    const result = v.safeParse(bootstrapNonceInputSchema, {
      installationId: installationId.value,
      journalBindingHash: journalBindingHash.value,
      releaseArtifactSha256: releaseArtifactSha256.value,
      sessionId: sessionId.value,
    });
    if (!result.success || !canonicalSessionId(result.output.sessionId)) invalid();

    return Object.freeze(result.output);
  } catch {
    return invalid();
  }
}

function canonicalCommitment(input: BootstrapNonceDerivationInput): string {
  // Keys are deliberately kept in lexical order. Changing this wire commitment
  // is a derivation-version change, not a formatting refactor.
  return JSON.stringify({
    domain: DERIVATION_DOMAIN,
    installationId: input.installationId,
    journalBindingHash: input.journalBindingHash,
    releaseArtifactSha256: input.releaseArtifactSha256,
    schemaVersion: 1,
    sessionId: input.sessionId,
  });
}

/**
 * Derive the temporary customer-Worker bootstrap nonce without persisting it.
 *
 * `encodedKey` is injected by the caller from DEPLOY_SESSION_ENCRYPTION_KEY;
 * this module never reads configuration or state. Rotating that key changes the
 * nonce and therefore intentionally invalidates recovery for every pending
 * bootstrap operation. Rotation must wait until their recovery windows close.
 */
export async function deriveBootstrapNonce<Key, Input>(
  encodedKey: Key,
  input: Input,
): Promise<string> {
  const validated = parseInput(input);
  const keyBytes = decodeDerivationKey(encodedKey);
  let signature: Uint8Array<ArrayBuffer> | null = null;
  try {
    const key = await crypto.subtle.importKey(
      'raw',
      keyBytes,
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['sign'],
    );
    signature = new Uint8Array(await crypto.subtle.sign(
      'HMAC',
      key,
      encoder.encode(canonicalCommitment(validated)),
    ));
    return encodeBase64Url(signature);
  } catch {
    return invalid();
  } finally {
    signature?.fill(0);
    keyBytes.fill(0);
  }
}

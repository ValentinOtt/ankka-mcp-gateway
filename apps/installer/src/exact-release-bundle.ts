import type { GatewayDeployEnv } from './env';
import { DeployError } from './errors';
import {
  RELEASE_ENVELOPE_SCHEMA_VERSION,
  RELEASE_SIGNATURE_CONTEXT,
  type VerifiedReleaseBundle,
} from './release';
import { canonicalJson } from './release-manifest';

const CHANNEL = /^(?:canary|stable)$/u;
const RELEASE = /^gateway-v(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)$/u;
const KEY_ID = /^[a-z0-9][a-z0-9._-]{0,63}$/u;
const PUBLIC_KEY = /^[A-Za-z0-9_-]{43}$/u;
const SHA256 = /^[a-f0-9]{64}$/u;
const SIGNATURE = /^[A-Za-z0-9_-]{86}$/u;

/**
 * Secret-free immutable identity exported by the installed customer Worker.
 * It selects one create-only release prefix; it is never accepted from a
 * browser request or replaced with the currently promoted channel release.
 */
export interface ExactReleaseBundleIdentity {
  readonly schemaVersion: 1;
  readonly channel: 'canary' | 'stable';
  readonly release: string;
  readonly keyId: string;
  /** Raw Ed25519 public key encoded as unpadded base64url. */
  readonly publicKey: string;
  /** Exact aggregate `manifest.artifact.treeSha256` without a prefix. */
  readonly artifactSha256: string;
}

export interface ExactReleaseBundleProvider {
  loadVerifiedReleaseBundleForIdentity(
    env: GatewayDeployEnv,
    identity: ExactReleaseBundleIdentity,
  ): Promise<VerifiedReleaseBundle>;
}

function record(value: unknown): value is Record<string, unknown> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  try {
    return Object.getPrototypeOf(value) === Object.prototype &&
      Reflect.ownKeys(value).every((key) => typeof key === 'string') &&
      Object.values(Object.getOwnPropertyDescriptors(value)).every((descriptor) => (
        descriptor.enumerable === true && Object.hasOwn(descriptor, 'value')
      ));
  } catch { return false; }
}

export function parseExactReleaseBundleIdentity(value: unknown): Readonly<ExactReleaseBundleIdentity> {
  if (!record(value) || Object.keys(value).sort().join(',') !==
      'artifactSha256,channel,keyId,publicKey,release,schemaVersion' ||
    value.schemaVersion !== 1 || typeof value.channel !== 'string' || !CHANNEL.test(value.channel) ||
    typeof value.release !== 'string' || !RELEASE.test(value.release) ||
    typeof value.keyId !== 'string' || !KEY_ID.test(value.keyId) ||
    typeof value.publicKey !== 'string' || !PUBLIC_KEY.test(value.publicKey) ||
    typeof value.artifactSha256 !== 'string' || !SHA256.test(value.artifactSha256)) {
    throw new DeployError(503, 'release_invalid');
  }
  return Object.freeze({
    schemaVersion: 1,
    channel: value.channel as 'canary' | 'stable',
    release: value.release,
    keyId: value.keyId,
    publicKey: value.publicKey,
    artifactSha256: value.artifactSha256,
  });
}

/** Re-checks the exact identity even when a test or runtime adapter is injected. */
export function assertExactReleaseBundleIdentity(
  bundle: VerifiedReleaseBundle,
  identityValue: ExactReleaseBundleIdentity,
): void {
  const identity = parseExactReleaseBundleIdentity(identityValue);
  try {
    if (!record(bundle) || Object.keys(bundle).sort().join(',') !==
        'channel,envelope,keyId,manifest,payload,publicKey,verification' ||
      !Object.isFrozen(bundle) || bundle.verification !== 'ed25519' ||
      bundle.channel !== identity.channel || bundle.keyId !== identity.keyId ||
      bundle.publicKey !== identity.publicKey || !record(bundle.manifest) ||
      bundle.manifest.release !== identity.release || !record(bundle.manifest.artifact) ||
      bundle.manifest.artifact.treeSha256 !== identity.artifactSha256 ||
      !record(bundle.envelope) || !Object.isFrozen(bundle.envelope) ||
      Object.keys(bundle.envelope).sort().join(',') !==
        'channel,keyId,manifest,schemaVersion,signature,signatureContext' ||
      bundle.envelope.schemaVersion !== RELEASE_ENVELOPE_SCHEMA_VERSION ||
      bundle.envelope.signatureContext !== RELEASE_SIGNATURE_CONTEXT ||
      bundle.envelope.channel !== identity.channel || bundle.envelope.keyId !== identity.keyId ||
      typeof bundle.envelope.signature !== 'string' || !SIGNATURE.test(bundle.envelope.signature) ||
      bundle.envelope.manifest !== canonicalJson(bundle.manifest) ||
      !Array.isArray(bundle.payload) || !Object.isFrozen(bundle.payload)) {
      throw new TypeError('exact_release_bundle');
    }
  } catch {
    throw new DeployError(503, 'release_invalid');
  }
}

/** Default entrypoint behavior: historical release access is explicitly absent. */
export class DisabledExactReleaseBundleProvider implements ExactReleaseBundleProvider {
  async loadVerifiedReleaseBundleForIdentity(
    _env: GatewayDeployEnv,
    _identity: ExactReleaseBundleIdentity,
  ): Promise<VerifiedReleaseBundle> {
    throw new DeployError(503, 'release_unavailable');
  }
}

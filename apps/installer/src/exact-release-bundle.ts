import * as v from 'valibot';

import type { ReleaseEnvironment } from './release';
import { DeployError } from './errors';
import {
  RELEASE_ENVELOPE_SCHEMA_VERSION,
  RELEASE_SIGNATURE_CONTEXT,
  type VerifiedReleaseBundle,
} from './release';
import { canonicalJson, parseControlPlaneOrigin } from './release-manifest';

const RELEASE = /^gateway-v(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)$/u;
const KEY_ID = /^[a-z0-9][a-z0-9._-]{0,63}$/u;
const PUBLIC_KEY = /^[A-Za-z0-9_-]{43}$/u;
const SHA256 = /^[a-f0-9]{64}$/u;
const SIGNATURE = /^[A-Za-z0-9_-]{86}$/u;
export const exactReleaseBundleIdentitySchema = v.strictObject({
  artifactSha256: v.pipe(v.string(), v.regex(SHA256)),
  channel: v.picklist(['canary', 'stable']),
  controlPlaneOrigin: v.pipe(v.string(), v.url()),
  keyId: v.pipe(v.string(), v.regex(KEY_ID)),
  publicKey: v.pipe(v.string(), v.regex(PUBLIC_KEY)),
  release: v.pipe(v.string(), v.regex(RELEASE)),
  schemaVersion: v.literal(1),
});

/**
 * Secret-free immutable identity exported by the installed customer Worker.
 * It selects one create-only release prefix; it is never accepted from a
 * browser request or replaced with the currently promoted channel release.
 */
export interface ExactReleaseBundleIdentity {
  readonly schemaVersion: 1;
  readonly channel: 'canary' | 'stable';
  readonly controlPlaneOrigin: string;
  readonly release: string;
  readonly keyId: string;
  /** Raw Ed25519 public key encoded as unpadded base64url. */
  readonly publicKey: string;
  /** Exact aggregate `manifest.artifact.treeSha256` without a prefix. */
  readonly artifactSha256: string;
}

export interface ExactReleaseBundleProvider {
  loadVerifiedReleaseBundleForIdentity(
    env: ReleaseEnvironment,
    identity: ExactReleaseBundleIdentity,
  ): Promise<VerifiedReleaseBundle>;
}

export function parseExactReleaseBundleIdentity<Input>(
  value: Input,
): Readonly<ExactReleaseBundleIdentity> {
  const parsed = v.safeParse(exactReleaseBundleIdentitySchema, value);
  if (!parsed.success) throw new DeployError(503, 'release_invalid');
  return Object.freeze({
    ...parsed.output,
    controlPlaneOrigin: parseControlPlaneOrigin(parsed.output.controlPlaneOrigin),
  });
}

/** Re-checks the exact identity even when a test or runtime adapter is injected. */
export function assertExactReleaseBundleIdentity(
  bundle: VerifiedReleaseBundle,
  identityValue: ExactReleaseBundleIdentity,
): void {
  const identity = parseExactReleaseBundleIdentity(identityValue);
  try {
    if (Object.keys(bundle).sort().join(',') !==
        'channel,envelope,keyId,manifest,payload,publicKey,verification' ||
      !Object.isFrozen(bundle) || bundle.verification !== 'ed25519' ||
      bundle.channel !== identity.channel || bundle.keyId !== identity.keyId ||
      bundle.publicKey !== identity.publicKey ||
      bundle.manifest.controlPlaneOrigin !== identity.controlPlaneOrigin ||
      bundle.manifest.release !== identity.release ||
      bundle.manifest.artifact.treeSha256 !== identity.artifactSha256 ||
      !Object.isFrozen(bundle.envelope) ||
      Object.keys(bundle.envelope).sort().join(',') !==
        'channel,keyId,manifest,schemaVersion,signature,signatureContext' ||
      bundle.envelope.schemaVersion !== RELEASE_ENVELOPE_SCHEMA_VERSION ||
      bundle.envelope.signatureContext !== RELEASE_SIGNATURE_CONTEXT ||
      bundle.envelope.channel !== identity.channel || bundle.envelope.keyId !== identity.keyId ||
      !SIGNATURE.test(bundle.envelope.signature) ||
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
    _env: ReleaseEnvironment,
    _identity: ExactReleaseBundleIdentity,
  ): Promise<VerifiedReleaseBundle> {
    throw new DeployError(503, 'release_unavailable');
  }
}

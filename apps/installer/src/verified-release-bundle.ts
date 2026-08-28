import * as v from 'valibot';

import { boundaryObjectSchema } from './boundary';
import { DeployError } from './errors';
import {
  RELEASE_ENVELOPE_SCHEMA_VERSION,
  RELEASE_SIGNATURE_CONTEXT,
  type SignedReleaseEnvelope,
} from './release';
import {
  canonicalJson,
  parseReleaseManifest,
  type ReleaseManifest,
} from './release-manifest';

const CHANNEL_PATTERN = /^(?:canary|stable)$/u;
const KEY_ID_PATTERN = /^[a-z0-9][a-z0-9._-]{0,63}$/u;
const PUBLIC_KEY_PATTERN = /^[A-Za-z0-9_-]{43}$/u;
const SIGNATURE_PATTERN = /^[A-Za-z0-9_-]{86}$/u;
const safeNonnegativeIntegerSchema = v.pipe(v.number(), v.safeInteger(), v.minValue(0));

const verifiedPayloadBlobSchema = v.strictObject({
  byteSize: safeNonnegativeIntegerSchema,
  bytes: v.instance(Blob),
  contentType: v.string(),
  path: v.string(),
  sha256: v.string(),
});

const verifiedReleaseBundleSchema = v.strictObject({
  channel: v.string(),
  envelope: v.strictObject({
    channel: v.string(),
    keyId: v.string(),
    manifest: v.string(),
    schemaVersion: v.literal(RELEASE_ENVELOPE_SCHEMA_VERSION),
    signature: v.string(),
    signatureContext: v.literal(RELEASE_SIGNATURE_CONTEXT),
  }),
  keyId: v.string(),
  manifest: boundaryObjectSchema,
  payload: v.array(verifiedPayloadBlobSchema),
  publicKey: v.string(),
  verification: v.literal('ed25519'),
});

export interface ParsedVerifiedPayloadBlob {
  readonly byteSize: number;
  readonly bytes: Blob;
  readonly contentType: string;
  readonly path: string;
  readonly sha256: string;
}

export interface ParsedVerifiedReleaseBundle {
  readonly channel: string;
  readonly envelope: SignedReleaseEnvelope;
  readonly keyId: string;
  readonly manifest: ReleaseManifest;
  readonly payload: readonly ParsedVerifiedPayloadBlob[];
  readonly publicKey: string;
  readonly verification: 'ed25519';
}

function invalid(): never {
  throw new DeployError(503, 'release_invalid');
}

/** Revalidates a signed bundle at every privileged byte-consuming boundary. */
export function parseVerifiedReleaseBundle<Input>(input: Input): ParsedVerifiedReleaseBundle {
  const result = v.safeParse(verifiedReleaseBundleSchema, input);
  if (!result.success) invalid();
  const value = result.output;
  if (
    !CHANNEL_PATTERN.test(value.channel) ||
    !KEY_ID_PATTERN.test(value.keyId) ||
    value.envelope.channel !== value.channel ||
    value.envelope.keyId !== value.keyId ||
    !SIGNATURE_PATTERN.test(value.envelope.signature) ||
    !PUBLIC_KEY_PATTERN.test(value.publicKey)
  ) invalid();

  const manifest = parseReleaseManifest(value.manifest);
  if (value.envelope.manifest !== canonicalJson(manifest)) invalid();
  return Object.freeze({
    channel: value.channel,
    envelope: Object.freeze({ ...value.envelope }),
    keyId: value.keyId,
    manifest,
    payload: Object.freeze(value.payload.map((entry) => Object.freeze({ ...entry }))),
    publicKey: value.publicKey,
    verification: 'ed25519',
  });
}

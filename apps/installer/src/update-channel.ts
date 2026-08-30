import * as v from 'valibot';

import { DeployError } from './errors';
import {
  RELEASE_ENVELOPE_SCHEMA_VERSION,
  RELEASE_SIGNATURE_CONTEXT,
  type VerifiedReleaseBundle,
} from './release';
import { canonicalJson, parseCanonicalReleaseManifest } from './release-manifest';

const HASH = /^[a-f0-9]{64}$/u;
const KEY_ID = /^[a-z0-9][a-z0-9._-]{0,63}$/u;
const SIGNATURE = /^[A-Za-z0-9_-]{86}$/u;
const CHANNELS = Object.freeze(['canary', 'stable'] as const);
type PublicReleaseChannel = (typeof CHANNELS)[number];
const publicReleaseChannelSchema = v.picklist(CHANNELS);
const releaseEnvelopeSchema = v.strictObject({
  channel: publicReleaseChannelSchema,
  keyId: v.string(),
  manifest: v.string(),
  schemaVersion: v.literal(RELEASE_ENVELOPE_SCHEMA_VERSION),
  signature: v.string(),
  signatureContext: v.literal(RELEASE_SIGNATURE_CONTEXT),
});

export const NORMAL_UPDATE_CHANGES = Object.freeze([
  'customer_worker_code',
  'management_assets',
] as const);

export const NORMAL_UPDATE_EXCLUSIONS = Object.freeze([
  'access_policies',
  'credentials',
  'dns',
  'durable_object_migrations',
  'mcp_portal_configuration',
  'sources',
  'tool_allowlists',
] as const);

export interface PublicUpdateChannel {
  readonly schemaVersion: 1;
  readonly channel: PublicReleaseChannel;
  readonly release: {
    readonly id: string;
    readonly artifactSha256: string;
    readonly sourceCommit: string;
  };
  readonly classification: {
    readonly kind: 'normal';
    readonly updaterProtocol: 2;
    readonly changes: typeof NORMAL_UPDATE_CHANGES;
    readonly excludes: typeof NORMAL_UPDATE_EXCLUSIONS;
  };
  readonly notes: readonly string[];
  readonly verification: {
    readonly algorithm: 'ed25519';
    readonly channel: PublicReleaseChannel;
    readonly keyId: string;
    readonly manifest: string;
    readonly schemaVersion: typeof RELEASE_ENVELOPE_SCHEMA_VERSION;
    readonly signature: string;
    readonly signatureContext: typeof RELEASE_SIGNATURE_CONTEXT;
  };
}

const publicUpdateChannelSchema = v.strictObject({
  channel: publicReleaseChannelSchema,
  classification: v.strictObject({
    changes: v.tuple([
      v.literal('customer_worker_code'),
      v.literal('management_assets'),
    ]),
    excludes: v.tuple([
      v.literal('access_policies'),
      v.literal('credentials'),
      v.literal('dns'),
      v.literal('durable_object_migrations'),
      v.literal('mcp_portal_configuration'),
      v.literal('sources'),
      v.literal('tool_allowlists'),
    ]),
    kind: v.literal('normal'),
    updaterProtocol: v.literal(2),
  }),
  notes: v.pipe(
    v.array(v.pipe(v.string(), v.minLength(1), v.maxLength(512))),
    v.minLength(1),
    v.maxLength(8),
  ),
  release: v.strictObject({
    artifactSha256: v.string(),
    id: v.string(),
    sourceCommit: v.string(),
  }),
  schemaVersion: v.literal(1),
  verification: v.strictObject({
    algorithm: v.literal('ed25519'),
    channel: publicReleaseChannelSchema,
    keyId: v.string(),
    manifest: v.string(),
    schemaVersion: v.literal(RELEASE_ENVELOPE_SCHEMA_VERSION),
    signature: v.string(),
    signatureContext: v.literal(RELEASE_SIGNATURE_CONTEXT),
  }),
});

function invalid(): never {
  throw new DeployError(503, 'release_invalid');
}

export function buildPublicUpdateChannel(bundle: VerifiedReleaseBundle): PublicUpdateChannel {
  const channelResult = v.safeParse(publicReleaseChannelSchema, bundle.channel);
  const envelopeResult = v.safeParse(releaseEnvelopeSchema, bundle.envelope);
  if (
    !Object.isFrozen(bundle) ||
    !channelResult.success ||
    !envelopeResult.success ||
    bundle.verification !== 'ed25519' ||
    !KEY_ID.test(bundle.keyId) ||
    envelopeResult.output.channel !== channelResult.output ||
    envelopeResult.output.keyId !== bundle.keyId ||
    envelopeResult.output.manifest !== canonicalJson(bundle.manifest) ||
    !SIGNATURE.test(envelopeResult.output.signature) ||
    bundle.manifest.artifact.treeSha256.length !== 64 ||
    !HASH.test(bundle.manifest.artifact.treeSha256)
  ) invalid();
  return Object.freeze({
    schemaVersion: 1,
    channel: channelResult.output,
    release: Object.freeze({
      id: bundle.manifest.release,
      artifactSha256: `sha256:${bundle.manifest.artifact.treeSha256}`,
      sourceCommit: bundle.manifest.sourceCommit,
    }),
    classification: Object.freeze({
      kind: 'normal',
      updaterProtocol: 2,
      changes: NORMAL_UPDATE_CHANGES,
      excludes: NORMAL_UPDATE_EXCLUSIONS,
    }),
    notes: Object.freeze([
      `Signed ${bundle.manifest.release} gateway runtime and management application.`,
      'Normal update: customer configuration, credentials, Access, DNS, MCP sources, and tool allowlists are unchanged.',
      ...(bundle.manifest.release === 'gateway-v0.1.15' ? [
        'Team permissions apply only to MCP sources already installed in your gateway.',
        'New-source creation is unavailable in this release, including first-source onboarding for fresh empty gateways.',
        'Administrators remain fixed; source write tools are not activated and existing read-only boundaries are unchanged.',
        'Once a permission-policy write is armed, automatic teardown and rollback to older runtimes are blocked, including when the write outcome is uncertain.',
      ] : []),
    ]),
    verification: Object.freeze({
      algorithm: 'ed25519',
      channel: channelResult.output,
      keyId: envelopeResult.output.keyId,
      manifest: envelopeResult.output.manifest,
      schemaVersion: RELEASE_ENVELOPE_SCHEMA_VERSION,
      signature: envelopeResult.output.signature,
      signatureContext: RELEASE_SIGNATURE_CONTEXT,
    }),
  });
}

export function parsePublicUpdateChannel<Input>(input: Input): PublicUpdateChannel {
  const result = v.safeParse(publicUpdateChannelSchema, input);
  if (!result.success) invalid();
  const value = result.output;
  if (!/^sha256:[a-f0-9]{64}$/u.test(value.release.artifactSha256) ||
      !/^[a-f0-9]{40}$/u.test(value.release.sourceCommit) ||
      value.verification.channel !== value.channel ||
      !KEY_ID.test(value.verification.keyId) ||
      !SIGNATURE.test(value.verification.signature)) invalid();
  const manifest = parseCanonicalReleaseManifest(value.verification.manifest);
  if (manifest.release !== value.release.id ||
      `sha256:${manifest.artifact.treeSha256}` !== value.release.artifactSha256 ||
      manifest.sourceCommit !== value.release.sourceCommit) invalid();
  return Object.freeze({
    schemaVersion: 1,
    channel: value.channel,
    release: Object.freeze({ ...value.release }),
    classification: Object.freeze({
      kind: 'normal',
      updaterProtocol: 2,
      changes: NORMAL_UPDATE_CHANGES,
      excludes: NORMAL_UPDATE_EXCLUSIONS,
    }),
    notes: Object.freeze([...value.notes]),
    verification: Object.freeze({ ...value.verification }),
  });
}

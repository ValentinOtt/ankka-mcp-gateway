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

function invalid(): never {
  throw new DeployError(503, 'release_invalid');
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function exactKeys(value: Record<string, unknown>, keys: readonly string[]): boolean {
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  return actual.length === expected.length && actual.every((key, index) => key === expected[index]);
}

function exactStrings(value: unknown, expected: readonly string[]): boolean {
  return Array.isArray(value) && value.length === expected.length &&
    value.every((entry, index) => entry === expected[index]);
}

export function buildPublicUpdateChannel(bundle: VerifiedReleaseBundle): PublicUpdateChannel {
  if (
    !Object.isFrozen(bundle) ||
    !CHANNELS.includes(bundle.channel as PublicReleaseChannel) ||
    bundle.verification !== 'ed25519' ||
    !KEY_ID.test(bundle.keyId) ||
    !isRecord(bundle.envelope) ||
    !exactKeys(bundle.envelope as unknown as Record<string, unknown>, [
      'channel', 'keyId', 'manifest', 'schemaVersion', 'signature', 'signatureContext',
    ]) ||
    bundle.envelope.schemaVersion !== RELEASE_ENVELOPE_SCHEMA_VERSION ||
    bundle.envelope.channel !== bundle.channel ||
    bundle.envelope.keyId !== bundle.keyId ||
    bundle.envelope.manifest !== canonicalJson(bundle.manifest) ||
    !SIGNATURE.test(bundle.envelope.signature) ||
    bundle.envelope.signatureContext !== RELEASE_SIGNATURE_CONTEXT ||
    bundle.manifest.artifact.treeSha256.length !== 64 ||
    !HASH.test(bundle.manifest.artifact.treeSha256)
  ) invalid();
  return Object.freeze({
    schemaVersion: 1,
    channel: bundle.channel as PublicReleaseChannel,
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
    ]),
    verification: Object.freeze({
      algorithm: 'ed25519',
      channel: bundle.channel as PublicReleaseChannel,
      keyId: bundle.envelope.keyId,
      manifest: bundle.envelope.manifest,
      schemaVersion: RELEASE_ENVELOPE_SCHEMA_VERSION,
      signature: bundle.envelope.signature,
      signatureContext: RELEASE_SIGNATURE_CONTEXT,
    }),
  });
}

export function parsePublicUpdateChannel(input: unknown): PublicUpdateChannel {
  if (!isRecord(input) || !exactKeys(input, [
    'channel', 'classification', 'notes', 'release', 'schemaVersion', 'verification',
  ]) || input.schemaVersion !== 1 || !CHANNELS.includes(input.channel as PublicReleaseChannel) ||
      !isRecord(input.release) || !exactKeys(input.release, ['artifactSha256', 'id', 'sourceCommit']) ||
      typeof input.release.id !== 'string' || typeof input.release.artifactSha256 !== 'string' ||
      !/^sha256:[a-f0-9]{64}$/u.test(input.release.artifactSha256) ||
      typeof input.release.sourceCommit !== 'string' || !/^[a-f0-9]{40}$/u.test(input.release.sourceCommit) ||
      !isRecord(input.classification) || !exactKeys(input.classification, [
        'changes', 'excludes', 'kind', 'updaterProtocol',
      ]) || input.classification.kind !== 'normal' || input.classification.updaterProtocol !== 2 ||
      !exactStrings(input.classification.changes, NORMAL_UPDATE_CHANGES) ||
      !exactStrings(input.classification.excludes, NORMAL_UPDATE_EXCLUSIONS) ||
      !Array.isArray(input.notes) || input.notes.length < 1 || input.notes.length > 8 ||
      input.notes.some((note) => typeof note !== 'string' || note.length < 1 || note.length > 512) ||
      !isRecord(input.verification) || !exactKeys(input.verification, [
        'algorithm', 'channel', 'keyId', 'manifest', 'schemaVersion', 'signature', 'signatureContext',
      ]) || input.verification.algorithm !== 'ed25519' ||
      input.verification.channel !== input.channel ||
      typeof input.verification.keyId !== 'string' || !KEY_ID.test(input.verification.keyId) ||
      typeof input.verification.manifest !== 'string' ||
      input.verification.schemaVersion !== RELEASE_ENVELOPE_SCHEMA_VERSION ||
      typeof input.verification.signature !== 'string' || !SIGNATURE.test(input.verification.signature) ||
      input.verification.signatureContext !== RELEASE_SIGNATURE_CONTEXT) invalid();
  const manifest = parseCanonicalReleaseManifest(input.verification.manifest);
  if (manifest.release !== input.release.id ||
      `sha256:${manifest.artifact.treeSha256}` !== input.release.artifactSha256 ||
      manifest.sourceCommit !== input.release.sourceCommit) invalid();
  return Object.freeze({
    schemaVersion: 1,
    channel: input.channel as PublicReleaseChannel,
    release: Object.freeze({ ...input.release }) as PublicUpdateChannel['release'],
    classification: Object.freeze({
      kind: 'normal',
      updaterProtocol: 2,
      changes: NORMAL_UPDATE_CHANGES,
      excludes: NORMAL_UPDATE_EXCLUSIONS,
    }),
    notes: Object.freeze([...(input.notes as string[])]),
    verification: Object.freeze({ ...input.verification }) as PublicUpdateChannel['verification'],
  });
}

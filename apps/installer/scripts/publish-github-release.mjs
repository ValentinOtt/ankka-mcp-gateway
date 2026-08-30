/**
 * Reviewed GitHub Release mirror for an already-published gateway release.
 *
 * Preparation is offline and writes only public verification material. The
 * Cloudflare publication receipt is validated but never copied because it
 * contains infrastructure identifiers. Publishing is a separate explicit CLI
 * mode and delegates the network mutation to the authenticated GitHub CLI.
 */
import { execFile } from 'node:child_process';
import {
  createHash,
  createPublicKey,
  verify as ed25519Verify,
} from 'node:crypto';
import { constants as FS_CONSTANTS } from 'node:fs';
import { lstat, mkdir, open, readdir, realpath, writeFile } from 'node:fs/promises';
import path from 'node:path';
import process from 'node:process';
import { pathToFileURL } from 'node:url';
import { promisify } from 'node:util';
import * as v from 'valibot';

import { loadVerifiedR2PublicationDirectory } from './generate-r2-publication-worker.mjs';
import {
  RELEASE_ENVELOPE_SCHEMA_VERSION,
  RELEASE_SIGNATURE_CONTEXT,
  canonicalJson,
  classifyReviewedFaultWorker,
  loadVerifiedPublicRelease,
  releaseSignatureCanonicalJson,
} from './sign-gateway-release.mjs';
import { loadReleaseSbom } from '../../../scripts/generate-release-sbom.mjs';

const execFileAsync = promisify(execFile);
const RELEASE_PATTERN = /^gateway-v(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)$/u;
const CHANNEL_PATTERN = /^(?:canary|stable)$/u;
const KEY_ID_PATTERN = /^[a-z0-9][a-z0-9._-]{0,63}$/u;
const PUBLIC_KEY_PATTERN = /^[A-Za-z0-9_-]{43}$/u;
const SIGNATURE_PATTERN = /^[A-Za-z0-9_-]{86}$/u;
const SHA256_PATTERN = /^[a-f0-9]{64}$/u;
const COMMIT_PATTERN = /^[a-f0-9]{40}$/u;
const ACCOUNT_ID_PATTERN = /^[a-f0-9]{32}$/u;
const BUCKET_PATTERN = /^[a-z0-9][a-z0-9.-]{1,62}$/u;
const REPOSITORY_PATTERN = /^[A-Za-z0-9](?:[A-Za-z0-9_.-]{0,98}[A-Za-z0-9])?\/[A-Za-z0-9](?:[A-Za-z0-9_.-]{0,98}[A-Za-z0-9])?$/u;
const SAFE_SEGMENT = /^[A-Za-z0-9._-]+$/u;
const RELEASE_ROOT = 'ankka-mcp-gateway/releases';
const PLAN_FILENAME = 'github-release-plan.json';
const ENVELOPE_FILENAME = 'release-envelope.json';
const VERIFICATION_FILENAME = 'release-verification.json';
const SBOM_FILENAME = 'sbom.cdx.json';
const LICENSE_FILENAME = 'LICENSE.txt';
const THIRD_PARTY_LICENSES_FILENAME = 'THIRD_PARTY_LICENSES.txt';
const NOTES_FILENAME = 'RELEASE_NOTES.md';
const REQUIRED_GITHUB_CLI_VERSION = '2.98.0';
const OUTPUT_FILES = Object.freeze([
  LICENSE_FILENAME,
  NOTES_FILENAME,
  THIRD_PARTY_LICENSES_FILENAME,
  PLAN_FILENAME,
  ENVELOPE_FILENAME,
  VERIFICATION_FILENAME,
  SBOM_FILENAME,
]);
const MAX_INPUT_BYTES = 2 * 1024 * 1024;
const MAX_CONTROL_PLANE_ORIGIN_LENGTH = 2_048;
const SPKI_PUBLIC_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');
const OBJECT_SCHEMA = v.object({});
const STRING_SCHEMA = v.string();

export class GitHubReleasePublicationError extends Error {
  constructor(code) {
    super(code);
    this.name = 'GitHubReleasePublicationError';
    this.code = code;
  }
}

function fail(code = 'github_release_invalid') {
  throw new GitHubReleasePublicationError(code);
}

function isRecord(value) {
  return v.is(OBJECT_SCHEMA, value) && !Array.isArray(value);
}

function exactKeys(value, expected) {
  if (!isRecord(value)) return false;
  const actual = Object.keys(value).sort();
  const sorted = [...expected].sort();
  return actual.length === sorted.length && actual.every((key, index) => key === sorted[index]);
}

function sha256Hex(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

function safeInteger(value, maximum = Number.MAX_SAFE_INTEGER) {
  return Number.isSafeInteger(value) && value >= 0 && value <= maximum;
}

function parseControlPlaneOrigin(value) {
  if (
    !v.is(STRING_SCHEMA, value) ||
    value.length === 0 ||
    value.length > MAX_CONTROL_PLANE_ORIGIN_LENGTH
  ) fail();
  try {
    const parsed = new URL(value);
    if (
      parsed.protocol !== 'https:' || parsed.username !== '' || parsed.password !== '' ||
      parsed.port !== '' || parsed.pathname !== '/' || parsed.search !== '' ||
      parsed.hash !== '' || parsed.origin !== value || value.includes("'")
    ) fail();
  } catch (error) {
    if (error instanceof GitHubReleasePublicationError) throw error;
    fail();
  }
  return value;
}

async function readRegularBytes(filename, maximum = MAX_INPUT_BYTES) {
  if (!v.is(STRING_SCHEMA, filename) || filename.length === 0 || filename.includes('\0')) fail();
  const resolved = path.resolve(filename);
  let handle;
  try {
    const before = await lstat(resolved);
    if (!before.isFile() || before.isSymbolicLink() || !safeInteger(before.size, maximum)) fail();
    handle = await open(resolved, FS_CONSTANTS.O_RDONLY | (FS_CONSTANTS.O_NOFOLLOW ?? 0));
    const opened = await handle.stat();
    if (!opened.isFile() || opened.size !== before.size || opened.dev !== before.dev || opened.ino !== before.ino) fail();
    const bytes = await handle.readFile();
    if (bytes.byteLength !== opened.size) fail();
    return bytes;
  } catch (error) {
    if (error instanceof GitHubReleasePublicationError) throw error;
    fail();
  } finally {
    await handle?.close().catch(() => {});
  }
}

async function readJson(filename) {
  const bytes = await readRegularBytes(filename);
  try {
    return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
  } catch {
    fail();
  } finally {
    bytes.fill(0);
  }
}

function parsePublicationReceipt(input) {
  if (!exactKeys(input, [
    'accountId',
    'artifactSha256',
    'bucketName',
    'channel',
    'controlPlaneOrigin',
    'keyId',
    'objectPlanSha256',
    'prefix',
    'publicKey',
    'release',
    'releaseEnvelopeSha256',
    'schemaVersion',
    'status',
  ])) fail();
  if (
    input.schemaVersion !== 1 ||
    input.status !== 'published' ||
    !v.is(STRING_SCHEMA, input.accountId) || !ACCOUNT_ID_PATTERN.test(input.accountId) ||
    !v.is(STRING_SCHEMA, input.bucketName) || !BUCKET_PATTERN.test(input.bucketName) ||
    !v.is(STRING_SCHEMA, input.channel) || !CHANNEL_PATTERN.test(input.channel) ||
    parseControlPlaneOrigin(input.controlPlaneOrigin) !== input.controlPlaneOrigin ||
    !v.is(STRING_SCHEMA, input.release) || !RELEASE_PATTERN.test(input.release) ||
    !v.is(STRING_SCHEMA, input.keyId) || !KEY_ID_PATTERN.test(input.keyId) ||
    !v.is(STRING_SCHEMA, input.publicKey) || !PUBLIC_KEY_PATTERN.test(input.publicKey) ||
    !v.is(STRING_SCHEMA, input.artifactSha256) || !SHA256_PATTERN.test(input.artifactSha256) ||
    !v.is(STRING_SCHEMA, input.releaseEnvelopeSha256) || !SHA256_PATTERN.test(input.releaseEnvelopeSha256) ||
    !v.is(STRING_SCHEMA, input.objectPlanSha256) || !SHA256_PATTERN.test(input.objectPlanSha256) ||
    input.prefix !== `${RELEASE_ROOT}/${input.channel}/${input.release}/`
  ) fail();
  return Object.freeze({ ...input });
}

function parseEnvelope(bytes, receipt, serializedManifest) {
  let serialized;
  let envelope;
  try {
    serialized = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
    envelope = JSON.parse(serialized);
    if (canonicalJson(envelope) !== serialized) fail();
  } catch (error) {
    if (error instanceof GitHubReleasePublicationError) throw error;
    fail();
  }
  if (
    !exactKeys(envelope, [
      'channel', 'keyId', 'manifest', 'schemaVersion', 'signature', 'signatureContext',
    ]) ||
    envelope.schemaVersion !== RELEASE_ENVELOPE_SCHEMA_VERSION ||
    envelope.channel !== receipt.channel ||
    envelope.keyId !== receipt.keyId ||
    envelope.manifest !== serializedManifest ||
    !v.is(STRING_SCHEMA, envelope.signature) || !SIGNATURE_PATTERN.test(envelope.signature) ||
    envelope.signatureContext !== RELEASE_SIGNATURE_CONTEXT
  ) fail();

  let rawPublic;
  let signature;
  let spki;
  try {
    rawPublic = Buffer.from(receipt.publicKey, 'base64url');
    signature = Buffer.from(envelope.signature, 'base64url');
    if (
      rawPublic.byteLength !== 32 || rawPublic.toString('base64url') !== receipt.publicKey ||
      signature.byteLength !== 64 || signature.toString('base64url') !== envelope.signature
    ) fail();
    spki = Buffer.concat([SPKI_PUBLIC_PREFIX, rawPublic]);
    const key = createPublicKey({ key: spki, format: 'der', type: 'spki' });
    if (!ed25519Verify(
      null,
      Buffer.from(releaseSignatureCanonicalJson(
        envelope.channel,
        envelope.keyId,
        envelope.manifest,
      ), 'utf8'),
      key,
      signature,
    )) fail();
  } catch (error) {
    if (error instanceof GitHubReleasePublicationError) throw error;
    fail();
  } finally {
    rawPublic?.fill(0);
    signature?.fill(0);
    spki?.fill(0);
  }
  return Object.freeze(envelope);
}

function releaseTitle(release, channel) {
  const version = release.slice('gateway-'.length);
  return `Ankka MCP Gateway ${version}${channel === 'canary' ? ' (canary)' : ''}`;
}

export function releaseNotes(repository, manifest, receipt) {
  const commitUrl = `https://github.com/${repository}/commit/${manifest.sourceCommit}`;
  const channelLabel = receipt.channel === 'canary' ? 'Canary pre-release' : 'Stable release';
  const teamReleaseNotes = ['gateway-v0.1.15', 'gateway-v0.1.16', 'gateway-v0.1.17'].includes(manifest.release)
    ? `## ${manifest.release.slice('gateway-'.length)} scope and limits\n\n` +
      '- Team permissions apply only to MCP sources already installed in your gateway.\n' +
      '- New-source creation is unavailable in this release, including first-source onboarding for fresh empty gateways.\n' +
      '- Administrators remain fixed; source write tools are not activated and existing read-only boundaries are unchanged.\n' +
      '- Once a permission-policy write is armed, automatic teardown and rollback to older runtimes are blocked, including when the write outcome is uncertain.\n\n'
    : '';
  const bridgeReleaseNotes = manifest.release === 'gateway-v0.1.17'
    ? '- Compatibility bridge: accepts the reviewed next Team release contract and fixes the installer return to your gateway after completion.\n' +
      '- This update does not create a Team credential or enable customer-local Team management; a separate second update is required.\n\n'
    : '';
  return `${channelLabel} of Ankka MCP Gateway. This GitHub Release mirrors the exact signed artifact already committed to the customer update channel.\n\n` +
    teamReleaseNotes +
    bridgeReleaseNotes +
    `- Source commit: [\`${manifest.sourceCommit.slice(0, 12)}\`](${commitUrl})\n` +
    `- Artifact SHA-256: \`${receipt.artifactSha256}\`\n` +
    `- Signature: Ed25519 (key ID \`${receipt.keyId}\`)\n` +
    `- Channel: \`${receipt.channel}\`\n\n` +
    `The attached \`${ENVELOPE_FILENAME}\` is the canonical signed release envelope. ` +
    `\`${VERIFICATION_FILENAME}\` contains only public verification material, and ` +
    `\`${SBOM_FILENAME}\` is the source-bound CycloneDX dependency inventory. ` +
    `\`${LICENSE_FILENAME}\` and \`${THIRD_PARTY_LICENSES_FILENAME}\` contain the complete distributed license texts. ` +
    `Cloudflare account, bucket, credentials, and private signing material are intentionally excluded.\n`;
}

function assetRecord(name, bytes) {
  return Object.freeze({ byteSize: bytes.byteLength, name, sha256: sha256Hex(bytes) });
}

function zeroVerifiedPublication(verified) {
  for (const object of verified?.objects ?? []) object.bytes.fill(0);
}

export async function prepareGitHubReleaseOutput(input) {
  if (!exactKeys(input, ['publicationResult', 'publishDirectory', 'releaseDirectory', 'repository', 'sbom'])) fail();
  if (!v.is(STRING_SCHEMA, input.repository) || !REPOSITORY_PATTERN.test(input.repository)) fail();
  const receipt = parsePublicationReceipt(await readJson(input.publicationResult));
  let signed;
  let candidate;
  let inputSbomBytes;
  try {
    signed = await loadVerifiedR2PublicationDirectory(input.publishDirectory);
    candidate = await loadVerifiedPublicRelease(input.releaseDirectory, receipt.release);
    const worker = candidate.payload.find((entry) => entry.record.path === 'payload/worker/index.js');
    if (!worker || classifyReviewedFaultWorker(worker.bytes) !== 'ordinary') {
      fail('github_fault_injection_forbidden');
    }
    const plan = signed.plan;
    if (
      plan.release !== receipt.release ||
      plan.channel !== receipt.channel ||
      plan.controlPlaneOrigin !== receipt.controlPlaneOrigin ||
      plan.keyId !== receipt.keyId ||
      plan.artifactSha256 !== receipt.artifactSha256 ||
      signed.objectPlanSha256 !== receipt.objectPlanSha256 ||
      candidate.manifest.artifact.treeSha256 !== receipt.artifactSha256 ||
      candidate.manifest.controlPlaneOrigin !== receipt.controlPlaneOrigin ||
      !COMMIT_PATTERN.test(candidate.manifest.sourceCommit)
    ) fail();
    const envelopeObject = signed.objects.find((object) => object.key === `${plan.prefix}${ENVELOPE_FILENAME}`);
    if (
      !envelopeObject ||
      envelopeObject.sha256 !== receipt.releaseEnvelopeSha256 ||
      sha256Hex(envelopeObject.bytes) !== receipt.releaseEnvelopeSha256
    ) fail();
    parseEnvelope(envelopeObject.bytes, receipt, candidate.serialized);
    inputSbomBytes = await readRegularBytes(input.sbom);
    loadReleaseSbom(inputSbomBytes, {
      release: receipt.release,
      sourceCommit: candidate.manifest.sourceCommit,
    });

    const envelopeBytes = Buffer.from(envelopeObject.bytes);
    const sbomBytes = Buffer.from(inputSbomBytes);
    const distributedFile = (filename) => {
      const matches = candidate.payload.filter((entry) =>
        entry.record.path === `payload/admin/${filename}` &&
        entry.record.contentType === 'text/plain; charset=utf-8');
      if (matches.length !== 1) fail();
      return Buffer.from(matches[0].bytes);
    };
    const licenseBytes = distributedFile(LICENSE_FILENAME);
    const thirdPartyLicensesBytes = distributedFile(THIRD_PARTY_LICENSES_FILENAME);
    const verification = Object.freeze({
      artifactSha256: receipt.artifactSha256,
      channel: receipt.channel,
      controlPlaneOrigin: receipt.controlPlaneOrigin,
      keyId: receipt.keyId,
      manifestSha256: sha256Hex(candidate.manifestBytes),
      objectPlanSha256: receipt.objectPlanSha256,
      publicKey: receipt.publicKey,
      release: receipt.release,
      releaseEnvelopeSha256: receipt.releaseEnvelopeSha256,
      schemaVersion: 1,
      signatureAlgorithm: 'ed25519',
      sourceCommit: candidate.manifest.sourceCommit,
    });
    const verificationBytes = Buffer.from(canonicalJson(verification), 'utf8');
    const notesBytes = Buffer.from(releaseNotes(input.repository, candidate.manifest, receipt), 'utf8');
    const assets = Object.freeze([
      assetRecord(ENVELOPE_FILENAME, envelopeBytes),
      assetRecord(VERIFICATION_FILENAME, verificationBytes),
      assetRecord(SBOM_FILENAME, sbomBytes),
      assetRecord(LICENSE_FILENAME, licenseBytes),
      assetRecord(THIRD_PARTY_LICENSES_FILENAME, thirdPartyLicensesBytes),
    ]);
    const githubPlan = Object.freeze({
      artifactSha256: receipt.artifactSha256,
      assets,
      channel: receipt.channel,
      latest: receipt.channel === 'stable',
      notesSha256: sha256Hex(notesBytes),
      prerelease: receipt.channel === 'canary',
      release: receipt.release,
      repository: input.repository,
      schemaVersion: 1,
      sourceCommit: candidate.manifest.sourceCommit,
      tag: receipt.release,
      title: releaseTitle(receipt.release, receipt.channel),
    });
    return Object.freeze({
      envelopeBytes,
      licenseBytes,
      notesBytes,
      plan: githubPlan,
      planBytes: Buffer.from(canonicalJson(githubPlan), 'utf8'),
      sbomBytes,
      thirdPartyLicensesBytes,
      verificationBytes,
    });
  } catch (error) {
    if (error instanceof GitHubReleasePublicationError) throw error;
    fail();
  } finally {
    candidate?.manifestBytes.fill(0);
    for (const entry of candidate?.payload ?? []) entry.bytes.fill(0);
    inputSbomBytes?.fill(0);
    zeroVerifiedPublication(signed);
  }
}

async function writeCreateOnly(filename, bytes) {
  try {
    await writeFile(filename, bytes, { flag: 'wx', mode: 0o600 });
  } catch {
    fail('github_release_output_exists');
  }
}

export async function writeGitHubReleaseOutput(prepared, outputDirectory) {
  if (!prepared?.plan || !v.is(STRING_SCHEMA, outputDirectory) || outputDirectory.length === 0 || outputDirectory.includes('\0')) fail();
  const resolved = path.resolve(outputDirectory);
  const basename = path.basename(resolved);
  if (!SAFE_SEGMENT.test(basename) || basename === '.' || basename === '..') fail();
  const parent = await realpath(path.dirname(resolved)).catch(() => fail());
  const root = path.join(parent, basename);
  try {
    await mkdir(root, { recursive: false, mode: 0o700 });
  } catch {
    fail('github_release_output_exists');
  }
  await writeCreateOnly(path.join(root, ENVELOPE_FILENAME), prepared.envelopeBytes);
  await writeCreateOnly(path.join(root, VERIFICATION_FILENAME), prepared.verificationBytes);
  await writeCreateOnly(path.join(root, SBOM_FILENAME), prepared.sbomBytes);
  await writeCreateOnly(path.join(root, LICENSE_FILENAME), prepared.licenseBytes);
  await writeCreateOnly(path.join(root, THIRD_PARTY_LICENSES_FILENAME), prepared.thirdPartyLicensesBytes);
  await writeCreateOnly(path.join(root, NOTES_FILENAME), prepared.notesBytes);
  await writeCreateOnly(path.join(root, PLAN_FILENAME), prepared.planBytes);
  return root;
}

function parseOutputPlan(input) {
  if (!exactKeys(input, [
    'artifactSha256', 'assets', 'channel', 'latest', 'notesSha256', 'prerelease',
    'release', 'repository', 'schemaVersion', 'sourceCommit', 'tag', 'title',
  ])) fail();
  if (
    input.schemaVersion !== 1 ||
    !v.is(STRING_SCHEMA, input.release) || !RELEASE_PATTERN.test(input.release) ||
    input.tag !== input.release ||
    !v.is(STRING_SCHEMA, input.channel) || !CHANNEL_PATTERN.test(input.channel) ||
    !v.is(STRING_SCHEMA, input.repository) || !REPOSITORY_PATTERN.test(input.repository) ||
    !v.is(STRING_SCHEMA, input.sourceCommit) || !COMMIT_PATTERN.test(input.sourceCommit) ||
    !v.is(STRING_SCHEMA, input.artifactSha256) || !SHA256_PATTERN.test(input.artifactSha256) ||
    !v.is(STRING_SCHEMA, input.notesSha256) || !SHA256_PATTERN.test(input.notesSha256) ||
    input.prerelease !== (input.channel === 'canary') ||
    input.latest !== (input.channel === 'stable') ||
    !v.is(STRING_SCHEMA, input.title) || input.title !== releaseTitle(input.release, input.channel) ||
    !Array.isArray(input.assets) || input.assets.length !== 5
  ) fail();
  const expectedNames = [
    ENVELOPE_FILENAME, VERIFICATION_FILENAME, SBOM_FILENAME,
    LICENSE_FILENAME, THIRD_PARTY_LICENSES_FILENAME,
  ];
  for (let index = 0; index < expectedNames.length; index += 1) {
    const asset = input.assets[index];
    if (
      !exactKeys(asset, ['byteSize', 'name', 'sha256']) ||
      asset.name !== expectedNames[index] ||
      !safeInteger(asset.byteSize, MAX_INPUT_BYTES) || asset.byteSize === 0 ||
      !v.is(STRING_SCHEMA, asset.sha256) || !SHA256_PATTERN.test(asset.sha256)
    ) fail();
  }
  return Object.freeze(input);
}

export async function loadGitHubReleaseOutput(outputDirectory) {
  if (!v.is(STRING_SCHEMA, outputDirectory) || outputDirectory.length === 0 || outputDirectory.includes('\0')) fail();
  let root;
  try {
    root = await realpath(path.resolve(outputDirectory));
    const metadata = await lstat(root);
    if (!metadata.isDirectory() || metadata.isSymbolicLink()) fail();
    const entries = await readdir(root, { withFileTypes: true });
    const names = entries.map((entry) => entry.name).sort();
    if (
      names.length !== OUTPUT_FILES.length ||
      names.some((name, index) => name !== OUTPUT_FILES[index]) ||
      entries.some((entry) => !entry.isFile() || entry.isSymbolicLink())
    ) fail();
  } catch (error) {
    if (error instanceof GitHubReleasePublicationError) throw error;
    fail();
  }
  const [
    planBytes, envelopeBytes, verificationBytes, sbomBytes, licenseBytes,
    thirdPartyLicensesBytes, notesBytes,
  ] = await Promise.all([
    readRegularBytes(path.join(root, PLAN_FILENAME)),
    readRegularBytes(path.join(root, ENVELOPE_FILENAME)),
    readRegularBytes(path.join(root, VERIFICATION_FILENAME)),
    readRegularBytes(path.join(root, SBOM_FILENAME)),
    readRegularBytes(path.join(root, LICENSE_FILENAME)),
    readRegularBytes(path.join(root, THIRD_PARTY_LICENSES_FILENAME)),
    readRegularBytes(path.join(root, NOTES_FILENAME)),
  ]);
  try {
    const planSerialized = new TextDecoder('utf-8', { fatal: true }).decode(planBytes);
    const planInput = JSON.parse(planSerialized);
    if (canonicalJson(planInput) !== planSerialized) fail();
    const plan = parseOutputPlan(planInput);
    if (
      sha256Hex(notesBytes) !== plan.notesSha256 ||
      sha256Hex(envelopeBytes) !== plan.assets[0].sha256 || envelopeBytes.byteLength !== plan.assets[0].byteSize ||
      sha256Hex(verificationBytes) !== plan.assets[1].sha256 || verificationBytes.byteLength !== plan.assets[1].byteSize ||
      sha256Hex(sbomBytes) !== plan.assets[2].sha256 || sbomBytes.byteLength !== plan.assets[2].byteSize ||
      sha256Hex(licenseBytes) !== plan.assets[3].sha256 || licenseBytes.byteLength !== plan.assets[3].byteSize ||
      sha256Hex(thirdPartyLicensesBytes) !== plan.assets[4].sha256 ||
        thirdPartyLicensesBytes.byteLength !== plan.assets[4].byteSize
    ) fail();
    loadReleaseSbom(sbomBytes, { release: plan.release, sourceCommit: plan.sourceCommit });
    const verificationSerialized = new TextDecoder('utf-8', { fatal: true }).decode(verificationBytes);
    const verification = JSON.parse(verificationSerialized);
    if (
      canonicalJson(verification) !== verificationSerialized ||
      !exactKeys(verification, [
        'artifactSha256', 'channel', 'controlPlaneOrigin', 'keyId', 'manifestSha256', 'objectPlanSha256',
        'publicKey', 'release', 'releaseEnvelopeSha256', 'schemaVersion',
        'signatureAlgorithm', 'sourceCommit',
      ]) ||
      verification.schemaVersion !== 1 ||
      verification.release !== plan.release ||
      verification.channel !== plan.channel ||
      parseControlPlaneOrigin(verification.controlPlaneOrigin) !== verification.controlPlaneOrigin ||
      verification.sourceCommit !== plan.sourceCommit ||
      verification.artifactSha256 !== plan.artifactSha256 ||
      verification.releaseEnvelopeSha256 !== plan.assets[0].sha256 ||
      verification.signatureAlgorithm !== 'ed25519' ||
      !v.is(STRING_SCHEMA, verification.keyId) || !KEY_ID_PATTERN.test(verification.keyId) ||
      !v.is(STRING_SCHEMA, verification.publicKey) || !PUBLIC_KEY_PATTERN.test(verification.publicKey) ||
      !v.is(STRING_SCHEMA, verification.manifestSha256) || !SHA256_PATTERN.test(verification.manifestSha256) ||
      !v.is(STRING_SCHEMA, verification.objectPlanSha256) || !SHA256_PATTERN.test(verification.objectPlanSha256)
    ) fail();
    const envelope = parseEnvelope(envelopeBytes, {
      channel: verification.channel,
      keyId: verification.keyId,
      publicKey: verification.publicKey,
    }, JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(envelopeBytes)).manifest);
    let manifest;
    try {
      manifest = JSON.parse(envelope.manifest);
      if (canonicalJson(manifest) !== envelope.manifest) fail();
    } catch (error) {
      if (error instanceof GitHubReleasePublicationError) throw error;
      fail();
    }
    if (
      sha256Hex(Buffer.from(envelope.manifest, 'utf8')) !== verification.manifestSha256 ||
      manifest.release !== plan.release ||
      manifest.sourceCommit !== plan.sourceCommit ||
      manifest.controlPlaneOrigin !== verification.controlPlaneOrigin ||
      !isRecord(manifest.artifact) ||
      manifest.artifact.treeSha256 !== plan.artifactSha256
    ) fail();
    return Object.freeze({ root, plan });
  } catch (error) {
    if (error instanceof GitHubReleasePublicationError) throw error;
    fail();
  } finally {
    planBytes.fill(0);
    envelopeBytes.fill(0);
    verificationBytes.fill(0);
    sbomBytes.fill(0);
    licenseBytes.fill(0);
    thirdPartyLicensesBytes.fill(0);
    notesBytes.fill(0);
  }
}

async function defaultCommand(command, args) {
  try {
    const result = await execFileAsync(command, args, {
      encoding: 'utf8',
      env: { HOME: process.env.HOME, PATH: process.env.PATH },
      maxBuffer: MAX_INPUT_BYTES,
    });
    return Object.freeze({ code: 0, stdout: result.stdout, stderr: result.stderr });
  } catch (error) {
    return Object.freeze({
      code: Number.isInteger(error?.code) ? error.code : 1,
      stdout: v.is(STRING_SCHEMA, error?.stdout) ? error.stdout : '',
      stderr: v.is(STRING_SCHEMA, error?.stderr) ? error.stderr : '',
    });
  }
}

export async function publishGitHubReleaseOutput(outputDirectory, command = defaultCommand) {
  const verified = await loadGitHubReleaseOutput(outputDirectory);
  const { plan, root } = verified;
  const cliVersion = await command('gh', ['--version']);
  const reportedVersion = /^gh version ((?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*))(?: \([^\r\n]+\))?(?:\r?\n|$)/u
    .exec(cliVersion.stdout)?.[1];
  if (cliVersion.code !== 0 || reportedVersion !== REQUIRED_GITHUB_CLI_VERSION) {
    fail('github_cli_version_required');
  }
  const immutable = await command('gh', [
    'api', `repos/${plan.repository}/immutable-releases`,
    '--header', 'X-GitHub-Api-Version: 2026-03-10', '--jq', '.enabled',
  ]);
  if (immutable.code !== 0 || immutable.stdout.trim() !== 'true') {
    fail('github_release_immutability_required');
  }
  const commit = await command('gh', [
    'api', `repos/${plan.repository}/commits/${plan.sourceCommit}`, '--jq', '.sha',
  ]);
  if (commit.code !== 0 || commit.stdout.trim() !== plan.sourceCommit) fail('github_source_commit_unavailable');
  const existing = await command('gh', [
    'release', 'view', plan.tag, '--repo', plan.repository, '--json', 'tagName',
  ]);
  if (existing.code === 0) fail('github_release_exists');
  const existingTag = await command('gh', [
    'api', `repos/${plan.repository}/git/ref/tags/${encodeURIComponent(plan.tag)}`, '--jq', '.object.sha',
  ]);
  if (existingTag.code === 0) fail('github_tag_exists');

  const args = [
    'release', 'create', plan.tag,
    path.join(root, ENVELOPE_FILENAME),
    path.join(root, VERIFICATION_FILENAME),
    path.join(root, SBOM_FILENAME),
    path.join(root, LICENSE_FILENAME),
    path.join(root, THIRD_PARTY_LICENSES_FILENAME),
    '--repo', plan.repository,
    '--target', plan.sourceCommit,
    '--title', plan.title,
    '--notes-file', path.join(root, NOTES_FILENAME),
    `--latest=${String(plan.latest)}`,
  ];
  if (plan.prerelease) args.push('--prerelease');
  const created = await command('gh', args);
  if (created.code !== 0) fail('github_release_create_failed');

  const inspected = await command('gh', [
    'api', `repos/${plan.repository}/releases/tags/${encodeURIComponent(plan.tag)}`,
    '--header', 'X-GitHub-Api-Version: 2026-03-10',
  ]);
  let release;
  try {
    release = JSON.parse(inspected.stdout);
  } catch {
    fail('github_release_verification_failed');
  }
  const expectedAssets = new Map(plan.assets.map((asset) => [asset.name, asset]));
  const seenAssets = new Set();
  const assetsMatch = Array.isArray(release.assets) && release.assets.length === expectedAssets.size &&
    release.assets.every((asset) => {
      const expected = expectedAssets.get(asset?.name);
      if (!expected || seenAssets.has(asset.name)) return false;
      seenAssets.add(asset.name);
      return asset.size === expected.byteSize && asset.digest === `sha256:${expected.sha256}`;
    });
  if (
    inspected.code !== 0 ||
    release.tag_name !== plan.tag ||
    release.target_commitish !== plan.sourceCommit ||
    release.name !== plan.title ||
    release.draft !== false ||
    release.immutable !== true ||
    release.prerelease !== plan.prerelease ||
    !assetsMatch ||
    !v.is(STRING_SCHEMA, release.html_url) || !release.html_url.startsWith(`https://github.com/${plan.repository}/releases/tag/`)
  ) fail('github_release_verification_failed');

  const releaseVerified = await command('gh', [
    'release', 'verify', plan.tag, '--repo', plan.repository,
  ]);
  if (releaseVerified.code !== 0) fail('github_release_verification_failed');
  for (const asset of plan.assets) {
    const assetVerified = await command('gh', [
      'release', 'verify-asset', plan.tag, path.join(root, asset.name),
      '--repo', plan.repository,
    ]);
    if (assetVerified.code !== 0) fail('github_release_verification_failed');
  }
  return Object.freeze({
    schemaVersion: 1,
    status: 'published',
    release: plan.release,
    repository: plan.repository,
    sourceCommit: plan.sourceCommit,
    url: release.html_url,
  });
}

const HELP = `Usage:\n` +
  `  node scripts/publish-github-release.mjs \\\n` +
  `    --release-dir <candidate> --publish-dir <signed-publish-dir> \\\n` +
  `    --publication-result <published-receipt.json> --repository <owner/repo> \\\n` +
  `    --sbom <source-bound-sbom.cdx.json> --out <new-output-directory>\n` +
  `  node scripts/publish-github-release.mjs --validate-output-dir <output-directory>\n` +
  `  node scripts/publish-github-release.mjs --publish-output-dir <output-directory>\n\n` +
  `Preparation and validation are offline. Publishing is the only network mutation.\n`;

function parseCli(argv) {
  if (argv.length === 1 && argv[0] === '--help') return Object.freeze({ mode: 'help' });
  if (argv.length === 2 && argv[0] === '--validate-output-dir') {
    return Object.freeze({ mode: 'validate', outputDirectory: argv[1] });
  }
  if (argv.length === 2 && argv[0] === '--publish-output-dir') {
    return Object.freeze({ mode: 'publish', outputDirectory: argv[1] });
  }
  const allowed = new Set([
    '--out',
    '--publication-result',
    '--publish-dir',
    '--release-dir',
    '--repository',
    '--sbom',
  ]);
  const values = {};
  for (let index = 0; index < argv.length; index += 2) {
    const flag = argv[index];
    if (!allowed.has(flag) || index + 1 >= argv.length || argv[index + 1].startsWith('--') || flag in values) fail();
    values[flag] = argv[index + 1];
  }
  if ([...allowed].some((flag) => !v.is(STRING_SCHEMA, values[flag]))) fail();
  return Object.freeze({
    mode: 'prepare',
    outputDirectory: values['--out'],
    input: Object.freeze({
      publicationResult: values['--publication-result'],
      publishDirectory: values['--publish-dir'],
      releaseDirectory: values['--release-dir'],
      repository: values['--repository'],
      sbom: values['--sbom'],
    }),
  });
}

export async function runGitHubReleaseCli({ argv, stdout, stderr }) {
  let parsed;
  try {
    parsed = parseCli(argv);
  } catch {
    stderr.write(HELP);
    return 2;
  }
  if (parsed.mode === 'help') {
    stdout.write(HELP);
    return 0;
  }
  try {
    if (parsed.mode === 'validate') {
      const verified = await loadGitHubReleaseOutput(parsed.outputDirectory);
      stdout.write(`${JSON.stringify({ schemaVersion: 1, status: 'verified', ...verified.plan }, null, 2)}\n`);
      return 0;
    }
    if (parsed.mode === 'publish') {
      const result = await publishGitHubReleaseOutput(parsed.outputDirectory);
      stdout.write(`${JSON.stringify(result, null, 2)}\n`);
      return 0;
    }
    const prepared = await prepareGitHubReleaseOutput(parsed.input);
    const outputDirectory = await writeGitHubReleaseOutput(prepared, parsed.outputDirectory);
    stdout.write(`${JSON.stringify({
      schemaVersion: 1,
      status: 'prepared',
      outputDirectory,
      ...prepared.plan,
    }, null, 2)}\n`);
    return 0;
  } catch (error) {
    const code = error instanceof GitHubReleasePublicationError ? error.code : 'github_release_internal_error';
    stderr.write(`GitHub Release operation failed: ${code}.\n`);
    return 1;
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  runGitHubReleaseCli({ argv: process.argv.slice(2), stdout: process.stdout, stderr: process.stderr })
    .then((code) => { process.exitCode = code; });
}

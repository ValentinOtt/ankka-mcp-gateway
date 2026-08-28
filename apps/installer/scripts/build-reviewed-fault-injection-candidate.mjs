#!/usr/bin/env node

/**
 * Builds the one deliberately unhealthy release used by the reviewed updater
 * compensation canary. The output remains a canonical gateway release
 * candidate, but its exact-version runtime-action probe always returns 503.
 * It cannot be signed accidentally: sign-gateway-release.mjs recognizes the
 * injected marker and requires both the canary channel and a separate explicit
 * acknowledgement.
 */
import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath, pathToFileURL } from 'node:url';
import * as v from 'valibot';

import {
  ReleaseCandidateError,
  buildReleaseCandidate,
  writeReleaseCandidate,
} from './build-gateway-release-candidate.mjs';
import {
  REVIEWED_FAULT_INJECTION,
  REVIEWED_FAULT_INJECTION_MARKER,
  REVIEWED_FAULT_INJECTION_SENTINEL,
  canonicalJson,
} from './sign-gateway-release.mjs';

const RELEASE_PATTERN = /^gateway-v(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)$/u;
const WORKER_ENTRY = 'payload/worker/index.js';
const SOURCE_TOOL_PATH = 'apps/installer/scripts/build-reviewed-fault-injection-candidate.mjs';
const PROBE_ANCHOR = "    if (control?.command === 'probe') {\n";
const INJECTED_PROBE =
  "    if (control?.command === 'probe') {\n" +
  `      ${REVIEWED_FAULT_INJECTION_MARKER}\n` +
  `      return fixedJson(503, { schemaVersion: 1, error: '${REVIEWED_FAULT_INJECTION_SENTINEL}' });\n` +
  "    }\n";
const plainRecordSchema = v.record(v.string(), v.unknown());
const stringSchema = v.string();

export class ReviewedFaultCandidateError extends Error {
  constructor(code) {
    super(code);
    this.name = 'ReviewedFaultCandidateError';
    this.code = code;
  }
}

function fail(code) {
  throw new ReviewedFaultCandidateError(code);
}

function exactKeys(value, keys) {
  if (
    !v.is(plainRecordSchema, value) ||
    Object.getPrototypeOf(value) !== Object.prototype
  ) return false;
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  return actual.length === expected.length && actual.every((key, index) => key === expected[index]);
}

function sha256Hex(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

function occurrences(value, needle) {
  let count = 0;
  let offset = 0;
  while (true) {
    const found = value.indexOf(needle, offset);
    if (found < 0) return count;
    count += 1;
    offset = found + needle.length;
  }
}

function releaseParts(release) {
  if (!v.is(stringSchema, release) || !RELEASE_PATTERN.test(release)) fail('invalid_release');
  return release.slice('gateway-v'.length).split('.').map((part) => BigInt(part));
}

function releaseIsStrictlyNewer(baseRelease, release) {
  const base = releaseParts(baseRelease);
  const target = releaseParts(release);
  for (let index = 0; index < 3; index += 1) {
    if (target[index] > base[index]) return true;
    if (target[index] < base[index]) return false;
  }
  return false;
}

function componentFromRecords(records) {
  const byteSize = records.reduce((total, record) => total + record.byteSize, 0);
  return Object.freeze({
    byteSize,
    fileCount: records.length,
    files: Object.freeze(records),
    treeSha256: sha256Hex(Buffer.from(canonicalJson(records), 'utf8')),
  });
}

function injectProbeFailure(candidate, release) {
  const worker = candidate.files.find((file) => file.record.path === WORKER_ENTRY);
  if (!worker) fail('worker_entry_missing');
  let source;
  try {
    source = new TextDecoder('utf-8', { fatal: true }).decode(worker.bytes);
  } catch {
    fail('worker_entry_invalid');
  }
  if (
    occurrences(source, PROBE_ANCHOR) !== 1 ||
    occurrences(source, REVIEWED_FAULT_INJECTION_MARKER) !== 0
  ) fail('probe_anchor_mismatch');

  const injectedBytes = Buffer.from(source.replace(PROBE_ANCHOR, `${INJECTED_PROBE}${PROBE_ANCHOR}`), 'utf8');
  if (
    occurrences(injectedBytes.toString('utf8'), REVIEWED_FAULT_INJECTION_MARKER) !== 1 ||
    occurrences(injectedBytes.toString('utf8'), REVIEWED_FAULT_INJECTION_SENTINEL) !== 1 ||
    injectedBytes.equals(worker.bytes)
  ) fail('fault_injection_failed');

  const files = Object.freeze(candidate.files.map((file) => {
    if (file.record.path !== WORKER_ENTRY) return file;
    return Object.freeze({
      bytes: injectedBytes,
      record: Object.freeze({
        ...file.record,
        byteSize: injectedBytes.byteLength,
        sha256: sha256Hex(injectedBytes),
      }),
    });
  }));
  const componentFiles = Object.fromEntries(Object.keys(candidate.manifest.components).map((name) => [
    name,
    files
      .filter((file) => candidate.manifest.components[name].files.some(
        (record) => record.path === file.record.path,
      ))
      .map((file) => file.record),
  ]));
  const components = Object.freeze(Object.fromEntries(Object.entries(componentFiles).map(([name, records]) => [
    name,
    componentFromRecords(records),
  ])));
  const records = Object.values(componentFiles).flat()
    .sort((left, right) => (left.path < right.path ? -1 : left.path > right.path ? 1 : 0));
  const artifact = Object.freeze({
    byteSize: records.reduce((total, record) => total + record.byteSize, 0),
    fileCount: records.length,
    treeSha256: sha256Hex(Buffer.from(canonicalJson(records), 'utf8')),
  });
  const manifest = Object.freeze({
    artifact,
    cloudflare: candidate.manifest.cloudflare,
    components,
    oauthScopeIds: candidate.manifest.oauthScopeIds,
    release,
    schemaVersion: 1,
    sourceCommit: candidate.manifest.sourceCommit,
  });
  const manifestBytes = Buffer.from(canonicalJson(manifest), 'utf8');
  return Object.freeze({
    files,
    manifest,
    manifestBytes,
    manifestSha256: sha256Hex(manifestBytes),
    sourceRoot: candidate.sourceRoot,
  });
}

export async function buildReviewedFaultInjectionCandidate(input) {
  if (
    !exactKeys(input, [
      'baseRelease', 'channel', 'fault', 'release', 'sourceCommit', 'sourceDirectory',
    ]) ||
    input.channel !== 'canary' ||
    input.fault !== REVIEWED_FAULT_INJECTION ||
    !releaseIsStrictlyNewer(input.baseRelease, input.release)
  ) fail('invalid_input');
  let candidate;
  try {
    candidate = await buildReleaseCandidate({
      sourceDirectory: input.sourceDirectory,
      sourceCommit: input.sourceCommit,
      release: input.baseRelease,
    });
  } catch (error) {
    if (error instanceof ReleaseCandidateError) fail(`base_${error.code}`);
    throw error;
  }
  try {
    const [runningTool, committedTool] = await Promise.all([
      readFile(fileURLToPath(import.meta.url)),
      readFile(path.join(candidate.sourceRoot, ...SOURCE_TOOL_PATH.split('/'))),
    ]);
    if (!runningTool.equals(committedTool)) fail('fault_builder_source_mismatch');
  } catch (error) {
    if (error instanceof ReviewedFaultCandidateError) throw error;
    fail('fault_builder_source_mismatch');
  }
  return injectProbeFailure(candidate, input.release);
}

export function reviewedFaultCandidateSummary(candidate, baseRelease, outputDirectory) {
  return Object.freeze({
    schemaVersion: 1,
    purpose: 'reviewed_updater_compensation_canary',
    channelConstraint: 'canary',
    faultInjection: REVIEWED_FAULT_INJECTION,
    baseRelease,
    release: candidate.manifest.release,
    sourceCommit: candidate.manifest.sourceCommit,
    artifact: candidate.manifest.artifact,
    manifestSha256: candidate.manifestSha256,
    outputDirectory,
    signed: false,
  });
}

const HELP = `Usage: node scripts/build-reviewed-fault-injection-candidate.mjs \\
  --source <public ankka-mcp-gateway checkout> \\
  --source-commit <40-hex exact commit> \\
  --base-release <gateway-vX.Y.Z> --release <strictly-newer gateway-vX.Y.Z> \\
  --channel canary --fault exact-version-health-probe-v1 \\
  --out <new directory>

Builds one create-only, schema-valid candidate for the reviewed updater
compensation drill. Its exact-version runtime-action probe deterministically
returns 503. It is never a stable release and nothing is signed, published, or
uploaded. The signer requires a separate explicit fault acknowledgement.
`;

function parseCliArguments(argv) {
  if (argv.length === 1 && argv[0] === '--help') return { help: true };
  const flags = new Set([
    '--source', '--source-commit', '--base-release', '--release', '--channel', '--fault', '--out',
  ]);
  const values = {};
  for (let index = 0; index < argv.length; index += 2) {
    const flag = argv[index];
    if (!flags.has(flag) || index + 1 >= argv.length || argv[index + 1].startsWith('--') || flag in values) {
      fail('invalid_arguments');
    }
    values[flag] = argv[index + 1];
  }
  if ([...flags].some((flag) => !v.is(stringSchema, values[flag]))) fail('invalid_arguments');
  return Object.freeze({
    help: false,
    sourceDirectory: values['--source'],
    sourceCommit: values['--source-commit'],
    baseRelease: values['--base-release'],
    release: values['--release'],
    channel: values['--channel'],
    fault: values['--fault'],
    outputDirectory: values['--out'],
  });
}

export async function runReviewedFaultCandidateCli({ argv, stdout, stderr }) {
  let options;
  try {
    options = parseCliArguments(argv);
  } catch {
    stderr.write(HELP);
    return 2;
  }
  if (options.help) {
    stdout.write(HELP);
    return 0;
  }
  try {
    const candidate = await buildReviewedFaultInjectionCandidate({
      sourceDirectory: options.sourceDirectory,
      sourceCommit: options.sourceCommit,
      baseRelease: options.baseRelease,
      release: options.release,
      channel: options.channel,
      fault: options.fault,
    });
    const outputDirectory = await writeReleaseCandidate(candidate, options.outputDirectory);
    stdout.write(`${JSON.stringify(reviewedFaultCandidateSummary(
      candidate,
      options.baseRelease,
      outputDirectory,
    ), null, 2)}\n`);
    return 0;
  } catch (error) {
    const code = error instanceof ReviewedFaultCandidateError || error instanceof ReleaseCandidateError
      ? error.code
      : 'internal_error';
    stderr.write(
      `Reviewed fault candidate build failed: ${code}. ` +
      'Nothing was signed, published, or uploaded.\n',
    );
    return 1;
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  runReviewedFaultCandidateCli({ argv: process.argv.slice(2), stdout: process.stdout, stderr: process.stderr })
    .then((code) => { process.exitCode = code; });
}

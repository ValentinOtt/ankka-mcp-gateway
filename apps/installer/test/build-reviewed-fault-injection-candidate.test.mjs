import { generateKeyPairSync } from 'node:crypto';
import { mkdir, readFile, readdir, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

import { describe, expect, it } from 'vitest';

import {
  buildReleaseCandidate,
  writeReleaseCandidate,
} from '../scripts/build-gateway-release-candidate.mjs';
import {
  ReviewedFaultCandidateError,
  buildReviewedFaultInjectionCandidate,
  runReviewedFaultCandidateCli,
} from '../scripts/build-reviewed-fault-injection-candidate.mjs';
import {
  REVIEWED_FAULT_INJECTION,
  REVIEWED_FAULT_INJECTION_MARKER,
  REVIEWED_FAULT_INJECTION_SENTINEL,
  classifyReviewedFaultWorker,
  loadVerifiedPublicRelease,
  prepareSignedReleasePublishPlan,
} from '../scripts/sign-gateway-release.mjs';
import {
  FIXTURE_PAYLOAD,
  fixtureGit,
  releaseCandidateCheckout,
} from './release-candidate-fixture.mjs';

const BASE_RELEASE = 'gateway-v1.2.3';
const FAULT_RELEASE = 'gateway-v1.2.4';
const CONTROL_PLANE_ORIGIN = 'https://deploy.ankka.ai';
const PROBE_WORKER = `
const CONTROL_PLANE_ORIGIN = 'https://deploy.ankka.ai';
function fixedJson(status, value) {
  return new Response(JSON.stringify(value), { status });
}
function parseManagementEnvironment(env) {
  if (!CONTROL_PLANE_ORIGIN) return null;
  return env;
}
async function handleRuntimeActionApply(request, env) {
  const control = { command: 'probe' };
  let internal = request;
    if (control?.command === 'probe') {
      const environment = parseManagementEnvironment(env);
      if (!environment) return fixedJson(409, { schemaVersion: 1, error: 'runtime_probe_version_mismatch' });
      internal = request;
    }
  return internal;
}
export class AdminState {}
export default { fetch: handleRuntimeActionApply };
`;

function signingKey() {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const pkcs8 = privateKey.export({ format: 'der', type: 'pkcs8' });
  const spki = publicKey.export({ format: 'der', type: 'spki' });
  const seed = Buffer.from(pkcs8.subarray(pkcs8.byteLength - 32));
  const encodedPublic = Buffer.from(spki.subarray(spki.byteLength - 32)).toString('base64url');
  pkcs8.fill(0);
  spki.fill(0);
  return { seed, publicKey: encodedPublic };
}

async function fixture() {
  const checkout = await releaseCandidateCheckout({
    ...FIXTURE_PAYLOAD,
    'payload/worker/index.js': PROBE_WORKER,
  });
  const toolPath = 'apps/installer/scripts/build-reviewed-fault-injection-candidate.mjs';
  await mkdir(path.dirname(path.join(checkout.source, ...toolPath.split('/'))), { recursive: true });
  await writeFile(
    path.join(checkout.source, ...toolPath.split('/')),
    await readFile(new URL('../scripts/build-reviewed-fault-injection-candidate.mjs', import.meta.url)),
    { flag: 'wx' },
  );
  fixtureGit(checkout.source, 'add', toolPath);
  fixtureGit(checkout.source, 'commit', '-q', '-m', 'bind reviewed fault builder');
  const sourceCommit = fixtureGit(checkout.source, 'rev-parse', 'HEAD');
  const input = {
    sourceDirectory: checkout.source,
    sourceCommit,
    baseRelease: BASE_RELEASE,
    release: FAULT_RELEASE,
    channel: 'canary',
    controlPlaneOrigin: CONTROL_PLANE_ORIGIN,
    fault: REVIEWED_FAULT_INJECTION,
  };
  return { checkout: { ...checkout, commit: sourceCommit }, input };
}

describe('build-reviewed-fault-injection-candidate', () => {
  it('classifies only the exact marker and sentinel pair as a reviewed fault', () => {
    expect(classifyReviewedFaultWorker(Buffer.from('ordinary worker'))).toBe('ordinary');
    expect(classifyReviewedFaultWorker(Buffer.from(
      `${REVIEWED_FAULT_INJECTION_MARKER}\n${REVIEWED_FAULT_INJECTION_SENTINEL}`,
    ))).toBe('reviewed-fault');
    expect(() => classifyReviewedFaultWorker(Buffer.from(REVIEWED_FAULT_INJECTION_MARKER)))
      .toThrowError('Release signing failed');
    expect(() => classifyReviewedFaultWorker(Buffer.from(REVIEWED_FAULT_INJECTION_SENTINEL)))
      .toThrowError('Release signing failed');
  });

  it('changes only the primary Worker probe, recomputes the canonical manifest, and stays signer-valid', async () => {
    const { checkout, input } = await fixture();
    try {
      const ordinary = await buildReleaseCandidate({
        controlPlaneOrigin: CONTROL_PLANE_ORIGIN,
        sourceDirectory: checkout.source,
        sourceCommit: checkout.commit,
        release: BASE_RELEASE,
      });
      const ordinaryOutput = await writeReleaseCandidate(
        ordinary,
        path.join(checkout.sandbox, 'ordinary-candidate'),
      );
      const falseAcknowledgement = signingKey();
      await expect(prepareSignedReleasePublishPlan({
        channel: 'canary', keyId: 'throwaway-canary-key', privateKeySeed: falseAcknowledgement.seed,
        publicKey: falseAcknowledgement.publicKey, release: BASE_RELEASE, releaseDirectory: ordinaryOutput,
        reviewedFaultInjection: REVIEWED_FAULT_INJECTION,
      })).rejects.toMatchObject({ code: 'release_signing_failed' });

      const candidate = await buildReviewedFaultInjectionCandidate(input);
      expect(candidate.manifest.release).toBe(FAULT_RELEASE);
      expect(candidate.manifest.sourceCommit).toBe(checkout.commit);
      const worker = candidate.files.find((file) => file.record.path === 'payload/worker/index.js');
      expect(worker.bytes.toString()).toContain(REVIEWED_FAULT_INJECTION_MARKER);
      expect(worker.bytes.toString()).toContain("return fixedJson(503, { schemaVersion: 1, error: 'reviewed_fault_injected' });");
      const ordinaryByPath = new Map(ordinary.files.map((file) => [file.record.path, file.bytes]));
      const changedPayloadPaths = [];
      for (const file of candidate.files) {
        const baseBytes = ordinaryByPath.get(file.record.path);
        expect(baseBytes).toBeDefined();
        if (!file.bytes.equals(baseBytes)) changedPayloadPaths.push(file.record.path);
      }
      expect(changedPayloadPaths).toEqual(['payload/worker/index.js']);

      const output = await writeReleaseCandidate(candidate, checkout.output);
      const executableWorker = await import(
        `${pathToFileURL(path.join(output, 'payload/worker/index.js')).href}?fault=${Date.now()}`
      );
      const probe = await executableWorker.default.fetch(new Request('https://worker.invalid/__ankka/runtime-action'), {});
      expect(probe.status).toBe(503);
      expect(await probe.json()).toEqual({ schemaVersion: 1, error: 'reviewed_fault_injected' });
      const verified = await loadVerifiedPublicRelease(output, FAULT_RELEASE);
      expect(verified.manifest.artifact.treeSha256).toBe(candidate.manifest.artifact.treeSha256);
      for (const entry of verified.payload) entry.bytes.fill(0);
      verified.manifestBytes.fill(0);

      const unacknowledged = signingKey();
      await expect(prepareSignedReleasePublishPlan({
        channel: 'canary', keyId: 'throwaway-canary-key', privateKeySeed: unacknowledged.seed,
        publicKey: unacknowledged.publicKey, release: FAULT_RELEASE, releaseDirectory: output,
      })).rejects.toMatchObject({ code: 'release_signing_failed' });

      const stable = signingKey();
      await expect(prepareSignedReleasePublishPlan({
        channel: 'stable', keyId: 'throwaway-canary-key', privateKeySeed: stable.seed,
        publicKey: stable.publicKey, release: FAULT_RELEASE, releaseDirectory: output,
        reviewedFaultInjection: REVIEWED_FAULT_INJECTION,
      })).rejects.toMatchObject({ code: 'release_signing_failed' });

      const canary = signingKey();
      const prepared = await prepareSignedReleasePublishPlan({
        channel: 'canary', keyId: 'throwaway-canary-key', privateKeySeed: canary.seed,
        publicKey: canary.publicKey, release: FAULT_RELEASE, releaseDirectory: output,
        reviewedFaultInjection: REVIEWED_FAULT_INJECTION,
      });
      expect(prepared.channel).toBe('canary');
      expect(prepared.release).toBe(FAULT_RELEASE);
      expect(prepared.artifactSha256).toBe(candidate.manifest.artifact.treeSha256);
    } finally {
      await checkout.cleanup();
    }
  }, 30_000);

  it('requires the exact canary purpose, a strictly newer version, one clean probe anchor, and a new output root', async () => {
    const { checkout, input } = await fixture();
    try {
      for (const override of [
        { channel: 'stable' },
        { fault: 'some-other-fault' },
        { release: BASE_RELEASE },
        { release: 'gateway-v1.2.2' },
        { unexpected: true },
      ]) {
        await expect(buildReviewedFaultInjectionCandidate({ ...input, ...override }))
          .rejects.toBeInstanceOf(ReviewedFaultCandidateError);
      }

      const sourceToolPath = path.join(
        checkout.source,
        'apps/installer/scripts/build-reviewed-fault-injection-candidate.mjs',
      );
      await writeFile(sourceToolPath, '// different committed fault builder\n');
      fixtureGit(checkout.source, 'add', '-A');
      fixtureGit(checkout.source, 'commit', '-q', '-m', 'change fault builder');
      await expect(buildReviewedFaultInjectionCandidate({
        ...input,
        sourceCommit: fixtureGit(checkout.source, 'rev-parse', 'HEAD'),
      })).rejects.toMatchObject({ code: 'fault_builder_source_mismatch' });

      await writeFile(
        sourceToolPath,
        await readFile(new URL('../scripts/build-reviewed-fault-injection-candidate.mjs', import.meta.url)),
      );
      const workerPath = path.join(checkout.source, 'payload', 'worker', 'index.js');
      await writeFile(workerPath, PROBE_WORKER.replace(
        "    if (control?.command === 'probe') {\n",
        "    if (control?.command === 'different') {\n",
      ));
      fixtureGit(checkout.source, 'add', '-A');
      fixtureGit(checkout.source, 'commit', '-q', '-m', 'remove exact probe anchor');
      await expect(buildReviewedFaultInjectionCandidate({
        ...input,
        sourceCommit: fixtureGit(checkout.source, 'rev-parse', 'HEAD'),
      })).rejects.toMatchObject({ code: 'probe_anchor_mismatch' });
    } finally {
      await checkout.cleanup();
    }
  }, 30_000);

  it('offers only an explicit create-only CLI and prints a public fault record', async () => {
    const { checkout, input } = await fixture();
    const stdout = [];
    const stderr = [];
    const io = {
      stdout: { write: (chunk) => stdout.push(String(chunk)) },
      stderr: { write: (chunk) => stderr.push(String(chunk)) },
    };
    try {
      const args = [
        '--source', input.sourceDirectory,
        '--source-commit', input.sourceCommit,
        '--control-plane-origin', input.controlPlaneOrigin,
        '--base-release', input.baseRelease,
        '--release', input.release,
        '--channel', input.channel,
        '--fault', input.fault,
        '--out', checkout.output,
      ];
      expect(await runReviewedFaultCandidateCli({ argv: args, ...io })).toBe(0);
      expect(JSON.parse(stdout.join(''))).toMatchObject({
        purpose: 'reviewed_updater_compensation_canary',
        channelConstraint: 'canary',
        faultInjection: REVIEWED_FAULT_INJECTION,
        baseRelease: BASE_RELEASE,
        release: FAULT_RELEASE,
        outputDirectory: checkout.output,
        signed: false,
      });
      expect((await readdir(checkout.output)).sort()).toEqual(['manifest.json', 'payload']);
      expect((await readFile(path.join(checkout.output, 'manifest.json'), 'utf8'))).not.toContain('private');

      stdout.length = 0;
      expect(await runReviewedFaultCandidateCli({ argv: args, ...io })).toBe(1);
      expect(stderr.join('')).toContain('output_exists');
      expect(await runReviewedFaultCandidateCli({ argv: ['--help'], ...io })).toBe(0);
    } finally {
      await checkout.cleanup();
    }
  }, 30_000);
});

import { createHash, generateKeyPairSync } from 'node:crypto';
import { readFile, readdir, rm, symlink, writeFile } from 'node:fs/promises';
import path from 'node:path';

import { describe, expect, it } from 'vitest';

import {
  ReleaseCandidateError,
  buildReleaseCandidate,
  candidateSummary,
  runReleaseCandidateCli,
  writeReleaseCandidate,
} from '../scripts/build-gateway-release-candidate.mjs';
import {
  APPROVED_CLOUDFLARE_CONTRACT,
  REQUIRED_OAUTH_SCOPES as SIGNER_SCOPES,
  canonicalJson,
  prepareSignedReleasePublishPlan,
} from '../scripts/sign-gateway-release.mjs';
import { REQUIRED_OAUTH_SCOPES } from '../src/constants';
import {
  APPROVED_CLOUDFLARE_RELEASE_CONTRACT,
  parseCanonicalReleaseManifest,
} from '../src/release-manifest';
import {
  FIXTURE_PAYLOAD,
  FIXTURE_RELEASE_FILES as RELEASE_FILES,
  fixtureGit as git,
  releaseCandidateCheckout as publicCheckout,
} from './release-candidate-fixture.mjs';

const RELEASE = 'gateway-v1.2.3';
const CONTROL_PLANE_ORIGIN = 'https://deploy.ankka.ai';

function sha256(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

async function expectFailure(promise, code) {
  await expect(promise).rejects.toBeInstanceOf(ReleaseCandidateError);
  await expect(promise).rejects.toMatchObject({ code });
}

describe('build-gateway-release-candidate', () => {
  it('keeps the signer contract constants identical to the runtime contract', () => {
    expect(canonicalJson(APPROVED_CLOUDFLARE_CONTRACT)).toBe(canonicalJson(APPROVED_CLOUDFLARE_RELEASE_CONTRACT));
    expect([...SIGNER_SCOPES]).toEqual([...REQUIRED_OAUTH_SCOPES]);
  });

  it('builds the canonical manifest for the exact committed payload bytes', async () => {
    const checkout = await publicCheckout();
    try {
      const candidate = await buildReleaseCandidate({
        controlPlaneOrigin: CONTROL_PLANE_ORIGIN,
        sourceDirectory: checkout.source,
        sourceCommit: checkout.commit,
        release: RELEASE,
      });
      const serialized = candidate.manifestBytes.toString('utf8');
      expect(canonicalJson(JSON.parse(serialized))).toBe(serialized);
      const parsed = parseCanonicalReleaseManifest(serialized);
      expect(parsed.release).toBe(RELEASE);
      expect(parsed.sourceCommit).toBe(checkout.commit);
      expect(parsed.artifact.fileCount).toBe(Object.keys(RELEASE_FILES).length + 1);
      expect(parsed.artifact.byteSize).toBe(
        candidate.files.reduce((total, file) => total + file.bytes.byteLength, 0),
      );

      // Independent digest computation with the signer's definition.
      const records = candidate.files.map(({ bytes, record }) => ({
        byteSize: bytes.byteLength,
        contentType: record.contentType,
        path: record.path,
        sha256: sha256(bytes),
      })).sort((left, right) => (left.path < right.path ? -1 : 1));
      expect(parsed.artifact.treeSha256).toBe(sha256(Buffer.from(canonicalJson(records))));
      for (const [name, component] of Object.entries(parsed.components)) {
        expect(component.treeSha256).toBe(sha256(Buffer.from(canonicalJson(component.files))));
        expect(component.fileCount).toBe(component.files.length);
        expect(name).toBeTruthy();
      }
      expect(parsed.components.admin.files.map((file) => file.contentType).sort()).toEqual([
        'text/html; charset=utf-8',
        'text/javascript; charset=utf-8',
        'text/plain; charset=utf-8',
        'text/plain; charset=utf-8',
      ].sort());
      expect(parsed.components.worker.files[0].contentType).toBe('application/javascript+module');
      expect(parsed.components.workerBootstrap.files[0].contentType)
        .toBe('application/javascript+module');
      expect(candidate.manifestSha256).toBe(sha256(candidate.manifestBytes));
      expect(candidateSummary(candidate)).toMatchObject({
        schemaVersion: 1,
        release: RELEASE,
        sourceCommit: checkout.commit,
        signed: false,
        outputDirectory: null,
      });
      expect(JSON.stringify(candidateSummary(candidate))).not.toContain('bytes');
    } finally {
      await checkout.cleanup();
    }
  });

  it('compiles one isolated control-plane origin into the Worker before hashing', async () => {
    const checkout = await publicCheckout();
    const isolatedOrigin = 'https://installer.canary.example';
    try {
      const candidate = await buildReleaseCandidate({
        controlPlaneOrigin: isolatedOrigin,
        sourceDirectory: checkout.source,
        sourceCommit: checkout.commit,
        release: RELEASE,
      });
      const worker = candidate.files.find(({ record }) => record.path === 'payload/worker/index.js');
      expect(worker).toBeDefined();
      expect(worker.bytes.toString('utf8')).toContain(`// ankka-control-plane-origin:${isolatedOrigin}`);
      expect(worker.bytes.toString('utf8')).toContain(
        `var CONTROL_PLANE_ORIGIN = "${isolatedOrigin}";`,
      );
      expect(worker.bytes.toString('utf8')).not.toContain(
        'ankka-control-plane-origin:https://deploy.ankka.ai',
      );
      expect(candidate.manifest.controlPlaneOrigin).toBe(isolatedOrigin);
      expect(worker.record.sha256).toBe(sha256(worker.bytes));
      const workerComponent = candidate.manifest.components.worker;
      expect(workerComponent.files).toEqual([worker.record]);
      expect(workerComponent.treeSha256).toBe(
        sha256(Buffer.from(canonicalJson(workerComponent.files))),
      );
      const records = Object.values(candidate.manifest.components)
        .flatMap((component) => component.files)
        .sort((left, right) => (left.path < right.path ? -1 : 1));
      expect(candidate.manifest.artifact.treeSha256).toBe(
        sha256(Buffer.from(canonicalJson(records))),
      );
      const outputRoot = await writeReleaseCandidate(candidate, checkout.output);
      expect((await readFile(path.join(outputRoot, 'payload/worker/index.js'), 'utf8')))
        .toBe(worker.bytes.toString('utf8'));
    } finally {
      await checkout.cleanup();
    }
  }, 15_000);

  it('requires exactly one committed Worker control-plane compile anchor', async () => {
    const anchor = "const CONTROL_PLANE_ORIGIN = 'https://deploy.ankka.ai';";
    for (const workerSource of [
      'export class AdminState {}\nexport default {};\n',
      `${anchor}\n${anchor}\nexport class AdminState {}\nexport default {};\n`,
    ]) {
      const checkout = await publicCheckout({
        ...FIXTURE_PAYLOAD,
        'payload/worker/index.js': workerSource,
      });
      try {
        await expectFailure(buildReleaseCandidate({
          controlPlaneOrigin: 'https://installer.canary.example',
          sourceDirectory: checkout.source,
          sourceCommit: checkout.commit,
          release: RELEASE,
        }), 'worker_control_plane_origin_anchor_invalid');
      } finally {
        await checkout.cleanup();
      }
    }
  }, 20_000);

  it('is deterministic across builds and materialises a directory the signer accepts', async () => {
    const checkout = await publicCheckout();
    try {
      const first = await buildReleaseCandidate({
        controlPlaneOrigin: CONTROL_PLANE_ORIGIN, sourceDirectory: checkout.source, sourceCommit: checkout.commit, release: RELEASE,
      });
      const second = await buildReleaseCandidate({
        controlPlaneOrigin: CONTROL_PLANE_ORIGIN, sourceDirectory: checkout.source, sourceCommit: checkout.commit, release: RELEASE,
      });
      expect(second.manifestBytes.equals(first.manifestBytes)).toBe(true);

      const outputRoot = await writeReleaseCandidate(first, checkout.output);
      expect((await readdir(outputRoot)).sort()).toEqual(['manifest.json', 'payload']);
      expect((await readFile(path.join(outputRoot, 'manifest.json'))).equals(first.manifestBytes)).toBe(true);
      for (const [relative, contents] of Object.entries(RELEASE_FILES)) {
        if (relative === 'payload/worker/index.js') continue;
        expect((await readFile(path.join(outputRoot, ...relative.split('/')))).toString()).toBe(contents);
      }
      expect(await readFile(path.join(outputRoot, 'payload/worker-bootstrap/index.js'), 'utf8'))
        .toContain('ankka-bootstrap-runtime:v1');

      // The exact signer prepare step accepts the candidate with an in-test
      // throwaway key. Nothing here is a release signature: the seed is
      // generated and discarded inside the test.
      const { privateKey, publicKey } = generateKeyPairSync('ed25519');
      const pkcs8 = privateKey.export({ format: 'der', type: 'pkcs8' });
      const spki = publicKey.export({ format: 'der', type: 'spki' });
      const seed = Buffer.from(pkcs8.subarray(pkcs8.byteLength - 32));
      const rawPublic = Buffer.from(spki.subarray(spki.byteLength - 32)).toString('base64url');
      const prepared = await prepareSignedReleasePublishPlan({
        channel: 'canary',
        keyId: 'test-throwaway-key',
        privateKeySeed: seed,
        publicKey: rawPublic,
        release: RELEASE,
        releaseDirectory: outputRoot,
      });
      expect(prepared.artifactSha256).toBe(first.manifest.artifact.treeSha256);
      expect(JSON.parse(prepared.releaseEnvelopeCanonicalJson).manifest).toBe(first.manifestBytes.toString('utf8'));

      // A second write to the same directory is refused; the directory is never reused.
      await expectFailure(writeReleaseCandidate(first, checkout.output), 'output_exists');
    } finally {
      await checkout.cleanup();
    }
  }, 15_000);

  it('refuses anything that is not the exact committed payload of the stated commit', async () => {
    const checkout = await publicCheckout();
    try {
      const base = { controlPlaneOrigin: CONTROL_PLANE_ORIGIN, sourceDirectory: checkout.source, sourceCommit: checkout.commit, release: RELEASE };
      for (const controlPlaneOrigin of [
        undefined,
        'http://deploy.ankka.ai',
        'https://deploy.ankka.ai/',
        'https://deploy.ankka.ai/path',
        'https://deploy.ankka.ai:443',
        'https://owner@deploy.ankka.ai',
        "https://deploy'.ankka.ai",
      ]) {
        await expectFailure(
          buildReleaseCandidate({ ...base, controlPlaneOrigin }),
          'invalid_control_plane_origin',
        );
      }
      await expectFailure(buildReleaseCandidate({ ...base, sourceCommit: '0'.repeat(40) }), 'source_commit_mismatch');
      await expectFailure(buildReleaseCandidate({ ...base, sourceCommit: 'abc' }), 'invalid_source_commit');
      await expectFailure(buildReleaseCandidate({ ...base, release: 'gateway-v1.2.3-rc1' }), 'invalid_release');
      await expectFailure(buildReleaseCandidate({ ...base, sourceDirectory: path.join(checkout.sandbox, 'missing') }), 'source_missing');

      // Uncommitted payload edit.
      const workerPath = path.join(checkout.source, 'payload', 'worker', 'index.js');
      await writeFile(workerPath, 'export default { changed: true };\n');
      await expectFailure(buildReleaseCandidate(base), 'source_release_inputs_dirty');
      git(checkout.source, 'checkout', '--', 'payload');

      // Untracked file inside payload.
      const strayPath = path.join(checkout.source, 'payload', 'worker', 'notes.txt');
      await writeFile(strayPath, 'stray');
      await expectFailure(buildReleaseCandidate(base), 'source_release_inputs_dirty');
      await rm(strayPath);

      // Even committed textual inputs must be canonical LF UTF-8 before their
      // raw bytes can enter a release digest.
      await writeFile(workerPath, "const CONTROL_PLANE_ORIGIN = 'https://deploy.ankka.ai';\r\nexport default { fetch() { return new Response(\"ok\"); } };\r\n");
      git(checkout.source, 'add', workerPath);
      git(checkout.source, 'commit', '-q', '-m', 'crlf payload');
      await expectFailure(buildReleaseCandidate({
        controlPlaneOrigin: CONTROL_PLANE_ORIGIN,
        ...base,
        sourceCommit: git(checkout.source, 'rev-parse', 'HEAD'),
      }), 'payload_text_not_lf');
      await writeFile(workerPath, RELEASE_FILES['payload/worker/index.js']);
      git(checkout.source, 'add', workerPath);
      git(checkout.source, 'commit', '-q', '-m', 'restore lf payload');

      // A committed symlink or unknown extension is still rejected.
      await symlink('index.js', path.join(checkout.source, 'payload', 'worker', 'link.js'));
      git(checkout.source, 'add', '-A');
      git(checkout.source, 'commit', '-q', '-m', 'symlink');
      await expectFailure(buildReleaseCandidate({ ...base, sourceCommit: git(checkout.source, 'rev-parse', 'HEAD') }), 'payload_symlink');
      git(checkout.source, 'rm', '-q', 'payload/worker/link.js');
      await writeFile(path.join(checkout.source, 'payload', 'worker', 'index.js.map'), '{}');
      git(checkout.source, 'add', '-A');
      git(checkout.source, 'commit', '-q', '-m', 'map');
      await expectFailure(buildReleaseCandidate({ ...base, sourceCommit: git(checkout.source, 'rev-parse', 'HEAD') }), 'payload_content_type_unknown');
      git(checkout.source, 'rm', '-q', 'payload/worker/index.js.map');

      // An extra top-level payload entry or a missing component.
      await writeFile(path.join(checkout.source, 'payload', 'README.md'), 'extra');
      git(checkout.source, 'add', '-A');
      git(checkout.source, 'commit', '-q', '-m', 'extra');
      await expectFailure(buildReleaseCandidate({ ...base, sourceCommit: git(checkout.source, 'rev-parse', 'HEAD') }), 'payload_layout_unexpected');
    } finally {
      await checkout.cleanup();
    }
  }, 30_000);

  it('binds the running candidate builder and signer loader to the stated source commit', async () => {
    const checkout = await publicCheckout();
    try {
      const builder = path.join(
        checkout.source,
        'apps/installer/scripts/build-gateway-release-candidate.mjs',
      );
      await writeFile(builder, '// different committed release builder\n');
      git(checkout.source, 'add', builder);
      git(checkout.source, 'commit', '-q', '-m', 'change release builder');
      await expectFailure(buildReleaseCandidate({
        controlPlaneOrigin: CONTROL_PLANE_ORIGIN,
        sourceDirectory: checkout.source,
        sourceCommit: git(checkout.source, 'rev-parse', 'HEAD'),
        release: RELEASE,
      }), 'source_tool_mismatch');
    } finally {
      await checkout.cleanup();
    }
  });

  it('exposes a dry-run CLI that prints digests only and a write mode that refuses existing output', async () => {
    const checkout = await publicCheckout();
    const stdout = [];
    const stderr = [];
    const io = {
      stdout: { write: (chunk) => stdout.push(String(chunk)) },
      stderr: { write: (chunk) => stderr.push(String(chunk)) },
    };
    try {
      const dryRun = await runReleaseCandidateCli({
        argv: ['--source', checkout.source, '--source-commit', checkout.commit, '--control-plane-origin', CONTROL_PLANE_ORIGIN, '--release', RELEASE],
        ...io,
      });
      expect(dryRun).toBe(0);
      const summary = JSON.parse(stdout.join(''));
      expect(summary).toMatchObject({ release: RELEASE, sourceCommit: checkout.commit, outputDirectory: null, signed: false });
      expect(await readdir(checkout.sandbox)).toEqual(['public']);

      stdout.length = 0;
      const written = await runReleaseCandidateCli({
        argv: ['--source', checkout.source, '--source-commit', checkout.commit, '--control-plane-origin', CONTROL_PLANE_ORIGIN, '--release', RELEASE, '--out', checkout.output],
        ...io,
      });
      expect(written).toBe(0);
      expect(JSON.parse(stdout.join('')).outputDirectory).toBe(checkout.output);

      stdout.length = 0;
      const again = await runReleaseCandidateCli({
        argv: ['--source', checkout.source, '--source-commit', checkout.commit, '--control-plane-origin', CONTROL_PLANE_ORIGIN, '--release', RELEASE, '--out', checkout.output],
        ...io,
      });
      expect(again).toBe(1);
      expect(stderr.join('')).toContain('output_exists');
      expect(stderr.join('')).toContain('Nothing was signed');

      expect(await runReleaseCandidateCli({ argv: ['--source', checkout.source], ...io })).toBe(2);
      expect(await runReleaseCandidateCli({ argv: ['--help'], ...io })).toBe(0);
    } finally {
      await checkout.cleanup();
    }
  });
});

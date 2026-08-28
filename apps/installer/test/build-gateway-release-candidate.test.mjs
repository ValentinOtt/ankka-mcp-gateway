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
  FIXTURE_RELEASE_FILES as RELEASE_FILES,
  fixtureGit as git,
  releaseCandidateCheckout as publicCheckout,
} from './release-candidate-fixture.mjs';

const RELEASE = 'gateway-v1.2.3';

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
        sourceDirectory: checkout.source,
        sourceCommit: checkout.commit,
        release: RELEASE,
      });
      const serialized = candidate.manifestBytes.toString('utf8');
      expect(canonicalJson(JSON.parse(serialized))).toBe(serialized);
      const parsed = parseCanonicalReleaseManifest(serialized);
      expect(parsed.release).toBe(RELEASE);
      expect(parsed.sourceCommit).toBe(checkout.commit);
      expect(parsed.artifact.fileCount).toBe(Object.keys(RELEASE_FILES).length);
      expect(parsed.artifact.byteSize).toBe(
        Object.values(RELEASE_FILES).reduce((total, contents) => total + Buffer.byteLength(contents), 0),
      );

      // Independent digest computation with the signer's definition.
      const records = Object.entries(RELEASE_FILES).map(([relative, contents]) => ({
        byteSize: Buffer.byteLength(contents),
        contentType: parsed.components[
          relative.startsWith('payload/admin/') ? 'admin'
            : relative.startsWith('payload/installer/') ? 'installer'
              : relative.startsWith('payload/worker-cleanup/') ? 'workerCleanup'
                : relative.startsWith('payload/worker-retirement/') ? 'workerRetirement' : 'worker'
        ].files.find((file) => file.path === relative).contentType,
        path: relative,
        sha256: sha256(Buffer.from(contents)),
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

  it('is deterministic across builds and materialises a directory the signer accepts', async () => {
    const checkout = await publicCheckout();
    try {
      const first = await buildReleaseCandidate({
        sourceDirectory: checkout.source, sourceCommit: checkout.commit, release: RELEASE,
      });
      const second = await buildReleaseCandidate({
        sourceDirectory: checkout.source, sourceCommit: checkout.commit, release: RELEASE,
      });
      expect(second.manifestBytes.equals(first.manifestBytes)).toBe(true);

      const outputRoot = await writeReleaseCandidate(first, checkout.output);
      expect((await readdir(outputRoot)).sort()).toEqual(['manifest.json', 'payload']);
      expect((await readFile(path.join(outputRoot, 'manifest.json'))).equals(first.manifestBytes)).toBe(true);
      for (const [relative, contents] of Object.entries(RELEASE_FILES)) {
        expect((await readFile(path.join(outputRoot, ...relative.split('/')))).toString()).toBe(contents);
      }

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
      const base = { sourceDirectory: checkout.source, sourceCommit: checkout.commit, release: RELEASE };
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
      await writeFile(workerPath, 'export default { fetch() { return new Response("ok"); } };\r\n');
      git(checkout.source, 'add', workerPath);
      git(checkout.source, 'commit', '-q', '-m', 'crlf payload');
      await expectFailure(buildReleaseCandidate({
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
        argv: ['--source', checkout.source, '--source-commit', checkout.commit, '--release', RELEASE],
        ...io,
      });
      expect(dryRun).toBe(0);
      const summary = JSON.parse(stdout.join(''));
      expect(summary).toMatchObject({ release: RELEASE, sourceCommit: checkout.commit, outputDirectory: null, signed: false });
      expect(await readdir(checkout.sandbox)).toEqual(['public']);

      stdout.length = 0;
      const written = await runReleaseCandidateCli({
        argv: ['--source', checkout.source, '--source-commit', checkout.commit, '--release', RELEASE, '--out', checkout.output],
        ...io,
      });
      expect(written).toBe(0);
      expect(JSON.parse(stdout.join('')).outputDirectory).toBe(checkout.output);

      stdout.length = 0;
      const again = await runReleaseCandidateCli({
        argv: ['--source', checkout.source, '--source-commit', checkout.commit, '--release', RELEASE, '--out', checkout.output],
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

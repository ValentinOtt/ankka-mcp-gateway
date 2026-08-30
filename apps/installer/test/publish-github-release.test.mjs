import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { createHash, createPrivateKey, createPublicKey, randomBytes } from 'node:crypto';
import { readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import { afterAll, beforeAll, describe, it } from 'vitest';

import {
  GitHubReleasePublicationError,
  loadGitHubReleaseOutput,
  prepareGitHubReleaseOutput,
  publishGitHubReleaseOutput,
  releaseNotes,
  writeGitHubReleaseOutput,
} from '../scripts/publish-github-release.mjs';
import {
  buildReleaseCandidate,
  writeReleaseCandidate,
} from '../scripts/build-gateway-release-candidate.mjs';
import {
  canonicalJson,
  prepareSignedReleasePublishPlan,
  writeSignedReleasePublishDirectory,
} from '../scripts/sign-gateway-release.mjs';
import { prepareReleaseSbom } from '../../../scripts/generate-release-sbom.mjs';
import { releaseCandidateCheckout } from './release-candidate-fixture.mjs';

const execFileAsync = promisify(execFile);
const TEST_ROOT = path.dirname(fileURLToPath(import.meta.url));
const REPOSITORY_ROOT = path.resolve(TEST_ROOT, '../../..');
const RELEASE = 'gateway-v9.9.9';
const CHANNEL = 'canary';
const REPOSITORY = 'example/ankka-mcp-gateway';
const PKCS8_SEED_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');
const REVIEWED_GH_VERSION = 'gh version 2.98.0 (2026-08-20)\nhttps://github.com/cli/cli/releases/tag/v2.98.0\n';

let fixture;

function publicKeyForSeed(seed) {
  const der = Buffer.concat([PKCS8_SEED_PREFIX, seed]);
  try {
    const privateKey = createPrivateKey({ key: der, format: 'der', type: 'pkcs8' });
    const spki = createPublicKey(privateKey).export({ format: 'der', type: 'spki' });
    return Buffer.from(spki).subarray(-32).toString('base64url');
  } finally {
    der.fill(0);
  }
}

function liveGitHubCommand(prepared, calls, verificationFailure = () => false) {
  return async (executable, args) => {
    calls.push([executable, args]);
    if (args.length === 1 && args[0] === '--version') {
      return { code: 0, stdout: REVIEWED_GH_VERSION, stderr: '' };
    }
    if (args[0] === 'api' && args[1].endsWith('/immutable-releases')) {
      return { code: 0, stdout: 'true\n', stderr: '' };
    }
    if (args[0] === 'api' && args[1].includes('/commits/')) {
      return { code: 0, stdout: `${fixture.sourceCommit}\n`, stderr: '' };
    }
    if (args[0] === 'api' && args[1].includes('/releases/tags/')) {
      return {
        code: 0,
        stdout: JSON.stringify({
          assets: prepared.plan.assets.map((asset) => ({
            digest: `sha256:${asset.sha256}`,
            name: asset.name,
            size: asset.byteSize,
          })),
          draft: false,
          html_url: `https://github.com/${REPOSITORY}/releases/tag/${RELEASE}`,
          immutable: true,
          name: prepared.plan.title,
          prerelease: prepared.plan.prerelease,
          tag_name: prepared.plan.tag,
          target_commitish: prepared.plan.sourceCommit,
        }),
        stderr: '',
      };
    }
    if (args[0] === 'api') return { code: 1, stdout: '', stderr: 'not found' };
    if (args[0] === 'release' && args[1] === 'view') {
      return { code: 1, stdout: '', stderr: 'not found' };
    }
    if (args[0] === 'release' && args[1] === 'create') {
      return { code: 0, stdout: `https://github.com/${REPOSITORY}/releases/tag/${RELEASE}\n`, stderr: '' };
    }
    if (args[0] === 'release' && (args[1] === 'verify' || args[1] === 'verify-asset')) {
      return verificationFailure(args)
        ? { code: 1, stdout: '', stderr: 'untrusted verification diagnostic' }
        : { code: 0, stdout: 'verified\n', stderr: '' };
    }
    return { code: 1, stdout: '', stderr: 'unexpected command' };
  };
}

beforeAll(async () => {
  const checkout = await releaseCandidateCheckout();
  const root = checkout.sandbox;
  const sourceCommit = checkout.commit;
  const candidate = await buildReleaseCandidate({
    controlPlaneOrigin: 'https://deploy.ankka.ai',
    sourceDirectory: checkout.source,
    sourceCommit,
    release: RELEASE,
  });
  const releaseDirectory = await writeReleaseCandidate(candidate, checkout.output);
  const seed = randomBytes(32);
  const publicKey = publicKeyForSeed(seed);
  const signed = await prepareSignedReleasePublishPlan({
    channel: CHANNEL,
    keyId: 'test-github-release-key',
    privateKeySeed: seed,
    publicKey,
    release: RELEASE,
    releaseDirectory,
  });
  const publishDirectory = path.join(root, 'signed');
  await writeSignedReleasePublishDirectory(signed, publishDirectory);
  const publicationResult = path.join(root, 'publication-result.json');
  await writeFile(publicationResult, canonicalJson({
    accountId: 'a'.repeat(32),
    artifactSha256: signed.artifactSha256,
    bucketName: 'synthetic-release-bucket',
    channel: CHANNEL,
    controlPlaneOrigin: candidate.manifest.controlPlaneOrigin,
    keyId: signed.keyId,
    objectPlanSha256: signed.objectPlanSha256,
    prefix: `ankka-mcp-gateway/releases/${CHANNEL}/${RELEASE}/`,
    publicKey,
    release: RELEASE,
    releaseEnvelopeSha256: signed.releaseEnvelopeSha256,
    schemaVersion: 1,
    status: 'published',
  }), { flag: 'wx', mode: 0o600 });
  const { stdout: rawSbom } = await execFileAsync('npm', [
    'sbom', '--package-lock-only', '--omit', 'dev', '--omit', 'optional',
    '--sbom-format', 'cyclonedx', '--sbom-type', 'application',
  ], { cwd: REPOSITORY_ROOT, encoding: 'utf8', maxBuffer: 2 * 1024 * 1024 });
  const sbom = path.join(root, 'sbom.cdx.json');
  await writeFile(sbom, prepareReleaseSbom({
    npmSbom: JSON.parse(rawSbom),
    packageLockSha256: createHash('sha256')
      .update(await readFile(path.join(REPOSITORY_ROOT, 'package-lock.json'))).digest('hex'),
    release: RELEASE,
    sourceCommit,
  }), { flag: 'wx', mode: 0o600 });
  fixture = Object.freeze({
    cleanup: checkout.cleanup,
    input: Object.freeze({ publicationResult, publishDirectory, releaseDirectory, repository: REPOSITORY, sbom }),
    root,
    sourceCommit,
  });
}, 30_000);

afterAll(async () => {
  if (fixture?.cleanup) await fixture.cleanup();
});

describe('reviewed GitHub Release publication', () => {
  it.each(['gateway-v0.1.15', 'gateway-v0.1.16', 'gateway-v0.1.17', 'gateway-v0.1.18'])('discloses %s Team limitations before the verification details', (release) => {
    const notes = releaseNotes(REPOSITORY, {
      release, sourceCommit: 'a'.repeat(40),
    }, { channel: 'stable', artifactSha256: 'b'.repeat(64), keyId: 'test-public-key' });
    assert.match(notes, /Team permissions apply only to MCP sources already installed in your gateway\./u);
    assert.match(notes, /New-source creation is unavailable in this release, including first-source onboarding for fresh empty gateways\./u);
    assert.match(notes, /Administrators remain fixed; source write tools are not activated and existing read-only boundaries are unchanged\./u);
    assert.match(notes, /Once a permission-policy write is armed, automatic teardown and rollback to older runtimes are blocked, including when the write outcome is uncertain\./u);
    const headingIndex = notes.indexOf(`## ${release.slice('gateway-'.length)} scope and limits`);
    assert.ok(headingIndex >= 0 && headingIndex < notes.indexOf('- Source commit:'));
  });

  it('discloses the v17 bridge and separate Team update without creating a credential', () => {
    const notes = releaseNotes(REPOSITORY, {
      release: 'gateway-v0.1.17', sourceCommit: 'a'.repeat(40),
    }, { channel: 'stable', artifactSha256: 'b'.repeat(64), keyId: 'test-public-key' });
    assert.match(notes, /Compatibility bridge: accepts the reviewed next Team release contract and fixes the installer return to your gateway after completion\./u);
    assert.match(notes, /This update does not create a Team credential or enable customer-local Team management; a separate second update is required\./u);
    assert.ok(notes.indexOf('Compatibility bridge:') < notes.indexOf('- Source commit:'));
  });

  it('discloses the v18 customer-local Team credential and bridge prerequisite', () => {
    const notes = releaseNotes(REPOSITORY, {
      release: 'gateway-v0.1.18', sourceCommit: 'a'.repeat(40),
    }, { channel: 'canary', artifactSha256: 'b'.repeat(64), keyId: 'test-public-key' });
    assert.match(notes, /Team saves run in your Cloudflare account without installer OAuth; they require a separately approved management credential\./u);
    assert.match(notes, /Upgrade v16 through the v17 compatibility bridge first\. This update does not provision that credential\./u);
    assert.ok(notes.indexOf('Team saves run in your Cloudflare account') < notes.indexOf('- Source commit:'));
    assert.doesNotMatch(notes, /does not create a Team credential or enable customer-local Team management/u);
  });

  it.each(['gateway-v0.1.14', 'gateway-v0.1.19'])(
    'preserves generic GitHub release notes for %s', (release) => {
      const sourceCommit = 'a'.repeat(40);
      const artifactSha256 = 'b'.repeat(64);
      const notes = releaseNotes(REPOSITORY, { release, sourceCommit }, {
        channel: CHANNEL, artifactSha256, keyId: 'test-public-key',
      });
      assert.equal(notes,
        'Canary pre-release of Ankka MCP Gateway. This GitHub Release mirrors the exact signed artifact already committed to the customer update channel.\n\n' +
        `- Source commit: [\`${sourceCommit.slice(0, 12)}\`](https://github.com/${REPOSITORY}/commit/${sourceCommit})\n` +
        `- Artifact SHA-256: \`${artifactSha256}\`\n` +
        '- Signature: Ed25519 (key ID `test-public-key`)\n' +
        '- Channel: `canary`\n\n' +
        'The attached `release-envelope.json` is the canonical signed release envelope. ' +
        '`release-verification.json` contains only public verification material, and ' +
        '`sbom.cdx.json` is the source-bound CycloneDX dependency inventory. ' +
        '`LICENSE.txt` and `THIRD_PARTY_LICENSES.txt` contain the complete distributed license texts. ' +
        'Cloudflare account, bucket, credentials, and private signing material are intentionally excluded.\n',
      );
    },
  );

  it('prepares a public mirror only after exact signed R2 publication', async () => {
    const prepared = await prepareGitHubReleaseOutput(fixture.input);
    assert.equal(prepared.plan.release, RELEASE);
    assert.equal(prepared.plan.sourceCommit, fixture.sourceCommit);
    assert.equal(prepared.plan.prerelease, true);
    assert.equal(prepared.plan.latest, false);
    assert.deepEqual(prepared.plan.assets.map((asset) => asset.name), [
      'release-envelope.json',
      'release-verification.json',
      'sbom.cdx.json',
      'LICENSE.txt',
      'THIRD_PARTY_LICENSES.txt',
    ]);

    const output = await writeGitHubReleaseOutput(prepared, path.join(fixture.root, 'github-output'));
    const verified = await loadGitHubReleaseOutput(output);
    assert.deepEqual(verified.plan, prepared.plan);
    const mirroredSbom = JSON.parse(await readFile(path.join(output, 'sbom.cdx.json'), 'utf8'));
    const verification = JSON.parse(await readFile(path.join(output, 'release-verification.json'), 'utf8'));
    assert.equal(verification.controlPlaneOrigin, 'https://deploy.ankka.ai');
    assert.equal(mirroredSbom.metadata.component.name, '@ankka/mcp-gateway');
    assert.match(await readFile(path.join(output, 'LICENSE.txt'), 'utf8'), /Apache-2\.0/u);
    assert.match(await readFile(path.join(output, 'THIRD_PARTY_LICENSES.txt'), 'utf8'), /third-party license/u);
    assert.equal(
      mirroredSbom.metadata.component.purl,
      `pkg:npm/%40ankka/mcp-gateway@${RELEASE.slice('gateway-v'.length)}`,
    );
    const allPublicOutput = (await Promise.all([
      readFile(path.join(output, 'github-release-plan.json'), 'utf8'),
      readFile(path.join(output, 'release-verification.json'), 'utf8'),
      readFile(path.join(output, 'RELEASE_NOTES.md'), 'utf8'),
      readFile(path.join(output, 'sbom.cdx.json'), 'utf8'),
      readFile(path.join(output, 'LICENSE.txt'), 'utf8'),
      readFile(path.join(output, 'THIRD_PARTY_LICENSES.txt'), 'utf8'),
    ])).join('\n');
    assert.doesNotMatch(allPublicOutput, /accountId|bucketName|synthetic-release-bucket/u);
    assert.match(allPublicOutput, /Ed25519/u);
  });

  it('rejects a publication receipt whose origin differs from the object plan and candidate', async () => {
    const receipt = JSON.parse(await readFile(fixture.input.publicationResult, 'utf8'));
    receipt.controlPlaneOrigin = 'https://foreign-control.example';
    const mismatchedReceipt = path.join(fixture.root, 'foreign-origin-publication-result.json');
    await writeFile(mismatchedReceipt, canonicalJson(receipt), { flag: 'wx', mode: 0o600 });
    await assert.rejects(
      prepareGitHubReleaseOutput({ ...fixture.input, publicationResult: mismatchedReceipt }),
      (error) => error instanceof GitHubReleasePublicationError,
    );
  });

  it('publishes the exact commit as a canary prerelease through bounded gh arguments', async () => {
    const prepared = await prepareGitHubReleaseOutput(fixture.input);
    const output = await writeGitHubReleaseOutput(prepared, path.join(fixture.root, 'github-live-output'));
    const calls = [];
    const command = liveGitHubCommand(prepared, calls);
    const result = await publishGitHubReleaseOutput(output, command);
    assert.equal(result.status, 'published');
    const create = calls.find(([, args]) => args[0] === 'release' && args[1] === 'create');
    assert.ok(create);
    assert.ok(create[1].includes('--prerelease'));
    assert.ok(create[1].includes('--latest=false'));
    assert.equal(create[1][create[1].indexOf('--target') + 1], fixture.sourceCommit);
    assert.equal(create[1][create[1].indexOf('--repo') + 1], REPOSITORY);
    assert.deepEqual(calls[0], ['gh', ['--version']]);
    const inspectedIndex = calls.findIndex(([, args]) =>
      args[0] === 'api' && args[1].includes('/releases/tags/'));
    const releaseVerifyIndex = calls.findIndex(([, args]) =>
      args[0] === 'release' && args[1] === 'verify');
    assert.ok(releaseVerifyIndex > inspectedIndex);
    assert.deepEqual(calls[releaseVerifyIndex], [
      'gh', ['release', 'verify', RELEASE, '--repo', REPOSITORY],
    ]);
    assert.deepEqual(
      calls.filter(([, args]) => args[0] === 'release' && args[1] === 'verify-asset'),
      prepared.plan.assets.map((asset) => [
        'gh', ['release', 'verify-asset', RELEASE, path.join(output, asset.name), '--repo', REPOSITORY],
      ]),
    );
  });

  it('requires exactly the reviewed GitHub CLI before any network call', async () => {
    const prepared = await prepareGitHubReleaseOutput(fixture.input);
    const output = await writeGitHubReleaseOutput(prepared, path.join(fixture.root, 'github-cli-version-output'));
    const calls = [];
    await assert.rejects(
      publishGitHubReleaseOutput(output, async (executable, args) => {
        calls.push([executable, args]);
        return {
          code: 0,
          stdout: 'gh version 2.76.1 (2025-07-30)\nhttps://github.com/cli/cli/releases/tag/v2.76.1\n',
          stderr: 'untrusted diagnostic',
        };
      }),
      (error) => error instanceof GitHubReleasePublicationError &&
        error.code === 'github_cli_version_required' &&
        error.message === 'github_cli_version_required',
    );
    assert.deepEqual(calls, [['gh', ['--version']]]);
  });

  it('fails with one fixed diagnostic when GitHub integrity verification fails', async () => {
    const prepared = await prepareGitHubReleaseOutput(fixture.input);
    const releaseOutput = await writeGitHubReleaseOutput(
      prepared,
      path.join(fixture.root, 'github-release-integrity-failure-output'),
    );
    const releaseCalls = [];
    await assert.rejects(
      publishGitHubReleaseOutput(
        releaseOutput,
        liveGitHubCommand(prepared, releaseCalls, (args) => args[1] === 'verify'),
      ),
      (error) => error instanceof GitHubReleasePublicationError &&
        error.code === 'github_release_verification_failed' &&
        error.message === 'github_release_verification_failed',
    );
    assert.equal(
      releaseCalls.some(([, args]) => args[0] === 'release' && args[1] === 'verify-asset'),
      false,
    );

    const assetOutput = await writeGitHubReleaseOutput(
      prepared,
      path.join(fixture.root, 'github-asset-integrity-failure-output'),
    );
    const assetCalls = [];
    await assert.rejects(
      publishGitHubReleaseOutput(
        assetOutput,
        liveGitHubCommand(prepared, assetCalls, (args) =>
          args[1] === 'verify-asset' && args[3] === path.join(assetOutput, 'THIRD_PARTY_LICENSES.txt')),
      ),
      (error) => error instanceof GitHubReleasePublicationError &&
        error.code === 'github_release_verification_failed' &&
        error.message === 'github_release_verification_failed',
    );
    assert.equal(
      assetCalls.filter(([, args]) => args[0] === 'release' && args[1] === 'verify-asset').length,
      5,
    );
  });

  it('fails closed on a changed public verification artifact and an existing release', async () => {
    const prepared = await prepareGitHubReleaseOutput(fixture.input);
    const tampered = await writeGitHubReleaseOutput(prepared, path.join(fixture.root, 'github-tampered-output'));
    await writeFile(path.join(tampered, 'release-verification.json'), '{}');
    await assert.rejects(
      loadGitHubReleaseOutput(tampered),
      (error) => error instanceof GitHubReleasePublicationError,
    );

    const mutableOutput = await writeGitHubReleaseOutput(prepared, path.join(fixture.root, 'github-mutable-output'));
    await assert.rejects(
      publishGitHubReleaseOutput(mutableOutput, async (_executable, args) =>
        args[0] === '--version'
          ? { code: 0, stdout: REVIEWED_GH_VERSION, stderr: '' }
          : { code: 0, stdout: 'false\n', stderr: '' }),
      (error) => error instanceof GitHubReleasePublicationError && error.code === 'github_release_immutability_required',
    );

    const output = await writeGitHubReleaseOutput(prepared, path.join(fixture.root, 'github-existing-output'));
    await assert.rejects(
      publishGitHubReleaseOutput(output, async (_executable, args) => {
        if (args[0] === '--version') {
          return { code: 0, stdout: REVIEWED_GH_VERSION, stderr: '' };
        }
        if (args[0] === 'api' && args[1].endsWith('/immutable-releases')) {
          return { code: 0, stdout: 'true\n', stderr: '' };
        }
        if (args[0] === 'api') return { code: 0, stdout: `${fixture.sourceCommit}\n`, stderr: '' };
        return { code: 0, stdout: JSON.stringify({ tagName: RELEASE }), stderr: '' };
      }),
      (error) => error instanceof GitHubReleasePublicationError && error.code === 'github_release_exists',
    );

    const tagOutput = await writeGitHubReleaseOutput(prepared, path.join(fixture.root, 'github-tag-output'));
    await assert.rejects(
      publishGitHubReleaseOutput(tagOutput, async (_executable, args) => {
        if (args[0] === '--version') {
          return { code: 0, stdout: REVIEWED_GH_VERSION, stderr: '' };
        }
        if (args[0] === 'api' && args[1].endsWith('/immutable-releases')) {
          return { code: 0, stdout: 'true\n', stderr: '' };
        }
        if (args[0] === 'api' && args[1].includes('/commits/')) {
          return { code: 0, stdout: `${fixture.sourceCommit}\n`, stderr: '' };
        }
        if (args[0] === 'release' && args[1] === 'view') {
          return { code: 1, stdout: '', stderr: 'not found' };
        }
        return { code: 0, stdout: `${fixture.sourceCommit}\n`, stderr: '' };
      }),
      (error) => error instanceof GitHubReleasePublicationError && error.code === 'github_tag_exists',
    );

    const duplicateAssetOutput = await writeGitHubReleaseOutput(
      prepared,
      path.join(fixture.root, 'github-duplicate-asset-output'),
    );
    await assert.rejects(
      publishGitHubReleaseOutput(duplicateAssetOutput, async (_executable, args) => {
        if (args[0] === '--version') {
          return { code: 0, stdout: REVIEWED_GH_VERSION, stderr: '' };
        }
        if (args[0] === 'api' && args[1].endsWith('/immutable-releases')) {
          return { code: 0, stdout: 'true\n', stderr: '' };
        }
        if (args[0] === 'api' && args[1].includes('/commits/')) {
          return { code: 0, stdout: `${fixture.sourceCommit}\n`, stderr: '' };
        }
        if (args[0] === 'release' && args[1] === 'view') {
          return { code: 1, stdout: '', stderr: 'not found' };
        }
        if (args[0] === 'api' && args[1].includes('/git/ref/tags/')) {
          return { code: 1, stdout: '', stderr: 'not found' };
        }
        if (args[0] === 'release' && args[1] === 'create') {
          return { code: 0, stdout: 'created\n', stderr: '' };
        }
        const duplicate = prepared.plan.assets[0];
        return {
          code: 0,
          stdout: JSON.stringify({
            assets: prepared.plan.assets.map(() => ({
              digest: `sha256:${duplicate.sha256}`,
              name: duplicate.name,
              size: duplicate.byteSize,
            })),
            draft: false,
            html_url: `https://github.com/${REPOSITORY}/releases/tag/${RELEASE}`,
            immutable: true,
            name: prepared.plan.title,
            prerelease: prepared.plan.prerelease,
            tag_name: prepared.plan.tag,
            target_commitish: prepared.plan.sourceCommit,
          }),
          stderr: '',
        };
      }),
      (error) => error instanceof GitHubReleasePublicationError &&
        error.code === 'github_release_verification_failed',
    );
  });

  it('rejects legacy and cross-channel replayed envelopes at the GitHub mirror boundary', async () => {
    const prepared = await prepareGitHubReleaseOutput(fixture.input);
    const rewrite = async (directory, mutateEnvelope, mutatePlan = () => undefined) => {
      const output = await writeGitHubReleaseOutput(prepared, directory);
      const planPath = path.join(output, 'github-release-plan.json');
      const envelopePath = path.join(output, 'release-envelope.json');
      const verificationPath = path.join(output, 'release-verification.json');
      const plan = JSON.parse(await readFile(planPath, 'utf8'));
      const envelope = JSON.parse(await readFile(envelopePath, 'utf8'));
      const verification = JSON.parse(await readFile(verificationPath, 'utf8'));
      mutateEnvelope(envelope, verification);
      mutatePlan(plan);
      const envelopeBytes = Buffer.from(canonicalJson(envelope), 'utf8');
      verification.releaseEnvelopeSha256 = createHash('sha256').update(envelopeBytes).digest('hex');
      const verificationBytes = Buffer.from(canonicalJson(verification), 'utf8');
      plan.assets[0].byteSize = envelopeBytes.byteLength;
      plan.assets[0].sha256 = verification.releaseEnvelopeSha256;
      plan.assets[1].byteSize = verificationBytes.byteLength;
      plan.assets[1].sha256 = createHash('sha256').update(verificationBytes).digest('hex');
      await Promise.all([
        writeFile(envelopePath, envelopeBytes),
        writeFile(verificationPath, verificationBytes),
        writeFile(planPath, canonicalJson(plan)),
      ]);
      return output;
    };

    const replay = await rewrite(
      path.join(fixture.root, 'github-cross-channel-output'),
      (envelope, verification) => {
        envelope.channel = 'stable';
        verification.channel = 'stable';
      },
      (plan) => {
        plan.channel = 'stable';
        plan.latest = true;
        plan.prerelease = false;
        plan.title = `Ankka MCP Gateway ${RELEASE.slice('gateway-'.length)}`;
      },
    );
    await assert.rejects(
      loadGitHubReleaseOutput(replay),
      (error) => error instanceof GitHubReleasePublicationError,
    );

    const legacy = await rewrite(
      path.join(fixture.root, 'github-legacy-envelope-output'),
      (envelope) => {
        delete envelope.channel;
        delete envelope.signatureContext;
        envelope.schemaVersion = 1;
      },
    );
    await assert.rejects(
      loadGitHubReleaseOutput(legacy),
      (error) => error instanceof GitHubReleasePublicationError,
    );
  });

  it('rejects a canonical SBOM containing a private locator before mirror output', async () => {
    const sbom = JSON.parse(await readFile(fixture.input.sbom, 'utf8'));
    sbom.components[0].accountId = 'a'.repeat(32);
    const unsafe = path.join(fixture.root, 'unsafe-sbom.cdx.json');
    await writeFile(unsafe, canonicalJson(sbom), { flag: 'wx', mode: 0o600 });
    await assert.rejects(
      prepareGitHubReleaseOutput({ ...fixture.input, sbom: unsafe }),
      (error) => error instanceof GitHubReleasePublicationError,
    );
  });
});

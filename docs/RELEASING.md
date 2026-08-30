# Release integrity

This document describes the public release-integrity contract. It is not a
deployment runbook and grants no signing, publication, or Cloudflare authority.

Release support expectations are defined by the
[support policy](../SUPPORT.md): support is best-effort, and only the newest
release of each channel receives fixes. Canary artifacts are prereleases for
evaluation; a stable release marks a maintainer recommendation, not a
warranty.

## Source binding

A release candidate must be built from one clean public commit with:

- the pinned Node.js, npm, Wrangler, and lockfile inputs;
- no staged or modified tracked file and no untracked release input;
- no symlink, credential, or private identifier;
- a passing repository verification suite; and
- deterministic output when rebuilt from the same commit.

The builder may recreate ignored `apps/admin/dist` from the locked source. That
directory is untracked build output, not source input. The materialized release
candidate and all signed or publishable output stay outside the repository.

## Signed components

The release contains five components:

- the primary gateway Worker;
- the generated gateway dashboard;
- the hosted installer assets used by the operator-approved flow;
- the receipt-authorized cleanup Worker; and
- the inert retirement Worker.

The canonical manifest records the release identifier, public source commit,
release channel, one canonical HTTPS control-plane origin, required OAuth
scopes, Cloudflare deployment contract, every file's path, media type, size and
SHA-256 digest, component digests, and the aggregate artifact digest. Candidate
generation compiles that origin into the gateway Worker before computing any
file, component, or aggregate hash.

The release builder also produces the project license, exact production
third-party license texts, and a source-bound CycloneDX SBOM.

## Signature

An external Ed25519 key signs a domain-separated canonical statement that
binds:

- the exact manifest bytes;
- the `canary` or `stable` channel;
- the public key identifier;
- the signature schema; and
- the signature context.

The installer and updater reject unknown keys, malformed manifests, digest
mismatches, legacy envelope formats, and a valid envelope copied to a different
channel. They also reject any disagreement between the embedded Worker origin,
manifest, release pin, publication receipt, installer origin, or current
installed origin.

The private signing seed is never committed, placed in CI, stored in
Cloudflare, or given to the publisher. Source availability does not confer
signing authority.

## Publication

Signed releases are published create-only. A version prefix must be empty
before publication and cannot be overwritten.

The public GitHub Release mirrors the exact source commit and carries the
signed envelope, sanitized verification record, SBOM, project license, and
production third-party license bundle. GitHub Releases are immutable.

The hosted release endpoint serves only the exact maintainer-approved release
pinned into that build. Publishing a release does not activate the installer,
promote a channel, or update a gateway.

Signing, publication, installer deployment, public activation, rollback, and
stable promotion are separate maintainer-approved operations.

## Verifying a published release

GitHub's release attestation can verify a release and a downloaded asset:

```sh
gh release verify <tag> --repo ValentinOtt/ankka-mcp-gateway
gh release verify-asset <tag> <downloaded-file> --repo ValentinOtt/ankka-mcp-gateway
```

That verifies GitHub's release provenance and asset digest. The installer
separately verifies Ankka's Ed25519 envelope, pinned public key, manifest, and
payload digests before using a release.

There is no supported release or stable tag yet. The first release must publish
its signing key identity and sanitized verification record alongside the signed
envelope before users can perform the complete check.

## Signing-key lifecycle

The signing key has a stable public key and key identifier. Its private seed
must have an independently recoverable encrypted backup outside the repository,
CI, Cloudflare, GitHub, application storage, and support systems. Backup
verification compares only the derived public key and must not expose the seed.

If the key is lost without suspected compromise, stop signing until the
approved backup is recovered and verified. Never place a different key behind
the old key identifier.

If compromise is suspected, stop signing and promotion, preserve evidence
without copying the seed, and treat every unpublished artifact signed by that
key as untrusted. Key rotation is a separately approved trust-root migration,
not an ordinary gateway update.

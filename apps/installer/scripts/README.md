# Offline gateway release candidate and signing

## Exact release candidate builder

`build-gateway-release-candidate.mjs` produces the `--release-dir` the signer
consumes. It is offline and secret-free: it reads this public repository's
checkout, requires `HEAD` to equal the stated
`--source-commit` and every release input to carry no uncommitted, staged, or
untracked change. It rebuilds the single React/Kumo dashboard from
`apps/admin`, maps its generated files to `payload/admin`, and combines them
with the four hand-authored components under `payload/`. It then enumerates
exactly those five release components (no symlinks, no extra entries,
allowlisted extensions only) and emits the canonical
`manifest.json` — per-file size, content type and SHA-256; component and
aggregate tree digests by the signer's definition (SHA-256 over the canonical
JSON of the sorted file records); the approved Cloudflare contract; the exact
ten OAuth scope IDs; release id; source commit.

All signed textual payloads must decode as strict UTF-8 and contain only LF
line endings; the builder rejects CR/CRLF and NUL before hashing. Binary formats
remain byte-for-byte inputs under their explicit MIME allowlist.

The admin build also generates `LICENSE.txt` and
`THIRD_PARTY_LICENSES.txt` from the exact production dependency graph. These
files are signed as part of `payload/admin`; the GitHub Release mirror attaches
the same bytes alongside the envelope, verification record, and SBOM.

```bash
node scripts/build-gateway-release-candidate.mjs \
  --source ../.. \
  --source-commit <40-hex HEAD of that checkout> \
  --release gateway-vX.Y.Z \
  [--out /absolute/path/to/new-candidate-directory]
```

Without `--out` it is a dry run that prints the digests only. With `--out` it
writes `payload/` create-only into a directory that must not exist, writes
`manifest.json` last, and then proves the result with the signer's own
release-directory loader, so a zero exit means the signer would accept the
directory byte-for-byte. The printed `artifact.treeSha256` is the value the
publication receipt and runtime pin later carry as `artifactSha256`. Nothing is
signed, published, or uploaded; regenerate into a new directory after any
release-input change rather than editing an output. Generated dashboard assets
remain ignored and are never a second source of truth.

The component tree digests here are not the public repository's layout-test
`TREE_SHA256` values: those hash a different record shape. Review both; they
identify the same bytes.

## Reviewed compensation fault candidate

`build-reviewed-fault-injection-candidate.mjs` creates the single deliberately
unhealthy candidate used to prove updater compensation. It starts from the
same clean, exact source commit as the ordinary builder, rebuilds those release
bytes, then makes one deterministic change to `payload/worker/index.js`: an
exact-version runtime-action probe returns `503 reviewed_fault_injected`. The
candidate still has the canonical schema and recomputed file, component, and
artifact digests, so the ordinary release verifier accepts its exact bytes.

The command is intentionally narrow. It requires the literal fault ID and
`--channel canary`, requires the target version to be strictly newer than the
stated healthy base version, writes only to a new output directory, and proves
the result with the signer's loader. Use a target version that has never been
published. The immutable R2 intent rejects a different artifact under an
existing release ID; because an exact interrupted publication is intentionally
restartable, the operator must also verify from retained release receipts and
publication-intent evidence that the chosen target ID has never completed
publication.

```bash
node scripts/build-reviewed-fault-injection-candidate.mjs \
  --source ../.. \
  --source-commit <40-hex exact HEAD> \
  --base-release gateway-vX.Y.Z \
  --release gateway-vX.Y.N \
  --channel canary \
  --fault exact-version-health-probe-v1 \
  --out /absolute/path/to/new-fault-candidate
```

The signer recognizes the embedded public marker. It refuses this artifact on
every channel except `canary`, refuses it without the separate
`--reviewed-fault-injection exact-version-health-probe-v1` acknowledgement, and
rejects that acknowledgement for an ordinary candidate. Nothing in the fault
builder signs, publishes, uploads, or holds a secret. Never mirror this
deliberately unhealthy artifact as a GitHub Release or promote it to stable.

## Signing

`sign-gateway-release.mjs` is an operator-side, network-free boundary between
the public release builder and the hosted installer's private immutable release
bucket. It does not import Wrangler, read environment variables or Keychain,
or implement an R2 uploader.

The input must be a complete public release directory containing the exact
canonical `manifest.json` and `payload/` tree. The tool independently checks
the rich manifest contract, release/channel/key identifiers, exact regular-file
tree, safe paths, MIME allowlist, byte counts, every file SHA-256, component
tree digests, and aggregate digest before signing a canonical, domain-separated
release statement. Envelope schema 2 binds the exact canonical manifest bytes,
the `canary` or `stable` channel, key ID, schema version, and literal
`ankka-mcp-gateway-release-envelope-v2` signature context. A schema-1 signature
over manifest bytes alone is rejected. The tree must contain all five signed
components: admin, installer, primary Worker, cleanup Worker, and
declarative-retirement Worker.

The Ed25519 signing seed is exactly 32 raw bytes and is accepted only through
the library's per-call `privateKeySeed` or raw stdin with
`--private-key-stdin`. It is never accepted through argv, environment, a file,
or an error message. The caller-provided seed view and internal DER buffers are
zeroed before the signing call settles. An explicit raw public key is required
and must match the private seed before an envelope is emitted.

`derive-ed25519-public-key.mjs` derives that raw public key from the same exact
32-byte seed. It accepts the seed only as raw stdin and prints only a public,
secret-free JSON record. When an operator stores a base64-encoded seed in
Keychain, decode it directly in a pipe to this helper; do not use command
substitution, an environment variable, a temporary file, or a password
argument.

By default the CLI is an offline dry run and prints only the canonical,
secret-free object plan. Supplying both `--write-publish-directory` and `--out`
creates a brand-new local directory; the output root must not already exist.
Every file is written create-only and verified, and `r2-object-plan.json` is
written last as the completion marker. A failed partial directory must be
quarantined or removed by the operator, never reused.

The directory contains an `objects/` tree whose relative paths are the exact R2
keys under:

```text
ankka-mcp-gateway/releases/<channel>/<release>/
```

The object plan is not itself an R2 object. It declares the exact envelope and
payload object set, sizes, MIME types, hashes, and local source paths.

For the one reviewed compensation fixture only, the signing command must also
include:

```text
--channel canary \
--reviewed-fault-injection exact-version-health-probe-v1
```

The same retained release key is required so the installed updater exercises
ordinary signature verification. The signer fails closed if the marker,
channel, and explicit acknowledgement do not agree.

## OAuth client credential preflight

`verify-oauth-client-pair.mjs` is the mandatory live preflight for the hosted
installer's Cloudflare OAuth client ID and secret. The secret is read only from
bounded stdin. The script sends a deliberately invalid authorization code to
Cloudflare's token endpoint: a matching client ID and secret are authenticated
first and produce `invalid_grant`; `invalid_client` fails with a fixed,
secret-free diagnostic. The request cannot issue an OAuth grant.

```sh
security find-generic-password \
  -s "ankka-mcp-gateway-oauth-client-secret" -w \
  | node scripts/verify-oauth-client-pair.mjs \
      --client-id '<reviewed public client ID>' \
      --client-secret-stdin
```

Run it before every hosted-installer deployment and immediately after rotating
the Worker secret. A nonzero result is a deployment blocker.

## OAuth scope catalogue preflight

`verify-oauth-scope-catalogue.mjs` performs the separate live, read-only
`GET /oauth/scopes` gate. Cloudflare documents that the endpoint requires
authentication but no authorization role. The token is accepted only through
bounded stdin, the request target is fixed, and output contains only verified
scope counts:

```sh
security find-generic-password -s '<short-lived-canary-token-service>' -w \
  | node scripts/verify-oauth-scope-catalogue.mjs --api-token-stdin
```

The exact ten required IDs are regression-bound to `src/constants.ts`. A
missing ID, duplicate catalogue ID, malformed response, non-200 status, timeout,
or oversized response fails with a fixed diagnostic and never prints provider
content or the token.

## Public self-service Access verifier

`edge-gate/verify-public.mjs` is the read-only post-activation check for a live
host that already has no Ankka Access application. It does not remove
applications or carry a session cookie. Before activation, runbook §10 requires
an independent complete account read plus disabled-shell probes; the active-only
verifier then repeats the Access proof immediately after activation. Its
complete paginated Access-app read must prove that no
whole-host, path-specific, wildcard, or destination selector can
cover `deploy.ankka.ai`; unknown selector shapes fail closed.

The same run makes cookie-free, manual-redirect requests to the active runtime.
It requires the exact active `mutationsEnabled: true` health response, a `200`
installer root whose bytes match `payload/installer/index.html` in the signed manifest,
application-level callback rejection, both exact release
paths, and no Access redirect. Cloudflare-injected `NEL` or `Report-To` headers
on the Ankka-owned hosted zone are permitted under the separately reviewed
platform-metadata policy; the verifier does not treat them as readiness
evidence. It uses
`HEAD /api/session`, not the state-minting GET. The active release descriptor
must match the operator-supplied channel, release, source commit, artifact
digest and key ID, and its channel-bound schema-2 Ed25519 signature must verify
against the supplied public key. The inactive channel must return the exact
application-level `404`.

The Cloudflare read token is accepted only through bounded stdin and is sent
only to the fixed Cloudflare API origin. Output contains no account, Access-app
or identity identifiers:

```sh
security find-generic-password -s '<short-lived-access-read-token-service>' -w \
  | node scripts/edge-gate/verify-public.mjs \
      --api-token-stdin \
      --channel canary \
      --release gateway-vX.Y.Z \
      --source-commit '<40-lowerhex>' \
      --artifact-sha256 '<64-lowerhex>' \
      --key-id '<reviewed-key-id>' \
      --public-key '<raw-ed25519-base64url>'
```

There is intentionally no public Access mutator. The current cutover never
creates, deletes, or recreates an Access application on `deploy.ankka.ai`; the
live host stays on the no-Access disabled shell until activation and returns to
that shell on rollback. `apply-access.mjs` is a credential-free fail-closed
stub. `verify-access.mjs` remains a read-only description of the retired live
private contract and is expected to fail while no Access app exists. The public
verifier supplies read-back and behavioral proof without adding deployment
authority here.

An optional private canary uses `apply-isolated-access.mjs` and
`verify-isolated-access.mjs` with the same exact outside-repository target JSON
required by `generate-reviewed-isolated-canary.mjs`. That wrapper refuses to
generate without `--isolated-target` and refuses to validate a live schema-1
artifact; `generate-reviewed-canary.mjs` retains the reviewed live defaults for
later public activation. The target binds one lowercase non-live hostname, an
`ankka-gateway-deploy-isolated-*` Worker, the exact publication account, and a
separate isolated-only OAuth client ID. Both parsers reject the live hostname,
production Worker, and permanently Public live OAuth client ID. The apply
command has an offline `--dry-run`; an actual
create requires a token through bounded `--api-token-stdin`, creates the three
exact path Bypasses before whole-host protection, and resumes only exact prior
creates. The verifier uses a read token through bounded stdin, performs a
complete paginated application read and cookie-free behavior probes, and emits
counts only. Run it with `--runtime disabled` after the isolated false/null
shell is deployed, then with `--runtime active` after activation. The first
mode requires exact application-level `503` responses on every bypass; the
second requires the callback's exact `400 session_invalid` rejection and
application-shaped release responses. Neither command prints account,
application, identity-provider, hostname, token, or operator identifiers.

The reviewed `src/r2-release-publisher.ts` primitive creates an immutable intent
outside the consumer release prefix, writes every object through an R2 binding
with `If-None-Match: *`, and writes `release-envelope.json` last as the commit
marker. It can resume an identical partial publication, rejects conflicts and
unexpected prefix contents, and finishes by re-reading the exact intent and
release object set. It is not referenced by a production route, Worker
entrypoint, binding, or Wrangler configuration. An overwrite-capable `put`,
copy, sync, Wrangler object command, or REST upload is not an acceptable
substitute.

## Ephemeral create-only publication operator

`generate-r2-publication-worker.mjs` is the only callable wrapper around that
primitive. It still makes no network call. It accepts an exact signer-created
publish directory, exact Cloudflare account ID, exact R2 bucket name, and the
nonsecret raw Ed25519 public key used for the release, then independently
checks:

- the canonical object plan and its immutable channel/release prefix;
- the exact regular-file and directory tree, with no symlinks or extras;
- every object path, byte count, and SHA-256;
- the canonical schema-2 release envelope and its Ed25519 signature over the
  domain-separated, channel-bound release statement against the supplied public
  key; and
- a deliberately smaller operator limit of 512 objects and 1,500,000 total
  release bytes, keeping the embedded generated Worker below 2,250,000 source
  bytes and requiring no request upload.

It writes a brand-new temporary directory containing one release-specific
Worker. The output path must not exist and is never reused. Its only binding is
`RELEASE_BUCKET`, configured with the exact bucket and `remote = true`.
`account_id` is also pinned at the top level from the required canonical
32-character lowercase hexadecimal input; ambient environment variables,
cached Wrangler profiles, and other account defaults cannot select a different
account. The Worker itself runs locally on `127.0.0.1:5732`; only that binding
is proxied to the real R2 bucket. There is no route, workers.dev URL, Preview URL,
observability, OAuth credential, request body, query parameter, arbitrary R2
key, or arbitrary R2 value. Publication can start once per generated Worker
process at the capability path committed to the object-plan SHA-256.

Generate it offline:

```bash
node scripts/generate-r2-publication-worker.mjs \
  --publish-dir /absolute/path/to/signed-publish-directory \
  --account-id 0123456789abcdef0123456789abcdef \
  --bucket ankka-gateway-releases \
  --public-key '<raw-ed25519-base64url>' \
  --out /absolute/path/to/new-temporary-operator-directory
```

Review `wrangler.toml`, `INVOCATION.txt`, and the object-plan digest before the
explicit live step. From the generated directory, start only the local proxy:

`INVOCATION.txt` records the already-installed, generator-verified Wrangler
executable as an absolute path. Its command has this shape:

```bash
'node_modules/wrangler/bin/wrangler.js' dev \
  --config wrangler.toml --ip 127.0.0.1 --port 5732
```

In a second terminal, invoke the exact command recorded in `INVOCATION.txt`
once. Send no body and no query. Under `wrangler dev` a bodiless POST reaches
the operator as an empty stream rather than a null body; the operator treats
"no body" as zero body bytes and rejects any byte before the one-shot is
burned (first live run, 2026-08-23). Stop Wrangler immediately after the response,
then remove or quarantine the temporary directory. The success response is a
secret-free exact receipt containing only `schemaVersion`, `status`,
`accountId`, `bucketName`, `channel`, `release`, `prefix`, `keyId`, `publicKey`,
`artifactSha256`, `releaseEnvelopeSha256`, and `objectPlanSha256`. A retry after
an ambiguous result requires stopping and regenerating the local Worker; the
underlying publisher safely settles identical create-only writes by exact GET.

Do not add `--remote`: current Wrangler runs the Worker locally and uses the
binding-level `remote = true` proxy. Do not run `wrangler deploy` for this
operator, and do not use `wrangler r2 object put` because it does not preserve
the required conditional create-only contract.

## GitHub Release mirror

`publish-github-release.mjs` makes an already-published signed gateway version
visible in the repository's Releases section. GitHub is a public mirror, not
the customer update authority: R2 publication must finish first, and the exact
successful publication receipt is a mandatory input.

Preparation is offline. It independently validates the release candidate, the
signed publish directory, the Ed25519 signature, and the exact R2 publication
receipt, then creates a new local directory containing only:

- the canonical `release-envelope.json`;
- a sanitized `release-verification.json` with the public key and digests;
- a deterministic, source- and lockfile-bound CycloneDX `sbom.cdx.json`;
- the shipped Apache-2.0 `LICENSE.txt` and complete production
  `THIRD_PARTY_LICENSES.txt` texts;
- deterministic release notes; and
- a canonical `github-release-plan.json` completion marker.

The Cloudflare account ID, bucket name, publication receipt, credentials, and
private signing seed are never copied into the output. Canary versions are
GitHub prereleases and are never marked Latest; stable versions are ordinary
releases and may be Latest.

```sh
node scripts/publish-github-release.mjs \
  --release-dir /absolute/path/to/release-candidate \
  --publish-dir /absolute/path/to/signed-publish-directory \
  --publication-result /absolute/path/to/publication-receipt.json \
  --repository owner/ankka-mcp-gateway \
  --sbom /absolute/path/to/source-bound-sbom.cdx.json \
  --out /absolute/path/to/new-github-release-output

node scripts/publish-github-release.mjs \
  --validate-output-dir /absolute/path/to/new-github-release-output
```

Review the printed tag, exact source commit, artifact digest, asset digests,
title, and prerelease/latest classification. Publishing is the only network
mutation and requires a separately authenticated GitHub CLI 2.97.0 session.
The live command checks `gh --version` locally first and makes no GitHub request
unless the CLI reports exactly that reviewed version:

```sh
node scripts/publish-github-release.mjs \
  --publish-output-dir /absolute/path/to/new-github-release-output
```

The live mode first requires repository-level immutable Releases, then proves
that the exact source commit exists in the selected repository and that neither
the tag nor its Release already exists. It invokes the authenticated GitHub CLI
with the exact full commit as the release target. For an immutable Release,
GitHub CLI 2.97.0 creates a draft, uploads the five reviewed public assets, and
publishes only after those uploads complete. The operator then re-reads the
published Release and requires its exact API shape: tag, target, title,
immutable state, classification, asset names, byte sizes, and SHA-256 digests.
Only after that check succeeds does it require `gh release verify` for the
Release and `gh release verify-asset` against each of the five local asset
files. Any CLI-version, Release-integrity, or asset-integrity failure stops with
a fixed diagnostic; command output is never copied into the diagnostic. The
operator never overwrites or clobbers an existing Release or asset.

Generate the SBOM only from a clean checkout at the candidate's exact source
commit. The generator proves its own and the canonical-JSON implementation's
bytes match that checkout, enforces the source-pinned Node and npm versions,
uses the lockfile without network access, and rechecks the source after npm
returns. It omits optional cross-platform packages that npm cannot resolve into
one portable graph, excludes development-only build/test tooling, removes npm's
random serial number and timestamp, sorts the
component/dependency graph bytewise, and binds the result to the release,
source commit, and package-lock SHA-256. Both generation and mirror validation
reject credential-bearing URLs, private material, sensitive locator fields and
local filesystem paths:

```sh
node ../../scripts/generate-release-sbom.mjs \
  --source /absolute/path/to/clean-checkout \
  --source-commit <40-character-commit> \
  --release gateway-vX.Y.Z \
  --out /absolute/path/to/new-sbom.cdx.json
```

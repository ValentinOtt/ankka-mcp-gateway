# First-party Cloudflare dogfood runbook

This is the sanctioned development path for a consenting first party to test a
real Ankka MCP Gateway in its own Cloudflare account before a supported public
release exists.

> **Status: executable, unsupported, and not live-qualified.** The repository
> tests the signed-origin, publication, install, update, rollback, recovery,
> source-management, and receipt-bound removal contracts. No live Cloudflare
> result is asserted here. Use a disposable or explicitly approved pre-release
> target, expect breaking changes, and do not present this path as production
> support.

The checked-in installer remains non-deploying. This runbook creates an exact,
isolated installer from a clean public commit and a locally generated
development signature. It does not grant production signing or deployment
authority.

## Non-negotiable boundaries

- The installer hostname is one canonical HTTPS origin. Candidate generation
  compiles that origin into the customer Worker before hashing it; the signed
  manifest, release pin, publication receipt, generated installer, browser
  handoffs, update discovery, and management handoffs must all agree. A request,
  environment variable, or gateway configuration cannot select another origin.
- Both drill releases use the same origin, `canary` channel, key identifier,
  Ed25519 key, R2 bucket, customer account, OAuth client, and isolated Worker.
  Changing any of them is a different trust or deployment exercise.
- A production signing pipeline is not required. A valid local development
  Ed25519 signature is required. Never disable or patch signature verification.
- Every Cloudflare resource, grant, log, source credential, and generated
  artifact belongs to the customer. The customer gateway sends no telemetry to
  Ankka. The isolated installer retains the fixed installer funnel in the
  customer's own Analytics Engine dataset.
- Generated candidates, signed output, keys, pins, publication receipts,
  target files, Wrangler state, live identifiers, and command output stay in an
  operator-controlled directory outside this repository.
- Never put an upstream MCP credential in gateway configuration or send it to
  the installer. A shared BLS bearer belongs only in the customer-owned
  `bls-read` source Worker's secret binding. Because that workload handles
  personal data, its MCP ingress must use standards-compliant per-user OAuth.
  `authentication.mode: none` is not acceptable for it: the Portal would send
  unauthenticated HTTP, and the current management path cannot attach a
  separate Cloudflare Access service-token header pair. Generic bearer and
  custom-header source credentials are deliberately outside the dashboard.
- The gateway remains read-only with exact tool allowlists. A source Worker
  must independently reject write operations; tool names and prompts are not
  authorization.
- The founding-team BLS deployment uses one Access group and one shared
  `readonly` BLS origin credential. MCP identity terminates at Access and is
  never forwarded or mapped to a per-user BLS identity. Multi-group
  partitioning, exact actor correlation, and write infrastructure are not
  prerequisites.

Stop if any invariant cannot be met.

## 1. Prepare the exact public input

Use a clean checkout of the exact public commit to be released. The release
builder rejects a dirty checkout, a commit mismatch, symlinks, generated
release output, credentials, and private identifiers.

```sh
npm ci
npm run check
git status --short
git rev-parse HEAD
```

The full gate must pass and `git status --short` must be empty. Record the
40-character commit outside the repository. Use only the Node, npm, Wrangler,
and dependency versions pinned by that checkout.

Choose these customer-owned values:

- an isolated hostname with at least three DNS labels, for example
  `installer.dogfood.example.com`;
- an empty R2 bucket dedicated to the drill;
- a Worker name beginning `ankka-gateway-deploy-isolated-`;
- one 32-character lowercase hexadecimal, non-public Cloudflare OAuth client
  identifier; and
- a development key identifier matching `[a-z0-9._-]`, such as
  `dogfood-dev-1`.

Create a private, account-owned Cloudflare OAuth client. Its redirect URL is
`https://<isolated-hostname>/oauth/callback`, its response and grant types are
`code` and `authorization_code`, and its token authentication method is
`client_secret_basic`. Configure these discovery scopes as required:

- `account-settings.read`
- `memberships.read`
- `user-details.read`
- `zone.read`

Configure these mutation scopes as optional so the installer requests only the
set needed by each reviewed phase:

- `access-acct.write`
- `access.write`
- `dns.write`
- `mcp-portals.write`
- `workers-routes.read`
- `workers-scripts.write`

Cloudflare documents the account-owned client in
[Create your OAuth client](https://developers.cloudflare.com/fundamentals/oauth/create-an-oauth-client/).

Create the following target JSON outside the repository, replacing every
placeholder with the exact selected value:

```json
{
  "schemaVersion": 1,
  "kind": "ankka-gateway-deploy-isolated-target",
  "accountId": "<32-lowercase-hex-account-id>",
  "hostname": "<isolated-hostname>",
  "oauthClientId": "<32-lowercase-hex-oauth-client-id>",
  "workerName": "ankka-gateway-deploy-isolated-<suffix>"
}
```

The generator rejects the public installer hostname, public client identifier,
wrong account, extra fields, unsafe names, and origin mismatches.

Before deploying the hostname, prepare the purpose-built private operator gate.
It creates one whole-host Access Allow application for the exact operator
emails and three narrower Bypass applications only for the OAuth callback and
the signed `canary` and `stable` release descriptors. First review the
content-free plan:

```sh
node apps/installer/scripts/edge-gate/apply-isolated-access.mjs \
  --target <outside-repository-dir>/isolated-target.json \
  --email <operator-email> \
  --session 8h \
  --dry-run
```

Then pipe a least-privilege, customer-owned Cloudflare token directly from an
approved secret tool. The token needs only the exact account-level Access
application and identity-provider reads/writes used by this one operation:

```sh
<approved-cloudflare-token-source> | \
  node apps/installer/scripts/edge-gate/apply-isolated-access.mjs \
    --target <outside-repository-dir>/isolated-target.json \
    --email <operator-email> \
    --session 8h \
    --api-token-stdin
```

The tool reads the token only from bounded standard input, creates missing
applications without replacing drifted ones, and reports counts rather than
provider IDs or identities. Operator emails are necessarily explicit inputs;
keep the invocation and output in the private qualification record.

## 2. Build and sign release A

Generate a new Ed25519 key with an approved local tool. Keep the 32-byte raw
private seed encrypted and outside the repository, CI, Cloudflare, GitHub,
application storage, logs, shell history, and support output. Derive its raw
32-byte public key and encode that public value as unpadded base64url. The
signer reads the raw private seed only from standard input and never from an
argument, environment variable, or file option.

Build the first candidate with a valid semantic release such as
`gateway-v0.1.0`. The output directory must not already exist:

```sh
node apps/installer/scripts/build-gateway-release-candidate.mjs \
  --source . \
  --source-commit <40-hex-public-commit> \
  --control-plane-origin https://<isolated-hostname> \
  --release gateway-v0.1.0 \
  --out <outside-repository-dir>/candidate-a
```

Pipe the raw seed from the approved secret tool directly into the signer:

```sh
<approved-secret-tool-producing-32-raw-bytes> | \
  node apps/installer/scripts/sign-gateway-release.mjs \
    --release-dir <outside-repository-dir>/candidate-a \
    --release gateway-v0.1.0 \
    --channel canary \
    --key-id dogfood-dev-1 \
    --public-key <raw-ed25519-public-key-base64url> \
    --private-key-stdin \
    --write-publish-directory \
    --out <outside-repository-dir>/publish-a
```

Do not replace the placeholder secret command with `echo`, a command-line
argument, or an environment variable. Run both scripts with `--help` if the
checked-out version differs from this document.

## 3. Publish release A create-only

Create the dedicated empty R2 bucket in the exact customer account. Generate a
single-release local publisher:

```sh
node apps/installer/scripts/generate-r2-publication-worker.mjs \
  --publish-dir <outside-repository-dir>/publish-a \
  --account-id <32-lowercase-hex-account-id> \
  --bucket <dedicated-r2-bucket> \
  --public-key <raw-ed25519-public-key-base64url> \
  --out <outside-repository-dir>/publisher-a
```

Inspect `INVOCATION.txt` in that generated directory. It starts the
repository-pinned Wrangler locally with one explicitly remote R2 binding and
gives one body-free loopback `POST`. Run it once, save the response directly as
`publication-a.json` outside the repository, stop Wrangler immediately, and
remove the temporary publisher directory. The operator verifies the signed
tree again and fails if any object exists under the release prefix; it has no
delete or overwrite capability.

Do not publish with a generic `r2 object put`, copy the prefix, or retry after
an ambiguous response. Inspect the exact bucket state first. An unknown result
is a recovery condition, not permission to overwrite.

Create an exact, secret-free pin outside the repository from the signed object
plan and successful publication receipt:

```json
{
  "schemaVersion": 1,
  "channel": "canary",
  "controlPlaneOrigin": "https://<isolated-hostname>",
  "release": "gateway-v0.1.0",
  "keyId": "dogfood-dev-1",
  "publicKey": "<raw-ed25519-public-key-base64url>",
  "artifactSha256": "<64-lowercase-hex-artifact-digest>"
}
```

Every pin value must exactly match `publication-a.json`; do not transcribe a
digest from console output when the receipt is available.

## 4. Generate and deploy the isolated installer

Generate a new self-contained directory and then independently validate it:

```sh
node apps/installer/scripts/generate-reviewed-isolated-canary.mjs \
  --pin <outside-repository-dir>/pin-a.json \
  --publication-result <outside-repository-dir>/publication-a.json \
  --isolated-target <outside-repository-dir>/isolated-target.json \
  --output-dir <outside-repository-dir>/installer-a

node apps/installer/scripts/generate-reviewed-isolated-canary.mjs \
  --validate-output-dir <outside-repository-dir>/installer-a
```

Review `reviewed-canary-record.json`, both bundled modules, and both Wrangler
files. From the generated directory, use the exact Wrangler executable pinned
in the clean checkout to run a dry run against `wrangler.canary.toml`.

Supply these three values through a non-echoing Cloudflare Worker-secret flow,
never through Wrangler configuration or command arguments:

- `CLOUDFLARE_OAUTH_CLIENT_SECRET`
- `DEPLOY_SESSION_ENCRYPTION_KEY`
- `BOOTSTRAP_NONCE_DERIVATION_KEY`

The last two are distinct, independently random 32-byte values encoded as
canonical base64 or unpadded base64url. Do not reuse the release signing key.
Deploy only `wrangler.canary.toml` with the pinned Wrangler. Verify the exact
custom hostname, Worker, Durable Object migration, R2 binding, disabled
observability, and customer-owned installer analytics dataset in Cloudflare
before opening the installer.

Finally prove both the complete Access configuration and anonymous edge
behavior. This must report `status: "verified"` and `runtimeMode: "active"`;
the whole host must redirect to Access while only the callback and signed
release descriptors bypass it:

```sh
<approved-cloudflare-read-token-source> | \
  node apps/installer/scripts/edge-gate/verify-isolated-access.mjs \
    --target <outside-repository-dir>/isolated-target.json \
    --runtime active \
    --api-token-stdin
```

Do not open the installer or mint a deployment session until this proof passes.

## 5. Install and exercise sources

Open the exact isolated hostname, complete Cloudflare discovery and consent,
review the deterministic plan, and install an empty gateway. Record the MCP and
management URLs privately. Confirm the management status reports the same
`controlPlaneOrigin` used above.

From the customer dashboard:

1. Before the first source install, make the live source catalogue an exact
   gate. Place
   the reviewed config outside this repository, acquire a least-privilege
   standards-compliant OAuth access token through an approved customer-owned
   client, and pipe it directly to the verifier:

   ```sh
   <approved-oauth-token-source> | \
     node tools/verify-live-source-catalogue.mjs \
       --config <outside-repository-dir>/gateway.config.json \
       --source bls-read \
       --oauth-token-stdin
   ```

   Continue only when it reports `status: "verified"`, equal exact counts, and
   equal digests. Any live `tools/list` addition, omission, duplicate,
   pagination failure, redirect, or mismatch blocks installation. The tool
   never prints the endpoint, token, or names and accepts OAuth authority only
   from bounded standard input.
2. Discover each source and inspect its catalogue. The dashboard's discovery
   challenge must identify standards-compliant OAuth for `bls-read`; a public
   or generic bearer/custom-header workaround is a stop condition.
3. Save an exact read-only allowlist and apply it with a fresh operation-scoped
   Cloudflare grant.
4. For a large generated source, use the deterministic OpenAPI workflow in
   [Spec-driven OpenAPI allowlists](../../docs/OPENAPI_ALLOWLISTS.md) and the
   limits in [Large sources and Code Mode](../../docs/LARGE_SOURCES_AND_CODE_MODE.md).
5. Only if testing optional multi-group source visibility, freshly enumerate
   Access groups and follow
   [Per-source Cloudflare Access groups](../../docs/SOURCE_ACCESS_GROUPS.md).
6. Connect a test identity to the Portal and prove an allowed read succeeds,
   an unlisted operation is absent, and the upstream independently rejects
   writes.

For `bls-read`, keep the service token only in that source Worker's secret
binding for its private origin hop. That is separate from the required
standards-compliant per-user OAuth at MCP ingress. Do not select gateway
`bearer`, `headers`, or `none` configuration merely because the offline schema
can describe it: the current dashboard runtime accepts standards-compliant
per-user OAuth for this protected source and must not receive either credential.

## 6. Publish release B and drill update and rollback

Repeat sections 2 and 3 from the same clean public commit or a second reviewed
clean public commit, using:

- release `gateway-v0.1.1`;
- the same exact control-plane origin;
- the same `canary` channel;
- the same development key and key identifier; and
- the same account and R2 bucket.

Use new, non-existing `candidate-b`, `publish-b`, and `publisher-b` directories.
The create-only prefix must be new. Produce `publication-b.json` and `pin-b.json`,
then generate a new `installer-b` directory against the same isolated target.
Validate it and redeploy `wrangler.canary.toml` to the same isolated Worker.

In the installed gateway dashboard:

1. Check for an update. Release B must be discovered anonymously from the exact
   compiled origin.
2. Review and apply B with a fresh Cloudflare grant.
3. Confirm the candidate probe and activation complete and source, Portal,
   Access, DNS, credentials, and Durable Object state remain unchanged.
4. Request rollback with another fresh grant and confirm the retained A Worker
   version becomes active.
5. Confirm the documented caveat: Worker rollback does not roll back Durable
   Object data or migrations.

Do not use a direct Wrangler upload to the customer Worker as a substitute for
the signed update or rollback workflow.

## 7. Exercise recovery and receipt-bound removal

Use only the dashboard's reviewed actions. In the disposable drill, interrupt
one source apply or lifecycle action after intent is durable but before a final
result is known. Reopen the dashboard, preserve its recovery record, freshly
read provider state, and follow the offered resume or reconcile action. Never
delete a pending journal to make the UI appear healthy.

Exercise both returning paths while the isolated installer is still deployed:

- return an applied source-action receipt to the exact signed origin; then
- initiate gateway removal from the customer dashboard, follow the
  same-origin receipt handoff, review the teardown plan, and authorize it with
  a fresh grant.

Removal must use the checksum-valid installation receipt and fresh provider
readback. It must stop on drift, collisions, missing authority, or ambiguous
state and remove only receipt-owned gateway resources in reverse dependency
order. A hostname, Worker name, or provider ID alone is never deletion
authority.

## 8. Capture evidence without customer data

Record only a private, customer-owned qualification checklist:

- exact source commit and release A/B identifiers;
- pass/fail for install, source apply, Code Mode, update, rollback, recovery,
  returning handoff, and removal;
- fixed application error codes and phase timings; and
- confirmation that the expected Cloudflare resources and customer-owned logs
  were inspected.

Do not copy account or resource IDs, hostnames, user emails, access-group IDs,
OAuth material, source credentials, request arguments, raw results, provider
responses, cookies, or free-form exceptions into this repository or a public
issue. Report security findings through `SECURITY.md`.

## 9. Clean up the isolated control plane

Keep the isolated installer available until receipt-bound gateway removal and
any recovery work are complete. Then clean up using exact customer inventory:

1. Deploy `wrangler.rollback.toml` to the exact isolated Worker and verify the
   disabled shell with `verify-isolated-access.mjs --runtime disabled`, again
   piping the read token only through standard input.
2. From a fresh complete Access-application inventory, remove exactly the four
   canary applications for the target: the whole-host operator Allow app plus
   the OAuth callback and two release-channel Bypass apps. The checked-in apply
   tool intentionally has no deletion capability; use the customer console or
   a separately reviewed exact-ID operation and re-read the inventory.
3. Delete the exact isolated Worker and its custom-domain attachment. Review
   the corresponding Durable Object namespace/storage and remove it only after
   confirming no recovery state is needed.
4. Inventory the dedicated R2 bucket. Delete it only after both release
   prefixes are understood and no installed gateway or recovery path can use
   them.
5. Delete the exact private OAuth client and its redirect registration.
6. Review and remove any exact customer-created Analytics Engine dataset,
   hostname DNS/custom-domain state, and Cloudflare certificate that remain.
   Certificate cleanup is outside the installer grant.
7. Destroy the local development seed and its backup according to the
   customer's key-handling policy, then remove external candidates, pins,
   receipts, target files, generated installer directories, and Wrangler state.

Do not use broad, wildcard, prefix-only, or name-only deletion. Unrelated
Cloudflare resources and upstream systems are outside the drill.

## Completion criteria

The dogfood qualification is complete only when both create-only releases and
all lifecycle checks above have evidence, receipt-bound gateway removal has
completed or has an explicitly retained recovery record, and exact cleanup is
verified. Until a maintainer publishes that live evidence and a support policy,
the result remains a private development qualification—not a supported Ankka
release.

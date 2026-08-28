# Reviewed isolated private-canary runbook

This is an operator gate, not a deploy script. Generation and validation are
offline. The checked-in `wrangler.toml` continues to use `src/index.ts`, and
`src/reviewed-activation.ts` remains exact `false`/`null`. Nothing here
activates or routes that checked-in runtime; it has no production route. The
first isolated live operation is explicitly marked in section 7 and requires
separate approval.

This optional private-canary runbook is not the current public-cutover path.
Under [`docs/PUBLIC_CUTOVER.md`](../../docs/PUBLIC_CUTOVER.md),
`deploy.ankka.ai` stays without an Ankka Access application and on the disabled
shell until public activation; rollback returns it to that same posture without
creating Access. Sections 5, 7, and the private-canary arm of section 8 may be
used only for an explicitly isolated non-live hostname/account. The checked-in
generator preserves the exact `deploy.ankka.ai` defaults for later public
activation, but its `--isolated-target` mode and the separate isolated Access
tools bind this proof to a different hostname, Worker, and publication account.
The retired live Access mutator cannot recreate Access on the public host.

The original implementation, tests, generated-payload review, and runbook were
prepared offline. A later reviewed private canary exercised OAuth, signing,
publication, hosted Worker deployment, and a customer-owned installation. That
run is evidence, not standing authority: the checked-in runtime is still
fail-closed, the first updater promotion gate in section 9 is still open, and a
fresh run must satisfy every gate below.

The live OAuth client is already permanently **Public**, verified for
`deploy.ankka.ai`, and bound to the live callback. Never try to make it Private
again or move its callback for an isolated proof. An isolated run requires a
separate reviewed isolated-only client that stays Private and is compiled into
the schema-2 target-bound artifact. Without that separate client, stop before
isolated activation.

## 0. Exact release candidate

Build the signer input from the exact public commit under review (offline,
secret-free; see `scripts/README.md`):

```sh
node scripts/build-gateway-release-candidate.mjs \
  --source ../.. \
  --source-commit "$(git -C ../.. rev-parse HEAD)" \
  --release gateway-vX.Y.Z \
  --out /private/tmp/ankka-gateway-release-candidate-gateway-vX.Y.Z
```

Record the printed `artifact.treeSha256`, `manifestSha256`, and component
digests in the review. That directory is the `--release-dir` for
`sign-gateway-release.mjs`; signing remains a separately approved step.

After that approval, derive the public verification key without materializing
the retained private seed:

```sh
security find-generic-password \
  -s 'ankka-mcp-gateway-canary-signing-seed-v1' \
  -a '<reviewed key ID>' -w \
  | openssl base64 -d -A \
  | node scripts/derive-ed25519-public-key.mjs --private-key-stdin
```

The command prints only the public-key record. Read the Keychain item a second
time and pipe the decoded 32 raw bytes directly to the signer's
`--private-key-stdin`; never copy the seed through a file, argv, an environment
variable, command substitution, or `tee`.

## 1. Exact secret-free inputs

Use the one-shot publication runner's successful response without editing it.
The receipt must contain exactly these 12 fields:

```json
{
  "accountId": "<exact 32-character lowercase-hex Cloudflare account ID>",
  "artifactSha256": "<64 lowercase hex>",
  "bucketName": "<exact private R2 bucket>",
  "channel": "canary",
  "keyId": "<reviewed signing key ID>",
  "objectPlanSha256": "<64 lowercase hex>",
  "prefix": "ankka-mcp-gateway/releases/canary/gateway-vX.Y.Z/",
  "publicKey": "<43-character raw Ed25519 base64url public key>",
  "release": "gateway-vX.Y.Z",
  "releaseEnvelopeSha256": "<64 lowercase hex>",
  "schemaVersion": 1,
  "status": "published"
}
```

Save that exact response as `publication-receipt.json`. Separately create the
secret-free runtime pin with exactly:

```json
{
  "schemaVersion": 1,
  "channel": "canary",
  "release": "gateway-vX.Y.Z",
  "keyId": "<same key ID>",
  "publicKey": "<same public key>",
  "artifactSha256": "<same artifact digest>"
}
```

The public key is verification material, not a private signing key. The
generator rejects extra fields, requires all pin identity fields to match the
publication receipt, and accepts only a lowercase 32-hex `accountId`. The
receipt's exact account, bucket, plan digest, and envelope digest are retained
in the canonical generation record.

### Public GitHub Release mirror

After the create-only R2 publication succeeds, prepare and validate the public
GitHub Release mirror using `scripts/publish-github-release.mjs` as documented
in `scripts/README.md`. The mirror must target the manifest's exact full source
commit and use the gateway release ID as its tag. A canary must be a prerelease
with `Latest` false. Repository-level immutable Releases must be enabled before
the live publish so the new tag and assets become immutable when the draft is
published.

Generate the deterministic, production-only CycloneDX SBOM from a clean
checkout at the exact source commit and lockfile, then review the local output
before the separate live publish. It may contain only the signed release
envelope, sanitized public verification record, source-bound SBOM, shipped
project and production-dependency license texts, release notes, and canonical
GitHub plan. It must not contain or mention the Cloudflare account ID, bucket
name, publication receipt, credential, or private signing material. GitHub
publication does not activate the hosted installer and does
not replace the private R2 channel; it makes the already-published release and
its public verification evidence discoverable from the repository.

## 2. Offline create-only generation

Run from `apps/installer`. Use a new output directory outside the
repository; it must not exist. Do not run `npm install` between publication,
generation, dry-run, and deployment review.

Create a private target file outside the repository with exactly these fields:

```json
{
  "accountId": "<same lowercase 32-hex account as the publication receipt>",
  "hostname": "<exact non-live canary hostname>",
  "kind": "ankka-gateway-deploy-isolated-target",
  "oauthClientId": "<separate isolated-only 32-hex OAuth client ID>",
  "schemaVersion": 1,
  "workerName": "ankka-gateway-deploy-isolated-<reviewed-suffix>"
}
```

The hostname must be a lowercase, exact subdomain with no scheme, path, port,
or wildcard. The parser rejects `deploy.ankka.ai`, Cloudflare development
hostnames, the production Worker name, unknown fields, and any account that
does not equal the create-only publication receipt. It also rejects the live
OAuth client ID, so isolated generation cannot silently move or reuse its
permanent callback. Keep this locator and the generated output outside the
public repository.

```sh
CANARY_DIR=/private/tmp/ankka-gateway-reviewed-canary-gateway-vX.Y.Z
node scripts/generate-reviewed-isolated-canary.mjs \
  --pin /absolute/path/release-pin.json \
  --publication-result /absolute/path/publication-receipt.json \
  --isolated-target /absolute/path/isolated-canary-target.json \
  --output-dir "$CANARY_DIR"
node scripts/generate-reviewed-isolated-canary.mjs --validate-output-dir "$CANARY_DIR"
```

The output is create-only and contains exactly:

- `reviewed-canary-worker.mjs`: a self-contained ESM Worker module that exports
  `GatewayDeploySession` and instantiates the reviewed runtime with the exact
  compile-time pin and exact isolated public origin. Every origin check, OAuth
  callback URL, redirect, and `__Host-` cookie flow therefore stays on the
  isolated hostname. It has no source-relative imports and contains no live
  installer origin.
- `reviewed-rollback-worker.mjs`: a self-contained ESM Worker module exporting
  the same Durable Object class but instantiating exact reviewed
  `{ enabled: false, pin: null }` behavior under that same isolated origin.
- `wrangler.canary.toml` and `wrangler.rollback.toml`: account-pinned,
  no-bundle configurations pointing only at those materialized modules.
- `reviewed-canary-record.json`: canonical secret-free evidence, the exact
  isolated deployment target, hashes and sizes for every generated artifact,
  entry-source hashes, every bundled source input, and installed toolchain
  provenance.

Generation snapshots the relevant TypeScript source into memory and bundles
from that snapshot with installed esbuild `0.28.1`. The record binds the exact
package lock, esbuild package/runtime/launcher/platform-native binary, and
Wrangler `4.123.0` package/CLI/runtime/schema bytes. Validation rehashes the
already materialized modules and toolchain; it does not rebuild from mutable
repository source. A different OS/architecture, dependency install, or tool
mutation makes validation fail closed. Regenerate into another new directory
after review; never edit an output file or its record.

## 3. Exact generated configuration contract

Both TOMLs have the exact receipt `accountId` as top-level `account_id` and:

- the exact isolated `ankka-gateway-deploy-isolated-*` Worker name.
- compatibility date `2026-08-14`.
- `no_bundle = true` and `find_additional_modules = false`.
- `workers_dev = false`, `preview_urls = false`, and `send_metrics = false`.
- the exact isolated custom domain only, never `deploy.ankka.ai`.
- `GATEWAY_DEPLOY_SESSION` -> `GatewayDeploySession`, with SQLite migration
  tag `v1` and `new_sqlite_classes = ["GatewayDeploySession"]`.
- observability, application logs, invocation logs, log persistence, traces,
  and trace persistence disabled, with sampling rates zero.

The active TOML additionally has:

- main `reviewed-canary-worker.mjs`.
- non-secret `CLOUDFLARE_OAUTH_CLIENT_ID` equal to the exact separate
  isolated-only client in the schema-2 target, never the live client ID.
- `ANONYMOUS_SESSION_RATE_LIMIT`, namespace `588230349`, at 6 requests per
  60 seconds.
- `SESSION_READ_RATE_LIMIT`, namespace `913742685`, at 120 requests per
  60 seconds.
- `SESSION_MUTATION_RATE_LIMIT`, namespace `74228090`, at 30 requests per
  60 seconds.
- `GATEWAY_RELEASE_BUCKET` bound to the exact published `bucketName`.

Both materialized Worker modules compile `PUBLIC_ORIGIN` to the exact isolated
HTTPS hostname in the schema-2 target; the OAuth callback is therefore
`https://<isolated-canary-host>/oauth/callback`. Their provenance records that
origin, and validation rejects an isolated module that retains the live origin.

The rollback TOML uses main `reviewed-rollback-worker.mjs` and has no R2
binding, OAuth client variable, or rate-limit binding because its fixed shell
cannot create sessions or execute mutations. Neither config contains a secret
value.

Wrangler `4.123.0` has `binding` and `bucket_name` for R2, but its locally
validated schema has no `read_only` option. The runtime uses only R2 `get` and
`list`; the configuration cannot independently enforce read-only authority.
If code-level read-only access plus the private create-only release bucket is
not accepted, stop. Do not invent or claim a provider-enforced `read_only`
binding.

Every dry-run, secret, deploy, and rollback command below passes one of these
TOMLs with `--config`; that top-level `account_id` is the account selector.
Wrangler `secret put` has no separate account-ID flag. Before proceeding,
remove an ambient selector and verify both configs contain the receipt account:

```sh
unset CLOUDFLARE_ACCOUNT_ID
ACCOUNT_ID="$(jq -er '.accountId | select(test("^[a-f0-9]{32}$"))' \
  /absolute/path/publication-receipt.json)"
rg -x "account_id = \"$ACCOUNT_ID\"" "$CANARY_DIR/wrangler.canary.toml"
rg -x "account_id = \"$ACCOUNT_ID\"" "$CANARY_DIR/wrangler.rollback.toml"
jq -e --arg account "$ACCOUNT_ID" \
  '.publication.accountId == $account' \
  "$CANARY_DIR/reviewed-canary-record.json"
```

Each `rg` must return exactly one line and `jq` must return true. An auth profile/token without authority
for this pinned account must fail; never switch the generated account to make
an ambient credential work.

Omitting `--isolated-target` deliberately preserves the separately reviewed
live artifact contract: Worker `ankka-gateway-deploy`, custom domain
`deploy.ankka.ai`, and the schema-1 generation record. Do not omit the flag for
sections 5–9. The isolated record uses schema 2 so validation cannot silently
reinterpret it as the live configuration.

No local server is needed. Do not run `wrangler dev`, bind a port, or use the
reserved ports 3000, 3333, 5173, or 8080.

## 4. OAuth-client credential and visibility boundaries

The live client is already permanently **Public**, its
`client_uri_verification.status` is `verified`, and its callback is exactly
`https://deploy.ankka.ai/oauth/callback`. Public promotion is irreversible.
Do not try to make that client Private, remove or replace its live callback, or
add an isolated callback merely to complete this proof.

The only reviewed safe alternative for the optional isolated proof is a
separate isolated-only OAuth client. Its public client ID is an exact field in
`isolated-canary-target.json` and is compiled into the schema-2 Worker; the
target parser rejects the live client ID. This tooling does not create or edit
an OAuth client. Before generation, privately prove the isolated client:

- is **Private** and belongs to the Ankka account whose members run the proof;
- has exactly one callback, `https://<isolated-canary-host>/oauth/callback`;
- is not used by `deploy.ankka.ai` or any customer production runtime; and
- grants exactly these ten scope IDs, with no missing or extra scope:

  1. `access-acct.write`
  2. `access.write`
  3. `account-settings.read`
  4. `dns.write`
  5. `mcp-portals.write`
  6. `memberships.read`
  7. `user-details.read`
  8. `workers-routes.read`
  9. `workers-scripts.write`
  10. `zone.read`

The consent page must show the expected account and exactly those ten
permissions. Cancel authorization on any difference.

Verify by scope **id**, never by the label beside the checkbox. Cloudflare
shows the same label for permissions that differ only in scope: under
Cloudflare One / Zero Trust, "Access: Apps and Policies Write" is the
zone-scoped `zone-access.write` in one row and the account-scoped
`access.write` in another, and the plain "Access" row is a third. Checking by
label on 2026-08-24 removed the required `access.write` while leaving the
unwanted `zone-access.write`, which still totals ten and still fails: the
installer asserts the granted set equals the exact ten and rejects a missing
scope as hard as an extra one.

Immediately before the private canary, feed the short-lived API token through
bounded stdin and require a verified result from the live catalogue:

```sh
security find-generic-password -s '<short-lived-canary-token-service>' -w \
  | node scripts/verify-oauth-scope-catalogue.mjs --api-token-stdin
```

This is a read-only catalogue check, not proof that the OAuth client was
configured with those scopes; the client inspection and consent checks above
remain mandatory.

Before any isolated secret write or active deployment, prove that the target's
isolated client ID and its separately named Keychain secret are one matching
client. This zero-authority request uses an intentionally invalid authorization
code: a matching pair produces `invalid_grant`; `invalid_client` or an
inconclusive response fails closed. The secret flows only through bounded
stdin:

```sh
set +x
security find-generic-password \
  -s '<isolated-oauth-client-secret-service>' -w \
  | node scripts/verify-oauth-client-pair.mjs \
      --client-id '<exact isolated target OAuth client ID>' \
      --client-secret-stdin
```

Require `status: "verified"`. Run it again after any isolated-secret rotation
and before updating the isolated Worker secret. Keep the isolated client
Private through teardown; do not promote it or repurpose it for the live host.
Revoke every canary grant after use. The exact-path callback Access Bypass lets
Cloudflare deliver a valid redirect, while the encrypted callback cookie,
state/verifier hashes, PKCE, and one-time Durable Object consume reject a
request without the matching isolated session. Access still protects every
other isolated installer path.

The live client remains a separate public-cutover gate. Before live activation,
repeat the same client-pair preflight for the existing live client and its live
Keychain service, recheck its exact ten scopes, Public visibility, verified
domain, and unchanged live callback. Isolated-client evidence does not satisfy
or weaken any of those live checks.

## 5. Optional isolated edge and callback-privacy gate

Complete and verify every item here only for a separately reviewed isolated
private-canary hostname/account before enabling that canary. Record rule IDs,
active versions, API/dashboard evidence, and verification time. The generator
deliberately does not create or mutate WAF, rate-limit, or Logpush
configuration. This section does not authorize any Access change on
`deploy.ankka.ai` during public cutover.

### Private access control

**Current live-host status 2026-08-27:** the old Access applications are absent
and the exact disabled shell serves `deploy.ankka.ai`. External probes proved
`/health` returns `{"ok":true,"mutationsEnabled":false}` while `/`,
`/api/session`, both release channels, and the OAuth callback return the
fail-closed `503` response. That no-Access disabled posture is now intentional
through public preflight. Do not restore the applications on the live host.

For an optional isolated private canary, the four-application contract below
remains the operator-identity boundary and the Worker-native bindings bound
request cost. Neither control substitutes for the other.

Amended 2026-08-24. This section previously required a Cloudflare IP List
named `ankka_gateway_canary_allowed_ips` and a custom WAF rule blocking every
source outside it. **That control cannot work here and must not be relied on.**
`deploy.ankka.ai` is a Workers Custom Domain, so the hostname points straight
at the Worker and the zone's `http_request_firewall_custom` and
`http_ratelimit` phases never evaluate for it.

The obsolete `scripts/edge-gate/apply.mjs` and `verify.mjs` entrypoints are
retained only as fail-closed migration stubs. They cannot read credentials,
make network calls, or mutate a ruleset. `apply-access.mjs` is likewise a
fail-closed stub, so no checked-in command can create Access on the live host.
`verify-access.mjs` remains read-only live-host evidence and exits nonzero when
the intentionally absent private contract is not enforced.

The evidence, gathered live on 2026-08-24: the reviewed rule was deployed and
enabled with the exact expression above, backed by a populated list, and a
client from a non-allowlisted address still received `200` with a CSRF token,
while the zone recorded no firewall event for the hostname in a window that did
contain managed-WAF events for the apex. A rule that cannot fire is worse than
an absent one, because it reads as protection in an audit.

For an isolated private canary, the optional replacement control is Cloudflare
Access, which does apply to Workers Custom Domains and keys on identity rather
than on an address the operator does not control. Create exactly four
self-hosted applications in that isolated environment, in this order so the
exclusions exist before the protection does:

| Application domain | Decision | Include |
| --- | --- | --- |
| `<isolated-canary-host>/oauth/callback` | Bypass | everyone |
| `<isolated-canary-host>/api/releases/canary` | Bypass | everyone |
| `<isolated-canary-host>/api/releases/stable` | Bypass | everyone |
| `<isolated-canary-host>` | Allow | explicit operator emails |

The callback bypass is mandatory for the same reason the WAF exclusion was:
Cloudflare's OAuth service must reach the private client's redirect URI
unauthenticated. The two release bypasses are mandatory because installed,
customer-owned Workers fetch their fixed signed channel without an Access
identity, cookie, account ID, hostname, or user input. Each exact-path
application matches before the whole-host application. Do not bypass
`/api/releases`, `/api`, or the host: the Worker accepts only `GET` on the two
fixed channel paths. The protected application must never include `everyone` —
that admits anyone who completes an identity-provider login, which for a
private canary is indistinguishable from no protection.

The separately reviewed isolated tooling must preserve the structural and
behavioral contract. Review the offline plan first; it reads neither a token
nor the network and prints only counts:

```sh
node scripts/edge-gate/apply-isolated-access.mjs \
  --target /absolute/path/isolated-canary-target.json \
  --email '<operator identity>' \
  --session 8h \
  --dry-run
```

After separate approval for the four Access creates, pipe a narrowly scoped
token through bounded stdin. The mutator creates the callback and two release
Bypass apps before the whole-host Allow app, resumes only exact prior creates,
rejects wildcard/broader/unknown selectors and drift, and never prints the
target, account, application, identity-provider, or operator identifiers:

```sh
security find-generic-password -s '<isolated-access-write-token-service>' -w \
  | node scripts/edge-gate/apply-isolated-access.mjs \
      --target /absolute/path/isolated-canary-target.json \
      --email '<operator identity>' \
      --session 8h \
      --api-token-stdin
```

The successful apply result includes a final complete paginated read-back of
all four exact applications. Runtime behavior cannot be proved until the custom
domain serves the generated Worker, so run the read-only verifier first in
`disabled` mode after the false/null deployment and again in `active` mode
after activation, at the exact points in section 7. Both modes require the
isolated root and non-state-minting `HEAD /api/session` to redirect to Access.
Disabled mode requires the callback and both release paths to reach the exact
application-level `503 release_unavailable` shell. Active mode requires the
cookie-free callback to reach the exact `400 session_invalid` state rejection;
each release path must return either its application descriptor or the exact
inactive-channel `404`. Record application IDs separately in private operator
evidence if required; the tools deliberately redact them. Neither command
accepts `deploy.ankka.ai` or the production Worker target.

The callback remains protected at the application boundary rather than at the
edge, exactly as before: the encrypted `__Host-ankka_gateway_deploy_oauth`
cookie, exact state and verifier hashes, S256 PKCE, an atomic one-time Durable
Object `/consume`, and confidential-client authentication.

### Rate limits

Zone `http_ratelimit` rules do not execute for this Workers Custom Domain. The
active reviewed Worker therefore uses Cloudflare Workers Rate Limiting
bindings, whose exact configuration is generated into `wrangler.canary.toml`:

| Binding | Covered operation | Threshold |
| --- | --- | ---: |
| `ANONYMOUS_SESSION_RATE_LIMIT` | creation of a session by `GET /api/session` or `GET /api/discovery` when no usable session exists | 6 per 60 seconds |
| `SESSION_READ_RATE_LIMIT` | authenticated `GET /api/session` and `GET /api/discovery` before Durable Object lookup | 120 per 60 seconds |
| `SESSION_MUTATION_RATE_LIMIT` | every `POST`, `PUT`, `PATCH`, or `DELETE` below `/api/` | 30 per 60 seconds |

For anonymous creation, the Worker reads Cloudflare's edge-supplied connecting
address only long enough to compute an HMAC-SHA-256 key with the deployment
encryption secret and the fixed `anonymous-session-v1` purpose. Authenticated
session polling derives a separate `session-read-v1` HMAC from the opaque
session ID before any Durable Object lookup. Mutations derive a distinct
`session-mutation-v1` HMAC from that ID, or an `anonymous-mutation-v1` client
key for a flow that has not established a session. Raw addresses and session
IDs are never sent to a binding, logged, or stored as rate-limit evidence.
Purpose separation prevents the binding keys from being correlated across
those uses.

Reviewed sessions use the existing 43-character cookie schema as a
self-authenticating token: 16 random bytes plus a 16-byte truncated HMAC tag.
The Worker verifies that tag before resolving the supplied Durable Object name.
A format-valid but unauthenticated cookie follows the anonymous-creation path:
the anonymous limiter runs first, exhaustion returns `rate_limited` before any
Durable Object lookup, and an allowed request mints and overwrites the cookie
with a freshly authenticated session. Thus random cookie spray cannot
instantiate empty objects under attacker-supplied names, while activating this
contract safely rotates sessions minted by an older private canary. Do not
activate while an earlier canary OAuth callback is in flight.

The active runtime fails closed when the required binding, connecting address,
deployment key, or binding result is absent or invalid, and when the binding
call fails. Exhaustion returns exact HTTP `429` JSON
`{"code":"rate_limited"}`. An unavailable control returns exact HTTP `503`
JSON `{"code":"abuse_controls_unavailable"}`. Existing valid session reads
consume the read limit but not the mutation limit. `GET /api/management/context`
validates its one-time OAuth handoff cookie without resolving a deploy-session
Durable Object, so it does not consume the session-read limit. `GET /health`,
the two exact signed release channels, signed static assets, and
`GET /oauth/callback` do not call any limiter. The callback remains protected
by its one-time cryptographic state contract below.

Workers Rate Limiting counters are local to a Cloudflare location and
eventually consistent. They are an abuse-cost bound, not exact accounting and
not authorization. The fixed namespace IDs in section 3 are configuration
identities, not Cloudflare resource locators. The generator validates the
pinned Wrangler schema for `name`, `namespace_id`, and the exact `simple`
limit/period contract; output validation rejects any edited TOML.

Before activating an isolated generated canary, leave these gates unchecked
until they are actually proved:

- [ ] Validate all three generated bindings and confirm the rollback config has
  no rate-limit binding.
- [ ] With one valid disposable session, sustain combined `GET /api/session`
  and `GET /api/discovery` polling until the shared per-session allowance
  produces the fixed 429 before another Durable Object lookup.
- [ ] In an isolated Access-authenticated disposable browser session, sustain
  same-session mutations until the configured allowance produces the fixed
  429 without a provider write; record Cloudflare's location-local,
  eventually-consistent result rather than asserting an exact request ordinal.
- [ ] From a clean client identity, prove anonymous session creation reaches
  the fixed 429 after the configured allowance, then let every disposable
  session expire and verify its Durable Object alarm removed the state.
- [ ] Deploy a deliberately incomplete reviewed config to an isolated test
  name and prove session creation, valid-session reads, and mutations return the
  fixed 503 when their respective binding is missing; never replace the live
  fail-closed rollback with that fixture.

### Callback exclusion from security-event rules

Inventory all existing and proposed custom WAF, managed-WAF override/skip,
firewall, bot, and rate-limit rules that apply to `deploy.ankka.ai`. The exact
path `/oauth/callback` must be excluded from every rule that can emit a WAF or
rate-limit Security Event. Do not add a callback rate limit. If an account/zone
feature cannot express or prove that exclusion, stop the canary; do not invent
a rule shape.

For an optional isolated private canary, its Access denial is itself a logged
event carrying the requested URL, so the exact callback and release Bypass
applications remain part of that isolated inventory. The live public host has
no such applications: its preflight and post-activation verifier instead fail
if any Access selector covers the host or redirects the callback or release
channels.

The public callback is instead protected at the application boundary by the
exact encrypted `__Host-ankka_gateway_deploy_oauth` `HttpOnly; Secure;
SameSite=Lax` cookie, exact state and verifier hashes, atomic one-time Durable
Object `/consume`, S256 PKCE, and confidential-client authentication with the
client secret. Invalid, expired, mismatched, or replayed state is rejected.
The authorization code is never written to application storage: after the
one-time consume and signed-plan rebind, it is exchanged in the same awaited
callback request with the PKCE verifier and client secret. The callback first
streams the signature-verified result shell and fixed heartbeats, then owns the
ephemeral grant in memory until the reviewed executor revokes and discards it.
The stream, Durable Object state, and public progress projection never contain
the authorization code or grant.

### Logpush and residual Cloudflare metadata

Before live approval, enumerate enabled zone-level and account-level Logpush
jobs in the dashboard or API. Record the job IDs/datasets/filters/status and
prove that no HTTP request, firewall/security event, Workers trace, or other
enabled job has a destination or filter that captures `deploy.ankka.ai`. A
broad job that cannot be narrowed to exclude this hostname is a stop condition.

The generated Worker keeps Ankka application logging, invocation logs, traces,
and log persistence off, and the prerequisite above keeps Ankka-configured
Logpush from exporting the hostname. This is **not platform-level zero
logging**. Cloudflare necessarily terminates and processes the callback URL,
including its query, and Cloudflare Security Analytics/control-plane systems
may sample or retain callback URI metadata even though no WAF/rate-limit event
is created. The operator must explicitly accept this residual callback-metadata
risk in the private canary evidence before live approval. Without that written
acceptance, stop.

Cloudflare may inject `NEL` and `Report-To` response headers independently of
Worker observability. The reviewed owner decision is to keep Network Error
Logging enabled for the Ankka-owned hosted installer. Before public exposure:

- [ ] retain private evidence of the exact live policy on the installer root,
  callback error, and both release-channel responses;
- [ ] record the report destination owner, documented report fields and
  retention, and explicit acceptance of the residual request/callback metadata;
  and
- [ ] confirm the application source itself does not set either header.

Do not commit live header values when they contain a report token or provider
identifier. The public verifier intentionally permits these Cloudflare-injected
headers; their presence is neither a pass nor a failure for application
reachability. This hosted platform policy does not authorize telemetry from a
customer-deployed gateway. The signed customer release contract keeps metrics,
dependency instrumentation, and observability disabled for primary, cleanup,
and retirement Workers; direct upload and read-back require Logpush off and no
tail consumers; payload tests reject Ankka analytics beacons and application-set
`NEL`/`Report-To` headers.

The active reviewed hosted build also writes the default product funnel defined
in [`docs/HOSTED_INSTALLER_ANALYTICS.md`](../../docs/HOSTED_INSTALLER_ANALYTICS.md)
to `ankka_installer_funnel_v1`. This is separate from NEL and from disabled
Worker logs/traces.

- [ ] Verify `wrangler.canary.toml` contains exactly one
  `HOSTED_INSTALLER_ANALYTICS` Analytics Engine binding and that its public
  release/channel vars equal the embedded signed pin.
- [ ] Verify `wrangler.rollback.toml` contains no analytics binding or label.
- [ ] Query a bounded live interval and retain only a secret-free result proving
  every row matches the exact event/outcome/flow allowlists and contains no
  additional dimension. Weight counts with `_sample_interval`.
- [ ] Prove a missing or throwing analytics binding does not change the HTTP
  response, provider action, compensation, cleanup, or stored result.

Analytics rows are directional milestones, not unique people or billing data.
Do not join timestamps to OAuth, support, or infrastructure records to
reconstruct an individual journey.

Official references for the reviewed edge semantics:

- [Access application paths and specific-path precedence](https://developers.cloudflare.com/cloudflare-one/access-controls/policies/app-paths/)
- [Access application create API](https://developers.cloudflare.com/api/resources/zero_trust/subresources/access/subresources/applications/methods/create/)
- [IP allowlist custom-rule pattern](https://developers.cloudflare.com/waf/custom-rules/use-cases/allow-traffic-from-ips-in-allowlist/)
- [Workers Rate Limiting binding](https://developers.cloudflare.com/workers/runtime-apis/bindings/rate-limit/)

## 6. Offline no-rebundle gates

Use the exact installed Wrangler recorded by the generator, new dry-run
directories, and the generated directory as `--cwd` so no repository `.env` or
source is discovered:

```sh
WRANGLER_JS="$PWD/node_modules/wrangler/bin/wrangler.js"
test "$(node "$WRANGLER_JS" --version)" = "4.123.0"
ROLLBACK_DRY_RUN_DIR="$(mktemp -d)"
CANARY_DRY_RUN_DIR="$(mktemp -d)"

node "$WRANGLER_JS" deploy --dry-run \
  --cwd "$CANARY_DIR" \
  --config "$CANARY_DIR/wrangler.rollback.toml" \
  --outdir "$ROLLBACK_DRY_RUN_DIR"
cmp -s \
  "$CANARY_DIR/reviewed-rollback-worker.mjs" \
  "$ROLLBACK_DRY_RUN_DIR/reviewed-rollback-worker.mjs"

node "$WRANGLER_JS" deploy --dry-run \
  --cwd "$CANARY_DIR" \
  --config "$CANARY_DIR/wrangler.canary.toml" \
  --outdir "$CANARY_DRY_RUN_DIR"
cmp -s \
  "$CANARY_DIR/reviewed-canary-worker.mjs" \
  "$CANARY_DRY_RUN_DIR/reviewed-canary-worker.mjs"

node scripts/generate-reviewed-isolated-canary.mjs --validate-output-dir "$CANARY_DIR"
```

Every command and both `cmp` checks must exit zero. With `no_bundle = true` and
`find_additional_modules = false`, pinned Wrangler must copy the reviewed main
module byte-for-byte; any re-bundle or mutable source lookup is a failed gate.
Wrangler also places a generated `README.md` in each `--outdir`; it is not an
upload module. Review the binding summary: active may contain only the Durable
Object namespace, exact R2 bucket, one Analytics Engine dataset, the three
fixed rate-limit bindings, and the documented non-secret variables; rollback
must contain only the Durable Object binding and omit R2, analytics, rate
limits, and variables. Neither may expose workers.dev, a preview URL, or an
extra route.

Wrangler may create a local `.wrangler/` cache beside the config. The validator
permits that single tool-owned directory while still requiring the exact five
evidence files and rejecting every other entry. Validation rehashes the exact
module uploaded by dry-run; it never recompiles repository source.

The next section is an optional isolated live operation and requires separate
explicit deployment approval. Stop here without it.

## 7. Optional isolated private-canary sequence (approval required)

Skip this section for the current public cutover. These commands are authorized
only after the schema-2 generation record, both TOMLs, OAuth callback, isolated
Access apply/read-back, and output validator all bind one reviewed non-live
target. Set `ISOLATED_CANARY_ORIGIN` to that exact HTTPS origin and prove it
equals `https://` plus the record's `deploymentTarget.hostname`; never set it
to the live host. All commands remain account-bound through the isolated
generated TOML. Run the checked-in validator immediately before each deploy
below. First deploy the validated false/null shell so secret creation cannot
bootstrap an active mutation runtime:

```sh
node scripts/generate-reviewed-isolated-canary.mjs --validate-output-dir "$CANARY_DIR"
node "$WRANGLER_JS" deploy \
  --cwd "$CANARY_DIR" \
  --config "$CANARY_DIR/wrangler.rollback.toml"
curl --fail --silent --show-error "$ISOLATED_CANARY_ORIGIN/health" \
  | jq -e '. == {"ok":true,"mutationsEnabled":false}'
ROLLBACK_BODY="$(mktemp)"
test "$(curl --silent --show-error --output "$ROLLBACK_BODY" \
  --write-out '%{http_code}' "$ISOLATED_CANARY_ORIGIN/")" = "503"
jq -e '. == {"code":"release_unavailable"}' "$ROLLBACK_BODY"

security find-generic-password -s '<isolated-access-read-token-service>' -w \
  | node scripts/edge-gate/verify-isolated-access.mjs \
      --target /absolute/path/isolated-canary-target.json \
      --runtime disabled \
      --api-token-stdin
```

Every command must exit zero. The disabled-mode verifier proves that Access
protects operator paths while all three required bypass paths reach the
false/null application, before any active runtime exists. Disable shell tracing
before the three exact secret puts. Each value flows only through the pipe into
Wrangler stdin; no secret is printed, put in argv/environment, or written to a
file:

```sh
set +x
security find-generic-password \
  -s "<isolated-oauth-client-secret-service>" -w \
  | node "$WRANGLER_JS" secret put CLOUDFLARE_OAUTH_CLIENT_SECRET \
      --cwd "$CANARY_DIR" \
      --config "$CANARY_DIR/wrangler.rollback.toml"
openssl rand -base64 32 | tr -d '\n' \
  | node "$WRANGLER_JS" secret put DEPLOY_SESSION_ENCRYPTION_KEY \
      --cwd "$CANARY_DIR" \
      --config "$CANARY_DIR/wrangler.rollback.toml"
openssl rand -base64 32 | tr -d '\n' \
  | node "$WRANGLER_JS" secret put BOOTSTRAP_NONCE_DERIVATION_KEY \
      --cwd "$CANARY_DIR" \
      --config "$CANARY_DIR/wrangler.rollback.toml"
```

Do not add `tee`, `echo`, command substitution, shell tracing, or an
environment variable. The two random keys come from independent invocations
and are not reused. Each `secret put` must report success before continuing.

Run that isolated validator again, deploy the active byte-reviewed module, and
run both health gates:

```sh
node scripts/generate-reviewed-isolated-canary.mjs --validate-output-dir "$CANARY_DIR"
node "$WRANGLER_JS" deploy \
  --cwd "$CANARY_DIR" \
  --config "$CANARY_DIR/wrangler.canary.toml"
curl --fail --silent --show-error "$ISOLATED_CANARY_ORIGIN/health" \
  | jq -e '. == {"ok":true,"mutationsEnabled":true}'
test "$(curl --silent --show-error --output /dev/null \
  --write-out '%{http_code}' "$ISOLATED_CANARY_ORIGIN/")" = "200"

security find-generic-password -s '<isolated-access-read-token-service>' -w \
  | node scripts/edge-gate/verify-isolated-access.mjs \
      --target /absolute/path/isolated-canary-target.json \
      --runtime active \
      --api-token-stdin
```

`GET /` is mandatory: unlike `/health`, it loads the pinned R2 release,
verifies the Ed25519 envelope and every signed payload, and builds the signed
installer asset index. A true health response with a non-200 root is failure.
The active-mode Access verifier separately proves that an unauthenticated
callback reaches the Worker but is rejected for missing session/state, without
weakening the private-client, exact-scope, or client-pair gates in section 4.

Only after all gates may the allowlisted operator run one complete UI canary.
Confirm the consent account and exact ten scopes before authorization. Verify
that the signed result page appears immediately after consent, removes the
callback query from browser history, asks the operator to keep the tab open,
and advances through all 15 journal-backed installation actions without a page
reload. Keep the callback tab connected until the terminal result. Verify
the final receipt, customer Worker URL, management URL, and Portal URL. Confirm
the OAuth grant was automatically revoked. If revocation is unconfirmed,
manually revoke the connected application before ending the test. Keep the
client Private.

### Required same-session removal drill

The canary is incomplete until that exact successful installation is removed
through the retained installer session. This is a reversible canary boundary,
not a general uninstall or day-two management product:

1. Keep the original opaque `__Host-ankka_gateway_deploy` browser session. The
   immutable successful install journal in that same `GatewayDeploySession`
   Durable Object is the only removal authority. Treat its exact
   `recoverUntil`—the install session's original `expiresAt` plus 24 hours—as a
   hard deadline. Closing the browser is safe only if its session cookie will
   be retained; clearing it, deleting the session, or reaching `recoverUntil`
   makes hosted removal unavailable.
2. Generate the removal preview in the UI. `POST /api/uninstall/plan` must
   report `writesPerformed: false`, the exact installation and signed release,
   a lifetime of at most ten minutes without extending `recoverUntil`, and the
   reviewed operations in order: temporary cleanup Worker bridge; seven
   gateway resources; management Custom Domain and companion DNS absence;
   administrator Access policy; parent Access application; `AdminState`
   retirement; management Worker deletion; final no-managed-residue proof.
3. Confirm the plan displays this provider notice before approval: Cloudflare
   retains the Advanced Certificate after Custom Domain removal, it is outside
   Ankka's reviewed OAuth scope, and it requires manual Cloudflare review or
   removal.
4. Choose the removal authorization action only for the exact displayed plan
   hash. This must start a fresh Cloudflare authorization, not reuse the install
   grant. Confirm the same expected account and exact ten scopes again. The
   sealed OAuth attempt must be purpose-bound to `uninstall`; an install-purpose
   callback must fail before token exchange.
5. Let the reviewed executor finish synchronously. Verify the removal receipt
   reports the original installation ID, removal time, provider notice, and
   grant revocation as confirmed or unconfirmed. The executor may report
   success only after its durable journal has a verified zero-resource customer
   receipt, final no-residue evidence, and a removed tombstone. If revocation is
   unconfirmed, manually revoke the connected application immediately.
6. Verify independently in Cloudflare that the seven gateway resources, exact
   management hostname/DNS, overlapping Worker route, administrator Access
   policy/application, `AdminState` namespace, and management Worker are
   absent. Then inspect the retained Advanced Certificate and remove it
   manually if the canary account no longer needs it.

The journal is the only recovery controller. Every destructive call is armed
before its one send and verified from provider state before the next step.
Worker version/deployment and management deletes may converge after an
interruption using read-only provider proof. Never replay the customer cleanup
POST after an armed or unknown outcome: that endpoint intentionally has no
retry or authenticated status read. If the UI reports recovery, preserve the
same browser session and begin only the offered retry, which must obtain a new
OAuth grant. If it reports a non-retryable recovery code or the exact
`recoverUntil` has arrived, stop and finish any necessary cleanup manually in
the customer account; do not invent provider writes outside the reviewed
sequence.

## 8. Isolated private-canary rollback

Any failed build, byte, account, edge-rule, Logpush, risk-acceptance, OAuth,
health, signed-root, execution, or revocation gate triggers rollback. Deploy
the already dry-run and validated false/null module with the same account,
Worker name, Durable Object binding, and custom domain:

```sh
node "$WRANGLER_JS" deploy \
  --cwd "$CANARY_DIR" \
  --config "$CANARY_DIR/wrangler.rollback.toml"
curl --fail --silent --show-error "$ISOLATED_CANARY_ORIGIN/health" \
  | jq -e '. == {"ok":true,"mutationsEnabled":false}'
ROLLBACK_BODY="$(mktemp)"
test "$(curl --silent --show-error --output "$ROLLBACK_BODY" \
  --write-out '%{http_code}' "$ISOLATED_CANARY_ORIGIN/")" = "503"
jq -e '. == {"code":"release_unavailable"}' "$ROLLBACK_BODY"
```

The rollback module has no R2 binding or OAuth client variable and cannot
instantiate the reviewed active runtime. Worker secrets remain stored but the
false/null shell does not read them. Revoke any outstanding OAuth connected
application grant. In this isolated mode only, keep the four exact
private-canary Access applications in place until incident review is complete.

Deploying the false/null installer rollback does not remove a customer gateway.
If the installation completed, first use the required same-session removal
drill above while its retained authority is still valid, or document and
perform explicit manual customer-account cleanup. The active reviewed installer
also supports returning teardown only when a fresh zero-write preflight detects
one exact coherent gateway and its Access-verified customer dashboard supplies
the one-time action authority. The disabled shell cannot run that flow, and it
is not a generalized lookup, repair, adoption, or partial-installation recovery
path.

Do not publish the isolated OAuth client, remove or broaden the isolated
private-canary Access applications, or retry active deployment until the failed
gate has a reviewed explanation and a newly generated output directory. Public
live-host rollback follows section 10 instead and never creates Access.

## 9. First updater promotion gate

The update implementation does not make a pre-updater installation
updater-capable. The first isolated updater proof requires two separately
reviewed and signed releases using the same stable Ed25519 key: updater-capable
N installed
through the normal wizard, followed by N+1 discovered by N. A different key ID
or public key is a migration and must stop this run.

`gateway-v0.1.12` is legacy private-canary evidence, not N. Its schema-1
signature covered only manifest bytes and is rejected by updater protocol 2.
Do not overwrite or promote its immutable publication. Retire the disposable
installation and reinstall a fresh schema-2 N whose signature statement binds
the exact `canary` channel, key ID, canonical manifest and v2 signature context.

Keep exact evidence for the signed envelopes, artifact roots, source commits,
Cloudflare Worker/version/deployment IDs, customer update records, and test
times. Keep OAuth codes, grants, action keys, cookies, and signing material out
of the evidence.

1. Install signed N in the disposable customer account. Confirm the three
   public updater bindings are exact and that workers.dev is disabled. Make one
   real employee MCP tool call through the Portal.
2. Pin signed N+1 on the reviewed canary channel. From the customer management
   page, confirm update discovery is anonymous, signature-verified, classified
   `normal`, and lists only Worker code and management assets as changes.
3. Review N+1, start Update, and authorize a fresh Cloudflare grant. Confirm
   the user returns immediately to live customer-owned progress and that no
   token appears in a URL, response, log, journal, or retained state.
4. Before activation, verify Cloudflare's active deployment contains N at 100%
   and N+1 at 0%. Confirm the N+1 health request used an exact version override
   and succeeded. Then verify N+1 alone at 100%, workers.dev disabled, and a
   second real employee MCP tool call.
5. Prepare a separately signed intentionally broken candidate under the same
   exact normal contract. Use the exact clean source commit for the healthy
   base release now installed as N+1, and choose a strictly newer
   `BROKEN_RELEASE` that has never been published:

   ```sh
   BROKEN_DIR=/private/tmp/ankka-gateway-fault-$BROKEN_RELEASE
   node scripts/build-reviewed-fault-injection-candidate.mjs \
     --source ../.. \
     --source-commit "$(git -C ../.. rev-parse HEAD)" \
     --base-release "$N_PLUS_ONE_RELEASE" \
     --release "$BROKEN_RELEASE" \
     --channel canary \
     --fault exact-version-health-probe-v1 \
     --out "$BROKEN_DIR"
   ```

   Review the printed source commit, manifest digest, and artifact digest. The
   builder refuses the same or an older version and writes create-only. Before
   signing, reconcile `BROKEN_RELEASE` against retained release receipts and
   R2 publication-intent evidence. The ID must be absent, except when resuming
   the exact reviewed partial publication from this run. The immutable R2
   intent rejects different bytes, but an exact prior intent is deliberately
   restartable and therefore is not proof that this run chose a new version.

   Sign with the same retained key used by N and N+1, using the normal bounded
   stdin flow and adding both exact constraints below:

   ```text
   --channel canary
   --reviewed-fault-injection exact-version-health-probe-v1
   ```

   The signer detects the injected marker and refuses stable, a missing or
   different acknowledgement, duplicate markers, and an acknowledgement on an
   ordinary candidate. Publish with the ordinary create-only R2 operator, pin
   the hosted canary to that exact receipt, and validate the generated canary
   output before deployment. Do not create a GitHub Release mirror for this
   deliberately unhealthy fixture.

   Approve it and prove the exact-version candidate probe returns failure, the
   prior healthy version is restored at 100%, compensation is provider-verified,
   and the customer action reports failure rather than success. Never promote
   the broken candidate to stable.
6. Update to another healthy candidate, then choose Rollback and authorize a
   fresh grant. Verify the recorded previous Cloudflare version is staged at
   0%, exact-version probed, activated at 100%, health-checked, and usable for a
   real employee MCP tool call. Confirm the UI states that Durable Object data
   was retained.
7. With the original installer session and immutable install receipt, run the
   same-session removal drill after an update. The cleanup and retirement code
   must come from the current reviewed signed bundle while ownership remains
   bound to the original receipt. Independently prove zero receipt-owned
   residue.

Any mixed customer traffic, missing 0% candidate, key drift, migration field,
scope/binding/compatibility drift, unverified compensation, lost rollback
version, credential persistence, or uninstall mismatch fails this gate. Keep
the updater release on canary and use the installer rollback procedure in §8
until the failure has a reviewed explanation.

## 10. Public activation from the no-Access disabled shell

This is a distinct release boundary. `deploy.ankka.ai` remains without an Ankka
Access application and serves the exact disabled shell until activation. Do
not run `apply-access.mjs`, create a temporary operator Allow application, or
create callback/release Bypass applications on the live host. An optional
isolated private canary in §§5–8 is a separate environment and must not have a
selector capable of covering the live hostname.

Before activation, retain reviewed evidence for every item:

- schema-2 releases N and N+1 under the retained Ed25519 key, anonymous signed
  discovery, the 0%/100% update sequence, broken-candidate compensation, a
  healthy update, explicit rollback, and real employee MCP calls;
- same-session post-update uninstall and returning-customer uninstall, each
  followed by independent zero Ankka-managed residue;
- isolated Worker-rate-limit exhaustion with the exact `429`
  `{"code":"rate_limited"}` response and an isolated missing-binding canary
  with the exact `503` `{"code":"abuse_controls_unavailable"}` response,
  while existing-session reads, the callback, and signed discovery still
  behave as specified;
- the existing live OAuth client still **Public**, with `deploy.ankka.ai`
  domain verification reported as `verified`, the exact live callback
  unchanged, its client-secret pair reverified, and the exact ten scopes
  rechecked; the separate isolated-only client is not promoted or substituted;
- every account- and zone-level Logpush job re-read and proved unable to
  capture `deploy.ankka.ai`; and
- Network Error Logging remains enabled for the hosted zone, with the exact
  private evidence and residual-metadata acceptance above, while the signed
  customer Worker telemetry-off contract and its deployment read-back remain
  green.

Perform the public preflight while the disabled shell is still active:

1. Prove there is no callback or mutation in flight from an earlier run. Finish
   or reconcile any retained receipt-owned customer work before proceeding;
   never delete its journal or receipt to clear this gate.
2. From a fresh complete paginated account read, inspect every Access
   application using the same whole-host, path, wildcard, destination, and
   unknown-selector fail-closed rules as `verify-public.mjs`. Require zero
   application capable of covering `deploy.ankka.ai`. This is read-only: do not
   create or delete an application to make the result pass.
3. From a cookie-free client with manual redirect handling, require
   `/health` to return exactly `{"ok":true,"mutationsEnabled":false}` and
   require `/`, `/api/session`, the callback, and both release channels to
   return the fixed disabled response without an Access redirect.
4. Revalidate the exact generated active and rollback artifacts. Require the
   rollback artifact to have no release, analytics, or rate-limit binding and
   retain only secret-free evidence of the activation approval.

Only after all four preflight steps pass may the operator deploy the exact
reviewed active artifact. Activation is its own approved action. Immediately
run the read-only public verifier from an unauthenticated client. The token
needs only the read permissions required to resolve the zone and list Access
applications, is read through bounded stdin, and is never used on an installer
request:

```sh
security find-generic-password -s '<short-lived-access-read-token-service>' -w \
  | node scripts/edge-gate/verify-public.mjs \
      --api-token-stdin \
      --channel canary \
      --release gateway-vX.Y.Z \
      --source-commit '<40-lowerhex reviewed source commit>' \
      --artifact-sha256 '<64-lowerhex reviewed artifact digest>' \
      --key-id '<reviewed key ID>' \
      --public-key '<43-character raw Ed25519 base64url public key>'
```

Zero exit requires a complete paginated account read with no Access
application—whole-host, path-specific, wildcard or destination-based—
that can cover `deploy.ankka.ai`. It also requires cookie-free observations of
the exact active health response with `mutationsEnabled: true`, a `200`
installer root whose bytes match the signed manifest, an application-level callback rejection, both exact release
paths and no Access redirect. Cloudflare-injected `NEL`/`Report-To` headers are
allowed under the separately approved hosted-zone policy. The active channel
must serve the exact reviewed descriptor and valid Ed25519 signature; the
inactive channel must return the exact application-level `404`. The API check
uses `HEAD /api/session`, never a state-minting session GET.

Finally, complete the wizard from a fresh unrelated Cloudflare account and
retain only secret-free results. Public mode is not established until the
preflight, post-activation verifier, and unrelated-account browser flow all
pass. A missing Access application by itself, a green `/health` alone, or an
HTTP response that merely avoids the Access login is not sufficient evidence.

If activation or public exposure fails, do not create Access. Stop inviting new
sessions and identify every callback or receipt-owned mutation already in
flight. Let each known operation reach a durable terminal result, or use its
existing journal and receipt authority to recover and reconcile provider state.
After independent provider verification, deploy the exact disabled shell and
repeat the complete Access read and cookie-free disabled-shell probes. OAuth
Public promotion remains permanent; the no-Access disabled shell is the live
rollback posture.

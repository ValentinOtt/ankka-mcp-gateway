# Cloudflare two-stage installer handover

**Handover date:** 2026-09-02  
**Branch:** `codex/cloudflare-two-stage-bootstrap`  
**Repository:** `/Users/val/Documents/GitHub/ankka-mcp-gateway`  
**Production status:** disabled and unwired  
**Git status:** deliberately dirty; do not stage, commit, or push this work

## Executive status

The architecture is settled and the live Cloudflare canaries have passed. The
browser-only bootstrap was conclusively rejected because Cloudflare's
management API does not support the required browser CORS requests. The chosen
default is therefore:

```text
deploy.ankka.ai
  -> temporary Stage 1 grant: workers-scripts.write only
  -> restricted customer-owned Gateway Worker + SQLite Durable Object
  -> revoke and discard Stage 1 grant
  -> token-free health/readiness check
  -> same-browser one-time capability handoff to the customer Worker
  -> customer Worker runs Stage 2 PKCE through the code-only auth.ankka.ai relay
  -> temporary Stage 2 token is exchanged, used, revoked, and discarded inside
     the customer-owned Worker
  -> final Gateway, Portal, Access, DNS, routes, and receipts converge there
```

The Stage 1 provider coordinator was completed at the end of this session and
its focused tests are green. The next cohesive unit of work is the hosted
installer's secret-free session state machine, encrypted bootstrap cookie, and
clean two-stage HTTP runtime. Do not try to preserve or shim the current legacy
installer route graph: there are no users, and the user explicitly asked for a
clean cutover.

No Cloudflare resource, canary process, or OAuth grant is intentionally left
running. Production activation remains compile-time false.

## Non-negotiable product and security decisions

1. No permanent Cloudflare management credential is provisioned or required.
2. Stage 1 requests exactly `workers-scripts.write` and nothing else.
3. Stage 2 authority is temporary, exchanged and held only inside the customer
   Gateway, and uses exact fixed-operation scope catalogues.
4. `auth.ankka.ai` relays only the authorization code. It never receives the
   PKCE verifier and has no token-exchange path.
5. Cloudflare tokens, refresh tokens, OAuth codes, PKCE verifiers, bootstrap
   capabilities, provider responses, account/resource IDs, and source
   credentials must never enter logs, traces, telemetry, exceptions, or durable
   Ankka state.
6. Source credentials such as Google/BLS remain customer-side and are entered
   only after management Access is enforced.
7. Customer resources and lifecycle receipts remain owned by the customer's
   Cloudflare account. Foreign/ambiguous resources fail closed.
8. The UI must show two understandable Cloudflare approvals. Hiding the second
   approval would weaken the trust boundary.
9. Team membership is managed manually in Cloudflare for V1. The Team editor is
   disabled. `ANKKA_TEAM_MANAGEMENT_TOKEN` is not part of the default or V1
   architecture.
10. Cloudflare has confirmed that API tokens cannot be scoped to one reusable
    Access policy. Account-level `Access: Policies Write` is not an acceptable
    default fallback.
11. Do not widen Cloudflare permissions to make an endpoint work. The direct
    script upload path is the qualified Worker mutation path.
12. Keep production routes and mutation activation disabled until every release
    gate in this document passes.

## Live evidence already obtained

### Browser-only bootstrap

Rejected. Browser preflights to `api.cloudflare.com` failed for account reads
and Worker create/read/delete operations without CORS allow headers.
`allowed_cors_origins` affects OAuth integration, not the management API.

### Stage 1

Passed with exactly `workers-scripts.write`:

- exact one-account selection;
- rejection when two accounts were selected;
- confidential-client Authorization Code + PKCE exchange;
- no refresh token;
- direct Worker script upload;
- SQLite Durable Object migration and namespace read-back;
- exact version/deployment/namespace verification;
- temporary `workers.dev` enablement and verification;
- token revocation before runtime handoff;
- token-free `/health` polling;
- one-time fragment capability consumption and replay rejection;
- full retirement/delete/absence verification in the lifecycle canary.

The Workers Versions submit endpoint failed with HTTP 403/provider code 100406
under this exact scope. Direct script upload passed and is the approved path.

### Stage 2

Passed with the exact seven-scope install ceiling:

```text
access-acct.read
zone-access.write
dns.write
mcp-portals.write
workers-routes.read
workers-scripts.write
zone.read
```

The canary covered customer-side public-client PKCE exchange, code-only relay,
exact account/scope checks, Zone/Access/Portal/DNS/Worker operations, final
self-update, unknown-outcome recovery, rollback, customer-side uninstall,
hosted finalization, and revocation.

### Later-operation ownership proof

Passed. The customer Gateway uses a customer-generated Ed25519 key. Only its
AES-256-GCM ciphertext is persisted in the customer's Durable Object; the wrap
key is a customer Worker secret. The relay allocates state only after a signed
preflight, stores hashes only, and consumes a challenge once before issuing a
fixed-operation ticket.

The live SQLite adapter must use `SELECT changes()` in the same synchronous
transaction. `SqlStorageCursor.rowsWritten` was not reliable enough.

## Work completed in code

### Fixed operation and permission boundary

`apps/installer/src/cloudflare-operation-authority.ts` defines the fixed
operations and scope ceilings:

- `bootstrap` — hosted installer, `workers-scripts.write`;
- `install` — customer Gateway, the seven exact scopes above;
- `upgrade` / `rollback` — customer Gateway, `workers-scripts.write`;
- source add/update/remove — customer Gateway,
  `zone-access.write` + `mcp-portals.write`;
- `uninstall` — receipt-kind-derived fixed ceiling;
- `uninstall-finalize` — hosted installer, `workers-scripts.write`.

There is no arbitrary scope input, generic repair operation, generic Cloudflare
proxy, or browser-supplied cleanup resource list.

### Signed six-component release contract

The release contract now has:

- admin;
- installer;
- worker;
- worker bootstrap;
- worker cleanup;
- worker retirement.

The bootstrap variant fixes its SQLite `AdminState` class, assets, bindings,
compatibility date, no observability, no metrics, no preview URLs, and no
workers.dev in final desired state. `ANKKA_INSTALLER_ORIGIN` was added to the
exact bootstrap plain-binding contract and is fixed to
`https://deploy.ankka.ai`.

### Team token removal

The normal runtime/admin/docs surfaces were changed so V1 Team management is
manual and does not expose or depend on `ANKKA_TEAM_MANAGEMENT_TOKEN`. Before
release, run a repository-wide search to make sure no normal installation
surface reintroduced it.

### Customer-owned Stage 2 implementation

The ignored candidate modules include:

- restricted bootstrap and final Gateway entrypoints;
- bootstrap capability and durable state;
- Stage 2 converger, journal, recovery router, and durable state;
- code-only relay HTTP boundary;
- fixed operation authority;
- ownership handoff, certificate, challenge, proof, and relay ticket;
- customer Worker self-update;
- receipt-bound uninstall and hosted finalizer.

Their focused and full installer tests passed earlier in this session before
the final Stage 1 coordinator addition.

### Dedicated hosted Stage 1 coordinator — completed tonight

Primary file:

```text
apps/installer/src/hosted-stage1-bootstrap.ts
```

Primary test:

```text
apps/installer/test/hosted-stage1-bootstrap.test.ts
```

Exports:

- `createHostedStage1Secrets`
- `provisionHostedStage1`
- `completeHostedStage1Handoff`
- `parseHostedStage1Provision`

Important properties:

- generates capability, bootstrap nonce, and ownership wrapping key together;
- validates the exact static plan and signed six-component release;
- exchanges the confidential Stage 1 code and resolves exactly one account;
- reads the account Workers subdomain;
- deploys the restricted real Gateway plus SQLite Durable Object using the
  qualified direct-upload path;
- enables and verifies only the exact temporary workers.dev route;
- signs and self-verifies the exact ownership handoff while the callback owns
  the provider read-back;
- revokes and discards the grant before returning `HostedStage1Provision`;
- returns no raw capability, nonce, wrapping key, or access token;
- performs a later token-free `/health` read with exact-origin CORS;
- signs the ownership certificate after matching customer ownership key,
  install ID, release, Worker, namespace, handoff, and plan;
- releases the capability only in the URL fragment for
  `/__ankka/install` on the customer Worker origin.

The verified operation ordering in the focused test is:

```text
token exchange
account read
workers subdomain read
worker + SQLite deployment
workers.dev enable
workers.dev verification
grant revoke
token-free customer health
fragment handoff
```

`hosted-bootstrap-grant.ts` was generalized so the fixed deployment callback
can return a typed secret-free deployment result. The wrapper does not return
until revocation is confirmed and the in-memory grant is discarded.

### Error contract

Two stable codes were added:

- `bootstrap_not_ready` — token-free polling should continue;
- `bootstrap_failed` — customer runtime/read-back contract was invalid.

## Last known tests

At the end of the session:

```text
npm run typecheck --workspace @ankka/gateway-installer
```

passed.

The focused boundary suite:

```text
npm test --workspace @ankka/gateway-installer -- --run \
  test/hosted-stage1-bootstrap.test.ts \
  test/hosted-bootstrap-grant.test.ts \
  test/customer-bootstrap-worker-deployment.test.ts \
  test/customer-bootstrap-worker-readback.test.ts \
  test/customer-stage2-converger.test.ts
```

passed: **5 files, 18 tests**.

Before the final Stage 1 coordinator was added, the complete installer suite
passed: **83 files, 921 tests**. Do not claim the complete suite is current
until it is rerun with the new coordinator.

No full repository gate was run after the final Stage 1 coordinator. The next
developer should use focused tests while wiring, then `npm run check:fast`, and
only then the full `npm run check` release gate.

## Current worktree and Git handling

The branch has a large existing dirty worktree spanning installer, runtime,
admin, docs, payload, and tests. These changes belong to this two-stage/Team
boundary work; do not reset, restore, or overwrite them casually.

The user explicitly requested that the Cloudflare two-stage candidate not be
included in Git tracking yet. Candidate-only new files and both local decision
documents are listed in `.git/info/exclude`. This handover is also locally
excluded. Do not `git add -f`, commit, or push any of them.

Tracked files already modified by the broader work still appear in
`git status`; `.git/info/exclude` cannot hide modifications to tracked files.
Treat that as expected. Before any future publication decision, perform a
separate public-boundary and history review.

Useful checks:

```text
git branch --show-current
git status --short
git status --short --ignored | rg '^!! (apps/installer|docs/CLOUDFLARE)'
git ls-files --others --exclude-standard
```

The last command should be empty for the local two-stage files.

## What is not wired yet

The main production-facing gaps are clear:

1. `apps/installer/wrangler.toml` still points to `src/index.ts`, the legacy
   installer runtime.
2. `reviewed-entrypoint.ts` still imports the legacy-backed
   `reviewed-runtime.ts`.
3. The clean hosted two-stage HTTP/session runtime does not exist yet.
4. The existing signed installer UI still starts with a separate read-only
   discovery flow and presents legacy plan/deploy/removal routes.
5. The Stage 1 raw secrets are not yet integrated into one encrypted,
   short-lived `__Host-` HttpOnly cookie.
6. The hosted Durable Object does not yet persist the new secret-free Stage 1
   state machine.
7. Lost-cookie/post-revocation deterministic cleanup is not implemented.
8. The ownership issuer private key still needs a strict environment-secret
   parser/importer for the hosted runtime.
9. `wrangler.auth.toml` currently contains an `auth.ankka.ai` custom-domain
   route. Remove that route while activation remains disabled; only a reviewed
   activation change should restore it.
10. The public HTTPS customer-account -> `auth.ankka.ai` topology still needs
    the final production-shaped qualification. The live ownership canary used a
    same-account Service Binding to avoid same-account workers.dev loop issues.

The bottom of `docs/CLOUDFLARE_TWO_STAGE_INSTALL.md` still lists “dedicated
hosted Stage 1 executor” as remaining. That item is stale now. Update it only
after the new session/runtime integration establishes the final contract.

## Recommended implementation sequence

### 1. Establish a fresh baseline

Run the installer typecheck and focused Stage 1 suite first. If both pass, run
the complete installer test suite once before touching the runtime. This gives
tomorrow's developer a clean fault boundary.

### 2. Add a new secret-free hosted session model

Prefer a new file such as:

```text
apps/installer/src/hosted-stage1-session.ts
```

Recommended phases:

```text
draft
authorizing
provisioned
handed_off
failed
cleanup_required
```

Durable state may contain:

- normalized customer selection;
- exact static plan and its hash;
- release pin/identity;
- attempt ID;
- state/verifier hashes only;
- capability commitment and expiry, never capability secret;
- exact account/Worker/namespace/version/deployment identity after provider
  read-back;
- signed handoff or its exact digest, if retained;
- revocation result;
- revision, phase timestamps, and stable failure code;
- deterministic cleanup status for the exact Stage 1 root.

Durable state must not contain raw OAuth state, verifier, authorization code,
access/refresh token, capability secret, bootstrap nonce, ownership wrapping
key, provider response body, or arbitrary Cloudflare metadata.

Every transition should be exact compare-and-set/revision checked. Duplicate or
stale callbacks must fail before token exchange.

### 3. Add one strict encrypted Stage 1 OAuth cookie schema

Add a new schema version to `crypto.ts` rather than overloading legacy cookie
shapes. It should include only the short-lived raw values that must survive the
Cloudflare redirect:

```text
purpose: bootstrap
sessionId
attemptId
state
verifier
expiresAt
bootstrapId
capabilitySecret
capabilityExpiresAt
bootstrapNonce
ownershipWrapKey
planId
planHash
```

The cookie must be:

- encrypted/authenticated with the existing dedicated session key pattern;
- `__Host-`, HttpOnly, Secure, SameSite=Lax, Path=/;
- bounded to the same ten-minute authorization/capability window;
- validated against durable hashes and exact plan identity;
- cleared on success, rejection, expiry, and terminal failure;
- retained only across the token-free readiness polling window after Stage 1
  revocation, because it still holds the capability needed for handoff.

Do not put the capability in JavaScript-accessible storage at
`deploy.ankka.ai`. Release it only in the final cross-origin URL fragment.

### 4. Implement a clean two-stage Durable Object

Create a new class, e.g. `TwoStageDeploySession`, rather than adding more modes
to the 2,800-line legacy `GatewayDeploySession`.

Responsibilities:

- initialize one bounded session;
- enforce CSRF and same-origin mutation headers;
- normalize/save the nontechnical selection;
- build and freeze the exact static plan against the pinned release;
- authorize one bootstrap attempt;
- atomically consume the callback attempt before code exchange;
- store only secret-free provision metadata after confirmed revocation;
- expose token-free handoff readiness state;
- mark handoff complete or cleanup required;
- expire and erase state with an alarm;
- authorize exact-root cleanup on a fresh Stage 1 grant.

Keep this class small. Do not port legacy discovery, generic management relay,
returning uninstall, or old retained-token recovery into it.

### 5. Implement the clean hosted HTTP runtime

Use a new runtime module independent of `index.ts` and the legacy
`reviewed-runtime.ts`. Suggested routes:

```text
GET  /health
GET  /api/session
PUT  /api/selection
POST /api/plan
POST /api/bootstrap
GET  /oauth/callback
GET  /api/bootstrap/handoff
GET  /                  signed installer asset
GET  /gateway           signed installer asset
GET  /review            signed installer asset
GET  /deploy            signed installer asset
GET  /result            signed installer asset
GET  /assets/<exact>     signed immutable asset
```

Exact route naming can be tightened, but there should be no `/api/discovery`,
generic proxy, legacy install callback, or browser-provided provider IDs.

Expected callback flow:

1. Parse only `code`, `state`, and standard Cloudflare denial fields.
2. Open and validate the encrypted bootstrap cookie.
3. Ask the Durable Object to atomically consume the exact attempt.
4. Load/revalidate the exact pinned signed release.
5. Import the ownership issuer key from a strict secret binding.
6. Call `provisionHostedStage1` in the callback request.
7. Persist only `HostedStage1Provision` and confirmed revocation state.
8. Redirect query-free to `/result` or an equivalent handoff page.
9. Keep the encrypted cookie until token-free readiness succeeds.

Expected handoff polling flow:

1. Open cookie and exact-match session/attempt/plan/provision commitments.
2. Call `completeHostedStage1Handoff` without any Cloudflare management token.
3. If `bootstrap_not_ready`, return a bounded retry response and keep the
   cookie.
4. If successful, atomically mark handed off, clear the cookie, and return or
   redirect to the customer Worker's fragment URL.
5. Never include the fragment URL in logs, telemetry, durable state, or an
   exception.

### 6. Implement deterministic lost-cookie cleanup

This is the most important unfinished recovery boundary.

If the provider callback has created the restricted Worker and revoked the
grant, but the browser loses/expires the encrypted cookie before handoff, the
capability cannot be reconstructed. The durable session should become
`cleanup_required` and retain only exact provider identities/commitments.

A fresh Stage 1 `workers-scripts.write` authorization may then:

- reassert the exact account;
- read back the exact recorded Worker, immutable Worker ID, deployment,
  version, namespace, release, plan/install bindings, and workers.dev state;
- refuse cleanup on any mismatch or ambiguity;
- disable workers.dev;
- retire/delete only the recorded SQLite namespace and Worker in the reviewed
  order;
- verify absence;
- revoke and discard the fresh grant;
- clear the durable session or permit a new bootstrap attempt.

Do not silently adopt the incomplete Worker, mint a new capability for it, or
use names alone as ownership evidence. Reuse the exact lifecycle primitives
where possible, but do not bend the final uninstall protocol into a weaker
bootstrap cleanup path.

### 7. Cut the production build entrypoint cleanly, still disabled

After the new runtime and class are tested:

- make `reviewed-entrypoint.ts` import only the clean reviewed two-stage
  runtime;
- export `TwoStageDeploySession` from the Wrangler main module;
- change `wrangler.toml` main away from `src/index.ts`;
- update the Durable Object binding/class/migration for the new class;
- keep `REVIEWED_GATEWAY_DEPLOY_ACTIVATION` exactly `{enabled:false,pin:null}`;
- keep deploy.ankka.ai without a checked-in production route;
- remove the checked-in live auth.ankka.ai route until activation review;
- verify the disabled shell touches no environment binding and exposes only
  zero-write health/unavailable responses.

Because there are no users, do not add dual routing, migration compatibility,
or legacy fallback logic.

### 8. Replace the signed installer UX

The current payload still describes a read-only discovery grant and legacy
plan flow. Replace it with one guided install:

```text
deploy.ankka.ai
  -> Connect Cloudflare
  -> choose exactly one account in Cloudflare
  -> Ankka Gateway installed
  -> Finish secure setup
  -> choose storefront domain inside customer-owned Stage 2
  -> complete
```

The first page can collect a gateway display name, storefront domain, primary
admin email, and derive sensible management/portal hostnames. It must not ask
for account IDs, zone IDs, Worker names, Durable Objects, routes, Terraform,
Wrangler, GitHub, or scopes.

Be candid in plain language:

- approval 1 installs the small Gateway shell;
- approval 2 lets that customer-owned Gateway finish its own setup;
- both permissions are temporary;
- no permanent Cloudflare token exists;
- Team membership is managed in Cloudflare for V1.

The UI must survive users being away from the computer. Use clear expiry copy,
safe polling, and a one-click “start a fresh approval” path rather than a chain
of manually retriggered short-lived links.

### 9. Bind the production-shaped relay topology

The existing auth entrypoint and ownership challenge Durable Object are strong
candidate primitives. Wire and test them over public HTTPS from a customer
account, with:

- fixed redirect URI and public client ID;
- fixed signed operation and scope map;
- no verifier/token exchange at the relay;
- pre-allocation ownership proof for later operations;
- single-use state/challenges;
- no callback query logging or traces;
- no-store, no-referrer, no open redirects;
- exact callback hostname/account/Worker certificate binding.

Do not activate the real route or mutate the real OAuth client during this
work.

## Runtime/environment bindings to settle

The clean hosted runtime will need strictly validated bindings for:

- hosted confidential OAuth client ID and secret;
- customer-operation public OAuth client ID;
- deploy-session AES-GCM key;
- ownership issuer Ed25519 private key, public key, and key ID;
- read-only signed release bucket;
- new session Durable Object namespace;
- existing rate-limit bindings;
- optional documented hosted funnel analytics only.

The issuer private key must remain an encrypted Worker secret. Validate the
private key's canonical format, derive or verify its public key, import it
non-extractably for signing, and reject a public/private/key-ID mismatch before
any OAuth exchange or provider write.

The disabled activation path must not read any of these bindings.

## Known technical issues and review notes

- `HostedStage1Provision.bootstrapOrigin` is canonicalized with a trailing
  slash. Preserve that invariant consistently in URL comparisons.
- `completeHostedStage1Handoff` requires exact installer-origin CORS and
  `Vary: Origin` from customer `/health`.
- Add a direct entrypoint test for the real bootstrap Worker's `/health`, not
  only the mocked Stage 1 coordinator response.
- The bootstrap entrypoint currently also exposes an internal status route,
  while the decision record describes four restricted operational routes.
  Reconcile the documentation and route allowlist; do not casually widen it.
- `provisionHostedStage1` deliberately maps provider-operation failure to a
  stable generic error. Preserve redaction, but consider whether cleanup state
  needs a separate internal classification without provider text.
- The random-byte helper should overwrite temporary byte arrays after encoding
  where practical.
- The type re-exports at the bottom of `hosted-stage1-bootstrap.ts` may be
  unnecessary; remove them if no caller needs them.
- Runtime propagation can lag successful management read-back. Never poll edge
  readiness in the OAuth callback; a free-plan canary hit the 50-subrequest
  limit that way.
- A Worker invocation can disappear after token exchange and before revoke.
  This cannot be made impossible without persisting a token, which is forbidden.
  The product can truthfully promise revoke/discard attempts and no stored
  credential, not perfect crash-time revocation.
- Cloudflare may leave a Connected Applications dashboard row after the token
  has been proven unusable. Do not equate the row with a live token.
- Public OAuth apps can be blocked by account administrators. Keep
  customer-managed OAuth/manual installation as an advanced fallback.
- Cloudflare OAuth scope/endpoint behavior can drift. A failing qualification
  must block release, not trigger scope widening.

## Tests to add during wiring

At minimum:

1. encrypted bootstrap cookie round trip and every invalid/expired/mismatched
   field;
2. secret-free durable-state serialization audit;
3. stale/duplicate callback rejected before exchange;
4. two-account authorization rejected before write;
5. exact Stage 1 scope/no refresh-token enforcement;
6. revocation always attempted on success and every failure point;
7. provision metadata available only after confirmed revoke;
8. health polling contains no bearer token or capability;
9. capability appears only in customer-origin fragment and is never persisted;
10. not-ready retry keeps cookie; successful handoff clears it;
11. lost-cookie state requires fresh cleanup authorization;
12. cleanup rejects name-only, account mismatch, provider-ID mismatch,
    release/plan mismatch, extra namespace, and foreign resources;
13. exact cleanup succeeds, verifies absence, then revokes;
14. disabled reviewed entrypoint touches no bindings;
15. signed assets cannot shadow `/health`, `/api/*`, or `/oauth/callback`;
16. route allowlist rejects every legacy discovery/proxy path;
17. real bootstrap `/health` CORS contract;
18. end-to-end Stage 1 callback -> revoke -> health -> fragment handoff;
19. end-to-end Stage 2 relay -> customer exchange -> final self-update ->
    workers.dev disable -> READY;
20. rollback, unknown-outcome recovery, split uninstall, and idempotent
    finalizer against the production-shaped runtime;
21. repository scan proving no permanent Team token/default management token;
22. public-boundary scan proving no live account/resource IDs, secrets,
    generated output, or canary artifacts.

## Gate order

Use this sequence to keep failures attributable:

```text
npm run typecheck --workspace @ankka/gateway-installer
npm test --workspace @ankka/gateway-installer -- --run <new focused tests>
npm test --workspace @ankka/gateway-installer
npm run check:fast
npm run check
```

Before any deployment or activation review, also run targeted searches:

```text
rg -n 'ANKKA_TEAM_MANAGEMENT_TOKEN|access\.write|access-acct\.write' .
rg -n 'api/discovery|DISCOVERY_OAUTH_SCOPES|createGatewayDeployWorker' apps/installer/src
rg -n 'routes\s*=|custom_domain' apps/installer/wrangler*.toml
git diff --check
git status --short
```

Interpret search hits; some may belong to explicit historical rejection tests
or docs. The production runtime and default config must have none of the stale
behavior.

## Definition of done for production activation review

Do not enable the route merely because unit tests pass. Activation review can
start only when all of these are true:

- clean two-stage runtime is the only deploy.ankka.ai mutation entrypoint;
- disabled build remains zero-write and environment-independent;
- Stage 1 cookie/session/cleanup lifecycle is complete and adversarially tested;
- customer bootstrap health and one-time adoption work end to end;
- Stage 2 public HTTPS relay topology passes with exact scopes and no refresh
  token;
- final self-update kills the bootstrap surface and disables workers.dev;
- recovery, rollback, uninstall, and hosted finalization pass against disposable
  resources;
- no default or optional permanent Team management credential remains;
- OAuth clients, callback URIs, secret custody, logging/tracing suppression,
  release pin, scope catalogue, and routes receive explicit review;
- all full test/build/lint/public-boundary/history gates pass;
- disposable grants, clients, Workers, namespaces, DNS, Access, and Portal
  resources are verified absent after qualification.

## Primary reference files

- `docs/CLOUDFLARE_TWO_STAGE_INSTALL.md` — full decision record and canary
  evidence.
- `apps/installer/src/hosted-stage1-bootstrap.ts` — new Stage 1 coordinator.
- `apps/installer/test/hosted-stage1-bootstrap.test.ts` — ordering and secret
  boundary proof.
- `apps/installer/src/hosted-bootstrap-grant.ts` — narrow grant lifetime.
- `apps/installer/src/cloudflare-operation-authority.ts` — fixed operation and
  scope catalogue.
- `apps/installer/src/customer-gateway-bootstrap-entrypoint.ts` — restricted
  customer runtime.
- `apps/installer/src/customer-stage2-converger.ts` — customer-owned Stage 2.
- `apps/installer/src/cloudflare-code-relay-http.ts` — code-only relay.
- `apps/installer/src/cloudflare-gateway-ownership-proof.ts` — ownership key,
  certificate, challenge, and proof.
- `apps/installer/src/cloudflare-uninstall-finalizer.ts` — exact root finalizer
  authorization.
- `apps/installer/src/reviewed-entrypoint.ts` and `reviewed-runtime.ts` — current
  legacy-backed reviewed shell to replace.
- `apps/installer/src/durable/gateway-deploy-session.ts` — legacy 2,800-line DO;
  use it only for narrow implementation patterns, not as the new architecture.
- `payload/installer/` — signed UI that still needs the noob-friendly rewrite.
- `apps/installer/wrangler.toml` and `wrangler.auth.toml` — remain disabled/unwired
  until the final gate.

## First action tomorrow

Start by rerunning the focused tests and the complete installer suite. Then add
the new secret-free session model and its tests before touching routing or UI.
That keeps the next commit-sized thought focused on the hardest trust boundary:
all recoverable identity in Durable Object state, all redirect secrets in one
short-lived encrypted browser cookie, and no provider credential anywhere
persistent.

## Progress after handover (2026-09-02, later session)

### Baseline repaired

The complete suite had one real regression and three masked breakages, all
from earlier worktree edits:

- `payload/worker/index.js` mirrors `APPROVED_CLOUDFLARE_RELEASE_CONTRACT` as
  `APPROVED_UPDATE_CLOUDFLARE_CONTRACT` and rejects any update manifest whose
  contract differs canonically. `ANKKA_INSTALLER_ORIGIN` had been added to
  `release-manifest.ts` but not to the mirror, so every customer `/api/update`
  reported `unavailable`. Fixed; keep the two in lockstep.
- `test/release-payload-layout.test.mjs` fingerprints for `worker` and
  `worker-cleanup` restated; `edge-gate-public.test.mjs` fixture now carries
  `workerBootstrap`; oxlint anti-slop findings in `customer-bootstrap-request`,
  `cloudflare-gateway-fresh-preflight`, `cloudflare-worker-direct-upload` (+test)
  fixed in the reviewed-runtime optional-controls style.
- `wrangler.auth.toml` no longer carries the `auth.ankka.ai` route. The unused
  type re-exports were removed from `hosted-stage1-bootstrap.ts`.

`npm run check` passed end to end after these changes.

### Step 2 of the sequence: secret-free session model — done

New candidate files (locally excluded, not tracked):

```text
apps/installer/src/hosted-stage1-session.ts
apps/installer/src/hosted-stage1-session-durable-state.ts
apps/installer/test/hosted-stage1-session.test.ts
apps/installer/test/hosted-stage1-session-durable-state.test.ts
```

Phases: `draft → authorizing → provisioned → handed_off`, with `failed` and
`cleanup_required`. Transitions are pure, revision-incrementing, and validated
through one strict schema plus phase invariants and `forbiddenStoredKeyPath`.
Durable state holds the normalized selection, the exact static plan, attempt
commitments (`stateHash`, `verifierHash`, capability commitment) and the
secret-free `HostedStage1Provision`; it never holds state, verifier, code,
tokens, capability secret, nonce, or wrapping key. Exports:

- `initializeHostedStage1Session`, `saveHostedStage1Selection`,
  `freezeHostedStage1Plan`, `authorizeHostedStage1Bootstrap`
  (returns raw state/verifier/challenge once for the cookie),
  `consumeHostedStage1Callback` (atomic claim before exchange; duplicate,
  stale, mismatched, expired all fail), `failHostedStage1Attempt`,
  `recordHostedStage1Provision` (requires `grantRevocation: 'confirmed'` and
  exact commitment/plan match), `markHostedStage1HandedOff`,
  `markHostedStage1CleanupRequired`, `authorizeHostedStage1Cleanup`,
  `completeHostedStage1Cleanup` (back to `draft`, plan discarded),
  `reapHostedStage1Session` (alarm: erase / retain / replace; cleanup
  obligations are never erased), `publicHostedStage1Session`.
- `HostedStage1SessionDurableStatePort` with `read`, `compareAndSet`, `erase`
  over table `ankka_stage1_session`, `changes()` read in-transaction.

Note: `verifierHash` equals the public PKCE challenge by construction
(`pkceChallenge === sha256`). That leaks nothing beyond what Cloudflare already
sees in the authorization URL, but it is worth stating in review.

### Step 3 of the sequence: encrypted bootstrap cookie — done (2026-09-03)

Tracked edits: `crypto.ts`, `cookies.ts`, `constants.ts`. New excluded test:
`apps/installer/test/hosted-stage1-cookie.test.ts`.

- `crypto.ts` schema 10, `purpose: 'bootstrap'`, `kind: 'bootstrap' | 'cleanup'`,
  fields `sessionId` (`s1s_`), `attemptId` (`attempt_`), `state`, `verifier`,
  `expiresAt`, `planId`, `planHash`, and `capability`
  (`bootstrapId`, `capabilitySecret`, `capabilityExpiresAt`, `bootstrapNonce`,
  `ownershipWrapKey`) or `null` for cleanup attempts. Sealed under its own AAD
  (`ankka-gateway-deploy-bootstrap-cookie-v1`) with the same AES-GCM session
  key, so the legacy OAuth cookie and this one cannot open each other.
  `sealHostedStage1Cookie(key, payload, now)` / `openHostedStage1Cookie(key,
  sealed, now)` enforce the ten-minute window (`HOSTED_STAGE1_COOKIE_TTL_MS`)
  and `capabilityExpiresAt === expiresAt` for bootstrap attempts.
- `cookies.ts`: `readBootstrapCookie`, `bootstrapCookie` (Max-Age 1..600),
  `clearBootstrapCookie`; name `BOOTSTRAP_COOKIE = '__Host-ankka_gateway_bootstrap'`
  with `Path=/; HttpOnly; Secure; SameSite=Lax`.
- `hosted-stage1-session.ts`: `matchHostedStage1Cookie({ current, cookie, now })`
  exact-matches session id, attempt id, plan id/hash, and the capability
  commitment (`sha256:` of the cookie's secret vs. the stored commitment) per
  phase: `authorizing` (attempt), `provisioned` (provision, for the token-free
  readiness polling window), `cleanup_required` (cleanup attempt, no
  capability). Any other phase is a `phase` error.

### Step 4 of the sequence: `TwoStageDeploySession` — done (2026-09-03)

New excluded files:

```text
apps/installer/src/two-stage-deploy-session.ts
apps/installer/test/two-stage-deploy-session.test.ts
apps/installer/test/hosted-stage1-sql-fake.ts
```

The object is a revision-checked RPC over the pure session model and nothing
else: no provider I/O, no OAuth exchange, no cookie handling, and it never
receives a capability secret (`/bootstrap/authorize` takes only the
commitment: `bootstrapId`, `secretCommitment`, `expiresAt`). Internal origin
`https://two-stage-deploy-session.invalid`; `GET /session`; `POST`
`/initialize`, `/selection`, `/plan`, `/bootstrap/authorize`,
`/bootstrap/consume`, `/attempt/fail`, `/bootstrap/provision`,
`/bootstrap/handed-off`, `/cleanup/require`, `/cleanup/authorize`,
`/cleanup/complete`. Bodies are strict valibot schemas (256 KiB cap); every
write is `compareAndSet` on the revision read in the same request and returns
409 `session_conflict` on a race. Model errors map to 400 `session_invalid`,
409 `callback_invalid` (duplicate callback), 409 `session_conflict` (phase),
410 `session_expired`. The alarm is set to the exact next deadline (session
expiry, attempt expiry, or capability expiry); `alarm()` erases dead sessions
(`erase` + `deleteAll` + schema re-init), escalates a lapsed capability to
`cleanup_required`, fails an expired attempt, and never drops a cleanup
obligation. `TwoStageDeploySessionClient` is the typed same-release client
for the Worker; it re-parses every response through the session parser.

`hosted-stage1-session.ts` now exports `HostedStage1CapabilityCommitment`,
`HOSTED_STAGE1_FAILURE_CODES`, `HOSTED_STAGE1_CLEANUP_REASONS`, and
`authorizeHostedStage1Bootstrap` takes `capability` (commitment) instead of
the full secrets. The durable port accepts the minimal `sql`/`transactionSync`
surface (`HostedStage1SessionSqlStorage`) so fakes need no assertions.

### Step 5 of the sequence: clean hosted HTTP runtime — done (2026-09-03)

New excluded files:

```text
apps/installer/src/two-stage-runtime.ts
apps/installer/src/ownership-issuer-key.ts
apps/installer/test/two-stage-runtime.test.ts
apps/installer/test/ownership-issuer-key.test.ts
```

Tracked edit: `abuse-controls.ts` now exports `AbuseControlEnv` (the exact
bindings the rate limits read) so the clean runtime reuses the same
anonymous/read/mutation limits and authenticated session ids without the
legacy env type.

`two-stage-runtime.ts` — `createTwoStageDeployRuntime(pin, deps)` and
`createTwoStageDeployEntrypoint(activation, deps)` (disabled arm = zero-write
health/unavailable shell, reads no binding or dependency). Route allowlist
`TWO_STAGE_API_ROUTES`: `GET /health`, `GET /api/session` (mints the
authenticated `__Host-` session cookie, auto-rotates an expired session),
`PUT /api/selection`, `POST /api/plan` (30-minute static plan from the pinned
release), `POST /api/bootstrap` (re-freezes the plan if it cannot outlast the
capability, mints secrets, DO authorize, seals the schema-10 cookie, returns
the `workers-scripts.write` authorization URL), `POST /api/cleanup`,
`GET /oauth/callback`, `GET /api/bootstrap/handoff`; every other `/api/*` is
404, wrong methods 405, and non-API GET/HEAD goes to the signed installer
asset index. Mutations require `Origin: https://deploy.ankka.ai`, a
same-origin `Sec-Fetch-Site` when present, and `x-csrf-token` equal to
`deriveCsrfToken(key, sessionId)` (constant-time), then the mutation rate
limit.

Callback: exact query parse (only `code`/`state`/echoed exact scope or the
standard denial fields) → open cookie → `state` must equal the cookie's →
`matchHostedStage1Cookie` → DO `consumeCallback` before any exchange →
denied ⇒ `failAttempt(authorization_rejected)`; bootstrap ⇒ load snapshot,
`importOwnershipIssuerKey`, `provisionHostedStage1` in this request, DO
`recordProvision`, 303 to `/result` keeping the cookie; failure ⇒
`failAttempt` (`grant_invalid` / `revocation_unconfirmed` /
`provision_failed`) and clear cookie; cleanup ⇒ injected
`TwoStageCleanupExecutor` then DO `completeCleanup`. A replayed callback after
provisioning is 409 and keeps the cookie (it is still needed for the handoff).
Handoff: match in `provisioned`, `completeHostedStage1Handoff` (token-free),
`bootstrap_not_ready` ⇒ 503 `{status:'not_ready', retryAfterMs:3000}` with the
cookie kept; `bootstrap_failed` ⇒ DO `requireCleanup(handoff_rejected)` and
502; success ⇒ DO `markHandedOff`, 200 `{handoffUrl}` (fragment carries the
capability; never persisted) and the cookie is cleared.

`ownership-issuer-key.ts` — `importOwnershipIssuerKey({ privateKeySeed,
publicKey, keyId })`: 32-byte base64url seed → PKCS#8 → derives the public key
via JWK and verifies it against the pinned public key before importing a
non-extractable signing key. Env bindings the runtime validates:
`CLOUDFLARE_OAUTH_CLIENT_ID/SECRET`, `CLOUDFLARE_CUSTOMER_OAUTH_CLIENT_ID`,
`DEPLOY_SESSION_ENCRYPTION_KEY`, `CLOUDFLARE_OWNERSHIP_ISSUER_PRIVATE_KEY`
(seed), `CLOUDFLARE_OWNERSHIP_ISSUER_PUBLIC_KEY`,
`CLOUDFLARE_OWNERSHIP_ISSUER_KEY_ID`, `TWO_STAGE_DEPLOY_SESSION`,
`GATEWAY_RELEASE_BUCKET`, and the three rate-limit bindings.

Review note: `oxlint .` (used by `check:fast`) honours `.git/info/exclude`, so
the excluded candidate files are NOT linted by the repo gate. Lint them
explicitly (`npx oxlint <files> --deny-warnings`) until they are tracked; the
whole candidate set was clean on 2026-09-03.

### Step 6 of the sequence: lost-cookie cleanup executor — done (2026-09-03)

New excluded files: `apps/installer/src/hosted-stage1-cleanup.ts`,
`apps/installer/test/hosted-stage1-cleanup.test.ts`. Two candidate helpers
were exported for reuse: `exactCustomerBootstrapVersionBindings` and
`exactCustomerBootstrapModule` (readback), and
`expectedCustomerBootstrapBindings` (coordinator).

`executeHostedStage1Cleanup({ code, verifier, oauth, transport, session,
bundle, customerOauthClientId, issuerKeyId, issuerPublicKey, now, wait? })`
runs under `executeHostedBootstrapGrant` (exactly `workers-scripts.write`,
single account, no refresh token, revoke in `finally`). Requires the session
to be `cleanup_required` with a consumed (`exchanging`) cleanup attempt.
Order: account reassert → `GET /workers/workers/{name}` (id, name, exact tag
set incl. `ankka-bootstrap-id:<bootstrapId>`, no tail consumers) → active
deployment must be the recorded version at 100 % → version read-back with
the exact expected binding set and the signed bootstrap module hash →
`inspectAdminStateDurableObjectNamespace` with the recorded namespace id and
name (ambiguity ⇒ `ambiguous`) → only then: workers.dev disable + verify →
direct-upload the signed `payload/worker-retirement/index.js` with
`exports.AdminState = { state: 'deleted', type: 'durable-object' }` → wait for
the namespace to leave the catalogue → `DELETE /workers/workers/{id}` → prove
absence by id, by name, in the script list, and in the namespace list, with
bounded retries. Failure codes: `invalid`, `account_mismatch`,
`identity_mismatch`, `ambiguous`, `provider_rejected`, `provider_unknown`,
`absence_not_proven` (each with a `stage`). No mutation is sent on any
mismatch; the fresh grant is revoked on every path. The runtime's default
`TwoStageCleanupExecutor` now calls it; the callback then records DO
`completeCleanup` (back to `draft`, plan discarded) or
`failAttempt(cleanup_failed)`.

### Step 7 of the sequence: entrypoint cut — done (2026-09-03), still disabled

Tracked edits: `src/reviewed-entrypoint.ts` now imports only
`createTwoStageDeployEntrypoint` (two-stage runtime) and re-exports
`TwoStageDeploySession`; it no longer references `reviewed-runtime.ts`,
`index.ts`, or the legacy Durable Object. `wrangler.toml` main is
`src/reviewed-entrypoint.ts`, the Durable Object binding is
`TWO_STAGE_DEPLOY_SESSION` / `TwoStageDeploySession`, migration `v1` declares
`new_sqlite_classes = ["TwoStageDeploySession"]` (clean, no legacy class,
per the no-dual-routing decision), and there is still no production route.
`REVIEWED_GATEWAY_DEPLOY_ACTIVATION` is unchanged (`{enabled:false, pin:null}`).
`test/runtime-boundary.test.mjs` asserts the new main, binding, class,
migration, and entrypoint imports. New excluded test
`test/two-stage-entrypoint.test.ts` proves the checked-in default export is
the zero-write shell against a poisoned env (every read throws): `/health`
answers `{ok:true, mutationsEnabled:false}` and every other path is 503
`release_unavailable` with no cookie.

`wrangler deploy --dry-run --config wrangler.toml` bundles the new main
(~386 KiB vs ~1 MiB for the legacy main) with the expected bindings.

Not changed on purpose: `scripts/generate-reviewed-canary.mjs` (the live
deploy.ankka.ai artifact generator) still emits entry modules that import
`GatewayDeploySession` + `createReviewedGatewayDeployRuntime` and a Wrangler
config with the `GATEWAY_DEPLOY_SESSION` binding. Switching it to
`createTwoStageDeployRuntime` + `TwoStageDeploySession` is part of the
activation review, together with the new secret bindings
(`CLOUDFLARE_CUSTOMER_OAUTH_CLIENT_ID`, `CLOUDFLARE_OWNERSHIP_ISSUER_*`) and
the `auth.ankka.ai` route. `src/index.ts` and `reviewed-runtime.ts` remain in
the tree only for the legacy suite; they are no longer reachable from any
checked-in Wrangler main.

### Step 8 of the sequence: installer UX rewrite — done (2026-09-03)

Tracked edits: `payload/installer/index.html` (rewritten),
`payload/installer/assets/installer-cafdf608.js` (new and deliberately left
UNTRACKED like every other uncommitted change here; it replaces the deleted
`installer-bee893ae.js`, so do not `git clean` it away), `test/release-payload-layout.test.mjs`
(installer file list, tree fingerprint, and the installer contract test
rewritten for the two-stage API), `test/installer-webmcp.test.mjs` (rewritten
for the new tools), and `test/installer-management-redirect.test.mjs`
(deleted: the `/manage` runtime-callback flow no longer exists on
deploy.ankka.ai). The CSS asset is byte-identical, so its hashed name and the
typography/accessibility floor assertions are unchanged.

The page is one guided flow over the new contract: `/` describes the gateway
(name, storefront domain, administrator email; management/portal hostnames
are derived as `manage.<domain>` / `mcp.<domain>` and editable) →
`PUT /api/selection` + `POST /api/plan` → `/review` (plan summary, expiry,
"Connect Cloudflare") → `POST /api/bootstrap` → `/deploy` (approval link,
ten-minute expiry copy, "Start a fresh approval") → Cloudflare → callback →
`/result`, which polls `GET /api/bootstrap/handoff` token-free and, on
`ready`, validates the handoff URL (https, exact recorded Gateway origin,
`/__ankka/install`, no query, fragment only) and navigates the browser to it
("Finish secure setup"). `failed` shows the failure and a fresh approval;
`cleanup_required` explains the removal and drives `POST /api/cleanup`;
`handed_off` links to the Gateway origin. A rejected handoff stops polling
(no retry loop); `bootstrap_not_ready` re-polls at the server's
`retryAfterMs` (3–15 s). Copy states plainly: two approvals, both temporary,
no stored Cloudflare token, Team membership managed in Cloudflare Access.
The footer says the installer sends no analytics, which is true of the new
runtime (no analytics sink is wired); if the hosted funnel analytics are
re-added, both the runtime and this notice change together.

WebMCP tools (registered with an abort signal, unregistered on pagehide):
`get_installer_status`, `configure_gateway`, `begin_authorization`,
`finish_secure_setup` (navigates this browser; never returns the handoff to
the caller), `begin_cleanup`. Agents receive Cloudflare approval links to hand
to the user and never open them.

No `/manage`, `/oauth/handoff`, `/api/discovery`, `/api/deploy`,
`/api/management/*`, `/api/uninstall*`, or `/api/returning-uninstall*`
reference remains in the payload; the contract test asserts their absence.

### Step 9 of the sequence: relay topology qualification — offline proof done, live run pending (2026-09-03)

New excluded files: `apps/installer/test/two-stage-relay-topology.test.ts`
and `docs/CLOUDFLARE_RELAY_TOPOLOGY_QUALIFICATION.md` (the live runbook).

The test drives the production customer relay clients over absolute public
HTTPS URLs (no Service Binding) into the real `createCloudflareAuthWorker`
with the real `CloudflareGatewayOwnershipChallenge` class; only SQLite storage
and the dash.cloudflare.com browser hop are stand-ins. It proves the fixed
authorization (public client id, relay redirect URI, exact install scopes,
S256, sealed state), code-only relay to the certified Gateway callback,
one-fixed-error denial forwarding, tampered/duplicate/expired state never
redirecting, customer-side single-use callback consumption, hardened headers
with no CORS or cookie, fixed-origin-only service, and a source scan of the
relay module set for any token endpoint, client secret, or logging.

**Defect fixed:** `cloudflare-gateway-ownership-challenge-durable-state.ts`
accepted only `LATER_CUSTOMER_CLOUDFLARE_OPERATIONS` (schema picklist and SQL
`CHECK`), so the real relay answered every Stage 2 `install` challenge with
400 `ownership_proof_rejected` and Stage 2 could never start. The live
ownership canary used a disposable relay and only exercised `upgrade`. The
store now accepts `CUSTOMER_CLOUDFLARE_OPERATIONS`; its test covers `install`.
Any relay Durable Object created before this fix must be recreated (its table
`CHECK` is baked in).

**Live run (2026-09-03): approval and decline paths PASSED** over public
HTTPS with the real auth entrypoint on a disposable custom domain and a
disposable Gateway Worker (same Ankka account, so cross-account isolation is
still unproven). One client-side observation to chase before activation: the
operator's Chrome profile got an empty 403 on the final hop to the Gateway
host that curl and another Chromium did not; details in the runbook.
Second live defect found and fixed: Cloudflare echoes a `scope` parameter on
the code response and the relay callback accepted only `code`+`state`
(400 `relay_rejected`). `cloudflare-code-relay.ts` /
`cloudflare-code-relay-http.ts` now accept an optional echoed `scope`,
validate every echoed scope against the sealed operation's fixed ceiling, and
still forward only `code`+`state`; offline test added. Details and the
remaining decline/teardown steps are in the qualification runbook. The
qualification tooling lives in the excluded `apps/installer/qual/` directory
(secrets under `qual/secrets/`, mode 600; delete with the teardown).

### Step 10 of the sequence: activation review change — done (2026-09-03), activation still disabled

One reviewed change covering the three items deferred from step 7. Nothing
was deployed; `REVIEWED_GATEWAY_DEPLOY_ACTIVATION` is still
`{enabled:false, pin:null}`, and the real route and OAuth clients are
untouched.

**Generator switch (tracked: `scripts/generate-reviewed-canary.mjs`,
`test/generate-reviewed-canary.test.mjs`).** The live deploy.ankka.ai
artifact now bundles `createTwoStageDeployRuntime` (active) /
`createTwoStageDeployEntrypoint` (rollback) with `TwoStageDeploySession`;
the Wrangler config binds `TWO_STAGE_DEPLOY_SESSION` /
`TwoStageDeploySession` (migration `v1`, sqlite), keeps the three rate
limits, the read-only release bucket, the Custom Domain route, and the
`CLOUDFLARE_OAUTH_CLIENT_ID` var. The hosted analytics dataset and its two
vars are gone (the runtime has no sink and the installer page says so). The
six request-time bindings are provisioned outside the repository with
`wrangler secret put` and are named in a comment only:
`CLOUDFLARE_OAUTH_CLIENT_SECRET`, `DEPLOY_SESSION_ENCRYPTION_KEY`,
`CLOUDFLARE_CUSTOMER_OAUTH_CLIENT_ID`,
`CLOUDFLARE_OWNERSHIP_ISSUER_PRIVATE_KEY`,
`CLOUDFLARE_OWNERSHIP_ISSUER_PUBLIC_KEY`,
`CLOUDFLARE_OWNERSHIP_ISSUER_KEY_ID`. The public key, key id, and customer
client id are not secrets, but provisioning them the same way keeps the
artifact bound to the pin alone and survives redeploys (Wrangler keeps
`secret_text` bindings). The generator's secret scan forbids an assignment
of any of them; the provenance check now requires
`src/two-stage-runtime.ts` and `src/two-stage-deploy-session.ts` in the
bundle inputs and rejects `src/reviewed-runtime.ts`,
`src/durable/gateway-deploy-session.ts`, `src/index.ts`, and
`src/hosted-installer-analytics.ts`; the self-containment check rejects any
`GatewayDeploySession` or analytics identifier in either module. The
Wrangler schema contract no longer inspects analytics datasets.

**Auth route restored (excluded: `wrangler.auth.toml`).** `auth.ankka.ai` is
back as the relay's only `custom_domain` route. The topology test now
asserts exactly that route and nothing else; `wrangler deploy --dry-run`
of the config succeeds (~118 KiB, one Durable Object binding). The
qualification runbook's "declares no route" sentence was updated.

**Finding fixed on the way (tracked: `src/two-stage-runtime.ts`,
`test/two-stage-runtime.test.ts`,
`test/offline-two-release-origin-lifecycle.test.mjs`).** The two-stage
runtime did not serve `GET /api/releases/{canary|stable}`, which every
installed Gateway polls for self-update (`discoverRuntimeUpdate` in
`payload/worker/index.js`). Activating it would have silently disabled
updates for all installs. The route is now in `TWO_STAGE_API_ROUTES`, served
token-free from the pinned verified bundle before any binding besides the
bucket is read (a bucket-only env is tested), 404 `release_unavailable` for
the other channel, 405 on non-GET, 404 with any query string. The offline
two-release lifecycle test drives release A's real customer Worker `/api/update`
through the generated two-stage Worker again; its legacy
`/api/management/authorize` sections (rollback/source/teardown handoffs) were
removed, since that surface is retired in the two-stage runtime, and the
test now asserts the retired route answers 404.

**Runbook.** `~/Documents/ankka-releases/RUNBOOK.md` step 7 gained the
provisioning list for both Workers (deploy: the six above; relay: customer
client id, issuer public key and key id, `CLOUDFLARE_RELAY_STATE_KEY`,
`CLOUDFLARE_RELAY_TICKET_KEY`) and the note that the relay deploy is part of
the same activation ceremony.

**Gates.** `npm run check:fast` exit 0 (lint, typecheck ×4, boundary,
builds, admin 302, adapter 15, connectors 631, core 685). Installer suite
`npx vitest run`: 93 files, 964 tests, all passed. Explicit oxlint of every
touched excluded file clean.

**Still open before the route can be enabled** (unchanged from the
definition of done): the operator-browser 403 on the Gateway hop (check
Security → Events); cross-account isolation of the relay (both
qualification Workers lived in the Ankka account); the production public
PKCE client for Stage 2 (redirect `https://auth.ankka.ai/oauth/callback`,
exact seven install scopes) does not exist yet; the production issuer key
pair has not been generated; and the activation pin itself, which stays a
code change.

### Next

Activation ceremony, in this order and only after the open items above:
create the Stage 2 public client and the issuer key pair; provision the
relay's five bindings and deploy `wrangler.auth.toml`; provision the deploy
Worker's six bindings; run the release ceremony (runbook step 7) with the
two-stage artifact; verify `/health`, `/api/releases/canary`, and a full
install against a disposable customer account; then tear the disposable
resources down.

### Operator checklist toward activation (written 2026-09-03)

Prepared offline: with `.git/info/exclude` lifted for everything except
`apps/installer/qual/`, the public-boundary check passes for 510 files, and no
account id, operator email, workers.dev subdomain, or disposable client id
appears in any candidate file. The permission classifier refused the
assistant two actions on purpose: writing a secrets-provisioning helper and
deploying the production relay. Both are operator steps.

1. Land: un-exclude everything except `qual/`, `git add`, commit, push,
   PR, merge when `check` is green. `payload/installer/assets/installer-cafdf608.js`
   is untracked and must be added too.
2. Dashboard: Security → Events for the 403; create the Stage 2 public PKCE
   client (`https://auth.ankka.ai/oauth/callback`, seven install scopes,
   public visibility needs `ankka.ai` domain verification); confirm the
   Stage 1 client `6ace98c3…` is public.
3. Relay: `wrangler deploy --config apps/installer/wrangler.auth.toml`
   (takes over the existing proxied `auth.ankka.ai` record), then
   `wrangler secret put` for `CLOUDFLARE_RELAY_STATE_KEY`,
   `CLOUDFLARE_RELAY_TICKET_KEY` (random 32 bytes base64url each),
   `CLOUDFLARE_OWNERSHIP_ISSUER_PUBLIC_KEY`,
   `CLOUDFLARE_OWNERSHIP_ISSUER_KEY_ID`, `CLOUDFLARE_CUSTOMER_OAUTH_CLIENT_ID`.
   `/health` must answer `{ok:true, role:'cloudflare-code-relay', tokenExchange:false}`.
4. Deploy Worker: decide delete-and-recreate (recommended) versus a `v2`
   migration in the generator; the live Worker already applied `v1` for
   `GatewayDeploySession`, so the generated `v1` for `TwoStageDeploySession`
   is skipped and the binding fails. Then provision the six bindings listed
   in step 10 (issuer seed = the same key pair as the relay's public key).
5. Release ceremony (runbook step 7) from the merged commit; verify
   `/health`, `/api/releases/canary`, and the installer page.
6. Full install from a second Cloudflare account that owns a real zone
   (cross-account isolation), then tear down and record the evidence here.

### Activation log

- 2026-09-03: PR #47 merged (squash `236462b`). Stage 1 client confirmed
  public and verified. Security → Events shows no edge block for the
  qualification host, so the operator-browser 403 was client-side.
- 2026-09-03: Stage 2 public PKCE client created by the operator (redirect
  `https://auth.ankka.ai/oauth/callback`, seven required install scopes,
  client URL `https://ankka.ai`, no post-logout or CORS entries).
- 2026-09-03: relay deployed from `wrangler.auth.toml` with its Custom
  Domain; all five bindings provisioned as secrets (issuer key id
  `ankka-ownership-issuer-2026-09-v1`; the issuer seed lives in the
  operator's Bitwarden). Verified live: `/health` 200
  `{ok:true, role:'cloudflare-code-relay', tokenExchange:false}` with
  `no-store` and `no-referrer`; unknown paths 404 `no-store` with no cookie
  or CORS header; the workers.dev alias answers 404. Pending: deploy Worker
  cut decision, its six bindings, release ceremony, second-account install.
- 2026-09-03: release gateway-v0.1.21 cut from main `868e9c6` (candidate
  manifest `cb63c204…`, artifact `1f53c568…`, deterministic across two
  builds). Two tooling defects surfaced on the way and were fixed on main:
  the signer's secret scan misread two constant names as credentials
  (PR #50) and the local R2 publisher capped a release at 2 MB while the
  source-built customer bundles put v0.1.21 at 3.6 MB (PR #51, cap now
  6 MB with a derived module cap). Signed by the operator, published
  create-only to R2 (receipt `status: published`, envelope digest verified
  by direct object read), temporary publisher removed.
- 2026-09-03: the legacy `ankka-gateway-deploy` Worker was deleted (its
  `v1` migration for the legacy class would have blocked the new binding)
  and the reviewed canary artifact deployed fresh: two-stage runtime,
  `TwoStageDeploySession`, release bucket, three rate limits, Custom Domain.
  Live checks: `/health` `{ok:true, mutationsEnabled:true}`,
  `/api/releases/canary` reports gateway-v0.1.21, `/` serves the new
  installer page, `/api/releases/stable` 404, `/api/session` 500
  `internal_error` (fail-closed until the six bindings are provisioned).
  Pending: the six deploy-Worker bindings (Stage 1 client secret must be
  regenerated, the old one died with the Worker), the GitHub release
  (prepare/validate/publish refused to the assistant by the classifier),
  and the second-account install test.
- 2026-09-03: GitHub release `gateway-v0.1.21` published (immutable
  prerelease, five assets). The operator provisioned the deploy Worker's six
  bindings; the issuer pair was regenerated as
  `ankka-ownership-issuer-2026-09-v2` (the v1 seed was never stored) and the
  relay updated to the same public key and key id. Live: `/api/session`
  issues a session; a token-free probe walked selection → plan (pinned to
  v0.1.21) → bootstrap and received the Stage 1 authorization URL
  (`dash.cloudflare.com/oauth2/auth`, client `6ace98c3…`, scope
  `workers-scripts.write` only, S256, callback `/oauth/callback`). Ceremony
  evidence and the rollback artifact live in
  `~/Documents/ankka-releases/gateway-v0.1.21/` (`live-activation/`).
  Remaining before the install is declared production-ready: one complete
  install from a second Cloudflare account owning a real zone.
- 2026-09-03: legacy hosted runtime retired from the tree: `src/index.ts`,
  `src/durable/gateway-deploy-session.ts`, `src/reviewed-runtime.ts`, the
  hosted analytics sink, the hosted install/uninstall journals and executors,
  the returning-uninstall surface, discovery, the legacy relays, `env.ts`,
  `session.ts`, and their 26 test files (about 32,000 lines). Nothing
  reachable from a checked-in Wrangler main or a release script changed;
  `abuse-controls.ts` and `exact-release-bundle.ts` now declare their own
  environment types, and the shared test fixtures lost the legacy Durable
  Object fakes. `cloudflare-uninstall-finalizer.ts` stays: it is the
  two-stage hosted finalizer, not yet wired to a route.
- 2026-09-03 decision (operator): deploy.ankka.ai serves one channel. The
  hosted runtime keeps a single pin; the first stable release repins the
  site to stable, after which `/api/releases/canary` answers 404 and canary
  installs stop updating (none exist in production). Canary releases remain
  published for testing on isolated hostnames. No runtime change follows
  from this; the alternatives (two pins, or a separate canary site) were
  declined.
- 2026-09-03: the first install from a second Cloudflare account failed
  right after the consent approval. The result page said the shell could not
  be installed with the temporary permission, `/api/session` recorded
  `provision_failed` / `internal_error`, and no `ankka-gateway-*` Worker
  existed in the customer account, so nothing after deployment was involved.
  Cause: `resolveSingleAuthorizedCloudflareAccount` runs between the approval
  and the deployment, inside `grant.withAccessToken` but outside the try that
  wraps `deploy()`, and throws `CustomerCloudflareGrantError` rather than
  `DeployError`; `stableError` filed it under the catch-all. PR #57 translates
  it at that boundary: `account_ambiguous` becomes `target_account_ambiguous`
  (403, shown to the operator as `grant_invalid`), any other grant error
  becomes `oauth_exchange_failed` with reason `account_read_<code>`, and
  nothing is deployed in either case. The reviewed canary was regenerated from
  main `fe3fff8` into `live-activation-3/` and validated; its delta against
  the live version `0fff05d6` is 60 bundle lines: this fix, the reason
  plumbing of PR #54 and PR #55 (the live artifact was built 30 s after #54
  merged and carries neither), and one dead constant dropped by the
  retirement. The deploy was refused to the assistant by the classifier and
  is pending for the operator, followed by the install retry, after which
  `failure.reason` on `/api/session` names the failing step. If it reads
  `target_account_ambiguous`, the approving user can see more than one
  account and the refusal is by design; whether such a customer may name the
  target account instead of being turned away is an open product decision.
- 2026-09-03 (evening): the hosted runtime was redeployed with the
  account-read translation (#57); the retry from the second account then
  reported `provision_failed` / `account_read_provider_unavailable`. PR #61
  made the account read carry the provider's HTTP status and numeric error
  code, and the next retry read
  `account_read_provider_unavailable_not_json_http_200`: Cloudflare answered
  200 and our reader failed. Root cause: `withDeadline` aborts its controller
  in `finally` whichever way the operation settles, and workerd and Node then
  error any response body stream that is still open, so every call site that
  took the `Response` out of `withDeadline` and read the body afterwards
  failed on every real fetch. Reproduced in Node and in workerd via
  `wrangler dev`; tests never saw it because their fake transports ignore the
  signal. PR #63 added `fetchBoundedText`, which reads the bounded body inside
  the deadline, and used it at the five sites with that shape: the Stage 1
  account read, the customer token exchange, the zone resolution, the relay
  start and the post-deploy health poll, with signal-aware regression tests
  that failed before the change. Each fix was activated by regenerating the
  reviewed canary from main and redeploying `ankka-gateway-deploy` (the
  assistant ran these deploys under an operator-granted allow rule). The
  third retry from the second account reached `phase: provisioned` with no
  failure: the shell Worker exists on the customer's `workers.dev` subdomain
  and the hosted health poll passed, so Stage 1 is proven across accounts.
  The shell shipped in gateway-v0.1.21 is built from
  `customer-gateway-bootstrap-entrypoint.ts` and carries the same flaw in its
  token exchange, zone resolution and relay start, so Stage 2 needs
  gateway-v0.1.22: the candidate was built from main `840defb` (manifest
  `47fe8738…`, deterministic across two dry runs) and the SBOM generated;
  signing, the R2 publication, the GitHub release and the repin are the
  operator's next ceremony.
- 2026-09-03 (night), correction and continuation: the previous entry's
  claim that the hosted health poll passed was wrong. The third retry reached
  `phase: provisioned` because the shell existed, but the readiness read was
  made against `/health`, which on the deployed shell is answered by the
  static-assets SPA fallback (only `/__ankka/*` and `/api/*` run the Worker
  first), and its `redirect: 'error'` option is rejected by workerd. PR #65
  reads readiness from `/__ankka/install/status` with `redirect: 'manual'`,
  names the handoff step in the session, and adds `readiness_*` reasons.
  PR #66 binds install relay tickets to the certificate's bootstrap callback
  (the shell's own origin) instead of the management callback, which the
  relay had been refusing at the install start. gateway-v0.1.22 was signed by
  the operator, published (R2 create-only, immutable GitHub prerelease, source
  `840defb`) and pinned; the relay was redeployed from `b35c6c2`. With that,
  Stage 2 from a second account ran through the shell's `continue` and
  `oauth/start`, the relay's ticket and start routes, and Cloudflare's consent
  form. Three findings: (1) the hosted result page redirects the moment the
  server-side readiness poll succeeds, before the new `workers.dev` hostname
  has propagated to the browser's vantage point, so the first load can be
  Cloudflare's placeholder page and a reload is needed (open); (2) the Stage 2
  OAuth client was private, so Cloudflare's consent refused users outside the
  parent account until the operator made it public (client URL domain
  verification through the `cloudflare_oauth_client_publisher` TXT record);
  (3) after consent, the shell's callback fails inside the payload's bootstrap
  at the portal create and is recorded as `provider_recovery_required`, while
  the same create succeeds with an account API token, and nothing named the
  provider outcome.
- 2026-09-04: PR #67 makes that failure name itself. The payload returns a
  fixed-word `provider` detail (kind, step, status, HTTP status, provider
  code) beside its 409; the shell folds it into a secret-free `failureReason`
  (`payload_<kind>_<step>_<status>[_http_n][_code_n]`, otherwise
  `converge_<code>`, `grant_<code>`, `payload_request_<stage>_<outcome>` or
  `unexpected`), stores it next to `failureCode`, and exposes it on the
  callback answer and on `/__ankka/install/status` as
  `failure: { code, reason }`. The payload still logs nothing.
  gateway-v0.1.23 was cut from `d6a9b69` (manifest `c9bb3097…`, identical
  across a dry run and the written build; artifact `c9d49faa…`), published to
  R2 and GitHub, and pinned on deploy.ankka.ai (version `43d11a51`). Operator
  decision: a second release signing key, `release-2026-09-dev1` (public key
  `WGwI3OF_w3t_v20ybyvrXbm0j1akX_D7_whaImOg5rI`), lives in the operator's
  local keychain so the assistant can run the canary ceremony end to end;
  v0.1.23 is the first release signed with it. The production key
  `release-2026-08-v1` stays in the operator's vault for stable. Because
  deploy.ankka.ai serves the canary channel, dev-key-signed releases reach
  real installs; revoking the key means deleting it and repinning. Next: one
  browser install run, then read `failure.reason` from the shell's status
  route and fix the cause. Also open: the lifecycle canary client reports a
  successful run as unknown.
- 2026-09-04 (early morning), correction and continuation: the first
  install on gateway-v0.1.23 failed the Stage 1 readiness read, and the cause
  was PR #67 itself: the shell's status answer gained a `failure` field while
  the hosted runtime parsed that answer with its own strict schema and
  reported `readiness_schema_invalid` as an identity mismatch; both suites
  were green because each side used a hand-written fixture. PR #69 moved the
  schema into one module that the shell types its answer against and the
  hosted runtime parses with. PR #70 split CI into parallel jobs on a cached
  module tree (pull-request runs take about two minutes) and the reviewed
  canary is now generated from the rebased branch head while the merge
  trails, so testing no longer waits for a merge. The next run got through
  both authorizations and failed with `payload_request_response_rejected`:
  the converger does not post over the network, the shell entrypoint runs
  the payload's bootstrap in-process and had handed it the shell's own
  Stage 1 bindings, which carry no zone id, zone name or Zero Trust flag, so
  the payload's strict environment parser refused before reading the
  request; this path had never passed. PR #71 completes that environment for
  both in-process calls and adds a contract test that drives the converger's
  real request into the shipped payload module (gateway-v0.1.24). The next
  run failed at the grant's zone check: the filtered zone read under the
  Stage 2 token answered without the approved zone while the same query
  under an API token returns it; PR #72 falls back to listing the grant's
  zones and matching name, account and status locally, with a detail naming
  the disagreeing field or the visible zone count (gateway-v0.1.25). The
  next run resolved the zone, the payload created the portal, its Access
  application and policy and the DNS record under the OAuth token, and the
  converger's immediate receipt re-verification returned false as a bare
  boolean; it had no test. A root test now proves the verification accepts
  the receipt the bootstrap just wrote against the fake provider, PR #73
  makes it return a fixed-word reason that the converger reports as
  `verify_<resource>_<status>`, retries a refused token revocation before
  reporting it unconfirmed, and adds a token-mode live harness under
  `apps/installer/test-live/` that runs the converger's bootstrap request
  into the shipped payload against a test account with an API token, no
  browser and no consent (gateway-v0.1.26, pinned as version `93fa6a7d`).
  Lesson for every shell, hosted and payload boundary: one shared schema
  and one test that runs the real counterpart, never two fixtures.
- 2026-09-04 (before dawn): the first complete Stage 2 convergence, in token
  mode. A full live harness (`apps/installer/test-live/stage2-full.live.ts`)
  runs the hosted Stage 1 code against a test account with an API token
  standing in for the grant (only the OAuth token and revoke endpoints and
  the account list are answered locally), deploys the real shell Worker,
  completes the handoff against it with the same readiness poll, then runs
  the Stage 2 converger in-process against the real provider with the
  shipped payload. It reached the final runtime self-update, which had never
  been exercised against Cloudflare, and found two provider-facing defects
  (PR #76): the inherit bindings named the exact previous version id, which
  the script upload API now refuses (code 10057, only `latest`), and the
  bootstrap nonce secret survived the upload because Cloudflare never drops
  secrets on a deployment, so the exact readback rightly refused the version.
  Inheriting from `latest` (the caller has just proven latest is the verified
  bootstrap version and reads the result back exactly) and deleting the nonce
  through the Workers Secrets API after the upload made the harness converge
  end to end in about two minutes: shell deploy, readiness, handoff,
  ownership readback, zone, Access organization, management application and
  policy, portal, application, policy and DNS record, receipt verification,
  custom domain, final runtime, workers.dev disable, terminal verification,
  and cleanup. Shipped as gateway-v0.1.27, pinned on deploy.ankka.ai
  (version `22f18653`). The first browser install driven by the assistant
  (Claude in Chrome, test account) completed Stage 1 from the hosted page;
  the page's handoff poll then reported an internal error although the
  handoff endpoint could release the one-time link, and the diagnostic read
  of that endpoint consumed the link. Open: the exact reason the page's poll
  failed (console tracking starts before the next attempt), a way to start
  over from a `handed_off` session before it expires, and showing the
  server's failure reason on the result page.
- 2026-09-04 (dawn), first real install run end to end by the assistant:
  on gateway-v0.1.27 the browser flow (Claude in Chrome on the test
  account) completed both consents; the hosted page's handoff poll
  navigated to the shell by itself this time, the shell's callback ran the
  converger, and the payload's bootstrap created the portal, its Access
  application and policy and the DNS record under the OAuth token. The
  run stopped at the receipt re-verification with
  `verify_portal_access_application_unknown`, plus `revocation_unconfirmed`:
  the discovery of the just-created application got an answer that settled
  nothing (a rate limit, a 5xx or a body that was not JSON) and counted it
  as a failure at once. PR #78 makes the verification read such an answer
  again up to three more times with a short back-off and name a resource
  that never settles with the last HTTP status and provider code; the grant
  keeps the last refused revocation's status as the `revoke_failed` detail
  and the callback reports it when the convergence itself succeeded
  (gateway-v0.1.28, version `26dbaf1d`). The full token-mode harness passes
  against v0.1.28. Open: why the OAuth-token discovery is unsettled where
  the API-token harness never is, and the refused revocation.
- 2026-09-04 (morning), root cause of the unsettled discovery and the
  refused revocation, both at once: the customer shell ran the whole Stage 2
  convergence inside the OAuth callback invocation, and a Workers Free
  account allows 50 subrequests per invocation. The token-mode harness
  counted the convergence at 110 provider calls, plus the exchange, the
  account check and the revocation; call 51 falls inside the receipt
  re-verification, exactly where both real runs stopped, and the runtime
  throws `Too many subrequests` there, which the payload can only report as
  an unsettled answer and the grant as a refused revocation. Two throwaway
  probe Workers on the test account confirmed the budget (50, then the
  throw), that every Durable Object request and every alarm invocation has
  its own budget, and that object memory survives back-to-back alarms. The
  API-token harness never saw it because Node has no such budget. PR #80
  splits the convergence into passes: the converger takes fixed checkpoints
  and pauses after the journal transition they name, proving each resource
  once per pass; the callback arms the attempt, exchanges, checks the
  account and hands the grant to a driver that keeps it in object memory and
  re-arms an alarm after every paused pass; the browser lands on a page that
  follows the status route. Measured against the real provider, the passes
  cost 25, 21, 22 and 28 provider calls (96 in all; the single run cost 110). The final runtime upload and
  everything after it share one pass so the object never resumes on new code
  without its grant; a lost grant settles `INCOMPLETE` with `grant_lost`.
  Lesson: the customer's plan limits are part of the contract; a harness in
  Node proves the provider calls, not the platform they run on. Open: the
  recovery router in the final runtime still converges in one invocation.
- 2026-09-04 (08:35), fourth real install, on gateway-v0.1.29: the browser
  ran both consents, the callback answered at once with the progress page,
  and the passes created everything under the OAuth token, verified the
  receipt, attached the custom domain and uploaded the final runtime; the
  management hostname answered with the Access login for the management
  application. The last pass then died: Cloudflare restarts a Durable
  Object as soon as its Worker has a new version and refuses storage to the
  in-flight pass (documented under the object lifecycle), so journaling the
  upload failed, `workers.dev` stayed enabled (closed by hand), the grant
  was never revoked, and the durable state stayed CONVERGING. The
  single-invocation design had the same flaw and had simply never reached
  the upload on Cloudflare. PR #81 orders the final runtime last in the
  journal, after `workers_dev_disable` and a `terminal_verify` that proves
  everything but the runtime; right before the upload the shell marks the
  attempt finalizing and arms an alarm, then only uploads, drops the
  bootstrap nonce and revokes, writing nothing more. The final runtime's
  alarm handler moves a finalizing attempt to READY; its own presence is
  the proof the shell could not write. Recovery, tests and the Node harness
  keep the journaled path, which now completes the journal after the final
  runtime is verified. Measured against the real provider with the shell's
  hook, the passes cost 25, 21, 22 and 23 provider calls (91 in all; the handover comes after 19 calls of the last pass, and the API then shows workers.dev closed and the final runtime bindings active). Open: the
  recovery router in the final runtime still converges in one invocation.
- 2026-09-04 (09:33), fifth real install, on gateway-v0.1.30, the first
  that finished on its own: both consents, the progress page at once, the
  passes behind alarms, workers.dev closed by the converger, then the final
  runtime uploaded and the bootstrap nonce dropped two seconds later; the
  page read the closed address as "setup finished" and the API shows the
  final runtime bindings active, only the ownership wrap key left as a
  secret, the custom domain attached, both Access applications with their
  policies, the portal and its DNS record, and the management hostname
  answering with the Access login. What the outside cannot read is the
  READY word the final runtime's alarm writes behind Access; the harness
  proves that path and an admin can confirm it on
  `/__ankka/install/status` at the management hostname. One hosted defect
  showed on the way: the result page's first handoff poll got a 503 while
  the fresh shell's route was still propagating, and the page stopped
  polling and reported an internal error; reloading the result page made it
  poll again and hand off normally. The hosted page must treat a 503 from
  the handoff route as "not yet". Open: that page fix (its source is not in
  this repository), and the recovery router in the final runtime still
  converging in one invocation.
- 2026-09-04 (13:50), the finished install's management page: after the
  Access login, `/sources` showed "Couldn't load the gateway" because
  `/api/status` and `/api/sources` answered 503 `unavailable`. The shell ran
  the payload's bootstrap in-process and skipped what the payload's own
  public bootstrap route does afterwards: publishing the public status and
  the management control into the management object, which the management
  API reads. The shell also kept the receipt in the management object, where
  the payload's teardown never looks (it reads the installation object,
  `v1:<install id>`). PR #83 runs the bootstrap and the receipt verification
  in the installation object through two internal requests the Worker entry
  never forwards, and publishes the status and control into the management
  object through a function the payload now exports for hosts that run its
  bootstrap themselves (`publishBootstrapCompletion`, written exactly as the
  route writes them). A failed publication answers
  `management_publication_failed`. The harness now asserts the management
  object answers `/status`, `/sources` and `/management-control`, and a
  root test compares the shell's records with the route's, which is the
  check that would have caught this. Lesson: a route the shell replaces has
  to be replaced whole; its side effects were the contract.
- 2026-09-04 (14:20), sixth real install, on gateway-v0.1.31 with the
  management publication in place: Stage 1 handed off without a reload this
  time, and the second pass stopped at the portal discovery with
  `payload_portal_discover_blocked_http_400_code_7001`, which the progress
  page showed at once. Cloudflare error 7001 is "not valid ID format": the
  portal hostname `mcpsix.zimtente.com` truncates to a key hint that ends on
  a label boundary, so the MCP portal id carried two hyphens in a row
  (`portal-mcpsix-zimtente--<digest>`), which the portals API refuses while
  a single hyphen answers 404 as expected. Every earlier hostname happened
  to cut inside a label. PR #84 trims a trailing hyphen from the truncated
  hint in the payload, the hosted derivation and the two fixture copies,
  which are one contract; the pinned desired hashes moved with it (the
  `portal-app` key for `mcp.example.com` had the same double hyphen without
  consequence, since Access application keys never appear in a URL). An
  installer test derives keys for boundary hostnames and a root test runs
  the payload's bootstrap for one, comparing its keys with the hosted
  derivation. Lesson: a provider identifier format is part of the contract
  too; derive keys with the provider's grammar, not only the byte budget.
- 2026-09-04 (15:18), seventh real install, on gateway-v0.1.32, the first
  whose management page works: both consents (the hosted result page needed
  its reload once more), the passes behind alarms, workers.dev closed, the
  final runtime uploaded and the bootstrap nonce dropped, and after the
  Access login `https://manageseven.zimtente.com/sources` rendered the
  Gateway as ready with `/api/status`, `/api/sources` and `/api/update`
  answering 200. The API shows the final runtime bindings active, only the
  ownership wrap key as a secret, the custom domain, both Access
  applications with their policies, the portal and its DNS record. This
  closes the activation sequence's install path on a second account; what
  remains open is the hosted result page's first-poll 503 and the recovery
  router still converging in one invocation.
- 2026-09-04 (15:40), the two leftovers: the hosted result page stopped on
  a not-ready handoff poll because the runtime's `not_ready` body carried no
  `code`, and the page only keeps polling on `bootstrap_not_ready`; every
  other body it reads as an internal error. The body now says its code
  (PR #86), so a fresh shell's route propagation is waited out instead of
  reported. The final runtime's recovery flow ran the converger inside the
  callback invocation, under the same Workers Free budget the shell had; it
  now hands the grant to the same driver and runs its passes from the
  object's alarm, answering the recovery callback with the progress page
  on the management origin. The recovery router's tests run the driver
  inline. The test account keeps the afternoon-seven install, the canary
  dashboard and the manual test portal; every other install residue since
  August is removed.

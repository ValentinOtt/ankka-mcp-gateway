# Ankka MCP Gateway deploy service

Public-source, isolated Cloudflare Worker for the hosted installer at
`https://deploy.ankka.ai`. It implements the authorization boundary for an
OS-style customer-account deploy flow. The checked-in mutation path remains
compile-time disabled; separately generated, signed canary builds have exercised
the reviewed path.

## Current safety state

- `workers_dev = false`; the production Worker is custom-domain-only.
- The checked-in `wrangler.toml` carries no production route. Only the
  create-only reviewed canary generator emits the exact `deploy.ankka.ai`
  Custom Domain configuration.
- Worker logs, invocation logs, and traces are disabled.
- The active reviewed hosted build has one Analytics Engine binding for the
  fixed, identifier-free setup funnel in
  [`docs/HOSTED_INSTALLER_ANALYTICS.md`](../../docs/HOSTED_INSTALLER_ANALYTICS.md).
  It is absent from the disabled and rollback shells and from every
  customer-deployed gateway; sink failure is drop-only.
- No Logpush job may include `deploy.ankka.ai`. The live host has no Ankka
  Access application and remains on the disabled shell until public activation.
  Before activation, a complete account read must prove that no whole-host,
  path-specific, wildcard, or destination-based Access app can cover it. An
  optional private Access contract is retained only for separately isolated
  canaries; it is not created on the live host or recreated during rollback.
  Zone WAF and rate-limit phases are not treated as a
  control for this Workers Custom Domain because they do not evaluate for it.
  Cloudflare still necessarily processes the callback URI as OAuth issuer and
  edge provider and may retain request metadata in platform analytics; this is
  an explicit canary risk acceptance, not a claim of platform-level zero
  logging. The one-use code remains PKCE- and client-secret-bound and is
  consumed before the clean redirect.
- Cloudflare Network Error Logging remains enabled on the Ankka-owned hosted
  zone, so the edge may inject `NEL`/`Report-To`. The public verifier permits
  those platform headers under the reviewed residual-metadata policy. This is
  separate from customer gateway telemetry: the signed release and deployment
  contracts keep metrics, instrumentation, observability, Logpush, tail
  consumers, analytics beacons, and application-set reporting headers off.
- Active reviewed builds include three fail-closed Workers Rate Limiting
  bindings: 6 new anonymous sessions per client per minute, 120 authenticated
  session/discovery reads per opaque session per minute, and 30 state-changing
  API calls per opaque session per minute. Binding keys are purpose-separated
  HMACs derived with the deployment secret; the Worker does not log or store raw
  client addresses or limiter subjects. The callback, management context, and
  exact signed release endpoints do not consume these rate-limit bindings;
  management context does not resolve a deploy-session Durable Object.
- `GatewayDeploySession` is a SQLite Durable Object.
- Every stored session schedules a Durable Object alarm at its next fixed
  session, lease, or recovery deadline; the final alarm validates and deletes
  all anonymous or PII-bearing session state.
- `DisabledInstallExecutor`, `DisabledUninstallExecutor`, and
  `DisabledReturningUninstallExecutor` are the production defaults and have no
  environment flag that can enable writes.
- `src/reviewed-activation.ts` remains the exact compile-time `false`/`null`
  activation. The reviewed install and removal executors therefore
  cannot be reached from the checked-in Worker entry point.
- The checked-in Ed25519 release-key registry is empty. Consequently
  `POST /api/plan` returns `release_unavailable` with the default provider and
  OAuth cannot begin.
- A separately generated signed private-canary build has completed a real
  customer-owned installation. That does not activate the checked-in default,
  close the updater promotion gate, or establish production support.

### Release gates for the public payload

The repository's public `payload/` tree is consumed here only through the
reviewed signing and manifest path. Its activation state is tracked by gate:

| Gate | State | Evidence |
| --- | --- | --- |
| P1A primary → cleanup receipt transition | repaired, regression-covered | cleanup accepts only the primary's stored `ready` receipt (checksum-verified, canonically equal to the claim), durably enters `uninstalling` before provider I/O; `test/payload-lifecycle.mjs` chains the real primary Worker into the real cleanup Worker |
| P1B Access application ownership | decided: explicit creation | both Access applications are `POST`ed with the live-canary request shapes; generated look-alikes fail closed; Managed OAuth is proven on the single-application read |
| P1C exact-payload lifecycle canary | payload lifecycle passed; hosted install exercised; promotion proof open | the retired evidence record under `scripts/exact-payload-canary/` documents seven resources, employee tool call, receipt-bound cleanup, zero residue and retirement. A later signed private canary exercised hosted OAuth, R2 publication and installation. Still open: repeat the corrected build under a retained key, prove runbook §9, then perform same-session removal and independent zero-residue verification. |
| Payload bytes | current admin, installer, Worker, cleanup, and retirement trees | pinned in the public `test/release-payload-layout.test.mjs`; installer UI includes fixed 429/503 abuse-control guidance |
| Historical private canary | `gateway-v0.1.11` | signed, create-only R2 publication, private-repository prerelease mirror, and hosted installation exercised; it will not be copied into the sanitized public repository and its deliberately discarded signing key makes it unsuitable as updater-capable N |
| Next release candidate | current reviewed source after public-history remediation | build, sign, publish and pin only after its exact source commit and retained key are approved |

The checked-in `REVIEWED_GATEWAY_DEPLOY_ACTIVATION` stays
`{ enabled: false, pin: null }`. A canary build may replace it only through the
reviewed generator after a human signs, publishes, and pins the exact release.

Enabling an executor later requires a separate review: pin an Ed25519 release
public key in source, fetch artifacts from fixed release locations, verify the
schema-2 signature over the domain-separated statement binding the exact
canonical `manifest.json` bytes, channel, key ID and signature context, and verify every
payload file's path, size, content type, and SHA-256 plus every component and
aggregate tree digest. The rich public manifest is accepted only with its exact
ten scopes and exact three-variant Worker deployment contract: the asset-backed
primary Worker, the cleanup-only Worker with its active SQLite Durable Object
export, and the inert retirement Worker with the exact declarative `AdminState`
deleted export. Every variant rejects migration metadata and pins its
compatibility settings, bindings, observability, instrumentation, metrics,
`workers.dev`, and preview URLs. Unknown fields and
parallel thin-manifest aliases are rejected. Only then may a separately
reviewed executor receive the release. An environment variable alone must
never enable mutations.

The canonical release checksum shown in plans and receipts, and later supplied
to the customer Worker as `ANKKA_GATEWAY_RELEASE_SHA256`, is the full
`manifest.artifact.treeSha256`. Primary Worker, cleanup Worker, retirement
Worker, admin-asset, and installer component tree digests remain separate
integrity fields used only for their respective byte checks; none can
substitute for the aggregate release identity.

The signing envelope itself is canonical JSON with exactly
`{ channel, keyId, manifest, schemaVersion, signature, signatureContext }`.
`manifest` is a string holding the exact canonical UTF-8 public manifest;
`signature` is unpadded base64url Ed25519 over the domain-separated canonical
statement containing those manifest bytes, the channel, key ID, schema, and
signature context. The current environment provider deliberately
has no artifact fetcher, so even pinning a key without implementing the reviewed
all-files fetch path remains fail-closed.

## OAuth client

The non-secret reviewed client ID is configured as
`CLOUDFLARE_OAUTH_CLIENT_ID` in `wrangler.toml`. The exact callback is fixed in
code:

```text
https://deploy.ankka.ai/oauth/callback
```

Secrets belong only in Worker secrets or local `.dev.vars`:

- `CLOUDFLARE_OAUTH_CLIENT_SECRET`
- `DEPLOY_SESSION_ENCRYPTION_KEY` (exactly 32 random bytes, base64/base64url)
- `BOOTSTRAP_NONCE_DERIVATION_KEY` (a different 32 random bytes, base64/base64url)

Never reuse, commit, or print these values. `.dev.vars.example` contains names and
placeholders only.

The self-managed OAuth client uses two separate grants. Onboarding starts with
an exact read-only discovery grant containing only `user-details.read`,
`memberships.read`, `account-settings.read`, and `zone.read`. It fetches the
actor email, authorized accounts, and active zones, then is revoked and
discarded. The later install or removal grant uses the full exact scope set
below only after the corresponding deterministic plan is reviewed.

The comments intentionally pin both dashboard label and API identifier so they
cannot be confused with older Wrangler/API-token spellings.

| Cloudflare consent label | OAuth scope ID |
| --- | --- |
| User Details Read | `user-details.read` |
| Memberships Read | `memberships.read` |
| Account Settings Read | `account-settings.read` |
| Workers Scripts Write (`Workers → Edit`) | `workers-scripts.write` |
| Workers Routes Read | `workers-routes.read` |
| Zone Read | `zone.read` |
| DNS Write | `dns.write` |
| Access: Apps and Policies Write | `access.write` |
| Access: Organizations, Identity Providers, and Groups Write | `access-acct.write` |
| MCP Portals Write | `mcp-portals.write` |

Source catalogue: Cloudflare's self-managed OAuth scope catalogue in
`cloudflare/mcp/src/auth/derived-oauth-scopes.json` (verified 2026-08-23).
Returned grants must contain the exact set for their purpose—missing and
additional scopes fail before discovery or execution. `workers-routes.read` is
read-only and is used to prove that an existing route cannot intercept the
requested management hostname before the Custom Domain is attached.

## Browser contract

1. `GET /api/session` creates or resumes an opaque session cookie and returns
   the stable top-level `InstallerSession` fields plus `csrf`. The client strips
   `csrf` before putting the session into React state.
2. The browser keeps `csrf` outside React/persisted app state and sends it as
   `X-CSRF-Token` on every mutation.
3. `GET /api/discovery` returns only discovery status, actor email, account and
   zone names, and opaque target hashes. `POST /api/discovery` creates the
   portable read-only handoff. Its callback revokes and discards that grant.
4. `PUT /api/selection` stores the complete, credential-free selection, binds
   it to one opaque target hash, and returns a top-level `InstallerSession`.
   Raw provider IDs remain internal to the expiring Durable Object.
5. `POST /api/plan` verifies the release, stores the deterministic zero-write
   plan, and returns a top-level `InstallerSession`.
6. `POST /api/deploy` accepts only the exact `{ planId, planHash }` the user
   reviewed and returns the direct `authorizationUrl` plus a short-lived
   `handoffUrl`. The latter carries only an authenticated-encrypted fragment,
   so it can be opened in a different browser without putting the PKCE verifier
   or session identifier in a request URL.
7. `POST /api/oauth/handoff` exchanges that fragment from the same-origin
   signed installer, establishes the sealed attempt and session cookies in the
   user's chosen browser, and returns the fixed Cloudflare authorization URL.
   It neither approves consent nor performs a provider write.
8. Cloudflare redirects to the fixed callback. Discovery and removal callbacks
   redirect to clean installer routes. A successful install authorization
   callback immediately streams the signature-verified `/result` installer
   shell, removes the callback query from browser history, and keeps that HTTP
   response connected while the memory-only grant executes. The response sends
   fixed HTML-comment heartbeats and contains no result or provider data.
9. The callback page and the initiating agent or browser poll the original
   session while installation runs. All clients are bound to the same Durable
   Object and observe a public projection of the 15 journal action names,
   phases, and timestamps; records, locators, provider IDs, and request hashes
   remain internal.
10. After a successful install, the original opaque browser session can call
   `POST /api/uninstall/plan` to build a zero-write removal plan. It remains
   eligible only in that same Durable Object through the install journal's
   exact `recoverUntil`, which is the original session `expiresAt` plus 24
   hours.
11. `POST /api/uninstall` accepts only the exact reviewed uninstall
   `{ planId, planHash }` and starts a new, uninstall-purpose OAuth approval.
   Its callback also redirects to the clean `/result` URL.
12. A returning customer first repeats read-only discovery and the exact
   gateway selection. The double-scan fresh preflight can return an
   `existing_gateway_detected` summary without inspecting or changing the
   deterministic Worker. From the linked, Access-protected customer dashboard,
   a one-time `/manage#…` handoff is bound to that actor, selected account,
   installation, Worker, and management origin. The installer shows a
   zero-write removal plan before `POST /api/returning-uninstall` can start a
   fresh, purpose-bound OAuth approval. The customer Worker's checksum-verified
   receipt and HMAC action proof—not the summary or names—remain deletion
   authority.
13. `DELETE /api/session` destroys the DO session after same-origin and CSRF
   validation, unless an armed install or uninstall action makes destruction
   unsafe.

The checked-in scaffold advertises `capabilities.deploy = false`,
`capabilities.uninstall = false`, `capabilities.events = false`, and (until a
signed plan exists) `capabilities.signedRelease = false`. There is no
`/api/events` endpoint, so the UI does not poll a capability the service cannot
fulfill.

The current wizard creates the customer gateway and an empty MCP Portal before
the write-scoped OAuth grant. Sources are configured later from the
customer-owned management page:

```ts
{
  schemaVersion: 1,
  basics: {
    gatewayName,
    zoneName,
    adminEmail,
    additionalAdminEmails,
    managementHostname,
    portalHostname,
  },
  firstSource: null,
}
```

Both hostnames must be distinct subdomains of the selected active zone. The
schema still accepts the former first-source object so retained sessions and
receipts remain parseable and uninstallable, but the browser and WebMCP wizard
no longer request it.

Invalid selection responses remain secret-free but include one optional fixed
`reason` such as `admin_email_invalid` or `portal_hostname_invalid`. The browser maps only this reviewed vocabulary to
repair guidance. It never displays arbitrary provider or exception text.

The static plan enumerates five management resources (Worker, Durable Object,
assets, Access application, Access policy) and four provider-neutral gateway
resources (Portal, Portal Access app/policy, DNS record). Legacy selections
with an initial source retain the seven-resource plan.

### Agent browser contract (experimental WebMCP)

When `document.modelContext` is available, the same signed installer asset
registers seven browser-local tools: `begin_cloudflare_discovery`,
`configure_gateway`, `create_review_plan`, `get_installer_status`,
`begin_authorization`, `create_removal_plan`, and `begin_removal`. This is a
progressive enhancement; absence or rejection of
WebMCP registration leaves the ordinary browser UI unchanged.

The tools call only the same same-origin API used by the visible wizard. They do
not add an execution path, accept provider credentials, or weaken the exact
plan-hash and retained-session boundaries. Configuration and plan tools return
structured secret-free summaries. Authorization tools return a short-lived
`deploy.ankka.ai/oauth/handoff#…` link instead of navigating the agent's page.
The encrypted fragment is never sent in the handoff page's GET request; the
signed page exchanges it same-origin, establishes the attempt cookies in the
user's chosen browser, and then opens the fixed Cloudflare consent flow. The
user still reviews and approves Cloudflare permissions. The initiating agent
can poll its retained session until the callback completes. Removal remains
destructive and is available only from the original successful install session
or after the returning-customer receipt handoff. A WebMCP tool cannot discover
or adopt an installation from user-supplied names or provider IDs.

The ordinary wizard exposes the same handoff after its Authorize action as a
real `Open Cloudflare sign-in` link with `target="_blank"`. Browser-control
agents can therefore drive the semantic form, read or relay that link, and
leave the installer page polling even when WebMCP is unavailable. A human using
the wizard gets the same two-context flow without configuring any agent MCP.

Installer assets explicitly allow `tools=(self)` while retaining same-origin
isolation, `frame-ancestors 'none'`, and the existing restrictive CSP. A
production WebMCP experiment additionally requires browser support and the
appropriate origin-trial enrollment; the public payload carries no trial token
or browser-specific polyfill.

## Customer runtime update boundary

The reviewed runtime exposes `GET /api/releases/stable` or
`GET /api/releases/canary` from its exact pinned, signature-verified release
bundle and serves only the channel selected by that pin. The endpoint is
anonymous and has no tenant selector. Updater-capable customer Workers fetch
their installed fixed channel URL without
authorization, cookies, referrer, account ID, hostname, or user identity and
verify the response against the public Ed25519 key installed with the gateway.
An optional isolated private-canary environment may use two more-specific
Bypass applications for `/api/releases/canary` and `/api/releases/stable` under
the private Access contract; never broaden those paths. That tooling is not
part of the live cutover. `deploy.ankka.ai` has no Ankka Access application:
the pre-activation account read proves zero coverage while the disabled shell
is serving, and `scripts/edge-gate/verify-public.mjs` repeats the complete
account and cookie-free behavior checks after activation, validates the exact
channel-bound Ed25519 descriptor against the reviewed release pin, and never
mints a session.

Only an exact unchanged Cloudflare release contract is classified as a normal
update. The allowed change set is customer Worker code and management assets;
Access, DNS, MCP Portal configuration, sources, tool allowlists, credentials,
OAuth scopes, bindings, compatibility settings, signing-key rotation, and
Durable Object migrations are excluded. See
[`docs/UPDATES.md`](../../docs/UPDATES.md) for the full contract.

After explicit approval, the customer Worker creates a one-time action and the
signed management shell hands it to `/manage#…`. `POST
/api/management/authorize` establishes a fresh confidential OAuth attempt. The
callback verifies the actor and account, keeps the Cloudflare token in memory,
and drives the exact Versions API sequence through a temporarily enabled
workers.dev HMAC channel:

```text
current 100% + candidate 0%
  -> exact candidate version override probe
  -> candidate 100%
  -> normal-route health probe
  -> customer-owned completion record
```

Failure after staging restores and verifies the old version at 100%. A later
rollback is a separate user-approved OAuth action using the previous Cloudflare
version ID recorded in customer state. It rolls back code and assets only;
Durable Object data is retained. The original install journal and root receipt
remain immutable, while uninstall uses the currently pinned signed cleanup and
retirement payload against that original ownership receipt.

The management page registers `check_gateway_update`,
`review_gateway_update`, `apply_gateway_update`, and
`rollback_gateway_update` when WebMCP is available. Apply and rollback tools
return a short-lived consent link; they never accept a Cloudflare token or
approve consent for the user.

The updater implementation is not permission to promote it. A real signed
updater-capable N → N+1 canary, broken-candidate compensation, explicit
rollback, employee MCP call, post-update uninstall, and zero-residue proof are
required before stable activation.

## Reviewed removal boundary

The checked-in removal executors remain compile-time disabled and may be
enabled only in an exact reviewed build. Two bounded entry paths share the same
fresh OAuth and receipt-ownership requirements:

- a completed installation retained in its original `GatewayDeploySession`;
  and
- a returning customer who repeats read-only discovery and exact selection,
  receives `existing_gateway_detected` with zero writes, and follows the linked
  customer dashboard's actor-bound receipt handoff in the same browser.

The returning path does not adopt an installation by hostname, Worker name,
account, or provider IDs. Those fields bind the review session; the
customer-resident checksum receipt and one-time HMAC action proof remain the
authority. Before customer gateway removal is durably verified, losing or
expiring the hosted session requires a fresh zero-write detection and customer
action rather than reuse of an old handoff. After that verified boundary, the
retained hosted journal can issue a new reviewed recovery plan for up to 24
hours with fresh Cloudflare OAuth, without depending on the removed dashboard
or retaining its action key.

For retained-session removal, the completed install journal is immutable
authority. Removal state and its journal are stored beside it in the same
`GatewayDeploySession` Durable Object and are bound to the installation ID,
install binding hash, exact signed release pin, authorized account, and active
zone. Returning removal imports only the receipt authority proved by the
customer Worker and journals every later transition in the hosted session.
That authority also carries the installed release ID, aggregate artifact
digest, update channel, key ID, and public verification key from the Worker's
validated bindings. The reviewed executor loads cleanup and retirement bytes
only from that exact create-only R2 release prefix and re-verifies the
channel-bound schema-2 signature and every payload digest. It never substitutes
the currently promoted release, so an installation at N remains removable
after the channel advances to N+1. Before deletion, the executor also derives
the exact clean-version commitment from that bundle and every expected
plaintext Worker binding, requires Cloudflare read-back of every exact module
byte, and proves that version is serving at 100%; a patterned Worker tag or
mutable release binding is never sufficient evidence. Cloudflare's Versions
API does not expose an immutable static-asset manifest or content digest, so
active asset content is not treated as release authority for teardown.
Planning performs no writes and is valid for at most ten minutes without
extending `recoverUntil`.
**Authorize removal** always creates a fresh confidential OAuth authorization
with the same exact ten scopes. The sealed verifier cookie and Durable Object
attempt are explicitly purpose-bound to `uninstall`; an install callback cannot
consume an uninstall attempt or vice versa.

The reviewed executor converges the approved plan in this order:

1. Prove fresh target state and the installed `AdminState` namespace.
2. Create and deploy the installed release's exactly verified cleanup Worker, temporarily enable
   `workers.dev` with preview URLs disabled, remove the seven gateway resources
   through the customer-owned cleanup endpoint, disable `workers.dev`, and
   restore the last clean primary deployment.
3. Remove the exact management Custom Domain and prove its same-name DNS record
   is absent.
4. Remove the exact administrator Access policy, then its parent Access
   application.
5. Create and deploy the signed retirement Worker, prove the `AdminState`
   namespace is retired, and delete the exact management Worker.
6. Prove no Ankka-managed gateway, domain, DNS, overlapping route, Access,
   Durable Object, or Worker residue remains before writing the final removed
   tombstone.

Every mutation is journaled as prepared, send-armed, submitted, and verified.
After an interruption, the executor reads provider state before continuing.
Worker version/deployment and management-delete outcomes converge from those
read-only proofs. The customer cleanup endpoint is a special one-send boundary:
an armed POST with unknown outcome is never replayed, because the public
contract has no authenticated request-status read. Recovery then stops with a
stable code and requires operator handling rather than risking a duplicate
destructive request. A retry that is allowed still requires a new OAuth grant.

Cloudflare retains the Advanced Certificate after the Custom Domain is removed.
It is outside the reviewed ten OAuth scopes and must be reviewed or removed
manually in Cloudflare; both the removal plan and receipt keep this notice
visible.

## Credential and replay boundary

- The session cookie is an opaque 256-bit identifier with
  `__Host-`, `HttpOnly`, `Secure`, `Path=/`, and `SameSite=Lax` attributes.
- OAuth uses confidential Authorization Code plus S256 PKCE.
- The PKCE verifier survives the redirect only in a short-lived AES-GCM sealed
  `__Host-` HttpOnly cookie. The DO stores only its SHA-256 hash.
- The DO stores only the OAuth state hash and consumes it transactionally once
  before token exchange.
- Install and uninstall OAuth cookies carry an exact purpose, and each Durable
  Object consume route rejects the other purpose before token exchange.
- The OAuth attempt and sealed verifier cookie cannot outlive the exact static
  plan the user approved; consumption at or after plan expiry is rejected.
- Authorization code, verifier plaintext, access token, refresh token, and
  OAuth client secret are never written to DO storage, responses, queues, or
  logs.
- The install callback owns the access and refresh credentials only in memory.
  Its signature-verified HTML stream is the request-lifetime anchor. Closing or
  reloading that page, losing the connection beyond the bounded cleanup window,
  or replacing the Worker may require a fresh authorization to recover the
  journaled partial installation.
- The callback verifies the exact granted scopes, authorizing actor equals the
  typed primary admin, exactly one authorized account, and exactly one active
  zone matching the typed zone.
- Every bounded access/refresh credential string in a successful token response
  is captured by an in-memory disposable owner before metadata validation.
  Access and unexpected refresh grants are both revocation-attempted under a
  bounded deadline—even when later metadata is malformed—and the owner is
  discarded in `finally`.
- Responses expose fixed error codes only. OAuth/provider bodies and arbitrary
  redirect targets never reach the browser.

## Local verification

```bash
npm ci
npm run typecheck
npm test
npx wrangler deploy --dry-run --config wrangler.toml
```

There is intentionally no package `deploy` script. Isolated canary work and the
separate live activation use only generated reviewed configuration after their
respective signed-release, install, uninstall, and explicit approval gates
pass. Prior private-canary deployments are historical evidence and do not grant
authority to another run.

The Durable Object alarm bounds retained state; it is not an abuse-control
substitute. If an isolated private canary is used, its exact four Access
applications remain a separate operator-identity boundary. The live public
host instead remains no-Access and disabled until its zero-coverage preflight
passes. Worker-native abuse controls are part of every generated active
reviewed configuration, but public self-service remains disabled until their
429 and fail-closed 503 behavior is recorded, the retained-key lifecycle and
OAuth/Logpush/hosted-NEL disclosure gates pass, and the post-activation public
verifier plus an unrelated-account browser flow succeed. Zone WAF rules do not
protect a Workers Custom Domain.

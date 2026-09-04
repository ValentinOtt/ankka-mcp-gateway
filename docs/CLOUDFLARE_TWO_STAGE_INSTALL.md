# Cloudflare two-stage installation candidate

> **Status:** live-qualified, feature-disabled candidate. It is not wired into the
> production installer, signed release schema, or production routes. This
> document records the 2026-09-01–02 canaries, subsequent Cloudflare support
> guidance, and the boundary implemented for further review.

## Decision

The browser-only bootstrap is **not viable**. Cloudflare's OAuth endpoints can
be configured for a browser public client, but the Cloudflare management API
does not provide the CORS response headers needed for browser JavaScript to
list accounts or manage Workers.

The recommended default is therefore a two-stage install:

```text
deploy.ankka.ai
  → Connect Cloudflare (Workers Scripts Write; choose one account)
  → restricted Gateway installed in that account
  → Finish secure setup (fixed customer-Worker PKCE operation)
  → Portal, Access, DNS, and final Gateway converge in that account
  → temporary grants revoked and discarded
```

There is no GitHub, Wrangler, Terraform, raw zone ID, or Cloudflare resource
form in the customer path. Cloudflare still has to show two authorization
decisions: one grant cannot both remain narrow in Ankka and later materialize
inside the customer Worker.

Ankka handles the short-lived Stage 1 Worker grant in one hosted callback.
Ankka's code relay sees the Stage 2 authorization code, but it has neither the
PKCE verifier nor a token-exchange path. The Stage 2 management token exists
only in the customer-owned Gateway invocation.

## Canary 1: browser-only management API

### Result: rejected

The following browser preflights were run against `api.cloudflare.com` with an
installer origin:

| Requested browser call | Result | CORS response |
| --- | --- | --- |
| authorized `GET /client/v4/accounts` | `OPTIONS` returned `400`, Cloudflare code `7001` | no `Access-Control-Allow-Origin`, methods, or headers |
| authorized Worker upload | `OPTIONS` returned `400`, Cloudflare code `9106` | no CORS allow headers |
| authorized Worker read/delete | `OPTIONS` returned `400`, Cloudflare code `9106` | no CORS allow headers |

This failure is decisive. `fetch(..., { mode: "no-cors" })` cannot add a Bearer
authorization header, issue `PUT` or `DELETE`, or expose a response for
verification. A browser therefore cannot complete the required
create/read-back/delete/revoke lifecycle against the management API.

Cloudflare's `allowed_cors_origins` OAuth-client field applies to OAuth browser
integration. It must not be described as enabling CORS on
`api.cloudflare.com`. An anonymous `OPTIONS` response from the token or
revocation endpoint is not by itself conclusive because a correctly encoded
form POST can be CORS-safelisted; that nuance does not change the management
API result.

## Canary 2: narrow bootstrap grant and account selection

### Result: exact permission, confidential exchange, topology, lifecycle, and post-revocation handoff passed

A disposable OAuth client requested only `workers-scripts.write`. The same
Cloudflare identity was temporarily authorized against two canary accounts.

1. Selecting only account B returned the exact requested scope, no refresh
   token, and `GET /accounts` exposed only B.
2. Selecting accounts A and B returned two account records. The installer
   rejected it with: **“Please authorize exactly one Cloudflare account.”**
3. The grants were revoked and the temporary account membership and OAuth
   clients were removed.

Cloudflare documents Workers Scripts Write for Worker upload, read/delete,
Workers subdomain/custom-domain management, and Durable Object namespace
operations. Together with the exact-scope account canary, the minimum Stage 1
OAuth permission is therefore:

```text
workers-scripts.write
```

No membership, user-detail, account-settings, zone, DNS, Access, Portal,
OpenID, offline-access, or refresh-token permission belongs in Stage 1.

A second disposable client then qualified the intended hosted-client shape
against a separate customer account. It was domain verified and public, used
Authorization Code with PKCE S256 and `client_secret_basic`, requested exactly
`workers-scripts.write`, and had refresh tokens disabled. The callback kept
the client secret in an encrypted Worker binding. The consent screen showed
one permission and one selected customer account.

A recoverable client-authentication mismatch encountered during setup failed at the
token endpoint with `401`: no management token was issued and no customer
resource was created. Rotating the disposable client secret and updating the
encrypted callback binding allowed the next fresh authorization to pass. This
qualifies fail-closed secret rotation without changing scope or persisting a
grant.

This is account-wide Workers write authority while the callback runs. It can
modify Workers other than Ankka's; Cloudflare does not offer a resource-bound
"create only this new Worker" OAuth scope. The narrowness comes from the fixed
hosted operation, not from a provider-enforced Worker-name restriction.

A disposable Worker-hosted canary then exercised the combined topology with
only this scope. It created a restricted Worker, uploaded the reviewed version,
activated its deployment, applied a SQLite Durable Object migration, read back
the exact Worker/version/deployment/namespace graph, and enabled the exact
`workers.dev` route. It immediately revoked the OAuth access token and proved
that the token could no longer list accounts before any runtime handoff.

After revocation, an installer page polled only the target's inert `/health`
route using an exact installer-origin CORS response. No management token or
bootstrap capability was present in those requests. Once the released asset
and SQLite state were live at the edge, the installer released a one-time
capability to the customer origin in a URL fragment. The customer page cleared
the fragment before its same-origin POST, consumed the capability once, and
proved that replay returned `409` and SQLite state was `consumed`.

The decisive live result was:

```json
{
  "outcome": "passed",
  "scope": ["workers-scripts.write"],
  "managementReadback": "worker_version_deployment_sqlite_namespace",
  "tokenRevocation": "confirmed_before_handoff",
  "runtime": "asset_and_sqlite_health_verified_after_revocation",
  "bootstrapCapability": "consumed_once_replay_rejected"
}
```

The passing target was removed after the proof and its public health route
returned `404`; the Durable Object namespace was absent on provider read-back.
The companion confidential-client lifecycle also created the restricted
Worker and SQLite namespace, consumed and replay-tested the bootstrap
capability, disabled `workers.dev`, retired the namespace, deleted the Worker,
proved both were absent, and then proved token revocation. The canary does not
claim that edge runtime readiness and handoff cleanup should remain in the
OAuth callback: the evidence says they must be split at revocation.

The narrow grant exposed one important endpoint distinction. Submitting a
version through the Workers Versions API was rejected with HTTP `403`, provider
code `100406`. The direct Worker script upload endpoint accepted the same
reviewed module, assets, SQLite migration, bindings, and compatibility date;
the resulting version, deployment, namespace, and runtime were read back and
verified. Namespace retirement through a direct upload also passed. Stage 1
must therefore use the qualified direct script upload path and must not widen
permissions merely to make the Versions submit endpoint work.

After the canaries, the customer account contained no Workers or Durable Object
namespaces. The disposable callback Worker, OAuth client and both rotated
client secrets, publisher-verification TXT record, customer targets, and grants
were removed. The documented production OAuth client was not modified.

## Canary 3: Stage 2 public-client lifecycle

### Result: exact scopes, customer-side exchange, convergence, recovery, rollback, and uninstall passed

A disposable public OAuth client used Authorization Code with PKCE S256,
`token_endpoint_auth_method=none`, one fixed relay callback, no client secret,
and no refresh-token grant. The customer Gateway generated and retained the
verifier, while the code relay received only Cloudflare's authorization code
and a signed fixed-operation state. The Gateway exchanged the code directly
with Cloudflare and held the resulting grant only in the active customer
invocation. No refresh token was issued, and revocation made the access token
unusable.

The exact seven-scope `install` grant below then passed all of these live
provider operations in a disposable customer graph:

- exact one-account assertion and positive zone discovery;
- Zero Trust organization and identity-provider reads;
- Access application and policy create, get, list, update, delete, and absence
  verification;
- Worker-route collision reads and Worker custom-domain create, get, list,
  delete, and absence verification;
- MCP server and Portal create, get, list, update where supported, delete, and
  absence verification;
- Portal Access application/policy and exact DNS record create, get, list,
  delete, and absence verification; and
- direct-upload final Worker activation, exact read-back, clean self-update,
  recovery from an intentionally unknown update outcome, and rollback.

The same canary completed customer-side uninstall: receipt-owned dependent
resources were absent, an inert release was active, the wrapping-key secret was
removed, the SQLite namespace was retired, and `workers.dev` was disabled. A
separate hosted finalizer authorization then exercised the root deletion
boundary and revocation. Repeating the finalizer against an already absent
target failed closed at provider read-back while still revoking its grant,
which is the intended idempotent recovery result.

The decisive Stage 2 properties were:

```json
{
  "outcome": "passed",
  "exchange": "customer_gateway_only",
  "relay": "authorization_code_only",
  "refreshToken": "absent",
  "scopeSet": "exact",
  "selfUpdateRecoveryRollback": "passed",
  "customerUninstallAndHostedFinalize": "passed",
  "tokenRevocation": "confirmed"
}
```

## Canary 4: ownership-bound later-operation relay tickets

### Result: persistent customer proof, pre-allocation rejection, and one-time ticket issuance passed

The initial install certificate binds the exact account, Worker, SQLite
namespace, Gateway callback, public OAuth client, handoff digest, and a
customer-generated Ed25519 public key. For `upgrade`, `rollback`, source
add/update/remove, and `uninstall`, the Gateway first signs a fresh challenge
request. The relay verifies the certificate and signature before allocating
state, stores only the certificate digest, challenge digest, fixed operation,
and expiry, and atomically consumes the exact challenge before issuing one
short-lived fixed-operation relay ticket. `install` cannot enter this
reissuance path.

Cloudflare Workers could generate a non-extractable Ed25519 key, but neither
Durable Object storage nor `structuredClone()` could persist its `CryptoKey`.
The qualified design therefore generates the key as exportable only during its
initial customer invocation, encrypts the 48-byte PKCS#8 value with AES-256-GCM
under a dedicated customer Worker secret named
`ANKKA_GATEWAY_OWNERSHIP_WRAP_KEY`, and immediately reimports the in-memory key
as non-extractable. Only canonical authenticated ciphertext and the public key
persist in the customer's Durable Object. On later operations the Gateway
decrypts, imports non-extractably, verifies the key pair, and overwrites the
temporary plaintext bytes. The wrapping secret and private key never transit
or persist at Ankka, and the relay HMAC key never ships to the customer Worker.

The live relay Durable Object also exposed a runtime mismatch:
`SqlStorageCursor.rowsWritten` did not report the successful upsert reliably.
The reviewed adapter now checks `SELECT changes()` immediately inside the same
synchronous transaction for both challenge upsert and consume. The final live
canary then passed twice, including a fresh deployment of the cleaned harness:

```json
{
  "outcome": "passed",
  "persistentCiphertext": true,
  "invocationKeyExtractable": false,
  "wrongKeyRejectedBeforeAllocation": true,
  "proofReplayRejected": true,
  "exactTicketAccepted": true,
  "hashOnlyRelayState": true,
  "relayStateRemaining": 0
}
```

## Exact OAuth permissions

Cloudflare's 2026-09-01 OAuth scope picker was used to confirm the current
canonical IDs. In particular, the old aliases `access.write` and
`access-acct.write` are not used by this candidate.

### Stage 1

| API action | Scope ID | Evidence |
| --- | --- | --- |
| assert exactly one selected account with `GET /accounts` | `workers-scripts.write` | live exact-scope positive and multi-account rejection |
| upload/read/delete the restricted Worker through direct script upload; read back its resulting version and deployment | `workers-scripts.write` | live confidential-client topology and full lifecycle canaries |
| create/read/delete the SQLite Durable Object namespace through the reviewed Worker migration/lifecycle | `workers-scripts.write` | live combined topology and cleanup canaries |
| enable and later disable the exact Worker's `workers.dev` surface | `workers-scripts.write` | live combined topology and cleanup canaries |

The Workers Versions submit endpoint is deliberately excluded from Stage 1:
the live exact-scope grant received HTTP `403`, provider code `100406`. Direct
script upload is the qualified path and no additional permission is justified.

### Stage 2 `install`

| API action | Current scope ID | Why it is needed | Qualification status |
| --- | --- | --- | --- |
| reassert one account | the operation's existing scope set | bind the grant to the signed Stage 1 account | live exact one-account pass |
| list the selected account's eligible zones | `zone.read` | show a storefront-domain picker instead of asking for a zone ID | live positive-zone pass |
| read the Zero Trust organization and identity providers | `access-acct.read` | converge Access without changing organization or IdP settings | live read pass |
| create/read/update/delete Access apps and policies | `zone-access.write` | protect management and Gateway surfaces | live full-lifecycle and absence pass |
| create/read/update/delete MCP servers and Portals | `mcp-portals.write` | converge the customer-owned Portal graph | live full-lifecycle and absence pass |
| create/read/delete exact DNS receipt resources | `dns.write` | attach the reviewed management and Portal hostnames | live full-lifecycle and absence pass |
| inspect Worker route collisions | `workers-routes.read` | fail closed before binding a hostname | live collision-read pass |
| publish/activate the final Worker, manage its custom domain, and disable `workers.dev` | `workers-scripts.write` | replace the restricted bootstrap release with the final runtime | live self-update, recovery, rollback, and cleanup pass |

The fixed Stage 2 `install` scope ceiling is exactly:

```text
access-acct.read
zone-access.write
dns.write
mcp-portals.write
workers-routes.read
workers-scripts.write
zone.read
```

`zone.read` belongs only to customer-side installation. The current
architecture requires an exact zone and collision-checked management/Portal
hostnames; moving zone discovery into Stage 1 would widen Ankka's grant for UI
convenience. If a future Cloudflare API can resolve a user-entered domain with
less authority, this scope should be removed after a positive canary.

Every endpoint/scope pair in the Stage 2 table and the final clean self-update
passed the disposable live canary. This is release-pinned evidence, not a
permanent provider guarantee: scope catalogue, OAuth-client, or endpoint drift
must trigger requalification before activation, and a failing call must not be
fixed by widening permissions.

Cloudflare support confirmed that the observed `403` from a resource-scoped
Access Policy Admin OAuth grant was not a client-configuration error. The
resource-scoped role remains beta, and individual policy endpoints can
currently be evaluated differently from the newer resource-scoped list
endpoints. This does not invalidate the broader temporary Stage 2 OAuth model;
it reinforces that every Access endpoint/scope pair must pass a positive and
negative live canary before release.

### Team management is outside V1

The default V1 installer does not provision a permanent Cloudflare management
credential, and the Team policy editor remains disabled. Administrators manage
team policy directly in Cloudflare for V1. The retired optional
`ANKKA_TEAM_MANAGEMENT_TOKEN` candidate is not part of the two-stage installer
release path and is not an exception to its credential boundary.

Cloudflare support has now confirmed there is no API-token representation left
to discover for an exact reusable Access policy. Account-owned (`cfat_...`) and
user-owned API tokens can select only User, Account, or Zone resources. Giving
either token **Access: Policies Write** for the selected account therefore gives
it write authority over every Access policy in that account, not only the Ankka
policy. Per-policy **Cloudflare Access Policy Admin** scoping exists only in the
human/member IAM model. Cloudflare also confirmed that resource-scoped member
OAuth currently has a beta gap: individual policy API requests can be evaluated
differently from the newer resource-scoped list endpoints, explaining the live
`403` without making the broader Stage 2 OAuth model invalid.

The V1 credential boundary is therefore explicit:

- Stage 1 uses only a temporary `workers-scripts.write` grant handled by
  `deploy.ankka.ai`;
- Stage 2 and later fixed operations use fresh temporary OAuth grants exchanged
  and consumed inside the customer Gateway;
- Team membership is managed directly in Cloudflare; and
- no permanent Cloudflare management credential is provisioned or required.

A future Team editor has only two currently realistic qualification paths:

1. re-test resource-scoped member OAuth if Cloudflare closes the individual-
   policy endpoint gap; or
2. deliberately offer an opt-in account-wide **Access: Policies Write** token,
   with application-level ownership checks while explicitly accepting that
   Cloudflare does not isolate the token to Ankka resources.

The second path must not become the default. Neither future experiment is a
Stage 1 or Stage 2 release gate.

## OAuth clients

The hosted bootstrap client should be:

```text
visibility:                 public
grant_types:                authorization_code
response_types:             code
token_endpoint_auth_method: client_secret_basic
PKCE:                       S256
refresh_token:              disabled
scopes:                     workers-scripts.write
redirect URI:               fixed deploy.ankka.ai callback
```

Its secret remains only at `deploy.ankka.ai`. PKCE S256 is defense in depth for
the hosted callback. A domain-verified public disposable client with this exact
configuration passed both the post-revocation handoff and complete
create/verify/retire/delete/revoke lifecycle against a separate customer
account. No refresh token was issued. The callback used the same Basic client
authentication for exchange and revocation.

The customer-operation client should be public, use Authorization Code,
`token_endpoint_auth_method=none`, require PKCE S256, omit refresh-token grant
types, and have only the fixed `auth.ankka.ai` callback. Cloudflare public
visibility is permanent and requires client-domain verification, so the real
clients must be reviewed before promotion. The account-selection canary used a
disposable private client; the end-to-end Stage 1 topology, handoff, and full
lifecycle canaries used a domain-verified disposable public confidential
client. A disposable public customer-operation client with the exact shape
above passed code-only relay, direct customer-Gateway exchange, exact-scope
validation, the complete Stage 2 lifecycle, and revocation. The production
client and routes remain unwired and require release review before promotion.

Cloudflare account administrators can block public OAuth applications. Those
accounts need the advanced customer-managed OAuth or manual path. The product
must explain the policy block without asking for broader permissions.

## Candidate lifecycle

### Stage 1 — narrow hosted bootstrap

1. `deploy.ankka.ai` starts a fresh authorization and accepts exactly one
   selected account.
2. The token is exchanged into callback-local memory. It is never persisted,
   logged, returned to the browser, or exposed to a generic request proxy.
3. The installer chooses a fresh Worker identity, installation ID, one-time
   256-bit bootstrap capability, dedicated 256-bit ownership wrapping secret,
   and exact signed release. Only the capability commitment and the wrapping
   secret as a Cloudflare `secret_text` binding enter the Worker. Neither is
   persisted by Ankka.
4. The restricted Worker and its SQLite `AdminState` Durable Object are
   created. The object atomically tracks the installation, one-time capability,
   expiry, and revision. On first execution the customer Worker generates its
   Ed25519 ownership key and stores only its authenticated encrypted form and
   public key. The callback reads back the exact
   Worker/version/deployment/namespace graph and the enabled temporary
   `workers.dev` setting through the management API.
5. The installer signs an ownership handoff binding account, Worker, namespace,
   release hash, install ID, and capability commitment, then revokes, proves
   revocation, and discards the Stage 1 grant. Runtime propagation is not
   awaited while the grant is live.
6. An installer page polls only the inert customer `/health` route with no
   token or capability. The route allows only the exact installer origin and
   reports the reviewed asset, SQLite availability, `INCOMPLETE` state, and
   ownership public key. The installer signs an ownership certificate binding
   that key to the exact provider read-back and signed handoff; this needs no
   Cloudflare management grant.
7. Only after that proof does the installer release the one-time capability
   from its short-lived authenticated `__Host-` HttpOnly cookie into a URL
   fragment. The customer origin clears the fragment before consuming the
   capability same-origin; Ankka does not cross-origin POST it into the Worker.
8. A consumed/replayed capability and post-consumption health check are
   verified before Stage 2 starts.

The restricted runtime exposes only:

```text
GET  /health
POST /bootstrap/continue
POST /oauth/start
GET  /oauth/callback
```

Everything else fails closed. Discovering the temporary hostname is not enough
to start or take over an installation.

### Stage 2 — code-only relay and customer convergence

1. The Gateway verifies and adopts the signed Stage 1 ownership handoff.
2. The Gateway generates the verifier, S256 challenge, state, and nonce. The
   verifier is held in a bounded `__Host-` HttpOnly, Secure, SameSite=Lax cookie,
   not in Ankka or durable management state.
3. The Gateway presents a signed, expiring relay ticket for one fixed operation.
   `auth.ankka.ai` maps that operation to the compile-time scope ceiling; no
   caller supplies scopes or arbitrary endpoint authority.
4. Cloudflare redirects its code to `auth.ankka.ai`. The relay verifies state
   and redirects only the code and original Gateway state to the exact signed
   Gateway callback. It has no token-exchange transport.
5. The Gateway atomically arms the attempt before exchange, exchanges directly
   with Cloudflare, rejects refresh tokens or a non-exact scope set, and checks
   that `/accounts` returns only the handoff account.
6. The grant stays in the Durable Object's memory, never in its storage, and
   runs the existing intent-journaled, receipt-owned reconciler in passes:
   the callback arms the attempt and answers with a page that follows the
   status route, and each pass runs from a Durable Object alarm, which is its
   own invocation with its own subrequest budget. The reconciler pauses after
   fixed journal transitions (management policy verified, Gateway resources
   submitted, custom domain verified) and proves each resource once per pass,
   so no pass makes more than about 30 provider calls where a Workers Free
   account allows 50 per invocation; one invocation needed 113. It refuses
   foreign or ambiguous resources instead of adopting or overwriting them.
   An object restart between passes loses the grant; the next pass then
   settles `INCOMPLETE` with `grant_lost` rather than resuming from anything
   durable, and an attempt older than fifteen minutes is revoked and settled
   `INCOMPLETE` with `convergence_deadline` instead of running on.
7. The last pass disables `workers.dev`, records the terminal verification
   of everything but the runtime, marks the attempt finalizing, arms an
   alarm, and only then publishes the clean recovery-capable final runtime,
   drops the bootstrap nonce and revokes the grant. Cloudflare restarts the
   Durable Object on the new code as soon as the Worker has a new version
   and refuses storage to the pass that uploaded it, so that pass writes
   nothing after the upload: the journal keeps `final_runtime` armed, and
   the final runtime's own alarm handler moves a finalizing attempt to
   `READY`. The final runtime answering at all is the proof the shell could
   not write. Where nothing restarts after the upload (recovery in the
   final runtime, tests, the harness in Node) the journaled path is
   unchanged and completes the journal once the final runtime is verified.

`auth.ankka.ai` must disable request/query logging and traces for the callback,
redact the complete URL, and return `Cache-Control: no-store` and
`Referrer-Policy: no-referrer`. An OAuth code is less useful without the PKCE
verifier, but it is still a short-lived sensitive artifact and is treated as
such.

Source credentials such as Google or BLS are entered only after management
Access is enforced and are submitted directly to the customer Gateway. They do
not transit `deploy.ankka.ai` or `auth.ankka.ai`.

## Fixed operations

| Operation | Executor | Scope ceiling |
| --- | --- | --- |
| `bootstrap` | hosted installer | `workers-scripts.write` |
| `install` | customer Gateway | the seven exact Stage 2 scopes above |
| `upgrade` / `rollback` | customer Gateway | `workers-scripts.write` |
| `source-add` / `source-update` / `source-remove` | customer Gateway | `zone-access.write`, `mcp-portals.write` |
| `uninstall` | customer Gateway | union derived only from checksum-valid receipt resource kinds |
| `uninstall-finalize` | hosted installer | `workers-scripts.write` |

There is no generic scope request, arbitrary Cloudflare request proxy, generic
`repair`, or browser-provided uninstall resource list. An incomplete install is
resumed through the fixed `install` operation. A post-READY repair operation is
deferred until its exact mutations and scope ceiling are demonstrated.

### Later-operation relay-ticket issuance

Stage 1 issues the initial `install` ticket only from its exact provider
read-back and token-free customer health proof. After adoption, the Gateway
requests tickets only by proving possession of the customer-owned Ed25519 key
certified during installation. A signed preflight is required before challenge
allocation, the relay stores hashes only, and successful proof consumes the
challenge exactly once. The certificate fixes the account, Worker, namespace,
callback, and public client, while the route fixes the operation; neither the
Gateway nor browser can submit arbitrary scopes or a replacement callback.

The relay retains its ticket-signing HMAC key only at `auth.ankka.ai`. The
Gateway retains only the ownership certificate, public key, and AES-GCM-sealed
private-key ciphertext in customer state; its wrapping key is a customer Worker
secret. Losing or rotating that secret without a reviewed key-rotation flow
removes silent proof capability and requires an explicitly authorized recovery
path. It never justifies copying the relay HMAC key or a Cloudflare management
credential into the Gateway.

## Recovery and uninstall

`INCOMPLETE`, `CONVERGING`, and `READY` are durable convergence states, not
evidence that a token was stored.

- A partial write, token-exchange failure, invocation loss, or unconfirmed
  revocation leaves the installation `INCOMPLETE` and requires fresh OAuth.
- A stale or duplicate callback fails its atomic revision check before token
  exchange.
- `READY` is one-way. Bootstrap capability, session, and PKCE attempts are
  erased and the restricted routes do not reopen.
- A lost bootstrap session can be rotated only through a fresh narrow Stage 1
  authorization; it cannot recover a management token.

The root Worker cannot safely delete itself before revoking its grant, so
uninstall is intentionally split:

1. The customer Gateway verifies receipts, deletes only dependent receipt-owned
   resources, activates an inert recovery-capable release, retires `AdminState`,
   disables `workers.dev`, emits a signed tombstone, revokes, and discards its
   grant.
2. A fresh hosted `uninstall-finalize` authorization reauthenticates the
   original signed ownership history, validates the ready receipt, tombstone,
   inert release, provider read-back, account, exact Worker, and exact namespace,
   then deletes only that namespace and Worker and revokes its grant.

Foreign resources remain untouched. A handoff expiry limits initial adoption;
once adoption is receipt-proven, the signed Ed25519 history remains usable to
authenticate later cleanup without trusting an expired bearer handoff.

The live canary passed self-update, unknown-outcome recovery, rollback,
customer-side dependent cleanup, inert-release verification, wrapping-secret
removal, namespace retirement, `workers.dev` disablement, hosted root
finalization, absence read-back, and revocation without widening either stage.

## Security and architecture contentions

- **Provider scope is broader than the operation.** `workers-scripts.write`
  can affect every Worker in the selected account. Fixed code paths, fresh
  names, signed releases, exact account checks, receipts, read-back, and prompt
  revocation are compensating controls, not equivalent provider isolation.
- **There are two consent moments.** Hiding the second Cloudflare authorization
  would either put broader authority in Ankka or require a retained credential.
  The UI can present both as one guided install, but it should not claim one
  grant or one consent screen.
- **Crash-time revocation is not guaranteed.** If an invocation disappears
  after exchange but before revocation, the non-refresh access token can remain
  valid until Cloudflare expires or revokes it. Persisting it for retry would
  violate the stronger no-stored-credential boundary.
- **Runtime readiness must be split from the OAuth callback.** Management API
  read-back can succeed before a new `workers.dev` hostname serves the release.
  Repeated edge polling in the same callback also competes with cleanup and
  revocation for the Worker's subrequest budget. A free-plan canary exhausted
  its 50 external subrequests after a long poll loop. The final design therefore
  revokes after bounded management read-back and performs token-free browser
  readiness polling afterward.
- **Post-revocation failure requires fresh authority.** If edge readiness or
  customer adoption fails after revocation, the restricted Worker remains
  `INCOMPLETE`; retry or cleanup uses a fresh narrow Stage 1 authorization. No
  token is retained to make that recovery silent.
- **Provider revocation and dashboard authorization rows are distinct live
  observations.** The revocation endpoint made the access token unusable, but
  Cloudflare's Connected Applications page retained an authorization row until
  it was manually removed. No refresh token was issued. The product must not
  equate a lingering dashboard row with a proven-live token, but should account
  for the row and possible repeat-consent UX during final qualification.
- **OAuth-client creation must be idempotent.** The dashboard returned timeout
  or service-unavailable errors while disposable clients had in fact been
  created. Provisioning must list and reconcile the intended client before any
  retry so it cannot create duplicate authorization surfaces.
- **Relay metadata is sensitive.** Codes, state, callback URLs, account IDs,
  provider errors, and tokens must not enter logs, traces, telemetry, browser
  history beyond the unavoidable redirects, or exception strings.
- **OAuth scope IDs can change.** The live picker currently maps Access apps
  and policies to `zone-access.write` and organization/IdP reads to
  `access-acct.read`. Release qualification must detect catalogue drift.
- **Ownership-key persistence needs a separate customer secret.** Cloudflare
  Workers can generate non-extractable Ed25519 keys, but Durable Object storage
  and structured cloning cannot persist their `CryptoKey`. The qualified
  fallback stores only AES-GCM ciphertext in the customer Durable Object and
  keeps the wrapping key in a customer Worker secret binding. Losing that
  binding makes later proof unavailable; copying it outside the customer's
  Cloudflare account or weakening it into plaintext state is not recovery.
- **SQLite mutation counts need an explicit check.** In the live relay Durable
  Object, `SqlStorageCursor.rowsWritten` did not reliably reflect a successful
  upsert. Challenge allocation and exact consume therefore execute
  `SELECT changes()` immediately in the same synchronous transaction. A later
  storage-adapter change must preserve and requalify that atomic behavior.
- **Same-account canary transport was not the production topology.** The live
  proof harness used a Cloudflare Service Binding from the Gateway to the relay
  because same-account public `workers.dev` fetches can loop or fail. The
  production boundary remains public HTTPS from the customer account to the
  independently hosted fixed `auth.ankka.ai` origin. **Qualified 2026-09-03
  (approval path):** the real auth entrypoint on a disposable custom domain
  received challenge, proof, ticket, and start over public HTTPS from a
  disposable Gateway Worker in the same account (a custom-domain relay host
  avoids the `workers.dev` loop), and relayed only `code` and the Gateway's
  state to the certified callback after human consent. Two defects were found
  and fixed by that run: the relay challenge store rejected the `install`
  operation, and the relay callback rejected Cloudflare's echoed `scope`
  parameter. Cross-account isolation and the decline path were not exercised
  live; see `docs/CLOUDFLARE_RELAY_TOPOLOGY_QUALIFICATION.md`.
- **Team writes are excluded from V1.** The default two-stage product can keep
  its no-permanent-management-credential boundary because the Team editor is
  disabled and administrators manage policy in Cloudflare. Cloudflare confirms
  that API tokens cannot be scoped to one reusable Access policy. A future
  editor must either requalify resource-scoped member OAuth after the beta gap
  is fixed or explicitly accept an opt-in account-wide Access-policy token; the
  latter must not be presented as resource-isolated or become the default.
- **Lifecycle ownership must stay intact.** Existing target binding,
  intent-journal, collision, receipt, adoption, rollback, and cleanup rules are
  reused. The account-only Stage 1 target is bridged into them through the
  signed ownership handoff; it is not silently treated as a full existing
  install target.

The installer may retain its existing documented, session-scoped funnel
events. Tokens, codes, account or resource IDs, provider responses, and free
form Cloudflare metadata are outside that telemetry contract.

## Implemented feature-disabled boundary

The candidate primitives in `apps/installer/src` now cover:

- fixed operation, scope, endpoint-family, mutation, and postcondition
  authority;
- signed expiring code-only relay and signed Gateway relay ticket;
- customer-owned Ed25519 ownership certificates, AES-GCM-sealed proof keys,
  signed pre-allocation challenge requests, and one-time hash-only challenge
  consumption for later fixed operations;
- no-store relay HTTP responses with fixed callbacks and redacted failures;
- one-time bootstrap capability and atomic
  `INCOMPLETE → CONVERGING → READY` state machine;
- public-client PKCE exchange in the customer callback, exact scope/account
  checks, non-serializable request-local grant, revocation, and discard;
- restricted four-route bootstrap adapter;
- signed Stage 1 ownership handoff plus adoption receipt and historical cleanup
  proof;
- final convergence evidence and failure-injection tests;
- receipt-bound two-part uninstall and hosted root finalizer.

The candidate remains unwired. Before activation it still needs:

1. wire the implemented SQLite compare-and-set adapter into the actual
   restricted `AdminState` Durable Object, including sealed ownership-key state;
2. a dedicated hosted Stage 1 executor around the request-local grant wrapper;
3. the existing reviewed reconciler bound to the customer callback;
4. the proven split, token-free readiness and same-origin fragment handoff
   integrated into the final non-technical UX;
5. bind the qualified ownership proof and later-operation ticket protocol to
   the production `auth.ankka.ai` Durable Object and public HTTPS topology;
6. release review of both OAuth clients, signing/HMAC/wrapping-key custody,
   callback log suppression, scope-catalogue drift, and confirmation that V1
   Team mutation surfaces and permanent management credentials remain absent
   from the default installation.

## Cloudflare references

- [Create an OAuth client](https://developers.cloudflare.com/fundamentals/oauth/create-an-oauth-client/)
- [Integrate an OAuth client](https://developers.cloudflare.com/fundamentals/oauth/integrate-with-cloudflare/)
- [Authorize an application and select resources](https://developers.cloudflare.com/fundamentals/oauth/authorizing-an-application/)
- [List accounts](https://developers.cloudflare.com/api/resources/accounts/methods/list/)
- [List zones](https://developers.cloudflare.com/api/resources/zones/methods/list/)
- [Upload a Worker](https://developers.cloudflare.com/api/resources/workers/subresources/scripts/methods/update/)
- [Delete a Worker](https://developers.cloudflare.com/api/resources/workers/subresources/scripts/methods/delete/)
- [List Durable Object namespaces](https://developers.cloudflare.com/api/resources/durable_objects/subresources/namespaces/methods/list/)
- [Configure a Worker subdomain](https://developers.cloudflare.com/api/resources/workers/subresources/scripts/subresources/subdomain/methods/create/)
- [`workers.dev` routing](https://developers.cloudflare.com/workers/configuration/routing/workers-dev/)
- [Workers subrequest limits](https://developers.cloudflare.com/workers/platform/limits/#subrequests)
- [Workers Web Crypto](https://developers.cloudflare.com/workers/runtime-apis/web-crypto/)
- [Durable Object SQLite storage API](https://developers.cloudflare.com/durable-objects/api/sqlite-storage-api/)
- [Access Durable Object storage](https://developers.cloudflare.com/durable-objects/best-practices/access-durable-objects-storage/)
- [Attach a Worker Custom Domain](https://developers.cloudflare.com/api/resources/workers/subresources/domains/methods/update/)
- [List Worker routes](https://developers.cloudflare.com/api/resources/workers/subresources/routes/methods/list/)
- [Create an Access application](https://developers.cloudflare.com/api/resources/zero_trust/subresources/access/subresources/applications/methods/create/)
- [Create an Access policy](https://developers.cloudflare.com/api/resources/zero_trust/subresources/access/subresources/applications/subresources/policies/methods/create/)
- [List identity providers](https://developers.cloudflare.com/api/resources/zero_trust/subresources/identity_providers/methods/list/)
- [Create an MCP server](https://developers.cloudflare.com/api/resources/zero_trust/subresources/access/subresources/ai_controls/subresources/mcp/subresources/servers/methods/create/)
- [Create an MCP Portal](https://developers.cloudflare.com/api/resources/zero_trust/subresources/access/subresources/ai_controls/subresources/mcp/subresources/portals/methods/create/)
- [Create a DNS record](https://developers.cloudflare.com/api/resources/dns/subresources/records/methods/create/)

The relay boundary is modeled after the reviewed behavior in
[HQBase/hqbase](https://github.com/HQBase/hqbase) and
[HQBase/hqbase-cloudflare-auth](https://github.com/HQBase/hqbase-cloudflare-auth):
fixed client and redirect identity, fixed operations/scopes, signed expiring
state, and no code exchange in the relay.

# Customer self-service

Ankka MCP Gateway is installed into and operated from your Cloudflare account.
The hosted installer coordinates a reviewed action, but Cloudflare resources,
Access policies, logs, source configuration, and upstream credentials remain
under your control.

The public source tree is fail-closed. Installation and removal are available
only from a reviewed installer release that explicitly enables those
capabilities and pins an exact signed gateway release. A preview or disabled
installer must not be treated as production deployment authority.

An active reviewed hosted installer also requires its three Worker-native rate
limit bindings. New anonymous sessions are keyed by a purpose-separated HMAC of
the transient Cloudflare client address. Authenticated session polling and
mutations use separate HMAC purposes over the opaque session ID, so neither raw
addresses nor session IDs are logged, stored, or sent to a limiter. The
fixed-length session cookie also carries a truncated HMAC so the Worker can
reject random cookie spray before resolving a Durable Object. These cost
controls do not replace OAuth, CSRF, or receipt ownership.

The live public-cutover host and an optional isolated private canary are
intentionally different. `deploy.ankka.ai` remains without an Ankka Access
application and serves the disabled shell until the final activation gate.
Private Access tooling may be used only for a separately approved isolated
canary; it is not temporarily installed on the live host and is not recreated
during public rollback.

Absence of Access alone is not evidence that the service is ready. Before
activation, the public preflight performs a complete Access-app read, proves
zero selector can cover the live hostname, and confirms cookie-free requests
reach the exact disabled shell without an Access redirect. After activation,
the full public gate repeats the Access read, requires the reviewed installer
to report `mutationsEnabled: true`, loads its signed root, and verifies the
exact channel-bound Ed25519 release descriptor. It also checks that the
callback and both fixed release paths reach the application without an Access
redirect. Cloudflare Network Error Logging remains enabled on the Ankka-owned
hosted zone, so its edge may add
`NEL`/`Report-To`; those headers are permitted platform metadata, not public-gate
success evidence. The session-path observation is `HEAD` and does not mint
customer state. A final browser run must come from an unrelated fresh
Cloudflare account. Until those checks in the
[public release checklist](PUBLIC_RELEASE_CHECKLIST.md) are green, treat
`https://deploy.ankka.ai` as preview or unavailable rather than customer-ready.

Customer-deployed gateways have a separate, testable no-Ankka-telemetry
boundary. Their signed release contract disables Workers metrics, dependency
instrumentation, and observability for the primary, cleanup, and retirement
variants. Deployment requires `logpush: false` and no tail consumers, and the
application payload emits no analytics beacon or `NEL`/`Report-To` header. Its
only routine Ankka-origin request is anonymous signed release discovery: it
sends no account, hostname, user, cookie, authorization, or referrer. A
customer’s Cloudflare zone may independently add its own platform reporting
headers after the Worker responds; Ankka neither configures nor receives those
reports.

The Ankka-hosted installer itself records a fixed, identifier-free setup funnel
by default, separately from NEL. It contains milestone, public release/channel,
coarse outcome, and flow fields only; it never receives a customer-gateway
event. See [Hosted installer analytics](HOSTED_INSTALLER_ANALYTICS.md) for the
exact destination, schema, retention, limitations, and event allowlist. Using
the public source without Ankka's hosted installer does not write to Ankka's
dataset.

## Before you start

You need:

- a Cloudflare account with an active zone for the gateway hostnames;
- permission to create Workers, Durable Objects, DNS, Access applications and
  policies, and Cloudflare MCP Portal resources in the selected account;
- Cloudflare Zero Trust configured for that account;
- one hostname for the employee-facing MCP Portal and a different hostname for
  the customer-resident management dashboard; and
- the primary administrator email and any additional administrator emails that
  should initially be allowed through Cloudflare Access. These addresses also
  form the initial Portal audience.

The browser flow uses Cloudflare OAuth. Do not create an API token for Ankka,
paste credentials into the wizard, or place credentials in URLs or
configuration. Ankka never needs an upstream provider token.

## Install a gateway

1. Open `https://deploy.ankka.ai` and choose **Sign in with Cloudflare**.
2. Select the intended Cloudflare account and active zone. Discovery is
   read-only; selecting a target does not create or change resources.
3. Enter a gateway name, the employee-facing Portal hostname, the separate
   management hostname, and the exact primary and additional administrators.
4. Review the complete portal-only plan. The current first-run wizard creates
   the customer Worker, Durable Object, dashboard assets, management Access
   application and policy, then the Portal, Portal Access application and
   policy, and DNS record. It does not ask for or install an upstream source.
5. Choose **Authorize with Cloudflare**, review Cloudflare's consent screen,
   and approve the short-lived operation-scoped grant. The installer journals
   progress before each write and does not persist the grant.
6. Keep the result page open until it reports success. Save the displayed MCP
   URL and management URL.
7. In the customer dashboard, add the first MCP source. Use a public HTTPS MCP
   URL or a standards-compliant per-user OAuth source, then review and freeze
   the exact read-only tool allowlist. Wildcard tools and credential-bearing
   URLs are rejected. After applying the source, connect an MCP client to the
   Portal URL and complete Cloudflare Access with an allowed identity.

If the installer detects an existing coherent Ankka gateway, it performs no
writes and does not adopt or overwrite it. Open the linked customer management
dashboard to manage or remove that installation.

## Operate the gateway

Open the management URL and authenticate through the customer's Cloudflare
Access policy.

- **Overview** shows the installed release, MCP endpoint, audience, source
  state, and custody boundary.
- **Sources** discovers a public MCP catalogue or records an independently
  verified protected source, freezes an exact tool allowlist, and creates a
  one-time Cloudflare authorization for the reviewed change.
- **Updates** verifies the installed signed release channel and prepares an
  explicit update or rollback. Updates replace only Worker code and management
  assets; sources, Access, DNS, credentials, and Durable Object data stay in
  place.

Saving a source draft changes only customer-owned Durable Object state.
Applying a source, updating, rolling back, or removing the gateway always
requires a new short-lived Cloudflare authorization. Per-user upstream OAuth
happens through the customer's Portal; Ankka does not receive those tokens.

## Remove a gateway

1. In the browser that you will use for removal, open the hosted installer and
   complete its read-only Cloudflare discovery for the account. Enter the same
   gateway name and hostnames. The fresh preflight scans the candidate sets
   twice; a coherent existing installation produces a secret-free summary and
   performs no Cloudflare writes. A collision or incomplete match stops instead
   of being adopted.
2. Follow the summary's link to the customer management dashboard and
   authenticate through Cloudflare Access. Keep this in the same browser so the
   one-time handoff remains bound to the detected installer session.
3. On **Overview**, choose **Review teardown plan**. The dashboard creates a
   one-time handoff bound to the Access-verified actor, selected account, and
   installation. The handoff contains no Cloudflare credential.
4. Review the installation identity and bounded removal steps in the installer.
5. Approve the plan, choose **Authorize with Cloudflare**, and approve the new
   short-lived grant.
6. Leave the result page open while the journal-backed teardown runs. The
   gateway verifies receipt ownership before every deletion and stops on
   conflicting or ambiguous state. Cleanup and retirement code comes from the
   exact immutable release reported by the installed gateway, not whichever
   release is currently promoted on its update channel. Before deletion, the
   installer proves that the active Cloudflare version and deployment match
   every exact module byte and expected plaintext binding from that bundle; a
   matching Worker tag alone is not accepted. The Versions API does not expose
   an immutable static-asset manifest or content digest, so active asset content
   is not used as teardown release authority.
7. Confirm that the result reports removal and zero Ankka-managed residue. The
   employee MCP URL and management URL should no longer resolve to the removed
   gateway.

If the preflight finds only a partial or conflicting installation, or the
management Access boundary cannot authenticate an administrator, self-service
stops. Do not force a fresh install over it; repair the customer-owned Access
boundary or use a separately reviewed manual recovery with provider-state
evidence.

The teardown removes only resources proven to belong to that installation. It
does not delete unrelated Cloudflare resources or upstream provider accounts.
A separately configured advanced source credential or OAuth client remains
customer-managed and may require its own provider-side revocation. Cloudflare
also retains an Advanced Certificate after the management Custom Domain is
removed; it is outside the reviewed OAuth scope set and must be reviewed or
removed manually in Cloudflare.

## Recovery and support evidence

Do not delete a pending receipt, journal, recovery record, or installation
authority to make an error disappear. Those records are what let a retry prove
whether a resource was created or removed before an interrupted request.

If an action stops:

1. keep the result page open and use a retry only when the page offers one. If
   the customer Worker is still available, the installer may reuse the current
   reviewed action or require a fresh dashboard action. If the journal proves
   that the customer gateway was already removed, the installer instead offers
   a hosted recovery plan for up to 24 hours; that path requires a fresh
   Cloudflare authorization but no longer depends on the removed dashboard or
   its one-time action key;
2. record the displayed stable error code, installation ID, and release when
   shown; and
3. verify provider state before any manual change.

Never send OAuth codes, access tokens, cookies, private keys, raw provider
responses, or credential-bearing screenshots as support evidence. The product
is designed to expose stable, secret-free status and recovery codes instead.

For the exact release and promotion status, see the
[first public release checklist](PUBLIC_RELEASE_CHECKLIST.md). For update
semantics and recovery behavior, see [Gateway updates and rollback](UPDATES.md).

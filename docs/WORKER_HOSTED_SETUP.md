# Worker-hosted installer configuration

The hosted landing page starts the initial deployment without collecting a
gateway name, domain, or administrator email. The first Cloudflare approval
requests exactly `workers-scripts.write zone.read` and selects one account.

The hosted callback lists active zones using the exact account filter. It
rejects an incomplete or inconsistent list before deploying the Worker.
An empty list is allowed: the first approval can create the setup Worker and
register its account workers.dev subdomain without a custom domain.
Discovery is bounded to 100 domains so the signed handoff fits its size limits.
It reads the account Workers subdomain and reuses it. Explicit missing-subdomain
responses permit registration of a generated `ankka-<random>` label, followed
by read-back verification. Permission and transient errors are not absence.
The account subdomain is shared infrastructure and is never cleanup-owned.
Cloudflare's registration API is also an update API: the installer rechecks
absence immediately before registration, but that check and write are not
atomic. Parallel first-time account setup must be included in live qualification.

The initial plan identifies a release and generated installation/Worker name.
It does not predict the final domain or derive Worker identity from a display
name. The initial grant is revoked before token-free Worker readiness checks
and browser handoff.

The handoff contains a signed setup permit: the initial plan and ownership
handoff, eligible domain choices, exact bootstrap callback, and the ownership
public key read from the deployed Worker. The existing one-time capability
authenticates the browser to that Worker. The permit and configuration draft
contain no Cloudflare grant and may be stored in its Durable Object. The setup
session and permit expire with the original ten-minute capability.

The Worker serves the gateway form, domain dropdown, and review page. When no
active domain was discovered, it instead explains the custom-domain requirement,
shows example management and MCP addresses, and links to Cloudflare's dashboard
and domain setup guide. Final configuration and certification still require a
domain from the signed list. Domain choices are a snapshot from the first
approval: after adding and activating a domain, start a new deployment to
discover it with a fresh grant. No grant is retained to refresh that list.

Each review signs the selected configuration and permit digest with its existing
ownership key. `POST /api/bootstrap/configure` on the fixed hosted issuer checks
the permit, Worker signature, release, expiry, and allowed zone. It returns the
final plan, a handoff for the same physical Worker and namespace, and a
certificate binding the final callback. This endpoint accepts no Cloudflare
grant, uses no arbitrary destination, and persists no request body. It uses
signature authentication rather than a hosted browser session or CORS access.

Final plans carry `bootstrapIdentity` so adoption can verify the initial
Worker's original plan bindings while independently checking the reviewed final
plan. Edits can change display names and hostnames without replacing the Worker.
Configuration locks when the second approval starts. The fresh grant reasserts
the account, selected zone, and hostname availability, then runs the existing
installation and revocation flow. Updates and removal retain their existing
operation-specific scope sets.

While installation or recovery holds its temporary grant, the customer Worker
keeps one timer bounded by the existing fifteen-minute convergence deadline.
This prevents ordinary idle hibernation between alarm passes when the progress
page is not being polled. Settlement releases the timer; unexpected restarts
still lose the grant and stop the attempt. No credential is persisted.

In-flight fully configured plans remain readable for recovery. Newly started
deployments use the configuration-free bootstrap path. Hosted session evidence
expires after one hour; the Worker owns its setup draft. No MCP source-provider
credentials enter either stage.

After handoff, **Start a new deployment** creates a new hosted session with a
new CSRF token and clears the old approval cookie. The previous session and its
evidence expire normally. Restart requires the existing session's same-origin
CSRF check and is refused while approval, handoff, or cleanup is pending.

## Validation and promotion

Synthetic tests cover account filtering, pagination, absent versus denied
subdomain reads, existing-subdomain reuse, registration/read-back, revocation
before handoff, configuration signing and edits, foreign domains and keys,
expiry, browser-session/origin checks, and final installation from the initial
Worker identity.

Before promotion, verify the registered confidential client accepts the exact
combined first-stage scopes through real browser approvals. A fresh account
with no Workers subdomain or active domain must complete registration, Worker
deployment, grant revocation, and handoff to the domain guide. An account with
an active domain must complete the two-approval installation, including reuse
of its Workers subdomain and final domain configuration. Verify cleanup leaves
the shared account subdomain intact. An isolated API-token registration test or
live evidence for `workers-scripts.write` alone cannot replace the fresh-account
OAuth check. Source changes do not alter activation pins, OAuth registrations,
or live deployments.

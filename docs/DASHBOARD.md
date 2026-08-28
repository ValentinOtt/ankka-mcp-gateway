# Customer dashboard

## Product boundary

The gateway has two distinct surfaces:

1. `deploy.ankka.ai`, a hosted short-lived installer that reviews an exact
   plan and performs bounded Cloudflare authorization; and
2. a customer-resident dashboard for ongoing source and runtime management.

The dashboard, its Worker, Durable Object state, Access boundary, and logs live
in the customer's Cloudflare account. Its management origin must be different
from the employee-facing MCP Portal hostname.

```text
deploy.ankka.ai                         customer Cloudflare account
short-lived install session     --->   access-admin.example.com
                                             |
                                             +-- Overview
                                             +-- Sources
                                             +-- Updates

employee MCP clients            --->   mcp.example.com
                                             |
                                             +-- Cloudflare MCP Portal
                                             +-- approved upstream MCPs
```

Provider credentials are not dashboard fields. Per-user upstream authorization
happens through Cloudflare Portal, and Cloudflare mutation grants remain only
in the connected hosted callback for one reviewed action.

## Source management

Administrators add one public HTTPS MCP endpoint and inspect it before saving.
For a public source, the customer Worker loads the live `tools/list` catalogue,
preferring MCP `2026-07-28` and falling back to the compatible `2025-06-18`
initialize/session lifecycle. It accepts JSON or SSE, follows bounded opaque
pagination, sends no authorization header, and retains no MCP session ID.

For a protected source, the unauthenticated probe must return the standard MCP
Bearer challenge with a public HTTPS `resource_metadata` URL. The administrator
then enters independently verified exact tool names. Applying the draft creates
the source resources and maps the source into the customer Portal with
per-user OAuth. OAuth client secrets, bearer tokens, arbitrary credential
headers, and credential-bearing URLs are never accepted.

Tool descriptions and MCP safety annotations are untrusted source-authored
review aids. They do not authorize a tool. The V1 boundary is always an exact,
frozen allowlist; wildcard and automatically expanding lists are rejected.

Saving a draft changes only customer Durable Object state. Applying it requires
a fresh ten-minute authorization bound to the Access-verified actor, account,
source revision, source hash, Worker, and management origin. The Worker journals
each source resource and the Portal mapping without retaining the grant.

## Access boundary

Portal users are established by the reviewed installation and compiled into
the source and Portal Access policies. Dashboard administrators are a separate
bootstrap boundary controlled by the management origin's Cloudflare Access
policy and the Worker's exact deployment allowlist.

The dashboard displays audience counts but does not offer a second settings
implementation for Access or Portal hostnames. Those deployment-owned values
cannot be silently changed from ongoing source management.

## Updates and rollback

The Updates screen checks only the signed release channel installed with the
gateway. It shows the current and available releases, signed notes, normal
update classification, and whether a previous Worker version is retained.
A channel outage does not block source management or an available rollback.

Update and rollback are explicit mutations. Each starts a new operation-scoped
Cloudflare OAuth handoff after review. The customer page polls its own journal
after consent. A normal update changes only Worker code and dashboard assets,
stages the candidate at 0%, probes its exact version, and then activates it.
Configuration, sources, Access, DNS, credentials, and Durable Object data remain
in place. Rollback changes the Worker version and never rolls back data.

See [Gateway updates and rollback](UPDATES.md) for the signed-channel contract.

## Gateway teardown

The Overview screen can prepare a one-time teardown handoff after an
administrator has first used the hosted installer's zero-write fresh preflight
to identify the exact existing gateway in the same browser. The customer
Worker binds that handoff to the Access-verified actor, Cloudflare account,
installation ID, Worker, management origin, and a ten-minute action key. No
Cloudflare credential is included in the handoff.

The hosted installer checks the detected installation and selected account,
shows the bounded removal plan, and requests a fresh Cloudflare grant only
after explicit approval. The customer Worker then proves its checksum-verified
root receipt before deletion can begin. Names, hostnames, or provider IDs alone
are never adoption or removal authority.

The one-time action key is held only by the browser handoff and is never stored
by either side. Once the hosted journal verifies that the customer gateway was
removed, any interrupted management-resource cleanup continues through a fresh
hosted recovery authorization within the retained 24-hour window; it does not
depend on reopening the deleted dashboard.

## Agent-native management

The same React application registers bounded browser-local WebMCP tools for:

- listing, discovering, and saving source drafts;
- preparing an exact source apply handoff;
- checking and reviewing a signed update; and
- preparing an approved update or rollback handoff; and
- preparing a destructive gateway-teardown handoff for user review.

Agent tools return authorization URLs to the user. They cannot approve OAuth,
request a token, or bypass the same customer Worker APIs used by the human UI.

## Single source and release build

`apps/admin` is the only dashboard source. It uses the lean public Cloudflare
OS stack:

- React 19 and TypeScript;
- Vite and Tailwind CSS 4;
- Cloudflare Kumo and Phosphor icons;
- TanStack Router; and
- Vitest and Testing Library.

`npm run build:admin` creates deterministic, fingerprinted assets in the
ignored `apps/admin/dist` directory. The offline release-candidate builder
first proves the dashboard source, package manifests, lockfile, and hand-written
payload components match one clean public commit. It then rebuilds the SPA and
maps its output into the signed release path `payload/admin`.

There is no checked-in second dashboard, static management shell, or generated
admin release output. The reviewed primary Worker remains
`payload/worker/index.js`; it serves the compiled SPA through the Cloudflare
`ASSETS` binding with `/api/*` routed through the Worker first.

## Security and state

The management Worker validates the Cloudflare Access JWT issuer, audience,
signature, verified email, and exact deployment administrator list. It rejects
cross-origin mutations and does not trust the convenience identity header by
itself.

The Durable Object stores only secret-free desired state, exact source
allowlists, action journals, and runtime version metadata. Telemetry is off.
Cloudflare and upstream credentials must not appear in configuration, state,
logs, errors, API responses, browser storage, or release output.

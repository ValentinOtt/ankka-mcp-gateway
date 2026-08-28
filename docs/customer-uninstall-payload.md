# Customer Worker release payloads

The `payload/` directory contains the four hand-authored components consumed by
the signed gateway release builder. Worker modules ship directly as ES modules;
there is no local bundling or implicit environment lookup for those components.
The fifth component, the customer dashboard, is rebuilt deterministically from
`apps/admin` and mapped to `payload/admin` only in the new release candidate.

The resulting release candidate has five exact components:

- `payload/worker/index.js` is the primary customer runtime. It exports
  `AdminState` and `default`, accepts the canonical HMAC-authenticated bootstrap
  request at `POST /__ankka/bootstrap`, accepts a separate exact source action
  at `POST /__ankka/source-action`, and exposes Access-JWT-gated status, source
  discovery, source draft, and action-status APIs after installation.
- `payload/admin` is generated from the single React/Kumo source in
  `apps/admin`. It loads same-origin, content-fingerprinted CSS and JavaScript
  and renders no provider locator or durable receipt. Its human UI and WebMCP
  tools share the same bounded APIs and one-time authorization handoff.
- `payload/installer` is the hosted installer shell. It consumes the hosted
  session, selection, plan, deploy, uninstall-plan, and uninstall HTTP
  contracts without persisting tokens or CSRF state in browser storage.

- `payload/worker-cleanup/index.js` is the customer-resident uninstall Worker.
  Its only public mutation is `POST /__ankka/uninstall`. It retains the existing
  `AdminState` SQLite Durable Object export while it removes the exact seven
  receipt-owned resources and writes a checksum-protected `removed` tombstone.
  It first removes every receipt-owned day-two source and reduces the Portal to
  its root mapping, then removes the original seven-resource installation.
- `payload/worker-retirement/index.js` is the inert final Worker deployed only
  after cleanup is proven complete. It always returns `410` and has no binding,
  storage, network, logging, telemetry, or mutation surface.

The files are unsigned source payloads. This repository carries no signing key,
signed release envelope, generated release, or production publication or
deployment authority. Its source tooling is non-authoritative and fails closed
without separately reviewed inputs. Do not treat a local payload digest as
release authority.

The checked-in payload remains unsigned and carries no activation authority.
The primary-to-cleanup receipt handoff and explicit Access-application
ownership model are exact and covered by a chained regression (see below); the
exact payload has also completed a disposable-account canary with a real
employee tool invocation. Signing and activation still require explicit
external, human-reviewed artifacts.

## Primary bootstrap contract

The primary Worker independently validates canonical JSON, exact HMAC-SHA256,
five-minute freshness, target and release environment bindings, and the full
customer settings schema. It rebuilds the same deterministic resource keys,
configuration hash, installation ID, desired-state hash, markers, and identity
hash used by the hosted installer. The Cloudflare OAuth grant exists only in
the request-local provider calls and is never written to Durable Object state,
responses, logs, or the read-only management projection.

Before any replay-sensitive provider call, the Worker saves an exact
`send_armed` record. An unknown result stays pending and is not resent under the
same signed request. A fresh signed request must first resolve the old result by
read. Completion replaces bootstrap state with the exact checksum-protected
seven-resource `ready` receipt under
`ankka-mcp-gateway/uninstall-state/v1`, which is the same key the cleanup
variant later consumes.

### Explicit Access application ownership

Both Access applications are explicit receipt-owned resources, matching the
seven-resource model proven live in the disposable-account canary. The Worker
never adopts an application Cloudflare generated on its own. Creation order and
request shapes are exactly:

1. `mcp_server`;
2. `source_access_application` — `POST /access/apps` with `type: "mcp"`, the
   ownership marker as `name`, and one `via_mcp_server_portal` destination
   bound to the receipt-owned server ID;
3. `source_access_policy`;
4. `portal`;
5. `portal_access_application` — `POST /access/apps` with `type: "mcp_portal"`,
   the gateway name, the Portal hostname as `domain` and single `public`
   destination, and the reviewed Managed OAuth / Dynamic Client Registration
   configuration;
6. `portal_access_policy`;
7. `dns_record`.

Before each Access application create, the Worker lists applications and treats
any application that already claims the server, the Portal hostname, or the
installation's application name as a collision: it returns the fixed,
non-retryable `bootstrap_requires_repair` result and creates nothing further.
After each create, and when settling a journaled `send_armed` intent, it
re-reads the single application by ID and requires the exact shape — name,
type, domain, exactly one destination, and for the Portal application the
exact Managed OAuth projection. Two matching candidates, or one candidate that
is not the exact application, fail closed the same way.

The Worker does not attempt to update an incompatible application: preserving
unrelated and write-only Cloudflare fields must first be proven in the
disposable-account canary. An application that does not expose the exact
reviewed Managed OAuth settings leaves the journal in its `submitted` state and
no later gateway resource is created.

The customer management endpoint verifies the Access JWT signature against the
configured Cloudflare Access issuer, exact audience, expiry, and administrator
email. Its response contains the gateway name and URL, release, approved source,
tool allowlist, and audience counts only. Provider IDs, installation IDs,
receipt evidence, lifecycle state, and credentials are omitted.

### Day-two source actions

An Access-verified administrator may inspect one public or standards-compliant
OAuth MCP endpoint, save its exact tool allowlist as a draft, and prepare a
short-lived source action. A protected endpoint is recognized only from the
standard MCP Bearer challenge and is mapped into Cloudflare Portal with
per-user upstream OAuth. The Durable Object stores the actor, authentication
mode, exact source revision and hash, action-key hash, expiry, resource journal,
and result. The action key, Cloudflare grant, and upstream OAuth grants are
never stored by Ankka; upstream tokens remain in the customer's Cloudflare
account.

The hosted callback verifies the OAuth actor and account plus the claimed
Worker custom domain, temporarily enables only the exact Worker's disabled
`workers.dev` route, and submits one canonical HMAC request. The customer
Worker re-discovers the catalogue, creates the MCP server, explicit source
Access application and policy, and replaces the Portal's complete server
mapping. Every provider intent is durable before mutation. Ambiguous results
become `recovery_required`; a fresh user authorization rotates the action key,
re-reads the pending resource, and resumes without replaying the unknown write.

## Browser asset contract

Both HTML entrypoints use external same-origin assets and contain no inline
script, event handler, or style. The asset basenames carry the first eight hex
characters of their exact SHA-256 digest. The hosted installer supports `/`,
`/gateway`, `/review`, `/deploy`, `/manage`, `/oauth/handoff`, and
`/result`.
Its first step uses a separately revoked read-only OAuth grant to discover the
actor, accounts, and active zones; the browser receives names and an opaque
target hash, never raw account or zone IDs. The later write grant is still
minted only for an exact reviewed plan. Its callback immediately serves the
signed result shell and keeps the grant only in the connected invocation while
the UI polls a provider-ID-free projection of the install journal. The handoff
route moves an encrypted
OAuth attempt fragment into the user's chosen browser without putting it in
the GET request URL, and the result screen
exposes canary-only uninstall review and fresh OAuth confirmation when the
private session advertises that capability.

The browser keeps its session CSRF value only in memory, follows only the fixed
same-origin API surface, and accepts OAuth redirects only at Cloudflare's exact
authorization origin and path. It never renders provider IDs, installation
journal records, customer removal evidence, or credentials.

## Cleanup contract

The cleanup release variant has exactly one module, `index.js`, and no assets.
Its release metadata must declare:

- main module `index.js`;
- compatibility date `2026-08-08` with no compatibility flags;
- one `ADMIN_STATE` Durable Object binding to class `AdminState`;
- an active `AdminState` SQLite Durable Object export;
- no migrations, Preview URL, `workers.dev`, observability, dependency
  instrumentation, or metrics;
- the exact non-secret variables `ANKKA_GATEWAY_RELEASE`,
  `ANKKA_GATEWAY_RELEASE_SHA256`, `CLOUDFLARE_ACCOUNT_ID`,
  `CLOUDFLARE_ZONE_ID`, `CLOUDFLARE_ZONE_NAME`, and `ZERO_TRUST_READY`; and
- one attempt-scoped `ANKKA_UNINSTALL_NONCE` secret.

The endpoint accepts canonical JSON only. The request has exactly:

```text
schemaVersion, requestId, issuedAt, expiresAt, target, release, expected,
cloudflareAccessToken
```

`x-ankka-uninstall-signature` is `sha256=<lowercase hex HMAC-SHA256>` over the
exact request bytes, keyed by the 32-byte unpadded-base64url uninstall nonce.
The Worker rejects cookies, browser origin/referrer authority, Authorization
headers, noncanonical JSON, expired grants, environment drift, receipt drift,
and malformed or oversized input before reading Durable Object state.

### Receipt transition

The cleanup Worker operates exclusively from the receipt the primary Worker
stored. There is exactly one legitimate transition:

```text
ready
  ↓ authenticated uninstall claim + exact receipt equality
uninstalling
  ↓ proven reverse-order cleanup
removed
```

After the uninstall request is authenticated and validated, the Worker reads
`ankka-mcp-gateway/uninstall-state/v1` from `v1:<installationId>`. A stored
`ready` receipt is accepted only when it is a structurally valid canonical
receipt for the claim's installation, release, and target, its checksum
verifies, and it is canonically identical to `expected.readyReceipt` in the
claim. Before the first provider read it is durably replaced by the initial
`uninstalling` envelope, which preserves that receipt as the immutable
`rootReceipt` authority. Absent state, a primary journal that never reached
`ready`, a corrupted or partially matching receipt, and any different receipt
all return `uninstall_request_mismatch` without provider access and without a
write. A claim alone never starts an uninstall. There is no migration or
adoption path.

The ready receipt must contain exactly these resources in this order:

1. `mcp_server`
2. `source_access_application`
3. `source_access_policy`
4. `portal`
5. `portal_access_application`
6. `portal_access_policy`
7. `dns_record`

Cleanup re-reads and proves each exact locator and its provider-visible
ownership before deletion — server and Portal descriptions, policy name
suffixes, the DNS comment, the source application's marker name and server
destination, and the Portal application's hostname — processes the list in
reverse order, journals a
`send_armed` intent before each provider request, and confirms absence before
committing it. An ambiguous DELETE is never replayed under the same request.
A fresh signed request may first settle the old outcome by read, mark a
still-present old intent `not_applied`, and only then arm a fresh attempt.
OAuth material and the HMAC nonce are never stored, returned, or logged.

If the management Durable Object contains day-two source ownership, cleanup
first writes a separate source-removal journal, replaces the Portal mapping
with the original source only, and deletes each additional policy, application,
and server in reverse dependency order. Only after that phase is complete does
the original receipt-owned seven-resource cleanup begin. Older releases that
have draft state but no management-control ownership record take a verified
no-op compatibility path.

While this variant is active, every `/api/*` request returns `423
uninstall_in_progress`; all other paths except the uninstall endpoint return
`404`. Completion returns the exact customer-owned `removed` receipt with an
empty resource list and retains it for idempotent recovery.

## Declarative retirement contract

The retirement release variant also has exactly one module, `index.js`, no
assets, compatibility date `2026-08-08`, and no compatibility flags. Its
module deliberately does **not** export `AdminState`. The direct upload
metadata—not JavaScript source—must declare:

```json
{
  "bindings": [],
  "exports": {
    "AdminState": { "state": "deleted", "type": "durable-object" }
  }
}
```

It must contain no migrations or public bindings, and must disable Preview
URLs, `workers.dev`, observability, dependency instrumentation, and metrics.
The hosted installer is responsible for proving the
retirement version and the customer-owned SQLite namespace lifecycle before
any later Worker-script deletion. This repository contains no callable
deployment path for those operations.

## Local verification

Run the payload-only checks with:

```sh
npm run test:payload
```

Run `npm run check` for the complete repository suite and public-boundary
scan. These tests use in-memory storage and fetch-injected synthetic provider
responses; they make no network or Cloudflare calls.

`test/payload-lifecycle.mjs` runs the real primary Worker to `ready` against a
deterministic explicit-model provider fake. The cleanup tests start from that
produced Durable Object storage, the same provider state, and the exact receipt
the primary returned; they never construct a starting receipt by hand. The
chained regression proves the exact primary-generated receipt is accepted, the
seven created resources are deleted once each in exact reverse order, ambiguous
outcomes retain recovery state, the `removed` tombstone is persisted, a retry
after completion performs no provider mutation, and neither OAuth grant nor
either HMAC nonce ever reaches storage.

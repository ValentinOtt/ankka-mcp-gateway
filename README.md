# Ankka MCP Gateway

Ankka MCP Gateway is the customer-owned edge for connecting a company's
approved MCP sources behind one employee connection. The first target is
Cloudflare MCP Server Portals: the Portal, both explicit Access applications
and policies, DNS, request logs, and encrypted upstream credentials remain in
the customer's Cloudflare account.

> **Status:** public-preview release candidate, not a general production
> release. The live hosted installer is held on the fail-closed disabled shell
> with no Ankka Access application while the retained-key promotion and
> public-exposure gates are completed. The
> exact customer payload has completed a disposable-account lifecycle including
> a real employee Portal tool call and zero-residue removal. Release signing,
> activation, and promotion remain explicit human-reviewed operations.

## Product boundary

This repository is the inspectable source boundary for both the customer-owned
Gateway and Ankka's optional hosted installer. Publishing source does not
publish deployment authority: credentials, signing private keys, generated
releases and production CI permissions remain external.

It owns:

- customer-owned Cloudflare deployment and removal tooling;
- the hosted installer's OAuth, plan-review and orchestration implementation;
- MCP Portal, DNS, and Access desired state;
- exact source and tool allowlists;
- public configuration, receipt, upgrade, and health contracts.

It does not contain Ankka's product dashboard, Wiki semantics, operational
database, billing, customer data, provider credentials, private signing
material, or production Cloudflare account and resource identifiers.

## Shipped offline CLI

`gateway.config.json` is non-secret desired state. The current general-purpose
CLI validates it and produces an offline plan only:

```sh
npm run validate -- examples/gateway.config.json
npm run plan -- examples/gateway.config.json \
  --observed examples/observed.empty.json \
  --access examples/access-input.json
npm run plan:example
npm test
```

The validator requires HTTPS upstreams, a declared read-only capability mode,
and exact tool allowlists. It rejects wildcard tools and secret-looking fields.
The plan is deterministic and reports blockers, required provider
capabilities, ownership-aware changes, and a non-authoritative uninstall
preview. It performs no network requests or writes. Offline observed JSON is
never mutation or deletion authority.

The separate zero-write preflight can verify one explicit Cloudflare account,
zone, and hostname. It reads its token only from `CLOUDFLARE_API_TOKEN`, emits
no selected identifiers, and makes no mutations:

```sh
npm --silent run canary:preflight -- \
  --account-id <32-character-id> \
  --zone-id <32-character-id> \
  --hostname <gateway.example.com>
```

This proves provider reads only. It does not prove installer write authority or
replace live validation of Cloudflare's `GET /oauth/scopes` catalogue.

## Implemented canary stack

The library now implements locally:

- fixed-origin, bounded Cloudflare reads with sanitized errors;
- a receipt-bound seven-resource mutation adapter;
- approval-bound apply, idempotency, uninstall, residue checks, and recovery;
- a deterministic, credential-free MCP fixture exposed for live testing through
  a temporary Cloudflare Quick Tunnel;
- owner-only receipt persistence and explicit stale-lock recovery.

The exact apply order is:

```text
MCP server
  -> explicit source mcp Access application
  -> source Access policy
  -> Portal
  -> explicit portal mcp_portal Access application
  -> Portal Access policy
  -> DNS record
```

Cleanup is the exact reverse: DNS, Portal policy, explicit Portal Access
application, Portal, source policy, explicit source Access application, then
MCP server. Both Access applications are explicit receipt-owned resources; the
adapter does not rely on Cloudflare to auto-create either one.

The canary runner requires a preview-derived lifecycle approval and a separate
disposable-target confirmation. It verifies the synthetic upstream before the
first write, journals each intent before mutation, re-reads live state, and
never replays an outcome-unknown create. A clean API-only lifecycle is still a
partial result: without an interactive call through the employee-facing
Portal, it reports verification pending and exits `3`, not success.

## Customer dashboard

`apps/admin` is the single dashboard source. It uses the lean public Cloudflare
OS stack: React 19, TypeScript, Vite, Tailwind CSS 4, Cloudflare Kumo,
Phosphor icons, TanStack Router, and Vitest. Its deterministic production build
is generated in `apps/admin/dist` and mapped to `payload/admin` only inside a
new release candidate; generated dashboard assets are not committed.

The dashboard has three routes:

- **Overview** shows the installed gateway, endpoint, release, audience count,
  source state, custody boundary, and receipt-authorized teardown entry;
- **Sources** discovers public or standards-compliant per-user OAuth MCPs,
  freezes exact tool allowlists, saves customer-owned drafts, and starts the
  one-time authorization needed to apply them; and
- **Updates** reviews the signed release channel and starts bounded update or
  rollback authorizations without rolling back Durable Object data.

The Worker validates the Cloudflare Access JWT rather than trusting identity
headers, rejects cross-origin API requests, and stores source state in the
customer's Durable Object. The React dashboard exposes equivalent human and
WebMCP flows for live catalogue discovery, exact draft saves, a one-time
Cloudflare OAuth apply handoff, and a customer-receipt teardown review handoff.
The customer Worker journals the exact three source resources and full Portal
update without retaining the grant.
It also exposes a signed, installed-channel update and rollback flow. Preview
installations stay on the canary channel; stable promotion remains gated by the
public release checklist. Normal updates replace only customer Worker code and
management assets, use a fresh
one-time Cloudflare grant, stage the candidate at 0% for an exact-version
probe, and keep their ledger in the customer's Durable Object. Durable Object
data is never rolled back.
The dashboard origin must be separate from the MCP Portal hostname.

See [Customer dashboard](docs/DASHBOARD.md) and
[Gateway updates and rollback](docs/UPDATES.md) for the product and deployment
contracts.

## Hosted installer

`apps/installer` contains the optional hosted service used to review an exact
fresh-create plan, obtain one operation-scoped Cloudflare OAuth grant, deploy a
signed release into the customer's account and discard the grant. It also owns
the retained-session removal path and the returning-customer path that starts
with zero-write existing-gateway detection and a customer-receipt handoff.
Provider credentials and ordinary proxied provider results are never persisted
by this service. The operation-scoped OAuth grant exists only in the connected
callback invocation, whose signed result page displays journal-backed
deployment progress before revocation.

The checked-in default deployment remains fail-closed: install and uninstall
executors are compile-time disabled, the release-key registry and release pin
are empty, and no environment variable can enable mutations. A reviewed canary
is generated from explicit external pin and publication artifacts. The signing
and publication tools produce or consume explicit artifacts, but the repository
contains no private key, release envelope, R2 authority or generated release.

See [Customer self-service](docs/CUSTOMER_SELF_SERVICE.md) for the install,
day-two management, removal, and recovery flow, and
[Hosted installer](apps/installer/README.md) for its security and release
contract. The Ankka-hosted service's default, identifier-free product funnel
and separate Cloudflare NEL boundary are specified in
[Hosted installer analytics](docs/HOSTED_INSTALLER_ANALYTICS.md); no customer
gateway receives that analytics binding.

## Local UI studio

Run both user-facing interfaces locally with synthetic data and hot reload:

```sh
npm run dev:ui
```

The command starts the deployment wizard at `http://127.0.0.1:5731` and the
customer dashboard at `http://127.0.0.1:5730`. Its terminal output lists direct
links for every useful state: discovery, configuration, plan review,
authorization, deployment progress, success, failure, removal, source
authorization, management updates, populated dashboard pages, empty onboarding,
and load failure.

The studio never contacts Cloudflare and does not need OAuth, credentials, a
Worker, or Durable Object state. Portal edits are retained in memory until the
dev process or page is restarted. OAuth and other external links are
deliberately inert. Edit `payload/installer` for the deployment wizard and
`apps/admin/src` for the customer dashboard; Vite refreshes the corresponding
page immediately.

## Canary status

The exact `gateway-v0.1.0` payload completed the full customer lifecycle in a
disposable account on 2026-08-23: all seven resources converged, a second apply
was a no-op, an employee invoked the synthetic read-only tool through Access and
Portal Code Mode, cleanup consumed the real stored receipt, and independent
verification found zero residue.

The hosted OAuth installer subsequently completed a signed private-canary
installation. Its signed `gateway-v0.1.11` envelope and sanitized verification
record were mirrored in an immutable prerelease in the private repository. That
artifact is historical evidence and will not be copied into the sanitized
public repository. The first installed management UI exposed fresh-install
verification defects that are repaired on the current release branch. That
installation used a deliberately discarded canary signing key, so it is not a
valid base for the normal updater promotion gate. A retained-key N → N+1
update, failure compensation, rollback, same-session removal, and independent
zero-residue proof remain open.

The subsequent private `gateway-v0.1.12` canary is legacy evidence only. Its
schema-1 envelope did not cryptographically bind the release channel and is
rejected by the current schema-2/updater-protocol-2 path. It must be retired and
reinstalled from a fresh schema-2 N, never promoted or reused as N.

## Credential and recovery boundary

- `CLOUDFLARE_API_TOKEN` and `ANKKA_CANARY_ALLOWED_EMAIL` come only from the
  local customer-controlled environment; neither is a CLI argument or receipt
  field.
- The lifecycle requires an explicit receipt path. Receipt and cleanup-recovery
  files are atomic, owner-only mode `0600`; lock directories are `0700` with
  `0600` metadata.
- A crash-left lock is never removed because it is old. Inspect it first, then
  recover only a reported stale candidate using its exact lock ID and the
  explicit confirmation phrase shown by the CLI.
- Pending or ambiguous state remains recovery authority. Do not delete the
  receipt, mutate a receipt-owned Portal Access application outside an approved
  plan, or continue to DNS.

## What remains

Before promoting the hosted canary to a general release, the project still
needs:

1. publish only the proven sanitized root and pass public-host CI and CodeQL;
2. complete the retained-key updater, rollback, removal, and abuse-control
   promotion proofs on isolated canaries while the live host stays disabled;
3. permanently publish the verified OAuth client, prove zero Access coverage
   before live activation, and pass the post-activation verifier plus an
   unrelated-account customer flow; and
4. preserve explicit signing, activation, rollout, rollback, and promotion
   review.

The exact gate ledger is in the
[public release checklist](docs/PUBLIC_RELEASE_CHECKLIST.md). The
[public-preview cutover](docs/PUBLIC_CUTOVER.md) orders the external changes and
their rollback; [release signing-key operations](docs/SIGNING_KEY_OPERATIONS.md)
defines custody, backup, loss, compromise, and rotation behavior.

```text
employee MCP client
  -> Cloudflare Access + MCP Portal (customer account)
       -> optional Ankka company-context MCP
       -> provider-native MCP servers
       -> other customer-approved MCP servers
```

Cloudflare OS is an optional compatible client/runtime; it is not required or
vendored here.

## Offline release payload

The dependency-free `payload/` tree contains the primary customer Worker, the
customer management assets, hosted installer assets, the HMAC-authenticated
cleanup Worker, and the inert retirement Worker. It is source material for the
reviewed signing and deployment boundary in `apps/installer`. Source code alone
cannot sign, publish, or deploy it because all private keys, credentials and
deployment authority remain external.

> **Checked-in source remains fail-closed.** Reviewed canary builds are generated
> and activated only from external signing and publication records; the default
> source activation remains `false`/`null` and carries no deployment authority.

The primary Worker exposes one bootstrap-only mutation endpoint and an
Access-JWT-gated, read-only status projection. Bootstrap recomputes the hosted
installer's exact configuration evidence, stores no OAuth grant or HMAC nonce,
journals before each provider write, and explicitly creates the current four
Portal resources or the seven resources in a retained first-source selection.
Both shapes include an explicit Portal Access application; the seven-resource
shape also includes the explicit source Access application proven in the live
canary. Bootstrap writes the checksum-protected ready receipt into the same
SQLite Durable Object state later consumed by cleanup. It never adopts a
Cloudflare-generated Access application: any application that already claims
the server, the Portal hostname, or the installation's name is a collision and
fails closed. It also fails closed if the Portal application it created does
not read back with the exact reviewed Managed OAuth settings; updating an
application remains blocked until the disposable-account canary proves
Cloudflare's writable-field preservation contract.

The cleanup Worker accepts exactly one starting authority: the primary's stored
`ready` receipt, checksum-verified and canonically identical to the receipt in
the authenticated uninstall claim. It durably replaces that receipt with the
`uninstalling` envelope before its first provider read, removes the receipt's
four or seven resources in reverse order, and leaves the `removed` tombstone. A claim alone,
an unfinished primary journal, or any differing receipt is rejected before
provider access. `test/payload-lifecycle.mjs` drives the real primary Worker
and hands its produced Durable Object storage to the real cleanup Worker, so
the handoff is tested end to end rather than from a hand-built receipt.

The installer assets cover session creation, selection, zero-write plan review,
fresh OAuth handoff, retained result polling, retained-session removal, and
returning-customer receipt-handoff removal. They keep the CSRF token only in
memory and never render provider
locators, journal data, removal receipts, credentials, or release envelopes.
The customer management assets show the secret-free gateway projection and
support agent-native source listing, discovery, draft save, per-action OAuth
apply, and teardown review handoff. A protected source is recognized only from
the standard MCP `WWW-Authenticate` protected-resource challenge; its Portal
mapping uses per-user upstream OAuth. Cleanup removes day-two source resources
before the original receipt-owned resources.

```sh
npm run test:payload
npm run check
```

Both commands are local-only. They do not call Cloudflare, sign a release, or
perform a deployment. See [customer release payloads](docs/customer-uninstall-payload.md).

See [Architecture](docs/ARCHITECTURE.md), [Security model](docs/SECURITY_MODEL.md),
[hosted installer analytics](docs/HOSTED_INSTALLER_ANALYTICS.md),
[canary runbook](docs/CLOUDFLARE_CANARY.md), and [roadmap](docs/ROADMAP.md).

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE).

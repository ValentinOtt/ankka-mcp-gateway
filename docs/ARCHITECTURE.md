# Architecture

Ankka MCP Gateway is a self-hosted Cloudflare edge for approved MCP
sources. Employees connect to one Cloudflare MCP Server Portal; the Portal
connects to the sources selected by the operator.

```text
employee MCP clients
  -> Cloudflare Access
  -> team MCP Portal
       -> approved MCP sources

administrators
  -> Cloudflare Access
  -> gateway management Worker
       -> gateway Durable Object
```

The management Worker and MCP Portal use separate hostnames.

## Components

### Deployment account

<a id="customer-account"></a>

The gateway deployment contains:

- an MCP Portal and DNS hostname;
- explicit Access applications and policies;
- a management Worker and static dashboard;
- a SQLite Durable Object for secret-free desired state, action journals, and
  runtime state; and
- Cloudflare-managed upstream source credentials and connections.

The initial installation creates an empty Portal. Administrators add sources
later from the gateway dashboard. Each added source has an exact tool
allowlist and may add an MCP server plus its Access resources before updating
the Portal mapping.

### Hosted installer

The optional hosted installer in `apps/installer` provides:

- read-only discovery of eligible Cloudflare accounts and zones;
- secret-free configuration and deterministic plan review;
- a fresh Cloudflare OAuth authorization for each approved mutation;
- signed-release verification and deployment progress; and
- receipt-authorized installation removal.

Cloudflare grants are distinct from upstream MCP credentials. The read-only
discovery grant is used only by the installer. A mutation grant may be forwarded
once, in request-local memory, to the exact authenticated gateway Worker
action. The implementation attempts bounded provider-side revocation and always
discards its local copy. A grant must never enter Durable Object state, logs,
analytics, or browser output.

The checked-in hosted installer is fail-closed: mutation executors are disabled
at compile time and the signed release pin is empty. Source code alone cannot
activate a deployment.

### Repository-local tools

The root CLI validates secret-free configuration and builds deterministic
offline plans. Its observed-state JSON is preview input only. Live mutations
require fresh Cloudflare state, an exact operator-approved plan and target, and
a durable intent record. Adoption and deletion additionally require
receipt-bound ownership.

Synthetic fixtures and provider adapters exist for tests and
maintainer-approved isolated verification. They are not a general-purpose
Cloudflare administration CLI.

## Installation lifecycle

A normal hosted installation follows this shape:

1. Discover the Cloudflare actor, accounts, and active zones with a read-only
   OAuth grant.
2. Save a secret-free selection and build a deterministic plan.
3. Ask the user to approve the exact plan and a new write-scoped OAuth grant.
4. Deploy the management Worker and its operator-owned state.
5. Create the management Access boundary, MCP Portal, Portal Access boundary,
   and DNS records.
6. Verify the installed state and store its ownership receipt in the gateway
   account.
7. Revoke or discard the operation grant and retain only a secret-free result.

Provider outcomes are journaled before mutation. An unknown create or delete
result is not blindly retried; the next attempt must first read provider state
and resolve the pending operation.

## Source management

The gateway dashboard accepts public HTTPS MCP endpoints and
standards-compliant OAuth-protected MCP endpoints.

For public endpoints, the gateway Worker performs bounded discovery without an
authorization header. For protected endpoints, it accepts only the standard MCP
Bearer challenge with public HTTPS protected-resource metadata. Arbitrary
credential headers, embedded credentials, private-network endpoints, wildcard
tools, and manually supplied bearer tokens are rejected.

Saving a source changes gateway Durable Object state only. Applying it requires
a new, short-lived Cloudflare authorization. A protected source defaults to
`onBehalfOfUser: false`: a gateway operator connects it once, Cloudflare stores
the source credential, and employees authenticate only to the Portal. The
current dashboard does not expose per-user upstream authentication. Upstream
OAuth remains between the operator, Cloudflare Portal, and upstream provider.

The phase-one Ankka Source Catalog is a signed, declarative resolver in front of
this same source workflow. Its strict contract and dashboard picker currently
ship without production presets. Reviewed remote implementations can resolve
into the existing URL, authentication, connection, and exact-tool contract. The
Registry will not become a gateway-runtime dependency, and catalog changes
will not mutate installed sources. Self-hosted packaged or adapter
implementations require separate provisioning lifecycles. See
[Source catalog architecture](SOURCE_CATALOG.md).

`apps/search-console-adapter` is an experimental slice of that future boundary:
an isolated, self-hosted OpenAPI Code Mode Worker with an exact read-only
host policy. It is deliberately absent from the production catalog and hosted
installer. Its Google OAuth topology, Portal Code Mode compatibility, resource
lifecycle, and live canary remain release gates rather than inferred behavior.

## Ownership and removal

Names, hostnames, tags, and provider identifiers locate resources; they do not
prove ownership. Every provider mutation requires:

- fresh provider reads;
- the exact operator-approved target and plan;
- the expected resource shape; and
- durable intent and outcome records.

Adopting or deleting an existing installation additionally requires a
checksum-valid installation receipt and matching ownership markers.

Removal deletes only receipt-owned resources in reverse dependency order. It
stops on drift, collisions, missing authority, or ambiguous provider state.
Unrelated Cloudflare and upstream-provider resources are outside its scope.

## Releases and updates

Gateway releases are built from one clean public source commit and signed with
Ed25519 outside the repository. The signed manifest covers the release channel,
one canonical HTTPS control-plane origin, source commit, deployment contract,
and every payload file. Candidate generation compiles that origin into the
gateway Worker before hashing; update discovery uses the same
non-runtime-selectable origin.

The gateway Worker payloads remain hand-authored JavaScript by design. Each is
a dependency-free, single-module deployment unit, and the reviewed file bytes
are the bytes covered by the release manifest. The control plane, dashboard,
and reusable libraries use TypeScript; release tooling does not transpile a
second Worker artifact that would need a separate provenance boundary.

An ordinary update persists changes only to gateway Worker code and management
assets. It does not persist changes to Access, DNS, Portal configuration,
sources, credentials, or Durable Object data. Rollback restores a previous
Worker version but does not roll back Durable Object data. See
[Gateway updates and rollback](UPDATES.md).

## Telemetry boundary

Neither self-hosted gateway code nor the hosted installer sends telemetry to
Ankka. The hosted installer keeps only its short-lived setup session and
records no analytics events. Cloudflare and upstream services still process
traffic according to the team's account configuration and their own
policies.

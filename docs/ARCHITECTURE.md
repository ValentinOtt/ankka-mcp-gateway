# Architecture

Ankka MCP Gateway is a customer-owned Cloudflare edge for approved MCP
sources. Employees connect to one Cloudflare MCP Server Portal; the Portal
connects to the sources selected by the customer.

```text
employee MCP clients
  -> Cloudflare Access
  -> customer MCP Portal
       -> approved MCP sources

administrators
  -> Cloudflare Access
  -> customer management Worker
       -> customer Durable Object
```

The management Worker and MCP Portal use separate hostnames.

## Components

### Customer account

The customer deployment contains:

- an MCP Portal and DNS hostname;
- explicit Access applications and policies;
- a management Worker and static dashboard;
- a SQLite Durable Object for secret-free desired state, action journals, and
  runtime state; and
- Cloudflare-managed upstream credentials and per-user OAuth grants.

The current hosted browser flow creates an empty Portal. The signed installation
contract can also carry one explicitly planned initial source with an exact tool
allowlist, but the browser flow does not expose that option. Administrators
using ordinary self-service add sources later from the customer dashboard. A
source may add an MCP server plus its Access resources before updating the
Portal mapping.

### Hosted installer

The optional hosted installer in `apps/installer` provides:

- read-only discovery of eligible Cloudflare accounts and zones;
- secret-free configuration and deterministic plan review;
- a fresh Cloudflare OAuth authorization for each approved mutation;
- signed-release verification and deployment progress; and
- receipt-authorized installation removal.

Cloudflare grants are distinct from upstream MCP credentials. The read-only
discovery grant is used only by the installer. A mutation grant may be forwarded
once, in request-local memory, to the exact authenticated customer Worker
action. The implementation attempts bounded provider-side revocation and always
discards its local copy. A grant must never enter Durable Object state, logs,
analytics, or browser output.

The checked-in hosted installer is fail-closed: mutation executors are disabled
at compile time and the signed release pin is empty. Source code alone cannot
activate a deployment.

### Repository-local tools

The root CLI validates secret-free configuration and builds deterministic
offline plans. Its observed-state JSON is preview input only. Live mutations
require fresh Cloudflare state, an exact customer-approved plan and target, and
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
4. Deploy the management Worker and its customer-owned state.
5. Create the management Access boundary, MCP Portal, Portal Access boundary,
   and DNS records.
6. Verify the installed state and store its ownership receipt in the customer
   account.
7. Revoke or discard the operation grant and retain only a secret-free result.

Provider outcomes are journaled before mutation. An unknown create or delete
result is not blindly retried; the next attempt must first read provider state
and resolve the pending operation.

## Source management

The customer dashboard accepts public HTTPS MCP endpoints and
standards-compliant per-user OAuth MCP endpoints.

For public endpoints, the customer Worker performs bounded discovery without an
authorization header. For protected endpoints, it accepts only the standard MCP
Bearer challenge with public HTTPS protected-resource metadata. Arbitrary
credential headers, embedded credentials, private-network endpoints, wildcard
tools, and manually supplied bearer tokens are rejected.

Saving a source changes customer Durable Object state only. Applying it requires
a new, short-lived Cloudflare authorization. Upstream OAuth remains between the
user, Cloudflare Portal, and upstream provider.

## Ownership and removal

Names, hostnames, tags, and provider identifiers locate resources; they do not
prove ownership. Every provider mutation requires:

- fresh provider reads;
- the exact customer-approved target and plan;
- the expected resource shape; and
- durable intent and outcome records.

Adopting or deleting an existing installation additionally requires a
checksum-valid customer receipt and matching ownership markers.

Removal deletes only receipt-owned resources in reverse dependency order. It
stops on drift, collisions, missing authority, or ambiguous provider state.
Unrelated Cloudflare and upstream-provider resources are outside its scope.

## Releases and updates

Customer releases are built from one clean public source commit and signed with
Ed25519 outside the repository. The signed manifest covers the release channel,
source commit, deployment contract, and every payload file.

An ordinary update persists changes only to customer Worker code, management
assets, and two non-secret release-identity text bindings. It does not persist
changes to Access, DNS, Portal configuration, sources, credentials, resource or
secret bindings, compatibility settings, or Durable Object data. Rollback
restores a previous Worker version and its release identity but does not roll
back customer data. See
[Gateway updates and rollback](UPDATES.md).

## Telemetry boundary

Customer-deployed gateway code sends no telemetry to Ankka. The hosted installer
has a separate, fixed analytics policy documented in
[Hosted installer analytics](HOSTED_INSTALLER_ANALYTICS.md). Cloudflare and
upstream services still process traffic according to the customer's account
configuration and their own policies.

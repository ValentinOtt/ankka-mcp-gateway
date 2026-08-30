# Source catalog architecture

> **Status:** phase-one contract, Registry checker, and empty dashboard picker
> are implemented. No reviewed production preset currently ships. Phase one is
> deliberately limited to a small set of reviewed remote MCP servers.

The Ankka Source Catalog is a signed, declarative curation and resolution layer
in front of the existing source workflow. It lets an administrator select a
business system without making the official MCP Registry, Ankka, or a package
catalogue part of the gateway's runtime path.

```text
Official MCP Registry
  -> bounded maintainer refresh
  -> reviewed Ankka Source Catalog source
  -> signed gateway-dashboard release
  -> existing source draft and apply workflow
  -> team Cloudflare MCP Portal
  -> approved remote MCP source
```

The official MCP Registry is upstream discovery metadata. It is not deployment
authority, an endorsement, a tool allowlist, or a runtime availability
dependency. The catalog records Ankka's small reviewed overlay and a pinned
reference to the selected Registry implementation. The self-hosted gateway
continues to store the resolved connection and exact tool policy.

## Invariants

- The deploying team owns the gateway runtime, Cloudflare resources, source
  connections, credentials, and any self-hosted source runtime. A
  provider-hosted MCP runtime remains provider-owned.
- Source-provider credentials never transit or persist at Ankka and never
  appear in catalog data.
- Catalog selection never silently changes an installed endpoint,
  authentication mode, or tool allowlist.
- Every installed source has an exact, operator-reviewed `enabledTools` array.
  Wildcards and automatic tool expansion remain forbidden.
- Registry identity and source-authored metadata are review evidence, not
  authorization. The upstream must independently enforce read-only access.
- The current custom-URL flow remains available for compatible sources that
  are not in the curated catalog.
- Catalog browsing and selection add no telemetry from the deployed
  gateway to Ankka.

## Object boundaries

Keeping these identities separate avoids coupling gateway state to a mutable
catalog decision.

| Object | Purpose | Authority |
| --- | --- | --- |
| Business source | Stable user-facing identity such as `example-analytics` | Catalog UX only |
| Catalog implementation revision | One immutable, reviewed way to connect that business source | Signed catalog release |
| Installed source instance | One team's installed connection; multiple instances may use the same business source | Gateway state |
| Resolved source | Exact URL, auth mode, connection mode, and `enabledTools` | Existing gateway source contract |
| Provider resources | MCP server, Access resources, Portal mapping, and credentials | Deployment Cloudflare account |

A future catalog entry may contain multiple implementations and name one as
preferred for new connections. Existing instances remain pinned. Changing the
preference is not failover and does not migrate existing installations.

An implementation revision is immutable. Changing its catalog provenance,
pinned Registry record, selected endpoint, transport, authentication mode,
connection mode, or recommended tools creates a new revision. Presentation,
Registry status, publisher evidence, and review freshness can change in a later
catalog release without rewriting that behavioral identity.

## 1. Registry fit with the current source model

The Registry's documented consumer contract is an unauthenticated, read-only
REST API. A versioned server record can contain both `remotes[]` and
`packages[]`; the Registry-managed response metadata adds publication time,
update time, latest-version state, and mutable active, deprecated, or deleted
status. The server record does not provide an authoritative live tool list,
read-only policy, provider endorsement, OAuth compatibility proof, or
Cloudflare compatibility proof.

The fields map to Ankka as follows:

| Registry data | Ankka use |
| --- | --- |
| Exact server name and version | Pinned catalog implementation reference, never an installed source-instance ID |
| One selected `remotes[]` entry | Phase-one endpoint candidate after compatibility review |
| `packages[]` entry | Future gateway-runtime provisioning input, not a Portal source |
| Repository, website, namespace, and publisher metadata | Provenance evidence only |
| Registry status and timestamps | Refresh and deprecation signals |
| Remote URL variables or secret-header inputs | Incompatible with phase one |
| Descriptions, icons, and other presentation fields | Untrusted upstream metadata; do not copy by default |

Registry records may contain packages and remotes at the same time, so a
Registry server is not itself a deployment type. Phase one selects one exact,
fixed, public Streamable HTTP remote. It must also pass the gateway's stricter
URL, authentication, discovery, and tool-policy checks.

The current resolved source shapes remain the output of catalog selection:

- offline configuration uses `id`, `label`, `url`, `authentication`, optional
  `accessGroup`, and exact `enabledTools`; and
- gateway source state uses `id`, `label`, `url`, `authMode`,
  `onBehalfOfUser`, exact `enabledTools`, and `status`.

The catalog is a resolver before those contracts, not another runtime source
type.

## 2. Synchronization strategy

Use a periodic, maintainer-side import and reviewed snapshot. Do not query the
Registry from the user's browser, gateway Worker, release build, or source
apply action.

The official guidance for downstream registries is to poll regularly but not
frequently, retain their own data, and tolerate Registry downtime or data
loss. The service remains in preview and does not provide an uptime or
durability guarantee. A live dependency would also let mutable upstream
metadata bypass Ankka review and make an operator action depend on an unrelated
service.

A refresh should:

1. call the fixed official host and pinned `/v0.1` API with strict time, page,
   redirect, and response-size limits;
2. use cursor pagination and `updated_since` for ordinary refreshes, with an
   occasional bounded full reconciliation;
3. validate the response at the trust boundary against a pinned Registry
   schema revision and Ankka's narrower local schema;
4. retain exact name, version, mutable Registry status, source-schema revision,
   canonical server-record digest, and observation time for selected
   candidates;
5. produce a human-readable public diff without committing automatically;
6. require review of publisher evidence, endpoint ownership, transport, auth,
   Cloudflare compatibility, tools, and source behavior; and
7. review the origin and publication rights of every transferred field, update
   `ORIGINS.md` and `THIRD_PARTY_NOTICES.md` where applicable, and commit only
   the selected normalized catalog data. A normal signed release then covers
   the generated dashboard asset containing it.

The import cache is rebuildable maintenance data, not production authority and
need not be committed as a mirror of the Registry. Builds remain network-free
and deterministic. If refresh fails, the last reviewed catalog remains usable;
no new claim of freshness is made.

A Registry deprecation, deletion, or changed preferred version should open a
review item. It must not modify or disable an installed source automatically.
The exact versioned Registry metadata is generally immutable, but the Registry
status and the behavior behind a remote URL can change.

The phase-one manifest accepts only Registry records observed as `active`. The
checker may report a `deprecated` or `deleted` record for diagnosis, but emits
no compatible candidates for it. A reviewed status change therefore removes
that implementation from the next catalog offered for new connections; it
does not add lifecycle states to the picker or change installed gateway
state. The append-only public catalog history retains the last reviewed record
and makes the removal visible in the release diff.

## 3. Minimum Ankka catalog metadata

Phase one needs only enough data to present, substantiate, resolve, and review
one remote connection. The conceptual manifest is:

```yaml
schemaVersion: 1
catalogRevision: 2026-08-29.1
sources:
  - sourceId: example-analytics
    displayName: Example Analytics
    description: Read reviewed reporting data.
    documentationUrl: https://example.com/docs/mcp
    implementation:
      implementationId: example-analytics-registry
      implementationRevision: 1
      catalogProvenance: official_registry
      kind: native_mcp
      behaviorSha256: sha256-of-normalized-behavior-fields
      registry:
        serverName: com.example/analytics
        serverVersion: 1.2.3
        serverSchemaRevision: 2025-12-11
        recordSha256: sha256-of-canonical-selected-record
        status: active
        observedAt: 2026-08-29
      deployment:
        kind: remote_mcp
        transport: streamable_http
        url: https://mcp.example.com/mcp
      connection:
        authMode: oauth
        onBehalfOfUser: false
      recommendedTools:
        - properties.list
        - reports.read
    publisher:
      relationship: provider
      evidence:
        - https://example.com/docs/mcp
    review:
      status: ankka_reviewed
      reviewedAt: 2026-08-29
```

Names are provisional, but the boundaries are intentional:

- `sourceId` is stable business identity. The `implementationId` and
  `implementationRevision` pair identifies one immutable reviewed resolution
  and can change without renaming the business source.
- `behaviorSha256` covers normalized provenance, implementation kind, pinned
  Registry record, endpoint, transport, authentication, connection, and
  recommended-tool fields. Any change to those fields requires a new
  implementation revision.
- The Registry reference pins an exact version and server-record digest. Its
  mutable status, observation time, publisher evidence, and review freshness
  are deliberately outside the behavioral digest.
- `publisher.relationship` and `review.status` are separate facts; avoid a
  single ambiguous `trustLevel` or numeric preference score.
- The deployment block contains the exact selected remote, rather than an
  unresolved array index or `latest` reference.
- Authentication metadata contains modes and public setup requirements only,
  never tokens, client secrets, custom secret headers, deployment account IDs,
  or provider resource IDs.
- `recommendedTools` is an exact reviewed seed tied to this implementation
  revision. It is not installed policy until the operator approves it.
- Description, setup text, compatibility notes, and documentation links should
  be short Ankka-authored text. Do not copy upstream branding or content unless
  its origin and licence are reviewed and recorded.

An optional semantic overlay is not part of the phase-one minimum. Search tags
or Ankka-authored setup guidance can be added later. Tool aliases, rewritten
descriptions, argument transforms, or API calls change behavior and belong to
a separately reviewed adapter or Portal policy, not a descriptive catalog
overlay.

## 4. Remote and packaged implementations

Do not use one enum containing `remote_mcp`, `openapi_adapter`, and
`custom_adapter`. Registry provenance, behavior implementation, and deployment
are independent concerns:

| Axis | Initial values | Meaning |
| --- | --- | --- |
| Catalog provenance | `official_registry`, later `direct` | Where the implementation was discovered and pinned |
| Implementation kind | `native_mcp`, later `openapi_adapter` or `custom_adapter` | How MCP behavior is implemented |
| Deployment | `remote_mcp`, later `customer_deployed_mcp` | Whether a compatible endpoint already exists |
| Publisher relationship | `provider` or `community` | Relationship between publisher and business system |
| Review state | `ankka_reviewed`, `unreviewed`, later `stale` | Ankka's current review claim |

Phase one permits only a Registry-referenced, native `remote_mcp` with a fixed
public HTTPS Streamable HTTP endpoint. Legacy SSE, unresolved URL templates,
secret-header recipes, stdio packages, and package-only entries are not
polished catalog options.

A future `customer_deployed_mcp` requires a separate provisioning design. It
must pin and verify an artifact, create a self-hosted runtime and bindings,
expose an authenticated remote MCP endpoint, and support updates, rollback,
recovery, and receipt-authorized removal. Only after verification does its
resolved endpoint enter the existing source-apply pipeline.

The experimental Search Console Worker under `apps/search-console-adapter`
tests the runtime and policy portion of this shape. It does not relax this
gate: it has no catalog entry, no hosted-installer deployment authority, and no
approved OAuth or removal lifecycle. Its pinned spec and capability-policy
digests are future receipt inputs, not evidence that the implementation is
production-ready.

OpenAPI and custom adapters are implementation kinds that may themselves be
provider-hosted or self-hosted. They must not be smuggled into the current
`authMode`, run arbitrary packages in the management Worker, or create an open
credential-forwarding proxy.

## 5. Provider-published identification

The polished catalog should initially show only provider-published entries that
also pass Ankka review, plus narrowly selected community entries with explicit
Ankka review. Prefer the label **provider-published** over **official** in the
data model because it states the evidence more precisely.

Registry authentication can establish control of a GitHub user or organization
namespace, or a reverse-DNS domain namespace. Package verification can add
artifact-ownership evidence. Neither fact proves that a server is endorsed by
the SaaS provider, controls the advertised remote endpoint, is safe, is
read-only, or works through Cloudflare Portal.

Classify an implementation as provider-published only when a reviewer can
record public, dated evidence connecting all of these:

- the business system and its controlled domain or source-code organization;
- the exact Registry publisher namespace and server version;
- the exact repository or remote endpoint; and
- provider-controlled documentation announcing or linking that implementation.

For a remote, independently verify endpoint ownership because the current
Registry contract does not provide a clear endpoint-control attestation. A
matching product name, description, icon, repository topic, Registry listing,
or publisher's unsupported self-assertion is insufficient. Ambiguous cases are
community or unreviewed, fail closed, and do not appear in the polished catalog.

Ankka review is a separate dated claim covering the selected implementation,
endpoint, auth path, Portal behavior, exact recommended tools, upstream
read-only controls, maintenance posture, and known limitations. Review expiry
or a material change should mark an entry stale until re-reviewed; it should
not alter existing gateway state.

## 6. Gateway schema changes

Phase one requires no change to the resolved gateway or managed-source schema.
The catalog UI resolves a selection into the current source draft and then uses
the existing inspect, save, review, and apply path. The resolved URL, auth mode,
operator-connection mode, and exact tools remain authoritative in gateway
state.

The phase-one catalog manifest needs its own strict, versioned schema and
validator. It should be compiled into the signed dashboard assets from an
exact release input. Keeping the authored data under `apps/admin` satisfies the
current release builder's source-input boundary; placing it elsewhere requires
expanding that builder's clean-source checks explicitly.

The authored production manifest carries canonical behavior digests. Release
tests recompute those digests and validate every transition from the simple
append-only public baseline. After a release, maintainers append the old
manifest before authoring a new revision; they do not rewrite prior history.
New entries and behavioral, Registry, presentation, or publisher-evidence
changes require the review date to match the advancing catalog revision's
date. A new entry, changed Registry evidence, or a refreshed observation
likewise requires an observation on that revision date. Same-day `.2`
corrections therefore remain possible, while evidence dated after its catalog
revision is rejected. This keeps the evolution rules executable rather than
review guidance alone.

Do not reuse catalog `sourceId` as the installed source instance ID. Current managed
source identity and draft matching are URL-oriented, and the current workflow
does not support replacing or removing an installed source. That is sufficient
for a first catalog picker but cannot support a transparent implementation
swap.

Before adding drift reporting, multiple instances, or implementation migration,
introduce a versioned source-state revision with an optional non-authoritative
reference such as:

```text
catalogRef = {
  sourceId,
  implementationId,
  implementationRevision,
  catalogRevision,
  behaviorSha256,
  registryServerName,
  registryServerVersion
}
```

The installed source instance still needs its own opaque stable ID. A migration
must compare endpoint, authentication, and exact tools; create and verify the
replacement; update the Portal mapping; and remove only receipt-owned old
resources. It requires explicit operator approval and recovery semantics.

## 7. Cloudflare Portal and `enabledTools`

Cloudflare Portal and its Access application remain the aggregation,
employee-authentication, upstream-connection, tool-policy, Code Mode, logging,
and Portal-lifecycle layers. Access authenticates employees; the Portal can
register an already-running remote HTTP MCP server, but it does not deploy a
package or adapter runtime.

The existing source apply action remains the provisioning boundary:

1. inspect the resolved remote and auth challenge;
2. save a secret-free draft with exact tools;
3. obtain a fresh operation-scoped Cloudflare authorization;
4. create the MCP server and its source Access resources; and
5. attach it to the Portal with `default_disabled: true` and the exact
   `updated_tools` selection.

Registry metadata does not contain the authoritative tool catalogue.
`recommendedTools` may preselect a reviewed subset in the UI, but the operator
must see and approve the exact names. Public sources still undergo fresh live
discovery before save and apply. OAuth-protected sources cannot currently be
listed before authentication, so catalog recommendations improve setup but do
not prove that the tools still exist.

Cloudflare can synchronize capabilities from some OAuth servers, and its
default behavior can expose newly discovered capabilities. The gateway must
continue writing a deny-by-default Portal mapping so new tools remain disabled.
A catalog refresh, Cloudflare capability sync, or changed recommendation must
never expand installed `enabledTools`. Direct out-of-band Portal edits are
drift, not a second policy authority.

Phase-one entries must match the authentication flow the dashboard actually
supports: unauthenticated sources or standards-compliant OAuth that Cloudflare
can connect once with `onBehalfOfUser: false`. The catalog must not imply
support for manual bearer tokens, arbitrary headers, OAuth client secrets, or
per-user upstream authentication. Cloudflare may support some of those modes,
but the current Ankka self-service boundary intentionally does not accept their
credentials.

A later two-stage OAuth experience may connect first, synchronize capabilities,
then ask the administrator to approve an exact allowlist. It needs a separate
design and a canary proving Cloudflare's behavior; it is not a reason to weaken
phase-one policy.

## 8. Registry client libraries

Use the documented REST/OpenAPI contract directly with the platform's native
`fetch` and the repository's existing Valibot dependency. The integration needs
only a small bounded importer and narrow response validator, not a general MCP
or Registry client framework.

The official project documents community Go, TypeScript, and Java Registry
clients with explicit third-party support and security disclaimers. It does not
document a supported Registry-consumption SDK. The official `mcp-publisher`
tool publishes records; it is not an aggregator client. The MCP TypeScript SDK
implements the MCP protocol, not the Registry API.

Pin the API route revision and input schema revision separately, keep raw data
outside the signed runtime, and fail closed on unknown or malformed fields that
affect selection. Reconsider generated or official client types only if a
stable supported package materially reduces code and supply-chain risk.

## 9. Architectural contentions

| Contention | Guardrail |
| --- | --- |
| The Registry remains a preview service without runtime availability or durability guarantees | Use a reviewed signed snapshot and no gateway-runtime dependency |
| Namespace or package ownership is not endorsement, endpoint ownership, quality, safety, or read-only behavior | Keep publisher evidence and Ankka review separate; verify each selected endpoint |
| A version record can be immutable while the remote behavior and tool surface change | Pin the record, re-inspect live, date reviews, and require explicit tool diffs |
| Registry records may be package-only, templated, header-authenticated, SSE-only, or incompatible with Portal proxying | Apply a stricter phase-one compatibility gate |
| Registry data has no authoritative tools or semantics | Maintain a small reviewed recommendation and preserve exact operator approval |
| A curated catalog still creates ongoing review work | Keep the polished set intentionally small and add entries only for demonstrated user demand |
| The Registry covers publicly available endpoints or installation methods, not private-network or private-registry sources | Preserve custom URL support; private and organization-specific sources remain outside Registry discovery |
| Committing normalized Registry metadata or copying upstream content creates provenance and publication-rights obligations | Prefer identifiers, digests, links, and Ankka-authored prose; review rights and record origins and notices before transferring anything |
| Silent implementation fallback can change credentials, data scope, and tools | Pin installed implementations and require an explicit replacement action |
| Self-hosted packages create a new runtime and supply-chain lifecycle | Design provisioning, signing, secrets, receipts, upgrades, and removal separately |

The Registry should therefore be Ankka's default **discovery input**, not its
runtime source of truth. The signed catalog is Ankka's reviewed recommendation;
the resolved gateway state is installation authority; Cloudflare Portal is the
enforcement target; and the upstream remains responsible for operation-level
authorization.

## Staged delivery

1. Define and test a strict catalog manifest with synthetic fixtures, a
   bounded maintainer refresh/check tool, and an empty signed picker.
2. Ship the first reviewed remote sources in the signed
   dashboard, while retaining the custom-URL flow and current source schema.
3. Add versioned catalog provenance, stable installed source-instance IDs,
   staleness reporting, and explicit receipt-safe replacement only when update
   or migration is needed.
4. Design self-hosted MCP provisioning as a separate lifecycle for one
   demonstrated package use case.
5. Add OpenAPI or custom adapters only for concrete user needs and keep
   their implementation, credential, update, and removal boundaries explicit.

This sequence improves connection setup without committing Ankka to hundreds
of provider-specific runtimes or credential flows.

The contract and empty picker complete stage one. The dated review of
[BigQuery, Google Search Console, Ahrefs, and Gorgias](SOURCE_CATALOG_CANDIDATES.md)
explains why none is promoted to production catalog data yet.

### Maintainer Registry check

Inspect one exact official Registry version with the bounded, read-only tool:

```sh
npm run catalog:registry:check -- \
  --server <registry-server-name> \
  --version <exact-version>
```

The command uses only the fixed official Registry origin, rejects `latest`,
follows no redirects, bounds response time and size, and requires the supported
server-schema URL and revision. It prints only counts, fixed status fields,
digests, and phase-one-compatible endpoint URLs. Incompatible remote URLs are
never printed because they may contain userinfo, query credentials, or hostile
display text. Its phase-one transport shape accepts only the pinned schema's
known remote fields and rejects unresolved URL templates or unknown auth
extensions. Passing `--expect-record-sha256 <sha256:digest>` turns a
previously reviewed record digest into an exact drift check. It never edits the
catalog.

## Primary references

The external contracts were reviewed on 2026-08-29:

- [Official MCP Registry overview](https://modelcontextprotocol.io/registry/about)
- [Guidance for downstream registries](https://modelcontextprotocol.io/registry/registry-aggregators)
- [Registry authentication and namespace ownership](https://modelcontextprotocol.io/registry/authentication)
- [Registry remote-server model](https://modelcontextprotocol.io/registry/remote-servers)
- [Registry package types and verification](https://modelcontextprotocol.io/registry/package-types)
- [Registry versioning](https://modelcontextprotocol.io/registry/versioning)
- [Registry terms of service](https://modelcontextprotocol.io/registry/terms-of-service)
- [Registry OpenAPI contract](https://github.com/modelcontextprotocol/registry/blob/main/docs/reference/api/openapi.yaml)
- [Registry community projects](https://github.com/modelcontextprotocol/registry/blob/main/docs/community-projects.md)
- [Cloudflare MCP server portals](https://developers.cloudflare.com/cloudflare-one/access-controls/ai-controls/mcp-portals/)
- [Cloudflare MCP server API](https://developers.cloudflare.com/api/resources/zero_trust/subresources/access/subresources/ai_controls/subresources/mcp/subresources/servers/methods/create/)

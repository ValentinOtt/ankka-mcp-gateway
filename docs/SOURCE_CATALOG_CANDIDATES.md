# Initial source-catalog candidates

> **Status:** dated research evidence, not an approval list. Reviewed on
> 2026-08-29. No entry below currently ships in the production Source Catalog.

This review applies the phase-one catalog boundary to the first requested
business systems: BigQuery, Google Search Console, Ahrefs, and Gorgias. A
provider-hosted MCP endpoint is not sufficient by itself. A polished preset
also needs reviewed provenance, compatible Cloudflare authentication, an exact
read-only tool recommendation, upstream operation-level enforcement, and an
immutable catalog implementation revision.

## Summary

**2026-08-30 implementation update:** the separate
[read-only connector Worker](../apps/read-only-connectors/README.md) now includes
ordinary MCP readers for Search Console domain properties and Gorgias (as well
as GA4, Notion, HubSpot, and Zendesk). Its Google readers use deployment-owned
service accounts and work without nested Code Mode. These are local experimental
implementations, not approved native presets; provider grants, Cloudflare
authentication, and adapter lifecycle still need live qualification. The native
BigQuery and Ahrefs holds below are unchanged.

| System | Provider-hosted remote | Provider record in official MCP Registry | Current result |
| --- | --- | --- | --- |
| BigQuery | Yes | No | Hold for authentication and discovery work |
| Google Search Console | No first-party remote found | No | Experimental self-hosted adapter; hold for OAuth, lifecycle, and live canary |
| Ahrefs | Yes | No | Hold for explicit provider permission before any canary |
| Gorgias | Yes, beta | No | Hold for read-only OAuth scope and tool enforcement |

The official Registry currently contains no provider-published record for any
of these four systems. Community records must not be promoted merely because
their names match a requested product.

## BigQuery

Google operates a fully managed remote MCP server at
`https://bigquery.googleapis.com/mcp`. Google documents HTTP transport,
Google OAuth and IAM, the broad BigQuery OAuth scope, its exact tool reference,
and an IAM deny policy for the non-read-only `execute_sql` tool. This makes it a
strong future source with a credible upstream read-only boundary.

It does not fit the current polished flow yet:

- the official Registry search returns only a community package record, not a
  Google publisher record;
- Google documents OAuth client credentials or an agent identity, while the
  current Ankka flow accepts neither manual OAuth client secrets nor agent
  credentials; and
- BigQuery permits unauthenticated `tools/list`, so its authentication
  classification must be independent of public catalogue discovery (fixed in
  the compatibility update below).

**2026-08-30 compatibility update:** the management Worker now classifies the
exact BigQuery endpoint as OAuth-protected independently of public discovery,
and blocks saving/applying it. Cloudflare supports manually registered OAuth
clients, but its current API explicitly documents no admin authentication flow
for manual OAuth. That prevents claiming the required `on_behalf: false`
operator-shared connection. Google consent, refresh, a bounded GA4 read and the
compound Gateway canary remain blocked. See
[BigQuery Google authentication](BIGQUERY_GOOGLE_AUTH.md) for the exact evidence,
tool review, setup steps and smallest proposed alternative; no new adapter was
implemented.

Evidence:

- [Google BigQuery MCP documentation](https://docs.cloud.google.com/bigquery/docs/use-bigquery-mcp)
- [Google BigQuery MCP tool reference](https://docs.cloud.google.com/bigquery/docs/reference/mcp)
- [Google-managed MCP repository](https://github.com/google/mcp)
- [Official Registry BigQuery search](https://registry.modelcontextprotocol.io/v0.1/servers?search=bigquery&version=latest&limit=100)
- [Community BigQuery Registry record](https://registry.modelcontextprotocol.io/v0.1/servers/io.github.SnowLeopard-AI%2Fbigquery-mcp/versions/0.1.1)

## Google Search Console

No Google-maintained Search Console MCP server was found in Google's current
MCP documentation or repository. The available Registry and source-code
implementations are community adapters. They do not satisfy the initial
provider-published preference and should not be presented as Google presets.

A concrete need now justifies an experimental, self-hosted adapter. The
Worker in `apps/search-console-adapter` uses Cloudflare's OpenAPI Code Mode
helper and exposes only `search` and `execute`. A bundled reduced spec describes
three read operations, while a separate host policy enforces fixed Google
origins, approved properties, strict request shapes, budgets, and the exact
`webmasters.readonly` scope requirement. Cloudflare's helper currently returns
an MCP SDK v1 server, so that workspace is an intentionally pinned compatibility
island served through `createLegacyMcpHandler`; it does not move the gateway to
an older protocol or SDK.

This is still not a production preset. Cloudflare does not support wrapping an
upstream Code Mode MCP server in Portal Code Mode, so a canary Portal must be
exactly `off`. The current source flow also does not implement the operator-owned
Google OAuth topology needed to obtain and refresh the inbound token.
OAuth, apply-time Portal policy enforcement, artifact provisioning, recovery,
rollback, receipt-authorized removal, and a live Cloudflare/Google canary must
land before a catalog revision can be approved.

Evidence:

- [Google announcement and supported MCP examples](https://cloud.google.com/blog/products/ai-machine-learning/announcing-official-mcp-support-for-google-services)
- [Google-managed MCP repository](https://github.com/google/mcp)
- [Community Search Console remote record](https://registry.modelcontextprotocol.io/v0.1/servers/ai.b77%2Fgoogle-search-console/versions/1.0.0)
- [Community Search Console package record](https://registry.modelcontextprotocol.io/v0.1/servers/com.mcparmory%2Fgoogle-search-console/versions/1.0.3)
- [Cloudflare OpenAPI Code Mode MCP guide](https://developers.cloudflare.com/agents/model-context-protocol/guides/build-codemode-openapi-mcp-server/)
- [Cloudflare nested Code Mode limitation](https://developers.cloudflare.com/cloudflare-one/access-controls/ai-controls/mcp-portals/#upstream-servers-with-code-mode-turned-on)
- [Google Search Console authorization](https://developers.google.com/webmaster-tools/v1/how-tos/authorizing)

## Ahrefs

Ahrefs operates a hosted Streamable HTTP server at
`https://api.ahrefs.com/mcp/mcp`. Its documentation describes an OAuth consent
flow that creates a dedicated MCP-scoped API key and identifies supported tool
categories. Live protocol metadata advertises dynamic client registration,
which is structurally compatible with Cloudflare's automatic OAuth path.

Ahrefs is structurally the strongest first canary candidate, but it is not
ready to test or ship:

- the official Registry has no Ahrefs-owned record; its Ahrefs results are
  community implementations;
- exact tools are available only after authorization and still need a
  read-only audit; and
- Ahrefs documents restrictions on external scripts and bridges. Cloudflare
  Portal compatibility and permitted use need provider confirmation rather
  than inference.

The next evaluation must first obtain explicit Ahrefs confirmation that using
its MCP server through a self-hosted Cloudflare Portal is permitted. Only
after that confirmation may an operator authorize a canary. The canary would
then confirm the complete exact tool surface and read-only enforcement while
retaining no credential or raw provider response in this repository or at
Ankka. If Ahrefs does not confirm this use, drop it from phase-one evaluation.

Evidence:

- [Ahrefs MCP introduction and endpoint](https://docs.ahrefs.com/en/mcp/docs/introduction)
- [Ahrefs MCP tool categories](https://docs.ahrefs.com/en/mcp/docs/tool-categories)
- [Official Registry Ahrefs search](https://registry.modelcontextprotocol.io/v0.1/servers?search=ahrefs&version=latest&limit=100)
- [Community Ahrefs remote record](https://registry.modelcontextprotocol.io/v0.1/servers/com.jojapi%2Fahrefs/versions/1.0.0)

## Gorgias

Gorgias operates a first-party remote at `https://mcp.gorgias.com/mcp` and
documents compatibility with remote MCP clients. It is currently beta and its
documented use cases include both data reads and mutations such as replying to
tickets and changing helpdesk configuration.

Live OAuth metadata advertises dynamic registration and granular read and
write scopes, but the current source contract does not select or attest OAuth
scopes. An exact Portal tool allowlist is necessary but does not replace the
upstream read-only boundary. A polished Gorgias entry therefore requires a
design that proves read-only provider scopes or a provider-enforced read-only
identity before connection.

The official Registry currently returns no Gorgias record. The optional
brand-specific endpoint also uses a query parameter, which the current gateway
URL contract intentionally rejects; the base endpoint remains the only
candidate for a future canary.

Evidence:

- [Gorgias first-party MCP setup](https://docs.gorgias.com/en-US/connect-your-ai-assistant-to-the-gorgias-mcp-6310546)
- [Gorgias MCP beta announcement](https://updates.gorgias.com/publications/gorgias-mcp-is-now-in-open-beta)
- [Official Registry Gorgias search](https://registry.modelcontextprotocol.io/v0.1/servers?search=gorgias&version=latest&limit=100)

## Decision and next review order

Production catalog data stays empty rather than weakening provenance or
read-only guarantees. The next provider work should proceed in this order:

1. obtain explicit Ahrefs confirmation that self-hosted Cloudflare Portal
   use is permitted; only then run an authenticated canary, otherwise drop it;
2. design BigQuery auth classification and its non-DCR/manual-client path;
3. design explicit read-only OAuth scope enforcement before a Gorgias canary;
4. canary the isolated Search Console adapter only after its operator-owned
   OAuth and Portal-`off` topology is implemented; keep it out of the catalog
   until provisioning and removal are complete; and
5. decide whether narrowly evidenced `provider_direct` provenance should be
   admitted before one of these providers publishes an official Registry
   record.

That final provenance decision is intentionally separate from approving any
specific source. Direct provider documentation can establish publisher
relationship, but it does not remove the auth, tool, read-only, or Cloudflare
compatibility gates.

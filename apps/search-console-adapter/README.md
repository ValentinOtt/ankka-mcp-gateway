# Google Search Console Code Mode adapter

> **Status:** experimental, self-hosted verification slice. This package
> is not a production Source Catalog preset and is not provisioned by the
> hosted installer.

This Worker turns a reduced Google Search Console API description into the two
MCP tools `search` and `execute` with Cloudflare's `openApiMcpServer()` helper.
It exists to verify the self-hosted adapter architecture without making
Ankka a credential holder or a general API proxy.

The package is an intentional compatibility island. `@cloudflare/codemode`
0.5.1 currently returns an MCP SDK v1 server, so this workspace pins
`@modelcontextprotocol/sdk` 1.30.0 and serves it with
`createLegacyMcpHandler()`. The rest of the gateway is not moved onto the
legacy handler. Moving this adapter to MCP SDK v2 waits for a compatible
Cloudflare helper or a separately reviewed reimplementation.

## Capability boundary

Model-written code sees three virtual API operations:

| Method | Virtual path | Fixed Google request |
| --- | --- | --- |
| `GET` | `/sites` | list properties, then return only the configured approved set |
| `POST` | `/search-analytics/query` | Search Analytics query for an approved property |
| `POST` | `/url-inspection/inspect` | URL Inspection for a URL inside an approved property |

The two POST operations are reads. Every other method and path is rejected
before `fetch()`. The bundled OpenAPI document is a discovery aid, not the
authorization boundary: `src/policy.ts` independently validates the exact
operation, property, request shape, date and row bounds, call concurrency,
deadline, response size, response shape, and fixed upstream origin.

The sandbox has `globalOutbound: null`, no extra modules, and no bindings.
Outbound requests are constructed from scratch with only `Accept`, the
request-local Google bearer token, and `Content-Type` when required. Redirects
are rejected. Provider errors become fixed codes, and Worker logs and traces
are disabled.

## Credential boundary

The incoming bearer must be a Google OAuth access token granted exactly:

```text
https://www.googleapis.com/auth/webmasters.readonly
```

The token is captured inside one Worker request and passed only to the fixed
Google origin selected by the approved operation. It is never stored in a
module variable, binding, configuration file, receipt, log, error, or Ankka
service.

Before starting the sandbox, the Worker makes one bounded call to Google's
fixed `sites.list` endpoint and verifies that the token has readable access to
every configured property. A malformed token, a token without the full
approved set, or an unverified property gets only a fixed authorization error;
the Loader is never started. This preflight proves property access, not the
token's exact scope. The operator-owned OAuth issuance flow must enforce the
single read-only scope above and must not mint the broader Search Console
scope.

This package deliberately does not implement token acquisition or refresh.
Before it can become a preset, a live canary must prove one operator-owned
OAuth topology in Cloudflare. The existing dashboard rejects manual bearer
tokens, arbitrary headers, and OAuth client secrets, so this Worker must not be
added to the ordinary source flow until that topology is implemented and
reviewed.

## Cloudflare Portal constraint

This upstream already is a Code Mode MCP server. Cloudflare documents that an
MCP Portal cannot wrap an upstream Code Mode server in Portal Code Mode. A
canary Portal must therefore have Code Mode exactly `off`. Provisioning must
block for `opt_in`, `default_on`, or `enforced`; it must never silently change
an existing aggregate Portal. A dedicated Portal may be required.

## Self-hosted canary setup

<a id="customer-owned-canary-setup"></a>

Use a dedicated Google identity whose Search Console access is limited to the
properties under test. Store the exact JSON array of approved property names
only in your Cloudflare account:

```sh
npx wrangler secret put SEARCH_CONSOLE_ALLOWED_SITE_URLS \
  --config apps/search-console-adapter/wrangler.toml
```

Example input shape (replace it at the prompt; do not commit deployment-specific values):

```json
["sc-domain:example.test", "https://www.example.test/"]
```

Build the exact Worker bundle without deploying:

```sh
npm run build --workspace @ankka/search-console-adapter
```

A maintainer-approved live canary must additionally prove Google OAuth refresh
and revocation, a successful read, a denied write, exact Portal tools
(`search`, `execute`), content-free logs, and complete removal. Provider tokens,
property names, API responses, account IDs, and Cloudflare resource IDs must
not be copied into this repository or an Ankka service.

## Upgrade and release gates

The adapter remains experimental until all of these are implemented:

1. a reviewed operator-owned OAuth topology that never sends Google
   credentials through Ankka;
2. create, update, recovery, rollback, and receipt-authorized removal for the
   gateway Worker, Loader binding, Portal source, and OAuth grant;
3. an apply-time assertion that Portal Code Mode is `off`;
4. a live Cloudflare and Google canary; and
5. a new immutable Source Catalog implementation revision covering the exact
   Worker artifact, spec digest, policy digest, auth mode, and `search` /
   `execute` tool selection.

Adding an operation, widening approved properties, changing OAuth topology,
changing the spec or policy descriptor, or moving away from the v1 handler is
a reviewed behavior change.

## Primary references

- [Cloudflare: Build a Code Mode MCP server from OpenAPI](https://developers.cloudflare.com/agents/model-context-protocol/guides/build-codemode-openapi-mcp-server/)
- [Cloudflare: upstream servers with Code Mode turned on](https://developers.cloudflare.com/cloudflare-one/access-controls/ai-controls/mcp-portals/#upstream-servers-with-code-mode-turned-on)
- [Google Search Console OAuth scopes](https://developers.google.com/webmaster-tools/v1/how-tos/authorizing)
- [Google Search Analytics query](https://developers.google.com/webmaster-tools/v1/searchanalytics/query)
- [Google Search Console v1 discovery artifact](https://raw.githubusercontent.com/googleapis/discovery-artifact-manager/master/discoveries/searchconsole.v1.json)
- [Google URL Inspection](https://developers.google.com/webmaster-tools/v1/urlInspection.index/inspect)

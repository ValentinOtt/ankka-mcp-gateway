# OAuth scope request diagnostic

A public, synthetic **non-authorizing** Worker for examining the scopes requested
by an MCP client's OAuth flow. It is not an OAuth provider, Gorgias connector,
credential store, or substitute for the existing synthetic MCP lifecycle canary.
It never issues an authorization code, token, refresh token, cookie, or grant.

The only proof this fixture provides is which synthetic scopes appear in an
authorization request. It does **not** prove granted permissions, upstream
read-only enforcement, successful token exchange, or production Gorgias safety.
Do not use real account information, credentials, or provider OAuth grants with
this fixture. Real providers are neither contacted nor impersonated.

## Protocol

- `GET /health` identifies `ankka-oauth-scope-diagnostic`.
- `GET` or `POST /mcp` always challenges unauthenticated clients with HTTP 401 and
  `scope="ankka:read"`; supplied credentials never authorize a request. Invalid
  query parameters or cross-origin requests are rejected before that challenge.
- `GET /.well-known/oauth-protected-resource` and the `/mcp`-suffixed variant
  identify this origin's `/mcp` endpoint and its authorization-server metadata.
  The protected resource advertises only `ankka:read`.
- `GET /.well-known/oauth-authorization-server` advertises `ankka:read` and
  `ankka:write`, public-client DCR, authorization-code shape, and S256 PKCE.
- `POST /register` accepts bounded JSON metadata for an HTTPS redirect URI.
  It returns the fixed **non-secret** client identifier
  `ankka-diagnostic-public-client`, not a persisted registration or credential.
  Only validated `redirect_uris`, `client_name`, `client_uri`, `logo_uri`,
  `grant_types`, `response_types`, `token_endpoint_auth_method`, and `scope` are
  accepted. Explicit known scopes are preserved; an omitted scope stays omitted
  so registration does not bias the later authorization request. Client metadata
  may include `refresh_token` alongside the required `authorization_code` grant
  type for compatibility with common MCP clients. This is metadata only:
  `/token` rejects both grant types and never issues credentials.
- `GET /authorize` checks the public client identifier, `response_type=code`, an
  HTTPS `redirect_uri`, a 43-character base64url `code_challenge`,
  `code_challenge_method=S256`, and a bounded nonempty `state`. An optional
  `resource` must equal this origin's `/mcp`. It does not redirect or grant access.
  Its redacted JSON report contains only the fixture identifier,
  `authorizationIssued: false`, `scopeClass` (`missing`, `read_only`,
  `read_and_write`, `write_only`, or `unsupported`), and the booleans
  `readRequested` and `writeRequested`. No raw request parameters are returned.
- `POST /token` returns HTTP 400 `unsupported_grant_type` without reading its body.

Unknown fields, duplicate parameters/JSON keys, unsupported methods, malformed
URLs, and oversized requests receive fixed errors. Registration bodies are
limited to 8 KiB, 128 chunks, and two seconds. HTTPS callback and metadata URLs
are validated but **never fetched or followed**. No client secret is accepted.
All non-MCP routes reject `Authorization` and `Cookie` headers.

Every response disables caching, uses a restrictive CSP and no-referrer policy,
and exposes no CORS permissions. An explicit cross-origin `Origin` is rejected;
ordinary top-level authorization navigation without that header can display the
redacted report. There is no outbound network access in the code, persistence,
mutable module-level request state, or logging.

## Development and deployment boundary

Run local unit tests from the repository root:

```sh
node --test test/oauth-scope-diagnostic.test.mjs
```

The optional Wrangler configuration has no credentials, account/resource IDs,
bindings, or routes. It uses only Web Platform APIs, so no Node compatibility flag
is needed. A gateway operator must separately authorize any deployment to their
canary account; running these tests performs no deployment.

Worker logs, invocation logs, traces, and Logpush are explicitly disabled because
OAuth query strings can contain state and callback information. Do not enable
tailing, request logging, or an external logging proxy for a diagnostic run.
Cloudflare account-level logging settings and browser history are outside this
fixture's control. Store live endpoints and any run-specific details privately,
not in this public repository.

## Cloudflare diagnostic procedure

Use only the existing approved canary account. Deploy a separate disposable
Worker and register its `/mcp` endpoint as a new OAuth MCP server, without
attaching it to an existing portal or changing any existing source. Keep exact
resource identifiers and cleanup ownership outside this repository.

API-created servers also need a companion Access application before the
dashboard considers their setup complete. Use `type: "mcp"` with exactly one
`via_mcp_server_portal` destination referencing this disposable server. Leave
policies empty (default deny), public hostnames unset, and portals unattached.
Record the companion application's exact ID and ownership marker privately;
never repair this test by changing an existing application or access policy.

Cloudflare's documented automatic-OAuth path starts administrative authorization
from the MCP server's dashboard action. Follow that flow only to this synthetic
fixture's diagnostic response; no consent or token exchange can complete here.
Save only the redacted report, not the browser URL, callback, state, or PKCE
values. The server remaining in `Waiting` / authentication-required state is
expected because this fixture never issues credentials.

Direct requests to `/authorize` test the fixture itself, **not Cloudflare**.
Only a request reached through an observed Cloudflare-generated authorization
flow is evidence about Cloudflare's requested scopes. A rejected registration
means the diagnostic and client metadata are incompatible, not that the client
requested excessive permissions.

Delete the receipt-owned, policy-free companion application first, then the
diagnostic MCP server and Worker, and verify all are absent. Do not use production
provider accounts for this procedure. Even a `read_only` result still leaves
actual token grants and the provider's operation-level enforcement unverified.

The logging exception is intentional: Cloudflare's [Workers Logs documentation](https://developers.cloudflare.com/workers/observability/logs/workers-logs/)
states that invocation logs include request URLs. This small fixture follows the
[Workers best practices](https://developers.cloudflare.com/workers/best-practices/workers-best-practices/)
for bounded body handling and request-local state, without enabling query logging.

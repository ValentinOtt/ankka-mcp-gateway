# Agent instructions

This repository is designed to become public. Treat every commit, test fixture,
comment, and Git revision as publishable.

## Product boundary

Ankka MCP Gateway is the customer-owned edge for a company's MCP sources.
The first deployment target is Cloudflare. Runtime resources, access policies,
logs, and upstream credentials belong to the customer's Cloudflare account.

This repository may contain deployment tooling, the source for Ankka's hosted
installer, declarative configuration, customer-resident runtime code, public
protocol contracts, and synthetic examples. Public source does not carry
deployment authority: it must not contain private product code, customer data,
internal semantic content, Cloudflare account or resource IDs, credentials,
private signing material, generated release output, or private repository
history. Public service hostnames and OAuth client identifiers are allowed when
they are explicitly documented as non-secret.

## Security invariants

- MCP source-provider credentials must never transit or be stored by Ankka.
  The distinct Cloudflare installer grant is operation-scoped: it exists only
  in the connected callback's request-local memory and, where a reviewed relay
  requires it, is forwarded once to the exact HMAC-authenticated customer
  Worker. It is never persisted, logged, exposed to any other destination, or
  reused for another action.
- Secrets must not appear in configuration files, logs, exceptions, telemetry,
  tests, snapshots, or deployment output.
- Customer-deployed gateways send no telemetry to Ankka. The Ankka-hosted
  installer may collect documented, identifier-free, server-authored funnel
  events by default. Its exact fields, destination, retention, and user-facing
  notice must remain public; it must not add visitor, session, customer,
  provider-resource, request, credential, or free-form dimensions.
- The initial capability boundary is read-only with explicit tool allowlists.
- Prompts and tool names are not authorization boundaries; upstreams must also
  enforce the allowed operations.
- Do not introduce arbitrary credential forwarding or open-proxy behavior.

## Development

- Keep the dependency graph small.
- Record the origin and license of any transferred or vendored material in
  `ORIGINS.md` and `THIRD_PARTY_NOTICES.md`.
- Run `npm run check` before committing.
- Never commit `.env`, `.dev.vars`, Cloudflare account/resource IDs, API tokens,
  Terraform state, private keys, or generated deployment output.
- Production deployment credentials, signing keys, and CI authority remain
  outside this repository even when the implementation they invoke is public.

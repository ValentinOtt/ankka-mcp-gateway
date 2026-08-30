# Agent instructions

Treat this as a public repository. Every commit, test fixture, comment, and Git
revision must be publishable.

## Product boundary

Ankka MCP Gateway is the self-hosted edge for a team's MCP sources.
The first deployment target is Cloudflare. Runtime resources, access policies,
logs, and upstream credentials belong to the team's Cloudflare account.

This repository may contain deployment tooling, the source for Ankka's hosted
installer, declarative configuration, gateway runtime code, public
protocol contracts, and synthetic examples. Public source does not carry
deployment authority: it must not contain private product code, private data,
internal semantic content, Cloudflare account or resource IDs, credentials,
private signing material, generated release output, or private repository
history. Public service hostnames and OAuth client identifiers are allowed when
they are explicitly documented as non-secret.

## Security invariants

- MCP source-provider credentials must never transit or be stored by Ankka.
  The distinct Cloudflare installer grant is operation-scoped: it exists only
  in the connected callback's request-local memory and, where a reviewed relay
  requires it, is forwarded once to the exact HMAC-authenticated gateway
  Worker. It is never persisted, logged, exposed to any other destination, or
  reused for another action.
- Secrets must not appear in configuration files, logs, exceptions, telemetry,
  tests, snapshots, or deployment output.
- Self-hosted gateways send no telemetry to Ankka. The Ankka-hosted
  installer may collect documented, server-authored, session-scoped funnel
  events by default. Its exact fields, destination, retention, and user-facing
  notice must remain public; it must not add cookies, cross-session identifiers,
  account or user identifiers, IP or raw user-agent storage, provider-resource,
  credential, or free-form dimensions.
- The initial capability boundary is read-only with explicit tool allowlists.
- Prompts and tool names are not authorization boundaries; upstreams must also
  enforce the allowed operations.
- Do not introduce arbitrary credential forwarding or open-proxy behavior.

## Stage-appropriate engineering

- Keep implementation proportional to current users, requirements, and threat
  model. Preserve the security invariants above, but prefer a few simple,
  auditable boundaries over speculative enterprise machinery.
- Do not add generalized IAM, fine-grained RBAC, policy engines, approval
  workflows, or elaborate audit infrastructure without a current product need
  or demonstrated risk. Record a follow-up or narrow extension point instead.

## Product language

- Address people as "you" and "your team" in product copy. Use "users" for
  people connecting through the gateway and "gateway operators" or
  "administrators" for the people managing it.
- Describe the deployment as "self-hosted" or "in your Cloudflare account";
  do not imply a commercial relationship with Ankka.
- Keep existing protocol fields, configuration values, routes, and published
  document paths stable when changing copy.

## Development

- Keep the dependency graph small.
- Record the origin and license of any transferred or vendored material in
  `ORIGINS.md` and `THIRD_PARTY_NOTICES.md`.
- Run `npm run check:fast` while developing. The full `npm run check` release
  gate runs in continuous integration on every pull request and must pass
  before merge.
- The toolchain is pinned by `.nvmrc`, `packageManager`, and `devEngines`.
  Local drift warns; `check:toolchain` enforces the exact versions in
  continuous integration and at the head of the full gate.
- `main` accepts only pull requests with a passing `check` status. Work on a
  branch; merge with rebase or squash (`gh land` opens the pull request and
  auto-merges when checks pass).
- A working clone may carry the intentionally private `private-history`
  remote, private local branches, and private tags. Never push private refs
  to `origin`. The public-history check audits the publishable surface only:
  `HEAD`, `origin` refs, and tags.
- Bumping wrangler moves reviewed toolchain pins: restate the version,
  lockfile path, and tool-file locations in
  `apps/installer/scripts/generate-reviewed-canary.mjs` and its test, and
  keep the esbuild pin aligned with wrangler's bundled esbuild.
- Never commit `.env`, `.dev.vars`, Cloudflare account/resource IDs, API tokens,
  Terraform state, private keys, or generated deployment output.
- Production deployment credentials, signing keys, and CI authority remain
  outside this repository even when the implementation they invoke is public.

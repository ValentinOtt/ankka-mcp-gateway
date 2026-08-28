# Ankka MCP Gateway

Ankka MCP Gateway gives a company one MCP endpoint for its approved tools while
keeping the gateway, access policies, logs, and upstream credentials in the
company's Cloudflare account.

> **Status:** pre-release. The customer runtime and hosted-installer source are
> available for review and local development, but the checked-in installer is
> intentionally unable to deploy or remove gateways. There is no supported
> production release yet.

## Why this exists

Connecting every employee and agent directly to every MCP server creates a
scattered access and credential surface. Ankka MCP Gateway puts Cloudflare
Access and an MCP Server Portal in front of an explicit set of sources:

```text
employee MCP client
  -> Cloudflare Access
  -> customer-owned MCP Portal
       -> approved MCP sources
```

The initial capability boundary is read-only. Every source has an exact tool
allowlist; wildcard tools are rejected. Tool names and source-authored safety
annotations are useful for review, but they are not authorization by
themselves.

## Ownership model

The customer owns and operates:

- the MCP Portal and its hostname;
- Cloudflare Access applications and policies;
- the customer management Worker and Durable Object;
- DNS, request logs, installation state, and removal authority; and
- all upstream credentials and per-user OAuth grants.

Ankka's optional hosted installer coordinates a customer-approved deployment
with a short-lived, operation-scoped Cloudflare OAuth grant. It must not persist
that grant, receive upstream provider credentials, or proxy ordinary MCP
traffic.

This repository contains the inspectable customer runtime, dashboard, hosted
installer, offline planning tools, release contracts, and synthetic fixtures.
It does not contain customer data, private Cloudflare account or resource
identifiers, credentials, private signing keys, generated releases, or
deployment authority. The documented service hostname and OAuth client
identifier are public identifiers, not secrets.

## Product surfaces

- **MCP endpoint:** the employee-facing Cloudflare MCP Portal.
- **Customer dashboard:** a customer-owned interface for status, sources,
  updates, rollback, and removal.
- **Hosted installer:** an optional Ankka-hosted flow for discovery, plan
  review, Cloudflare consent, installation, and removal.
- **Offline tools:** secret-free configuration validation and deterministic
  planning for development and review.

The management dashboard and MCP Portal must use different hostnames.

## Run locally

Development is pinned to Node.js `22.23.2` and npm `10.9.8`; any Node manager
that reads `.nvmrc` works.

```sh
nvm install   # or: fnm install / mise install
nvm use
npm ci
npm run check
```

To open both user interfaces with synthetic data:

```sh
npm run dev:ui
```

This starts the customer dashboard at `http://127.0.0.1:5730` and the hosted
installer preview at `http://127.0.0.1:5731`. The preview does not contact
Cloudflare and needs no credentials.

The offline configuration tools are also safe to run locally:

```sh
npm run validate -- examples/gateway.config.json
npm run plan:example
```

They read local, secret-free JSON and perform no network requests or mutations.
The observed-state examples are planning input only and never grant update or
deletion authority.

## Repository map

| Path | Purpose |
| --- | --- |
| [`src/`](src/) | Offline configuration, planning, receipt, and lifecycle libraries |
| [`apps/admin/`](apps/admin/) | Customer management dashboard |
| [`apps/installer/`](apps/installer/) | Optional hosted installer |
| [`payload/`](payload/) | Source inputs for signed customer releases |
| [`deploy/cloudflare/`](deploy/cloudflare/) | Cloudflare deployment notes |
| [`fixtures/`](fixtures/) | Synthetic, credential-free test fixtures |
| [`docs/`](docs/) | Public product, security, privacy, and update contracts |

Generated builds, signed envelopes, credentials, and deployment output are not
committed.

The history gate treats commit `4ba4c065aa67a761287bd74fc56f4911f7e558b3`
as the last already-published branding baseline. Only retired gateway naming in
that commit and its ancestors is grandfathered. Every other content, path,
generated-output, and structural check still covers all reachable history, and
every other commit receives the complete policy.

### JavaScript and TypeScript boundary

Application and library source is TypeScript. The JavaScript under `payload/`
is intentional: those files are dependency-free, single-module release inputs
whose exact bytes are hashed and signed before customer deployment. Compiling
them from TypeScript during release would introduce a second, toolchain-shaped
artifact between the reviewed source and the signed payload.

Standalone Node.js release utilities and tests use `.mjs` when they need to run
directly without producing checked-in build output. New reusable runtime logic
belongs in TypeScript unless it must be part of an exact signed payload.

## Security and privacy

- MCP source-provider credentials never transit or persist at Ankka.
- Customer-deployed gateways send no telemetry to Ankka.
- The Ankka-hosted installer may record only the fixed funnel without user,
  session, request, or customer identifiers documented in
  [Hosted installer analytics](docs/HOSTED_INSTALLER_ANALYTICS.md).
- Every Cloudflare resource mutation requires fresh provider state, an exact
  customer-approved target and plan, and a durable intent record. Adoption and
  deletion additionally require receipt-bound ownership.
- Secrets must not appear in configuration, logs, errors, analytics, tests, or
  support reports.

Report vulnerabilities privately as described in [SECURITY.md](SECURITY.md).

## Documentation

- [Customer self-service](docs/CUSTOMER_SELF_SERVICE.md)
- [Architecture](docs/ARCHITECTURE.md)
- [Security model](docs/SECURITY_MODEL.md)
- [Gateway updates and rollback](docs/UPDATES.md)
- [Hosted installer analytics](docs/HOSTED_INSTALLER_ANALYTICS.md)
- [Release integrity](docs/RELEASING.md)
- [Contributing](CONTRIBUTING.md)
- [Changelog](CHANGELOG.md)
- [Code of conduct](CODE_OF_CONDUCT.md)

## Getting help

For a reproducible, non-security problem, open a
[GitHub issue](https://github.com/ValentinOtt/ankka-mcp-gateway/issues) using
synthetic values and fixed public error codes only. There is no production
support commitment during the preview.

Never include credentials, customer data, private hostnames, Cloudflare account
or resource identifiers, cookies, or raw provider responses. Report
vulnerabilities privately through [SECURITY.md](SECURITY.md).

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE).

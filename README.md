# Ankka MCP Gateway — self-hosted on Cloudflare

Ankka MCP Gateway is an open-source Model Context Protocol (MCP) gateway for
teams that want one endpoint for approved, read-only tools. The gateway,
access policies, logs, and upstream credentials stay in your team's
Cloudflare account, not at Ankka.

> **Status:** canary preview. Signed [canary releases](https://github.com/ValentinOtt/ankka-mcp-gateway/releases)
> are available. This repository contains the gateway runtime and hosted-installer
> source; live deployment authority and credentials remain outside the public
> repository.

[Try the local preview](#run-locally) ·
[What Ankka adds](#what-ankka-adds-to-cloudflare-mcp-portals) ·
[Common questions](#common-questions) · [Documentation](#documentation)

## Who is it for?

Ankka MCP Gateway is for teams using Cloudflare that want to:

- give team members and agents one MCP endpoint for an approved set of sources;
- keep access policies, provider credentials, and gateway operations under
  their own account's control; and
- review exact tool allowlists and an inspectable deployment and update path.

It is not a hosted catalogue of provider accounts or a general-purpose proxy.
You bring your own MCP sources and enforce read-only access upstream as well
as at the gateway.

## Why this exists

Connecting every team member and agent directly to every MCP server creates a
scattered access and credential surface. Ankka MCP Gateway puts Cloudflare
Access and an MCP Server Portal in front of an explicit set of sources:

```text
team member or agent's MCP client
  -> Cloudflare Access
  -> Cloudflare MCP Portal in your account
       -> approved MCP sources
```

The initial capability boundary is read-only. Every source has an exact tool
allowlist; wildcard tools are rejected. Tool names and source-authored safety
annotations are useful for review, but they are not authorization by
themselves.

## Run locally

Try the gateway dashboard and installer with synthetic data. This preview
needs no credentials, does not contact Cloudflare, and does not deploy a
gateway or connect real MCP sources.

Use Node.js `22.23.2` and npm `10.9.8`. The example below uses nvm; fnm and mise
can also read the pinned version from `.nvmrc`.

```sh
git clone https://github.com/ValentinOtt/ankka-mcp-gateway.git
cd ankka-mcp-gateway
nvm install   # or: fnm install / mise install
nvm use
npm ci
npm run dev:ui
```

Open the [gateway dashboard](http://127.0.0.1:5730) or the
[installer preview](http://127.0.0.1:5731). Stop both with `Ctrl+C`.

To inspect a configuration and its deployment plan without making changes,
run these commands from the repository root:

```sh
npm run validate -- examples/gateway.config.json
npm run plan:example
```

They read local, secret-free JSON and perform no network requests or mutations.
The observed-state examples are planning input only and never grant update or
deletion authority.

See [Contributing](CONTRIBUTING.md#set-up-the-project) for the development
checks and [Self-service deployment](docs/CUSTOMER_SELF_SERVICE.md) for deployment
prerequisites and availability.

## What Ankka adds to Cloudflare MCP Portals

[Cloudflare MCP Server Portals](https://developers.cloudflare.com/cloudflare-one/access-controls/ai-controls/mcp-portals/)
provide the shared MCP endpoint, Access authentication, tool selection, Code
Mode, and request logs. Ankka uses these Cloudflare capabilities; it does not
replace them or route ordinary MCP traffic through an Ankka-hosted service.

This repository adds an inspectable management layer around those resources:

- **Configuration and planning:** secret-free configuration, exact read-only
  tool allowlists, and deterministic plans for review.
- **Self-hosted management:** a dashboard and Worker for source management
  and operator-approved lifecycle actions.
- **Release and ownership contracts:** signed updates, rollback, and removal
  constrained to resources the installation can prove it owns.

Read the [architecture](docs/ARCHITECTURE.md),
[security model](docs/SECURITY_MODEL.md), and
[update and rollback boundaries](docs/UPDATES.md) before evaluating a deployment.

## Ownership model

Your team owns and operates:

- the MCP Portal and its hostname;
- Cloudflare Access applications and policies;
- the gateway management Worker and Durable Object;
- DNS, request logs, installation state, and removal authority; and
- all upstream credentials and Cloudflare-managed source connections.

Ankka's optional hosted installer coordinates a deployment you approve
with a short-lived, operation-scoped Cloudflare OAuth grant. It must not persist
that grant, receive upstream provider credentials, or proxy ordinary MCP
traffic.

## Product surfaces

- **MCP endpoint:** the team-facing Cloudflare MCP Portal.
- **Gateway dashboard:** an interface in your Cloudflare account for status,
  sources, updates, rollback, and removal.
- **Hosted installer:** an optional Ankka-hosted flow for discovery, plan
  review, Cloudflare consent, installation, and removal.
- **Offline tools:** secret-free configuration validation and deterministic
  planning for development and review.

The management dashboard and MCP Portal must use different hostnames.

## Security and privacy

- MCP source-provider credentials never transit or persist at Ankka.
- Self-hosted gateways send no telemetry to Ankka.
- The Ankka-hosted installer may record only the fixed, session-scoped funnel
  documented in [Hosted installer analytics](docs/HOSTED_INSTALLER_ANALYTICS.md):
  no cookies, no IP or raw user-agent storage, and no identifier that outlives
  the session. Deploying from this repository sends no analytics.
- Every Cloudflare resource mutation requires fresh provider state, an exact
  operator-approved target and plan, and a durable intent record. Adoption and
  deletion additionally require receipt-bound ownership.
- Secrets must not appear in configuration, logs, errors, analytics, tests, or
  support reports.

Report vulnerabilities privately as described in [SECURITY.md](SECURITY.md).

## Common questions

### Does Ankka receive my MCP provider credentials?

No. MCP source-provider credentials stay in your Cloudflare account;
they never transit or persist at Ankka. The optional hosted installer uses a
separate, short-lived Cloudflare grant for the operation you approve.
That grant is not an upstream provider credential.

### Does read-only access depend on tool names?

No. Exact tool allowlists are required, but names, descriptions, and safety
annotations are not authorization boundaries. Each upstream must independently
enforce the permitted operations. Read-only describes the exposed source
capabilities; it does not prevent operator-approved management actions such as
deployment, updates, or removal.

### Can I deploy it outside Cloudflare?

Cloudflare is the only current deployment target. Running the synthetic UI
preview or offline planner locally does not provide a standalone gateway for
another cloud or a local container runtime.

### Which MCP clients and sources can I use?

A client must support the MCP transport exposed by the Cloudflare Portal and
complete your team's Cloudflare Access flow. Sources must meet the gateway's
discovery and authorization requirements; a provider's MCP label alone does
not establish compatibility. See
[supported MCP sources](docs/CUSTOMER_SELF_SERVICE.md#supported-mcp-sources)
and [connecting a client](docs/CUSTOMER_SELF_SERVICE.md#connecting-an-mcp-client).

## Repository map

| Path | Purpose |
| --- | --- |
| [`src/`](src/) | Offline configuration, planning, receipt, and lifecycle libraries |
| [`apps/admin/`](apps/admin/) | Gateway management dashboard |
| [`apps/installer/`](apps/installer/) | Optional hosted installer |
| [`payload/`](payload/) | Source inputs for signed gateway releases |
| [`deploy/cloudflare/`](deploy/cloudflare/) | Cloudflare deployment notes |
| [`fixtures/`](fixtures/) | Synthetic, credential-free test fixtures |
| [`docs/`](docs/) | Public product, security, privacy, and update contracts |

This repository contains the inspectable gateway runtime, dashboard, hosted
installer, offline planning tools, release contracts, and synthetic fixtures.
It does not contain private data, private Cloudflare account or resource
identifiers, credentials, private signing keys, generated releases, or
deployment authority. The documented service hostname and OAuth client
identifier are public identifiers, not secrets.

Generated builds, signed envelopes, credentials, and deployment output are not
committed. Contributor-facing toolchain and history policies are documented in
[Contributing](CONTRIBUTING.md).

## Documentation

- [Documentation index and connection review checklist](docs/README.md)
- [Self-service deployment](docs/CUSTOMER_SELF_SERVICE.md)
- [First-party Cloudflare dogfood runbook](deploy/cloudflare/FIRST_PARTY_DOGFOOD.md)
- [Local canary profiles](docs/CANARY_PROFILES.md)
- [Portal audit logging in your account](docs/CUSTOMER_AUDIT_LOGGING.md)
- [Large sources and Code Mode](docs/LARGE_SOURCES_AND_CODE_MODE.md)
- [Source catalog architecture](docs/SOURCE_CATALOG.md)
- [Provider setup guides and readiness](docs/NATIVE_CONNECTOR_SETUP.md)
- [Experimental self-hosted read-only connectors](apps/read-only-connectors/README.md)
- [B2B connector demand research](docs/CONNECTOR_DEMAND_RESEARCH.md)
- [Experimental Google Search Console adapter](apps/search-console-adapter/README.md)
- [Spec-driven OpenAPI allowlists](docs/OPENAPI_ALLOWLISTS.md)
- [Per-source Cloudflare Access groups](docs/SOURCE_ACCESS_GROUPS.md)
- [Governance roadmap](docs/GOVERNANCE_ROADMAP.md)
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
synthetic values and fixed public error codes only. Support is best-effort as
described in the [support policy](SUPPORT.md). Check the
[release status](https://github.com/ValentinOtt/ankka-mcp-gateway/releases)
before deploying a preview release.

Never include credentials, private data, private hostnames, Cloudflare account
or resource identifiers, cookies, or raw provider responses. Report
vulnerabilities privately through [SECURITY.md](SECURITY.md).

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE).

# Ankka MCP Gateway documentation

Start with the task you want to complete. Ankka MCP Gateway is a canary preview:
check the [release notes](https://github.com/ValentinOtt/ankka-mcp-gateway/releases)
for the version you intend to use. Main-branch source can be ahead of an
installed release; a document or fixture is not a compatibility certification.

## Evaluate the gateway

- [Run the local preview](../README.md#run-locally): synthetic dashboard and
  installer, no credentials and no Cloudflare deployment.
- [Understand what Ankka adds](../README.md#what-ankka-adds-to-cloudflare-mcp-portals):
  native Portal capabilities versus Ankka's management layer.
- [Review the architecture](ARCHITECTURE.md): account ownership, request path,
  management surfaces, and release contracts.
- [Check source and client requirements](CUSTOMER_SELF_SERVICE.md#supported-mcp-sources):
  transport, discovery, shared upstream authentication, and current limitations.

## Install and operate

- [Self-service deployment](CUSTOMER_SELF_SERVICE.md): prerequisites, exact
  Cloudflare permissions, plan review, source setup, and removal.
- [Updates and rollback](UPDATES.md): operator-approved changes and the
  distinction between Worker versions and retained gateway data.
- [Portal audit logging](CUSTOMER_AUDIT_LOGGING.md): logs in your account,
  fields, access, and retention responsibilities.
- [Large sources and Code Mode](LARGE_SOURCES_AND_CODE_MODE.md): tested local
  limits, name handling, and the additional live qualification required.
- [OpenAPI allowlists](OPENAPI_ALLOWLISTS.md): derive exact tool selections
  from a reviewed specification without treating HTTP methods as authorization.
- [Source access groups](SOURCE_ACCESS_GROUPS.md): per-source audience
  boundaries and what the dashboard exposes.

## Review trust and privacy

- [Security model](SECURITY_MODEL.md): provider credentials, authorization,
  release integrity, logging, and known limitations.
- [Hosted installer analytics](HOSTED_INSTALLER_ANALYTICS.md): the fixed,
  session-scoped installer funnel, separate from the gateway's no-telemetry boundary.
- [Release integrity](RELEASING.md): manifests, signatures, pinned authority,
  and publication requirements.
- [Support policy](../SUPPORT.md): best-effort support, latest-release-only
  fixes, and reporting boundaries.
- [Report a vulnerability privately](../SECURITY.md).

## Before sharing a gateway

Qualify a synthetic or independently approved read-only source first:

1. Record the gateway release, client version, source version where available,
   source authentication mode, and exact approved tool names. Keep private
   deployment details outside public reports.
2. Confirm the intended user can authenticate to the Portal and an unauthorized
   test identity cannot. Do not weaken Access policy to make a client work.
3. Verify source authentication and readiness separately from catalogue
   discovery. A public tool list does not prove public tool execution or a
   compatible shared OAuth connection.
4. In a direct-tool session, check that approved upstream tools are present
   and an unapproved upstream tool is absent. Cloudflare's built-in Portal
   tools are distinct from that upstream allowlist.
5. Execute one harmless allowed read against known synthetic data. Do not
   invoke a destructive operation just to test rejection. Names, descriptions,
   and `readOnlyHint` annotations do not replace upstream permissions.
6. If using Code Mode, qualify its search and execution path separately with
   the same harmless read. Follow the detailed
   [live qualification checklist](LARGE_SOURCES_AND_CODE_MODE.md#live-qualification-for-228-and-224-tools).

Read-only operations can still expose sensitive data or incur provider costs.
Review both the accessible data and your upstream account limits. Do not
publish a client/provider compatibility claim from local fixtures alone.

## Contribute or investigate

Use [Contributing](../CONTRIBUTING.md) for pinned toolchain and test commands,
the [changelog](../CHANGELOG.md) for repository changes, and the
[synthetic MCP fixture](../fixtures/synthetic-mcp/README.md) for repeatable,
credential-free tests. The [governance roadmap](GOVERNANCE_ROADMAP.md) describes
future work, not a promise that every feature is available in a signed release.

For update-routing investigations, the [runtime probe canary](RUNTIME_PROBE_CANARY.md)
tests two Worker versions against disposable synthetic Durable Object state.
It never targets an existing gateway and is not a release acceptance test.

For a non-security issue, share fixed public error codes and non-sensitive
version information only. Never include tokens, cookies, private hostnames,
account or resource identifiers, raw provider responses, or private data.

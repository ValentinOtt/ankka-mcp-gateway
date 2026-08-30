# Support policy

Ankka MCP Gateway is an open-source project maintained on a best-effort basis.
This policy is intentionally minimal: it defines what support means today and
will be revised if the project's usage grows. It grants no warranty and no
service-level commitment.

## What support means

- Support is best-effort. There is no committed response time, fix timeline,
  or availability guarantee for any release or channel.
- The project accepts reproducible issue reports and private security reports.
  Accepting a report does not commit to a fix or a date.

## Supported releases

- Only the most recent published release of each channel is supported.
- Fixes, including security fixes, ship as new releases built from `main`.
  Published releases are immutable and are never patched in place; older
  releases receive no backports.
- Getting a fix means updating through the operator-approved
  [update flow](docs/UPDATES.md).

## Channels

- `canary` releases are previews for evaluation. Behavior can change between
  releases without a deprecation period.
- A `stable` release marks the release the maintainers currently recommend
  for regular use. It carries the same best-effort support defined by this
  policy — a channel name is not a warranty, certification, or SLA.

## Self-hosted boundary

Gateways run in your Cloudflare account. Maintainers have no access to your
deployment and cannot operate, inspect, or recover it. Diagnostic help is
limited to fixed public error codes and non-sensitive version information —
never include credentials, private hostnames, Cloudflare account or resource
identifiers, or raw provider responses in a report.

## Reporting

- Non-security problems: open a
  [GitHub issue](https://github.com/ValentinOtt/ankka-mcp-gateway/issues)
  using synthetic values and fixed public error codes only.
- Vulnerabilities: report privately as described in [SECURITY.md](SECURITY.md).

## Changes to this policy

This policy may change in any release. The version of this file at a release's
pinned source commit is the policy that applies to that release.

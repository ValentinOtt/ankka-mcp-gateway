# Security policy

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability or exposed
credential. Use GitHub's
[private vulnerability reporting](https://github.com/ValentinOtt/ankka-mcp-gateway/security/advisories/new).

If private reporting is unavailable, open the detail-free
[Private reporting unavailable issue form](https://github.com/ValentinOtt/ankka-mcp-gateway/issues/new?template=private-reporting-unavailable.yml).
Do not include technical details, credentials, private information, private
hostnames, or provider identifiers. Maintainers will restore a private channel
before requesting more information.

If a credential may be exposed, revoke or rotate it immediately. Deleting a
file or rewriting Git history does not revoke a credential.

## Supported versions

Security fixes target `main` and ship in the next release. Only the most
recent published release of each channel is supported; older releases receive
no backports. See the [support policy](SUPPORT.md). Repository visibility or
a signed artifact does not imply production support.

## Security boundary

- Upstream provider credentials must be authorized and stored in the
  team's Cloudflare account.
- MCP source credentials must not be submitted to an Ankka API, committed to
  this repository, placed in configuration, or emitted in logs, errors,
  analytics, tests, or support material.
- The hosted installer uses a short-lived, operation-scoped Cloudflare OAuth
  grant. The grant exists only in request-local memory for the
  operator-approved operation and is not persisted or reused.
- Gateway sources are read-only and use exact tool allowlists.
- Self-hosted gateways send no telemetry to Ankka.
- Updates require signed release evidence and explicit operator approval.
  Removal additionally requires operator-owned, receipt-bound authority.

See [the security model](docs/SECURITY_MODEL.md) for the complete trust and
authorization design.

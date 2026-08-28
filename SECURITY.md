# Security policy

## Reporting a vulnerability

Please do not open a public issue for a suspected vulnerability or exposed
credential. Use the repository's
[private vulnerability report](https://github.com/ValentinOtt/ankka-mcp-gateway/security/advisories/new).
If that form is unavailable, open an issue titled `Private reporting
unavailable` with no vulnerability detail, credential, customer identifier, or
private locator. Maintainers will restore the private intake before asking for
technical details.

Never include real provider credentials, Cloudflare tokens, customer data, or
production identifiers in a report. If a real credential has been exposed,
revoke or rotate it immediately; deleting a file or rewriting Git history is
not sufficient.

## Supported versions

The project is pre-release, and its initial public launch is a preview. Until an
independent security review is complete and a stable support policy has been
chosen and documented, only the latest commit on `main` is in scope for
security fixes. No preview deployment is production-supported, and repository
visibility or a signed preview artifact does not imply stable support.

## Credential boundary

MCP source-provider credentials must be authorized and stored in the customer's
Cloudflare account. They must not be submitted to an Ankka API, committed to
this repository, placed in gateway configuration, or emitted in logs and
errors. The separate Cloudflare installer grant is operation-scoped and exists
only in the connected callback's request-local memory. A reviewed action may
forward it once to the exact HMAC-authenticated customer Worker; it is never
persisted, logged, sent to any other destination, or reused.

See [docs/SECURITY_MODEL.md](docs/SECURITY_MODEL.md) for the current trust model
and known limitations.

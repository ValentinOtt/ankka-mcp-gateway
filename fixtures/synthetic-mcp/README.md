# Synthetic MCP canary fixture

This disposable local fixture exposes a stateless Streamable HTTP MCP endpoint
containing no credentials, customer data, clock values, or external network
calls. It advertises exactly one deterministic read-only tool:
`ankka_canary_status`.

The fixture exists only to characterize Cloudflare MCP Server and Portal
behavior before the production mutation adapter is connected. Do not attach
real sources or credentials to it.

## First canary: local listener and Quick Tunnel

The first live canary does not require permission to deploy Workers. Start the
fixture on loopback only:

```sh
npm run canary:fixture:serve
```

In a second terminal, expose that listener through a temporary Cloudflare Quick
Tunnel:

```sh
cloudflared tunnel --url http://127.0.0.1:9610
```

Use the tunnel's exact HTTPS hostname plus `/mcp` as the Cloudflare MCP server
endpoint with authentication set to **None**. Keep both processes running for
the canary, then stop them with Ctrl-C. Quick Tunnels are disposable test
infrastructure and are not the production deployment design.

Before any Cloudflare mutation, the canary runner must call
`inspectSyntheticEndpoint` from `inspect.mjs`. It performs initialization,
tool discovery, and one constant tool call, then returns only this sanitized
proof:

```json
{
  "fixture": "ankka-synthetic-mcp-canary",
  "schemaVersion": 1,
  "toolNames": ["ankka_canary_status"],
  "callVerified": true
}
```

Any endpoint or tool mismatch fails closed without returning upstream bodies.

## MCP contract

- transport: stateless Streamable HTTP at `POST /mcp`;
- authentication: none;
- supported requests: `initialize`, `server/discover`, `ping`, `tools/list`,
  and `tools/call`;
- notifications: accepted with HTTP 202 and no response body;
- tool: `ankka_canary_status`, accepting an empty object;
- response: constant synthetic text and structured content;
- server-initiated SSE: intentionally unsupported; `GET /mcp` returns 405.

The endpoint supports Cloudflare's initialization-based MCP sync across the
2025 Streamable HTTP revisions and the current stateless `2026-07-28`
`server/discover` flow. Modern requests are accepted only when the protocol,
method, and tool-name headers match the JSON-RPC body.

The fixture has no durable state. Stopping the local listener and Quick Tunnel
is its complete teardown. This repository intentionally contains no Worker
deployment or deletion command for the first canary.

## Partial-install cleanup recovery

Use the ordinary lifecycle `preview` and `run` commands after a bounded pending
Portal rollback. When the runner finds the exact checksum-valid rollback
receipt (server, source Access application, and source Access policy only), it
automatically returns the separate `cleanup_partial_install` preview. That
preview contains no apply actions and lists only the three receipt-owned
deletions in reverse dependency order.

Cleanup still requires the freshly rendered lifecycle approval and disposable-
target confirmation. The approval is bound to the receipt and provenance
checksums, current live plan, exact uninstall plan, and provider locators. The
run re-reads all of that evidence before it writes the immutable cleanup
snapshot or deletes anything. Drift, missing ownership, upper-layer residue,
pending work, or a conflicting cleanup sidecar fails closed.

A successful cleanup prints `PARTIAL INSTALL CLEANUP COMPLETE`, exits zero,
requires zero owned/generated residue, and retains the checksum-protected main
receipt tombstone plus the cleanup snapshot. It is a cleanup result, not proof
that the full Portal canary or interactive tool call succeeded.

## Interrupted local lifecycle lock

The lifecycle receipt and its cleanup-recovery sidecar each use an owner-only
local lock. Inspect a lock without Cloudflare credentials:

```sh
node src/canary-lifecycle-cli.mjs lock inspect \
  --receipt /path/to/canary.receipt.json \
  --store receipt
```

Use `--store cleanup` to inspect the cleanup sidecar. Never remove a live or
ambiguous lock. For a reported stale candidate, copy its exact lock ID and use
the literal confirmation printed by `--help`; recovery performs another fresh
process and file-identity check before removing only that selected lock.

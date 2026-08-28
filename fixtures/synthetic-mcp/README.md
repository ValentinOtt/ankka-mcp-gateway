# Synthetic MCP fixture

This fixture is a deterministic, stateless MCP endpoint used by local tests. It
contains no credentials, customer data, clock values, durable state, or
external network calls.

It exposes one read-only tool: `ankka_canary_status`.

## Run locally

From the repository root:

```sh
npm run canary:fixture:serve
npm run canary:fixture:test
```

The server listens on `127.0.0.1:9610` and exposes Streamable HTTP at
`POST /mcp`. Stop it with Ctrl-C.

## Contract

- supports `initialize`, `server/discover`, `ping`, `tools/list`, and
  `tools/call`;
- accepts notifications with HTTP 202 and no body;
- accepts an empty object for `ankka_canary_status`;
- returns constant synthetic text and structured content; and
- does not support server-initiated SSE.

The fixture is test infrastructure, not a production MCP source. Do not attach
real credentials or customer data.

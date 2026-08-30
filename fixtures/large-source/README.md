# Synthetic large-source fixture

`openapi.json` is a secret-free OpenAPI 3.1 document with 228 synthetic GET
operations, complete operation IDs, summaries, and descriptions.
`gateway.config.json` is the corresponding one-source gateway configuration
whose exact allowlist is generated from those operation IDs. The operations are
grouped into twelve generic domains; they do not describe a real organization or
production API.

The fixture is deliberately formatted with one sorted tool name per line so a
generated allowlist change remains an ordinary, reviewable source diff. It is
used by `test/large-source-scale.test.mjs` to cover validation, deterministic
OpenAPI extraction, planning, and bounded human plan output at this scale.

The same test derives a second, secret-free 224-tool workload in memory. That
supplemental profile mirrors the current dogfood cardinality without replacing
or relabelling the brief's reproducible 228-operation fixture. The checked-in
`sanitization-hostile.config.json` fixture also proves that the gateway keeps
leading-digit, reserved-word, hyphen, dot, and underscore names exact. Three
of its distinct names deliberately collapse to `catalog_item_read` under the
documented hyphen-and-dot replacement shape; it is a collision canary, not a
promise about Cloudflare's final identifier mapping.

Run the public commands directly against it:

```sh
npm run validate -- fixtures/large-source/gateway.config.json
node tools/openapi-enabled-tools.mjs \
  --spec fixtures/large-source/openapi.json \
  --config fixtures/large-source/gateway.config.json \
  --source synthetic-large-source \
  --method GET \
  --check
npm run plan -- fixtures/large-source/gateway.config.json \
  --observed examples/observed.empty.json \
  --access examples/access-input.json
```

This is a repository-local scale fixture, not evidence that a particular
Cloudflare account or MCP client accepts 228 tools. See
[Large sources and Code Mode](../../docs/LARGE_SOURCES_AND_CODE_MODE.md) for
the verified boundary and live qualification checklist.

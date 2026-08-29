# Spec-driven OpenAPI allowlists

`tools/openapi-enabled-tools.mjs` replaces one gateway source's `enabledTools`
with the exact tool names selected from a local OpenAPI document. It is an
offline review aid: it performs no network requests and never deploys anything.

The mapping is deliberately narrow:

- only OpenAPI 3.0 and 3.1 path operations are accepted;
- `--method GET` is required explicitly, and GET is the only method allowed by
  the mechanical selection workflow;
- every selected operation must have an `operationId`;
- that `operationId` becomes the tool name verbatim—the tool does not trim,
  derive, prefix, or otherwise normalize it;
- selected IDs must be unique and match the gateway's cross-surface tool-name contract,
  `[A-Za-z0-9_.:/-]{1,128}`; and
- path-item `$ref` values are rejected because this small tool does not resolve
  them and must not silently omit an operation.

Without `--manifest`, this remains a GET-only operation and behaves exactly as
described above. There is deliberately no `--method POST`, broad read-method
switch, tag selector, or name-pattern selector.

The resulting names are sorted by Unicode code point. The selected source's
existing array is replaced, not combined with the generated names. Other
sources and all other gateway values remain semantically unchanged. `--write`
canonicalizes the complete file's indentation and object-key order, so review
that formatting diff on the first run. Before output or a write, the complete
gateway configuration passes the shared validator, which also rejects
unsupported and credential-bearing fields.

## Review workflow

Start with a secret-free gateway config already tracked beside the source API.
Run the generator after the API build produces its OpenAPI document:

```sh
node tools/openapi-enabled-tools.mjs \
  --spec dist/openapi.json \
  --config gateway.config.json \
  --source inventory-read \
  --method GET \
  --write

npm run validate -- gateway.config.json
git diff -- gateway.config.json
```

Review and commit the config diff before any deployment. A new selected
operation then appears as an explicit added tool name; a removed operation
appears as an explicit deletion. Do not generate and deploy an unreviewed
configuration in one job.

Use check mode in CI to prevent spec/config drift without changing the working
tree:

```sh
node tools/openapi-enabled-tools.mjs \
  --spec dist/openapi.json \
  --config gateway.config.json \
  --source inventory-read \
  --method GET \
  --check
```

Without `--write` or `--check`, the merged config is printed to standard output.
This is useful for inspecting a candidate without changing the input file.

## Security boundary

HTTP GET is a review filter, not proof that an operation is safe. Independently
verify the selected operations and generate the upstream MCP server from the
same reviewed read-only set. The upstream API and MCP server must reject
mutating operations even if a prompt, annotation, tool name, or gateway
configuration is wrong.

This workflow assumes the upstream OpenAPI-to-MCP generator exposes each
`operationId` as the MCP tool name without transformation. Confirm that mapping
against the source's actual MCP tool catalogue before deployment. If the names
differ, do not use this tool to guess the transformation.

Neither the OpenAPI document nor any source credential is copied into the
gateway configuration. Gateway config files must remain secret-free; source
credentials stay in the customer's Cloudflare account.

## Explicit reviewed non-GET selections

Some read APIs use a non-GET method to carry a structured query or an ID list.
Pass `--manifest` only for those individually reviewed exceptions and for
synthetic tools implemented by the upstream MCP wrapper but absent from its
OpenAPI document:

```sh
node tools/openapi-enabled-tools.mjs \
  --spec dist/openapi.json \
  --manifest mcp/readonly-non-get-manifest.json \
  --config gateway.config.json \
  --source inventory-read \
  --method GET \
  --write
```

The manifest selections are unioned with the default GET-derived names. Each
non-GET entry is matched against the exact OpenAPI `operationId`, uppercase
HTTP method, and path. Moving, renaming, deleting, changing the method of, or
making a reviewed operation public makes generation and `--check` fail. A
manifest never authorizes every operation of a method.

### Public manifest contract

The current contract is the following exact JSON object. Both arrays are
required and may be empty individually; using `--manifest` with both empty is
an error. `$comment` is the only optional top-level field.

```json
{
  "$comment": "Review additions as new read scope. This file is public and secret-free.",
  "entries": [
    {
      "operationId": "queryInventory",
      "method": "POST",
      "path": "/inventory/query",
      "reason": "A structured inventory lookup; the implementation performs no mutation.",
      "verified": "2026-08-29 code review"
    }
  ],
  "syntheticTools": [
    {
      "name": "inventoryReadHealth",
      "reason": "A fixed wrapper-local health result which never calls the origin."
    }
  ]
}
```

Unknown or missing fields are rejected at the root and in both entry types.
`operationId` and `name` use the same 128-character tool-name contract as the
gateway. Methods must be uppercase standard HTTP methods and must not be GET.
Paths must be absolute OpenAPI paths without query strings, fragments,
whitespace, or control characters. Review prose must be non-empty, trimmed,
single-line text without control or Unicode format characters; it is
validation evidence only and is never copied to the
gateway configuration or error output. The complete manifest is limited to
500 selections, and its union with GET-derived names must also fit the
gateway's 500-tool per-source limit.

Operation IDs, method/path pairs, and synthetic names must be unambiguous and
unique. A synthetic name must not collide with any operation ID in the spec,
whether that operation is selected or excluded. The resulting tool names are
sorted deterministically by Unicode code point; under the gateway's ASCII
tool-name contract this is also byte order.

### Authentication check

A manifest-selected non-GET operation must have an effective OpenAPI security
requirement, inherited from the document or declared on the operation. Missing
security, `security: []`, or any anonymous `{}` alternative is treated as a
public/credential-free operation and rejected. Every named security scheme in
every alternative must exist in `components.securitySchemes`; malformed or
unknown requirements fail closed.

This is a structural check, not proof of read-only behavior. The reviewer must
still inspect the implementation identified by `operationId` and record why it
cannot mutate state. The upstream MCP wrapper must enforce the same exact
selection. Synthetic entries require the same review and must be confirmed in
the wrapper's actual `tools/list` result before deployment.

Use the same `--manifest` argument in CI. `--check` recomputes the union and
fails on config selection drift as well as invalid spec/manifest binding:

```sh
node tools/openapi-enabled-tools.mjs \
  --spec dist/openapi.json \
  --manifest mcp/readonly-non-get-manifest.json \
  --config gateway.config.json \
  --source inventory-read \
  --method GET \
  --check
```

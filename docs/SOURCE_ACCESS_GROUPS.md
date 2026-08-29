# Per-source Cloudflare Access groups

Each source may optionally name one customer-chosen Cloudflare Access group:

```json
{
  "id": "erp",
  "label": "ERP",
  "url": "https://erp.example.com/mcp",
  "authentication": { "mode": "oauth", "onBehalfOfUser": true },
  "accessGroup": "ERP Readers",
  "enabledTools": ["erp_search"]
}
```

`accessGroup` is a logical, exact, case-sensitive name. It is public
configuration, not a provider resource ID and not an authorization claim. A
source without this field retains the existing email audience. The Portal
Access policy always retains the `allowedEmails` audience so that members can
authenticate to the Portal before source-specific policies narrow visibility.

## Fresh resolution input

Immediately before each plan, provider readback, and apply, the customer-side
caller must freshly list the account's Cloudflare Access groups with an
appropriately scoped grant and pass only `{id,name}` observations in the
ephemeral access input. `groups` is a provider-observation snapshot, not stored
configuration:

```json
{
  "allowedEmails": ["owner@example.com"],
  "groups": [
    { "id": "synthetic-access-group", "name": "ERP Readers" }
  ]
}
```

The checked-in example is synthetic. Do not commit a live access-input file:
Cloudflare account and resource IDs belong to the customer environment. This
repository consumes the observations but does not itself obtain authority to
list groups.

For example, after producing a temporary access-input file outside the
repository:

```sh
npm run plan -- fixtures/access-groups/gateway.config.json \
  --observed examples/observed.empty.json \
  --access /path/to/temporary-access-input.json
```

Resolution is fail closed. A configured logical name must match exactly one
valid observation. Missing observations, case differences, duplicate names,
duplicate rows, unsafe IDs, extra fields, and malformed names block the plan.
There is no fallback from a configured source group to `allowedEmails`. If a
resolved ID changes, disappears, or becomes ambiguous between planning and
mutation, the provider rejects the mutation before submitting a Cloudflare
write.

## Provider and output boundary

For a resolved source, the Cloudflare Access Allow policy contains exactly one
include rule:

```json
{ "group": { "id": "resolved-at-apply-time" } }
```

The provider reconstructs this rule from the fresh access input and the
desired-state digest. Readback accepts only that exact selector; a different
ID, an email selector, an additional rule, or an extra nested field is drift.

Plans and desired state contain only `identityType`, `identityCount`, and a
stable SHA-256 digest. Receipts retain only the digest already used for policy
ownership checks. They never contain a raw group ID, group membership, or the
ephemeral observation list.

Cloudflare Access is one layer of authorization. The upstream MCP source must
still enforce the caller's allowed operations; tool names and group names do
not grant upstream authority.

# Source visibility and live canaries

This document records the boundary for two optional post-preview capabilities.
The customer-operated live Portal runner described below is implemented, but
no customer deployment or live result is part of this repository. The only
implemented gateway capability mode remains `read_only`, with exact tool
allowlists and independent upstream enforcement.

For the current founding-team dogfood deployment, one Access group and manual
health/catalogue checks are sufficient. Multiple visibility partitions,
scheduled machine identities, exact actor correlation, and every form of write
execution are deferred until a present product need justifies them.

## Readiness summary

| Capability | Current state | Remaining gate |
| --- | --- | --- |
| Per-source Access groups | Implemented and optional; one group is enough for current dogfood | Live qualification only when a deployment actually needs more than one visibility audience |
| Write tools | Parked; rejected by the schema-level capability boundary | A future user need and a new threat-model review; no current implementation plan |
| Scheduled live-source canary | Optional standalone bounded runner implemented; synthetic transport tests pass | Customer-owned scheduling and sink only if manual qualification stops being sufficient |

## Per-source Access groups

The founding-team deployment uses one group. The machinery below remains a
generic optional capability; it is not a reason to create sensitivity
partitions or additional groups for the current BLS source.

Cloudflare enforces Access selectors, including Groups, on MCP server
applications reached through a Portal. The implemented contract is documented
in [Per-source Cloudflare Access groups](SOURCE_ACCESS_GROUPS.md).

An optional source `accessGroup` carries a customer-chosen exact logical name.
Immediately before plan, readback, and apply, the caller must freshly enumerate
Cloudflare groups with customer-owned authority and supply an ephemeral
`groups: [{id,name}]` observation snapshot. The offline planner does not fetch
that snapshot. It binds the logical name only when exactly one observation
matches and blocks missing, malformed, or ambiguous mappings without falling
back to the Portal-wide email audience.

A bound source receives a default-deny Allow policy with exactly one
`{group:{id}}` include selector. Sources without `accessGroup` retain the prior
email behavior, and the Portal policy always remains email-based. Plans expose
only the identity type, count, and stable digest; receipts retain the policy
identity digest, not provider group IDs or membership. Provider mutation
rebuilds the expected policy from the current config and snapshot before any
write, while readback treats a changed ID, extra selector, or extra nested field
as drift.

Synthetic config, planner, receipt, provider-mutation, and drift tests cover
the contract. This repository does not claim a live Cloudflare qualification:
the customer must still verify multiple groups, one user in each relevant
group, and a user in no group in its own account. Caller-side group enumeration
and any hosted UI that constructs the snapshot remain external integrations.

Group names, tool names, and prompts are not authorization. The upstream source
must still reject operations outside the caller's actual authority.

## Writes are parked

The current product is read-only. A possible future `bls-admin` source remains
physically separate from `bls-read`, but it is not part of this roadmap or a
current implementation target. Existing write-risk notes are historical
research only and must not drive approval workflows, idempotency machinery,
policy engines, or generalized IAM into the founding-team deployment.

If a real write use case arrives, start a new design from that operation, its
current users, and its demonstrated failure modes. Never widen the `bls-read`
credential or catalogue as a shortcut.

## Customer-owned live canary

A live canary must not sample arbitrary business tools. Each source should
expose one dedicated read-only health tool with fixed synthetic output, no
arguments that select customer records, and no provider credential or response
content. The same operation must be safe to repeat.

The scheduled runner should live in the customer's account or monitoring
system and use a dedicated machine identity. Its Portal and every target source
need matching least-privilege Access Service Auth policies. The current gateway
does not declaratively create those machine-identity policies.

The standalone runner is implemented in
[`tools/live-portal-canary.mjs`](../tools/live-portal-canary.mjs). It makes three
stateless MCP `2026-07-28` JSON-RPC operations: list the Portal surface, search
for one exact sanitized Code Mode identifier, and execute that identifier with
an empty object. It does not create a service token, change an Access policy,
inspect Portal logs, schedule itself, or export to a monitoring sink. Those
customer operations and the first live result remain external qualification.

The JSON configuration can live inside or outside this repository and has one
strict, secret-free shape:

```json
{
  "schemaVersion": 1,
  "portalUrl": "https://portal.example.com/mcp",
  "healthToolIdentifier": "bls_read_ankka_canary_status",
  "arguments": {},
  "expectedCanonicalResultSha256": "sha256:ccf234692f2ac6ca25aacd6fb331d57cd619c7859fdb5b4d9922bf063f46fa2c"
}
```

That example digest is for the fixed JSON value
`{"fixture":"ankka-live-canary","ok":true,"version":1}`. Canonicalization
recursively sorts object keys, preserves array order, emits compact JSON, and
hashes its UTF-8 bytes. Configure the digest from the health tool's reviewed,
synthetic constant; do not derive it by printing a live business response.
`arguments` must be exactly `{}`. Unknown configuration fields, URL query
parameters, non-HTTPS URLs, and non-sanitized identifiers are rejected.

Derive the example digest offline from that reviewed synthetic constant:

```sh
node --input-type=module -e 'import { canonicalResultSha256 } from "./tools/live-portal-canary.mjs"; const value = { fixture: "ankka-live-canary", ok: true, version: 1 }; process.stdout.write(`${canonicalResultSha256(value)}\n`);'
```

Replace only the `value` literal with the exact constant returned by the
customer's health tool. This command does not make a network request.

The exact Portal URL must end at `/mcp` without a query or fragment. Therefore,
configure the Portal's Code Mode policy as `default_on` or `enforced`; the
runner does not append an opt-in query. Put the service-token values only in the
runner environment, then invoke:

```sh
export CF_ACCESS_CLIENT_ID
export CF_ACCESS_CLIENT_SECRET
npm run canary:live -- --config /absolute/path/to/live-portal-canary.json
```

The runner reads no other credential input. It sends those two values only as
the Cloudflare Access service-token headers to the exact configured origin,
uses no cookie or MCP session, and rejects redirects. Provider credentials are
not part of this flow. Each request has a seven-second timeout; the complete run
has a twenty-second deadline. Configuration, individual responses, aggregate
responses, the canonical health value, result depth, and the Portal tool count
all have fixed local bounds.

Standard output is exactly one small JSON record. It contains only a status,
fixed code, timestamps, and phase latencies; it never contains the URL, tool
identifier, Code Mode program, call arguments, response, credential, email, or
exception text. A successful shape is:

```json
{"schemaVersion":1,"status":"passed","code":"ok","startedAt":"2026-08-29T00:00:00.000Z","finishedAt":"2026-08-29T00:00:01.000Z","latenciesMs":{"total":1000,"list_tools":100,"search":300,"execute":600}}
```

Any non-`ok` fixed code exits nonzero. Send this content-free record only to a
customer-owned monitoring sink.

One run should verify:

1. Portal authentication succeeds for the canary identity.
2. Code Mode advertises `portal_codemode_search` and
   `portal_codemode_execute`, plus only the reviewed Portal-native management
   tools, with no upstream tool exposed directly.
3. Search finds the dedicated health tool by its exact sanitized identifier.
4. Execute returns the fixed synthetic response whose canonical digest matches
   the configured SHA-256.
5. Portal logs contain the expected identity, source, tool, success, and
   duration fields.
6. The result is exported only to the customer's monitoring sink.

Store only the runner's bounded JSON record. Do not store tool arguments,
results, tokens, cookies, raw provider errors, user emails, customer data, or
source credentials in the dashboard canary record. A failure should alert the
customer; it must not send telemetry to Ankka.

Canary execution stays read-only. Update and rollback drills remain separate,
explicitly approved lifecycle operations.

## Cloudflare reference

Cloudflare owns the Portal source-visibility and Access-selector behavior
assumed by this roadmap. Revalidate it before each live qualification:

- [MCP server portals](https://developers.cloudflare.com/cloudflare-one/access-controls/ai-controls/mcp-portals/)

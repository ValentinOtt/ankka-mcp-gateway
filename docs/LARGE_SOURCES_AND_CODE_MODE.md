# Large sources and Code Mode

Ankka MCP Gateway treats one source with 228 exact tools as an intended local
configuration and planning scale. The checked-in
[`large-source` fixture](../fixtures/large-source/README.md) keeps that boundary
public and reproducible. It is not a claim about an untested Cloudflare account,
upstream server, MCP client, or model.

The same focused test derives a secret-free 224-tool workload from that fixture
to mirror the current first-party dogfood cardinality. This supplemental case
does not rename or silently replace the original 228-operation brief baseline.
Both cardinalities must continue to pass.

The repository accepts at most 500 enabled tools per source across its public
configuration, installer, management runtime, cleanup runtime, and dashboard
contracts. This is an explicit local resource bound, not evidence that
Cloudflare accepts a 500-tool server or mapping.

The management runtime also limits the complete persisted source-state record
to 1 MiB of canonical UTF-8 JSON. One 500-tool source with maximum-length names
fits this aggregate bound. Multiple large sources can reach the byte bound
before the separate 32-source count bound; a draft that would cross it is
rejected before the Durable Object write. Draft admission measures the
worst-case all-installed state at the maximum revision width, reserving the
bytes needed for later lifecycle transitions. This keeps source state
comfortably below Cloudflare's
[2 MB key-and-value limit](https://developers.cloudflare.com/durable-objects/platform/limits/)
for SQLite-backed Durable Object storage.

## What is verified in this repository

The fixture pairs an OpenAPI 3.1 document containing 228 synthetic GET
operations with a one-source gateway config containing the 228 operation IDs.
It sets Code Mode to `default_on` and contains no credentials or customer data.
The focused scale test verifies that:

- all operations have summaries and descriptions and deterministically extract
  to the exact allowlist;
- the JSON Schema and TypeScript validator accept all 228 exact names;
- validation stays within a five-second process-CPU regression guard for 100
  in-process validations;
- five offline plans stay within a five-second process-CPU regression guard and
  are structurally identical with stable hashes;
- the MCP server policy and Portal mapping contain the same sorted 228 names;
- changing one allowlist entry changes the desired-state and plan hashes and
  only the expected names; and
- the human plan remains a short resource-level summary instead of printing a
  228-line wall.

It repeats the validation, CPU guard, deterministic planning, source-policy,
Portal-mapping, installer-selection, dashboard-review, and removal-authority
assertions at exactly 224 names. A separate checked-in
sanitization-hostile configuration includes leading-digit and reserved-word
names plus three distinct hyphen/dot/underscore spellings that can collapse to
one JavaScript-shaped identifier. The test proves the gateway never rewrites
those upstream names; their live Code Mode behavior remains a qualification
question.

Run it with:

```sh
node --test test/large-source-scale.test.mjs
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

The five-second process-CPU checks are deliberately loose regression tripwires,
not latency service-level objectives. CPU time avoids false failures when the
test runner executes many files concurrently. These checks characterize only
local validation and pure offline planning. They do not include scheduling,
network, provider, source-discovery, dashboard, or model latency.

### Review shape

The configuration file is the exact allowlist review artifact. Keep generated
names sorted and one per line so an endpoint addition or removal appears as a
small Git diff. The default human plan identifies affected resources and hashes
without repeating the full list. `plan --json` retains the full desired arrays
for machines, so it is intentionally larger and should not replace the config
diff during human review.

The focused root test proves the configuration and planning path at 228 and
224 tools. Separate synthetic tests exercise the customer Worker discovering
the fixture's 228
read-shaped tools alongside one unselected destructive tool over ten 25-tool
MCP pages, persisting the exact 228-name draft, recovering an ambiguous
provider create, applying the same provider mapping, and completing
receipt-bound teardown. The same test accepts and saves exactly 500
maximum-length tool names over twenty 25-tool pages. The dashboard test
exercises filtering, select-shown, clear-shown, bulk selection, and draft save
at both 228 and 224 tools; installed lists remain collapsed behind an exact-tool
count. A platform-shaped storage test accepts a
draft whose worst-case installed projection is exactly 1 MiB, rejects a
one-byte-larger projection before `put`, and proves the unconstrained 32-source
maximum would exceed Cloudflare storage's 2 MB entry limit.

Discovery has three independent local resource bounds: at most 500 tools,
twenty `tools/list` pages, and 4 MiB per MCP response. One inspection or
reverification also has an 8 MiB aggregate response budget and a 30-second
wall-clock deadline; each individual request is limited to eight seconds,
including body consumption. Twenty pages admit the full tool-count ceiling
when an upstream returns at least 25 tools per page. A source with fewer than
500 tools can still be rejected if it spreads them over more than twenty pages,
exceeds either response-size bound, or misses a deadline. These local tests use
a deterministic provider simulator. They still do not prove live Cloudflare
acceptance, client behavior, or model performance.

## What Cloudflare Code Mode does

The gateway does not generate a code API. It sends the configured policy as
Cloudflare's `code_mode` Portal field. Cloudflare currently documents four
policies: `off`, `opt_in`, `default_on`, and `enforced`.

When Code Mode is active, Cloudflare documents two model-facing tools:
`portal_codemode_search` and `portal_codemode_execute`. Search runs JavaScript
against `codemode.tools()` to discover upstream definitions; execute runs
JavaScript against a `codemode` proxy whose properties call upstream tools.
This means a model need not receive all 228 upstream definitions in its initial
tool list.

Cloudflare's Portal documentation says context usage stays fixed as tools are
added, but it does not publish an exact token count for a 228-tool Portal. This
repository therefore does **not** claim that the overhead is approximately
1,000 tokens. Token use depends on the Portal response, client serialization,
model tokenizer, search results, and conversation. Measure it in each target
client before adopting a token budget.

Cloudflare separately describes roughly 1,000 tokens of Code Mode context for
its own MCP server exposing 2,594 tools. That vendor example is useful context,
not a transferable measurement for this gateway, its 228-tool fixture, or a
particular client.

### Names, descriptions, and schemas

`enabledTools` contains exact upstream MCP tool names. It is an authorization
selection, not a generated JavaScript API. Cloudflare documents the ordinary
Portal namespace as `{server_id}_{tool_name}` and Code Mode search results as
sanitized JavaScript identifiers. Its sanitizer replaces characters such as
hyphens and dots with underscores; other leading, reserved-word, and collision
cases can also affect the identifier.

Do not guess a callable name from the config. Query `codemode.tools()` and use
the returned identifier. Prefer stable, unique upstream names that are already
valid JavaScript-style identifiers, and include sanitization-collision cases in
the live canary. The Cloudflare Portal documentation does not specify Portal
collision behavior closely enough for this repository to promise it.

Without an alias, Cloudflare uses the upstream name and description. Portal-
level aliases and descriptions take precedence over server-level values, which
in turn take precedence over the upstream metadata. The current gateway config
selects exact names but does not declare aliases or description overrides.
Consequently, upstream operation IDs, summaries, descriptions, and input
schemas must be clear and stable: Code Mode search is only as useful as the
metadata it searches and returns.

## Choosing `default_on` or `enforced`

For a first large-source deployment, prefer `default_on`. Code Mode is active
without a special URL, while a client that already implements its own code
execution can opt out with `?codemode=off` and avoid nested execution.

Use `enforced` only after every supported client has been qualified and the
customer intentionally wants to prohibit direct-tool sessions. Enforced mode
ignores client overrides. `opt_in` is useful during a staged migration;
`off` exposes the ordinary tool surface and removes the large-catalog benefit.

Code Mode changes presentation and orchestration, not authorization. Exact
Portal allowlists and upstream read-only enforcement remain required.

## Live qualification for 228 and 224 tools

Before calling the scale supported end to end, use a synthetic or independently
approved read-only source and record at least:

1. In Cloudflare AI Controls, the authenticated source reports **Ready** and
   its synchronized `tools/list` names and count equal the exact reviewed
   config set. A mismatch or duplicate is a stop condition.
2. Provider create/update/read-back succeeds with exactly the expected 228 or
   224 enabled tools.
3. Source discovery, dashboard search/review, draft save, apply, and recovery
   all preserve the same sorted names.
4. A Portal session with `?codemode=off` exposes the expected direct-tool
   surface. Its exact names and count match the reviewed config, one allowed
   read succeeds, and an unlisted operation is absent.
5. In that direct-tool session, the synthetic health tool separately returns
   its reviewed small fixed value.
6. A session without `?codemode=off` passes the Code Mode search/execute canary
   against that same health tool. It advertises the documented Code Mode tools
   rather than all upstream definitions.
7. Search finds tools at the beginning, middle, and end of the catalogue and
   returns their effective descriptions and input schemas.
8. Execute successfully calls those synthetic read-only tools, including
   parallel calls where the client supports them.
9. Sanitization and cross-source name-collision cases behave as expected.
10. Client-reported input tokens and end-to-end latency are captured for an
   empty/baseline Portal and each qualified large Portal over repeated fresh
   sessions.

For a public source, the content-free raw-source verifier may additionally
prove the complete paginated `tools/list` before install:

   ```sh
   node tools/verify-live-source-catalogue.mjs \
     --config <outside-repository-dir>/gateway.config.json \
     --source <source-id>
   ```

For an OAuth source, the verifier's raw-token path is optional and may be used
only when an approved customer-owned client already supplies a bounded operator
OAuth access token:

```sh
<approved-customer-oauth-token-source> | \
  node tools/verify-live-source-catalogue.mjs \
    --config <outside-repository-dir>/gateway.config.json \
    --source <oauth-source-id> \
    --oauth-token-stdin
```

Do not loosen dynamic client registration, extract or reuse Portal-stored
credentials, or imply that the repository provides a standard token-minting
path. The verifier rejects pagination loops, oversized responses, redirects,
and catalogue mismatches. Success prints only exact counts and SHA-256 digests,
never a URL, token, or tool name.

As of 2026-08-29, Cloudflare publicly documents a limit of 40 MCP servers per
Portal but does not document a tools-per-server or enabled-tools-per-mapping
ceiling. Absence of a documented limit is not confirmation that 228 or 224
works; provider read-back and a live canary are the acceptance evidence.

## External behavior references

Cloudflare owns the runtime behavior described above; verify these pages again
when qualifying a release:

- [MCP server portals](https://developers.cloudflare.com/cloudflare-one/access-controls/ai-controls/mcp-portals/)
- [Code Mode](https://developers.cloudflare.com/agents/tools/codemode/)
- [Use MCP tools with Code Mode](https://developers.cloudflare.com/agents/tools/codemode/mcp/)
- [Cloudflare's own MCP servers](https://developers.cloudflare.com/agents/model-context-protocol/cloudflare/servers-for-cloudflare/)

The repository tests do not fetch or pin those pages.

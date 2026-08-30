# Portal audit logging in your account

<a id="customer-owned-portal-audit-logging"></a>

This is optional reference material, not a founding-team deployment gate. The
initial BLS deployment relies on Cloudflare Access, a shared `readonly` origin
credential, and content-free source logs. It does not require Enterprise
Logpush, exact Portal-user-to-BLS correlation, or new audit infrastructure.

Cloudflare's account-scoped `mcp_portal_logs` Logpush dataset is the current
source of per-user MCP Portal audit events. It is configured and retained by
your team. Ankka MCP Gateway does not receive a copy and the gateway
runtime sends no telemetry to Ankka.

> **Availability:** Cloudflare currently documents MCP Portal Logpush as an
> Enterprise-plan feature. Confirm dataset and field availability in the
> target account before making it an audit control.

## What the portal can attribute

Cloudflare documents these useful fields:

| Purpose | Fields |
| --- | --- |
| Time and route | `Datetime`, `PortalID`, `PortalAUD`, `ServerID`, `ServerAUD` |
| Actor | `UserID`, `UserEmail` |
| Operation | `Method`, `ToolCallName` |
| Outcome | `Success`, `ServerResponseDurationMs` |
| Session | `SessionID` |

Cloudflare documents enough fields for portal-level actor/tool attribution in
principle: who used which Portal tool, against which source, at what time, and
whether the Portal observed success. Qualify the actual fields and values in
the target account before relying on them. This remains useful when the
upstream MCP source uses one operator-owned, least-privilege shared service
credential, because Portal authentication and upstream authentication are
separate layers.

The current dashboard source workflow supports public MCP endpoints and
standard OAuth-protected endpoints. It fixes **Require user auth** off: one
gateway operator connects the source and Cloudflare Portal stores that source
credential; team members still authenticate individually to the Portal. The
dashboard does not accept a bearer token or custom headers. For a source Worker
that calls a private origin with a separate shared credential, keep that
credential in the source Worker's operator-owned secret binding and make the
source independently enforce its read-only operation boundary. Never put the
origin credential in gateway configuration, a URL, a tool result, or an
Ankka-hosted request.

## Minimal source-Worker record without Portal Logpush

When `mcp_portal_logs` is unavailable on your Cloudflare plan, a
self-hosted source Worker can emit content-free operation evidence to its
own Workers log destination. This is a source outcome record, not a substitute
for Portal actor attribution. Its exact JSON payload has five keys:

```json
{
  "schemaVersion": 1,
  "event": "source_tool_call",
  "tool": "synthetic_read_status",
  "outcome": "succeeded",
  "durationMs": 17
}
```

The closed contract is:

| Field | Exact rule |
| --- | --- |
| `schemaVersion` | Integer literal `1` |
| `event` | String literal `source_tool_call` |
| `tool` | An exact statically allowlisted MCP tool name, or JSON `null` when an unlisted name is rejected; never log attacker-supplied text |
| `outcome` | One of `succeeded`, `failed`, or `rejected` |
| `durationMs` | Integer from `0` through `30000`, measured in the Worker and clamped before logging |

Use the platform log envelope's server-authored timestamp and Worker identity;
do not add them from a request. Reject extra keys. Emit one record only after
the Worker has classified the request against its static read-only allowlist,
and derive `outcome` from the response path without copying an exception.
Unknown tool names use `tool: null`, so untrusted input never becomes log text.

The record must never contain arguments, results, response bodies, free-form
errors, URLs, headers, cookies, tokens, credentials, IP addresses, user-agent
text, email, user ID, Access identity, session ID, or a client-supplied request
or correlation identifier. Configure retention and any export entirely in the
your Cloudflare account and confirm Workers log availability for that
plan. Ankka receives no copy.

This source record can prove that one allowlisted operation reached the source
Worker and how that Worker classified it. It cannot say which Portal user made
the call, and timestamp/tool/duration matching to a separate Portal event
remains heuristic. Do not present it as exact end-to-end attribution.

## Minimal export profile

Create an account-scoped Logpush job for `mcp_portal_logs` to a
operator-controlled destination. Start with only:

```text
Datetime,PortalID,PortalAUD,ServerID,ServerAUD,Method,ToolCallName,
UserID,UserEmail,Success,ServerResponseDurationMs,SessionID
```

The destination credentials belong in Cloudflare's Logpush configuration, not
this repository or the gateway runtime. Restrict sink access, define retention,
and treat `UserID` and `UserEmail` as personal data.

Do not export these fields by default:

- `ClientIP` and `ClientCountry`, unless a documented security purpose and
  retention policy require them;
- `Error`, because it may contain free-form upstream detail;
- `ServerURL`, if the source location is sensitive; and
- `ResourceReadURI` or `PromptGetName`, unless that content is independently
  reviewed for the audit sink.

Never add MCP arguments, results, authorization headers, cookies, source
credentials, or raw provider responses to this dataset in a downstream
pipeline. Prefer opaque provider IDs as labels; keep email as an inspected
field rather than a high-cardinality metrics label.

For Loki/Grafana, preserve the original event timestamp and derive only bounded
labels such as Portal, source, JSON-RPC method, success, and tool name. Keep the
actor in the structured log record. Alert on sustained failures, unexpected
tool names, and missing expected canary calls without copying request or result
content into an alert.

## End-to-end correlation gap

The published `mcp_portal_logs` field set has no request identifier documented
as being forwarded to the upstream MCP server. `SessionID` identifies a
stateful MCP session; it is not documented as an upstream request header and
may be absent for stateless protocol requests. The gateway also does not proxy
ordinary MCP traffic, so its gateway Worker cannot inject a correlation
header.

Consequently, joining a Portal event to one exact upstream request by timestamp,
tool name, or duration is diagnostic evidence, not an auditable one-to-one
join. Do not claim exact end-to-end attribution from that heuristic.

Close this gap only after a live, documented provider contract supplies a
shared request identifier, or after a separately reviewed source protocol
carries a cryptographically authenticated actor/request assertion. An arbitrary
client-supplied identity or correlation header is not trustworthy. Any future
identifier must stay operator-owned, contain no credential or request content,
and appear in both Portal and source logs without transiting Ankka.

## Qualification checklist

Before relying on the export:

1. Verify the Logpush job targets only your team's sink and selects the
   reviewed fields.
2. Call a synthetic read-only tool as two test identities and confirm the
   Portal records distinguish them.
3. Confirm failure events contain no argument, result, token, or raw upstream
   response.
4. Verify retention, access controls, deletion, and alert redaction in the
   destination.
5. Record the exact Cloudflare field contract and plan availability used by
   the deployment.
6. Treat upstream correlation as unavailable until the same provider-generated
   identifier is observed and documented at both layers.

## Cloudflare references

- [MCP Portal Logs field reference](https://developers.cloudflare.com/logs/logpush/logpush-job/datasets/account/mcp_portal_logs/)
- [Logpush API configuration](https://developers.cloudflare.com/logs/logpush/logpush-job/api-configuration/)
- [MCP server portals](https://developers.cloudflare.com/cloudflare-one/access-controls/ai-controls/mcp-portals/)

These pages describe Cloudflare-owned behavior and are not pinned by repository
tests. Revalidate them during live qualification.

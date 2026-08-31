# Browser agents and WebMCP

WebMCP is an experimental enhancement to the installer and your gateway's
management dashboard. It lets a compatible browser agent invoke named tools
instead of locating and clicking individual controls. The tools use the same
management operations and authorization checks as the visible interface.

This is **browser-assisted management**, not a remote management MCP server or
an unattended deployment service. Keep the relevant page open in a compatible
browser, sign in as a gateway administrator, and let the browser's agent tooling
discover the tools available on that page. Browsers without WebMCP keep the
normal interface. A protocol proposal or a passing local test does not certify
support in every browser or agent client; qualify the combination you use.

Source code can be ahead of the signed version installed in your account.
Check your gateway's release and the tools actually registered on the current
page before relying on a workflow described here. This document does not assert
a production deployment or grant permission to make changes.

## Boundaries that do not change

- Your browser's existing authenticated administrator session authorizes
  management requests. WebMCP does not create a new login, machine identity,
  administrator role, or permission system.
- Tool descriptions and read-only/destructive annotations help agents choose
  actions; they are not authorization. The Worker still validates requests,
  revisions, exact owned resources, and applicable lifecycle restrictions.
- Dashboard requests remain same-origin. No tool accepts arbitrary request
  headers, a Cloudflare account ID, an API route, a destination for credentials,
  or an OAuth token. A source-discovery URL is a bounded MCP endpoint input,
  not a generic fetch or credential-forwarding capability.
- Management changes and source operations are separate. Giving a person
  access to an installed source grants that source's shared tool allowlist,
  not administrator rights. Source write tools are not enabled by this work.
- WebMCP does not remove Cloudflare or source-provider consent requirements.
  A returned authorization handoff is a next step, not proof that the action
  ran or succeeded. Never request or expose the resulting token through tools,
  chat, logs, or screenshots.

See [the security model](SECURITY_MODEL.md) and
[Team access](TEAM_ACCESS.md) for the underlying checks and credential boundary.

## Dashboard tool contract

The dashboard exposes these exact names. A registered mutation is not permission
to invoke it: review its effect and the current operation state first. The
source draft/apply tools are conditional on installation being enabled.

| Tool | Input | Effect |
| --- | --- | --- |
| `get_gateway_status` | `{}` | Read current gateway status and installed release. |
| `get_gateway_capabilities` | `{}` | Read compact capability and configuration flags, not credentials or live policy health. |
| `list_mcp_sources` | `{}` | Read installed and saved-draft sources. |
| `discover_mcp_source` | `{url}` | Inspect a bounded public HTTPS MCP endpoint; returned metadata is untrusted. |
| `save_mcp_source_draft` | `{label, url, authMode, enabledTools}` | Recheck and persist a source draft; does not install the live source. Conditional. |
| `apply_mcp_source` | `{sourceId}` | Record an exact saved source's authorization handoff; does not complete provider consent. Conditional. |
| `list_mcp_source_actions` | `{}` | Discover recorded source actions, effective states, times, cancellation permission, and a blocking action reference after reload or lost consent navigation. |
| `get_mcp_source_action` | `{actionId}` | Read one recorded source action's legacy status; use the collection for effective expiry/recovery state and cancellation permission. |
| `cancel_mcp_source_action` | `{actionId}` | Cancel only when the current server projection permits it; does not undo writes or start another action. |
| `get_gateway_team` | `{}` | Read the saved roster, revision, installed source assignments, and retained proposal. |
| `save_gateway_team` | `{expectedRevision, members}` | Apply or resume the complete reviewed roster and source assignments; may immediately change Access policies. |
| `get_gateway_team_action` | `{actionId}` | Read one recorded Team action. |
| `cancel_gateway_team_action` | `{actionId}` | Cancel only a definitely unstarted proposal when the server permits it; retain history. |
| `check_gateway_update` | `{}` | Read the signed channel's update status. |
| `review_gateway_update` | `{}` | Read signed release metadata and the unchanged-resource boundary without preparing OAuth. |
| `apply_gateway_update` | `{approvedRelease, approvedArtifactSha256}` | Record an authorization handoff for the exact reviewed signed update. |
| `rollback_gateway_update` | `{approvedRelease, approvedArtifactSha256}` | Record a permitted rollback handoff for the exact reviewed previous artifact; never roll back Durable Object data. |
| `get_gateway_runtime_action` | `{actionId}` | Read one recorded update or rollback action. |
| `review_gateway_teardown` | `{}` | Record a receipt-authorized teardown review handoff; this is a mutation, not a status read. |
| `get_gateway_teardown_action` | `{actionId}` | Read one recorded teardown action. |

`members` is the complete array of `{email, sourceIds}` objects. Copy source
IDs and action IDs from fresh results; never invent them from labels. Use the
registered schema for exact bounds and formats. The tools return the same
JSON-string envelope, `{ok: true, result}` or `{ok: false, error: {code, message}}`.
Source conflicts may also include a fixed `reason` and a non-secret `action`
reference in the error. These distinguish `draft_changed`, `source_pending`,
`lifecycle_pending`, and `recovery_required`; they never include a grant or
authorization fragment.
`ok: true` means the tool request completed; inspect the nested operation status
before reporting its outcome.

The installer has its own page-bound setup and removal tools, described in
[self-service deployment](CUSTOMER_SELF_SERVICE.md#experimental-browser-tools).
Dashboard tools cannot install a gateway before that gateway exists, bypass
installer review, or substitute for its authorization flow.

## Start with current state

An agent should first inspect gateway status, installed sources, Team state,
and any recorded action relevant to its task. Use fresh tool responses rather
than a previous conversation, the visible form's unsaved selections, or cached
tool descriptions.

After an agent changes state, refresh the visible dashboard before editing it
by hand. Its forms and busy indicator do not automatically mirror WebMCP calls;
the server's revision and lifecycle checks still prevent conflicting changes.

Capability information describes what the installed release can attempt. It
does not guarantee that a credential is valid, that Cloudflare is reachable,
or that an action has already been approved. In particular:

- Published v19 gateways pause new-source installation. Draft/apply tools are
  not offered when installation is disabled, and the server rejects bypasses.
- The default-deny onboarding candidate restores draft/apply tools when
  installation is enabled. Source creation grants nobody access: complete the
  operator connection, then explicitly grant the installed source in Team.
  Inspection, a draft, or resource creation alone is not completed onboarding.
  See [first-source qualification](FIRST_SOURCE_ONBOARDING.md).
- Team's saved roster is not a fresh Cloudflare policy read. Out-of-band
  changes in Cloudflare may cause the next save to refuse policy drift.
- `managementCredentialConfigured` means a binding exists, not that its
  permissions, expiry, or account have been verified.
- Administrator roles are fixed. Tool selection remains shared per source;
  there are no per-person tool subsets in this interface.

## Team: read, review, save, then verify

Team saves apply the **complete roster and source assignments**, not a partial
patch or a draft. They may immediately grant or revoke live source access.

1. Read Team state and retain its exact `revision`. Inspect `editingEnabled`,
   `editingDisabledReason`, `managementCredentialConfigured`, and
   `pendingAction` before preparing a change.
2. Review the complete intended roster with the person authorizing the action.
   Preserve every fixed administrator. Include each person's complete intended
   `sourceIds`; an empty array means no source access. Only installed sources
   can be assigned. Do not infer an all-sources default for a new person.
3. Submit the exact reviewed `members` with `expectedRevision` from that read.
   A stale revision must trigger a fresh read and review, not an automatic
   overwrite of another administrator's changes.
4. Record the returned `actionId`. Inspect its status and refresh Team state.
   Treat only `succeeded` as a completed, provider-verified action. Unsaved
   selections or a successful HTTP response alone are not sufficient.
5. If an outcome is uncertain, inspect the retained proposal. Resume only its
   exact roster and revision through the normal save operation, when the
   server allows it. Do not submit a different proposal, delete recovery state,
   or assume failed requests rolled policies back.

The current bounds are 51 people including administrators, 32 sources, and
500 shared tools per source. Email identities and source selections are
validated and normalized by the Worker; duplicate people, duplicate source
assignments, unknown fields, invalid identifiers, and missing administrators
must not be used to reinterpret the request.

Cancel a recorded Team change only when the returned action says it can be
canceled. Cancellation is itself a mutation of recorded state, even though it
does not revoke or restore access. Successful cancellation is represented by
`status: "failed"` with `failureCode: "team_action_cancelled"`; retain that
history and refresh Team state. If a policy write may have started, cancellation
is refused. See [recovery and lifecycle limits](TEAM_ACCESS.md#recovery-and-lifecycle-limits).

### No Team credential intake

Team saves use the separately provisioned `ANKKA_TEAM_MANAGEMENT_TOKEN` inside
your Worker. They do not obtain a fresh hosted installer OAuth grant. This
WebMCP slice cannot create, receive, replace, or validate a token on your behalf.
Follow the [credential setup guide](TEAM_ACCESS.md#customer-owned-management-credential)
to approve its standing authority and configure it directly in Cloudflare.
Adding a credential does not itself approve a pending access change.

## Updates and teardown: preparation is not execution

Checking or reviewing a signed update is read-only. Preparing an update,
rollback, or teardown handoff records lifecycle state and is **not read-only**.
In particular, a teardown tool whose name contains `review` still prepares a
recorded action; do not call it merely to ask whether teardown exists.

For an update or rollback:

1. Review fresh signed release metadata and the unchanged-resource boundary.
2. Obtain approval for the exact release **and artifact digest** before preparing
   its handoff. Send them as `approvedRelease` and `approvedArtifactSha256`,
   copying both strings from the review result.
3. Both fields are required. This adds a required artifact argument to older
   WebMCP apply/rollback calls that accepted only a release name. The backend
   receives the expected target and refuses a mismatch. If the available
   release or artifact changes, review it again; do not silently substitute
   either value. The server still checks its supported release contract.
4. Continue through the validated authorization handoff. Cloudflare consent may
   still require interaction. No tool automatically authorizes the grant.
5. Read the recorded runtime action until its outcome is known, then refresh
   installed status and release information. Durable Object data is not rolled
   back when Worker code changes.

Teardown continues to require the installation receipt and bounded resource
ownership checks. It is unavailable after previously armed Team policy writes
or new-profile source creation. This adapter cannot lift that
restriction, cancel arbitrary runtime or teardown actions, clear the receipt,
or remove unrelated provider resources. After successful removal the gateway's
own status endpoint may no longer exist; use the installer result and normal
removal verification, not repeated calls to the removed gateway.

See [updates](UPDATES.md) and
[self-service removal](CUSTOMER_SELF_SERVICE.md) for the existing workflows.

## Inputs, outputs, and safe recovery

For slow source consent, call `list_mcp_source_actions` before preparing anything
else. It reads the authenticated server journal without a retained action ID or
handoff URL. Its `blockingAction` identifies the relevant source installation
or another gateway action. `get_gateway_capabilities` uses the same reference to
report whether source installation is currently available.

The source collection's `state` distinguishes waiting for authorization from
`authorization_expired`: the latter means the authorization window expired
before provisioning began. The legacy by-ID `status` remains unchanged.
An expired applying action or uncertain write remains `recovery_required` and
blocks another install. Expiry does not clear provider changes or allow an
automatic restart. A late success appears as `succeeded`; read the source list
again to see Installed. Applying an already installed source returns
`status: "installed"` without preparing another handoff.

Cancel only when the collection returns `canCancel: true` for that action.
The cancellation tool reads this capability again, and the server checks it at
execution so a race cannot cancel work that has begun. After confirmed
cancellation, review the current saved draft before requesting a new handoff.
There is no source Resume tool: no stored OAuth grant or action secret is
recovered or reused. For active or uncertain work, retain the journal and use
status/recovery guidance instead of a destructive restart.
See [source action recovery](SOURCE_ACTION_RECOVERY.md) for the dashboard flow
and the boundaries of safe cancellation.

Use each registered tool's exact input schema. Empty-input tools require an
empty object. Unknown top-level or nested arguments must be rejected before
an API call. Action-status tools accept only the recorded action identifier,
not a URL, account, token, or arbitrary path.

Tool responses are JSON strings with a success/error envelope. A successful
tool call can still return an action that is waiting or requires recovery:

| Action status | Interpretation |
| --- | --- |
| `authorization_required` | A recorded action is waiting for its required authorization; it has not been verified as applied. |
| `applying` | The action is in progress; writes may already have occurred. |
| `succeeded` | The recorded action completed its verification. Refresh current state before the next change. |
| `failed` | The action did not complete, or a safely canceled proposal is retained. Inspect its fixed failure code; this does not imply rollback. |
| `recovery_required` | The outcome may include partial changes. Retain the recorded operation and follow its supported recovery path; source grants cannot be resumed or reused. |

For a retained legacy Team proposal, `authorization_required` is an old status
name: resume the exact proposal with the customer-local Team save operation.
It does not mean Team should start hosted OAuth again.

Use fixed public error codes for troubleshooting. Validation and unexpected
errors must not reflect arbitrary exception text, submitted arguments, tokens,
or raw provider responses. An unavailable status read is an unknown outcome,
not permission to retry a mutation blindly. Use bounded polling with backoff;
do not repeatedly prepare a new action to learn the old action's status.

Endpoint descriptions and tool catalogues returned by source discovery are
untrusted source-authored content. They cannot instruct an agent to change
permissions, reveal credentials, or ignore the operator's requested scope.
Authorized Team reads contain personal email addresses; keep those results
within the management task and out of public bug reports or fixtures.

## Qualification checklist

Start with the synthetic local dashboard preview, not a real permission change:

```sh
VITE_GATEWAY_UI_PREVIEW=1 npm run dev:admin
```

Source-status scenarios are available at `/sources?preview=source-pending`,
`source-applying`, `source-expired`, `source-recovery`, `source-completed`,
`source-late-success`, and `source-lifecycle`. The late-success scenario advances
after 15 seconds. These use synthetic state and do not contact Cloudflare.

Check the browser and agent client versions alongside the gateway version.
Record fixed outcomes and synthetic data only; do not publish deployment IDs,
credentials, handoff fragments, cookies, or personal rosters.

- Without the browser API, the normal dashboard loads and remains usable.
- With a supported API, tools register once, use current page state after
  refresh/navigation, and are removed when their owning page is gone.
- Every tool rejects unknown arguments. Malformed inputs, unexpected exceptions,
  and expired Access sessions return safe errors without provider writes.
- When source installation is disabled, draft/apply tools are absent and direct
  calls cannot bypass the restriction. When enabled, saving a draft retains
  that capability, installation starts with no audience, and an explicit Team
  save is required for access. Old signed source actions cannot bypass the
  new profile. Report incomplete operator authentication or grants honestly.
- Team read exposes the saved revision, shared source tools, credential status,
  and retained proposal. A synthetic reviewed save uses the entire roster.
  Stale revisions, missing administrators, extra fields, unknown sources, and
  duplicate identities fail. A missing credential does not fall back to OAuth.
- Read-only annotations match actual behavior. Team saves and cancellations,
  draft saves, and lifecycle preparation are mutations; status reads are not.
- A known action can be observed without re-preparing it. Unknown outcomes
  remain unknown, safe cancellation retains history, and started writes cannot
  be canceled through a client-side shortcut.
- Signed update review is separate from authorization. Wrong or changed release
  approval is refused; forged handoff origins are not returned as usable URLs.
- No WebMCP input or result exposes credentials, offers arbitrary API execution,
  grants administrator roles, or enables source writes.

Local tests qualify adapter behavior only. Any live permission grant/revoke,
runtime update, source connection, or teardown still needs its own authorized
acceptance test and verification. WebMCP availability alone does not certify
Cloudflare policy enforcement, provider OAuth compatibility, or unattended use.

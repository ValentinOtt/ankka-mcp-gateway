# Default-deny source onboarding: release qualification

Status: candidate design and acceptance checklist, not a deployment claim.
The published native-permissions preview pauses source installation. Restoring
the workflow requires the implementation and live checks below; changing a
client-side capability flag alone is not sufficient.

## Intended workflow

1. Install an empty gateway and sign in as its administrator.
2. In Sources, discover one supported HTTPS MCP endpoint and review its exact
   read-only tool selection. Save the secret-free draft.
3. Review and authorize that draft's source installation. The gateway asks
   Cloudflare directly for a short-lived grant limited to Access applications
   and MCP portals, creates the exact source resources with it, and revokes
   it. It is not an upstream credential and is not retained for Team
   management.
4. The new source starts with a single deny-Everyone Access policy. Creating
   it grants nobody access, including administrators and existing team members.
   If Cloudflare has not synced its tools, installation pauses before attaching
   the source to the Portal and shows the next connection step.
5. Connect the upstream once through Cloudflare's operator authentication flow.
   Keep Require user auth off. Source credentials stay in your Cloudflare
   account; do not paste them into Ankka or the gateway dashboard.
   For upstreams with a redirect allowlist, configure the exact callback shown
   by Cloudflare in the upstream's OAuth settings. Once the server is Ready,
   return to Sources and renew consent. The gateway verifies the retained
   resources and exact tool catalogue before attaching the source to the Portal.
6. In Cloudflare, update the receipt-owned reusable Access policy to grant the
   installed source to the intended people. The gateway Team page is read-only
   in V1; do not create a standing API token to enable it.
7. Verify an allowed read through the Portal, and verify that a person without
   the source assignment cannot invoke its tools directly or through Code Mode.

Discovery, a saved draft, successful resource creation, upstream authentication,
and an effective Team grant are distinct outcomes. Do not report a usable source
until all applicable stages have been verified.

Tool names and annotations are not authorization boundaries. Before granting
access, independently confirm that the selected operations are read-safe and
the upstream credential cannot write. Shared-auth discovery may require the
operator connection before the actual catalogue can be compared with the
reviewed exact allowlist; an entered name is not proof that an operation is safe.

## Compatibility and lifecycle boundary

The candidate must preserve the original installation receipt and all existing
source assignments. It recognizes only the exact historical initial audience
and the new empty initial audience; it does not adopt arbitrary provider policy
changes. New sources must remain unassigned even when Team is first opened
after installation.

Previously prepared source actions do not acquire new authorization merely
because the runtime was upgraded. An old action with a pending or potentially
applied provider write must remain retained and blocked for reviewed recovery.
Do not erase its journal or replay its authorization URL.

The proposed conservative lifecycle safeguard disables automatic teardown and
blocks older-runtime rollback before the first new-source provider write may
start. Reading, discovering, saving a draft, and reviewing an action must not
set that restriction. This is a material release limitation requiring explicit
review before activation, not an assertion that resources were deleted or that
a failed installation rolled back. A later compatible teardown implementation
is a separate follow-up.

## Required local regression coverage

- The original receipt, existing source assignments, shared allowlists, and
  fixed administrator roles are preserved.
- A new source has exactly one deny-Everyone policy before Portal attachment;
  extra policies, unexpected selectors, or changed Portal mappings fail closed.
- Missing operator authentication, incomplete synchronization, or a missing
  selected tool pauses before Portal attachment. Fresh consent can resume the
  same receipts without recreating resources or granting access.
- A first Team read cannot grant a new source implicitly. A later explicit
  source grant uses the ordinary complete-roster revision check.
- Old source actions cannot enter the new execution path; pending and uncertain
  provider writes retain their recovery evidence.
- Failed or uncertain creation never claims rollback or broadens cleanup
  authority. The lifecycle floor is armed only at the mutation boundary.
- Ownership, installed-source state, and the completed action journal commit
  atomically. A storage failure before that commit or a lost response after it
  must not replay provider creation or leave an unrecoverable partial record.
- GET and successful PUT source responses report the same installation
  capability, so saving a draft does not hide Apply or unregister WebMCP tools.
- Dashboard, WebMCP, authenticated API, and direct Durable Object checks agree.
  No caller field or environment variable can select an older audience policy.
- Unknown tool arguments, stale revisions, unavailable Team editing, and
  malformed provider results fail with bounded messages and no secret or result
  logging.

## Required live acceptance

Use an explicitly approved disposable gateway/source and two selected test
identities. Local mocks are not proof of Cloudflare policy enforcement.

Verify empty-gateway onboarding, one-time shared upstream authentication while
the native source audience is empty, and then an explicit Team grant. If
Cloudflare's admin-connect flow cannot complete while the native source policy
denies everyone, stop: do not temporarily Allow everyone, enable per-user
upstream authentication, or claim the shared-auth workflow is qualified.

For the unassigned identity, test both exact tool invocation and Code Mode.
After revocation, check a fresh session and the already-connected session over
a bounded observation window; record the observed delay rather than promising
immediate revocation. Keep source results, identities, provider IDs, credentials,
and authorization URLs out of public evidence.

Only after these checks pass should entry-point documentation describe this
workflow as available in a signed release. See [Team access](TEAM_ACCESS.md),
[WebMCP](WEBMCP.md), and [self-service deployment](CUSTOMER_SELF_SERVICE.md).

# Live contract probe (retired)

This directory preserves the source and sanitized findings from the disposable
account probe used during early contract discovery. Its runner now fails before
reading credentials or making a network request.

The original runner combined exact reviewed executors with an account-wide
name/marker sweep. That sweep was not authorized by one immutable installation
receipt, so a mistaken target could remove another gateway. It is unsuitable
for publication as an executable operator workflow. Provider error bodies also
do not belong in shared output.

Use the approval-bound canary lifecycle or the reviewed hosted-installer
runbook for any new live exercise. Both bind mutation to an exact target,
reviewed plan, receipt, and recovery path. The sections below are historical,
identifier-free evidence only; they do not grant authority for another run.

## First green install — 2026-08-23

The pre-public `gateway-v0.1.0` candidate ran in a maintainer-controlled
disposable account and zone: 89 provider calls, 98s, `final_convergence`
verified. Live contract facts it found, in order:

| Assumed | Live |
| --- | --- |
| a Durable Object binding can ship in a new Worker's first version | the class must be provisioned by a prior deployment first (403) |
| version read-back returns `compatibility_flags`, `modules`, `assets`, `exports_reconciliation` | all omitted when empty or unreconciled; `modules` only with `?include=modules`; adds `env`, `source`, `urls` |
| Durable Object namespace list returns `total_pages` | omitted; page count derives from `total_count` |
| every provider id is 32-hex or a UUID | Worker custom-domain ids are 40 hex characters |
| a Worker verified after deployment has no `deployed_on` and no references | it has both; the terminal proof asserts the exact domain and namespace reference instead |
| 15s covers one bootstrap request | only a resumed no-op; a first convergence of seven resources needs far longer |
| a verified workers.dev subdomain serves immediately | the edge lags; an unsigned GET probe must confirm the route before the signed request is armed |
| `/workers/scripts` lists every Worker | a version-less Worker record appears only in `/workers/workers` |

## First green uninstall — 2026-08-23

The removal path had never executed live. Everything below was found by the
probe; none of it changed the payload, so the release candidate is unchanged.

| Assumed | Live |
| --- | --- |
| an Access policy reports its boolean flags | `approval_required`, `isolation_required`, and `purpose_justification_required` are omitted when false |
| an installed Worker's domain reference carries `certificate_id` and its `durable_objects` list is empty | no `certificate_id`; `durable_objects` carries the AdminState namespace |
| `/workers/workers` and `/workers/workers/{id}/versions` return `total_pages` | omitted, like the namespace list — the whole Workers list family omits it, while Access and DNS report it |
| a version annotation may carry any correlation tag | `workers/tag` is capped at 100 characters, and a 64-character digest spends most of it (10021) |
| an empty Custom Domains list reports the requested `per_page` | it reports `per_page: 0` |
| 15s covers the one-shot removal request | the cleanup Worker removes every gateway resource inside that one request; the contract has no retry, so the ceiling now matches the bootstrap submit |
| the armed timestamp can be read again when the journal transition is written | the journal requires the armed value's own timestamp; the wall clock advances while the provider prepares the arm. A fixed test clock hid this — both reads returned the same value |
| the customer cleanup Worker either removes everything or rejects the claim | it can stop mid-sequence with `uninstall_recovery_required`; the reviewed recovery path (new authority, resumed Durable Object state) then completes the removal from where it stopped |
| retiring a Durable Object export removes it from the version's export map | the export stays and is marked `state: 'deleted'` — a stronger retirement proof than absence |
| a version read-back always carries `bindings` | a version with no bindings omits the field entirely |
| a resumed run can re-assert every earlier stage | a deployment's activeness and an enabled workers.dev subdomain are both deliberately reversed by later stages; re-asserting them contradicts the journal |

Green single-session lifecycle: install 97s / 89 provider calls, removal 115s /
116 provider calls, `status: removed`, convergence
`sha256:2571f114…`, then `residue` reported 0 — including the Durable Object
namespace, which is retired with its Worker.

## Release gate P1C — closed 2026-08-24

One lifecycle carried all three of P1C's requirements: `install` on the exact
release bytes, then an employee authenticated through Access and called the
canary tool through the Portal under Code Mode — where it surfaces as
`mcp_<server-id>_<tool>`, not the bare name the source advertises — then
`uninstall` (117s / 116 provider calls, convergence `sha256:6962741f…`) and
`residue` 0, confirmed independently across Durable Object namespaces, Workers,
custom domains, Access applications, MCP servers, Portals and DNS.

The probe cannot close the rest: the hosted installer UI, the customer OAuth
consent, release signing and R2 publication are outside what it stands in for.
Activation stays `{enabled: false, pin: null}`.

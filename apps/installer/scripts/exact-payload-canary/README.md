# Exact-payload disposable-account canary (retired)

This directory preserves sanitized evidence from the one-off exact-payload
canary completed on 2026-08-23. Its runner now fails before reading credentials,
local configuration, or state and before making a network request.

The historical harness deployed the exact release-candidate primary, cleanup,
retirement, installer, and dashboard bytes into a maintainer-controlled
disposable Cloudflare account. It proved the seven-resource installation,
idempotent bootstrap, one authenticated employee tool call, receipt-owned
reverse cleanup, zero residue, Durable Object retirement, and final Worker
deletion.

That result is payload and provider-contract evidence. It did not prove the
hosted installer session, customer OAuth consent, release signing, R2
publication, or a production promotion.

## Why the executable is retired

The harness predated the final operator-safety boundary. Some Worker operations
were selected by editable local names and state rather than one immutable,
freshly verified installation receipt. It could also expose provider-derived
identifiers or bodies in local output. Those properties are unacceptable in a
public mutation tool even when documentation says to use a disposable account.

New live exercises use the approval-bound canary lifecycle or the reviewed
hosted-installer runbook. Those workflows bind mutation to an exact target,
reviewed plan, receipt, and recovery authority and expose only fixed,
value-free failures. See `docs/CLOUDFLARE_CANARY.md` for the sanitized lifecycle
record and remaining gates.

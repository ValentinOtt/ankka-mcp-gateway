# Hosted installer analytics

An active, maintainer-approved Ankka-hosted installer records a small product
funnel by default. The checked-in disabled and rollback builds have no analytics
binding and emit no events. Running this source yourself does not send events
to Ankka, and customer-deployed gateways never receive the binding.

The installer shows this notice:

> Ankka keeps fixed setup event, public release/channel, coarse outcome, and
> flow fields for three months in Cloudflare Analytics Engine—without user,
> session, or Cloudflare-account identifiers. Cloudflare separately processes
> hosted-zone reliability data. Customer gateways do not report usage to
> Ankka.

## Destination and retention

The hosted Worker writes directly to the Cloudflare Workers Analytics Engine
dataset `ankka_installer_funnel_v1` in Ankka's Cloudflare account. There is no
browser beacon or public ingestion endpoint, and Ankka does not export the
dataset to another analytics processor.

Cloudflare documents Analytics Engine retention as three months. See
[Analytics Engine limits](https://developers.cloudflare.com/analytics/analytics-engine/limits/).

Writes are best-effort and non-authoritative. A missing binding, invalid build
label, quota issue, or provider failure drops the event and cannot delay,
approve, retry, fail, or change a customer operation.

## Exact schema

Cloudflare supplies the timestamp. The Worker writes only:

| Column | Meaning | Allowed values |
| --- | --- | --- |
| `index1` | event | one event from the allowlist below |
| `blob1` | public signed release | `gateway-vX.Y.Z` |
| `blob2` | release channel | `canary` or `stable` |
| `blob3` | outcome | `none`, `succeeded`, `failed`, `denied`, or `existing_gateway` |
| `blob4` | flow | `none`, `fresh_install`, `same_session_removal`, or `returning_removal` |
| `double1` | count | exactly `1` |

Allowed events:

- `installer_session_created`
- `discovery_authorization_created`
- `discovery_completed`
- `configuration_saved`
- `install_plan_created`
- `install_authorization_created`
- `install_completed`
- `removal_plan_created`
- `removal_authorization_created`
- `removal_completed`

Events are emitted only by server-authoritative code after the corresponding
state transition. The browser cannot supply an event name or payload.

## Data that is not collected

The dataset has no field for:

- IP address, country, colo, user agent, or referrer;
- user, visitor, session, request, email, or customer identifier, including
  hashed identifiers;
- Cloudflare account, zone, hostname, gateway, installation, plan, or provider
  resource;
- URL, path, query, OAuth state, code, token, or other credential;
- duration, free-form error, or arbitrary property.

Rows are timestamped, so low-volume events may still correlate in time with
information held elsewhere. Ankka must not join the dataset to OAuth, support,
or infrastructure records to reconstruct an individual journey.

Counts are attempts and accepted milestones, not unique people. The data is not
used for billing, individual tracking, authorization, support decisions, or
security decisions.

## Network Error Logging

Cloudflare Network Error Logging (NEL) is separate from the product funnel.
NEL remains enabled for Ankka's hosted zone. Cloudflare adds `NEL` and
`Report-To` headers to browser responses, and browsers may send reports about
last-mile failures to Cloudflare. Application code does not set those headers
or receive the browser reports.

Cloudflare documents that reports can include request and network-failure
metadata, that it derives coarse network location from the client address, and
that it discards the client address after processing. See Cloudflare's
[Network Error Logging documentation](https://developers.cloudflare.com/network-error-logging/).

The three-month retention above applies only to Ankka's Analytics Engine funnel
rows. Ankka does not receive or store NEL reports. Cloudflare documents the
immediate disposal of the client IP address, but the cited page does not state a
retention period for the remaining NEL data; that processing is governed by
Cloudflare's service and policies.

NEL is not configured in customer gateway code. A customer's own Cloudflare
zone may independently apply its own reporting policy.

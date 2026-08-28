# Hosted installer analytics

Ankka collects a deliberately small setup funnel on the Ankka-hosted installer
at `https://deploy.ankka.ai`. Collection is enabled by default on that hosted
service. Running the public source yourself does not send these events to
Ankka, and customer-deployed gateways never receive this analytics binding.

This is product telemetry, not an authorization, audit, billing, support, or
security log. It is useful for directional questions such as whether people
reach planning, authorization, installation, and removal, and at which stage a
flow completes unsuccessfully.

## Destination and retention

The reviewed hosted Worker writes directly to the Cloudflare Workers Analytics
Engine dataset `ankka_installer_funnel_v1` in Ankka's Cloudflare account. There
is no browser beacon or public event-ingestion endpoint. Ankka does not export
or copy the dataset or send it to any additional analytics processor; query
credentials are read-only, remain outside the Worker, and are not published.
Cloudflare processes and stores the dataset and currently retains Analytics
Engine data for three months; see Cloudflare's
[Analytics Engine limits](https://developers.cloudflare.com/analytics/analytics-engine/limits/).

An analytics write is best-effort and non-authoritative. A missing binding,
invalid build label, quota problem, or provider failure drops the event and
cannot delay, fail, retry, approve, or change an installation or removal.

## Exact schema

Cloudflare supplies the row timestamp. The Worker writes only:

| Column | Meaning | Allowed values |
| --- | --- | --- |
| `index1` | sampling key | the exact event from the event allowlist below |
| `blob1` | public signed release | `gateway-vX.Y.Z` |
| `blob2` | public release channel | `canary` or `stable` |
| `blob3` | outcome | `none`, `succeeded`, `failed`, `denied`, or `existing_gateway` |
| `blob4` | flow | `none`, `fresh_install`, `same_session_removal`, or `returning_removal` |
| `double1` | count | exactly `1` |

The event allowlist is:

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

Milestones are emitted only by server-authoritative code after the corresponding
state transition is accepted. Completion events are emitted after the final
result has been stored. There is no browser-controlled event name or payload.

The dataset must never contain an IP address, country or colo, user or session
identifier (raw or hashed), request identifier, email, Cloudflare account or
zone identifier, hostname, gateway or installation identifier, plan or attempt
identifier, credential, OAuth state/code/token, request URL/path/query,
referrer, user agent, duration, free-form error, or arbitrary dimension.

Rows are timestamped, so the dataset is identifier-free rather than guaranteed
anonymous: at very low volume, timing may still correlate with information
held elsewhere. Ankka must not join it to OAuth, support, or infrastructure
records to reconstruct an individual journey.

## Interpreting counts

Counts describe accepted milestones and attempts, not unique people. A new
installer session can be bot-inflated, authorization can be retried, and there
is intentionally no per-session correlation. Do not use this dataset for
billing, individual behavior, exact cohort conversion, or security decisions.

Analytics Engine can sample rows. Queries must weight the count with
`_sample_interval`, for example:

```sql
SELECT
  index1 AS event,
  blob3 AS outcome,
  blob4 AS flow,
  SUM(_sample_interval * double1) AS events
FROM ankka_installer_funnel_v1
WHERE timestamp >= NOW() - INTERVAL '7' DAY
GROUP BY event, outcome, flow
ORDER BY event, outcome, flow
```

## Network Error Logging is separate

Cloudflare Network Error Logging remains enabled on the Ankka-owned hosted
zone. Cloudflare may add `NEL` and `Report-To` headers and process browser
reports about last-mile connectivity. NEL is useful for DNS, TCP, TLS, and
protocol failures that never reach the Worker; it is not the product funnel
above. Cloudflare documents its fields, destination, and privacy behavior in
the [Network Error Logging overview](https://developers.cloudflare.com/network-error-logging/).

The public-preview preflight on 2026-08-28 observed the same valid Cloudflare
policy on the installer root, callback error, and both release-channel
responses: a Cloudflare-operated report destination and a seven-day browser
policy lifetime. No report token or provider resource identifier was retained.
Cloudflare documents report fields for request URL/referrer, method, phase,
protocol, status, elapsed time, sampling fraction, and network-error type. It
also states that client IP is used only in volatile memory for the lifetime of
the report request, is not logged in the NEL pipeline, and reports are not
shared with third parties. The header lifetime is not report retention;
Cloudflare does not state retention for derived non-PII operational data on
that page. The owner explicitly accepts that residual provider-metadata and
unspecified aggregate-retention boundary while NEL remains enabled. Application
source does not set either header.

Neither hosted analytics mechanism changes the customer-runtime contract:
customer-deployed gateway Workers send no telemetry to Ankka.

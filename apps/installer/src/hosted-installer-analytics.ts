/**
 * Versioned, low-cardinality product events for Ankka's hosted installer.
 *
 * Every column is server-authored and allowlisted. Version 2 adds an opaque
 * per-session key and coarse request context: country, browser family, and,
 * for page views only, the external referrer host. The dataset still has no
 * IP, raw user-agent, URL, query-string, OAuth, Cloudflare-account, zone,
 * hostname, email, plan, key, or free-form field, no cookie of its own, and
 * no identifier that outlives the installer session. Release and channel are
 * public build identifiers; Cloudflare supplies the event timestamp.
 */
export const HOSTED_INSTALLER_ANALYTICS_EVENTS = Object.freeze([
  'installer_page_viewed',
  'installer_session_created',
  'discovery_authorization_created',
  'discovery_completed',
  'configuration_saved',
  'install_plan_created',
  'install_authorization_created',
  'install_completed',
  'removal_plan_created',
  'removal_authorization_created',
  'removal_completed',
] as const);

export type HostedInstallerAnalyticsEvent =
  (typeof HOSTED_INSTALLER_ANALYTICS_EVENTS)[number];

export const HOSTED_INSTALLER_ANALYTICS_OUTCOMES = Object.freeze([
  'none',
  'succeeded',
  'failed',
  'denied',
  'existing_gateway',
] as const);

export type HostedInstallerAnalyticsOutcome =
  (typeof HOSTED_INSTALLER_ANALYTICS_OUTCOMES)[number];

export const HOSTED_INSTALLER_ANALYTICS_FLOWS = Object.freeze([
  'none',
  'fresh_install',
  'same_session_removal',
  'returning_removal',
] as const);

export type HostedInstallerAnalyticsFlow =
  (typeof HOSTED_INSTALLER_ANALYTICS_FLOWS)[number];

export const HOSTED_INSTALLER_ANALYTICS_BROWSERS = Object.freeze([
  'none',
  'chromium',
  'firefox',
  'safari',
  'other',
] as const);

export type HostedInstallerAnalyticsBrowser =
  (typeof HOSTED_INSTALLER_ANALYTICS_BROWSERS)[number];

export const HOSTED_INSTALLER_ANALYTICS_DATASET = 'ankka_installer_funnel_v2';
export const HOSTED_INSTALLER_ANALYTICS_SCHEMA = Object.freeze({
  schemaVersion: 2,
  index1: 'event',
  blob1: 'release',
  blob2: 'channel',
  blob3: 'outcome',
  blob4: 'flow',
  blob5: 'session',
  blob6: 'country',
  blob7: 'browser',
  blob8: 'referrer',
  double1: 'count',
  retention: 'cloudflare-analytics-engine-3-months',
} as const);

export interface HostedInstallerAnalyticsSink {
  dataset?: AnalyticsEngineDataset;
  channel?: string;
  release?: string;
  session?: string;
  country?: string;
  browser?: string;
  referrer?: string;
}

const EVENT_SET = new Set<string>(HOSTED_INSTALLER_ANALYTICS_EVENTS);
const OUTCOME_SET = new Set<string>(HOSTED_INSTALLER_ANALYTICS_OUTCOMES);
const FLOW_SET = new Set<string>(HOSTED_INSTALLER_ANALYTICS_FLOWS);
const BROWSER_SET = new Set<string>(HOSTED_INSTALLER_ANALYTICS_BROWSERS);
const ALLOWED_TUPLES = new Set<string>([
  'installer_page_viewed\0none\0none',
  'installer_session_created\0none\0none',
  'discovery_authorization_created\0none\0none',
  'discovery_completed\0succeeded\0none',
  'discovery_completed\0failed\0none',
  'discovery_completed\0denied\0none',
  'configuration_saved\0none\0fresh_install',
  'install_plan_created\0none\0fresh_install',
  'install_authorization_created\0none\0fresh_install',
  'install_completed\0succeeded\0fresh_install',
  'install_completed\0failed\0fresh_install',
  'install_completed\0denied\0fresh_install',
  'install_completed\0existing_gateway\0fresh_install',
  'removal_plan_created\0none\0same_session_removal',
  'removal_plan_created\0none\0returning_removal',
  'removal_authorization_created\0none\0same_session_removal',
  'removal_authorization_created\0none\0returning_removal',
  'removal_completed\0succeeded\0same_session_removal',
  'removal_completed\0failed\0same_session_removal',
  'removal_completed\0denied\0same_session_removal',
  'removal_completed\0succeeded\0returning_removal',
  'removal_completed\0failed\0returning_removal',
  'removal_completed\0denied\0returning_removal',
]);
const RELEASE = /^gateway-v(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)$/u;
const CHANNEL = /^(?:canary|stable)$/u;
const SESSION_KEY = /^[a-f0-9]{16}$/u;
const COUNTRY = /^[A-Z]{2}$/u;
const REFERRER_HOST = /^[a-z0-9](?:[a-z0-9.-]{0,62})$/u;

/**
 * Context columns degrade to fixed fallbacks instead of dropping the event:
 * a malformed header must not distort the funnel, and only allowlisted or
 * fallback values are ever written.
 */
function sanitizedContext(
  sink: HostedInstallerAnalyticsSink,
  event: HostedInstallerAnalyticsEvent,
): readonly [string, string, string, string] {
  const session = sink.session !== undefined && SESSION_KEY.test(sink.session)
    ? sink.session
    : 'none';
  const country = sink.country !== undefined && COUNTRY.test(sink.country)
    ? sink.country
    : 'ZZ';
  const browser = sink.browser !== undefined && BROWSER_SET.has(sink.browser)
    ? sink.browser
    : 'none';
  const referrer = event === 'installer_page_viewed' &&
    sink.referrer !== undefined &&
    (sink.referrer === 'direct' || REFERRER_HOST.test(sink.referrer))
    ? sink.referrer
    : 'none';
  return [session, country, browser, referrer];
}

/**
 * Best-effort by design: product analytics must never change installer
 * behavior, error handling, provider mutations, or cleanup.
 */
export function recordHostedInstallerAnalytics(
  sink: HostedInstallerAnalyticsSink,
  event: HostedInstallerAnalyticsEvent,
  outcome: HostedInstallerAnalyticsOutcome,
  flow: HostedInstallerAnalyticsFlow,
): void {
  try {
    const { release, channel } = sink;
    if (
      !EVENT_SET.has(event) ||
      !OUTCOME_SET.has(outcome) ||
      !FLOW_SET.has(flow) ||
      !ALLOWED_TUPLES.has(`${event}\0${outcome}\0${flow}`) ||
      release === undefined ||
      !RELEASE.test(release) ||
      channel === undefined ||
      !CHANNEL.test(channel)
    ) return;
    sink.dataset?.writeDataPoint({
      indexes: [event],
      blobs: [release, channel, outcome, flow, ...sanitizedContext(sink, event)],
      doubles: [1],
    });
  } catch {
    // Analytics is intentionally non-authoritative and fail-open.
  }
}

/**
 * Versioned, low-cardinality product events for Ankka's hosted installer.
 *
 * The dataset deliberately has no visitor, session, request, account, zone,
 * hostname, email, IP, user-agent, URL, query-string, OAuth, plan, key, or
 * free-form fields. Release and channel are public build identifiers;
 * Cloudflare supplies the event timestamp. Counts therefore describe the
 * aggregate setup funnel without creating a per-user history.
 */
export const HOSTED_INSTALLER_ANALYTICS_EVENTS = Object.freeze([
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

export const HOSTED_INSTALLER_ANALYTICS_DATASET = 'ankka_installer_funnel_v1';
export const HOSTED_INSTALLER_ANALYTICS_SCHEMA = Object.freeze({
  schemaVersion: 1,
  index1: 'event',
  blob1: 'release',
  blob2: 'channel',
  blob3: 'outcome',
  blob4: 'flow',
  double1: 'count',
  retention: 'cloudflare-analytics-engine-3-months',
} as const);

export interface HostedInstallerAnalyticsSink {
  dataset?: AnalyticsEngineDataset;
  channel?: string;
  release?: string;
}

const EVENT_SET = new Set<string>(HOSTED_INSTALLER_ANALYTICS_EVENTS);
const OUTCOME_SET = new Set<string>(HOSTED_INSTALLER_ANALYTICS_OUTCOMES);
const FLOW_SET = new Set<string>(HOSTED_INSTALLER_ANALYTICS_FLOWS);
const ALLOWED_TUPLES = new Set<string>([
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
      typeof release !== 'string' ||
      !RELEASE.test(release) ||
      typeof channel !== 'string' ||
      !CHANNEL.test(channel)
    ) return;
    sink.dataset?.writeDataPoint({
      indexes: [event],
      blobs: [release, channel, outcome, flow],
      doubles: [1],
    });
  } catch {
    // Analytics is intentionally non-authoritative and fail-open.
  }
}

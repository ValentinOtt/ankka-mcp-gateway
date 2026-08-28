import { describe, expect, it, vi } from 'vitest';

import {
  HOSTED_INSTALLER_ANALYTICS_BROWSERS,
  HOSTED_INSTALLER_ANALYTICS_DATASET,
  HOSTED_INSTALLER_ANALYTICS_EVENTS,
  HOSTED_INSTALLER_ANALYTICS_FLOWS,
  HOSTED_INSTALLER_ANALYTICS_OUTCOMES,
  HOSTED_INSTALLER_ANALYTICS_SCHEMA,
  recordHostedInstallerAnalytics,
} from '../src/hosted-installer-analytics';

function environment(writeDataPoint: AnalyticsEngineDataset['writeDataPoint']) {
  return {
    dataset: { writeDataPoint },
    channel: 'canary',
    release: 'gateway-v1.2.3',
  };
}

describe('hosted installer analytics', () => {
  it('writes only the fixed session-scoped funnel schema', () => {
    const writeDataPoint = vi.fn<AnalyticsEngineDataset['writeDataPoint']>();
    const sinkWithForbiddenAmbientValues = {
      ...environment(writeDataPoint),
      CLOUDFLARE_OAUTH_CLIENT_SECRET: 'synthetic-test-only',
      DEPLOY_SESSION_ENCRYPTION_KEY: 'synthetic-test-only',
      requestUrl: 'https://deploy.ankka.ai/oauth/callback?code=synthetic-test-only',
    };
    recordHostedInstallerAnalytics(
      sinkWithForbiddenAmbientValues,
      'install_completed',
      'succeeded',
      'fresh_install',
    );

    expect(writeDataPoint).toHaveBeenCalledOnce();
    expect(writeDataPoint).toHaveBeenCalledWith({
      indexes: ['install_completed'],
      blobs: ['gateway-v1.2.3', 'canary', 'succeeded', 'fresh_install', 'none', 'ZZ', 'none', 'none'],
      doubles: [1],
    });
    expect(JSON.stringify(writeDataPoint.mock.calls)).not.toContain('synthetic-test-only');
    expect(HOSTED_INSTALLER_ANALYTICS_DATASET).toBe('ankka_installer_funnel_v2');
    expect(HOSTED_INSTALLER_ANALYTICS_SCHEMA).toEqual({
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
    });
  });

  it('writes allowlisted session context and degrades malformed context to fallbacks', () => {
    const writeDataPoint = vi.fn<AnalyticsEngineDataset['writeDataPoint']>();
    recordHostedInstallerAnalytics(
      {
        ...environment(writeDataPoint),
        session: 'a'.repeat(16),
        country: 'FI',
        browser: 'firefox',
        referrer: 'news.ycombinator.com',
      },
      'installer_page_viewed',
      'none',
      'none',
    );
    expect(writeDataPoint).toHaveBeenLastCalledWith({
      indexes: ['installer_page_viewed'],
      blobs: ['gateway-v1.2.3', 'canary', 'none', 'none', 'a'.repeat(16), 'FI', 'firefox', 'news.ycombinator.com'],
      doubles: [1],
    });

    recordHostedInstallerAnalytics(
      {
        ...environment(writeDataPoint),
        session: 'a'.repeat(16),
        country: 'FI',
        browser: 'firefox',
        referrer: 'news.ycombinator.com',
      },
      'installer_session_created',
      'none',
      'none',
    );
    expect(writeDataPoint).toHaveBeenLastCalledWith({
      indexes: ['installer_session_created'],
      blobs: ['gateway-v1.2.3', 'canary', 'none', 'none', 'a'.repeat(16), 'FI', 'firefox', 'none'],
      doubles: [1],
    });

    recordHostedInstallerAnalytics(
      {
        ...environment(writeDataPoint),
        session: 'customer@example.com',
        country: 'Finland',
        browser: 'Mozilla/5.0 (synthetic)',
        referrer: 'https://example.com/?token=synthetic-test-only',
      },
      'installer_page_viewed',
      'none',
      'none',
    );
    expect(writeDataPoint).toHaveBeenLastCalledWith({
      indexes: ['installer_page_viewed'],
      blobs: ['gateway-v1.2.3', 'canary', 'none', 'none', 'none', 'ZZ', 'none', 'none'],
      doubles: [1],
    });
    expect(JSON.stringify(writeDataPoint.mock.calls)).not.toContain('synthetic-test-only');
  });

  it('keeps every dimension finite and reviewable', () => {
    expect(HOSTED_INSTALLER_ANALYTICS_EVENTS).toEqual([
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
    ]);
    expect(HOSTED_INSTALLER_ANALYTICS_OUTCOMES).toEqual([
      'none', 'succeeded', 'failed', 'denied', 'existing_gateway',
    ]);
    expect(HOSTED_INSTALLER_ANALYTICS_FLOWS).toEqual([
      'none', 'fresh_install', 'same_session_removal', 'returning_removal',
    ]);
    expect(HOSTED_INSTALLER_ANALYTICS_BROWSERS).toEqual([
      'none', 'chromium', 'firefox', 'safari', 'other',
    ]);
  });

  it('drops absent, malformed, or throwing sinks without affecting the installer', () => {
    expect(() => recordHostedInstallerAnalytics(
      {
        channel: 'canary',
        release: 'gateway-v1.2.3',
      },
      'installer_session_created',
      'none',
      'none',
    )).not.toThrow();

    const malformedWrite = vi.fn<AnalyticsEngineDataset['writeDataPoint']>();
    recordHostedInstallerAnalytics(
      {
        ...environment(malformedWrite),
        release: 'customer@example.com',
      },
      'installer_session_created',
      'none',
      'none',
    );
    expect(malformedWrite).not.toHaveBeenCalled();

    recordHostedInstallerAnalytics(
      environment(malformedWrite),
      'installer_session_created',
      'existing_gateway',
      'returning_removal',
    );
    expect(malformedWrite).not.toHaveBeenCalled();

    const throwing = vi.fn<AnalyticsEngineDataset['writeDataPoint']>(() => {
      throw new Error('synthetic sink failure');
    });
    expect(() => recordHostedInstallerAnalytics(
      environment(throwing),
      'installer_session_created',
      'none',
      'none',
    )).not.toThrow();
  });
});

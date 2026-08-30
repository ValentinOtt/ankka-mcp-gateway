import type { ReadConnector } from '../connector';
import { createBigQueryConnector } from './bigquery';
import { createNotionConnector } from './notion';
import { createHubSpotConnector } from './hubspot';
import { createZendeskConnector } from './zendesk';
import { createGorgiasConnector } from './gorgias';
import { createGoogleSearchConsoleConnector } from './google-search-console';
import { createGoogleAnalyticsConnector } from './google-analytics';

export function createConnector(provider: string, config: string, token: string): ReadConnector {
  switch (provider) {
    case 'notion': return createNotionConnector(config, token);
    case 'hubspot': return createHubSpotConnector(config, token);
    case 'zendesk': return createZendeskConnector(config, token);
    case 'gorgias': return createGorgiasConnector(config, token);
    case 'google-search-console': return createGoogleSearchConsoleConnector(config, token);
    case 'google-analytics': return createGoogleAnalyticsConnector(config, token);
    case 'bigquery': return createBigQueryConnector(config, token);
    default: throw new Error('CONNECTOR_CONFIGURATION_INVALID');
  }
}

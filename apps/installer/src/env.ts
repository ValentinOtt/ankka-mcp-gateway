import type { ReleaseEnvironment } from './release';

export interface GatewayDeployEnv extends ReleaseEnvironment {
  GATEWAY_DEPLOY_SESSION: DurableObjectNamespace;
  HOSTED_INSTALLER_ANALYTICS?: AnalyticsEngineDataset;
  HOSTED_INSTALLER_ANALYTICS_CHANNEL?: string;
  HOSTED_INSTALLER_ANALYTICS_RELEASE?: string;
  ANONYMOUS_SESSION_RATE_LIMIT?: RateLimit;
  SESSION_READ_RATE_LIMIT?: RateLimit;
  SESSION_MUTATION_RATE_LIMIT?: RateLimit;
  CLOUDFLARE_OAUTH_CLIENT_ID: string;
  CLOUDFLARE_OAUTH_CLIENT_SECRET: string;
  DEPLOY_SESSION_ENCRYPTION_KEY: string;
  BOOTSTRAP_NONCE_DERIVATION_KEY: string;
}

export const PUBLIC_ORIGIN = 'https://deploy.ankka.ai';
export const OAUTH_CALLBACK_URL = `${PUBLIC_ORIGIN}/oauth/callback`;
export const OAUTH_AUTHORIZE_URL = 'https://dash.cloudflare.com/oauth2/auth';
export const OAUTH_EXCHANGE_URL = 'https://dash.cloudflare.com/oauth2/token';
export const OAUTH_REVOKE_URL = 'https://dash.cloudflare.com/oauth2/revoke';
export const CLOUDFLARE_API_ORIGIN = 'https://api.cloudflare.com';

export const SESSION_COOKIE = '__Host-ankka_gateway_deploy';
export const OAUTH_COOKIE = '__Host-ankka_gateway_deploy_oauth';
export const BOOTSTRAP_COOKIE = '__Host-ankka_gateway_bootstrap';

export const SESSION_TTL_MS = 30 * 60 * 1000;
export const OAUTH_ATTEMPT_TTL_MS = 10 * 60 * 1000;

// The first authorization is deliberately read-only and is revoked as soon as
// account and active-zone discovery completes. A separate grant is required
// for the exact reviewed deployment plan.
export const DISCOVERY_OAUTH_SCOPES = Object.freeze([
  'account-settings.read',
  'memberships.read',
  'user-details.read',
  'zone.read',
] as const);

export type DiscoveryOauthScope = (typeof DISCOVERY_OAUTH_SCOPES)[number];

// This list is an application security boundary, not release-manifest input.
// A release is accepted only when it requests this exact set.
export const REQUIRED_OAUTH_SCOPES = Object.freeze([
  'access-acct.read',
  'zone-access.write',
  'dns.write',
  'mcp-portals.write',
  'workers-routes.read',
  'workers-scripts.write',
  'zone.read',
] as const);

export type RequiredOauthScope = (typeof REQUIRED_OAUTH_SCOPES)[number];

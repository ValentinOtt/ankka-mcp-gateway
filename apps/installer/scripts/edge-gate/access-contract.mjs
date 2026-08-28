/**
 * Exact private-canary Cloudflare Access boundary for the hosted installer.
 *
 * The whole host is identity-gated. Only endpoints that must be callable
 * without an Access session receive narrower, path-specific Bypass apps:
 * Cloudflare's OAuth redirect and the two public, signed release channels.
 * Public self-service has no Ankka Access application on this host and is
 * verified separately by verify-public.mjs.
 */

import { isIsolatedCanaryHostname } from '../isolated-canary-target.mjs';

export const ACCESS_HOST = 'deploy.ankka.ai';
export const OAUTH_CALLBACK_PATH = '/oauth/callback';
export const RELEASE_CHANNEL_PATHS = Object.freeze([
  '/api/releases/canary',
  '/api/releases/stable',
]);

function privateInstallerApplication(accessHost) {
  return Object.freeze({
    key: 'protected installer',
    name: 'Ankka MCP Gateway installer',
    domain: accessHost,
    policyName: 'MCP Gateway installer operators',
  });
}

function accessBypassApplications(accessHost) {
  return Object.freeze([
    Object.freeze({
      key: 'oauth callback',
      name: 'Ankka MCP Gateway installer callback (bypass)',
      domain: `${accessHost}${OAUTH_CALLBACK_PATH}`,
      policyName: 'Cloudflare OAuth redirect must reach the callback unauthenticated',
    }),
    ...RELEASE_CHANNEL_PATHS.map((pathname) => Object.freeze({
      key: `release channel ${pathname.slice('/api/releases/'.length)}`,
      name: `Ankka MCP Gateway ${pathname.slice('/api/releases/'.length)} release channel (bypass)`,
      domain: `${accessHost}${pathname}`,
      policyName: 'Signed anonymous release discovery must bypass interactive Access',
    })),
  ]);
}

export const PRIVATE_INSTALLER_APPLICATION = privateInstallerApplication(ACCESS_HOST);
export const ACCESS_BYPASS_APPLICATIONS = accessBypassApplications(ACCESS_HOST);

function baseApplication(name, domain) {
  return {
    name,
    domain,
    type: 'self_hosted',
    app_launcher_visible: false,
    auto_redirect_to_identity: false,
    enable_binding_cookie: false,
    http_only_cookie_attribute: true,
    options_preflight_bypass: false,
  };
}

function bypassApplicationBodyFor(specification, expectedApplications) {
  if (!expectedApplications.includes(specification)) {
    throw new TypeError('invalid_access_bypass_application');
  }
  return {
    ...baseApplication(specification.name, specification.domain),
    session_duration: '0s',
    policies: [{
      name: specification.policyName,
      decision: 'bypass',
      precedence: 1,
      include: [{ everyone: {} }],
    }],
  };
}

export function bypassApplicationBody(specification) {
  return bypassApplicationBodyFor(specification, ACCESS_BYPASS_APPLICATIONS);
}

function protectedInstallerApplicationBodyFor(
  specification,
  { emails, identityProviderId, sessionDuration },
) {
  if (!Array.isArray(emails) || emails.length === 0 ||
      emails.some((email) => typeof email !== 'string' || email.length === 0) ||
      new Set(emails).size !== emails.length ||
      !(identityProviderId === null ||
        (typeof identityProviderId === 'string' && identityProviderId.length > 0)) ||
      typeof sessionDuration !== 'string' || !/^[1-9]\d*(?:m|h|d)$/u.test(sessionDuration)) {
    throw new TypeError('invalid_protected_installer_application');
  }
  return {
    ...baseApplication(specification.name, specification.domain),
    session_duration: sessionDuration,
    ...(identityProviderId
      ? { allowed_idps: [identityProviderId], auto_redirect_to_identity: true }
      : {}),
    policies: [{
      name: specification.policyName,
      decision: 'allow',
      precedence: 1,
      include: emails.map((email) => ({ email: { email } })),
    }],
  };
}

export function protectedInstallerApplicationBody(input) {
  return protectedInstallerApplicationBodyFor(PRIVATE_INSTALLER_APPLICATION, input);
}

function isRecord(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function baseApplicationMatches(application, specification) {
  return isRecord(application) &&
    application.name === specification.name &&
    application.domain === specification.domain &&
    noRules(application.destinations) &&
    application.type === 'self_hosted' &&
    application.app_launcher_visible === false &&
    application.enable_binding_cookie === false &&
    application.http_only_cookie_attribute === true &&
    application.options_preflight_bypass === false;
}

function noRules(value) {
  return value === undefined || (Array.isArray(value) && value.length === 0);
}

function exactEveryoneRule(value) {
  return isRecord(value) && Object.keys(value).length === 1 &&
    isRecord(value.everyone) && Object.keys(value.everyone).length === 0;
}

/** Exact provider read-back contract for one private-canary Bypass app. */
function assessPrivateBypassApplicationFor(application, specification, expectedApplications) {
  if (!expectedApplications.includes(specification) ||
      !baseApplicationMatches(application, specification) ||
      application.auto_redirect_to_identity !== false ||
      application.session_duration !== '0s' ||
      !Array.isArray(application.policies) || application.policies.length !== 1) {
    return Object.freeze({ ok: false });
  }
  const policy = application.policies[0];
  const ok = isRecord(policy) &&
    policy.name === specification.policyName &&
    policy.decision === 'bypass' && policy.precedence === 1 &&
    Array.isArray(policy.include) && policy.include.length === 1 &&
    exactEveryoneRule(policy.include[0]) && noRules(policy.exclude) && noRules(policy.require);
  return Object.freeze({ ok });
}

export function assessPrivateBypassApplication(application, specification) {
  return assessPrivateBypassApplicationFor(
    application,
    specification,
    ACCESS_BYPASS_APPLICATIONS,
  );
}

/** Exact structural read-back contract for the private whole-host Allow app. */
function assessPrivateInstallerApplicationFor(application, specification) {
  if (!baseApplicationMatches(application, specification) ||
      typeof application.session_duration !== 'string' ||
      !/^[1-9]\d*(?:m|h|d)$/u.test(application.session_duration) ||
      !Array.isArray(application.policies) || application.policies.length !== 1) {
    return Object.freeze({ ok: false, operatorIdentityCount: 0, identityProviderCount: 0 });
  }
  const idps = application.allowed_idps ?? [];
  if (!Array.isArray(idps) || idps.length > 1 ||
      idps.some((idp) => typeof idp !== 'string' || idp.length === 0) ||
      application.auto_redirect_to_identity !== (idps.length === 1)) {
    return Object.freeze({ ok: false, operatorIdentityCount: 0, identityProviderCount: 0 });
  }
  const policy = application.policies[0];
  if (!isRecord(policy) || policy.name !== specification.policyName ||
      policy.decision !== 'allow' || policy.precedence !== 1 ||
      !Array.isArray(policy.include) || policy.include.length === 0 ||
      !noRules(policy.exclude) || !noRules(policy.require)) {
    return Object.freeze({ ok: false, operatorIdentityCount: 0, identityProviderCount: idps.length });
  }
  const emails = policy.include.map((rule) => (
    isRecord(rule) && Object.keys(rule).length === 1 && isRecord(rule.email) &&
    Object.keys(rule.email).length === 1 && typeof rule.email.email === 'string' &&
    rule.email.email.length > 0 ? rule.email.email : null
  ));
  const ok = emails.every((email) => email !== null) && new Set(emails).size === emails.length;
  return Object.freeze({
    ok,
    operatorIdentityCount: ok ? emails.length : 0,
    identityProviderCount: idps.length,
  });
}

export function assessPrivateInstallerApplication(application) {
  return assessPrivateInstallerApplicationFor(application, PRIVATE_INSTALLER_APPLICATION);
}

/** Exact contract factory for a separately reviewed non-live private canary. */
export function createIsolatedPrivateAccessContract(accessHost) {
  if (!isIsolatedCanaryHostname(accessHost)) {
    throw new TypeError('invalid_isolated_access_host');
  }
  const privateInstaller = privateInstallerApplication(accessHost);
  const bypassApplications = accessBypassApplications(accessHost);
  return Object.freeze({
    accessHost,
    bypassApplications,
    privateInstallerApplication: privateInstaller,
    assessBypassApplication: (application, specification) =>
      assessPrivateBypassApplicationFor(application, specification, bypassApplications),
    assessInstallerApplication: (application) =>
      assessPrivateInstallerApplicationFor(application, privateInstaller),
    bypassApplicationBody: (specification) =>
      bypassApplicationBodyFor(specification, bypassApplications),
    protectedInstallerApplicationBody: (input) =>
      protectedInstallerApplicationBodyFor(privateInstaller, input),
  });
}

/**
 * Return every public hostname selector carried by an Access app.
 * Cloudflare currently returns `domain`; newer application shapes can also
 * expose the same target as a public destination URI. An unparseable
 * app is deliberately `unverifiable` when its type could cover a hostname: a
 * public-mode verifier may not assume an unknown selector is unrelated.
 */
export function accessApplicationHostSelectors(application) {
  if (!isRecord(application) || typeof application.type !== 'string') {
    return Object.freeze({ status: 'unverifiable', selectors: Object.freeze([]) });
  }
  const selectors = [];
  if (application.domain !== undefined && application.domain !== null) {
    if (typeof application.domain !== 'string') {
      return Object.freeze({ status: 'unverifiable', selectors: Object.freeze([]) });
    }
    selectors.push(application.domain);
  }
  if (application.destinations !== undefined && application.destinations !== null) {
    if (!Array.isArray(application.destinations)) {
      return Object.freeze({ status: 'unverifiable', selectors: Object.freeze([]) });
    }
    for (const destination of application.destinations) {
      if (!isRecord(destination) || typeof destination.uri !== 'string') {
        return Object.freeze({ status: 'unverifiable', selectors: Object.freeze([]) });
      }
      selectors.push(destination.uri);
    }
  }
  if (selectors.length === 0) {
    return Object.freeze({
      status: application.type === 'self_hosted' ? 'unverifiable' : 'unrelated',
      selectors: Object.freeze([]),
    });
  }
  return Object.freeze({ status: 'parsed', selectors: Object.freeze([...new Set(selectors)]) });
}

function selectorHostname(selector) {
  if (
    typeof selector !== 'string' || selector.length === 0 || selector.length > 2048 ||
    /[\u0000-\u001f\u007f?#@]/u.test(selector) || selector !== selector.trim()
  ) return null;
  let value = selector;
  const scheme = /^(https?):\/\//iu.exec(value);
  if (scheme) {
    if (scheme[1].toLowerCase() !== 'https') return null;
    value = value.slice(scheme[0].length);
  } else if (value.includes('://')) {
    return null;
  }
  const authority = value.split('/', 1)[0].toLowerCase();
  const portIndex = authority.lastIndexOf(':');
  const hostname = portIndex < 0 ? authority : authority.slice(0, portIndex);
  const port = portIndex < 0 ? null : authority.slice(portIndex + 1);
  if (
    (port !== null && port !== '443') ||
    !/^[a-z0-9*.-]+$/u.test(hostname) ||
    hostname.startsWith('.') || hostname.endsWith('.') || hostname.includes('..')
  ) return null;
  return hostname;
}

function wildcardHostnameMatches(pattern, hostname) {
  const expression = pattern
    .replace(/[.+?^${}()|[\]\\]/gu, '\\$&')
    .replaceAll('*', '.*');
  return new RegExp(`^${expression}$`, 'u').test(hostname);
}

/**
 * Classify whether a Cloudflare Access application could affect any path on
 * the hosted installer. Public self-service requires `unrelated` for every
 * application in the complete account listing; path-specific leftovers are
 * not accepted merely because the particular probe URLs happen to work.
 */
export function classifyAccessApplicationForHostname(application, targetHostname) {
  if (typeof targetHostname !== 'string' || targetHostname.length === 0) return 'unverifiable';
  const parsed = accessApplicationHostSelectors(application);
  if (parsed.status !== 'parsed') return parsed.status;
  for (const selector of parsed.selectors) {
    const selectorHost = selectorHostname(selector);
    if (selectorHost === null) return 'unverifiable';
    if (wildcardHostnameMatches(selectorHost, targetHostname)) return 'covering';
  }
  return 'unrelated';
}

export function classifyAccessApplicationForInstaller(application) {
  return classifyAccessApplicationForHostname(application, ACCESS_HOST);
}

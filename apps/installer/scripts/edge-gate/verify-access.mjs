/**
 * Proves the isolated private-installer Access contract, with only the OAuth
 * callback and exact signed release channels deliberately excluded.
 *
 * Two kinds of evidence, because configuration alone is not protection:
 *
 *   - Configuration, read back from the API: all exact-path Bypass
 *     applications exist, no broader Bypass application covers a release
 *     channel, and the installer admits explicit identities rather than
 *     `everyone`.
 *   - Behaviour, observed over plain HTTP: the installer redirects an
 *     unauthenticated client to the Access login, while the callback and both
 *     release channels do not.
 *
 * The behavioural half works from anywhere, including the operator's own
 * machine, because Access keys on identity rather than on network position —
 * a request without an Access cookie is an outside request wherever it starts.
 * That is precisely what the IP allowlist it replaced could not demonstrate.
 *
 * Usage:
 *   CLOUDFLARE_API_TOKEN=… node scripts/edge-gate/verify-access.mjs
 */
import process from 'node:process';
import * as v from 'valibot';

import {
  ACCESS_BYPASS_APPLICATIONS,
  ACCESS_HOST,
  OAUTH_CALLBACK_PATH,
  PRIVATE_INSTALLER_APPLICATION,
  RELEASE_CHANNEL_PATHS,
  assessPrivateBypassApplication,
  assessPrivateInstallerApplication,
  isCloudflareAccessLoginUrl,
} from './access-contract.mjs';

const API = 'https://api.cloudflare.com/client/v4';
const ZONE = 'ankka.ai';
const NUMBER_SCHEMA = v.number();
const STRING_SCHEMA = v.string();

const results = [];
function record(item, verdict, detail) { results.push({ item, verdict, detail }); }

function requireToken() {
  const token = process.env.CLOUDFLARE_API_TOKEN;
  if (!v.is(STRING_SCHEMA, token) || token.length < 20) throw new Error('CLOUDFLARE_API_TOKEN must be set');
  return token;
}

async function cf(pathname) {
  const response = await fetch(`${API}${pathname}`, {
    headers: { accept: 'application/json', authorization: `Bearer ${requireToken()}` },
  });
  let body = null;
  try { body = JSON.parse(await response.text()); } catch { body = null; }
  return body?.success === true ? { ok: true, result: body.result } : { ok: false };
}

/** An unauthenticated observation: never follow the redirect, just read it. */
async function probe(url, { accept = 'text/html', method = 'GET' } = {}) {
  try {
    const response = await fetch(url, {
      method,
      redirect: 'manual',
      headers: { accept },
    });
    return { error: null, status: response.status, location: response.headers.get('location') ?? '' };
  } catch (error) {
    return { error: error?.name ?? 'error', status: null, location: '' };
  }
}

function policiesOf(app) {
  return app?.policies ?? [];
}

function isAccessRedirect(observation) {
  return v.is(NUMBER_SCHEMA, observation.status) &&
    observation.status >= 300 && observation.status < 400 &&
    isCloudflareAccessLoginUrl(observation.location);
}

function applicationDomainMatches(domain, target) {
  if (!v.is(STRING_SCHEMA, domain)) return false;
  if (domain === target || target.startsWith(`${domain}/`)) return true;
  if (!domain.includes('*')) return false;
  const expression = domain
    .replace(/[.+?^${}()|[\]\\]/gu, '\\$&')
    .replaceAll('*', '.*');
  return new RegExp(`^${expression}$`, 'u').test(target);
}

function broaderReleaseBypasses(applications) {
  const exactDomains = new Set(ACCESS_BYPASS_APPLICATIONS.map(({ domain }) => domain));
  const releaseDomains = RELEASE_CHANNEL_PATHS.map((pathname) => `${ACCESS_HOST}${pathname}`);
  return applications.filter((app) => (
    !exactDomains.has(app.domain) &&
    policiesOf(app).some((policy) => policy.decision === 'bypass') &&
    releaseDomains.some((domain) => applicationDomainMatches(app.domain, domain))
  ));
}

async function main() {
  requireToken();
  const zones = await cf(`/zones?name=${encodeURIComponent(ZONE)}`);
  const zone = zones.ok ? zones.result?.[0] : null;
  if (!zone) throw new Error(`zone ${ZONE} not readable`);
  const accountId = zone.account.id;

  const apps = await cf(`/accounts/${accountId}/access/apps?per_page=100`);
  if (!apps.ok) {
    record(
      'access apps',
      'UNVERIFIABLE',
      'cannot read the Access application contract',
    );
  } else {
    const applications = apps.result ?? [];
    const installerApps = applications.filter((app) => app.domain === ACCESS_HOST);
    const installerApp = installerApps[0] ?? null;
    const bypassApps = ACCESS_BYPASS_APPLICATIONS.map((specification) => ({
      applications: applications.filter((app) => app.domain === specification.domain),
      specification,
    }));
    const anyBypass = bypassApps.some((entry) => entry.applications.length > 0);

    // Absence is reported explicitly and remains non-zero. This isolated
    // verifier must never treat a missing control as a successful posture.
    if (!anyBypass && !installerApp) {
      record(
        'access protection',
        'NOT ENFORCED',
        `no Access application for ${ACCESS_HOST}; isolated private protection is absent`,
      );
    }

    for (const entry of bypassApps) {
      const item = `${entry.specification.key} bypass app`;
      if (entry.applications.length === 0) {
        record(item, 'MISSING', `no Access application for ${entry.specification.domain}`);
      } else if (entry.applications.length !== 1) {
        record(item, 'FAIL', `${entry.applications.length} applications, expected exactly 1`);
      } else {
        const assessment = assessPrivateBypassApplication(
          entry.applications[0],
          entry.specification,
        );
        record(
          item,
          assessment.ok ? 'PASS' : 'FAIL',
          assessment.ok ? 'exact name, domain, settings and Everyone Bypass policy' :
            'application does not match the exact private-canary contract',
        );
      }
    }

    const broadBypasses = broaderReleaseBypasses(applications);
    record(
      'release bypass width',
      broadBypasses.length === 0 ? 'PASS' : 'FAIL',
      broadBypasses.length === 0
        ? 'only exact canary and stable channel paths bypass Access'
        : `${broadBypasses.length} broader Bypass application(s) could cover a release channel`,
    );

    if (installerApps.length > 1) {
      record('installer app', 'FAIL', `${installerApps.length} applications, expected exactly 1`);
    } else if (!installerApp && anyBypass) {
      record('installer app', 'MISSING', `path bypass exists but nothing protects ${ACCESS_HOST}`);
    } else if (!installerApp) {
      // Reported above as the deliberate posture.
    } else {
      const assessment = assessPrivateInstallerApplication(installerApp);
      record(
        'installer app',
        assessment.ok ? 'PASS' : 'FAIL',
        assessment.ok
          ? `exact ${PRIVATE_INSTALLER_APPLICATION.name} contract; ` +
            `${assessment.operatorIdentityCount} explicit operator identit` +
            `${assessment.operatorIdentityCount === 1 ? 'y' : 'ies'}; ` +
            `${assessment.identityProviderCount === 1 ? 'one identity provider pinned' : 'all identity providers enabled'}`
          : 'application does not match the exact private-canary contract',
      );
    }
  }

  // Behaviour. A configuration read cannot show what the edge actually does.
  const root = await probe(`https://${ACCESS_HOST}/`);
  const rootGated = isAccessRedirect(root);
  record(
    'installer requires login',
    root.error ? 'ERROR' : (rootGated ? 'PASS' : 'EXPOSED'),
    root.error
      ? `GET / failed: ${root.error}`
      : (rootGated ? `GET / -> ${root.status} Access login` : `GET / -> ${root.status}`),
  );

  // The session endpoint is the exposure that actually costs something: an
  // anonymous GET with no cookie can mint a Durable Object session. Worker
  // bindings bound that cost in an active reviewed build, but this private
  // verifier still uses HEAD so its own check never mints state.
  const api = await probe(`https://${ACCESS_HOST}/api/session`, { method: 'HEAD' });
  const apiGated = isAccessRedirect(api);
  record(
    'api requires login',
    api.error ? 'ERROR' : (apiGated ? 'PASS' : 'EXPOSED'),
    api.error
      ? `HEAD /api/session failed: ${api.error}`
      : (apiGated
        ? `HEAD /api/session -> ${api.status} Access login`
        : `HEAD /api/session -> ${api.status}; private operator gate is absent`),
  );

  const callback = await probe(`https://${ACCESS_HOST}${OAUTH_CALLBACK_PATH}`);
  const redirectedToLogin = isAccessRedirect(callback);
  record(
    'callback reachable',
    callback.error ? 'ERROR' : (redirectedToLogin ? 'FAIL' : 'PASS'),
    callback.error
      ? `GET ${OAUTH_CALLBACK_PATH} failed: ${callback.error}`
      : (redirectedToLogin
        ? `GET ${OAUTH_CALLBACK_PATH} redirects to Access login; Cloudflare's OAuth service could not complete a grant`
        : `GET ${OAUTH_CALLBACK_PATH} -> ${callback.status} (app-level response, not an Access redirect)`),
  );

  for (const pathname of RELEASE_CHANNEL_PATHS) {
    const release = await probe(`https://${ACCESS_HOST}${pathname}`, { accept: 'application/json' });
    const redirectedRelease = isAccessRedirect(release);
    record(
      `${pathname.slice('/api/releases/'.length)} channel reachable`,
      release.error ? 'ERROR' : (redirectedRelease ? 'FAIL' : 'PASS'),
      release.error
        ? `GET ${pathname} failed: ${release.error}`
        : (redirectedRelease
          ? `GET ${pathname} redirects to Access login; installed gateways could not discover updates`
          : `GET ${pathname} -> ${release.status} (app-level response, not an Access redirect)`),
    );
  }

  const width = Math.max(...results.map((entry) => entry.item.length));
  process.stdout.write('--- isolated private Access verification ---\n');
  for (const entry of results) {
    process.stdout.write(`  ${entry.item.padEnd(width)}  ${entry.verdict.padEnd(13)} ${entry.detail}\n`);
  }
  return results.some((entry) => (
    ['MISSING', 'FAIL', 'ERROR', 'UNVERIFIABLE', 'NOT ENFORCED', 'EXPOSED'].includes(entry.verdict)
  )) ? 1 : 0;
}

main().then(
  (code) => { process.exitCode = code; },
  (error) => { process.stderr.write(`${error?.message ?? String(error)}\n`); process.exitCode = 1; },
);

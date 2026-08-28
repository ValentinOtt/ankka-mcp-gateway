import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';

import {
  ACCESS_BYPASS_APPLICATIONS,
  ACCESS_HOST,
  OAUTH_CALLBACK_PATH,
  PRIVATE_INSTALLER_APPLICATION,
  RELEASE_CHANNEL_PATHS,
  assessPrivateBypassApplication,
  assessPrivateInstallerApplication,
  bypassApplicationBody,
  protectedInstallerApplicationBody,
} from '../apps/installer/scripts/edge-gate/access-contract.mjs';

const execFileAsync = promisify(execFile);

test('Access bypasses only the OAuth callback and exact signed release channels', () => {
  assert.deepEqual(RELEASE_CHANNEL_PATHS, [
    '/api/releases/canary',
    '/api/releases/stable',
  ]);
  assert.deepEqual(
    ACCESS_BYPASS_APPLICATIONS.map(({ domain }) => domain),
    [
      `${ACCESS_HOST}${OAUTH_CALLBACK_PATH}`,
      `${ACCESS_HOST}/api/releases/canary`,
      `${ACCESS_HOST}/api/releases/stable`,
    ],
  );
  assert.equal(
    ACCESS_BYPASS_APPLICATIONS.some(({ domain }) => domain === `${ACCESS_HOST}/api/releases`),
    false,
  );
  assert.equal(ACCESS_BYPASS_APPLICATIONS.some(({ domain }) => domain.includes('*')), false);

  for (const specification of ACCESS_BYPASS_APPLICATIONS) {
    assert.deepEqual(bypassApplicationBody(specification), {
      name: specification.name,
      domain: specification.domain,
      type: 'self_hosted',
      app_launcher_visible: false,
      auto_redirect_to_identity: false,
      enable_binding_cookie: false,
      http_only_cookie_attribute: true,
      options_preflight_bypass: false,
      session_duration: '0s',
      policies: [{
        name: specification.policyName,
        decision: 'bypass',
        precedence: 1,
        include: [{ everyone: {} }],
      }],
    });
  }
});

test('the whole-host installer remains restricted to explicit operator identities', () => {
  const body = protectedInstallerApplicationBody({
    emails: ['operator@example.com'],
    identityProviderId: 'account-members-idp',
    sessionDuration: '8h',
  });
  assert.deepEqual(body, {
    name: PRIVATE_INSTALLER_APPLICATION.name,
    domain: ACCESS_HOST,
    type: 'self_hosted',
    app_launcher_visible: false,
    auto_redirect_to_identity: true,
    enable_binding_cookie: false,
    http_only_cookie_attribute: true,
    options_preflight_bypass: false,
    session_duration: '8h',
    allowed_idps: ['account-members-idp'],
    policies: [{
      name: 'MCP Gateway installer operators',
      decision: 'allow',
      precedence: 1,
      include: [{ email: { email: 'operator@example.com' } }],
    }],
  });
  assert.deepEqual(assessPrivateInstallerApplication(body), {
    ok: true,
    operatorIdentityCount: 1,
    identityProviderCount: 1,
  });
  assert.equal(
    assessPrivateInstallerApplication({
      ...body,
      policies: [{ ...body.policies[0], name: 'similar but not exact' }],
    }).ok,
    false,
  );
  assert.throws(
    () => protectedInstallerApplicationBody({
      emails: [],
      identityProviderId: null,
      sessionDuration: '8h',
    }),
    /invalid_protected_installer_application/u,
  );
  assert.throws(
    () => protectedInstallerApplicationBody({
      emails: ['operator@example.com', 'operator@example.com'],
      identityProviderId: null,
      sessionDuration: '8h',
    }),
    /invalid_protected_installer_application/u,
  );
});

test('private bypass read-back requires the exact application and policy names', () => {
  for (const specification of ACCESS_BYPASS_APPLICATIONS) {
    const body = bypassApplicationBody(specification);
    assert.deepEqual(assessPrivateBypassApplication(body, specification), { ok: true });
    assert.equal(assessPrivateBypassApplication({ ...body, name: 'look-alike' }, specification).ok, false);
    assert.equal(assessPrivateBypassApplication({
      ...body,
      policies: [{ ...body.policies[0], name: 'look-alike policy' }],
    }, specification).ok, false);
  }
});

test('obsolete zone WAF operator entrypoints fail before credentials or network access', async () => {
  for (const filename of ['apply.mjs', 'verify.mjs']) {
    const script = new URL(`../apps/installer/scripts/edge-gate/${filename}`, import.meta.url);
    const source = await readFile(script, 'utf8');
    assert.doesNotMatch(source, /(?:CLOUDFLARE_API_TOKEN|--force|\bfetch\s*\(|client\/v4|method:\s*['"]PUT['"])/u);
    await assert.rejects(
      execFileAsync(process.execPath, [fileURLToPath(script)], {
        env: { PATH: process.env.PATH ?? '' },
        encoding: 'utf8',
      }),
      (error) => {
        assert.equal(error.code, 1);
        assert.match(error.stderr, /^Retired: /u);
        assert.equal(error.stdout, '');
        return true;
      },
    );
  }
});

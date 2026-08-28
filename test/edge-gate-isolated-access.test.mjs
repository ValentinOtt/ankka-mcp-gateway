import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';

import { applyIsolatedAccess, runIsolatedAccessApplyCli } from
  '../apps/installer/scripts/edge-gate/apply-isolated-access.mjs';
import {
  createIsolatedPrivateAccessContract,
} from '../apps/installer/scripts/edge-gate/access-contract.mjs';
import { verifyIsolatedAccess } from
  '../apps/installer/scripts/edge-gate/verify-isolated-access.mjs';

const execFileAsync = promisify(execFile);
const TOKEN = 'A'.repeat(24);
const TARGET = Object.freeze({
  accountId: '1'.repeat(32),
  hostname: 'installer-proof.canary.example.net',
  kind: 'ankka-gateway-deploy-isolated-target',
  oauthClientId: '2'.repeat(32),
  schemaVersion: 1,
  workerName: 'ankka-gateway-deploy-isolated-proof',
});

function sink() {
  let value = '';
  return {
    write(chunk) { value += String(chunk); },
    value() { return value; },
  };
}

function providerBody(result, resultInfo) {
  return new Response(JSON.stringify({
    result,
    ...(resultInfo ? { result_info: resultInfo } : {}),
    success: true,
  }), { status: 200, headers: { 'content-type': 'application/json' } });
}

function providerHarness() {
  const applications = [];
  const calls = [];
  return {
    applications,
    calls,
    async fetch(url, init = {}) {
      calls.push({ body: init.body ?? null, method: init.method ?? 'GET', url });
      const parsed = new URL(url);
      assert.equal(parsed.origin, 'https://api.cloudflare.com');
      assert.doesNotMatch(url, /deploy\.ankka\.ai/u);
      assert.equal(init.headers.authorization, `Bearer ${TOKEN}`);
      if (parsed.pathname.endsWith('/access/apps') && (init.method ?? 'GET') === 'POST') {
        const body = JSON.parse(init.body);
        applications.push({ id: `app-${applications.length + 1}`, ...body });
        return providerBody({ id: applications.at(-1).id });
      }
      if (parsed.pathname.endsWith('/access/apps')) {
        return providerBody(applications, applications.length === 0
          ? { count: 0, page: 1, per_page: 100, total_count: 0, total_pages: 0 }
          : {
              count: applications.length,
              page: 1,
              per_page: 100,
              total_count: applications.length,
              total_pages: 1,
            });
      }
      if (parsed.pathname.endsWith('/access/identity_providers')) {
        return providerBody([{
          id: 'account-member-idp',
          type: 'cloudflare',
          config: { restrict_to_account_members: true },
        }]);
      }
      throw new Error('unexpected provider call');
    },
  };
}

test('isolated Access contract derives exact non-live domains and refuses live', () => {
  const contract = createIsolatedPrivateAccessContract(TARGET.hostname);
  assert.deepEqual(contract.bypassApplications.map(({ domain }) => domain), [
    `${TARGET.hostname}/oauth/callback`,
    `${TARGET.hostname}/api/releases/canary`,
    `${TARGET.hostname}/api/releases/stable`,
  ]);
  assert.equal(contract.privateInstallerApplication.domain, TARGET.hostname);
  assert.throws(
    () => createIsolatedPrivateAccessContract('deploy.ankka.ai'),
    /invalid_isolated_access_host/u,
  );
  assert.throws(
    () => createIsolatedPrivateAccessContract('*.canary.example.net'),
    /invalid_isolated_access_host/u,
  );
});

test('legacy live Access mutator is a credential-free fail-closed stub', async () => {
  const script = new URL(
    '../apps/installer/scripts/edge-gate/apply-access.mjs',
    import.meta.url,
  );
  const source = await readFile(script, 'utf8');
  assert.doesNotMatch(source, /CLOUDFLARE_API_TOKEN|\bfetch\s*\(|client\/v4|method:\s*['"]POST['"]/u);
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
});

test('isolated apply creates bypasses before protection, resumes exactly, and redacts output', async () => {
  const harness = providerHarness();
  const first = await applyIsolatedAccess({
    emails: ['operator@example.com'],
    fetchImpl: harness.fetch,
    readToken: async () => TOKEN,
    sessionDuration: '8h',
    target: TARGET,
  });
  assert.deepEqual(first, {
    applicationCount: 4,
    createdApplications: 4,
    reusedApplications: 0,
    schemaVersion: 1,
    status: 'applied',
  });
  assert.deepEqual(harness.applications.map(({ domain }) => domain), [
    `${TARGET.hostname}/oauth/callback`,
    `${TARGET.hostname}/api/releases/canary`,
    `${TARGET.hostname}/api/releases/stable`,
    TARGET.hostname,
  ]);
  assert.deepEqual(harness.applications.at(-1).allowed_idps, ['account-member-idp']);
  const second = await applyIsolatedAccess({
    emails: ['operator@example.com'],
    fetchImpl: harness.fetch,
    readToken: async () => TOKEN,
    sessionDuration: '8h',
    target: TARGET,
  });
  assert.deepEqual(second, {
    applicationCount: 4,
    createdApplications: 0,
    reusedApplications: 4,
    schemaVersion: 1,
    status: 'applied',
  });
  assert.doesNotMatch(JSON.stringify(first), /operator|example\.com|app-|account-member|1{16}/u);
});

test('isolated verifier proves exact inventory and cookie-free behavior without identifiers', async () => {
  const harness = providerHarness();
  await applyIsolatedAccess({
    emails: ['operator@example.com'],
    fetchImpl: harness.fetch,
    readToken: async () => TOKEN,
    sessionDuration: '8h',
    target: TARGET,
  });
  const behaviorFetch = async (url, init = {}) => {
    if (url.startsWith('https://api.cloudflare.com/')) return harness.fetch(url, init);
    const parsed = new URL(url);
    assert.equal(parsed.hostname, TARGET.hostname);
    assert.equal(init.redirect, 'manual');
    assert.equal(init.credentials, 'omit');
    if (parsed.pathname === '/' || parsed.pathname === '/api/session') {
      return new Response('', {
        status: 302,
        headers: { location: 'https://proof.cloudflareaccess.com/cdn-cgi/access/login' },
      });
    }
    if (parsed.pathname === '/oauth/callback') {
      return new Response('{"code":"session_invalid"}', {
        status: 400,
        headers: { 'content-type': 'application/json; charset=utf-8' },
      });
    }
    if (parsed.pathname === '/api/releases/canary') {
      return new Response(JSON.stringify({
        channel: 'canary',
        classification: {},
        notes: ['synthetic'],
        release: {
          artifactSha256: `sha256:${'a'.repeat(64)}`,
          id: 'gateway-v1.2.3',
          sourceCommit: 'b'.repeat(40),
        },
        schemaVersion: 1,
        verification: {},
      }), { status: 200, headers: { 'content-type': 'application/json' } });
    }
    return new Response('{"code":"release_unavailable"}', {
      status: 404,
      headers: { 'content-type': 'application/json' },
    });
  };
  const result = await verifyIsolatedAccess({
    fetchImpl: behaviorFetch,
    readToken: async () => TOKEN,
    runtimeMode: 'active',
    target: TARGET,
  });
  assert.deepEqual(result, {
    anonymousBehaviorChecks: 5,
    applicationCount: 4,
    identityProviderCount: 1,
    operatorIdentityCount: 1,
    runtimeMode: 'active',
    schemaVersion: 1,
    status: 'verified',
  });
  assert.doesNotMatch(JSON.stringify(result), /example\.net|app-|account-member|1{16}/u);
});

test('isolated verifier distinguishes the exact disabled shell from active callback state', async () => {
  const harness = providerHarness();
  await applyIsolatedAccess({
    emails: ['operator@example.com'],
    fetchImpl: harness.fetch,
    readToken: async () => TOKEN,
    sessionDuration: '8h',
    target: TARGET,
  });
  const disabledFetch = async (url, init = {}) => {
    if (url.startsWith('https://api.cloudflare.com/')) return harness.fetch(url, init);
    const parsed = new URL(url);
    if (parsed.pathname === '/' || parsed.pathname === '/api/session') {
      return new Response('', {
        status: 302,
        headers: { location: 'https://proof.cloudflareaccess.com/cdn-cgi/access/login' },
      });
    }
    return new Response('{"code":"release_unavailable"}', {
      status: 503,
      headers: { 'content-type': 'application/json; charset=utf-8' },
    });
  };
  const result = await verifyIsolatedAccess({
    fetchImpl: disabledFetch,
    readToken: async () => TOKEN,
    runtimeMode: 'disabled',
    target: TARGET,
  });
  assert.equal(result.runtimeMode, 'disabled');

  await assert.rejects(
    verifyIsolatedAccess({
      fetchImpl: disabledFetch,
      readToken: async () => TOKEN,
      runtimeMode: 'active',
      target: TARGET,
    }),
    /callback_boundary_not_verified/u,
  );
});

test('isolated apply rejects extra destination selectors on an otherwise exact app', async () => {
  const harness = providerHarness();
  await applyIsolatedAccess({
    emails: ['operator@example.com'],
    fetchImpl: harness.fetch,
    readToken: async () => TOKEN,
    sessionDuration: '8h',
    target: TARGET,
  });
  harness.applications[0].destinations = [{ uri: `https://*.${TARGET.hostname}/` }];
  await assert.rejects(
    applyIsolatedAccess({
      emails: ['operator@example.com'],
      fetchImpl: harness.fetch,
      readToken: async () => TOKEN,
      sessionDuration: '8h',
      target: TARGET,
    }),
    /access_application_drift/u,
  );
});

test('isolated apply dry-run validates the target before reading credentials or making calls', async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'isolated-access-test-'));
  try {
    const targetFile = path.join(root, 'target.json');
    await writeFile(targetFile, JSON.stringify(TARGET));
    const stdout = sink();
    const stderr = sink();
    let calls = 0;
    const code = await runIsolatedAccessApplyCli({
      argv: ['--target', targetFile, '--email', 'operator@example.com', '--dry-run'],
      fetchImpl: async () => { calls += 1; throw new Error('must not call'); },
      stdin: null,
      stderr,
      stdout,
    });
    assert.equal(code, 0);
    assert.equal(calls, 0);
    assert.equal(stderr.value(), '');
    assert.deepEqual(JSON.parse(stdout.value()), {
      applicationCount: 4,
      operatorIdentityCount: 1,
      schemaVersion: 1,
      status: 'planned',
    });
    assert.doesNotMatch(stdout.value(), /operator@example\.com|1{16}/u);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

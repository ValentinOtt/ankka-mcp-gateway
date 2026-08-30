import * as v from 'valibot';
import { afterEach, beforeAll, describe, expect, it, vi } from 'vitest';

import * as cloudflareTarget from '../src/cloudflare-target';
import { CloudflareDirectUploadError } from '../src/cloudflare-worker-direct-upload';
import { OAUTH_COOKIE, PUBLIC_ORIGIN, REQUIRED_OAUTH_SCOPES, SESSION_COOKIE } from '../src/constants';
import { base64UrlEncode, deriveCsrfToken, openOauthCookie, sha256 } from '../src/crypto';
import { DeployError } from '../src/errors';
import { createGatewayDeployWorker, type GatewayDeployWorkerDependencies } from '../src/index';
import * as oauthModule from '../src/oauth';
import * as runtimeRelay from '../src/runtime-update-relay';
import { buildStaticDeployPlan, parseDeploySelection } from '../src/schema';
import type { StoredDeploySession } from '../src/session';
import * as sourceRelay from '../src/source-action-relay';
import { responseJson } from './boundary';
import { cookiePair, env, FakeDeploySessionNamespace, requiredFixture, selectionInput } from './fixtures';
import { sourceActionRuntimeFixture, type SourceActionRuntimeFixture } from './source-action-runtime-fixture';

const NOW = Date.UTC(2026, 7, 26, 1, 0, 0);
const ACCOUNT_ID = 'a'.repeat(32);
const ACTION_ID = 'action_' + 'A'.repeat(32);
const ACTION_KEY = 'BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc';
const SESSION_ID = 'S'.repeat(43);
const SESSION_PAIR = SESSION_COOKIE + '=' + SESSION_ID;
const MANAGEMENT_ORIGIN = 'https://manage.example.com';
const ACCESS_TOKEN = 'ephemeral-management-callback-test-token';
type Flow = 'source' | 'runtime';
let runtime: SourceActionRuntimeFixture;

beforeAll(async () => {
  runtime = await sourceActionRuntimeFixture({
    accountId: ACCOUNT_ID,
    actorEmail: 'admin@example.com',
    managementHostname: 'manage.example.com',
    workerId: 'b'.repeat(32),
    workerName: 'ankka-gateway-example',
    workersSubdomain: 'customer-workers',
  });
});

afterEach(() => vi.restoreAllMocks());

async function fixture(flow: Flow, overrides: GatewayDeployWorkerDependencies = {}) {
  const namespace = new FakeDeploySessionNamespace(() => NOW);
  const workerEnv = env(namespace);
  namespace.get(namespace.idFromName(SESSION_ID));
  const storage = requiredFixture(namespace.states.get(SESSION_ID), 'retained session').storage;
  const selection = parseDeploySelection(selectionInput);
  const retained: StoredDeploySession = {
    schemaVersion: 1,
    status: 'succeeded',
    csrfHash: await sha256(await deriveCsrfToken(workerEnv.DEPLOY_SESSION_ENCRYPTION_KEY, SESSION_ID)),
    createdAt: NOW - 60_000,
    updatedAt: NOW - 1_000,
    expiresAt: NOW + 20 * 60_000,
    selection,
    plan: await buildStaticDeployPlan(selection, runtime.bundle.manifest, NOW + 10 * 60_000),
    oauthAttempt: null,
    result: {
      code: 'install_complete',
      completedAt: NOW - 1_000,
      grantRevocation: 'confirmed',
      installationId: 'acg-' + 'c'.repeat(24),
    },
  };
  await storage.put('deploy-session-v1', retained);
  const source = vi.spyOn(sourceRelay, 'relaySourceAction').mockResolvedValue({
    schemaVersion: 1, actionId: ACTION_ID, status: 'succeeded',
    managementUrl: MANAGEMENT_ORIGIN + '/?sourceAction=' + ACTION_ID,
  });
  const update = vi.spyOn(runtimeRelay, 'relayRuntimeUpdate').mockResolvedValue({
    schemaVersion: 1, actionId: ACTION_ID, operation: 'update', status: 'succeeded',
    managementUrl: MANAGEMENT_ORIGIN + '/?runtimeAction=' + ACTION_ID,
  });
  const calls = { exchanged: 0, revoked: 0 };
  const worker = createGatewayDeployWorker({
    now: () => NOW,
    exactReleaseProvider: { loadVerifiedReleaseBundleForIdentity: async () => runtime.bundle },
    releaseProvider: {
      loadVerifiedRelease: async () => runtime.bundle,
      loadVerifiedReleaseBundle: async () => runtime.bundle,
    },
    transport: async (input, init) => {
      const request = new Request(input, init);
      const url = new URL(request.url);
      if (url.pathname === '/oauth2/token') {
        calls.exchanged += 1;
        return Response.json({
          access_token: ACCESS_TOKEN, token_type: 'Bearer', scope: REQUIRED_OAUTH_SCOPES.join(' '),
        });
      }
      if (url.pathname === '/oauth2/revoke') {
        calls.revoked += 1;
        return Response.json({});
      }
      if (url.pathname === '/client/v4/user') {
        return Response.json({ success: true, result: { id: 'user-identifier', email: 'admin@example.com' } });
      }
      if (url.pathname === '/client/v4/accounts') {
        return Response.json({ success: true, result: [{ id: ACCOUNT_ID, name: 'Example account' }] });
      }
      throw new Error('unexpected synthetic provider request');
    },
    managementCallbackResponse: async ({ execute }) => {
      await execute();
      return new Response('<!doctype html><title>Management action</title>', {
        headers: { 'content-type': 'text/html; charset=utf-8' },
      });
    },
    ...overrides,
  });
  const prior = await worker.fetch(new Request(PUBLIC_ORIGIN + '/api/session', {
    headers: { cookie: SESSION_PAIR },
  }), workerEnv);
  expect(prior.status).toBe(200);
  expect(await prior.json()).toMatchObject({ deployment: { status: 'succeeded' } });
  const before = namespace.serialized();
  const sessionReads = vi.spyOn(namespace, 'get');
  const shared = {
    actionId: ACTION_ID, actionKey: ACTION_KEY, actorEmail: 'admin@example.com', accountId: ACCOUNT_ID,
    controlPlaneOrigin: PUBLIC_ORIGIN, workerName: 'ankka-gateway-example', workersSubdomain: 'customer-workers',
    managementOrigin: MANAGEMENT_ORIGIN, expiresAt: NOW + 10 * 60_000,
  };
  const claim = flow === 'source'
    ? { schemaVersion: 1, ...shared, releaseIdentity: runtime.identity }
    : {
        schemaVersion: 2, actionType: 'runtime_update', ...shared, operation: 'update',
        from: { release: 'gateway-v0.9.0', artifactSha256: 'sha256:' + 'f'.repeat(64), versionId: null },
        to: {
          release: runtime.bundle.manifest.release,
          artifactSha256: 'sha256:' + runtime.bundle.manifest.artifact.treeSha256,
          versionId: null,
        },
      };
  const authorize = await worker.fetch(new Request(PUBLIC_ORIGIN + '/api/management/authorize', {
    method: 'POST',
    headers: { cookie: SESSION_PAIR, origin: PUBLIC_ORIGIN, 'content-type': 'application/json' },
    body: JSON.stringify({ handoff: base64UrlEncode(new TextEncoder().encode(JSON.stringify(claim))) }),
  }), workerEnv);
  expect(authorize.status).toBe(200);
  const payload = await responseJson(authorize, v.object({ authorizationUrl: v.string() }));
  const state = new URL(payload.authorizationUrl).searchParams.get('state');
  if (!state) throw new TypeError('missing synthetic OAuth state');
  const oauth = cookiePair(authorize.headers.get('set-cookie') ?? '', OAUTH_COOKIE);
  return {
    calls, source, update, worker, workerEnv, oauth,
    callback: (denied = false) => worker.fetch(new Request(
      PUBLIC_ORIGIN + '/oauth/callback?' +
        (denied ? 'error=access_denied' : 'code=authorization-code-value') + '&state=' + state,
      { headers: { cookie: SESSION_PAIR + '; ' + oauth } },
    ), workerEnv),
    assertRetained: (response: Response) => {
      expect(sessionReads).not.toHaveBeenCalled();
      expect(namespace.serialized()).toBe(before);
      expect(response.headers.get('set-cookie')).not.toContain(SESSION_COOKIE + '=');
    },
  };
}

describe.each(['source', 'runtime'] as const)('%s management callback with a retained install result', (flow) => {
  it('shows canceled consent without loading the previous successful install', async () => {
    const current = await fixture(flow);
    const response = await current.callback(true);
    expect(response.status).toBe(400);
    expect(response.headers.get('location')).toBeNull();
    expect(response.headers.get('set-cookie')).toContain(OAUTH_COOKIE + '=;');
    expect(await response.json()).toEqual({ code: 'oauth_denied' });
    expect(current.calls).toEqual({ exchanged: 0, revoked: 0 });
    expect(current.source).not.toHaveBeenCalled();
    expect(current.update).not.toHaveBeenCalled();
    current.assertRetained(response);
  });

  it('returns the current action failure without redirecting to the previous successful install', async () => {
    const current = await fixture(flow);
    const relay = flow === 'source' ? current.source : current.update;
    relay.mockRejectedValue(new DeployError(409, 'session_conflict'));
    const response = await current.callback();
    expect(response.status).toBe(409);
    expect(response.headers.get('location')).toBeNull();
    expect(response.headers.get('set-cookie')).toContain(OAUTH_COOKIE + '=;');
    expect(await response.json()).toEqual({ code: 'session_conflict', reason: `${flow}_action_relay` });
    expect(current.calls).toEqual({ exchanged: 1, revoked: 1 });
    expect(relay).toHaveBeenCalledTimes(1);
    current.assertRetained(response);
  });

  it('keeps callback-shell failures bounded after the action and grant cleanup finish', async () => {
    const current = await fixture(flow, {
      managementCallbackResponse: async () => {
        throw new Error('synthetic-private-provider-body:' + ACCESS_TOKEN);
      },
    });
    const response = await current.callback();
    expect(response.status).toBe(500);
    expect(response.headers.get('location')).toBeNull();
    expect(response.headers.get('set-cookie')).toContain(OAUTH_COOKIE + '=;');
    expect(await response.json()).toEqual({ code: 'internal_error', reason: `${flow}_callback_shell` });
    expect(current.calls).toEqual({ exchanged: 1, revoked: 1 });
    expect(flow === 'source' ? current.source : current.update).toHaveBeenCalledTimes(1);
    current.assertRetained(response);
  });

  it('completes the current action once and returns only verified management context', async () => {
    const current = await fixture(flow);
    const response = await current.callback();
    expect(response.status).toBe(200);
    expect(response.headers.get('location')).toBeNull();
    expect(current.calls).toEqual({ exchanged: 1, revoked: 1 });
    expect(flow === 'source' ? current.source : current.update).toHaveBeenCalledTimes(1);
    current.assertRetained(response);
    const verified = cookiePair(response.headers.get('set-cookie') ?? '', OAUTH_COOKIE);
    expect(verified).not.toBe(current.oauth);
    const sealed = await openOauthCookie(
      current.workerEnv.DEPLOY_SESSION_ENCRYPTION_KEY, verified.slice(OAUTH_COOKIE.length + 1),
    );
    expect(sealed).toMatchObject({
      schemaVersion: 9, purpose: 'management_action_result',
      actionType: flow === 'source' ? 'source_apply' : 'runtime_update', actionId: ACTION_ID,
    });
    const context = await current.worker.fetch(new Request(PUBLIC_ORIGIN + '/api/management/context', {
      headers: { cookie: SESSION_PAIR + '; ' + verified },
    }), current.workerEnv);
    expect(context.status).toBe(200);
    expect(await context.json()).toMatchObject({
      actionId: ACTION_ID,
      managementUrl: MANAGEMENT_ORIGIN + '/?' + (flow === 'source' ? 'sourceAction=' : 'runtimeAction=') + ACTION_ID,
    });
    current.assertRetained(context);
  });
});

describe.each(['source', 'runtime'] as const)('fixed %s callback phase diagnostics', (flow) => {
  it('reports release verification without exchanging or relaying a grant', async () => {
    const failRelease = async () => { throw new DeployError(409, 'session_conflict'); };
    const current = await fixture(flow, flow === 'source' ? {
      exactReleaseProvider: {
        loadVerifiedReleaseBundleForIdentity: failRelease,
      },
    } : {
      releaseProvider: { loadVerifiedRelease: async () => runtime.bundle, loadVerifiedReleaseBundle: failRelease },
    });
    const response = await current.callback();
    expect(response.status).toBe(409);
    expect(response.headers.get('set-cookie')).toContain(OAUTH_COOKIE + '=;');
    expect(await response.json()).toEqual({ code: 'session_conflict', reason: `${flow}_release_verification` });
    expect(current.calls).toEqual({ exchanged: 0, revoked: 0 });
    expect(current.source).not.toHaveBeenCalled();
    expect(current.update).not.toHaveBeenCalled();
    current.assertRetained(response);
  });

  it('reports grant exchange without using exception text', async () => {
    const current = await fixture(flow);
    vi.spyOn(oauthModule, 'exchangeAuthorizationCode').mockRejectedValue(new Error(ACCESS_TOKEN));
    const response = await current.callback();
    expect(response.status).toBe(500);
    expect(response.headers.get('set-cookie')).toContain(OAUTH_COOKIE + '=;');
    expect(await response.json()).toEqual({ code: 'internal_error', reason: `${flow}_grant_exchange` });
    expect(current.calls).toEqual({ exchanged: 0, revoked: 0 });
    expect(current.source).not.toHaveBeenCalled();
    expect(current.update).not.toHaveBeenCalled();
    current.assertRetained(response);
  });

  it('reports account authorization and revokes the exchanged grant', async () => {
    const current = await fixture(flow);
    vi.spyOn(cloudflareTarget, 'resolveAuthorizedAccount').mockRejectedValue(new DeployError(403, 'oauth_grant_invalid'));
    const response = await current.callback();
    expect(response.status).toBe(403);
    expect(response.headers.get('set-cookie')).toContain(OAUTH_COOKIE + '=;');
    expect(await response.json()).toEqual({ code: 'oauth_grant_invalid', reason: `${flow}_account_authorization` });
    expect(current.calls).toEqual({ exchanged: 1, revoked: 1 });
    expect(current.source).not.toHaveBeenCalled();
    expect(current.update).not.toHaveBeenCalled();
    current.assertRetained(response);
  });

  it('preserves an existing bounded diagnostic instead of replacing it with the phase', async () => {
    const current = await fixture(flow);
    const relay = flow === 'source' ? current.source : current.update;
    relay.mockRejectedValue(new DeployError(504, 'oauth_exchange_failed', 'customer_action_route_timeout'));
    const response = await current.callback();
    expect(response.status).toBe(504);
    expect(response.headers.get('set-cookie')).toContain(OAUTH_COOKIE + '=;');
    expect(await response.json()).toEqual({ code: 'oauth_exchange_failed', reason: 'customer_action_route_timeout' });
    expect(current.calls).toEqual({ exchanged: 1, revoked: 1 });
    expect(relay).toHaveBeenCalledTimes(1);
    current.assertRetained(response);
  });
});

function uploadError() {
  const error = new CloudflareDirectUploadError('provider_rejected', 'worker_version', 'rejected', {
    workerCreated: false,
    workerVerified: false,
    assetSessionCreated: true,
    assetBucketsCompleted: 1,
    assetBucketCount: 1,
    versionCreated: false,
    deploymentVerified: false,
  }, [{ kind: 'worker', accountId: ACCOUNT_ID, workerName: 'synthetic-private-worker', workerId: 'd'.repeat(32) }]);
  error.message = 'synthetic-private-provider-body:' + ACCESS_TOKEN;
  return error;
}

describe('closed runtime upload diagnostics', () => {
  it.each([
    ['invalid_input', 'validate', 'not_sent'],
    ['provider_unknown', 'asset_session', 'unknown'],
    ['provider_rejected', 'asset_bucket', 'rejected'],
    ['provider_rejected', 'worker_version', 'rejected'],
    ['provider_mismatch', 'version_verify', 'submitted'],
  ] as const)('reports only the reviewed upload vocabulary (%s/%s/%s)', async (code, stage, outcome) => {
    const current = await fixture('runtime');
    const error = uploadError();
    Object.assign(error, { code, stage, outcome });
    current.update.mockRejectedValue(error);
    const response = await current.callback();
    expect(response.status).toBe(500);
    expect(response.headers.get('location')).toBeNull();
    expect(response.headers.get('set-cookie')).toContain(OAUTH_COOKIE + '=;');
    expect(await response.json()).toEqual({
      code: 'internal_error', reason: `runtime_upload_${code}_${stage}_${outcome}`,
    });
    expect(current.calls).toEqual({ exchanged: 1, revoked: 1 });
    expect(current.update).toHaveBeenCalledTimes(1);
    expect(current.source).not.toHaveBeenCalled();
    current.assertRetained(response);
  });

  it.each(['code', 'stage', 'outcome'] as const)('refuses an unreviewed upload %s', async (field) => {
    const current = await fixture('runtime');
    const error = uploadError();
    // Valid diagnostic syntax is not enough: only the reviewed enum is public.
    Object.assign(error, { [field]: 'synthetic_private_value' });
    current.update.mockRejectedValue(error);
    const response = await current.callback();
    expect(response.status).toBe(500);
    expect(response.headers.get('set-cookie')).toContain(OAUTH_COOKIE + '=;');
    expect(await response.json()).toEqual({ code: 'internal_error', reason: 'runtime_action_relay' });
    expect(current.calls).toEqual({ exchanged: 1, revoked: 1 });
    expect(current.update).toHaveBeenCalledTimes(1);
    current.assertRetained(response);
  });

  it('does not trust diagnostic-looking properties on an ordinary error', async () => {
    const current = await fixture('runtime');
    current.update.mockRejectedValue(Object.assign(new Error(ACCESS_TOKEN), {
      code: 'provider_rejected', stage: 'worker_version', outcome: 'rejected',
    }));
    const response = await current.callback();
    expect(await response.json()).toEqual({ code: 'internal_error', reason: 'runtime_action_relay' });
    expect(current.calls).toEqual({ exchanged: 1, revoked: 1 });
    expect(current.update).toHaveBeenCalledTimes(1);
    current.assertRetained(response);
  });

  it('leaves source callback diagnostics unchanged for the same upload error', async () => {
    const current = await fixture('source');
    current.source.mockRejectedValue(uploadError());
    const response = await current.callback();
    expect(await response.json()).toEqual({ code: 'internal_error', reason: 'source_action_relay' });
    expect(current.calls).toEqual({ exchanged: 1, revoked: 1 });
    expect(current.source).toHaveBeenCalledTimes(1);
    current.assertRetained(response);
  });
});

describe('bounded runtime control callback diagnostics', () => {
  it.each([
    'runtime_candidate_probe_version_mismatch',
    'runtime_candidate_probe_timeout',
    'runtime_progress_candidate_staged_action_conflict',
    'runtime_candidate_stage_verify',
    'runtime_route_disable_failed',
  ])('preserves %s while revoking the grant once and retaining the prior install', async (reason) => {
    const current = await fixture('runtime');
    const error = new DeployError(409, 'session_conflict', reason);
    error.message = `synthetic-private-control:${ACCESS_TOKEN}`;
    current.update.mockRejectedValue(error);
    const response = await current.callback();
    expect(response.status).toBe(409);
    expect(response.headers.get('location')).toBeNull();
    expect(response.headers.get('set-cookie')).toContain(OAUTH_COOKIE + '=;');
    expect(await response.json()).toEqual({ code: 'session_conflict', reason });
    expect(current.calls).toEqual({ exchanged: 1, revoked: 1 });
    expect(current.update).toHaveBeenCalledTimes(1);
    expect(current.source).not.toHaveBeenCalled();
    current.assertRetained(response);
  });

  it('does not surface a diagnostic-looking reason on an untrusted ordinary exception', async () => {
    const current = await fixture('runtime');
    current.update.mockRejectedValue(Object.assign(new Error(ACCESS_TOKEN), {
      status: 409, code: 'session_conflict', reason: 'runtime_candidate_probe_version_mismatch',
    }));
    const response = await current.callback();
    expect(response.status).toBe(500);
    expect(response.headers.get('set-cookie')).toContain(OAUTH_COOKIE + '=;');
    expect(await response.json()).toEqual({ code: 'internal_error', reason: 'runtime_action_relay' });
    expect(current.calls).toEqual({ exchanged: 1, revoked: 1 });
    expect(current.update).toHaveBeenCalledTimes(1);
    current.assertRetained(response);
  });
});

import assert from 'node:assert/strict';
import test from 'node:test';

import { publishBootstrapCompletion } from '../payload/worker/index.js';
import { cloudflareProvider, goldenClaim, installReadyGateway } from './payload-lifecycle.mjs';

const STATUS_KEY = 'ankka-mcp-gateway/public-status/v1';
const CONTROL_KEY = 'ankka-mcp-gateway/management-control/v1';
const SOURCES_KEY = 'ankka-mcp-gateway/management-sources/v1';

// The Stage 1 shell runs the bootstrap in the installation object itself and
// then has to publish what the public bootstrap route publishes into the
// management object afterwards. The fifth real install of 2026-09-04 skipped
// this and its management API answered "unavailable".

test('the shell publishes the same status and control the public route publishes after a ready bootstrap', async () => {
  const objects = new Map();
  const { env, body } = await installReadyGateway({ provider: cloudflareProvider(), objects, claimInput: goldenClaim() });
  const route = objects.get('v1:management');
  assert.ok(route, 'the public route publishes into the management object');
  const routeStatus = route.storage.snapshot(STATUS_KEY);
  const routeControl = route.storage.snapshot(CONTROL_KEY);
  assert.equal(routeStatus?.status, 'ready');
  assert.ok(routeControl);

  const shell = env.ADMIN_STATE.get('v1:shell-management');
  const published = await publishBootstrapCompletion(goldenClaim('B'.repeat(22)), body, env, Date.now(), (request) => shell.fetch(request));
  assert.equal(published, true);
  const shellObject = objects.get('v1:shell-management');
  const shellStatus = shellObject.storage.snapshot(STATUS_KEY);
  assert.deepEqual({ ...shellStatus, updatedAt: null }, { ...routeStatus, updatedAt: null });
  assert.deepEqual(shellObject.storage.snapshot(CONTROL_KEY), routeControl);
  assert.deepEqual(shellObject.storage.snapshot(SOURCES_KEY), route.storage.snapshot(SOURCES_KEY));

  // The management API reads exactly these through the object's internal routes.
  for (const path of ['/status', '/sources', '/management-control']) {
    const response = await shell.fetch(new Request(`https://admin-state.invalid${path}`));
    assert.equal(response.status, 200, path);
  }
});

test('the publication refuses a claim, environment or ready body the payload does not accept, and a refused write', async () => {
  const objects = new Map();
  const { env, body } = await installReadyGateway({ provider: cloudflareProvider(), objects, claimInput: goldenClaim() });
  const sink = { calls: 0, fetch: async () => { sink.calls += 1; return Response.json({ ok: true }); } };
  assert.equal(await publishBootstrapCompletion(goldenClaim(), { status: 'recovery_required' }, env, Date.now(), sink.fetch), false);
  assert.equal(await publishBootstrapCompletion({ ...goldenClaim(), expiresAt: 1 }, body, env, Date.now(), sink.fetch), false);
  assert.equal(await publishBootstrapCompletion(goldenClaim(), body, {}, Date.now(), sink.fetch), false);
  assert.equal(sink.calls, 0);
  const refusing = async () => Response.json({ schemaVersion: 1, error: 'invalid_status' }, { status: 400 });
  assert.equal(await publishBootstrapCompletion(goldenClaim(), body, env, Date.now(), refusing), false);
  const throwing = async () => { throw new Error('object unreachable'); };
  assert.equal(await publishBootstrapCompletion(goldenClaim(), body, env, Date.now(), throwing), false);
});

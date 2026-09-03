import assert from 'node:assert/strict';
import { describe, it } from 'vitest';

import { REQUIRED_OAUTH_SCOPES } from '../src/constants';
import {
  OAuthScopeCatalogueError,
  REQUIRED_SCOPE_IDS,
  verifyOAuthScopeCatalogue,
} from '../scripts/verify-oauth-scope-catalogue.mjs';

const TOKEN = 'a'.repeat(40);

function response(ids, status = 200) {
  return new Response(JSON.stringify({
    errors: [],
    messages: [],
    result: ids.map((id) => ({ category: 'synthetic', id, name: id, scopes: [] })),
    success: status === 200,
  }), { status, headers: { 'content-type': 'application/json' } });
}

describe('live OAuth scope catalogue verification', () => {
  it('keeps the script scope list identical to the reviewed runtime manifest', () => {
    assert.deepEqual(REQUIRED_SCOPE_IDS, REQUIRED_OAUTH_SCOPES);
  });

  it('uses one fixed read-only endpoint and reports only counts', async () => {
    const calls = [];
    const result = await verifyOAuthScopeCatalogue({
      readToken: async () => TOKEN,
      fetchImpl: async (url, init) => {
        calls.push({ url, init });
        return response([...REQUIRED_SCOPE_IDS, 'unrelated.read']);
      },
    });
    assert.deepEqual(result, {
      catalogueScopeCount: 8,
      requiredScopeCount: 7,
      schemaVersion: 1,
      status: 'verified',
    });
    assert.equal(calls.length, 1);
    assert.equal(calls[0].url, 'https://api.cloudflare.com/client/v4/oauth/scopes');
    assert.equal(calls[0].init.method, 'GET');
    assert.equal(calls[0].init.headers.authorization, `Bearer ${TOKEN}`);
  });

  it('fails closed with fixed diagnostics when a required scope or response is invalid', async () => {
    await assert.rejects(
      verifyOAuthScopeCatalogue({
        readToken: async () => TOKEN,
        fetchImpl: async () => response(REQUIRED_SCOPE_IDS.slice(1)),
      }),
      (error) => error instanceof OAuthScopeCatalogueError &&
        error.code === 'oauth_scope_catalogue_required_scope_missing',
    );
    await assert.rejects(
      verifyOAuthScopeCatalogue({
        readToken: async () => TOKEN,
        fetchImpl: async () => new Response('provider secret body', { status: 500 }),
      }),
      (error) => error instanceof OAuthScopeCatalogueError &&
        error.code === 'oauth_scope_catalogue_unavailable' &&
        !error.message.includes('provider secret body'),
    );
  });
});

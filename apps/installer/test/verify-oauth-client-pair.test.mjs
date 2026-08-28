import { describe, expect, it, vi } from 'vitest';

import {
  OauthClientPairPreflightError,
  runOauthClientPairPreflightCli,
  verifyOauthClientPair,
} from '../scripts/verify-oauth-client-pair.mjs';

const CLIENT_ID = 'a'.repeat(32);
const CLIENT_SECRET = 'synthetic-client-secret-value';

function output() {
  let value = '';
  return {
    stream: { write: (chunk) => { value += chunk; } },
    read: () => value,
  };
}

describe('OAuth client credential preflight', () => {
  it('accepts only an authenticated client rejected for the deliberately invalid grant', async () => {
    const transport = vi.fn(async (_url, init) => {
      expect(init.method).toBe('POST');
      expect(init.redirect).toBe('manual');
      expect(Buffer.from(init.headers.authorization.slice('Basic '.length), 'base64').toString('utf8'))
        .toBe(`${CLIENT_ID}:${CLIENT_SECRET}`);
      expect(String(init.body)).toContain('code=ankka_oauth_client_pair_preflight_invalid_code');
      return new Response(JSON.stringify({ error: 'invalid_grant' }), {
        status: 400,
        headers: { 'content-type': 'application/json' },
      });
    });
    await expect(verifyOauthClientPair({
      clientId: CLIENT_ID,
      readClientSecret: async () => CLIENT_SECRET,
      transport,
    })).resolves.toEqual({
      schemaVersion: 1,
      status: 'verified',
      clientId: CLIENT_ID,
      tokenEndpoint: 'https://dash.cloudflare.com/oauth2/token',
      proof: 'authenticated_client_rejected_invalid_code',
    });
  });

  it('reports a fixed mismatch without surfacing provider descriptions or the secret', async () => {
    const providerDescription = `wrong ${CLIENT_SECRET}`;
    await expect(verifyOauthClientPair({
      clientId: CLIENT_ID,
      readClientSecret: async () => CLIENT_SECRET,
      transport: async () => new Response(JSON.stringify({
        error: 'invalid_client',
        error_description: providerDescription,
      }), { status: 401 }),
    })).rejects.toEqual(expect.objectContaining({
      name: 'OauthClientPairPreflightError',
      code: 'client_credentials_mismatch',
    }));
    try {
      await verifyOauthClientPair({
        clientId: CLIENT_ID,
        readClientSecret: async () => CLIENT_SECRET,
        transport: async () => new Response(providerDescription, { status: 401 }),
      });
    } catch (error) {
      expect(error).toBeInstanceOf(OauthClientPairPreflightError);
      expect(String(error)).not.toContain(CLIENT_SECRET);
      expect(String(error)).not.toContain(providerDescription);
    }
  });

  it('keeps CLI output secret-free for success, mismatch, and malformed input', async () => {
    const successOut = output();
    const successErr = output();
    const success = await runOauthClientPairPreflightCli({
      argv: ['--client-id', CLIENT_ID, '--client-secret-stdin'],
      stdin: (async function* () { yield Buffer.from(`${CLIENT_SECRET}\n`); }()),
      stdout: successOut.stream,
      stderr: successErr.stream,
      transport: async () => new Response(JSON.stringify({ error: 'invalid_grant' }), { status: 400 }),
    });
    expect(success).toBe(0);
    expect(successOut.read()).toContain('"status":"verified"');
    expect(successOut.read()).not.toContain(CLIENT_SECRET);
    expect(successErr.read()).toBe('');

    const mismatchOut = output();
    const mismatchErr = output();
    const mismatch = await runOauthClientPairPreflightCli({
      argv: ['--client-id', CLIENT_ID, '--client-secret-stdin'],
      stdin: (async function* () { yield Buffer.from(`${CLIENT_SECRET}\n`); }()),
      stdout: mismatchOut.stream,
      stderr: mismatchErr.stream,
      transport: async () => new Response(JSON.stringify({
        error: 'invalid_client', error_description: CLIENT_SECRET,
      }), { status: 401 }),
    });
    expect(mismatch).toBe(1);
    expect(mismatchOut.read()).toBe('');
    expect(mismatchErr.read()).toBe('OAuth client credential preflight failed: client_credentials_mismatch.\n');
    expect(mismatchErr.read()).not.toContain(CLIENT_SECRET);

    const malformedOut = output();
    const malformedErr = output();
    const malformed = await runOauthClientPairPreflightCli({
      argv: ['--client-id', 'bad', '--client-secret-stdin'],
      stdin: (async function* () {})(),
      stdout: malformedOut.stream,
      stderr: malformedErr.stream,
    });
    expect(malformed).toBe(1);
    expect(malformedOut.read()).toBe('');
    expect(malformedErr.read()).toBe('OAuth client credential preflight failed: input_invalid.\n');
  });
});

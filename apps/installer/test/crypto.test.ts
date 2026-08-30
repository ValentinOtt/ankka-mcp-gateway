import { describe, expect, it } from 'vitest';

import {
  base64UrlEncode,
  deriveCsrfToken,
  openOauthCookie,
  sealOauthCookie,
} from '../src/crypto';
import {
  clearOauthCookie,
  oauthCookie,
  parseCookies,
  sessionCookie,
} from '../src/cookies';
import { PUBLIC_ORIGIN } from '../src/constants';
import { ENCRYPTION_KEY, NOW } from './fixtures';

describe('opaque and sealed cookies', () => {
  const payload = {
    schemaVersion: 2 as const,
    purpose: 'install' as const,
    sessionId: base64UrlEncode(new Uint8Array(32).fill(1)),
    attemptId: `att_${base64UrlEncode(new Uint8Array(24).fill(2))}`,
    verifier: base64UrlEncode(new Uint8Array(32).fill(3)),
    expiresAt: NOW + 600_000,
  };

  it('round trips the verifier only through authenticated encryption', async () => {
    const sealed = await sealOauthCookie(ENCRYPTION_KEY, payload);
    expect(sealed).not.toContain(payload.verifier);
    await expect(openOauthCookie(ENCRYPTION_KEY, sealed)).resolves.toEqual(payload);
  });

  it('rejects tampering and a different encryption key', async () => {
    const sealed = await sealOauthCookie(ENCRYPTION_KEY, payload);
    const tampered = `${sealed.slice(0, -1)}${sealed.endsWith('A') ? 'B' : 'A'}`;
    await expect(openOauthCookie(ENCRYPTION_KEY, tampered)).rejects.toMatchObject({ code: 'session_invalid' });
    await expect(openOauthCookie(base64UrlEncode(new Uint8Array(32).fill(9)), sealed))
      .rejects.toMatchObject({ code: 'session_invalid' });
  });

  it('binds the exact OAuth operation purpose into the sealed payload', async () => {
    const uninstall = { ...payload, purpose: 'uninstall' as const };
    const sealed = await sealOauthCookie(ENCRYPTION_KEY, uninstall);
    await expect(openOauthCookie(ENCRYPTION_KEY, sealed)).resolves.toEqual(uninstall);
  });

  it('round trips the v3 cross-browser handoff state inside authenticated encryption', async () => {
    const handoff = {
      ...payload,
      schemaVersion: 3 as const,
      state: base64UrlEncode(new Uint8Array(32).fill(4)),
    };
    const sealed = await sealOauthCookie(ENCRYPTION_KEY, handoff);
    expect(sealed).not.toContain(handoff.state);
    expect(sealed).not.toContain(handoff.verifier);
    await expect(openOauthCookie(ENCRYPTION_KEY, sealed)).resolves.toEqual(handoff);
  });

  it('seals the exact v4 source release authority and rejects missing or widened identities', async () => {
    const source = {
      schemaVersion: 4 as const,
      purpose: 'source_apply' as const,
      state: base64UrlEncode(new Uint8Array(32).fill(4)),
      verifier: base64UrlEncode(new Uint8Array(32).fill(5)),
      expiresAt: NOW + 600_000,
      actionId: `action_${'A'.repeat(32)}`,
      actionKey: base64UrlEncode(new Uint8Array(32).fill(6)),
      actorEmail: 'owner@example.com',
      accountId: 'a'.repeat(32),
      workerName: 'ankka-gateway-example',
      workersSubdomain: 'customer-workers',
      managementOrigin: 'https://manage.example.com',
      releaseIdentity: {
        schemaVersion: 1 as const,
        channel: 'canary' as const,
        controlPlaneOrigin: PUBLIC_ORIGIN,
        release: 'gateway-v1.0.0',
        keyId: 'release-key-1',
        publicKey: 'B'.repeat(43),
        artifactSha256: 'c'.repeat(64),
      },
    };
    const sealed = await sealOauthCookie(ENCRYPTION_KEY, source);
    expect(sealed).not.toContain(source.actionKey);
    expect(sealed).not.toContain(source.releaseIdentity.publicKey);
    expect(sealed).not.toContain(source.releaseIdentity.artifactSha256);
    await expect(openOauthCookie(ENCRYPTION_KEY, sealed)).resolves.toEqual(source);

    const access = { ...source, action: 'access' as const };
    const sealedAccess = await sealOauthCookie(ENCRYPTION_KEY, access);
    await expect(openOauthCookie(ENCRYPTION_KEY, sealedAccess)).resolves.toEqual(access);

    const { releaseIdentity: _releaseIdentity, ...missingIdentity } = source;
    for (const invalid of [
      missingIdentity,
      { ...source, action: 'source' },
      { ...access, action: 'runtime_update' },
      { ...access, audienceEmails: ['member@example.com'] },
      { ...source, releaseIdentity: { ...source.releaseIdentity, copiedAuthority: true } },
      { ...source, releaseIdentity: { ...source.releaseIdentity, artifactSha256: `sha256:${'c'.repeat(64)}` } },
    ]) {
      await expect(sealOauthCookie(ENCRYPTION_KEY, invalid))
        .rejects.toMatchObject({ code: 'session_invalid' });
    }
  });

  it('round trips the v6 teardown review and v7 teardown attempt without exposing their one-time action key', async () => {
    const review = {
      schemaVersion: 6 as const,
      purpose: 'gateway_teardown_review' as const,
      sessionId: base64UrlEncode(new Uint8Array(32).fill(5)),
      expiresAt: NOW + 600_000,
      actionId: `action_${'A'.repeat(32)}`,
      actionKey: base64UrlEncode(new Uint8Array(32).fill(6)),
      actorEmail: 'owner@example.com',
      accountId: 'a'.repeat(32),
      installationId: `acg-${'b'.repeat(24)}`,
      gatewayName: 'Example Gateway',
      portalHostname: 'mcp.example.com',
      workerName: 'ankka-gateway-example',
      workersSubdomain: 'customer-workers',
      managementOrigin: 'https://manage.example.com',
    };
    const attempt = {
      ...review,
      schemaVersion: 7 as const,
      purpose: 'gateway_teardown' as const,
      attemptId: `att_${'C'.repeat(32)}`,
      state: base64UrlEncode(new Uint8Array(32).fill(7)),
      verifier: base64UrlEncode(new Uint8Array(32).fill(8)),
    };

    const sealedReview = await sealOauthCookie(ENCRYPTION_KEY, review);
    const sealedAttempt = await sealOauthCookie(ENCRYPTION_KEY, attempt);
    expect(sealedReview).not.toContain(review.actionKey);
    expect(sealedAttempt).not.toContain(attempt.actionKey);
    expect(sealedAttempt).not.toContain(attempt.verifier);
    await expect(openOauthCookie(ENCRYPTION_KEY, sealedReview)).resolves.toEqual(review);
    await expect(openOauthCookie(ENCRYPTION_KEY, sealedAttempt)).resolves.toEqual(attempt);

    const tampered = `${sealedAttempt.slice(0, -2)}${sealedAttempt.endsWith('AA') ? 'BB' : 'AA'}`;
    await expect(openOauthCookie(ENCRYPTION_KEY, tampered))
      .rejects.toMatchObject({ code: 'session_invalid' });
  });

  it('rejects authenticated teardown cookies with a widened shape or mismatched schema purpose', async () => {
    const review = {
      schemaVersion: 6,
      purpose: 'gateway_teardown_review',
      sessionId: base64UrlEncode(new Uint8Array(32).fill(5)),
      expiresAt: NOW + 600_000,
      actionId: `action_${'A'.repeat(32)}`,
      actionKey: base64UrlEncode(new Uint8Array(32).fill(6)),
      actorEmail: 'owner@example.com',
      accountId: 'a'.repeat(32),
      installationId: `acg-${'b'.repeat(24)}`,
      gatewayName: 'Example Gateway',
      portalHostname: 'mcp.example.com',
      workerName: 'ankka-gateway-example',
      workersSubdomain: 'customer-workers',
      managementOrigin: 'https://manage.example.com',
    };
    const invalid = [
      { ...review, state: base64UrlEncode(new Uint8Array(32).fill(9)) },
      { ...review, schemaVersion: 7, purpose: 'gateway_teardown' },
      { ...review, purpose: 'gateway_teardown' },
      { ...review, portalHostname: 'MCP.example.com' },
      { ...review, managementOrigin: 'https://manage.example.com/path' },
    ];

    for (const value of invalid) {
      await expect(sealOauthCookie(ENCRYPTION_KEY, value))
        .rejects.toMatchObject({ code: 'session_invalid' });
    }
  });

  it.each(['source_apply', 'access_apply', 'runtime_update'] as const)('seals exact verified redirect authority (%s)', async (actionType) => {
    const verified = {
      schemaVersion: 9 as const,
      purpose: 'management_action_result' as const,
      actionType,
      actionId: `action_${'A'.repeat(32)}`,
      managementOrigin: 'https://manage.example.com',
      expiresAt: NOW + 600_000,
    };
    const sealed = await sealOauthCookie(ENCRYPTION_KEY, verified);
    expect(sealed).not.toContain(verified.managementOrigin);
    await expect(openOauthCookie(ENCRYPTION_KEY, sealed)).resolves.toEqual(verified);

    for (const invalid of [
      { ...verified, actionKey: base64UrlEncode(new Uint8Array(32).fill(9)) },
      { ...verified, purpose: 'source_apply' },
      { ...verified, managementOrigin: 'https://manage.example.com/path' },
    ]) {
      await expect(sealOauthCookie(ENCRYPTION_KEY, invalid))
        .rejects.toMatchObject({ code: 'session_invalid' });
    }
  });

  it('derives a stable session-bound CSRF value without storing it', async () => {
    const first = await deriveCsrfToken(ENCRYPTION_KEY, payload.sessionId);
    const second = await deriveCsrfToken(ENCRYPTION_KEY, payload.sessionId);
    const other = await deriveCsrfToken(ENCRYPTION_KEY, base64UrlEncode(new Uint8Array(32).fill(4)));
    expect(first).toBe(second);
    expect(first).not.toBe(other);
    expect(first).toHaveLength(43);
  });

  it('uses strict __Host cookies with no Domain attribute', () => {
    for (const value of [sessionCookie(payload.sessionId, 600), oauthCookie('sealed', 600)]) {
      expect(value).toContain('__Host-');
      expect(value).toContain('Path=/');
      expect(value).toContain('HttpOnly');
      expect(value).toContain('Secure');
      expect(value).toContain('SameSite=Lax');
      expect(value).not.toContain('Domain=');
    }
    expect(clearOauthCookie()).toContain('Max-Age=0');
    expect(parseCookies('a=1; b=two')).toEqual(new Map([['a', '1'], ['b', 'two']]));
  });
});

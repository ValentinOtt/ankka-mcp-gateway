import { PUBLIC_ORIGIN } from '../src/constants';
import { REVIEWED_GATEWAY_DEPLOY_ACTIVATION } from '../src/reviewed-activation';
import entrypoint, { TwoStageDeploySession } from '../src/reviewed-entrypoint';
import type { TwoStageDeployEnv } from '../src/two-stage-runtime';

describe('checked-in two-stage entrypoint', () => {
  it('is the disabled zero-write shell and exports the two-stage Durable Object class', async () => {
    expect(REVIEWED_GATEWAY_DEPLOY_ACTIVATION).toEqual({ enabled: false, pin: null });
    expect(TwoStageDeploySession.name).toBe('TwoStageDeploySession');
    expect(Object.isFrozen(entrypoint)).toBe(true);

    // SAFETY: every property read on the proxy throws, so the empty target is never observed as an env.
    const poisoned = new Proxy({} as TwoStageDeployEnv, {
      get() {
        throw new Error('disabled entrypoint touched an environment binding');
      },
      has() {
        throw new Error('disabled entrypoint probed an environment binding');
      },
    });
    const health = await entrypoint.fetch(new Request(`${PUBLIC_ORIGIN}/health`), poisoned);
    expect(health.status).toBe(200);
    expect(await health.json()).toEqual({ ok: true, mutationsEnabled: false });
    expect(health.headers.get('cache-control')).toBe('no-store');

    for (const [method, path] of [
      ['GET', '/'],
      ['GET', '/api/session'],
      ['PUT', '/api/selection'],
      ['POST', '/api/bootstrap'],
      ['GET', '/oauth/callback?code=x&state=y'],
      ['GET', '/api/bootstrap/handoff'],
      ['GET', '/api/discovery'],
      ['POST', '/health'],
    ] as const) {
      const response = await entrypoint.fetch(new Request(`${PUBLIC_ORIGIN}${path}`, { method }), poisoned);
      expect(response.status, `${method} ${path}`).toBe(503);
      expect(await response.json()).toEqual({ code: 'release_unavailable' });
      expect(response.headers.get('set-cookie')).toBeNull();
    }
  });
});

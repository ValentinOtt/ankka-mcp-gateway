import { streamingInstallCallbackResponse } from '../src/streaming-callback';

function deferred(): { readonly promise: Promise<void>; readonly resolve: () => void } {
  let resolve = (): void => undefined;
  const promise = new Promise<void>((nextResolve) => {
    resolve = nextResolve;
  });
  return { promise, resolve };
}

describe('streaming OAuth callback response', () => {
  it('enqueues the verified shell before awaiting deployment and strips fixed-body headers', async () => {
    const deployment = deferred();
    let started = false;
    const response = await streamingInstallCallbackResponse(new Response(
      '<!doctype html><main>live installer</main>',
      {
        headers: {
          'cache-control': 'public, max-age=60',
          'content-length': '41',
          'content-type': 'text/html; charset=utf-8',
          etag: '"signed-shell"',
        },
      },
    ), async () => {
      started = true;
      await deployment.promise;
    }, { heartbeatMs: 1_000 });

    expect(response.status).toBe(200);
    expect(response.headers.get('cache-control')).toBe('no-store');
    expect(response.headers.get('content-encoding')).toBe('identity');
    expect(response.headers.has('content-length')).toBe(false);
    expect(response.headers.has('etag')).toBe(false);
    const reader = response.body?.getReader();
    expect(reader).toBeDefined();
    const first = await reader?.read();
    expect(new TextDecoder().decode(first?.value)).toContain('live installer');
    expect(first?.done).toBe(false);
    expect(started).toBe(true);

    deployment.resolve();
    expect((await reader?.read())?.done).toBe(true);
  });

  it('keeps cleanup registered when the browser disconnects and never writes an error body', async () => {
    const deployment = deferred();
    const registered: Promise<unknown>[] = [];
    const context = {
      waitUntil(task: Promise<unknown>) {
        registered.push(task);
      },
    } as unknown as ExecutionContext;
    const response = await streamingInstallCallbackResponse(new Response(
      '<!doctype html><main>live installer</main>',
      { headers: { 'content-type': 'text/html; charset=utf-8' } },
    ), async () => deployment.promise, { context, heartbeatMs: 1_000 });

    expect(registered).toHaveLength(1);
    const reader = response.body?.getReader();
    await reader?.read();
    await reader?.cancel('browser disconnected');
    deployment.resolve();
    await expect(registered[0]).resolves.toBeUndefined();
  });

  it('contains operation failures inside the stream lifecycle', async () => {
    const response = await streamingInstallCallbackResponse(new Response(
      '<!doctype html><main>live installer</main>',
      { headers: { 'content-type': 'text/html; charset=utf-8' } },
    ), async () => {
      throw new Error('provider body cfoat_must_not_surface');
    }, { heartbeatMs: 1_000 });

    const body = await response.text();
    expect(body).toContain('live installer');
    expect(body).not.toContain('cfoat_must_not_surface');
  });
});

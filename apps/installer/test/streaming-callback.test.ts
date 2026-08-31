import {
  streamingInstallCallbackResponse,
  streamingRuntimeCallbackResponse,
  type RuntimeCallbackResult,
} from '../src/streaming-callback';

interface Deferred {
  readonly promise: Promise<void>;
  readonly resolve: () => void;
}

function deferred(): Deferred {
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
    };
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

describe('streaming runtime callback response', () => {
  const html = '<!doctype html><body><!-- ankka-runtime-callback-state -->' +
    '<main>live management</main><script src="/assets/installer-test.js"></script></body>';
  const success: RuntimeCallbackResult = {
    schemaVersion: 1, kind: 'runtime_update', status: 'succeeded',
    managementUrl: 'https://manage.example.com/?runtimeAction=action_' + 'A'.repeat(32),
  };
  const shell = (body = html) => new Response(body, {
    headers: { 'content-type': 'text/html; charset=utf-8', 'content-security-policy': "script-src 'self'" },
  });

  it('streams pending HTML first and only emits a terminal marker when execution resolves', async () => {
    const operation = deferred();
    const response = await streamingRuntimeCallbackResponse(shell(), async () => {
      await operation.promise;
      return success;
    });
    expect(response.status).toBe(200);
    expect(response.headers.get('content-security-policy')).toBe("script-src 'self'");
    expect(response.headers.get('cache-control')).toBe('no-store');
    expect(response.headers.get('content-encoding')).toBe('identity');
    const reader = response.body?.getReader();
    const first = new TextDecoder().decode((await reader?.read())?.value);
    expect(first).toContain('<template id="ankka-runtime-callback-pending"></template>');
    expect(first).not.toContain('ankka-runtime-callback-result');
    operation.resolve();
    const terminal = new TextDecoder().decode((await reader?.read())?.value);
    expect(terminal).toContain('<template id="ankka-runtime-callback-result">' + JSON.stringify(success));
    expect((await reader?.read())?.done).toBe(true);
  });

  it('uses passive escaped markup without executing result text', async () => {
    const response = await streamingRuntimeCallbackResponse(shell(), async () => ({
      ...success, status: 'failed', code: 'session_conflict', reason: '</template><script>&payload</script>',
    }));
    const body = await response.text();
    expect(body).toContain('&lt;/template&gt;&lt;script&gt;&amp;payload&lt;/script&gt;');
    expect(body).not.toContain('<script>&payload');
    expect(body.match(/id="ankka-runtime-callback-result"/gu)).toHaveLength(1);
  });

  it('closes without a terminal marker or exception text on an unexpected execution failure', async () => {
    const response = await streamingRuntimeCallbackResponse(shell(), async () => {
      throw new Error('cfoat_private_provider_detail');
    });
    const body = await response.text();
    expect(body).toContain('ankka-runtime-callback-pending');
    expect(body).not.toContain('ankka-runtime-callback-result');
    expect(body).not.toContain('cfoat_private_provider_detail');
  });

  it('rejects missing or ambiguous pending markers without starting the operation', async () => {
    const execute = vi.fn(async () => success);
    for (const body of ['<main>missing marker</main>', html + '<!-- ankka-runtime-callback-state -->']) {
      await expect(streamingRuntimeCallbackResponse(shell(body), execute)).rejects.toThrow('runtime_callback_shell_invalid');
    }
    expect(execute).not.toHaveBeenCalled();
  });

  it('never emits an oversized terminal result', async () => {
    const response = await streamingRuntimeCallbackResponse(shell(), async () => ({
      ...success, managementUrl: 'https://manage.example.com/' + 'a'.repeat(4_096),
    }));
    expect(await response.text()).not.toContain('ankka-runtime-callback-result');
  });

  it('keeps exactly one bounded cleanup task after a disconnect without writing a terminal marker', async () => {
    const operation = deferred();
    const registered: Promise<unknown>[] = [];
    const execute = vi.fn(async () => { await operation.promise; return success; });
    const response = await streamingRuntimeCallbackResponse(shell(), execute, {
      context: { waitUntil: (task) => { registered.push(task); } },
    });
    const reader = response.body?.getReader();
    await reader?.read();
    await reader?.cancel();
    operation.resolve();
    await Promise.all(registered);
    expect(registered).toHaveLength(1);
    expect(execute).toHaveBeenCalledTimes(1);
    expect((await reader?.read())?.done).toBe(true);
  });
});

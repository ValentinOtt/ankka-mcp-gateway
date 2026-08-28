const encoder = new TextEncoder();
const HEARTBEAT = encoder.encode('\n<!-- ankka-install-stream-heartbeat -->\n');
export const INSTALL_STREAM_HEARTBEAT_MS = 10_000;

export interface StreamingCallbackOptions {
  readonly heartbeatMs?: number;
  readonly context?: ExecutionContext;
}

function safeWaitUntil(context: ExecutionContext | undefined, task: Promise<void>): void {
  if (context && typeof context.waitUntil === 'function') context.waitUntil(task);
}

/**
 * Turns the already verified, no-store installer HTML response into the live
 * lifetime anchor for one memory-only OAuth grant. The operation is never
 * serialized into the stream or a background primitive. While the browser is
 * connected, the response keeps the callback invocation alive; waitUntil only
 * provides the platform's bounded cleanup window after a disconnect.
 */
export async function streamingInstallCallbackResponse(
  shell: Response,
  execute: () => Promise<void>,
  options: StreamingCallbackOptions = {},
): Promise<Response> {
  if (
    shell.status !== 200 ||
    !shell.headers.get('content-type')?.toLowerCase().startsWith('text/html')
  ) throw new TypeError('streaming_callback_shell_invalid');
  const heartbeatMs = options.heartbeatMs ?? INSTALL_STREAM_HEARTBEAT_MS;
  if (!Number.isSafeInteger(heartbeatMs) || heartbeatMs < 1_000 || heartbeatMs > 60_000) {
    throw new TypeError('streaming_callback_heartbeat_invalid');
  }

  const shellBytes = new Uint8Array(await shell.arrayBuffer());
  if (shellBytes.byteLength === 0) throw new TypeError('streaming_callback_shell_invalid');

  let controller: ReadableStreamDefaultController<Uint8Array> | null = null;
  const activeController = (): ReadableStreamDefaultController<Uint8Array> | null => controller;
  let cancelled = false;
  let heartbeat: ReturnType<typeof setInterval> | null = null;
  let resolveStarted = (): void => undefined;
  const started = new Promise<void>((resolve) => {
    resolveStarted = resolve;
  });

  const stream = new ReadableStream<Uint8Array>({
    start(nextController) {
      controller = nextController;
      nextController.enqueue(shellBytes);
      resolveStarted();
    },
    cancel() {
      cancelled = true;
      controller = null;
      if (heartbeat !== null) clearInterval(heartbeat);
    },
  });

  const task = (async (): Promise<void> => {
    await started;
    heartbeat = setInterval(() => {
      const current = activeController();
      if (!cancelled && current) {
        try {
          current.enqueue(HEARTBEAT);
        } catch {
          cancelled = true;
          controller = null;
          if (heartbeat !== null) clearInterval(heartbeat);
        }
      }
    }, heartbeatMs);
    try {
      await execute();
    } finally {
      if (heartbeat !== null) clearInterval(heartbeat);
      heartbeat = null;
      const current = activeController();
      if (!cancelled && current) {
        try {
          current.close();
        } catch {
          // A simultaneous client disconnect already closed the stream.
        }
      }
      controller = null;
    }
  })();
  // Consume the task rejection here so a terminal internal error cannot become
  // an unhandled rejection or leak through the HTML body. Session polling is
  // the only public result channel.
  const settled = task.catch(() => undefined);
  safeWaitUntil(options.context, settled);

  const headers = new Headers(shell.headers);
  headers.delete('content-length');
  headers.delete('etag');
  headers.set('cache-control', 'no-store');
  // Prevent an intermediary compression buffer from delaying the signed shell
  // until the deployment task (and therefore the response body) completes.
  headers.set('content-encoding', 'identity');
  return new Response(stream, { status: 200, headers });
}

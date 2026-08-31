import { type DeployErrorCode } from './errors';

const encoder = new TextEncoder();
const HEARTBEAT = encoder.encode('\n<!-- ankka-install-stream-heartbeat -->\n');
export const INSTALL_STREAM_HEARTBEAT_MS = 10_000;

export interface StreamingCallbackContext {
  waitUntil(task: Promise<unknown>): void;
}

export interface StreamingCallbackOptions {
  readonly heartbeatMs?: number;
  readonly context?: StreamingCallbackContext;
}

export type RuntimeCallbackResult = Readonly<{
  schemaVersion: 1;
  kind: 'runtime_update';
  managementUrl: string;
} & (
  | { status: 'succeeded' }
  | { status: 'failed'; code: DeployErrorCode; reason: string | null }
)>;

const RUNTIME_CALLBACK_STATE = '<!-- ankka-runtime-callback-state -->';

/** Only already-sanitized, bounded public results belong in this passive node. */
function runtimeResultBytes(result: RuntimeCallbackResult): Uint8Array {
  const json = JSON.stringify(result);
  if (json.length > 4_096) throw new TypeError('runtime_callback_result_invalid');
  const escaped = json.replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;');
  return encoder.encode('\n<template id="ankka-runtime-callback-result">' + escaped + '</template>\n');
}

/** The result is emitted only when execute has finished its grant cleanup. */
export async function streamingRuntimeCallbackResponse(
  shell: Response,
  execute: () => Promise<RuntimeCallbackResult>,
  options: StreamingCallbackOptions = {},
): Promise<Response> {
  // This is the bounded, verified release HTML, not a caller-controlled body.
  const html = await shell.text();
  if (html.split(RUNTIME_CALLBACK_STATE).length !== 2) {
    throw new TypeError('runtime_callback_shell_invalid');
  }
  const pending = html.replace(RUNTIME_CALLBACK_STATE, '<template id="ankka-runtime-callback-pending"></template>');
  return streamingCallbackResponse(new Response(pending, {
    status: shell.status,
    headers: shell.headers,
  }), async () => runtimeResultBytes(await execute()), options);
}

function safeWaitUntil(context: StreamingCallbackContext | undefined, task: Promise<void>): void {
  if (context) context.waitUntil(task);
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
  return streamingCallbackResponse(shell, execute, options);
}

async function streamingCallbackResponse(
  shell: Response,
  execute: () => Promise<Uint8Array | void>,
  options: StreamingCallbackOptions,
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
      const terminal = await execute();
      const current = activeController();
      if (terminal && !cancelled && current) current.enqueue(terminal);
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
  // an unhandled rejection or leak through the HTML body. Installations use
  // session polling; runtime actions require an explicit sanitized terminal
  // marker. An unexpected failure leaves no marker, never a success signal.
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

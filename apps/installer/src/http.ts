import { DeployError, type DeployErrorCode } from './errors';

/**
 * Runs an operation under a deadline. The controller is aborted once the
 * operation settles, whichever way, and spec-compliant runtimes (workerd,
 * Node) then error any response body stream that is still open. A Response
 * returned from here must therefore have had its body consumed inside the
 * operation; use fetchBoundedText for a fetch whose body is needed.
 */
export async function withDeadline<T>(
  operation: (signal: AbortSignal) => Promise<T>,
  errorCode: DeployErrorCode,
  timeoutMs = 10_000,
): Promise<T> {
  const controller = new AbortController();
  let timeout: ReturnType<typeof setTimeout> | undefined;
  const expired = new Promise<never>((_resolve, reject) => {
    timeout = setTimeout(() => {
      controller.abort();
      reject(new DeployError(504, errorCode));
    }, timeoutMs);
  });
  try {
    return await Promise.race([operation(controller.signal), expired]);
  } catch (error) {
    if (error instanceof DeployError) throw error;
    throw new DeployError(502, errorCode);
  } finally {
    if (timeout !== undefined) clearTimeout(timeout);
    controller.abort();
  }
}

export async function readBoundedText(
  response: Response,
  errorCode: DeployErrorCode,
  maxBytes = 64 * 1024,
): Promise<string> {
  const declaredHeader = response.headers.get('content-length');
  if (declaredHeader !== null) {
    const declared = Number(declaredHeader);
    if (!Number.isSafeInteger(declared) || declared < 0 || declared > maxBytes) {
      await response.body?.cancel().catch(() => undefined);
      throw new DeployError(502, errorCode);
    }
  }
  if (!response.body) return '';
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > maxBytes) {
      await reader.cancel();
      throw new DeployError(502, errorCode);
    }
    chunks.push(value);
  }
  const combined = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    combined.set(chunk, offset);
    offset += chunk.byteLength;
  }
  try {
    return new TextDecoder('utf-8', { fatal: true }).decode(combined);
  } catch {
    throw new DeployError(502, errorCode);
  }
}

export interface BoundedRead {
  readonly response: Response;
  readonly text: string;
}

/**
 * Fetches a response and reads its bounded text body inside one deadline, so
 * the body is consumed before the deadline aborts its controller. A body that
 * cannot be read within the bound surfaces as the error code with the reason
 * "body_read_failed"; a transport failure carries no reason; an expired
 * deadline is the 504 from withDeadline.
 */
export async function fetchBoundedText(
  transport: (input: RequestInfo | URL, init?: RequestInit) => Promise<Response>,
  input: RequestInfo | URL,
  init: Omit<RequestInit, 'signal'>,
  errorCode: DeployErrorCode,
  options: { readonly maxBytes?: number; readonly timeoutMs?: number } = {},
): Promise<BoundedRead> {
  return withDeadline(async (signal) => {
    const response = await transport(input, { ...init, signal });
    let text: string;
    try {
      text = await readBoundedText(response, errorCode, options.maxBytes);
    } catch {
      throw new DeployError(502, errorCode, 'body_read_failed');
    }
    return Object.freeze({ response, text });
  }, errorCode, options.timeoutMs);
}

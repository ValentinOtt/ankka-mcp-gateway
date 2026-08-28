import { DeployError, type DeployErrorCode } from './errors';

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
  const declared = Number(response.headers.get('content-length'));
  if (Number.isFinite(declared) && declared > maxBytes) throw new DeployError(502, errorCode);
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

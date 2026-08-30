export const INCOMING_LIMITS = { bytes: 32_768, chunks: 128, milliseconds: 5_000 } as const;

/** Bound the stream itself; Content-Length is not trusted. No batch RPC requests. */
export async function readRequestBody(request: Request): Promise<string> {
  const length = request.headers.get('content-length');
  if (length !== null && (!/^\d{1,8}$/.test(length) || Number(length) > INCOMING_LIMITS.bytes)) {
    throw new Error('CONNECTOR_REQUEST_INVALID');
  }
  if (!request.body) throw new Error('CONNECTOR_REQUEST_INVALID');
  const reader = request.body.getReader();
  let timer: ReturnType<typeof setTimeout> | undefined;
  let ended = false;
  const deadline = new Promise<never>((_resolve, reject) => {
    timer = setTimeout(() => {
      ended = true;
      void reader.cancel().catch(() => {});
      reject(new Error('CONNECTOR_REQUEST_INVALID'));
    }, INCOMING_LIMITS.milliseconds);
  });
  const consume = async (): Promise<string> => {
    const decoder = new TextDecoder('utf-8', { fatal: true });
    let bytes = 0;
    let chunks = 0;
    let text = '';
    while (!ended) {
      const chunk = await reader.read();
      if (chunk.done) return text + decoder.decode();
      bytes += chunk.value.byteLength;
      chunks += 1;
      if (bytes > INCOMING_LIMITS.bytes || chunks > INCOMING_LIMITS.chunks) throw new Error();
      text += decoder.decode(chunk.value, { stream: true });
    }
    throw new Error();
  };
  try {
    const text = await Promise.race([consume(), deadline]);
    // Structural protocol validation remains the SDK's job. Reject batch amplification here.
    if (!text.trimStart().startsWith('{')) throw new Error();
    return text;
  } catch {
    ended = true;
    void reader.cancel().catch(() => {});
    throw new Error('CONNECTOR_REQUEST_INVALID');
  } finally {
    clearTimeout(timer);
  }
}

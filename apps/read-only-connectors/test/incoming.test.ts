import { describe, expect, it, vi } from 'vitest';
import { INCOMING_LIMITS, readRequestBody } from '../src/incoming';

function request(body: string): Request {
  return new Request('https://connector.example.com/mcp', { method: 'POST', body });
}
describe('incoming request limits', () => {
  it('accepts a bounded single JSON object', async () => {
    expect(await readRequestBody(request('{"method":"tools/list"}'))).toBe('{"method":"tools/list"}');
  });
  it.each(['', '[]', '[{"method":"tools/call"}]', 'null'])('rejects non-object/batch payload %s', async (body) => {
    await expect(readRequestBody(request(body))).rejects.toThrow('CONNECTOR_REQUEST_INVALID');
  });
  it('rejects oversized bodies without trusting Content-Length', async () => {
    const input = request('{' + 'x'.repeat(INCOMING_LIMITS.bytes));
    input.headers.set('content-length', '2');
    await expect(readRequestBody(input)).rejects.toThrow('CONNECTOR_REQUEST_INVALID');
  });
  it('rejects malformed or excessive declared sizes', async () => {
    for (const size of ['-1', 'NaN', '99999999']) {
      const input = request('{}');
      input.headers.set('content-length', size);
      await expect(readRequestBody(input)).rejects.toThrow('CONNECTOR_REQUEST_INVALID');
    }
  });
  it('bounds a stalled body and cancels it', async () => {
    vi.useFakeTimers();
    try {
      const cancel = vi.fn();
      const stream = new ReadableStream<Uint8Array>({ cancel });
      const init = { method: 'POST', body: stream, duplex: 'half' };
      const input = new Request('https://connector.example.com/mcp', init);
      const result = expect(readRequestBody(input)).rejects.toThrow('CONNECTOR_REQUEST_INVALID');
      await vi.advanceTimersByTimeAsync(INCOMING_LIMITS.milliseconds);
      await result;
      expect(cancel).toHaveBeenCalled();
    } finally { vi.useRealTimers(); }
  });
});

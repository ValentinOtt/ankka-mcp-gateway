import { readBoundedText, withDeadline } from '../src/http';

describe('bounded provider I/O', () => {
  it('bounds a request that never returns headers', async () => {
    await expect(withDeadline(
      async () => new Promise<never>(() => {}),
      'oauth_exchange_failed',
      5,
    )).rejects.toMatchObject({ code: 'oauth_exchange_failed', status: 504 });
  });

  it('bounds a body read that never completes', async () => {
    const response = new Response(new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(new TextEncoder().encode('{'));
      },
    }));
    await expect(withDeadline(
      async () => readBoundedText(response, 'target_zone_invalid'),
      'target_zone_invalid',
      5,
    )).rejects.toMatchObject({ code: 'target_zone_invalid', status: 504 });
  });

  it('rejects a declared or streamed oversized body', async () => {
    await expect(readBoundedText(new Response('small', {
      headers: { 'content-length': '999' },
    }), 'oauth_exchange_failed', 10)).rejects.toMatchObject({ code: 'oauth_exchange_failed' });
    await expect(readBoundedText(new Response('x'.repeat(11)), 'oauth_exchange_failed', 10))
      .rejects.toMatchObject({ code: 'oauth_exchange_failed' });
  });
});

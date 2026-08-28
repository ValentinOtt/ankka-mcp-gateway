const BODY = '{"schemaVersion":1,"status":"retired"}';

/**
 * Inert final deployment used only while Cloudflare retires the AdminState
 * SQLite Durable Object export. It has no bindings, outbound calls, storage,
 * logging, telemetry, or mutation surface.
 */
export default {
  fetch() {
    return new Response(BODY, {
      status: 410,
      headers: {
        'cache-control': 'no-store',
        'content-type': 'application/json; charset=utf-8',
        'permissions-policy': 'camera=(), geolocation=(), microphone=()',
        'referrer-policy': 'no-referrer',
        'x-content-type-options': 'nosniff',
      },
    });
  },
};

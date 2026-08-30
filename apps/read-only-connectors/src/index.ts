import { createMcpHandler, McpServer } from '@modelcontextprotocol/server';
import { z } from 'zod';
import { verifyAccess } from './access';
import { readRequestBody } from './incoming';
import { createConnector } from './providers';
import { executeReadRequest } from './request';

const rpcEnvelope = z.object({
  jsonrpc: z.literal('2.0'),
  method: z.enum(['initialize', 'notifications/initialized', 'ping', 'tools/list', 'tools/call', 'server/discover']),
}).passthrough();

function reject(status: number, code: string): Response {
  return Response.json({ error: code }, {
    status, headers: { 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff' },
  });
}

/** One deployment, one provider, one deployment-owned credential. No auth bypass. */
export async function handleRequest(
  request: Request,
  env: Env,
  fetcher: typeof globalThis.fetch = globalThis.fetch,
): Promise<Response> {
  try {
    const origin = new URL(env.PUBLIC_ORIGIN);
    const url = new URL(request.url);
    if (origin.protocol !== 'https:' || origin.origin !== env.PUBLIC_ORIGIN || origin.port !== '' ||
      origin.username !== '' || origin.password !== '' || url.origin !== origin.origin ||
      (request.headers.has('origin') && request.headers.get('origin') !== origin.origin)) {
      return reject(403, 'CONNECTOR_ORIGIN_REJECTED');
    }
    if (url.pathname !== '/mcp' || url.search !== '' || url.hash !== '') return reject(404, 'NOT_FOUND');
    if (request.method !== 'POST') return reject(405, 'METHOD_NOT_ALLOWED');
    if (request.headers.get('content-type')?.split(';')[0]?.trim().toLowerCase() !== 'application/json') {
      return reject(415, 'CONNECTOR_REQUEST_INVALID');
    }
    if (!await verifyAccess(request, env.ACCESS_TEAM_DOMAIN, env.ACCESS_AUD, fetcher)) {
      // Cloudflare Managed OAuth supplies discovery/challenges at the Access edge.
      return reject(403, 'CONNECTOR_ACCESS_REQUIRED');
    }
    let body: string;
    try {
      body = await readRequestBody(request);
      rpcEnvelope.parse(JSON.parse(body));
    } catch {
      return reject(400, 'CONNECTOR_REQUEST_INVALID');
    }
    // Read the provider secret only after origin, Access JWT, and request validation.
    const connector = createConnector(env.CONNECTOR_PROVIDER, env.CONNECTOR_CONFIG_JSON, env.PROVIDER_TOKEN);
    const handler = createMcpHandler(() => {
      const server = new McpServer({ name: `ankka-${connector.id}-read-only`, version: '0.1.0-alpha.0' });
      connector.registerTools(server, async (plan) => {
        // Refuse unapproved operations before minting any short-lived provider token.
        if (!connector.allowRequest(plan)) throw new Error('CONNECTOR_REQUEST_NOT_ALLOWED');
        const providerHeaders = connector.authorize === undefined
          ? connector.headers : await connector.authorize(fetcher);
        return executeReadRequest({
          origin: connector.origin, plan, headers: providerHeaders,
          allowRequest: (candidate) => connector.allowRequest(candidate), fetch: fetcher,
        });
      });
      return server;
    }, { legacy: 'stateless', maxSubscriptions: 0, keepAliveMs: 0 });
    const headers = new Headers();
    for (const name of ['accept', 'content-type', 'mcp-protocol-version', 'mcp-method', 'mcp-name']) {
      const value = request.headers.get(name);
      if (value !== null) headers.set(name, value);
    }
    const response = await handler.fetch(new Request(request.url, {
      method: 'POST', headers, body, signal: request.signal,
    }));
    const responseHeaders = new Headers(response.headers);
    responseHeaders.set('Cache-Control', 'no-store');
    responseHeaders.set('X-Content-Type-Options', 'nosniff');
    return new Response(response.body, { status: response.status, headers: responseHeaders });
  } catch {
    return reject(503, 'CONNECTOR_UNAVAILABLE');
  }
}

export default {
  fetch(request, env) { return handleRequest(request, env); },
} satisfies ExportedHandler<Env>;

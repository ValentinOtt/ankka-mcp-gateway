import { createServer } from 'node:http';
import { pathToFileURL } from 'node:url';
import {
  SYNTHETIC_MAX_BODY_BYTES,
  handleSyntheticMcpRequest,
} from './worker.mjs';

const DEFAULT_HOST = '127.0.0.1';
const DEFAULT_PORT = 9610;

export async function startSyntheticMcpServer({
  host = DEFAULT_HOST,
  port = DEFAULT_PORT,
} = {}) {
  if (host !== DEFAULT_HOST) {
    throw new TypeError('The synthetic MCP listener must bind to 127.0.0.1');
  }
  if (!Number.isInteger(port) || port < 0 || port > 65_535) {
    throw new TypeError('port must be an integer from 0 to 65535');
  }

  const server = createServer({ maxHeaderSize: 16 * 1024 }, async (incoming, outgoing) => {
    try {
      const body = await readBody(incoming);
      const request = new Request(
        new URL(incoming.url ?? '/', 'http://synthetic.invalid'),
        {
          method: incoming.method,
          headers: incoming.headers,
          body,
        },
      );
      const response = await handleSyntheticMcpRequest(request);
      outgoing.writeHead(response.status, Object.fromEntries(response.headers));
      outgoing.end(Buffer.from(await response.arrayBuffer()));
    } catch (error) {
      if (error instanceof RequestTooLargeError) {
        incoming.resume();
        outgoing.writeHead(413, {
          'Cache-Control': 'no-store',
          'Content-Type': 'application/json; charset=utf-8',
          'X-Content-Type-Options': 'nosniff',
        });
        outgoing.end('{"error":"request_too_large"}');
        return;
      }
      outgoing.writeHead(500, {
        'Cache-Control': 'no-store',
        'Content-Type': 'application/json; charset=utf-8',
        'X-Content-Type-Options': 'nosniff',
      });
      outgoing.end('{"error":"synthetic_fixture_failure"}');
    }
  });
  server.requestTimeout = 10_000;
  server.headersTimeout = 10_000;
  server.keepAliveTimeout = 5_000;

  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, host, resolve);
  });

  const address = server.address();
  if (!address || typeof address === 'string') {
    await closeServer(server);
    throw new Error('Synthetic MCP listener did not return a TCP address');
  }
  const origin = `http://${DEFAULT_HOST}:${address.port}`;

  return Object.freeze({
    origin,
    endpoint: `${origin}/mcp`,
    close: () => closeServer(server),
  });
}

class RequestTooLargeError extends Error {}

function readBody(incoming) {
  const declaredLength = Number(incoming.headers['content-length']);
  if (Number.isFinite(declaredLength) && declaredLength > SYNTHETIC_MAX_BODY_BYTES) {
    throw new RequestTooLargeError();
  }

  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    let settled = false;
    incoming.on('data', (chunk) => {
      if (settled) return;
      size += chunk.length;
      if (size > SYNTHETIC_MAX_BODY_BYTES) {
        settled = true;
        chunks.length = 0;
        reject(new RequestTooLargeError());
        return;
      }
      chunks.push(chunk);
    });
    incoming.once('end', () => {
      if (settled) return;
      settled = true;
      resolve(chunks.length > 0 ? Buffer.concat(chunks) : undefined);
    });
    incoming.once('error', (error) => {
      if (settled) return;
      settled = true;
      reject(error);
    });
  });
}

function closeServer(server) {
  return new Promise((resolve, reject) => {
    server.close((error) => (error ? reject(error) : resolve()));
  });
}

function parseCliArgs(argv) {
  let host = DEFAULT_HOST;
  let port = DEFAULT_PORT;
  for (let index = 0; index < argv.length; index += 1) {
    const flag = argv[index];
    const value = argv[index + 1];
    if (flag === '--host' && value) {
      host = value;
      index += 1;
    } else if (flag === '--port' && value && /^\d+$/.test(value)) {
      port = Number(value);
      index += 1;
    } else {
      throw new TypeError(`Unknown or incomplete option: ${flag}`);
    }
  }
  return { host, port };
}

async function main() {
  const listener = await startSyntheticMcpServer(parseCliArgs(process.argv.slice(2)));
  process.stdout.write(`${JSON.stringify({
    kind: 'synthetic_mcp_local_listener',
    endpoint: listener.endpoint,
  })}\n`);

  const stop = async () => {
    await listener.close();
    process.exitCode = 0;
  };
  process.once('SIGINT', stop);
  process.once('SIGTERM', stop);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((error) => {
    process.stderr.write(`Synthetic MCP listener failed: ${error.message}\n`);
    process.exitCode = 1;
  });
}

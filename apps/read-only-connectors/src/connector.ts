import type { McpServer } from '@modelcontextprotocol/server';
import { z } from 'zod';
import type { ConnectorJson, ReadRequestPlan } from './request';

export interface ReadExecutor {
  // The shared request boundary validates and bounds provider JSON before return.
  (plan: ReadRequestPlan): Promise<ConnectorJson>;
}

export interface ReadConnector {
  readonly id: string;
  readonly origin: string;
  readonly headers: Readonly<Record<string, string>>;
  authorize?(fetcher: typeof globalThis.fetch): Promise<Readonly<Record<string, string>>>;
  allowRequest(plan: ReadRequestPlan): boolean;
  registerTools(server: McpServer, execute: ReadExecutor): void;
}

// oxlint-disable-next-line anti-slop/no-shape-in-symbol-names -- ZodRawShape is the third-party library's public generic constraint.
export function registerReadTool<T extends z.ZodRawShape>(
  server: McpServer,
  execute: ReadExecutor,
  name: string,
  description: string,
  schema: z.ZodObject<T>,
  build: (input: z.output<z.ZodObject<T>>) => ReadRequestPlan,
): void {
  server.registerTool(name, {
    description,
    inputSchema: schema,
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
  }, async (input) => {
    try {
      const result = await execute(build(input));
      return { content: [{ type: 'text', text: JSON.stringify(result) }] };
    } catch {
      // Do not reflect provider bodies, credentials, arguments, URLs, or exceptions.
      return { isError: true, content: [{ type: 'text', text: 'CONNECTOR_READ_FAILED' }] };
    }
  });
}

export function parseConfig<T extends z.ZodType>(raw: string, schema: T): z.output<T> {
  try {
    if (new TextEncoder().encode(raw).byteLength > 16_384) throw new Error();
    return schema.parse(JSON.parse(raw));
  } catch {
    throw new Error('CONNECTOR_CONFIGURATION_INVALID');
  }
}

export function bearerHeaders(token: string) {
  if (!/^[\x21-\x7e]{1,4096}$/.test(token)) throw new Error('CONNECTOR_CONFIGURATION_INVALID');
  return { Authorization: `Bearer ${token}` };
}

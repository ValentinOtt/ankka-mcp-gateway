import * as v from 'valibot';
import { canonicalJson } from './canonical-json';

export const BIGQUERY_SETUP_TOOLS = Object.freeze(['execute_sql_readonly', 'get_table_info', 'list_table_ids']);
const project = v.pipe(v.string(), v.regex(/^[a-z][a-z0-9-]{4,61}[a-z0-9]$/u));
export const bigQueryConfigurationSchema = v.strictObject({
  queryProjectId: project,
  allowedDatasets: v.pipe(v.array(v.strictObject({
    projectId: project,
    datasetId: v.pipe(v.string(), v.regex(/^[A-Za-z0-9_]{1,1024}$/u)),
  })), v.minLength(1), v.maxLength(16), v.check((items) =>
    new Set(items.map((item) => `${item.projectId}/${item.datasetId}`)).size === items.length)),
});
export type BigQueryConfiguration = v.InferOutput<typeof bigQueryConfigurationSchema>;
export const bigQueryPrepareSchema = v.strictObject({
  schemaVersion: v.literal(1),
  revision: v.pipe(v.number(), v.safeInteger(), v.minValue(1)),
  label: v.pipe(v.string(), v.minLength(2), v.maxLength(80), v.check((text) => [...text].every((char) => char.charCodeAt(0) >= 32 && char.charCodeAt(0) !== 127 && char !== '<' && char !== '>'))),
  configuration: bigQueryConfigurationSchema,
  readOnlyConfirmed: v.literal(true),
});
export const bigQueryResumeSchema = v.strictObject({
  schemaVersion: v.literal(1),
  actionId: v.pipe(v.string(), v.regex(/^action_[A-Za-z0-9_-]{32}$/u)),
});
const identifier = v.pipe(v.string(), v.regex(/^[A-Za-z0-9_-]{1,128}$/u));
export const bigQueryRecordSchema = v.strictObject({
  schemaVersion: v.literal(1),
  sourceId: v.pipe(v.string(), v.regex(/^source-[a-f0-9]{16}$/u)),
  actionId: v.pipe(v.string(), v.regex(/^action_[A-Za-z0-9_-]{32}$/u)),
  configuration: bigQueryConfigurationSchema,
  workerName: v.pipe(v.string(), v.regex(/^ankka-bq-[a-f0-9]{24}$/u)),
  hostname: v.pipe(v.string(), v.regex(/^bq-[a-f0-9]{16}\.[a-z0-9.-]+$/u)),
  operatorEmail: v.pipe(v.string(), v.maxLength(254), v.regex(/^[^\s@]+@[a-z0-9.-]+$/u)),
  sourceHash: v.pipe(v.string(), v.regex(/^sha256:[a-f0-9]{64}$/u)),
  application: v.nullable(v.strictObject({ id: identifier, audience: v.pipe(v.string(), v.regex(/^[a-f0-9]{64}$/u)) })),
  workerVersion: v.nullable(identifier),
  domainId: v.nullable(identifier),
  pending: v.nullable(v.picklist(['application', 'worker', 'domain'])),
  ready: v.boolean(),
});
export type BigQueryRecord = v.InferOutput<typeof bigQueryRecordSchema>;

export async function bigQueryHex(value: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value));
  return [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, '0')).join('');
}

export async function bigQuerySourceNames(installationId: string, zoneName: string, configuration: BigQueryConfiguration) {
  const normalized = { ...configuration, allowedDatasets: [...configuration.allowedDatasets]
    .sort((a, b) => `${a.projectId}/${a.datasetId}` < `${b.projectId}/${b.datasetId}` ? -1 : 1) };
  const hash = await bigQueryHex(canonicalJson({ installationId, configuration: normalized }));
  const hostname = `bq-${hash.slice(0, 16)}.${zoneName}`;
  const url = `https://${hostname}/mcp`;
  return { configuration: normalized, hostname, url, workerName: `ankka-bq-${hash.slice(0, 24)}`,
    sourceId: `source-${(await bigQueryHex(url)).slice(0, 16)}` };
}

/** Bounded request/response read; fixed diagnostics never include provider or credential content. */
export async function readBigQueryText(body: ReadableStream<Uint8Array> | null, maximum = 32_768): Promise<string> {
  if (body === null) throw new Error('bigquery_request_invalid');
  const reader = body.getReader();
  const chunks: Uint8Array[] = [];
  let bytes = 0;
  let count = 0;
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    const read = async () => {
      for (;;) {
        const next = await reader.read();
        if (next.done) break;
        bytes += next.value.byteLength;
        if (bytes > maximum || ++count > 128) throw new Error('bigquery_request_invalid');
        chunks.push(next.value);
      }
      const combined = new Uint8Array(bytes);
      let offset = 0;
      for (const chunk of chunks) { combined.set(chunk, offset); offset += chunk.byteLength; }
      return new TextDecoder('utf-8', { fatal: true }).decode(combined);
    };
    return await Promise.race([read(), new Promise<never>((_resolve, reject) => {
      timer = setTimeout(() => reject(new Error('bigquery_request_invalid')), 8_000);
    })]);
  } finally {
    clearTimeout(timer);
    await reader.cancel().catch(() => {});
  }
}

import type { CloudflareFetch } from '../../src/cloudflare-client.ts';

export interface SyntheticMcpInspectionOptions {
  readonly fetchImpl?: CloudflareFetch;
}

export interface SyntheticMcpInspectionReport {
  readonly callVerified: true;
  readonly fixture: string;
  readonly schemaVersion: 1;
  readonly toolNames: readonly string[];
}

export class SyntheticMcpInspectionError extends Error {
  readonly code: string;
  constructor(code: string);
}

export function inspectSyntheticEndpoint(
  endpoint: string,
  options?: SyntheticMcpInspectionOptions,
): Promise<SyntheticMcpInspectionReport>;

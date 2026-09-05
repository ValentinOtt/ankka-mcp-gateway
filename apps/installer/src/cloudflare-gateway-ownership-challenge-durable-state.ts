import * as v from 'valibot';

import {
  CLOUDFLARE_GATEWAY_OWNERSHIP_CHALLENGE_TTL_MS,
  CloudflareGatewayOwnershipProofError,
  type CloudflareGatewayOwnershipChallengeRecord,
  type CloudflareGatewayOwnershipChallengeStore,
} from './cloudflare-gateway-ownership-proof';
import { CUSTOMER_CLOUDFLARE_OPERATIONS } from './cloudflare-operation-authority';

const SCHEMA_VERSION = 1;
const recordSchema = v.strictObject({
  certificateSha256: v.pipe(v.string(), v.regex(/^sha256:[a-f0-9]{64}$/u)),
  operation: v.picklist(CUSTOMER_CLOUDFLARE_OPERATIONS),
  challengeSha256: v.pipe(v.string(), v.regex(/^sha256:[a-f0-9]{64}$/u)),
  expiresAt: v.pipe(v.number(), v.safeInteger(), v.minValue(1)),
});

type SchemaRow = { readonly schema_version: number };
type ChangesRow = { readonly changed: number };

function invalid(): never {
  throw new CloudflareGatewayOwnershipProofError('invalid');
}

function parseRecord(
  record: CloudflareGatewayOwnershipChallengeRecord,
): v.InferOutput<typeof recordSchema> {
  const parsed = v.safeParse(recordSchema, record);
  if (!parsed.success || parsed.output.expiresAt <= CLOUDFLARE_GATEWAY_OWNERSHIP_CHALLENGE_TTL_MS) {
    invalid();
  }
  return parsed.output;
}

function changedExactlyOneRow(storage: DurableObjectStorage): boolean {
  const rows = storage.sql.exec<ChangesRow>('SELECT changes() AS changed').toArray();
  return rows.length === 1 && rows[0]?.changed === 1;
}

/**
 * Initializes the relay's SQLite challenge table. The hosting Durable Object
 * should be deterministically sharded by certificate digest and call this once
 * from its constructor's `blockConcurrencyWhile` initialization.
 */
export function initializeCloudflareGatewayOwnershipChallengeSql(
  storage: DurableObjectStorage,
): void {
  storage.sql.exec(`
    CREATE TABLE IF NOT EXISTS ankka_gateway_ownership_schema (
      singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
      schema_version INTEGER NOT NULL CHECK (schema_version = 1)
    ) STRICT
  `);
  storage.sql.exec(`
    INSERT INTO ankka_gateway_ownership_schema (singleton, schema_version)
    VALUES (1, 1)
    ON CONFLICT(singleton) DO NOTHING
  `);
  const schemaRows = storage.sql.exec<SchemaRow>(`
    SELECT schema_version
    FROM ankka_gateway_ownership_schema
    WHERE singleton = 1
    LIMIT 2
  `).toArray();
  if (schemaRows.length !== 1 || schemaRows[0]?.schema_version !== SCHEMA_VERSION) invalid();
  storage.sql.exec(`
    CREATE TABLE IF NOT EXISTS ankka_gateway_ownership_challenges (
      certificate_sha256 TEXT NOT NULL CHECK (
        length(certificate_sha256) = 71 AND certificate_sha256 GLOB 'sha256:[0-9a-f]*'
      ),
      operation TEXT NOT NULL CHECK (
        operation IN (
          'install', 'upgrade', 'rollback', 'source-add', 'bigquery-add', 'source-update',
          'source-remove', 'uninstall'
        )
      ),
      challenge_sha256 TEXT NOT NULL CHECK (
        length(challenge_sha256) = 71 AND challenge_sha256 GLOB 'sha256:[0-9a-f]*'
      ),
      expires_at INTEGER NOT NULL CHECK (expires_at > 0),
      PRIMARY KEY (certificate_sha256, operation)
    ) STRICT
  `);
}

/**
 * Strongly consistent hash-only state for one certificate shard. A fresh,
 * customer-signed request replaces an earlier challenge for the same fixed
 * operation. Exact deletion makes proof consumption single-use.
 */
export class CloudflareGatewayOwnershipChallengeDurableState
  implements CloudflareGatewayOwnershipChallengeStore {
  constructor(private readonly storage: DurableObjectStorage) {}

  async put(record: CloudflareGatewayOwnershipChallengeRecord): Promise<boolean> {
    const parsed = parseRecord(record);
    const issuedAt = parsed.expiresAt - CLOUDFLARE_GATEWAY_OWNERSHIP_CHALLENGE_TTL_MS;
    return this.storage.transactionSync(() => {
      this.storage.sql.exec(`
        DELETE FROM ankka_gateway_ownership_challenges
        WHERE expires_at <= ?
      `, issuedAt);
      this.storage.sql.exec(`
        INSERT INTO ankka_gateway_ownership_challenges (
          certificate_sha256, operation, challenge_sha256, expires_at
        ) VALUES (?, ?, ?, ?)
        ON CONFLICT(certificate_sha256, operation) DO UPDATE SET
          challenge_sha256 = excluded.challenge_sha256,
        expires_at = excluded.expires_at
      `, parsed.certificateSha256, parsed.operation, parsed.challengeSha256, parsed.expiresAt);
      return changedExactlyOneRow(this.storage);
    });
  }

  async consume(record: CloudflareGatewayOwnershipChallengeRecord): Promise<boolean> {
    const parsed = parseRecord(record);
    return this.storage.transactionSync(() => {
      this.storage.sql.exec(`
        DELETE FROM ankka_gateway_ownership_challenges
        WHERE certificate_sha256 = ?
          AND operation = ?
          AND challenge_sha256 = ?
          AND expires_at = ?
      `, parsed.certificateSha256, parsed.operation, parsed.challengeSha256, parsed.expiresAt);
      return changedExactlyOneRow(this.storage);
    });
  }

  /** Invoke from the Durable Object alarm to remove expired hash metadata. */
  pruneExpired(now: number): number {
    if (!Number.isSafeInteger(now) || now < 0) invalid();
    return this.storage.sql.exec(`
      DELETE FROM ankka_gateway_ownership_challenges
      WHERE expires_at <= ?
    `, now).rowsWritten;
  }
}

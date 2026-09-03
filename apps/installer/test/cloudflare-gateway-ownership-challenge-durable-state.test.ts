import {
  CloudflareGatewayOwnershipChallengeDurableState,
  initializeCloudflareGatewayOwnershipChallengeSql,
} from '../src/cloudflare-gateway-ownership-challenge-durable-state';
import type { CloudflareGatewayOwnershipChallengeRecord } from
  '../src/cloudflare-gateway-ownership-proof';

type StoredChallenge = Readonly<{
  certificateSha256: string;
  operation: string;
  challengeSha256: string;
  expiresAt: number;
}>;

const NOW = 1_788_192_000_000;
const CERTIFICATE_SHA256 = `sha256:${'a'.repeat(64)}`;

class FakeSqlStorage {
  schemaVersion: number | null = null;
  readonly challenges = new Map<string, StoredChallenge>();
  lastChanges = 0;

  private key(certificateSha256: string, operation: string): string {
    return `${certificateSha256}.${operation}`;
  }

  exec<Row extends Record<string, ArrayBuffer | string | number | null>>(
    query: string,
    ...bindings: unknown[]
  ): SqlStorageCursor<Row> {
    const normalized = query.replace(/\s+/gu, ' ').trim();
    let rows: Record<string, ArrayBuffer | string | number | null>[] = [];
    let rowsWritten = 0;
    if (normalized.startsWith('CREATE TABLE IF NOT EXISTS ankka_gateway_ownership_schema')) {
      // no-op
    } else if (normalized.startsWith('INSERT INTO ankka_gateway_ownership_schema')) {
      if (this.schemaVersion === null) {
        this.schemaVersion = 1;
        rowsWritten = 1;
        this.lastChanges = 1;
      } else {
        this.lastChanges = 0;
      }
    } else if (normalized.startsWith('SELECT schema_version')) {
      if (this.schemaVersion !== null) rows = [{ schema_version: this.schemaVersion }];
    } else if (normalized.startsWith(
      'CREATE TABLE IF NOT EXISTS ankka_gateway_ownership_challenges',
    )) {
      // no-op
    } else if (normalized ===
      'DELETE FROM ankka_gateway_ownership_challenges WHERE expires_at <= ?') {
      const cutoff = Number(bindings[0]);
      for (const [key, challenge] of this.challenges) {
        if (challenge.expiresAt <= cutoff) {
          this.challenges.delete(key);
          rowsWritten += 1;
        }
      }
      this.lastChanges = rowsWritten;
    } else if (normalized.startsWith(
      'INSERT INTO ankka_gateway_ownership_challenges',
    )) {
      const challenge = Object.freeze({
        certificateSha256: String(bindings[0]),
        operation: String(bindings[1]),
        challengeSha256: String(bindings[2]),
        expiresAt: Number(bindings[3]),
      });
      this.challenges.set(this.key(challenge.certificateSha256, challenge.operation), challenge);
      // The live Workers runtime can report zero on this cursor even though
      // SQLite committed the upsert. Production checks changes() immediately.
      rowsWritten = 0;
      this.lastChanges = 1;
    } else if (normalized.startsWith(
      'DELETE FROM ankka_gateway_ownership_challenges WHERE certificate_sha256 = ?',
    )) {
      const certificateSha256 = String(bindings[0]);
      const operation = String(bindings[1]);
      const challengeSha256 = String(bindings[2]);
      const expiresAt = Number(bindings[3]);
      const key = this.key(certificateSha256, operation);
      const stored = this.challenges.get(key);
      if (stored?.challengeSha256 === challengeSha256 && stored.expiresAt === expiresAt) {
        this.challenges.delete(key);
        rowsWritten = 0;
        this.lastChanges = 1;
      } else {
        this.lastChanges = 0;
      }
    } else if (normalized === 'SELECT changes() AS changed') {
      rows = [{ changed: this.lastChanges }];
    } else {
      throw new Error('unexpected SQL');
    }
    // SAFETY: each fake row is built for the query-selected Row shape, while
    // production still validates every returned field and record.
    const typedRows = rows as Row[];
    const cursor: SqlStorageCursor<Row> = Object.create(null);
    Object.defineProperties(cursor, {
      toArray: { value: (): Row[] => typedRows },
      rowsWritten: { value: rowsWritten },
    });
    return cursor;
  }
}

function fakeDurableStorage(sql: FakeSqlStorage): DurableObjectStorage {
  const storage: DurableObjectStorage = Object.create(null);
  Object.defineProperties(storage, {
    sql: { value: sql },
    transactionSync: { value: <Value>(closure: () => Value): Value => closure() },
  });
  return storage;
}

function record(
  operation: CloudflareGatewayOwnershipChallengeRecord['operation'],
  fill: string,
  expiresAt = NOW + 120_000,
): CloudflareGatewayOwnershipChallengeRecord {
  return Object.freeze({
    certificateSha256: CERTIFICATE_SHA256,
    operation,
    challengeSha256: `sha256:${fill.repeat(64)}`,
    expiresAt,
  });
}

describe('ownership challenge SQLite Durable Object state', () => {
  it('replaces by certificate and operation, then consumes the exact challenge once', async () => {
    const sql = new FakeSqlStorage();
    const storage = fakeDurableStorage(sql);
    initializeCloudflareGatewayOwnershipChallengeSql(storage);
    const state = new CloudflareGatewayOwnershipChallengeDurableState(storage);
    const first = record('upgrade', 'b');
    const replacement = record('upgrade', 'c', NOW + 120_001);

    await expect(state.put(first)).resolves.toBe(true);
    await expect(state.put(replacement)).resolves.toBe(true);
    expect(sql.challenges.size).toBe(1);
    expect(sql.challenges.values().next().value).toEqual(replacement);
    await expect(state.consume(first)).resolves.toBe(false);
    await expect(state.consume(replacement)).resolves.toBe(true);
    await expect(state.consume(replacement)).resolves.toBe(false);
    expect(sql.challenges.size).toBe(0);
  });

  it('keeps operations separate and prunes only expired hash metadata', async () => {
    const sql = new FakeSqlStorage();
    const storage = fakeDurableStorage(sql);
    initializeCloudflareGatewayOwnershipChallengeSql(storage);
    const state = new CloudflareGatewayOwnershipChallengeDurableState(storage);
    const upgrade = record('upgrade', 'd', NOW + 120_000);
    const rollback = record('rollback', 'e', NOW + 120_001);
    await state.put(upgrade);
    await state.put(rollback);
    expect(sql.challenges.size).toBe(2);
    expect(state.pruneExpired(NOW + 120_000)).toBe(1);
    expect(sql.challenges.size).toBe(1);
    expect(JSON.stringify([...sql.challenges.values()])).not.toContain('accountId');
    expect(JSON.stringify([...sql.challenges.values()])).not.toContain('callback');
    expect(JSON.stringify([...sql.challenges.values()])).not.toContain('rawChallenge');
  });

  it('fails closed on schema drift and malformed records', async () => {
    const sql = new FakeSqlStorage();
    const storage = fakeDurableStorage(sql);
    initializeCloudflareGatewayOwnershipChallengeSql(storage);
    sql.schemaVersion = 2;
    expect(() => initializeCloudflareGatewayOwnershipChallengeSql(storage)).toThrow('invalid');

    sql.schemaVersion = 1;
    const state = new CloudflareGatewayOwnershipChallengeDurableState(storage);
    await expect(state.put({
      ...record('upgrade', 'f'),
      challengeSha256: 'sha256:invalid',
    })).rejects.toMatchObject({ code: 'invalid' });
    expect(() => state.pruneExpired(-1)).toThrow('invalid');
  });

  it('stores and consumes the Stage 2 install challenge like every later fixed operation', async () => {
    const sql = new FakeSqlStorage();
    const storage = fakeDurableStorage(sql);
    initializeCloudflareGatewayOwnershipChallengeSql(storage);
    const store = new CloudflareGatewayOwnershipChallengeDurableState(storage);
    const record: CloudflareGatewayOwnershipChallengeRecord = {
      certificateSha256: CERTIFICATE_SHA256,
      operation: 'install',
      challengeSha256: `sha256:${'b'.repeat(64)}`,
      expiresAt: NOW + 60_000,
    };
    expect(await store.put(record)).toBe(true);
    expect(await store.consume(record)).toBe(true);
    expect(await store.consume(record)).toBe(false);
  });
});

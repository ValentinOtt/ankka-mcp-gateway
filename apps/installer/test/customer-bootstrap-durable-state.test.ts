import {
  CustomerBootstrapDurableStatePort,
  initializeCustomerBootstrapSql,
} from '../src/customer-bootstrap-durable-state';
import {
  consumeCustomerBootstrapCapability,
  createCustomerBootstrapCapability,
  initialCustomerBootstrapState,
} from '../src/customer-bootstrap-state';

type StoredState = { revision: number; stateJson: string };

class FakeSqlStorage {
  schemaVersion: number | null = null;
  state: StoredState | null = null;
  lastChanges = 0;

  exec<Row extends Record<string, ArrayBuffer | string | number | null>>(
    query: string,
    ...bindings: unknown[]
  ): SqlStorageCursor<Row> {
    const normalized = query.replace(/\s+/gu, ' ').trim();
    let rows: Record<string, ArrayBuffer | string | number | null>[] = [];
    let rowsWritten = 0;
    if (normalized.startsWith('CREATE TABLE IF NOT EXISTS ankka_bootstrap_schema')) {
      // no-op
    } else if (normalized.startsWith('INSERT INTO ankka_bootstrap_schema')) {
      if (this.schemaVersion === null) {
        this.schemaVersion = 1;
        rowsWritten = 1;
        this.lastChanges = 1;
      } else {
        this.lastChanges = 0;
      }
    } else if (normalized.startsWith('SELECT schema_version')) {
      if (this.schemaVersion !== null) rows = [{ schema_version: this.schemaVersion }];
    } else if (normalized.startsWith('CREATE TABLE IF NOT EXISTS ankka_bootstrap_state')) {
      // no-op
    } else if (normalized.startsWith('SELECT revision, state_json')) {
      if (this.state !== null) rows = [{ revision: this.state.revision, state_json: this.state.stateJson }];
    } else if (normalized.startsWith('INSERT INTO ankka_bootstrap_state')) {
      if (this.state === null) {
        this.state = { revision: Number(bindings[1]), stateJson: String(bindings[2]) };
        // The live runtime can report zero here after committing the write.
        // Production checks changes() immediately in the same transaction.
        rowsWritten = 0;
        this.lastChanges = 1;
      } else {
        this.lastChanges = 0;
      }
    } else if (normalized.startsWith('UPDATE ankka_bootstrap_state')) {
      const expectedRevision = Number(bindings[3]);
      if (this.state?.revision === expectedRevision) {
        this.state = { revision: Number(bindings[0]), stateJson: String(bindings[1]) };
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
    // SAFETY: every fake row above is constructed for the query-selected Row
    // shape, and the production adapter still validates all returned fields.
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

const randomBytes = (length: number): Uint8Array => new Uint8Array(length).fill(7);

describe('customer bootstrap SQLite Durable Object state', () => {
  it('initializes schema without PRAGMA metadata and atomically rejects a stale revision', async () => {
    const sql = new FakeSqlStorage();
    const storage = fakeDurableStorage(sql);
    initializeCustomerBootstrapSql(storage);
    const port = new CustomerBootstrapDurableStatePort(storage);
    const capability = await createCustomerBootstrapCapability({ now: 1_800_000_000_000, randomBytes });
    const initial = initialCustomerBootstrapState({
      installId: `acg-${'a'.repeat(24)}`,
      bootstrapId: capability.bootstrapId,
      secretCommitment: capability.secretCommitment,
      expiresAt: capability.expiresAt,
    });
    expect(await port.compareAndSet(null, initial)).toBe(true);
    expect(await port.compareAndSet(null, initial)).toBe(false);

    const first = await consumeCustomerBootstrapCapability({
      current: initial,
      bootstrapId: capability.bootstrapId,
      secret: capability.secret,
      now: 1_800_000_000_001,
      randomBytes,
    });
    const second = await consumeCustomerBootstrapCapability({
      current: initial,
      bootstrapId: capability.bootstrapId,
      secret: capability.secret,
      now: 1_800_000_000_002,
      randomBytes: (length) => new Uint8Array(length).fill(8),
    });
    expect(await port.compareAndSet(initial.revision, first.state)).toBe(true);
    expect(await port.compareAndSet(initial.revision, second.state)).toBe(false);
    expect(await port.read()).toEqual(first.state);
  });

  it('fails closed on schema drift and noncanonical or corrupted state', async () => {
    const sql = new FakeSqlStorage();
    const storage = fakeDurableStorage(sql);
    initializeCustomerBootstrapSql(storage);
    sql.schemaVersion = 2;
    expect(() => initializeCustomerBootstrapSql(storage)).toThrow('conflict');

    sql.schemaVersion = 1;
    sql.state = { revision: 1, stateJson: '{"schemaVersion":1}' };
    const port = new CustomerBootstrapDurableStatePort(storage);
    await expect(port.read()).rejects.toThrow('conflict');
  });
});

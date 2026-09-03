import {
  HostedStage1SessionDurableStatePort,
  initializeHostedStage1SessionSql,
} from '../src/hosted-stage1-session-durable-state';
import {
  initializeHostedStage1Session,
  saveHostedStage1Selection,
} from '../src/hosted-stage1-session';
import { parseDeploySelection } from '../src/schema';
import { selectionInput } from './fixtures';

const NOW = 1_800_000_000_000;

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
    if (normalized.startsWith('CREATE TABLE IF NOT EXISTS ankka_stage1_schema')) {
      // no-op
    } else if (normalized.startsWith('INSERT INTO ankka_stage1_schema')) {
      if (this.schemaVersion === null) {
        this.schemaVersion = 1;
        this.lastChanges = 1;
      } else {
        this.lastChanges = 0;
      }
    } else if (normalized.startsWith('SELECT schema_version')) {
      if (this.schemaVersion !== null) rows = [{ schema_version: this.schemaVersion }];
    } else if (normalized.startsWith('CREATE TABLE IF NOT EXISTS ankka_stage1_session')) {
      // no-op
    } else if (normalized.startsWith('SELECT revision, state_json')) {
      if (this.state !== null) rows = [{ revision: this.state.revision, state_json: this.state.stateJson }];
    } else if (normalized.startsWith('INSERT INTO ankka_stage1_session')) {
      if (this.state === null) {
        this.state = { revision: Number(bindings[1]), stateJson: String(bindings[2]) };
        this.lastChanges = 1;
      } else {
        this.lastChanges = 0;
      }
    } else if (normalized.startsWith('UPDATE ankka_stage1_session')) {
      const expectedRevision = Number(bindings[3]);
      if (this.state?.revision === expectedRevision) {
        this.state = { revision: Number(bindings[0]), stateJson: String(bindings[1]) };
        this.lastChanges = 1;
      } else {
        this.lastChanges = 0;
      }
    } else if (normalized.startsWith('DELETE FROM ankka_stage1_session')) {
      const expectedRevision = Number(bindings[1]);
      if (this.state?.revision === expectedRevision) {
        this.state = null;
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
    // shape, and the production port still validates all returned fields.
    const typedRows = rows as Row[];
    const cursor: SqlStorageCursor<Row> = Object.create(null);
    Object.defineProperties(cursor, {
      toArray: { value: (): Row[] => typedRows },
      // The live runtime reported zero here after committing; the port must
      // rely on changes() inside the same transaction instead.
      rowsWritten: { value: 0 },
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

describe('hosted Stage 1 session SQLite Durable Object port', () => {
  it('initializes the schema and applies revision-checked writes and erasure atomically', async () => {
    const sql = new FakeSqlStorage();
    const storage = fakeDurableStorage(sql);
    initializeHostedStage1SessionSql(storage);
    const port = new HostedStage1SessionDurableStatePort(storage);
    expect(await port.read()).toBeNull();

    const initial = initializeHostedStage1Session({ now: NOW, randomBytes });
    expect(await port.compareAndSet(null, initial)).toBe(true);
    expect(await port.compareAndSet(null, initial)).toBe(false);
    expect(await port.read()).toEqual(initial);

    const selection = parseDeploySelection(selectionInput);
    const first = saveHostedStage1Selection({ current: initial, selection, now: NOW + 1 });
    const second = saveHostedStage1Selection({
      current: initial, selection: parseDeploySelection({ ...selectionInput, firstSource: null }), now: NOW + 2,
    });
    expect(await port.compareAndSet(initial.revision, first)).toBe(true);
    expect(await port.compareAndSet(initial.revision, second)).toBe(false);
    expect(await port.read()).toEqual(first);

    await expect(port.compareAndSet(first.revision, first)).rejects.toMatchObject({ code: 'invalid' });
    await expect(port.compareAndSet(null, first)).rejects.toMatchObject({ code: 'invalid' });

    expect(await port.erase(initial.revision)).toBe(false);
    expect(await port.read()).toEqual(first);
    expect(await port.erase(first.revision)).toBe(true);
    expect(await port.read()).toBeNull();
    await expect(port.erase(0)).rejects.toMatchObject({ code: 'invalid' });
  });

  it('fails closed on schema drift and noncanonical, corrupted, or mismatched stored state', async () => {
    const sql = new FakeSqlStorage();
    const storage = fakeDurableStorage(sql);
    initializeHostedStage1SessionSql(storage);
    sql.schemaVersion = 2;
    expect(() => initializeHostedStage1SessionSql(storage)).toThrow('conflict');

    sql.schemaVersion = 1;
    const port = new HostedStage1SessionDurableStatePort(storage);
    sql.state = { revision: 1, stateJson: '{"schemaVersion":1}' };
    await expect(port.read()).rejects.toThrow('conflict');
    sql.state = { revision: 1, stateJson: '{not json' };
    await expect(port.read()).rejects.toThrow('conflict');

    const initial = initializeHostedStage1Session({ now: NOW, randomBytes });
    sql.state = { revision: 2, stateJson: JSON.stringify(initial) };
    await expect(port.read()).rejects.toThrow('conflict');
    sql.state = { revision: 1, stateJson: JSON.stringify({ ...initial, expiresAt: initial.expiresAt, phase: 'draft' }, null, 2) };
    await expect(port.read()).rejects.toThrow('conflict');
  });
});

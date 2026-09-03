import type {
  TwoStageDeploySessionState,
  TwoStageDeploySessionStorage,
} from '../src/two-stage-deploy-session';

type StoredState = { revision: number; stateJson: string };

/**
 * In-memory stand-in for the SQLite surface the hosted Stage 1 port uses.
 * rowsWritten is deliberately reported as zero, mirroring the live runtime
 * behavior that forced the port to read changes() inside the transaction.
 */
export class FakeHostedStage1SqlStorage {
  schemaVersion: number | null = null;
  state: StoredState | null = null;
  lastChanges = 0;

  exec<Row extends Record<string, SqlStorageValue>>(
    query: string,
    ...bindings: unknown[]
  ): SqlStorageCursor<Row> {
    const normalized = query.replace(/\s+/gu, ' ').trim();
    let rows: Record<string, SqlStorageValue>[] = [];
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
      rowsWritten: { value: 0 },
    });
    return cursor;
  }
}

export class FakeTwoStageStorage implements TwoStageDeploySessionStorage {
  readonly sqlFake = new FakeHostedStage1SqlStorage();
  alarmAt: number | null = null;
  deleteAllCalls = 0;

  get sql(): FakeHostedStage1SqlStorage {
    return this.sqlFake;
  }

  transactionSync<T>(closure: () => T): T {
    return closure();
  }

  async setAlarm(scheduledTime: number | Date): Promise<void> {
    this.alarmAt = scheduledTime instanceof Date ? scheduledTime.getTime() : scheduledTime;
  }

  async deleteAlarm(): Promise<void> {
    this.alarmAt = null;
  }

  async deleteAll(): Promise<void> {
    this.deleteAllCalls += 1;
    this.sqlFake.schemaVersion = null;
    this.sqlFake.state = null;
    this.alarmAt = null;
  }
}

export class FakeTwoStageState implements TwoStageDeploySessionState {
  readonly storage = new FakeTwoStageStorage();

  async blockConcurrencyWhile<T>(callback: () => Promise<T>): Promise<T> {
    return callback();
  }
}

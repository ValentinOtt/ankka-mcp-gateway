import { canonicalJson } from './canonical-json';
import {
  HostedStage1SessionError,
  MAX_HOSTED_STAGE1_SESSION_BYTES,
  parseHostedStage1Session,
  type HostedStage1Session,
} from './hosted-stage1-session';

const SCHEMA_VERSION = 1;
const STATE_ROW_ID = 1;

type SchemaRow = { readonly schema_version: number };
type StateRow = { readonly revision: number; readonly state_json: string };
type ChangesRow = { readonly changed: number };

/** Revision-checked port for one hosted Stage 1 session; the schema accepts no secret material. */
export interface HostedStage1SessionPort {
  read(): Promise<HostedStage1Session | null>;
  compareAndSet(expectedRevision: number | null, state: HostedStage1Session): Promise<boolean>;
  erase(expectedRevision: number): Promise<boolean>;
}

function conflict(): never {
  throw new HostedStage1SessionError('conflict');
}

/** The exact SQLite surface the port touches; a real DurableObjectStorage satisfies it structurally. */
export interface HostedStage1SqlExecutor {
  exec<Row extends Record<string, SqlStorageValue>>(query: string, ...bindings: unknown[]): SqlStorageCursor<Row>;
}

export interface HostedStage1SessionSqlStorage {
  readonly sql: HostedStage1SqlExecutor;
  transactionSync<T>(closure: () => T): T;
}

/**
 * Initializes the hosted Stage 1 session schema. Call once from the Durable
 * Object constructor inside blockConcurrencyWhile; it performs no network I/O.
 */
export function initializeHostedStage1SessionSql(storage: Pick<HostedStage1SessionSqlStorage, 'sql'>): void {
  storage.sql.exec(`
    CREATE TABLE IF NOT EXISTS ankka_stage1_schema (
      singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
      schema_version INTEGER NOT NULL CHECK (schema_version = 1)
    ) STRICT
  `);
  storage.sql.exec(`
    INSERT INTO ankka_stage1_schema (singleton, schema_version)
    VALUES (1, 1)
    ON CONFLICT(singleton) DO NOTHING
  `);
  const schema = storage.sql.exec<SchemaRow>(`
    SELECT schema_version
    FROM ankka_stage1_schema
    WHERE singleton = 1
    LIMIT 2
  `).toArray();
  if (schema.length !== 1 || schema[0]?.schema_version !== SCHEMA_VERSION) conflict();
  storage.sql.exec(`
    CREATE TABLE IF NOT EXISTS ankka_stage1_session (
      singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
      revision INTEGER NOT NULL CHECK (revision >= 1),
      state_json TEXT NOT NULL CHECK (length(state_json) BETWEEN 2 AND 65536)
    ) STRICT
  `);
}

/**
 * SQLite-backed session port. transactionSync keeps the revision predicate and
 * the write in one non-yielding transaction, and changes() is read inside that
 * same transaction because rowsWritten was not reliable on the live runtime.
 */
export class HostedStage1SessionDurableStatePort implements HostedStage1SessionPort {
  constructor(private readonly storage: HostedStage1SessionSqlStorage) {}

  async read(): Promise<HostedStage1Session | null> {
    const rows = this.storage.sql.exec<StateRow>(`
      SELECT revision, state_json
      FROM ankka_stage1_session
      WHERE singleton = ?
      LIMIT 2
    `, STATE_ROW_ID).toArray();
    if (rows.length === 0) return null;
    const row = rows[0];
    if (rows.length !== 1 || row === undefined || !Number.isSafeInteger(row.revision) ||
        row.revision < 1 || row.state_json.length > MAX_HOSTED_STAGE1_SESSION_BYTES) conflict();
    let decoded: unknown;
    try {
      decoded = JSON.parse(row.state_json);
    } catch {
      conflict();
    }
    const session = parseHostedStage1Session(decoded);
    if (session === null || session.revision !== row.revision || canonicalJson(session) !== row.state_json) {
      conflict();
    }
    return session;
  }

  async compareAndSet(expectedRevision: number | null, state: HostedStage1Session): Promise<boolean> {
    const parsed = parseHostedStage1Session(state);
    if (parsed === null || (expectedRevision === null
      ? parsed.revision !== 1
      : !Number.isSafeInteger(expectedRevision) || expectedRevision < 1 ||
        parsed.revision !== expectedRevision + 1)) {
      throw new HostedStage1SessionError('invalid');
    }
    const serialized = canonicalJson(parsed);
    if (new TextEncoder().encode(serialized).byteLength > MAX_HOSTED_STAGE1_SESSION_BYTES) {
      throw new HostedStage1SessionError('invalid');
    }
    return this.storage.transactionSync(() => {
      if (expectedRevision === null) {
        this.storage.sql.exec(`
          INSERT INTO ankka_stage1_session (singleton, revision, state_json)
          VALUES (?, ?, ?)
          ON CONFLICT(singleton) DO NOTHING
        `, STATE_ROW_ID, parsed.revision, serialized);
      } else {
        this.storage.sql.exec(`
          UPDATE ankka_stage1_session
          SET revision = ?, state_json = ?
          WHERE singleton = ? AND revision = ?
        `, parsed.revision, serialized, STATE_ROW_ID, expectedRevision);
      }
      const changes = this.storage.sql.exec<ChangesRow>('SELECT changes() AS changed').toArray();
      return changes.length === 1 && changes[0]?.changed === 1;
    });
  }

  async erase(expectedRevision: number): Promise<boolean> {
    if (!Number.isSafeInteger(expectedRevision) || expectedRevision < 1) {
      throw new HostedStage1SessionError('invalid');
    }
    return this.storage.transactionSync(() => {
      this.storage.sql.exec(`
        DELETE FROM ankka_stage1_session
        WHERE singleton = ? AND revision = ?
      `, STATE_ROW_ID, expectedRevision);
      const changes = this.storage.sql.exec<ChangesRow>('SELECT changes() AS changed').toArray();
      return changes.length === 1 && changes[0]?.changed === 1;
    });
  }
}

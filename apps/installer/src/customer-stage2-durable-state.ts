import { canonicalJson } from './canonical-json';
import {
  CustomerStage2JournalError,
  parseCustomerStage2Journal,
  type CustomerStage2Journal,
} from './customer-stage2-journal';

const SCHEMA_VERSION = 1;
const STATE_ROW_ID = 1;
const MAX_STATE_BYTES = 256 * 1024;

type SchemaRow = { readonly schema_version: number };
type StateRow = { readonly revision: number; readonly state_json: string };
type ChangesRow = { readonly changed: number };

export interface CustomerStage2JournalPort {
  read(): Promise<CustomerStage2Journal | null>;
  compareAndSet(expectedRevision: number | null, state: CustomerStage2Journal): Promise<boolean>;
}

function conflict(): never {
  throw new CustomerStage2JournalError('conflict');
}

/** Initialize the customer-owned, credential-free Stage 2 journal schema. */
export function initializeCustomerStage2Sql(storage: DurableObjectStorage): void {
  storage.sql.exec(`
    CREATE TABLE IF NOT EXISTS ankka_stage2_schema (
      singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
      schema_version INTEGER NOT NULL CHECK (schema_version = 1)
    ) STRICT
  `);
  storage.sql.exec(`
    INSERT INTO ankka_stage2_schema (singleton, schema_version)
    VALUES (1, 1)
    ON CONFLICT(singleton) DO NOTHING
  `);
  const schema = storage.sql.exec<SchemaRow>(`
    SELECT schema_version
    FROM ankka_stage2_schema
    WHERE singleton = 1
    LIMIT 2
  `).toArray();
  if (schema.length !== 1 || schema[0]?.schema_version !== SCHEMA_VERSION) conflict();
  storage.sql.exec(`
    CREATE TABLE IF NOT EXISTS ankka_stage2_journal (
      singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
      revision INTEGER NOT NULL CHECK (revision >= 1),
      state_json TEXT NOT NULL CHECK (length(state_json) BETWEEN 2 AND 262144)
    ) STRICT
  `);
}

/** Atomic revision port; no token, code, verifier, or provider response is accepted by its schema. */
export class CustomerStage2DurableStatePort implements CustomerStage2JournalPort {
  constructor(private readonly storage: DurableObjectStorage) {}

  async read(): Promise<CustomerStage2Journal | null> {
    const rows = this.storage.sql.exec<StateRow>(`
      SELECT revision, state_json
      FROM ankka_stage2_journal
      WHERE singleton = ?
      LIMIT 2
    `, STATE_ROW_ID).toArray();
    if (rows.length === 0) return null;
    const row = rows[0];
    if (rows.length !== 1 || row === undefined || row.state_json.length > MAX_STATE_BYTES) conflict();
    let decoded: unknown;
    try {
      decoded = JSON.parse(row.state_json);
    } catch {
      conflict();
    }
    const journal = parseCustomerStage2Journal(decoded);
    if (journal === null || journal.revision !== row.revision || canonicalJson(journal) !== row.state_json) {
      conflict();
    }
    return journal;
  }

  async compareAndSet(expectedRevision: number | null, state: CustomerStage2Journal): Promise<boolean> {
    const parsed = parseCustomerStage2Journal(state);
    if (parsed === null || (expectedRevision === null
      ? parsed.revision !== 1
      : !Number.isSafeInteger(expectedRevision) || expectedRevision < 1 ||
        parsed.revision !== expectedRevision + 1)) {
      throw new CustomerStage2JournalError('invalid');
    }
    const serialized = canonicalJson(parsed);
    if (new TextEncoder().encode(serialized).byteLength > MAX_STATE_BYTES) {
      throw new CustomerStage2JournalError('invalid');
    }
    return this.storage.transactionSync(() => {
      if (expectedRevision === null) {
        this.storage.sql.exec(`
          INSERT INTO ankka_stage2_journal (singleton, revision, state_json)
          VALUES (?, ?, ?)
          ON CONFLICT(singleton) DO NOTHING
        `, STATE_ROW_ID, parsed.revision, serialized);
      } else {
        this.storage.sql.exec(`
          UPDATE ankka_stage2_journal
          SET revision = ?, state_json = ?
          WHERE singleton = ? AND revision = ?
        `, parsed.revision, serialized, STATE_ROW_ID, expectedRevision);
      }
      const changes = this.storage.sql.exec<ChangesRow>('SELECT changes() AS changed').toArray();
      return changes.length === 1 && changes[0]?.changed === 1;
    });
  }
}

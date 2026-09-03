import { canonicalJson } from './canonical-json';
import {
  CustomerBootstrapStateError,
  parseCustomerBootstrapState,
  type CustomerBootstrapState,
} from './customer-bootstrap-state';
import type { CustomerBootstrapStatePort } from './customer-bootstrap-router';

const SCHEMA_VERSION = 1;
const STATE_ROW_ID = 1;

type BootstrapStateRow = {
  readonly revision: number;
  readonly state_json: string;
};

type BootstrapSchemaRow = {
  readonly schema_version: number;
};

type ChangesRow = {
  readonly changed: number;
};

function conflict(): never {
  throw new CustomerBootstrapStateError('conflict');
}

/**
 * Initializes the bootstrap-only SQLite schema. Call this once from a Durable
 * Object constructor inside blockConcurrencyWhile; it performs no network I/O.
 */
export function initializeCustomerBootstrapSql(storage: DurableObjectStorage): void {
  storage.sql.exec(`
    CREATE TABLE IF NOT EXISTS ankka_bootstrap_schema (
      singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
      schema_version INTEGER NOT NULL CHECK (schema_version = 1)
    ) STRICT
  `);
  storage.sql.exec(`
    INSERT INTO ankka_bootstrap_schema (singleton, schema_version)
    VALUES (1, 1)
    ON CONFLICT(singleton) DO NOTHING
  `);
  const schemaRows = storage.sql.exec<BootstrapSchemaRow>(`
    SELECT schema_version
    FROM ankka_bootstrap_schema
    WHERE singleton = 1
    LIMIT 2
  `).toArray();
  if (schemaRows.length !== 1 || schemaRows[0]?.schema_version !== SCHEMA_VERSION) conflict();

  storage.sql.exec(`
    CREATE TABLE IF NOT EXISTS ankka_bootstrap_state (
      singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
      revision INTEGER NOT NULL CHECK (revision >= 1),
      state_json TEXT NOT NULL CHECK (length(state_json) BETWEEN 2 AND 16384)
    ) STRICT
  `);
}

/**
 * SQLite-backed state port for the restricted bootstrap release. Cloudflare's
 * transactionSync keeps the revision predicate and write in one non-yielding
 * transaction even when concurrent requests interleave around provider I/O.
 */
export class CustomerBootstrapDurableStatePort implements CustomerBootstrapStatePort {
  constructor(private readonly storage: DurableObjectStorage) {}

  async read(): Promise<CustomerBootstrapState | null> {
    const rows = this.storage.sql.exec<BootstrapStateRow>(`
      SELECT revision, state_json
      FROM ankka_bootstrap_state
      WHERE singleton = ?
      LIMIT 2
    `, STATE_ROW_ID).toArray();
    if (rows.length === 0) return null;
    const row = rows[0];
    if (rows.length !== 1 || row === undefined || !Number.isSafeInteger(row.revision) ||
        row.revision < 1 || row.state_json.length > 16_384) conflict();
    let decoded: unknown;
    try {
      decoded = JSON.parse(row.state_json);
    } catch {
      conflict();
    }
    const state = parseCustomerBootstrapState(decoded);
    if (state === null || state.revision !== row.revision || canonicalJson(state) !== row.state_json) conflict();
    return state;
  }

  async compareAndSet(
    expectedRevision: number | null,
    state: CustomerBootstrapState,
  ): Promise<boolean> {
    const parsed = parseCustomerBootstrapState(state);
    if (parsed === null || (expectedRevision === null
      ? parsed.revision !== 1
      : !Number.isSafeInteger(expectedRevision) || expectedRevision < 1 ||
        parsed.revision !== expectedRevision + 1)) {
      throw new CustomerBootstrapStateError('invalid');
    }
    const serialized = canonicalJson(parsed);
    if (serialized.length > 16_384) throw new CustomerBootstrapStateError('invalid');

    return this.storage.transactionSync(() => {
      if (expectedRevision === null) {
        this.storage.sql.exec(`
          INSERT INTO ankka_bootstrap_state (singleton, revision, state_json)
          VALUES (?, ?, ?)
          ON CONFLICT(singleton) DO NOTHING
        `, STATE_ROW_ID, parsed.revision, serialized);
      } else {
        this.storage.sql.exec(`
          UPDATE ankka_bootstrap_state
          SET revision = ?, state_json = ?
          WHERE singleton = ? AND revision = ?
        `, parsed.revision, serialized, STATE_ROW_ID, expectedRevision);
      }
      const changes = this.storage.sql.exec<ChangesRow>(
        'SELECT changes() AS changed',
      ).toArray();
      return changes.length === 1 && changes[0]?.changed === 1;
    });
  }
}

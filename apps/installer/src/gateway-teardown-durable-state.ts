import { canonicalJson } from './canonical-json';
import { parseGatewayTeardownJob, type GatewayTeardownJob } from './gateway-teardown-job';
import type { HostedStage1SessionSqlStorage } from './hosted-stage1-session-durable-state';

export interface GatewayTeardownJobPort {
  read(): Promise<GatewayTeardownJob | null>;
  compareAndSet(expectedRevision: number | null, job: GatewayTeardownJob): Promise<boolean>;
}
const MAX_BYTES = 64 * 1024;
type JobRow = { revision: number; state_json: string };

function invalid(): never { throw new Error('teardown_job_invalid'); }

export function initializeGatewayTeardownSql(storage: Pick<HostedStage1SessionSqlStorage, 'sql'>): void {
  storage.sql.exec(`CREATE TABLE IF NOT EXISTS ankka_gateway_teardown (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    revision INTEGER NOT NULL CHECK (revision >= 1),
    state_json TEXT NOT NULL CHECK (length(state_json) BETWEEN 2 AND 65536)
  ) STRICT`);
}

/** No expiry alarm erases this journal: it must survive removal of the customer gateway. */
export class GatewayTeardownDurableStatePort implements GatewayTeardownJobPort {
  constructor(private readonly storage: HostedStage1SessionSqlStorage) {}

  private readSync(): GatewayTeardownJob | null {
    const rows = this.storage.sql.exec<JobRow>(
      'SELECT revision, state_json FROM ankka_gateway_teardown WHERE singleton = 1 LIMIT 2',
    ).toArray();
    if (rows.length === 0) return null;
    const row = rows[0];
    if (rows.length !== 1 || row === undefined || row.state_json.length > MAX_BYTES) invalid();
    try {
      const job = parseGatewayTeardownJob(JSON.parse(row.state_json));
      if (job.revision !== row.revision || canonicalJson(job) !== row.state_json) invalid();
      return job;
    } catch { invalid(); }
  }

  async read(): Promise<GatewayTeardownJob | null> { return this.readSync(); }

  async compareAndSet(expectedRevision: number | null, input: GatewayTeardownJob): Promise<boolean> {
    const job = parseGatewayTeardownJob(input);
    if (expectedRevision === null ? job.revision !== 1 || job.phase !== 'review'
      : !Number.isSafeInteger(expectedRevision) || expectedRevision < 1 || job.revision !== expectedRevision + 1) invalid();
    const serialized = canonicalJson(job);
    if (new TextEncoder().encode(serialized).byteLength > MAX_BYTES) invalid();
    return this.storage.transactionSync(() => {
      const previous = this.readSync();
      if ((previous?.revision ?? null) !== expectedRevision) return false;
      if (previous !== null) {
        if (previous.handoff !== job.handoff || previous.handoffSha256 !== job.handoffSha256 ||
            previous.acceptedAt !== job.acceptedAt || previous.updatedAt > job.updatedAt ||
            canonicalJson(previous.release) !== canonicalJson(job.release) ||
            previous.retirementModuleSha256 !== job.retirementModuleSha256 ||
            previous.verifiedSteps.some((step, index) => job.verifiedSteps[index] !== step) ||
            previous.phase.startsWith('removed') ||
            (previous.revocation === 'unconfirmed' && job.revocation !== 'unconfirmed')) invalid();
        this.storage.sql.exec('UPDATE ankka_gateway_teardown SET revision = ?, state_json = ? WHERE singleton = 1 AND revision = ?',
          job.revision, serialized, expectedRevision);
      } else {
        this.storage.sql.exec('INSERT INTO ankka_gateway_teardown (singleton, revision, state_json) VALUES (1, ?, ?)', job.revision, serialized);
      }
      const changes = this.storage.sql.exec<{ changed: number }>('SELECT changes() AS changed').toArray();
      return changes.length === 1 && changes[0]?.changed === 1;
    });
  }
}

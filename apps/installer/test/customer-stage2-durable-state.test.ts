import {
  CustomerStage2DurableStatePort,
  initializeCustomerStage2Sql,
} from '../src/customer-stage2-durable-state';
import { createCustomerStage2Journal } from '../src/customer-stage2-journal';
import type { CustomerGatewayFreshPreflightAttestation } from
  '../src/cloudflare-gateway-fresh-preflight';

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
    if (normalized.startsWith('CREATE TABLE IF NOT EXISTS ankka_stage2_schema') ||
        normalized.startsWith('CREATE TABLE IF NOT EXISTS ankka_stage2_journal')) {
      // no-op
    } else if (normalized.startsWith('INSERT INTO ankka_stage2_schema')) {
      if (this.schemaVersion === null) {
        this.schemaVersion = 1;
        this.lastChanges = 1;
      } else {
        this.lastChanges = 0;
      }
    } else if (normalized.startsWith('SELECT schema_version')) {
      if (this.schemaVersion !== null) rows = [{ schema_version: this.schemaVersion }];
    } else if (normalized.startsWith('SELECT revision, state_json')) {
      if (this.state !== null) rows = [{ revision: this.state.revision, state_json: this.state.stateJson }];
    } else if (normalized.startsWith('INSERT INTO ankka_stage2_journal')) {
      if (this.state === null) {
        this.state = { revision: Number(bindings[1]), stateJson: String(bindings[2]) };
        this.lastChanges = 1;
      } else {
        this.lastChanges = 0;
      }
    } else if (normalized.startsWith('UPDATE ankka_stage2_journal')) {
      const expectedRevision = Number(bindings[3]);
      if (this.state?.revision === expectedRevision) {
        this.state = { revision: Number(bindings[0]), stateJson: String(bindings[1]) };
        this.lastChanges = 1;
      } else {
        this.lastChanges = 0;
      }
    } else if (normalized === 'SELECT changes() AS changed') {
      rows = [{ changed: this.lastChanges }];
    } else {
      throw new Error('unexpected SQL');
    }
    const cursor: SqlStorageCursor<Row> = Object.create(null);
    Object.defineProperties(cursor, {
      toArray: { value: () => rows as Row[] },
      rowsWritten: { value: 0 },
    });
    return cursor;
  }
}

function durableStorage(sql: FakeSqlStorage): DurableObjectStorage {
  const storage: DurableObjectStorage = Object.create(null);
  Object.defineProperties(storage, {
    sql: { value: sql },
    transactionSync: { value: <Value>(closure: () => Value): Value => closure() },
  });
  return storage;
}

const NOW = 1_800_000_000_000;
const ACCOUNT_ID = 'a'.repeat(32);
const ZONE_ID = 'b'.repeat(32);
const INSTALL_ID = `acg-${'c'.repeat(24)}`;
const PLAN_ID = `plan-${'d'.repeat(24)}`;
const PLAN_HASH = `sha256:${'e'.repeat(64)}`;
const CONFIGURATION_HASH = `sha256:${'f'.repeat(64)}`;
const DESIRED_HASH = `sha256:${'1'.repeat(64)}`;
const RELEASE_HASH = '2'.repeat(64);

const preflight: CustomerGatewayFreshPreflightAttestation = {
  schemaVersion: 1,
  kind: 'customer_gateway_fresh_preflight',
  accountId: ACCOUNT_ID,
  zoneId: ZONE_ID,
  planId: PLAN_ID,
  planHash: PLAN_HASH,
  installationId: INSTALL_ID,
  configurationHash: CONFIGURATION_HASH,
  desiredHash: DESIRED_HASH,
  releaseId: 'gateway-v1.0.0',
  releaseArtifactSha256: RELEASE_HASH,
  zeroCandidateKinds: ['portal', 'portal_access_application', 'portal_access_policy', 'dns_record'],
  checkedAt: NOW - 1,
  expiresAt: NOW + 30_000,
  attestationHash: `sha256:${'3'.repeat(64)}`,
};

function journal() {
  return createCustomerStage2Journal({
    now: NOW,
    leaseExpiresAt: NOW + 300_000,
    attemptId: `attempt_${'g'.repeat(24)}`,
    identity: {
      accountId: ACCOUNT_ID,
      zoneId: ZONE_ID,
      zoneName: 'example.com',
      installId: INSTALL_ID,
      planId: PLAN_ID,
      planHash: PLAN_HASH,
      configurationHash: CONFIGURATION_HASH,
      desiredHash: DESIRED_HASH,
      workerName: 'ankka-gateway-stage2-test',
      workerId: '4'.repeat(32),
      namespaceId: '5'.repeat(32),
      bootstrapVersionId: '11111111-1111-4111-8111-111111111111',
      releaseId: 'gateway-v1.0.0',
      releaseArtifactSha256: RELEASE_HASH,
      finalRuntimeSha256: '6'.repeat(64),
      updateChannel: 'stable',
      updateKeyId: 'release-key-v1',
      updatePublicKey: 'H'.repeat(43),
      ownershipReceiptSha256: `sha256:${'7'.repeat(64)}`,
    },
    organization: {
      name: 'Example team',
      authDomain: 'example.cloudflareaccess.com',
      issuer: 'https://example.cloudflareaccess.com',
    },
    identityProviderIds: ['8'.repeat(32)],
    workersSubdomain: 'tenant',
    preflight,
  });
}

describe('customer Stage 2 SQLite journal', () => {
  it('atomically creates one canonical journal and rejects stale creation', async () => {
    const sql = new FakeSqlStorage();
    const storage = durableStorage(sql);
    initializeCustomerStage2Sql(storage);
    const port = new CustomerStage2DurableStatePort(storage);
    const value = journal();
    await expect(port.compareAndSet(null, value)).resolves.toBe(true);
    await expect(port.compareAndSet(null, value)).resolves.toBe(false);
    await expect(port.read()).resolves.toEqual(value);
  });

  it('fails closed on schema drift and noncanonical state', async () => {
    const sql = new FakeSqlStorage();
    const storage = durableStorage(sql);
    initializeCustomerStage2Sql(storage);
    sql.schemaVersion = 2;
    expect(() => initializeCustomerStage2Sql(storage)).toThrow('conflict');
    sql.schemaVersion = 1;
    sql.state = { revision: 1, stateJson: '{"schemaVersion":1}' };
    await expect(new CustomerStage2DurableStatePort(storage).read()).rejects.toThrow('conflict');
  });
});

import { describe, expect, it } from 'vitest';
import { GatewayTeardownDurableStatePort, initializeGatewayTeardownSql } from '../src/gateway-teardown-durable-state';
import { authorizeGatewayTeardownJob } from '../src/gateway-teardown-job';
import { gatewayTeardownFixture, ROOT_TEST } from './gateway-teardown-fixture';
import { teardownSqliteFixture } from './gateway-teardown-sqlite-fixture';

describe('hosted removal SQLite state', () => {
  it('survives reopening and rejects stale writes or changed accepted authority', async () => {
    const sql = teardownSqliteFixture();
    try {
      initializeGatewayTeardownSql(sql.storage);
      const port = new GatewayTeardownDurableStatePort(sql.storage);
      const { job } = await gatewayTeardownFixture();
      expect(await port.read()).toBeNull();
      expect(await port.compareAndSet(null, job)).toBe(true);
      expect(await port.compareAndSet(null, job)).toBe(false);
      const started = authorizeGatewayTeardownJob({ job, attemptId: `attempt_${'a'.repeat(24)}`,
        stateHash: 's'.repeat(43), verifierHash: 'v'.repeat(43), now: ROOT_TEST.now + 1 });
      for (const changed of [
        { acceptedAt: job.acceptedAt - 1 }, { handoff: 'different' }, { retirementModuleSha256: 'f'.repeat(64) },
        { release: { ...job.release, release: 'gateway-v9.0.0' } },
      ]) await expect(port.compareAndSet(job.revision, { ...started, ...changed })).rejects.toThrow();
      expect(await port.read()).toEqual(job);
      expect(await port.compareAndSet(job.revision, started)).toBe(true);
      expect(await port.compareAndSet(job.revision, started)).toBe(false);
      const reopened = new GatewayTeardownDurableStatePort(sql.storage);
      expect(await reopened.read()).toEqual(started);
      sql.storage.sql.exec('UPDATE ankka_gateway_teardown SET state_json = ? WHERE singleton = 1', JSON.stringify(started, null, 2));
      await expect(reopened.read()).rejects.toThrow('teardown_job_invalid');
    } finally { sql.close(); }
  });
});

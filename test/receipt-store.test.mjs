import * as fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import assert from 'node:assert/strict';
import {
  ReceiptStoreError,
  STALE_LOCK_RECOVERY_CONFIRMATION,
  createFileReceiptStore,
} from '../src/receipt-store.mjs';

async function fixture(t) {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'acg-receipt-store-'));
  t.after(() => fs.rm(directory, { recursive: true, force: true }));
  return {
    directory,
    file: path.join(directory, 'installation-receipt.json'),
  };
}

async function writeLockDirectory(lockDirectory, metadata, raw = JSON.stringify(metadata)) {
  await fs.mkdir(lockDirectory, { mode: 0o700 });
  const metadataFile = path.join(lockDirectory, `${metadata.lockId}.json`);
  await fs.writeFile(metadataFile, raw, { mode: 0o600 });
  return metadataFile;
}

test('requires an explicit file path', () => {
  assert.throws(() => createFileReceiptStore(), /explicit receipt file path/);
  assert.throws(() => createFileReceiptStore(''), /explicit receipt file path/);
});

test('reads a missing receipt as null and writes owner-only JSON', async (t) => {
  const { file } = await fixture(t);
  const store = createFileReceiptStore(file);
  assert.equal(await store.read(), null);

  const receipt = { schemaVersion: 1, state: 'ready' };
  await store.writeAtomic(receipt);

  assert.deepEqual(await store.read(), receipt);
  assert.equal((await fs.stat(file)).mode & 0o777, 0o600);
});

test('atomically replaces an existing receipt without leftover temp files', async (t) => {
  const { directory, file } = await fixture(t);
  const store = createFileReceiptStore(file);
  await store.writeAtomic({ revision: 1 });
  await store.writeAtomic({ revision: 2 });

  assert.deepEqual(JSON.parse(await fs.readFile(file, 'utf8')), { revision: 2 });
  assert.deepEqual(await fs.readdir(directory), ['installation-receipt.json']);
  assert.equal((await fs.stat(file)).mode & 0o777, 0o600);
});

test('reports invalid JSON without reflecting contents or the file path', async (t) => {
  const { file } = await fixture(t);
  const marker = 'private-receipt-material';
  await fs.writeFile(file, `{${marker}`, { mode: 0o600 });

  await assert.rejects(createFileReceiptStore(file).read(), (error) => {
    assert.ok(error instanceof ReceiptStoreError);
    assert.equal(error.code, 'invalid_json');
    assert.doesNotMatch(error.message, new RegExp(marker));
    assert.doesNotMatch(error.message, new RegExp(path.basename(file)));
    return true;
  });
});

test('rejects symlink and non-regular receipt targets', async (t) => {
  const { directory } = await fixture(t);
  const actual = path.join(directory, 'actual.json');
  const link = path.join(directory, 'linked.json');
  await fs.writeFile(actual, '{"unchanged":true}', { mode: 0o600 });
  await fs.symlink(actual, link);

  const linkedStore = createFileReceiptStore(link);
  await assert.rejects(linkedStore.read(), (error) => error.code === 'unsafe_target');
  await assert.rejects(
    linkedStore.writeAtomic({ changed: true }),
    (error) => error.code === 'unsafe_target',
  );
  assert.equal(await fs.readFile(actual, 'utf8'), '{"unchanged":true}');

  const directoryStore = createFileReceiptStore(directory);
  await assert.rejects(directoryStore.read(), (error) => error.code === 'unsafe_target');
});

test('injected replacement failure keeps prior receipt and cleans temp file', async (t) => {
  const { directory, file } = await fixture(t);
  await fs.writeFile(file, '{"revision":1}', { mode: 0o600 });
  const marker = 'private-injected-error';
  const injected = {
    ...fs,
    async rename() {
      const error = new Error(marker);
      error.code = 'EIO';
      throw error;
    },
  };
  const store = createFileReceiptStore(file, { fs: injected });

  await assert.rejects(store.writeAtomic({ revision: 2 }), (error) => {
    assert.ok(error instanceof ReceiptStoreError);
    assert.equal(error.code, 'eio');
    assert.doesNotMatch(error.message, new RegExp(marker));
    assert.doesNotMatch(error.message, new RegExp(path.basename(file)));
    return true;
  });
  assert.equal(await fs.readFile(file, 'utf8'), '{"revision":1}');
  assert.deepEqual(await fs.readdir(directory), ['installation-receipt.json']);
});

test('serializes mutations with a fail-closed exclusive lock', async (t) => {
  const { directory, file } = await fixture(t);
  const firstStore = createFileReceiptStore(file);
  const secondStore = createFileReceiptStore(file);
  let release;
  let signalAcquired;
  const acquired = new Promise((resolve) => { signalAcquired = resolve; });
  const gate = new Promise((resolve) => { release = resolve; });

  const first = firstStore.withExclusiveLock(
    async () => {
      signalAcquired();
      await gate;
      return 'complete';
    },
    { operationId: 'test-install' },
  );
  await acquired;
  const lockFile = path.join(directory, '.installation-receipt.json.lock');
  assert.equal((await fs.stat(lockFile)).mode & 0o777, 0o700);
  const inspection = await secondStore.inspectLock();
  assert.equal(inspection.status, 'live');
  assert.deepEqual(inspection.metadata, inspection.evidence);
  assert.equal(inspection.metadata.version, 1);
  assert.equal(inspection.metadata.pid, process.pid);
  assert.equal(inspection.metadata.operationId, 'test-install');
  assert.match(inspection.metadata.lockId, /^[A-Za-z0-9-]+$/);
  assert.match(inspection.metadata.ownerId, /^[A-Za-z0-9-]+$/);
  assert.equal(new Date(inspection.metadata.createdAt).toISOString(), inspection.metadata.createdAt);
  assert.doesNotMatch(JSON.stringify(inspection), new RegExp(path.basename(file)));
  const metadataFile = path.join(lockFile, `${inspection.metadata.lockId}.json`);
  assert.equal((await fs.stat(metadataFile)).mode & 0o777, 0o600);
  assert.deepEqual(JSON.parse(await fs.readFile(metadataFile, 'utf8')), inspection.metadata);

  await assert.rejects(
    secondStore.recoverStaleLock({
      evidence: inspection.evidence,
      confirmation: STALE_LOCK_RECOVERY_CONFIRMATION,
    }),
    (error) => error.code === 'lock_live',
  );

  await assert.rejects(secondStore.withExclusiveLock(async () => 'duplicate'), (error) => {
    assert.ok(error instanceof ReceiptStoreError);
    assert.equal(error.code, 'locked');
    assert.doesNotMatch(error.message, new RegExp(path.basename(file)));
    return true;
  });

  release();
  assert.equal(await first, 'complete');
  assert.deepEqual(await fs.readdir(directory), []);
  assert.equal(await secondStore.withExclusiveLock(async () => 'next'), 'next');
});

test('recovers only an inspected stale lock with exact evidence and confirmation', async (t) => {
  const { directory, file } = await fixture(t);
  const lockFile = path.join(directory, '.installation-receipt.json.lock');
  const metadata = {
    version: 1,
    lockId: 'stale-lock-id',
    ownerId: 'stale-owner-id',
    pid: 99999999,
    createdAt: '2026-08-22T12:00:00.000Z',
    operationId: 'test-install',
  };
  const metadataFile = await writeLockDirectory(lockFile, metadata);
  const store = createFileReceiptStore(file, {
    processProbe: async () => 'not_running',
  });

  await assert.rejects(store.withExclusiveLock(async () => 'must-not-run'), (error) => {
    assert.equal(error.code, 'locked');
    return true;
  });
  const inspection = await store.inspectLock();
  assert.deepEqual(inspection, {
    status: 'stale_candidate',
    metadata,
    evidence: metadata,
  });

  await assert.rejects(
    store.recoverStaleLock({ evidence: inspection.evidence, confirmation: 'yes' }),
    (error) => error.code === 'confirmation_required',
  );
  await assert.rejects(
    store.recoverStaleLock({
      evidence: { ...inspection.evidence, lockId: 'different-lock-id' },
      confirmation: STALE_LOCK_RECOVERY_CONFIRMATION,
    }),
    (error) => error.code === 'lock_evidence_mismatch',
  );
  assert.deepEqual(JSON.parse(await fs.readFile(metadataFile, 'utf8')), metadata);

  assert.deepEqual(
    await store.recoverStaleLock({
      evidence: inspection.evidence,
      confirmation: STALE_LOCK_RECOVERY_CONFIRMATION,
    }),
    { status: 'removed', lockId: metadata.lockId },
  );
  assert.equal(await store.inspectLock(), null);
  assert.equal(await store.withExclusiveLock(async () => 'recovered'), 'recovered');
});

test('fails closed for ambiguous, malformed, and replaced locks', async (t) => {
  const { directory, file } = await fixture(t);
  const lockFile = path.join(directory, '.installation-receipt.json.lock');
  const metadata = {
    version: 1,
    lockId: 'first-lock-id',
    ownerId: 'first-owner-id',
    pid: 99999999,
    createdAt: '2026-08-22T12:00:00.000Z',
    operationId: 'test-install',
  };
  let metadataFile = await writeLockDirectory(lockFile, metadata);
  const ambiguousStore = createFileReceiptStore(file, {
    processProbe: async () => 'ambiguous',
  });
  const ambiguous = await ambiguousStore.inspectLock();
  assert.equal(ambiguous.status, 'ambiguous');
  await assert.rejects(
    ambiguousStore.recoverStaleLock({
      evidence: ambiguous.evidence,
      confirmation: STALE_LOCK_RECOVERY_CONFIRMATION,
    }),
    (error) => error.code === 'lock_ambiguous',
  );

  const staleStore = createFileReceiptStore(file, {
    processProbe: async () => 'not_running',
  });
  const stale = await staleStore.inspectLock();
  const replacement = { ...metadata, lockId: 'replacement-lock-id' };
  await fs.unlink(metadataFile);
  metadataFile = path.join(lockFile, `${replacement.lockId}.json`);
  await fs.writeFile(metadataFile, JSON.stringify(replacement), { mode: 0o600 });
  await assert.rejects(
    staleStore.recoverStaleLock({
      evidence: stale.evidence,
      confirmation: STALE_LOCK_RECOVERY_CONFIRMATION,
    }),
    (error) => error.code === 'lock_evidence_mismatch',
  );

  const marker = 'private-lock-material';
  await fs.writeFile(metadataFile, `{${marker}`, { mode: 0o600 });
  const malformed = await staleStore.inspectLock();
  assert.deepEqual(malformed, {
    status: 'ambiguous',
    reason: 'invalid_lock_metadata',
  });
  assert.doesNotMatch(JSON.stringify(malformed), new RegExp(marker));
  assert.doesNotMatch(JSON.stringify(malformed), new RegExp(path.basename(file)));
});

test('treats an empty crash-left lock directory as ambiguous', async (t) => {
  const { directory, file } = await fixture(t);
  const lockDirectory = path.join(directory, '.installation-receipt.json.lock');
  await fs.mkdir(lockDirectory, { mode: 0o700 });
  const store = createFileReceiptStore(file, {
    processProbe: async () => 'not_running',
  });

  assert.deepEqual(await store.inspectLock(), {
    status: 'ambiguous',
    reason: 'invalid_lock_metadata',
  });
  await assert.rejects(store.withExclusiveLock(async () => 'must-not-run'), (error) => {
    assert.equal(error.code, 'locked');
    return true;
  });
  assert.deepEqual(await fs.readdir(lockDirectory), []);
});

test('concurrent stale recovery cannot unlink a newly acquired live lock', async (t) => {
  const { directory, file } = await fixture(t);
  const lockFile = path.join(directory, '.installation-receipt.json.lock');
  const metadata = {
    version: 1,
    lockId: 'concurrent-stale-lock',
    ownerId: 'concurrent-stale-owner',
    pid: 99999999,
    createdAt: '2026-08-22T12:00:00.000Z',
    operationId: 'test-recovery',
  };
  const metadataFile = await writeLockDirectory(lockFile, metadata);

  let signalCanonicalRemoved;
  let resumeFirst;
  const canonicalRemoved = new Promise((resolve) => { signalCanonicalRemoved = resolve; });
  const firstMayFinish = new Promise((resolve) => { resumeFirst = resolve; });
  let paused = false;
  const firstStore = createFileReceiptStore(file, {
    processProbe: async (pid) => pid === metadata.pid ? 'not_running' : 'live',
    fs: {
      ...fs,
      async unlink(target) {
        if (!paused && target === metadataFile) {
          paused = true;
          signalCanonicalRemoved();
          await firstMayFinish;
        }
        await fs.unlink(target);
      },
    },
  });
  const secondStore = createFileReceiptStore(file, {
    processProbe: async (pid) => pid === metadata.pid ? 'not_running' : 'live',
  });
  const inspection = await firstStore.inspectLock();
  const recovery = {
    evidence: inspection.evidence,
    confirmation: STALE_LOCK_RECOVERY_CONFIRMATION,
  };

  const firstRecovery = firstStore.recoverStaleLock(recovery);
  await canonicalRemoved;
  assert.deepEqual(await secondStore.recoverStaleLock(recovery), {
    status: 'removed',
    lockId: metadata.lockId,
  });

  let releaseLive;
  let signalLive;
  const live = new Promise((resolve) => { signalLive = resolve; });
  const liveGate = new Promise((resolve) => { releaseLive = resolve; });
  const liveOperation = secondStore.withExclusiveLock(async () => {
    signalLive();
    await liveGate;
    return 'live-complete';
  });
  await live;
  resumeFirst();
  await assert.rejects(firstRecovery, (error) => error.code === 'lock_replaced');
  assert.equal((await secondStore.inspectLock()).status, 'live');
  releaseLive();
  assert.equal(await liveOperation, 'live-complete');
});

test('normal release leaves a replacement lock intact and reports failure', async (t) => {
  const { directory, file } = await fixture(t);
  const lockFile = path.join(directory, '.installation-receipt.json.lock');
  const replacement = {
    version: 1,
    lockId: 'replacement-live-lock',
    ownerId: 'replacement-live-owner',
    pid: process.pid,
    createdAt: '2026-08-22T12:00:00.000Z',
    operationId: 'replacement-operation',
  };
  let replaced = false;
  const store = createFileReceiptStore(file, {
    fs: {
      ...fs,
      async unlink(target) {
        if (!replaced) {
          replaced = true;
          await fs.unlink(target);
          await fs.rmdir(lockFile);
          await writeLockDirectory(lockFile, replacement);
        }
        return fs.unlink(target);
      },
    },
  });

  await assert.rejects(store.withExclusiveLock(async () => 'done'), (error) => {
    assert.equal(error.code, 'lock_replaced');
    return true;
  });
  assert.deepEqual(
    JSON.parse(await fs.readFile(path.join(lockFile, `${replacement.lockId}.json`), 'utf8')),
    replacement,
  );
  assert.equal((await store.inspectLock()).metadata.lockId, replacement.lockId);
  assert.deepEqual(
    (await fs.readdir(directory)).sort(),
    ['.installation-receipt.json.lock'],
  );
});

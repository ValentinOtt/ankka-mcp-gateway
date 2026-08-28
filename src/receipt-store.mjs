import { constants as fsConstants } from 'node:fs';
import * as fsPromises from 'node:fs/promises';
import path from 'node:path';
import { randomUUID } from 'node:crypto';

const OWNER_ONLY_MODE = 0o600;
const OWNER_ONLY_DIRECTORY_MODE = 0o700;
const NO_FOLLOW = fsConstants.O_NOFOLLOW ?? 0;
const LOCK_VERSION = 1;
const MAX_LOCK_BYTES = 4096;
const SAFE_LOCK_ID = /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$/;
const SAFE_OPERATION_ID = /^[a-z][a-z0-9._:-]{0,63}$/;
const PROCESS_OWNER_ID = randomUUID();

export const STALE_LOCK_RECOVERY_CONFIRMATION = 'remove-inspected-stale-receipt-lock';

export class ReceiptStoreError extends Error {
  constructor(code) {
    const safeCode = typeof code === 'string' && /^[a-z0-9_]+$/i.test(code)
      ? code
      : 'store_error';
    super(`Receipt store operation failed (${safeCode}).`);
    this.name = 'ReceiptStoreError';
    this.code = safeCode;
  }
}

/**
 * Persist one customer-owned receipt as JSON. Mutation workflows must run
 * inside withExclusiveLock; standalone writes are atomic but are not CAS.
 * Locks fail closed and are never broken automatically after a process crash.
 */
export function createFileReceiptStore(filePath, { fs, processProbe = probeProcess } = {}) {
  if (typeof filePath !== 'string' || filePath.trim() === '' || /[\u0000]/.test(filePath)) {
    throw new TypeError('An explicit receipt file path is required.');
  }
  if (fs !== undefined && (fs === null || typeof fs !== 'object')) {
    throw new TypeError('fs must be an object when provided.');
  }
  if (typeof processProbe !== 'function') throw new TypeError('processProbe must be a function.');

  const io = fs === undefined ? fsPromises : { ...fsPromises, ...fs };
  const target = path.resolve(filePath);
  const directory = path.dirname(target);
  const basename = path.basename(target);
  const lockPath = path.join(directory, `.${basename}.lock`);

  return Object.freeze({
    async withExclusiveLock(operation, options = {}) {
      if (typeof operation !== 'function') throw new TypeError('operation must be a function.');
      const metadata = createLockMetadata(options);
      const metadataPath = path.join(lockPath, `${metadata.lockId}.json`);
      let handle;
      let acquiredDirectory = false;
      let primaryError;
      let result;
      try {
        await io.mkdir(lockPath, { mode: OWNER_ONLY_DIRECTORY_MODE });
        acquiredDirectory = true;
        if (typeof io.chmod === 'function') await io.chmod(lockPath, OWNER_ONLY_DIRECTORY_MODE);
        handle = await io.open(
          metadataPath,
          fsConstants.O_WRONLY |
            fsConstants.O_CREAT |
            fsConstants.O_EXCL |
            NO_FOLLOW,
          OWNER_ONLY_MODE,
        );
        await handle.writeFile(JSON.stringify(metadata), { encoding: 'utf8' });
        if (typeof handle.chmod === 'function') await handle.chmod(OWNER_ONLY_MODE);
        await syncFile(handle);
        await syncDirectoryIfPractical(io, directory);
        result = await operation();
      } catch (error) {
        primaryError = error?.code === 'EEXIST'
          ? new ReceiptStoreError('locked')
          : error;
      } finally {
        await closeQuietly(handle);
        if (acquiredDirectory) {
          try {
            await removeLockDirectory(io, lockPath, metadataPath);
          } catch (error) {
            if (!isMissing(error) && primaryError === undefined) {
              primaryError = safeStoreError(error, 'lock_release_failed');
            }
          }
          await syncDirectoryIfPractical(io, directory);
        }
      }
      if (primaryError !== undefined) throw primaryError;
      return result;
    },

    async inspectLock() {
      const inspection = await inspectLockDirectory(io, lockPath, processProbe);
      return inspection === null ? null : inspection.public;
    },

    async recoverStaleLock(input = {}) {
      validateRecoveryInput(input);
      if (input.confirmation !== STALE_LOCK_RECOVERY_CONFIRMATION) {
        throw new ReceiptStoreError('confirmation_required');
      }

      const inspection = await inspectLockDirectory(io, lockPath, processProbe);
      if (inspection === null) throw new ReceiptStoreError('lock_not_found');
      if (inspection.public.status === 'live') throw new ReceiptStoreError('lock_live');
      if (inspection.public.status !== 'stale_candidate') {
        throw new ReceiptStoreError('lock_ambiguous');
      }
      if (!sameEvidence(input.evidence, inspection.public.evidence)) {
        throw new ReceiptStoreError('lock_evidence_mismatch');
      }

      try {
        const fresh = await inspectLockDirectory(io, lockPath, processProbe);
        if (fresh === null) throw new ReceiptStoreError('lock_not_found');
        if (fresh.public.status === 'live') throw new ReceiptStoreError('lock_live');
        if (fresh.public.status !== 'stale_candidate') {
          throw new ReceiptStoreError('lock_ambiguous');
        }
        if (
          !sameEvidence(input.evidence, fresh.public.evidence) ||
          !sameFileIdentity(inspection.fileIdentity, fresh.fileIdentity)
        ) {
          throw new ReceiptStoreError('lock_evidence_mismatch');
        }
        await removeLockDirectory(io, lockPath, fresh.metadataPath);
        await syncDirectoryIfPractical(io, directory);
        return { status: 'removed', lockId: fresh.public.metadata.lockId };
      } catch (error) {
        if (error instanceof ReceiptStoreError) throw error;
        throw safeStoreError(error, 'lock_recovery_failed');
      }
    },

    async read() {
      const exists = await assertRegularOrMissing(io, target, 'read_failed');
      if (!exists) return null;

      let handle;
      let raw;
      try {
        handle = await io.open(target, fsConstants.O_RDONLY | NO_FOLLOW);
        const stat = await handle.stat();
        if (!stat.isFile()) throw new ReceiptStoreError('unsafe_target');
        raw = await handle.readFile({ encoding: 'utf8' });
      } catch (error) {
        if (isMissing(error)) return null;
        throw safeStoreError(error, 'read_failed');
      } finally {
        await closeQuietly(handle);
      }

      try {
        return JSON.parse(raw);
      } catch {
        throw new ReceiptStoreError('invalid_json');
      }
    },

    async writeAtomic(receipt) {
      let serialized;
      try {
        serialized = JSON.stringify(receipt);
      } catch {
        throw new ReceiptStoreError('invalid_json');
      }
      if (typeof serialized !== 'string') throw new ReceiptStoreError('invalid_json');

      await assertRegularOrMissing(io, target, 'write_failed');
      const temporary = path.join(
        directory,
        `.${basename}.tmp-${process.pid}-${randomUUID()}`,
      );
      let handle;
      let renamed = false;
      try {
        handle = await io.open(
          temporary,
          fsConstants.O_WRONLY |
            fsConstants.O_CREAT |
            fsConstants.O_EXCL |
            NO_FOLLOW,
          OWNER_ONLY_MODE,
        );
        await handle.writeFile(serialized, { encoding: 'utf8' });
        if (typeof handle.chmod === 'function') await handle.chmod(OWNER_ONLY_MODE);
        await syncFile(handle);
        await handle.close();
        handle = undefined;

        // Re-check immediately before replacement so directories and symlinks
        // are never accepted as an existing receipt target.
        await assertRegularOrMissing(io, target, 'write_failed');
        await io.rename(temporary, target);
        renamed = true;
        await io.chmod(target, OWNER_ONLY_MODE);
        await syncDirectoryIfPractical(io, directory);
      } catch (error) {
        await closeQuietly(handle);
        if (!renamed) await unlinkQuietly(io, temporary);
        throw safeStoreError(error, 'write_failed');
      }
    },
  });
}

function createLockMetadata(options) {
  if (!isObject(options)) throw new TypeError('lock options must be an object.');
  const unknown = Object.keys(options).filter((key) => key !== 'operationId');
  if (unknown.length > 0) throw new TypeError('lock options contain unsupported fields.');
  const operationId = options.operationId ?? 'receipt-mutation';
  if (typeof operationId !== 'string' || !SAFE_OPERATION_ID.test(operationId)) {
    throw new TypeError('operationId must be a safe identifier.');
  }
  return {
    version: LOCK_VERSION,
    lockId: randomUUID(),
    ownerId: PROCESS_OWNER_ID,
    pid: process.pid,
    createdAt: new Date().toISOString(),
    operationId,
  };
}

async function inspectLockDirectory(io, lockPath, processProbe) {
  let pathStat;
  try {
    pathStat = await io.lstat(lockPath);
  } catch (error) {
    if (isMissing(error)) return null;
    throw safeStoreError(error, 'lock_inspection_failed');
  }
  if (
    pathStat.isSymbolicLink() ||
    !pathStat.isDirectory() ||
    (pathStat.mode & 0o077) !== 0
  ) {
    return ambiguousInspection('unsafe_lock_target', fileIdentity(pathStat));
  }

  let entries;
  try {
    entries = await io.readdir(lockPath);
  } catch (error) {
    if (isMissing(error)) return null;
    throw safeStoreError(error, 'lock_inspection_failed');
  }
  if (entries.length !== 1 || !/^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\.json$/.test(entries[0])) {
    return ambiguousInspection('invalid_lock_metadata', fileIdentity(pathStat));
  }
  const metadataPath = path.join(lockPath, entries[0]);

  let handle;
  try {
    handle = await io.open(metadataPath, fsConstants.O_RDONLY | NO_FOLLOW);
    const stat = await handle.stat();
    if (!stat.isFile()) return ambiguousInspection('unsafe_lock_target', fileIdentity(stat));
    if (stat.size > MAX_LOCK_BYTES || (stat.mode & 0o077) !== 0) {
      return ambiguousInspection('invalid_lock_metadata', fileIdentity(stat));
    }
    const raw = await handle.readFile({ encoding: 'utf8' });
    const metadata = parseLockMetadata(raw);
    if (metadata === null || entries[0] !== `${metadata.lockId}.json`) {
      return ambiguousInspection('invalid_lock_metadata', fileIdentity(stat));
    }

    let ownerState;
    try {
      ownerState = await processProbe(metadata.pid);
    } catch {
      ownerState = 'ambiguous';
    }
    if (!['live', 'not_running', 'ambiguous'].includes(ownerState)) ownerState = 'ambiguous';
    const status = ownerState === 'live'
      ? 'live'
      : ownerState === 'not_running'
        ? 'stale_candidate'
        : 'ambiguous';
    const evidence = copyLockMetadata(metadata);
    return {
      public: {
        status,
        metadata: copyLockMetadata(metadata),
        evidence,
      },
      fileIdentity: {
        directory: fileIdentity(pathStat),
        metadata: fileIdentity(stat),
      },
      metadataPath,
    };
  } catch (error) {
    if (isMissing(error)) return null;
    if (error?.code === 'ELOOP') {
      return ambiguousInspection('unsafe_lock_target', fileIdentity(pathStat));
    }
    throw safeStoreError(error, 'lock_inspection_failed');
  } finally {
    await closeQuietly(handle);
  }
}

async function removeLockDirectory(io, lockPath, metadataPath) {
  try {
    await io.unlink(metadataPath);
  } catch (error) {
    if (isMissing(error)) throw new ReceiptStoreError('lock_replaced');
    throw error;
  }
  try {
    await io.rmdir(lockPath);
  } catch (error) {
    if (isMissing(error) || ['ENOTEMPTY', 'EEXIST'].includes(error?.code)) {
      throw new ReceiptStoreError('lock_replaced');
    }
    throw error;
  }
}

function parseLockMetadata(raw) {
  let value;
  try {
    value = JSON.parse(raw);
  } catch {
    return null;
  }
  if (!isObject(value)) return null;
  const expected = ['createdAt', 'lockId', 'operationId', 'ownerId', 'pid', 'version'];
  const keys = Object.keys(value).sort();
  if (keys.length !== expected.length || expected.some((key, index) => keys[index] !== key)) {
    return null;
  }
  if (value.version !== LOCK_VERSION) return null;
  if (!Number.isSafeInteger(value.pid) || value.pid <= 0) return null;
  if (typeof value.lockId !== 'string' || !SAFE_LOCK_ID.test(value.lockId)) return null;
  if (typeof value.ownerId !== 'string' || !SAFE_LOCK_ID.test(value.ownerId)) return null;
  if (typeof value.operationId !== 'string' || !SAFE_OPERATION_ID.test(value.operationId)) {
    return null;
  }
  if (typeof value.createdAt !== 'string') return null;
  const createdAt = new Date(value.createdAt);
  if (!Number.isFinite(createdAt.getTime()) || createdAt.toISOString() !== value.createdAt) {
    return null;
  }
  return copyLockMetadata(value);
}

function validateRecoveryInput(input) {
  if (!isObject(input)) throw new ReceiptStoreError('invalid_recovery_input');
  const keys = Object.keys(input).sort();
  if (keys.length !== 2 || keys[0] !== 'confirmation' || keys[1] !== 'evidence') {
    throw new ReceiptStoreError('invalid_recovery_input');
  }
  let evidence;
  try {
    evidence = isObject(input.evidence)
      ? parseLockMetadata(JSON.stringify(input.evidence))
      : null;
  } catch {
    evidence = null;
  }
  if (evidence === null) {
    throw new ReceiptStoreError('invalid_recovery_input');
  }
}

function sameEvidence(left, right) {
  if (!isObject(left) || !isObject(right)) return false;
  return (
    left.version === right.version &&
    left.lockId === right.lockId &&
    left.ownerId === right.ownerId &&
    left.pid === right.pid &&
    left.createdAt === right.createdAt &&
    left.operationId === right.operationId
  );
}

function copyLockMetadata(value) {
  return {
    version: value.version,
    lockId: value.lockId,
    ownerId: value.ownerId,
    pid: value.pid,
    createdAt: value.createdAt,
    operationId: value.operationId,
  };
}

function ambiguousInspection(reason, identity) {
  return {
    public: { status: 'ambiguous', reason },
    fileIdentity: identity,
  };
}

function fileIdentity(stat) {
  return {
    dev: stat?.dev,
    ino: stat?.ino,
    size: stat?.size,
    mtimeMs: stat?.mtimeMs,
  };
}

function sameFileIdentity(left, right) {
  if (left?.directory || right?.directory) {
    return (
      sameFileIdentity(left?.directory, right?.directory) &&
      sameFileIdentity(left?.metadata, right?.metadata)
    );
  }
  return (
    left?.dev === right?.dev &&
    left?.ino === right?.ino &&
    left?.size === right?.size &&
    left?.mtimeMs === right?.mtimeMs
  );
}

function probeProcess(pid) {
  try {
    process.kill(pid, 0);
    return 'live';
  } catch (error) {
    if (error?.code === 'ESRCH') return 'not_running';
    if (error?.code === 'EPERM') return 'live';
    return 'ambiguous';
  }
}

async function assertRegularOrMissing(io, target, fallbackCode) {
  let stat;
  try {
    stat = await io.lstat(target);
  } catch (error) {
    if (isMissing(error)) return false;
    throw safeStoreError(error, fallbackCode);
  }
  if (stat.isSymbolicLink() || !stat.isFile()) {
    throw new ReceiptStoreError('unsafe_target');
  }
  return true;
}

async function syncFile(handle) {
  if (typeof handle?.sync !== 'function') return;
  try {
    await handle.sync();
  } catch (error) {
    if (!isUnsupportedSync(error)) throw error;
  }
}

async function syncDirectoryIfPractical(io, directory) {
  let handle;
  try {
    handle = await io.open(directory, fsConstants.O_RDONLY);
    if (typeof handle.sync === 'function') await handle.sync();
  } catch {
    // Some platforms and injected filesystem adapters cannot fsync a directory.
  } finally {
    await closeQuietly(handle);
  }
}

async function closeQuietly(handle) {
  if (!handle || typeof handle.close !== 'function') return;
  try {
    await handle.close();
  } catch {
    // Preserve the primary operation error.
  }
}

async function unlinkQuietly(io, target) {
  try {
    await io.unlink(target);
  } catch {
    // Cleanup must not replace the primary operation error.
  }
}

function safeStoreError(error, fallbackCode) {
  if (error instanceof ReceiptStoreError) return error;
  if (error?.code === 'ELOOP') return new ReceiptStoreError('unsafe_target');
  const fsCode = typeof error?.code === 'string' && /^[A-Z0-9_]+$/.test(error.code)
    ? error.code.toLowerCase()
    : fallbackCode;
  return new ReceiptStoreError(fsCode);
}

function isMissing(error) {
  return error?.code === 'ENOENT';
}

function isUnsupportedSync(error) {
  return ['EINVAL', 'ENOSYS', 'ENOTSUP', 'EOPNOTSUPP'].includes(error?.code);
}

function isObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

import { constants as fsConstants, type Stats } from 'node:fs';
import * as fsPromises from 'node:fs/promises';
import type { FileHandle } from 'node:fs/promises';
import path from 'node:path';
import { randomUUID } from 'node:crypto';
import * as v from 'valibot';

import { boundaryValueSchema, type BoundaryValue } from './json.ts';

const OWNER_ONLY_MODE = 0o600;
const OWNER_ONLY_DIRECTORY_MODE = 0o700;
const NO_FOLLOW = fsConstants.O_NOFOLLOW ?? 0;
const LOCK_VERSION = 1;
const MAX_LOCK_BYTES = 4096;
const SAFE_LOCK_ID = /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$/;
const SAFE_OPERATION_ID = /^[a-z][a-z0-9._:-]{0,63}$/;
const PROCESS_OWNER_ID = randomUUID();
const stringSchema = v.string();
const functionSchema = v.function();
const fileSystemErrorSchema = v.object({ code: v.optional(v.string()) });
const lockMetadataSchema = v.strictObject({
  createdAt: v.string(),
  lockId: v.string(),
  operationId: v.string(),
  ownerId: v.string(),
  pid: v.number(),
  version: v.literal(LOCK_VERSION),
});
const processOwnerStateSchema = v.picklist(['ambiguous', 'live', 'not_running']);

type FileSystemAdapter = typeof fsPromises;
type FileSystemError = v.InferOutput<typeof fileSystemErrorSchema>;
type ProcessOwnerState = 'ambiguous' | 'live' | 'not_running';
type ProcessProbe = (pid: number) => ProcessOwnerState | Promise<ProcessOwnerState>;
type LockStatus = 'ambiguous' | 'live' | 'stale_candidate';

export type LockMetadata = v.InferOutput<typeof lockMetadataSchema>;

export interface LockOptions {
  readonly operationId?: string;
}

export interface StaleLockRecoveryInput {
  readonly confirmation: string;
  readonly evidence: LockMetadata;
}

export type LockInspection = {
  readonly evidence?: LockMetadata;
  readonly metadata?: LockMetadata;
  readonly reason?: string;
  readonly status: LockStatus;
};

export interface FileReceiptStoreOptions {
  readonly fs?: Partial<FileSystemAdapter>;
  readonly processProbe?: ProcessProbe;
}

export interface FileReceiptStore {
  inspectLock(): Promise<LockInspection | null>;
  read(): Promise<BoundaryValue>;
  recoverStaleLock(input: StaleLockRecoveryInput): Promise<{
    readonly lockId: string;
    readonly status: 'removed';
  }>;
  withExclusiveLock<Result>(
    operation: () => Promise<Result> | Result,
    options?: LockOptions,
  ): Promise<Result>;
  writeAtomic(receipt: BoundaryValue): Promise<void>;
}

interface FileIdentity {
  readonly dev: number;
  readonly ino: number;
  readonly mtimeMs: number;
  readonly size: number;
}

interface LockFileIdentity {
  readonly directory: FileIdentity;
  readonly metadata: FileIdentity;
}

interface ValidLockInspection {
  readonly fileIdentity: LockFileIdentity;
  readonly metadataPath: string;
  readonly public: {
    readonly evidence: LockMetadata;
    readonly metadata: LockMetadata;
    readonly status: LockStatus;
  };
}

interface UnsafeLockInspection {
  readonly fileIdentity: FileIdentity;
  readonly public: {
    readonly reason: string;
    readonly status: 'ambiguous';
  };
}

type InternalLockInspection = UnsafeLockInspection | ValidLockInspection;

export const STALE_LOCK_RECOVERY_CONFIRMATION = 'remove-inspected-stale-receipt-lock';

export class ReceiptStoreError extends Error {
  readonly code: string;

  constructor(code: BoundaryValue) {
    const safeCode = v.is(stringSchema, code) && /^[a-z0-9_]+$/i.test(code)
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
export function createFileReceiptStore(
  filePath?: string,
  { fs, processProbe = probeProcess }: FileReceiptStoreOptions = {},
): FileReceiptStore {
  if (!v.is(stringSchema, filePath) || filePath.trim() === '' || filePath.includes('\0')) {
    throw new TypeError('An explicit receipt file path is required.');
  }
  if (fs !== undefined && !v.is(v.object({}), fs)) {
    throw new TypeError('fs must be an object when provided.');
  }
  if (!v.safeParse(functionSchema, processProbe).success) {
    throw new TypeError('processProbe must be a function.');
  }

  const io: FileSystemAdapter = fs === undefined ? fsPromises : { ...fsPromises, ...fs };
  const target = path.resolve(filePath);
  const directory = path.dirname(target);
  const basename = path.basename(target);
  const lockPath = path.join(directory, `.${basename}.lock`);

  return Object.freeze({
    async withExclusiveLock<Result>(
      operation: () => Promise<Result> | Result,
      options: LockOptions = {},
    ): Promise<Result> {
      if (!v.safeParse(functionSchema, operation).success) {
        throw new TypeError('operation must be a function.');
      }
      const metadata = createLockMetadata(options);
      const metadataPath = path.join(lockPath, `${metadata.lockId}.json`);
      let handle: FileHandle | undefined;
      let acquiredDirectory = false;
      let primaryError: Error | undefined;
      let outcome: { readonly completed: true; readonly value: Result } | undefined;
      try {
        await io.mkdir(lockPath, { mode: OWNER_ONLY_DIRECTORY_MODE });
        acquiredDirectory = true;
        await io.chmod(lockPath, OWNER_ONLY_DIRECTORY_MODE);
        handle = await io.open(
          metadataPath,
          fsConstants.O_WRONLY |
            fsConstants.O_CREAT |
            fsConstants.O_EXCL |
            NO_FOLLOW,
          OWNER_ONLY_MODE,
        );
        await handle.writeFile(JSON.stringify(metadata), { encoding: 'utf8' });
        await handle.chmod(OWNER_ONLY_MODE);
        await syncFile(handle);
        await syncDirectoryIfPractical(io, directory);
        outcome = { completed: true, value: await operation() };
      } catch (error) {
        const parsed = v.safeParse(fileSystemErrorSchema, error);
        const safeError = error instanceof Error
          ? error
          : new ReceiptStoreError('operation_failed');
        primaryError = parsed.success && parsed.output.code === 'EEXIST'
          ? new ReceiptStoreError('locked')
          : safeError;
      } finally {
        await closeQuietly(handle);
        if (acquiredDirectory) {
          try {
            await removeLockDirectory(io, lockPath, metadataPath);
          } catch (error) {
            const parsed = v.safeParse(fileSystemErrorSchema, error);
            if (primaryError === undefined) {
              if (error instanceof ReceiptStoreError) {
                primaryError = error;
              } else {
                const safeError = parsed.success
                  ? parsed.output
                  : new Error('lock_release_failed');
                if (!isMissing(safeError)) {
                  primaryError = safeStoreError(safeError, 'lock_release_failed');
                }
              }
            }
          }
          await syncDirectoryIfPractical(io, directory);
        }
      }
      if (primaryError !== undefined) throw primaryError;
      if (!outcome?.completed) throw new ReceiptStoreError('operation_incomplete');
      return outcome.value;
    },

    async inspectLock(): Promise<LockInspection | null> {
      const inspection = await inspectLockDirectory(io, lockPath, processProbe);
      return inspection === null ? null : inspection.public;
    },

    async recoverStaleLock(input: StaleLockRecoveryInput): Promise<{
      readonly lockId: string;
      readonly status: 'removed';
    }> {
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
      if (!isValidInspection(inspection)) throw new ReceiptStoreError('lock_ambiguous');
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
        if (!isValidInspection(fresh)) throw new ReceiptStoreError('lock_ambiguous');
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
        const parsed = v.safeParse(fileSystemErrorSchema, error);
        throw safeStoreError(
          parsed.success ? parsed.output : new Error('lock_recovery_failed'),
          'lock_recovery_failed',
        );
      }
    },

    async read(): Promise<BoundaryValue> {
      const exists = await assertRegularOrMissing(io, target, 'read_failed');
      if (!exists) return null;

      let handle: FileHandle | undefined;
      let raw = '';
      try {
        handle = await io.open(target, fsConstants.O_RDONLY | NO_FOLLOW);
        const stat = await handle.stat();
        if (!stat.isFile()) throw new ReceiptStoreError('unsafe_target');
        raw = await handle.readFile({ encoding: 'utf8' });
      } catch (error) {
        const parsed = v.safeParse(fileSystemErrorSchema, error);
        if (parsed.success && isMissing(parsed.output)) return null;
        throw safeStoreError(
          parsed.success ? parsed.output : new Error('read_failed'),
          'read_failed',
        );
      } finally {
        await closeQuietly(handle);
      }

      try {
        return v.parse(boundaryValueSchema, JSON.parse(raw));
      } catch {
        throw new ReceiptStoreError('invalid_json');
      }
    },

    async writeAtomic(receipt: BoundaryValue): Promise<void> {
      let serialized: string | undefined;
      try {
        serialized = JSON.stringify(receipt);
      } catch {
        throw new ReceiptStoreError('invalid_json');
      }
      if (!v.is(stringSchema, serialized)) throw new ReceiptStoreError('invalid_json');

      await assertRegularOrMissing(io, target, 'write_failed');
      const temporary = path.join(
        directory,
        `.${basename}.tmp-${process.pid}-${randomUUID()}`,
      );
      let handle: FileHandle | undefined;
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
        await handle.chmod(OWNER_ONLY_MODE);
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
        const parsed = v.safeParse(fileSystemErrorSchema, error);
        throw safeStoreError(
          parsed.success ? parsed.output : new Error('write_failed'),
          'write_failed',
        );
      }
    },
  });
}

function createLockMetadata(options: LockOptions): LockMetadata {
  if (!v.is(v.object({}), options)) throw new TypeError('lock options must be an object.');
  const unknown = Object.keys(options).filter((key) => key !== 'operationId');
  if (unknown.length > 0) throw new TypeError('lock options contain unsupported fields.');
  const operationId = options.operationId ?? 'receipt-mutation';
  if (!v.is(stringSchema, operationId) || !SAFE_OPERATION_ID.test(operationId)) {
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

async function inspectLockDirectory(
  io: FileSystemAdapter,
  lockPath: string,
  processProbe: ProcessProbe,
): Promise<InternalLockInspection | null> {
  let pathStat: Stats;
  try {
    pathStat = await io.lstat(lockPath);
  } catch (error) {
    const parsed = v.safeParse(fileSystemErrorSchema, error);
    if (parsed.success && isMissing(parsed.output)) return null;
    throw safeStoreError(
      parsed.success ? parsed.output : new Error('lock_inspection_failed'),
      'lock_inspection_failed',
    );
  }
  if (
    pathStat.isSymbolicLink() ||
    !pathStat.isDirectory() ||
    (pathStat.mode & 0o077) !== 0
  ) {
    return ambiguousInspection('unsafe_lock_target', fileIdentity(pathStat));
  }

  let entries: string[];
  try {
    entries = await io.readdir(lockPath);
  } catch (error) {
    const parsed = v.safeParse(fileSystemErrorSchema, error);
    if (parsed.success && isMissing(parsed.output)) return null;
    throw safeStoreError(
      parsed.success ? parsed.output : new Error('lock_inspection_failed'),
      'lock_inspection_failed',
    );
  }
  const entry = entries.at(0);
  if (entries.length !== 1 || !entry || !/^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\.json$/.test(entry)) {
    return ambiguousInspection('invalid_lock_metadata', fileIdentity(pathStat));
  }
  const metadataPath = path.join(lockPath, entry);

  let handle: FileHandle | undefined;
  try {
    handle = await io.open(metadataPath, fsConstants.O_RDONLY | NO_FOLLOW);
    const stat = await handle.stat();
    if (!stat.isFile()) return ambiguousInspection('unsafe_lock_target', fileIdentity(stat));
    if (stat.size > MAX_LOCK_BYTES || (stat.mode & 0o077) !== 0) {
      return ambiguousInspection('invalid_lock_metadata', fileIdentity(stat));
    }
    const raw = await handle.readFile({ encoding: 'utf8' });
    const metadata = parseLockMetadata(raw);
    if (metadata === null || entry !== `${metadata.lockId}.json`) {
      return ambiguousInspection('invalid_lock_metadata', fileIdentity(stat));
    }

    let ownerState: ProcessOwnerState;
    try {
      ownerState = await processProbe(metadata.pid);
    } catch {
      ownerState = 'ambiguous';
    }
    if (!v.is(processOwnerStateSchema, ownerState)) ownerState = 'ambiguous';
    const status: LockStatus = ownerState === 'live'
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
    const parsed = v.safeParse(fileSystemErrorSchema, error);
    if (parsed.success && isMissing(parsed.output)) return null;
    if (parsed.success && parsed.output.code === 'ELOOP') {
      return ambiguousInspection('unsafe_lock_target', fileIdentity(pathStat));
    }
    throw safeStoreError(
      parsed.success ? parsed.output : new Error('lock_inspection_failed'),
      'lock_inspection_failed',
    );
  } finally {
    await closeQuietly(handle);
  }
}

async function removeLockDirectory(
  io: FileSystemAdapter,
  lockPath: string,
  metadataPath: string,
): Promise<void> {
  try {
    await io.unlink(metadataPath);
  } catch (error) {
    const parsed = v.safeParse(fileSystemErrorSchema, error);
    if (parsed.success && isMissing(parsed.output)) throw new ReceiptStoreError('lock_replaced');
    throw safeStoreError(
      parsed.success ? parsed.output : new Error('lock_release_failed'),
      'lock_release_failed',
    );
  }
  try {
    await io.rmdir(lockPath);
  } catch (error) {
    const parsed = v.safeParse(fileSystemErrorSchema, error);
    if (parsed.success
      && (isMissing(parsed.output) || ['ENOTEMPTY', 'EEXIST'].includes(parsed.output.code ?? ''))) {
      throw new ReceiptStoreError('lock_replaced');
    }
    throw safeStoreError(
      parsed.success ? parsed.output : new Error('lock_release_failed'),
      'lock_release_failed',
    );
  }
}

function parseLockMetadata(raw: string): LockMetadata | null {
  let value: BoundaryValue;
  try {
    value = v.parse(boundaryValueSchema, JSON.parse(raw));
  } catch {
    return null;
  }
  const parsed = v.safeParse(lockMetadataSchema, value);
  if (!parsed.success) return null;
  const metadata = parsed.output;
  if (!Number.isSafeInteger(metadata.pid) || metadata.pid <= 0) return null;
  if (!SAFE_LOCK_ID.test(metadata.lockId) || !SAFE_LOCK_ID.test(metadata.ownerId)) return null;
  if (!SAFE_OPERATION_ID.test(metadata.operationId)) return null;
  const createdAt = new Date(metadata.createdAt);
  if (!Number.isFinite(createdAt.getTime()) || createdAt.toISOString() !== metadata.createdAt) {
    return null;
  }
  return copyLockMetadata(metadata);
}

function validateRecoveryInput(input: StaleLockRecoveryInput): void {
  if (!v.is(v.object({}), input)) throw new ReceiptStoreError('invalid_recovery_input');
  const keys = Object.keys(input).sort();
  if (keys.length !== 2 || keys[0] !== 'confirmation' || keys[1] !== 'evidence') {
    throw new ReceiptStoreError('invalid_recovery_input');
  }
  let evidence: LockMetadata | null;
  try {
    evidence = parseLockMetadata(JSON.stringify(input.evidence));
  } catch {
    evidence = null;
  }
  if (evidence === null) {
    throw new ReceiptStoreError('invalid_recovery_input');
  }
}

function sameEvidence(left: LockMetadata, right: LockMetadata): boolean {
  return (
    left.version === right.version &&
    left.lockId === right.lockId &&
    left.ownerId === right.ownerId &&
    left.pid === right.pid &&
    left.createdAt === right.createdAt &&
    left.operationId === right.operationId
  );
}

function copyLockMetadata(value: LockMetadata): LockMetadata {
  return {
    version: value.version,
    lockId: value.lockId,
    ownerId: value.ownerId,
    pid: value.pid,
    createdAt: value.createdAt,
    operationId: value.operationId,
  };
}

function ambiguousInspection(reason: string, identity: FileIdentity): UnsafeLockInspection {
  return {
    public: { status: 'ambiguous', reason },
    fileIdentity: identity,
  };
}

function fileIdentity(stat: Stats): FileIdentity {
  return {
    dev: stat.dev,
    ino: stat.ino,
    size: stat.size,
    mtimeMs: stat.mtimeMs,
  };
}

function sameFileIdentity(
  left: FileIdentity | LockFileIdentity,
  right: FileIdentity | LockFileIdentity,
): boolean {
  if (isLockFileIdentity(left) || isLockFileIdentity(right)) {
    if (!isLockFileIdentity(left) || !isLockFileIdentity(right)) return false;
    return (
      sameFileIdentity(left.directory, right.directory) &&
      sameFileIdentity(left.metadata, right.metadata)
    );
  }
  return (
    left.dev === right.dev &&
    left.ino === right.ino &&
    left.size === right.size &&
    left.mtimeMs === right.mtimeMs
  );
}

function isLockFileIdentity(
  value: FileIdentity | LockFileIdentity,
): value is LockFileIdentity {
  return Object.hasOwn(value, 'directory');
}

function isValidInspection(
  inspection: InternalLockInspection,
): inspection is ValidLockInspection {
  return Object.hasOwn(inspection, 'metadataPath');
}

function probeProcess(pid: number): ProcessOwnerState {
  try {
    process.kill(pid, 0);
    return 'live';
  } catch (error) {
    const parsed = v.safeParse(fileSystemErrorSchema, error);
    if (parsed.success && parsed.output.code === 'ESRCH') return 'not_running';
    if (parsed.success && parsed.output.code === 'EPERM') return 'live';
    return 'ambiguous';
  }
}

async function assertRegularOrMissing(
  io: FileSystemAdapter,
  target: string,
  fallbackCode: string,
): Promise<boolean> {
  let stat: Stats;
  try {
    stat = await io.lstat(target);
  } catch (error) {
    const parsed = v.safeParse(fileSystemErrorSchema, error);
    if (parsed.success && isMissing(parsed.output)) return false;
    throw safeStoreError(
      parsed.success ? parsed.output : new Error(fallbackCode),
      fallbackCode,
    );
  }
  if (stat.isSymbolicLink() || !stat.isFile()) {
    throw new ReceiptStoreError('unsafe_target');
  }
  return true;
}

async function syncFile(handle: FileHandle | undefined): Promise<void> {
  if (!handle) return;
  try {
    await handle.sync();
  } catch (error) {
    const parsed = v.safeParse(fileSystemErrorSchema, error);
    if (!parsed.success || !isUnsupportedSync(parsed.output)) throw error;
  }
}

async function syncDirectoryIfPractical(
  io: FileSystemAdapter,
  directory: string,
): Promise<void> {
  let handle: FileHandle | undefined;
  try {
    handle = await io.open(directory, fsConstants.O_RDONLY);
    await handle.sync();
  } catch {
    // Some platforms and injected filesystem adapters cannot fsync a directory.
  } finally {
    await closeQuietly(handle);
  }
}

async function closeQuietly(handle: FileHandle | undefined): Promise<void> {
  if (!handle) return;
  try {
    await handle.close();
  } catch {
    // Preserve the primary operation error.
  }
}

async function unlinkQuietly(io: FileSystemAdapter, target: string): Promise<void> {
  try {
    await io.unlink(target);
  } catch {
    // Cleanup must not replace the primary operation error.
  }
}

function safeStoreError(
  error: Error | FileSystemError,
  fallbackCode: string,
): ReceiptStoreError {
  if (error instanceof ReceiptStoreError) return error;
  const parsed = v.safeParse(fileSystemErrorSchema, error);
  if (parsed.success && parsed.output.code === 'ELOOP') {
    return new ReceiptStoreError('unsafe_target');
  }
  const fsCode = parsed.success
    && parsed.output.code
    && /^[A-Z0-9_]+$/.test(parsed.output.code)
    ? parsed.output.code.toLowerCase()
    : fallbackCode;
  return new ReceiptStoreError(fsCode);
}

function isMissing(error: Error | FileSystemError): boolean {
  const parsed = v.safeParse(fileSystemErrorSchema, error);
  return parsed.success && parsed.output.code === 'ENOENT';
}

function isUnsupportedSync(error: Error | FileSystemError): boolean {
  const parsed = v.safeParse(fileSystemErrorSchema, error);
  return parsed.success
    && ['EINVAL', 'ENOSYS', 'ENOTSUP', 'EOPNOTSUPP'].includes(parsed.output.code ?? '');
}

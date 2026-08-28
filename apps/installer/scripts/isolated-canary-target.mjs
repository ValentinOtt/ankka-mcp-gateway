import { constants as FS_CONSTANTS } from 'node:fs';
import { lstat, open, realpath } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

export const LIVE_INSTALLER_HOSTNAME = 'deploy.ankka.ai';
export const LIVE_INSTALLER_WORKER_NAME = 'ankka-gateway-deploy';
export const LIVE_INSTALLER_OAUTH_CLIENT_ID = '97ef364689fbda8582a55237066a67a0';

const MAX_TARGET_BYTES = 4096;
const REPOSITORY_ROOT = path.resolve(fileURLToPath(new URL('../../../', import.meta.url)));
const ACCOUNT_ID_PATTERN = /^[a-f0-9]{32}$/u;
const OAUTH_CLIENT_ID_PATTERN = /^[a-f0-9]{32}$/u;
const WORKER_NAME_PATTERN = /^ankka-gateway-deploy-isolated-[a-z0-9](?:[a-z0-9-]{0,26}[a-z0-9])?$/u;
const HOST_LABEL_PATTERN = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/u;
const RESERVED_HOST_SUFFIXES = Object.freeze([
  '.example',
  '.invalid',
  '.localhost',
  '.pages.dev',
  '.test',
  '.workers.dev',
]);

export class IsolatedCanaryTargetError extends Error {
  constructor() {
    super('Isolated canary target is invalid');
    this.name = 'IsolatedCanaryTargetError';
    this.code = 'isolated_canary_target_invalid';
  }
}

function fail() {
  throw new IsolatedCanaryTargetError();
}

function isPlainRecord(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value) &&
    Object.getPrototypeOf(value) === Object.prototype;
}

function exactKeys(value, keys) {
  if (!isPlainRecord(value)) return false;
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  return actual.length === expected.length &&
    actual.every((key, index) => key === expected[index]);
}

function isWithinRepository(filename) {
  const relative = path.relative(REPOSITORY_ROOT, filename);
  return relative === '' || (
    relative !== '..' &&
    !relative.startsWith(`..${path.sep}`) &&
    !path.isAbsolute(relative)
  );
}

export function isIsolatedCanaryHostname(value) {
  if (
    typeof value !== 'string' ||
    value.length > 253 ||
    value !== value.toLowerCase() ||
    value === LIVE_INSTALLER_HOSTNAME ||
    RESERVED_HOST_SUFFIXES.some((suffix) => value.endsWith(suffix))
  ) return false;
  const labels = value.split('.');
  return labels.length >= 3 && labels.every((label) => HOST_LABEL_PATTERN.test(label));
}

export function parseIsolatedCanaryTarget(input) {
  if (!exactKeys(input, [
    'accountId',
    'hostname',
    'kind',
    'oauthClientId',
    'schemaVersion',
    'workerName',
  ])) fail();
  if (
    input.schemaVersion !== 1 ||
    input.kind !== 'ankka-gateway-deploy-isolated-target' ||
    typeof input.accountId !== 'string' || !ACCOUNT_ID_PATTERN.test(input.accountId) ||
    !isIsolatedCanaryHostname(input.hostname) ||
    typeof input.oauthClientId !== 'string' ||
    !OAUTH_CLIENT_ID_PATTERN.test(input.oauthClientId) ||
    input.oauthClientId === LIVE_INSTALLER_OAUTH_CLIENT_ID ||
    typeof input.workerName !== 'string' || !WORKER_NAME_PATTERN.test(input.workerName) ||
    input.workerName === LIVE_INSTALLER_WORKER_NAME
  ) fail();
  return Object.freeze({
    accountId: input.accountId,
    hostname: input.hostname,
    kind: input.kind,
    oauthClientId: input.oauthClientId,
    schemaVersion: 1,
    workerName: input.workerName,
  });
}

export async function readIsolatedCanaryTargetFile(filename) {
  if (typeof filename !== 'string' || filename.length === 0 || filename.includes('\0')) fail();
  let resolved;
  let handle;
  let bytes;
  try {
    resolved = await realpath(path.resolve(filename));
    if (isWithinRepository(resolved)) fail();
    const before = await lstat(resolved);
    if (
      !before.isFile() ||
      before.isSymbolicLink() ||
      !Number.isSafeInteger(before.size) ||
      before.size < 1 ||
      before.size > MAX_TARGET_BYTES
    ) fail();
    handle = await open(resolved, FS_CONSTANTS.O_RDONLY | (FS_CONSTANTS.O_NOFOLLOW ?? 0));
    const opened = await handle.stat();
    if (
      !opened.isFile() ||
      opened.size !== before.size ||
      opened.dev !== before.dev ||
      opened.ino !== before.ino
    ) fail();
    bytes = await handle.readFile();
    if (bytes.byteLength !== opened.size) fail();
    const serialized = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
    return parseIsolatedCanaryTarget(JSON.parse(serialized));
  } catch (error) {
    if (error instanceof IsolatedCanaryTargetError) throw error;
    fail();
  } finally {
    bytes?.fill(0);
    await handle?.close().catch(() => {});
  }
}

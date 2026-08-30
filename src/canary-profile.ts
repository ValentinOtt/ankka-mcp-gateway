import { constants as fsConstants } from 'node:fs';
import { chmod, lstat, mkdir, open, realpath } from 'node:fs/promises';
import { homedir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import * as v from 'valibot';

import { validateCloudflareId, validateHostname } from './canary-command.ts';

const PROFILE_KIND = 'ankka-cloudflare-disposable-canary-profile';
const PROFILE_NAME = /^[a-z][a-z0-9-]{0,47}$/u;
const MAX_PROFILE_BYTES = 4096;
const OWNER_ONLY_DIRECTORY_MODE = 0o700;
const NO_FOLLOW = fsConstants.O_NOFOLLOW ?? 0;
const REPOSITORY_ROOT = path.resolve(fileURLToPath(new URL('../', import.meta.url)));
const fileSystemErrorSchema = v.object({ code: v.optional(v.string()) });
const objectSchema = v.object({});
const stringSchema = v.string();
const profileSchema = v.strictObject({
  schemaVersion: v.literal(1),
  kind: v.literal(PROFILE_KIND),
  profileId: v.string(),
  accountId: v.string(),
  zoneId: v.string(),
  hostname: v.string(),
  syntheticMcpUrl: v.string(),
  authentication: v.optional(v.picklist(['email', 'service_token'])),
});

type ProfileInput = v.InferOutput<typeof profileSchema>;
type ProfileErrorCode =
  | 'directory_invalid'
  | 'profile_invalid'
  | 'profile_name_invalid'
  | 'profile_unavailable'
  | 'profile_unsafe'
  | 'receipt_directory_unavailable';

export interface CanaryProfilePaths {
  readonly directory: string;
  readonly profilePath: string;
  readonly profilesDirectory: string;
  readonly receiptDirectory: string;
  readonly receiptPath: string;
}

export interface LoadedCanaryProfile extends CanaryProfilePaths {
  readonly accountId: string;
  readonly authentication?: 'email' | 'service_token';
  readonly hostname: string;
  readonly kind: typeof PROFILE_KIND;
  readonly profileId: string;
  readonly schemaVersion: 1;
  readonly syntheticMcpUrl: string;
  readonly zoneId: string;
}

export interface CanaryProfileOptions {
  readonly directory?: string;
}

export class CanaryProfileError extends Error {
  readonly code: ProfileErrorCode;

  constructor(code: ProfileErrorCode) {
    const messages = new Map<ProfileErrorCode, string>([
      ['directory_invalid', 'The local canary profile directory is invalid.'],
      ['profile_invalid', 'The selected local canary profile is invalid.'],
      ['profile_name_invalid', 'The local canary profile name is invalid.'],
      ['profile_unavailable', 'The selected local canary profile is unavailable.'],
      ['profile_unsafe', 'The selected local canary profile is not stored safely.'],
      [
        'receipt_directory_unavailable',
        'The local canary receipt directory could not be prepared safely.',
      ],
    ]);
    super(messages.get(code));
    this.name = 'CanaryProfileError';
    this.code = code;
  }
}

export function defaultCanaryProfileDirectory(
  environment: NodeJS.ProcessEnv = process.env,
  userHome: string = homedir(),
): string {
  const configured = environment.ANKKA_CANARY_DIRECTORY;
  if (configured !== undefined) return validateDirectory(configured);
  return validateDirectory(path.join(userHome, '.config', 'ankka-canary'));
}

export function resolveCanaryProfilePaths(
  profileId: string,
  options: CanaryProfileOptions = {},
): CanaryProfilePaths {
  requireExactOptions(options);
  if (!PROFILE_NAME.test(profileId)) {
    throw new CanaryProfileError('profile_name_invalid');
  }
  const directory = validateDirectory(
    options.directory ?? defaultCanaryProfileDirectory(),
  );
  const profilesDirectory = path.join(directory, 'profiles');
  const receiptDirectory = path.join(directory, 'receipts');
  return Object.freeze({
    directory,
    profilesDirectory,
    profilePath: path.join(profilesDirectory, `${profileId}.json`),
    receiptDirectory,
    receiptPath: path.join(receiptDirectory, `${profileId}.receipt.json`),
  });
}

export async function readCanaryProfile(
  profileId: string,
  options: CanaryProfileOptions = {},
): Promise<LoadedCanaryProfile> {
  const paths = resolveCanaryProfilePaths(profileId, options);
  await assertOwnerOnlyDirectory(paths.directory);
  await assertOwnerOnlyDirectory(paths.profilesDirectory);

  let handle: Awaited<ReturnType<typeof open>> | undefined;
  let bytes: Buffer<ArrayBufferLike> | undefined;
  try {
    const before = await lstat(paths.profilePath);
    if (
      before.isSymbolicLink() ||
      !before.isFile() ||
      !Number.isSafeInteger(before.size) ||
      before.size < 1 ||
      before.size > MAX_PROFILE_BYTES ||
      !isOwnerOnly(before.mode)
    ) {
      throw new CanaryProfileError('profile_unsafe');
    }
    const canonical = await realpath(paths.profilePath);
    if (isWithinRepository(canonical)) {
      throw new CanaryProfileError('profile_unsafe');
    }
    handle = await open(paths.profilePath, fsConstants.O_RDONLY | NO_FOLLOW);
    const opened = await handle.stat();
    if (
      !opened.isFile() ||
      opened.dev !== before.dev ||
      opened.ino !== before.ino ||
      opened.size !== before.size ||
      !isOwnerOnly(opened.mode)
    ) {
      throw new CanaryProfileError('profile_unsafe');
    }
    bytes = await handle.readFile();
    if (bytes.byteLength !== opened.size) {
      throw new CanaryProfileError('profile_unsafe');
    }
    const serialized = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
    const parsed = v.parse(profileSchema, JSON.parse(serialized));
    return normalizeProfile(parsed, profileId, paths);
  } catch (error) {
    if (error instanceof CanaryProfileError) throw error;
    const parsed = v.safeParse(fileSystemErrorSchema, error);
    if (parsed.success && parsed.output.code === 'ENOENT') {
      throw new CanaryProfileError('profile_unavailable');
    }
    if (parsed.success && parsed.output.code === 'ELOOP') {
      throw new CanaryProfileError('profile_unsafe');
    }
    throw new CanaryProfileError('profile_invalid');
  } finally {
    bytes?.fill(0);
    await handle?.close().catch(() => {});
  }
}

export async function ensureCanaryReceiptDirectory(
  profile: LoadedCanaryProfile,
): Promise<void> {
  validateReceiptPaths(profile);
  try {
    await assertOwnerOnlyDirectory(profile.directory);
    try {
      await mkdir(profile.receiptDirectory, { mode: OWNER_ONLY_DIRECTORY_MODE });
      await chmod(profile.receiptDirectory, OWNER_ONLY_DIRECTORY_MODE);
    } catch (error) {
      const parsed = v.safeParse(fileSystemErrorSchema, error);
      if (!parsed.success || parsed.output.code !== 'EEXIST') throw error;
    }
    await assertCanaryReceiptDirectory(profile, false);
  } catch (error) {
    if (
      error instanceof CanaryProfileError &&
      error.code === 'receipt_directory_unavailable'
    ) {
      throw error;
    }
    throw new CanaryProfileError('receipt_directory_unavailable');
  }
}

export async function assertCanaryReceiptDirectorySafe(
  profile: LoadedCanaryProfile,
): Promise<void> {
  validateReceiptPaths(profile);
  try {
    await assertOwnerOnlyDirectory(profile.directory);
    await assertCanaryReceiptDirectory(profile, true);
  } catch (error) {
    if (
      error instanceof CanaryProfileError &&
      error.code === 'receipt_directory_unavailable'
    ) {
      throw error;
    }
    throw new CanaryProfileError('receipt_directory_unavailable');
  }
}

function normalizeProfile(
  input: ProfileInput,
  requestedProfileId: string,
  paths: CanaryProfilePaths,
): LoadedCanaryProfile {
  if (input.profileId !== requestedProfileId || !PROFILE_NAME.test(input.profileId)) {
    throw new CanaryProfileError('profile_invalid');
  }
  try {
    validateCloudflareId(input.accountId, 'account');
    validateCloudflareId(input.zoneId, 'zone');
  } catch {
    throw new CanaryProfileError('profile_invalid');
  }
  let hostname: string;
  try {
    hostname = validateHostname(input.hostname);
  } catch {
    throw new CanaryProfileError('profile_invalid');
  }
  const firstLabel = hostname.split('.')[0];
  if (firstLabel === undefined || !/^ankka-canary(?:-[a-z0-9-]+)?$/u.test(firstLabel)) {
    throw new CanaryProfileError('profile_invalid');
  }
  const syntheticMcpUrl = normalizeSyntheticMcpUrl(input.syntheticMcpUrl);
  const profile: LoadedCanaryProfile = {
    ...paths,
    schemaVersion: 1,
    kind: PROFILE_KIND,
    profileId: input.profileId,
    accountId: input.accountId.toLowerCase(),
    zoneId: input.zoneId.toLowerCase(),
    hostname,
    syntheticMcpUrl,
  };
  if (input.authentication === undefined) return Object.freeze(profile);
  return Object.freeze({ ...profile, authentication: input.authentication });
}

function normalizeSyntheticMcpUrl(value: string): string {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new CanaryProfileError('profile_invalid');
  }
  const hostname = url.hostname.toLowerCase();
  const labels = hostname.split('.');
  const firstLabel = labels[0];
  const quickTunnel = labels.length === 3 &&
    labels[1] === 'trycloudflare' &&
    labels[2] === 'com' &&
    firstLabel !== undefined &&
    /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/u.test(firstLabel);
  if (
    url.protocol !== 'https:' ||
    url.username !== '' ||
    url.password !== '' ||
    url.search !== '' ||
    url.hash !== '' ||
    url.pathname !== '/mcp' ||
    (!hostname.includes('canary') && !quickTunnel)
  ) {
    throw new CanaryProfileError('profile_invalid');
  }
  return url.toString();
}

async function assertOwnerOnlyDirectory(directory: string): Promise<void> {
  let stat: Awaited<ReturnType<typeof lstat>>;
  try {
    stat = await lstat(directory);
  } catch (error) {
    const parsed = v.safeParse(fileSystemErrorSchema, error);
    if (parsed.success && parsed.output.code === 'ENOENT') {
      throw new CanaryProfileError('profile_unavailable');
    }
    throw new CanaryProfileError('profile_unsafe');
  }
  if (stat.isSymbolicLink() || !stat.isDirectory() || !isOwnerOnly(stat.mode)) {
    throw new CanaryProfileError('profile_unsafe');
  }
  let canonical: string;
  try {
    canonical = await realpath(directory);
  } catch {
    throw new CanaryProfileError('profile_unsafe');
  }
  if (isWithinRepository(canonical)) {
    throw new CanaryProfileError('profile_unsafe');
  }
}

async function assertCanaryReceiptDirectory(
  profile: LoadedCanaryProfile,
  allowMissing: boolean,
): Promise<void> {
  let stat: Awaited<ReturnType<typeof lstat>>;
  try {
    stat = await lstat(profile.receiptDirectory);
  } catch (error) {
    const parsed = v.safeParse(fileSystemErrorSchema, error);
    if (allowMissing && parsed.success && parsed.output.code === 'ENOENT') return;
    throw new CanaryProfileError('receipt_directory_unavailable');
  }
  if (stat.isSymbolicLink() || !stat.isDirectory() || !isOwnerOnly(stat.mode)) {
    throw new CanaryProfileError('receipt_directory_unavailable');
  }
  let canonical: string;
  try {
    canonical = await realpath(profile.receiptDirectory);
  } catch {
    throw new CanaryProfileError('receipt_directory_unavailable');
  }
  if (isWithinRepository(canonical)) {
    throw new CanaryProfileError('receipt_directory_unavailable');
  }
}

function validateReceiptPaths(profile: LoadedCanaryProfile): void {
  if (
    profile.receiptDirectory !== path.dirname(profile.receiptPath) ||
    profile.receiptDirectory !== path.join(profile.directory, 'receipts') ||
    isWithinRepository(profile.receiptDirectory)
  ) {
    throw new CanaryProfileError('receipt_directory_unavailable');
  }
}

function validateDirectory(value: string): string {
  if (
    !v.is(stringSchema, value) ||
    value.length === 0 ||
    value.includes('\0') ||
    !path.isAbsolute(value)
  ) {
    throw new CanaryProfileError('directory_invalid');
  }
  const resolved = path.resolve(value);
  if (isWithinRepository(resolved)) {
    throw new CanaryProfileError('directory_invalid');
  }
  return resolved;
}

function requireExactOptions(value: CanaryProfileOptions): void {
  if (
    !v.is(objectSchema, value) ||
    Object.keys(value).some((key) => key !== 'directory')
  ) {
    throw new CanaryProfileError('directory_invalid');
  }
}

function isWithinRepository(filename: string): boolean {
  const relative = path.relative(REPOSITORY_ROOT, filename);
  return relative === '' || (
    relative !== '..' &&
    !relative.startsWith(`..${path.sep}`) &&
    !path.isAbsolute(relative)
  );
}

function isOwnerOnly(mode: number): boolean {
  return (mode & 0o077) === 0;
}

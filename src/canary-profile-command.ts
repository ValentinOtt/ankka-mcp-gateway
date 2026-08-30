import * as v from 'valibot';

import {
  executeCanaryLifecycleCommand,
  type LifecycleInvocation,
} from './canary-lifecycle-command.ts';
import {
  ensureCanaryReceiptDirectory,
  readCanaryProfile,
  type LoadedCanaryProfile,
} from './canary-profile.ts';
import type { BoundaryValue } from './json.ts';

const SAFE_LIFECYCLE_APPROVAL = /^canary-lifecycle-[0-9a-f]{24}$/u;
const SAFE_TARGET_CONFIRMATION = /^canary-target-[0-9a-f]{24}$/u;
const stringSchema = v.string();
const booleanSchema = v.boolean();
const functionSchema = v.function();
const previewReportSchema = v.object({
  schemaVersion: v.literal(1),
  kind: v.literal('cloudflare_canary_lifecycle_preview'),
  ready: v.literal(true),
  writesPerformed: v.literal(false),
  approvalId: v.string(),
  targetConfirmationId: v.string(),
});

type LifecycleCommandResult = Awaited<ReturnType<typeof executeCanaryLifecycleCommand>>;
type LifecycleExecutor = (invocation: LifecycleInvocation) => Promise<LifecycleCommandResult>;
type ProfileReader = (profileId: string) => Promise<LoadedCanaryProfile>;
type ReceiptDirectoryPreparer = (profile: LoadedCanaryProfile) => Promise<void>;

interface ParsedProfileLifecycleInvocation {
  readonly json: boolean;
  readonly mode: 'preview' | 'run';
  readonly profileId: string;
}

export interface CanaryProfileLifecycleInvocation {
  readonly json?: BoundaryValue;
  readonly mode?: BoundaryValue;
  readonly profileId?: BoundaryValue;
}

export interface CanaryProfileLifecycleDependencies {
  readonly executeLifecycle?: LifecycleExecutor;
  readonly prepareReceiptDirectory?: ReceiptDirectoryPreparer;
  readonly readProfile?: ProfileReader;
}

export class CanaryProfileCommandError extends Error {
  readonly code: 'invalid_invocation' | 'preview_invalid' | 'runtime_not_configured';

  constructor(code: 'invalid_invocation' | 'preview_invalid' | 'runtime_not_configured') {
    const messages = {
      invalid_invocation: 'The local canary profile command is invalid.',
      preview_invalid: 'The local canary profile preview was not safe to run.',
      runtime_not_configured: 'The local canary profile runtime is not configured.',
    } as const;
    super(messages[code]);
    this.name = 'CanaryProfileCommandError';
    this.code = code;
  }
}

/**
 * Execute one enrolled local profile without weakening the lifecycle runner.
 * Run mode obtains fresh approval values from a structured preview and the
 * existing runner independently recomputes them before its first mutation.
 */
export async function executeCanaryProfileLifecycleCommand(
  invocation: CanaryProfileLifecycleInvocation = {},
  dependencies: CanaryProfileLifecycleDependencies = {},
): Promise<LifecycleCommandResult> {
  const parsed = validateInvocation(invocation);
  const runtime = validateDependencies(dependencies);
  const profile = await runtime.readProfile(parsed.profileId);
  let base: LifecycleInvocation = {
    accountId: profile.accountId,
    zoneId: profile.zoneId,
    hostname: profile.hostname,
    syntheticMcpUrl: profile.syntheticMcpUrl,
    receiptPath: profile.receiptPath,
    json: parsed.json,
  };
  if (profile.authentication === 'service_token') {
    base = { ...base, authentication: 'service_token' };
  }

  if (parsed.mode === 'preview') {
    return runtime.executeLifecycle({ ...base, mode: 'preview' });
  }

  await runtime.prepareReceiptDirectory(profile);
  const preview = await runtime.executeLifecycle({ ...base, mode: 'preview' });
  const approval = validatePreview(preview);
  return runtime.executeLifecycle({
    ...base,
    mode: 'run',
    approvalId: approval.approvalId,
    targetConfirmationId: approval.targetConfirmationId,
  });
}

function validateInvocation(
  value: CanaryProfileLifecycleInvocation,
): ParsedProfileLifecycleInvocation {
  if (
    !v.is(v.object({}), value) ||
    Object.keys(value).some((key) => !['json', 'mode', 'profileId'].includes(key)) ||
    !v.is(v.picklist(['preview', 'run']), value.mode) ||
    !v.is(stringSchema, value.profileId) ||
    value.profileId.length === 0 ||
    (value.json !== undefined && !v.is(booleanSchema, value.json))
  ) {
    throw new CanaryProfileCommandError('invalid_invocation');
  }
  return {
    mode: value.mode,
    profileId: value.profileId,
    json: value.json === true,
  };
}

function validateDependencies(
  value: CanaryProfileLifecycleDependencies,
): Required<CanaryProfileLifecycleDependencies> {
  if (
    !v.is(v.object({}), value) ||
    Object.keys(value).some((key) => ![
      'executeLifecycle',
      'prepareReceiptDirectory',
      'readProfile',
    ].includes(key))
  ) {
    throw new CanaryProfileCommandError('runtime_not_configured');
  }
  const runtime = {
    executeLifecycle: value.executeLifecycle ?? executeCanaryLifecycleCommand,
    prepareReceiptDirectory: value.prepareReceiptDirectory ?? ensureCanaryReceiptDirectory,
    readProfile: value.readProfile ?? readCanaryProfile,
  };
  if (
    !v.is(functionSchema, runtime.executeLifecycle) ||
    !v.is(functionSchema, runtime.prepareReceiptDirectory) ||
    !v.is(functionSchema, runtime.readProfile)
  ) {
    throw new CanaryProfileCommandError('runtime_not_configured');
  }
  return runtime;
}

function validatePreview(result: LifecycleCommandResult): {
  readonly approvalId: string;
  readonly targetConfirmationId: string;
} {
  if (result.exitCode !== 0) {
    throw new CanaryProfileCommandError('preview_invalid');
  }
  const parsed = v.safeParse(previewReportSchema, result.report);
  if (
    !parsed.success ||
    !SAFE_LIFECYCLE_APPROVAL.test(parsed.output.approvalId) ||
    !SAFE_TARGET_CONFIRMATION.test(parsed.output.targetConfirmationId)
  ) {
    throw new CanaryProfileCommandError('preview_invalid');
  }
  return Object.freeze({
    approvalId: parsed.output.approvalId,
    targetConfirmationId: parsed.output.targetConfirmationId,
  });
}

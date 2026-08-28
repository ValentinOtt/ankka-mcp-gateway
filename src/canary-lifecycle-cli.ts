#!/usr/bin/env node

import {
  CanaryLockCommandError,
  CanaryLifecycleCommandError,
  executeCanaryLockCommand,
  executeCanaryLifecycleCommand,
  type LifecycleInvocation,
  type LockInvocation,
} from './canary-lifecycle-command.ts';
import { CanaryLifecycleError } from './canary-runner.ts';
import { STALE_LOCK_RECOVERY_CONFIRMATION } from './receipt-store.ts';

const USAGE = `Usage:
  node src/canary-lifecycle-cli.ts preview --account-id <id> --zone-id <id> --hostname <ankka-canary.example.com> --synthetic-mcp-url <https-url>/mcp --receipt <path> [--json]
  node src/canary-lifecycle-cli.ts run --account-id <id> --zone-id <id> --hostname <ankka-canary.example.com> --synthetic-mcp-url <https-url>/mcp --receipt <path> --approve <lifecycle-id> --confirm-disposable-target <target-id> [--json]
  node src/canary-lifecycle-cli.ts lock inspect --receipt <path> --store <receipt|cleanup> [--json]
  node src/canary-lifecycle-cli.ts lock recover --receipt <path> --store <receipt|cleanup> --lock-id <id> --confirm ${STALE_LOCK_RECOVERY_CONFIRMATION} [--json]

CLOUDFLARE_API_TOKEN and ANKKA_CANARY_ALLOWED_EMAIL must come from the local environment for preview/run.
Lock inspection and recovery never read those secrets. The cleanup store is the owner-only .cleanup-recovery sidecar.`;

class CliInputError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'CliInputError';
  }
}

try {
  const invocation = parse(process.argv.slice(2));
  if ('help' in invocation) {
    console.log(USAGE);
  } else if (invocation.command === 'lock') {
    const result = await executeCanaryLockCommand(invocation.lock);
    console.log(result.output);
    process.exitCode = result.exitCode;
  } else {
    const result = invocation.lifecycle.json === true
      ? await executeCanaryLifecycleCommand(invocation.lifecycle)
      : await executeCanaryLifecycleCommand(invocation.lifecycle, {
        onProgress(event) {
          const detail = [event.action, event.kind].filter(Boolean).join(' ');
          console.error(
            `Canary ${event.stage}: ${event.status}${detail ? ` (${detail})` : ''}`,
          );
        },
      });
    console.log(result.output);
    process.exitCode = result.exitCode;
  }
} catch (error) {
  const usage =
    error instanceof CliInputError ||
    error instanceof CanaryLifecycleCommandError ||
    (error instanceof CanaryLockCommandError &&
      ['invalid_invocation', 'runtime_not_configured'].includes(error.code));
  if (
    error instanceof CliInputError ||
    error instanceof CanaryLockCommandError ||
    error instanceof CanaryLifecycleCommandError ||
    error instanceof CanaryLifecycleError
  ) {
    console.error(error.message);
  } else {
    console.error('The canary lifecycle command failed safely.');
  }
  if (usage) console.error(`\n${USAGE}`);
  process.exitCode = usage ? 2 : 1;
}

type ParsedCli =
  | { readonly help: true }
  | { readonly command: 'lifecycle'; readonly lifecycle: LifecycleInvocation }
  | { readonly command: 'lock'; readonly lock: LockInvocation };

interface LifecycleParseState {
  accountId?: string;
  approvalId?: string;
  hostname?: string;
  json: boolean;
  mode: 'preview' | 'run';
  receiptPath?: string;
  syntheticMcpUrl?: string;
  targetConfirmationId?: string;
  zoneId?: string;
}

type LifecycleValueProperty = Exclude<keyof LifecycleParseState, 'json' | 'mode'>;

interface LockParseState {
  confirmation?: string;
  json: boolean;
  lockId?: string;
  operation: 'inspect' | 'recover';
  receiptPath?: string;
  store?: string;
}

type LockValueProperty = Exclude<keyof LockParseState, 'json' | 'operation'>;

function parse(args: readonly string[]): ParsedCli {
  if (args.length === 1 && ['--help', '-h'].includes(args[0] ?? '')) return { help: true };
  if (args[0] === 'lock') return { command: 'lock', lock: parseLock(args.slice(1)) };
  const mode = args[0];
  if (mode !== 'preview' && mode !== 'run') {
    throw new CliInputError('Choose preview, run, or lock inspect/recover.');
  }
  const invocation: LifecycleParseState = {
    mode,
    json: false,
  };
  const options = new Map<string, LifecycleValueProperty>([
    ['--account-id', 'accountId'],
    ['--zone-id', 'zoneId'],
    ['--hostname', 'hostname'],
    ['--synthetic-mcp-url', 'syntheticMcpUrl'],
    ['--receipt', 'receiptPath'],
    ['--approve', 'approvalId'],
    ['--confirm-disposable-target', 'targetConfirmationId'],
  ]);
  for (let index = 1; index < args.length; index += 1) {
    const argument = args[index];
    if (argument === undefined) throw new CliInputError('A command option is required.');
    if (argument === '--json') {
      if (invocation.json) throw new CliInputError('--json may only be provided once.');
      invocation.json = true;
      continue;
    }
    const property = options.get(argument);
    if (property === undefined) {
      throw new CliInputError('The canary lifecycle command received an unknown option.');
    }
    const value = args[index + 1];
    if (!value || value.startsWith('-')) {
      throw new CliInputError(`${argument} requires a value.`);
    }
    if (invocation[property] !== undefined) {
      throw new CliInputError(`${argument} may only be provided once.`);
    }
    invocation[property] = value;
    index += 1;
  }
  for (const [option, property] of options.entries()) {
    const lifecycleOnly = property === 'approvalId' || property === 'targetConfirmationId';
    if (invocation.mode === 'preview' && lifecycleOnly) {
      if (invocation[property] !== undefined) {
        throw new CliInputError('Approval values are accepted only by the run subcommand.');
      }
      continue;
    }
    if (invocation[property] === undefined) {
      throw new CliInputError(`${option} is required.`);
    }
  }
  if (
    invocation.accountId === undefined ||
    invocation.zoneId === undefined ||
    invocation.hostname === undefined ||
    invocation.syntheticMcpUrl === undefined ||
    invocation.receiptPath === undefined
  ) {
    throw new CliInputError('All target and fixture options are required.');
  }
  const lifecycleBase = {
    mode: invocation.mode,
    accountId: invocation.accountId,
    zoneId: invocation.zoneId,
    hostname: invocation.hostname,
    syntheticMcpUrl: invocation.syntheticMcpUrl,
    receiptPath: invocation.receiptPath,
    json: invocation.json,
  };
  if (invocation.mode === 'preview') {
    return { command: 'lifecycle', lifecycle: lifecycleBase };
  }
  if (invocation.approvalId === undefined || invocation.targetConfirmationId === undefined) {
    throw new CliInputError('The run subcommand requires both approval values.');
  }
  return {
    command: 'lifecycle',
    lifecycle: {
      ...lifecycleBase,
      approvalId: invocation.approvalId,
      targetConfirmationId: invocation.targetConfirmationId,
    },
  };
}

function parseLock(args: readonly string[]): LockInvocation {
  const operation = args[0];
  if (operation !== 'inspect' && operation !== 'recover') {
    throw new CliInputError('Choose the lock inspect or lock recover subcommand.');
  }
  const invocation: LockParseState = {
    operation,
    json: false,
  };
  const options = new Map<string, LockValueProperty>([
    ['--receipt', 'receiptPath'],
    ['--store', 'store'],
    ['--lock-id', 'lockId'],
    ['--confirm', 'confirmation'],
  ]);
  for (let index = 1; index < args.length; index += 1) {
    const argument = args[index];
    if (argument === undefined) throw new CliInputError('A lock option is required.');
    if (argument === '--json') {
      if (invocation.json) throw new CliInputError('--json may only be provided once.');
      invocation.json = true;
      continue;
    }
    const property = options.get(argument);
    if (property === undefined) {
      throw new CliInputError('The canary lock command received an unknown option.');
    }
    const value = args[index + 1];
    if (!value || value.startsWith('-')) {
      throw new CliInputError(`${argument} requires a value.`);
    }
    if (invocation[property] !== undefined) {
      throw new CliInputError(`${argument} may only be provided once.`);
    }
    invocation[property] = value;
    index += 1;
  }
  if (invocation.receiptPath === undefined) throw new CliInputError('--receipt is required.');
  if (invocation.store === undefined) throw new CliInputError('--store is required.');
  if (invocation.store !== 'receipt' && invocation.store !== 'cleanup') {
    throw new CliInputError('--store must be receipt or cleanup.');
  }
  if (invocation.operation === 'inspect') {
    if (invocation.lockId !== undefined || invocation.confirmation !== undefined) {
      throw new CliInputError('--lock-id and --confirm are accepted only by lock recover.');
    }
    return {
      operation: 'inspect',
      receiptPath: invocation.receiptPath,
      store: invocation.store,
      json: invocation.json,
    };
  } else {
    if (invocation.lockId === undefined) throw new CliInputError('--lock-id is required.');
    if (invocation.confirmation === undefined) throw new CliInputError('--confirm is required.');
    if (invocation.confirmation !== STALE_LOCK_RECOVERY_CONFIRMATION) {
      throw new CliInputError(`--confirm must equal ${STALE_LOCK_RECOVERY_CONFIRMATION}.`);
    }
  }
  return {
    operation: 'recover',
    receiptPath: invocation.receiptPath,
    store: invocation.store,
    lockId: invocation.lockId,
    confirmation: invocation.confirmation,
    json: invocation.json,
  };
}

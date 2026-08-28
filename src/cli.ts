#!/usr/bin/env node

import { readFile } from 'node:fs/promises';
import {
  CanaryPreflightInputError,
  executeCanaryPreflightCommand,
  validateCloudflareId,
  validateHostname,
} from './canary-command.ts';
import { validateGatewayConfig } from './config.ts';
import { jsonValueSchema, type JsonValue } from './json.ts';
import {
  buildGatewayPlan,
  type GatewayPlan,
  type PlanBlocker,
  type PlanChange,
} from './plan.ts';
import * as v from 'valibot';

const USAGE = `Usage:
  npm run validate -- <gateway.config.json>
  npm run plan -- <gateway.config.json> --observed <observed-state.json> --access <access-input.json> [--json] [--release <value>]
  npm --silent run canary:preflight -- --account-id <32-character-id> --zone-id <32-character-id> --hostname <gateway.example.com> [--json]`;

class CliUsageError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'CliUsageError';
  }
}

type CliInvocation =
  | { readonly command: 'help' }
  | { readonly command: 'validate'; readonly configFile: string }
  | {
    readonly accessFile: string;
    readonly command: 'plan';
    readonly configFile: string;
    readonly json: boolean;
    readonly observedFile: string;
    readonly release?: string;
  }
  | {
    readonly accountId: string;
    readonly command: 'canary-preflight';
    readonly hostname: string;
    readonly json: boolean;
    readonly zoneId: string;
  };

interface PlanParseState {
  accessFile?: string;
  configFile: string;
  json: boolean;
  observedFile?: string;
  release?: string;
}

interface CanaryParseState {
  accountId?: string;
  hostname?: string;
  json: boolean;
  zoneId?: string;
}

try {
  const invocation = parseArguments(process.argv.slice(2));

  if (invocation.command === 'help') {
    console.log(USAGE);
  } else if (invocation.command === 'validate') {
    const config = validateGatewayConfig(await readJson(invocation.configFile));
    console.log(
      `Valid gateway configuration: ${config.sources.length} source(s), ` +
        `${config.sources.reduce((total, source) => total + source.enabledTools.length, 0)} tool(s).`,
    );
  } else if (invocation.command === 'plan') {
    const config = await readJson(invocation.configFile);
    validateGatewayConfig(config);
    const observed = await readJson(invocation.observedFile);
    const access = await readJson(invocation.accessFile);
    const plan = await buildGatewayPlan(config, observed, {
      release: invocation.release,
      access,
    });
    console.log(invocation.json ? JSON.stringify(plan, null, 2) : renderPlan(plan));
  } else {
    const result = await executeCanaryPreflightCommand({
      accountId: invocation.accountId,
      zoneId: invocation.zoneId,
      hostname: invocation.hostname,
      json: invocation.json,
    });
    console.log(result.output);
    process.exitCode = result.exitCode;
  }
} catch (error) {
  const usageError = error instanceof CliUsageError || error instanceof CanaryPreflightInputError;
  console.error(error instanceof Error ? error.message : 'Command failed.');
  if (usageError) console.error(`\n${USAGE}`);
  process.exitCode = usageError ? 2 : 1;
}

function parseArguments(args: readonly string[]): CliInvocation {
  if (args.includes('--help') || args.includes('-h')) return { command: 'help' };
  if (args.length === 0) {
    throw new CliUsageError('A command is required.');
  }
  const command = args[0];
  if (command === undefined) throw new CliUsageError('A command is required.');

  // Keep the original `npm run validate -- file.json` interface stable.
  if (command !== 'plan' && command !== 'validate' && command !== 'canary') {
    if (args.length !== 1 || command.startsWith('-')) {
      throw new CliUsageError('The validate command accepts exactly one configuration file.');
    }
    return { command: 'validate', configFile: command };
  }

  if (command === 'validate') {
    const configFile = args[1];
    if (args.length !== 2 || configFile === undefined || configFile.startsWith('-')) {
      throw new CliUsageError('The validate command requires exactly one configuration file.');
    }
    return { command: 'validate', configFile };
  }

  if (command === 'canary') return parseCanaryArguments(args);

  const configFile = args[1];
  if (configFile === undefined || configFile.startsWith('-')) {
    throw new CliUsageError('The plan command requires a configuration file.');
  }
  const invocation: PlanParseState = {
    configFile,
    json: false,
  };

  for (let index = 2; index < args.length; index += 1) {
    const argument = args[index];
    if (argument === undefined) throw new CliUsageError('A plan option is required.');
    if (argument === '--json') {
      if (invocation.json) throw new CliUsageError('--json may only be provided once.');
      invocation.json = true;
    } else if (
      argument === '--observed' ||
      argument === '--access' ||
      argument === '--release'
    ) {
      const value = args[index + 1];
      if (!value || value.startsWith('-')) {
        throw new CliUsageError(`${argument} requires a value.`);
      }
      const property: 'accessFile' | 'observedFile' | 'release' =
        argument === '--observed'
          ? 'observedFile'
          : argument === '--access'
            ? 'accessFile'
            : 'release';
      if (invocation[property] !== undefined) {
        throw new CliUsageError(`${argument} may only be provided once.`);
      }
      invocation[property] = value;
      index += 1;
    } else {
      throw new CliUsageError(`Unknown plan option: ${argument}`);
    }
  }

  if (!invocation.observedFile) {
    throw new CliUsageError('The plan command requires --observed <observed-state.json>.');
  }
  if (!invocation.accessFile) {
    throw new CliUsageError('The plan command requires --access <access-input.json>.');
  }
  if (
    invocation.release !== undefined &&
    !/^[A-Za-z0-9][A-Za-z0-9._+-]{0,79}$/.test(invocation.release)
  ) {
    throw new CliUsageError(
      '--release must be an identifier of at most 80 letters, numbers, dots, underscores, pluses, or hyphens.',
    );
  }
  if (invocation.release === undefined) {
    return {
      command: 'plan',
      configFile: invocation.configFile,
      observedFile: invocation.observedFile,
      accessFile: invocation.accessFile,
      json: invocation.json,
    };
  }
  return {
    command: 'plan',
    configFile: invocation.configFile,
    observedFile: invocation.observedFile,
    accessFile: invocation.accessFile,
    json: invocation.json,
    release: invocation.release,
  };
}

function parseCanaryArguments(args: readonly string[]): CliInvocation {
  if (args[1] !== 'preflight') {
    throw new CliUsageError('The canary command requires the preflight subcommand.');
  }
  const invocation: CanaryParseState = {
    json: false,
  };
  for (let index = 2; index < args.length; index += 1) {
    const argument = args[index];
    if (argument === undefined) throw new CliUsageError('A canary option is required.');
    if (argument === '--json') {
      if (invocation.json) throw new CliUsageError('--json may only be provided once.');
      invocation.json = true;
      continue;
    }
    if (
      argument !== '--account-id' &&
      argument !== '--zone-id' &&
      argument !== '--hostname'
    ) {
      throw new CliUsageError('The canary preflight command received an unknown option.');
    }
    const value = args[index + 1];
    if (!value || value.startsWith('-')) {
      throw new CliUsageError(`${argument} requires a value.`);
    }
    const property =
      argument === '--account-id'
        ? 'accountId'
        : argument === '--zone-id'
          ? 'zoneId'
          : 'hostname';
    if (invocation[property] !== undefined) {
      throw new CliUsageError(`${argument} may only be provided once.`);
    }
    invocation[property] = value;
    index += 1;
  }
  if (!invocation.accountId || !invocation.zoneId || !invocation.hostname) {
    throw new CliUsageError(
      'The canary preflight command requires explicit --account-id, --zone-id, and --hostname values.',
    );
  }
  validateCloudflareId(invocation.accountId, 'account');
  validateCloudflareId(invocation.zoneId, 'zone');
  return {
    command: 'canary-preflight',
    accountId: invocation.accountId,
    zoneId: invocation.zoneId,
    hostname: validateHostname(invocation.hostname),
    json: invocation.json,
  };
}

async function readJson(file: string): Promise<JsonValue> {
  let raw: string;
  try {
    raw = await readFile(file, 'utf8');
  } catch (error) {
    throw new Error(
      `Could not read ${file}: ${error instanceof Error ? error.message : 'unknown error'}`,
      { cause: error },
    );
  }
  try {
    return v.parse(jsonValueSchema, JSON.parse(raw));
  } catch (error) {
    throw new Error(
      `${file} is not valid JSON: ${error instanceof Error ? error.message : 'parse failed'}`,
      { cause: error },
    );
  }
}

function renderPlan(plan: GatewayPlan): string {
  const lines = [
    `Plan: ${display(plan.planId)}`,
    `Installation: ${display(plan.installationId)}`,
    `Desired state: ${display(plan.desiredHash)}`,
    `Release: ${display(plan.release)}`,
    '',
    `Blockers (${plan.blockers.length}):`,
    ...renderList(plan.blockers, describeBlocker),
    '',
    `Required provider capabilities (${plan.requiredCapabilities.length}):`,
    ...renderList(plan.requiredCapabilities, describeCapability),
    '  OAuth consent: not requested by offline planning.',
    '',
    `Changes (${plan.changes.length}):`,
    ...renderList(plan.changes, describeAction),
    '',
    `Removal preview, non-authoritative (${plan.uninstall.length}):`,
    ...renderList(plan.uninstall, describeAction),
  ];
  return lines.join('\n');
}

function renderList<Item>(
  items: readonly Item[],
  describe: (item: Item) => string,
): readonly string[] {
  return items.length === 0 ? ['  - none'] : items.map((item) => `  - ${describe(item)}`);
}

function describeBlocker(item: PlanBlocker): string {
  return joinDistinct([item.code, item.message]);
}

function describeCapability(item: string): string {
  return display(item);
}

function describeAction(item: PlanChange): string {
  return joinDistinct([item.action, item.kind, item.key]);
}

function joinDistinct(values: readonly string[]): string {
  const parts: string[] = [];
  for (const value of values) {
    if (value.length > 0 && !parts.includes(value)) parts.push(value);
  }
  return parts.length > 0 ? parts.map(display).join(' ') : 'unavailable';
}

function display(value: string): string {
  return value.length > 0 ? value.replaceAll(/[\r\n\t]/g, ' ') : 'unavailable';
}

#!/usr/bin/env node

import { readFile } from 'node:fs/promises';
import {
  CanaryPreflightInputError,
  executeCanaryPreflightCommand,
  validateCloudflareId,
  validateHostname,
} from './canary-command.mjs';
import { validateGatewayConfig } from './config.mjs';
import { buildGatewayPlan } from './plan.mjs';

const USAGE = `Usage:
  npm run validate -- <gateway.config.json>
  npm run plan -- <gateway.config.json> --observed <observed-state.json> --access <access-input.json> [--json] [--release <value>]
  npm --silent run canary:preflight -- --account-id <32-character-id> --zone-id <32-character-id> --hostname <gateway.example.com> [--json]`;

class CliUsageError extends Error {
  constructor(message) {
    super(message);
    this.name = 'CliUsageError';
  }
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
    const config = validateGatewayConfig(await readJson(invocation.configFile));
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

function parseArguments(args) {
  if (args.includes('--help') || args.includes('-h')) return { command: 'help' };
  if (args.length === 0) {
    throw new CliUsageError('A command is required.');
  }

  // Keep the original `npm run validate -- file.json` interface stable.
  if (args[0] !== 'plan' && args[0] !== 'validate' && args[0] !== 'canary') {
    if (args.length !== 1 || args[0].startsWith('-')) {
      throw new CliUsageError('The validate command accepts exactly one configuration file.');
    }
    return { command: 'validate', configFile: args[0] };
  }

  if (args[0] === 'validate') {
    if (args.length !== 2 || args[1].startsWith('-')) {
      throw new CliUsageError('The validate command requires exactly one configuration file.');
    }
    return { command: 'validate', configFile: args[1] };
  }

  if (args[0] === 'canary') return parseCanaryArguments(args);

  const invocation = {
    command: 'plan',
    configFile: args[1],
    observedFile: undefined,
    accessFile: undefined,
    json: false,
    release: undefined,
  };
  if (!invocation.configFile || invocation.configFile.startsWith('-')) {
    throw new CliUsageError('The plan command requires a configuration file.');
  }

  for (let index = 2; index < args.length; index += 1) {
    const argument = args[index];
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
      const property =
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
  return invocation;
}

function parseCanaryArguments(args) {
  if (args[1] !== 'preflight') {
    throw new CliUsageError('The canary command requires the preflight subcommand.');
  }
  const invocation = {
    command: 'canary-preflight',
    accountId: undefined,
    zoneId: undefined,
    hostname: undefined,
    json: false,
  };
  for (let index = 2; index < args.length; index += 1) {
    const argument = args[index];
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
  invocation.hostname = validateHostname(invocation.hostname);
  return invocation;
}

async function readJson(file) {
  let raw;
  try {
    raw = await readFile(file, 'utf8');
  } catch (error) {
    throw new Error(`Could not read ${file}: ${error instanceof Error ? error.message : 'unknown error'}`);
  }
  try {
    return JSON.parse(raw);
  } catch (error) {
    throw new Error(`${file} is not valid JSON: ${error instanceof Error ? error.message : 'parse failed'}`);
  }
}

function renderPlan(plan) {
  const lines = [
    `Plan: ${display(plan.planId)}`,
    `Installation: ${display(plan.installationId)}`,
    `Desired state: ${display(plan.desiredHash)}`,
    `Release: ${display(plan.release)}`,
    '',
    `Blockers (${list(plan.blockers).length}):`,
    ...renderList(plan.blockers, describeBlocker),
    '',
    `Required provider capabilities (${list(plan.requiredCapabilities).length}):`,
    ...renderList(plan.requiredCapabilities, describeCapability),
    '  OAuth consent: not requested by offline planning.',
    '',
    `Changes (${list(plan.changes).length}):`,
    ...renderList(plan.changes, describeAction),
    '',
    `Removal preview, non-authoritative (${list(plan.uninstall).length}):`,
    ...renderList(plan.uninstall, describeAction),
  ];
  return lines.join('\n');
}

function renderList(value, describe) {
  const items = list(value);
  return items.length === 0 ? ['  - none'] : items.map((item) => `  - ${describe(item)}`);
}

function describeBlocker(item) {
  if (typeof item === 'string') return display(item);
  return joinKnown(item, ['code', 'message']);
}

function describeCapability(item) {
  if (typeof item === 'string') return display(item);
  return joinKnown(item, ['capability', 'name']);
}

function describeAction(item) {
  if (typeof item === 'string') return display(item);
  return joinKnown(item, ['action', 'kind', 'resourceKind', 'key', 'resourceKey', 'id']);
}

function joinKnown(item, fields) {
  if (item === null || typeof item !== 'object' || Array.isArray(item)) return 'unavailable';
  const parts = [];
  for (const field of fields) {
    const value = item[field];
    if (typeof value === 'string' && value.length > 0 && !parts.includes(value)) parts.push(value);
  }
  return parts.length > 0 ? parts.map(display).join(' ') : 'unavailable';
}

function display(value) {
  return typeof value === 'string' && value.length > 0 ? value.replaceAll(/[\r\n\t]/g, ' ') : 'unavailable';
}

function list(value) {
  return Array.isArray(value) ? value : [];
}

import { randomBytes } from 'node:crypto';
import { lstat, open, readFile, rename, rm } from 'node:fs/promises';
import path from 'node:path';
import process from 'node:process';
import { pathToFileURL } from 'node:url';
import * as v from 'valibot';

import {
  GatewayConfigError,
  MAX_ENABLED_TOOLS_PER_SOURCE,
  validateGatewayConfig,
} from '../src/config.ts';

const HTTP_METHODS = Object.freeze([
  'DELETE',
  'GET',
  'HEAD',
  'OPTIONS',
  'PATCH',
  'POST',
  'PUT',
  'TRACE',
]);
const HTTP_METHOD_SET = new Set(HTTP_METHODS);
const READ_ONLY_METHODS = new Set(['GET']);
const TOOL_NAME = /^[A-Za-z0-9_.:/-]{1,128}$/u;
const SOURCE_ID = /^[a-z][a-z0-9-]{0,31}$/u;
const OPENAPI_VERSION = /^3\.(?:0|1)\.\d+(?:-[0-9A-Za-z.-]+)?$/u;
const MANIFEST_PATH = /^\/[^\s?#]{0,2047}$/u;
const CONTROL_CHARACTER = /[\p{Cc}\p{Cf}]/u;
const MANIFEST_KEYS = new Set(['$comment', 'entries', 'syntheticTools']);
const MANIFEST_ENTRY_KEYS = new Set(['method', 'operationId', 'path', 'reason', 'verified']);
const SYNTHETIC_TOOL_KEYS = new Set(['name', 'reason']);
const MAX_REASON_LENGTH = 1024;
const MAX_VERIFICATION_LENGTH = 256;
const MAX_COMMENT_LENGTH = 4096;
const OBJECT_SCHEMA = v.object({});
const STRING_SCHEMA = v.string();

const USAGE = `Usage:
  node tools/openapi-enabled-tools.mjs \\
    --spec <openapi.json> \\
    --config <gateway.config.json> \\
    --source <source-id> \\
    --method GET \\
    [--manifest <reviewed-selection.json>] \\
    [--write | --check]

Modes:
  (default)  Print the updated gateway configuration to stdout.
  --write    Replace the selected source's enabledTools in the config file.
  --check    Exit nonzero unless enabledTools already matches the generated list.`;

export class OpenApiEnabledToolsError extends Error {
  constructor(code, detail = '') {
    super(detail === '' ? code : `${code}: ${detail}`);
    this.name = 'OpenApiEnabledToolsError';
    this.code = code;
  }
}

function fail(code, detail = '') {
  throw new OpenApiEnabledToolsError(code, detail);
}

function isRecord(value) {
  return v.is(OBJECT_SCHEMA, value) && !Array.isArray(value);
}

function compareText(left, right) {
  const leftPoints = [...left];
  const rightPoints = [...right];
  const limit = Math.min(leftPoints.length, rightPoints.length);
  for (let index = 0; index < limit; index += 1) {
    const difference = leftPoints[index].codePointAt(0) - rightPoints[index].codePointAt(0);
    if (difference !== 0) return difference;
  }
  return leftPoints.length - rightPoints.length;
}

function hasExactKeys(value, allowed, required, code, location) {
  const keys = Object.keys(value);
  if (keys.some((key) => !allowed.has(key)) || required.some((key) => !Object.hasOwn(value, key))) {
    fail(code, location);
  }
}

function isReviewText(value, maximumLength) {
  return v.is(STRING_SCHEMA, value) &&
    value.length > 0 &&
    value.length <= maximumLength &&
    value === value.trim() &&
    !CONTROL_CHARACTER.test(value);
}

function selectedMethods(methods) {
  if (!Array.isArray(methods) || methods.length === 0) {
    fail('method_required', 'pass --method GET explicitly');
  }
  const selected = new Set();
  for (const value of methods) {
    if (!v.is(STRING_SCHEMA, value)) fail('method_invalid');
    const method = value.toUpperCase();
    if (!HTTP_METHOD_SET.has(method)) fail('method_invalid');
    if (!READ_ONLY_METHODS.has(method)) {
      fail('method_outside_read_only_boundary', method);
    }
    if (selected.has(method)) fail('method_duplicate', method);
    selected.add(method);
  }
  return selected;
}

function extractSelectedMethodTools(openApi, methods, allowEmpty) {
  if (!isRecord(openApi) || !v.is(STRING_SCHEMA, openApi.openapi) ||
      !OPENAPI_VERSION.test(openApi.openapi)) {
    fail('openapi_version_invalid', 'expected an OpenAPI 3.0 or 3.1 document');
  }
  if (!isRecord(openApi.paths)) fail('openapi_paths_invalid');

  const selected = selectedMethods(methods);
  const operationIds = new Map();
  const paths = Object.keys(openApi.paths).sort(compareText);
  for (const [pathIndex, pathName] of paths.entries()) {
    const pathItem = openApi.paths[pathName];
    const pathLocation = `paths[${pathIndex}]`;
    if (!isRecord(pathItem)) fail('path_item_invalid', pathLocation);
    if (Object.hasOwn(pathItem, '$ref')) {
      fail('path_item_reference_unsupported', pathLocation);
    }
    for (const method of HTTP_METHODS) {
      if (!selected.has(method)) continue;
      const operation = pathItem[method.toLowerCase()];
      if (operation === undefined) continue;
      const location = `${method} operation at ${pathLocation}`;
      if (!isRecord(operation)) fail('operation_invalid', location);
      if (!v.is(STRING_SCHEMA, operation.operationId) || operation.operationId.length === 0) {
        fail('operation_id_missing', location);
      }
      const operationId = operation.operationId;
      if (operationId !== operationId.trim()) {
        fail('operation_id_not_verbatim_safe', location);
      }
      if (!TOOL_NAME.test(operationId)) {
        fail('operation_id_not_tool_safe', location);
      }
      const prior = operationIds.get(operationId);
      if (prior !== undefined) {
        fail('operation_id_duplicate', `${prior}; ${location}`);
      }
      operationIds.set(operationId, location);
    }
  }
  if (operationIds.size === 0 && !allowEmpty) fail('selected_operations_empty');
  return Object.freeze([...operationIds.keys()].sort(compareText));
}

/**
 * Validate the exact public selection-manifest contract without retaining its
 * review prose in generated gateway state or diagnostics.
 */
export function validateSelectionManifest(manifest) {
  if (!isRecord(manifest)) fail('manifest_invalid');
  hasExactKeys(
    manifest,
    MANIFEST_KEYS,
    ['entries', 'syntheticTools'],
    'manifest_shape_invalid',
    'root',
  );
  if (Object.hasOwn(manifest, '$comment') &&
      !isReviewText(manifest.$comment, MAX_COMMENT_LENGTH)) {
    fail('manifest_comment_invalid');
  }
  if (!Array.isArray(manifest.entries)) fail('manifest_entries_invalid');
  if (!Array.isArray(manifest.syntheticTools)) fail('manifest_synthetic_tools_invalid');
  if (manifest.entries.length + manifest.syntheticTools.length === 0) {
    fail('manifest_selection_empty');
  }
  if (manifest.entries.length + manifest.syntheticTools.length > MAX_ENABLED_TOOLS_PER_SOURCE) {
    fail('manifest_selection_limit_exceeded');
  }

  const operationIds = new Set();
  const endpoints = new Set();
  const entries = manifest.entries.map((raw, index) => {
    const location = `entries[${index}]`;
    if (!isRecord(raw)) fail('manifest_entry_invalid', location);
    hasExactKeys(
      raw,
      MANIFEST_ENTRY_KEYS,
      ['operationId', 'method', 'path', 'reason', 'verified'],
      'manifest_entry_shape_invalid',
      location,
    );
    if (!v.is(STRING_SCHEMA, raw.operationId) || !TOOL_NAME.test(raw.operationId)) {
      fail('manifest_operation_id_invalid', location);
    }
    if (!v.is(STRING_SCHEMA, raw.method) || !HTTP_METHOD_SET.has(raw.method)) {
      fail('manifest_method_invalid', location);
    }
    if (raw.method === 'GET') fail('manifest_get_operation_forbidden', location);
    if (!v.is(STRING_SCHEMA, raw.path) || !MANIFEST_PATH.test(raw.path) ||
        CONTROL_CHARACTER.test(raw.path)) {
      fail('manifest_path_invalid', location);
    }
    if (!isReviewText(raw.reason, MAX_REASON_LENGTH)) {
      fail('manifest_reason_invalid', location);
    }
    if (!isReviewText(raw.verified, MAX_VERIFICATION_LENGTH)) {
      fail('manifest_verification_invalid', location);
    }
    if (operationIds.has(raw.operationId)) {
      fail('manifest_operation_duplicate', location);
    }
    const endpoint = `${raw.method}\u0000${raw.path}`;
    if (endpoints.has(endpoint)) fail('manifest_endpoint_duplicate', location);
    operationIds.add(raw.operationId);
    endpoints.add(endpoint);
    return Object.freeze({
      method: raw.method,
      operationId: raw.operationId,
      path: raw.path,
    });
  });

  const syntheticNames = new Set();
  const syntheticTools = manifest.syntheticTools.map((raw, index) => {
    const location = `syntheticTools[${index}]`;
    if (!isRecord(raw)) fail('manifest_synthetic_tool_invalid', location);
    hasExactKeys(
      raw,
      SYNTHETIC_TOOL_KEYS,
      ['name', 'reason'],
      'manifest_synthetic_tool_shape_invalid',
      location,
    );
    if (!v.is(STRING_SCHEMA, raw.name) || !TOOL_NAME.test(raw.name)) {
      fail('manifest_synthetic_tool_name_invalid', location);
    }
    if (!isReviewText(raw.reason, MAX_REASON_LENGTH)) {
      fail('manifest_synthetic_tool_reason_invalid', location);
    }
    if (syntheticNames.has(raw.name)) {
      fail('manifest_synthetic_tool_duplicate', location);
    }
    if (operationIds.has(raw.name)) {
      fail('manifest_tool_name_collision', location);
    }
    syntheticNames.add(raw.name);
    return raw.name;
  });

  return Object.freeze({
    entries: Object.freeze(entries),
    syntheticTools: Object.freeze(syntheticTools),
  });
}

function indexSpecOperationIds(openApi) {
  const index = new Map();
  for (const pathName of Object.keys(openApi.paths).sort(compareText)) {
    const pathItem = openApi.paths[pathName];
    if (!isRecord(pathItem)) continue;
    for (const method of HTTP_METHODS) {
      const operation = pathItem[method.toLowerCase()];
      if (!isRecord(operation) || !v.is(STRING_SCHEMA, operation.operationId)) continue;
      index.set(operation.operationId, (index.get(operation.operationId) ?? 0) + 1);
    }
  }
  return index;
}

function requireProtectedOperation(openApi, operation, location) {
  const security = Object.hasOwn(operation, 'security') ? operation.security : openApi.security;
  if (security === undefined || (Array.isArray(security) && security.length === 0)) {
    fail('manifest_operation_public', location);
  }
  if (!Array.isArray(security)) fail('manifest_operation_security_invalid', location);
  const securitySchemes = isRecord(openApi.components) &&
    isRecord(openApi.components.securitySchemes)
    ? openApi.components.securitySchemes
    : null;
  for (const requirement of security) {
    if (!isRecord(requirement)) fail('manifest_operation_security_invalid', location);
    const schemeNames = Object.keys(requirement);
    if (schemeNames.length === 0) fail('manifest_operation_public', location);
    for (const schemeName of schemeNames) {
      if (securitySchemes === null || !Object.hasOwn(securitySchemes, schemeName) ||
          !isRecord(securitySchemes[schemeName])) {
        fail('manifest_operation_security_invalid', location);
      }
      const scopes = requirement[schemeName];
      if (!Array.isArray(scopes) || scopes.some((scope) => !v.is(STRING_SCHEMA, scope))) {
        fail('manifest_operation_security_invalid', location);
      }
    }
  }
}

function extractManifestTools(openApi, manifest, selectedTools) {
  const validated = validateSelectionManifest(manifest);
  const specOperationIds = indexSpecOperationIds(openApi);
  const names = new Set(selectedTools);

  for (const [index, entry] of validated.entries.entries()) {
    const location = `entries[${index}]`;
    const pathItem = openApi.paths[entry.path];
    if (!isRecord(pathItem) || Object.hasOwn(pathItem, '$ref')) {
      fail('manifest_operation_drift', location);
    }
    const operation = pathItem[entry.method.toLowerCase()];
    if (!isRecord(operation) || operation.operationId !== entry.operationId) {
      fail('manifest_operation_drift', location);
    }
    if (specOperationIds.get(entry.operationId) !== 1) {
      fail('manifest_operation_ambiguous', location);
    }
    requireProtectedOperation(openApi, operation, location);
    if (names.has(entry.operationId)) fail('manifest_tool_name_collision', location);
    names.add(entry.operationId);
  }

  for (const [index, name] of validated.syntheticTools.entries()) {
    const location = `syntheticTools[${index}]`;
    if (specOperationIds.has(name) || names.has(name)) {
      fail('manifest_tool_name_collision', location);
    }
    names.add(name);
  }
  if (names.size > MAX_ENABLED_TOOLS_PER_SOURCE) fail('manifest_selection_limit_exceeded');
  return Object.freeze([...names].sort(compareText));
}

/**
 * Extract exact MCP tool names from GET operations and, only when supplied,
 * union exact reviewed manifest selections. Operation IDs remain verbatim.
 */
export function extractEnabledTools(openApi, { methods, manifest }) {
  const selectedTools = extractSelectedMethodTools(openApi, methods, manifest !== undefined);
  if (manifest === undefined) return selectedTools;
  return extractManifestTools(openApi, manifest, selectedTools);
}

/** Replace, rather than union, one source's allowlist and revalidate the result. */
export function mergeEnabledTools(config, sourceId, enabledTools) {
  let validated;
  try {
    validated = validateGatewayConfig(config);
  } catch (error) {
    if (error instanceof GatewayConfigError) fail('gateway_config_invalid');
    throw error;
  }
  if (!v.is(STRING_SCHEMA, sourceId) || !SOURCE_ID.test(sourceId)) fail('source_id_invalid');
  if (!Array.isArray(enabledTools) || enabledTools.length === 0 ||
      enabledTools.some((tool) => !v.is(STRING_SCHEMA, tool) || !TOOL_NAME.test(tool)) ||
      new Set(enabledTools).size !== enabledTools.length) {
    fail('enabled_tools_invalid');
  }
  const tools = [...enabledTools].sort(compareText);
  let found = false;
  const sources = validated.sources.map((source) => {
    if (source.id !== sourceId) return source;
    found = true;
    return { ...source, enabledTools: tools };
  });
  if (!found) fail('source_not_found', sourceId);
  const merged = { ...validated, sources };
  try {
    return validateGatewayConfig(merged);
  } catch (error) {
    if (error instanceof GatewayConfigError) fail('generated_gateway_config_invalid');
    throw error;
  }
}

export function serializeGatewayConfig(config) {
  return `${JSON.stringify(config, null, 2)}\n`;
}

function arraysEqual(left, right) {
  return left.length === right.length && left.every((value, index) => value === right[index]);
}

function parseArguments(argv) {
  const options = {
    check: false,
    config: '',
    manifest: '',
    methods: [],
    source: '',
    spec: '',
    write: false,
  };
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (argument === '--help' || argument === '-h') return { help: true };
    if (argument === '--write') {
      if (options.write) fail('argument_duplicate', argument);
      options.write = true;
      continue;
    }
    if (argument === '--check') {
      if (options.check) fail('argument_duplicate', argument);
      options.check = true;
      continue;
    }
    if (!['--config', '--manifest', '--method', '--source', '--spec'].includes(argument)) {
      fail('argument_unknown');
    }
    const value = argv[index + 1];
    if (value === undefined || value.startsWith('--')) fail('argument_value_missing', argument);
    index += 1;
    if (argument === '--method') options.methods.push(value);
    else {
      const option = argument.slice(2);
      if (options[option] !== '') fail('argument_duplicate', argument);
      options[option] = value;
    }
  }
  if (options.spec === '') fail('argument_required', '--spec');
  if (options.config === '') fail('argument_required', '--config');
  if (options.source === '') fail('argument_required', '--source');
  if (options.write && options.check) fail('mode_conflict', '--write and --check');
  return options;
}

async function readJson(file, label) {
  let bytes;
  try {
    bytes = await readFile(file, 'utf8');
  } catch {
    fail(`${label}_read_failed`);
  }
  try {
    return JSON.parse(bytes);
  } catch {
    fail(`${label}_json_invalid`);
  }
}

async function replaceFileAtomically(file, contents) {
  let metadata;
  try {
    metadata = await lstat(file);
  } catch {
    fail('gateway_config_write_failed');
  }
  if (!metadata.isFile()) fail('gateway_config_write_failed');
  const temporary = path.join(
    path.dirname(file),
    `.${path.basename(file)}.${process.pid}.${randomBytes(8).toString('hex')}.tmp`,
  );
  let handle = null;
  try {
    handle = await open(temporary, 'wx', metadata.mode & 0o777);
    await handle.writeFile(contents, 'utf8');
    await handle.sync();
    await handle.close();
    handle = null;
    await rename(temporary, file);
  } catch {
    try { await handle?.close(); } catch { /* The fixed write error remains authoritative. */ }
    try { await rm(temporary, { force: true }); } catch { /* The fixed write error remains authoritative. */ }
    fail('gateway_config_write_failed');
  }
}

export async function runOpenApiEnabledTools(argv, io = {}) {
  const stdout = io.stdout ?? process.stdout;
  const options = parseArguments(argv);
  if (options.help) {
    stdout.write(`${USAGE}\n`);
    return;
  }

  const [openApi, config, manifest] = await Promise.all([
    readJson(path.resolve(options.spec), 'openapi'),
    readJson(path.resolve(options.config), 'gateway_config'),
    options.manifest === ''
      ? Promise.resolve(undefined)
      : readJson(path.resolve(options.manifest), 'manifest'),
  ]);
  const enabledTools = extractEnabledTools(openApi, { methods: options.methods, manifest });
  const merged = mergeEnabledTools(config, options.source, enabledTools);
  const current = config.sources.find((source) => source.id === options.source).enabledTools;
  const upToDate = arraysEqual(current, enabledTools);

  if (options.check) {
    if (!upToDate) {
      const currentSet = new Set(current);
      const generatedSet = new Set(enabledTools);
      const added = enabledTools.filter((tool) => !currentSet.has(tool)).length;
      const removed = current.filter((tool) => !generatedSet.has(tool)).length;
      fail(
        'enabled_tools_stale',
        `${enabledTools.length} expected; ${added} added; ${removed} removed; run with --write`,
      );
    }
    stdout.write(`enabledTools is current for ${options.source} (${enabledTools.length} tools).\n`);
    return;
  }

  if (options.write) {
    if (!upToDate) {
      await replaceFileAtomically(
        path.resolve(options.config),
        serializeGatewayConfig(merged),
      );
      stdout.write(`Updated enabledTools for ${options.source} (${enabledTools.length} tools).\n`);
    } else {
      stdout.write(`enabledTools is current for ${options.source} (${enabledTools.length} tools).\n`);
    }
    return;
  }

  stdout.write(serializeGatewayConfig(merged));
}

function isMainModule() {
  return process.argv[1] !== undefined &&
    pathToFileURL(path.resolve(process.argv[1])).href === import.meta.url;
}

if (isMainModule()) {
  runOpenApiEnabledTools(process.argv.slice(2)).catch((error) => {
    if (error instanceof OpenApiEnabledToolsError) {
      process.stderr.write(`OpenAPI enabledTools error: ${error.message}\n`);
    } else {
      process.stderr.write('OpenAPI enabledTools error: unexpected_failure\n');
    }
    process.exitCode = 1;
  });
}

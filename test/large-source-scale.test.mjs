import { execFile } from 'node:child_process';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import test from 'node:test';
import assert from 'node:assert/strict';
import { validateGatewayConfig } from '../src/config.ts';
import { buildGatewayPlan } from '../src/plan.ts';
import { extractEnabledTools } from '../tools/openapi-enabled-tools.mjs';

const execFileAsync = promisify(execFile);
const fixtureUrl = new URL('../fixtures/large-source/gateway.config.json', import.meta.url);
const openApiUrl = new URL('../fixtures/large-source/openapi.json', import.meta.url);
const hostileNamesUrl = new URL(
  '../fixtures/large-source/sanitization-hostile.config.json',
  import.meta.url,
);
const schemaUrl = new URL('../schema/gateway-config.schema.json', import.meta.url);
const fixturePath = fileURLToPath(fixtureUrl);
const cliPath = fileURLToPath(new URL('../src/cli.ts', import.meta.url));
const observedPath = fileURLToPath(new URL('../examples/observed.empty.json', import.meta.url));
const accessPath = fileURLToPath(new URL('../examples/access-input.json', import.meta.url));
const SCALE_TOOL_COUNT = 228;
const CURRENT_WORKLOAD_TOOL_COUNT = 224;
const VALIDATION_ITERATIONS = 100;
const PLAN_ITERATIONS = 5;
const SCALE_CPU_GUARD_MS = 5_000;

async function fixture() {
  return JSON.parse(await readFile(fixtureUrl, 'utf8'));
}

async function hostileNamesFixture() {
  return JSON.parse(await readFile(hostileNamesUrl, 'utf8'));
}

function workloadAtCurrentCardinality(input) {
  const output = structuredClone(input);
  output.sources[0].label = 'Synthetic 224-tool read catalogue';
  if (CURRENT_WORKLOAD_TOOL_COUNT <= SCALE_TOOL_COUNT) {
    output.sources[0].enabledTools = output.sources[0].enabledTools.slice(
      0,
      CURRENT_WORKLOAD_TOOL_COUNT,
    );
  } else {
    const supplementalNames = Array.from(
      { length: CURRENT_WORKLOAD_TOOL_COUNT - SCALE_TOOL_COUNT },
      (_value, index) => `workload_read_${String(index + 1).padStart(3, '0')}`,
    );
    output.sources[0].enabledTools = [
      ...output.sources[0].enabledTools,
      ...supplementalNames,
    ].sort();
  }
  return output;
}

function planningInput() {
  return {
    target: {
      accountId: 'example-account-id',
      zoneId: 'example-zone-id',
      zoneName: 'example.com',
      zoneStatus: 'active',
      zeroTrustReady: true,
    },
    resources: [],
  };
}

function planningOptions() {
  return {
    release: 'large-source-test',
    access: { allowedEmails: ['owner@example.com'] },
  };
}

function sourceToolNames(plan) {
  const source = plan.changes.find((change) => change.kind === 'mcp_server');
  assert.ok(source?.desired);
  return source.desired.toolPolicy.allowedTools;
}

function portalToolNames(plan) {
  const portal = plan.changes.find((change) => change.kind === 'portal');
  assert.ok(portal?.desired);
  assert.equal(portal.desired.sourceMappings.length, 1);
  return portal.desired.sourceMappings[0].allowedTools;
}

function elapsedCpuMilliseconds(start) {
  const elapsed = process.cpuUsage(start);
  return (elapsed.user + elapsed.system) / 1_000;
}

test('the public large-source fixture is synthetic, sorted, and schema-valid', async () => {
  const input = await fixture();
  const raw = await readFile(fixtureUrl, 'utf8');
  const openApi = JSON.parse(await readFile(openApiUrl, 'utf8'));
  const schema = JSON.parse(await readFile(schemaUrl, 'utf8'));
  const tools = input.sources[0].enabledTools;
  const enabledToolsSchema = schema.properties.sources.items.properties.enabledTools;

  assert.equal(tools.length, SCALE_TOOL_COUNT);
  assert.equal(new Set(tools).size, SCALE_TOOL_COUNT);
  assert.deepEqual(tools, [...tools].sort());
  assert.ok(tools.every((name) => /^[a-z]+_read_[0-9]{3}$/u.test(name)));
  assert.equal(
    raw.split('\n').filter((line) => /^        "[a-z]+_read_[0-9]{3}"[,]?$/u.test(line)).length,
    SCALE_TOOL_COUNT,
  );
  assert.ok(
    enabledToolsSchema.maxItems === undefined ||
    enabledToolsSchema.maxItems >= SCALE_TOOL_COUNT,
  );
  assert.equal(Object.keys(openApi.paths).length, SCALE_TOOL_COUNT);
  for (const { get } of Object.values(openApi.paths)) {
    assert.match(get.summary, /\S/u);
    assert.match(get.description, /\S/u);
  }
  assert.deepEqual(extractEnabledTools(openApi, { methods: ['GET'] }), tools);
  assert.deepEqual(validateGatewayConfig(input), input);
});

test('validation and planning stay bounded at 228 exact tools', async () => {
  const input = await fixture();

  const validationStart = process.cpuUsage();
  for (let index = 0; index < VALIDATION_ITERATIONS; index += 1) {
    validateGatewayConfig(input);
  }
  const validationElapsed = elapsedCpuMilliseconds(validationStart);
  assert.ok(
    validationElapsed < SCALE_CPU_GUARD_MS,
    `${VALIDATION_ITERATIONS} validations used ${validationElapsed.toFixed(1)}ms CPU`,
  );

  const plans = [];
  const planStart = process.cpuUsage();
  for (let index = 0; index < PLAN_ITERATIONS; index += 1) {
    plans.push(await buildGatewayPlan(input, planningInput(), planningOptions()));
  }
  const planElapsed = elapsedCpuMilliseconds(planStart);
  assert.ok(
    planElapsed < SCALE_CPU_GUARD_MS,
    `${PLAN_ITERATIONS} plans used ${planElapsed.toFixed(1)}ms CPU`,
  );
  assert.deepEqual(plans.slice(1), Array(PLAN_ITERATIONS - 1).fill(plans[0]));
  assert.deepEqual(sourceToolNames(plans[0]), input.sources[0].enabledTools);
  assert.deepEqual(portalToolNames(plans[0]), input.sources[0].enabledTools);
});

test('validation and planning cover the current 224-tool workload cardinality', async () => {
  const input = workloadAtCurrentCardinality(await fixture());
  assert.equal(input.sources[0].enabledTools.length, CURRENT_WORKLOAD_TOOL_COUNT);
  assert.equal(new Set(input.sources[0].enabledTools).size, CURRENT_WORKLOAD_TOOL_COUNT);
  assert.deepEqual(input.sources[0].enabledTools, [...input.sources[0].enabledTools].sort());
  assert.deepEqual(validateGatewayConfig(input), input);

  const validationStart = process.cpuUsage();
  for (let index = 0; index < VALIDATION_ITERATIONS; index += 1) {
    validateGatewayConfig(input);
  }
  const validationElapsed = elapsedCpuMilliseconds(validationStart);
  assert.ok(
    validationElapsed < SCALE_CPU_GUARD_MS,
    `${VALIDATION_ITERATIONS} validations used ${validationElapsed.toFixed(1)}ms CPU`,
  );

  const plans = [];
  const planStart = process.cpuUsage();
  for (let index = 0; index < PLAN_ITERATIONS; index += 1) {
    plans.push(await buildGatewayPlan(input, planningInput(), planningOptions()));
  }
  const planElapsed = elapsedCpuMilliseconds(planStart);
  assert.ok(
    planElapsed < SCALE_CPU_GUARD_MS,
    `${PLAN_ITERATIONS} plans used ${planElapsed.toFixed(1)}ms CPU`,
  );
  assert.deepEqual(plans.slice(1), Array(PLAN_ITERATIONS - 1).fill(plans[0]));
  assert.deepEqual(sourceToolNames(plans[0]), input.sources[0].enabledTools);
  assert.deepEqual(portalToolNames(plans[0]), input.sources[0].enabledTools);
});

test('sanitization-hostile names remain exact through validation and planning', async () => {
  const input = await hostileNamesFixture();
  const names = input.sources[0].enabledTools;
  const plan = await buildGatewayPlan(input, planningInput(), planningOptions());

  assert.deepEqual(validateGatewayConfig(input), input);
  assert.deepEqual(sourceToolNames(plan), names);
  assert.deepEqual(portalToolNames(plan), names);
  assert.equal(new Set(names).size, names.length);
  assert.deepEqual(names, [...names].sort());
  assert.deepEqual(
    names
      .filter((name) => name.startsWith('catalog'))
      .map((name) => name.replaceAll('-', '_').replaceAll('.', '_')),
    Array(3).fill('catalog_item_read'),
  );
});

test('one allowlist edit changes the plan exactly and keeps human output concise', async () => {
  const input = await fixture();
  const changed = structuredClone(input);
  changed.sources[0].enabledTools = changed.sources[0].enabledTools
    .filter((name) => name !== 'support_read_019')
    .concat('support_read_020')
    .sort();

  const before = await buildGatewayPlan(input, planningInput(), planningOptions());
  const after = await buildGatewayPlan(changed, planningInput(), planningOptions());
  assert.notEqual(after.desiredHash, before.desiredHash);
  assert.notEqual(after.planId, before.planId);
  assert.deepEqual(
    sourceToolNames(before).filter((name) => !sourceToolNames(after).includes(name)),
    ['support_read_019'],
  );
  assert.deepEqual(
    sourceToolNames(after).filter((name) => !sourceToolNames(before).includes(name)),
    ['support_read_020'],
  );
  assert.deepEqual(portalToolNames(after), sourceToolNames(after));

  const result = await execFileAsync(process.execPath, [
    cliPath,
    'plan',
    fixturePath,
    '--observed',
    observedPath,
    '--access',
    accessPath,
    '--release',
    'large-source-test',
  ], { cwd: new URL('..', import.meta.url), encoding: 'utf8' });

  assert.equal(result.stderr, '');
  assert.match(result.stdout, /Changes \(7\):/u);
  assert.ok(result.stdout.split('\n').length < 50);
  assert.doesNotMatch(result.stdout, /analytics_read_001|support_read_019/u);
});

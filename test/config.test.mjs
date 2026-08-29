import { readFile } from 'node:fs/promises';
import test from 'node:test';
import assert from 'node:assert/strict';
import {
  GatewayConfigError,
  MAX_ENABLED_TOOLS_PER_SOURCE,
  validateGatewayConfig,
} from '../src/config.ts';

async function example() {
  return JSON.parse(
    await readFile(new URL('../examples/gateway.config.json', import.meta.url), 'utf8'),
  );
}

test('accepts the checked-in secret-free example', async () => {
  const config = await example();
  assert.deepEqual(validateGatewayConfig(config), config);
});

test('accepts an optional exact logical Access group name', async () => {
  const config = await example();
  config.sources[0].accessGroup = 'ERP Readers';
  assert.deepEqual(validateGatewayConfig(config), config);
});

test('rejects malformed logical Access group names', async () => {
  for (const accessGroup of [
    '',
    ' ERP Readers',
    'ERP Readers ',
    '\u00a0ERP Readers',
    'ERP Readers\u00a0',
    'ERP\u0000Readers',
    'ERP\u007fReaders',
  ]) {
    const config = await example();
    config.sources[0].accessGroup = accessGroup;
    assert.throws(
      () => validateGatewayConfig(config),
      (error) => error instanceof GatewayConfigError
        && error.errors.some((message) => message.includes('.accessGroup must be an exact')),
      JSON.stringify(accessGroup),
    );
  }
});

test('counts logical Access group length in Unicode code points like JSON Schema', async () => {
  const config = await example();
  config.sources[0].accessGroup = '\u{1f986}'.repeat(128);
  assert.deepEqual(validateGatewayConfig(config), config);

  config.sources[0].accessGroup = '\u{1f986}'.repeat(129);
  assert.throws(
    () => validateGatewayConfig(config),
    (error) => error instanceof GatewayConfigError
      && error.errors.some((message) => message.includes('.accessGroup must be an exact')),
  );
});

test('rejects secret-bearing configuration fields', async () => {
  const config = await example();
  config.sources[0].apiToken = 'not-a-real-token';
  assert.throws(
    () => validateGatewayConfig(config),
    (error) =>
      error instanceof GatewayConfigError &&
      error.errors.some((message) => message.includes('forbidden secret-bearing field')),
  );
});

test('rejects non-HTTPS and credential-like query parameters', async () => {
  const config = await example();
  config.sources[0].url = 'http://context.example.com/mcp?api_key=example';
  assert.throws(
    () => validateGatewayConfig(config),
    (error) =>
      error instanceof GatewayConfigError &&
      error.errors.some((message) => message.includes('must be HTTPS')) &&
      error.errors.some((message) => message.includes('credential-like query')),
  );
});

test('rejects wildcard and duplicate tool exposure', async () => {
  const config = await example();
  config.sources[0].enabledTools = ['company_prepare', 'company_prepare', '*'];
  assert.throws(
    () => validateGatewayConfig(config),
    (error) =>
      error instanceof GatewayConfigError &&
      error.errors.some((message) => message.includes('duplicates company_prepare')) &&
      error.errors.some((message) => message.includes('must not be a wildcard')),
  );
});

test('accepts exactly 500 enabled tools and rejects a 501st', async () => {
  const config = await example();
  config.sources[0].enabledTools = Array.from(
    { length: MAX_ENABLED_TOOLS_PER_SOURCE },
    (_value, index) => `synthetic_read_${String(index + 1).padStart(3, '0')}`,
  );
  assert.deepEqual(validateGatewayConfig(config), config);

  config.sources[0].enabledTools.push('synthetic_read_501');
  assert.throws(
    () => validateGatewayConfig(config),
    (error) =>
      error instanceof GatewayConfigError &&
      error.errors.some((message) => message.includes('cannot contain more than 500 entries')),
  );
});

test('rejects duplicate source identities', async () => {
  const config = await example();
  config.sources.push({ ...config.sources[0] });
  assert.throws(
    () => validateGatewayConfig(config),
    (error) =>
      error instanceof GatewayConfigError &&
      error.errors.some((message) => message.includes('duplicates company-context')),
  );
});

test('rejects unsupported fields and IP-address upstreams', async () => {
  const config = await example();
  config.gateway.callbackUrl = 'https://telemetry.example.com';
  config.sources[0].url = 'https://127.0.0.1/mcp';
  assert.throws(
    () => validateGatewayConfig(config),
    (error) =>
      error instanceof GatewayConfigError &&
      error.errors.some((message) => message.includes('callbackUrl is not supported')) &&
      error.errors.some((message) => message.includes('public fully qualified hostname')),
  );
});

test('keeps the shared validator free of IP-literal upstreams', async () => {
  const config = await example();
  config.sources[0].url = 'https://[2001:db8::1]/mcp';
  assert.throws(
    () => validateGatewayConfig(config),
    (error) =>
      error instanceof GatewayConfigError &&
      error.errors.some((message) => message.includes('public fully qualified hostname')),
  );
});

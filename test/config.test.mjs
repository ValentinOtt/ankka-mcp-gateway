import { readFile } from 'node:fs/promises';
import test from 'node:test';
import assert from 'node:assert/strict';
import { GatewayConfigError, validateGatewayConfig } from '../src/config.mjs';

async function example() {
  return JSON.parse(
    await readFile(new URL('../examples/gateway.config.json', import.meta.url), 'utf8'),
  );
}

test('accepts the checked-in secret-free example', async () => {
  const config = await example();
  assert.equal(validateGatewayConfig(config), config);
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

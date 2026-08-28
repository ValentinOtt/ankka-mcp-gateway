import test from 'node:test';
import assert from 'node:assert/strict';
import {
  CanaryPreflightInputError,
  executeCanaryPreflightCommand,
} from '../src/canary-command.ts';

const ACCOUNT_ID = 'a'.repeat(32);
const ZONE_ID = 'b'.repeat(32);
const ZONE_NAME = 'canary.example';
const HOSTNAME = `gateway.${ZONE_NAME}`;
const TOKEN = 'test-only-sensitive-token';

function readClient(overrides = {}) {
  return {
    getZone: async () => ({
      id: ZONE_ID,
      name: ZONE_NAME,
      status: 'active',
      account: { id: ACCOUNT_ID },
    }),
    listIdentityProviders: async () => [{ id: ACCOUNT_ID }],
    listMcpServers: async () => [],
    listPortals: async () => [],
    listAccessApps: async () => [],
    listDnsRecords: async () => [],
    ...overrides,
  };
}

test('reads the token only through the injected closure and produces safe JSON', async () => {
  let reads = 0;
  const fetchImpl = async () => {
    throw new Error('unused');
  };
  const result = await executeCanaryPreflightCommand(
    { accountId: ACCOUNT_ID, zoneId: ZONE_ID, hostname: HOSTNAME, json: true },
    {
      readToken: () => {
        reads += 1;
        return TOKEN;
      },
      fetchImpl,
      clientFactory(options) {
        assert.equal(options.token, TOKEN);
        assert.equal(options.accountId, ACCOUNT_ID);
        assert.equal(options.zoneId, ZONE_ID);
        assert.equal(options.fetchImpl, fetchImpl);
        return readClient();
      },
    },
  );

  assert.equal(reads, 1);
  assert.equal(result.exitCode, 0);
  assert.equal(JSON.parse(result.output).ready, true);
  assert.equal(JSON.parse(result.output).writesPerformed, false);
  assert.doesNotMatch(result.output, new RegExp(TOKEN));
  assert.doesNotMatch(result.output, new RegExp(ACCOUNT_ID));
  assert.doesNotMatch(result.output, new RegExp(ZONE_ID));
  assert.doesNotMatch(result.output, new RegExp(HOSTNAME));
});

test('renders a concise human result with an explicit zero-write statement', async () => {
  const result = await executeCanaryPreflightCommand(
    { accountId: ACCOUNT_ID, zoneId: ZONE_ID, hostname: HOSTNAME },
    { readToken: () => TOKEN, clientFactory: () => readClient() },
  );

  assert.match(result.output, /^Cloudflare canary preflight: READY/);
  assert.match(result.output, /Active zone: ready/);
  assert.match(result.output, /MCP Portal read: available/);
  assert.match(result.output, /No Cloudflare resources were changed\./);
  assert.doesNotMatch(result.output, new RegExp(TOKEN));
  assert.doesNotMatch(result.output, new RegExp(ACCOUNT_ID));
  assert.doesNotMatch(result.output, new RegExp(ZONE_ID));
  assert.doesNotMatch(result.output, new RegExp(HOSTNAME));
});

test('returns a sanitized nonzero result for denied reads', async () => {
  const result = await executeCanaryPreflightCommand(
    { accountId: ACCOUNT_ID, zoneId: ZONE_ID, hostname: HOSTNAME },
    {
      readToken: () => TOKEN,
      clientFactory: () => readClient({ listPortals: async () => { throw new Error(TOKEN); } }),
    },
  );

  assert.equal(result.exitCode, 1);
  assert.match(result.output, /^Cloudflare canary preflight: NOT READY/);
  assert.match(result.output, /MCP Portal read: failed/);
  assert.match(result.output, /unexpected_error/);
  assert.doesNotMatch(result.output, new RegExp(TOKEN));
});

test('rejects missing environment tokens without calling the client factory', async () => {
  let clientCalls = 0;
  await assert.rejects(
    executeCanaryPreflightCommand(
      { accountId: ACCOUNT_ID, zoneId: ZONE_ID, hostname: HOSTNAME },
      {
        readToken: () => undefined,
        clientFactory: () => {
          clientCalls += 1;
          return readClient();
        },
      },
    ),
    (error) => {
      assert.ok(error instanceof CanaryPreflightInputError);
      assert.match(error.message, /CLOUDFLARE_API_TOKEN is required/);
      return true;
    },
  );
  assert.equal(clientCalls, 0);
});

test('redacts errors from injected token and client closures', async () => {
  await assert.rejects(
    executeCanaryPreflightCommand(
      { accountId: ACCOUNT_ID, zoneId: ZONE_ID, hostname: HOSTNAME },
      { readToken: () => { throw new Error(TOKEN); } },
    ),
    (error) => {
      assert.doesNotMatch(error.message, new RegExp(TOKEN));
      return true;
    },
  );
  await assert.rejects(
    executeCanaryPreflightCommand(
      { accountId: ACCOUNT_ID, zoneId: ZONE_ID, hostname: HOSTNAME },
      { readToken: () => TOKEN, clientFactory: () => { throw new Error(TOKEN); } },
    ),
    (error) => {
      assert.doesNotMatch(error.message, new RegExp(TOKEN));
      return true;
    },
  );
});

test('requires exact Cloudflare identifiers and rejects unsupported invocation fields', async () => {
  await assert.rejects(
    executeCanaryPreflightCommand(
      { accountId: 'private-account-value', zoneId: ZONE_ID, hostname: HOSTNAME },
      { readToken: () => TOKEN },
    ),
    (error) => {
      assert.match(error.message, /32-character Cloudflare identifier/);
      assert.doesNotMatch(error.message, /private-account-value/);
      return true;
    },
  );
  await assert.rejects(
    executeCanaryPreflightCommand(
      { accountId: ACCOUNT_ID, zoneId: ZONE_ID, hostname: HOSTNAME, token: TOKEN },
      { readToken: () => TOKEN },
    ),
    (error) => {
      assert.match(error.message, /unsupported fields/);
      assert.doesNotMatch(error.message, new RegExp(TOKEN));
      return true;
    },
  );
});

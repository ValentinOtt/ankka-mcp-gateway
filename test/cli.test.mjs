import { execFile } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import test from 'node:test';
import assert from 'node:assert/strict';

const execFileAsync = promisify(execFile);
const cli = fileURLToPath(new URL('../src/cli.mjs', import.meta.url));
const config = fileURLToPath(new URL('../examples/gateway.config.json', import.meta.url));
const observed = fileURLToPath(new URL('../examples/observed.empty.json', import.meta.url));
const access = fileURLToPath(new URL('../examples/access-input.json', import.meta.url));

async function run(args) {
  return execFileAsync(process.execPath, [cli, ...args], {
    cwd: new URL('..', import.meta.url),
    encoding: 'utf8',
  });
}

test('preserves the original validate invocation', async () => {
  const result = await run([config]);
  assert.match(result.stdout, /Valid gateway configuration: 1 source\(s\), 1 tool\(s\)\./);
  assert.equal(result.stderr, '');
});

test('prints command help successfully', async () => {
  const result = await run(['--help']);
  assert.match(result.stdout, /npm run validate/);
  assert.match(result.stdout, /npm run plan/);
  assert.match(result.stdout, /npm --silent run canary:preflight/);
  assert.equal(result.stderr, '');
});

test('requires explicit canary account and zone identifiers', async () => {
  await assert.rejects(
    run(['canary', 'preflight']),
    (error) => {
      assert.equal(error.code, 2);
      assert.match(error.stderr, /requires explicit --account-id, --zone-id, and --hostname/);
      assert.doesNotMatch(error.stderr, /CLOUDFLARE_API_TOKEN=/);
      return true;
    },
  );
});

test('rejects canary token flags and invalid identifiers without echoing values', async () => {
  const privateValue = 'private-account-value';
  await assert.rejects(
    run([
      'canary',
      'preflight',
      '--account-id',
      privateValue,
      '--zone-id',
      'b'.repeat(32),
      '--hostname',
      'gateway.canary.example',
    ]),
    (error) => {
      assert.equal(error.code, 2);
      assert.match(error.stderr, /32-character Cloudflare identifier/);
      assert.doesNotMatch(error.stderr, new RegExp(privateValue));
      return true;
    },
  );
  await assert.rejects(
    run([
      'canary',
      'preflight',
      '--account-id',
      'a'.repeat(32),
      '--zone-id',
      'b'.repeat(32),
      '--hostname',
      'gateway.canary.example',
      '--token',
      'must-not-be-accepted',
    ]),
    (error) => {
      assert.equal(error.code, 2);
      assert.match(error.stderr, /unknown option/);
      assert.doesNotMatch(error.stderr, /must-not-be-accepted/);
      return true;
    },
  );
});

test('requires the canary token from the environment and never echoes selected identifiers', async () => {
  const accountId = 'a'.repeat(32);
  const zoneId = 'b'.repeat(32);
  const hostname = 'gateway.canary.example';
  await assert.rejects(
    execFileAsync(
      process.execPath,
      [
        cli,
        'canary',
        'preflight',
        '--account-id',
        accountId,
        '--zone-id',
        zoneId,
        '--hostname',
        hostname,
      ],
      {
        cwd: new URL('..', import.meta.url),
        encoding: 'utf8',
        env: { ...process.env, CLOUDFLARE_API_TOKEN: '' },
      },
    ),
    (error) => {
      assert.equal(error.code, 2);
      assert.match(error.stderr, /CLOUDFLARE_API_TOKEN is required/);
      assert.doesNotMatch(error.stderr, new RegExp(accountId));
      assert.doesNotMatch(error.stderr, new RegExp(zoneId));
      assert.doesNotMatch(error.stderr, new RegExp(hostname));
      return true;
    },
  );
});

test('the documented silent npm wrapper does not echo canary target arguments', async () => {
  const accountId = 'c'.repeat(32);
  const zoneId = 'd'.repeat(32);
  const hostname = 'gateway.wrapper.example';
  await assert.rejects(
    execFileAsync(
      'npm',
      [
        '--silent',
        'run',
        'canary:preflight',
        '--',
        '--account-id',
        accountId,
        '--zone-id',
        zoneId,
        '--hostname',
        hostname,
      ],
      {
        cwd: new URL('..', import.meta.url),
        encoding: 'utf8',
        env: { ...process.env, CLOUDFLARE_API_TOKEN: '' },
      },
    ),
    (error) => {
      const output = `${error.stdout ?? ''}\n${error.stderr ?? ''}`;
      assert.equal(error.code, 2);
      assert.match(output, /CLOUDFLARE_API_TOKEN is required/);
      assert.doesNotMatch(output, new RegExp(accountId));
      assert.doesNotMatch(output, new RegExp(zoneId));
      assert.doesNotMatch(output, new RegExp(hostname));
      return true;
    },
  );
});

test('rejects an invalid canary hostname without echoing it', async () => {
  const privateHostname = 'not a hostname';
  await assert.rejects(
    run([
      'canary',
      'preflight',
      '--account-id',
      'a'.repeat(32),
      '--zone-id',
      'b'.repeat(32),
      '--hostname',
      privateHostname,
    ]),
    (error) => {
      assert.equal(error.code, 2);
      assert.match(error.stderr, /--hostname must be an explicit valid DNS hostname/);
      assert.doesNotMatch(error.stderr, new RegExp(privateHostname));
      return true;
    },
  );
});

test('prints a machine-readable deterministic plan', async () => {
  const first = await run([
    'plan',
    config,
    '--observed',
    observed,
    '--access',
    access,
    '--release',
    'test-release',
    '--json',
  ]);
  const second = await run([
    'plan',
    config,
    '--observed',
    observed,
    '--access',
    access,
    '--release',
    'test-release',
    '--json',
  ]);

  assert.equal(first.stderr, '');
  assert.equal(first.stdout, second.stdout);
  assert.doesNotMatch(first.stdout, /owner@example\.com/);
  const plan = JSON.parse(first.stdout);
  assert.equal(plan.schemaVersion, 1);
  assert.equal(plan.release, 'test-release');
  assert.match(plan.planId, /\S/);
  assert.match(plan.desiredHash, /\S/);
  assert.ok(Array.isArray(plan.requiredCapabilities));
  assert.equal(Object.hasOwn(plan, 'permissions'), false);
  assert.ok(Array.isArray(plan.changes));
  assert.ok(Array.isArray(plan.uninstall));
});

test('human plan output is concise and does not print private input details', async () => {
  const result = await run(['plan', config, '--observed', observed, '--access', access]);

  assert.match(result.stdout, /^Plan: \S+/);
  assert.match(result.stdout, /Required provider capabilities/);
  assert.match(result.stdout, /OAuth consent: not requested by offline planning/);
  assert.match(result.stdout, /Changes \(/);
  assert.match(result.stdout, /Removal preview, non-authoritative \(/);
  assert.doesNotMatch(result.stdout, /owner@example\.com/);
  assert.doesNotMatch(result.stdout, /context\.example\.com/);
  assert.equal(result.stderr, '');
});

test('rejects incomplete plan arguments with usage and exit code 2', async () => {
  await assert.rejects(
    run(['plan', config]),
    (error) => {
      assert.equal(error.code, 2);
      assert.match(error.stderr, /requires --observed/);
      assert.match(error.stderr, /npm run plan/);
      return true;
    },
  );
});

test('requires a separate process-local Access input', async () => {
  await assert.rejects(
    run(['plan', config, '--observed', observed]),
    (error) => {
      assert.equal(error.code, 2);
      assert.match(error.stderr, /requires --access/);
      assert.match(error.stderr, /access-input\.json/);
      return true;
    },
  );
});

test('rejects unsafe release labels before planning', async () => {
  await assert.rejects(
    run([
      'plan',
      config,
      '--observed',
      observed,
      '--access',
      access,
      '--release',
      'release with spaces',
    ]),
    (error) => {
      assert.equal(error.code, 2);
      assert.match(error.stderr, /--release must be an identifier/);
      return true;
    },
  );
});

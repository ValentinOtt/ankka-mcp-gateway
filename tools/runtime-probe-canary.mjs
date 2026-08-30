import { readFile } from 'node:fs/promises';
import { pathToFileURL } from 'node:url';
import { RUNTIME_PROBE_PLAN, cloudflareTransport, runRuntimeProbeCanary } from './runtime-probe/run.mjs';

export async function main(args, env = process.env, output = console.log) {
  if (args.length === 0 || (args.length === 1 && args[0] === '--plan')) {
    output(JSON.stringify({ mode: 'plan', steps: RUNTIME_PROBE_PLAN }, null, 2));
    return 0;
  }
  if (args.length !== 1 || args[0] !== '--execute') {
    output('Use --plan or --execute. Existing Worker names and cleanup/resume files are not accepted.');
    return 2;
  }
  try {
    const fixtureSource = await readFile(new URL('../fixtures/runtime-probe/worker.mjs', import.meta.url), 'utf8');
    const result = await runRuntimeProbeCanary({
      accountId: env.CLOUDFLARE_ACCOUNT_ID,
      fixtureSource,
      api: cloudflareTransport(env.CLOUDFLARE_API_TOKEN),
      onEvent: (event) => output(JSON.stringify(event)),
    });
    output(JSON.stringify(result, null, 2));
    return result.passed ? 0 : 1;
  } catch {
    output('Canary could not start. Check the account ID, API token, and local fixture; no exception details are printed.');
    return 1;
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  process.exitCode = await main(process.argv.slice(2));
}

import { runCustomerRuntimeUpdate, type CustomerRuntimeControlCommand } from '../src/customer-runtime-update';

/**
 * Runs the gateway's own updater from this process against a real installed
 * Worker on the test account, with the API token standing in for the upgrade
 * grant and the journal replaced by a log: it proves the provider side of a
 * gateway-run update (bundle download and verification, asset session and
 * upload, script upload with inherited secrets) without a browser. The
 * Worker it targets ends up running the pinned release with its journal
 * untouched, so use it on a test install only.
 */
const token = process.env.ANKKA_LIVE_TOKEN ?? '';
const accountId = process.env.ANKKA_LIVE_ACCOUNT_ID ?? '';
const workerName = process.env.ANKKA_LIVE_WORKER_NAME ?? '';
const targetRelease = process.env.ANKKA_LIVE_TARGET_RELEASE ?? '';
const targetSha = process.env.ANKKA_LIVE_TARGET_SHA256 ?? '';
const keyId = process.env.ANKKA_LIVE_UPDATE_KEY_ID ?? '';
const publicKey = process.env.ANKKA_LIVE_UPDATE_PUBLIC_KEY ?? '';

describe('gateway-run update against the test account', () => {
  it('downloads, verifies, and uploads the pinned release over a real Worker', async () => {
    if (!token || !accountId || !workerName) throw new Error('missing live environment');
    const commands: CustomerRuntimeControlCommand[] = [];
    const calls: string[] = [];
    try {
      const result = await runCustomerRuntimeUpdate({
        accessToken: token,
        accountId,
        workerName,
        controlPlaneOrigin: 'https://deploy.ankka.ai',
        channel: 'canary',
        updateKeyId: keyId,
        updatePublicKey: publicKey,
        target: { release: targetRelease, artifactSha256: targetSha },
        transport: async (input, init) => {
          const request = input instanceof Request ? input : new Request(input, init);
          const started = Date.now();
          const response = await fetch(request);
          const path = new URL(request.url).pathname.replace(accountId, '<account>').slice(0, 110);
          calls.push(`${response.status} ${Date.now() - started}ms ${request.method} ${path}`);
          return response;
        },
        control: async (command) => {
          commands.push(command);
          console.log(`control ${command.command}${command.command === 'progress' ? ` ${command.stage}` : ''}`);
          return true;
        },
        armHandover: async ({ fromVersionId }) => {
          console.log(`handover armed from version ${fromVersionId}`);
        },
      });
      console.log(`result ${result.status} from ${result.fromVersionId}`);
      expect(result.status).toBe('uploaded');
    } finally {
      console.log(`provider calls: ${calls.length}`);
      for (const line of calls) console.log(`  ${line}`);
    }
    expect(commands.some((command) => command.command === 'fail')).toBe(false);
  }, 180_000);
});

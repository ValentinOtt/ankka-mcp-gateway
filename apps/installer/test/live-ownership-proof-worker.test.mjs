import { readFile } from 'node:fs/promises';
import { spawnSync } from 'node:child_process';

import { describe, expect, it } from 'vitest';

const root = new URL('../../..', import.meta.url);
const relay = new URL('../scripts/live-ownership-proof-relay-worker.mjs', import.meta.url);
const gateway = new URL('../scripts/live-ownership-proof-gateway-worker.mjs', import.meta.url);

describe('disposable live ownership-proof Workers', () => {
  it('bundle the feature-disabled production proof boundary for Cloudflare', () => {
    for (const entry of [relay, gateway]) {
      const built = spawnSync('node_modules/.bin/esbuild', [
        entry.pathname,
        '--bundle',
        '--format=esm',
        '--platform=browser',
        '--external:cloudflare:workers',
        '--log-level=warning',
        '--outfile=/dev/null',
      ], { cwd: root, encoding: 'utf8' });
      expect(built.status, built.stderr).toBe(0);
    }
  });

  it('keeps relay-only authority and customer-only private-key state separated', async () => {
    const relaySource = await readFile(relay, 'utf8');
    const gatewaySource = await readFile(gateway, 'utf8');
    expect(relaySource).toContain('RELAY_TICKET_KEY');
    expect(gatewaySource).not.toContain('RELAY_TICKET_KEY');
    expect(gatewaySource).toContain("this.ctx.storage.get('ownership-sealed-private-key')");
    expect(gatewaySource).toContain('privateKey.extractable');
    expect(gatewaySource).toContain('OWNERSHIP_WRAP_KEY');
    expect(gatewaySource).toContain('RELAY_SERVICE.fetch');
    expect(gatewaySource).toContain('issueBody = init.body');
    expect(gatewaySource).not.toContain('request.clone().text()');
    expect(relaySource).not.toContain('OWNERSHIP_WRAP_KEY');
    expect(relaySource).toContain("url.pathname === '/canary/audit'");
    expect(gatewaySource).toContain("operation: 'upgrade'");
    expect(gatewaySource).not.toContain("operation: 'install'");
  });
});

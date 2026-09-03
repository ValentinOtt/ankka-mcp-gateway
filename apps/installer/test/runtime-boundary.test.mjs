import { readFile, readdir } from 'node:fs/promises';
import { describe, expect, it } from 'vitest';

const appUrl = new URL('../', import.meta.url);

async function source(path) {
  return readFile(new URL(path, appUrl), 'utf8');
}

describe('compile-time reviewed runtime files', () => {
  it('keeps the deployed Wrangler main on the disabled two-stage entrypoint with no production route', async () => {
    const [config, release, entrypoint] = await Promise.all([
      source('wrangler.toml'),
      source('src/release.ts'),
      source('src/reviewed-entrypoint.ts'),
    ]);

    expect(config).toMatch(/^main = "src\/reviewed-entrypoint\.ts"$/mu);
    expect(config).toMatch(/^name = "TWO_STAGE_DEPLOY_SESSION"$/mu);
    expect(config).toMatch(/^class_name = "TwoStageDeploySession"$/mu);
    expect(config).toMatch(/^new_sqlite_classes = \["TwoStageDeploySession"\]$/mu);
    expect(config).not.toContain('GatewayDeploySession');
    expect(entrypoint).toMatch(/from '\.\/two-stage-runtime'/u);
    expect(entrypoint).toMatch(/export \{ TwoStageDeploySession \} from '\.\/two-stage-deploy-session'/u);
    expect(entrypoint).not.toMatch(/reviewed-runtime|\.\/index'|gateway-deploy-session/u);
    expect(config).not.toMatch(/^\[\[routes\]\]$/mu);
    expect(config).not.toMatch(/^route(?:s)?\s*=/mu);
    expect(config).not.toContain('pattern = "deploy.ankka.ai"');
    expect(release).toMatch(
      /const PINNED_RELEASE_PUBLIC_KEYS:[^=]+= Object\.freeze\(\{\}\);/u,
    );
  });

  it('keeps the reviewed dry-run config unreachable and incapable of loading a release', async () => {
    const config = await source('wrangler.reviewed-disabled.toml');

    expect(config).toMatch(/^main = "src\/reviewed-entrypoint\.ts"$/mu);
    expect(config).toMatch(/^workers_dev = false$/mu);
    expect(config).toMatch(/^preview_urls = false$/mu);
    expect(config).not.toMatch(/^\[\[routes\]\]$/mu);
    expect(config).not.toMatch(/^route(?:s)?\s*=/mu);
    expect(config).not.toMatch(/^\[\[r2_buckets(?:\.|\]\])/mu);
    expect(config).not.toMatch(/^\[\[durable_objects(?:\.|\]\])/mu);
    expect(config).not.toMatch(/^\[\[migrations\]\]$/mu);
    expect(config).not.toContain('GATEWAY_RELEASE_BUCKET');
    expect(config).not.toContain('CLOUDFLARE_OAUTH_CLIENT_ID');
    expect(config).not.toContain('CLOUDFLARE_OAUTH_CLIENT_SECRET');
    expect(config).not.toContain('DEPLOY_SESSION_ENCRYPTION_KEY');
    expect(config).not.toContain('BOOTSTRAP_NONCE_DERIVATION_KEY');
  });

  it('never hands the bare global fetch out as a default transport anywhere in src', async () => {
    // workerd's global fetch throws "Illegal invocation" when invoked as a
    // method with a foreign receiver; every call site invokes the transport as
    // `input.transport(...)`. Found live on 2026-08-23; Node never reproduces it.
    const offenders = [];
    const visit = async (directory) => {
      for (const entry of await readdir(new URL(directory, appUrl), { withFileTypes: true })) {
        const relative = `${directory}${entry.name}`;
        if (entry.isDirectory()) { await visit(`${relative}/`); continue; }
        if (!entry.name.endsWith('.ts')) continue;
        const text = await source(relative);
        if (/\?\?\s*fetch\b|transport:\s*fetch\b|=\s*fetch\s*;|\(fetch\)\s*as/u.test(text)) offenders.push(relative);
      }
    };
    await visit('src/');
    expect(offenders).toEqual([]);
  });

  it('contains no environment or runtime override for the exact false/null activation', async () => {
    const activation = await source('src/reviewed-activation.ts');
    expect(activation).toMatch(
      /REVIEWED_GATEWAY_DEPLOY_ACTIVATION = Object\.freeze\(\{\s*enabled: false,\s*pin: null,\s*\} as const\)/u,
    );
    expect(activation).not.toMatch(/(?:process\.env|globalThis|\benv\s*\[|\benv\s*\.|ENABLE_REVIEWED|ACTIVATE_REVIEWED)/u);
  });
});

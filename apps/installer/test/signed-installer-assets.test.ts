import * as v from 'valibot';

import { REQUIRED_OAUTH_SCOPES } from '../src/constants';
import { DeployError } from '../src/errors';
import type { VerifiedReleaseBundle, VerifiedReleasePayloadBlob } from '../src/release';
import {
  APPROVED_CLOUDFLARE_RELEASE_CONTRACT,
  canonicalJson,
  parseReleaseManifest,
  type ReleaseComponent,
  type ReleaseFileRecord,
  type ReleaseManifest,
} from '../src/release-manifest';
import {
  APPROVED_INSTALLER_HTML_ROUTES,
  buildSignedInstallerAssetResponse,
  createSignedInstallerAssetIndex,
} from '../src/signed-installer-assets';
import { requiredFixture } from './fixtures';

const encoder = new TextEncoder();

interface SourceFile {
  readonly bytes: Uint8Array;
  readonly record: ReleaseFileRecord;
}

interface Fixture {
  readonly bundle: VerifiedReleaseBundle;
  readonly manifest: ReleaseManifest;
  readonly source: readonly SourceFile[];
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');
}

async function sha256(value: Uint8Array | string): Promise<string> {
  const bytes = v.is(v.string(), value) ? encoder.encode(value) : value;
  const owned = new Uint8Array(bytes.byteLength);
  owned.set(bytes);
  return bytesToHex(new Uint8Array(await crypto.subtle.digest('SHA-256', owned)));
}

async function file(path: string, contentType: string, text: string): Promise<SourceFile> {
  const bytes = encoder.encode(text);
  return Object.freeze({
    bytes,
    record: Object.freeze({
      path,
      contentType,
      byteSize: bytes.byteLength,
      sha256: await sha256(bytes),
    }),
  });
}

async function component(files: readonly ReleaseFileRecord[]): Promise<ReleaseComponent> {
  return Object.freeze({
    byteSize: files.reduce((total, entry) => total + entry.byteSize, 0),
    fileCount: files.length,
    files: Object.freeze([...files]),
    treeSha256: await sha256(canonicalJson(files)),
  });
}

async function fixture(installerOverrides?: readonly SourceFile[]): Promise<Fixture> {
  const admin = [await file(
    'payload/admin/index.html',
    'text/html; charset=utf-8',
    '<!doctype html><main>customer admin only</main>',
  )];
  const installer = installerOverrides ?? [
    await file(
      'payload/installer/assets/index-A1b2C3d4.js',
      'text/javascript; charset=utf-8',
      'globalThis.__signedInstaller = true;',
    ),
    await file(
      'payload/installer/assets/styles-Q9w8E7r6.css',
      'text/css; charset=utf-8',
      'body{background:#fff}',
    ),
    await file(
      'payload/installer/index.html',
      'text/html; charset=utf-8',
      '<!doctype html><script type="module" src="/assets/index-A1b2C3d4.js"></script>',
    ),
  ];
  const worker = [await file(
    'payload/worker/index.js',
    'application/javascript+module',
    "const CONTROL_PLANE_ORIGIN = 'https://deploy.ankka.ai';\nexport default { fetch() { return new Response(\"worker only\"); } };",
  )];
  const workerBootstrap = [await file(
    'payload/worker-bootstrap/index.js',
    'application/javascript+module',
    'export class AdminState {}; export default { fetch() { return new Response("bootstrap only"); } };',
  )];
  const workerCleanup = [await file(
    'payload/worker-cleanup/index.js',
    'application/javascript+module',
    'export class AdminState {}; export default { fetch() { return new Response("cleanup only"); } };',
  )];
  const workerRetirement = [await file(
    'payload/worker-retirement/index.js',
    'application/javascript+module',
    'export default { fetch() { return new Response(null, { status: 410 }); } };',
  )];
  const source = Object.freeze([
    ...admin,
    ...installer,
    ...workerBootstrap,
    ...workerCleanup,
    ...workerRetirement,
    ...worker,
  ]);
  const records = source.map((entry) => entry.record);
  const manifest = parseReleaseManifest({
    artifact: {
      byteSize: records.reduce((total, entry) => total + entry.byteSize, 0),
      fileCount: records.length,
      treeSha256: await sha256(canonicalJson(records)),
    },
    cloudflare: APPROVED_CLOUDFLARE_RELEASE_CONTRACT,
    controlPlaneOrigin: 'https://deploy.ankka.ai',
    components: {
      admin: await component(admin.map((entry) => entry.record)),
      installer: await component(installer.map((entry) => entry.record)),
      worker: await component(worker.map((entry) => entry.record)),
      workerBootstrap: await component(workerBootstrap.map((entry) => entry.record)),
      workerCleanup: await component(workerCleanup.map((entry) => entry.record)),
      workerRetirement: await component(workerRetirement.map((entry) => entry.record)),
    },
    oauthScopeIds: REQUIRED_OAUTH_SCOPES,
    release: 'gateway-v1.2.3',
    schemaVersion: 1,
    sourceCommit: '0123456789abcdef0123456789abcdef01234567',
  });
  const payload = Object.freeze(source.map((entry): VerifiedReleasePayloadBlob => {
    const owned = new Uint8Array(entry.bytes.byteLength);
    owned.set(entry.bytes);
    return Object.freeze({
      ...entry.record,
      bytes: new Blob([owned], { type: entry.record.contentType }),
    });
  }));
  return {
    source,
    manifest,
    bundle: Object.freeze({
      verification: 'ed25519', channel: 'stable', keyId: 'release-key-1', manifest, payload,
      envelope: Object.freeze({
        schemaVersion: 2, channel: 'stable', keyId: 'release-key-1',
        manifest: canonicalJson(manifest), signature: 'A'.repeat(86),
        signatureContext: 'ankka-mcp-gateway-release-envelope-v2',
      }),
      publicKey: 'A'.repeat(43),
    }),
  };
}

function replacePayload<Payload>(bundle: VerifiedReleaseBundle, payload: Payload) {
  return { ...bundle, payload };
}

async function expectInvalid<Input>(bundle: Input): Promise<void> {
  await expect(createSignedInstallerAssetIndex(bundle)).rejects.toMatchObject({
    code: 'release_invalid',
    status: 503,
  });
}

describe('signed installer SPA asset boundary', () => {
  it('builds a frozen, installer-only public index without release-provider internals', async () => {
    const input = await fixture();
    const index = await createSignedInstallerAssetIndex(input.bundle);

    expect(index).toEqual({
      schemaVersion: 1,
      release: input.manifest.release,
      artifactSha256: input.manifest.artifact.treeSha256,
      htmlRoutes: APPROVED_INSTALLER_HTML_ROUTES,
      assets: [
        expect.objectContaining({ path: '/assets/index-A1b2C3d4.js' }),
        expect.objectContaining({ path: '/assets/styles-Q9w8E7r6.css' }),
      ],
    });
    expect(Object.isFrozen(index)).toBe(true);
    expect(Object.isFrozen(index.assets)).toBe(true);
    expect(Object.isFrozen(index.assets[0])).toBe(true);
    const serialized = JSON.stringify(index);
    expect(serialized).not.toContain('release-key-1');
    expect(serialized).not.toContain('payload/admin');
    expect(serialized).not.toContain('payload/worker');
    expect(serialized).not.toContain('customer admin only');
    expect(serialized).not.toContain('worker only');
    expect(serialized).not.toContain('manifest');
    expect(serialized).not.toContain('provider');
  });

  it.each(APPROVED_INSTALLER_HTML_ROUTES)('serves no-store HTML only for approved route %s', async (route) => {
    const input = await fixture();
    const index = await createSignedInstallerAssetIndex(input.bundle);
    const response = buildSignedInstallerAssetResponse(index, new Request(`https://deploy.ankka.ai${route}`));

    expect(response.status).toBe(200);
    expect(response.headers.get('content-type')).toBe('text/html; charset=utf-8');
    expect(response.headers.get('cache-control')).toBe('no-store');
    expect(response.headers.get('content-security-policy')).toContain("default-src 'none'");
    expect(response.headers.get('content-security-policy')).toContain("connect-src 'self'");
    expect(response.headers.get('content-security-policy')).toContain("frame-ancestors 'none'");
    expect(response.headers.get('permissions-policy')).toContain('tools=(self)');
    expect(response.headers.get('referrer-policy')).toBe('no-referrer');
    expect(response.headers.get('x-content-type-options')).toBe('nosniff');
    expect(response.headers.get('x-frame-options')).toBe('DENY');
    expect(await response.text()).toContain('/assets/index-A1b2C3d4.js');
  });

  it('serves exact hashed assets immutably with pinned MIME, size, digest, and HEAD behavior', async () => {
    const input = await fixture();
    const index = await createSignedInstallerAssetIndex(input.bundle);
    const scriptMetadata = index.assets.find((entry) => entry.path.endsWith('.js'));
    if (!scriptMetadata) throw new TypeError('signed script fixture');
    const requestUrl = `https://deploy.ankka.ai${scriptMetadata.path}`;

    const response = buildSignedInstallerAssetResponse(index, new Request(requestUrl));
    expect(response.status).toBe(200);
    expect(response.headers.get('cache-control')).toBe('public, max-age=31536000, immutable');
    expect(response.headers.get('content-type')).toBe('text/javascript; charset=utf-8');
    expect(response.headers.get('content-length')).toBe(String(scriptMetadata.byteSize));
    expect(response.headers.get('etag')).toBe(`"sha256-${scriptMetadata.sha256}"`);
    expect(response.headers.get('cross-origin-resource-policy')).toBe('same-origin');
    expect(await response.text()).toBe('globalThis.__signedInstaller = true;');

    const head = buildSignedInstallerAssetResponse(index, new Request(requestUrl, { method: 'HEAD' }));
    expect(head.status).toBe(200);
    expect(head.headers.get('content-length')).toBe(String(scriptMetadata.byteSize));
    expect(await head.text()).toBe('');
  });

  it.each([
    '/index.html',
    '/gateway/',
    '/unknown',
    '/api/session',
    '/assets/index-A1b2C3d4.js?release=other',
    '/?utm_source=other',
    '/assets%2Findex-A1b2C3d4.js',
  ])('does not alias, redirect, query-vary, or generically fall back for %s', async (path) => {
    const input = await fixture();
    const index = await createSignedInstallerAssetIndex(input.bundle);
    const response = buildSignedInstallerAssetResponse(index, new Request(`https://deploy.ankka.ai${path}`));
    expect(response.status).toBe(404);
    expect(response.headers.get('location')).toBeNull();
    expect(response.headers.get('cache-control')).toBe('no-store');
    expect(await response.text()).toBe('');
  });

  it('rejects mutation methods without selecting or returning an asset body', async () => {
    const input = await fixture();
    const index = await createSignedInstallerAssetIndex(input.bundle);
    const response = buildSignedInstallerAssetResponse(index, new Request('https://deploy.ankka.ai/', {
      method: 'POST',
    }));
    expect(response.status).toBe(405);
    expect(response.headers.get('allow')).toBe('GET, HEAD');
    expect(response.headers.get('cache-control')).toBe('no-store');
    expect(await response.text()).toBe('');
  });

  it('revalidates exact installer Blob bytes, size, type, and payload relation', async () => {
    const input = await fixture();
    const payload = input.bundle.payload;
    const installerScriptIndex = payload.findIndex((entry) => entry.path.endsWith('.js') && entry.path.includes('/installer/'));
    if (installerScriptIndex < 0) throw new TypeError('installer script fixture');
    const script = requiredFixture(payload.at(installerScriptIndex), 'installer script');
    const tampered = new Uint8Array(await script.bytes.arrayBuffer());
    const firstByte = requiredFixture(tampered.at(0), 'installer script byte');
    tampered[0] = firstByte ^ 0xff;

    await expectInvalid(replacePayload(input.bundle, [
      ...payload.slice(0, installerScriptIndex),
      { ...script, bytes: new Blob([tampered], { type: script.contentType }) },
      ...payload.slice(installerScriptIndex + 1),
    ]));
    await expectInvalid(replacePayload(input.bundle, [
      ...payload.slice(0, installerScriptIndex),
      { ...script, bytes: new Blob([new Uint8Array(script.byteSize + 1)], { type: script.contentType }) },
      ...payload.slice(installerScriptIndex + 1),
    ]));
    await expectInvalid(replacePayload(input.bundle, [
      ...payload.slice(0, installerScriptIndex),
      { ...script, bytes: new Blob([await script.bytes.arrayBuffer()], { type: 'text/plain' }) },
      ...payload.slice(installerScriptIndex + 1),
    ]));
    const firstPayload = requiredFixture(payload.at(0), 'first payload');
    await expectInvalid(replacePayload(input.bundle, [firstPayload, firstPayload, ...payload.slice(2)]));
    await expectInvalid(replacePayload(input.bundle, payload.slice(1)));
  });

  it('never reads admin or Worker payload bytes into the installer index', async () => {
    const input = await fixture();
    let foreignReads = 0;
    class ForeignBlob extends Blob {
      override async arrayBuffer(): Promise<ArrayBuffer> {
        foreignReads += 1;
        throw new Error('foreign component must not be read');
      }
    }
    const payload = input.bundle.payload.map((entry) => entry.path.includes('/installer/')
      ? entry
      : {
          ...entry,
          bytes: new ForeignBlob([entry.bytes], { type: entry.contentType }),
        });
    const index = await createSignedInstallerAssetIndex(replacePayload(input.bundle, payload));
    expect(index.assets).toHaveLength(2);
    expect(foreignReads).toBe(0);
  });

  it.each([
    ['payload/installer/assets/app.js', 'text/javascript; charset=utf-8'],
    ['payload/installer/assets/app.map-A1b2C3d4.js', 'text/javascript; charset=utf-8'],
    ['payload/installer/assets/release-envelope-A1b2C3d4.json', 'application/json; charset=utf-8'],
    ['payload/installer/assets/client-secret-A1b2C3d4.js', 'text/javascript; charset=utf-8'],
    ['payload/installer/assets/provider-data-A1b2C3d4.json', 'application/json; charset=utf-8'],
  ])('rejects non-immutable or release-internal installer asset %s', async (path, contentType) => {
    const installer = [
      await file(path, contentType, 'unservable'),
      await file('payload/installer/index.html', 'text/html; charset=utf-8', '<!doctype html>'),
    ];
    const input = await fixture(installer);
    await expectInvalid(input.bundle);
  });

  it('rejects inline or external source-map directives inside otherwise approved hashed assets', async () => {
    const installer = [
      await file(
        'payload/installer/assets/app-A1b2C3d4.js',
        'text/javascript; charset=utf-8',
        'globalThis.app=true;\n//# sourceMappingURL=data:application/json;base64,e30=',
      ),
      await file('payload/installer/index.html', 'text/html; charset=utf-8', '<!doctype html>'),
    ];
    const input = await fixture(installer);
    await expectInvalid(input.bundle);
  });

  it('rejects additional HTML files instead of creating hidden session-page aliases', async () => {
    const installer = [
      await file('payload/installer/index.html', 'text/html; charset=utf-8', '<!doctype html>'),
      await file('payload/installer/session.html', 'text/html; charset=utf-8', '<main>session</main>'),
    ];
    const input = await fixture(installer);
    await expectInvalid(input.bundle);
  });

  it('rejects a forged public index instead of accepting caller-provided bytes or provider fields', () => {
    const forged = Object.freeze({
      schemaVersion: 1,
      release: 'gateway-v1.2.3',
      artifactSha256: 'a'.repeat(64),
      htmlRoutes: APPROVED_INSTALLER_HTML_ROUTES,
      assets: Object.freeze([]),
    });
    expect(() => buildSignedInstallerAssetResponse(
      forged,
      new Request('https://deploy.ankka.ai/'),
    )).toThrow(expect.objectContaining<Partial<DeployError>>({ code: 'release_invalid', status: 503 }));
  });

  it('rejects unknown bundle fields, provenance changes, and aggregate tree mismatches', async () => {
    const input = await fixture();
    await expectInvalid({ ...input.bundle, provider: 'r2' });
    await expectInvalid({ ...input.bundle, verification: 'checksum' });
    await expectInvalid({ ...input.bundle, keyId: '../key' });
    await expectInvalid({ ...input.bundle, publicKey: 'not-a-key' });
    await expectInvalid({
      ...input.bundle,
      envelope: { ...input.bundle.envelope, channel: 'canary' },
    });
    await expectInvalid({
      ...input.bundle,
      envelope: {
        keyId: input.bundle.envelope.keyId,
        manifest: input.bundle.envelope.manifest,
        schemaVersion: 1,
        signature: input.bundle.envelope.signature,
      },
    });

    const aggregateMismatch = {
      ...input.manifest,
      artifact: { ...input.manifest.artifact, treeSha256: 'f'.repeat(64) },
    };
    await expectInvalid({ ...input.bundle, manifest: aggregateMismatch });
  });
});

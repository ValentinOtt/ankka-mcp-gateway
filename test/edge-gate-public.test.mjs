import assert from 'node:assert/strict';
import {
  createHash,
  generateKeyPairSync,
  sign,
} from 'node:crypto';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

import {
  ACCESS_HOST,
  classifyAccessApplicationForInstaller,
} from '../apps/installer/scripts/edge-gate/access-contract.mjs';
import {
  PublicAccessVerificationError,
  verifyPublicReleaseDescriptor,
  verifyPublicSelfService,
} from '../apps/installer/scripts/edge-gate/verify-public.mjs';
import {
  RELEASE_ENVELOPE_SCHEMA_VERSION,
  RELEASE_SIGNATURE_CONTEXT,
  canonicalJson,
  releaseSignatureCanonicalJson,
} from '../apps/installer/scripts/sign-gateway-release.mjs';

const EXPECTED = Object.freeze({
  artifactSha256: 'a'.repeat(64),
  channel: 'canary',
  keyId: 'launch-key-v1',
  release: 'gateway-v1.2.3',
  sourceCommit: 'b'.repeat(40),
});
const ROOT_HTML = '<!doctype html><html><body>reviewed installer</body></html>';
const ROOT_SHA256 = createHash('sha256').update(ROOT_HTML, 'utf8').digest('hex');

function signedDescriptor() {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const rawPublicKey = publicKey.export({ format: 'der', type: 'spki' }).subarray(-32).toString('base64url');
  const manifest = canonicalJson({
    artifact: {
      byteSize: 1,
      fileCount: 1,
      treeSha256: EXPECTED.artifactSha256,
    },
    cloudflare: {},
    components: {
      admin: {},
      installer: {
        byteSize: Buffer.byteLength(ROOT_HTML, 'utf8'),
        fileCount: 1,
        files: [{
          byteSize: Buffer.byteLength(ROOT_HTML, 'utf8'),
          contentType: 'text/html; charset=utf-8',
          path: 'payload/installer/index.html',
          sha256: ROOT_SHA256,
        }],
        treeSha256: 'c'.repeat(64),
      },
      worker: {},
      workerCleanup: {},
      workerRetirement: {},
    },
    oauthScopeIds: [],
    release: EXPECTED.release,
    schemaVersion: 1,
    sourceCommit: EXPECTED.sourceCommit,
  });
  const signature = sign(
    null,
    Buffer.from(releaseSignatureCanonicalJson(EXPECTED.channel, EXPECTED.keyId, manifest), 'utf8'),
    privateKey,
  ).toString('base64url');
  return {
    descriptor: {
      schemaVersion: 1,
      channel: EXPECTED.channel,
      release: {
        id: EXPECTED.release,
        artifactSha256: `sha256:${EXPECTED.artifactSha256}`,
        sourceCommit: EXPECTED.sourceCommit,
      },
      classification: {
        kind: 'normal',
        updaterProtocol: 2,
        changes: ['customer_worker_code', 'management_assets'],
        excludes: [
          'access_policies',
          'credentials',
          'dns',
          'durable_object_migrations',
          'mcp_portal_configuration',
          'sources',
          'tool_allowlists',
        ],
      },
      notes: ['Synthetic signed release for the verifier contract.'],
      verification: {
        algorithm: 'ed25519',
        channel: EXPECTED.channel,
        keyId: EXPECTED.keyId,
        manifest,
        schemaVersion: RELEASE_ENVELOPE_SCHEMA_VERSION,
        signature,
        signatureContext: RELEASE_SIGNATURE_CONTEXT,
      },
    },
    expected: Object.freeze({ ...EXPECTED, publicKey: rawPublicKey }),
  };
}

function json(value, status = 200, headers = {}) {
  return new Response(JSON.stringify(value), {
    status,
    headers: { 'content-type': 'application/json; charset=utf-8', ...headers },
  });
}

function fullVerifierTransport({
  accessApplications = [],
  accessPages,
  emptyAccessUsesLivePagination = false,
  responseHeaders = {},
  rootBody = ROOT_HTML,
} = {}) {
  const release = signedDescriptor();
  const calls = [];
  const pages = accessPages ?? [accessApplications];
  const fetchImpl = async (input, init = {}) => {
    const url = new URL(input);
    const method = init.method ?? 'GET';
    const headers = new Headers(init.headers);
    calls.push({ url, method, headers });
    if (url.origin === 'https://api.cloudflare.com') {
      assert.equal(method, 'GET');
      assert.match(headers.get('authorization') ?? '', /^Bearer /u);
      if (url.pathname === '/client/v4/zones') {
        return json({
          success: true,
          result: [{ name: 'ankka.ai', account: { id: 'synthetic-account' } }],
        });
      }
      if (url.pathname === '/client/v4/accounts/synthetic-account/access/apps') {
        const page = Number(url.searchParams.get('page'));
        const result = pages[page - 1] ?? [];
        const liveEmpty = emptyAccessUsesLivePagination && page === 1 && result.length === 0;
        return json({
          success: true,
          result,
          result_info: liveEmpty
            ? { count: 0, page: 1, per_page: 100, total_count: 0, total_pages: 0 }
            : { page, total_pages: pages.length },
        });
      }
      throw new Error(`unexpected Cloudflare URL ${url.pathname}`);
    }

    assert.equal(url.hostname, ACCESS_HOST);
    assert.equal(headers.has('authorization'), false);
    assert.equal(headers.has('cookie'), false);
    const common = responseHeaders;
    if (url.pathname === '/health') {
      return json({ ok: true, mutationsEnabled: true }, 200, common);
    }
    if (url.pathname === '/') {
      return new Response(rootBody, {
        status: 200,
        headers: { 'content-type': 'text/html; charset=utf-8', ...common },
      });
    }
    if (url.pathname === '/api/session') {
      assert.equal(method, 'HEAD');
      return new Response(null, {
        status: 404,
        headers: { 'content-type': 'application/json; charset=utf-8', ...common },
      });
    }
    if (url.pathname === '/oauth/callback') {
      return json({ code: 'session_invalid' }, 400, common);
    }
    if (url.pathname === '/api/releases/canary') return json(release.descriptor, 200, common);
    if (url.pathname === '/api/releases/stable') {
      return json({ code: 'release_unavailable' }, 404, common);
    }
    throw new Error(`unexpected installer URL ${url.pathname}`);
  };
  return { calls, expected: release.expected, fetchImpl };
}

test('public mode rejects every Access selector that could cover the installer host', () => {
  for (const application of [
    { type: 'self_hosted', domain: ACCESS_HOST },
    { type: 'self_hosted', domain: `${ACCESS_HOST}/oauth/callback` },
    { type: 'self_hosted', domain: '*.ankka.ai/private' },
    { type: 'self_hosted', destinations: [{ type: 'public', uri: `https://${ACCESS_HOST}/admin` }] },
  ]) {
    assert.equal(classifyAccessApplicationForInstaller(application), 'covering');
  }
  assert.equal(
    classifyAccessApplicationForInstaller({ type: 'self_hosted', domain: 'other.example.com' }),
    'unrelated',
  );
  assert.equal(
    classifyAccessApplicationForInstaller({ type: 'self_hosted', domain: `http://${ACCESS_HOST}` }),
    'unverifiable',
  );
  assert.equal(
    classifyAccessApplicationForInstaller({ type: 'bookmark', domain: ACCESS_HOST }),
    'covering',
  );
});

test('public release discovery is bound to the exact signed reviewed pin', () => {
  const { descriptor, expected } = signedDescriptor();
  assert.deepEqual(verifyPublicReleaseDescriptor(descriptor, expected), {
    channel: 'canary',
    installerIndex: {
      byteSize: Buffer.byteLength(ROOT_HTML, 'utf8'),
      sha256: ROOT_SHA256,
    },
    release: EXPECTED.release,
    schemaVersion: 1,
    status: 'verified',
  });

  const replayed = structuredClone(descriptor);
  replayed.channel = 'stable';
  replayed.verification.channel = 'stable';
  assert.throws(
    () => verifyPublicReleaseDescriptor(replayed, { ...expected, channel: 'stable' }),
    (error) => error instanceof PublicAccessVerificationError && error.code === 'public_release_invalid',
  );

  const tampered = structuredClone(descriptor);
  tampered.release.artifactSha256 = `sha256:${'c'.repeat(64)}`;
  assert.throws(
    () => verifyPublicReleaseDescriptor(tampered, expected),
    (error) => error instanceof PublicAccessVerificationError && error.code === 'public_release_invalid',
  );
});

test('public verifier proves no Access coverage and uses only anonymous non-minting behavior probes', async () => {
  const transport = fullVerifierTransport({
    accessPages: [
      [{ id: 'unrelated-one', type: 'self_hosted', domain: 'one.example.com' }],
      [{ id: 'unrelated-two', type: 'bookmark', domain: 'two.example.com' }],
    ],
  });
  const result = await verifyPublicSelfService({
    expected: transport.expected,
    fetchImpl: transport.fetchImpl,
    readToken: async () => 'T'.repeat(32),
  });
  assert.deepEqual(result, {
    accessApplicationsCoveringInstaller: 0,
    activeChannel: 'canary',
    anonymousBehaviorChecks: 6,
    schemaVersion: 1,
    status: 'verified',
  });
  const sessionCalls = transport.calls.filter(({ url }) => url.pathname === '/api/session');
  assert.equal(sessionCalls.length, 1);
  assert.equal(sessionCalls[0].method, 'HEAD');
  assert.equal(
    transport.calls.filter(({ url }) => url.hostname === ACCESS_HOST)
      .every(({ headers }) => !headers.has('authorization') && !headers.has('cookie')),
    true,
  );
});

test('public verifier accepts Cloudflare live zero-page pagination only for a complete empty inventory', async () => {
  const transport = fullVerifierTransport({ emptyAccessUsesLivePagination: true });
  const result = await verifyPublicSelfService({
    expected: transport.expected,
    fetchImpl: transport.fetchImpl,
    readToken: async () => 'T'.repeat(32),
  });
  assert.equal(result.status, 'verified');
  assert.equal(
    transport.calls.filter(({ url }) => url.pathname.endsWith('/access/apps')).length,
    1,
  );
});

test('public verifier rejects an ambiguous zero-page Access inventory', async () => {
  const transport = fullVerifierTransport({
    accessPages: [[{ id: 'residual', type: 'self_hosted', domain: 'other.example.com' }]],
  });
  const originalFetch = transport.fetchImpl;
  transport.fetchImpl = async (input, init) => {
    const url = new URL(input);
    if (url.pathname.endsWith('/access/apps')) {
      return json({
        success: true,
        result: [{ id: 'residual', type: 'self_hosted', domain: 'other.example.com' }],
        result_info: { count: 1, page: 1, per_page: 100, total_count: 1, total_pages: 0 },
      });
    }
    return originalFetch(input, init);
  };
  await assert.rejects(
    verifyPublicSelfService({
      expected: transport.expected,
      fetchImpl: transport.fetchImpl,
      readToken: async () => 'T'.repeat(32),
    }),
    (error) => error instanceof PublicAccessVerificationError &&
      error.code === 'access_configuration_unavailable',
  );
});

test('public verifier stops on residual Access coverage before probing the installer', async () => {
  const transport = fullVerifierTransport({
    accessApplications: [{ id: 'private-installer', type: 'self_hosted', domain: ACCESS_HOST }],
  });
  await assert.rejects(
    verifyPublicSelfService({
      expected: transport.expected,
      fetchImpl: transport.fetchImpl,
      readToken: async () => 'T'.repeat(32),
    }),
    (error) => error instanceof PublicAccessVerificationError && error.code === 'access_application_present',
  );
  assert.equal(transport.calls.some(({ url }) => url.hostname === ACCESS_HOST), false);
});

test('public verifier permits Cloudflare platform reporting headers on the hosted installer', async () => {
  const transport = fullVerifierTransport({
    responseHeaders: {
      nel: '{"report_to":"platform"}',
      'report-to': '{"group":"platform","endpoints":[{"url":"https://reports.example.invalid"}]}',
    },
  });
  const result = await verifyPublicSelfService({
    expected: transport.expected,
    fetchImpl: transport.fetchImpl,
    readToken: async () => 'T'.repeat(32),
  });
  assert.equal(result.status, 'verified');
  assert.equal(result.anonymousBehaviorChecks, 6);
});

test('public verifier binds the served installer root to the signed release manifest', async () => {
  const transport = fullVerifierTransport({
    rootBody: '<!doctype html><html><body>different installer</body></html>',
  });
  await assert.rejects(
    verifyPublicSelfService({
      expected: transport.expected,
      fetchImpl: transport.fetchImpl,
      readToken: async () => 'T'.repeat(32),
    }),
    (error) => (
      error instanceof PublicAccessVerificationError &&
      error.code === 'active_installer_not_verified'
    ),
  );
});

test('checked-in public verifier has no state-changing HTTP method', async () => {
  const source = await readFile(
    new URL('../apps/installer/scripts/edge-gate/verify-public.mjs', import.meta.url),
    'utf8',
  );
  assert.doesNotMatch(source, /method:\s*['"](?:DELETE|PATCH|POST|PUT)['"]/u);
  assert.doesNotMatch(source, /CLOUDFLARE_API_TOKEN/u);
  assert.match(source, /--api-token-stdin/u);
});

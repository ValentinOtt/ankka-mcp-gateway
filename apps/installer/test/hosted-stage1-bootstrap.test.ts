import * as v from 'valibot';

import type { BoundaryValue } from '../src/boundary';
import type { CustomerInstallStatus } from '../src/customer-install-status';
import {
  verifyCloudflareGatewayOwnershipCertificate,
} from '../src/cloudflare-gateway-ownership-proof';
import { REQUIRED_OAUTH_SCOPES } from '../src/constants';
import { base64UrlDecode, base64UrlEncode } from '../src/crypto';
import {
  completeHostedStage1Handoff,
  createHostedStage1Secrets,
  provisionHostedStage1,
  type HostedStage1Provider,
} from '../src/hosted-stage1-bootstrap';
import type { VerifiedReleaseBundle, VerifiedReleasePayloadBlob } from '../src/release';
import {
  APPROVED_CLOUDFLARE_RELEASE_CONTRACT,
  canonicalJson,
  parseReleaseManifest,
  type ReleaseComponent,
  type ReleaseFileRecord,
} from '../src/release-manifest';
import { buildStaticDeployPlan, parseDeploySelection } from '../src/schema';

const NOW = 1_800_000_000_000;
const ACCOUNT_ID = 'a'.repeat(32);
const WORKER_ID = 'b'.repeat(32);
const NAMESPACE_ID = 'c'.repeat(32);
const VERSION_ID = '11111111-1111-4111-8111-111111111111';
const DEPLOYMENT_ID = '22222222-2222-4222-8222-222222222222';
const ACCESS_TOKEN = `token_${'d'.repeat(32)}`;
const HOSTED_CLIENT_ID = 'e'.repeat(32);
const HOSTED_CLIENT_SECRET = `secret-${'f'.repeat(32)}`;
const CUSTOMER_CLIENT_ID = 'g'.repeat(32);
const ISSUER_KEY_ID = 'ownership-key-v1';
const CUSTOMER_OWNERSHIP_PUBLIC_KEY = base64UrlEncode(new Uint8Array(32).fill(10));
const encoder = new TextEncoder();

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');
}

async function sha256(value: Uint8Array | string): Promise<string> {
  const bytes = v.is(v.string(), value) ? encoder.encode(value) : value;
  const owned = new Uint8Array(new ArrayBuffer(bytes.byteLength));
  owned.set(bytes);
  return bytesToHex(new Uint8Array(await crypto.subtle.digest('SHA-256', owned)));
}

async function file(
  path: string,
  contentType: string,
  body: string,
): Promise<{ readonly bytes: Uint8Array; readonly record: ReleaseFileRecord }> {
  const bytes = encoder.encode(body);
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

async function component(records: readonly ReleaseFileRecord[]): Promise<ReleaseComponent> {
  return Object.freeze({
    byteSize: records.reduce((total, record) => total + record.byteSize, 0),
    fileCount: records.length,
    files: Object.freeze([...records]),
    treeSha256: await sha256(canonicalJson(records)),
  });
}

async function releaseBundle(): Promise<VerifiedReleaseBundle> {
  const files = [
    await file('payload/admin/index.html', 'text/html; charset=utf-8', '<!doctype html><main>admin</main>'),
    await file('payload/installer/index.html', 'text/html; charset=utf-8', '<!doctype html><main>install</main>'),
    await file('payload/worker-bootstrap/index.js', 'application/javascript+module',
      'export class AdminState{};export default{fetch(){return new Response("bootstrap")}};'),
    await file('payload/worker-cleanup/index.js', 'application/javascript+module',
      'export class AdminState{};export default{fetch(){return new Response("cleanup")}};'),
    await file('payload/worker-retirement/index.js', 'application/javascript+module',
      'export default{fetch(){return new Response(null,{status:410})}};'),
    await file('payload/worker/index.js', 'application/javascript+module',
      '// ankka-control-plane-origin:https://deploy.ankka.ai\nexport default{fetch(){return new Response("ready")}};'),
  ] as const;
  const records = files.map((entry) => entry.record);
  const manifest = parseReleaseManifest({
    artifact: {
      byteSize: records.reduce((total, record) => total + record.byteSize, 0),
      fileCount: records.length,
      treeSha256: await sha256(canonicalJson(records)),
    },
    cloudflare: APPROVED_CLOUDFLARE_RELEASE_CONTRACT,
    controlPlaneOrigin: 'https://deploy.ankka.ai',
    components: {
      admin: await component(records.slice(0, 1)),
      installer: await component(records.slice(1, 2)),
      workerBootstrap: await component(records.slice(2, 3)),
      workerCleanup: await component(records.slice(3, 4)),
      workerRetirement: await component(records.slice(4, 5)),
      worker: await component(records.slice(5, 6)),
    },
    oauthScopeIds: REQUIRED_OAUTH_SCOPES,
    release: 'gateway-v1.2.3',
    schemaVersion: 1,
    sourceCommit: '0123456789abcdef0123456789abcdef01234567',
  });
  const payload = Object.freeze(files.map((entry): VerifiedReleasePayloadBlob => Object.freeze({
    ...entry.record,
    bytes: new Blob([new Uint8Array(entry.bytes)], { type: entry.record.contentType }),
  })));
  return Object.freeze({
    verification: 'ed25519',
    channel: 'stable',
    keyId: 'release-key-v1',
    envelope: Object.freeze({
      schemaVersion: 2,
      channel: 'stable',
      keyId: 'release-key-v1',
      manifest: canonicalJson(manifest),
      signature: 'A'.repeat(86),
      signatureContext: 'ankka-mcp-gateway-release-envelope-v2',
    }),
    manifest,
    payload,
    publicKey: 'B'.repeat(43),
  });
}

function oauthTransport(events: string[]) {
  return async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const request = new Request(input, init);
    const url = new URL(request.url);
    if (url.pathname === '/oauth2/token') {
      events.push('token-exchange');
      return Response.json({
        access_token: ACCESS_TOKEN,
        token_type: 'bearer',
        scope: 'workers-scripts.write',
      });
    }
    if (url.hostname === 'api.cloudflare.com' && url.pathname === '/client/v4/accounts') {
      events.push('account-read');
      return Response.json({
        success: true,
        errors: [],
        messages: [],
        result: [{ id: ACCOUNT_ID }],
      });
    }
    if (url.pathname === '/oauth2/revoke') {
      events.push('revoke');
      return new Response(null, { status: 200 });
    }
    throw new Error(`unexpected transport ${request.method}`);
  };
}

function provider(events: string[]): HostedStage1Provider {
  const getAccountWorkersSubdomain: HostedStage1Provider['getAccountWorkersSubdomain'] =
    async ({ accessToken, accountId }) => {
      expect(accessToken).toBe(ACCESS_TOKEN);
      expect(accountId).toBe(ACCOUNT_ID);
      events.push('subdomain-read');
      return Object.freeze({ accountId, subdomain: 'tenant' });
    };
  const deployCustomerBootstrapWorker: HostedStage1Provider['deployCustomerBootstrapWorker'] =
    async (input) => {
      expect(input.accessToken).toBe(ACCESS_TOKEN);
      expect(input.accountId).toBe(ACCOUNT_ID);
      expect(input.plainTextBindings.ANKKA_INSTALLER_ORIGIN).toBe('https://deploy.ankka.ai');
      events.push('worker-deploy');
      return Object.freeze({
        workerId: WORKER_ID,
        workerName: input.workerName,
        namespaceId: NAMESPACE_ID,
        namespaceName: `${input.workerName}_AdminState`,
        deploymentId: DEPLOYMENT_ID,
        versionId: VERSION_ID,
        release: input.release.release,
        artifactSha256: input.release.artifactSha256,
        bootstrapComponentSha256: input.release.componentSha256,
        sourceSha256: input.release.worker.modules[0]?.sha256 ?? '',
        recovery: 'created' as const,
      });
    };
  const setWorkerBootstrapSubdomain: HostedStage1Provider['setWorkerBootstrapSubdomain'] =
    async ({ accessToken, enabled }) => {
      expect(accessToken).toBe(ACCESS_TOKEN);
      expect(enabled).toBe(true);
      events.push('subdomain-enable');
      return Object.freeze({ enabled: true, previewsEnabled: false as const });
    };
  const verifyWorkerBootstrapSubdomain: HostedStage1Provider['verifyWorkerBootstrapSubdomain'] =
    async ({ accessToken, expectedEnabled }) => {
      expect(accessToken).toBe(ACCESS_TOKEN);
      expect(expectedEnabled).toBe(true);
      events.push('subdomain-verify');
      return Object.freeze({ enabled: true, previewsEnabled: false as const });
    };
  return Object.freeze({
    getAccountWorkersSubdomain,
    deployCustomerBootstrapWorker,
    setWorkerBootstrapSubdomain,
    verifyWorkerBootstrapSubdomain,
  });
}

async function setup() {
  const bundle = await releaseBundle();
  const selection = parseDeploySelection({
    schemaVersion: 1,
    basics: {
      gatewayName: 'Example Gateway',
      zoneName: 'example.com',
      adminEmail: 'owner@example.com',
      additionalAdminEmails: [],
      managementHostname: 'manage.example.com',
      portalHostname: 'mcp.example.com',
    },
    firstSource: null,
  });
  const plan = await buildStaticDeployPlan(selection, bundle.manifest, NOW + 20 * 60_000);
  const secrets = await createHostedStage1Secrets({ now: NOW });
  // SAFETY: Ed25519 generateKey always yields a key pair; the union only exists for symmetric algorithms.
  const keys = await crypto.subtle.generateKey('Ed25519', true, ['sign', 'verify']) as CryptoKeyPair;
  const publicKey = base64UrlEncode(new Uint8Array(await crypto.subtle.exportKey('raw', keys.publicKey)));
  const events: string[] = [];
  const provision = await provisionHostedStage1({
    code: `code_${'h'.repeat(32)}`,
    verifier: 'i'.repeat(43),
    oauth: { clientId: HOSTED_CLIENT_ID, clientSecret: HOSTED_CLIENT_SECRET },
    transport: oauthTransport(events),
    bundle,
    plan,
    secrets,
    customerOauthClientId: CUSTOMER_CLIENT_ID,
    issuerKeyId: ISSUER_KEY_ID,
    issuerPublicKey: publicKey,
    issuerPrivateKey: keys.privateKey,
    now: () => NOW + 1,
    provider: provider(events),
  });
  return { bundle, plan, secrets, keys, publicKey, events, provision };
}

/**
 * A health body that arrives only when pulled and errors once the request
 * signal has aborted, like a real fetch body: the poll must consume it inside
 * its deadline.
 */
function streamedHealth(value: BoundaryValue, signal: AbortSignal | null | undefined): Response {
  const bytes = new TextEncoder().encode(JSON.stringify(value));
  let delivered = false;
  const body = new ReadableStream<Uint8Array>({
    pull(controller) {
      if (signal?.aborted) {
        controller.error(new DOMException('The operation was aborted', 'AbortError'));
        return;
      }
      if (delivered) {
        controller.close();
        return;
      }
      delivered = true;
      controller.enqueue(bytes);
    },
  }, { highWaterMark: 0 });
  return new Response(body, {
    status: 200,
    headers: {
      'content-type': 'application/json',
      'access-control-allow-origin': 'https://deploy.ankka.ai',
      vary: 'Origin',
    },
  });
}

describe('hosted Stage 1 coordinator', () => {
  it('revokes before token-free readiness and releases the capability only in the customer fragment', async () => {
    const fixture = await setup();
    expect(fixture.events).toEqual([
      'token-exchange',
      'account-read',
      'subdomain-read',
      'worker-deploy',
      'subdomain-enable',
      'subdomain-verify',
      'revoke',
    ]);
    const serializedProvision = JSON.stringify(fixture.provision);
    expect(serializedProvision).not.toContain(ACCESS_TOKEN);
    expect(serializedProvision).not.toContain(fixture.secrets.capability.secret);
    expect(serializedProvision).not.toContain(fixture.secrets.bootstrapNonce);
    expect(serializedProvision).not.toContain(fixture.secrets.ownershipWrapKey);

    const result = await completeHostedStage1Handoff({
      provision: fixture.provision,
      plan: fixture.plan,
      capabilitySecret: fixture.secrets.capability.secret,
      customerOauthClientId: CUSTOMER_CLIENT_ID,
      issuerKeyId: ISSUER_KEY_ID,
      issuerPublicKey: fixture.publicKey,
      issuerPrivateKey: fixture.keys.privateKey,
      transport: async (input, init) => {
        const request = new Request(input, init);
        expect(request.url).toBe(`${fixture.provision.bootstrapOrigin}__ankka/install/status`);
        expect(request.headers.get('authorization')).toBeNull();
        // workerd rejects redirect: 'error' when the request is built.
        expect(init?.redirect).toBe('manual');
        fixture.events.push('token-free-health');
        return streamedHealth({
          schemaVersion: 1,
          role: 'customer-gateway-bootstrap',
          status: 'INCOMPLETE',
          installId: fixture.plan.managementOwnershipMarker,
          release: fixture.plan.releaseId,
          ownershipPublicKey: CUSTOMER_OWNERSHIP_PUBLIC_KEY,
          failure: null,
        }, init?.signal);
      },
      now: () => NOW + 2,
    });
    expect(fixture.events.at(-2)).toBe('revoke');
    expect(fixture.events.at(-1)).toBe('token-free-health');
    const url = new URL(result.handoffUrl);
    expect(url.origin).toBe(fixture.provision.bootstrapOrigin.slice(0, -1));
    expect(url.pathname).toBe('/__ankka/install');
    expect(url.search).toBe('');
    const payload = v.parse(v.strictObject({
      bootstrapId: v.string(),
      ownershipCertificate: v.string(),
      secret: v.string(),
      serializedHandoff: v.string(),
      serializedPlan: v.string(),
    }), JSON.parse(new TextDecoder().decode(base64UrlDecode(url.hash.slice(1)))));
    expect(payload.bootstrapId).toBe(fixture.secrets.capability.bootstrapId);
    expect(payload.secret).toBe(fixture.secrets.capability.secret);
    expect(payload.serializedHandoff).toBe(fixture.provision.handoff);
    expect(payload.serializedPlan).toBe(canonicalJson(fixture.plan));
    const certificate = await verifyCloudflareGatewayOwnershipCertificate({
      certificate: payload.ownershipCertificate,
      pinnedIssuerPublicKey: fixture.publicKey,
      expectedKeyId: ISSUER_KEY_ID,
      expectedPublicClientId: CUSTOMER_CLIENT_ID,
    });
    expect(certificate.statement.accountId).toBe(ACCOUNT_ID);
    expect(certificate.statement.ownershipKey.publicKey).toBe(CUSTOMER_OWNERSHIP_PUBLIC_KEY);
  });

  it('accepts a shell that names an earlier failure and stays strict about unknown keys and status', async () => {
    type Answer = Partial<CustomerInstallStatus> & { readonly extra?: true };
    const answer = (extra: Answer) => async (_input: RequestInfo | URL, init?: RequestInit) => {
      const value = {
        schemaVersion: 1,
        role: 'customer-gateway-bootstrap',
        status: 'INCOMPLETE',
        installId: '',
        release: '',
        ownershipPublicKey: CUSTOMER_OWNERSHIP_PUBLIC_KEY,
        failure: null,
        ...extra,
      };
      // SAFETY: `value` is a literal of strings, numbers, null and one nested
      // literal; an `undefined` field stands for a shell that omits it and is
      // dropped by JSON.stringify inside streamedHealth, so what is sent is
      // always a JSON object.
      return streamedHealth(value as BoundaryValue, init?.signal);
    };
    const attempt = async (extra: Answer) => {
      const fixture = await setup();
      return completeHostedStage1Handoff({
        provision: fixture.provision,
        plan: fixture.plan,
        capabilitySecret: fixture.secrets.capability.secret,
        customerOauthClientId: CUSTOMER_CLIENT_ID,
        issuerKeyId: ISSUER_KEY_ID,
        issuerPublicKey: fixture.publicKey,
        issuerPrivateKey: fixture.keys.privateKey,
        transport: answer({
          installId: fixture.plan.managementOwnershipMarker,
          release: fixture.plan.releaseId,
          ...extra,
        }),
        now: () => NOW + 2,
      });
    };
    // The shell's status answer carries the last Stage 2 outcome; readiness
    // only checks identity, so a named failure does not block the handoff.
    const named = await attempt({
      failure: { code: 'provider_recovery_required', reason: 'payload_portal_create_auth_http_403_code_10000' },
    });
    expect(new URL(named.handoffUrl).pathname).toBe('/__ankka/install');
    // Shells from a release before the field existed answer without it.
    const legacy = await attempt({ failure: undefined });
    expect(new URL(legacy.handoffUrl).pathname).toBe('/__ankka/install');
    await expect(attempt({ extra: true }))
      .rejects.toMatchObject({ code: 'bootstrap_failed', status: 502, reason: 'readiness_schema_invalid' });
    await expect(attempt({ failure: { code: 'provider_recovery_required', reason: 'not a reason' } }))
      .rejects.toMatchObject({ code: 'bootstrap_failed', status: 502, reason: 'readiness_schema_invalid' });
    await expect(attempt({ status: 'READY' }))
      .rejects.toMatchObject({ code: 'bootstrap_failed', status: 502, reason: 'readiness_status_unexpected' });
  });

  it('keeps the capability private while the customer Worker is not ready', async () => {
    const fixture = await setup();
    await expect(completeHostedStage1Handoff({
      provision: fixture.provision,
      plan: fixture.plan,
      capabilitySecret: fixture.secrets.capability.secret,
      customerOauthClientId: CUSTOMER_CLIENT_ID,
      issuerKeyId: ISSUER_KEY_ID,
      issuerPublicKey: fixture.publicKey,
      issuerPrivateKey: fixture.keys.privateKey,
      transport: async () => new Response(null, { status: 404 }),
      now: () => NOW + 2,
    })).rejects.toMatchObject({ code: 'bootstrap_not_ready', status: 503, reason: 'readiness_http_404' });
  });

  it('refuses a shell that answers its status route with a page instead of JSON', async () => {
    const fixture = await setup();
    await expect(completeHostedStage1Handoff({
      provision: fixture.provision,
      plan: fixture.plan,
      capabilitySecret: fixture.secrets.capability.secret,
      customerOauthClientId: CUSTOMER_CLIENT_ID,
      issuerKeyId: ISSUER_KEY_ID,
      issuerPublicKey: fixture.publicKey,
      issuerPrivateKey: fixture.keys.privateKey,
      transport: async () => new Response('<!doctype html><title>Ankka MCP Gateway</title>', {
        status: 200, headers: { 'content-type': 'text/html' },
      }),
      now: () => NOW + 2,
    })).rejects.toMatchObject({ code: 'bootstrap_failed', status: 502, reason: 'readiness_not_json' });
  });

  it('names a fetch that settles without a response as a transport failure', async () => {
    const fixture = await setup();
    await expect(completeHostedStage1Handoff({
      provision: fixture.provision,
      plan: fixture.plan,
      capabilitySecret: fixture.secrets.capability.secret,
      customerOauthClientId: CUSTOMER_CLIENT_ID,
      issuerKeyId: ISSUER_KEY_ID,
      issuerPublicKey: fixture.publicKey,
      issuerPrivateKey: fixture.keys.privateKey,
      transport: async () => { throw new TypeError('Invalid redirect value'); },
      now: () => NOW + 2,
    })).rejects.toMatchObject({ code: 'bootstrap_not_ready', status: 503, reason: 'readiness_transport_failed' });
  });
});

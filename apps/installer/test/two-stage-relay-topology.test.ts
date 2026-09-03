import { readFile } from 'node:fs/promises';

import * as v from 'valibot';

import {
  CloudflareGatewayOwnershipChallenge,
  createCloudflareAuthWorker,
  type CloudflareAuthDurableObjectNamespace,
  type CloudflareAuthEnv,
} from '../src/auth-entrypoint';
import {
  CLOUDFLARE_AUTHORIZE_ENDPOINT,
  CLOUDFLARE_CODE_RELAY_CALLBACK,
  CLOUDFLARE_CODE_RELAY_ORIGIN,
} from '../src/cloudflare-code-relay';
import {
  generateCloudflareGatewayOwnershipKeyPair,
  issueCloudflareGatewayOwnershipCertificate,
  verifyCloudflareGatewayOwnershipCertificate,
} from '../src/cloudflare-gateway-ownership-proof';
import { exactOperationScopes } from '../src/cloudflare-operation-authority';
import { base64UrlEncode, randomBase64Url } from '../src/crypto';
import { beginCustomerBootstrapRelay } from '../src/customer-bootstrap-relay-client';
import {
  consumeCustomerBootstrapOauthCallback,
  consumeCustomerBootstrapCapability,
  createCustomerBootstrapCapability,
  initialCustomerBootstrapState,
  startCustomerBootstrapOauth,
} from '../src/customer-bootstrap-state';
import type { CustomerCloudflareTransport } from '../src/customer-cloudflare-grant';
import { requestCustomerGatewayRelayTicket } from '../src/customer-gateway-relay-ticket-client';
import { CUSTOMER_INSTALL_OAUTH_CALLBACK_PATH } from '../src/customer-install-paths';

/**
 * Production-shaped relay topology, proven offline:
 *
 *   customer Gateway (any account) --public HTTPS--> https://auth.ankka.ai
 *
 * The customer side uses only the production relay clients over absolute
 * public URLs (no Service Binding), and the relay side is the real
 * `createCloudflareAuthWorker` with its real operation-sharded challenge
 * Durable Object. The only stand-ins are the SQLite storage fake and the
 * browser hop to dash.cloudflare.com.
 */

const ACCOUNT_ID = 'a'.repeat(32);
const WORKER_PROVIDER_ID = 'b'.repeat(32);
const NAMESPACE_ID = 'c'.repeat(32);
const INSTALL_ID = `acg-${'d'.repeat(24)}`;
const WORKER_NAME = `ankka-gateway-topology-${INSTALL_ID}`;
const BOOTSTRAP_CALLBACK = `https://${WORKER_NAME}.tenant.workers.dev${CUSTOMER_INSTALL_OAUTH_CALLBACK_PATH}`;
const GATEWAY_CALLBACK = `https://manage.example.com${CUSTOMER_INSTALL_OAUTH_CALLBACK_PATH}`;
const CLIENT_ID = 'customer_oauth_client_1234567890';
const ISSUER_KEY_ID = 'ownership-key-v1';
const HANDOFF_SHA256 = `sha256:${'e'.repeat(64)}`;
const AUTHORIZATION_CODE = `code_${'h'.repeat(32)}`;
/** The relay's challenge Durable Object uses the wall clock, so the fixture is anchored to real time. */
const NOW = Date.now();

const relayStateSchema = v.pipe(v.string(), v.regex(/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]{43}$/u));

interface RecordedCall {
  readonly url: string;
  readonly method: string;
  readonly headers: Readonly<Record<string, string>>;
  readonly body: string;
}

interface StoredChallenge {
  readonly certificateSha256: string;
  readonly operation: string;
  readonly challengeSha256: string;
  readonly expiresAt: number;
}

/** Faithful stand-in for the relay's SQLite challenge table; changes() is read in-transaction as in production. */
class ChallengeSqlFake {
  schemaVersion: number | null = null;
  readonly challenges = new Map<string, StoredChallenge>();
  lastChanges = 0;

  exec<Row extends Record<string, SqlStorageValue>>(query: string, ...bindings: unknown[]): SqlStorageCursor<Row> {
    const normalized = query.replace(/\s+/gu, ' ').trim();
    let rows: Record<string, SqlStorageValue>[] = [];
    if (normalized.startsWith('CREATE TABLE IF NOT EXISTS ankka_gateway_ownership_')) {
      // no-op
    } else if (normalized.startsWith('INSERT INTO ankka_gateway_ownership_schema')) {
      this.lastChanges = this.schemaVersion === null ? 1 : 0;
      this.schemaVersion ??= 1;
    } else if (normalized.startsWith('SELECT schema_version')) {
      if (this.schemaVersion !== null) rows = [{ schema_version: this.schemaVersion }];
    } else if (normalized === 'DELETE FROM ankka_gateway_ownership_challenges WHERE expires_at <= ?') {
      let removed = 0;
      for (const [key, challenge] of this.challenges) {
        if (challenge.expiresAt <= Number(bindings[0])) {
          this.challenges.delete(key);
          removed += 1;
        }
      }
      this.lastChanges = removed;
    } else if (normalized.startsWith('INSERT INTO ankka_gateway_ownership_challenges')) {
      const challenge: StoredChallenge = Object.freeze({
        certificateSha256: String(bindings[0]),
        operation: String(bindings[1]),
        challengeSha256: String(bindings[2]),
        expiresAt: Number(bindings[3]),
      });
      this.challenges.set(`${challenge.certificateSha256}.${challenge.operation}`, challenge);
      this.lastChanges = 1;
    } else if (normalized.startsWith('DELETE FROM ankka_gateway_ownership_challenges WHERE certificate_sha256 = ?')) {
      const key = `${String(bindings[0])}.${String(bindings[1])}`;
      const stored = this.challenges.get(key);
      if (stored?.challengeSha256 === String(bindings[2]) && stored.expiresAt === Number(bindings[3])) {
        this.challenges.delete(key);
        this.lastChanges = 1;
      } else {
        this.lastChanges = 0;
      }
    } else if (normalized === 'SELECT changes() AS changed') {
      rows = [{ changed: this.lastChanges }];
    } else {
      throw new Error(`unexpected SQL ${normalized}`);
    }
    // SAFETY: every fake row above is constructed for the query-selected Row
    // shape, and the production adapter still validates all returned fields.
    const typedRows = rows as Row[];
    const cursor: SqlStorageCursor<Row> = Object.create(null);
    Object.defineProperties(cursor, { toArray: { value: (): Row[] => typedRows }, rowsWritten: { value: 0 } });
    return cursor;
  }
}

async function exportPublicKey(key: CryptoKey): Promise<string> {
  return base64UrlEncode(new Uint8Array(await crypto.subtle.exportKey('raw', key)));
}

async function relayFixture() {
  // SAFETY: Ed25519 generateKey always yields a key pair; the union only exists for symmetric algorithms.
  const issuer = await crypto.subtle.generateKey('Ed25519', true, ['sign', 'verify']) as CryptoKeyPair;
  const issuerPublicKey = await exportPublicKey(issuer.publicKey);
  const ownership = await generateCloudflareGatewayOwnershipKeyPair();
  const certificate = await issueCloudflareGatewayOwnershipCertificate({
    accountId: ACCOUNT_ID,
    installId: INSTALL_ID,
    worker: { name: WORKER_NAME, providerId: WORKER_PROVIDER_ID },
    adminStateNamespaceId: NAMESPACE_ID,
    bootstrapCallback: BOOTSTRAP_CALLBACK,
    gatewayCallback: GATEWAY_CALLBACK,
    publicClientId: CLIENT_ID,
    ownershipPublicKey: ownership.publicKey,
    handoffSha256: HANDOFF_SHA256,
    issuedAt: NOW,
    keyId: ISSUER_KEY_ID,
  }, issuer.privateKey);
  const verified = await verifyCloudflareGatewayOwnershipCertificate({
    certificate,
    pinnedIssuerPublicKey: issuerPublicKey,
    expectedKeyId: ISSUER_KEY_ID,
    expectedPublicClientId: CLIENT_ID,
  });

  const clock = { now: NOW + 1 };
  const objects = new Map<string, CloudflareGatewayOwnershipChallenge>();
  const shardNames: string[] = [];
  let env: CloudflareAuthEnv;
  const namespace: CloudflareAuthDurableObjectNamespace = {
    idFromName(name) {
      shardNames.push(name);
      const id: DurableObjectId = Object.create(null);
      Object.defineProperties(id, { toString: { value: () => name }, equals: { value: (other: DurableObjectId) => other.toString() === name } });
      return id;
    },
    get(id) {
      const name = id.toString();
      let object = objects.get(name);
      if (object === undefined) {
        const sql = new ChallengeSqlFake();
        const storage: DurableObjectStorage = Object.create(null);
        Object.defineProperties(storage, {
          sql: { value: sql },
          transactionSync: { value: <Value>(closure: () => Value): Value => closure() },
          setAlarm: { value: async () => undefined },
          deleteAlarm: { value: async () => undefined },
        });
        object = new CloudflareGatewayOwnershipChallenge({
          storage,
          blockConcurrencyWhile: async (callback) => callback(),
        }, env);
        objects.set(name, object);
      }
      const bound = object;
      return { fetch: (request: Request) => bound.fetch(request) };
    },
  };
  env = {
    CLOUDFLARE_CUSTOMER_OAUTH_CLIENT_ID: CLIENT_ID,
    CLOUDFLARE_RELAY_STATE_KEY: randomBase64Url(32),
    CLOUDFLARE_RELAY_TICKET_KEY: randomBase64Url(32),
    CLOUDFLARE_OWNERSHIP_ISSUER_PUBLIC_KEY: issuerPublicKey,
    CLOUDFLARE_OWNERSHIP_ISSUER_KEY_ID: ISSUER_KEY_ID,
    GATEWAY_OWNERSHIP_CHALLENGE: namespace,
  };
  const relay = createCloudflareAuthWorker({ now: () => clock.now });

  const calls: RecordedCall[] = [];
  const responses: Response[] = [];
  /** The customer account's only path to the relay: absolute public HTTPS URLs on the fixed origin. */
  const publicHttps: CustomerCloudflareTransport = async (input, init) => {
    const request = new Request(input, init);
    const url = new URL(request.url);
    expect(url.protocol).toBe('https:');
    expect(url.origin).toBe(CLOUDFLARE_CODE_RELAY_ORIGIN);
    expect(request.headers.get('authorization')).toBeNull();
    expect(request.headers.get('cookie')).toBeNull();
    const body = await request.clone().text();
    const headers: Record<string, string> = {};
    request.headers.forEach((value, key) => { headers[key] = value; });
    calls.push(Object.freeze({ url: request.url, method: request.method, headers: Object.freeze(headers), body }));
    const response = await relay.fetch(request, env);
    responses.push(response);
    return response;
  };
  return { env, relay, clock, calls, responses, shardNames, publicHttps, certificate, verified, ownership, issuerPublicKey };
}

function expectRelayHeaders(response: Response): void {
  expect(response.headers.get('cache-control')).toBe('no-store');
  expect(response.headers.get('referrer-policy')).toBe('no-referrer');
  expect(response.headers.get('x-content-type-options')).toBe('nosniff');
  expect(response.headers.get('content-security-policy')).toContain("default-src 'none'");
  expect(response.headers.get('access-control-allow-origin')).toBeNull();
  expect(response.headers.get('set-cookie')).toBeNull();
}

describe('production-shaped relay topology: customer account to auth.ankka.ai over public HTTPS', () => {
  it('obtains one fixed install ticket, mints the exact authorization, and relays only the code to the certified callback', async () => {
    const f = await relayFixture();
    let counter = 0;
    const randomBytes = (length: number): Uint8Array => {
      counter += 1;
      return new Uint8Array(length).map((_, index) => (index * 5 + counter * 37) & 255);
    };
    const capability = await createCustomerBootstrapCapability({ now: NOW, randomBytes });
    const initial = initialCustomerBootstrapState({
      installId: INSTALL_ID,
      bootstrapId: capability.bootstrapId,
      secretCommitment: capability.secretCommitment,
      expiresAt: capability.expiresAt,
    });
    const session = await consumeCustomerBootstrapCapability({
      current: initial, bootstrapId: capability.bootstrapId, secret: capability.secret, now: NOW + 1, randomBytes,
    });
    const start = await startCustomerBootstrapOauth({
      current: session.state, sessionSecret: session.sessionSecret, now: NOW + 2, randomBytes,
    });

    const ticket = await requestCustomerGatewayRelayTicket({
      certificate: f.certificate,
      certificateSha256: f.verified.certificateSha256,
      gatewayCallback: GATEWAY_CALLBACK,
      operation: 'install',
      ownershipPrivateKey: f.ownership.privateKey,
      transport: f.publicHttps,
      now: () => f.clock.now,
    });
    expect(f.shardNames).toEqual(['v1:install', 'v1:install']);

    const relayStart = await beginCustomerBootstrapRelay({
      publicClientId: CLIENT_ID,
      relayTicket: ticket.relayTicket,
      gatewayState: start.state,
      pkceChallenge: start.challenge,
      gatewayCallback: GATEWAY_CALLBACK,
      transport: f.publicHttps,
    });
    const authorization = new URL(relayStart.authorizationUrl);
    expect(authorization.origin + authorization.pathname).toBe(CLOUDFLARE_AUTHORIZE_ENDPOINT);
    expect(authorization.searchParams.get('client_id')).toBe(CLIENT_ID);
    expect(authorization.searchParams.get('redirect_uri')).toBe(CLOUDFLARE_CODE_RELAY_CALLBACK);
    expect(authorization.searchParams.get('scope')).toBe(exactOperationScopes('install').join(' '));
    expect(authorization.searchParams.get('code_challenge')).toBe(start.challenge);
    expect(authorization.searchParams.get('code_challenge_method')).toBe('S256');
    const relayState = v.parse(relayStateSchema, authorization.searchParams.get('state'));

    expect(f.calls.map((call) => `${call.method} ${new URL(call.url).pathname}`)).toEqual([
      'POST /oauth/relay-ticket/challenge/install',
      'POST /oauth/relay-ticket/issue/install',
      'POST /oauth/start/install',
    ]);
    for (const call of f.calls) {
      expect(call.body).not.toContain(start.verifier);
      expect(call.body).not.toContain(capability.secret);
      expect(call.body).not.toContain(session.sessionSecret);
      expect(call.body).not.toContain('"scope"');
      expect(call.body).not.toContain('token');
    }
    for (const response of f.responses) expectRelayHeaders(response);

    // The browser returns from dash.cloudflare.com to the relay with only code and state.
    const callback = await f.relay.fetch(new Request(
      `${CLOUDFLARE_CODE_RELAY_CALLBACK}?code=${AUTHORIZATION_CODE}&state=${relayState}`,
      { redirect: 'manual' },
    ), f.env);
    expect(callback.status).toBe(302);
    expectRelayHeaders(callback);
    const forwarded = new URL(callback.headers.get('location') ?? '');
    expect(`${forwarded.origin}${forwarded.pathname}`).toBe(GATEWAY_CALLBACK);
    expect([...forwarded.searchParams.keys()].sort()).toEqual(['code', 'state']);
    expect(forwarded.searchParams.get('code')).toBe(AUTHORIZATION_CODE);
    expect(forwarded.searchParams.get('state')).toBe(start.state);
    expect(forwarded.hash).toBe('');

    // The customer Gateway consumes its own state exactly once before any exchange.
    const consumed = await consumeCustomerBootstrapOauthCallback({
      current: start.next, sessionSecret: session.sessionSecret, attemptId: start.attemptId,
      state: forwarded.searchParams.get('state') ?? '', now: NOW + 3,
    });
    expect(consumed.next.oauth?.phase).toBe('exchanging');
    await expect(consumeCustomerBootstrapOauthCallback({
      current: consumed.next, sessionSecret: session.sessionSecret, attemptId: start.attemptId,
      state: start.state, now: NOW + 4,
    })).rejects.toMatchObject({ code: 'conflict' });

    // The relay itself never contacted a token endpoint: it has no transport and no client secret.
    expect(f.calls.some((call) => call.url.includes('oauth2/token'))).toBe(false);
    const health = await f.relay.fetch(new Request(`${CLOUDFLARE_CODE_RELAY_ORIGIN}/health`), f.env);
    expect(await health.json()).toMatchObject({ role: 'cloudflare-code-relay', tokenExchange: false });
  });

  it('forwards a denial as one fixed error, refuses tampered or substituted state, and never open-redirects', async () => {
    const f = await relayFixture();
    const ticket = await requestCustomerGatewayRelayTicket({
      certificate: f.certificate,
      certificateSha256: f.verified.certificateSha256,
      gatewayCallback: GATEWAY_CALLBACK,
      operation: 'install',
      ownershipPrivateKey: f.ownership.privateKey,
      transport: f.publicHttps,
      now: () => f.clock.now,
    });
    const gatewayState = randomBase64Url(32);
    const relayStart = await beginCustomerBootstrapRelay({
      publicClientId: CLIENT_ID,
      relayTicket: ticket.relayTicket,
      gatewayState,
      pkceChallenge: randomBase64Url(32),
      gatewayCallback: GATEWAY_CALLBACK,
      transport: f.publicHttps,
    });
    const relayState = new URL(relayStart.authorizationUrl).searchParams.get('state') ?? '';

    const denied = await f.relay.fetch(new Request(
      `${CLOUDFLARE_CODE_RELAY_CALLBACK}?error=access_denied&error_description=${encodeURIComponent('user said no')}&state=${relayState}`,
      { redirect: 'manual' },
    ), f.env);
    expect(denied.status).toBe(302);
    const deniedTarget = new URL(denied.headers.get('location') ?? '');
    expect(`${deniedTarget.origin}${deniedTarget.pathname}`).toBe(GATEWAY_CALLBACK);
    expect([...deniedTarget.searchParams.keys()].sort()).toEqual(['error', 'state']);
    expect(deniedTarget.searchParams.get('state')).toBe(gatewayState);
    expect(denied.headers.get('location')).not.toContain('user said no');

    const tampered = `${relayState.slice(0, -1)}${relayState.endsWith('A') ? 'B' : 'A'}`;
    for (const query of [
      `code=${AUTHORIZATION_CODE}&state=${tampered}`,
      `code=${AUTHORIZATION_CODE}&state=${relayState}&redirect_uri=https://evil.example/`,
      `code=${AUTHORIZATION_CODE}&code=${AUTHORIZATION_CODE}&state=${relayState}`,
      `state=${relayState}`,
      `code=${AUTHORIZATION_CODE}`,
    ]) {
      const response = await f.relay.fetch(new Request(`${CLOUDFLARE_CODE_RELAY_CALLBACK}?${query}`, { redirect: 'manual' }), f.env);
      expect(response.status, query).not.toBe(302);
      expect(response.headers.get('location'), query).toBeNull();
      expectRelayHeaders(response);
    }

    f.clock.now = NOW + 11 * 60_000;
    const expired = await f.relay.fetch(new Request(
      `${CLOUDFLARE_CODE_RELAY_CALLBACK}?code=${AUTHORIZATION_CODE}&state=${relayState}`,
      { redirect: 'manual' },
    ), f.env);
    expect(expired.status).not.toBe(302);
  });

  it('binds tickets to the certified callback and refuses unsafe callbacks before any request leaves the customer account', async () => {
    const f = await relayFixture();
    for (const gatewayCallback of [
      `http://manage.example.com${CUSTOMER_INSTALL_OAUTH_CALLBACK_PATH}`,
      `https://manage.example.com:8443${CUSTOMER_INSTALL_OAUTH_CALLBACK_PATH}`,
      'https://manage.example.com/other/callback',
      `https://manage.example.com${CUSTOMER_INSTALL_OAUTH_CALLBACK_PATH}?x=1`,
    ]) {
      await expect(requestCustomerGatewayRelayTicket({
        certificate: f.certificate,
        certificateSha256: f.verified.certificateSha256,
        gatewayCallback,
        operation: 'install',
        ownershipPrivateKey: f.ownership.privateKey,
        transport: f.publicHttps,
        now: () => f.clock.now,
      }), gatewayCallback).rejects.toMatchObject({ code: 'invalid' });
    }
    expect(f.calls).toEqual([]);

    const foreignCallback = `https://other.example.com${CUSTOMER_INSTALL_OAUTH_CALLBACK_PATH}`;
    await expect(requestCustomerGatewayRelayTicket({
      certificate: f.certificate,
      certificateSha256: f.verified.certificateSha256,
      gatewayCallback: foreignCallback,
      operation: 'install',
      ownershipPrivateKey: f.ownership.privateKey,
      transport: f.publicHttps,
      now: () => f.clock.now,
    })).rejects.toMatchObject({ code: 'relay_rejected' });

    const ticket = await requestCustomerGatewayRelayTicket({
      certificate: f.certificate,
      certificateSha256: f.verified.certificateSha256,
      gatewayCallback: GATEWAY_CALLBACK,
      operation: 'install',
      ownershipPrivateKey: f.ownership.privateKey,
      transport: f.publicHttps,
      now: () => f.clock.now,
    });
    await expect(beginCustomerBootstrapRelay({
      publicClientId: CLIENT_ID,
      relayTicket: ticket.relayTicket,
      gatewayState: randomBase64Url(32),
      pkceChallenge: randomBase64Url(32),
      gatewayCallback: foreignCallback,
      transport: f.publicHttps,
    })).rejects.toThrow('relay_rejected');
  });

  it('serves only the fixed public origin and its deployable config declares exactly that route and no token or secret binding', async () => {
    const f = await relayFixture();
    for (const origin of ['https://ankka-cloudflare-auth.tenant.workers.dev', 'http://auth.ankka.ai', 'https://auth.ankka.ai:8443']) {
      const response = await f.relay.fetch(new Request(`${origin}/health`), f.env);
      expect(response.status, origin).toBe(503);
    }
    const [config, ...sources] = await Promise.all([
      readFile(new URL('../wrangler.auth.toml', import.meta.url), 'utf8'),
      ...[
        'auth-entrypoint', 'cloudflare-code-relay', 'cloudflare-code-relay-http',
        'cloudflare-gateway-ownership-proof-http', 'cloudflare-gateway-relay-ticket',
        'cloudflare-gateway-ownership-challenge-durable-state',
      ].map((name) => readFile(new URL(`../src/${name}.ts`, import.meta.url), 'utf8')),
    ]);
    expect(config).toMatch(/^main = "src\/auth-entrypoint\.ts"$/mu);
    expect(config.match(/^\[\[routes\]\]$/gmu)).toHaveLength(1);
    expect(config).toMatch(/^\[\[routes\]\]\npattern = "auth\.ankka\.ai"\ncustom_domain = true$/mu);
    expect(config).not.toMatch(/^routes\s*=|^pattern = "(?!auth\.ankka\.ai")/mu);
    expect(config).toMatch(/^class_name = "CloudflareGatewayOwnershipChallenge"$/mu);
    expect(config).not.toMatch(/CLIENT_SECRET|GATEWAY_RELEASE_BUCKET|DEPLOY_SESSION_ENCRYPTION_KEY/u);
    expect(config).toMatch(/^\[observability\.logs\]\nenabled = false/mu);
    const relaySource = sources.join('\n');
    expect(relaySource).not.toMatch(/oauth2\/token|client_secret|clientSecret|access_token|refresh_token/u);
    expect(relaySource).not.toMatch(/console\.(?:log|info|warn|error|debug)/u);
  });
});

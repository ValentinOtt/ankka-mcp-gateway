import {
  GatewayDeploySession,
  type GatewayDeploySessionState,
  type GatewayDeploySessionTransaction,
} from '../src/durable/gateway-deploy-session';
import type {
  GatewayDeployEnv,
  GatewayDeploySessionNamespace,
  GatewayDeploySessionStub,
} from '../src/env';
import type {
  ReleaseBundleProvider,
  VerifiedRelease,
  VerifiedReleaseBundle,
} from '../src/release';
import { REQUIRED_OAUTH_SCOPES } from '../src/constants';
import {
  APPROVED_CLOUDFLARE_RELEASE_CONTRACT,
  canonicalJson,
  type ReleaseManifest,
} from '../src/release-manifest';

export const NOW = 1_787_444_000_000;
export const ENCRYPTION_KEY = 'BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc';
export const BOOTSTRAP_NONCE_KEY = 'CAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg';
export const CLIENT_ID = '27cbab94797bd7c22211ec6920fdd913';
export const CLIENT_SECRET = 'test-client-secret-never-store';

export const selectionInput = {
  schemaVersion: 1,
  basics: {
    gatewayName: 'Example Gateway',
    zoneName: 'example.com',
    adminEmail: 'Owner@Example.com',
    additionalAdminEmails: ['admin@example.com', 'owner@example.com'],
    managementHostname: 'manage.example.com',
    portalHostname: 'mcp.example.com',
  },
  firstSource: {
    name: 'Company context',
    url: 'https://source.example.net/mcp',
    enabledTools: ['company_search', 'company_prepare', 'company_search'],
    portalUserEmails: ['member@example.com', 'ADMIN@example.com'],
  },
} as const;

export const manifest: ReleaseManifest = {
  artifact: {
    byteSize: 6,
    fileCount: 6,
    treeSha256: '9'.repeat(64),
  },
  cloudflare: APPROVED_CLOUDFLARE_RELEASE_CONTRACT,
  controlPlaneOrigin: 'https://deploy.ankka.ai',
  components: {
    admin: {
      byteSize: 1,
      fileCount: 1,
      files: [{
        byteSize: 1,
        contentType: 'text/html; charset=utf-8',
        path: 'payload/admin/index.html',
        sha256: '1'.repeat(64),
      }],
      treeSha256: '2'.repeat(64),
    },
    installer: {
      byteSize: 1,
      fileCount: 1,
      files: [{
        byteSize: 1,
        contentType: 'text/html; charset=utf-8',
        path: 'payload/installer/index.html',
        sha256: '3'.repeat(64),
      }],
      treeSha256: '4'.repeat(64),
    },
    worker: {
      byteSize: 1,
      fileCount: 1,
      files: [{
        byteSize: 1,
        contentType: 'application/javascript+module',
        path: 'payload/worker/index.js',
        sha256: '5'.repeat(64),
      }],
      treeSha256: '6'.repeat(64),
    },
    workerBootstrap: {
      byteSize: 1,
      fileCount: 1,
      files: [{
        byteSize: 1,
        contentType: 'application/javascript+module',
        path: 'payload/worker-bootstrap/index.js',
        sha256: 'c'.repeat(64),
      }],
      treeSha256: 'd'.repeat(64),
    },
    workerCleanup: {
      byteSize: 1,
      fileCount: 1,
      files: [{
        byteSize: 1,
        contentType: 'application/javascript+module',
        path: 'payload/worker-cleanup/index.js',
        sha256: '7'.repeat(64),
      }],
      treeSha256: '8'.repeat(64),
    },
    workerRetirement: {
      byteSize: 1,
      fileCount: 1,
      files: [{
        byteSize: 1,
        contentType: 'application/javascript+module',
        path: 'payload/worker-retirement/index.js',
        sha256: 'a'.repeat(64),
      }],
      treeSha256: 'b'.repeat(64),
    },
  },
  oauthScopeIds: REQUIRED_OAUTH_SCOPES,
  release: 'gateway-v0.1.0',
  schemaVersion: 1,
  sourceCommit: 'a'.repeat(40),
};

export const verifiedRelease: VerifiedRelease = Object.freeze({
  verification: 'ed25519',
  keyId: 'test-key',
  manifest,
});

export const verifiedReleaseBundle: VerifiedReleaseBundle = Object.freeze({
  ...verifiedRelease,
  channel: 'stable',
  envelope: Object.freeze({
    schemaVersion: 2,
    channel: 'stable',
    keyId: verifiedRelease.keyId,
    manifest: canonicalJson(manifest),
    signature: 'A'.repeat(86),
    signatureContext: 'ankka-mcp-gateway-release-envelope-v2',
  }),
  // Core callback tests exercise the handoff boundary, not payload validation.
  // The reviewed R2/runtime tests provide fully verified immutable payloads.
  payload: Object.freeze([]),
  publicKey: 'A'.repeat(43),
});

export const releaseProvider: ReleaseBundleProvider = {
  loadVerifiedRelease: async () => verifiedRelease,
  loadVerifiedReleaseBundle: async () => verifiedReleaseBundle,
};

export class FakeStorage implements GatewayDeploySessionTransaction {
  readonly values = new Map<string, unknown>();
  alarmAt: number | null = null;

  async get<T>(key: string): Promise<T | undefined> {
    // SAFETY: This in-memory fake mirrors Cloudflare's generic storage get:
    // callers own T, while every inserted value is preserved by structured clone.
    return structuredClone(this.values.get(key)) as T | undefined;
  }

  async put<Value>(key: string, value: Value): Promise<void> {
    this.values.set(key, structuredClone(value));
  }

  async transaction<T>(closure: (transaction: GatewayDeploySessionTransaction) => Promise<T>): Promise<T> {
    return closure(this);
  }

  async delete(key: string): Promise<boolean> {
    return this.values.delete(key);
  }

  async deleteAll(): Promise<void> {
    this.values.clear();
  }

  async setAlarm(scheduledTime: number | Date): Promise<void> {
    this.alarmAt = scheduledTime instanceof Date ? scheduledTime.getTime() : scheduledTime;
  }

  async deleteAlarm(): Promise<void> {
    this.alarmAt = null;
  }
}

export class FakeState implements GatewayDeploySessionState {
  readonly storage = new FakeStorage();
}

class FakeDurableObjectId implements DurableObjectId {
  constructor(readonly name: string) {}

  toString(): string {
    return this.name;
  }

  equals(other: DurableObjectId): boolean {
    return other.toString() === this.name;
  }
}

export class FakeDeploySessionNamespace implements GatewayDeploySessionNamespace {
  readonly states = new Map<string, FakeState>();
  readonly objects = new Map<string, GatewayDeploySession>();

  constructor(private readonly now: () => number = Date.now) {}

  idFromName(name: string): DurableObjectId {
    return new FakeDurableObjectId(name);
  }

  get(id: DurableObjectId): GatewayDeploySessionStub {
    const name = id.name;
    if (!name) throw new Error('test Durable Object ID has no name');
    let object = this.objects.get(name);
    if (!object) {
      const state = new FakeState();
      object = new GatewayDeploySession(state, undefined, this.now);
      this.states.set(name, state);
      this.objects.set(name, object);
    }
    return { fetch: (request: Request) => object.fetch(request) };
  }

  serialized(): string {
    return JSON.stringify([...this.states.values()].map((state) => [...state.storage.values.values()]));
  }
}

export function env(namespace = new FakeDeploySessionNamespace()): GatewayDeployEnv {
  return {
    GATEWAY_DEPLOY_SESSION: namespace,
    CLOUDFLARE_OAUTH_CLIENT_ID: CLIENT_ID,
    CLOUDFLARE_OAUTH_CLIENT_SECRET: CLIENT_SECRET,
    DEPLOY_SESSION_ENCRYPTION_KEY: ENCRYPTION_KEY,
    BOOTSTRAP_NONCE_DERIVATION_KEY: BOOTSTRAP_NONCE_KEY,
  };
}

export function internalRequest<Body>(path: string, method: string, body?: Body): Request {
  const input = body === undefined
    ? { method }
    : {
        method,
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(body),
      };
  return new Request(`https://internal.invalid${path}`, input);
}

export function requiredFixture<Value>(value: Value | undefined, name: string): Value {
  if (value === undefined) throw new TypeError(`missing fixture ${name}`);
  return value;
}

export function cookiePair(setCookie: string, name: string): string {
  const match = setCookie.match(new RegExp(`(?:^|,\\s*)(${name}=[^;]+)`));
  if (!match) throw new Error(`missing cookie ${name}`);
  return requiredFixture(match.at(1), `cookie ${name}`);
}

import type { VerifiedRelease, VerifiedReleaseBundle } from '../src/release';
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

export function requiredFixture<Value>(value: Value | undefined, name: string): Value {
  if (value === undefined) throw new TypeError(`missing fixture ${name}`);
  return value;
}

export function cookiePair(setCookie: string, name: string): string {
  const match = setCookie.match(new RegExp(`(?:^|,\\s*)(${name}=[^;]+)`));
  if (!match) throw new Error(`missing cookie ${name}`);
  return requiredFixture(match.at(1), `cookie ${name}`);
}

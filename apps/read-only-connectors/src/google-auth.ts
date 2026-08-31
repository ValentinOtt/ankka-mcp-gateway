import { importPKCS8, SignJWT } from 'jose';
import { z } from 'zod';

export const GOOGLE_AUTH_LIMITS = {
  secretBytes: 16_384, requestBytes: 8_192, responseBytes: 16_384,
  responseChunks: 32, milliseconds: 8_000, assertionSeconds: 300,
} as const;
export const GOOGLE_TOKEN_ENDPOINT = 'https://oauth2.googleapis.com/token';
export const GOOGLE_PROVIDER_SCOPES = {
  'search-console': 'https://www.googleapis.com/auth/webmasters.readonly',
  'google-analytics': 'https://www.googleapis.com/auth/analytics.readonly',
  // jobs.insert is used only with configuration.dryRun:true for Google's
  // statement classification. It does not accept cloud-platform.read-only;
  // dedicated dataset-read IAM, not the OAuth scope, prevents data writes.
  bigquery: 'https://www.googleapis.com/auth/bigquery',
} as const;
type GoogleProvider = keyof typeof GOOGLE_PROVIDER_SCOPES;

export class GoogleAuthorizationError extends Error {
  constructor(readonly code: 'GOOGLE_AUTH_CONFIGURATION_INVALID' | 'GOOGLE_AUTH_FAILED') {
    super(code);
    this.name = 'GoogleAuthorizationError';
  }
}

const serviceAccount = z.object({
  type: z.literal('service_account'),
  project_id: z.string().regex(/^[a-z][a-z0-9-]{4,61}[a-z0-9]$/u),
  private_key_id: z.string().regex(/^[a-f0-9]{40}$/u),
  private_key: z.string().min(1).max(8_192),
  client_email: z.string().max(256).regex(/^[a-z0-9][a-z0-9-]{4,62}[a-z0-9]@[a-z][a-z0-9-]{4,61}[a-z0-9]\.iam\.gserviceaccount\.com$/u),
  client_id: z.string().regex(/^[0-9]{1,32}$/u).optional(),
  auth_uri: z.literal('https://accounts.google.com/o/oauth2/auth').optional(),
  token_uri: z.literal(GOOGLE_TOKEN_ENDPOINT),
  auth_provider_x509_cert_url: z.literal('https://www.googleapis.com/oauth2/v1/certs').optional(),
  client_x509_cert_url: z.string().max(1_024).optional(),
  universe_domain: z.literal('googleapis.com').optional(),
}).strict().refine((value) =>
  value.client_email.endsWith(`@${value.project_id}.iam.gserviceaccount.com`) &&
  (value.client_x509_cert_url === undefined || value.client_x509_cert_url ===
    `https://www.googleapis.com/robot/v1/metadata/x509/${encodeURIComponent(value.client_email)}`),
);
const rsaSigningKey = z.object({
  name: z.literal('RSASSA-PKCS1-v1_5'),
  modulusLength: z.number().int().min(2_048).max(4_096),
  hash: z.object({ name: z.literal('SHA-256') }),
});
const encoder = new TextEncoder();

/**
 * Deployment-owned service-account key only. OAuth hosts/scopes are code-owned;
 * delegated subjects, user OAuth refresh tokens, and external-account JSON fail
 * closed. No imported key or access token is cached across calls.
 */
export function createGoogleAuthorization(rawSecret: string, provider: GoogleProvider) {
  let account: z.infer<typeof serviceAccount>;
  let scope: string;
  try {
    if (rawSecret.length > GOOGLE_AUTH_LIMITS.secretBytes ||
      encoder.encode(rawSecret).byteLength > GOOGLE_AUTH_LIMITS.secretBytes) throw new Error();
    account = serviceAccount.parse(JSON.parse(rawSecret));
    scope = GOOGLE_PROVIDER_SCOPES[z.enum(['search-console', 'google-analytics', 'bigquery']).parse(provider)];
  } catch {
    throw new GoogleAuthorizationError('GOOGLE_AUTH_CONFIGURATION_INVALID');
  }

  return async (fetcher: typeof globalThis.fetch): Promise<Readonly<Record<string, string>>> => {
    const controller = new AbortController();
    let expired = false;
    let reader: ReadableStreamDefaultReader<Uint8Array> | undefined;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const deadline = new Promise<never>((_resolve, reject) => {
      timer = setTimeout(() => {
        expired = true;
        controller.abort();
        cancelReader(reader);
        reject(new GoogleAuthorizationError('GOOGLE_AUTH_FAILED'));
      }, GOOGLE_AUTH_LIMITS.milliseconds);
    });
    const mint = async (): Promise<Readonly<Record<string, string>>> => {
      try {
        const key = await importPKCS8(account.private_key, 'RS256');
        rsaSigningKey.parse(key.algorithm);
        const issuedAt = Math.floor(Date.now() / 1_000);
        const assertion = await new SignJWT({ scope })
          .setProtectedHeader({ alg: 'RS256', typ: 'JWT', kid: account.private_key_id })
          .setIssuer(account.client_email).setAudience(GOOGLE_TOKEN_ENDPOINT)
          .setIssuedAt(issuedAt).setExpirationTime(issuedAt + GOOGLE_AUTH_LIMITS.assertionSeconds)
          .sign(key);
        const body = new URLSearchParams({
          grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer', assertion,
        }).toString();
        if (expired || encoder.encode(body).byteLength > GOOGLE_AUTH_LIMITS.requestBytes) throw new Error();
        const response = await fetcher(GOOGLE_TOKEN_ENDPOINT, {
          method: 'POST', redirect: 'error', signal: controller.signal,
          headers: { Accept: 'application/json', 'Content-Type': 'application/x-www-form-urlencoded' },
          body,
        });
        const length = response.headers.get('Content-Length');
        if (expired || response.status !== 200 || response.redirected ||
          (response.url !== '' && response.url !== GOOGLE_TOKEN_ENDPOINT) ||
          !/^application\/json(?:\s*;[^\r\n]*)?$/iu.test(response.headers.get('Content-Type') ?? '') ||
          (length !== null && (!/^(?:0|[1-9]\d*)$/u.test(length) || Number(length) > GOOGLE_AUTH_LIMITS.responseBytes))) {
          cancelBody(response.body);
          throw new Error();
        }
        if (response.body === null) throw new Error();
        reader = response.body.getReader();
        const decoder = new TextDecoder('utf-8', { fatal: true });
        let bytes = 0;
        let chunks = 0;
        let text = '';
        while (true) {
          const chunk = await reader.read();
          if (expired) throw new Error();
          if (chunk.done) break;
          bytes += chunk.value.byteLength;
          chunks += 1;
          if (bytes > GOOGLE_AUTH_LIMITS.responseBytes || chunks > GOOGLE_AUTH_LIMITS.responseChunks) throw new Error();
          text += decoder.decode(chunk.value, { stream: true });
        }
        text += decoder.decode();
        const token = z.object({
          access_token: z.string().min(16).max(4_096).regex(/^[A-Za-z0-9._~+/-]+=*$/u),
          token_type: z.literal('Bearer'), expires_in: z.number().int().min(1).max(3_600),
          scope: z.literal(scope).optional(),
        }).parse(JSON.parse(text));
        return { Authorization: `Bearer ${token.access_token}` };
      } catch {
        cancelReader(reader);
        throw new GoogleAuthorizationError('GOOGLE_AUTH_FAILED');
      }
    };
    try {
      return await Promise.race([mint(), deadline]);
    } finally {
      clearTimeout(timer);
    }
  };
}

function cancelReader(reader: ReadableStreamDefaultReader<Uint8Array> | undefined): void {
  if (reader !== undefined) void reader.cancel().catch(() => {});
}
function cancelBody(body: ReadableStream<Uint8Array> | null): void {
  if (body !== null) void body.cancel().catch(() => {});
}

import * as v from 'valibot';

import type { JsonObject } from './boundary';
import {
  R2ReleasePublicationError,
  type PublishR2ReleaseInput,
  type R2ReleaseBucket,
  type R2ReleasePublicationBlob,
  type R2ReleasePublicationResult,
} from './r2-release-publisher';

const SHA256_PATTERN = /^[a-f0-9]{64}$/u;
const ACCOUNT_ID_PATTERN = /^[a-f0-9]{32}$/u;
const RELEASE_PATTERN = /^gateway-v(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)$/u;
const CHANNEL_PATTERN = /^(?:canary|stable)$/u;
const KEY_ID_PATTERN = /^[a-z0-9][a-z0-9._-]{0,63}$/u;
const BUCKET_PATTERN = /^[a-z0-9](?:[a-z0-9-]{1,61}[a-z0-9])$/u;
const PUBLIC_KEY_PATTERN = /^[A-Za-z0-9_-]{43}$/u;
const RELEASE_ROOT = 'ankka-mcp-gateway/releases';
const PUBLICATION_PATH_ROOT = '/__ankka/publish/';
const JSON_HEADERS = Object.freeze({
  'cache-control': 'no-store',
  'content-type': 'application/json; charset=utf-8',
  'referrer-policy': 'no-referrer',
  'x-content-type-options': 'nosniff',
});
const publicationIdentitySchema = v.strictObject({
  accountId: v.string(),
  artifactSha256: v.string(),
  bucketName: v.string(),
  channel: v.string(),
  keyId: v.string(),
  objectPlanSha256: v.string(),
  prefix: v.string(),
  publicKey: v.string(),
  release: v.string(),
  releaseEnvelopeSha256: v.string(),
  schemaVersion: v.literal(1),
});
const publicationBlobSchema = v.strictObject({
  bytes: v.instance(Blob),
  key: v.string(),
});
const publicationOperatorInputSchema = v.strictObject({
  blobs: v.array(publicationBlobSchema),
  objectPlan: v.unknown(),
  objectPlanSha256: v.string(),
  publicationIdentity: publicationIdentitySchema,
  publish: v.function(),
});
const publicationEnvironmentSchema = v.strictObject({
  RELEASE_BUCKET: v.object({
    get: v.function(),
    list: v.function(),
    put: v.function(),
  }),
});

export interface R2PublicationOperatorEnv {
  readonly RELEASE_BUCKET: R2ReleaseBucket;
}

export type R2PublicationFunction = (
  input: PublishR2ReleaseInput,
) => Promise<R2ReleasePublicationResult>;

export interface CreateR2PublicationOperatorInput {
  readonly blobs: readonly R2ReleasePublicationBlob[];
  readonly objectPlan: unknown;
  readonly objectPlanSha256: string;
  readonly publicationIdentity: R2PublicationIdentity;
  readonly publish: R2PublicationFunction;
}

export interface R2PublicationIdentity {
  readonly accountId: string;
  readonly artifactSha256: string;
  readonly bucketName: string;
  readonly channel: string;
  readonly keyId: string;
  readonly objectPlanSha256: string;
  readonly prefix: string;
  readonly publicKey: string;
  readonly release: string;
  readonly releaseEnvelopeSha256: string;
  readonly schemaVersion: 1;
}

export interface R2PublicationOperator {
  fetch(request: Request, env: R2PublicationOperatorEnv): Promise<Response>;
}

function fixedJson(status: number, body: JsonObject): Response {
  return new Response(JSON.stringify(body), { status, headers: JSON_HEADERS });
}

function hasExactBucket(env: R2PublicationOperatorEnv): boolean {
  return v.safeParse(publicationEnvironmentSchema, env).success;
}

function statusForPublicationError(error: R2ReleasePublicationError): number {
  switch (error.code) {
    case 'release_publication_invalid':
      return 400;
    case 'release_publication_conflict':
      return 409;
    case 'release_publication_unavailable':
      return 503;
  }
}

function parsePublicationIdentity<Input>(
  input: Input,
  objectPlanSha256: string,
): R2PublicationIdentity | null {
  const result = v.safeParse(publicationIdentitySchema, input);
  if (!result.success) return null;
  const value = result.output;
  if (
    !ACCOUNT_ID_PATTERN.test(value.accountId) ||
    !SHA256_PATTERN.test(value.artifactSha256) ||
    !BUCKET_PATTERN.test(value.bucketName) ||
    !CHANNEL_PATTERN.test(value.channel) ||
    !KEY_ID_PATTERN.test(value.keyId) ||
    value.objectPlanSha256 !== objectPlanSha256 ||
    !PUBLIC_KEY_PATTERN.test(value.publicKey) ||
    !RELEASE_PATTERN.test(value.release) ||
    !SHA256_PATTERN.test(value.releaseEnvelopeSha256) ||
    value.prefix !== `${RELEASE_ROOT}/${value.channel}/${value.release}/`
  ) return null;
  return Object.freeze({ ...value });
}

/**
 * Builds the deliberately tiny request surface used only by a generated,
 * ephemeral local Worker with one explicitly remote R2 binding. The capability path commits to one
 * exact object-plan digest. It accepts no caller-supplied key, body, query,
 * release data, or credentials, and starts publication at most once per
 * Worker isolate.
 */
async function requestCarriesBodyBytes(request: Request): Promise<boolean> {
  const declared = request.headers.get('content-length');
  if (declared !== null && declared !== '0') return true;
  if (request.body === null) return false;
  const reader = request.body.getReader();
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) return false;
      if (value.byteLength > 0) {
        await reader.cancel().catch(() => undefined);
        return true;
      }
    }
  } catch {
    return true;
  } finally {
    try { reader.releaseLock(); } catch { /* the verdict above stands */ }
  }
}

export function createR2PublicationOperator(
  input: CreateR2PublicationOperatorInput,
): R2PublicationOperator {
  const result = v.safeParse(publicationOperatorInputSchema, input);
  if (!result.success) throw new TypeError('invalid_r2_publication_operator');
  const publicationIdentity = parsePublicationIdentity(
    result.output.publicationIdentity,
    result.output.objectPlanSha256,
  );
  if (
    !SHA256_PATTERN.test(result.output.objectPlanSha256) ||
    publicationIdentity === null
  ) {
    throw new TypeError('invalid_r2_publication_operator');
  }

  const path = `${PUBLICATION_PATH_ROOT}${input.objectPlanSha256}`;
  let invocationStarted = false;

  return Object.freeze({
    async fetch(request: Request, env: R2PublicationOperatorEnv): Promise<Response> {
      let url: URL;
      try {
        url = new URL(request.url);
      } catch {
        return fixedJson(404, { error: 'not_found' });
      }
      if (url.pathname !== path || url.search !== '' || request.url.includes('?')) {
        return fixedJson(404, { error: 'not_found' });
      }
      if (request.method !== 'POST') {
        const response = fixedJson(405, { error: 'method_not_allowed' });
        response.headers.set('allow', 'POST');
        return response;
      }
      // The invocation carries no body. Under `wrangler dev` a bodiless POST is
      // delivered as an empty stream rather than `null`, so the contract is
      // "zero body bytes": any byte is rejected before the one-shot is burned.
      if (await requestCarriesBodyBytes(request)) {
        return fixedJson(400, { error: 'request_body_not_allowed' });
      }
      if (!hasExactBucket(env)) {
        return fixedJson(503, { error: 'release_bucket_unavailable' });
      }
      if (invocationStarted) {
        return fixedJson(409, { error: 'publication_already_invoked' });
      }
      invocationStarted = true;

      try {
        const result = await input.publish({
          blobs: input.blobs,
          bucket: env.RELEASE_BUCKET,
          clock: { now: () => Date.now() },
          objectPlan: input.objectPlan,
        });
        if (
          result.objectPlanSha256 !== input.objectPlanSha256 ||
          result.channel !== publicationIdentity.channel ||
          result.release !== publicationIdentity.release ||
          result.prefix !== publicationIdentity.prefix
        ) {
          return fixedJson(500, { error: 'publication_result_invalid' });
        }
        return fixedJson(200, {
          ...publicationIdentity,
          status: 'published',
        });
      } catch (error) {
        if (error instanceof R2ReleasePublicationError) {
          return fixedJson(statusForPublicationError(error), { error: error.code });
        }
        return fixedJson(500, { error: 'publication_failed' });
      }
    },
  });
}

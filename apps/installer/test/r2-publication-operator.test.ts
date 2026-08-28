import {
  createR2PublicationOperator,
  type R2PublicationFunction,
  type R2PublicationIdentity,
} from '../src/r2-publication-operator';
import type { R2ReleaseBucket } from '../src/r2-release-publisher';

const PLAN_SHA = 'a'.repeat(64);
const ARTIFACT_SHA = 'b'.repeat(64);
const ENVELOPE_SHA = 'c'.repeat(64);
const CHANNEL = 'canary';
const RELEASE = 'gateway-v1.2.3';
const PREFIX = `ankka-mcp-gateway/releases/${CHANNEL}/${RELEASE}/`;
const PATH = `/__ankka/publish/${PLAN_SHA}`;
const PUBLIC_KEY = 'A'.repeat(43);
const ACCOUNT_ID = '0123456789abcdef0123456789abcdef';

const identity: R2PublicationIdentity = Object.freeze({
  accountId: ACCOUNT_ID,
  artifactSha256: ARTIFACT_SHA,
  bucketName: 'ankka-gateway-releases',
  channel: CHANNEL,
  keyId: 'gateway-release-canary-1',
  objectPlanSha256: PLAN_SHA,
  prefix: PREFIX,
  publicKey: PUBLIC_KEY,
  release: RELEASE,
  releaseEnvelopeSha256: ENVELOPE_SHA,
  schemaVersion: 1,
});

function bucket(): R2ReleaseBucket {
  return {
    get: async () => null,
    list: async () => ({ objects: [], truncated: false, delimitedPrefixes: [] }),
    put: async () => {
      throw new Error('publisher fixture must not write through the bucket');
    },
  };
}

function successfulPublisher(calls: { count: number }): R2PublicationFunction {
  return async (input) => {
    calls.count += 1;
    expect(input.bucket).toBeDefined();
    expect(input.blobs).toEqual([]);
    expect(input.objectPlan).toEqual({ exact: true });
    return {
      schemaVersion: 1,
      status: 'published',
      channel: CHANNEL,
      release: RELEASE,
      prefix: PREFIX,
      intentKey: 'ankka-mcp-gateway/publication-intents/v1/canary/gateway-v1.2.3.json',
      objectCount: 2,
      totalByteSize: 100,
      objectPlanSha256: PLAN_SHA,
      createdAt: input.clock.now(),
    };
  };
}

function operator(calls = { count: 0 }) {
  return {
    calls,
    worker: createR2PublicationOperator({
      blobs: [],
      objectPlan: { exact: true },
      objectPlanSha256: PLAN_SHA,
      publicationIdentity: identity,
      publish: successfulPublisher(calls),
    }),
  };
}

describe('ephemeral R2 publication operator', () => {
  it('serves only the fixed query-free bodyless POST capability', async () => {
    const cases = [
      new Request(`http://127.0.0.1:5732${PATH}?release=other`, { method: 'POST' }),
      new Request(`http://127.0.0.1:5732${PATH}?`, { method: 'POST' }),
      new Request('http://127.0.0.1:5732/__ankka/publish', { method: 'POST' }),
      new Request(`http://127.0.0.1:5732${PATH}/extra`, { method: 'POST' }),
    ];
    for (const request of cases) {
      const current = operator();
      const response = await current.worker.fetch(request, { RELEASE_BUCKET: bucket() });
      expect(response.status).toBe(404);
      expect(current.calls.count).toBe(0);
    }

    const wrongMethod = operator();
    const get = await wrongMethod.worker.fetch(
      new Request(`http://127.0.0.1:5732${PATH}`),
      { RELEASE_BUCKET: bucket() },
    );
    expect(get.status).toBe(405);
    expect(get.headers.get('allow')).toBe('POST');
    expect(wrongMethod.calls.count).toBe(0);

    const withBody = operator();
    const body = await withBody.worker.fetch(
      new Request(`http://127.0.0.1:5732${PATH}`, {
        method: 'POST',
        body: new Uint8Array([0x7b]),
      }),
      { RELEASE_BUCKET: bucket() },
    );
    expect(body.status).toBe(400);
    await expect(body.json()).resolves.toEqual({ error: 'request_body_not_allowed' });
    expect(withBody.calls.count).toBe(0);

    // wrangler dev delivers a bodiless POST as an empty stream; that is still
    // "no body" and must not be rejected or counted as the invocation.
    const emptyStream = operator();
    const declaredEmpty = await emptyStream.worker.fetch(
      new Request(`http://127.0.0.1:5732${PATH}`, {
        method: 'POST',
        body: new Uint8Array(0),
      }),
      { RELEASE_BUCKET: bucket() },
    );
    expect(declaredEmpty.status).toBe(200);
    expect(emptyStream.calls.count).toBe(1);
  });

  it('requires the exact single R2 binding before burning the one-shot invocation', async () => {
    const current = operator();
    const request = () => new Request(`http://127.0.0.1:5732${PATH}`, { method: 'POST' });
    const extraEnvironment = {
      RELEASE_BUCKET: bucket(),
      EXTRA: 'forbidden',
    };
    const extraBinding = await current.worker.fetch(request(), extraEnvironment);
    expect(extraBinding.status).toBe(503);
    expect(current.calls.count).toBe(0);

    const success = await current.worker.fetch(request(), { RELEASE_BUCKET: bucket() });
    expect(success.status).toBe(200);
    expect(current.calls.count).toBe(1);
  });

  it('invokes the frozen publisher only once and emits the exact verified public receipt', async () => {
    const current = operator();
    const request = () => new Request(`http://127.0.0.1:5732${PATH}`, { method: 'POST' });
    const first = await current.worker.fetch(request(), { RELEASE_BUCKET: bucket() });
    expect(first.status).toBe(200);
    await expect(first.json()).resolves.toEqual({ ...identity, status: 'published' });
    expect(current.calls.count).toBe(1);

    const second = await current.worker.fetch(request(), { RELEASE_BUCKET: bucket() });
    expect(second.status).toBe(409);
    await expect(second.json()).resolves.toEqual({ error: 'publication_already_invoked' });
    expect(current.calls.count).toBe(1);
  });

  it('fails closed if the publisher result does not match the embedded release identity', async () => {
    const worker = createR2PublicationOperator({
      blobs: [],
      objectPlan: { exact: true },
      objectPlanSha256: PLAN_SHA,
      publicationIdentity: identity,
      publish: async (input) => ({
        ...(await successfulPublisher({ count: 0 })(input)),
        release: 'gateway-v9.9.9',
      }),
    });
    const response = await worker.fetch(
      new Request(`http://127.0.0.1:5732${PATH}`, { method: 'POST' }),
      { RELEASE_BUCKET: bucket() },
    );
    expect(response.status).toBe(500);
    await expect(response.json()).resolves.toEqual({ error: 'publication_result_invalid' });
  });
});

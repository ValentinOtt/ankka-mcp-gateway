import * as v from 'valibot';

import { jsonValueSchema, type JsonObject } from './boundary';
import type { PreparedCustomerBootstrapClaim } from './customer-bootstrap-request';
import type { CustomerGatewayOwnershipStorage } from './customer-gateway-ownership-state';
import { customerPayloadEnvironment, type CustomerPayloadZone } from './customer-payload-environment';
import type { CustomerStage2ReadinessVerdict } from './customer-stage2-converger';

/**
 * The payload keeps one Durable Object per installation for the receipt it
 * writes during the bootstrap and reads back for verification and teardown,
 * and a separate management object for status, control and sources. The
 * shell runs the bootstrap and the verification in the installation object
 * through the two internal requests below so the receipt lands where the
 * final runtime looks for it. Neither request can arrive from outside: the
 * Worker entry forwards only the install routes to any object.
 */
export const CUSTOMER_INSTALLATION_BOOTSTRAP_PATH = '/__ankka/bootstrap';
export const CUSTOMER_INSTALLATION_VERIFY_PATH = '/__ankka/install/verify-receipt';
export const CUSTOMER_INSTALLATION_OBJECT_ORIGIN = 'https://admin-state.invalid';

export function customerInstallationObjectName(installId: string): string {
  return `v1:${installId}`;
}

export interface CustomerInstallationObjectStub {
  fetch(request: Request): Promise<Response>;
}

/** What the payload requires beyond the object's own bindings: the zone and the readiness word. */
export interface CustomerPayloadRuntimeEnvironment {
  readonly CLOUDFLARE_ZONE_ID: string;
  readonly CLOUDFLARE_ZONE_NAME: string;
  readonly ZERO_TRUST_READY: 'true';
}

/** The payload functions the installation object runs, exactly as shipped. */
export interface CustomerInstallationPayload {
  readonly processBootstrap: (
    request: Request,
    env: CustomerPayloadRuntimeEnvironment,
    storage: CustomerGatewayOwnershipStorage,
  ) => Promise<Response>;
  readonly verifyReceipt: (
    claim: JsonObject,
    env: CustomerPayloadRuntimeEnvironment,
    storage: CustomerGatewayOwnershipStorage,
    nowMs: number,
  ) => Promise<CustomerStage2ReadinessVerdict>;
}

export interface CustomerInstallationObjectPorts<Env extends object> {
  /** The object's own bindings; the zone and readiness come from the request's target. */
  readonly bootstrapEnv: Env;
  readonly storage: CustomerGatewayOwnershipStorage;
  readonly payload: CustomerInstallationPayload;
  readonly now: () => number;
}

/** The verification claim as the converger prepares it, with the request-local grant. */
export type CustomerInstallationVerifyClaim = PreparedCustomerBootstrapClaim & {
  readonly cloudflareAccessToken: string;
};

const zoneSchema = v.strictObject({
  accountId: v.pipe(v.string(), v.regex(/^[a-f0-9]{32}$/u)),
  zoneId: v.pipe(v.string(), v.regex(/^[a-f0-9]{32}$/u)),
  zoneName: v.pipe(v.string(), v.minLength(3), v.maxLength(253)),
});
const bootstrapClaimTargetSchema = v.looseObject({ target: zoneSchema });
const verifyBodySchema = v.strictObject({
  schemaVersion: v.literal(1),
  claim: v.record(v.string(), jsonValueSchema),
  target: zoneSchema,
});
const verdictSchema = v.strictObject({
  verified: v.boolean(),
  reason: v.union([v.pipe(v.string(), v.regex(/^[a-z][a-z0-9_]{0,120}$/u)), v.null()]),
});
const MAX_BODY_BYTES = 256 * 1024;

function json(status: number, value: JsonObject): Response {
  return new Response(JSON.stringify(value), {
    status,
    headers: { 'cache-control': 'no-store', 'content-type': 'application/json; charset=utf-8' },
  });
}

function boundedJsonText(text: string) {
  if (text.length > MAX_BODY_BYTES) return null;
  try {
    return v.safeParse(jsonValueSchema, JSON.parse(text));
  } catch {
    return null;
  }
}

async function boundedJson(request: Request) {
  return boundedJsonText(await request.text());
}

/**
 * Answers the two internal requests when the object is asked one; null for
 * anything else so the caller falls through to its own routes.
 */
export async function handleCustomerInstallationObjectRequest<Env extends object>(
  request: Request,
  ports: CustomerInstallationObjectPorts<Env>,
): Promise<Response | null> {
  const url = new URL(request.url);
  if (request.method === 'POST' && url.pathname === CUSTOMER_INSTALLATION_BOOTSTRAP_PATH) {
    const parsed = boundedJsonText(await request.clone().text());
    const claim = parsed === null || !parsed.success ? null : v.safeParse(bootstrapClaimTargetSchema, parsed.output);
    if (claim === null || !claim.success) return json(400, { schemaVersion: 1, error: 'bootstrap_rejected' });
    return ports.payload.processBootstrap(
      request,
      customerPayloadEnvironment(ports.bootstrapEnv, claim.output.target),
      ports.storage,
    );
  }
  if (request.method === 'POST' && url.origin === CUSTOMER_INSTALLATION_OBJECT_ORIGIN &&
      url.pathname === CUSTOMER_INSTALLATION_VERIFY_PATH) {
    const parsed = await boundedJson(request);
    const body = parsed === null || !parsed.success ? null : v.safeParse(verifyBodySchema, parsed.output);
    if (body === null || !body.success) return json(400, { schemaVersion: 1, error: 'verify_rejected' });
    const verdict = await ports.payload.verifyReceipt(
      body.output.claim,
      customerPayloadEnvironment(ports.bootstrapEnv, body.output.target),
      ports.storage,
      ports.now(),
    );
    return json(200, { verified: verdict.verified, reason: verdict.reason });
  }
  return null;
}

/** Runs the receipt verification inside the installation object. */
export async function verifyReceiptInInstallationObject(
  stub: CustomerInstallationObjectStub,
  input: {
    readonly claim: CustomerInstallationVerifyClaim;
    readonly target: CustomerPayloadZone & { readonly accountId: string };
  },
): Promise<CustomerStage2ReadinessVerdict> {
  let response: Response;
  try {
    response = await stub.fetch(new Request(`${CUSTOMER_INSTALLATION_OBJECT_ORIGIN}${CUSTOMER_INSTALLATION_VERIFY_PATH}`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ schemaVersion: 1, claim: input.claim, target: input.target }),
    }));
  } catch {
    return { verified: false, reason: 'verify_object_unreachable' };
  }
  if (response.status !== 200) return { verified: false, reason: `verify_object_http_${response.status}` };
  const parsed = boundedJsonText(await response.text());
  const verdict = parsed === null || !parsed.success ? null : v.safeParse(verdictSchema, parsed.output);
  if (verdict === null || !verdict.success) return { verified: false, reason: 'verify_object_invalid' };
  return verdict.output;
}

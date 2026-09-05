import * as v from 'valibot';

import { canonicalJson } from './canonical-json';
import { base64UrlDecode, base64UrlEncode, constantTimeEqual, openCustomerTeardownCookie, pkceChallenge, randomBase64Url, sealCustomerTeardownCookie, sha256 } from './crypto';
import { validCustomerBootstrapRelayAuthorization } from './customer-bootstrap-router';
import { beginCustomerBootstrapRelay } from './customer-bootstrap-relay-client';
import { exchangeCustomerCloudflareAuthorizationCode, verifyCustomerCloudflareGrantAccountAccess, type CustomerCloudflareTransport, type EphemeralCustomerCloudflareGrant } from './customer-cloudflare-grant';
import { CUSTOMER_INSTALL_OAUTH_CALLBACK_PATH } from './customer-install-paths';
import { operationSignature } from './customer-operation-secrets';
import { customerTeardownKindsSchema, type CustomerTeardownAttempt, type CustomerTeardownAttemptPort } from './customer-teardown-attempt';
import type { ReceiptOwnedCloudflareResourceKind } from './cloudflare-operation-authority';
import { readBoundedText } from './http';

export const CUSTOMER_TEARDOWN_PATH = '/__ankka/operation/teardown';
export const CUSTOMER_TEARDOWN_START_PATH = `${CUSTOMER_TEARDOWN_PATH}/start`;
export const CUSTOMER_TEARDOWN_COOKIE = '__Host-ankka_customer_teardown';
const token = v.pipe(v.string(), v.regex(/^[A-Za-z0-9_-]{43}$/u));
const actionId = v.pipe(v.string(), v.regex(/^action_[A-Za-z0-9_-]{32}$/u));
const time = v.pipe(v.number(), v.safeInteger(), v.minValue(0));
const claimSchema = v.strictObject({
  schemaVersion: v.literal(3), actionType: v.literal('gateway_teardown'),
  actionId, actionKey: token, actorEmail: v.pipe(v.string(), v.email(), v.maxLength(256)),
  accountId: v.pipe(v.string(), v.regex(/^[a-f0-9]{32}$/u)),
  installationId: v.pipe(v.string(), v.regex(/^acg-[a-f0-9]{24}$/u)),
  controlPlaneOrigin: v.pipe(v.string(), v.url()), managementOrigin: v.pipe(v.string(), v.url()),
  workerName: v.pipe(v.string(), v.minLength(1), v.maxLength(63)),
  workersSubdomain: v.pipe(v.string(), v.minLength(1), v.maxLength(63)),
  gatewayName: v.pipe(v.string(), v.minLength(1), v.maxLength(256)),
  portalHostname: v.pipe(v.string(), v.minLength(3), v.maxLength(253)), expiresAt: time,
});
const proofSchema = v.looseObject({
  schemaVersion: v.literal(1), actionId, status: v.literal('authorized'), receiptResourceKinds: customerTeardownKindsSchema,
});
const completionSchema = v.strictObject({
  schemaVersion: v.literal(1), actionId, status: v.literal('gateway_removed'),
  installationId: v.pipe(v.string(), v.regex(/^acg-[a-f0-9]{24}$/u)),
  removedResourceCount: v.pipe(v.number(), v.safeInteger(), v.minValue(1)),
  readyReceiptChecksum: v.pipe(v.string(), v.regex(/^sha256:[a-f0-9]{64}$/u)),
  dependencyResourcesHash: v.pipe(v.string(), v.regex(/^sha256:[a-f0-9]{64}$/u)),
});
const progressSchema = v.strictObject({ schemaVersion: v.literal(1), actionId, status: v.literal('removing'),
  installationId: v.pipe(v.string(), v.regex(/^acg-[a-f0-9]{24}$/u)),
  progress: v.pipe(v.string(), v.regex(/^sha256:[a-f0-9]{64}$/u)),
});
// Below the callback's 1,000 internal-subrequest allowance, including proof,
// settlement and ownership reads. Each command has its own external budget.
const MAX_REMOVAL_PASSES = 768;
export type CustomerTeardownCompletion = v.InferOutput<typeof completionSchema>;
export interface CustomerTeardownConfig {
  readonly accountId: string; readonly installId: string; readonly managementOrigin: string;
  readonly controlPlaneOrigin: string; readonly workerName: string; readonly workersSubdomain: string;
  readonly publicClientId: string; readonly encryptionKey: string;
}
export interface CustomerTeardownDependencies {
  readonly attempts: CustomerTeardownAttemptPort;
  readonly transport: CustomerCloudflareTransport;
  readonly now?: () => number;
  readonly assertOperational: () => Promise<void>;
  readonly command: (command: 'prove' | 'apply' | 'settle', body: string, signature: string) => Promise<Response>;
  readonly issueRelayTicket: (kinds: readonly ReceiptOwnedCloudflareResourceKind[]) => Promise<{ readonly relayTicket: string; readonly expiresAt: number }>;
  readonly signHandoff: (completion: CustomerTeardownCompletion, priorGrantRevocationUnconfirmed: boolean) => Promise<string>;
}
function headers(type = 'application/json; charset=utf-8'): Headers {
  return new Headers({ 'content-type': type, 'cache-control': 'no-store', 'referrer-policy': 'no-referrer',
    'content-security-policy': "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
    'x-content-type-options': 'nosniff', 'cross-origin-opener-policy': 'same-origin' });
}
function json(status: number, body: { readonly error?: string; readonly authorizationUrl?: string }, cookie?: string): Response {
  const responseHeaders = headers();
  if (cookie !== undefined) responseHeaders.set('set-cookie', cookie);
  return new Response(JSON.stringify({ schemaVersion: 1, ...body }), { status, headers: responseHeaders });
}
function clearCookie(): string { return `${CUSTOMER_TEARDOWN_COOKIE}=; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=0`; }
function cookieValue(request: Request): string | null {
  const matches = (request.headers.get('cookie') ?? '').split(';').map((part) => part.trim()).filter((part) => part.startsWith(`${CUSTOMER_TEARDOWN_COOKIE}=`));
  return matches.length === 1 ? (matches[0]?.slice(CUSTOMER_TEARDOWN_COOKIE.length + 1) ?? null) : null;
}
export function customerTeardownCookiePresent(request: Request): boolean { return cookieValue(request) !== null; }
function redirect(location: string): Response {
  const responseHeaders = headers(); responseHeaders.set('location', location); responseHeaders.set('set-cookie', clearCookie());
  return new Response(null, { status: 303, headers: responseHeaders });
}
function page(failed: boolean): Response {
  const nonce = crypto.randomUUID().replaceAll('-', '');
  const responseHeaders = headers('text/html; charset=utf-8');
  responseHeaders.set('content-security-policy', `default-src 'none'; script-src 'nonce-${nonce}'; connect-src 'self'; style-src 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'`);
  return new Response(`<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>Remove your Ankka Gateway</title><style>body{font:16px/1.5 system-ui,sans-serif;max-width:42rem;margin:5rem auto;padding:0 1.25rem;color:#171713}button{font:inherit;padding:.75rem 1rem}a{color:inherit}</style><h1>Remove your Ankka Gateway</h1><p>This removes your gateway's Portal, registered MCP servers, and their access policies and DNS record. Managed BigQuery bridges and their stored Google key copies are removed too. Your team will lose its gateway connections. Your upstream services and their data stay in their own accounts.</p><p>Two temporary Cloudflare approvals are required. The first removes the gateway's connected resources. The second removes its management page, stored configuration, and Worker. Each phase checks the saved installation receipts before deleting resources.</p><p id="message">${failed ? 'Removal needs fresh authorization. Return to Settings and review removal again. Saved progress will be checked before it continues.' : 'You can cancel before granting access. Once removal begins, deleted resources cannot be restored by cancelling.'}</p><button id="authorize"${failed ? ' hidden' : ''}>Authorize removal in Cloudflare</button><p><a href="/settings">Back to Settings</a></p><script nonce="${nonce}">(()=>{const handoff=location.hash.slice(1);history.replaceState(null,'',location.pathname);const button=document.querySelector('#authorize');const message=document.querySelector('#message');button.addEventListener('click',async()=>{button.disabled=true;try{if(!/^[A-Za-z0-9_-]{40,8192}$/.test(handoff))throw new Error();const response=await fetch('${CUSTOMER_TEARDOWN_START_PATH}',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({schemaVersion:1,handoff}),credentials:'same-origin',cache:'no-store'});const result=await response.json();if(!response.ok||typeof result.authorizationUrl!=='string')throw new Error();location.replace(result.authorizationUrl)}catch{message.textContent='Removal could not start. Return to Settings and review removal again.';button.hidden=true}})})();</script></html>`, { headers: responseHeaders });
}

/** The gateway removes dependencies; only signed, verified completion can authorize the hosted root phase. */
export function createCustomerTeardownRouter(config: CustomerTeardownConfig, dependencies: CustomerTeardownDependencies) {
  const now = dependencies.now ?? Date.now;
  for (const value of [config.managementOrigin, config.controlPlaneOrigin]) {
    const url = new URL(value);
    if (url.protocol !== 'https:' || url.origin !== value || url.username !== '' || url.password !== '') throw new Error('teardown_config_invalid');
  }
  const gatewayCallback = `${config.managementOrigin}${CUSTOMER_INSTALL_OAUTH_CALLBACK_PATH}`;
  async function command(kind: 'prove' | 'apply' | 'settle', identity: { readonly actionId: string; readonly actorEmail: string; readonly actionExpiresAt: number }, key: string, extra: { readonly requestId?: string; readonly cloudflareAccessToken?: string } = {}) {
    const body = canonicalJson({ schemaVersion: 1, command: kind, actionId: identity.actionId, actionKey: key,
      actorEmail: identity.actorEmail, accountId: config.accountId, installationId: config.installId,
      issuedAt: now(), expiresAt: identity.actionExpiresAt, ...extra });
    return dependencies.command(kind, body, await operationSignature(key, body));
  }
  async function settle(attempt: CustomerTeardownAttempt, key: string, unconfirmed: boolean): Promise<void> {
    if (!await dependencies.attempts.compareAndSet(attempt.revision, { ...attempt, revision: attempt.revision + 1,
      phase: 'settled', priorGrantRevocationUnconfirmed: attempt.priorGrantRevocationUnconfirmed || unconfirmed })) throw new Error('teardown_attempt_conflict');
    const response = await command('settle', attempt, key); await response.body?.cancel();
    if (response.status !== 200) throw new Error('teardown_settlement_failed');
  }
  async function start(request: Request): Promise<Response> {
    if (request.headers.get('origin') !== config.managementOrigin ||
        ![null, 'same-origin'].includes(request.headers.get('sec-fetch-site')) ||
        request.headers.get('content-type')?.split(';', 1)[0]?.trim().toLowerCase() !== 'application/json') return json(403, { error: 'origin_required' });
    const raw = await readBoundedText(new Response(request.body, { headers: request.headers }), 'bad_request', 12 * 1024);
    const body = v.parse(v.strictObject({ schemaVersion: v.literal(1), handoff: v.pipe(v.string(), v.regex(/^[A-Za-z0-9_-]{40,8192}$/u)) }), JSON.parse(raw));
    const claim = v.parse(claimSchema, JSON.parse(new TextDecoder().decode(base64UrlDecode(body.handoff))));
    const at = now();
    if (claim.accountId !== config.accountId || claim.installationId !== config.installId ||
        claim.managementOrigin !== config.managementOrigin || claim.controlPlaneOrigin !== config.controlPlaneOrigin ||
        claim.workerName !== config.workerName || claim.workersSubdomain !== config.workersSubdomain ||
        claim.expiresAt <= at || claim.expiresAt > at + 10 * 60 * 1000) return json(400, { error: 'teardown_invalid' });
    const current = await dependencies.attempts.read();
    if (current !== null && current.phase !== 'settled' && current.expiresAt > at) return json(409, { error: 'teardown_attempt_pending' });
    const identity = { actionId: claim.actionId, actorEmail: claim.actorEmail, actionExpiresAt: claim.expiresAt };
    const proofResponse = await command('prove', identity, claim.actionKey);
    if (proofResponse.status !== 200) { await proofResponse.body?.cancel(); return json(409, { error: 'teardown_proof_rejected' }); }
    const proof = v.parse(proofSchema, JSON.parse(await readBoundedText(proofResponse, 'bad_request', 512 * 1024)));
    if (proof.actionId !== claim.actionId || new Set(proof.receiptResourceKinds).size !== proof.receiptResourceKinds.length) throw new Error('teardown_proof_invalid');
    const verifier = randomBase64Url(32); const state = randomBase64Url(32);
    const attempt: CustomerTeardownAttempt = { schemaVersion: 1, revision: (current?.revision ?? 0) + 1,
      ...identity, attemptId: `attempt_${randomBase64Url(18)}`, expiresAt: claim.expiresAt,
      stateHash: await sha256(state), verifierHash: await sha256(verifier), phase: 'authorizing',
      receiptResourceKinds: proof.receiptResourceKinds,
      priorGrantRevocationUnconfirmed: current?.priorGrantRevocationUnconfirmed === true || current?.phase === 'exchanging' };
    if (!await dependencies.attempts.compareAndSet(current?.revision ?? null, attempt)) return json(409, { error: 'teardown_attempt_pending' });
    try {
      const ticket = await dependencies.issueRelayTicket(attempt.receiptResourceKinds);
      if (!Number.isSafeInteger(ticket.expiresAt) || ticket.expiresAt <= now()) throw new Error('teardown_ticket_invalid');
      const challenge = await pkceChallenge(verifier);
      const relay = await beginCustomerBootstrapRelay({ publicClientId: config.publicClientId,
        relayTicket: ticket.relayTicket, gatewayState: state, pkceChallenge: challenge, gatewayCallback,
        operation: 'uninstall', receiptResourceKinds: attempt.receiptResourceKinds, transport: dependencies.transport });
      if (!validCustomerBootstrapRelayAuthorization(relay, config.publicClientId, challenge, 'uninstall', attempt.receiptResourceKinds)) throw new Error('teardown_relay_invalid');
      const sealed = await sealCustomerTeardownCookie(config.encryptionKey, { schemaVersion: 1, purpose: 'customer_teardown',
        attemptId: attempt.attemptId, expiresAt: attempt.expiresAt, verifier, actionKey: claim.actionKey });
      return json(200, { authorizationUrl: relay.authorizationUrl }, `${CUSTOMER_TEARDOWN_COOKIE}=${sealed}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=${Math.max(1, Math.floor((attempt.expiresAt - now()) / 1000))}`);
    } catch {
      await settle(attempt, claim.actionKey, false);
      return json(503, { error: 'teardown_authorization_unavailable' }, clearCookie());
    }
  }
  async function callback(request: Request, url: URL): Promise<Response> {
    const sealed = cookieValue(request);
    if (sealed === null || sealed.length > 4096) return json(400, { error: 'teardown_callback_rejected' }, clearCookie());
    const cookie = await openCustomerTeardownCookie(config.encryptionKey, sealed, now());
    const attempt = await dependencies.attempts.read();
    const state = url.searchParams.get('state') ?? ''; const code = url.searchParams.get('code') ?? '';
    const denied = url.searchParams.get('error') === 'authorization_rejected' && code === '';
    if (attempt === null || attempt.phase !== 'authorizing' || attempt.attemptId !== cookie.attemptId ||
        attempt.expiresAt !== cookie.expiresAt || attempt.expiresAt <= now() || !v.is(token, state) ||
        !constantTimeEqual(await sha256(state), attempt.stateHash) ||
        !constantTimeEqual(await sha256(cookie.verifier), attempt.verifierHash) || url.searchParams.size !== 2 ||
        (!denied && (url.searchParams.has('error') || !/^[A-Za-z0-9._~-]{8,4096}$/u.test(code)))) return json(400, { error: 'teardown_callback_rejected' }, clearCookie());
    if (denied) { await settle(attempt, cookie.actionKey, false); return redirect(`${config.managementOrigin}${CUSTOMER_TEARDOWN_PATH}?result=recovery_required`); }
    const exchanging: CustomerTeardownAttempt = { ...attempt, revision: attempt.revision + 1, phase: 'exchanging' };
    if (!await dependencies.attempts.compareAndSet(attempt.revision, exchanging)) return json(409, { error: 'teardown_callback_rejected' }, clearCookie());
    let grant: EphemeralCustomerCloudflareGrant | null = null;
    let completion: CustomerTeardownCompletion | null = null; let revoked = false;
    try {
      grant = await exchangeCustomerCloudflareAuthorizationCode({ clientId: config.publicClientId, code, verifier: cookie.verifier,
        operation: 'uninstall', receiptResourceKinds: attempt.receiptResourceKinds, transport: dependencies.transport });
      grant.assertUsable();
      completion = await grant.withAccessToken(async (accessToken) => {
        await verifyCustomerCloudflareGrantAccountAccess({ accessToken, expectedAccountId: config.accountId,
          operation: 'uninstall', workerName: config.workerName, transport: dependencies.transport });
        const requestId = randomBase64Url(16);
        const seen = new Set<string>();
        for (let pass = 0; pass < MAX_REMOVAL_PASSES; pass++) {
          grant?.assertUsable();
          if (now() >= attempt.expiresAt) throw new Error('teardown_expired');
          const response = await command('apply', attempt, cookie.actionKey, { requestId, cloudflareAccessToken: accessToken });
          if (response.status !== 200) { await response.body?.cancel(); throw new Error('teardown_apply_failed'); }
          const result = v.parse(v.union([completionSchema, progressSchema]), JSON.parse(await readBoundedText(response, 'bad_request', 8192)));
          if (result.actionId !== attempt.actionId || result.installationId !== config.installId) throw new Error('teardown_apply_invalid');
          if (result.status === 'gateway_removed') return result;
          if (seen.has(result.progress)) throw new Error('teardown_no_progress');
          seen.add(result.progress);
        }
        throw new Error('teardown_pass_limit');
      });
    } catch { /* A durable pending boundary is resumed only with a fresh grant. */ }
    finally {
      if (grant !== null) {
        try { await grant.revoke({ clientId: config.publicClientId, transport: dependencies.transport }); revoked = true; }
        catch { /* Keep the warning across every subsequent attempt. */ }
        finally { grant.discard(); }
      }
    }
    await settle(exchanging, cookie.actionKey, !revoked);
    if (completion !== null && revoked) {
      const handoff = await dependencies.signHandoff(completion, exchanging.priorGrantRevocationUnconfirmed);
      return redirect(`${config.controlPlaneOrigin}/teardown#${base64UrlEncode(new TextEncoder().encode(handoff))}`);
    }
    return redirect(`${config.managementOrigin}${CUSTOMER_TEARDOWN_PATH}?result=recovery_required`);
  }
  return { async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);
    if (url.origin !== config.managementOrigin || url.hash !== '' || url.username !== '' || url.password !== '') return json(404, { error: 'not_found' });
    try {
      await dependencies.assertOperational();
      if (request.method === 'GET' && url.pathname === CUSTOMER_TEARDOWN_PATH &&
          (url.search === '' || url.search === '?result=recovery_required')) return page(url.search !== '');
      if (request.method === 'POST' && url.pathname === CUSTOMER_TEARDOWN_START_PATH && url.search === '') return await start(request);
      if (request.method === 'GET' && url.pathname === CUSTOMER_INSTALL_OAUTH_CALLBACK_PATH) return await callback(request, url);
      return json(404, { error: 'not_found' });
    } catch { return json(409, { error: 'teardown_recovery_required' }); }
  } };
}

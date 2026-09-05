import type { CustomerBootstrapCallbackOutcome } from './customer-bootstrap-router';
import { CUSTOMER_INSTALL_ROOT_PATH, CUSTOMER_INSTALL_STATUS_PATH } from './customer-install-paths';

function secureHeaders(contentType: string): Headers {
  return new Headers({
    'cache-control': 'no-store',
    'content-security-policy': "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
    'content-type': contentType,
    'cross-origin-opener-policy': 'same-origin',
    'referrer-policy': 'no-referrer',
    'x-content-type-options': 'nosniff',
  });
}

function scriptLiteral<Value>(value: Value): string {
  return JSON.stringify(value).replaceAll('<', '\\u003c');
}

/**
 * Where the second Cloudflare approval lands. The passes run behind alarms,
 * so the page follows the status route until the attempt settles; the
 * temporary workers.dev address can close before the final runtime upload.
 * Losing that address is not proof of readiness, so the page asks the
 * administrator to check the management page without claiming success.
 */
export function customerInstallProgressPage(
  managementHostname: string,
  outcome: CustomerBootstrapCallbackOutcome,
  cookies: readonly string[],
): Response {
  const nonce = crypto.randomUUID().replaceAll('-', '');
  const headers = secureHeaders('text/html; charset=utf-8');
  headers.set('content-security-policy', `default-src 'none'; script-src 'nonce-${nonce}'; connect-src 'self'; style-src 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'`);
  for (const cookie of cookies) headers.append('set-cookie', cookie);
  if (outcome.status === 'INCOMPLETE' && outcome.failureCode === 'authorization_rejected') {
    headers.set('content-security-policy', "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'");
    return new Response(`<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><meta name="referrer" content="no-referrer"><title>Cloudflare approval did not complete</title><style>body{font:16px/1.5 system-ui,sans-serif;max-width:42rem;margin:5rem auto;padding:0 1.25rem;color:#171713}a{color:#1d4ed8}</style><main><h1>Cloudflare approval did not complete</h1><p>Cloudflare did not authorize this setup attempt. Return to your gateway setup to review the settings and try the approval again.</p><p><a href="${CUSTOMER_INSTALL_ROOT_PATH}">Return to gateway setup</a></p></main></html>`, {
      status: 200,
      headers,
    });
  }
  const initial = scriptLiteral({
    status: outcome.status,
    failure: outcome.failureCode === null ? null : { code: outcome.failureCode, reason: outcome.failureReason },
  });
  return new Response(`<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><meta name="referrer" content="no-referrer"><title>Install Ankka Gateway</title><style>body{font:16px/1.5 system-ui,sans-serif;max-width:42rem;margin:5rem auto;padding:0 1.25rem;color:#171713}code{font:.9375em ui-monospace,monospace}a{color:#1d4ed8}</style><h1 id="title">Finishing your Ankka Gateway</h1><p id="message">Cloudflare approved the install. Setting up the Gateway takes a few minutes; this page updates itself.</p><p id="detail"></p><script nonce="${nonce}">(()=>{const management=${scriptLiteral(`https://${managementHostname}/`)};const title=document.querySelector('#title');const message=document.querySelector('#message');const detail=document.querySelector('#detail');let misses=0;let sawConverging=false;const show=(state)=>{if(state.status==='READY'){title.textContent='Your Ankka Gateway is ready';message.textContent='';const link=document.createElement('a');link.href=management;link.textContent='Open your management page';message.append(link);detail.textContent='';return true}if(state.status==='INCOMPLETE'){title.textContent='Setup did not complete';message.textContent='The Gateway stopped before it was ready. Return to deploy.ankka.ai to remove this install and try again.';const failure=state.failure;detail.textContent=failure?'Reason: '+failure.code+(failure.reason?' / '+failure.reason:''):'';return true}sawConverging=true;return false};const closed=()=>{title.textContent='Check your gateway';message.textContent='This temporary setup address is no longer reachable. Open your management page to check whether setup completed. If your gateway is not ready, return to deploy.ankka.ai to review the installation.';const link=document.createElement('a');link.href=management;link.textContent=management;detail.textContent='';detail.append(link)};const poll=async()=>{try{const response=await fetch(${scriptLiteral(CUSTOMER_INSTALL_STATUS_PATH)},{credentials:'omit',cache:'no-store'});if(!response.ok)throw new Error();misses=0;if(show(await response.json()))return}catch{misses+=1;if(sawConverging&&misses>=3){closed();return}}setTimeout(poll,3000)};if(!show(${initial}))setTimeout(poll,3000)})();</script></html>`, {
    status: 200,
    headers,
  });
}

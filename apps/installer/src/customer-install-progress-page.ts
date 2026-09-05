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
 * Losing that address is not proof of readiness. The fixed management page
 * continues checking same-origin status behind Access before opening the dashboard.
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
  return new Response(`<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><meta name="referrer" content="no-referrer"><title>Install Ankka Gateway</title><style>body{font:16px/1.5 system-ui,sans-serif;max-width:42rem;margin:5rem auto;padding:0 1.25rem;color:#171713}code{font:.9375em ui-monospace,monospace}a{color:#1d4ed8}</style><h1 id="title">Finishing your Ankka Gateway</h1><p id="message">Cloudflare approved the install. Setting up the Gateway takes a few minutes; this page updates itself.</p><p id="detail"></p><script nonce="${nonce}">
(()=>{
  const management=${scriptLiteral(`https://${managementHostname}/?setup=finishing`)};
  const title=document.querySelector('#title');
  const message=document.querySelector('#message');
  const detail=document.querySelector('#detail');
  let misses=0;
  let active=true;
  let timer;
  let controller;
  const stop=()=>{active=false;clearTimeout(timer);if(controller)controller.abort()};
  addEventListener('pagehide',stop);
  const openManagement=()=>{
    if(!active)return;
    stop();
    title.textContent='Opening your management page';
    message.textContent='Your management page will check that setup finished before opening your dashboard. Cloudflare may ask you to sign in.';
    const link=document.createElement('a');
    link.href=management;
    link.textContent='Open your management page';
    detail.textContent='';
    detail.append(link);
    location.replace(management);
  };
  const show=(state)=>{
    if(state.status==='READY'){openManagement();return true}
    if(state.status==='INCOMPLETE'){
      title.textContent='Setup did not complete';
      message.textContent='The Gateway stopped before it was ready. Return to deploy.ankka.ai to remove this install and try again.';
      const failure=state.failure;
      detail.textContent=failure?'Reason: '+failure.code+(failure.reason?' / '+failure.reason:''):'';
      return true;
    }
    if(state.status!=='CONVERGING')throw new Error();
    return false;
  };
  const poll=async()=>{
    controller=new AbortController();
    const timeout=setTimeout(()=>controller.abort(),5000);
    try{
      const response=await fetch(${scriptLiteral(CUSTOMER_INSTALL_STATUS_PATH)},{credentials:'same-origin',cache:'no-store',redirect:'error',signal:controller.signal});
      if(!response.ok)throw new Error();
      const state=await response.json();
      if(!active)return;
      if(show(state))return;
      misses=0;
    }catch{
      if(!active)return;
      misses+=1;
      if(misses>=3){openManagement();return}
    }finally{clearTimeout(timeout)}
    if(active)timer=setTimeout(poll,3000);
  };
  if(!show(${initial}))timer=setTimeout(poll,3000);
})();
</script></html>`, {
    status: 200,
    headers,
  });
}

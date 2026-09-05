'use strict';

const ROUTES = new Set(['/', '/gateway', '/review', '/deploy', '/result']);
const STEP_ROUTES = Object.freeze(['/', '/review', '/deploy', '/result']);
const CUSTOMER_INSTALL_PATH = '/__ankka/install';
const HANDOFF_POLL_MS = 3000;
const HANDOFF_POLL_MAX_MS = 15000;
const BROWSER_READINESS_TIMEOUT_MS = 5000;
const BROWSER_READINESS_MAX_BYTES = 8192;

const state = {
  session: null,
  csrf: null,
  now: 0,
  clockOffset: 0,
  route: ROUTES.has(window.location.pathname) ? window.location.pathname : '/',
  busy: false,
  authorizationUrl: null,
  authorizationExpiresAt: null,
  authorizationKind: null,
  handoffUrl: null,
  handoffTimer: null,
  handoffController: null,
  handoffFailed: false,
  agentToolsRegistered: false,
  agentToolsController: null,
  agentToolsRegistration: null,
  agentPageActive: true,
};

const byId = (id) => document.getElementById(id);
const notice = byId('live-notice');
const OBJECT_TAG = Object.prototype.toString;
const FUNCTION_SOURCE = Function.prototype.toString;

function isText(value) {
  return Object(value) !== value && OBJECT_TAG.call(value) === '[object String]';
}

function isCallable(value) {
  try {
    FUNCTION_SOURCE.call(value);
    return true;
  } catch {
    return false;
  }
}

function text(value) {
  return isText(value) ? value : '';
}

const SELECTION_ERROR_MESSAGES = Object.freeze({
  active_zone_required: 'Your Cloudflare account needs an active domain before you can install a gateway.',
  zone_discovery_rejected: 'Cloudflare did not allow domain discovery. Check that you approved domain read access for the selected account.',
  zone_discovery_limit: 'This setup supports accounts with up to 100 active domains. Use the source deployment flow for larger accounts.',
  account_worker_subdomain_create_rejected: 'Cloudflare could not register your Workers subdomain. Try again, or register one in Workers & Pages.',
  selection_contract_invalid: 'The setup form is incomplete. Check every field.',
  gateway_name_invalid: 'Enter a gateway name between 2 and 80 letters, numbers, spaces, or hyphens.',
  admin_email_invalid: 'Enter a valid administrator email.',
  additional_admin_emails_invalid: 'Enter valid additional administrator emails.',
  zone_name_invalid: 'Enter the storefront domain you host on Cloudflare, such as example.com.',
  management_hostname_invalid: 'Enter a valid management hostname beneath your domain.',
  portal_hostname_invalid: 'Enter a valid portal hostname beneath your domain.',
  gateway_hostnames_invalid: 'Use two different hostnames beneath the storefront domain.',
});

const API_ERROR_MESSAGES = Object.freeze({
  rate_limited: 'This installer is receiving too many requests. Wait one minute, then retry.',
  abuse_controls_unavailable: 'The installer request protection is temporarily unavailable. Wait and retry; no Cloudflare change was attempted.',
  session_conflict: 'This step no longer matches the saved setup. Reload the page to continue from the current step.',
  session_expired: 'The setup session expired. Reload the page to start a fresh approval.',
  session_invalid: 'The setup session could not be validated. Reload the page before continuing.',
  csrf_invalid: 'The page is out of date. Reload it before continuing.',
  origin_invalid: 'The request did not come from this installer page. Reload it before continuing.',
  bad_request: 'The installer rejected the request. Check the form and try again.',
  release_unavailable: 'The signed gateway release is not available right now. Try again in a few minutes.',
  release_invalid: 'The signed gateway release could not be verified. Try again later.',
  callback_invalid: 'Cloudflare returned an incomplete approval. Start a fresh approval in this browser.',
  bootstrap_failed: 'Your Gateway did not answer with the expected identity, so the incomplete install must be removed before retrying.',
  internal_error: 'The installer encountered an internal error.',
});

const FAILURE_MESSAGES = Object.freeze({
  attempt_expired: 'The Cloudflare approval window closed before it was completed.',
  authorization_rejected: 'The Cloudflare approval was declined.',
  callback_invalid: 'Cloudflare returned an approval that did not match this browser session.',
  cleanup_failed: 'The removal of the incomplete install could not be completed.',
  grant_invalid: 'Cloudflare granted permissions different from those requested, or more than one account was selected.',
  provision_failed: 'The Gateway shell could not be installed with the temporary permission.',
  revocation_unconfirmed: 'The temporary permission could not be confirmed as revoked. Check Cloudflare Connected Applications before retrying.',
  session_expired: 'The setup session expired.',
});

const LOCAL_AGENT_ERRORS = Object.freeze({
  invalid_arguments: 'The tool arguments do not match its declared input schema.',
  action_unavailable: 'This action is not available in the current setup step.',
  page_inactive: 'This installer page is no longer active. Reopen it before continuing.',
  action_cancelled: 'The action was cancelled before it started.',
  installer_busy: 'Another installer action is still running.',
  plan_unavailable: 'Describe the gateway and create the review plan first.',
});

const AGENT_API_ERROR_CODES = new Set([
  ...Object.keys(API_ERROR_MESSAGES),
  'bootstrap_not_ready', 'install_mutations_disabled',
]);

class ApiError extends Error {
  constructor(status, payload) {
    super('request_failed');
    this.name = 'ApiError';
    this.status = status;
    this.code = isText(payload?.code) ? payload.code : 'internal_error';
    this.reason = isText(payload?.reason) ? payload.reason : null;
    this.payload = payload;
  }
}

function showNotice(message, tone = 'neutral') {
  notice.textContent = message;
  notice.classList.toggle('notice-error', tone === 'error');
  notice.classList.toggle('notice-success', tone === 'success');
  notice.hidden = message.length === 0;
}

function setBusy(value) {
  state.busy = value;
  for (const button of document.querySelectorAll('button')) button.disabled = value;
}

async function api(path, { method = 'GET', body, signal } = {}) {
  const headers = { accept: 'application/json' };
  if (method !== 'GET') {
    if (!state.csrf) throw new ApiError(401, { code: 'session_invalid' });
    headers['x-csrf-token'] = state.csrf;
  }
  if (body !== undefined) headers['content-type'] = 'application/json';
  const request = { method, headers, credentials: 'same-origin', redirect: 'error' };
  if (body !== undefined) request.body = JSON.stringify(body);
  if (signal) request.signal = signal;
  const response = await fetch(path, request);
  let payload = null;
  try { payload = await response.json(); } catch { /* The fixed UI error is enough. */ }
  if (!response.ok) throw new ApiError(response.status, payload);
  if (!payload || payload.schemaVersion !== 1) throw new ApiError(502, null);
  if (isText(payload.csrfToken)) state.csrf = payload.csrfToken;
  if (Number.isSafeInteger(payload.now)) {
    state.now = payload.now;
    state.clockOffset = payload.now - Date.now();
  }
  if (payload.session && isText(payload.session.phase)) state.session = payload.session;
  return payload;
}

function apiErrorMessage(error, fallback) {
  if (!(error instanceof ApiError)) return fallback;
  if (error.reason && Object.hasOwn(SELECTION_ERROR_MESSAGES, error.reason)) {
    return SELECTION_ERROR_MESSAGES[error.reason];
  }
  return API_ERROR_MESSAGES[error.code] ?? `${fallback} Diagnostic: ${text(error.code) || 'internal_error'}.`;
}

function agentError(error) {
  if (error instanceof ApiError) {
    const code = AGENT_API_ERROR_CODES.has(error.code) ? error.code : 'internal_error';
    const reason = Object.hasOwn(SELECTION_ERROR_MESSAGES, error.reason ?? '') ? error.reason : null;
    return {
      code,
      reason,
      message: reason ? SELECTION_ERROR_MESSAGES[reason] : (API_ERROR_MESSAGES[code] ?? 'The installer request was rejected.'),
      retryable: error.code === 'rate_limited' || error.code === 'bootstrap_not_ready' || error.status >= 500,
    };
  }
  const code = error instanceof Error && Object.hasOwn(LOCAL_AGENT_ERRORS, error.message)
    ? error.message
    : 'internal_error';
  return {
    code,
    reason: null,
    message: LOCAL_AGENT_ERRORS[code] ?? 'The installer action could not complete.',
    retryable: code === 'installer_busy',
  };
}

function route(path, replace = false) {
  const target = ROUTES.has(path) ? path : '/';
  if (replace) window.history.replaceState(null, '', target);
  else window.history.pushState(null, '', target);
  state.route = target;
  render();
  byId('main').focus({ preventScroll: true });
  window.scrollTo({ top: 0, behavior: 'auto' });
}

function clearChildren(element) {
  while (element.firstChild) element.removeChild(element.firstChild);
}

function summaryRows(container, rows) {
  clearChildren(container);
  for (const [label, value] of rows) {
    if (!value) continue;
    const row = document.createElement('div');
    row.className = 'summary-row';
    const key = document.createElement('span');
    key.textContent = label;
    const strong = document.createElement('strong');
    strong.textContent = value;
    row.append(key, strong);
    container.append(row);
  }
  container.hidden = container.childElementCount === 0;
}

function formatWhen(timestamp) {
  if (!Number.isSafeInteger(timestamp)) return '';
  try {
    return new Date(timestamp).toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' });
  } catch {
    return '';
  }
}

function minutesLeft(timestamp) {
  if (!Number.isSafeInteger(timestamp)) return 0;
  return Math.max(0, Math.ceil((timestamp - (state.now || Date.now())) / 60000));
}

function validAuthorizationUrl(value) {
  try {
    const url = new URL(value);
    return url.origin === 'https://dash.cloudflare.com' && !url.username && !url.password && !url.port &&
      url.pathname === '/oauth2/auth'
      ? url.href
      : null;
  } catch {
    return null;
  }
}

function validHandoffUrl(value, bootstrapOrigin) {
  try {
    const url = new URL(value);
    const expected = new URL(bootstrapOrigin);
    return url.protocol === 'https:' && url.origin === expected.origin &&
      !url.username && !url.password && !url.port &&
      url.pathname === CUSTOMER_INSTALL_PATH && url.search === '' &&
      /^#[A-Za-z0-9_-]{40,65536}$/u.test(url.hash)
      ? url.href
      : null;
  } catch {
    return null;
  }
}

function session() {
  return state.session;
}

function phase() {
  return session()?.phase ?? 'draft';
}

function selectionBasics() {
  return session()?.selection?.basics ?? null;
}

function planSummary() {
  return session()?.plan ?? null;
}

function provisionSummary() {
  return session()?.provision ?? null;
}

async function loadSession() {
  await api('/api/session');
  state.handoffFailed = false;
}

async function beginAuthorization(kind) {
  const path = kind === 'cleanup' ? '/api/cleanup' : '/api/bootstrap';
  const result = await api(path, { method: 'POST', body: {} });
  const url = validAuthorizationUrl(result.authorizationUrl);
  if (!url) throw new ApiError(502, { code: 'internal_error' });
  state.authorizationUrl = url;
  state.authorizationExpiresAt = Number.isSafeInteger(result.expiresAt) ? result.expiresAt : null;
  state.authorizationKind = kind;
  return { authorizationUrl: url, expiresAt: state.authorizationExpiresAt };
}

function stopHandoffPolling() {
  if (state.handoffTimer !== null) {
    window.clearTimeout(state.handoffTimer);
    state.handoffTimer = null;
  }
  state.handoffController?.abort();
  state.handoffController = null;
}

function checkHandoffExpiry(provision) {
  if (!Number.isSafeInteger(provision?.capabilityExpiresAt) ||
      Date.now() + state.clockOffset >= provision.capabilityExpiresAt) {
    throw new ApiError(410, { code: 'session_expired' });
  }
}

function browserReadinessUrl(provision) {
  try {
    const url = new URL(provision.bootstrapOrigin);
    const labels = url.hostname.split('.');
    if (url.protocol !== 'https:' || url.username || url.password || url.port ||
        url.pathname !== '/' || url.search || url.hash || labels.length !== 4 ||
        labels[0] !== provision.workerName || !/^[a-z0-9-]{1,63}$/u.test(labels[1]) ||
        labels.slice(2).join('.') !== 'workers.dev') return null;
    return new URL(CUSTOMER_INSTALL_PATH + '/status', url).href;
  } catch {
    return null;
  }
}

// A Cloudflare-to-Cloudflare read can succeed before this browser can establish
// TLS. Probe the exact public Worker first, while the one-time handoff is still
// safely retained by the installer. No cookie, grant, or fragment goes here.
async function checkBrowserReadiness(provision, releaseId, signal) {
  const url = browserReadinessUrl(provision);
  if (!url || !isText(releaseId)) throw new ApiError(502, { code: 'internal_error' });
  const controller = new AbortController();
  const abort = () => controller.abort();
  signal.addEventListener('abort', abort, { once: true });
  if (signal.aborted) abort();
  const timer = window.setTimeout(abort, BROWSER_READINESS_TIMEOUT_MS);
  let reader;
  try {
    const response = await fetch(url, {
      method: 'GET', mode: 'cors', credentials: 'omit', redirect: 'error',
      cache: 'no-store', referrerPolicy: 'no-referrer', signal: controller.signal,
    });
    if (response.status !== 200 || !response.body) throw new ApiError(503, { code: 'bootstrap_not_ready' });
    reader = response.body.getReader();
    const decoder = new TextDecoder();
    let body = '', size = 0;
    for (;;) {
      const chunk = await reader.read();
      if (chunk.done) break;
      size += chunk.value.byteLength;
      if (size > BROWSER_READINESS_MAX_BYTES) throw new ApiError(502, { code: 'bootstrap_failed' });
      body += decoder.decode(chunk.value, { stream: true });
    }
    body += decoder.decode();
    let value;
    try { value = JSON.parse(body); } catch { throw new ApiError(503, { code: 'bootstrap_not_ready' }); }
    if (value?.schemaVersion !== 1 || value.role !== 'customer-gateway-bootstrap' ||
        value.status !== 'INCOMPLETE' || value.installId !== provision.installId ||
        value.release !== releaseId || !/^[A-Za-z0-9_-]{43}$/u.test(text(value.ownershipPublicKey)) ||
        (value.failure !== undefined && value.failure !== null)) {
      throw new ApiError(502, { code: 'bootstrap_failed' });
    }
  } catch (error) {
    if (error instanceof ApiError) throw error;
    throw new ApiError(503, { code: 'bootstrap_not_ready' });
  } finally {
    window.clearTimeout(timer);
    signal.removeEventListener('abort', abort);
    controller.abort();
    await reader?.cancel().catch(() => { /* The response may already be closed. */ });
  }
}

async function pollHandoff(delayMs = 0) {
  if (state.handoffController !== null) return;
  stopHandoffPolling();
  if (phase() !== 'provisioned' || state.route !== '/result' || !state.agentPageActive) return;
  state.handoffTimer = window.setTimeout(async () => {
    state.handoffTimer = null;
    const controller = new AbortController();
    state.handoffController = controller;
    let retryAfter = null;
    try {
      const provision = provisionSummary();
      checkHandoffExpiry(provision);
      await checkBrowserReadiness(provision, planSummary()?.releaseId, controller.signal);
      if (controller.signal.aborted) return;
      checkHandoffExpiry(provision);
      const result = await api('/api/bootstrap/handoff', { signal: controller.signal });
      if (controller.signal.aborted) return;
      const handoff = validHandoffUrl(result.handoffUrl, provision.bootstrapOrigin);
      if (!handoff) throw new ApiError(502, { code: 'internal_error' });
      state.handoffUrl = handoff;
      await loadSession().catch(() => { /* The handoff itself succeeded. */ });
      if (controller.signal.aborted) return;
      render();
      window.location.assign(handoff);
    } catch (error) {
      if (controller.signal.aborted) return;
      if (error instanceof ApiError && error.code === 'bootstrap_not_ready') {
        retryAfter = Number.isSafeInteger(error.payload?.retryAfterMs)
          ? Math.min(HANDOFF_POLL_MAX_MS, Math.max(HANDOFF_POLL_MS, error.payload.retryAfterMs))
          : HANDOFF_POLL_MS;
        renderResult();
      } else {
        await loadSession().catch(() => { /* The failure below is still shown. */ });
        if (controller.signal.aborted) return;
        state.handoffFailed = true;
        showNotice(apiErrorMessage(error, 'Finishing secure setup did not complete.'), 'error');
        render();
      }
    } finally {
      if (state.handoffController === controller) state.handoffController = null;
    }
    if (retryAfter !== null) await pollHandoff(retryAfter);
  }, delayMs);
}

function renderSteps() {
  const current = state.route === '/gateway' ? '/' : state.route;
  for (const link of document.querySelectorAll('.steps a[data-route-link]')) {
    const target = link.dataset.routeLink;
    const index = STEP_ROUTES.indexOf(target);
    const currentIndex = STEP_ROUTES.indexOf(current);
    link.classList.toggle('is-current', target === current);
    link.classList.toggle('is-complete', index !== -1 && index < currentIndex);
    if (target === current) link.setAttribute('aria-current', 'step');
    else link.removeAttribute('aria-current');
  }
}

function renderWelcome() {
  byId('save-gateway').textContent = 'Deploy to Cloudflare';
}

function renderReview() {
  const basics = selectionBasics();
  const plan = planSummary();
  summaryRows(byId('review-summary'), [
    ['Gateway name', basics?.gatewayName],
    ['Storefront domain', basics?.zoneName],
    ['Management page', basics?.managementHostname],
    ['MCP portal', basics?.portalHostname],
    ['Administrator', basics?.adminEmail],
    ['Signed release', plan?.releaseId],
  ]);
  const expiry = byId('plan-expiry');
  expiry.textContent = plan
    ? `This review plan performs no writes. It stays valid until ${formatWhen(plan.expiresAt)} and is refreshed automatically when you connect.`
    : 'Prepare your initial Gateway deployment to continue.';
  byId('connect-cloudflare').hidden = !plan;
  byId('review-missing').hidden = Boolean(plan);
}

function renderDeploy() {
  const link = byId('authorization-link');
  const handoff = byId('authorization-handoff');
  const url = state.authorizationUrl;
  if (url) {
    link.href = url;
    link.hidden = false;
    handoff.hidden = false;
  } else {
    link.removeAttribute('href');
    link.hidden = true;
    handoff.hidden = true;
  }
  const expiresAt = state.authorizationExpiresAt ?? session()?.attempt?.expiresAt ?? null;
  byId('approval-expiry').textContent = expiresAt
    ? `This approval link is valid for about ${minutesLeft(expiresAt)} minutes (until ${formatWhen(expiresAt)}). If it lapses, start a fresh approval; nothing is left behind.`
    : '';
  byId('deploy-title').textContent = state.authorizationKind === 'cleanup'
    ? 'Approve the removal in Cloudflare'
    : 'Approve the first step in Cloudflare';
  byId('deploy-lede').textContent = state.authorizationKind === 'cleanup'
    ? 'Cloudflare will ask for one temporary permission to edit Workers. Ankka uses it once to remove exactly the incomplete Gateway shell it installed earlier, then revokes it.'
    : 'Choose one Cloudflare account and approve temporary permissions to edit Workers and read domains. Ankka deploys the initial Worker and discovers your domains, then revokes the grant before handing you over.';
}

function renderResult() {
  const current = phase();
  const provision = provisionSummary();
  const basics = selectionBasics();
  const failure = session()?.failure ?? null;
  const cleanup = session()?.cleanup ?? null;
  const title = byId('result-title');
  const intro = byId('result-intro');
  const detail = byId('result-detail');
  const stage = byId('operation-stage');
  const finish = byId('finish-setup');
  const fresh = byId('fresh-approval');
  const beginCleanup = byId('begin-cleanup');
  const gatewayLink = byId('continue-gateway');
  const cleanupLink = byId('cleanup-link');
  const describe = byId('describe-again');
  for (const element of [finish, fresh, beginCleanup, gatewayLink, cleanupLink, describe, stage]) element.hidden = true;
  summaryRows(byId('result-summary'), [
    ['Gateway name', basics?.gatewayName],
    ['Installed in account', provision ? 'Your Cloudflare account' : ''],
    ['Gateway shell', provision?.workerName],
    ['Management page', basics?.managementHostname],
  ]);
  byId('result-eyebrow').textContent = 'Installation status';
  switch (current) {
    case 'provisioned': {
      title.textContent = 'Ankka Gateway installed';
      intro.textContent = 'The first temporary permission was revoked. Your Gateway is starting inside your Cloudflare account.';
      stage.hidden = false;
      byId('operation-title').textContent = state.handoffUrl ? 'Ready to finish secure setup' : 'Waiting for your secure Gateway address';
      byId('operation-detail').textContent = state.handoffUrl
        ? 'Continue to your Gateway. It will ask Cloudflare for the second temporary approval so it can finish its own setup.'
        : `Cloudflare is preparing your new address. This browser checks its secure connection every few seconds and continues automatically when it is ready. Your setup link stays valid until ${formatWhen(provision?.capabilityExpiresAt)}.`;
      detail.textContent = 'Keep this browser open. The handoff is released only to this browser, and only once.';
      if (state.handoffUrl) {
        finish.hidden = false;
      }
      break;
    }
    case 'handed_off': {
      title.textContent = 'Setup continues on your Gateway';
      intro.textContent = 'The one-time handoff was released to your Gateway in this browser. The second approval and the rest of the setup happen there, inside your Cloudflare account.';
      detail.textContent = 'If you closed that tab, open your Gateway to continue. This installer holds no Cloudflare permission and nothing else to hand over.';
      if (provision?.bootstrapOrigin) {
        gatewayLink.href = provision.bootstrapOrigin;
        gatewayLink.hidden = false;
      }
      describe.hidden = false;
      break;
    }
    case 'failed': {
      title.textContent = 'The approval did not complete';
      intro.textContent = FAILURE_MESSAGES[failure?.code] ?? 'The Cloudflare approval did not complete.';
      detail.textContent = 'Nothing was left running. Start a fresh approval whenever you are ready; the same setup is kept.';
      fresh.hidden = !planSummary();
      describe.hidden = false;
      break;
    }
    case 'cleanup_required': {
      title.textContent = 'Remove the incomplete install first';
      intro.textContent = cleanup?.reason === 'handoff_rejected'
        ? 'Your Gateway shell did not answer with the identity Ankka recorded, so it must be removed before a new attempt.'
        : 'The one-time handoff to your Gateway was lost before setup finished, so the incomplete Gateway shell must be removed before a new attempt.';
      detail.textContent = 'Cloudflare will ask once more for the single temporary permission. Ankka removes exactly the shell it recorded, verifies it is gone, and revokes the permission. Nothing else in your account is touched.';
      if (state.authorizationUrl && state.authorizationKind === 'cleanup') {
        cleanupLink.href = state.authorizationUrl;
        cleanupLink.hidden = false;
      } else {
        beginCleanup.hidden = false;
      }
      if (failure?.code === 'cleanup_failed') {
        detail.textContent = `${FAILURE_MESSAGES.cleanup_failed} You can approve the removal again.`;
      }
      break;
    }
    case 'authorizing': {
      title.textContent = 'Approval still pending';
      intro.textContent = 'Cloudflare has not returned an approval for this browser yet.';
      detail.textContent = 'Finish the approval in the Cloudflare tab, or start a fresh approval here.';
      fresh.hidden = false;
      break;
    }
    default: {
      title.textContent = 'Nothing to finish yet';
      intro.textContent = 'Describe your gateway and connect Cloudflare to install it.';
      detail.textContent = '';
      describe.hidden = false;
    }
  }
  byId('result-actions').hidden = [finish, fresh, beginCleanup, gatewayLink, cleanupLink, describe].every((element) => element.hidden);
}

function render() {
  const current = state.route === '/gateway' ? '/' : state.route;
  for (const panel of document.querySelectorAll('[data-route]')) {
    panel.hidden = panel.dataset.route !== current;
  }
  renderSteps();
  if (current === '/') renderWelcome();
  if (current === '/review') renderReview();
  if (current === '/deploy') renderDeploy();
  if (current === '/result') renderResult();
  if (current === '/result' && phase() === 'provisioned' && state.handoffUrl === null && !state.handoffFailed) void pollHandoff();
  else if (current !== '/result') stopHandoffPolling();
}

function initialRoute() {
  const current = phase();
  if (current === 'provisioned' || current === 'handed_off' || current === 'failed' || current === 'cleanup_required') {
    return '/result';
  }
  if (current === 'authorizing') return state.route === '/result' ? '/result' : '/deploy';
  if (state.route === '/review' && !planSummary()) return '/';
  if (state.route === '/deploy' || state.route === '/result') return planSummary() ? '/review' : '/';
  return state.route;
}

async function runAction(pending, action, fallback) {
  if (state.busy) throw new Error('installer_busy');
  setBusy(true);
  showNotice(pending);
  try {
    const result = await action();
    showNotice('');
    return result;
  } catch (error) {
    showNotice(apiErrorMessage(error, fallback), 'error');
    throw error;
  } finally {
    setBusy(false);
  }
}

byId('gateway-form').addEventListener('submit', (event) => {
  event.preventDefault();
  void startApproval('bootstrap');
});

async function startApproval(kind) {
  try {
    const prepared = await runAction('Creating your Cloudflare approval link…', () => beginAuthorization(kind),
      'The Cloudflare approval could not be started.');
    if (kind === 'cleanup') render();
    else route('/deploy');
    window.location.assign(prepared.authorizationUrl);
  } catch { /* The notice already explains the failure. */ }
}

byId('connect-cloudflare').addEventListener('click', () => { void startApproval('bootstrap'); });
byId('fresh-approval').addEventListener('click', () => { void startApproval('bootstrap'); });
byId('restart-approval').addEventListener('click', () => { void startApproval('bootstrap'); });
byId('begin-cleanup').addEventListener('click', () => { void startApproval('cleanup'); });
byId('describe-again').addEventListener('click', async () => {
  try {
    await runAction('Starting a new deployment…', () => api('/api/session/new', { method: 'POST', body: {} }),
      'A new deployment could not be started.');
    state.authorizationUrl = null;
    state.authorizationExpiresAt = null;
    state.authorizationKind = null;
    state.handoffUrl = null;
    state.handoffFailed = false;
    route('/');
  } catch { /* Keep the current session visible when restarting is rejected. */ }
});
byId('finish-setup').addEventListener('click', () => {
  if (state.handoffUrl) window.location.assign(state.handoffUrl);
});

document.addEventListener('click', (event) => {
  const target = event.target.closest('[data-route-link], [data-go]');
  if (!target || state.busy) return;
  const path = target.dataset.routeLink ?? target.dataset.go;
  if (!ROUTES.has(path)) return;
  event.preventDefault();
  route(path);
});

window.addEventListener('popstate', () => {
  state.route = ROUTES.has(window.location.pathname) ? window.location.pathname : '/';
  render();
});

function validAgentInput(schema, input) {
  if (input === undefined || input === null) return Object.keys(schema.properties).length === 0 || !(schema.required ?? []).length;
  if (Object(input) !== input || Array.isArray(input)) return false;
  for (const key of Object.keys(input)) {
    if (!Object.hasOwn(schema.properties, key)) return false;
    const rule = schema.properties[key];
    const value = input[key];
    if (rule.type === 'string') {
      if (!isText(value) || value.length < (rule.minLength ?? 0) || value.length > (rule.maxLength ?? Infinity)) return false;
    } else {
      return false;
    }
  }
  for (const key of schema.required ?? []) {
    if (!Object.hasOwn(input, key)) return false;
  }
  return true;
}

function publicStatus() {
  const current = session();
  return {
    phase: phase(),
    gateway: selectionBasics() ? {
      gatewayName: selectionBasics().gatewayName,
      zoneName: selectionBasics().zoneName,
      managementHostname: selectionBasics().managementHostname,
      portalHostname: selectionBasics().portalHostname,
      adminEmail: selectionBasics().adminEmail,
    } : null,
    plan: planSummary() ? { planId: planSummary().planId, releaseId: planSummary().releaseId, expiresAt: planSummary().expiresAt } : null,
    installed: provisionSummary() ? {
      workerName: provisionSummary().workerName,
      gatewayOrigin: provisionSummary().bootstrapOrigin,
      handoffExpiresAt: provisionSummary().capabilityExpiresAt,
    } : null,
    failure: current?.failure?.code ?? null,
    cleanup: current?.cleanup ? { reason: current.cleanup.reason, completed: current.cleanup.completedAt !== null } : null,
    approvals: {
      first: 'Temporary Cloudflare permissions to edit Workers and read domains, used for the initial setup, then revoked.',
      second: 'Requested by your own Gateway to finish its setup; never held by Ankka.',
    },
  };
}

async function runAgentAction(pending, action) {
  if (!state.agentPageActive) throw new Error('page_inactive');
  const result = await runAction(pending, action, 'The installer action could not complete.');
  return JSON.stringify({ ok: true, ...result });
}

function unregisterAgentTools() {
  state.agentToolsController?.abort();
  state.agentToolsController = null;
  state.agentToolsRegistered = false;
}

async function registerAgentTools() {
  const modelContext = document.modelContext;
  if (!state.agentPageActive || state.agentToolsRegistered || !modelContext || !isCallable(modelContext.registerTool)) return;
  if (state.agentToolsRegistration) {
    await state.agentToolsRegistration;
    if (state.agentPageActive && !state.agentToolsRegistered) return registerAgentTools();
    return;
  }
  const controller = new AbortController();
  state.agentToolsController = controller;
  const tools = [
    {
      name: 'get_installer_status',
      description: 'Read the current Ankka MCP Gateway setup step: the initial deployment, its release plan, the installed Gateway shell, and any failure or pending removal. Performs no writes.',
      inputSchema: { type: 'object', properties: {}, additionalProperties: false },
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false, untrustedContentHint: false },
      execute: async () => {
        await loadSession();
        render();
        return JSON.stringify({ ok: true, status: publicStatus() });
      },
    },
    {
      name: 'prepare_deployment',
      description: 'Prepare a deployment of the initial Gateway Worker. Gateway name, domain selection, and administrators are configured later inside the Worker. Performs no Cloudflare writes.',
      inputSchema: { type: 'object', properties: {}, additionalProperties: false },
      annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: false, untrustedContentHint: false },
      execute: async () => runAgentAction('Preparing your Gateway deployment…', async () => {
        await api('/api/plan', { method: 'POST', body: {} });
        route('/review', true);
        return { status: publicStatus() };
      }),
    },
    {
      name: 'begin_authorization',
      description: 'Create the first Cloudflare approval link: temporary permissions to edit Workers and read available domains, used for the initial deployment and then revoked. Return the link to the user; do not open or approve it for them.',
      inputSchema: { type: 'object', properties: {}, additionalProperties: false },
      annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: true, untrustedContentHint: false },
      execute: async () => runAgentAction('Creating your Cloudflare approval link…', async () => {
        const prepared = await beginAuthorization('bootstrap');
        route('/deploy', true);
        return {
          status: 'user_authorization_required',
          authorizationUrl: prepared.authorizationUrl,
          expiresAt: prepared.expiresAt,
          instruction: 'Send authorizationUrl to the user. After they approve in Cloudflare, poll get_installer_status until phase is provisioned, then call finish_secure_setup in this browser.',
        };
      }),
    },
    {
      name: 'finish_secure_setup',
      description: 'After the Gateway shell is installed, check whether it is ready and, if so, continue this browser to the Gateway for the second approval. The one-time handoff is never returned to the caller.',
      inputSchema: { type: 'object', properties: {}, additionalProperties: false },
      annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: true, untrustedContentHint: false },
      execute: async () => runAgentAction('Checking whether your Gateway is ready…', async () => {
        await loadSession();
        if (phase() !== 'provisioned') throw new Error('action_unavailable');
        route('/result', true);
        await pollHandoff();
        return { status: 'checking', instruction: 'The browser continues to the Gateway automatically once it answers.' };
      }),
    },
    {
      name: 'begin_cleanup',
      description: 'When an incomplete Gateway shell must be removed, create the Cloudflare approval link for the single temporary permission that removes exactly the recorded shell. Return the link to the user; do not open or approve it for them.',
      inputSchema: { type: 'object', properties: {}, additionalProperties: false },
      annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: true, untrustedContentHint: false },
      execute: async () => runAgentAction('Creating your Cloudflare removal link…', async () => {
        await loadSession();
        if (phase() !== 'cleanup_required') throw new Error('action_unavailable');
        const prepared = await beginAuthorization('cleanup');
        route('/result', true);
        return {
          status: 'user_authorization_required',
          authorizationUrl: prepared.authorizationUrl,
          expiresAt: prepared.expiresAt,
          instruction: 'Send authorizationUrl to the user. After they approve, poll get_installer_status until phase returns to draft.',
        };
      }),
    },
  ];
  const registration = (async () => {
    try {
      for (const tool of tools) {
        if (controller.signal.aborted) return;
        await modelContext.registerTool({
          ...tool,
          execute: async (input, options = {}) => {
            try {
              if (controller.signal.aborted) throw new Error('page_inactive');
              if (options.signal?.aborted) throw new Error('action_cancelled');
              if (!validAgentInput(tool.inputSchema, input)) throw new Error('invalid_arguments');
              return await tool.execute(input ?? {});
            } catch (error) {
              return JSON.stringify({ ok: false, error: agentError(error) });
            }
          },
        }, { signal: controller.signal });
      }
      if (!controller.signal.aborted) state.agentToolsRegistered = true;
    } catch {
      controller.abort();
      if (state.agentToolsController === controller) state.agentToolsController = null;
    }
  })();
  state.agentToolsRegistration = registration;
  try { await registration; } finally { state.agentToolsRegistration = null; }
}

window.addEventListener('pagehide', () => {
  state.agentPageActive = false;
  stopHandoffPolling();
  unregisterAgentTools();
});
for (const event of ['pageshow', 'focus']) {
  window.addEventListener(event, () => {
    if (event === 'pageshow') {
      state.agentPageActive = true;
      render();
    }
    if (state.session) void registerAgentTools().catch(() => { /* The existing UI remains available. */ });
  });
}

(async () => {
  showNotice('Loading installer…');
  try {
    await loadSession();
    showNotice('');
    route(initialRoute(), true);
    void registerAgentTools().catch(() => { /* The existing UI remains available. */ });
  } catch (error) {
    showNotice(apiErrorMessage(error, 'The installer could not start.'), 'error');
    render();
  }
})();

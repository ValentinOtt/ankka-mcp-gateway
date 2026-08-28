const ROUTES = new Set(['/', '/gateway', '/review', '/deploy', '/manage', '/result']);
const OAUTH_HANDOFF_PATH = '/oauth/handoff';
const OAUTH_CALLBACK_PATH = '/oauth/callback';
const STEP_ROUTES = Object.freeze(['/gateway', '/review', '/deploy']);
const callbackStream = window.location.pathname === OAUTH_CALLBACK_PATH;
const state = {
  session: null,
  discovery: null,
  csrf: null,
  draft: null,
  selectedTargetIdHash: null,
  route: callbackStream
    ? '/result'
    : ROUTES.has(window.location.pathname) ? window.location.pathname : '/',
  busy: false,
  pollTimer: null,
  pollFailures: 0,
  callbackStreamActive: callbackStream,
  agentToolsRegistered: false,
};

const byId = (id) => document.getElementById(id);
const notice = byId('live-notice');

const SELECTION_ERROR_MESSAGES = Object.freeze({
  selection_shape_invalid: 'The configuration shape is incomplete. Review every gateway field.',
  gateway_name_invalid: 'Enter a gateway name between 2 and 80 letters, numbers, spaces, or hyphens.',
  admin_email_invalid: 'Enter a valid primary administrator email.',
  additional_admin_emails_invalid: 'Enter at most 19 valid additional administrator emails.',
  zone_name_invalid: 'Enter a valid active DNS zone.',
  management_hostname_invalid: 'Enter a valid management hostname.',
  portal_hostname_invalid: 'Enter a valid portal hostname.',
  gateway_hostnames_invalid: 'Use distinct management and portal hostnames beneath the active zone.',
});

const LOCAL_AGENT_ERRORS = Object.freeze({
  installer_busy: 'Another installer action is still running.',
  cloudflare_discovery_required: 'Connect Cloudflare and choose a discovered account and zone first.',
  plan_unavailable: 'Create and review a fresh plan first.',
  plan_hash_mismatch: 'The supplied plan hash does not match the retained reviewed plan.',
  removal_plan_unavailable: 'Create and review a fresh removal plan first.',
  removal_plan_hash_mismatch: 'The supplied removal plan hash does not match the retained plan.',
});

const API_ERROR_MESSAGES = Object.freeze({
  rate_limited: 'This installer is receiving too many requests. Wait one minute, then retry.',
  abuse_controls_unavailable: 'The installer request protection is temporarily unavailable. Wait and retry; no Cloudflare change was attempted.',
});

const DISCOVERY_FAILURE_MESSAGES = Object.freeze({
  oauth_denied: 'Cloudflare authorization was declined. Create a fresh sign-in link when you are ready.',
  oauth_exchange_failed: 'Cloudflare returned to the installer, but the authorization code exchange failed. Check that the deployed OAuth client ID and secret belong to the same Cloudflare OAuth client.',
  oauth_grant_invalid: 'Cloudflare returned a grant that did not contain exactly the requested read-only discovery permissions. Approve every permission shown on a fresh sign-in.',
  oauth_revoke_failed: 'Discovery stopped because automatic grant revocation could not be confirmed. Revoke Ankka MCP Gateway in Cloudflare Connected Applications before retrying.',
  target_account_ambiguous: 'Cloudflare returned an account list the installer could not safely use.',
  target_zone_invalid: 'Cloudflare returned an active-zone list the installer could not safely use.',
  oauth_state_invalid: 'The Cloudflare sign-in response no longer matched this installer session. Create one fresh link and complete it in the same browser session.',
  callback_invalid: 'Cloudflare returned an incomplete sign-in response. Create a fresh link and try again.',
  session_expired: 'The installer session expired before Cloudflare discovery completed. Reload the installer and create a fresh link.',
  session_invalid: 'The installer session could not be validated. Reload the installer before creating another link.',
  internal_error: 'The installer encountered an internal error while completing Cloudflare discovery.',
});

function discoveryFailureMessage(code) {
  const detail = DISCOVERY_FAILURE_MESSAGES[code] ?? 'Cloudflare discovery did not complete.';
  return `${detail} Diagnostic: ${text(code) || 'internal_error'}.`;
}

class ApiError extends Error {
  constructor(status, payload) {
    super('request_failed');
    this.name = 'ApiError';
    this.status = status;
    this.code = typeof payload?.code === 'string' ? payload.code : 'internal_error';
    this.reason = typeof payload?.reason === 'string' ? payload.reason : null;
  }
}

function text(value) {
  return typeof value === 'string' ? value : '';
}

function list(value, lowercase = false) {
  if (typeof value !== 'string') return [];
  const entries = value.split(/[\n,]/u)
    .map((entry) => entry.trim())
    .filter(Boolean)
    .map((entry) => lowercase ? entry.toLowerCase() : entry);
  return [...new Set(entries)].sort();
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

async function api(path, { method = 'GET', body, extraHeaders = {} } = {}) {
  const headers = { accept: 'application/json' };
  if (method !== 'GET') {
    if (!state.csrf) throw new Error('session_unavailable');
    headers['x-csrf-token'] = state.csrf;
  }
  if (body !== undefined) headers['content-type'] = 'application/json';
  Object.assign(headers, extraHeaders);
  const response = await fetch(path, {
    method,
    headers,
    credentials: 'same-origin',
    redirect: 'error',
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
  let payload = null;
  try { payload = await response.json(); } catch { /* The fixed UI error is enough. */ }
  if (!response.ok) throw new ApiError(response.status, payload);
  if (!payload || payload.schemaVersion !== 1) throw new ApiError(502, null);
  if (typeof payload.csrf === 'string') state.csrf = payload.csrf;
  if (payload.capabilities && payload.authorization) {
    state.session = payload;
    if (payload.selection) state.draft = structuredClone(payload.selection);
  }
  if (Array.isArray(payload.targets) && typeof payload.status === 'string') {
    state.discovery = payload;
    if (payload.selectedTargetIdHash) state.selectedTargetIdHash = payload.selectedTargetIdHash;
  }
  return payload;
}

function selectionErrorMessage(error) {
  if (error instanceof ApiError && API_ERROR_MESSAGES[error.code]) {
    return API_ERROR_MESSAGES[error.code];
  }
  return error instanceof ApiError && error.reason && SELECTION_ERROR_MESSAGES[error.reason]
    ? SELECTION_ERROR_MESSAGES[error.reason]
    : 'The configuration was rejected. Check the gateway name, hostnames, and administrator emails.';
}

function apiErrorMessage(error, fallback) {
  return error instanceof ApiError && API_ERROR_MESSAGES[error.code]
    ? API_ERROR_MESSAGES[error.code]
    : fallback;
}

function agentError(error) {
  if (error instanceof ApiError) {
    return {
      code: error.code,
      reason: error.reason,
      message: API_ERROR_MESSAGES[error.code] ?? (
        error.reason && SELECTION_ERROR_MESSAGES[error.reason]
          ? SELECTION_ERROR_MESSAGES[error.reason]
          : 'The installer request was rejected.'
      ),
      retryable: error.code === 'rate_limited' || error.status >= 500,
    };
  }
  const code = error instanceof Error && LOCAL_AGENT_ERRORS[error.message]
    ? error.message
    : 'internal_error';
  return {
    code,
    reason: null,
    message: LOCAL_AGENT_ERRORS[code] ?? 'The installer action could not complete.',
    retryable: code === 'installer_busy' || code === 'internal_error',
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

function setValue(id, value) {
  const element = byId(id);
  if (element && document.activeElement !== element) element.value = value ?? '';
}

function fillForms() {
  renderDiscoveredTargets();
  const selection = state.draft ?? state.session?.selection;
  if (!selection) return;
  setValue('gateway-name', selection.basics?.gatewayName);
  setValue('zone-name', selection.basics?.zoneName);
  setValue('admin-email', selection.basics?.adminEmail);
  setValue('additional-admins', selection.basics?.additionalAdminEmails?.join('\n'));
  setValue('management-hostname', selection.basics?.managementHostname);
  setValue('portal-hostname', selection.basics?.portalHostname);
}

function renderDiscoveredTargets() {
  const select = byId('cloudflare-target');
  if (!select) return;
  const targets = state.discovery?.targets ?? [];
  const retained = state.selectedTargetIdHash ?? select.value;
  select.replaceChildren();
  for (const target of targets) {
    const option = document.createElement('option');
    option.value = text(target.targetIdHash);
    option.textContent = `${text(target.zoneName)} — ${text(target.accountName)}`;
    select.append(option);
  }
  if (targets.some((target) => target.targetIdHash === retained)) select.value = retained;
  if (!select.value && targets[0]) select.value = targets[0].targetIdHash;
  state.selectedTargetIdHash = select.value || null;
}

function selectedDiscoveryTarget(targetIdHash = state.selectedTargetIdHash) {
  return (state.discovery?.targets ?? []).find((target) => target.targetIdHash === targetIdHash) ?? null;
}

function suggestedGatewayName(accountName) {
  let candidate = text(accountName).replace(/['’]s Account$/iu, '').trim();
  if (candidate.includes('@')) candidate = candidate.split('@', 1)[0];
  candidate = candidate
    .replace(/[^A-Za-z0-9 -]+/gu, ' ')
    .replace(/\s+/gu, ' ')
    .replace(/^[ -]+|[ -]+$/gu, '')
    .slice(0, 72)
    .replace(/[ -]+$/gu, '');
  return `${candidate.length >= 2 ? candidate : 'Ankka'} MCP Gateway`;
}

function applyDiscoveryDefaults(targetIdHash = state.selectedTargetIdHash) {
  const target = selectedDiscoveryTarget(targetIdHash);
  if (!target || !state.discovery?.actorEmail) return;
  state.selectedTargetIdHash = target.targetIdHash;
  const existing = state.draft ?? state.session?.selection;
  const zoneName = target.zoneName;
  state.draft = {
    schemaVersion: 1,
    basics: {
      gatewayName: existing?.basics?.gatewayName ?? suggestedGatewayName(target.accountName),
      zoneName,
      adminEmail: state.discovery.actorEmail,
      additionalAdminEmails: existing?.basics?.additionalAdminEmails ?? [],
      managementHostname: existing?.basics?.managementHostname?.endsWith(`.${zoneName}`)
        ? existing.basics.managementHostname : `manage.${zoneName}`,
      portalHostname: existing?.basics?.portalHostname?.endsWith(`.${zoneName}`)
        ? existing.basics.portalHostname : `mcp.${zoneName}`,
    },
    firstSource: null,
  };
}

function gatewayDraft() {
  return {
    schemaVersion: 1,
    basics: {
      gatewayName: byId('gateway-name').value.trim().replace(/\s+/gu, ' '),
      zoneName: byId('zone-name').value.trim().toLowerCase(),
      adminEmail: byId('admin-email').value.trim().toLowerCase(),
      additionalAdminEmails: list(byId('additional-admins').value, true),
      managementHostname: byId('management-hostname').value.trim().toLowerCase(),
      portalHostname: byId('portal-hostname').value.trim().toLowerCase(),
    },
    firstSource: null,
  };
}

function agentSelection(input) {
  const target = selectedDiscoveryTarget(input.targetIdHash);
  if (!target || !state.discovery?.actorEmail) throw new Error('cloudflare_discovery_required');
  state.selectedTargetIdHash = target.targetIdHash;
  return {
    schemaVersion: 1,
    basics: {
      gatewayName: input.gatewayName,
      zoneName: target.zoneName,
      adminEmail: state.discovery.actorEmail,
      additionalAdminEmails: input.additionalAdminEmails ?? [],
      managementHostname: input.managementHostname,
      portalHostname: input.portalHostname,
    },
    firstSource: null,
  };
}

function selectionSummary() {
  const selection = state.session?.selection;
  if (!selection) return null;
  const administrators = [
    selection.basics.adminEmail,
    ...selection.basics.additionalAdminEmails,
  ];
  return {
    gatewayName: selection.basics.gatewayName,
    zoneName: selection.basics.zoneName,
    managementHostname: selection.basics.managementHostname,
    portalHostname: selection.basics.portalHostname,
    administratorCount: new Set(administrators).size,
    initialSourceCount: 0,
  };
}

function planSummary(plan = state.session?.plan) {
  if (!plan) return null;
  return {
    planId: plan.planId,
    planHash: plan.planHash,
    expiresAt: plan.expiresAt,
    releaseVersion: text(plan.release?.version),
    writesPerformed: false,
    resourceGroups: (plan.resourceGroups ?? []).map((group) => ({
      label: text(group.label),
      operations: [...(group.operations ?? [])].map(String),
    })),
  };
}

function removalPlanSummary() {
  const removal = state.session?.removal;
  if (!removal?.plan) return null;
  return {
    planId: removal.plan.planId,
    planHash: removal.plan.planHash,
    expiresAt: removal.plan.expiresAt,
    writesPerformed: false,
    providerNotice: text(removal.plan.providerNotice),
    operations: (removal.plan.operations ?? []).map((operation) => text(operation.label)),
  };
}

function installerStatus() {
  const deployment = state.session?.deployment;
  const removal = state.session?.removal;
  return {
    route: state.route,
    cloudflare: state.discovery ? {
      status: state.discovery.status,
      actorEmail: state.discovery.actorEmail,
      targets: [...(state.discovery.targets ?? [])],
      selectedTargetIdHash: state.selectedTargetIdHash,
      grantRevocation: state.discovery.grantRevocation,
      failureCode: state.discovery.failureCode,
    } : null,
    configuration: selectionSummary(),
    plan: planSummary(),
    deployment: deployment ? {
      status: deployment.status,
      canRetry: deployment.canRetry === true,
      existingGateway: deployment.existingGateway ? {
        installationId: text(deployment.existingGateway.installationId),
        name: text(deployment.existingGateway.name),
        managementHostname: text(deployment.existingGateway.managementHostname),
        portalHostname: text(deployment.existingGateway.portalHostname),
      } : null,
      operations: (deployment.operations ?? []).map((operation) => ({
        label: text(operation.label),
        status: text(operation.status),
      })),
      receipt: deployment.receipt ? {
        managementUrl: safeLink(deployment.receipt.managementUrl),
        portalUrl: safeLink(deployment.receipt.portalUrl),
        grantRevocation: text(deployment.receipt.grantRevocation),
      } : null,
      failure: deployment.failure ? {
        code: text(deployment.failure.code),
        title: text(deployment.failure.title),
        detail: text(deployment.failure.detail),
        repairTarget: text(deployment.failure.repairTarget) || null,
      } : null,
    } : null,
    removal: removal ? {
      status: removal.status,
      canRetry: removal.canRetry === true,
      recovery: removal.recovery ? {
        status: text(removal.recovery.status),
        expiresAt: text(removal.recovery.expiresAt),
      } : null,
      plan: removalPlanSummary(),
    } : null,
  };
}

async function persistSelection(selection) {
  state.draft = selection;
  if (!state.selectedTargetIdHash) throw new Error('cloudflare_discovery_required');
  await api('/api/selection', {
    method: 'PUT',
    body: selection,
    extraHeaders: { 'x-cloudflare-target-hash': state.selectedTargetIdHash },
  });
  showNotice('');
  route('/review');
  return selectionSummary();
}

async function prepareDiscovery() {
  const result = await api('/api/discovery', { method: 'POST', body: {} });
  const target = validAuthorizationUrl(result.authorizationUrl);
  const handoff = validHandoffUrl(result.handoffUrl);
  if (!target || !handoff) throw new Error('authorization_unavailable');
  await api('/api/discovery');
  return { target, handoff };
}

async function createReviewPlan() {
  if (!state.session?.selection) throw new Error('plan_unavailable');
  if (!state.session.plan) await api('/api/plan', { method: 'POST' });
  showNotice('');
  route('/review');
  renderPlan();
  return planSummary();
}

async function createRemovalPlan() {
  const removal = state.session?.removal;
  const returning = String(removal?.plan?.planId ?? '').startsWith('returning-uninstall-plan-');
  if (returning && removal?.recovery) {
    await api('/api/returning-uninstall/recovery/plan', { method: 'POST' });
  } else if (!removal?.plan) {
    await api('/api/uninstall/plan', { method: 'POST' });
  }
  showNotice('');
  route('/result');
  renderResult();
  return removalPlanSummary();
}

function appendSummary(container, label, value) {
  const row = document.createElement('div');
  row.className = 'summary-row';
  const key = document.createElement('span');
  key.textContent = label;
  const content = document.createElement('strong');
  content.textContent = value;
  row.append(key, content);
  container.append(row);
}

function renderSelectionSummary(container) {
  container.replaceChildren();
  const selection = state.session?.selection;
  if (!selection) {
    const message = document.createElement('p');
    message.textContent = 'Complete the gateway step to create a plan.';
    container.append(message);
    return;
  }
  appendSummary(container, 'Gateway', selection.basics.gatewayName);
  appendSummary(container, 'Zone', selection.basics.zoneName);
  appendSummary(container, 'Management', selection.basics.managementHostname);
  appendSummary(container, 'Portal', selection.basics.portalHostname);
  appendSummary(container, 'Sources', 'Add after installation');
}

function renderPlan() {
  renderSelectionSummary(byId('selection-summary'));
  const groups = byId('plan-groups');
  const plan = state.session?.plan;
  groups.replaceChildren();
  byId('plan-expiry').textContent = '';
  byId('create-plan').textContent = plan ? 'Approve this plan' : 'Create review plan';
  if (!plan) return;
  for (const group of plan.resourceGroups ?? []) {
    const article = document.createElement('article');
    article.className = 'resource-group';
    const heading = document.createElement('h3');
    heading.textContent = text(group.label);
    const detail = document.createElement('p');
    detail.textContent = text(group.detail);
    const operations = document.createElement('ul');
    for (const operation of group.operations ?? []) {
      const item = document.createElement('li');
      item.textContent = String(operation);
      operations.append(item);
    }
    article.append(heading, detail, operations);
    groups.append(article);
  }
  const expiry = new Date(plan.expiresAt);
  byId('plan-expiry').textContent = Number.isNaN(expiry.valueOf())
    ? ''
    : `This plan expires at ${expiry.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}.`;
}

function renderDeploy() {
  const container = byId('deploy-summary');
  container.replaceChildren();
  const session = state.session;
  if (!session?.plan || !session.selection) {
    const message = document.createElement('p');
    message.textContent = 'Create and review a fresh plan before authorization.';
    container.append(message);
    byId('authorize').disabled = true;
    return;
  }
  appendSummary(container, 'Gateway', session.selection.basics.gatewayName);
  appendSummary(container, 'Cloudflare zone', session.selection.basics.zoneName);
  appendSummary(container, 'Runtime', 'Customer-owned Worker and durable state');
  appendSummary(container, 'Gateway access', 'Read-only allowlist');
  byId('authorize').disabled = state.busy || session.capabilities?.deploy !== true;
}

function currentOperation(operations, deploymentStatus) {
  if (!Array.isArray(operations) || operations.length === 0) return null;
  const running = operations.find((operation) => operation.status === 'running');
  if (running) return { operation: running, index: operations.indexOf(running) };
  const failure = [...operations].reverse().find((operation) => (
    operation.status === 'failed' || operation.status === 'blocked'
  ));
  if (failure) return { operation: failure, index: operations.indexOf(failure) };
  if (deploymentStatus === 'succeeded') {
    const final = [...operations].reverse().find((operation) => operation.status === 'succeeded') ?? operations.at(-1);
    return { operation: final, index: operations.indexOf(final) };
  }
  const queued = operations.find((operation) => !operation.status || operation.status === 'pending' || operation.status === 'queued');
  if (queued) return { operation: queued, index: operations.indexOf(queued) };
  const latest = [...operations].reverse().find((operation) => operation.status === 'succeeded') ?? operations[0];
  return { operation: latest, index: operations.indexOf(latest) };
}

function renderCurrentOperation(operations, deploymentStatus) {
  const stage = byId('operation-stage');
  const selected = currentOperation(operations, deploymentStatus);
  stage.hidden = selected === null;
  if (!selected) return;
  const { operation, index } = selected;
  const status = text(operation.status) || (deploymentStatus === 'queued' ? 'queued' : 'pending');
  const key = `${index}:${status}:${text(operation.label)}`;
  const changed = stage.dataset.stageKey !== key;
  stage.dataset.stageKey = key;
  stage.dataset.status = status;
  byId('operation-position').textContent = deploymentStatus === 'succeeded'
    ? 'Installation complete'
    : `Stage ${index + 1} of ${operations.length}`;
  byId('operation-title').textContent = text(operation.label) || 'Preparing installation';
  byId('operation-detail').textContent = text(operation.detail) || (
    status === 'running' ? 'Applying this reviewed change in your Cloudflare account…'
      : status === 'succeeded' ? 'This stage completed successfully.'
        : status === 'failed' || status === 'blocked' ? 'This stage needs attention before installation can continue.'
          : 'Waiting to begin…'
  );
  if (changed && !window.matchMedia('(prefers-reduced-motion: reduce)').matches) {
    byId('operation-copy').animate([
      { opacity: 0, transform: 'translateY(5px)' },
      { opacity: 1, transform: 'translateY(0)' },
    ], { duration: 220, easing: 'cubic-bezier(0.23, 1, 0.32, 1)' });
  }
}

function safeLink(value) {
  try {
    const url = new URL(value);
    return url.protocol === 'https:' && !url.username && !url.password ? url.href : null;
  } catch {
    return null;
  }
}

function addResultLink(container, label, value) {
  const href = safeLink(value);
  if (!href) return;
  const link = document.createElement('a');
  link.className = 'primary-button';
  link.href = href;
  link.rel = 'noreferrer';
  link.textContent = label;
  container.append(link);
}

function renderRemoval() {
  const section = byId('removal-section');
  const removal = state.session?.removal;
  const canRemove = state.session?.capabilities?.uninstall === true;
  section.hidden = !canRemove && !removal;
  if (section.hidden) return;
  const planContainer = byId('removal-plan');
  const previewButton = byId('preview-removal');
  const confirmButton = byId('confirm-removal');
  const returning = String(removal?.plan?.planId ?? '').startsWith('returning-uninstall-plan-');
  planContainer.replaceChildren();
  planContainer.hidden = !removal;
  previewButton.hidden = Boolean(removal) && !(removal?.recovery && removal.status !== 'planned');
  confirmButton.hidden = !removal || !(removal.status === 'planned' ||
    (returning && !removal.recovery && removal.status === 'failed' && removal.canRetry));
  if (!removal) return;
  const noticeCopy = document.createElement('p');
  noticeCopy.textContent = text(removal.plan?.providerNotice);
  const operations = document.createElement('ol');
  for (const operation of removal.plan?.operations ?? []) {
    const item = document.createElement('li');
    item.textContent = text(operation.label);
    operations.append(item);
  }
  planContainer.append(noticeCopy, operations);
  if (removal.status === 'removed') {
    confirmButton.hidden = true;
    previewButton.hidden = true;
    const complete = document.createElement('p');
    complete.textContent = removal.receipt?.grantRevocation === 'unconfirmed'
      ? 'The Ankka-managed gateway resources were removed. Manually revoke Ankka MCP Gateway in Cloudflare Connected Applications.'
      : 'The Ankka-managed gateway resources and short-lived grant were removed.';
    planContainer.append(complete);
  } else if (removal.failure) {
    const failure = document.createElement('p');
    failure.textContent = `${text(removal.failure.title)} ${text(removal.failure.detail)}`.trim();
    planContainer.append(failure);
    previewButton.hidden = !(removal.recovery || (!returning && removal.canRetry));
  }
}

function renderExistingGateway() {
  const section = byId('existing-gateway-section');
  const existing = state.session?.deployment?.existingGateway;
  section.hidden = !existing;
  if (!existing) return;
  byId('existing-gateway-name').textContent = text(existing.name) || 'Ankka MCP Gateway';
  byId('existing-gateway-portal').textContent = text(existing.portalHostname);
  byId('existing-gateway-management').textContent = text(existing.managementHostname);
  const managementUrl = safeLink(`https://${text(existing.managementHostname)}/?teardown=review`);
  const teardown = byId('existing-gateway-teardown');
  if (managementUrl) {
    teardown.href = managementUrl;
    teardown.hidden = false;
  } else {
    teardown.removeAttribute('href');
    teardown.hidden = true;
  }
}

function shouldPoll() {
  const deployment = state.session?.deployment?.status;
  const removal = state.session?.removal?.status;
  return state.callbackStreamActive || state.discovery?.status === 'authorizing' ||
    ['queued', 'running'].includes(deployment) || ['authorizing', 'running'].includes(removal);
}

function schedulePoll() {
  if (state.pollTimer) window.clearTimeout(state.pollTimer);
  state.pollTimer = null;
  if (!shouldPoll()) return;
  const delay = Math.min(10_000, 1_800 * (2 ** state.pollFailures));
  state.pollTimer = window.setTimeout(async () => {
    try {
      await api('/api/session');
      await api('/api/discovery');
      state.pollFailures = 0;
      if (state.discovery?.status === 'ready' && !state.draft && !state.session?.selection) {
        applyDiscoveryDefaults();
      }
      render();
      schedulePoll();
    } catch {
      state.pollFailures = Math.min(3, state.pollFailures + 1);
      showNotice('Status refresh failed. Reconnecting automatically…', 'error');
      schedulePoll();
    }
  }, delay);
}

function renderResult() {
  const deployment = state.session?.deployment;
  const intro = byId('result-intro');
  const streamNote = byId('stream-note');
  const actions = byId('result-actions');
  actions.replaceChildren();
  if (!deployment) {
    streamNote.hidden = true;
    intro.textContent = 'No deployment result is available in this session.';
    renderCurrentOperation([], 'idle');
    renderExistingGateway();
    renderRemoval();
    return;
  }
  renderCurrentOperation(deployment.operations, deployment.status);
  streamNote.hidden = deployment.status !== 'queued' && deployment.status !== 'running';
  if (deployment.status === 'succeeded') {
    state.callbackStreamActive = false;
    intro.textContent = deployment.operations?.some((operation) => operation.status === 'blocked')
      ? 'The gateway is ready, with one Cloudflare grant action still requiring attention.'
      : 'The customer-owned gateway is ready.';
    addResultLink(actions, 'Open management page', deployment.receipt?.managementUrl);
    addResultLink(actions, 'Open MCP endpoint', deployment.receipt?.portalUrl);
    showNotice('');
  } else if (deployment.status === 'failed') {
    state.callbackStreamActive = false;
    intro.textContent = `${text(deployment.failure?.title)} ${text(deployment.failure?.detail)}`.trim() ||
      'The deployment did not complete.';
    if (deployment.canRetry) {
      const retry = document.createElement('button');
      retry.type = 'button';
      retry.className = 'primary-button';
      retry.dataset.go = '/review';
      retry.textContent = 'Create a fresh plan';
      retry.addEventListener('click', () => route('/review'));
      actions.append(retry);
    }
    showNotice('');
  } else {
    intro.textContent = 'The customer-owned gateway is being created. The active stage updates live below.';
    showNotice('');
  }
  renderExistingGateway();
  renderRemoval();
  schedulePoll();
}

function updateProgress() {
  const session = state.session;
  const activeStep = state.route === '/'
    ? 'connect'
    : state.route === '/result'
      ? 'deploy'
      : STEP_ROUTES.includes(state.route) ? state.route.slice(1) : null;
  for (const link of document.querySelectorAll('[data-step]')) {
    const step = link.dataset.step;
    if (step === activeStep) link.setAttribute('aria-current', 'step');
    else link.removeAttribute('aria-current');
    const complete = step === 'connect'
      ? state.discovery?.status === 'ready'
      : step === 'gateway'
        ? Boolean(session?.selection)
        : step === 'review'
          ? Boolean(session?.plan)
          : step === 'deploy'
            ? session?.deployment?.status === 'succeeded'
            : false;
    link.dataset.complete = String(complete);
  }
}

function renderWelcome() {
  const button = byId('discover-cloudflare');
  if (!button) return;
  const ready = state.discovery?.status === 'ready';
  button.textContent = ready ? 'Continue with discovered account' : 'Connect Cloudflare';
  button.disabled = state.busy;
  if (ready) {
    const target = selectedDiscoveryTarget() ?? state.discovery.targets?.[0];
    if (state.discovery.grantRevocation === 'unconfirmed') {
      showNotice('Cloudflare discovery finished, but automatic grant revocation was not confirmed. Revoke Ankka MCP Gateway in Cloudflare Connected Applications before continuing.', 'error');
    } else {
      showNotice(target
        ? `Connected to ${target.accountName} · ${target.zoneName}. The discovery grant was revoked.`
        : 'Cloudflare connected, but no active zones were found.', target ? 'success' : 'error');
    }
  } else if (state.discovery?.status === 'failed') {
    showNotice(discoveryFailureMessage(state.discovery.failureCode), 'error');
  }
}

function render() {
  for (const panel of document.querySelectorAll('[data-route]')) {
    panel.hidden = panel.dataset.route !== state.route;
  }
  fillForms();
  updateProgress();
  if (state.route === '/') renderWelcome();
  if (state.route === '/review') renderPlan();
  if (state.route === '/deploy') renderDeploy();
  if (state.route === '/result') renderResult();
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

function validHandoffUrl(value) {
  try {
    const url = new URL(value);
    return url.origin === 'https://deploy.ankka.ai' && !url.username && !url.password && !url.port &&
      url.pathname === OAUTH_HANDOFF_PATH && url.search === '' &&
      /^#[A-Za-z0-9_-]{40,4096}$/u.test(url.hash)
      ? url.href
      : null;
  } catch {
    return null;
  }
}

async function prepareAuthorization(path, plan) {
  if (!plan?.planId || !plan?.planHash) throw new Error('plan_unavailable');
  const result = await api(path, {
    method: 'POST',
    body: { planId: plan.planId, planHash: plan.planHash },
  });
  const target = validAuthorizationUrl(result.authorizationUrl);
  const handoff = validHandoffUrl(result.handoffUrl);
  if (!target || !handoff) throw new Error('authorization_unavailable');
  await api('/api/session');
  return { target, handoff };
}

function revealAuthorizationLink(id, handoff) {
  const link = byId(id);
  link.href = handoff;
  link.hidden = false;
  if (id === 'authorization-link') byId('authorization-handoff').hidden = false;
}

async function completeOauthHandoff() {
  const handoff = window.location.hash.slice(1);
  window.history.replaceState(null, '', OAUTH_HANDOFF_PATH);
  if (!/^[A-Za-z0-9_-]{40,4096}$/u.test(handoff)) throw new Error('authorization_unavailable');
  const response = await fetch('/api/oauth/handoff', {
    method: 'POST',
    headers: { accept: 'application/json', 'content-type': 'application/json' },
    credentials: 'same-origin',
    redirect: 'error',
    body: JSON.stringify({ handoff }),
  });
  let payload = null;
  try { payload = await response.json(); } catch { /* The fixed UI error is enough. */ }
  if (!response.ok) throw new ApiError(response.status, payload);
  const target = validAuthorizationUrl(payload?.authorizationUrl);
  if (!target) throw new Error('authorization_unavailable');
  window.location.replace(target);
}

function validManagementUrl(value) {
  try {
    const url = new URL(value);
    const actionParameters = Number(url.searchParams.has('sourceAction')) + Number(url.searchParams.has('runtimeAction'));
    return url.protocol === 'https:' && !url.username && !url.password && !url.port &&
      url.hash === '' && actionParameters === 1 ? url.href : null;
  } catch {
    return null;
  }
}

async function completeManagementHandoff() {
  const handoff = window.location.hash.slice(1);
  window.history.replaceState(null, '', '/manage');
  if (!/^[A-Za-z0-9_-]{40,4096}$/u.test(handoff)) throw new Error('authorization_unavailable');
  const response = await fetch('/api/management/authorize', {
    method: 'POST',
    headers: { accept: 'application/json', 'content-type': 'application/json' },
    credentials: 'same-origin',
    redirect: 'error',
    body: JSON.stringify({ handoff }),
  });
  let payload = null;
  try { payload = await response.json(); } catch { /* The fixed UI error is enough. */ }
  if (!response.ok) throw new ApiError(response.status, payload);
  if (payload?.schemaVersion === 1 && payload.reviewUrl === '/result') {
    window.location.replace('/result');
    return;
  }
  const target = validAuthorizationUrl(payload?.authorizationUrl);
  if (!target) throw new Error('authorization_unavailable');
  window.location.replace(target);
}

async function managementCallbackContext() {
  const response = await fetch('/api/management/context', {
    headers: { accept: 'application/json' },
    credentials: 'same-origin',
    redirect: 'error',
  });
  if (!response.ok) return null;
  let payload = null;
  try { payload = await response.json(); } catch { return null; }
  const managementUrl = payload?.schemaVersion === 1 ? validManagementUrl(payload.managementUrl) : null;
  return managementUrl ? { ...payload, managementUrl } : null;
}

async function runAgentAction(message, action) {
  if (state.busy) {
    return JSON.stringify({ ok: false, error: agentError(new Error('installer_busy')) });
  }
  setBusy(true);
  showNotice(message);
  try {
    return JSON.stringify({ ok: true, result: await action() });
  } catch (error) {
    const detail = agentError(error);
    showNotice(detail.message, 'error');
    return JSON.stringify({ ok: false, error: detail });
  } finally {
    setBusy(false);
    render();
  }
}

const STRING_ARRAY_SCHEMA = Object.freeze({
  type: 'array',
  items: { type: 'string' },
});

async function registerAgentTools() {
  const modelContext = document.modelContext;
  if (state.agentToolsRegistered || !modelContext || typeof modelContext.registerTool !== 'function') return;
  const tools = [
    {
      name: 'begin_cloudflare_discovery',
      description: 'Create a short-lived, read-only Cloudflare authorization handoff link that discovers the user email, accounts, and active zones. Return the link to the user; do not open or approve it for them. The grant is revoked immediately after discovery.',
      inputSchema: { type: 'object', properties: {}, additionalProperties: false },
      annotations: {
        readOnlyHint: false,
        destructiveHint: false,
        idempotentHint: false,
        openWorldHint: true,
        untrustedContentHint: false,
      },
      execute: async () => runAgentAction('Opening Cloudflare…', async () => {
        const prepared = await prepareDiscovery();
        return {
          status: 'user_authorization_required',
          authorizationUrl: prepared.handoff,
          instruction: 'Send authorizationUrl to the user. After they finish Cloudflare consent, poll get_installer_status until cloudflare.status is ready or failed.',
        };
      }),
    },
    {
      name: 'configure_gateway',
      description: 'Save an empty Ankka MCP Portal configuration for a target returned by Cloudflare discovery. The actor email and zone are derived from that target. Sources are added later from the customer management page. Performs no Cloudflare writes.',
      inputSchema: {
        type: 'object',
        additionalProperties: false,
        properties: {
          gatewayName: { type: 'string', description: 'Human-readable gateway name.' },
          targetIdHash: { type: 'string', description: 'Opaque targetIdHash returned in cloudflare.targets by get_installer_status.' },
          additionalAdminEmails: { ...STRING_ARRAY_SCHEMA, maxItems: 19, uniqueItems: true, description: 'Optional additional administrator emails.' },
          managementHostname: { type: 'string', description: 'Unused management hostname beneath the active zone.' },
          portalHostname: { type: 'string', description: 'Unused MCP Portal hostname beneath the active zone.' },
        },
        required: [
          'gatewayName', 'targetIdHash', 'managementHostname', 'portalHostname',
        ],
      },
      annotations: {
        readOnlyHint: false,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: false,
        untrustedContentHint: false,
      },
      execute: async (input) => runAgentAction(
        'Saving your gateway…',
        () => persistSelection(agentSelection(input)),
      ),
    },
    {
      name: 'create_review_plan',
      description: 'Create or return the exact zero-provider-write Cloudflare installation plan for the retained configuration.',
      inputSchema: { type: 'object', properties: {}, additionalProperties: false },
      annotations: {
        readOnlyHint: false,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: false,
        untrustedContentHint: false,
      },
      execute: async () => runAgentAction('Preparing your review…', createReviewPlan),
    },
    {
      name: 'get_installer_status',
      description: 'Refresh and return the retained installer, deployment, and removal status without performing provider writes.',
      inputSchema: { type: 'object', properties: {}, additionalProperties: false },
      annotations: {
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: false,
        untrustedContentHint: false,
      },
      execute: async () => runAgentAction('Checking progress…', async () => {
        await api('/api/session');
        await api('/api/discovery');
        return installerStatus();
      }),
    },
    {
      name: 'begin_authorization',
      description: 'Create a short-lived Cloudflare authorization handoff link for the exact reviewed installation plan. Return the link to the user; do not open or approve it for them. The user may open it in any browser and must review the Cloudflare account and permissions.',
      inputSchema: {
        type: 'object',
        additionalProperties: false,
        properties: {
          planHash: { type: 'string', description: 'Exact plan hash returned by create_review_plan.' },
        },
        required: ['planHash'],
      },
      annotations: {
        readOnlyHint: false,
        destructiveHint: false,
        idempotentHint: false,
        openWorldHint: true,
        untrustedContentHint: false,
      },
      execute: async ({ planHash }) => runAgentAction('Preparing a Cloudflare authorization link…', async () => {
        const plan = state.session?.plan;
        if (!plan) throw new Error('plan_unavailable');
        if (plan.planHash !== planHash) throw new Error('plan_hash_mismatch');
        const prepared = await prepareAuthorization('/api/deploy', plan);
        return {
          status: 'user_authorization_required',
          authorizationUrl: prepared.handoff,
          expiresAt: plan.expiresAt,
          planHash,
          instruction: 'Send authorizationUrl to the user. After they finish Cloudflare consent, poll get_installer_status until deployment is no longer queued or running.',
        };
      }),
    },
    {
      name: 'create_removal_plan',
      description: 'Create or return the zero-provider-write removal plan for the successful installation retained in this session.',
      inputSchema: { type: 'object', properties: {}, additionalProperties: false },
      annotations: {
        readOnlyHint: false,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: false,
        untrustedContentHint: false,
      },
      execute: async () => runAgentAction('Preparing the removal plan…', createRemovalPlan),
    },
    {
      name: 'begin_removal',
      description: 'Create a short-lived Cloudflare authorization handoff link for the exact reviewed removal plan. Return the link to the user; do not open or approve it for them. The user must review the destructive removal in Cloudflare.',
      inputSchema: {
        type: 'object',
        additionalProperties: false,
        properties: {
          planHash: { type: 'string', description: 'Exact removal plan hash returned by create_removal_plan.' },
        },
        required: ['planHash'],
      },
      annotations: {
        readOnlyHint: false,
        destructiveHint: true,
        idempotentHint: false,
        openWorldHint: true,
        untrustedContentHint: false,
      },
      execute: async ({ planHash }) => runAgentAction('Preparing a Cloudflare removal authorization link…', async () => {
        const plan = state.session?.removal?.plan;
        if (!plan) throw new Error('removal_plan_unavailable');
        if (plan.planHash !== planHash) throw new Error('removal_plan_hash_mismatch');
        const path = String(plan.planId).startsWith('returning-uninstall-plan-')
          ? state.session?.removal?.recovery
            ? '/api/returning-uninstall/recovery'
            : '/api/returning-uninstall'
          : '/api/uninstall';
        const prepared = await prepareAuthorization(path, plan);
        return {
          status: 'user_authorization_required',
          authorizationUrl: prepared.handoff,
          expiresAt: plan.expiresAt,
          planHash,
          instruction: 'Send authorizationUrl to the user. After they finish Cloudflare consent, poll get_installer_status until removal is removed or failed.',
        };
      }),
    },
  ];
  for (const tool of tools) await modelContext.registerTool(tool);
  state.agentToolsRegistered = true;
}

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

byId('gateway-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  if (!event.currentTarget.reportValidity() || state.busy) return;
  setBusy(true);
  showNotice('Saving your gateway…');
  try {
    await persistSelection(gatewayDraft());
  } catch (error) {
    showNotice(selectionErrorMessage(error), 'error');
  } finally {
    setBusy(false);
  }
});

byId('cloudflare-target').addEventListener('change', (event) => {
  state.selectedTargetIdHash = event.currentTarget.value;
  applyDiscoveryDefaults(state.selectedTargetIdHash);
  fillForms();
});

byId('discover-cloudflare').addEventListener('click', async () => {
  if (state.busy) return;
  if (state.discovery?.status === 'ready') {
    if (!state.selectedTargetIdHash && state.discovery.targets?.[0]) {
      state.selectedTargetIdHash = state.discovery.targets[0].targetIdHash;
    }
    applyDiscoveryDefaults();
    route('/gateway');
    return;
  }
  const cloudflareWindow = window.open('about:blank', '_blank');
  if (cloudflareWindow) cloudflareWindow.opener = null;
  setBusy(true);
  showNotice('Opening Cloudflare…');
  try {
    const prepared = await prepareDiscovery();
    revealAuthorizationLink('discovery-link', prepared.handoff);
    let opened = false;
    if (cloudflareWindow && !cloudflareWindow.closed) {
      try {
        cloudflareWindow.location.replace(prepared.handoff);
        opened = true;
      } catch {
        try { cloudflareWindow.close(); } catch { /* The visible fallback remains usable. */ }
      }
    }
    if (opened) {
      byId('discovery-handoff').hidden = true;
      showNotice('Finish connecting Cloudflare in the new tab.');
    } else {
      byId('discovery-handoff').hidden = false;
      showNotice('Your browser blocked the Cloudflare tab. Use the link below.', 'error');
    }
    schedulePoll();
  } catch (error) {
    try { cloudflareWindow?.close(); } catch { /* The fixed local error is sufficient. */ }
    showNotice(apiErrorMessage(error, 'Cloudflare discovery could not start. Try again.'), 'error');
  } finally {
    setBusy(false);
  }
});

byId('create-plan').addEventListener('click', async () => {
  if (state.busy) return;
  if (state.session?.plan) {
    route('/deploy');
    return;
  }
  if (!state.session?.selection) {
    showNotice('Complete the gateway step first.', 'error');
    return;
  }
  setBusy(true);
  showNotice('Preparing your review…');
  try {
    await createReviewPlan();
  } catch (error) {
    showNotice(apiErrorMessage(
      error,
      'A fresh review plan could not be created. Reload the installer and try again.',
    ), 'error');
  } finally {
    setBusy(false);
  }
});

byId('authorize').addEventListener('click', async () => {
  if (state.busy) return;
  setBusy(true);
  showNotice('Preparing Cloudflare authorization…');
  try {
    const prepared = await prepareAuthorization('/api/deploy', state.session?.plan);
    revealAuthorizationLink('authorization-link', prepared.handoff);
    showNotice('Cloudflare sign-in link ready. This page will keep watching the installation.', 'success');
    schedulePoll();
  } catch (error) {
    showNotice(apiErrorMessage(
      error,
      'Cloudflare authorization could not start. Create a fresh plan and try again.',
    ), 'error');
  } finally {
    setBusy(false);
  }
});

byId('preview-removal').addEventListener('click', async () => {
  if (state.busy) return;
  setBusy(true);
  showNotice('Preparing the removal plan…');
  try {
    await createRemovalPlan();
  } catch (error) {
    showNotice(apiErrorMessage(
      error,
      'A bounded removal plan is not available for this retained result.',
    ), 'error');
  } finally {
    setBusy(false);
  }
});

byId('confirm-removal').addEventListener('click', async () => {
  if (state.busy) return;
  setBusy(true);
  showNotice('Preparing Cloudflare authorization for removal…');
  try {
    const plan = state.session?.removal?.plan;
    const path = String(plan?.planId ?? '').startsWith('returning-uninstall-plan-')
      ? state.session?.removal?.recovery
        ? '/api/returning-uninstall/recovery'
        : '/api/returning-uninstall'
      : '/api/uninstall';
    const prepared = await prepareAuthorization(path, plan);
    revealAuthorizationLink('removal-authorization-link', prepared.handoff);
    showNotice('Cloudflare removal sign-in link ready. This page will keep watching removal.', 'success');
    schedulePoll();
  } catch (error) {
    showNotice(apiErrorMessage(
      error,
      'Removal authorization could not start. Create a fresh removal plan and try again.',
    ), 'error');
  } finally {
    setBusy(false);
  }
});

async function start() {
  setBusy(true);
  try {
    if (window.location.pathname === OAUTH_HANDOFF_PATH) {
      showNotice('Opening Cloudflare authorization…');
      await completeOauthHandoff();
      return;
    }
    if (window.location.pathname === '/manage' && window.location.hash) {
      state.route = '/manage';
      render();
      showNotice('Opening Cloudflare authorization…');
      await completeManagementHandoff();
      return;
    }
    if (callbackStream) {
      const management = await managementCallbackContext();
      if (management) {
        window.history.replaceState(null, '', '/manage');
        state.route = '/manage';
        render();
        showNotice('Cloudflare authorized. Applying the source in your account…', 'success');
        window.addEventListener('load', () => window.location.replace(management.managementUrl), { once: true });
        return;
      }
      window.history.replaceState(null, '', '/result');
    }
    await api('/api/session');
    await api('/api/discovery');
    if (state.discovery?.status === 'ready' && !state.session?.selection) applyDiscoveryDefaults();
    try { await registerAgentTools(); } catch { /* The human UI remains the fallback. */ }
    showNotice('');
    if (state.route === '/result' || ['queued', 'running', 'failed', 'succeeded'].includes(
      state.session?.deployment?.status,
    ) || state.session?.removal) state.route = '/result';
    render();
  } catch (error) {
    if (state.callbackStreamActive) {
      state.pollFailures = 1;
      showNotice('Status refresh failed. Reconnecting automatically…', 'error');
      schedulePoll();
    } else {
      showNotice(apiErrorMessage(
        error,
        'The installer session could not be loaded. Reload this page to try again.',
      ), 'error');
    }
  } finally {
    setBusy(false);
    render();
  }
}

void start();

import type { Connect } from 'vite'

type InstallerScenario =
  | 'start'
  | 'connected'
  | 'configured'
  | 'planned'
  | 'running'
  | 'success'
  | 'failed'
  | 'removal'

const targetIdHash = `sha256:${'a'.repeat(64)}`
const previewCsrf = 'local-preview-csrf'

const selection = {
  schemaVersion: 1,
  basics: {
    gatewayName: 'Example MCP Gateway',
    zoneName: 'example.com',
    adminEmail: 'owner@example.com',
    additionalAdminEmails: ['admin@example.com'],
    managementHostname: 'manage.example.com',
    portalHostname: 'mcp.example.com',
  },
  firstSource: null,
}

const plan = {
  schemaVersion: 1,
  planId: 'plan-example-preview',
  planHash: 'sha256:example-reviewed-plan',
  writesPerformed: false,
  release: { version: 'gateway-v0.1.12', sha256: 'sha256:example-release' },
  resourceGroups: [
    {
      id: 'runtime',
      label: 'Customer-owned runtime',
      detail: 'Management Worker, dashboard assets, and SQLite durable state.',
      operations: ['Management Worker', 'SQLite Durable Object', 'Dashboard assets'],
    },
    {
      id: 'management-access',
      label: 'Management access',
      detail: 'An explicit Access application and administrator allow policy.',
      operations: ['Management Access application', 'Management Access policy'],
    },
    {
      id: 'gateway',
      label: 'Read-only MCP gateway',
      detail: 'An empty Portal, explicit administrator access policy, and Portal DNS.',
      operations: ['MCP Portal', 'Portal Access application', 'Portal Access policy', 'Portal DNS record'],
    },
  ],
  blockers: [],
  expiresAt: '2026-08-27T14:30:00.000Z',
}

const operationCopy = [
  ['connect', 'Connecting to your Cloudflare account'],
  ['verify', 'Checking the authorized account and active zone'],
  ['gateway_fresh_preflight', 'Checking requested Cloudflare names'],
  ['worker_create', 'Creating the management Worker'],
  ['management_access_application_create', 'Creating the management Access application'],
  ['management_admin_policy_create', 'Creating the administrator Access policy'],
  ['provision_worker_version_create', 'Uploading the provisioning Worker version'],
  ['provision_worker_deployment_create', 'Deploying the provisioning Worker'],
  ['bootstrap_worker_version_create', 'Uploading the bootstrap Worker version'],
  ['bootstrap_worker_deployment_create', 'Deploying the bootstrap Worker'],
  ['bootstrap_subdomain_enable', 'Enabling the temporary bootstrap URL'],
  ['customer_bootstrap_submit', 'Bootstrapping customer-owned gateway state'],
  ['bootstrap_subdomain_disable', 'Disabling the temporary bootstrap URL'],
  ['clean_worker_version_create', 'Uploading the final Worker version'],
  ['clean_worker_deployment_create', 'Deploying the final Worker version'],
  ['management_custom_domain_attach', 'Attaching the management custom domain'],
  ['final_convergence', 'Verifying final gateway convergence'],
  ['revoke', 'Revoking the short-lived Cloudflare grant'],
] as const

function scenarioFromRequest(request: Connect.IncomingMessage): InstallerScenario {
  const referer = request.headers.referer
  let location: URL
  try {
    location = new URL(referer ?? '/', 'http://127.0.0.1:5731')
  } catch {
    return 'start'
  }
  const requested = location.searchParams.get('preview')
  if (
    requested === 'start' ||
    requested === 'connected' ||
    requested === 'configured' ||
    requested === 'planned' ||
    requested === 'running' ||
    requested === 'success' ||
    requested === 'failed' ||
    requested === 'removal'
  ) return requested

  if (location.pathname === '/gateway') return 'connected'
  if (location.pathname === '/review') return 'configured'
  if (location.pathname === '/deploy') return 'planned'
  if (location.pathname === '/result') return 'running'
  return 'start'
}

function hasSelection(scenario: InstallerScenario): boolean {
  return !['start', 'connected'].includes(scenario)
}

function hasPlan(scenario: InstallerScenario): boolean {
  return ['planned', 'running', 'success', 'failed', 'removal'].includes(scenario)
}

function operations(scenario: InstallerScenario) {
  const runningIndex = 11
  return operationCopy.map(([id, label], index) => ({
    id,
    label,
    detail: index === runningIndex
      ? 'Creates the initial Portal, Access, and DNS configuration in the customer account.'
      : null,
    status: scenario === 'success' || scenario === 'removal'
      ? 'succeeded'
      : scenario === 'failed'
        ? index < runningIndex ? 'succeeded' : index === runningIndex ? 'failed' : 'pending'
        : index < runningIndex ? 'succeeded' : index === runningIndex ? 'running' : 'pending',
  }))
}

function deployment(scenario: InstallerScenario) {
  if (!['running', 'success', 'failed', 'removal'].includes(scenario)) return null
  const succeeded = scenario === 'success' || scenario === 'removal'
  const failed = scenario === 'failed'
  return {
    deploymentId: 'deploy-example-preview',
    status: succeeded ? 'succeeded' : failed ? 'failed' : 'running',
    operations: operations(scenario),
    failure: failed ? {
      code: 'oauth_grant_invalid',
      title: 'Cloudflare permission grant did not match',
      detail: 'Approve every requested permission on a fresh authorization.',
      repairTarget: 'account-home',
    } : null,
    canRetry: failed,
    receipt: succeeded ? {
      receiptId: 'receipt-example-preview',
      planId: plan.planId,
      planHash: plan.planHash,
      release: plan.release.version,
      releaseSha256: plan.release.sha256,
      appliedAt: '2026-08-27T12:30:00.000Z',
      managementUrl: 'https://manage.example.com/',
      portalUrl: 'https://mcp.example.com/mcp',
      grantRevocation: 'confirmed',
    } : null,
  }
}

const removal = {
  status: 'planned',
  recovery: { status: 'recovery_required', expiresAt: '2026-08-28T12:30:00.000Z' },
  plan: {
    schemaVersion: 1,
    planId: 'uninstall-example-preview',
    planHash: 'sha256:example-removal-plan',
    writesPerformed: false,
    installationId: 'example-installation',
    release: { version: plan.release.version, sha256: plan.release.sha256 },
    operations: [
      { id: 'dns', label: 'Remove the Portal DNS record' },
      { id: 'access', label: 'Remove the installation-owned Access resources' },
      { id: 'worker', label: 'Remove the installation-owned Worker' },
    ],
    providerNotice: 'Only resources owned by this retained installation receipt are removed.',
    expiresAt: '2026-08-27T14:30:00.000Z',
  },
  failure: null,
  canRetry: true,
  receipt: null,
}

function session(scenario: InstallerScenario) {
  return {
    schemaVersion: 1,
    csrf: previewCsrf,
    recovery: null,
    authorization: { status: 'anonymous', email: null, expiresAt: null },
    capabilities: {
      selection: true,
      plan: hasSelection(scenario),
      deploy: true,
      uninstall: scenario === 'success' || scenario === 'removal',
      events: true,
      signedRelease: hasPlan(scenario),
    },
    selection: hasSelection(scenario) ? selection : null,
    plan: hasPlan(scenario) ? plan : null,
    deployment: deployment(scenario),
    removal: scenario === 'removal' ? removal : null,
    updatedAt: '2026-08-27T12:30:00.000Z',
  }
}

function discovery(scenario: InstallerScenario, forcedReady: boolean) {
  const ready = forcedReady || scenario !== 'start'
  return {
    schemaVersion: 1,
    status: ready ? 'ready' : 'not_started',
    actorEmail: ready ? 'owner@example.com' : null,
    targets: ready ? [{
      targetIdHash,
      accountName: 'Example Company',
      zoneName: 'example.com',
    }] : [],
    selectedTargetIdHash: ready ? targetIdHash : null,
    failureCode: null,
    grantRevocation: ready ? 'confirmed' : null,
    updatedAt: ready ? '2026-08-27T12:00:00.000Z' : null,
  }
}

function authorization() {
  return {
    schemaVersion: 1,
    csrf: previewCsrf,
    authorizationUrl: 'https://dash.cloudflare.com/oauth2/auth?client_id=local-preview',
    handoffUrl: `https://deploy.ankka.ai/oauth/handoff#${'a'.repeat(48)}`,
  }
}

function sendJson<Body>(response: Connect.ServerResponse, status: number, body: Body): void {
  const bytes = JSON.stringify(body)
  response.statusCode = status
  response.setHeader('cache-control', 'no-store')
  response.setHeader('content-type', 'application/json; charset=utf-8')
  response.setHeader('content-length', Buffer.byteLength(bytes))
  response.end(bytes)
}

export function installerPreviewApi(): Connect.NextHandleFunction {
  let forcedDiscoveryReady = false

  return (request, response, next) => {
    if (!request.url?.startsWith('/api/')) {
      next()
      return
    }
    const scenario = scenarioFromRequest(request)
    const url = new URL(request.url, 'http://127.0.0.1:5731')

    if (request.method === 'GET' && url.pathname === '/api/session') {
      sendJson(response, 200, session(scenario))
      return
    }
    if (url.pathname === '/api/discovery') {
      if (request.method === 'POST') {
        forcedDiscoveryReady = true
        sendJson(response, 200, authorization())
      } else {
        sendJson(response, 200, discovery(scenario, forcedDiscoveryReady))
      }
      return
    }
    if (request.method === 'PUT' && url.pathname === '/api/selection') {
      sendJson(response, 200, { ...session('configured'), selection })
      return
    }
    if (request.method === 'POST' && url.pathname === '/api/plan') {
      sendJson(response, 200, session('planned'))
      return
    }
    if (request.method === 'POST' && (
      url.pathname === '/api/deploy' ||
      url.pathname === '/api/uninstall'
    )) {
      sendJson(response, 200, authorization())
      return
    }
    if (request.method === 'POST' && url.pathname === '/api/uninstall/plan') {
      sendJson(response, 200, session('removal'))
      return
    }
    sendJson(response, 404, { schemaVersion: 1, code: 'preview_route_not_found' })
  }
}

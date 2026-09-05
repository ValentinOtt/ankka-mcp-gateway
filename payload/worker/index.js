// Canonical email-audience projection shared by runtime and unit tests.
// Request byte limits bound input size; Cloudflare enforces its own seat allowance.
const TEAM_MAX_SOURCES = 32;
const TEAM_EMAIL = /^[^\s@]{1,64}@[A-Za-z0-9.-]{1,190}$/u;
const TEAM_SOURCE_ID = /^[a-z][a-z0-9-]{0,31}$/u;
const TEAM_PROVIDER_ID = /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$/u;
const TEAM_TOOL = /^[A-Za-z0-9_.:/-]{1,128}$/u;
const TEAM_ERROR_CODES = Object.freeze([
  'team_access_invalid_request',
  'team_access_revision_conflict',
  'team_access_admin_required',
  'team_access_invalid_state',
  'team_access_invalid_target',
]);

export class TeamAccessError extends Error {
  constructor(code) {
    const safeCode = TEAM_ERROR_CODES.includes(code) ? code : 'team_access_invalid_request';
    super(safeCode);
    this.name = 'TeamAccessError';
    this.code = safeCode;
  }
}

function teamFail(code = 'team_access_invalid_request') {
  throw new TeamAccessError(code);
}

function teamText(value) {
  return Object(value) !== value && Object.prototype.toString.call(value) === '[object String]';
}

function teamRecord(value) {
  if (value === null || Object(value) !== value || Array.isArray(value)) return false;
  return Object.getPrototypeOf(value) === Object.prototype &&
    Reflect.ownKeys(value).every((key) => {
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      return teamText(key) && descriptor.enumerable && Object.hasOwn(descriptor, 'value');
    });
}

function teamKeys(value, keys) {
  return teamRecord(value) && Object.keys(value).length === keys.length &&
    keys.every((key) => Object.hasOwn(value, key));
}

function teamCompare(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
}

function teamFreeze(value) {
  if (value !== null && Object(value) === value) {
    for (const child of Object.values(value)) teamFreeze(child);
    Object.freeze(value);
  }
  return value;
}

function teamName(value, maximum = 512) {
  if (!teamText(value) || value.length === 0 || value.length > maximum || value.trim() !== value) return false;
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code <= 31 || code === 127) return false;
  }
  return true;
}

function teamEmail(value) {
  if (!teamText(value)) teamFail();
  const email = value.trim().toLowerCase();
  if (email.length > 254 || !TEAM_EMAIL.test(email)) teamFail();
  return email;
}

function teamEmails(values, minimum = 0) {
  if (!Array.isArray(values) || values.length < minimum) teamFail();
  const emails = [];
  for (const value of values) emails.push(teamEmail(value));
  if (new Set(emails).size !== emails.length) teamFail();
  return emails.sort(teamCompare);
}

function teamContext(context) {
  if (!teamRecord(context) || !Number.isSafeInteger(context.revision) || context.revision < 0 ||
      context.revision >= Number.MAX_SAFE_INTEGER || !Array.isArray(context.sources) ||
      context.sources.length > TEAM_MAX_SOURCES) teamFail('team_access_invalid_state');
  try {
    const adminEmails = teamEmails(context.adminEmails, 1);
    const sources = new Map();
    for (const source of context.sources) {
      if (!teamKeys(source, ['id', 'label', 'enabledTools', 'installed']) ||
          !teamText(source.id) || !TEAM_SOURCE_ID.test(source.id) || sources.has(source.id) ||
          !teamName(source.label, 80) || (source.installed !== true && source.installed !== false) ||
          !Array.isArray(source.enabledTools) || source.enabledTools.length > 500) teamFail();
      const tools = [];
      for (const name of source.enabledTools) {
        if (!teamText(name) || !TEAM_TOOL.test(name)) teamFail();
        tools.push(name);
      }
      if (new Set(tools).size !== tools.length) teamFail();
      sources.set(source.id, { installed: source.installed });
    }
    return { revision: context.revision, adminEmails, sources };
  } catch {
    teamFail('team_access_invalid_state');
  }
}

function teamMembers(values, context) {
  if (!Array.isArray(values) || values.length === 0) teamFail();
  const emails = new Set();
  const members = [];
  for (const value of values) {
    if (!teamKeys(value, ['email', 'sourceIds']) || !Array.isArray(value.sourceIds) ||
        value.sourceIds.length > TEAM_MAX_SOURCES) teamFail();
    const email = teamEmail(value.email);
    if (emails.has(email)) teamFail();
    emails.add(email);
    const sourceIds = [];
    for (const id of value.sourceIds) {
      if (!teamText(id) || context.sources.get(id)?.installed !== true) teamFail();
      sourceIds.push(id);
    }
    if (new Set(sourceIds).size !== sourceIds.length) teamFail();
    members.push({ email, sourceIds: sourceIds.sort(teamCompare) });
  }
  if (context.adminEmails.some((email) => !emails.has(email))) teamFail('team_access_admin_required');
  return members.sort((left, right) => teamCompare(left.email, right.email));
}

export function normalizeTeamAccessRequest(value, context) {
  const current = teamContext(context);
  if (!teamKeys(value, ['schemaVersion', 'expectedRevision', 'members']) ||
      value.schemaVersion !== 1 || !Number.isSafeInteger(value.expectedRevision) ||
      value.expectedRevision < 0) teamFail();
  if (value.expectedRevision !== current.revision) teamFail('team_access_revision_conflict');
  return teamFreeze({
    schemaVersion: 1,
    expectedRevision: current.revision,
    members: teamMembers(value.members, current),
  });
}

export function teamPolicy(emails, name) {
  if (!teamName(name)) teamFail('team_access_invalid_target');
  const audience = teamEmails(emails);
  return teamFreeze({
    name,
    decision: audience.length === 0 ? 'deny' : 'allow',
    include: audience.length === 0
      ? [{ everyone: {} }]
      : audience.map((email) => ({ email: { email } })),
    exclude: [],
    require: [],
  });
}

function teamPolicyAudience(policy) {
  if (!teamRecord(policy) || !Array.isArray(policy.include) ||
      !Array.isArray(policy.exclude) || policy.exclude.length !== 0 ||
      !Array.isArray(policy.require) || policy.require.length !== 0) teamFail();
  if (policy.decision === 'deny') {
    if (policy.include.length !== 1 || !teamKeys(policy.include[0], ['everyone']) ||
        !teamKeys(policy.include[0].everyone, [])) teamFail();
    return [];
  }
  if (policy.decision !== 'allow' || policy.include.length === 0) teamFail();
  const emails = [];
  for (const rule of policy.include) {
    if (!teamKeys(rule, ['email']) || !teamKeys(rule.email, ['email'])) teamFail();
    emails.push(rule.email.email);
  }
  return teamEmails(emails, 1);
}

function teamNeutralPolicyFields(policy) {
  const metadata = ['id', 'uid', 'account_id', 'created_at', 'updated_at', 'precedence'];
  const body = ['name', 'decision', 'include', 'exclude', 'require'];
  const falseFields = ['approval_required', 'isolation_required', 'purpose_justification_required', 'reusable'];
  const emptyText = ['purpose_justification_prompt', 'session_duration'];
  const emptyObjects = ['connection_rules', 'mfa_config'];
  const known = new Set([...metadata, ...body, ...falseFields, ...emptyText, ...emptyObjects, 'approval_groups']);
  if (Object.keys(policy).some((key) => !known.has(key))) return false;
  if (Object.hasOwn(policy, 'uid') && policy.uid !== policy.id) return false;
  if (falseFields.some((key) => Object.hasOwn(policy, key) && policy[key] !== false)) return false;
  if (emptyText.some((key) => Object.hasOwn(policy, key) && policy[key] !== null && policy[key] !== '')) return false;
  if (emptyObjects.some((key) => Object.hasOwn(policy, key) && policy[key] !== null &&
      !teamKeys(policy[key], []))) return false;
  if (Object.hasOwn(policy, 'approval_groups') &&
      (!Array.isArray(policy.approval_groups) || policy.approval_groups.length !== 0)) return false;
  return !Object.hasOwn(policy, 'precedence') ||
    (Number.isSafeInteger(policy.precedence) && policy.precedence >= 0);
}

export function teamPolicyMatches(observed, expected, policyId) {
  try {
    if (!teamText(policyId) || !TEAM_PROVIDER_ID.test(policyId) || !teamRecord(observed) ||
        !teamRecord(expected) || observed.id !== policyId || observed.name !== expected.name ||
        !teamNeutralPolicyFields(observed)) return false;
    const expectedKeys = ['name', 'decision', 'include', 'exclude', 'require'];
    if (Object.hasOwn(expected, 'precedence')) expectedKeys.push('precedence');
    if (!teamKeys(expected, expectedKeys) || !teamName(expected.name) ||
        (Object.hasOwn(expected, 'precedence') && (!Number.isSafeInteger(expected.precedence) ||
          expected.precedence < 0 || observed.precedence !== expected.precedence))) return false;
    return observed.decision === expected.decision &&
      JSON.stringify(teamPolicyAudience(observed)) === JSON.stringify(teamPolicyAudience(expected));
  } catch {
    return false;
  }
}

function teamTarget(value, source = false) {
  const keys = ['applicationId', 'policyId', 'policyName'];
  if (source) keys.push('sourceId');
  if (!teamKeys(value, keys) || !teamText(value.applicationId) || !TEAM_PROVIDER_ID.test(value.applicationId) ||
      !teamText(value.policyId) || !TEAM_PROVIDER_ID.test(value.policyId) || !teamName(value.policyName) ||
      (source && (!teamText(value.sourceId) || !TEAM_SOURCE_ID.test(value.sourceId)))) {
    teamFail('team_access_invalid_target');
  }
  return { ...value };
}

export function planTeamAccessChange(value, context) {
  const input = normalizeTeamAccessRequest(value, context);
  const current = teamContext(context);
  let previous;
  try { previous = teamMembers(context.currentMembers, current); }
  catch { teamFail('team_access_invalid_state'); }
  const portalTarget = teamTarget(context.portalTarget);
  if (!Array.isArray(context.sourceTargets) || context.sourceTargets.length > TEAM_MAX_SOURCES) {
    teamFail('team_access_invalid_target');
  }
  const sourceTargets = context.sourceTargets.map((target) => teamTarget(target, true))
    .sort((left, right) => teamCompare(left.sourceId, right.sourceId));
  const installedIds = [...current.sources].filter(([, source]) => source.installed).map(([id]) => id).sort(teamCompare);
  if (JSON.stringify(sourceTargets.map((target) => target.sourceId)) !== JSON.stringify(installedIds)) {
    teamFail('team_access_invalid_target');
  }
  const targets = [portalTarget, ...sourceTargets];
  if (new Set(targets.map((target) => target.applicationId)).size !== targets.length ||
      new Set(targets.map((target) => target.policyId)).size !== targets.length) teamFail('team_access_invalid_target');
  const policies = [];
  for (const target of targets) {
    const audience = (members) => members.filter((member) =>
      target.sourceId === undefined || member.sourceIds.includes(target.sourceId)).map((member) => member.email);
    const before = teamPolicy(audience(previous), target.policyName);
    const after = teamPolicy(audience(input.members), target.policyName);
    policies.push({
      kind: target.sourceId === undefined ? 'portal' : 'source',
      ...target,
      before,
      after,
    });
  }
  const policyChanges = policies.filter((policy) => JSON.stringify(policy.before) !== JSON.stringify(policy.after));
  const oldEmails = new Set(previous.map((member) => member.email));
  const newEmails = new Set(input.members.map((member) => member.email));
  return teamFreeze({
    nextState: { schemaVersion: 1, revision: current.revision + 1, members: input.members },
    policies,
    policyChanges,
    summary: {
      addedPeople: input.members.filter((member) => !oldEmails.has(member.email)).length,
      removedPeople: previous.filter((member) => !newEmails.has(member.email)).length,
      changedSources: policyChanges.filter((change) => change.kind === 'source').length,
    },
  });
}

const API_ORIGIN = 'https://api.cloudflare.com';
const BOOTSTRAP_PATH = '/__ankka/bootstrap';
const SOURCE_ACTION_PATH = '/__ankka/source-action';
// Later operations are authorized on the gateway itself; see the installer's operation router.
const OPERATION_PATH = '/__ankka/operation';
const RUNTIME_ACTION_PATH = '/__ankka/runtime-action';
const TEARDOWN_ACTION_PATH = '/__ankka/teardown-action';
const CONTROL_PLANE_ORIGIN = 'https://deploy.ankka.ai';
const RELEASE_ENVELOPE_SCHEMA_VERSION = 2;
const RELEASE_SIGNATURE_CONTEXT = 'ankka-mcp-gateway-release-envelope-v2';
const INTERNAL_BOOTSTRAP_PATH = '/bootstrap';
const INTERNAL_PUBLISH_PATH = '/publish-status';
const INTERNAL_CONTROL_PATH = '/management-control';
const INTERNAL_ACTIONS_PATH = '/source-actions';
const INTERNAL_UPDATES_PATH = '/runtime-updates';
const INTERNAL_TEARDOWNS_PATH = '/teardown-actions';
const INTERNAL_TEARDOWN_ROOT_PATH = '/teardown-root';
const INTERNAL_STATUS_PATH = '/status';
const INTERNAL_SOURCES_PATH = '/sources';
const INTERNAL_TEAM_PATH = '/team';
const INTERNAL_TEAM_ACTIONS_PATH = '/team-actions';
const STORAGE_KEY = 'ankka-mcp-gateway/uninstall-state/v1';
const STATUS_KEY = 'ankka-mcp-gateway/public-status/v1';
const SOURCES_KEY = 'ankka-mcp-gateway/management-sources/v1';
const CONTROL_KEY = 'ankka-mcp-gateway/management-control/v1';
const ACTIONS_KEY = 'ankka-mcp-gateway/source-actions/v1';
const UPDATES_KEY = 'ankka-mcp-gateway/runtime-updates/v1';
const TEARDOWNS_KEY = 'ankka-mcp-gateway/teardown-actions/v1';
const TEAM_KEY = 'ankka-mcp-gateway/team-access/v1';
// New source policies start with no audience. Only a separate Team save grants
// access; historical receipts and their original audiences remain immutable.
const SOURCE_ADDITION_PAUSED = false;
const SOURCE_INITIAL_POLICY_VERSION = 2;
const MANAGER = 'ankka-mcp-gateway';
const PORTAL_CNAME_TARGET = 'gateway.agents.cloudflare.com';
// Public client callbacks; reviewed sources and scope in CUSTOMER_SELF_SERVICE.md.
// ChatGPT's only wildcard covers its connector-specific OAuth callback path.
const DEFAULT_OAUTH_CALLBACKS = Object.freeze([
  'https://claude.ai/api/mcp/auth_callback',
  'https://chatgpt.com/connector_platform_oauth_redirect',
  'https://chatgpt.com/connector/oauth/*',
  'https://www.cursor.com/agents/mcp/oauth/callback',
]);
const REQUEST_LIMIT_BYTES = 96 * 1024;
const BOOTSTRAP_REQUEST_LIMIT_BYTES = 128 * 1024;
const PROVIDER_RESPONSE_LIMIT_BYTES = 4 * 1024 * 1024;
const MCP_RESPONSE_LIMIT_BYTES = 4 * 1024 * 1024;
const MCP_DISCOVERY_LIMIT_BYTES = 8 * 1024 * 1024;
const MCP_REQUEST_LIMIT_BYTES = 32 * 1024;
const SOURCE_SAVE_REQUEST_LIMIT_BYTES = 96 * 1024;
const MANAGEMENT_SOURCES_LIMIT_BYTES = 1024 * 1024;
const MCP_REQUEST_TIMEOUT_MS = 8_000;
const MCP_DISCOVERY_TIMEOUT_MS = 30_000;
const MCP_MAX_PAGES = 20;
const MCP_MAX_TOOLS = 500;
const MAX_ENABLED_TOOLS_PER_SOURCE = 500;
const REQUEST_LIFETIME_SECONDS = 5 * 60;
const VERIFY_DISCOVERY_ATTEMPTS = 4;
const VERIFY_DISCOVERY_BACKOFF_MS = 1_000;
const MAX_CLOCK_SKEW_SECONDS = 30;
const MAX_PROVIDER_PAGES = 20;
const PROVIDER_PAGE_SIZE = 100;
const RESOURCE_ORDER = Object.freeze([
  'mcp_server',
  'source_access_application',
  'source_access_policy',
  'portal',
  'portal_access_application',
  'portal_access_policy',
  'dns_record',
]);
const PORTAL_RESOURCE_ORDER = Object.freeze([
  'portal',
  'portal_access_application',
  'portal_access_policy',
  'dns_record',
]);
const UPDATE_OAUTH_SCOPES = Object.freeze([
  'access-acct.read', 'zone-access.write', 'dns.write', 'mcp-portals.write',
  'workers-routes.read', 'workers-scripts.write', 'zone.read',
]);
const APPROVED_UPDATE_CLOUDFLARE_CONTRACT = Object.freeze({
  assets: Object.freeze({
    binding: 'ASSETS', notFoundHandling: 'single-page-application',
    payloadDirectory: 'payload/admin', runWorkerFirst: Object.freeze(['/__ankka/*', '/api/*']),
  }),
  compatibilityDate: '2026-08-08',
  compatibilityFlags: Object.freeze([]),
  dependenciesInstrumentation: Object.freeze({ enabled: false }),
  durableObjects: Object.freeze({
    bindings: Object.freeze([Object.freeze({ binding: 'ADMIN_STATE', className: 'AdminState' })]),
    exports: Object.freeze({
      AdminState: Object.freeze({ storage: 'sqlite', type: 'durable-object' }),
    }),
  }),
  mainModule: 'index.js',
  observability: Object.freeze({ enabled: false }),
  previewUrls: false,
  publicBindings: Object.freeze({
    secrets: Object.freeze([
      Object.freeze({ lifecycle: 'customer-worker', name: 'ANKKA_GATEWAY_OWNERSHIP_WRAP_KEY' }),
    ]),
    variables: Object.freeze([
      'ADMIN_EMAILS', 'ANKKA_INSTALL_ID', 'ANKKA_GATEWAY_RELEASE', 'ANKKA_GATEWAY_RELEASE_SHA256',
      'ANKKA_MANAGEMENT_HOSTNAME', 'ANKKA_UPDATE_CHANNEL', 'ANKKA_UPDATE_KEY_ID',
      'ANKKA_UPDATE_PUBLIC_KEY', 'ANKKA_WORKERS_SUBDOMAIN', 'ANKKA_WORKER_NAME',
      'CF_ACCESS_AUD', 'CF_ACCESS_ISSUER', 'CLOUDFLARE_ACCOUNT_ID',
      'CLOUDFLARE_ZONE_ID', 'CLOUDFLARE_ZONE_NAME', 'ZERO_TRUST_READY',
    ]),
  }),
  sendMetrics: false,
  workersDev: false,
  workerVariants: Object.freeze({
    bootstrap: Object.freeze({
      assets: Object.freeze({
        binding: 'ASSETS', notFoundHandling: 'single-page-application',
        payloadDirectory: 'payload/admin', runWorkerFirst: Object.freeze(['/__ankka/*', '/api/*']),
      }),
      component: 'workerBootstrap', compatibilityDate: '2026-08-08',
      compatibilityFlags: Object.freeze([]),
      dependenciesInstrumentation: Object.freeze({ enabled: false }),
      durableObjects: Object.freeze({
        bindings: Object.freeze([Object.freeze({ binding: 'ADMIN_STATE', className: 'AdminState' })]),
        exports: Object.freeze({ AdminState: Object.freeze({ storage: 'sqlite', type: 'durable-object' }) }),
      }),
      mainModule: 'index.js', observability: Object.freeze({ enabled: false }),
      payloadDirectory: 'payload/worker-bootstrap', previewUrls: false,
      publicBindings: Object.freeze({
        secrets: Object.freeze([
          Object.freeze({ lifecycle: 'bootstrap-only', name: 'ANKKA_BOOTSTRAP_NONCE' }),
          Object.freeze({ lifecycle: 'customer-worker', name: 'ANKKA_GATEWAY_OWNERSHIP_WRAP_KEY' }),
        ]),
        variables: Object.freeze([
          'ANKKA_BOOTSTRAP_CALLBACK', 'ANKKA_BOOTSTRAP_EXPIRES_AT', 'ANKKA_BOOTSTRAP_ID',
          'ANKKA_BOOTSTRAP_SECRET_SHA256', 'ANKKA_GATEWAY_RELEASE',
          'ANKKA_GATEWAY_RELEASE_SHA256', 'ANKKA_INSTALL_ID', 'ANKKA_INSTALLER_ORIGIN',
          'ANKKA_MANAGEMENT_HOSTNAME',
          'ANKKA_PLAN_HASH', 'ANKKA_PLAN_ID', 'ANKKA_UPDATE_CHANNEL', 'ANKKA_UPDATE_KEY_ID',
          'ANKKA_UPDATE_PUBLIC_KEY', 'ANKKA_WORKER_NAME', 'CLOUDFLARE_ACCOUNT_ID',
          'CLOUDFLARE_CUSTOMER_OAUTH_CLIENT_ID', 'CLOUDFLARE_OWNERSHIP_ISSUER_KEY_ID',
          'CLOUDFLARE_OWNERSHIP_ISSUER_PUBLIC_KEY',
        ]),
      }),
      sendMetrics: false, workersDev: false,
    }),
    cleanup: Object.freeze({
      component: 'workerCleanup', compatibilityDate: '2026-08-08', compatibilityFlags: Object.freeze([]),
      dependenciesInstrumentation: Object.freeze({ enabled: false }),
      durableObjects: Object.freeze({
        bindings: Object.freeze([Object.freeze({ binding: 'ADMIN_STATE', className: 'AdminState' })]),
        exports: Object.freeze({ AdminState: Object.freeze({ storage: 'sqlite', type: 'durable-object' }) }),
      }),
      mainModule: 'index.js', observability: Object.freeze({ enabled: false }),
      payloadDirectory: 'payload/worker-cleanup', previewUrls: false,
      publicBindings: Object.freeze({
        secrets: Object.freeze([Object.freeze({ lifecycle: 'uninstall-attempt', name: 'ANKKA_UNINSTALL_NONCE' })]),
        variables: Object.freeze([
          'ANKKA_GATEWAY_RELEASE', 'ANKKA_GATEWAY_RELEASE_SHA256', 'CLOUDFLARE_ACCOUNT_ID',
          'CLOUDFLARE_ZONE_ID', 'CLOUDFLARE_ZONE_NAME', 'ZERO_TRUST_READY',
        ]),
      }),
      publicPath: '/__ankka/uninstall', sendMetrics: false, workersDev: false,
    }),
    retirement: Object.freeze({
      component: 'workerRetirement', compatibilityDate: '2026-08-08', compatibilityFlags: Object.freeze([]),
      dependenciesInstrumentation: Object.freeze({ enabled: false }),
      durableObjects: Object.freeze({
        bindings: Object.freeze([]),
        exports: Object.freeze({ AdminState: Object.freeze({ state: 'deleted', type: 'durable-object' }) }),
      }),
      mainModule: 'index.js', observability: Object.freeze({ enabled: false }),
      payloadDirectory: 'payload/worker-retirement', previewUrls: false,
      publicBindings: Object.freeze({ secrets: Object.freeze([]), variables: Object.freeze([]) }),
      sendMetrics: false, workersDev: false,
    }),
  }),
});
const HASH = /^sha256:[a-f0-9]{64}$/u;
const INSTALLATION_ID = /^acg-[a-f0-9]{24}$/u;
const PLAN_ID = /^plan-[a-f0-9]{24}$/u;
const REQUEST_ID = /^[A-Za-z0-9_-]{22}$/u;
const RELEASE = /^[A-Za-z0-9][A-Za-z0-9._+-]{0,79}$/u;
const RESOURCE_KEY = /^[a-z][a-z0-9-]{0,31}$/u;
const SAFE_ID = /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$/u;
const ACCOUNT_ID = /^[a-f0-9]{32}$/u;
const ZONE_ID = /^[a-f0-9]{32}$/u;
const HOST_LABEL = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/u;
const NONCE = /^[A-Za-z0-9_-]{43}$/u;
const SIGNATURE = /^sha256=[a-f0-9]{64}$/u;
const EMAIL = /^[^\s@]{1,64}@[A-Za-z0-9.-]{1,190}$/u;
const TOOL = /^[A-Za-z0-9_.:/-]{1,128}$/u;
const SOURCE_ID = /^source-[a-f0-9]{16}$/u;
const ACTION_ID = /^action_[A-Za-z0-9_-]{32}$/u;
const KEY_ID = /^[a-z0-9][a-z0-9._-]{0,63}$/u;
const PUBLIC_KEY = /^[A-Za-z0-9_-]{43}$/u;
const WORKER_NAME = /^[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$/u;
const VERSION_ID = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/u;
const PUBLIC_HEADERS = Object.freeze({
  'cache-control': 'no-store',
  'content-type': 'application/json; charset=utf-8',
  'cross-origin-resource-policy': 'same-origin',
  'permissions-policy': 'camera=(), geolocation=(), microphone=(), payment=(), usb=()',
  'referrer-policy': 'no-referrer',
  'x-content-type-options': 'nosniff',
  'x-frame-options': 'DENY',
});
const OBJECT_TAG = Object.prototype.toString;
const FUNCTION_SOURCE = Function.prototype.toString;

function hasPrimitiveTag(value, tag) {
  return Object(value) !== value && OBJECT_TAG.call(value) === tag;
}

function isText(value) {
  return hasPrimitiveTag(value, '[object String]');
}

function hasControlCharacter(value) {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code <= 31 || code === 127) return true;
  }
  return false;
}

function isFiniteNumber(value) {
  return hasPrimitiveTag(value, '[object Number]') && Number.isFinite(value);
}

function isBoolean(value) {
  return hasPrimitiveTag(value, '[object Boolean]');
}

function isReference(value) {
  return value !== null && value !== undefined && Object(value) === value;
}

function isCallable(value) {
  try {
    FUNCTION_SOURCE.call(value);
    return true;
  } catch {
    return false;
  }
}

function isObjectReference(value) {
  return isReference(value) && !isCallable(value);
}

function compareText(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
}

function isRecord(value) {
  if (value === null || !isObjectReference(value) || Array.isArray(value)) return false;
  try {
    if (Object.getPrototypeOf(value) !== Object.prototype) return false;
    const descriptors = Object.getOwnPropertyDescriptors(value);
    return Object.values(descriptors).every((descriptor) => (
      descriptor.enumerable === true && 'value' in descriptor
    ));
  } catch {
    return false;
  }
}

function exactKeys(value, expected) {
  if (!isRecord(value)) return false;
  const actual = Object.keys(value).sort(compareText);
  const keys = [...expected].sort(compareText);
  return actual.length === keys.length && actual.every((key, index) => key === keys[index]);
}

function isPlainData(value, seen = new Set()) {
  if (value === null || isBoolean(value) || isText(value) || isFiniteNumber(value)) return true;
  if (!isObjectReference(value) || seen.has(value)) return false;
  seen.add(value);
  if (Array.isArray(value)) return value.every((entry) => isPlainData(entry, seen));
  if (!isRecord(value)) return false;
  return Object.values(value).every((entry) => isPlainData(entry, seen));
}

function canonicalJson(value) {
  if (value === null || isBoolean(value) || isText(value)) {
    return JSON.stringify(value);
  }
  if (isFiniteNumber(value)) return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (isRecord(value)) {
    return `{${Object.keys(value)
      .sort(compareText)
      .map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`)
      .join(',')}}`;
  }
  throw new TypeError('canonical_json_invalid');
}

function base64UrlEncode(bytes) {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/u, '');
}

function base64UrlDecode(value) {
  if (!isText(value) || !/^[A-Za-z0-9_-]*$/u.test(value)) return null;
  try {
    const padded = value.replaceAll('-', '+').replaceAll('_', '/') + '='.repeat((4 - value.length % 4) % 4);
    const binary = atob(padded);
    const bytes = Uint8Array.from(binary, (character) => character.charCodeAt(0));
    return base64UrlEncode(bytes) === value ? bytes : null;
  } catch {
    return null;
  }
}

function randomBase64Url(byteLength) {
  const bytes = new Uint8Array(byteLength);
  crypto.getRandomValues(bytes);
  try { return base64UrlEncode(bytes); } finally { bytes.fill(0); }
}

async function sha256(value) {
  const digest = new Uint8Array(await crypto.subtle.digest(
    'SHA-256',
    new TextEncoder().encode(isText(value) ? value : canonicalJson(value)),
  ));
  const result = `sha256:${[...digest].map((byte) => byte.toString(16).padStart(2, '0')).join('')}`;
  digest.fill(0);
  return result;
}

async function sha256Hex(value) {
  return (await sha256(value)).slice('sha256:'.length);
}

function fixedJson(status, body, headers = {}) {
  return new Response(canonicalJson(body), {
    status,
    headers: { ...PUBLIC_HEADERS, ...headers },
  });
}

function rejected(status = 400) {
  return fixedJson(status, { schemaVersion: 1, error: 'bootstrap_rejected', retryable: false });
}

function recovery(reason) {
  return fixedJson(409, {
    schemaVersion: 1,
    error: reason,
    retryable: reason === 'bootstrap_recovery_required',
  });
}

function hostname(value) {
  if (
    !isText(value) || value.length > 253 || value !== value.toLowerCase() ||
    value.includes(':') || /^(?:\d+\.)+\d+$/u.test(value)
  ) return false;
  const labels = value.split('.');
  return labels.length >= 2 && labels.every((label) => HOST_LABEL.test(label));
}

function normalizedEmail(value) {
  if (!isText(value)) return null;
  const email = value.trim().toLowerCase();
  return email.length <= 254 && EMAIL.test(email) ? email : null;
}

function exactSortedUniqueStrings(value, parser, maximum = Infinity, minimum = 0) {
  if (!Array.isArray(value) || value.length < minimum || value.length > maximum) return null;
  const parsed = [];
  for (const entry of value) {
    const item = parser(entry);
    if (item === null) return null;
    parsed.push(item);
  }
  const sorted = [...new Set(parsed)].sort(compareText);
  if (sorted.length !== parsed.length || canonicalJson(sorted) !== canonicalJson(parsed)) return null;
  return Object.freeze(sorted);
}

function canonicalBase64Url32(value) {
  if (!isText(value) || !NONCE.test(value)) return null;
  let decoded;
  try {
    const raw = atob(`${value.replaceAll('-', '+').replaceAll('_', '/')}=`);
    decoded = Uint8Array.from(raw, (character) => character.charCodeAt(0));
  } catch {
    return null;
  }
  if (decoded.byteLength !== 32 || decoded.every((byte) => byte === 0)) {
    decoded.fill(0);
    return null;
  }
  const canonical = btoa(String.fromCharCode(...decoded))
    .replaceAll('+', '-')
    .replaceAll('/', '_')
    .replace(/=+$/u, '');
  if (canonical !== value) {
    decoded.fill(0);
    return null;
  }
  return decoded;
}

function hexBytes(value) {
  if (!isText(value) || !SIGNATURE.test(value)) return null;
  return Uint8Array.from(value.slice('sha256='.length).match(/../gu) ?? [], (hex) => (
    Number.parseInt(hex, 16)
  ));
}

async function verifyHmac(rawBody, encodedNonce, signatureHeader) {
  const keyBytes = canonicalBase64Url32(encodedNonce);
  const signature = hexBytes(signatureHeader);
  if (!keyBytes || !signature || signature.byteLength !== 32) {
    keyBytes?.fill(0);
    signature?.fill(0);
    return false;
  }
  try {
    const key = await crypto.subtle.importKey(
      'raw', keyBytes, { name: 'HMAC', hash: 'SHA-256' }, false, ['verify'],
    );
    return await crypto.subtle.verify(
      'HMAC', key, signature, new TextEncoder().encode(rawBody),
    );
  } catch {
    return false;
  } finally {
    keyBytes.fill(0);
    signature.fill(0);
  }
}

async function readBoundedTextRecord(request, limit) {
  const declared = request.headers.get('content-length');
  if (declared !== null) {
    const size = Number(declared);
    if (!Number.isSafeInteger(size) || size < 0 || size > limit) {
      try { await request.body?.cancel(); } catch { /* The declared bound remains authoritative. */ }
      return null;
    }
  }
  if (!request.body) return null;
  const reader = request.body.getReader();
  const chunks = [];
  let total = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      if (value.byteLength > limit - total) {
        try { await reader.cancel(); } catch { /* The size failure is authoritative. */ }
        return null;
      }
      if (value.byteLength > 0) {
        chunks.push(value.slice());
        total += value.byteLength;
      }
    }
    if (total === 0) return null;
    const bytes = new Uint8Array(total);
    let offset = 0;
    for (const chunk of chunks) {
      bytes.set(chunk, offset);
      offset += chunk.byteLength;
    }
    try {
      return Object.freeze({
        text: new TextDecoder('utf-8', { fatal: true }).decode(bytes),
        byteLength: total,
      });
    } catch {
      return null;
    } finally {
      bytes.fill(0);
    }
  } catch {
    try { await reader.cancel(); } catch { /* The fixed rejection remains authoritative. */ }
    return null;
  } finally {
    for (const chunk of chunks) chunk.fill(0);
    try { reader.releaseLock(); } catch { /* The fixed rejection remains authoritative. */ }
  }
}

async function readBoundedText(request, limit) {
  return (await readBoundedTextRecord(request, limit))?.text ?? null;
}

class SourceDiscoveryError extends Error {
  constructor(status, code) {
    super(code);
    this.name = 'SourceDiscoveryError';
    this.status = status;
    this.code = code;
  }
}

function sourceFailure(error) {
  return error instanceof SourceDiscoveryError
    ? error
    : new SourceDiscoveryError(502, 'source_unreachable');
}

function validSourceLabel(value) {
  return isText(value) && value.length >= 2 && value.length <= 80 &&
    value.trim() === value && !hasControlCharacter(value);
}

function publicMcpUrl(value) {
  if (!isText(value) || value.length > 2048) return null;
  let url;
  try { url = new URL(value); } catch { return null; }
  const blockedSuffixes = ['.internal', '.invalid', '.local', '.localhost', '.onion', '.test'];
  if (url.protocol !== 'https:' || url.username || url.password || url.port || url.search || url.hash ||
      url.pathname === '/' || !hostname(url.hostname) ||
      url.hostname === 'localhost' || blockedSuffixes.some((suffix) => url.hostname.endsWith(suffix))) return null;
  return url.href;
}

function hasStandardOauthChallenge(response) {
  const challenge = response.headers.get('www-authenticate');
  if (!isText(challenge) || !/^\s*Bearer(?:\s|$)/iu.test(challenge)) return false;
  const match = challenge.match(/(?:^|[\s,])resource_metadata=(?:"([^"\r\n]+)"|([^,\s]+))/iu);
  const value = match?.[1] ?? match?.[2];
  if (!value || value.length > 2048) return false;
  let url;
  try { url = new URL(value); } catch { return false; }
  const blockedSuffixes = ['.internal', '.invalid', '.local', '.localhost', '.onion', '.test'];
  return url.protocol === 'https:' && !url.username && !url.password && !url.port && !url.hash &&
    hostname(url.hostname) && url.hostname !== 'localhost' &&
    !blockedSuffixes.some((suffix) => url.hostname.endsWith(suffix));
}

function parseJsonRpcMessage(serialized, contentType, requestId) {
  const candidates = [];
  if (contentType.startsWith('application/json')) {
    try { candidates.push(JSON.parse(serialized)); } catch { return null; }
  } else if (contentType.startsWith('text/event-stream')) {
    for (const event of serialized.split(/\r?\n\r?\n/u)) {
      const data = event.split(/\r?\n/u)
        .filter((line) => line.startsWith('data:'))
        .map((line) => line.slice(5).trimStart())
        .join('\n');
      if (!data) continue;
      try { candidates.push(JSON.parse(data)); } catch { return null; }
    }
  } else {
    return null;
  }
  return candidates.find((candidate) => isRecord(candidate) && candidate.jsonrpc === '2.0' &&
    candidate.id === requestId) ?? null;
}

function createMcpDiscoveryBudget() {
  const controller = new AbortController();
  let remainingBytes = MCP_DISCOVERY_LIMIT_BYTES;
  const timer = setTimeout(() => controller.abort(), MCP_DISCOVERY_TIMEOUT_MS);
  return {
    signal: controller.signal,
    responseLimit() {
      return Math.min(MCP_RESPONSE_LIMIT_BYTES, remainingBytes);
    },
    consume(byteLength) {
      if (!Number.isSafeInteger(byteLength) || byteLength < 0 || byteLength > remainingBytes) return false;
      remainingBytes -= byteLength;
      return true;
    },
    close() {
      clearTimeout(timer);
      controller.abort();
    },
  };
}

function createMcpRequestAbort(budget) {
  const controller = new AbortController();
  const abort = () => controller.abort();
  const timer = setTimeout(abort, MCP_REQUEST_TIMEOUT_MS);
  if (budget.signal.aborted) abort();
  else budget.signal.addEventListener('abort', abort, { once: true });
  return {
    signal: controller.signal,
    close() {
      clearTimeout(timer);
      budget.signal.removeEventListener('abort', abort);
      controller.abort();
    },
  };
}

async function mcpPost(endpoint, message, headers, budget) {
  const requestAbort = createMcpRequestAbort(budget);
  try {
    let response;
    try {
      response = await fetch(new Request(endpoint, {
        method: 'POST',
        headers: {
          accept: 'application/json, text/event-stream',
          'content-type': 'application/json',
          ...headers,
        },
        body: canonicalJson(message),
        redirect: 'manual',
        signal: requestAbort.signal,
      }));
    } catch {
      throw new SourceDiscoveryError(502, 'source_unreachable');
    }
    if (!(response instanceof Response) || response.redirected || response.status >= 300 && response.status < 400) {
      if (response instanceof Response) await discardBody(response);
      throw new SourceDiscoveryError(502, 'source_protocol_invalid');
    }
    if (response.status === 401 || response.status === 403) {
      const standardOauth = response.status === 401 && hasStandardOauthChallenge(response);
      await discardBody(response);
      throw new SourceDiscoveryError(
        401,
        standardOauth ? 'source_authentication_required' : 'source_authentication_unsupported',
      );
    }
    if (!response.ok) {
      await discardBody(response);
      throw new SourceDiscoveryError(
        [400, 405, 415, 422, 501].includes(response.status) ? 409 : 502,
        [400, 405, 415, 422, 501].includes(response.status)
          ? 'source_protocol_unsupported'
          : 'source_unreachable',
      );
    }
    const serialized = await readBoundedTextRecord(response, budget.responseLimit());
    if (!serialized || !budget.consume(serialized.byteLength)) {
      throw new SourceDiscoveryError(502, 'source_response_invalid');
    }
    const parsed = parseJsonRpcMessage(
      serialized.text,
      (response.headers.get('content-type') ?? '').toLowerCase(),
      message.id,
    );
    if (!parsed) throw new SourceDiscoveryError(502, 'source_response_invalid');
    return Object.freeze({ parsed, sessionId: response.headers.get('mcp-session-id') });
  } finally {
    requestAbort.close();
  }
}

async function mcpNotification(endpoint, message, headers, budget) {
  const requestAbort = createMcpRequestAbort(budget);
  try {
    let response;
    try {
      response = await fetch(new Request(endpoint, {
        method: 'POST',
        headers: {
          accept: 'application/json, text/event-stream',
          'content-type': 'application/json',
          ...headers,
        },
        body: canonicalJson(message),
        redirect: 'manual',
        signal: requestAbort.signal,
      }));
    } catch {
      throw new SourceDiscoveryError(502, 'source_unreachable');
    }
    if (!(response instanceof Response) || response.redirected || ![200, 202, 204].includes(response.status)) {
      if (response instanceof Response) await discardBody(response);
      throw new SourceDiscoveryError(502, 'source_response_invalid');
    }
    await discardBody(response);
  } finally {
    requestAbort.close();
  }
}

function requireMcpResult(message, allowUnsupported = false) {
  if (!isRecord(message) || message.jsonrpc !== '2.0') {
    throw new SourceDiscoveryError(502, 'source_response_invalid');
  }
  if (isRecord(message.error)) {
    throw new SourceDiscoveryError(
      allowUnsupported ? 409 : 502,
      allowUnsupported ? 'source_protocol_unsupported' : 'source_response_invalid',
    );
  }
  if (!isRecord(message.result)) throw new SourceDiscoveryError(502, 'source_response_invalid');
  return message.result;
}

function safeToolSummary(value) {
  if (!isRecord(value) || !isText(value.name) || !TOOL.test(value.name)) return null;
  const optionalText = (input, maximum) => (
    isText(input) && input.length <= maximum && !hasControlCharacter(input) ? input : null
  );
  const annotations = isRecord(value.annotations) ? value.annotations : {};
  const hint = (name) => isBoolean(annotations[name]) ? annotations[name] : null;
  const readOnlyHint = hint('readOnlyHint');
  const destructiveHint = hint('destructiveHint');
  return Object.freeze({
    name: value.name,
    title: optionalText(value.title, 160),
    description: optionalText(value.description, 2_000),
    readOnlyHint,
    destructiveHint,
    openWorldHint: hint('openWorldHint'),
    defaultSelected: readOnlyHint === true && destructiveHint === false,
  });
}

function collectToolPage(result, tools, names) {
  if (!Array.isArray(result.tools) || result.tools.length > MCP_MAX_TOOLS) {
    throw new SourceDiscoveryError(502, 'source_tool_list_invalid');
  }
  for (const candidate of result.tools) {
    const tool = safeToolSummary(candidate);
    if (!tool || names.has(tool.name) || tools.length >= MCP_MAX_TOOLS) {
      throw new SourceDiscoveryError(502, 'source_tool_list_invalid');
    }
    names.add(tool.name);
    tools.push(tool);
  }
  if (!Object.hasOwn(result, 'nextCursor')) return undefined;
  if (!isText(result.nextCursor) || result.nextCursor.length > 2048 || hasControlCharacter(result.nextCursor)) {
    throw new SourceDiscoveryError(502, 'source_tool_list_invalid');
  }
  return result.nextCursor;
}

function modernRequestMeta() {
  return {
    'io.modelcontextprotocol/clientInfo': {
      name: 'ankka-mcp-gateway',
      version: '1.0.0',
    },
  };
}

async function discoverModernMcpTools(endpoint, budget) {
  const tools = [];
  const names = new Set();
  let cursor;
  for (let page = 0; page < MCP_MAX_PAGES; page += 1) {
    const id = page + 1;
    const params = { _meta: modernRequestMeta() };
    if (cursor !== undefined) params.cursor = cursor;
    const response = await mcpPost(endpoint, {
      jsonrpc: '2.0', id, method: 'tools/list', params,
    }, {
      'mcp-protocol-version': '2026-07-28',
      'mcp-method': 'tools/list',
    }, budget);
    cursor = collectToolPage(requireMcpResult(response.parsed, true), tools, names);
    if (cursor === undefined) return Object.freeze({ protocolVersion: '2026-07-28', tools: Object.freeze(tools) });
  }
  throw new SourceDiscoveryError(502, 'source_tool_list_invalid');
}

function safeSessionId(value) {
  return isText(value) && /^[\x21-\x7e]{1,256}$/u.test(value) ? value : null;
}

async function discoverLegacyMcpTools(endpoint, budget) {
  const initialized = await mcpPost(endpoint, {
    jsonrpc: '2.0',
    id: 1,
    method: 'initialize',
    params: {
      protocolVersion: '2025-06-18',
      capabilities: {},
      clientInfo: { name: 'ankka-mcp-gateway', version: '1.0.0' },
    },
  }, { 'mcp-method': 'initialize' }, budget);
  const result = requireMcpResult(initialized.parsed);
  if (!isText(result.protocolVersion) ||
      !/^2025-(?:03-26|06-18|11-25)$/u.test(result.protocolVersion)) {
    throw new SourceDiscoveryError(502, 'source_protocol_unsupported');
  }
  const sessionId = initialized.sessionId === null ? null : safeSessionId(initialized.sessionId);
  if (initialized.sessionId !== null && !sessionId) {
    throw new SourceDiscoveryError(502, 'source_response_invalid');
  }
  const baseHeaders = {
    'mcp-protocol-version': result.protocolVersion,
  };
  if (sessionId) baseHeaders['mcp-session-id'] = sessionId;
  await mcpNotification(endpoint, {
    jsonrpc: '2.0', method: 'notifications/initialized',
  }, { ...baseHeaders, 'mcp-method': 'notifications/initialized' }, budget);
  const tools = [];
  const names = new Set();
  let cursor;
  for (let page = 0; page < MCP_MAX_PAGES; page += 1) {
    const id = page + 2;
    const params = cursor === undefined ? {} : { cursor };
    const response = await mcpPost(endpoint, {
      jsonrpc: '2.0', id, method: 'tools/list', params,
    }, { ...baseHeaders, 'mcp-method': 'tools/list' }, budget);
    cursor = collectToolPage(requireMcpResult(response.parsed), tools, names);
    if (cursor === undefined) return Object.freeze({
      protocolVersion: result.protocolVersion,
      tools: Object.freeze(tools),
    });
  }
  throw new SourceDiscoveryError(502, 'source_tool_list_invalid');
}

async function discoverMcpTools(value) {
  const endpoint = publicMcpUrl(value);
  if (!endpoint) throw new SourceDiscoveryError(400, 'source_url_invalid');
  const budget = createMcpDiscoveryBudget();
  try {
    try {
      const discovered = await discoverModernMcpTools(endpoint, budget);
      return Object.freeze({ endpoint, ...discovered });
    } catch (error) {
      const stable = sourceFailure(error);
      if (stable.code !== 'source_protocol_unsupported') throw stable;
    }
    try {
      const discovered = await discoverLegacyMcpTools(endpoint, budget);
      return Object.freeze({ endpoint, ...discovered });
    } catch (error) {
      const stable = sourceFailure(error);
      if (stable.code === 'source_protocol_unsupported') {
        throw new SourceDiscoveryError(502, 'source_response_invalid');
      }
      throw stable;
    }
  } finally {
    budget.close();
  }
}

async function inspectMcpSource(value) {
  const endpoint = publicMcpUrl(value);
  if (!endpoint) throw new SourceDiscoveryError(400, 'source_url_invalid');
  // Google's public catalogue does not make its operations unauthenticated.
  // Manual Portal OAuth currently has no shared administrative credential flow.
  const connectionBlock = bigQueryConnectionBlock(endpoint);
  const connection = connectionBlock ? { connectionBlock } : {};
  try {
    const discovered = await discoverMcpTools(endpoint);
    return Object.freeze({ authMode: connectionBlock ? 'oauth' : 'none', ...discovered, ...connection });
  } catch (error) {
    const stable = sourceFailure(error);
    if (stable.code !== 'source_authentication_required') throw stable;
    return Object.freeze({
      authMode: 'oauth',
      endpoint,
      protocolVersion: '2026-07-28',
      tools: Object.freeze([]),
      ...connection,
    });
  }
}

function bigQueryConnectionBlock(endpoint) {
  return endpoint === 'https://bigquery.googleapis.com/mcp'
    ? 'source_google_shared_oauth_unsupported'
    : null;
}

async function verifyManagedSource(source) {
  const connectionBlock = bigQueryConnectionBlock(publicMcpUrl(source.url));
  if (connectionBlock) throw new SourceDiscoveryError(409, connectionBlock);
  const inspected = await inspectMcpSource(source.url);
  if (inspected.authMode !== source.authMode) {
    throw new SourceDiscoveryError(409, 'source_authentication_changed');
  }
  if (source.authMode === 'none') {
    const available = new Set(inspected.tools.map((tool) => tool.name));
    if (source.enabledTools.some((tool) => !available.has(tool))) {
      throw new SourceDiscoveryError(409, 'source_tools_changed');
    }
  }
  return inspected;
}

function parseEnvironment(env, requireNonce = false) {
  if (!env || !isObjectReference(env)) return null;
  const value = {
    accountId: env.CLOUDFLARE_ACCOUNT_ID,
    zoneId: env.CLOUDFLARE_ZONE_ID,
    zoneName: env.CLOUDFLARE_ZONE_NAME,
    installId: env.ANKKA_INSTALL_ID,
    release: env.ANKKA_GATEWAY_RELEASE,
    releaseSha256: env.ANKKA_GATEWAY_RELEASE_SHA256,
    zeroTrustReady: env.ZERO_TRUST_READY,
    bootstrapNonce: env.ANKKA_BOOTSTRAP_NONCE,
  };
  if (
    !isText(value.accountId) || !ACCOUNT_ID.test(value.accountId) ||
    !isText(value.zoneId) || !ACCOUNT_ID.test(value.zoneId) ||
    !isText(value.installId) || !INSTALLATION_ID.test(value.installId) ||
    !hostname(value.zoneName) || !isText(value.release) || !RELEASE.test(value.release) ||
    !isText(value.releaseSha256) || !HASH.test(value.releaseSha256) ||
    value.zeroTrustReady !== 'true' ||
    (requireNonce && (!isText(value.bootstrapNonce) || !NONCE.test(value.bootstrapNonce)))
  ) return null;
  return Object.freeze(value);
}

function parseManagementEnvironment(env) {
  const base = parseEnvironment(env, false);
  if (!base || !isText(env.ANKKA_WORKER_NAME) || !WORKER_NAME.test(env.ANKKA_WORKER_NAME) ||
      !isText(env.ANKKA_WORKERS_SUBDOMAIN) || !HOST_LABEL.test(env.ANKKA_WORKERS_SUBDOMAIN) ||
      !hostname(env.ANKKA_MANAGEMENT_HOSTNAME) || !['canary', 'stable'].includes(env.ANKKA_UPDATE_CHANNEL) ||
      !isText(env.ANKKA_UPDATE_KEY_ID) || !KEY_ID.test(env.ANKKA_UPDATE_KEY_ID) ||
      !isText(env.ANKKA_UPDATE_PUBLIC_KEY) || !PUBLIC_KEY.test(env.ANKKA_UPDATE_PUBLIC_KEY)) return null;
  return Object.freeze({
    ...base,
    workerName: env.ANKKA_WORKER_NAME,
    workersSubdomain: env.ANKKA_WORKERS_SUBDOMAIN,
    managementHostname: env.ANKKA_MANAGEMENT_HOSTNAME,
    updateChannel: env.ANKKA_UPDATE_CHANNEL,
    updateKeyId: env.ANKKA_UPDATE_KEY_ID,
    updatePublicKey: env.ANKKA_UPDATE_PUBLIC_KEY,
  });
}

function exactReleaseIdentity(environment) {
  return Object.freeze({
    schemaVersion: 1,
    channel: environment.updateChannel,
    controlPlaneOrigin: CONTROL_PLANE_ORIGIN,
    release: environment.release,
    keyId: environment.updateKeyId,
    publicKey: environment.updatePublicKey,
    artifactSha256: environment.releaseSha256.slice('sha256:'.length),
  });
}

function updateSemver(value) {
  const match = /^gateway-v(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/u.exec(value);
  return match ? match.slice(1).map(Number) : null;
}

function compareUpdateRelease(left, right) {
  const a = updateSemver(left);
  const b = updateSemver(right);
  if (!a || !b) return null;
  for (let index = 0; index < 3; index += 1) {
    if (a[index] !== b[index]) return a[index] < b[index] ? -1 : 1;
  }
  return 0;
}

function parseUpdateFile(value, component) {
  if (!exactKeys(value, ['byteSize', 'contentType', 'path', 'sha256']) ||
      !Number.isSafeInteger(value.byteSize) || value.byteSize < 0 || value.byteSize > 8 * 1024 * 1024 ||
      !isText(value.contentType) || value.contentType.length < 1 || value.contentType.length > 128 ||
      !isText(value.path) || !value.path.startsWith(`payload/${component}/`) ||
      value.path.includes('\\') || value.path.split('/').some((pathPart) => !pathPart || pathPart === '.' || pathPart === '..') ||
      !isText(value.sha256) || !/^[a-f0-9]{64}$/u.test(value.sha256)) return null;
  return Object.freeze({ ...value });
}

async function parseUpdateComponent(value, component) {
  if (!exactKeys(value, ['byteSize', 'fileCount', 'files', 'treeSha256']) ||
      !Number.isSafeInteger(value.byteSize) || value.byteSize < 0 || value.byteSize > 32 * 1024 * 1024 ||
      !Number.isSafeInteger(value.fileCount) || value.fileCount < 1 || value.fileCount > 10_000 ||
      !Array.isArray(value.files) || value.files.length !== value.fileCount ||
      !isText(value.treeSha256) || !/^[a-f0-9]{64}$/u.test(value.treeSha256)) return null;
  const files = value.files.map((file) => parseUpdateFile(file, component));
  if (files.some((file) => file === null) || files.some((file, index) => index > 0 && files[index - 1].path >= file.path) ||
      files.reduce((sum, file) => sum + file.byteSize, 0) !== value.byteSize ||
      await sha256Hex(canonicalJson(files)) !== value.treeSha256) return null;
  return Object.freeze({ ...value, files: Object.freeze(files) });
}

async function parseSignedUpdateManifest(serialized) {
  if (!isText(serialized) || serialized.length < 1 || serialized.length > 8 * 1024 * 1024) return null;
  let value;
  try { value = JSON.parse(serialized); } catch { return null; }
  if (!isPlainData(value) || canonicalJson(value) !== serialized || !exactKeys(value, [
    'artifact', 'cloudflare', 'components', 'controlPlaneOrigin', 'oauthScopeIds', 'release', 'schemaVersion', 'sourceCommit',
  ]) || value.schemaVersion !== 1 || !updateSemver(value.release) ||
      value.controlPlaneOrigin !== CONTROL_PLANE_ORIGIN ||
      !isText(value.sourceCommit) || !/^[a-f0-9]{40}$/u.test(value.sourceCommit) ||
      canonicalJson(value.cloudflare) !== canonicalJson(APPROVED_UPDATE_CLOUDFLARE_CONTRACT) ||
      canonicalJson(value.oauthScopeIds) !== canonicalJson(UPDATE_OAUTH_SCOPES) ||
      !exactKeys(value.artifact, ['byteSize', 'fileCount', 'treeSha256']) ||
      !Number.isSafeInteger(value.artifact.byteSize) || value.artifact.byteSize < 1 ||
      value.artifact.byteSize > 32 * 1024 * 1024 ||
      !Number.isSafeInteger(value.artifact.fileCount) || value.artifact.fileCount < 1 ||
      value.artifact.fileCount > 10_000 || !isText(value.artifact.treeSha256) ||
      !/^[a-f0-9]{64}$/u.test(value.artifact.treeSha256) || !exactKeys(value.components, [
        'admin', 'installer', 'worker', 'workerBootstrap', 'workerCleanup', 'workerRetirement',
      ])) return null;
  const components = {};
  for (const [name, directory] of [
    ['admin', 'admin'], ['installer', 'installer'], ['worker', 'worker'],
    ['workerBootstrap', 'worker-bootstrap'],
    ['workerCleanup', 'worker-cleanup'], ['workerRetirement', 'worker-retirement'],
  ]) {
    components[name] = await parseUpdateComponent(value.components[name], directory);
    if (!components[name]) return null;
  }
  const files = Object.values(components).flatMap((component) => component.files)
    .sort((left, right) => compareText(left.path, right.path));
  if (files.length !== value.artifact.fileCount ||
      files.reduce((sum, file) => sum + file.byteSize, 0) !== value.artifact.byteSize ||
      await sha256Hex(canonicalJson(files)) !== value.artifact.treeSha256) return null;
  return Object.freeze({ ...value, components: Object.freeze(components) });
}

async function verifyUpdateEnvelope(value, environment) {
  if (!exactKeys(value, [
    'algorithm', 'channel', 'keyId', 'manifest', 'schemaVersion', 'signature', 'signatureContext',
  ]) || value.algorithm !== 'ed25519' || value.channel !== environment.updateChannel ||
      value.keyId !== environment.updateKeyId || value.schemaVersion !== RELEASE_ENVELOPE_SCHEMA_VERSION ||
      value.signatureContext !== RELEASE_SIGNATURE_CONTEXT ||
      !isText(value.manifest) || !isText(value.signature) ||
      !/^[A-Za-z0-9_-]{86}$/u.test(value.signature)) return null;
  const publicBytes = base64UrlDecode(environment.updatePublicKey);
  const signatureBytes = base64UrlDecode(value.signature);
  if (!publicBytes || publicBytes.byteLength !== 32 || !signatureBytes || signatureBytes.byteLength !== 64) return null;
  try {
    const key = await crypto.subtle.importKey('raw', publicBytes, { name: 'Ed25519' }, false, ['verify']);
    const statement = canonicalJson({
      channel: value.channel,
      keyId: value.keyId,
      manifest: value.manifest,
      schemaVersion: RELEASE_ENVELOPE_SCHEMA_VERSION,
      signatureContext: RELEASE_SIGNATURE_CONTEXT,
    });
    if (!await crypto.subtle.verify(
      'Ed25519', key, signatureBytes, new TextEncoder().encode(statement),
    )) return null;
  } catch { return null; } finally { publicBytes.fill(0); signatureBytes.fill(0); }
  return parseSignedUpdateManifest(value.manifest);
}

async function parseUpdateChannel(value, environment) {
  if (!exactKeys(value, ['channel', 'classification', 'notes', 'release', 'schemaVersion', 'verification']) ||
      value.schemaVersion !== 1 || value.channel !== environment.updateChannel ||
      !exactKeys(value.release, ['artifactSha256', 'id', 'sourceCommit']) || !updateSemver(value.release.id) ||
      !isText(value.release.artifactSha256) || !HASH.test(value.release.artifactSha256) ||
      !isText(value.release.sourceCommit) || !/^[a-f0-9]{40}$/u.test(value.release.sourceCommit) ||
      !exactKeys(value.classification, ['changes', 'excludes', 'kind', 'updaterProtocol']) ||
      value.classification.kind !== 'normal' || value.classification.updaterProtocol !== 2 ||
      canonicalJson(value.classification.changes) !== canonicalJson(['customer_worker_code', 'management_assets']) ||
      canonicalJson(value.classification.excludes) !== canonicalJson([
        'access_policies', 'credentials', 'dns', 'durable_object_migrations',
        'mcp_portal_configuration', 'sources', 'tool_allowlists',
      ]) || !Array.isArray(value.notes) || value.notes.length < 1 || value.notes.length > 8 ||
      value.notes.some((note) => !isText(note) || note.length < 1 || note.length > 512)) return null;
  const manifest = await verifyUpdateEnvelope(value.verification, environment);
  if (!manifest || manifest.release !== value.release.id ||
      `sha256:${manifest.artifact.treeSha256}` !== value.release.artifactSha256 ||
      manifest.sourceCommit !== value.release.sourceCommit) return null;
  return Object.freeze({
    schemaVersion: 1,
    channel: value.channel,
    release: Object.freeze({ ...value.release }),
    classification: Object.freeze({
      kind: 'normal', updaterProtocol: 2,
      changes: Object.freeze([...value.classification.changes]),
      excludes: Object.freeze([...value.classification.excludes]),
    }),
    notes: Object.freeze([...value.notes]),
    verification: Object.freeze({ ...value.verification }),
    manifest,
  });
}

async function discoverRuntimeUpdate(env) {
  const environment = parseManagementEnvironment(env);
  if (!environment) return null;
  let response;
  try {
    response = await fetch(`${CONTROL_PLANE_ORIGIN}/api/releases/${environment.updateChannel}`, {
      method: 'GET', headers: { accept: 'application/json' }, redirect: 'manual',
    });
  } catch { return null; }
  if (!response.ok || response.redirected ||
      !response.headers.get('content-type')?.toLowerCase().startsWith('application/json')) return null;
  const serialized = await readBoundedText(response, 8 * 1024 * 1024);
  let value;
  try { value = serialized === null ? null : JSON.parse(serialized); } catch { value = null; }
  const channel = await parseUpdateChannel(value, environment);
  if (!channel) return null;
  const comparison = compareUpdateRelease(environment.release, channel.release.id);
  if (comparison === null) return null;
  return Object.freeze({ environment, channel, comparison });
}

function parseSettings(value) {
  if (!exactKeys(value, ['schemaVersion', 'connect', 'access', 'sources']) || value.schemaVersion !== 1 ||
      !exactKeys(value.connect, ['name', 'hostname', 'codeMode']) ||
      !isText(value.connect.name) || value.connect.name.length < 2 || value.connect.name.length > 80 ||
      value.connect.name.trim() !== value.connect.name || hasControlCharacter(value.connect.name) ||
      !hostname(value.connect.hostname) || value.connect.codeMode !== 'default_on' ||
      !exactKeys(value.access, ['adminEmails', 'memberEmails']) ||
      !Array.isArray(value.sources) || value.sources.length > 1) return null;
  const adminEmails = exactSortedUniqueStrings(value.access.adminEmails, normalizedEmail, 1, 1);
  const memberEmails = exactSortedUniqueStrings(value.access.memberEmails, normalizedEmail);
  if (!adminEmails || !memberEmails || adminEmails.some((email) => memberEmails.includes(email))) return null;
  if (value.sources.length === 0) {
    return Object.freeze({
      schemaVersion: 1,
      connect: Object.freeze({ name: value.connect.name, hostname: value.connect.hostname, codeMode: 'default_on' }),
      access: Object.freeze({ adminEmails, memberEmails }),
      sources: Object.freeze([]),
    });
  }
  const source = value.sources[0];
  if (
      !exactKeys(source, ['id', 'label', 'url', 'authentication', 'enabledTools']) ||
      source.id !== 'company-context' || !isText(source.label) || source.label.length < 2 ||
      source.label.length > 80 || source.label.trim() !== source.label || hasControlCharacter(source.label) ||
      !exactKeys(source.authentication, ['mode', 'onBehalfOfUser']) ||
      source.authentication.mode !== 'none' || source.authentication.onBehalfOfUser !== false) return null;
  let sourceUrl;
  try { sourceUrl = new URL(source.url); } catch { return null; }
  if (sourceUrl.protocol !== 'https:' || sourceUrl.username || sourceUrl.password || sourceUrl.port ||
      sourceUrl.search || sourceUrl.hash || sourceUrl.pathname === '/' || !hostname(sourceUrl.hostname) ||
      sourceUrl.toString() !== source.url) return null;
  const enabledTools = exactSortedUniqueStrings(
    source.enabledTools,
    (entry) => isText(entry) && TOOL.test(entry) ? entry : null,
    MAX_ENABLED_TOOLS_PER_SOURCE,
    1,
  );
  if (!enabledTools) return null;
  return Object.freeze({
    schemaVersion: 1,
    connect: Object.freeze({ name: value.connect.name, hostname: value.connect.hostname, codeMode: 'default_on' }),
    access: Object.freeze({ adminEmails, memberEmails }),
    sources: Object.freeze([Object.freeze({
      id: 'company-context',
      label: source.label,
      url: sourceUrl.toString(),
      authentication: Object.freeze({ mode: 'none', onBehalfOfUser: false }),
      enabledTools,
    })]),
  });
}

async function stableResourceKey(prefix, installationId, logicalId) {
  const digest = await sha256Hex({ installationId, prefix, logicalId });
  const hint = logicalId
    .toLowerCase()
    .replace(/[^a-z0-9-]+/gu, '-')
    .replace(/^-+|-+$/gu, '');
  const hintLength = Math.max(0, 32 - prefix.length - 10);
  // A hint cut mid-label must not end in a hyphen: Cloudflare refuses ids
  // with two hyphens in a row (7001, "not valid ID format").
  const cut = hint.slice(0, hintLength).replace(/-+$/gu, '');
  if (cut && hintLength > 0) return `${prefix}-${cut}-${digest.slice(0, 8)}`;
  return `${prefix}-${digest.slice(0, 32 - prefix.length - 1)}`;
}

function marker(installationId, key) {
  return `acg:v1:${installationId}:${key}`;
}

async function buildDesiredResources(settings, installationId, sourceDefaultDeny = false) {
  const source = settings.sources[0] ?? null;
  const allowedEmails = [...settings.access.adminEmails, ...settings.access.memberEmails].sort(compareText);
  const identitiesHash = await sha256({ emails: allowedEmails });
  const metadata = { manager: MANAGER, installationId };
  const emailAllowPolicy = {
    identitiesRef: 'access.allowedEmails',
    identityType: 'email',
    identityCount: allowedEmails.length,
    identitiesHash,
  };
  const sourceAllowPolicy = sourceDefaultDeny ? {
    identitiesRef: 'team.sourceMembers', identityType: 'email', identityCount: 0,
    identitiesHash: await sha256({ emails: [] }),
  } : emailAllowPolicy;
  const mcpKey = source === null ? null : await stableResourceKey('mcp', installationId, source.id);
  const sourceApplicationKey = source === null ? null : await stableResourceKey('source-app', installationId, source.id);
  const sourceAccessKey = source === null ? null : await stableResourceKey('source-access', installationId, source.id);
  const portalKey = await stableResourceKey('portal', installationId, settings.connect.hostname);
  const portalApplicationKey = await stableResourceKey('portal-app', installationId, settings.connect.hostname);
  const portalAccessKey = await stableResourceKey('portal-access', installationId, settings.connect.hostname);
  const dnsKey = await stableResourceKey('dns', installationId, settings.connect.hostname);
  const sourceMappings = source === null ? [] : [{
    sourceResourceKey: mcpKey,
    defaultDisabled: true,
    allowedTools: [...source.enabledTools].sort(compareText),
    onBehalfOfUser: source.authentication.onBehalfOfUser,
  }];
  const sourceSpecifications = source === null ? [] : [
    {
      kind: 'mcp_server', key: mcpKey, desired: {
        metadata, sourceId: source.id, name: source.label, endpoint: source.url,
        capabilityMode: 'read_only', secureWebGateway: false,
        toolPolicy: { defaultDisabled: true, allowedTools: [...source.enabledTools].sort(compareText) },
        authentication: {
          mode: source.authentication.mode,
          onBehalfOfUser: source.authentication.onBehalfOfUser,
          credentialCustody: 'customer',
        },
      },
    },
    { kind: 'source_access_application', key: sourceApplicationKey, desired: {
      metadata, sourceResourceKey: mcpKey, applicationType: 'mcp',
    } },
    { kind: 'source_access_policy', key: sourceAccessKey, desired: {
      metadata, sourceApplicationResourceKey: sourceApplicationKey,
      defaultAction: 'deny', allow: sourceAllowPolicy,
    } },
  ];
  const specifications = [
    ...sourceSpecifications,
    { kind: 'portal', key: portalKey, desired: {
      metadata, name: settings.connect.name, hostname: settings.connect.hostname,
      capabilityMode: 'read_only', codeMode: settings.connect.codeMode,
      secureWebGateway: false, sourceMappings,
    } },
    { kind: 'portal_access_application', key: portalApplicationKey, desired: {
      metadata, portalResourceKey: portalKey, name: settings.connect.name,
      hostname: settings.connect.hostname, applicationType: 'mcp_portal',
      destination: { type: 'public', uri: settings.connect.hostname },
      authentication: {
        mode: 'managed_oauth',
        dynamicClientRegistration: { enabled: true, allowAnyOnLocalhost: true, allowAnyOnLoopback: true },
        grant: { accessTokenLifetime: '15m', sessionDuration: '336h' },
      },
    } },
    { kind: 'portal_access_policy', key: portalAccessKey, desired: {
      metadata, portalApplicationResourceKey: portalApplicationKey,
      defaultAction: 'deny', allow: emailAllowPolicy,
    } },
    { kind: 'dns_record', key: dnsKey, desired: {
      metadata, recordType: 'CNAME', hostname: settings.connect.hostname,
      content: PORTAL_CNAME_TARGET, proxied: true, dependsOnResourceKey: portalKey,
    } },
  ];
  return Object.freeze(await Promise.all(specifications.map(async (resource) => Object.freeze({
    ...resource,
    desiredHash: await sha256({
      schemaVersion: 1, kind: resource.kind, key: resource.key, desired: resource.desired,
    }),
  }))));
}

async function expectedEvidence(settings, target, release, installationId) {
  if (!isText(installationId) || !INSTALLATION_ID.test(installationId)) return null;
  const resources = await buildDesiredResources(settings, installationId);
  const desiredHash = await sha256({ schemaVersion: 1, installationId, resources });
  const configurationHash = await sha256({
    schemaVersion: 1, settingsRevision: 1, settings, target, release,
  });
  return Object.freeze({ configurationHash, installationId, desiredHash, resources });
}

async function parseClaim(value, environment, nowMs) {
  if (!exactKeys(value, [
    'schemaVersion', 'requestId', 'issuedAt', 'expiresAt', 'settingsRevision',
    'settings', 'target', 'release', 'expected', 'cloudflareAccessToken',
  ])) return null;
  if (
    value.schemaVersion !== 1 || !isText(value.requestId) || !REQUEST_ID.test(value.requestId) ||
    !Number.isSafeInteger(value.issuedAt) || !Number.isSafeInteger(value.expiresAt) ||
    value.expiresAt <= value.issuedAt || value.expiresAt - value.issuedAt > REQUEST_LIFETIME_SECONDS ||
    value.settingsRevision !== 1 ||
    !exactKeys(value.target, ['accountId', 'zoneId', 'zoneName']) ||
    value.target.accountId !== environment.accountId || value.target.zoneId !== environment.zoneId ||
    value.target.zoneName !== environment.zoneName ||
    !exactKeys(value.release, ['id', 'artifactSha256']) || value.release.id !== environment.release ||
    value.release.artifactSha256 !== environment.releaseSha256 ||
    !exactKeys(value.expected, ['configurationHash', 'installationId', 'desiredHash']) ||
    !isText(value.expected.configurationHash) || !HASH.test(value.expected.configurationHash) ||
    !isText(value.expected.installationId) || !INSTALLATION_ID.test(value.expected.installationId) ||
    !isText(value.expected.desiredHash) || !HASH.test(value.expected.desiredHash) ||
    !isText(value.cloudflareAccessToken) || value.cloudflareAccessToken.length === 0 ||
    value.cloudflareAccessToken.length > 16 * 1024 || value.cloudflareAccessToken.trim() !== value.cloudflareAccessToken ||
    hasControlCharacter(value.cloudflareAccessToken)
  ) return null;
  const now = Math.floor(nowMs / 1_000);
  if (value.issuedAt > now + MAX_CLOCK_SKEW_SECONDS || value.expiresAt < now ||
      now - value.issuedAt > REQUEST_LIFETIME_SECONDS) return null;
  const settings = parseSettings(value.settings);
  if (!settings) return null;
  const target = Object.freeze({ ...value.target });
  const release = Object.freeze({ ...value.release });
  if (value.expected.installationId !== environment.installId) return null;
  const derived = await expectedEvidence(settings, target, release, environment.installId);
  if (!derived || value.expected.configurationHash !== derived.configurationHash ||
      value.expected.installationId !== derived.installationId ||
      value.expected.desiredHash !== derived.desiredHash) return null;
  return Object.freeze({
    schemaVersion: 1,
    requestId: value.requestId,
    issuedAt: value.issuedAt,
    expiresAt: value.expiresAt,
    settingsRevision: 1,
    settings,
    target,
    release,
    expected: Object.freeze({ ...value.expected }),
    resources: derived.resources,
    cloudflareAccessToken: value.cloudflareAccessToken,
  });
}

async function verifyBootstrapRequest(request, env, nowMs) {
  if (!(request instanceof Request) || request.method !== 'POST') return null;
  const contentType = request.headers.get('content-type')?.split(';', 1)[0]?.trim().toLowerCase();
  if (contentType !== 'application/json' || request.headers.has('authorization') ||
      request.headers.has('cookie') || request.headers.has('referer') || request.headers.has('origin')) return null;
  const environment = parseEnvironment(env, true);
  if (!environment) return null;
  const signature = request.headers.get('x-ankka-bootstrap-signature');
  const rawBody = await readBoundedText(request, BOOTSTRAP_REQUEST_LIMIT_BYTES);
  if (!rawBody || !await verifyHmac(rawBody, environment.bootstrapNonce, signature)) return null;
  let parsed;
  try { parsed = JSON.parse(rawBody); } catch { return null; }
  if (!isPlainData(parsed) || canonicalJson(parsed) !== rawBody) return null;
  const claim = await parseClaim(parsed, environment, nowMs);
  if (!claim) return null;
  return Object.freeze({ rawBody, claim, signature });
}

async function discardBody(response, signal) {
  if (signal) {
    try { void response.body?.cancel().catch(() => undefined); } catch { /* Cancellation stays best effort. */ }
    return;
  }
  try { await response.body?.cancel(); } catch { /* Provider status remains authoritative. */ }
}

async function readBoundedProviderJson(response, signal) {
  const declared = response.headers.get('content-length');
  if (declared !== null) {
    const size = Number(declared);
    if (!Number.isSafeInteger(size) || size < 0 || size > PROVIDER_RESPONSE_LIMIT_BYTES) {
      await discardBody(response, signal);
      return null;
    }
  }
  const contentType = response.headers.get('content-type')?.split(';', 1)[0]?.trim().toLowerCase();
  if (contentType !== 'application/json') {
    await discardBody(response, signal);
    return null;
  }
  if (!response.body) return null;
  const reader = response.body.getReader();
  const abortRead = () => { void reader.cancel().catch(() => undefined); };
  signal?.addEventListener('abort', abortRead, { once: true });
  const chunks = [];
  let total = 0;
  try {
    if (signal?.aborted) { abortRead(); return null; }
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      if (value.byteLength > PROVIDER_RESPONSE_LIMIT_BYTES - total) {
        if (signal) abortRead();
        else try { await reader.cancel(); } catch { /* The bound remains authoritative. */ }
        return null;
      }
      chunks.push(value.slice());
      total += value.byteLength;
    }
    if (signal?.aborted) return null;
    const bytes = new Uint8Array(total);
    let offset = 0;
    for (const chunk of chunks) {
      bytes.set(chunk, offset);
      offset += chunk.byteLength;
    }
    try {
      const parsed = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
      return isPlainData(parsed) ? parsed : null;
    } catch {
      return null;
    } finally {
      bytes.fill(0);
    }
  } finally {
    signal?.removeEventListener('abort', abortRead);
    for (const chunk of chunks) chunk.fill(0);
    try { reader.releaseLock(); } catch { /* Provider parsing remains authoritative. */ }
  }
}

function providerUrl(path) {
  return new URL(`/client/v4${path}`, API_ORIGIN);
}

// Return only a fixed vocabulary. Never copy provider messages, values, or
// arbitrary validation paths into a response or retained journal.
function providerValidationLabel(message) {
  if (!isText(message)) return null;
  for (const [pattern, label] of [
    [/\bserver_id\b/iu, 'field_server_id'],
    [/\bhostname\b/iu, 'field_hostname'],
    [/\bon_behalf\b/iu, 'field_on_behalf'],
    [/\bupdated_tools\b/iu, 'field_updated_tools'],
    [/\bupdated_prompts\b/iu, 'field_updated_prompts'],
    [/\bdefault_disabled\b/iu, 'field_default_disabled'],
    [/\bcode_mode\b/iu, 'field_code_mode'],
    [/not valid id format/iu, 'id_format'],
    [/\bid\b/iu, 'field_id'],
  ]) {
    if (pattern.test(message)) return label;
  }
  return null;
}

async function providerHttpFailure(status, response, signal) {
  let envelope;
  try { envelope = await readBoundedProviderJson(response, signal); } catch { envelope = null; }
  const first = isRecord(envelope) && Array.isArray(envelope.errors) ? envelope.errors[0] : null;
  const code = isRecord(first) ? first.code : undefined;
  return providerResult(status, null, response.status,
    Number.isSafeInteger(code) && code >= 0 && code <= 999999 ? code : null,
    isRecord(first) ? providerValidationLabel(first.message) : null);
}

function providerResult(status, result, httpStatus = null, providerCode = null, providerValidation = null) {
  return Object.freeze({ status, result, httpStatus, providerCode, providerValidation });
}

async function providerCall(path, token, init = {}) {
  let response;
  try {
    const headers = {
      accept: 'application/json',
      authorization: `Bearer ${token}`,
    };
    if (init.body) headers['content-type'] = 'application/json';
    response = await fetch(new Request(providerUrl(path), {
      ...init,
      headers,
      redirect: 'manual',
    }));
  } catch {
    return providerResult('unknown', null);
  }
  if (init.signal?.aborted || !(response instanceof Response) || response.redirected ||
      (response.status >= 300 && response.status < 400)) {
    if (response instanceof Response) await discardBody(response, init.signal);
    return providerResult('unknown', null, response instanceof Response ? response.status : null);
  }
  if (response.status === 404) {
    await discardBody(response, init.signal);
    return providerResult('absent', null, 404);
  }
  if (response.status === 401 || response.status === 403) {
    return providerHttpFailure('auth', response, init.signal);
  }
  if (response.status === 429 || response.status >= 500) {
    return providerHttpFailure('unknown', response, init.signal);
  }
  if (response.status === 204) {
    await discardBody(response, init.signal);
    return providerResult('ok', null, 204);
  }
  if (response.status !== 200 && response.status !== 201) {
    return providerHttpFailure('blocked', response, init.signal);
  }
  let envelope;
  try { envelope = await readBoundedProviderJson(response, init.signal); } catch { envelope = null; }
  if (!isRecord(envelope) || envelope.success !== true || !Object.hasOwn(envelope, 'result')) {
    return providerResult('unknown', null, response.status);
  }
  return providerResult('ok', envelope.result, response.status);
}

/** A discover/create outcome that keeps the provider's status numbers without its text. */
function providerOutcome(status, response) {
  return Object.freeze({
    status,
    provider: null,
    httpStatus: response?.httpStatus ?? null,
    providerCode: response?.providerCode ?? null,
    providerValidation: response?.providerValidation ?? null,
  });
}

async function providerList(path, token, query = {}, signal) {
  const values = [];
  for (let page = 1; page <= MAX_PROVIDER_PAGES; page += 1) {
    const url = new URL(providerUrl(path));
    url.searchParams.set('page', String(page));
    url.searchParams.set('per_page', String(PROVIDER_PAGE_SIZE));
    for (const [name, value] of Object.entries(query)) url.searchParams.set(name, value);
    const relative = `${url.pathname.slice('/client/v4'.length)}${url.search}`;
    const response = await providerCall(relative, token, signal ? { signal } : {});
    if (response.status !== 'ok' || !Array.isArray(response.result)) return response;
    values.push(...response.result);
    if (response.result.length < PROVIDER_PAGE_SIZE) return Object.freeze({ status: 'ok', result: values });
  }
  return Object.freeze({ status: 'unknown', result: null });
}

function safeProviderId(value) {
  return isText(value) && SAFE_ID.test(value) ? value : null;
}

function exactOne(values, predicate) {
  if (!Array.isArray(values)) return null;
  const matches = values.filter((value) => isRecord(value) && predicate(value));
  return matches.length === 1 ? matches[0] : null;
}

function toolProjection(names) {
  return names.map((name) => ({ name, enabled: true }));
}

function emailRules(settings) {
  return [...settings.access.adminEmails, ...settings.access.memberEmails]
    .sort(compareText)
    .map((email) => ({ email: { email } }));
}

function resource(state, kind) {
  return state.desiredResources.find((entry) => entry.kind === kind) ?? null;
}

function locator(state, kind) {
  return state.resources.find((entry) => entry.kind === kind)?.provider ?? null;
}

function resultId(value) {
  return isRecord(value) ? safeProviderId(value.id) : null;
}

function mcpMatches(value, desired) {
  const oauth = desired.desired.authentication.mode === 'oauth';
  return isRecord(value) && value.id === desired.key && value.hostname === desired.desired.endpoint &&
    value.description === marker(desired.desired.metadata.installationId, desired.key) &&
    value.auth_type === (oauth ? 'oauth' : 'unauthenticated') && value.secure_web_gateway === false &&
    (!oauth || value.is_shared_oauth_callback_enabled === true);
}

function portalMatches(value, desired, serverId) {
  if (!isRecord(value) || value.id !== desired.key || value.hostname !== desired.desired.hostname ||
      value.name !== desired.desired.name || value.description !== marker(
        desired.desired.metadata.installationId, desired.key,
      ) || value.code_mode !== 'default_on' || value.secure_web_gateway !== false ||
      (value.servers !== undefined && !Array.isArray(value.servers))) return false;
  if (desired.desired.sourceMappings.length === 0) {
    return value.servers === undefined || value.servers.length === 0;
  }
  if (!Array.isArray(value.servers)) return false;
  const mapping = desired.desired.sourceMappings.find((candidate) => candidate.sourceResourceKey === serverId);
  return Boolean(mapping) && value.servers.some((server) => isRecord(server) &&
    (server.server_id === serverId || server.id === serverId) &&
    server.default_disabled === true && server.on_behalf === mapping.onBehalfOfUser);
}

function exactDestination(value, expected) {
  if (!Array.isArray(value.destinations) || value.destinations.length !== 1) return false;
  const destination = value.destinations[0];
  return isRecord(destination) && exactKeys(destination, Object.keys(expected)) &&
    Object.entries(expected).every(([key, entry]) => destination[key] === entry);
}

/**
 * An Access application that claims this installation's MCP server or Portal
 * hostname, or carries the name this installation creates. Any candidate that
 * is not the exact receipt-owned application is a collision, never adopted.
 */
function accessApplicationCandidate(value, kind, state) {
  if (!isRecord(value) || !safeProviderId(value.id)) return false;
  const destinations = Array.isArray(value.destinations) ? value.destinations : [];
  if (kind === 'source_access_application') {
    const server = locator(state, 'mcp_server');
    const desired = resource(state, kind);
    return value.name === marker(state.installationId, desired.key) || (
      value.type === 'mcp' && server !== null && destinations.some((destination) => (
        isRecord(destination) && destination.type === 'via_mcp_server_portal' &&
        destination.mcp_server_id === server.id
      ))
    );
  }
  const host = state.settings.connect.hostname;
  return value.name === state.settings.connect.name || (value.type === 'mcp_portal' && (
    value.domain === host || destinations.some((destination) => (
      isRecord(destination) && destination.type === 'public' && destination.uri === host
    ))
  ));
}

function accessApplicationIdentityMatches(value, kind, state) {
  if (!isRecord(value) || !safeProviderId(value.id)) return false;
  if (kind === 'source_access_application') {
    const server = locator(state, 'mcp_server');
    const desired = resource(state, kind);
    return value.type === 'mcp' && server !== null &&
      value.name === marker(state.installationId, desired.key) &&
      (value.domain === undefined || value.domain === null) &&
      exactDestination(value, { type: 'via_mcp_server_portal', mcp_server_id: server.id });
  }
  const host = state.settings.connect.hostname;
  return value.type === 'mcp_portal' && value.name === state.settings.connect.name &&
    value.domain === host && exactDestination(value, { type: 'public', uri: host }) &&
    managedOauthMatches(value);
}

function managedOauthMatches(value) {
  // Keep existing receipt verification compatible with older Portal callbacks.
  // Callback defaults are applied when creating the application.
  const oauth = isRecord(value) ? value.oauth_configuration : null;
  const registration = isRecord(oauth) ? oauth.dynamic_client_registration : null;
  const grant = isRecord(oauth) ? oauth.grant : null;
  return isRecord(oauth) && oauth.enabled === true && isRecord(registration) &&
    registration.enabled === true && registration.allow_any_on_localhost === true &&
    registration.allow_any_on_loopback === true && isRecord(grant) &&
    grant.access_token_lifetime === '15m' && grant.session_duration === '336h';
}

function policyMatches(value, desired, settings) {
  if (desired.kind === 'source_access_policy' && desired.desired.allow.identitiesRef === 'team.sourceMembers') {
    return teamPolicyMatches(value, teamPolicy([], `${settings.sources[0].label} users [${marker(
      desired.desired.metadata.installationId, desired.key,
    )}]`), value?.id);
  }
  if (!isRecord(value) || !safeProviderId(value.id) || value.decision !== 'allow' ||
      !isText(value.name) || !value.name.endsWith(` [${marker(
        desired.desired.metadata.installationId, desired.key,
      )}]`) || !Array.isArray(value.include)) return false;
  const emails = [];
  for (const rule of value.include) {
    const email = isRecord(rule) && isRecord(rule.email) ? normalizedEmail(rule.email.email) : null;
    if (!email) return false;
    emails.push(email);
  }
  return canonicalJson([...new Set(emails)].sort(compareText)) === canonicalJson(
    [...settings.access.adminEmails, ...settings.access.memberEmails].sort(compareText),
  );
}

function dnsMatches(value, desired) {
  return isRecord(value) && safeProviderId(value.id) && value.type === 'CNAME' &&
    value.name === desired.desired.hostname && value.content === PORTAL_CNAME_TARGET &&
    value.proxied === true && value.comment === marker(
      desired.desired.metadata.installationId, desired.key,
    );
}

async function discoverResource(state, kind, token, hint = null) {
  const desired = resource(state, kind);
  if (!desired) return Object.freeze({ status: 'conflict', provider: null });
  const account = encodeURIComponent(state.target.accountId);
  const zone = encodeURIComponent(state.target.zoneId);
  if (kind === 'mcp_server') {
    const response = await providerCall(
      `/accounts/${account}/access/ai-controls/mcp/servers/${encodeURIComponent(desired.key)}`,
      token,
    );
    return response.status === 'ok' && mcpMatches(response.result, desired)
      ? Object.freeze({ status: 'present', provider: Object.freeze({ id: desired.key }) })
      : providerOutcome(response.status === 'absent' ? 'absent' : response.status, response);
  }
  if (kind === 'portal') {
    const server = locator(state, 'mcp_server');
    if (!server && desired.desired.sourceMappings.length !== 0) {
      return Object.freeze({ status: 'conflict', provider: null });
    }
    const response = await providerCall(
      `/accounts/${account}/access/ai-controls/mcp/portals/${encodeURIComponent(desired.key)}`,
      token,
    );
    return response.status === 'ok' && portalMatches(response.result, desired, server?.id ?? null)
      ? Object.freeze({ status: 'present', provider: Object.freeze({ id: desired.key }) })
      : providerOutcome(response.status === 'absent' ? 'absent' : response.status, response);
  }
  if (kind === 'source_access_application' || kind === 'portal_access_application') {
    // The zone paths are the ones the grant covers. An MCP application has
    // no hostname and is stored with the account, where the zone listing
    // never shows it, so a known source application is read by id; only a
    // baseline without one falls back to listings, the account listing
    // included when the grant can read it. The portal application, a zone
    // hostname, keeps the listing that proves it is the only one.
    const known = kind === 'source_access_application' ? hint ?? locator(state, kind) : null;
    // A known application that is gone is absent; a listed one that vanishes
    // before its read is an unsettled answer, named with its status.
    const readApplication = async (id, listed) => {
      const read = await providerCall(`/zones/${zone}/access/apps/${encodeURIComponent(id)}`, token);
      if (read.status === 'absent') {
        return listed ? providerOutcome('unknown', read) : Object.freeze({ status: 'absent', provider: null });
      }
      if (read.status !== 'ok') return providerOutcome(read.status, read);
      return isRecord(read.result) && read.result.id === id &&
        accessApplicationIdentityMatches(read.result, kind, state)
        ? Object.freeze({ status: 'present', provider: Object.freeze({ id: read.result.id }) })
        : Object.freeze({ status: 'conflict', provider: null });
    };
    if (known) return readApplication(known.id, false);
    const listed = await providerList(`/zones/${zone}/access/apps`, token);
    if (listed.status !== 'ok') return providerOutcome(listed.status, listed);
    let candidates = listed.result.filter((value) => accessApplicationCandidate(value, kind, state));
    if (kind === 'source_access_application' && candidates.length === 0) {
      const accountListed = await providerList(`/accounts/${account}/access/apps`, token);
      if (accountListed.status === 'ok') {
        candidates = accountListed.result.filter((value) => accessApplicationCandidate(value, kind, state));
      } else if (accountListed.status !== 'blocked' && accountListed.status !== 'auth') {
        return providerOutcome(accountListed.status, accountListed);
      }
    }
    if (candidates.length === 0) return Object.freeze({ status: 'absent', provider: null });
    if (candidates.length > 1) return Object.freeze({ status: 'conflict', provider: null });
    // The exact application shape, including Managed OAuth, is proven on the
    // single-application read; the list is only used to bound the candidate set.
    return readApplication(candidates[0].id, true);
  }
  if (kind === 'source_access_policy' || kind === 'portal_access_policy') {
    const parentKind = kind === 'source_access_policy'
      ? 'source_access_application'
      : 'portal_access_application';
    const parent = locator(state, parentKind);
    if (!parent) return Object.freeze({ status: 'conflict', provider: null });
    // Policies stay a listing: a competing policy on the application must be seen.
    const policies = `/zones/${zone}/access/apps/${encodeURIComponent(parent.id)}/policies`;
    const response = await providerList(policies, token);
    if (response.status !== 'ok') return providerOutcome(response.status, response);
    if (kind === 'source_access_policy' && desired.desired.allow.identitiesRef === 'team.sourceMembers' &&
        (response.result.length > 1 || (response.result.length === 1 &&
          !policyMatches(response.result[0], desired, state.settings)))) {
      return Object.freeze({ status: 'conflict', provider: null });
    }
    const match = exactOne(response.result, (value) => policyMatches(value, desired, state.settings));
    return match
      ? Object.freeze({ status: 'present', provider: Object.freeze({ id: match.id, parentId: parent.id }) })
      : Object.freeze({ status: 'absent', provider: null });
  }
  const response = await providerList(`/zones/${zone}/dns_records`, token, {
    'name.exact': desired.desired.hostname,
    match: 'all',
  });
  if (response.status !== 'ok') return providerOutcome(response.status, response);
  const match = exactOne(response.result, (value) => dnsMatches(value, desired));
  return match
    ? Object.freeze({ status: 'present', provider: Object.freeze({ id: match.id }) })
    : Object.freeze({ status: 'absent', provider: null });
}

async function createResource(state, kind, token) {
  const desired = resource(state, kind);
  const account = encodeURIComponent(state.target.accountId);
  const zone = encodeURIComponent(state.target.zoneId);
  if (!desired) return Object.freeze({ status: 'conflict', provider: null });
  let path;
  let body;
  if (kind === 'source_access_application') {
    const server = locator(state, 'mcp_server');
    if (!server) return Object.freeze({ status: 'conflict', provider: null });
    // Cloudflare stores this hostname-less application with the account, but
    // the zone path is the one the grant covers and it accepts the creation.
    path = `/zones/${zone}/access/apps`;
    body = {
      name: marker(state.installationId, desired.key),
      type: 'mcp',
      destinations: [{ type: 'via_mcp_server_portal', mcp_server_id: server.id }],
    };
  } else if (kind === 'portal_access_application') {
    if (!locator(state, 'portal')) return Object.freeze({ status: 'conflict', provider: null });
    const application = desired.desired;
    path = `/zones/${zone}/access/apps`;
    body = {
      name: application.name,
      type: 'mcp_portal',
      domain: application.hostname,
      destinations: [{ type: application.destination.type, uri: application.destination.uri }],
      oauth_configuration: {
        enabled: true,
        dynamic_client_registration: {
          enabled: application.authentication.dynamicClientRegistration.enabled,
          allowed_uris: [...DEFAULT_OAUTH_CALLBACKS],
          allow_any_on_localhost: application.authentication.dynamicClientRegistration.allowAnyOnLocalhost,
          allow_any_on_loopback: application.authentication.dynamicClientRegistration.allowAnyOnLoopback,
        },
        grant: {
          access_token_lifetime: application.authentication.grant.accessTokenLifetime,
          session_duration: application.authentication.grant.sessionDuration,
        },
      },
    };
  } else if (kind === 'mcp_server') {
    const oauth = desired.desired.authentication.mode === 'oauth';
    path = `/accounts/${account}/access/ai-controls/mcp/servers`;
    body = {
      id: desired.key,
      name: desired.desired.name,
      hostname: desired.desired.endpoint,
      auth_type: oauth ? 'oauth' : 'unauthenticated',
      secure_web_gateway: false,
      description: marker(state.installationId, desired.key),
      updated_tools: toolProjection(desired.desired.toolPolicy.allowedTools),
    };
    if (oauth) body.is_shared_oauth_callback_enabled = true;
  } else if (kind === 'portal') {
    const server = locator(state, 'mcp_server');
    if (!server && desired.desired.sourceMappings.length !== 0) {
      return Object.freeze({ status: 'conflict', provider: null });
    }
    path = `/accounts/${account}/access/ai-controls/mcp/portals`;
    body = {
      id: desired.key,
      name: desired.desired.name,
      hostname: desired.desired.hostname,
      code_mode: 'default_on',
      secure_web_gateway: false,
      description: marker(state.installationId, desired.key),
    };
    if (server) {
      body.servers = [{
        id: server.id,
        server_id: server.id,
        default_disabled: true,
        on_behalf: state.settings.sources[0].authentication.onBehalfOfUser,
        updated_tools: toolProjection(state.settings.sources[0].enabledTools),
      }];
    }
  } else if (kind === 'source_access_policy' || kind === 'portal_access_policy') {
    const parentKind = kind === 'source_access_policy'
      ? 'source_access_application'
      : 'portal_access_application';
    const parent = locator(state, parentKind);
    if (!parent) return Object.freeze({ status: 'conflict', provider: null });
    path = `/zones/${zone}/access/apps/${encodeURIComponent(parent.id)}/policies`;
    const name = `${kind === 'source_access_policy' ? state.settings.sources[0].label : state.settings.connect.name} users [${marker(state.installationId, desired.key)}]`;
    body = kind === 'source_access_policy' && desired.desired.allow.identitiesRef === 'team.sourceMembers'
      ? teamPolicy([], name)
      : { name, decision: 'allow', include: emailRules(state.settings), exclude: [], require: [] };
  } else {
    path = `/zones/${zone}/dns_records`;
    body = {
      type: 'CNAME',
      name: desired.desired.hostname,
      content: PORTAL_CNAME_TARGET,
      proxied: true,
      ttl: 1,
      comment: marker(state.installationId, desired.key),
    };
  }
  const response = await providerCall(path, token, { method: 'POST', body: canonicalJson(body) });
  if (response.status !== 'ok') return providerOutcome(response.status, response);
  const id = resultId(response.result);
  if (!id) return providerOutcome('unknown', response);
  const parent = kind === 'source_access_policy'
    ? locator(state, 'source_access_application')
    : kind === 'portal_access_policy'
      ? locator(state, 'portal_access_application')
      : null;
  const provider = { id };
  if (parent) provider.parentId = parent.id;
  return Object.freeze({
    status: 'submitted',
    provider: Object.freeze(provider),
  });
}

function receiptResource(state, desired, provider) {
  const policy = desired.kind === 'source_access_policy' || desired.kind === 'portal_access_policy';
  const resourceValue = {
    kind: desired.kind,
    key: desired.key,
    provider,
    desiredHash: desired.desiredHash,
    marker: marker(state.installationId, desired.key),
  };
  if (policy) resourceValue.identityHash = state.accessPolicy.identitiesHash;
  return Object.freeze(resourceValue);
}

function validStoredState(value, claim) {
  return exactKeys(value, [
    'schemaVersion', 'status', 'installationId', 'approvedPlanId', 'configurationHash',
    'desiredHash', 'release', 'target', 'settings', 'accessPolicy', 'desiredResources',
    'resources', 'pending', 'receipt',
  ]) && value.schemaVersion === 1 && ['installing', 'ready'].includes(value.status) &&
    value.installationId === claim.expected.installationId && PLAN_ID.test(value.approvedPlanId) &&
    value.configurationHash === claim.expected.configurationHash &&
    value.desiredHash === claim.expected.desiredHash &&
    canonicalJson(value.release) === canonicalJson(claim.release) &&
    canonicalJson(value.target) === canonicalJson(claim.target) &&
    canonicalJson(value.settings) === canonicalJson(claim.settings) &&
    canonicalJson(value.desiredResources) === canonicalJson(claim.resources) &&
    Array.isArray(value.resources) && value.resources.length <= claim.resources.length;
}

function parseProviderLocator(value, policy) {
  if (!exactKeys(value, policy ? ['id', 'parentId'] : ['id'])) return null;
  if (!safeProviderId(value.id) || (policy && !safeProviderId(value.parentId))) return null;
  const provider = { id: value.id };
  if (policy) provider.parentId = value.parentId;
  return Object.freeze(provider);
}

async function parseReadyReceipt(value, claim) {
  const resourceOrder = claim.resources.map((resourceValue) => resourceValue.kind);
  if (canonicalJson(resourceOrder) !== canonicalJson(
    claim.settings.sources.length === 0 ? PORTAL_RESOURCE_ORDER : RESOURCE_ORDER,
  )) return null;
  if (!exactKeys(value, [
    'schemaVersion', 'manager', 'installationId', 'state', 'revision', 'release',
    'target', 'accessPolicy', 'desiredHash', 'resources', 'pending', 'checksum',
  ]) || value.schemaVersion !== 1 || value.manager !== MANAGER || value.state !== 'ready' ||
      value.installationId !== claim.expected.installationId || value.revision !== resourceOrder.length + 1 ||
      value.release !== claim.release.id || value.desiredHash !== claim.expected.desiredHash ||
      value.pending !== null || !isText(value.checksum) || !HASH.test(value.checksum) ||
      canonicalJson(value.target) !== canonicalJson({
        ...claim.target, hostname: claim.settings.connect.hostname,
      }) || !exactKeys(value.accessPolicy, ['identityType', 'identityCount', 'identitiesHash']) ||
      value.accessPolicy.identityType !== 'email' ||
      value.accessPolicy.identityCount !== claim.settings.access.adminEmails.length +
        claim.settings.access.memberEmails.length ||
      value.accessPolicy.identitiesHash !== await sha256({
        emails: [...claim.settings.access.adminEmails, ...claim.settings.access.memberEmails]
          .sort(compareText),
      }) || !Array.isArray(value.resources) || value.resources.length !== resourceOrder.length) return null;
  const parsedResources = [];
  const locators = new Set();
  for (let index = 0; index < resourceOrder.length; index += 1) {
    const resourceValue = value.resources[index];
    const desired = claim.resources[index];
    const kind = resourceOrder[index];
    const policy = kind === 'source_access_policy' || kind === 'portal_access_policy';
    if (!exactKeys(resourceValue, policy
      ? ['kind', 'key', 'provider', 'desiredHash', 'marker', 'identityHash']
      : ['kind', 'key', 'provider', 'desiredHash', 'marker'])) return null;
    const provider = parseProviderLocator(resourceValue.provider, policy);
    if (!provider || resourceValue.kind !== kind || desired.kind !== kind ||
        resourceValue.key !== desired.key || !RESOURCE_KEY.test(resourceValue.key) ||
        resourceValue.desiredHash !== desired.desiredHash ||
        resourceValue.marker !== marker(value.installationId, desired.key) ||
        (policy && resourceValue.identityHash !== value.accessPolicy.identitiesHash)) return null;
    const locatorKey = `${kind}\u0000${provider.parentId ?? ''}\u0000${provider.id}`;
    if (locators.has(locatorKey)) return null;
    locators.add(locatorKey);
    const parsedResource = {
      kind, key: desired.key, provider, desiredHash: desired.desiredHash,
      marker: resourceValue.marker,
    };
    if (policy) parsedResource.identityHash = resourceValue.identityHash;
    parsedResources.push(Object.freeze(parsedResource));
  }
  const sourceApplication = parsedResources.find((resourceValue) => resourceValue.kind === 'source_access_application');
  const sourcePolicy = parsedResources.find((resourceValue) => resourceValue.kind === 'source_access_policy');
  const portalApplication = parsedResources.find((resourceValue) => resourceValue.kind === 'portal_access_application');
  const portalPolicy = parsedResources.find((resourceValue) => resourceValue.kind === 'portal_access_policy');
  if (!portalApplication || !portalPolicy || portalPolicy.provider.parentId !== portalApplication.provider.id ||
      (sourceApplication
        ? !sourcePolicy || sourcePolicy.provider.parentId !== sourceApplication.provider.id ||
          sourceApplication.provider.id === portalApplication.provider.id
        : sourcePolicy !== undefined)) return null;
  const unsigned = {
    schemaVersion: 1,
    manager: MANAGER,
    installationId: value.installationId,
    state: 'ready',
    revision: resourceOrder.length + 1,
    release: value.release,
    target: value.target,
    accessPolicy: value.accessPolicy,
    desiredHash: value.desiredHash,
    resources: parsedResources,
    pending: null,
  };
  if (await sha256(unsigned) !== value.checksum) return null;
  return Object.freeze({ ...unsigned, checksum: value.checksum });
}

async function initialState(claim) {
  const allowedEmails = [...claim.settings.access.adminEmails, ...claim.settings.access.memberEmails]
    .sort(compareText);
  return {
    schemaVersion: 1,
    status: 'installing',
    installationId: claim.expected.installationId,
    approvedPlanId: `plan-${claim.expected.configurationHash.slice('sha256:'.length, 'sha256:'.length + 24)}`,
    configurationHash: claim.expected.configurationHash,
    desiredHash: claim.expected.desiredHash,
    release: claim.release,
    target: claim.target,
    settings: claim.settings,
    accessPolicy: {
      identityType: 'email',
      identityCount: allowedEmails.length,
      identitiesHash: await sha256({ emails: allowedEmails }),
    },
    desiredResources: claim.resources,
    resources: [],
    pending: null,
    receipt: null,
  };
}

async function readyReceipt(state) {
  const unsigned = {
    schemaVersion: 1,
    manager: MANAGER,
    installationId: state.installationId,
    state: 'ready',
    revision: state.resources.length + 1,
    release: state.release.id,
    target: { ...state.target, hostname: state.settings.connect.hostname },
    accessPolicy: state.accessPolicy,
    desiredHash: state.desiredHash,
    resources: state.resources,
    pending: null,
  };
  return Object.freeze({ ...unsigned, checksum: await sha256(unsigned) });
}

function readyResponse(state, applyInvoked, resumed) {
  return fixedJson(200, {
    schemaVersion: 1,
    status: 'ready',
    installationId: state.installationId,
    approvedPlanId: state.approvedPlanId,
    configurationHash: state.configurationHash,
    desiredHash: state.desiredHash,
    settingsRevision: 1,
    release: state.release,
    gateway: {
      hostname: state.settings.connect.hostname,
      mcpUrl: `https://${state.settings.connect.hostname}/mcp`,
    },
    receipt: {
      revision: state.receipt.revision,
      resourceCount: state.receipt.resources.length,
      evidence: state.receipt,
    },
    applyInvoked,
    resumed,
  });
}

async function save(storage, value) {
  await storage.put(STORAGE_KEY, value);
}

/**
 * A provider outcome that stopped the bootstrap, kept as numbers and fixed
 * words only: the resource kind, the outcome class, the HTTP status and the
 * provider's numeric error code. It is returned to the shell, which records
 * it as the failure reason behind its status route. The payload itself never
 * logs, by the public-payload purity gate.
 */
function providerFailureDetail(outcome, kind, step) {
  const detail = {
    kind: isText(kind) ? kind : 'unknown',
    step,
    status: isText(outcome.status) ? outcome.status : 'unknown',
  };
  if (Number.isSafeInteger(outcome.httpStatus)) detail.httpStatus = outcome.httpStatus;
  if (Number.isSafeInteger(outcome.providerCode)) detail.code = outcome.providerCode;
  return Object.freeze(detail);
}

function providerFailure(outcome, kind, step) {
  const provider = providerFailureDetail(outcome, kind, step);
  const reason = provider.status === 'unknown' ? 'bootstrap_recovery_required' : 'bootstrap_requires_repair';
  return fixedJson(409, {
    schemaVersion: 1,
    error: reason,
    retryable: reason === 'bootstrap_recovery_required',
    provider,
  });
}

export async function processBootstrap(request, env, storage) {
  const rawBody = await request.text();
  const environment = parseEnvironment(env, true);
  const signature = request.headers.get('x-ankka-bootstrap-signature');
  if (!environment || !await verifyHmac(rawBody, environment.bootstrapNonce, signature)) return rejected();
  let parsed;
  try { parsed = JSON.parse(rawBody); } catch { return rejected(); }
  if (!isPlainData(parsed) || canonicalJson(parsed) !== rawBody) return rejected();
  const claim = await parseClaim(parsed, environment, Date.now());
  if (!claim) return rejected();
  let stored;
    try { stored = await storage.get(STORAGE_KEY); } catch { return recovery('bootstrap_recovery_required'); }
    const resumed = stored !== undefined;
    if (stored !== undefined && stored?.state === 'ready') {
      const receipt = await parseReadyReceipt(stored, claim);
      if (!receipt) return recovery('bootstrap_request_mismatch');
      return readyResponse({
        ...await initialState(claim),
        status: 'ready',
        resources: receipt.resources,
        receipt,
      }, false, true);
    }
    let state = stored === undefined ? await initialState(claim) : stored;
    if (stored !== undefined && !validStoredState(state, claim)) return recovery('bootstrap_request_mismatch');
    if (state.status === 'ready') return readyResponse(state, false, true);
    if (stored === undefined) {
      try { await save(storage, state); } catch { return recovery('bootstrap_recovery_required'); }
    }
    let applyInvoked = false;
    for (const kind of state.desiredResources.map((resourceValue) => resourceValue.kind)) {
      if (locator(state, kind)) continue;
      const desired = resource(state, kind);
      if (!desired) return recovery('bootstrap_requires_repair');
      if (state.pending !== null) {
        if (!exactKeys(state.pending, ['kind', 'key', 'requestId', 'phase']) ||
            state.pending.kind !== kind || state.pending.key !== desired.key ||
            !REQUEST_ID.test(state.pending.requestId) ||
            !['send_armed', 'submitted', 'not_applied'].includes(state.pending.phase)) {
          return recovery('bootstrap_requires_repair');
        }
        const observed = await discoverResource(state, kind, claim.cloudflareAccessToken);
        if (observed.status === 'present') {
          state = {
            ...state,
            resources: [...state.resources, receiptResource(state, desired, observed.provider)],
            pending: null,
          };
          try { await save(storage, state); } catch { return recovery('bootstrap_recovery_required'); }
          continue;
        }
        if (observed.status !== 'absent') return providerFailure(observed, kind, 'discover_pending');
        if (state.pending.requestId === claim.requestId) return recovery('bootstrap_recovery_required');
        state = { ...state, pending: null };
        try { await save(storage, state); } catch { return recovery('bootstrap_recovery_required'); }
      }

      const before = await discoverResource(state, kind, claim.cloudflareAccessToken);
      if (before.status === 'present') return recovery('bootstrap_requires_repair');
      if (before.status !== 'absent') return providerFailure(before, kind, 'discover');
      state = {
        ...state,
        pending: { kind, key: desired.key, requestId: claim.requestId, phase: 'send_armed' },
      };
      try { await save(storage, state); } catch { return recovery('bootstrap_recovery_required'); }
      const created = await createResource(state, kind, claim.cloudflareAccessToken);
      if (created.status !== 'submitted') return providerFailure(created, kind, 'create');
      applyInvoked = true;
      state = { ...state, pending: { ...state.pending, phase: 'submitted' } };
      try { await save(storage, state); } catch { return recovery('bootstrap_recovery_required'); }
      const after = await discoverResource(state, kind, claim.cloudflareAccessToken);
      if (after.status !== 'present') return providerFailure(after, kind, 'verify');
      if (after.provider.id !== created.provider.id ||
          (created.provider.parentId ?? '') !== (after.provider.parentId ?? '')) {
        return recovery('bootstrap_requires_repair');
      }
      state = {
        ...state,
        resources: [...state.resources, receiptResource(state, desired, after.provider)],
        pending: null,
      };
      try { await save(storage, state); } catch { return recovery('bootstrap_recovery_required'); }
    }
  try {
    state = { ...state, status: 'ready', receipt: await readyReceipt(state), pending: null };
    await save(storage, state.receipt);
    return readyResponse(state, applyInvoked, resumed);
  } catch {
    return recovery('bootstrap_recovery_required');
  }
}

/**
 * Re-prove every receipt-owned Gateway resource with a fresh request-local
 * Cloudflare grant. Unlike processBootstrap, this path cannot create or update
 * anything and does not need the bootstrap HMAC secret after final cutover.
 */
export async function verifyBootstrapReceiptProviderState(value, env, storage, nowMs = Date.now()) {
  return (await verifyBootstrapReceiptProviderStateWithReason(value, env, storage, nowMs)).verified;
}

/**
 * The same check, naming the first disagreement with fixed words only: the
 * resource kind and the discovery status, never provider text or ids.
 */
export async function verifyBootstrapReceiptProviderStateWithReason(value, env, storage, nowMs = Date.now()) {
  const failure = (reason) => Object.freeze({ verified: false, reason });
  try {
    const environment = parseEnvironment(env, false);
    if (!environment) return failure('environment_invalid');
    if (!isPlainData(value) || !isRecord(value) || !Number.isSafeInteger(nowMs) || nowMs < 0) {
      return failure('claim_invalid');
    }
    const claim = await parseClaim(value, environment, nowMs);
    if (!claim) return failure('claim_invalid');
    const stored = await storage.get(STORAGE_KEY);
    if (stored === undefined) return failure('receipt_missing');
    const receipt = await parseReadyReceipt(stored, claim);
    if (!receipt) return failure('receipt_invalid');
    const state = {
      ...await initialState(claim),
      status: 'ready',
      resources: receipt.resources,
      receipt,
    };
    for (const kind of claim.resources.map((resourceValue) => resourceValue.kind)) {
      const expected = receipt.resources.find((resourceValue) => resourceValue.kind === kind);
      if (!expected) return failure(`${kind}_missing`);
      // A provider answer that settles nothing (rate limit, 5xx, not JSON) is
      // read again a few times before it counts; the resource was created
      // moments ago and the provider is allowed to be briefly unsettled.
      let observed = await discoverResource(state, kind, claim.cloudflareAccessToken);
      for (let attempt = 1; attempt < VERIFY_DISCOVERY_ATTEMPTS && observed.status === 'unknown'; attempt += 1) {
        await new Promise((resolve) => setTimeout(resolve, VERIFY_DISCOVERY_BACKOFF_MS * attempt));
        observed = await discoverResource(state, kind, claim.cloudflareAccessToken);
      }
      if (observed.status !== 'present') {
        const status = isText(observed.status) ? observed.status : 'unknown';
        const http = Number.isSafeInteger(observed.httpStatus) ? `_http_${observed.httpStatus}` : '';
        const code = Number.isSafeInteger(observed.providerCode) ? `_code_${observed.providerCode}` : '';
        return failure(`${kind}_${status}${http}${code}`);
      }
      if (canonicalJson(observed.provider) !== canonicalJson(expected.provider)) {
        return failure(`${kind}_locator_mismatch`);
      }
    }
    return Object.freeze({ verified: true, reason: null });
  } catch {
    return failure('threw');
  }
}

function safePublicStatus(value) {
  if (!isRecord(value) || !exactKeys(value, [
    'schemaVersion', 'status', 'release', 'gateway', 'source', 'access', 'updatedAt',
  ]) || value.schemaVersion !== 1 || value.status !== 'ready' ||
      !isText(value.release) || !RELEASE.test(value.release) ||
      !exactKeys(value.gateway, ['name', 'hostname', 'mcpUrl', 'capabilityMode', 'codeMode']) ||
      !isText(value.gateway.name) || !hostname(value.gateway.hostname) ||
      value.gateway.mcpUrl !== `https://${value.gateway.hostname}/mcp` ||
      value.gateway.capabilityMode !== 'read_only' || value.gateway.codeMode !== 'default_on' ||
      (value.source !== null && (
        !exactKeys(value.source, ['label', 'endpoint', 'enabledTools']) ||
        !isText(value.source.label) || !isText(value.source.endpoint) ||
        !Array.isArray(value.source.enabledTools)
      )) ||
      !exactKeys(value.access, ['administratorCount', 'memberCount']) ||
      !Number.isSafeInteger(value.access.administratorCount) || !Number.isSafeInteger(value.access.memberCount) ||
      !isText(value.updatedAt)) return null;
  return Object.freeze(structuredClone(value));
}

function publicStatusFromReadyResponse(body) {
  return {
    schemaVersion: 1,
    status: 'ready',
    release: body.release.id,
    gateway: {
      name: body.settings.connect.name,
      hostname: body.settings.connect.hostname,
      mcpUrl: `https://${body.settings.connect.hostname}/mcp`,
      capabilityMode: 'read_only',
      codeMode: 'default_on',
    },
    source: body.settings.sources.length === 0 ? null : {
      label: body.settings.sources[0].label,
      endpoint: body.settings.sources[0].url,
      enabledTools: [...body.settings.sources[0].enabledTools],
    },
    access: {
      administratorCount: body.settings.access.adminEmails.length,
      memberCount: body.settings.access.memberEmails.length,
    },
    updatedAt: new Date().toISOString(),
  };
}

function safeManagementControl(value) {
  if (!exactKeys(value, [
    'schemaVersion', 'installationId', 'accountId', 'zoneId', 'portal', 'audienceEmails', 'sourceOwnership',
  ]) || value.schemaVersion !== 1 || !INSTALLATION_ID.test(value.installationId) ||
      !ACCOUNT_ID.test(value.accountId) || !ZONE_ID.test(value.zoneId) || !exactKeys(value.portal, [
        'id', 'name', 'hostname', 'marker',
      ]) || !safeProviderId(value.portal.id) || !validSourceLabel(value.portal.name) ||
      !hostname(value.portal.hostname) || !isText(value.portal.marker) ||
      !value.portal.marker.startsWith(`acg:v1:${value.installationId}:`) ||
      !RESOURCE_KEY.test(value.portal.marker.slice(`acg:v1:${value.installationId}:`.length))) {
    return null;
  }
  const audienceEmails = exactSortedUniqueStrings(value.audienceEmails, normalizedEmail, undefined, 1);
  if (!audienceEmails || !Array.isArray(value.sourceOwnership) || value.sourceOwnership.length > 32) return null;
  const sourceOwnership = [];
  const sourceProviderLocators = new Set();
  for (const source of value.sourceOwnership) {
    if (!exactKeys(source, ['sourceId', 'resources']) || !SOURCE_ID.test(source.sourceId) ||
        !Array.isArray(source.resources) || source.resources.length !== 3) return null;
    const resources = source.resources.map(safeSourceActionResource);
    if (resources.some((resourceValue) => resourceValue === null) || resources.some((resourceValue) => (
      resourceValue.marker !== marker(value.installationId, resourceValue.key)
    )) || resources[2].provider.parentId !== resources[1].provider.id) return null;
    for (const resourceValue of resources) {
      const locatorKey = teardownProviderLocatorKey(resourceValue);
      if (sourceProviderLocators.has(locatorKey)) return null;
      sourceProviderLocators.add(locatorKey);
    }
    sourceOwnership.push(Object.freeze({ sourceId: source.sourceId, resources: Object.freeze(resources) }));
  }
  if (new Set(sourceOwnership.map((source) => source.sourceId)).size !== sourceOwnership.length ||
      new Set(sourceOwnership.map((source) => source.resources[0].provider.id)).size !== sourceOwnership.length) return null;
  return Object.freeze({
    schemaVersion: 1,
    installationId: value.installationId,
    accountId: value.accountId,
    zoneId: value.zoneId,
    portal: Object.freeze({ ...value.portal }),
    audienceEmails,
    sourceOwnership: Object.freeze(sourceOwnership),
  });
}

function readyResource(body, kind) {
  const resources = body?.receipt?.evidence?.resources;
  if (!Array.isArray(resources)) return null;
  const matches = resources.filter((resourceValue) => isRecord(resourceValue) && resourceValue.kind === kind);
  return matches.length === 1 && isRecord(matches[0].provider) ? matches[0] : null;
}

async function managementControlFromReadyResponse(claim, ready, env) {
  const environment = parseManagementEnvironment(env);
  const portal = readyResource(ready, 'portal');
  if (!environment || !portal) return null;
  let sourceOwnership = [];
  if (claim.settings.sources.length > 0) {
    const server = readyResource(ready, 'mcp_server');
    const application = readyResource(ready, 'source_access_application');
    const policy = readyResource(ready, 'source_access_policy');
    const sourceUrl = publicMcpUrl(claim.settings.sources[0].url);
    if (!server || !application || !policy || !sourceUrl) return null;
    sourceOwnership = [{
      sourceId: `source-${(await sha256Hex(sourceUrl)).slice(0, 16)}`,
      resources: [server, application, policy],
    }];
  }
  return safeManagementControl({
    schemaVersion: 1,
    installationId: claim.expected.installationId,
    accountId: environment.accountId,
    zoneId: environment.zoneId,
    portal: {
      id: portal.provider.id,
      name: claim.settings.connect.name,
      hostname: claim.settings.connect.hostname,
      marker: marker(claim.expected.installationId, portal.key),
    },
    audienceEmails: [
      ...claim.settings.access.adminEmails,
      ...claim.settings.access.memberEmails,
    ].sort(compareText),
    sourceOwnership,
  });
}

function toolName(value) {
  return isText(value) && TOOL.test(value) ? value : null;
}

function safeManagedSource(value) {
  const legacyPublic = exactKeys(value, ['id', 'label', 'url', 'enabledTools', 'status']);
  const legacyAuth = exactKeys(value, ['id', 'label', 'url', 'authMode', 'enabledTools', 'status']);
  const current = exactKeys(value, [
    'id', 'label', 'url', 'authMode', 'onBehalfOfUser', 'enabledTools', 'status',
  ]);
  if ((!legacyPublic && !legacyAuth && !current) ||
      !isText(value.id) || !SOURCE_ID.test(value.id) ||
      !validSourceLabel(value.label) || !publicMcpUrl(value.url) ||
      (value.status !== 'installed' && value.status !== 'draft')) return null;
  const authMode = legacyPublic ? 'none' : value.authMode;
  if (authMode !== 'none' && authMode !== 'oauth') return null;
  const onBehalfOfUser = current ? value.onBehalfOfUser : authMode === 'oauth';
  if (!isBoolean(onBehalfOfUser) || (authMode === 'none' && onBehalfOfUser !== false)) return null;
  const enabledTools = exactSortedUniqueStrings(
    value.enabledTools,
    toolName,
    MAX_ENABLED_TOOLS_PER_SOURCE,
    1,
  );
  if (!enabledTools) return null;
  return Object.freeze({
    id: value.id,
    label: value.label,
    url: publicMcpUrl(value.url),
    authMode,
    onBehalfOfUser,
    enabledTools,
    status: value.status,
  });
}

export function safeManagementSources(value) {
  if (!exactKeys(value, ['schemaVersion', 'revision', 'applyMode', 'sources']) ||
      value.schemaVersion !== 1 || !Number.isSafeInteger(value.revision) || value.revision < 1 ||
      value.revision > Number.MAX_SAFE_INTEGER || value.applyMode !== 'oauth_per_action' ||
      !Array.isArray(value.sources) || value.sources.length > 32) return null;
  const sources = value.sources.map(safeManagedSource);
  if (sources.some((source) => source === null)) return null;
  const ids = new Set(sources.map((source) => source.id));
  const urls = new Set(sources.map((source) => source.url));
  if (ids.size !== sources.length || urls.size !== sources.length) return null;
  const record = Object.freeze({
    schemaVersion: 1,
    revision: value.revision,
    applyMode: 'oauth_per_action',
    sources: Object.freeze(sources),
  });
  if (new TextEncoder().encode(canonicalJson(record)).byteLength > MANAGEMENT_SOURCES_LIMIT_BYTES) {
    return null;
  }
  return record;
}

export function managementSourcesInstallProjectionFits(record) {
  if (record.revision >= Number.MAX_SAFE_INTEGER) return false;
  const projected = {
    ...record,
    revision: Number.MAX_SAFE_INTEGER,
    sources: record.sources.map((source) => ({ ...source, status: 'installed' })),
  };
  return new TextEncoder().encode(canonicalJson(projected)).byteLength <= MANAGEMENT_SOURCES_LIMIT_BYTES;
}

async function initialManagementSources(status) {
  if (status.source === null) {
    return safeManagementSources({
      schemaVersion: 1,
      revision: 1,
      applyMode: 'oauth_per_action',
      sources: [],
    });
  }
  const url = publicMcpUrl(status.source.endpoint);
  if (!url) return null;
  const record = {
    schemaVersion: 1,
    revision: 1,
    applyMode: 'oauth_per_action',
    sources: [{
      id: `source-${(await sha256Hex(url)).slice(0, 16)}`,
      label: status.source.label,
      url,
      authMode: 'none',
      onBehalfOfUser: false,
      enabledTools: [...status.source.enabledTools].sort(compareText),
      status: 'installed',
    }],
  };
  return safeManagementSources(record);
}

export function parseSourceSave(value) {
  const validSource = isRecord(value?.source) && exactKeys(
    value.source, ['label', 'url', 'authMode', 'enabledTools'],
  );
  if (!exactKeys(value, ['schemaVersion', 'revision', 'source']) || value.schemaVersion !== 1 ||
      !Number.isSafeInteger(value.revision) || value.revision < 1 ||
      !validSource ||
      !validSourceLabel(value.source.label)) return null;
  const url = publicMcpUrl(value.source.url);
  const authMode = value.source.authMode;
  const enabledTools = exactSortedUniqueStrings(
    value.source.enabledTools,
    toolName,
    MAX_ENABLED_TOOLS_PER_SOURCE,
    1,
  );
  if (!url || !enabledTools || (authMode !== 'none' && authMode !== 'oauth')) return null;
  return Object.freeze({
    revision: value.revision,
    source: Object.freeze({
      label: value.source.label, url, authMode, enabledTools,
    }),
  });
}

export async function saveDraftSource(current, input) {
  if (input.revision !== current.revision) return null;
  const existing = current.sources.find((source) => source.url === input.source.url);
  if (existing?.status === 'installed') return null;
  const id = existing?.id ?? `source-${(await sha256Hex(input.source.url)).slice(0, 16)}`;
  const source = {
    id,
    label: input.source.label,
    url: input.source.url,
    authMode: input.source.authMode,
    onBehalfOfUser: false,
    enabledTools: [...input.source.enabledTools],
    status: 'draft',
  };
  const sources = existing
    ? current.sources.map((candidate) => candidate.id === id ? source : candidate)
    : [...current.sources, source];
  if (sources.length > 32) return null;
  sources.sort((left, right) => compareText(left.id, right.id));
  const updated = safeManagementSources({
    schemaVersion: 1,
    revision: current.revision + 1,
    applyMode: 'oauth_per_action',
    sources,
  });
  return updated && managementSourcesInstallProjectionFits(updated) ? updated : null;
}

const SOURCE_ACTION_RESOURCE_ORDER = Object.freeze([
  'mcp_server', 'source_access_application', 'source_access_policy',
]);

function safeSourceActionResource(value, index) {
  const kind = SOURCE_ACTION_RESOURCE_ORDER[index];
  const policy = kind === 'source_access_policy';
  if (!exactKeys(value, policy
    ? ['kind', 'key', 'provider', 'desiredHash', 'marker', 'identityHash']
    : ['kind', 'key', 'provider', 'desiredHash', 'marker']) || value.kind !== kind ||
      !RESOURCE_KEY.test(value.key) || !isText(value.desiredHash) || !HASH.test(value.desiredHash) ||
      !isText(value.marker) || !value.marker.startsWith('acg:v1:') ||
      (policy && (!isText(value.identityHash) || !HASH.test(value.identityHash)))) return null;
  const provider = parseProviderLocator(value.provider, policy);
  if (!provider) return null;
  return Object.freeze({ ...value, provider });
}

function safeSourceActionPending(value) {
  if (value === null) return null;
  if (!exactKeys(value, ['kind', 'phase', 'provider']) ||
      !SOURCE_ACTION_RESOURCE_ORDER.includes(value.kind) ||
      (value.phase !== 'send_armed' && value.phase !== 'submitted')) return false;
  const policy = value.kind === 'source_access_policy';
  const provider = value.provider === null ? null : parseProviderLocator(value.provider, policy);
  if (value.phase === 'send_armed' ? value.provider !== null : !provider) return false;
  return Object.freeze({ kind: value.kind, phase: value.phase, provider });
}

function safePortalUpdate(value) {
  if (value === null) return null;
  if (!exactKeys(value, ['phase', 'desiredHash']) ||
      (value.phase !== 'send_armed' && value.phase !== 'submitted') ||
      !isText(value.desiredHash) || !HASH.test(value.desiredHash)) return false;
  return Object.freeze({ ...value });
}

function safeSourceAction(value) {
  if (!exactKeys(value, [
    'schemaVersion', 'actionId', 'sourceId', 'sourceRevision', 'actorEmail', 'issuedAt',
    'expiresAt', 'status', 'actionKeyHash', 'sourceHash', 'resources', 'pending', 'portalUpdate', 'failureCode',
    ...(Object.hasOwn(value ?? {}, 'initialPolicyVersion') ? ['initialPolicyVersion'] : []),
    ...(Object.hasOwn(value ?? {}, 'renewedAt') ? ['renewedAt'] : []),
    ...(Object.hasOwn(value ?? {}, 'bigquerySetupStarted') ? ['bigquerySetupStarted'] : []),
  ]) || value.schemaVersion !== 1 || !ACTION_ID.test(value.actionId) || !SOURCE_ID.test(value.sourceId) ||
      (Object.hasOwn(value, 'bigquerySetupStarted') && value.bigquerySetupStarted !== true) ||
      (Object.hasOwn(value, 'initialPolicyVersion') && value.initialPolicyVersion !== SOURCE_INITIAL_POLICY_VERSION) ||
      !Number.isSafeInteger(value.sourceRevision) || value.sourceRevision < 1 ||
      !normalizedEmail(value.actorEmail) || !Number.isSafeInteger(value.issuedAt) ||
      (Object.hasOwn(value, 'renewedAt') && value.renewedAt !== value.issuedAt) ||
      !Number.isSafeInteger(value.expiresAt) || value.expiresAt <= value.issuedAt ||
      value.expiresAt - value.issuedAt > 10 * 60 * 1000 ||
      !['authorization_required', 'applying', 'succeeded', 'failed', 'recovery_required'].includes(value.status) ||
      !isText(value.actionKeyHash) || !HASH.test(value.actionKeyHash) ||
      !isText(value.sourceHash) || !HASH.test(value.sourceHash) ||
      !Array.isArray(value.resources) || value.resources.length > SOURCE_ACTION_RESOURCE_ORDER.length ||
      (value.failureCode !== null && (!isText(value.failureCode) ||
        !/^[a-z][a-z0-9_]{0,63}$/u.test(value.failureCode)))) return null;
  const resources = value.resources.map(safeSourceActionResource);
  const pending = safeSourceActionPending(value.pending);
  const portalUpdate = safePortalUpdate(value.portalUpdate);
  if (resources.some((resourceValue) => resourceValue === null) || pending === false || portalUpdate === false ||
      resources.some((resourceValue, index) => resourceValue.kind !== SOURCE_ACTION_RESOURCE_ORDER[index]) ||
      (pending && pending.kind !== SOURCE_ACTION_RESOURCE_ORDER[resources.length]) ||
      (portalUpdate && resources.length !== SOURCE_ACTION_RESOURCE_ORDER.length)) return null;
  return Object.freeze({
    ...value,
    actorEmail: normalizedEmail(value.actorEmail),
    resources: Object.freeze(resources),
    pending,
    portalUpdate,
  });
}

function safeSourceActions(value) {
  if (!exactKeys(value, ['schemaVersion', 'revision', 'actions']) || value.schemaVersion !== 1 ||
      !Number.isSafeInteger(value.revision) || value.revision < 1 ||
      !Array.isArray(value.actions) || value.actions.length > 16) return null;
  const actions = value.actions.map(safeSourceAction);
  if (actions.some((action) => action === null) ||
      new Set(actions.map((action) => action.actionId)).size !== actions.length) return null;
  return Object.freeze({ schemaVersion: 1, revision: value.revision, actions: Object.freeze(actions) });
}

function publicSourceAction(action) {
  return Object.freeze({
    schemaVersion: 1,
    actionId: action.actionId,
    sourceId: action.sourceId,
    status: action.status,
    expiresAt: new Date(action.expiresAt).toISOString(),
    failureCode: action.failureCode,
  });
}

function sourceActionHasWriteEvidence(action) {
  return action.bigquerySetupStarted === true || action.resources.length > 0 || action.pending !== null || action.portalUpdate !== null;
}

function sourceActionState(action, now) {
  if (action.status === 'succeeded') return 'succeeded';
  if (action.status === 'authorization_required' && action.renewedAt === action.issuedAt &&
      action.expiresAt > now) return 'authorization_required';
  if (action.status === 'recovery_required' ||
      (sourceActionHasWriteEvidence(action) && action.status !== 'applying') ||
      (action.status === 'applying' && action.expiresAt <= now)) return 'recovery_required';
  if (action.status === 'authorization_required' && action.expiresAt <= now) return 'authorization_expired';
  return action.status;
}

function sourceActionCanCancel(action, actorEmail, now) {
  return action.actorEmail === normalizedEmail(actorEmail) && now >= action.issuedAt &&
    action.status === 'authorization_required' && !sourceActionHasWriteEvidence(action);
}

function sourceActionCanRenew(action, actorEmail, now) {
  // A completed connection check has no outstanding write. Other recovery
  // work must wait out the previous execution window before rotating its key.
  // An unacknowledged hostname-less app creation has no authoritative locator:
  // the zone listing cannot prove it absent, so it still needs manual review.
  return action.actorEmail === normalizedEmail(actorEmail) && now >= action.issuedAt &&
    (action.expiresAt <= now || sourceActionConnectionPaused(action) ||
      (action.bigquerySetupStarted === true && action.failureCode === 'bigquery_setup_required')) &&
    action.initialPolicyVersion === SOURCE_INITIAL_POLICY_VERSION &&
    sourceActionState(action, now) === 'recovery_required' &&
    !(action.pending?.kind === 'source_access_application' && action.pending.provider === null);
}

function sourceActionConnectionPaused(action) {
  return action.status === 'recovery_required' && action.pending === null && action.portalUpdate === null &&
    action.resources.length === SOURCE_ACTION_RESOURCE_ORDER.length &&
    ['source_connection_required', 'source_sync_required', 'source_tools_mismatch'].includes(action.failureCode);
}

function sourceActionBlocks(action) {
  return action.status !== 'succeeded' && (action.status !== 'failed' || sourceActionHasWriteEvidence(action));
}

function sourceActionPointer(action, kind = 'source') {
  const pointer = { kind, actionId: action.actionId };
  if (kind === 'source') pointer.sourceId = action.sourceId;
  return Object.freeze(pointer);
}

function sourceActionConflict(reason, action) {
  const body = { schemaVersion: 1, error: 'source_action_conflict' };
  if (reason) body.reason = reason;
  if (action) body.action = action;
  return fixedJson(409, body);
}

async function sourceActionSnapshot(storage, actorEmail, now) {
  const raw = await storage.get(ACTIONS_KEY);
  const current = raw === undefined ? { schemaVersion: 1, revision: 1, actions: [] } : safeSourceActions(raw);
  if (!current) return null;
  const blocking = current.actions.find((action) => sourceActionBlocks(action) &&
    sourceActionState(action, now) === 'recovery_required') ?? current.actions.find(sourceActionBlocks);
  let blockingAction = blocking ? sourceActionPointer(blocking) : null;
  for (const [key, kind, parse] of [
    [UPDATES_KEY, 'runtime', safeRuntimeUpdates], [TEARDOWNS_KEY, 'teardown', safeTeardownActions],
  ]) {
    const value = await storage.get(key);
    if (value === undefined) continue;
    const state = parse(value);
    if (!state) return null;
    const action = state.actions.find((candidate) => !['succeeded', 'failed'].includes(candidate.status) &&
      (candidate.status !== 'authorization_required' || candidate.expiresAt > now ||
        (kind === 'runtime' && candidate.stage !== null)));
    if (!blockingAction && action) blockingAction = sourceActionPointer(action, kind);
  }
  const team = await storage.get(TEAM_KEY);
  if (team !== undefined) {
    if (!isRecord(team) || !Object.hasOwn(team, 'pendingAction')) return null;
    const action = team.pendingAction;
    if (action !== null) {
      if (!isRecord(action) || !ACTION_ID.test(action.actionId) ||
          !['authorization_required', 'applying', 'succeeded', 'failed', 'recovery_required'].includes(action.status)) return null;
      if (!blockingAction && !['succeeded', 'failed'].includes(action.status)) {
        blockingAction = sourceActionPointer(action, 'team');
      }
    }
  }
  const control = current.actions.some(sourceActionConnectionPaused)
    ? safeManagementControl(await storage.get(CONTROL_KEY)) : null;
  return { schemaVersion: 1, actions: current.actions.map((action) => {
    const summary = {
      ...publicSourceAction(action), issuedAt: new Date(action.issuedAt).toISOString(),
      state: sourceActionState(action, now), canCancel: sourceActionCanCancel(action, actorEmail, now),
      canRenew: sourceActionCanRenew(action, actorEmail, now),
    };
    if (control && sourceActionConnectionPaused(action)) {
      summary.connectionUrl = `https://dash.cloudflare.com/${encodeURIComponent(control.accountId)}` +
        '/one/access-controls/ai-controls/mcp-server/edit/' + encodeURIComponent(action.resources[0].provider.id);
    }
    return summary;
  }), blockingAction };
}

function sourceSnapshotConflict(snapshot) {
  if (!snapshot) return fixedJson(503, { schemaVersion: 1, error: 'source_actions_unavailable' });
  const pointer = snapshot.blockingAction;
  if (!pointer) return null;
  return sourceActionConflict(pointer.kind !== 'source' ? 'lifecycle_pending' :
    snapshot.actions.find((action) => action.actionId === pointer.actionId)?.state === 'recovery_required'
      ? 'recovery_required' : 'source_pending', pointer);
}

function parseSourceActionPrepare(value) {
  if (!exactKeys(value, [
    'schemaVersion', 'actionId', 'sourceId', 'sourceRevision', 'actorEmail',
    'issuedAt', 'expiresAt', 'actionKeyHash', 'sourceHash',
  ]) || value.schemaVersion !== 1 || !ACTION_ID.test(value.actionId) || !SOURCE_ID.test(value.sourceId) ||
      !Number.isSafeInteger(value.sourceRevision) || value.sourceRevision < 1 ||
      !normalizedEmail(value.actorEmail) || !Number.isSafeInteger(value.issuedAt) ||
      !Number.isSafeInteger(value.expiresAt) || value.expiresAt <= value.issuedAt ||
      value.expiresAt - value.issuedAt > 10 * 60 * 1000 ||
      !isText(value.actionKeyHash) || !HASH.test(value.actionKeyHash) ||
      !isText(value.sourceHash) || !HASH.test(value.sourceHash)) return null;
  return Object.freeze({ ...value, actorEmail: normalizedEmail(value.actorEmail) });
}

async function prepareSourceAction(storage, input) {
  if (SOURCE_ADDITION_PAUSED) return sourceAdditionPaused();
  const parsed = parseSourceActionPrepare(input);
  const sources = safeManagementSources(await storage.get(SOURCES_KEY));
  const control = safeManagementControl(await storage.get(CONTROL_KEY));
  if (!parsed || !sources || !control || !managementSourcesInstallProjectionFits(sources)) return sourceActionConflict();
  if (parsed.sourceRevision !== sources.revision) return sourceActionConflict('draft_changed');
  const source = sources.sources.find((candidate) => candidate.id === parsed.sourceId);
  if (!source || source.status !== 'draft') return sourceActionConflict('draft_changed');
  const conflict = sourceSnapshotConflict(await sourceActionSnapshot(storage, parsed.actorEmail, parsed.issuedAt));
  if (conflict) return conflict;
  const current = safeSourceActions(await storage.get(ACTIONS_KEY)) ?? Object.freeze({
    schemaVersion: 1, revision: 1, actions: Object.freeze([]),
  });
  // New authorization never adopts, discards, or reinterprets an unfinished
  // journal. Only an explicit cancellation can release a proven-unstarted one.
  const retained = current.actions.filter((action) => action.sourceId !== parsed.sourceId).slice(-15);
  const action = safeSourceAction({
    ...parsed,
    initialPolicyVersion: SOURCE_INITIAL_POLICY_VERSION,
    status: 'authorization_required',
    resources: [],
    pending: null,
    portalUpdate: null,
    failureCode: null,
  });
  if (!action) return sourceActionConflict();
  const updated = safeSourceActions({
    schemaVersion: 1,
    revision: current.revision + 1,
    actions: [...retained, action],
  });
  if (!updated) return sourceActionConflict();
  await storage.put(ACTIONS_KEY, updated);
  return action;
}

async function managedSourceHash(source) {
  return sha256({
    id: source.id,
    label: source.label,
    url: source.url,
    authMode: source.authMode,
    onBehalfOfUser: source.onBehalfOfUser,
    enabledTools: source.enabledTools,
  });
}

async function renewSourceAction(storage, input, env) {
  if (SOURCE_ADDITION_PAUSED) return sourceAdditionPaused();
  const parsed = parseSourceActionPrepare(input);
  const context = parsed && await storedSourceActionContext(storage, parsed.actionId);
  const action = context?.action;
  if (!parsed || !action || !sourceActionCanRenew(action, parsed.actorEmail, parsed.issuedAt)) {
    return sourceActionConflict('recovery_required');
  }
  if (parsed.sourceId !== action.sourceId || parsed.sourceRevision !== action.sourceRevision ||
      parsed.sourceRevision !== context.sources.revision || parsed.sourceHash !== action.sourceHash ||
      !await actionDesiredState(context.control, context.sources, action)) {
    return sourceActionConflict('draft_changed');
  }
  if (await otherLifecycleBlocksSource(storage, parsed.issuedAt, action.actionId) ||
      await teamActionBlocksLifecycle(storage)) return sourceActionConflict('lifecycle_pending');
  // Older runtimes cannot parse the renewed journal marker.
  if (!await armSourceCompatibility(storage, env)) return actionRecovery('source_action_state_unavailable');
  const renewed = await persistSourceAction(storage, {
    ...action, status: 'authorization_required', actionKeyHash: parsed.actionKeyHash,
    issuedAt: parsed.issuedAt, renewedAt: parsed.issuedAt, expiresAt: parsed.expiresAt,
  });
  return renewed ?? actionRecovery('source_action_state_unavailable');
}

async function storedSourceActionContext(storage, actionId) {
  const actions = safeSourceActions(await storage.get(ACTIONS_KEY));
  const sources = safeManagementSources(await storage.get(SOURCES_KEY));
  const control = safeManagementControl(await storage.get(CONTROL_KEY));
  const action = actions?.actions.find((candidate) => candidate.actionId === actionId) ?? null;
  return actions && sources && managementSourcesInstallProjectionFits(sources) && control && action
    ? Object.freeze({ actions, sources, control, action })
    : null;
}

async function persistSourceAction(storage, action) {
  const parsed = safeSourceAction(action);
  const actions = safeSourceActions(await storage.get(ACTIONS_KEY));
  if (!parsed || !actions) return null;
  const index = actions.actions.findIndex((candidate) => candidate.actionId === parsed.actionId);
  if (index < 0) return null;
  const updated = safeSourceActions({
    schemaVersion: 1,
    revision: actions.revision + 1,
    actions: actions.actions.map((candidate, candidateIndex) => candidateIndex === index ? parsed : candidate),
  });
  if (!updated) return null;
  await storage.put(ACTIONS_KEY, updated);
  return parsed;
}

async function cancelSourceAction(storage, actionId, actorEmail, now) {
  const actions = safeSourceActions(await storage.get(ACTIONS_KEY));
  const action = actions?.actions.find((candidate) => candidate.actionId === actionId);
  if (!actions || !action || !Number.isSafeInteger(now) ||
      !sourceActionCanCancel(action, actorEmail, now)) return null;
  return persistSourceAction(storage, {
    ...action,
    status: 'failed',
    failureCode: 'source_action_denied',
  });
}

function sameProvider(left, right) {
  return left && right && left.id === right.id && (left.parentId ?? '') === (right.parentId ?? '');
}

async function actionDesiredState(control, sources, action) {
  const source = sources.sources.find((candidate) => candidate.id === action.sourceId);
  if (!source || (source.status !== 'draft' && source.status !== 'installed') ||
      await managedSourceHash(source) !== action.sourceHash) return null;
  const settings = {
    schemaVersion: 1,
    connect: { name: control.portal.name, hostname: control.portal.hostname, codeMode: 'default_on' },
    access: { adminEmails: [...control.audienceEmails], memberEmails: [] },
    sources: [{
      id: source.id,
      label: source.label,
      url: source.url,
      authentication: {
        mode: source.authMode,
        onBehalfOfUser: source.onBehalfOfUser,
      },
      enabledTools: [...source.enabledTools],
    }],
  };
  const desiredResources = (await buildDesiredResources(settings, control.installationId, true)).slice(0, 3);
  return Object.freeze({
    installationId: control.installationId,
    target: Object.freeze({ accountId: control.accountId, zoneId: control.zoneId }),
    settings: Object.freeze(settings),
    accessPolicy: Object.freeze({ identitiesHash: await sha256({ emails: [] }) }),
    desiredResources: Object.freeze(desiredResources),
    resources: action.resources,
    source,
  });
}

function actionRecovery(code = 'source_action_recovery_required', detail = null) {
  return fixedJson(409, detail === null
    ? { schemaVersion: 1, error: code, retryable: true }
    : { schemaVersion: 1, error: code, retryable: true, detail });
}

// Names the stopped step, HTTP status, numeric code, and a fixed validation
// label: never provider text or identifiers.
function providerDetail(kind, step, outcome) {
  const status = outcome?.httpStatus;
  const code = outcome?.providerCode;
  return `${kind}_${step}_${outcome?.status ?? 'unknown'}` +
    `${Number.isInteger(status) ? `_http_${status}` : ''}${Number.isInteger(code) ? `_code_${code}` : ''}` +
    `${outcome?.providerValidation ? `_${outcome.providerValidation}` : ''}`;
}

function sourceAdditionPaused() {
  return fixedJson(409, { schemaVersion: 1, error: 'source_addition_paused', retryable: false });
}

async function failSourceAction(storage, action, code, terminal = false, detail = null) {
  const updated = await persistSourceAction(storage, {
    ...action,
    status: terminal ? 'failed' : 'recovery_required',
    failureCode: code,
  });
  return updated ? actionRecovery(code, detail) : actionRecovery('source_action_state_unavailable');
}

function sourceActionClaim(value, environment, action, nowMs) {
  if (!exactKeys(value, [
    'schemaVersion', 'actionId', 'actionKey', 'actorEmail', 'accountId',
    'issuedAt', 'expiresAt', 'cloudflareAccessToken',
    ...(Object.hasOwn(value ?? {}, 'bigqueryPhase') ? ['bigqueryPhase'] : []),
  ]) || (Object.hasOwn(value ?? {}, 'bigqueryPhase') && !['start', 'failed'].includes(value.bigqueryPhase)) || value.schemaVersion !== 1 || value.actionId !== action.actionId ||
      !isText(value.actionKey) || !NONCE.test(value.actionKey) ||
      normalizedEmail(value.actorEmail) !== action.actorEmail || value.accountId !== environment.accountId ||
      !Number.isSafeInteger(value.issuedAt) || !Number.isSafeInteger(value.expiresAt) ||
      value.expiresAt !== action.expiresAt || value.issuedAt > nowMs + MAX_CLOCK_SKEW_SECONDS * 1000 ||
      value.issuedAt < action.issuedAt || value.expiresAt <= nowMs ||
      !isText(value.cloudflareAccessToken) || value.cloudflareAccessToken.length < 20 ||
      value.cloudflareAccessToken.length > 16 * 1024 || hasControlCharacter(value.cloudflareAccessToken)) return null;
  return value;
}

async function parseSourceActionRequest(request, env, storage, nowMs) {
  if (!(request instanceof Request) || request.method !== 'POST' || request.headers.has('authorization') ||
      request.headers.has('cookie') || request.headers.has('referer') || request.headers.has('origin') ||
      request.headers.get('content-type')?.split(';', 1)[0]?.trim().toLowerCase() !== 'application/json') return null;
  const environment = parseManagementEnvironment(env);
  const rawBody = await readBoundedText(request, REQUEST_LIMIT_BYTES);
  if (!environment || !rawBody) return null;
  let parsed;
  try { parsed = JSON.parse(rawBody); } catch { return null; }
  if (!isPlainData(parsed) || canonicalJson(parsed) !== rawBody || !ACTION_ID.test(parsed.actionId)) return null;
  const context = await storedSourceActionContext(storage, parsed.actionId);
  if (!context || (context.action.status !== 'authorization_required' &&
      !(context.action.bigquerySetupStarted === true && context.action.status === 'applying'))) return null;
  const claim = sourceActionClaim(parsed, environment, context.action, nowMs);
  if (!claim || await sha256(claim.actionKey) !== context.action.actionKeyHash ||
      !await verifyHmac(rawBody, claim.actionKey, request.headers.get('x-ankka-source-action-signature'))) return null;
  return Object.freeze({ ...context, claim });
}

function portalServerMappings(control, sources, action) {
  const actionServer = action.resources[0]?.provider?.id;
  const ownership = actionServer && !control.sourceOwnership.some((entry) => entry.sourceId === action.sourceId)
    ? [...control.sourceOwnership, {
      sourceId: action.sourceId,
      resources: action.resources,
    }]
    : [...control.sourceOwnership];
  const mappings = [];
  for (const entry of ownership.sort((left, right) => compareText(left.sourceId, right.sourceId))) {
    const source = sources.sources.find((candidate) => candidate.id === entry.sourceId);
    const serverId = entry.resources?.[0]?.provider?.id;
    if (!source || !safeProviderId(serverId)) return null;
    mappings.push(Object.freeze({
      server_id: serverId,
      default_disabled: true,
      on_behalf: source.onBehalfOfUser,
      updated_tools: source.enabledTools.map((name) => Object.freeze({ name, enabled: true })),
    }));
  }
  return Object.freeze(mappings);
}

function normalizedPortalMappings(value) {
  if (!isRecord(value)) return null;
  // A newly created empty Portal may omit the optional servers array.
  const servers = Object.hasOwn(value, 'servers') ? value.servers : [];
  if (!Array.isArray(servers)) return null;
  const mappings = [];
  for (const mapping of servers) {
    if (!isRecord(mapping)) return null;
    const serverId = safeProviderId(mapping.server_id ?? mapping.id);
    if (!serverId || mapping.default_disabled !== true || !isBoolean(mapping.on_behalf) ||
        !Array.isArray(mapping.updated_tools) ||
        (Object.hasOwn(mapping, 'updated_prompts') &&
          (!Array.isArray(mapping.updated_prompts) || mapping.updated_prompts.length !== 0))) return null;
    const tools = [];
    for (const tool of mapping.updated_tools) {
      if (!exactKeys(tool, ['name', 'enabled']) || !toolName(tool.name) || tool.enabled !== true) return null;
      tools.push(Object.freeze({ name: tool.name, enabled: true }));
    }
    tools.sort((left, right) => compareText(left.name, right.name));
    if (new Set(tools.map((tool) => tool.name)).size !== tools.length) return null;
    mappings.push(Object.freeze({
      server_id: serverId,
      default_disabled: true,
      on_behalf: mapping.on_behalf,
      updated_tools: Object.freeze(tools),
    }));
  }
  mappings.sort((left, right) => compareText(left.server_id, right.server_id));
  return new Set(mappings.map((mapping) => mapping.server_id)).size === mappings.length
    ? Object.freeze(mappings)
    : null;
}

function portalStaticMatches(value, control) {
  return isRecord(value) && value.id === control.portal.id && value.name === control.portal.name &&
    value.hostname === control.portal.hostname && value.description === control.portal.marker &&
    value.code_mode === 'default_on' && value.secure_web_gateway === false;
}

function sourceConnectionFailure(server, source) {
  if (!isRecord(server)) return 'source_sync_required';
  if (['required', 'stale'].includes(server.authentication_status)) return 'source_connection_required';
  if (server.status !== 'ready' || !Array.isArray(server.tools) ||
      server.tools.some((tool) => !isRecord(tool) || !toolName(tool.name))) return 'source_sync_required';
  const names = new Set(server.tools.map((tool) => tool.name));
  return source.enabledTools.every((name) => names.has(name)) ? null : 'source_tools_mismatch';
}

function portalExact(value, control, mappings) {
  const observed = normalizedPortalMappings(value);
  const expected = [...mappings].map((mapping) => ({
    ...mapping,
    updated_tools: [...mapping.updated_tools].sort((left, right) => compareText(left.name, right.name)),
  })).sort((left, right) => compareText(left.server_id, right.server_id));
  return portalStaticMatches(value, control) && observed !== null && canonicalJson(observed) === canonicalJson(expected);
}

async function finalizeSourceAction(storage, action) {
  const ownership = Object.freeze({
    sourceId: action.sourceId,
    resources: action.resources,
  });
  let control = safeManagementControl(await storage.get(CONTROL_KEY));
  let sources = safeManagementSources(await storage.get(SOURCES_KEY));
  const actions = safeSourceActions(await storage.get(ACTIONS_KEY));
  const actionIndex = actions?.actions.findIndex((candidate) => candidate.actionId === action.actionId) ?? -1;
  if (!control || !sources || !actions || actionIndex < 0 ||
      canonicalJson(actions.actions[actionIndex]) !== canonicalJson(action)) return null;
  const retained = control.sourceOwnership.find((entry) => entry.sourceId === ownership.sourceId);
  if (retained && canonicalJson(retained) !== canonicalJson(ownership)) return null;
  if (!retained) {
    control = safeManagementControl({
      ...control,
      sourceOwnership: [...control.sourceOwnership, ownership].sort((left, right) => compareText(left.sourceId, right.sourceId)),
    });
    if (!control) return null;
  }
  const source = sources.sources.find((candidate) => candidate.id === action.sourceId);
  if (!source || await managedSourceHash(source) !== action.sourceHash ||
      (source.status !== 'draft' && source.status !== 'installed')) return null;
  if (source.status === 'draft') {
    sources = safeManagementSources({
      ...sources,
      revision: sources.revision + 1,
      sources: sources.sources.map((candidate) => candidate.id === source.id
        ? { ...candidate, status: 'installed' }
        : candidate),
    });
    if (!sources) return null;
  }
  const completed = safeSourceAction({
    ...action,
    status: 'succeeded',
    pending: null,
    portalUpdate: null,
    failureCode: null,
  });
  if (!completed) return null;
  const updatedActions = safeSourceActions({
    ...actions, revision: actions.revision + 1,
    actions: actions.actions.map((candidate, index) => index === actionIndex ? completed : candidate),
  });
  if (!updatedActions) return null;
  // One atomic multi-key write: a restart cannot leave installed ownership and
  // source status committed without the corresponding completed action journal.
  await storage.put({ [CONTROL_KEY]: control, [SOURCES_KEY]: sources, [ACTIONS_KEY]: updatedActions });
  return completed;
}

async function processSourceAction(request, env, storage, nowMs = Date.now()) {
  if (await teamActionBlocksLifecycle(storage)) return actionRecovery('team_action_conflict');
  const parsed = await parseSourceActionRequest(request, env, storage, nowMs);
  if (!parsed) return fixedJson(400, { schemaVersion: 1, error: 'source_action_rejected', retryable: false });
  // A release gate is enforced here as well as in the authenticated API.
  if (SOURCE_ADDITION_PAUSED) return sourceAdditionPaused();
  if (parsed.claim.bigqueryPhase !== undefined) return actionRecovery('source_action_rejected');
  let { action } = parsed;
  if (action.initialPolicyVersion !== SOURCE_INITIAL_POLICY_VERSION) {
    return fixedJson(409, { schemaVersion: 1, error: 'source_action_legacy_policy', retryable: false });
  }
  if (action.sourceRevision !== parsed.sources.revision ||
      await otherLifecycleBlocksSource(storage, nowMs, action.actionId)) return actionRecovery('source_action_conflict');
  const desiredState = await actionDesiredState(parsed.control, parsed.sources, action);
  if (!desiredState) return failSourceAction(storage, action, 'source_action_drift');
  // Claim execution before the first remote read. Cancellation is serialized
  // with this request, and concurrent status reads can no longer offer cancel.
  action = await persistSourceAction(storage, { ...action, status: 'applying', failureCode: null });
  if (!action) return actionRecovery('source_action_state_unavailable');
  try { await verifyManagedSource(desiredState.source); } catch {
    return failSourceAction(storage, action, 'source_discovery_failed');
  }
  for (let index = 0; index < SOURCE_ACTION_RESOURCE_ORDER.length; index += 1) {
    const kind = SOURCE_ACTION_RESOURCE_ORDER[index];
    const state = { ...desiredState, resources: action.resources };
    const desired = resource(state, kind);
    if (!desired) return failSourceAction(storage, action, 'source_action_invalid');
    if (action.resources.length > index) {
      const observed = await discoverResource(
        state, kind, parsed.claim.cloudflareAccessToken, action.resources[index].provider,
      );
      if (observed.status !== 'present' || !sameProvider(observed.provider, action.resources[index].provider)) {
        return failSourceAction(storage, action, 'source_resource_drift', false, providerDetail(kind, 'retained', observed));
      }
      continue;
    }
    if (action.pending) {
      const observed = await discoverResource(
        state, kind, parsed.claim.cloudflareAccessToken, action.pending.provider,
      );
      if (observed.status === 'absent') {
        action = await persistSourceAction(storage, { ...action, pending: null });
        if (!action) return actionRecovery('source_action_state_unavailable');
      } else if (observed.status !== 'present' ||
          (action.pending.provider && !sameProvider(observed.provider, action.pending.provider))) {
        return failSourceAction(
          storage, action, 'source_action_recovery_required', false, providerDetail(kind, 'resume', observed),
        );
      } else {
        action = await persistSourceAction(storage, {
          ...action,
          resources: [...action.resources, receiptResource(state, desired, observed.provider)],
          pending: null,
        });
        if (!action) return actionRecovery('source_action_state_unavailable');
        continue;
      }
    }
    const baseline = await discoverResource(state, kind, parsed.claim.cloudflareAccessToken);
    if (baseline.status !== 'absent') return failSourceAction(
      storage,
      action,
      baseline.status === 'auth' ? 'source_action_authorization_failed' : 'source_resource_collision',
      baseline.status === 'auth',
      providerDetail(kind, 'baseline', baseline),
    );
    if (Date.now() >= action.expiresAt) return failSourceAction(storage, action, 'source_action_recovery_required');
    action = await persistSourceAction(storage, {
      ...action,
      pending: { kind, phase: 'send_armed', provider: null },
    });
    if (!action) return actionRecovery('source_action_state_unavailable');
    if (!await armSourceCompatibility(storage, env)) return actionRecovery('source_action_state_unavailable');
    const created = await createResource(state, kind, parsed.claim.cloudflareAccessToken);
    if (created.status !== 'submitted') {
      return failSourceAction(
        storage, action, 'source_action_recovery_required', false, providerDetail(kind, 'create', created),
      );
    }
    action = await persistSourceAction(storage, {
      ...action,
      pending: { kind, phase: 'submitted', provider: created.provider },
    });
    if (!action) return actionRecovery('source_action_state_unavailable');
    const after = await discoverResource(
      { ...desiredState, resources: action.resources }, kind, parsed.claim.cloudflareAccessToken, created.provider,
    );
    if (after.status !== 'present' || !sameProvider(after.provider, created.provider)) {
      return failSourceAction(
        storage, action, 'source_action_recovery_required', false, providerDetail(kind, 'verify', after),
      );
    }
    action = await persistSourceAction(storage, {
      ...action,
      resources: [...action.resources, receiptResource(state, desired, after.provider)],
      pending: null,
    });
    if (!action) return actionRecovery('source_action_state_unavailable');
  }
  const refreshed = await storedSourceActionContext(storage, action.actionId);
  if (!refreshed) return actionRecovery('source_action_state_unavailable');
  action = refreshed.action;
  const mappings = portalServerMappings(refreshed.control, refreshed.sources, action);
  if (!mappings) return failSourceAction(storage, action, 'source_action_drift');
  const portalBody = {
    name: refreshed.control.portal.name,
    hostname: refreshed.control.portal.hostname,
    code_mode: 'default_on',
    secure_web_gateway: false,
    description: refreshed.control.portal.marker,
    servers: mappings,
  };
  const desiredHash = await sha256(portalBody);
  const portalPath = `/accounts/${encodeURIComponent(refreshed.control.accountId)}/access/ai-controls/mcp/portals/${encodeURIComponent(refreshed.control.portal.id)}`;
  let live = await providerCall(portalPath, parsed.claim.cloudflareAccessToken);
  if (live.status !== 'ok' || !portalStaticMatches(live.result, refreshed.control)) {
    return failSourceAction(storage, action, 'portal_drift', false, providerDetail('portal', 'read', live));
  }
  if (!portalExact(live.result, refreshed.control, mappings)) {
    if (action.portalUpdate && action.portalUpdate.desiredHash !== desiredHash) {
      return failSourceAction(storage, action, 'source_action_drift');
    }
    const baselineMappings = portalServerMappings(
      refreshed.control, refreshed.sources, { ...action, resources: [] },
    );
    if (!baselineMappings || !portalExact(live.result, refreshed.control, baselineMappings)) {
      return failSourceAction(storage, action, 'portal_drift');
    }
    if (Date.now() >= action.expiresAt) return failSourceAction(storage, action, 'source_action_recovery_required');
    if (action.portalUpdate) {
      action = await persistSourceAction(storage, { ...action, portalUpdate: null });
      if (!action) return actionRecovery('source_action_state_unavailable');
    }
    // Cloudflare validates overrides against its synced catalogue. OAuth
    // sources need an operator connection before this Portal write can work.
    const serverPath = `/accounts/${encodeURIComponent(refreshed.control.accountId)}` +
      `/access/ai-controls/mcp/servers/${encodeURIComponent(action.resources[0].provider.id)}`;
    const server = await providerCall(serverPath, parsed.claim.cloudflareAccessToken);
    if (server.status !== 'ok' || server.result?.id !== action.resources[0].provider.id) {
      return failSourceAction(storage, action, 'source_action_recovery_required', false,
        providerDetail('mcp_server', 'connection', server));
    }
    const connectionFailure = sourceConnectionFailure(server.result, desiredState.source);
    if (connectionFailure) return failSourceAction(storage, action, connectionFailure);
    if (Date.now() >= action.expiresAt) return failSourceAction(storage, action, 'source_action_recovery_required');
    action = await persistSourceAction(storage, {
      ...action,
      portalUpdate: { phase: 'send_armed', desiredHash },
    });
    if (!action) return actionRecovery('source_action_state_unavailable');
    if (!await armSourceCompatibility(storage, env)) return actionRecovery('source_action_state_unavailable');
    const updated = await providerCall(portalPath, parsed.claim.cloudflareAccessToken, {
      // The guide uses `id` while the API schema requires `server_id`.
      // Send both with one identity; keep retained desired hashes unchanged.
      method: 'PUT', body: canonicalJson({ ...portalBody,
        servers: mappings.map((mapping) => ({ ...mapping, id: mapping.server_id })),
      }),
    });
    if (updated.status !== 'ok') {
      return failSourceAction(
        storage, action, 'source_action_recovery_required', false, providerDetail('portal', 'update', updated),
      );
    }
    action = await persistSourceAction(storage, {
      ...action,
      portalUpdate: { phase: 'submitted', desiredHash },
    });
    if (!action) return actionRecovery('source_action_state_unavailable');
    live = await providerCall(portalPath, parsed.claim.cloudflareAccessToken);
    if (live.status !== 'ok' || !portalExact(live.result, refreshed.control, mappings)) {
      return failSourceAction(
        storage, action, 'source_action_recovery_required', false, providerDetail('portal', 'verify', live),
      );
    }
  } else if (action.portalUpdate?.desiredHash !== desiredHash && action.portalUpdate !== null) {
    return failSourceAction(storage, action, 'source_action_drift');
  }
  const completed = await finalizeSourceAction(storage, action);
  return completed
    ? fixedJson(200, publicSourceAction(completed))
    : actionRecovery('source_action_state_unavailable');
}

const RUNTIME_ACTION_STAGES = Object.freeze([
  'authorized', 'current_verified', 'assets_uploaded', 'candidate_created',
  'candidate_staged', 'candidate_verified', 'activated', 'health_verified', 'rolled_back',
]);

function runtimeVersion(value) {
  if (!exactKeys(value, ['artifactSha256', 'release', 'versionId']) || !updateSemver(value.release) ||
      !isText(value.artifactSha256) || !HASH.test(value.artifactSha256) ||
      !(value.versionId === null || (isText(value.versionId) && VERSION_ID.test(value.versionId)))) return null;
  return Object.freeze({ ...value });
}

function safeRuntimeAction(value) {
  if (!exactKeys(value, [
    'actionId', 'actionKeyHash', 'actorEmail', 'expiresAt', 'failureCode', 'from', 'fromVersionId',
    'issuedAt', 'operation', 'schemaVersion', 'stage', 'status', 'to', 'toVersionId',
  ]) || value.schemaVersion !== 1 || !ACTION_ID.test(value.actionId) ||
      !isText(value.actionKeyHash) || !HASH.test(value.actionKeyHash) ||
      normalizedEmail(value.actorEmail) !== value.actorEmail || !Number.isSafeInteger(value.issuedAt) ||
      !Number.isSafeInteger(value.expiresAt) || value.expiresAt <= value.issuedAt ||
      value.expiresAt - value.issuedAt > 10 * 60 * 1000 ||
      !['update', 'rollback'].includes(value.operation) ||
      !['authorization_required', 'applying', 'succeeded', 'failed', 'recovery_required'].includes(value.status) ||
      !(value.stage === null || RUNTIME_ACTION_STAGES.includes(value.stage)) ||
      !(value.failureCode === null || (isText(value.failureCode) &&
        /^[a-z][a-z0-9_]{0,79}$/u.test(value.failureCode))) ||
      !(value.fromVersionId === null || VERSION_ID.test(value.fromVersionId)) ||
      !(value.toVersionId === null || VERSION_ID.test(value.toVersionId))) return null;
  const from = runtimeVersion(value.from);
  const to = runtimeVersion(value.to);
  return from && to ? Object.freeze({ ...value, from, to }) : null;
}

function safeRuntimeUpdates(value) {
  if (!exactKeys(value, ['actions', 'current', 'previous', 'revision', 'schemaVersion']) ||
      value.schemaVersion !== 1 || !Number.isSafeInteger(value.revision) || value.revision < 1 ||
      !Array.isArray(value.actions) || value.actions.length > 12) return null;
  const current = runtimeVersion(value.current);
  const previous = value.previous === null ? null : runtimeVersion(value.previous);
  const actions = value.actions.map(safeRuntimeAction);
  if (!current || (value.previous !== null && !previous) || actions.some((action) => !action) ||
      new Set(actions.map((action) => action.actionId)).size !== actions.length) return null;
  return Object.freeze({ schemaVersion: 1, revision: value.revision, current, previous, actions: Object.freeze(actions) });
}

function initialRuntimeUpdates(environment) {
  return safeRuntimeUpdates({
    schemaVersion: 1, revision: 1,
    current: { release: environment.release, artifactSha256: environment.releaseSha256, versionId: null },
    previous: null, actions: [],
  });
}

async function runtimeUpdates(storage, environment) {
  const retained = safeRuntimeUpdates(await storage.get(UPDATES_KEY));
  if (retained) return followRunningRelease(storage, retained, environment);
  const initial = initialRuntimeUpdates(environment);
  if (!initial) return null;
  await storage.put(UPDATES_KEY, initial);
  return initial;
}

// The Worker can change outside the journal: an operator-run update, or a
// Cloudflare-side rollback to an earlier version. Once no action is in
// flight, the journal follows the release the object actually runs, keeps the
// recorded one as the rollback reference, and the public status follows too.
async function followRunningRelease(storage, state, environment) {
  if (state.current.release === environment.release &&
      state.current.artifactSha256 === environment.releaseSha256) return state;
  const now = Date.now();
  if (state.actions.some((action) =>
    !['succeeded', 'failed'].includes(action.status) && action.expiresAt > now)) return state;
  const current = runtimeVersion({
    release: environment.release, artifactSha256: environment.releaseSha256, versionId: null,
  });
  if (!current) return state;
  const followed = await saveRuntimeUpdates(storage, {
    ...state, revision: state.revision + 1, current, previous: state.current,
  });
  if (!followed) return state;
  const status = safePublicStatus(await storage.get(STATUS_KEY));
  if (status) {
    await storage.put(STATUS_KEY, Object.freeze({
      ...status, release: current.release, updatedAt: new Date().toISOString(),
    }));
  }
  return followed;
}

function publicRuntimeAction(action) {
  return Object.freeze({
    schemaVersion: 1, actionId: action.actionId, operation: action.operation,
    status: action.status, stage: action.stage,
    from: Object.freeze({ release: action.from.release, artifactSha256: action.from.artifactSha256 }),
    to: Object.freeze({ release: action.to.release, artifactSha256: action.to.artifactSha256 }),
    expiresAt: new Date(action.expiresAt).toISOString(), failureCode: action.failureCode,
  });
}

async function saveRuntimeUpdates(storage, state) {
  const parsed = safeRuntimeUpdates(state);
  if (!parsed) return null;
  await storage.put(UPDATES_KEY, parsed);
  return parsed;
}

async function prepareRuntimeAction(storage, environment, input) {
  if (await currentTeardownLocksRuntime(storage, Date.now())) return null;
  if (await teamActionBlocksLifecycle(storage) || !await teamRuntimeReleaseAllowed(storage, input?.to?.release)) return null;
  if (!exactKeys(input, [
    'actionId', 'actionKeyHash', 'actorEmail', 'expiresAt', 'issuedAt', 'operation', 'to',
  ]) || !ACTION_ID.test(input.actionId) || !isText(input.actionKeyHash) ||
      !HASH.test(input.actionKeyHash) || normalizedEmail(input.actorEmail) !== input.actorEmail ||
      !Number.isSafeInteger(input.issuedAt) || !Number.isSafeInteger(input.expiresAt) ||
      input.expiresAt <= input.issuedAt || input.expiresAt - input.issuedAt > 10 * 60 * 1000 ||
      !['update', 'rollback'].includes(input.operation)) return null;
  const state = await runtimeUpdates(storage, environment);
  const to = runtimeVersion(input.to);
  if (!state || !to || state.current.release !== environment.release ||
      state.current.artifactSha256 !== environment.releaseSha256 ||
      (input.operation === 'update' && compareUpdateRelease(state.current.release, to.release) !== -1) ||
      (input.operation === 'rollback' && (!state.previous || canonicalJson(state.previous) !== canonicalJson(to)))) {
    return null;
  }
  const active = state.actions.find((action) =>
    !['succeeded', 'failed'].includes(action.status) && action.expiresAt > input.issuedAt);
  if (active) return null;
  const action = safeRuntimeAction({
    schemaVersion: 1, actionId: input.actionId, actionKeyHash: input.actionKeyHash,
    actorEmail: input.actorEmail, issuedAt: input.issuedAt, expiresAt: input.expiresAt,
    operation: input.operation, from: state.current, to, status: 'authorization_required',
    stage: null, failureCode: null, fromVersionId: state.current.versionId, toVersionId: to.versionId,
  });
  if (!action) return null;
  const updated = await saveRuntimeUpdates(storage, {
    ...state, revision: state.revision + 1,
    actions: [...state.actions.filter((candidate) => candidate.expiresAt > input.issuedAt), action].slice(-12),
  });
  return updated ? action : null;
}

async function updateRuntimeAction(storage, environment, actionId, transform) {
  const state = await runtimeUpdates(storage, environment);
  const index = state?.actions.findIndex((action) => action.actionId === actionId) ?? -1;
  if (!state || index < 0) return null;
  const action = safeRuntimeAction(transform(state.actions[index], state));
  if (!action) return null;
  const actions = state.actions.map((candidate, candidateIndex) => candidateIndex === index ? action : candidate);
  const nextState = { ...state, revision: state.revision + 1, actions };
  if (action.status === 'succeeded') {
    Object.assign(nextState, {
      current: { ...action.to, versionId: action.toVersionId },
      previous: { ...action.from, versionId: action.fromVersionId },
    });
  }
  const next = await saveRuntimeUpdates(storage, nextState);
  if (next && action.status === 'succeeded') {
    const status = safePublicStatus(await storage.get(STATUS_KEY));
    if (!status) return null;
    await storage.put(STATUS_KEY, Object.freeze({
      ...status,
      release: action.to.release,
      updatedAt: new Date().toISOString(),
    }));
  }
  return next ? action : null;
}

async function processRuntimeActionControl(request, env, storage, nowMs = Date.now()) {
  const environment = parseManagementEnvironment(env);
  const rawBody = await readBoundedText(request, 32 * 1024);
  if (!environment || request.method !== 'POST' || !rawBody || request.headers.has('authorization') ||
      request.headers.has('cookie') || request.headers.has('origin') || request.headers.has('referer') ||
      request.headers.get('content-type')?.split(';', 1)[0]?.trim().toLowerCase() !== 'application/json') {
    return fixedJson(400, { schemaVersion: 1, error: 'runtime_action_rejected' });
  }
  let value;
  try { value = JSON.parse(rawBody); } catch { value = null; }
  if (!isPlainData(value) || canonicalJson(value) !== rawBody || !ACTION_ID.test(value?.actionId)) {
    return fixedJson(400, { schemaVersion: 1, error: 'runtime_action_rejected' });
  }
  const state = await runtimeUpdates(storage, environment);
  const action = state?.actions.find((candidate) => candidate.actionId === value.actionId);
  if (await teamActionBlocksLifecycle(storage) || !await teamRuntimeReleaseAllowed(storage, action?.to?.release)) {
    return fixedJson(409, { schemaVersion: 1, error: 'team_action_conflict' });
  }
  if (!action || !isText(value.actionKey) || !NONCE.test(value.actionKey) ||
      await sha256(value.actionKey) !== action.actionKeyHash ||
      !await verifyHmac(rawBody, value.actionKey, request.headers.get('x-ankka-runtime-action-signature')) ||
      !Number.isSafeInteger(value.issuedAt) || value.issuedAt < action.issuedAt ||
      value.issuedAt > nowMs + MAX_CLOCK_SKEW_SECONDS * 1000 || value.expiresAt !== action.expiresAt ||
      value.expiresAt <= nowMs || value.operation !== action.operation) {
    return fixedJson(400, { schemaVersion: 1, error: 'runtime_action_rejected' });
  }
  let updated = null;
  if (value.command === 'begin' && exactKeys(value, [
    'actionId', 'actionKey', 'command', 'expiresAt', 'issuedAt', 'operation', 'schemaVersion',
  ]) && value.schemaVersion === 1 && action.status === 'authorization_required') {
    updated = await updateRuntimeAction(storage, environment, action.actionId, (current) => ({
      ...current, status: 'applying', stage: 'authorized', failureCode: null,
    }));
  } else if (value.command === 'progress' && exactKeys(value, [
    'actionId', 'actionKey', 'command', 'expiresAt', 'fromVersionId', 'issuedAt', 'operation',
    'schemaVersion', 'stage', 'toVersionId',
  ]) && value.schemaVersion === 1 && action.status === 'applying' &&
      RUNTIME_ACTION_STAGES.includes(value.stage) &&
      (value.fromVersionId === null || VERSION_ID.test(value.fromVersionId)) &&
      (value.toVersionId === null || VERSION_ID.test(value.toVersionId))) {
    updated = await updateRuntimeAction(storage, environment, action.actionId, (current) => ({
      ...current, stage: value.stage, fromVersionId: value.fromVersionId, toVersionId: value.toVersionId,
    }));
  } else if (value.command === 'complete' && exactKeys(value, [
    'actionId', 'actionKey', 'command', 'expiresAt', 'fromVersionId', 'issuedAt', 'operation',
    'schemaVersion', 'toVersionId',
  ]) && value.schemaVersion === 1 && action.status === 'applying' &&
      VERSION_ID.test(value.fromVersionId) && VERSION_ID.test(value.toVersionId)) {
    updated = await updateRuntimeAction(storage, environment, action.actionId, (current) => ({
      ...current, status: 'succeeded', stage: 'health_verified', failureCode: null,
      fromVersionId: value.fromVersionId, toVersionId: value.toVersionId,
    }));
  } else if (value.command === 'finalize' && exactKeys(value, [
    'actionId', 'actionKey', 'command', 'expiresAt', 'fromVersionId', 'issuedAt', 'operation', 'schemaVersion',
  ]) && value.schemaVersion === 1 && action.status === 'applying' &&
      (value.fromVersionId === null || VERSION_ID.test(value.fromVersionId)) &&
      environment.release === action.to.release && environment.releaseSha256 === action.to.artifactSha256) {
    // The gateway finished its own update: this object now runs the target
    // release, which is the proof; the new version id is not knowable here.
    updated = await updateRuntimeAction(storage, environment, action.actionId, (current) => ({
      ...current, status: 'succeeded', stage: 'health_verified', failureCode: null,
      fromVersionId: value.fromVersionId, toVersionId: null,
    }));
  } else if (value.command === 'fail' && exactKeys(value, [
    'actionId', 'actionKey', 'command', 'expiresAt', 'failureCode', 'issuedAt', 'operation',
    'recoveryRequired', 'schemaVersion',
  ]) && value.schemaVersion === 1 && action.status === 'applying' &&
      isText(value.failureCode) && /^[a-z][a-z0-9_]{0,79}$/u.test(value.failureCode) &&
      isBoolean(value.recoveryRequired)) {
    updated = await updateRuntimeAction(storage, environment, action.actionId, (current) => ({
      ...current, status: value.recoveryRequired ? 'recovery_required' : 'failed',
      failureCode: value.failureCode,
    }));
  } else if (value.command === 'probe' && exactKeys(value, [
    'actionId', 'actionKey', 'command', 'expiresAt', 'issuedAt', 'operation', 'schemaVersion',
    'targetArtifactSha256', 'targetRelease',
  ]) && value.schemaVersion === 1 && action.status === 'applying' &&
      value.targetRelease === action.to.release && value.targetArtifactSha256 === action.to.artifactSha256 &&
      request.headers.get('x-ankka-runtime-probe-version') === 'verified') {
    return new Response(null, { status: 204, headers: { ...PUBLIC_HEADERS, 'x-ankka-runtime-action': 'ready' } });
  }
  return updated ? fixedJson(200, publicRuntimeAction(updated)) :
    fixedJson(409, { schemaVersion: 1, error: 'runtime_action_conflict' });
}

function safeTeardownAction(value) {
  if (!exactKeys(value, [
    'schemaVersion', 'actionId', 'actionKeyHash', 'actorEmail', 'installationId',
    'issuedAt', 'expiresAt', 'status', 'failureCode',
    ...(Object.hasOwn(value ?? {}, 'policyMode') ? ['policyMode'] : []),
  ]) || (Object.hasOwn(value, 'policyMode') && value.policyMode !== 'receipt_owned') ||
      value.schemaVersion !== 1 || !ACTION_ID.test(value.actionId) ||
      !isText(value.actionKeyHash) || !HASH.test(value.actionKeyHash) ||
      normalizedEmail(value.actorEmail) !== value.actorEmail ||
      !INSTALLATION_ID.test(value.installationId) || !Number.isSafeInteger(value.issuedAt) ||
      !Number.isSafeInteger(value.expiresAt) || value.expiresAt <= value.issuedAt ||
      value.expiresAt - value.issuedAt > 10 * 60 * 1000 ||
      !['authorization_required', 'applying', 'gateway_removed', 'failed', 'recovery_required'].includes(value.status) ||
      (value.failureCode !== null && (!isText(value.failureCode) ||
        !/^[a-z][a-z0-9_]{0,63}$/u.test(value.failureCode)))) return null;
  return Object.freeze({ ...value });
}

function safeTeardownActions(value) {
  if (!exactKeys(value, ['schemaVersion', 'revision', 'actions']) || value.schemaVersion !== 1 ||
      !Number.isSafeInteger(value.revision) || value.revision < 1 || !Array.isArray(value.actions) ||
      value.actions.length > 8) return null;
  const actions = value.actions.map(safeTeardownAction);
  if (actions.some((action) => action === null) ||
      new Set(actions.map((action) => action.actionId)).size !== actions.length) return null;
  return Object.freeze({ schemaVersion: 1, revision: value.revision, actions: Object.freeze(actions) });
}

function publicTeardownAction(action) {
  return Object.freeze({
    schemaVersion: 1,
    actionId: action.actionId,
    status: action.status,
    expiresAt: new Date(action.expiresAt).toISOString(),
    failureCode: action.failureCode,
  });
}

async function safePersistedReadyReceipt(value, environment, installationId) {
  if (!isRecord(value) || !exactKeys(value, [
    'schemaVersion', 'manager', 'installationId', 'state', 'revision', 'release',
    'target', 'accessPolicy', 'desiredHash', 'resources', 'pending', 'checksum',
  ]) || value.schemaVersion !== 1 || value.manager !== MANAGER || value.state !== 'ready' ||
      value.installationId !== installationId || !RELEASE.test(value.release) ||
      !isText(value.desiredHash) || !HASH.test(value.desiredHash) || value.pending !== null ||
      !isText(value.checksum) || !HASH.test(value.checksum) || !isRecord(value.target) ||
      !exactKeys(value.target, ['accountId', 'zoneId', 'zoneName', 'hostname']) ||
      value.target.accountId !== environment.accountId || value.target.zoneId !== environment.zoneId ||
      value.target.zoneName !== environment.zoneName || !hostname(value.target.hostname) ||
      !isRecord(value.accessPolicy) || !exactKeys(value.accessPolicy, [
        'identityType', 'identityCount', 'identitiesHash',
      ]) || value.accessPolicy.identityType !== 'email' ||
      !Number.isSafeInteger(value.accessPolicy.identityCount) || value.accessPolicy.identityCount < 1 ||
      !isText(value.accessPolicy.identitiesHash) || !HASH.test(value.accessPolicy.identitiesHash) ||
      !Array.isArray(value.resources)) return null;
  const kinds = value.resources.map((resource) => isRecord(resource) ? resource.kind : null);
  const expectedOrder = [RESOURCE_ORDER, PORTAL_RESOURCE_ORDER].find((candidate) =>
    canonicalJson(candidate) === canonicalJson(kinds));
  if (!expectedOrder || value.revision !== expectedOrder.length + 1) return null;
  const resources = [];
  const locators = new Set();
  const accessApplicationIds = new Set();
  for (let index = 0; index < expectedOrder.length; index += 1) {
    const resource = value.resources[index];
    const kind = expectedOrder[index];
    const policy = kind === 'source_access_policy' || kind === 'portal_access_policy';
    if (!exactKeys(resource, policy
      ? ['kind', 'key', 'provider', 'desiredHash', 'marker', 'identityHash']
      : ['kind', 'key', 'provider', 'desiredHash', 'marker']) || resource.kind !== kind ||
        !RESOURCE_KEY.test(resource.key) || !isText(resource.desiredHash) ||
        !HASH.test(resource.desiredHash) || resource.marker !== marker(installationId, resource.key) ||
        (policy && resource.identityHash !== value.accessPolicy.identitiesHash)) return null;
    const provider = parseProviderLocator(resource.provider, policy);
    if (!provider) return null;
    const locatorKey = `${kind}\u0000${provider.parentId ?? ''}\u0000${provider.id}`;
    if (locators.has(locatorKey)) return null;
    locators.add(locatorKey);
    if (kind === 'source_access_application' || kind === 'portal_access_application') {
      if (accessApplicationIds.has(provider.id)) return null;
      accessApplicationIds.add(provider.id);
    }
    resources.push(Object.freeze({ ...resource, provider }));
  }
  const sourceApplication = resources.find((resource) => resource.kind === 'source_access_application');
  const sourcePolicy = resources.find((resource) => resource.kind === 'source_access_policy');
  const portalApplication = resources.find((resource) => resource.kind === 'portal_access_application');
  const portalPolicy = resources.find((resource) => resource.kind === 'portal_access_policy');
  if (!portalApplication || !portalPolicy || portalPolicy.provider.parentId !== portalApplication.provider.id ||
      (sourceApplication ? sourcePolicy?.provider.parentId !== sourceApplication.provider.id : sourcePolicy)) return null;
  const receipt = Object.freeze({ ...value, resources: Object.freeze(resources) });
  const { checksum, ...unsigned } = receipt;
  return await sha256(unsigned) === checksum ? receipt : null;
}

async function storedTeardownRoot(storage, environment, installationId) {
  const value = await storage.get(STORAGE_KEY);
  const receipt = await safePersistedReadyReceipt(value, environment, installationId);
  if (receipt) return Object.freeze({
    schemaVersion: 1, status: 'ready', installationId, receipt, teardown: null,
  });
  if (!isRecord(value) || !exactKeys(value, [
    'schemaVersion', 'status', 'installationId', 'receipt', 'teardown',
  ]) || value.schemaVersion !== 1 || !['tearing_down', 'removed'].includes(value.status) ||
      value.installationId !== installationId) return null;
  const retainedReceipt = await safePersistedReadyReceipt(value.receipt, environment, installationId);
  if (!retainedReceipt) return null;
  return Object.freeze({ ...value, receipt: retainedReceipt });
}

async function rootTeardownEvidence(storage, environment, installationId, currentStatus = false) {
  const root = await storedTeardownRoot(storage, environment, installationId);
  if (!root) return null;
  const evidence = { schemaVersion: 1, installationId, root: Object.freeze({ receipt: root.receipt }) };
  if (currentStatus) evidence.removalStarted = root.status !== 'ready';
  return Object.freeze(evidence);
}

function teardownResourceKey(resource) {
  return `${resource.kind}\u0000${resource.provider.parentId ?? ''}\u0000${resource.provider.id}`;
}

function teardownProviderLocatorKey(resource) {
  if (resource.kind === 'source_access_application' || resource.kind === 'portal_access_application') {
    return `access_application\u0000${resource.provider.id}`;
  }
  if (resource.kind === 'source_access_policy' || resource.kind === 'portal_access_policy') {
    return `access_policy\u0000${resource.provider.parentId}\u0000${resource.provider.id}`;
  }
  return `${resource.kind}\u0000${resource.provider.id}`;
}

function sameTeardownResourceAuthority(left, right) {
  return canonicalJson(left) === canonicalJson(right);
}

function teardownResources(root, sourceOwnership, currentPolicies = false) {
  if (!Array.isArray(root.receipt?.resources) || !Array.isArray(sourceOwnership)) return null;
  const receiptSources = root.receipt.resources.filter((resource) => (
    SOURCE_ACTION_RESOURCE_ORDER.includes(resource.kind)
  ));
  const extras = [];
  let receiptSourceOwner = null;
  const sourceIds = new Set();
  const orderedOwnership = [...sourceOwnership].sort((left, right) => (
    compareText(left?.sourceId ?? '', right?.sourceId ?? '')
  ));
  for (const source of orderedOwnership) {
    if (!exactKeys(source, ['sourceId', 'resources']) || !SOURCE_ID.test(source.sourceId) ||
        !Array.isArray(source.resources) || source.resources.length !== SOURCE_ACTION_RESOURCE_ORDER.length) return null;
    if (sourceIds.has(source.sourceId)) return null;
    sourceIds.add(source.sourceId);
    const resources = source.resources.map(safeSourceActionResource);
    if (resources.some((resource) => resource === null)) return null;
    if (receiptSources.length > 0 && resources.every((resource, index) => (
      sameTeardownResourceAuthority(resource, receiptSources[index])
    ))) {
      // The initially configured source is deliberately represented in both
      // the immutable root receipt and management ownership. Only an exact
      // full-resource alias is accepted; a partial or drifted locator overlap
      // is an authority conflict.
      if (receiptSourceOwner !== null) return null;
      receiptSourceOwner = source.sourceId;
      continue;
    }
    extras.push(...resources);
  }
  if ((receiptSources.length > 0) !== (receiptSourceOwner !== null)) return null;
  const seenProviderLocators = new Set();
  const ordered = [];
  // The current flow removes the Portal before its servers. Cloudflare can
  // remove server mappings when a server is deleted; removing the Portal
  // first keeps restart verification independent of that cascade.
  const removal = currentPolicies
    ? [...root.receipt.resources].filter((resource) => !SOURCE_ACTION_RESOURCE_ORDER.includes(resource.kind)).reverse()
      .concat([...extras].reverse(), [...receiptSources].reverse())
    : [...extras].reverse().concat([...root.receipt.resources].reverse());
  for (const resource of removal) {
    const locatorKey = teardownProviderLocatorKey(resource);
    if (seenProviderLocators.has(locatorKey)) return null;
    seenProviderLocators.add(locatorKey);
    ordered.push(Object.freeze(structuredClone(resource)));
  }
  return Object.freeze({
    resources: Object.freeze(ordered),
    receiptSourceOwner,
  });
}

function teardownSettings(control, source, sourceId) {
  return Object.freeze({
    schemaVersion: 1,
    connect: Object.freeze({
      name: control.portal.name,
      hostname: control.portal.hostname,
      codeMode: 'default_on',
    }),
    access: Object.freeze({ adminEmails: control.audienceEmails, memberEmails: Object.freeze([]) }),
    sources: Object.freeze(source === null ? [] : [Object.freeze({
      id: sourceId,
      label: source.label,
      url: source.url,
      authentication: Object.freeze({
        mode: source.authMode,
        onBehalfOfUser: source.onBehalfOfUser,
      }),
      enabledTools: source.enabledTools,
    })]),
  });
}

function teardownReceiptResourceMatchesDesired(actual, desired, identityHash) {
  const policy = actual.kind === 'source_access_policy' || actual.kind === 'portal_access_policy';
  return actual.kind === desired.kind && actual.key === desired.key &&
    actual.desiredHash === desired.desiredHash &&
    actual.marker === marker(desired.desired.metadata.installationId, desired.key) &&
    (!policy || actual.identityHash === identityHash) &&
    ((actual.kind !== 'mcp_server' && actual.kind !== 'portal') || actual.provider.id === desired.key);
}

async function teardownAuthorityState(root, rawControl, rawSources, environment, currentPolicies = false) {
  const control = safeManagementControl(rawControl);
  const sources = safeManagementSources(rawSources);
  if (!control || !sources || control.installationId !== root.installationId ||
      control.accountId !== environment.accountId ||
      control.zoneId !== environment.zoneId ||
      root.receipt.target.accountId !== environment.accountId ||
      root.receipt.target.zoneId !== environment.zoneId ||
      root.receipt.target.zoneName !== environment.zoneName ||
      control.portal.hostname !== root.receipt.target.hostname) return null;
  const portalReceipt = root.receipt.resources.find((resource) => resource.kind === 'portal');
  if (!portalReceipt || control.portal.id !== portalReceipt.provider.id ||
      control.portal.marker !== portalReceipt.marker) return null;
  const layout = teardownResources(root, control.sourceOwnership, currentPolicies);
  if (!layout) return null;
  const installedSources = sources.sources.filter((source) => source.status === 'installed');
  const installedIds = installedSources.map((source) => source.id).sort(compareText);
  const ownershipIds = control.sourceOwnership.map((ownership) => ownership.sourceId).sort(compareText);
  if (canonicalJson(installedIds) !== canonicalJson(ownershipIds)) return null;
  const audienceHash = await sha256({ emails: control.audienceEmails });
  if (root.receipt.accessPolicy.identityCount !== control.audienceEmails.length ||
      root.receipt.accessPolicy.identitiesHash !== audienceHash) return null;

  const receiptSource = layout.receiptSourceOwner === null
    ? null
    : installedSources.find((source) => source.id === layout.receiptSourceOwner) ?? null;
  if ((layout.receiptSourceOwner !== null) !== (receiptSource !== null)) return null;
  const rootSettings = teardownSettings(control, receiptSource, 'company-context');
  const rootDesired = await buildDesiredResources(rootSettings, root.installationId);
  if (rootDesired.length !== root.receipt.resources.length ||
      root.receipt.desiredHash !== await sha256({
        schemaVersion: 1,
        installationId: root.installationId,
        resources: rootDesired,
      })) return null;
  const entries = new Map();
  const rootState = Object.freeze({
    installationId: root.installationId,
    target: root.receipt.target,
    settings: rootSettings,
    accessPolicy: Object.freeze({ identitiesHash: audienceHash }),
    desiredResources: rootDesired,
    resources: root.receipt.resources,
  });
  for (let index = 0; index < root.receipt.resources.length; index += 1) {
    const actual = root.receipt.resources[index];
    const desired = rootDesired[index];
    if (!teardownReceiptResourceMatchesDesired(actual, desired, audienceHash)) return null;
    entries.set(teardownResourceKey(actual), Object.freeze({ desired, state: rootState }));
  }
  for (const ownership of control.sourceOwnership) {
    if (ownership.sourceId === layout.receiptSourceOwner) continue;
    const source = installedSources.find((candidate) => candidate.id === ownership.sourceId);
    if (!source) return null;
    const settings = teardownSettings(control, source, source.id);
    // Two exact receipt profiles, not mutable policy inference: historical
    // sources began with the original audience; newly installed sources begin
    // with none. Both must rederive every original resource hash exactly.
    const emptyAudienceHash = await sha256({ emails: [] });
    const sourceIdentityHash = ownership.resources[2].identityHash;
    if (sourceIdentityHash !== audienceHash && sourceIdentityHash !== emptyAudienceHash) return null;
    const desiredResources = (await buildDesiredResources(
      settings, root.installationId, sourceIdentityHash === emptyAudienceHash,
    )).slice(0, 3);
    const state = Object.freeze({
      installationId: root.installationId,
      target: root.receipt.target,
      settings,
      accessPolicy: Object.freeze({ identitiesHash: sourceIdentityHash }),
      desiredResources: Object.freeze(desiredResources),
      resources: ownership.resources,
    });
    for (let index = 0; index < ownership.resources.length; index += 1) {
      const actual = ownership.resources[index];
      const desired = desiredResources[index];
      const key = teardownResourceKey(actual);
      if (entries.has(key) || !teardownReceiptResourceMatchesDesired(actual, desired, sourceIdentityHash)) return null;
      entries.set(key, Object.freeze({ desired, state }));
    }
  }
  if (entries.size !== layout.resources.length) return null;
  const portalMappings = portalServerMappings(control, sources, Object.freeze({
    sourceId: '',
    resources: Object.freeze([]),
  }));
  if (!portalMappings) return null;
  return Object.freeze({
    control,
    sources,
    resources: layout.resources,
    entries,
    portalMappings,
  });
}

function teardownProviderPath(resource, target) {
  const account = encodeURIComponent(target.accountId);
  const zone = encodeURIComponent(target.zoneId);
  const id = encodeURIComponent(resource.provider.id);
  if (resource.kind === 'mcp_server') {
    return `/accounts/${account}/access/ai-controls/mcp/servers/${id}`;
  }
  if (resource.kind === 'portal') {
    return `/accounts/${account}/access/ai-controls/mcp/portals/${id}`;
  }
  if (resource.kind === 'source_access_application' || resource.kind === 'portal_access_application') {
    return `/zones/${zone}/access/apps/${id}`;
  }
  if (resource.kind === 'source_access_policy' || resource.kind === 'portal_access_policy') {
    return `/zones/${zone}/access/apps/${encodeURIComponent(resource.provider.parentId)}/policies/${id}`;
  }
  return `/zones/${zone}/dns_records/${id}`;
}

function teardownPolicyMatches(value, desired, settings, currentPolicies = false) {
  if (currentPolicies) {
    // Assignment changes do not transfer ownership. The immutable locator and
    // exact marked name still bind the policy to this installation. Only the
    // supported email or deny-everyone policy shapes may have changed.
    const name = `${desired.kind === 'source_access_policy'
      ? settings.sources[0]?.label : settings.connect.name} users [${marker(
      desired.desired.metadata.installationId, desired.key,
    )}]`;
    try {
      return teamPolicyMatches(value, teamPolicy(teamPolicyAudience(value), name), value?.id);
    } catch { return false; }
  }
  if (!isRecord(value) || !safeProviderId(value.id) || value.decision !== 'allow' ||
      value.name !== `${desired.kind === 'source_access_policy'
        ? settings.sources[0]?.label
        : settings.connect.name} users [${marker(
        desired.desired.metadata.installationId,
        desired.key,
      )}]` || !Array.isArray(value.include) || !Array.isArray(value.exclude) ||
      value.exclude.length !== 0 || !Array.isArray(value.require) || value.require.length !== 0) return false;
  const emails = [];
  for (const rule of value.include) {
    const email = isRecord(rule) && exactKeys(rule, ['email']) && isRecord(rule.email) &&
      exactKeys(rule.email, ['email']) ? normalizedEmail(rule.email.email) : null;
    if (!email) return false;
    emails.push(email);
  }
  return emails.length === settings.access.adminEmails.length &&
    new Set(emails).size === emails.length && canonicalJson(emails.sort(compareText)) ===
      canonicalJson([...settings.access.adminEmails].sort(compareText));
}

function teardownOwnershipMatches(resource, result, authority, currentPolicies = false) {
  if (!isRecord(result) || result.id !== resource.provider.id) return false;
  const entry = authority.entries.get(teardownResourceKey(resource));
  if (!entry) return false;
  if (resource.kind === 'mcp_server') {
    return mcpMatches(result, entry.desired);
  }
  if (resource.kind === 'portal') {
    return portalExact(result, authority.control, authority.portalMappings);
  }
  if (resource.kind === 'source_access_policy' || resource.kind === 'portal_access_policy') {
    return teardownPolicyMatches(result, entry.desired, entry.state.settings, currentPolicies);
  }
  if (resource.kind === 'dns_record') {
    return dnsMatches(result, entry.desired);
  }
  return accessApplicationIdentityMatches(result, resource.kind, entry.state);
}

async function teardownResourceRead(root, resource, authority, token, currentPolicies = false) {
  const response = await providerCall(teardownProviderPath(resource, root.receipt.target), token);
  if (response.status === 'absent' || response.status === 'auth' || response.status === 'unknown') {
    return response.status;
  }
  if (response.status !== 'ok') return 'conflict';
  return teardownOwnershipMatches(resource, response.result, authority, currentPolicies) ? 'present' : 'conflict';
}

async function teardownServersUnshared(root, authority, token) {
  const serverIds = new Set(authority.resources.filter((resource) => resource.kind === 'mcp_server')
    .map((resource) => resource.provider.id));
  if (serverIds.size === 0) return true;
  const path = `/accounts/${encodeURIComponent(root.receipt.target.accountId)}/access/ai-controls/mcp/portals`;
  const portals = await providerList(path, token);
  if (portals.status !== 'ok') return false;
  const seen = new Set();
  for (const portal of portals.result) {
    if (!safeProviderId(portal?.id) || seen.has(portal.id)) return false;
    seen.add(portal.id);
    if (portal.id === authority.control.portal.id) continue;
    const read = await providerCall(`${path}/${encodeURIComponent(portal.id)}`, token);
    if (read.status !== 'ok' || !isRecord(read.result) || read.result.id !== portal.id) return false;
    const mappings = Object.hasOwn(read.result, 'servers') ? read.result.servers : [];
    if (!Array.isArray(mappings) || mappings.some((mapping) => !isRecord(mapping) ||
      !safeProviderId(mapping.server_id ?? mapping.id) ||
      (mapping.server_id !== undefined && mapping.id !== undefined && mapping.server_id !== mapping.id) ||
      serverIds.has(mapping.server_id ?? mapping.id))) return false;
  }
  return true;
}

async function teardownApplicationChildrenMatch(root, resource, authority, token) {
  if (!['source_access_application', 'portal_access_application'].includes(resource.kind)) return true;
  const path = `${teardownProviderPath(resource, root.receipt.target)}/policies`;
  const listed = await providerList(path, token);
  if (listed.status !== 'ok') return false;
  const owned = authority.resources.filter((entry) =>
    ['source_access_policy', 'portal_access_policy'].includes(entry.kind) &&
    entry.provider.parentId === resource.provider.id);
  const seen = new Set();
  for (const policy of listed.result) {
    const receipt = owned.find((entry) => entry.provider.id === policy?.id);
    if (!receipt || seen.has(policy.id) || !teardownOwnershipMatches(receipt, policy, authority, true)) return false;
    seen.add(policy.id);
  }
  return true;
}

async function teardownResourceDelete(root, resource, token) {
  const response = await providerCall(teardownProviderPath(resource, root.receipt.target), token, { method: 'DELETE' });
  if (response.status === 'ok') return 'submitted';
  return response.status;
}

function safeRootTeardown(value, root, resources, resourcesHash) {
  if (!isRecord(value) || !exactKeys(value, [
    'schemaVersion', 'installationId', 'resourcesHash', 'status', 'removedKeys', 'pending', 'removedAt',
  ]) || value.schemaVersion !== 1 || value.installationId !== root.installationId ||
      value.resourcesHash !== resourcesHash || !['applying', 'removed'].includes(value.status) ||
      !Array.isArray(value.removedKeys) || value.removedKeys.some((key, index) =>
        !isText(key) || key !== teardownResourceKey(resources[index])) ||
      value.removedKeys.length > resources.length ||
      !(value.removedAt === null || Number.isSafeInteger(value.removedAt))) return null;
  let pending = null;
  if (value.pending !== null) {
    if (value.removedKeys.length >= resources.length ||
        !exactKeys(value.pending, ['key', 'requestId', 'phase']) ||
        value.pending.key !== teardownResourceKey(resources[value.removedKeys.length]) ||
        !REQUEST_ID.test(value.pending.requestId) ||
        !['send_armed', 'submitted', 'not_applied'].includes(value.pending.phase)) return null;
    pending = Object.freeze({ ...value.pending });
  }
  if ((value.status === 'removed') !== (value.removedKeys.length === resources.length &&
      pending === null && Number.isSafeInteger(value.removedAt))) return null;
  return Object.freeze({ ...value, removedKeys: Object.freeze([...value.removedKeys]), pending });
}

function rootRemovalCompletion(root, removedResourceCount, resumed, resourcesHash, currentPolicies) {
  const result = { schemaVersion: 1, status: 'removed', installationId: root.installationId, removedResourceCount, resumed };
  if (currentPolicies) Object.assign(result, { readyReceiptChecksum: root.receipt.checksum, dependencyResourcesHash: resourcesHash });
  return Object.freeze(result);
}

async function processRootTeardownApply(storage, environment, input, nowMs = Date.now(), currentPolicies = false) {
  if (!isRecord(input) || !exactKeys(input, [
    'schemaVersion', 'actionId', 'installationId', 'requestId', 'control', 'sources',
    'cloudflareAccessToken', 'issuedAt', 'expiresAt',
  ]) || input.schemaVersion !== 1 || !ACTION_ID.test(input.actionId) ||
      !INSTALLATION_ID.test(input.installationId) || !REQUEST_ID.test(input.requestId) ||
      !isText(input.cloudflareAccessToken) || input.cloudflareAccessToken.length < 20 ||
      input.cloudflareAccessToken.length > 16 * 1024 || hasControlCharacter(input.cloudflareAccessToken) ||
      !Number.isSafeInteger(input.issuedAt) || !Number.isSafeInteger(input.expiresAt) ||
      input.issuedAt > nowMs + MAX_CLOCK_SKEW_SECONDS * 1000 || input.expiresAt <= nowMs) return null;
  let root = await storedTeardownRoot(storage, environment, input.installationId);
  if (!root) return null;
  const authority = await teardownAuthorityState(root, input.control, input.sources, environment, currentPolicies);
  const resources = authority?.resources ?? null;
  let resourcesHash = null;
  if (authority) {
    const identity = { schemaVersion: 1, resources, control: authority.control, sources: authority.sources };
    if (currentPolicies) identity.policyMode = 'receipt_owned';
    resourcesHash = await sha256(identity);
  }
  if (!authority || !resources || !resourcesHash) return null;
  let teardown = root.teardown === undefined ? null : safeRootTeardown(
    root.teardown, root, resources, resourcesHash,
  );
  if (root.status === 'ready') {
    if (teardown !== null) return null;
    teardown = Object.freeze({
      schemaVersion: 1,
      installationId: root.installationId,
      resourcesHash,
      status: 'applying',
      removedKeys: Object.freeze([]),
      pending: null,
      removedAt: null,
    });
    root = { ...root, status: 'tearing_down', teardown };
    await storage.put(STORAGE_KEY, root);
  } else if (!teardown) return null;
  if (currentPolicies && !await teardownServersUnshared(root, authority, input.cloudflareAccessToken)) return null;
  // Prove the complete graph before the first provider mutation. A resource
  // outside the already removed prefix may be absent only at the one journaled
  // ambiguous boundary; every other live resource must still have the exact
  // receipt-owned shape. This prevents a late collision from causing a
  // partial teardown before it is discovered.
  for (let index = 0; index < resources.length; index += 1) {
    const observed = await teardownResourceRead(
      root, resources[index], authority, input.cloudflareAccessToken, currentPolicies,
    );
    if (currentPolicies && observed === 'present' && !await teardownApplicationChildrenMatch(
      root, resources[index], authority, input.cloudflareAccessToken,
    )) return null;
    if (index < teardown.removedKeys.length) {
      if (observed !== 'absent') return null;
      continue;
    }
    if (index === teardown.removedKeys.length && teardown.pending !== null) {
      if (observed !== 'absent' && observed !== 'present') return null;
      continue;
    }
    if (observed !== 'present') return null;
  }
  if (teardown.status === 'removed') return rootRemovalCompletion(root, resources.length, true, resourcesHash, currentPolicies);
  let resumed = teardown.removedKeys.length > 0 || teardown.pending !== null;
  while (teardown.removedKeys.length < resources.length) {
    const resource = resources[teardown.removedKeys.length];
    const key = teardownResourceKey(resource);
    const observed = await teardownResourceRead(root, resource, authority, input.cloudflareAccessToken, currentPolicies);
    if (observed === 'absent') {
      teardown = { ...teardown, pending: null, removedKeys: [...teardown.removedKeys, key] };
      root = { ...root, teardown };
      await storage.put(STORAGE_KEY, root);
      continue;
    }
    if (observed !== 'present') return null;
    if (currentPolicies && !await teardownApplicationChildrenMatch(
      root, resource, authority, input.cloudflareAccessToken,
    )) return null;
    if (teardown.pending && teardown.pending.requestId === input.requestId &&
        teardown.pending.phase !== 'not_applied') return null;
    if (teardown.pending) {
      teardown = { ...teardown, pending: { ...teardown.pending, phase: 'not_applied' } };
      root = { ...root, teardown };
      await storage.put(STORAGE_KEY, root);
    }
    teardown = { ...teardown, pending: { key, requestId: input.requestId, phase: 'send_armed' } };
    root = { ...root, teardown };
    await storage.put(STORAGE_KEY, root);
    if (currentPolicies && (Date.now() >= input.expiresAt ||
        (resource.kind === 'mcp_server' && !await teardownServersUnshared(
          root, authority, input.cloudflareAccessToken,
        )))) return null;
    const deleted = await teardownResourceDelete(root, resource, input.cloudflareAccessToken);
    if (deleted === 'auth' || deleted === 'blocked') {
      teardown = { ...teardown, pending: { ...teardown.pending, phase: 'not_applied' } };
      await storage.put(STORAGE_KEY, { ...root, teardown });
      return null;
    }
    if (deleted === 'unknown') return null;
    teardown = { ...teardown, pending: { ...teardown.pending, phase: 'submitted' } };
    root = { ...root, teardown };
    await storage.put(STORAGE_KEY, root);
    if (await teardownResourceRead(root, resource, authority, input.cloudflareAccessToken, currentPolicies) !== 'absent') return null;
    teardown = { ...teardown, pending: null, removedKeys: [...teardown.removedKeys, key] };
    root = { ...root, teardown };
    await storage.put(STORAGE_KEY, root);
  }
  teardown = { ...teardown, status: 'removed', pending: null, removedAt: nowMs };
  root = { ...root, status: 'removed', teardown };
  await storage.put(STORAGE_KEY, root);
  return rootRemovalCompletion(root, resources.length, resumed, resourcesHash, currentPolicies);
}

async function rootTeardownAuthority(storage, environment, installationId, env) {
  const control = safeManagementControl(await storage.get(CONTROL_KEY));
  const sources = safeManagementSources(await storage.get(SOURCES_KEY));
  if (!control || !sources || control.installationId !== installationId ||
      control.accountId !== environment.accountId || control.zoneId !== environment.zoneId) return null;
  const rootStub = adminStateStub(env, `v1:${installationId}`);
  if (!rootStub) return null;
  let rootEvidence;
  try {
    const response = await rootStub.fetch(new Request(`https://admin-state.invalid${INTERNAL_TEARDOWN_ROOT_PATH}`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: canonicalJson({ schemaVersion: 1, installationId }),
    }));
    rootEvidence = response instanceof Response && response.status === 200 ? await response.json() : null;
  } catch { rootEvidence = null; }
  if (!isRecord(rootEvidence) || rootEvidence.schemaVersion !== 1 ||
      rootEvidence.installationId !== installationId || !isRecord(rootEvidence.root) ||
      rootEvidence.root.receipt?.target?.hostname !== control.portal.hostname) return null;
  const root = Object.freeze({
    schemaVersion: 1,
    status: 'ready',
    installationId,
    receipt: rootEvidence.root.receipt,
    teardown: null,
  });
  if (!await teardownAuthorityState(root, control, sources, environment)) return null;
  return Object.freeze({
    ...rootEvidence,
    control,
    sources,
    runtime: Object.freeze({
      release: environment.release,
      artifactSha256: environment.releaseSha256,
      updateChannel: environment.updateChannel,
      updateKeyId: environment.updateKeyId,
      updatePublicKey: environment.updatePublicKey,
      controlPlaneOrigin: CONTROL_PLANE_ORIGIN,
      accountId: environment.accountId,
      zoneId: environment.zoneId,
      zoneName: environment.zoneName,
      workerName: environment.workerName,
      workersSubdomain: environment.workersSubdomain,
      managementHostname: environment.managementHostname,
    }),
  });
}

async function prepareTeardownAction(storage, environment, input, env, currentPolicies = false) {
  if (currentPolicies ? await currentTeardownBlocked(storage, env) : await teamTeardownBlocked(storage)) return null;
  if (!exactKeys(input, [
    'schemaVersion', 'actionId', 'actionKeyHash', 'actorEmail', 'installationId', 'issuedAt', 'expiresAt',
  ]) || input.schemaVersion !== 1) return null;
  const proposed = { ...input, status: 'authorization_required', failureCode: null };
  if (currentPolicies) proposed.policyMode = 'receipt_owned';
  const candidate = safeTeardownAction(proposed);
  if (!candidate || !await rootTeardownAuthority(storage, environment, candidate.installationId, env)) return null;
  const current = safeTeardownActions(await storage.get(TEARDOWNS_KEY)) ?? Object.freeze({
    schemaVersion: 1, revision: 1, actions: Object.freeze([]),
  });
  const active = current.actions.find((action) => action.expiresAt > candidate.issuedAt &&
    (action.status === 'authorization_required' || action.status === 'applying'));
  if (active) return null;
  const retained = current.actions.filter((action) => action.expiresAt > candidate.issuedAt);
  const next = safeTeardownActions({
    schemaVersion: 1,
    revision: current.revision + 1,
    actions: [...retained, candidate],
  });
  if (!next) return null;
  await storage.put(TEARDOWNS_KEY, next);
  return candidate;
}

async function processTeardownActionProof(request, env, storage, nowMs = Date.now(), currentPolicies = false) {
  if (currentPolicies ? await currentTeardownBlocked(storage, env) : await teamTeardownBlocked(storage)) return null;
  if (!(request instanceof Request) || request.method !== 'POST' || request.headers.has('authorization') ||
      request.headers.has('cookie') || request.headers.has('referer') || request.headers.has('origin') ||
      request.headers.get('content-type')?.split(';', 1)[0]?.trim().toLowerCase() !== 'application/json') return null;
  const environment = parseManagementEnvironment(env);
  const rawBody = await readBoundedText(request, REQUEST_LIMIT_BYTES);
  if (!environment || !rawBody) return null;
  let value;
  try { value = JSON.parse(rawBody); } catch { return null; }
  if (!isPlainData(value) || canonicalJson(value) !== rawBody || !exactKeys(value, [
    'schemaVersion', 'command', 'actionId', 'actionKey', 'actorEmail', 'accountId',
    'installationId', 'issuedAt', 'expiresAt',
  ]) || value.schemaVersion !== 1 || value.command !== 'prove' || !ACTION_ID.test(value.actionId) ||
      !NONCE.test(value.actionKey) || normalizedEmail(value.actorEmail) !== value.actorEmail ||
      value.accountId !== environment.accountId || !INSTALLATION_ID.test(value.installationId) ||
      !Number.isSafeInteger(value.issuedAt) || !Number.isSafeInteger(value.expiresAt) ||
      value.issuedAt > nowMs + MAX_CLOCK_SKEW_SECONDS * 1000 || value.expiresAt <= nowMs) return null;
  const actions = safeTeardownActions(await storage.get(TEARDOWNS_KEY));
  const action = actions?.actions.find((candidate) => candidate.actionId === value.actionId);
  if (!actions || !action || (action.policyMode === 'receipt_owned') !== currentPolicies ||
      !['authorization_required', 'applying', 'gateway_removed'].includes(action.status) ||
      action.actorEmail !== value.actorEmail || action.installationId !== value.installationId ||
      action.expiresAt !== value.expiresAt || value.issuedAt < action.issuedAt ||
      await sha256(value.actionKey) !== action.actionKeyHash ||
      !await verifyHmac(rawBody, value.actionKey, request.headers.get('x-ankka-teardown-action-signature'))) {
    return null;
  }
  const authority = await rootTeardownAuthority(storage, environment, action.installationId, env);
  if (!authority) return null;
  const layout = currentPolicies ? teardownResources(authority.root, authority.control.sourceOwnership, true) : null;
  if (currentPolicies && !layout) return null;
  const kinds = {
    mcp_server: 'mcp_server', portal: 'mcp_portal', dns_record: 'dns_record',
    source_access_application: 'access_application', portal_access_application: 'access_application',
    source_access_policy: 'access_policy', portal_access_policy: 'access_policy',
  };
  const receiptScopeEvidence = currentPolicies ? {
    receiptResourceKinds: [...new Set(layout.resources.map((resource) => kinds[resource.kind]))].sort(compareText),
  } : {};
  // The proof response can be lost after the action is durably authorized but
  // before the hosted session imports the receipt. Replaying the exact HMAC
  // action is read-only and returns the same authority until gateway removal
  // begins, so that narrow crash window remains recoverable.
  if (currentPolicies || action.status === 'applying' || action.status === 'gateway_removed') {
    return Object.freeze({ schemaVersion: 1, actionId: action.actionId, status: 'authorized', authority, ...receiptScopeEvidence });
  }
  const applying = safeTeardownAction({ ...action, status: 'applying', failureCode: null });
  const next = applying && safeTeardownActions({
    schemaVersion: 1,
    revision: actions.revision + 1,
    actions: actions.actions.map((candidate) => candidate.actionId === applying.actionId ? applying : candidate),
  });
  if (!applying || !next) return null;
  await storage.put(TEARDOWNS_KEY, next);
  return Object.freeze({ schemaVersion: 1, actionId: action.actionId, status: 'authorized', authority, ...receiptScopeEvidence });
}

async function processTeardownActionApply(request, env, storage, nowMs = Date.now(), currentPolicies = false) {
  if (currentPolicies ? await currentTeardownBlocked(storage, env) : await teamTeardownBlocked(storage)) return null;
  if (!(request instanceof Request) || request.method !== 'POST' || request.headers.has('authorization') ||
      request.headers.has('cookie') || request.headers.has('referer') || request.headers.has('origin') ||
      request.headers.get('content-type')?.split(';', 1)[0]?.trim().toLowerCase() !== 'application/json') return null;
  const environment = parseManagementEnvironment(env);
  const rawBody = await readBoundedText(request, REQUEST_LIMIT_BYTES);
  if (!environment || !rawBody) return null;
  let value;
  try { value = JSON.parse(rawBody); } catch { return null; }
  if (!isPlainData(value) || canonicalJson(value) !== rawBody || !exactKeys(value, [
    'schemaVersion', 'command', 'actionId', 'actionKey', 'actorEmail', 'accountId',
    'installationId', 'requestId', 'cloudflareAccessToken', 'issuedAt', 'expiresAt',
  ]) || value.schemaVersion !== 1 || value.command !== 'apply' || !ACTION_ID.test(value.actionId) ||
      !NONCE.test(value.actionKey) || normalizedEmail(value.actorEmail) !== value.actorEmail ||
      value.accountId !== environment.accountId || !INSTALLATION_ID.test(value.installationId) ||
      !REQUEST_ID.test(value.requestId) || !isText(value.cloudflareAccessToken) ||
      value.cloudflareAccessToken.length < 20 || value.cloudflareAccessToken.length > 16 * 1024 ||
      hasControlCharacter(value.cloudflareAccessToken) || !Number.isSafeInteger(value.issuedAt) ||
      !Number.isSafeInteger(value.expiresAt) || value.issuedAt > nowMs + MAX_CLOCK_SKEW_SECONDS * 1000 ||
      value.expiresAt <= nowMs) return null;
  const actions = safeTeardownActions(await storage.get(TEARDOWNS_KEY));
  const action = actions?.actions.find((candidate) => candidate.actionId === value.actionId);
  const control = safeManagementControl(await storage.get(CONTROL_KEY));
  const sources = safeManagementSources(await storage.get(SOURCES_KEY));
  if (!actions || !action || (action.policyMode === 'receipt_owned') !== currentPolicies ||
      !control || !sources || !(currentPolicies ? ['authorization_required', 'applying', 'gateway_removed'] : ['applying', 'gateway_removed']).includes(action.status) ||
      action.actorEmail !== value.actorEmail || action.installationId !== value.installationId ||
      action.expiresAt !== value.expiresAt || control.installationId !== value.installationId ||
      value.issuedAt < action.issuedAt || await sha256(value.actionKey) !== action.actionKeyHash ||
      !await verifyHmac(rawBody, value.actionKey, request.headers.get('x-ankka-teardown-action-signature'))) {
    return null;
  }
  const rootStub = adminStateStub(env, `v1:${action.installationId}`);
  if (!rootStub) return null;
  if (currentPolicies && action.status === 'authorization_required') {
    // Receipt proof and consent navigation are read-only. Arm the persistent
    // lifecycle lock only when an actual apply is about to reach the root.
    const applying = safeTeardownAction({ ...action, status: 'applying', failureCode: null });
    const armed = applying && safeTeardownActions({ ...actions, revision: actions.revision + 1,
      actions: actions.actions.map((candidate) => candidate.actionId === action.actionId ? applying : candidate) });
    if (!armed) return null;
    await storage.put(TEARDOWNS_KEY, armed);
  }
  let removed;
  try {
    const response = await rootStub.fetch(new Request(`https://admin-state.invalid${INTERNAL_TEARDOWN_ROOT_PATH}/${currentPolicies ? 'apply-current' : 'apply'}`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: canonicalJson({
        schemaVersion: 1,
        actionId: action.actionId,
        installationId: action.installationId,
        requestId: value.requestId,
        control,
        sources,
        cloudflareAccessToken: value.cloudflareAccessToken,
        issuedAt: value.issuedAt,
        expiresAt: value.expiresAt,
      }),
    }));
    removed = response instanceof Response && response.status === 200 ? await response.json() : null;
  } catch { removed = null; }
  if (!isRecord(removed) || removed.schemaVersion !== 1 || removed.status !== 'removed' ||
      removed.installationId !== action.installationId || !Number.isSafeInteger(removed.removedResourceCount) ||
      (currentPolicies && (!HASH.test(removed.readyReceiptChecksum) || !HASH.test(removed.dependencyResourcesHash)))) {
    return null;
  }
  if (action.status !== 'gateway_removed') {
    const latest = safeTeardownActions(await storage.get(TEARDOWNS_KEY));
    if (!latest) return null;
    const updated = safeTeardownAction({ ...action, status: 'gateway_removed', failureCode: null });
    const next = updated && safeTeardownActions({
      schemaVersion: 1,
      revision: latest.revision + 1,
      actions: latest.actions.map((candidate) => candidate.actionId === action.actionId ? updated : candidate),
    });
    if (!updated || !next) return null;
    await storage.put(TEARDOWNS_KEY, next);
  }
  const result = {
    schemaVersion: 1, actionId: action.actionId, status: 'gateway_removed', installationId: action.installationId,
    removedResourceCount: removed.removedResourceCount,
  };
  if (currentPolicies) Object.assign(result, { readyReceiptChecksum: removed.readyReceiptChecksum, dependencyResourcesHash: removed.dependencyResourcesHash });
  return Object.freeze(result);
}

/** End a current consent attempt without erasing its receipt or deletion boundary. */
async function settleCurrentTeardownAction(request, env, storage, nowMs = Date.now()) {
  if (request.method !== 'POST' || ['authorization', 'cookie', 'referer', 'origin'].some((name) => request.headers.has(name)) ||
      request.headers.get('content-type')?.split(';', 1)[0]?.trim().toLowerCase() !== 'application/json') return null;
  const raw = await readBoundedText(request, REQUEST_LIMIT_BYTES);
  let value;
  try { value = raw === null ? null : JSON.parse(raw); } catch { return null; }
  if (!isPlainData(value) || canonicalJson(value) !== raw || !exactKeys(value, [
    'schemaVersion', 'command', 'actionId', 'actionKey', 'actorEmail', 'accountId',
    'installationId', 'issuedAt', 'expiresAt',
  ]) || value.schemaVersion !== 1 || value.command !== 'settle' || !ACTION_ID.test(value.actionId) ||
      !NONCE.test(value.actionKey) || !Number.isSafeInteger(value.issuedAt) || value.issuedAt > nowMs + 30_000) return null;
  const actions = safeTeardownActions(await storage.get(TEARDOWNS_KEY));
  const action = actions?.actions.find((candidate) => candidate.actionId === value.actionId);
  if (!actions || !action || action.policyMode !== 'receipt_owned' ||
      action.actorEmail !== value.actorEmail || action.installationId !== value.installationId ||
      action.expiresAt !== value.expiresAt || value.issuedAt < action.issuedAt ||
      await sha256(value.actionKey) !== action.actionKeyHash ||
      !await verifyHmac(raw, value.actionKey, request.headers.get('x-ankka-teardown-action-signature'))) return null;
  const environment = parseManagementEnvironment(env);
  if (!environment || value.accountId !== environment.accountId) return null;
  let untouched = false;
  try {
    const stub = adminStateStub(env, `v1:${action.installationId}`);
    const response = await stub?.fetch(new Request(`https://admin-state.invalid${INTERNAL_TEARDOWN_ROOT_PATH}/status-current`, {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: canonicalJson({ schemaVersion: 1, installationId: action.installationId }),
    }));
    const evidence = response?.status === 200 ? await response.json() : null;
    untouched = evidence?.schemaVersion === 1 && evidence.installationId === action.installationId && evidence.removalStarted === false;
  } catch { /* Unknown state keeps the recovery lock. */ }
  const updated = safeTeardownAction({ ...action, status: untouched ? 'failed' : 'recovery_required',
    failureCode: 'fresh_authorization_required' });
  const next = updated && safeTeardownActions({ ...actions, revision: actions.revision + 1,
    actions: actions.actions.map((candidate) => candidate.actionId === action.actionId ? updated : candidate) });
  if (!next) return null;
  await storage.put(TEARDOWNS_KEY, next);
  return publicTeardownAction(updated);
}

export class AdminState {
  constructor(state, env) {
    this.state = state;
    this.env = env;
    this.queue = Promise.resolve();
  }

  fetch(request) {
    const requestUrl = new URL(request.url);
    // Status must remain available while a serialized mutation awaits the
    // provider. These reads neither authorize work nor change the journal.
    if (request.method === 'GET' && ([INTERNAL_ACTIONS_PATH, INTERNAL_SOURCES_PATH, INTERNAL_STATUS_PATH].includes(requestUrl.pathname) ||
        requestUrl.pathname.startsWith(`${INTERNAL_ACTIONS_PATH}/`))) {
      return this.readSourceManagementState(request, requestUrl);
    }
    const operation = async () => {
      const url = new URL(request.url);
      if (url.pathname === INTERNAL_BOOTSTRAP_PATH) {
        return processBootstrap(
          request,
          this.env,
          this.state.storage,
        );
      }
      if (url.pathname === INTERNAL_PUBLISH_PATH && request.method === 'PUT') {
        const input = await request.json().catch(() => null);
        const status = safePublicStatus(input);
        if (!status) return fixedJson(400, { schemaVersion: 1, error: 'invalid_status' });
        await this.state.storage.put(STATUS_KEY, status);
        const retained = safeManagementSources(await this.state.storage.get(SOURCES_KEY));
        if (!retained) {
          const initial = await initialManagementSources(status);
          if (!initial) return fixedJson(400, { schemaVersion: 1, error: 'invalid_status' });
          await this.state.storage.put(SOURCES_KEY, initial);
        }
        return fixedJson(200, { schemaVersion: 1, accepted: true });
      }
      if (url.pathname === INTERNAL_CONTROL_PATH && request.method === 'PUT') {
        const input = await request.json().catch(() => null);
        const control = safeManagementControl(input);
        if (!control) return fixedJson(400, { schemaVersion: 1, error: 'invalid_control' });
        const retained = safeManagementControl(await this.state.storage.get(CONTROL_KEY));
        if (retained && canonicalJson(retained) !== canonicalJson(control)) {
          return fixedJson(409, { schemaVersion: 1, error: 'control_conflict' });
        }
        await this.state.storage.put(CONTROL_KEY, control);
        return fixedJson(200, { schemaVersion: 1, accepted: true });
      }
      if (url.pathname === INTERNAL_CONTROL_PATH && request.method === 'GET') {
        const control = safeManagementControl(await this.state.storage.get(CONTROL_KEY));
        return control ? fixedJson(200, control) :
          fixedJson(503, { schemaVersion: 1, error: 'control_unavailable' });
      }
      if ([INTERNAL_TEARDOWN_ROOT_PATH, `${INTERNAL_TEARDOWN_ROOT_PATH}/status-current`].includes(url.pathname) && request.method === 'POST') {
        const environment = parseManagementEnvironment(this.env);
        const input = await request.json().catch(() => null);
        const evidence = environment && exactKeys(input, ['schemaVersion', 'installationId']) &&
          input.schemaVersion === 1 && INSTALLATION_ID.test(input.installationId)
          ? await rootTeardownEvidence(this.state.storage, environment, input.installationId, url.pathname.endsWith('/status-current'))
          : null;
        return evidence ? fixedJson(200, evidence) :
          fixedJson(409, { schemaVersion: 1, error: 'teardown_root_unavailable' });
      }
      if ([`${INTERNAL_TEARDOWN_ROOT_PATH}/apply`, `${INTERNAL_TEARDOWN_ROOT_PATH}/apply-current`].includes(url.pathname) && request.method === 'POST') {
        const environment = parseManagementEnvironment(this.env);
        const input = await request.json().catch(() => null);
        const removed = environment ? await processRootTeardownApply(
          this.state.storage, environment, input, Date.now(), url.pathname.endsWith('/apply-current'),
        ) : null;
        return removed ? fixedJson(200, removed) :
          fixedJson(409, { schemaVersion: 1, error: 'teardown_root_recovery_required' });
      }
      if (url.pathname === INTERNAL_ACTIONS_PATH && request.method === 'POST') {
        if (SOURCE_ADDITION_PAUSED) return sourceAdditionPaused();
        const input = await request.json().catch(() => null);
        const action = await prepareSourceAction(this.state.storage, input);
        return action instanceof Response ? action : fixedJson(200, publicSourceAction(action));
      }
      if (url.pathname.startsWith(`${INTERNAL_ACTIONS_PATH}/`) && url.pathname.endsWith('/renew') &&
          request.method === 'POST') {
        const actionId = url.pathname.slice(INTERNAL_ACTIONS_PATH.length + 1, -'/renew'.length);
        const input = await request.json().catch(() => null);
        if (!ACTION_ID.test(actionId) || input?.actionId !== actionId) return sourceActionConflict();
        const action = await renewSourceAction(this.state.storage, input, this.env);
        return action instanceof Response ? action : fixedJson(200, publicSourceAction(action));
      }
      if (url.pathname === `${INTERNAL_ACTIONS_PATH}/bigquery` && request.method === 'POST') {
        const parsed = await parseSourceActionRequest(request, this.env, this.state.storage, Date.now());
        if (!parsed || !['start', 'failed'].includes(parsed.claim.bigqueryPhase)) return actionRecovery('source_action_rejected');
        if (await otherLifecycleBlocksSource(this.state.storage, Date.now(), parsed.action.actionId)) return sourceActionConflict();
        if (parsed.claim.bigqueryPhase === 'start' && !await armSourceCompatibility(this.state.storage, this.env)) {
          return actionRecovery('source_action_state_unavailable');
        }
        const action = await persistSourceAction(this.state.storage, {
          ...parsed.action, bigquerySetupStarted: true,
          status: parsed.claim.bigqueryPhase === 'start' ? 'applying' : 'recovery_required',
          failureCode: parsed.claim.bigqueryPhase === 'start' ? null : 'bigquery_setup_required',
        });
        return action ? fixedJson(200, publicSourceAction(action)) : actionRecovery('source_action_state_unavailable');
      }
      if (url.pathname === `${INTERNAL_ACTIONS_PATH}/apply` && request.method === 'POST') {
        const raw = await readBoundedText(request.clone(), REQUEST_LIMIT_BYTES);
        let value;
        try { value = raw === null ? null : JSON.parse(raw); } catch { value = null; }
        if (value?.action === 'access') {
          // Retire every old signed Team handoff, including an unspent one.
          // The retained proposal can only resume through the administrator API.
          return fixedJson(410, { schemaVersion: 1, error: 'team_oauth_retired' });
        }
        return processSourceAction(request, this.env, this.state.storage);
      }
      if (url.pathname.startsWith(`${INTERNAL_ACTIONS_PATH}/`) && request.method === 'DELETE') {
        const actionId = url.pathname.slice(`${INTERNAL_ACTIONS_PATH}/`.length);
        const input = await request.json().catch(() => null);
        const action = ACTION_ID.test(actionId) && exactKeys(input, ['actorEmail', 'now'])
          ? await cancelSourceAction(this.state.storage, actionId, input.actorEmail, input.now)
          : null;
        return action
          ? fixedJson(200, publicSourceAction(action))
          : sourceSnapshotConflict(await sourceActionSnapshot(this.state.storage, input?.actorEmail, Date.now())) ??
            sourceActionConflict();
      }
      // The current gateway coordinator uses these internal-only routes. Old
      // hosted handoffs cannot opt into the new receipt-owned policy matcher.
      if (url.pathname === `${INTERNAL_TEARDOWNS_PATH}/prepare-current` && request.method === 'POST') {
        const environment = parseManagementEnvironment(this.env);
        const input = await request.json().catch(() => null);
        const action = environment ? await prepareTeardownAction(
          this.state.storage, environment, input, this.env, true,
        ) : null;
        return action ? fixedJson(200, publicTeardownAction(action)) :
          fixedJson(409, { schemaVersion: 1, error: 'teardown_action_conflict' });
      }
      if (url.pathname === `${INTERNAL_TEARDOWNS_PATH}/prove-current` && request.method === 'POST') {
        const proof = await processTeardownActionProof(request, this.env, this.state.storage, Date.now(), true);
        return proof ? fixedJson(200, proof) :
          fixedJson(409, { schemaVersion: 1, error: 'teardown_action_rejected' });
      }
      if (url.pathname === `${INTERNAL_TEARDOWNS_PATH}/settle-current` && request.method === 'POST') {
        const settled = await settleCurrentTeardownAction(request, this.env, this.state.storage);
        return settled ? fixedJson(200, settled) : fixedJson(409, { schemaVersion: 1, error: 'teardown_action_rejected' });
      }
      if (url.pathname === `${INTERNAL_TEARDOWNS_PATH}/apply-current` && request.method === 'POST') {
        const applied = await processTeardownActionApply(request, this.env, this.state.storage, Date.now(), true);
        return applied ? fixedJson(200, applied) :
          fixedJson(409, { schemaVersion: 1, error: 'teardown_action_recovery_required' });
      }
      if (url.pathname === INTERNAL_TEARDOWNS_PATH && request.method === 'POST') {
        if (await teamTeardownBlocked(this.state.storage)) return fixedJson(409, {
          schemaVersion: 1, error: 'team_teardown_requires_compatible_release',
        });
        const environment = parseManagementEnvironment(this.env);
        const input = await request.json().catch(() => null);
        const action = environment
          ? await prepareTeardownAction(this.state.storage, environment, input, this.env)
          : null;
        return action ? fixedJson(200, publicTeardownAction(action)) :
          fixedJson(409, { schemaVersion: 1, error: 'teardown_action_conflict' });
      }
      if (url.pathname === `${INTERNAL_TEARDOWNS_PATH}/prove` && request.method === 'POST') {
        const proof = await processTeardownActionProof(request, this.env, this.state.storage);
        return proof ? fixedJson(200, proof) :
          fixedJson(409, { schemaVersion: 1, error: 'teardown_action_rejected' });
      }
      if (url.pathname === `${INTERNAL_TEARDOWNS_PATH}/apply` && request.method === 'POST') {
        const applied = await processTeardownActionApply(request, this.env, this.state.storage);
        return applied ? fixedJson(200, applied) :
          fixedJson(409, { schemaVersion: 1, error: 'teardown_action_recovery_required' });
      }
      if (url.pathname.startsWith(`${INTERNAL_TEARDOWNS_PATH}/`) && request.method === 'GET') {
        const actionId = url.pathname.slice(`${INTERNAL_TEARDOWNS_PATH}/`.length);
        const actions = safeTeardownActions(await this.state.storage.get(TEARDOWNS_KEY));
        const action = ACTION_ID.test(actionId)
          ? actions?.actions.find((candidate) => candidate.actionId === actionId)
          : null;
        return action ? fixedJson(200, publicTeardownAction(action)) :
          fixedJson(404, { schemaVersion: 1, error: 'teardown_action_not_found' });
      }
      if (url.pathname === INTERNAL_UPDATES_PATH && request.method === 'GET') {
        const environment = parseManagementEnvironment(this.env);
        const updates = environment ? await runtimeUpdates(this.state.storage, environment) : null;
        return updates ? fixedJson(200, {
          schemaVersion: 1,
          revision: updates.revision,
          current: updates.current,
          previous: updates.previous,
        }) : fixedJson(503, { schemaVersion: 1, error: 'runtime_updates_unavailable' });
      }
      if (url.pathname === INTERNAL_UPDATES_PATH && request.method === 'POST') {
        const environment = parseManagementEnvironment(this.env);
        const input = await request.json().catch(() => null);
        const action = environment ? await prepareRuntimeAction(this.state.storage, environment, input) : null;
        return action ? fixedJson(200, publicRuntimeAction(action)) :
          fixedJson(409, { schemaVersion: 1, error: 'runtime_action_conflict' });
      }
      if (url.pathname === `${INTERNAL_UPDATES_PATH}/control` && request.method === 'POST') {
        return processRuntimeActionControl(request, this.env, this.state.storage);
      }
      if (url.pathname.startsWith(`${INTERNAL_UPDATES_PATH}/`) && request.method === 'GET') {
        const environment = parseManagementEnvironment(this.env);
        const actionId = url.pathname.slice(`${INTERNAL_UPDATES_PATH}/`.length);
        const updates = environment ? await runtimeUpdates(this.state.storage, environment) : null;
        const action = ACTION_ID.test(actionId)
          ? updates?.actions.find((candidate) => candidate.actionId === actionId)
          : null;
        return action ? fixedJson(200, publicRuntimeAction(action)) :
          fixedJson(404, { schemaVersion: 1, error: 'runtime_action_not_found' });
      }
      if (url.pathname === INTERNAL_TEAM_PATH && request.method === 'GET') {
        const snapshot = await teamSnapshot(this.state.storage, this.env);
        return snapshot ? fixedJson(200, snapshot) : fixedJson(503, { schemaVersion: 1, error: 'team_unavailable' });
      }
      if (url.pathname === INTERNAL_TEAM_ACTIONS_PATH && request.method === 'POST') {
        return fixedJson(409, { schemaVersion: 1, error: 'team_editing_managed_in_cloudflare' });
      }
      if (url.pathname.startsWith(`${INTERNAL_TEAM_ACTIONS_PATH}/`) && ['GET', 'DELETE'].includes(request.method)) {
        const state = await readTeamState(this.state.storage, this.env);
        const actionId = url.pathname.slice(`${INTERNAL_TEAM_ACTIONS_PATH}/`.length);
        const action = ACTION_ID.test(actionId) && state?.pendingAction?.actionId === actionId ? state.pendingAction : null;
        if (!action) return fixedJson(404, { schemaVersion: 1, error: 'team_action_not_found' });
        if (request.method === 'GET') return fixedJson(200, publicTeamAction(action));
        const input = await request.json().catch(() => null);
        if (!exactKeys(input, ['actorEmail']) || input.actorEmail !== action.actorEmail || !publicTeamAction(action).canCancel) {
          return fixedJson(409, { schemaVersion: 1, error: 'team_action_conflict' });
        }
        const cancelled = { ...action, status: 'failed', failureCode: 'team_action_cancelled' };
        await this.state.storage.put(TEAM_KEY, { ...state, pendingAction: cancelled });
        return fixedJson(200, publicTeamAction(cancelled));
      }
      if (url.pathname === INTERNAL_SOURCES_PATH && request.method === 'PUT') {
        if (SOURCE_ADDITION_PAUSED) return sourceAdditionPaused();
        if (await teamActionBlocksLifecycle(this.state.storage)) return fixedJson(409, {
          schemaVersion: 1, error: 'team_action_conflict',
        });
        const raw = await readBoundedText(request, SOURCE_SAVE_REQUEST_LIMIT_BYTES);
        let parsed;
        try { parsed = raw === null ? null : JSON.parse(raw); } catch { parsed = null; }
        const input = parseSourceSave(parsed);
        const current = safeManagementSources(await this.state.storage.get(SOURCES_KEY));
        if (!input || !current) return fixedJson(400, { schemaVersion: 1, error: 'source_invalid' });
        const currentSource = current.sources.find((source) => source.url === input.source.url);
        const rawActions = await this.state.storage.get(ACTIONS_KEY);
        const actions = rawActions === undefined ? null : safeSourceActions(rawActions);
        if (rawActions !== undefined && actions === null) return sourceActionConflict();
        const pendingSource = currentSource && actions?.actions.find((action) =>
          action.sourceId === currentSource.id && sourceActionBlocks(action));
        if (pendingSource) {
          return sourceActionConflict(sourceActionState(pendingSource, Date.now()) === 'recovery_required'
            ? 'recovery_required' : 'source_pending', sourceActionPointer(pendingSource));
        }
        const installedConflict = current.sources.some((source) => (
          source.url === input.source.url && source.status === 'installed'
        ));
        if (input.revision !== current.revision || installedConflict) return fixedJson(409, {
          schemaVersion: 1,
          error: 'source_conflict',
          revision: current.revision,
        });
        const updated = await saveDraftSource(current, input);
        if (!updated) return fixedJson(413, {
          schemaVersion: 1,
          error: 'source_capacity_exceeded',
          revision: current.revision,
        });
        await this.state.storage.put(SOURCES_KEY, updated);
        return fixedJson(200, updated);
      }
      return fixedJson(404, { schemaVersion: 1, error: 'not_found' });
    };
    const result = this.queue.then(operation, operation);
    this.queue = result.then(() => undefined, () => undefined);
    return result;
  }

  async readSourceManagementState(request, url) {
    if (url.pathname === INTERNAL_STATUS_PATH) {
      const status = safePublicStatus(await this.state.storage.get(STATUS_KEY));
      return status ? fixedJson(200, status) : fixedJson(503, { schemaVersion: 1, status: 'unavailable' });
    }
    if (url.pathname === INTERNAL_SOURCES_PATH) {
      const sources = safeManagementSources(await this.state.storage.get(SOURCES_KEY));
      return sources ? fixedJson(200, sources) : fixedJson(503, { schemaVersion: 1, error: 'sources_unavailable' });
    }
    if (url.pathname === INTERNAL_ACTIONS_PATH) {
      const snapshot = await sourceActionSnapshot(this.state.storage,
        request.headers.get('x-ankka-actor-email'), Date.now());
      return snapshot ? fixedJson(200, snapshot) :
        fixedJson(503, { schemaVersion: 1, error: 'source_actions_unavailable' });
    }
    const actionId = url.pathname.slice(`${INTERNAL_ACTIONS_PATH}/`.length);
    const actions = safeSourceActions(await this.state.storage.get(ACTIONS_KEY));
    const action = ACTION_ID.test(actionId)
      ? actions?.actions.find((candidate) => candidate.actionId === actionId) : null;
    return action ? fixedJson(200, publicSourceAction(action)) :
      fixedJson(404, { schemaVersion: 1, error: 'source_action_not_found' });
  }
}

function decodeBase64Url(value) {
  if (!isText(value) || !/^[A-Za-z0-9_-]+$/u.test(value)) return null;
  try {
    const padding = '='.repeat((4 - value.length % 4) % 4);
    const raw = atob(`${value.replaceAll('-', '+').replaceAll('_', '/')}${padding}`);
    return Uint8Array.from(raw, (character) => character.charCodeAt(0));
  } catch {
    return null;
  }
}

function accessConfiguration(env) {
  if (!env || !isObjectReference(env) || !isText(env.CF_ACCESS_AUD) ||
      !/^[A-Za-z0-9_-]{8,256}$/u.test(env.CF_ACCESS_AUD) ||
      !isText(env.CF_ACCESS_ISSUER)) return null;
  let issuer;
  try { issuer = new URL(env.CF_ACCESS_ISSUER); } catch { return null; }
  if (issuer.protocol !== 'https:' || issuer.username || issuer.password || issuer.search || issuer.hash ||
      issuer.pathname !== '/' || !issuer.hostname.endsWith('.cloudflareaccess.com')) return null;
  const emails = isText(env.ADMIN_EMAILS)
    ? [...new Set(env.ADMIN_EMAILS.split(',').map(normalizedEmail).filter(Boolean))].sort(compareText)
    : [];
  if (emails.length < 1) return null;
  return Object.freeze({ aud: env.CF_ACCESS_AUD, issuer: issuer.origin, emails: Object.freeze(emails) });
}

export async function verifyAccess(request, env, nowMs = Date.now()) {
  const configuration = accessConfiguration(env);
  const assertion = request.headers.get('cf-access-jwt-assertion');
  const claimedEmail = normalizedEmail(request.headers.get('cf-access-authenticated-user-email'));
  if (!configuration || !assertion || !claimedEmail || !configuration.emails.includes(claimedEmail)) return false;
  const segments = assertion.split('.');
  if (segments.length !== 3) return false;
  const headerBytes = decodeBase64Url(segments[0]);
  const payloadBytes = decodeBase64Url(segments[1]);
  const signature = decodeBase64Url(segments[2]);
  if (!headerBytes || !payloadBytes || !signature || headerBytes.byteLength > 4096 ||
      payloadBytes.byteLength > 16 * 1024 || signature.byteLength > 1024) return false;
  let header;
  let payload;
  try {
    header = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(headerBytes));
    payload = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(payloadBytes));
  } catch {
    return false;
  } finally {
    headerBytes.fill(0);
    payloadBytes.fill(0);
  }
  const now = Math.floor(nowMs / 1000);
  const audiences = isText(payload.aud) ? [payload.aud] : payload.aud;
  const email = normalizedEmail(payload.email);
  if (!isRecord(header) || header.alg !== 'RS256' || !isText(header.kid) ||
      !/^[A-Za-z0-9_.:-]{1,256}$/u.test(header.kid) || !isRecord(payload) ||
      payload.iss !== configuration.issuer || !Array.isArray(audiences) ||
      !audiences.includes(configuration.aud) || email !== claimedEmail ||
      !Number.isSafeInteger(payload.exp) || payload.exp <= now ||
      (Object.hasOwn(payload, 'nbf') && (!Number.isSafeInteger(payload.nbf) || payload.nbf > now + 30))) return false;
  let response;
  try {
    response = await fetch(new Request(`${configuration.issuer}/cdn-cgi/access/certs`, {
      method: 'GET', headers: { accept: 'application/json' }, redirect: 'manual',
    }));
  } catch { return false; }
  if (!(response instanceof Response) || response.status !== 200 || response.redirected) {
    if (response instanceof Response) await discardBody(response);
    return false;
  }
  let jwks;
  try { jwks = await readBoundedProviderJson(response); } catch { return false; }
  if (!isRecord(jwks) || !Array.isArray(jwks.keys)) return false;
  const keys = jwks.keys.filter((key) => isRecord(key) && key.kid === header.kid &&
    key.kty === 'RSA' && key.alg === 'RS256' && key.use === 'sig');
  if (keys.length !== 1) return false;
  try {
    const key = await crypto.subtle.importKey(
      'jwk', keys[0], { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['verify'],
    );
    const verified = await crypto.subtle.verify(
      'RSASSA-PKCS1-v1_5', key, signature,
      new TextEncoder().encode(`${segments[0]}.${segments[1]}`),
    );
    return verified ? email : false;
  } catch {
    return false;
  } finally {
    signature.fill(0);
  }
}

function adminStateStub(env, name) {
  if (!env.ADMIN_STATE || !isCallable(env.ADMIN_STATE.idFromName) ||
      !isCallable(env.ADMIN_STATE.get)) return null;
  try {
    const stub = env.ADMIN_STATE.get(env.ADMIN_STATE.idFromName(name));
    return stub && isCallable(stub.fetch) ? stub : null;
  } catch {
    return null;
  }
}

/**
 * What this route publishes into the management object after a ready
 * bootstrap, for a host that runs the bootstrap in an object of its own: the
 * public status and the management control, written through `adminState`
 * exactly as the route writes them. Resolves false when the claim, the
 * environment, the ready body or either write is not what this payload
 * accepts; nothing is logged and nothing else is written.
 */
export async function publishBootstrapCompletion(claimValue, ready, env, nowMs, adminState) {
  const environment = parseEnvironment(env, true);
  if (!environment || !isCallable(adminState)) return false;
  const claim = await parseClaim(claimValue, environment, nowMs);
  if (!claim || !isRecord(ready) || ready.status !== 'ready') return false;
  const control = await managementControlFromReadyResponse(claim, ready, env);
  if (!control) return false;
  const publish = async (path, body) => {
    let response;
    try {
      response = await adminState(new Request(`https://admin-state.invalid${path}`, {
        method: 'PUT',
        headers: { 'content-type': 'application/json' },
        body: canonicalJson(body),
      }));
    } catch {
      return false;
    }
    return response instanceof Response && response.status === 200;
  };
  if (!await publish(INTERNAL_PUBLISH_PATH, publicStatusFromReadyResponse(claim))) return false;
  return publish(INTERNAL_CONTROL_PATH, control);
}

async function handleBootstrap(request, env, nowMs = Date.now()) {
  if (request.method !== 'POST') {
    return fixedJson(405, { schemaVersion: 1, error: 'method_not_allowed' }, { allow: 'POST' });
  }
  const verified = await verifyBootstrapRequest(request, env, nowMs);
  if (!verified) return rejected();
  const stub = adminStateStub(env, `v1:${verified.claim.expected.installationId}`);
  if (!stub) return recovery('bootstrap_recovery_required');
  let response;
  try {
    response = await stub.fetch(new Request(`https://admin-state.invalid${INTERNAL_BOOTSTRAP_PATH}`, {
      method: 'POST',
      headers: {
        accept: 'application/json',
        'content-type': 'application/json',
        'x-ankka-bootstrap-signature': verified.signature,
      },
      body: verified.rawBody,
      redirect: 'manual',
    }));
  } catch {
    return recovery('bootstrap_recovery_required');
  }
  if (!(response instanceof Response) || response.status !== 200) return response instanceof Response
    ? response
    : recovery('bootstrap_recovery_required');
  let ready;
  try { ready = await response.clone().json(); } catch { return recovery('bootstrap_recovery_required'); }
  if (!isRecord(ready) || ready.status !== 'ready') return recovery('bootstrap_recovery_required');
  const index = adminStateStub(env, 'v1:management');
  if (!index) return recovery('bootstrap_recovery_required');
  const published = await index.fetch(new Request(`https://admin-state.invalid${INTERNAL_PUBLISH_PATH}`, {
    method: 'PUT',
    headers: { 'content-type': 'application/json' },
    body: canonicalJson(publicStatusFromReadyResponse(verified.claim)),
  })).catch(() => null);
  if (!(published instanceof Response) || published.status !== 200) {
    return recovery('bootstrap_recovery_required');
  }
  const control = await managementControlFromReadyResponse(verified.claim, ready, env);
  if (!control) return recovery('bootstrap_recovery_required');
  const controlled = await index.fetch(new Request(`https://admin-state.invalid${INTERNAL_CONTROL_PATH}`, {
    method: 'PUT',
    headers: { 'content-type': 'application/json' },
    body: canonicalJson(control),
  })).catch(() => null);
  if (!(controlled instanceof Response) || controlled.status !== 200) {
    return recovery('bootstrap_recovery_required');
  }
  return response;
}

async function handleStatus(request, env) {
  if (request.method !== 'GET') {
    return fixedJson(405, { schemaVersion: 1, error: 'method_not_allowed' }, { allow: 'GET' });
  }
  if (!await verifyAccess(request, env)) {
    return fixedJson(401, { schemaVersion: 1, error: 'access_required' });
  }
  const environment = parseManagementEnvironment(env);
  if (!environment) return fixedJson(503, { schemaVersion: 1, status: 'unavailable' });
  const stub = adminStateStub(env, 'v1:management');
  if (!stub) return fixedJson(503, { schemaVersion: 1, status: 'unavailable' });
  try {
    const response = await stub.fetch(new Request(`https://admin-state.invalid${INTERNAL_STATUS_PATH}`));
    if (!(response instanceof Response)) {
      return fixedJson(503, { schemaVersion: 1, status: 'unavailable' });
    }
    if (response.status !== 200) return response;
    let status;
    try { status = await response.json(); } catch { status = null; }
    return isRecord(status)
      ? fixedJson(200, { ...status, controlPlaneOrigin: CONTROL_PLANE_ORIGIN })
      : fixedJson(503, { schemaVersion: 1, status: 'unavailable' });
  } catch {
    return fixedJson(503, { schemaVersion: 1, status: 'unavailable' });
  }
}

async function handleRuntimeUpdate(request, env) {
  if (request.method !== 'GET') {
    return fixedJson(405, { schemaVersion: 1, error: 'method_not_allowed' }, { allow: 'GET' });
  }
  if (!await verifyAccess(request, env)) {
    return fixedJson(401, { schemaVersion: 1, error: 'access_required' });
  }
  const environment = parseManagementEnvironment(env);
  const stub = adminStateStub(env, 'v1:management');
  let updateState = null;
  try {
    const response = stub ? await stub.fetch(new Request(`https://admin-state.invalid${INTERNAL_UPDATES_PATH}`)) : null;
    updateState = response instanceof Response && response.status === 200 ? await response.json() : null;
  } catch { updateState = null; }
  const previous = runtimeVersion(updateState?.previous);
  const current = runtimeVersion(updateState?.current);
  const discovered = await discoverRuntimeUpdate(env);
  if (!discovered) {
    return fixedJson(200, {
      schemaVersion: 1,
      channel: environment?.updateChannel ?? 'stable',
      status: 'unavailable',
      current: current ? { release: current.release, artifactSha256: current.artifactSha256 } : null,
      available: null,
      rollback: previous ? {
        available: true,
        release: previous.release,
        artifactSha256: previous.artifactSha256,
        dataRollback: false,
      } : { available: false },
    });
  }
  const available = discovered.comparison < 0;
  return fixedJson(200, {
    schemaVersion: 1,
    channel: discovered.channel.channel,
    status: available ? 'available' : discovered.comparison === 0 ? 'up_to_date' : 'newer_than_channel',
    current: {
      release: discovered.environment.release,
      artifactSha256: discovered.environment.releaseSha256,
    },
    available: available ? {
      release: discovered.channel.release.id,
      artifactSha256: discovered.channel.release.artifactSha256,
      sourceCommit: discovered.channel.release.sourceCommit,
      classification: discovered.channel.classification,
      notes: discovered.channel.notes,
    } : null,
    rollback: previous ? {
      available: true,
      release: previous.release,
      artifactSha256: previous.artifactSha256,
      dataRollback: false,
    } : { available: false },
  });
}

function sameOriginMutation(request) {
  const origin = request.headers.get('origin');
  try { return origin === new URL(request.url).origin; } catch { return false; }
}

function sourceErrorResponse(error) {
  const stable = sourceFailure(error);
  return fixedJson(stable.status, { schemaVersion: 1, error: stable.code });
}

async function readJsonInput(request, limit = MCP_REQUEST_LIMIT_BYTES) {
  const raw = await readBoundedText(request, limit);
  if (raw === null) return null;
  try {
    const parsed = JSON.parse(raw);
    return isPlainData(parsed) ? parsed : null;
  } catch {
    return null;
  }
}

async function handleSourceDiscovery(request, env) {
  if (request.method !== 'POST') {
    return fixedJson(405, { schemaVersion: 1, error: 'method_not_allowed' }, { allow: 'POST' });
  }
  if (!await verifyAccess(request, env)) {
    return fixedJson(401, { schemaVersion: 1, error: 'access_required' });
  }
  if (!sameOriginMutation(request)) return fixedJson(403, { schemaVersion: 1, error: 'origin_required' });
  const input = await readJsonInput(request);
  if (!exactKeys(input, ['url'])) return fixedJson(400, { schemaVersion: 1, error: 'source_url_invalid' });
  try {
    const discovered = await inspectMcpSource(input.url);
    const result = {
      schemaVersion: 1,
      status: discovered.authMode === 'oauth' ? 'authorization_required' : 'discovered',
      endpoint: discovered.endpoint,
      protocolVersion: discovered.protocolVersion,
      authentication: discovered.authMode,
      tools: discovered.tools,
    };
    if (discovered.connectionBlock) result.connectionBlock = discovered.connectionBlock;
    return fixedJson(200, result);
  } catch (error) {
    return sourceErrorResponse(error);
  }
}

async function handleSources(request, env) {
  if (request.method !== 'GET' && request.method !== 'PUT') {
    return fixedJson(405, { schemaVersion: 1, error: 'method_not_allowed' }, { allow: 'GET, PUT' });
  }
  if (!await verifyAccess(request, env)) {
    return fixedJson(401, { schemaVersion: 1, error: 'access_required' });
  }
  if (request.method === 'PUT' && !sameOriginMutation(request)) {
    return fixedJson(403, { schemaVersion: 1, error: 'origin_required' });
  }
  if (request.method === 'PUT' && SOURCE_ADDITION_PAUSED) return sourceAdditionPaused();
  const stub = adminStateStub(env, 'v1:management');
  if (!stub) return fixedJson(503, { schemaVersion: 1, error: 'sources_unavailable' });
  if (request.method === 'GET') {
    try {
      const response = await stub.fetch(new Request(`https://admin-state.invalid${INTERNAL_SOURCES_PATH}`));
      if (!(response instanceof Response)) return fixedJson(503, { schemaVersion: 1, error: 'sources_unavailable' });
      if (response.status !== 200) return response;
      const sources = safeManagementSources(await response.json());
      return sources ? fixedJson(200, { ...sources, installationEnabled: !SOURCE_ADDITION_PAUSED }) :
        fixedJson(503, { schemaVersion: 1, error: 'sources_unavailable' });
    } catch {
      return fixedJson(503, { schemaVersion: 1, error: 'sources_unavailable' });
    }
  }
  const input = parseSourceSave(await readJsonInput(request, SOURCE_SAVE_REQUEST_LIMIT_BYTES));
  if (!input) return fixedJson(400, { schemaVersion: 1, error: 'source_invalid' });
  try { await verifyManagedSource(input.source); } catch (error) { return sourceErrorResponse(error); }
  try {
    const response = await stub.fetch(new Request(`https://admin-state.invalid${INTERNAL_SOURCES_PATH}`, {
      method: 'PUT',
      headers: { 'content-type': 'application/json' },
      body: canonicalJson({ schemaVersion: 1, revision: input.revision, source: input.source }),
    }));
    if (!(response instanceof Response)) return fixedJson(503, { schemaVersion: 1, error: 'sources_unavailable' });
    if (response.status !== 200) return response;
    const sources = safeManagementSources(await response.json());
    return sources ? fixedJson(200, { ...sources, installationEnabled: !SOURCE_ADDITION_PAUSED }) :
      fixedJson(503, { schemaVersion: 1, error: 'sources_unavailable' });
  } catch {
    return fixedJson(503, { schemaVersion: 1, error: 'sources_unavailable' });
  }
}

function teamSources(sources) {
  return sources.sources.map((source) => ({
    id: source.id, label: source.label, enabledTools: source.enabledTools,
    installed: source.status === 'installed',
  }));
}

function safeTeamAction(value, context) {
  if (!exactKeys(value, ['schemaVersion', 'actionId', 'actorEmail', 'issuedAt', 'expiresAt',
    'actionKeyHash', 'status', 'failureCode', 'request', 'sourceRevision', 'planHash', 'journal']) ||
      value.schemaVersion !== 1 || !ACTION_ID.test(value.actionId) ||
      normalizedEmail(value.actorEmail) !== value.actorEmail || !context.adminEmails.includes(value.actorEmail) ||
      !Number.isSafeInteger(value.issuedAt) || !Number.isSafeInteger(value.expiresAt) ||
      value.expiresAt <= value.issuedAt || value.expiresAt - value.issuedAt > 600_000 ||
      !HASH.test(value.actionKeyHash) || !Number.isSafeInteger(value.sourceRevision) || value.sourceRevision < 1 ||
      !HASH.test(value.planHash) || !['authorization_required', 'applying', 'succeeded', 'failed', 'recovery_required'].includes(value.status) ||
      (value.failureCode !== null && !/^[a-z][a-z0-9_]{0,63}$/u.test(value.failureCode)) ||
      !Array.isArray(value.journal) || value.journal.length > 33) return null;
  try {
    normalizeTeamAccessRequest(value.request, { ...context,
      revision: value.status === 'succeeded' ? context.revision - 1 : context.revision });
  } catch { return null; }
  const ids = new Set();
  for (const entry of value.journal) {
    if (!exactKeys(entry, ['policyId', 'phase']) || !safeProviderId(entry.policyId) ||
        !['send_armed', 'verified'].includes(entry.phase) || ids.has(entry.policyId)) return null;
    ids.add(entry.policyId);
  }
  if (value.status === 'failed' && value.journal.length > 0) return null;
  return Object.freeze(structuredClone(value));
}

function safeTeamState(value, control, sources, admins) {
  if (!exactKeys(value, ['schemaVersion', 'revision', 'members', 'sourceBaselines', 'minimumRuntimeRelease', 'teardownDisabled', 'pendingAction']) ||
      value.schemaVersion !== 1 || !isBoolean(value.teardownDisabled) ||
      (value.minimumRuntimeRelease !== null && !updateSemver(value.minimumRuntimeRelease)) ||
      value.teardownDisabled !== (value.minimumRuntimeRelease !== null)) return null;
  const context = { revision: value.revision, adminEmails: admins, sources: teamSources(sources) };
  let normalized;
  try { normalized = normalizeTeamAccessRequest({ schemaVersion: 1, expectedRevision: value.revision, members: value.members }, context); }
  catch { return null; }
  const baselines = exactSortedUniqueStrings(value.sourceBaselines, (id) =>
    SOURCE_ID.test(id) && control.sourceOwnership.some((source) => source.sourceId === id) ? id : null, 32, 0);
  const pendingAction = value.pendingAction === null ? null : safeTeamAction(value.pendingAction, context);
  if (!baselines || (value.pendingAction !== null && !pendingAction)) return null;
  return Object.freeze({ ...value, members: normalized.members, sourceBaselines: baselines, pendingAction });
}

async function readTeamState(storage, env) {
  const control = safeManagementControl(await storage.get(CONTROL_KEY));
  const sources = safeManagementSources(await storage.get(SOURCES_KEY));
  const admins = accessConfiguration(env)?.emails;
  const environment = parseManagementEnvironment(env);
  if (!control || !sources || !admins || !environment ||
      control.accountId !== environment.accountId || control.zoneId !== environment.zoneId) return null;
  const raw = await storage.get(TEAM_KEY);
  if (raw !== undefined) return safeTeamState(raw, control, sources, admins);
  const legacyAudienceHash = await sha256({ emails: control.audienceEmails });
  const emptyAudienceHash = await sha256({ emails: [] });
  const installed = sources.sources.filter((source) => source.status === 'installed');
  if (installed.some((source) => {
    const hash = control.sourceOwnership.find((entry) => entry.sourceId === source.id)?.resources[2].identityHash;
    return hash !== legacyAudienceHash && hash !== emptyAudienceHash;
  })) return null;
  const sourceIds = installed.filter((source) => control.sourceOwnership.find((entry) =>
    entry.sourceId === source.id)?.resources[2].identityHash === legacyAudienceHash).map((source) => source.id).sort(compareText);
  const hasNativeSource = installed.length !== sourceIds.length;
  const initial = safeTeamState({
    schemaVersion: 1, revision: 1,
    // Restoring a missing Team record cannot erase evidence that a native
    // source was already provisioned, or make that source inherit old grants.
    minimumRuntimeRelease: hasNativeSource ? environment.release : null,
    teardownDisabled: hasNativeSource,
    sourceBaselines: sourceIds,
    members: [...new Set([...control.audienceEmails, ...admins])].sort(compareText).map((email) => ({
      email, sourceIds: control.audienceEmails.includes(email) ? sourceIds : [],
    })),
    pendingAction: null,
  }, control, sources, admins);
  if (initial) await storage.put(TEAM_KEY, initial);
  return initial;
}

async function armSourceCompatibility(storage, env) {
  const state = await readTeamState(storage, env);
  const environment = parseManagementEnvironment(env);
  if (!state || !environment || await teamActionBlocksLifecycle(storage)) return false;
  const minimumRuntimeRelease = state.minimumRuntimeRelease === null ||
    compareUpdateRelease(state.minimumRuntimeRelease, environment.release) === -1
    ? environment.release : state.minimumRuntimeRelease;
  if (!state.teardownDisabled || state.minimumRuntimeRelease !== minimumRuntimeRelease) {
    await storage.put(TEAM_KEY, { ...state, teardownDisabled: true, minimumRuntimeRelease });
  }
  return true;
}

async function otherLifecycleBlocksSource(storage, now, currentActionId) {
  for (const key of [ACTIONS_KEY, UPDATES_KEY, TEARDOWNS_KEY]) {
    const raw = await storage.get(key);
    if (raw === undefined) continue;
    const state = key === ACTIONS_KEY ? safeSourceActions(raw) : key === UPDATES_KEY
      ? safeRuntimeUpdates(raw) : safeTeardownActions(raw);
    if (!state || state.actions.some((action) => {
      if (action.actionId === currentActionId || action.status === 'succeeded') return false;
      // An expired grant is not evidence that its provider mutation never ran.
      // Retain source journals even if a historical status says unstarted/failed.
      if (key === ACTIONS_KEY && sourceActionHasWriteEvidence(action)) return true;
      if (action.status === 'failed') return false;
      if (action.status !== 'authorization_required' || action.expiresAt > now) return true;
      return key === UPDATES_KEY && action.stage !== null;
    })) return true;
  }
  return false;
}

async function teamActionBlocksLifecycle(storage) {
  const team = await storage.get(TEAM_KEY);
  if (team === undefined) return false;
  if (!isRecord(team) || !Object.hasOwn(team, 'pendingAction')) return true;
  const action = team.pendingAction;
  return action !== null && (!isRecord(action) ||
    !['succeeded', 'failed'].includes(action.status));
}

async function teamRuntimeReleaseAllowed(storage, release) {
  const team = await storage.get(TEAM_KEY);
  if (team === undefined) return true;
  if (!isRecord(team) || !Object.hasOwn(team, 'minimumRuntimeRelease')) return false;
  if (team.minimumRuntimeRelease === null) return team.teardownDisabled === false;
  return team.teardownDisabled === true && updateSemver(team.minimumRuntimeRelease) && updateSemver(release) &&
    compareUpdateRelease(release, team.minimumRuntimeRelease) !== -1;
}

async function currentTeardownLocksRuntime(storage, now) {
  const raw = await storage.get(TEARDOWNS_KEY);
  if (raw === undefined) return false;
  const state = safeTeardownActions(raw);
  if (!state) return true;
  return state.actions.some((action) => action.policyMode === 'receipt_owned' &&
    (['applying', 'gateway_removed', 'recovery_required'].includes(action.status) ||
      (action.status === 'authorization_required' && action.expiresAt > now)));
}

async function currentTeardownBlocked(storage, env) {
  if (!await readTeamState(storage, env) || await teamActionBlocksLifecycle(storage)) return true;
  for (const [key, parse] of [[ACTIONS_KEY, safeSourceActions], [UPDATES_KEY, safeRuntimeUpdates]]) {
    const raw = await storage.get(key);
    if (raw === undefined) continue;
    const state = parse(raw);
    // The current teardown receipts cover sources, but not their BigQuery bridge Workers.
    if (key === ACTIONS_KEY && state?.actions.some((action) => action.bigquerySetupStarted === true)) return true;
    if (!state || state.actions.some((action) => action.status !== 'succeeded' &&
      (action.status !== 'failed' || (key === ACTIONS_KEY && sourceActionHasWriteEvidence(action)) ||
        (key === UPDATES_KEY && action.stage !== null)))) return true;
  }
  return false;
}

async function teamTeardownBlocked(storage) {
  const team = await storage.get(TEAM_KEY);
  if (team === undefined) return false;
  // Native audience mutations cannot be interpreted by the immutable legacy
  // teardown matcher. Refuse the action; never weaken or rewrite that receipt.
  return !isRecord(team) || team.teardownDisabled !== false || team.minimumRuntimeRelease !== null ||
    await teamActionBlocksLifecycle(storage);
}

async function otherLifecycleBlocksTeam(storage, now) {
  for (const key of [ACTIONS_KEY, UPDATES_KEY, TEARDOWNS_KEY]) {
    const raw = await storage.get(key);
    if (raw === undefined) continue;
    const state = key === ACTIONS_KEY ? safeSourceActions(raw) : key === UPDATES_KEY
      ? safeRuntimeUpdates(raw) : safeTeardownActions(raw);
    if (!state || state.actions.some((action) => !['succeeded', 'failed'].includes(action.status) &&
      (action.status !== 'authorization_required' || action.expiresAt > now))) return true;
  }
  return false;
}

function publicTeamAction(action) {
  return { schemaVersion: 1, action: 'access', actionId: action.actionId, status: action.status,
    expiresAt: new Date(action.expiresAt).toISOString(), failureCode: action.failureCode,
    canCancel: ['authorization_required', 'recovery_required'].includes(action.status) && action.journal.length === 0 };
}

async function teamSnapshot(storage, env) {
  const state = await readTeamState(storage, env);
  const sources = safeManagementSources(await storage.get(SOURCES_KEY));
  const admins = accessConfiguration(env)?.emails;
  if (!state || !sources || !admins) return null;
  const blocked = await otherLifecycleBlocksTeam(storage, Date.now());
  return { schemaVersion: 1, revision: state.revision, members: state.members, adminEmails: admins,
    sources: sources.sources.map((source) => ({ id: source.id, label: source.label,
      enabledTools: source.enabledTools, status: source.status })),
    pendingAction: state.pendingAction ? publicTeamAction(state.pendingAction) : null,
    proposedMembers: state.pendingAction && !['succeeded', 'failed'].includes(state.pendingAction.status)
      ? state.pendingAction.request.members : null,
    // Kept for response compatibility with installed previews. V1 never
    // provisions or consumes a standing Cloudflare management credential.
    managementCredentialConfigured: false,
    editingEnabled: false,
    editingDisabledReason: blocked ? 'lifecycle_action_pending' : 'managed_in_cloudflare' };
}

async function handleTeam(request, env) {
  const actorEmail = await verifyAccess(request, env);
  if (!actorEmail) return fixedJson(401, { schemaVersion: 1, error: 'access_required' });
  const url = new URL(request.url);
  const environment = parseManagementEnvironment(env);
  if (!environment || url.hostname !== environment.managementHostname) {
    return fixedJson(503, { schemaVersion: 1, error: 'team_unavailable' });
  }
  const stub = adminStateStub(env, 'v1:management');
  if (!stub) return fixedJson(503, { schemaVersion: 1, error: 'team_unavailable' });
  if (request.method === 'GET' && url.pathname === '/api/team') try {
    const response = await stub.fetch(new Request(`https://admin-state.invalid${INTERNAL_TEAM_PATH}`));
    return response instanceof Response ? response : fixedJson(503, { schemaVersion: 1, error: 'team_unavailable' });
  } catch { return fixedJson(503, { schemaVersion: 1, error: 'team_unavailable' }); }
  if (url.pathname === '/api/team') return fixedJson(405, { schemaVersion: 1, error: 'method_not_allowed' }, { allow: 'GET' });
  const actionId = url.pathname.startsWith('/api/team-actions/') ? url.pathname.slice('/api/team-actions/'.length) : null;
  if (actionId && ACTION_ID.test(actionId) && ['GET', 'DELETE'].includes(request.method)) {
    if (request.method === 'DELETE' && !sameOriginMutation(request)) return fixedJson(403, { schemaVersion: 1, error: 'origin_required' });
    const options = { method: request.method };
    if (request.method === 'DELETE') Object.assign(options, { headers: { 'content-type': 'application/json' }, body: canonicalJson({ actorEmail }) });
    try { return await stub.fetch(new Request(`https://admin-state.invalid${INTERNAL_TEAM_ACTIONS_PATH}/${actionId}`, options)); }
    catch { return fixedJson(503, { schemaVersion: 1, error: 'team_unavailable' }); }
  }
  if (request.method !== 'POST' || url.pathname !== '/api/team-actions') return fixedJson(404, { schemaVersion: 1, error: 'team_action_not_found' });
  if (!sameOriginMutation(request)) return fixedJson(403, { schemaVersion: 1, error: 'origin_required' });
  return fixedJson(409, { schemaVersion: 1, error: 'team_editing_managed_in_cloudflare' });
}

async function handleSourceActions(request, env) {
  const actorEmail = await verifyAccess(request, env);
  if (!actorEmail) return fixedJson(401, { schemaVersion: 1, error: 'access_required' });
  const environment = parseManagementEnvironment(env);
  let url;
  try { url = new URL(request.url); } catch { return fixedJson(400, { schemaVersion: 1, error: 'source_action_invalid' }); }
  if (!environment || url.hostname !== environment.managementHostname) {
    return fixedJson(503, { schemaVersion: 1, error: 'source_actions_unavailable' });
  }
  const stub = adminStateStub(env, 'v1:management');
  if (!stub) return fixedJson(503, { schemaVersion: 1, error: 'source_actions_unavailable' });
  if (request.method === 'GET') {
    const actionId = url.pathname.slice('/api/source-actions/'.length);
    const collection = url.pathname === '/api/source-actions';
    if (!collection && !ACTION_ID.test(actionId)) return fixedJson(404, { schemaVersion: 1, error: 'source_action_not_found' });
    try {
      const response = await stub.fetch(new Request(
        `https://admin-state.invalid${INTERNAL_ACTIONS_PATH}${collection ? '' : `/${actionId}`}`,
        { headers: { 'x-ankka-actor-email': actorEmail } },
      ));
      return response instanceof Response
        ? response
        : fixedJson(503, { schemaVersion: 1, error: 'source_actions_unavailable' });
    } catch {
      return fixedJson(503, { schemaVersion: 1, error: 'source_actions_unavailable' });
    }
  }
  if (request.method === 'DELETE') {
    if (!sameOriginMutation(request)) return fixedJson(403, { schemaVersion: 1, error: 'origin_required' });
    const actionId = url.pathname.slice('/api/source-actions/'.length);
    if (!ACTION_ID.test(actionId)) return fixedJson(404, { schemaVersion: 1, error: 'source_action_not_found' });
    try {
      const response = await stub.fetch(new Request(
        `https://admin-state.invalid${INTERNAL_ACTIONS_PATH}/${actionId}`,
        {
          method: 'DELETE',
          headers: { 'content-type': 'application/json' },
          body: canonicalJson({ actorEmail, now: Date.now() }),
        },
      ));
      return response instanceof Response
        ? response
        : fixedJson(503, { schemaVersion: 1, error: 'source_actions_unavailable' });
    } catch {
      return fixedJson(503, { schemaVersion: 1, error: 'source_actions_unavailable' });
    }
  }
  if (request.method !== 'POST') {
    return fixedJson(405, { schemaVersion: 1, error: 'method_not_allowed' }, { allow: 'GET, POST, DELETE' });
  }
  const renewal = /^\/api\/source-actions\/(action_[A-Za-z0-9_-]{32})\/renew$/u.exec(url.pathname);
  const renewActionId = renewal?.[1] ?? null;
  if (url.pathname !== '/api/source-actions' && renewActionId === null) {
    return fixedJson(404, { schemaVersion: 1, error: 'source_action_not_found' });
  }
  if (!sameOriginMutation(request)) return fixedJson(403, { schemaVersion: 1, error: 'origin_required' });
  if (SOURCE_ADDITION_PAUSED) return sourceAdditionPaused();
  const input = await readJsonInput(request);
  if (!exactKeys(input, ['schemaVersion', 'revision', 'sourceId']) || input.schemaVersion !== 1 ||
      !Number.isSafeInteger(input.revision) || input.revision < 1 || !SOURCE_ID.test(input.sourceId)) {
    return fixedJson(400, { schemaVersion: 1, error: 'source_action_invalid' });
  }
  // Detect an existing authorization before another discovery request. The
  // serialized prepare below repeats this check before creating any action.
  try {
    const response = await stub.fetch(new Request(`https://admin-state.invalid${INTERNAL_ACTIONS_PATH}`, {
      headers: { 'x-ankka-actor-email': actorEmail },
    }));
    if (!(response instanceof Response) || response.status !== 200) {
      return fixedJson(503, { schemaVersion: 1, error: 'source_actions_unavailable' });
    }
    const snapshot = await response.json();
    if (renewActionId !== null) {
      const action = snapshot.actions?.find((entry) => entry.actionId === renewActionId);
      if (action?.sourceId !== input.sourceId || action.canRenew !== true ||
          snapshot.blockingAction?.kind !== 'source' || snapshot.blockingAction.actionId !== renewActionId) {
        return sourceActionConflict('recovery_required');
      }
    } else {
      const conflict = sourceSnapshotConflict(snapshot);
      if (conflict) return conflict;
    }
  } catch { return fixedJson(503, { schemaVersion: 1, error: 'source_actions_unavailable' }); }
  let sources;
  try {
    const response = await stub.fetch(new Request(`https://admin-state.invalid${INTERNAL_SOURCES_PATH}`));
    sources = response instanceof Response && response.status === 200 ? await response.json() : null;
  } catch { sources = null; }
  const parsedSources = safeManagementSources(sources);
  const source = parsedSources?.sources.find((candidate) => candidate.id === input.sourceId);
  if (!parsedSources || parsedSources.revision !== input.revision || !source || source.status !== 'draft') {
    return sourceActionConflict('draft_changed');
  }
  try { await verifyManagedSource(source); } catch (error) { return sourceErrorResponse(error); }
  const now = Date.now();
  const expiresAt = now + 10 * 60 * 1000;
  const actionId = renewActionId ?? `action_${randomBase64Url(24)}`;
  const actionKey = randomBase64Url(32);
  let prepared;
  try {
    const preparePath = `${INTERNAL_ACTIONS_PATH}${renewActionId === null ? '' : `/${actionId}/renew`}`;
    prepared = await stub.fetch(new Request(`https://admin-state.invalid${preparePath}`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: canonicalJson({
        schemaVersion: 1,
        actionId,
        sourceId: source.id,
        sourceRevision: parsedSources.revision,
        actorEmail,
        issuedAt: now,
        expiresAt,
        actionKeyHash: await sha256(actionKey),
        sourceHash: await managedSourceHash(source),
      }),
    }));
  } catch { prepared = null; }
  if (!(prepared instanceof Response) || prepared.status !== 200) {
    return prepared instanceof Response ? prepared :
      fixedJson(503, { schemaVersion: 1, error: 'source_actions_unavailable' });
  }
  const managementOrigin = `https://${environment.managementHostname}`;
  const claim = canonicalJson({
    schemaVersion: 1,
    actionId,
    actionKey,
    actorEmail,
    accountId: environment.accountId,
    controlPlaneOrigin: CONTROL_PLANE_ORIGIN,
    workerName: environment.workerName,
    workersSubdomain: environment.workersSubdomain,
    managementOrigin,
    releaseIdentity: exactReleaseIdentity(environment),
    expiresAt,
  });
  const fragment = base64UrlEncode(new TextEncoder().encode(claim));
  return fixedJson(200, {
    schemaVersion: 1,
    actionId,
    status: 'authorization_required',
    expiresAt: new Date(expiresAt).toISOString(),
    handoffUrl: `${managementOrigin}${OPERATION_PATH}#${fragment}`,
  });
}

async function handleSourceActionApply(request, env) {
  if (request.method === 'HEAD') {
    const environment = parseManagementEnvironment(env);
    return environment
      ? new Response(null, { status: 204, headers: { ...PUBLIC_HEADERS, 'x-ankka-source-action': 'ready' } })
      : fixedJson(503, { schemaVersion: 1, error: 'source_actions_unavailable' });
  }
  if (request.method !== 'POST') {
    return fixedJson(405, { schemaVersion: 1, error: 'method_not_allowed' }, { allow: 'HEAD, POST' });
  }
  const stub = adminStateStub(env, 'v1:management');
  if (!stub) return fixedJson(503, { schemaVersion: 1, error: 'source_actions_unavailable' });
  try {
    const response = await stub.fetch(new Request(
      `https://admin-state.invalid${INTERNAL_ACTIONS_PATH}/apply`,
      request,
    ));
    return response instanceof Response
      ? response
      : fixedJson(503, { schemaVersion: 1, error: 'source_actions_unavailable' });
  } catch {
    return fixedJson(503, { schemaVersion: 1, error: 'source_actions_unavailable' });
  }
}

async function handleRuntimeActions(request, env) {
  const actorEmail = await verifyAccess(request, env);
  if (!actorEmail) return fixedJson(401, { schemaVersion: 1, error: 'access_required' });
  const environment = parseManagementEnvironment(env);
  let url;
  try { url = new URL(request.url); } catch { return fixedJson(400, { schemaVersion: 1, error: 'runtime_action_invalid' }); }
  if (!environment || url.hostname !== environment.managementHostname) {
    return fixedJson(503, { schemaVersion: 1, error: 'runtime_updates_unavailable' });
  }
  const stub = adminStateStub(env, 'v1:management');
  if (!stub) return fixedJson(503, { schemaVersion: 1, error: 'runtime_updates_unavailable' });
  if (request.method === 'GET') {
    const actionId = url.pathname.slice('/api/update-actions/'.length);
    if (!ACTION_ID.test(actionId)) return fixedJson(404, { schemaVersion: 1, error: 'runtime_action_not_found' });
    try {
      const response = await stub.fetch(new Request(`https://admin-state.invalid${INTERNAL_UPDATES_PATH}/${actionId}`));
      return response instanceof Response ? response :
        fixedJson(503, { schemaVersion: 1, error: 'runtime_updates_unavailable' });
    } catch { return fixedJson(503, { schemaVersion: 1, error: 'runtime_updates_unavailable' }); }
  }
  if (request.method !== 'POST' || url.pathname !== '/api/update-actions') {
    return fixedJson(405, { schemaVersion: 1, error: 'method_not_allowed' }, { allow: 'GET, POST' });
  }
  if (!sameOriginMutation(request)) return fixedJson(403, { schemaVersion: 1, error: 'origin_required' });
  const input = await readJsonInput(request);
  if (!(exactKeys(input, ['operation', 'schemaVersion']) ||
        exactKeys(input, ['expectedTarget', 'operation', 'schemaVersion'])) || input.schemaVersion !== 1 ||
      !['update', 'rollback'].includes(input.operation)) {
    return fixedJson(400, { schemaVersion: 1, error: 'runtime_action_invalid' });
  }
  if (Object.hasOwn(input, 'expectedTarget') &&
      (!exactKeys(input.expectedTarget, ['artifactSha256', 'release']) ||
       !isText(input.expectedTarget.release) || !updateSemver(input.expectedTarget.release) ||
       !isText(input.expectedTarget.artifactSha256) ||
       !HASH.test(input.expectedTarget.artifactSha256))) {
    return fixedJson(400, { schemaVersion: 1, error: 'runtime_action_invalid' });
  }
  let updateState;
  try {
    const response = await stub.fetch(new Request(`https://admin-state.invalid${INTERNAL_UPDATES_PATH}`));
    updateState = response instanceof Response && response.status === 200 ? await response.json() : null;
  } catch { updateState = null; }
  const current = runtimeVersion(updateState?.current);
  let to = input.operation === 'rollback' ? runtimeVersion(updateState?.previous) : null;
  if (input.operation === 'update') {
    const discovered = await discoverRuntimeUpdate(env);
    if (!discovered || discovered.comparison >= 0) {
      return fixedJson(409, { schemaVersion: 1, error: 'runtime_update_not_available' });
    }
    to = runtimeVersion({
      release: discovered.channel.release.id,
      artifactSha256: discovered.channel.release.artifactSha256,
      versionId: null,
    });
  }
  if (!current || !to) return fixedJson(409, { schemaVersion: 1, error: 'runtime_action_conflict' });
  if (input.expectedTarget && (input.expectedTarget.release !== to.release ||
      input.expectedTarget.artifactSha256 !== to.artifactSha256)) {
    return fixedJson(409, { schemaVersion: 1, error: 'runtime_action_conflict' });
  }
  const now = Date.now();
  const expiresAt = now + 10 * 60 * 1000;
  const actionId = `action_${randomBase64Url(24)}`;
  const actionKey = randomBase64Url(32);
  let prepared;
  try {
    prepared = await stub.fetch(new Request(`https://admin-state.invalid${INTERNAL_UPDATES_PATH}`, {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: canonicalJson({
        actionId, actionKeyHash: await sha256(actionKey), actorEmail, expiresAt, issuedAt: now,
        operation: input.operation, to,
      }),
    }));
  } catch { prepared = null; }
  if (!(prepared instanceof Response) || prepared.status !== 200) {
    return fixedJson(409, { schemaVersion: 1, error: 'runtime_action_conflict' });
  }
  const claim = canonicalJson({
    schemaVersion: 2,
    actionType: 'runtime_update',
    actionId,
    actionKey,
    actorEmail,
    accountId: environment.accountId,
    controlPlaneOrigin: CONTROL_PLANE_ORIGIN,
    workerName: environment.workerName,
    workersSubdomain: environment.workersSubdomain,
    managementOrigin: `https://${environment.managementHostname}`,
    operation: input.operation,
    from: current,
    to,
    expiresAt,
  });
  const fragment = base64UrlEncode(new TextEncoder().encode(claim));
  return fixedJson(200, {
    schemaVersion: 1, actionId, operation: input.operation,
    status: 'authorization_required', expiresAt: new Date(expiresAt).toISOString(),
    handoffUrl: `https://${environment.managementHostname}${OPERATION_PATH}#${fragment}`,
  });
}

async function handleRuntimeActionApply(request, env) {
  if (request.method === 'HEAD') {
    return parseManagementEnvironment(env)
      ? new Response(null, { status: 204, headers: { ...PUBLIC_HEADERS, 'x-ankka-runtime-action': 'ready' } })
      : fixedJson(503, { schemaVersion: 1, error: 'runtime_updates_unavailable' });
  }
  if (request.method !== 'POST') {
    return fixedJson(405, { schemaVersion: 1, error: 'method_not_allowed' }, { allow: 'HEAD, POST' });
  }
  const stub = adminStateStub(env, 'v1:management');
  if (!stub) return fixedJson(503, { schemaVersion: 1, error: 'runtime_updates_unavailable' });
  try {
    let internal = request;
    const raw = await readBoundedText(request.clone(), 32 * 1024);
    let control = null;
    try { control = raw === null ? null : JSON.parse(raw); } catch { control = null; }
    if (control?.command === 'probe') {
      const environment = parseManagementEnvironment(env);
      if (!environment || control.targetRelease !== environment.release ||
          control.targetArtifactSha256 !== environment.releaseSha256) {
        return fixedJson(409, { schemaVersion: 1, error: 'runtime_probe_version_mismatch' });
      }
      const headers = new Headers(request.headers);
      // The override selects the outer candidate, not the retained Durable Object.
      headers.delete('Cloudflare-Workers-Version-Overrides');
      headers.set('x-ankka-runtime-probe-version', 'verified');
      internal = new Request(request, { headers });
    }
    const response = await stub.fetch(new Request(
      `https://admin-state.invalid${INTERNAL_UPDATES_PATH}/control`, internal,
    ));
    return response instanceof Response ? response :
      fixedJson(503, { schemaVersion: 1, error: 'runtime_updates_unavailable' });
  } catch { return fixedJson(503, { schemaVersion: 1, error: 'runtime_updates_unavailable' }); }
}

async function handleTeardownActions(request, env, currentPolicies = false) {
  const actorEmail = await verifyAccess(request, env);
  if (!actorEmail) return fixedJson(401, { schemaVersion: 1, error: 'access_required' });
  const environment = parseManagementEnvironment(env);
  let url;
  try { url = new URL(request.url); } catch {
    return fixedJson(400, { schemaVersion: 1, error: 'teardown_action_invalid' });
  }
  if (!environment || url.hostname !== environment.managementHostname) {
    return fixedJson(503, { schemaVersion: 1, error: 'teardown_actions_unavailable' });
  }
  const stub = adminStateStub(env, 'v1:management');
  if (!stub) return fixedJson(503, { schemaVersion: 1, error: 'teardown_actions_unavailable' });
  if (request.method === 'GET') {
    const actionId = url.pathname.slice('/api/teardown-actions/'.length);
    if (!ACTION_ID.test(actionId)) {
      return fixedJson(404, { schemaVersion: 1, error: 'teardown_action_not_found' });
    }
    try {
      const response = await stub.fetch(new Request(
        `https://admin-state.invalid${INTERNAL_TEARDOWNS_PATH}/${actionId}`,
      ));
      return response instanceof Response ? response :
        fixedJson(503, { schemaVersion: 1, error: 'teardown_actions_unavailable' });
    } catch {
      return fixedJson(503, { schemaVersion: 1, error: 'teardown_actions_unavailable' });
    }
  }
  if (request.method !== 'POST' || url.pathname !== '/api/teardown-actions') {
    return fixedJson(405, { schemaVersion: 1, error: 'method_not_allowed' }, { allow: 'GET, POST' });
  }
  if (!sameOriginMutation(request)) return fixedJson(403, { schemaVersion: 1, error: 'origin_required' });
  const input = await readJsonInput(request);
  if (!exactKeys(input, ['schemaVersion']) || input.schemaVersion !== 1) {
    return fixedJson(400, { schemaVersion: 1, error: 'teardown_action_invalid' });
  }
  let control;
  try {
    const response = await stub.fetch(new Request(`https://admin-state.invalid${INTERNAL_CONTROL_PATH}`));
    control = response instanceof Response && response.status === 200 ? await response.json() : null;
  } catch { control = null; }
  const parsedControl = safeManagementControl(control);
  if (!parsedControl || parsedControl.accountId !== environment.accountId) {
    return fixedJson(409, { schemaVersion: 1, error: 'teardown_action_conflict' });
  }
  const now = Date.now();
  const expiresAt = now + 10 * 60 * 1000;
  const actionId = `action_${randomBase64Url(24)}`;
  const actionKey = randomBase64Url(32);
  let prepared;
  try {
    prepared = await stub.fetch(new Request(`https://admin-state.invalid${INTERNAL_TEARDOWNS_PATH}${currentPolicies ? '/prepare-current' : ''}`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: canonicalJson({
        schemaVersion: 1,
        actionId,
        actionKeyHash: await sha256(actionKey),
        actorEmail,
        installationId: parsedControl.installationId,
        issuedAt: now,
        expiresAt,
      }),
    }));
  } catch { prepared = null; }
  if (!(prepared instanceof Response) || prepared.status !== 200) {
    return fixedJson(409, { schemaVersion: 1, error: 'teardown_action_conflict' });
  }
  const claim = canonicalJson({
    schemaVersion: 3,
    actionType: 'gateway_teardown',
    actionId,
    actionKey,
    actorEmail,
    accountId: environment.accountId,
    controlPlaneOrigin: CONTROL_PLANE_ORIGIN,
    installationId: parsedControl.installationId,
    gatewayName: parsedControl.portal.name,
    portalHostname: parsedControl.portal.hostname,
    workerName: environment.workerName,
    workersSubdomain: environment.workersSubdomain,
    managementOrigin: `https://${environment.managementHostname}`,
    expiresAt,
  });
  const fragment = base64UrlEncode(new TextEncoder().encode(claim));
  return fixedJson(200, {
    schemaVersion: 1,
    actionId,
    status: 'authorization_required',
    expiresAt: new Date(expiresAt).toISOString(),
    handoffUrl: `${currentPolicies ? `https://${environment.managementHostname}/__ankka/operation/teardown` : `${CONTROL_PLANE_ORIGIN}/manage`}#${fragment}`,
  });
}

/** The release builder substitutes this fixed origin before hashing the Worker. */
export function gatewayControlPlaneOrigin() { return CONTROL_PLANE_ORIGIN; }

/** Enabled by the certified final gateway entrypoint, never by a browser flag. */
export function prepareCurrentGatewayTeardown(request, env) {
  return handleTeardownActions(request, env, true);
}

async function handleTeardownActionProof(request, env) {
  if (request.method === 'HEAD') {
    return parseManagementEnvironment(env)
      ? new Response(null, { status: 204, headers: { ...PUBLIC_HEADERS, 'x-ankka-teardown-action': 'ready' } })
      : fixedJson(503, { schemaVersion: 1, error: 'teardown_actions_unavailable' });
  }
  if (request.method !== 'POST') {
    return fixedJson(405, { schemaVersion: 1, error: 'method_not_allowed' }, { allow: 'HEAD, POST' });
  }
  const stub = adminStateStub(env, 'v1:management');
  if (!stub) return fixedJson(503, { schemaVersion: 1, error: 'teardown_actions_unavailable' });
  try {
    let command = null;
    try { command = (await request.clone().json())?.command ?? null; } catch { command = null; }
    if (command !== 'prove' && command !== 'apply') {
      return fixedJson(400, { schemaVersion: 1, error: 'teardown_action_rejected' });
    }
    const response = await stub.fetch(new Request(
      `https://admin-state.invalid${INTERNAL_TEARDOWNS_PATH}/${command}`, request,
    ));
    return response instanceof Response ? response :
      fixedJson(503, { schemaVersion: 1, error: 'teardown_actions_unavailable' });
  } catch {
    return fixedJson(503, { schemaVersion: 1, error: 'teardown_actions_unavailable' });
  }
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname === BOOTSTRAP_PATH) return handleBootstrap(request, env);
    if (url.pathname === SOURCE_ACTION_PATH) return handleSourceActionApply(request, env);
    if (url.pathname === RUNTIME_ACTION_PATH) return handleRuntimeActionApply(request, env);
    if (url.pathname === TEARDOWN_ACTION_PATH) return handleTeardownActionProof(request, env);
    if (url.pathname === '/api/status') return handleStatus(request, env);
    if (url.pathname === '/api/update') return handleRuntimeUpdate(request, env);
    if (url.pathname === '/api/sources/discover') return handleSourceDiscovery(request, env);
    if (url.pathname === '/api/sources') return handleSources(request, env);
    if (url.pathname === '/api/team' || url.pathname === '/api/team-actions' || url.pathname.startsWith('/api/team-actions/')) {
      return handleTeam(request, env);
    }
    if (url.pathname === '/api/source-actions' || url.pathname.startsWith('/api/source-actions/')) {
      return handleSourceActions(request, env);
    }
    if (url.pathname === '/api/update-actions' || url.pathname.startsWith('/api/update-actions/')) {
      return handleRuntimeActions(request, env);
    }
    if (url.pathname === '/api/teardown-actions' || url.pathname.startsWith('/api/teardown-actions/')) {
      return handleTeardownActions(request, env);
    }
    if (url.pathname.startsWith('/api/')) {
      return fixedJson(404, { schemaVersion: 1, error: 'not_found' });
    }
    return fixedJson(404, { schemaVersion: 1, error: 'not_found' });
  },
};

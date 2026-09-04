import * as v from 'valibot';

import { resolveAccessGroupByDigest } from './access-groups.ts';
import {
  assertCanaryServiceIdentityConfig,
  canaryServiceIdentityDigest,
  canaryServiceTokenId,
  exactServiceTokenPolicyRule,
  serviceTokenPolicyMatchesDigest,
} from './canary-service-identity.ts';
import {
  createCloudflareClient,
  type CloudflareClient,
  type CloudflareFetch,
} from './cloudflare-client.ts';
import {
  readCloudflareObservedState,
  type CloudflareObservedStateInput,
} from './cloudflare-observed.ts';
import {
  MAX_ENABLED_TOOLS_PER_SOURCE,
  validateGatewayConfig,
  type GatewayConfig,
} from './config.ts';
import {
  boundaryObjectSchema,
  jsonObjectSchema,
  jsonValueSchema,
  type BoundaryObject,
  type BoundaryValue,
  type JsonObject,
  type JsonValue,
} from './json.ts';
import {
  buildGatewayDesiredState,
  type DesiredResource,
  type GatewayDesiredState,
  type ResourceKind,
} from './plan.ts';
import {
  ownershipMarker,
  validateInstallationReceipt,
  type InstallationReceipt,
  type ReceiptProviderLocator,
  type ReceiptResource,
  type ReceiptTarget,
} from './receipt.ts';

const SAFE_ID = /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$/;
const RESOURCE_KEY = /^[a-z][a-z0-9-]{0,31}$/;
const DESIRED_HASH = /^sha256:[0-9a-f]{64}$/;
const EMAIL = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const PORTAL_CNAME_TARGET = 'gateway.agents.cloudflare.com';
const CLAUDE_OAUTH_CALLBACK = 'https://claude.ai/api/mcp/auth_callback';
const stringSchema = v.string();
const numberSchema = v.number();
const functionSchema = v.function();
const resourceKindSchema = v.picklist([
  'mcp_server',
  'source_access_application',
  'source_access_policy',
  'portal',
  'portal_access_application',
  'portal_access_policy',
  'dns_record',
]);
const mutationActionSchema = v.picklist(['create', 'update', 'delete']);
const codeModeSchema = v.picklist(['off', 'opt_in', 'default_on', 'enforced']);
const POLICY_KINDS = new Set<ResourceKind>(['source_access_policy', 'portal_access_policy']);
const SAFE_CODES = new Set([
  'invalid_input',
  'target_mismatch',
  'unsupported_change',
  'ownership_conflict',
  'resource_collision',
  'immutable_server_drift',
  'authenticated_server_update_blocked',
  'source_authorization_required',
  'access_app_missing',
  'access_app_ambiguous',
  'access_app_shape_unsupported',
  'access_identity_mismatch',
  'invalid_provider_response',
  'sync_failed',
  'sync_timeout',
  'provider_read_failed',
  'provider_write_failed',
]);

type Delay = (milliseconds: number) => Promise<void>;

interface ResidueInspectionInput {
  readonly config?: BoundaryValue;
  readonly receipt?: BoundaryValue;
  readonly signal?: AbortSignal;
  readonly target?: BoundaryValue;
}

export interface CloudflareGatewayProviderOptions {
  readonly accountId: string;
  readonly delayImpl?: Delay;
  readonly discoveryAttempts?: number;
  readonly discoveryIntervalMs?: number;
  readonly fetchImpl?: CloudflareFetch;
  readonly requestTimeoutMs?: number;
  readonly token: string;
  readonly zoneId: string;
}

interface BoundTarget {
  readonly accountId: string;
  readonly zoneId: string;
}

interface PollingOptions {
  readonly attempts: number;
  readonly delayImpl: Delay;
  readonly intervalMs: number;
}

interface MutationAttempt {
  submitted: boolean;
}

type CreateMutationChange = {
  readonly action: 'create';
  readonly desired: JsonObject;
  readonly desiredHash: string;
  readonly key: string;
  readonly kind: ResourceKind;
};

type UpdateMutationChange = {
  readonly action: 'update';
  readonly desired: JsonObject;
  readonly desiredHash: string;
  readonly key: string;
  readonly kind: ResourceKind;
  readonly provider: ReceiptProviderLocator;
};

type DeleteMutationChange = {
  readonly action: 'delete';
  readonly desired?: JsonObject;
  readonly desiredHash?: string;
  readonly key: string;
  readonly kind: ResourceKind;
  readonly provider: ReceiptProviderLocator;
};

type MutationChange = CreateMutationChange | DeleteMutationChange | UpdateMutationChange;

interface GatewayMutation {
  readonly access: BoundaryValue;
  readonly change: MutationChange;
  readonly config: GatewayConfig;
  readonly configInput: JsonValue;
  readonly marker: string;
  readonly ownedResource: ReceiptResource | undefined;
  readonly receipt: InstallationReceipt;
  readonly target: BoundaryObject;
}

interface PendingPortalRollbackMutation extends GatewayMutation {
  readonly change: CreateMutationChange & { readonly kind: 'portal' };
  readonly expectedPortal: PortalDesired;
}

interface MutationResult {
  readonly provider?: ReceiptProviderLocator;
}

interface PortalRollbackSample {
  readonly appCandidates: readonly string[];
  readonly dnsRecords: readonly BoundaryValue[];
  readonly portal: BoundaryObject | null;
}

type PortalTool = {
  readonly enabled: boolean;
  readonly name: string;
};

type PortalServer = {
  readonly default_disabled: true;
  readonly on_behalf: boolean;
  readonly server_id: string;
  readonly updated_prompts: readonly JsonValue[];
  readonly updated_tools: readonly PortalTool[];
};

type ServerDesired = {
  readonly auth_type: 'bearer' | 'oauth' | 'unauthenticated';
  readonly description: string;
  readonly hostname: string;
  readonly name: string;
  readonly updated_tools: readonly PortalTool[];
};

type PortalDesired = {
  readonly code_mode: 'default_on' | 'enforced' | 'off' | 'opt_in';
  readonly description: string;
  readonly hostname: string;
  readonly name: string;
  readonly secure_web_gateway: false;
  readonly servers: readonly PortalServer[];
};

type ManagedOauth = {
  readonly dynamic_client_registration: {
    readonly allowed_uris: readonly string[];
    readonly allow_any_on_localhost: true;
    readonly allow_any_on_loopback: true;
    readonly enabled: true;
  };
  readonly enabled: true;
  readonly grant: {
    readonly access_token_lifetime: '15m';
    readonly session_duration: '336h';
  };
};

type PortalAccessApplicationBody = {
  readonly destinations: readonly [{ readonly type: 'public'; readonly uri: string }];
  readonly domain: string;
  readonly name: string;
  readonly oauth_configuration: ManagedOauth;
  readonly type: 'mcp_portal';
};

type PortalAccessApplicationDesired = {
  readonly body: PortalAccessApplicationBody;
  readonly portalResourceKey: string;
};

type SourceAccessApplicationDesired = {
  readonly sourceResourceKey: string;
};

type PolicyBody = {
  readonly decision: 'allow' | 'non_identity';
  readonly exclude: readonly JsonValue[];
  readonly include: readonly PolicyIncludeRule[];
  readonly name: string;
  readonly require: readonly JsonValue[];
};

type PolicyIncludeRule =
  | { readonly email: { readonly email: string } }
  | { readonly group: { readonly id: string } }
  | { readonly service_token: { readonly token_id: string } };
/** A value-free error suitable for installer output and receipt recovery. */
export class CloudflareGatewayProviderError extends Error {
  readonly code: string;
  readonly mutationOutcome?: 'not_submitted';

  constructor(
    code: string,
    { mutationOutcome }: { readonly mutationOutcome?: 'not_submitted' | undefined } = {},
  ) {
    const safeCode = SAFE_CODES.has(code) ? code : 'provider_write_failed';
    super(`Cloudflare gateway provider failed: code=${safeCode}`);
    this.name = 'CloudflareGatewayProviderError';
    this.code = safeCode;
    if (mutationOutcome === 'not_submitted') {
      Object.defineProperty(this, 'mutationOutcome', {
        value: 'not_submitted',
        enumerable: true,
        writable: false,
        configurable: false,
      });
    }
  }
}

/**
 * Bind the provider-neutral reconciler to one explicit Cloudflare account and
 * zone. The token and fetch implementation stay inside the returned closure.
 */
const defaultCloudflareFetch: CloudflareFetch = async (url, init) =>
  globalThis.fetch(url, init);

export function createCloudflareGatewayProvider(options: CloudflareGatewayProviderOptions) {
  if (!v.is(v.object({}), options)) throw new TypeError('provider options must be an object');
  rejectUnknownKeys(options, [
    'token',
    'accountId',
    'zoneId',
    'fetchImpl',
    'delayImpl',
    'discoveryAttempts',
    'discoveryIntervalMs',
    'requestTimeoutMs',
  ]);
  const {
    token,
    accountId,
    zoneId,
    fetchImpl = defaultCloudflareFetch,
    delayImpl = defaultDelay,
    discoveryAttempts = 30,
    discoveryIntervalMs = 1_000,
    requestTimeoutMs = 30_000,
  } = options;
  requireId(accountId);
  requireId(zoneId);
  if (!v.safeParse(functionSchema, delayImpl).success) {
    throw new TypeError('delayImpl must be a function');
  }
  if (!v.is(numberSchema, discoveryAttempts)
    || !Number.isInteger(discoveryAttempts)
    || discoveryAttempts < 1
    || discoveryAttempts > 120) {
    throw new TypeError('discoveryAttempts must be an integer from 1 to 120');
  }
  if (!v.is(numberSchema, discoveryIntervalMs)
    || !Number.isInteger(discoveryIntervalMs)
    || discoveryIntervalMs < 0
    || discoveryIntervalMs > 10_000) {
    throw new TypeError('discoveryIntervalMs must be an integer from 0 to 10000');
  }

  const cloudflare = createCloudflareClient({
    token,
    accountId,
    zoneId,
    fetchImpl,
    requestTimeoutMs,
  });
  const polling: PollingOptions = {
    delayImpl,
    attempts: discoveryAttempts,
    intervalMs: discoveryIntervalMs,
  };

  const readObservedState = (input: Omit<CloudflareObservedStateInput, 'cloudflare'>) =>
    readCloudflareObservedState({ ...input, cloudflare });

  const applyChange = async (input: BoundaryValue = {}) => {
    const mutationAttempt: MutationAttempt = { submitted: false };
    const applyCloudflare = trackCloudflareMutationAttempt(cloudflare, mutationAttempt);
    try {
      const mutation = await normalizeMutationInput(input, { accountId, zoneId });
      const result = await dispatchMutation(applyCloudflare, polling, mutation);
      return normalizeApplyMutationResult(mutation.change, result);
    } catch (error) {
      const code = error instanceof CloudflareGatewayProviderError
        ? error.code
        : 'provider_write_failed';
      throw new CloudflareGatewayProviderError(code, {
        mutationOutcome: mutationAttempt.submitted ? undefined : 'not_submitted',
      });
    }
  };

  const inspectCanaryResidue = async (
    input: BoundaryValue | ResidueInspectionInput = {},
  ) => {
    try {
      if (!isResidueInspectionInput(input)) fail('invalid_input');
      const signal = normalizeAbortSignal(input.signal);
      const residueCloudflare = signal
        ? createCloudflareClient({
          token,
          accountId,
          zoneId,
          fetchImpl,
          signal,
          requestTimeoutMs,
        })
        : cloudflare;
      return await inspectResidue(residueCloudflare, input, { accountId, zoneId });
    } catch (error) {
      if (error instanceof CloudflareGatewayProviderError) throw error;
      throw new CloudflareGatewayProviderError('provider_read_failed');
    }
  };

  const inspectPendingPortalCreateRollback = async (input: BoundaryValue = {}) => {
    try {
      const mutation = await normalizePendingPortalCreateRollbackInput(
        input,
        { accountId, zoneId },
      );
      const sample = await readPendingPortalCreateRollbackSample(cloudflare, mutation);
      assertNoPendingPortalAppCandidates(sample);
      if (sample.portal === null) {
        await provePendingPortalCreateRollbackQuiet(cloudflare, polling, mutation);
        return Object.freeze({ status: 'already_absent', portalKey: mutation.change.key });
      }
      assertPendingPortalCreateContract(sample.portal, mutation);
      return Object.freeze({ status: 'ready', portalKey: mutation.change.key });
    } catch (error) {
      if (error instanceof CloudflareGatewayProviderError) throw error;
      throw new CloudflareGatewayProviderError('provider_read_failed');
    }
  };

  const rollbackPendingPortalCreate = async (input: BoundaryValue = {}) => {
    try {
      const mutation = await normalizePendingPortalCreateRollbackInput(
        input,
        { accountId, zoneId },
      );
      const first = await readPendingPortalCreateRollbackSample(cloudflare, mutation);
      assertNoPendingPortalAppCandidates(first);
      if (first.portal === null) {
        await provePendingPortalCreateRollbackQuiet(cloudflare, polling, mutation);
        return Object.freeze({
          status: 'already_absent',
          portalKey: mutation.change.key,
          deleteRequest: 'not_needed',
        });
      }
      assertPendingPortalCreateContract(first.portal, mutation);

      await polling.delayImpl(polling.intervalMs);
      const second = await readPendingPortalCreateRollbackSample(cloudflare, mutation);
      assertNoPendingPortalAppCandidates(second);
      if (second.portal === null) {
        await provePendingPortalCreateRollbackQuiet(cloudflare, polling, mutation);
        return Object.freeze({
          status: 'already_absent',
          portalKey: mutation.change.key,
          deleteRequest: 'not_needed',
        });
      }
      assertPendingPortalCreateContract(second.portal, mutation);

      let deleteRequest = 'confirmed';
      try {
        await cloudflare.deletePortal(mutation.change.key);
      } catch {
        // A transport or response failure does not establish whether the exact
        // DELETE reached Cloudflare. Prove the postcondition before reporting
        // the outcome; the receipt remains pending outside this provider hook.
        deleteRequest = 'outcome_unknown';
      }
      await provePendingPortalCreateRollbackQuiet(cloudflare, polling, mutation);
      return Object.freeze({
        status: 'rolled_back',
        portalKey: mutation.change.key,
        deleteRequest,
      });
    } catch (error) {
      if (error instanceof CloudflareGatewayProviderError) throw error;
      throw new CloudflareGatewayProviderError('provider_write_failed');
    }
  };

  return Object.freeze({
    readObservedState,
    applyChange,
    inspectCanaryResidue,
    inspectPendingPortalCreateRollback,
    rollbackPendingPortalCreate,
  });
}

function normalizeApplyMutationResult(
  change: MutationChange,
  result: MutationResult | void,
) {
  const returnsCreatedLocator = change.action === 'create'
    && change.kind === 'portal_access_application';
  if (!returnsCreatedLocator) {
    if (result !== undefined) fail('invalid_provider_response');
    return Object.freeze({ status: 'submitted' });
  }
  if (result === undefined
    || !isObject(result)
    || Object.keys(result).sort().join(',') !== 'provider'
    || !isObject(result.provider)
    || Object.keys(result.provider).sort().join(',') !== 'id'
    || !safeId(result.provider.id)) fail('invalid_provider_response');
  return Object.freeze({
    status: 'submitted',
    provider: Object.freeze({ id: result.provider.id }),
  });
}

function trackCloudflareMutationAttempt(
  cloudflare: CloudflareClient,
  attempt: MutationAttempt,
): CloudflareClient {
  const submitted = <Arguments extends readonly JsonValue[], Result>(
    mutation: (...args: Arguments) => Promise<Result>,
  ) => (...args: Arguments): Promise<Result> => {
    attempt.submitted = true;
    return mutation(...args);
  };
  return Object.freeze({
    ...cloudflare,
    createMcpServer: submitted(cloudflare.createMcpServer),
    updateMcpServer: submitted(cloudflare.updateMcpServer),
    deleteMcpServer: submitted(cloudflare.deleteMcpServer),
    syncMcpServer: submitted(cloudflare.syncMcpServer),
    createPortal: submitted(cloudflare.createPortal),
    updatePortal: submitted(cloudflare.updatePortal),
    deletePortal: submitted(cloudflare.deletePortal),
    createAccessApp: submitted(cloudflare.createAccessApp),
    updateAccessApp: submitted(cloudflare.updateAccessApp),
    deleteAccessApp: submitted(cloudflare.deleteAccessApp),
    createAppPolicy: submitted(cloudflare.createAppPolicy),
    updateAppPolicy: submitted(cloudflare.updateAppPolicy),
    deleteAppPolicy: submitted(cloudflare.deleteAppPolicy),
    createDnsRecord: submitted(cloudflare.createDnsRecord),
    updateDnsRecord: submitted(cloudflare.updateDnsRecord),
    deleteDnsRecord: submitted(cloudflare.deleteDnsRecord),
  });
}

async function normalizePendingPortalCreateRollbackInput(
  input: BoundaryValue,
  boundTarget: BoundTarget,
): Promise<PendingPortalRollbackMutation> {
  const mutation = await normalizeMutationInput(input, boundTarget);
  if (mutation.change.action !== 'create'
    || mutation.change.kind !== 'portal'
    || mutation.receipt.pending?.type !== 'apply') fail('invalid_input');
  if (mutation.target.zoneName !== mutation.receipt.target.zoneName) fail('target_mismatch');
  if (mutation.receipt.resources.some((resource) =>
    ['portal', 'portal_access_application', 'portal_access_policy', 'dns_record']
      .includes(resource.kind))) {
    fail('ownership_conflict');
  }

  let desiredState: GatewayDesiredState;
  try {
    desiredState = await buildGatewayDesiredState(mutation.configInput, {
      target: mutation.target,
      access: mutation.access,
    });
  } catch {
    fail('invalid_input');
  }
  const desiredPortal = desiredState.resources.find((resource) =>
    resource.kind === 'portal' && resource.key === mutation.change.key);
  if (desiredState.installationId !== mutation.receipt.installationId
    || desiredPortal?.desiredHash !== mutation.change.desiredHash
    || canonicalJson(desiredPortal?.desired) !== canonicalJson(mutation.change.desired)
    || canonicalJson(desiredState.accessPolicy) !== canonicalJson(mutation.receipt.accessPolicy)) {
    fail('invalid_input');
  }
  assertPendingPortalRollbackReceiptTopology(desiredState.resources, mutation.receipt);

  const portalChange: CreateMutationChange & { readonly kind: 'portal' } = {
    action: 'create',
    desired: mutation.change.desired,
    desiredHash: mutation.change.desiredHash,
    key: mutation.change.key,
    kind: 'portal',
  };
  return {
    ...mutation,
    change: portalChange,
    expectedPortal: normalizePortalDesired(mutation.change.desired, mutation.marker),
  };
}

function assertPendingPortalRollbackReceiptTopology(
  desiredResources: readonly DesiredResource[],
  receipt: InstallationReceipt,
): void {
  const portalIndex = desiredResources.findIndex((resource) => resource.kind === 'portal');
  if (portalIndex < 0 || receipt.resources.length !== portalIndex) fail('invalid_input');
  const lowerDesired = desiredResources.slice(0, portalIndex);
  for (const desired of lowerDesired) {
    const matches = receipt.resources.filter((owned) =>
      owned.kind === desired.kind && owned.key === desired.key);
    const owned = matches[0];
    if (
      matches.length !== 1 ||
      owned === undefined ||
      owned.desiredHash !== desired.desiredHash ||
      owned.marker !== ownershipMarker(receipt.installationId, desired.key)
    ) {
      fail('invalid_input');
    }
    if (desired.kind === 'mcp_server' && owned.provider.id !== desired.key) {
      fail('invalid_input');
    }
    if (
      desired.kind === 'source_access_application' &&
      receipt.resources.filter((candidate) =>
        candidate.kind === 'mcp_server' &&
        candidate.key === desired.desired.sourceResourceKey &&
        candidate.provider.id === desired.desired.sourceResourceKey).length !== 1
    ) {
      fail('invalid_input');
    }
    if (desired.kind === 'source_access_policy') {
      const parents = receipt.resources.filter((candidate) =>
        candidate.kind === 'source_access_application' &&
        candidate.key === desired.desired.sourceApplicationResourceKey);
      const parent = parents[0];
      if (
        parents.length !== 1 ||
        parent === undefined ||
        owned.provider.parentId !== parent.provider.id ||
        owned.identityHash !== policyIdentityHash(desired.desired)
      ) {
        fail('invalid_input');
      }
    }
  }
}

async function readPendingPortalCreateRollbackSample(
  cloudflare: CloudflareClient,
  mutation: PendingPortalRollbackMutation,
): Promise<PortalRollbackSample> {
  const portal = await exactRead(
    () => cloudflare.getPortal(mutation.change.key),
    mutation.change.key,
  );
  const apps = await cloudflare.listAccessApps();
  if (!Array.isArray(apps)) fail('invalid_provider_response');
  const appCandidates = apps
    .filter((app) => isPortalAppCandidate(app, mutation.config.gateway.hostname))
    .map((app) => requireAppId(app).id);
  const dnsRecords = await cloudflare.listDnsRecords({
    'name.exact': mutation.config.gateway.hostname,
    match: 'all',
  });
  if (!Array.isArray(dnsRecords)) fail('invalid_provider_response');
  return { portal, appCandidates, dnsRecords };
}

function assertNoPendingPortalAppCandidates(sample: PortalRollbackSample): void {
  if (sample.appCandidates.length > 0 || sample.dnsRecords.length > 0) {
    fail('ownership_conflict');
  }
}

function assertPendingPortalCreateContract(
  portal: BoundaryObject,
  mutation: PendingPortalRollbackMutation,
): void {
  const expected = mutation.expectedPortal;
  if (!portalMatchesExpected(portal, mutation.change.key, expected)) {
    fail('ownership_conflict');
  }
}

function portalMatchesExpected(
  portal: BoundaryObject,
  portalId: string,
  expected: PortalDesired,
): boolean {
  return portal.id === portalId
    && portal.name === expected.name
    && portal.hostname === expected.hostname
    && portal.code_mode === expected.code_mode
    && portal.secure_web_gateway === expected.secure_web_gateway
    && portal.description === expected.description
    && samePortalServers(portal.servers, expected.servers);
}

function samePortalServers(
  liveServers: BoundaryValue,
  expectedServers: readonly PortalServer[],
): boolean {
  if (!Array.isArray(liveServers) || liveServers.length !== expectedServers.length) return false;
  return expectedServers.every((expected) => {
    const matches = liveServers.filter((live) =>
      (live?.server_id ?? live?.id) === expected.server_id);
    if (matches.length !== 1) return false;
    const live = matches[0];
    return live.default_disabled === expected.default_disabled
      && live.on_behalf === expected.on_behalf
      && optionalPromptsAreEmpty(live.updated_prompts)
      && sameEnabledPortalTools(live.updated_tools, expected.updated_tools);
  });
}

function sameEnabledPortalTools(
  liveTools: BoundaryValue,
  expectedTools: readonly PortalTool[],
): boolean {
  if (!Array.isArray(liveTools)) return false;
  const liveEnabled: string[] = [];
  for (const tool of liveTools) {
    if (!isObject(tool)
      || !v.is(stringSchema, tool.name)
      || !v.is(v.boolean(), tool.enabled)) {
      return false;
    }
    if (tool.enabled) liveEnabled.push(tool.name);
  }
  const expectedEnabled = expectedTools
    .filter((tool) => tool.enabled === true)
    .map((tool) => tool.name);
  return sameTextSet(liveEnabled, expectedEnabled);
}

function optionalPromptsAreEmpty(value: BoundaryValue): boolean {
  return value === undefined || (Array.isArray(value) && value.length === 0);
}

function sameTextSet(left: readonly string[], right: readonly string[]): boolean {
  return left.length === right.length
    && new Set(left).size === left.length
    && [...left].sort(compareText).every(
      (value, index) => value === [...right].sort(compareText)[index],
    );
}

async function provePendingPortalCreateRollbackQuiet(
  cloudflare: CloudflareClient,
  polling: PollingOptions,
  mutation: PendingPortalRollbackMutation,
): Promise<void> {
  let everySampleQuiet = true;
  for (let attempt = 0; attempt < polling.attempts; attempt += 1) {
    const sample = await readPendingPortalCreateRollbackSample(cloudflare, mutation);
    assertNoPendingPortalAppCandidates(sample);
    if (sample.portal !== null) {
      assertPendingPortalCreateContract(sample.portal, mutation);
      everySampleQuiet = false;
    }
    if (attempt + 1 < polling.attempts) await polling.delayImpl(polling.intervalMs);
  }
  if (!everySampleQuiet) fail('sync_timeout');
}

async function normalizeMutationInput(
  input: BoundaryValue,
  boundTarget: BoundTarget,
): Promise<GatewayMutation> {
  if (!isObject(input)) fail('invalid_input');
  rejectMutationKeys(input, ['change', 'receipt', 'config', 'target', 'access']);
  const { access, change: rawChange, config: rawConfig, target: rawTarget } = input;
  const receipt = await validateReceipt(input.receipt);
  assertTarget(rawTarget, boundTarget, receipt.target);
  if (!isObject(rawTarget)) fail('invalid_input');
  let configInput: JsonValue;
  let config: GatewayConfig;
  try {
    configInput = v.parse(jsonValueSchema, rawConfig);
    config = validateGatewayConfig(configInput);
  } catch {
    fail('invalid_input');
  }
  if (config.gateway.hostname !== receipt.target.hostname) {
    fail('invalid_input');
  }
  let serviceId: string | null;
  try {
    serviceId = canaryServiceTokenId(access);
    if (serviceId !== null || receipt.accessPolicy.identityType === 'service_token') {
      assertCanaryServiceIdentityConfig(config);
    }
  } catch {
    fail('access_identity_mismatch');
  }
  if (serviceId !== null || receipt.accessPolicy.identityType === 'service_token') {
    if (serviceId === null
      || receipt.accessPolicy.identityType !== 'service_token'
      || await canaryServiceIdentityDigest(serviceId) !== receipt.accessPolicy.identitiesHash) {
      fail('access_identity_mismatch');
    }
  }
  if (!isObject(rawChange)) {
    fail('unsupported_change');
  }
  const actionResult = v.safeParse(mutationActionSchema, rawChange.action);
  const kindResult = v.safeParse(resourceKindSchema, rawChange.kind);
  if (!actionResult.success || !kindResult.success) fail('unsupported_change');
  const action = actionResult.output;
  const kind = kindResult.output;
  if (!v.is(stringSchema, rawChange.key) || !RESOURCE_KEY.test(rawChange.key)) {
    fail('invalid_input');
  }
  const key = rawChange.key;
  if (!receipt.pending
    || receipt.pending.action !== action
    || receipt.pending.kind !== kind
    || receipt.pending.key !== key) fail('invalid_input');

  let change: MutationChange;
  let ownedResource: ReceiptResource | undefined;
  if (action !== 'delete') {
    if (!v.is(stringSchema, rawChange.desiredHash)
      || !DESIRED_HASH.test(rawChange.desiredHash)
      || !isObject(rawChange.desired)) fail('invalid_input');
    const desired = v.parse(jsonObjectSchema, rawChange.desired);
    const desiredHash = rawChange.desiredHash;
    if (desiredHash !== receipt.pending.expectedDesiredHash) fail('invalid_input');
    const computedDesiredHash = await hashCanonical({
      schemaVersion: 1,
      kind,
      key,
      desired,
    });
    if (computedDesiredHash !== desiredHash) fail('invalid_input');
    assertDesiredMetadata(desired, receipt.installationId);
    if (action === 'create') {
      change = { action, desired, desiredHash, key, kind };
    } else {
      const provider = normalizeProviderLocator(kind, rawChange.provider);
      if ((kind === 'mcp_server' || kind === 'portal') && provider.id !== key) {
        fail('ownership_conflict');
      }
      change = { action, desired, desiredHash, key, kind, provider };
    }
  } else {
    const provider = normalizeProviderLocator(kind, rawChange.provider);
    if ((kind === 'mcp_server' || kind === 'portal') && provider.id !== key) {
      fail('ownership_conflict');
    }
    change = { action, key, kind, provider };
  }
  if (change.action !== 'create') {
    ownedResource = receipt.resources.find((resource) =>
      resource.kind === change.kind
      && resource.key === change.key
      && sameLocator(resource.provider, change.provider));
    if (!ownedResource) fail('ownership_conflict');
  }
  return {
    change,
    receipt,
    config,
    configInput,
    target: rawTarget,
    access,
    ownedResource,
    marker: ownershipMarker(receipt.installationId, change.key),
  };
}

async function dispatchMutation(
  cloudflare: CloudflareClient,
  polling: PollingOptions,
  mutation: GatewayMutation,
): Promise<MutationResult | void> {
  const { change } = mutation;
  if (change.kind === 'mcp_server') return mutateServer(cloudflare, polling, mutation);
  if (change.kind === 'source_access_application') {
    return mutateSourceAccessApplication(cloudflare, polling, mutation);
  }
  if (change.kind === 'portal') return mutatePortal(cloudflare, polling, mutation);
  if (change.kind === 'portal_access_application') {
    return mutatePortalAccessApplication(cloudflare, polling, mutation);
  }
  if (POLICY_KINDS.has(change.kind)) return mutatePolicy(cloudflare, polling, mutation);
  if (change.kind === 'dns_record') return mutateDns(cloudflare, mutation);
  fail('unsupported_change');
}

async function mutateServer(
  cloudflare: CloudflareClient,
  polling: PollingOptions,
  mutation: GatewayMutation,
): Promise<void> {
  const { change, marker } = mutation;
  if (change.action === 'delete') {
    const live = await exactRead(() => cloudflare.getMcpServer(change.provider.id), change.provider.id);
    if (live === null) {
      await assertNoServerAccessApplications(cloudflare, change.provider.id);
      return;
    }
    assertMarker(live.description, marker);
    await assertNoServerAccessApplications(cloudflare, change.provider.id);
    const confirmed = await exactRead(
      () => cloudflare.getMcpServer(change.provider.id),
      change.provider.id,
    );
    if (confirmed === null) fail('ownership_conflict');
    assertMarker(confirmed.description, marker);
    await assertNoServerAccessApplications(cloudflare, change.provider.id);
    await cloudflare.deleteMcpServer(change.provider.id);
    return;
  }

  const expected = normalizeServerDesired(change.desired, marker);
  if (change.action === 'create') {
    if (await cloudflare.getMcpServer(change.key) !== null) fail('resource_collision');
    // The desired-state contract intentionally contains no upstream secret.
    // OAuth administrative authorization and static credentials are completed
    // in Cloudflare, not inferred or forwarded by this adapter.
    if (expected.auth_type !== 'unauthenticated') fail('source_authorization_required');
    await assertNoAccessAppBaseline(
      cloudflare,
      (app) => isExactServerApp(app, change.key),
    );
    await cloudflare.createMcpServer({
      id: change.key,
      auth_type: expected.auth_type,
      hostname: expected.hostname,
      name: expected.name,
      description: marker,
      secure_web_gateway: false,
      updated_prompts: [],
      updated_tools: expected.updated_tools,
    });
  } else {
    const live = await exactRead(() => cloudflare.getMcpServer(change.provider.id), change.provider.id);
    if (live === null) fail('ownership_conflict');
    assertMarker(live.description, marker);
    if (live.hostname !== expected.hostname || live.auth_type !== expected.auth_type) {
      fail('immutable_server_drift');
    }
    if (live.auth_type !== 'unauthenticated') fail('authenticated_server_update_blocked');
  }

  await cloudflare.syncMcpServer(change.key);
  await waitForServerSync(cloudflare, polling, change.key, expected.updated_tools);
  await cloudflare.updateMcpServer(change.key, {
    name: expected.name,
    description: marker,
    secure_web_gateway: false,
    updated_prompts: [],
    updated_tools: expected.updated_tools,
  });
}

async function mutateSourceAccessApplication(
  cloudflare: CloudflareClient,
  polling: PollingOptions,
  mutation: GatewayMutation,
): Promise<void> {
  const { change, marker } = mutation;
  if (change.action === 'delete') {
    let app = await exactRead(
      () => cloudflare.getAccessApp(change.provider.id),
      change.provider.id,
    );
    if (app === null) return;
    await assertSourceAccessApplicationAuthority(cloudflare, mutation, app, marker, {
      allowMissingServer: true,
    });
    await assertAccessApplicationPoliciesEmpty(cloudflare, app);
    app = await exactRead(() => cloudflare.getAccessApp(change.provider.id), change.provider.id);
    if (app === null) fail('ownership_conflict');
    await assertSourceAccessApplicationAuthority(cloudflare, mutation, app, marker, {
      allowMissingServer: true,
    });
    await assertAccessApplicationPoliciesEmpty(cloudflare, app);
    await cloudflare.deleteAccessApp(change.provider.id);
    await waitForAccessAppAbsence(cloudflare, polling, change.provider.id);
    return;
  }

  const expected = normalizeSourceAccessApplicationDesired(change.desired);
  const server = await assertReceiptOwnedServer(cloudflare, mutation, expected.sourceResourceKey);
  if (change.action === 'update') {
    const live = await exactRead(
      () => cloudflare.getAccessApp(change.provider.id),
      change.provider.id,
    );
    if (live === null || !isExactSourceAccessApplication(live, server.provider.id, marker)) {
      fail('ownership_conflict');
    }
    await assertAccessApplicationPoliciesEmpty(cloudflare, live);
    return;
  }

  const apps = await cloudflare.listAccessApps();
  if (!Array.isArray(apps)) fail('invalid_provider_response');
  if (apps.some((app) => (isObject(app) && app.name === marker)
    || isExactServerApp(app, server.provider.id))) {
    fail('resource_collision');
  }
  const created = await cloudflare.createAccessApp({
    name: marker,
    type: 'mcp',
    destinations: [{
      type: 'via_mcp_server_portal',
      mcp_server_id: server.provider.id,
    }],
  });
  const createdId = requireAppId(created).id;
  const live = await exactRead(() => cloudflare.getAccessApp(createdId), createdId);
  if (live === null || !isExactSourceAccessApplication(live, server.provider.id, marker)) {
    fail('ownership_conflict');
  }
  await assertReceiptOwnedServer(cloudflare, mutation, expected.sourceResourceKey);
  await assertAccessApplicationPoliciesEmpty(cloudflare, live);
}

async function mutatePortal(
  cloudflare: CloudflareClient,
  _polling: PollingOptions,
  mutation: GatewayMutation,
): Promise<void> {
  const { change, marker } = mutation;
  if (change.action === 'delete') {
    assertPortalApplicationReceiptAbsent(mutation.receipt);
    const live = await exactRead(() => cloudflare.getPortal(change.provider.id), change.provider.id);
    if (live === null) {
      await assertNoPortalAccessApplications(cloudflare, mutation.config.gateway.hostname);
      return;
    }
    assertMarker(live.description, marker);
    if (live.hostname !== mutation.config.gateway.hostname) fail('ownership_conflict');
    await assertNoPortalAccessApplications(cloudflare, mutation.config.gateway.hostname);
    const confirmed = await exactRead(
      () => cloudflare.getPortal(change.provider.id),
      change.provider.id,
    );
    if (confirmed === null
      || confirmed.hostname !== mutation.config.gateway.hostname) fail('ownership_conflict');
    assertMarker(confirmed.description, marker);
    assertPortalApplicationReceiptAbsent(mutation.receipt);
    await assertNoPortalAccessApplications(cloudflare, mutation.config.gateway.hostname);
    await cloudflare.deletePortal(change.provider.id);
    return;
  }
  const expected = normalizePortalDesired(change.desired, marker);
  const body = { ...expected,
    servers: expected.servers.map((mapping) => ({ ...mapping, id: mapping.server_id })),
  };
  if (change.action === 'create') {
    if (await cloudflare.getPortal(change.key) !== null) fail('resource_collision');
    await assertNoAccessAppBaseline(
      cloudflare,
      (app) => isPortalAppCandidate(app, mutation.config.gateway.hostname),
    );
    await cloudflare.createPortal({ id: change.key, ...body });
    return;
  }
  const live = await exactRead(() => cloudflare.getPortal(change.provider.id), change.provider.id);
  if (live === null) fail('ownership_conflict');
  assertMarker(live.description, marker);
  if (live.hostname !== mutation.config.gateway.hostname) fail('ownership_conflict');
  await cloudflare.updatePortal(change.provider.id, body);
}

async function mutatePortalAccessApplication(
  cloudflare: CloudflareClient,
  polling: PollingOptions,
  mutation: GatewayMutation,
): Promise<MutationResult | void> {
  const { change, marker } = mutation;
  if (change.action === 'delete') {
    let app = await exactRead(
      () => cloudflare.getAccessApp(change.provider.id),
      change.provider.id,
    );
    if (app === null) {
      await assertPortalAccessApplicationCandidateSet(
        cloudflare,
        mutation.config.gateway.hostname,
        mutation.config.gateway.name,
        change.provider.id,
        { allowAbsent: true },
      );
      return;
    }
    await assertPortalAccessApplicationAuthority(cloudflare, mutation, app, marker, {
      allowMissingPortal: true,
    });
    await assertPortalAccessApplicationCandidateSet(
      cloudflare,
      mutation.config.gateway.hostname,
      mutation.config.gateway.name,
      change.provider.id,
    );
    await assertAccessApplicationPoliciesEmpty(cloudflare, app);

    app = await exactRead(() => cloudflare.getAccessApp(change.provider.id), change.provider.id);
    if (app === null) fail('ownership_conflict');
    await assertPortalAccessApplicationAuthority(cloudflare, mutation, app, marker, {
      allowMissingPortal: true,
    });
    await assertPortalAccessApplicationCandidateSet(
      cloudflare,
      mutation.config.gateway.hostname,
      mutation.config.gateway.name,
      change.provider.id,
    );
    await assertAccessApplicationPoliciesEmpty(cloudflare, app);
    await cloudflare.deleteAccessApp(change.provider.id);
    await waitForAccessAppAbsence(cloudflare, polling, change.provider.id);
    return;
  }

  const expected = normalizePortalAccessApplicationDesired(change.desired);
  const expectedPortal = await expectedPortalForApplicationMutation(
    mutation,
    expected.portalResourceKey,
  );
  await assertReceiptOwnedPortal(cloudflare, mutation, expected.portalResourceKey, {
    expected: expectedPortal,
  });
  if (change.action === 'create') {
    await provePortalAccessApplicationBaselineQuiet(
      cloudflare,
      polling,
      expected.body.domain,
    );
    await assertReceiptOwnedPortal(cloudflare, mutation, expected.portalResourceKey, {
      expected: expectedPortal,
    });
    const apps = await cloudflare.listAccessApps();
    if (!Array.isArray(apps)) fail('invalid_provider_response');
    if (apps.some((app) => (isObject(app) && app.name === expected.body.name)
      || isPortalAppCandidate(app, expected.body.domain))) {
      fail('resource_collision');
    }
    const created = await cloudflare.createAccessApp(expected.body);
    const createdId = requireAppId(created).id;
    const live = await exactRead(() => cloudflare.getAccessApp(createdId), createdId);
    if (live === null || !portalAccessApplicationPrePolicyMatches(live, expected.body)) {
      fail('ownership_conflict');
    }
    // The exact POST result and exact GET are the last fallible operations
    // before returning the markerless app's provenance. Later list/parent/
    // policy checks happen only after the reconciler has atomically committed
    // this ID, so eventual consistency or a late same-shaped app cannot strand
    // or replace the application we just created.
    return Object.freeze({ provider: Object.freeze({ id: createdId }) });
  }

  let live = await exactRead(() => cloudflare.getAccessApp(change.provider.id), change.provider.id);
  if (live === null || live.name !== expected.body.name
    || !portalAccessApplicationContractMatches(live, expected.body.domain)) {
    fail('ownership_conflict');
  }
  await assertPortalAccessApplicationCandidateSet(
    cloudflare,
    expected.body.domain,
    expected.body.name,
    change.provider.id,
  );
  await assertPortalAccessApplicationPolicyPhase(cloudflare, mutation, live);
  live = await exactRead(() => cloudflare.getAccessApp(change.provider.id), change.provider.id);
  if (live === null || live.name !== expected.body.name
    || !portalAccessApplicationContractMatches(live, expected.body.domain)) {
    fail('ownership_conflict');
  }
  await assertReceiptOwnedPortal(cloudflare, mutation, expected.portalResourceKey, {
    expected: expectedPortal,
  });
  await assertPortalAccessApplicationPolicyPhase(cloudflare, mutation, live);
  await cloudflare.updateAccessApp(change.provider.id, expected.body);
}

async function mutatePolicy(
  cloudflare: CloudflareClient,
  _polling: PollingOptions,
  mutation: GatewayMutation,
): Promise<void> {
  const { change, marker } = mutation;
  if (change.action === 'delete') {
    const parentId = requireSafeId(change.provider.parentId);
    const parent = await assertPolicyParent(cloudflare, mutation, parentId);
    const policies = await cloudflare.listAppPolicies(parentId);
    assertInlinePolicySet(parent, policies);
    const listed = assertExpectedPolicySet(policies, change.provider.id, marker, { allowAbsent: true });
    if (listed === null) return;
    const live = await exactRead(
      () => cloudflare.getAppPolicy(parentId, change.provider.id),
      change.provider.id,
    );
    if (live === null) fail('ownership_conflict');
    assertMarker(live.name, marker);
    await assertCanaryPolicyIdentity(live, mutation);
    const confirmedParent = await assertPolicyParent(
      cloudflare,
      mutation,
      parentId,
    );
    if (POLICY_KINDS.has(change.kind)) {
      const confirmedPolicies = await cloudflare.listAppPolicies(parentId);
      const confirmedPolicy = assertExpectedPolicySet(confirmedPolicies, change.provider.id, marker);
      assertInlinePolicySet(confirmedParent, confirmedPolicies);
      await assertCanaryPolicyIdentity(confirmedPolicy, mutation);
    }
    await cloudflare.deleteAppPolicy(parentId, change.provider.id);
    return;
  }

  const body = await normalizePolicyDesired(change.desired, mutation.access, marker);
  await assertPolicyDesiredMatchesConfig(mutation);
  const parentId = change.action === 'create'
    ? findPolicyParent(mutation)
    : requireSafeId(change.provider.parentId);
  let parent = await assertPolicyParent(cloudflare, mutation, parentId);

  if (change.action === 'create') {
    if (!inlinePoliciesAreEmpty(parent)) fail('ownership_conflict');
    let policies = await cloudflare.listAppPolicies(parentId);
    if (!Array.isArray(policies)) fail('invalid_provider_response');
    assertEmptyPolicySet(policies, marker);
    parent = await assertPolicyParent(cloudflare, mutation, parentId);
    if (!inlinePoliciesAreEmpty(parent)) fail('ownership_conflict');
    policies = await cloudflare.listAppPolicies(parentId);
    if (!Array.isArray(policies)) fail('invalid_provider_response');
    assertEmptyPolicySet(policies, marker);
    await cloudflare.createAppPolicy(parentId, body);
    return;
  }

  const policies = await cloudflare.listAppPolicies(parentId);
  assertExpectedPolicySet(policies, change.provider.id, marker);
  assertInlinePolicySet(parent, policies);
  const live = await exactRead(
    () => cloudflare.getAppPolicy(parentId, change.provider.id),
    change.provider.id,
  );
  if (live === null) fail('ownership_conflict');
  assertMarker(live.name, marker);
  await assertCanaryPolicyIdentity(live, mutation);
  parent = await assertPolicyParent(cloudflare, mutation, parentId);
  if (POLICY_KINDS.has(change.kind)) {
    const confirmedPolicies = await cloudflare.listAppPolicies(parentId);
    const confirmedPolicy = assertExpectedPolicySet(confirmedPolicies, change.provider.id, marker);
    assertInlinePolicySet(parent, confirmedPolicies);
    await assertCanaryPolicyIdentity(confirmedPolicy, mutation);
  }
  await cloudflare.updateAppPolicy(parentId, change.provider.id, body);
}

async function assertPolicyDesiredMatchesConfig(mutation: GatewayMutation): Promise<void> {
  if (mutation.change.action === 'delete' || !POLICY_KINDS.has(mutation.change.kind)) {
    fail('invalid_input');
  }
  let desiredState: GatewayDesiredState;
  try {
    desiredState = await buildGatewayDesiredState(mutation.configInput, {
      target: mutation.target,
      access: mutation.access,
    });
  } catch {
    fail('invalid_input');
  }
  if (desiredState.blockers.some((blocker) => [
    'allowed_emails_required',
    'invalid_allowed_emails',
    'invalid_access_groups',
    'source_access_group_missing',
    'source_access_group_ambiguous',
  ].includes(blocker.code))) {
    fail('access_identity_mismatch');
  }
  if (desiredState.blockers.length > 0) fail('invalid_input');
  if ((desiredState.accessPolicy.identityType === 'service_token'
    || mutation.receipt.accessPolicy.identityType === 'service_token')
    && canonicalJson(desiredState.accessPolicy) !== canonicalJson(mutation.receipt.accessPolicy)) {
    fail('access_identity_mismatch');
  }
  const expected = desiredState.resources.find((resource) =>
    resource.kind === mutation.change.kind && resource.key === mutation.change.key);
  if (expected === undefined
    || expected.desiredHash !== mutation.change.desiredHash
    || canonicalJson(expected.desired) !== canonicalJson(mutation.change.desired)) {
    fail('invalid_input');
  }
}

async function assertCanaryPolicyIdentity(
  live: BoundaryValue,
  mutation: GatewayMutation,
): Promise<void> {
  if (mutation.receipt.accessPolicy.identityType !== 'service_token') return;
  if (!await serviceTokenPolicyMatchesDigest(live, mutation.receipt.accessPolicy.identitiesHash)) {
    fail('ownership_conflict');
  }
}

function assertInlinePolicySet(app: BoundaryObject, policies: BoundaryValue): void {
  if (!inlinePoliciesMatchListedPolicies(app, policies)) fail('ownership_conflict');
}

function assertEmptyPolicySet(policies: BoundaryValue, marker: string): void {
  if (!Array.isArray(policies)) fail('invalid_provider_response');
  if (policies.length === 0) return;
  if (policies.some((policy) => policy?.name !== marker)) fail('ownership_conflict');
  fail('resource_collision');
}

function assertExpectedPolicySet(
  policies: BoundaryValue,
  id: string,
  marker: string,
  { allowAbsent = false }: { readonly allowAbsent?: boolean } = {},
): BoundaryObject | null {
  if (!Array.isArray(policies)) fail('invalid_provider_response');
  const expected = policies.filter((policy) =>
    isObject(policy) && policy.id === id && policy.name === marker);
  const unexpected = policies.filter((policy) =>
    !isObject(policy) || policy.id !== id || policy.name !== marker);
  if (unexpected.length > 0 || expected.length > 1) fail('ownership_conflict');
  if (expected.length === 0) {
    if (allowAbsent && policies.length === 0) return null;
    fail('ownership_conflict');
  }
  const match = expected[0];
  if (match === undefined) fail('ownership_conflict');
  return match;
}

async function mutateDns(
  cloudflare: CloudflareClient,
  mutation: GatewayMutation,
): Promise<void> {
  const { change, marker, config } = mutation;
  if (change.action === 'delete') {
    const live = await exactRead(() => cloudflare.getDnsRecord(change.provider.id), change.provider.id);
    if (live === null) return;
    assertMarker(live.comment, marker);
    if (normalizeDns(live.name) !== config.gateway.hostname) fail('ownership_conflict');
    await cloudflare.deleteDnsRecord(change.provider.id);
    return;
  }
  const body = normalizeDnsDesired(change.desired, marker, config.gateway.hostname);
  const portalKey = requireResourceKey(change.desired.dependsOnResourceKey);
  if (change.action === 'create') {
    await assertDnsDependencies(cloudflare, mutation, portalKey);
    const collisions = await cloudflare.listDnsRecords({
      'name.exact': config.gateway.hostname,
      match: 'all',
    });
    if (!Array.isArray(collisions)) fail('invalid_provider_response');
    if (collisions.length > 0) fail('resource_collision');
    await assertDnsDependencies(cloudflare, mutation, portalKey);
    await cloudflare.createDnsRecord(body);
    return;
  }
  await assertDnsDependencies(cloudflare, mutation, portalKey);
  const live = await exactRead(() => cloudflare.getDnsRecord(change.provider.id), change.provider.id);
  if (live === null) fail('ownership_conflict');
  assertMarker(live.comment, marker);
  if (normalizeDns(live.name) !== config.gateway.hostname) fail('ownership_conflict');
  await assertDnsDependencies(cloudflare, mutation, portalKey);
  await cloudflare.updateDnsRecord(change.provider.id, body);
}

async function assertDnsDependencies(
  cloudflare: CloudflareClient,
  mutation: GatewayMutation,
  portalKey: string,
): Promise<void> {
  if (mutation.change.action === 'delete') fail('invalid_input');
  const mutationDesired = mutation.change.desired;
  let desiredState: GatewayDesiredState;
  try {
    desiredState = await buildGatewayDesiredState(mutation.configInput, {
      target: mutation.target,
      access: mutation.access,
    });
  } catch {
    fail('invalid_input');
  }
  const desiredDns = desiredState.resources.find((resource) =>
    resource.kind === 'dns_record' && resource.key === mutation.change.key);
  const desiredPortal = desiredState.resources.find((resource) =>
    resource.kind === 'portal' && resource.key === portalKey);
  const desiredApplication = desiredState.resources.find((resource) =>
    resource.kind === 'portal_access_application'
      && resource.desired.portalResourceKey === portalKey);
  const desiredPolicy = desiredState.resources.find((resource) =>
    resource.kind === 'portal_access_policy'
      && resource.desired.portalApplicationResourceKey === desiredApplication?.key);
  if (desiredState.installationId !== mutation.receipt.installationId
    || desiredDns === undefined
    || desiredDns.desiredHash !== mutation.change.desiredHash
    || desiredPortal === undefined
    || desiredApplication === undefined
    || desiredPolicy === undefined) fail('invalid_input');
  if (canonicalJson(desiredDns.desired) !== canonicalJson(mutationDesired)) {
    fail('invalid_input');
  }

  const receiptPortal = exactReceiptResource(mutation.receipt, desiredPortal);
  const receiptApplication = exactReceiptResource(mutation.receipt, desiredApplication);
  const receiptPolicy = exactReceiptResource(mutation.receipt, desiredPolicy);
  if (receiptPortal.provider.id !== desiredPortal.key
    || receiptPolicy.provider.parentId !== receiptApplication.provider.id
    || receiptPolicy.identityHash !== policyIdentityHash(desiredPolicy.desired)) {
    fail('ownership_conflict');
  }

  const expectedPortal = normalizePortalDesired(
    desiredPortal.desired,
    ownershipMarker(mutation.receipt.installationId, desiredPortal.key),
  );
  await assertReceiptOwnedPortal(cloudflare, mutation, desiredPortal.key, {
    expected: expectedPortal,
  });

  const expectedApplication = normalizePortalAccessApplicationDesired(
    desiredApplication.desired,
  ).body;
  const application = await exactRead(
    () => cloudflare.getAccessApp(receiptApplication.provider.id),
    receiptApplication.provider.id,
  );
  if (application === null || !portalAccessApplicationMatches(application, expectedApplication)) {
    fail('ownership_conflict');
  }
  await assertPortalAccessApplicationCandidateSet(
    cloudflare,
    expectedApplication.domain,
    expectedApplication.name,
    receiptApplication.provider.id,
  );

  const policyMarker = ownershipMarker(mutation.receipt.installationId, desiredPolicy.key);
  const policies = await cloudflare.listAppPolicies(receiptApplication.provider.id);
  assertExpectedPolicySet(policies, receiptPolicy.provider.id, policyMarker);
  if (!inlinePoliciesMatchListedPolicies(application, policies)) fail('ownership_conflict');
  const policy = await exactRead(
    () => cloudflare.getAppPolicy(receiptApplication.provider.id, receiptPolicy.provider.id),
    receiptPolicy.provider.id,
  );
  const expectedPolicy = await normalizePolicyDesired(
    desiredPolicy.desired,
    mutation.access,
    policyMarker,
  );
  if (policy === null || !accessPolicyMatches(policy, expectedPolicy)) {
    fail('ownership_conflict');
  }
}

function exactReceiptResource(
  receipt: InstallationReceipt,
  desired: DesiredResource,
): ReceiptResource {
  const matches = receipt.resources.filter((resource) =>
    resource.kind === desired.kind
      && resource.key === desired.key
      && resource.desiredHash === desired.desiredHash
      && resource.marker === ownershipMarker(receipt.installationId, desired.key));
  if (matches.length !== 1) fail('ownership_conflict');
  const match = matches[0];
  if (match === undefined) fail('ownership_conflict');
  return match;
}

function accessPolicyMatches(live: BoundaryObject, expected: PolicyBody): boolean {
  if (live.name !== expected.name || live.decision !== expected.decision
    || !Array.isArray(live.exclude) || live.exclude.length !== 0
    || !Array.isArray(live.require) || live.require.length !== 0
    || !Array.isArray(live.include) || live.include.length !== expected.include.length) {
    return false;
  }
  if (expected.decision === 'non_identity') {
    return expected.include.length === 1
      && exactServiceTokenPolicyRule(expected.include[0]) !== null
      && exactServiceTokenPolicyRule(live.include[0])
        === exactServiceTokenPolicyRule(expected.include[0]);
  }
  const expectedGroup = expected.include.length === 1
    ? extractPolicyGroup(expected.include[0])
    : null;
  if (expectedGroup !== null) {
    return live.include.length === 1
      && extractPolicyGroup(live.include[0]) === expectedGroup;
  }
  const liveEmails = live.include.map(extractPolicyEmail);
  const expectedEmails = expected.include.map(extractPolicyEmail);
  return liveEmails.every((email) => email !== null)
    && expectedEmails.every((email) => email !== null)
    && sameTextSet(
      liveEmails.map((email) => email === null ? '' : email.trim().toLowerCase()),
      expectedEmails.map((email) => email === null ? '' : email),
    );
}

function normalizeServerDesired(value: JsonObject, marker: string): ServerDesired {
  assertExactKeys(value, [
    'metadata', 'sourceId', 'name', 'endpoint', 'capabilityMode', 'secureWebGateway',
    'toolPolicy', 'authentication',
  ]);
  if (value.capabilityMode !== 'read_only' || value.secureWebGateway !== false) fail('invalid_input');
  const name = requireText(value.name);
  const endpoint = requireText(value.endpoint);
  if (name.length < 1 || name.length > 350) fail('invalid_input');
  requireHttpsUrl(endpoint);
  if (!isObject(value.toolPolicy)) fail('invalid_input');
  assertExactKeys(value.toolPolicy, ['defaultDisabled', 'allowedTools']);
  if (value.toolPolicy.defaultDisabled !== true) fail('invalid_input');
  const tools = normalizeTools(value.toolPolicy.allowedTools);
  if (!isObject(value.authentication)) fail('invalid_input');
  assertExactKeys(value.authentication, ['mode', 'onBehalfOfUser', 'credentialCustody']);
  if (value.authentication.credentialCustody !== 'customer') fail('invalid_input');
  const authType = value.authentication.mode === 'none'
    ? 'unauthenticated'
    : value.authentication.mode === 'oauth'
      ? 'oauth'
      : value.authentication.mode === 'bearer' || value.authentication.mode === 'headers'
        ? 'bearer'
        : null;
  if (!authType) fail('invalid_input');
  return {
    auth_type: authType,
    hostname: endpoint,
    name,
    description: marker,
    updated_tools: tools.map((toolName) => ({ name: toolName, enabled: true as const })),
  };
}

function normalizeSourceAccessApplicationDesired(
  value: JsonObject,
): SourceAccessApplicationDesired {
  assertExactKeys(value, ['metadata', 'sourceResourceKey', 'applicationType']);
  const sourceResourceKey = requireResourceKey(value.sourceResourceKey);
  if (value.applicationType !== 'mcp') fail('invalid_input');
  return { sourceResourceKey };
}

function normalizePortalAccessApplicationDesired(
  value: JsonObject,
): PortalAccessApplicationDesired {
  assertExactKeys(value, [
    'metadata', 'portalResourceKey', 'name', 'hostname', 'applicationType',
    'destination', 'authentication',
  ]);
  const portalResourceKey = requireResourceKey(value.portalResourceKey);
  const name = requireText(value.name);
  const hostname = requireText(value.hostname);
  if (value.applicationType !== 'mcp_portal' || name.length < 1) fail('invalid_input');
  requireHostname(hostname);
  if (!isObject(value.destination)) fail('invalid_input');
  assertExactKeys(value.destination, ['type', 'uri']);
  if (value.destination.type !== 'public' || value.destination.uri !== hostname) {
    fail('invalid_input');
  }
  if (name.length > 350 || hasControlCharacter(name)) fail('invalid_input');
  return {
    portalResourceKey,
    body: {
      name,
      type: 'mcp_portal',
      domain: hostname,
      destinations: [{ type: 'public', uri: hostname }],
      oauth_configuration: normalizeManagedOauth(value.authentication),
    },
  };
}

function normalizePortalDesired(value: JsonObject, marker: string): PortalDesired {
  assertExactKeys(value, [
    'metadata', 'name', 'hostname', 'capabilityMode', 'codeMode',
    'secureWebGateway', 'sourceMappings',
  ]);
  if (value.capabilityMode !== 'read_only' || value.secureWebGateway !== false) fail('invalid_input');
  const name = requireText(value.name);
  const hostname = requireText(value.hostname);
  if (name.length < 1 || name.length > 350) fail('invalid_input');
  requireHostname(hostname);
  const codeModeResult = v.safeParse(codeModeSchema, value.codeMode);
  if (!codeModeResult.success) fail('invalid_input');
  const codeMode = codeModeResult.output;
  if (!Array.isArray(value.sourceMappings) || value.sourceMappings.length === 0) fail('invalid_input');
  const seen = new Set<string>();
  const servers: PortalServer[] = value.sourceMappings.map((mapping) => {
    if (!isObject(mapping)) fail('invalid_input');
    assertExactKeys(mapping, ['sourceResourceKey', 'defaultDisabled', 'allowedTools', 'onBehalfOfUser']);
    const sourceResourceKey = requireResourceKey(mapping.sourceResourceKey);
    if (seen.has(sourceResourceKey)) fail('invalid_input');
    seen.add(sourceResourceKey);
    if (mapping.defaultDisabled !== true || !v.is(v.boolean(), mapping.onBehalfOfUser)) {
      fail('invalid_input');
    }
    return {
      server_id: sourceResourceKey,
      default_disabled: true as const,
      on_behalf: mapping.onBehalfOfUser,
      updated_prompts: [],
      updated_tools: normalizeTools(mapping.allowedTools)
        .map((toolName) => ({ name: toolName, enabled: true as const })),
    };
  });
  return {
    hostname,
    name,
    code_mode: codeMode,
    description: marker,
    secure_web_gateway: false,
    servers,
  };
}

async function normalizePolicyDesired(
  value: JsonObject,
  access: BoundaryValue,
  marker: string,
): Promise<PolicyBody> {
  assertExactKeys(value, value.portalApplicationResourceKey === undefined
    ? ['metadata', 'sourceApplicationResourceKey', 'defaultAction', 'allow']
    : ['metadata', 'portalApplicationResourceKey', 'defaultAction', 'allow']);
  const parentKey = value.sourceApplicationResourceKey ?? value.portalApplicationResourceKey;
  requireResourceKey(parentKey);
  if (value.defaultAction !== 'deny' || !isObject(value.allow)) {
    fail('invalid_input');
  }
  assertExactKeys(value.allow, ['identitiesRef', 'identityType', 'identityCount', 'identitiesHash']);
  if (!v.is(numberSchema, value.allow.identityCount)
    || !v.is(stringSchema, value.allow.identitiesHash)) fail('access_identity_mismatch');

  let include: PolicyIncludeRule[];
  let decision: PolicyBody['decision'] = 'allow';
  if (value.allow.identitiesRef === 'access.allowedEmails'
    && value.allow.identityType === 'email') {
    const emails = normalizeEmails(access);
    if (emails.length !== value.allow.identityCount) fail('access_identity_mismatch');
    const hash = await hashCanonical({ emails });
    if (hash !== value.allow.identitiesHash) fail('access_identity_mismatch');
    include = emails.map((email) => ({ email: { email } }));
  } else if (value.allow.identitiesRef === 'access.groups'
    && value.allow.identityType === 'group') {
    const group = await resolveAccessGroupByDigest(
      access,
      value.allow.identityCount,
      value.allow.identitiesHash,
    );
    if (group === null) fail('access_identity_mismatch');
    include = [{ group: { id: group.id } }];
  } else if (value.allow.identitiesRef === 'access.canaryServiceTokenId'
    && value.allow.identityType === 'service_token') {
    let id: string | null;
    try {
      id = canaryServiceTokenId(access);
    } catch {
      fail('access_identity_mismatch');
    }
    if (id === null || value.allow.identityCount !== 1
      || await canaryServiceIdentityDigest(id) !== value.allow.identitiesHash) {
      fail('access_identity_mismatch');
    }
    decision = 'non_identity';
    include = [{ service_token: { token_id: id } }];
  } else {
    fail('invalid_input');
  }
  return {
    name: marker,
    decision,
    include,
    exclude: [],
    require: [],
  };
}

function normalizeDnsDesired(
  value: JsonObject,
  marker: string,
  hostname: string,
) {
  assertExactKeys(value, [
    'metadata', 'recordType', 'hostname', 'content', 'proxied', 'dependsOnResourceKey',
  ]);
  if (value.recordType !== 'CNAME'
    || value.hostname !== hostname
    || value.content !== PORTAL_CNAME_TARGET
    || value.proxied !== true
    || !safeResourceKey(value.dependsOnResourceKey)) fail('invalid_input');
  return {
    type: 'CNAME',
    name: hostname,
    content: PORTAL_CNAME_TARGET,
    proxied: true,
    ttl: 1,
    comment: marker,
  };
}

function findPolicyParent(mutation: GatewayMutation): string {
  if (mutation.change.kind === 'source_access_policy') {
    const applicationKey = requireResourceKey(
      mutation.change.desired?.sourceApplicationResourceKey,
    );
    const matches = mutation.receipt.resources.filter((resource) =>
      resource.kind === 'source_access_application' && resource.key === applicationKey);
    if (matches.length !== 1) fail('ownership_conflict');
    const match = matches[0];
    if (match === undefined) fail('ownership_conflict');
    return match.provider.id;
  }
  const applicationKey = requireResourceKey(
    mutation.change.desired?.portalApplicationResourceKey,
  );
  const matches = mutation.receipt.resources.filter((resource) =>
    resource.kind === 'portal_access_application' && resource.key === applicationKey);
  if (matches.length !== 1) fail('ownership_conflict');
  const match = matches[0];
  if (match === undefined) fail('ownership_conflict');
  return match.provider.id;
}

async function assertPolicyParent(
  cloudflare: CloudflareClient,
  mutation: GatewayMutation,
  parentId: string,
): Promise<BoundaryObject> {
  const app = await exactRead(() => cloudflare.getAccessApp(parentId), parentId);
  if (app === null) fail('access_app_missing');
  if (mutation.change.kind === 'portal_access_policy') {
    const desiredApplicationKey = optionalResourceKey(
      mutation.change.desired?.portalApplicationResourceKey,
    );
    const receiptApplications = mutation.receipt.resources.filter((resource) =>
      resource.kind === 'portal_access_application'
      && (!desiredApplicationKey || resource.key === desiredApplicationKey)
      && resource.provider.id === parentId);
    if (receiptApplications.length !== 1) fail('ownership_conflict');
    const receiptApplication = receiptApplications[0];
    if (receiptApplication === undefined) fail('ownership_conflict');
    await assertPortalAccessApplicationAuthority(
      cloudflare,
      mutation,
      app,
      ownershipMarker(mutation.receipt.installationId, receiptApplication.key),
      {
        allowMissingPortal: mutation.change.action === 'delete',
        requireDesired: true,
      },
    );
    return app;
  }
  const desiredApplicationKey = optionalResourceKey(
    mutation.change.desired?.sourceApplicationResourceKey,
  );
  const receiptApplications = mutation.receipt.resources.filter((resource) =>
    resource.kind === 'source_access_application'
    && (!desiredApplicationKey || resource.key === desiredApplicationKey)
    && resource.provider.id === parentId);
  if (receiptApplications.length !== 1) fail('ownership_conflict');
  const receiptApplication = receiptApplications[0];
  if (receiptApplication === undefined) fail('ownership_conflict');
  await assertSourceAccessApplicationAuthority(
    cloudflare,
    mutation,
    app,
    ownershipMarker(mutation.receipt.installationId, receiptApplication.key),
    { allowMissingServer: mutation.change.action === 'delete' },
  );
  return app;
}

async function assertReceiptOwnedServer(
  cloudflare: CloudflareClient,
  mutation: GatewayMutation,
  serverKey: string,
): Promise<ReceiptResource> {
  const servers = mutation.receipt.resources.filter((resource) =>
    resource.kind === 'mcp_server'
    && resource.key === serverKey
    && resource.provider.id === serverKey);
  if (servers.length !== 1) fail('ownership_conflict');
  const server = servers[0];
  if (server === undefined) fail('ownership_conflict');
  const live = await exactRead(
    () => cloudflare.getMcpServer(server.provider.id),
    server.provider.id,
  );
  if (live === null
    || live.description !== ownershipMarker(mutation.receipt.installationId, server.key)) {
    fail('ownership_conflict');
  }
  return server;
}

async function assertSourceAccessApplicationAuthority(
  cloudflare: CloudflareClient,
  mutation: GatewayMutation,
  app: BoundaryObject,
  marker: string,
  { allowMissingServer = false }: { readonly allowMissingServer?: boolean } = {},
): Promise<ReceiptResource | null> {
  if (app?.name !== marker || app?.type !== 'mcp' || !sourceAppHasNoDomain(app)
    || !Array.isArray(app.destinations)
    || app.destinations.length !== 1) fail('ownership_conflict');
  const destination = app.destinations[0];
  if (!isObject(destination)
    || Object.keys(destination).sort().join(',') !== 'mcp_server_id,type'
    || destination.type !== 'via_mcp_server_portal'
    || !safeId(destination.mcp_server_id)) {
    fail('ownership_conflict');
  }
  const serverId = destination.mcp_server_id;
  const servers = mutation.receipt.resources.filter((resource) =>
    resource.kind === 'mcp_server'
    && resource.provider.id === serverId
    && resource.provider.id === resource.key);
  if (servers.length === 1) {
    const server = servers[0];
    if (server === undefined) fail('ownership_conflict');
    const live = await exactRead(
      () => cloudflare.getMcpServer(server.provider.id),
      server.provider.id,
    );
    if (live === null) {
      if (allowMissingServer) return server;
      fail('ownership_conflict');
    }
    if (live.description !== ownershipMarker(mutation.receipt.installationId, server.key)) {
      fail('ownership_conflict');
    }
    return server;
  }
  if (allowMissingServer && servers.length === 0) {
    const live = await exactRead(
      () => cloudflare.getMcpServer(serverId),
      serverId,
    );
    if (live === null) return null;
  }
  fail('ownership_conflict');
}

async function expectedPortalForApplicationMutation(
  mutation: GatewayMutation,
  portalKey: string,
): Promise<PortalDesired> {
  if (mutation.change.action === 'delete') fail('invalid_input');
  const mutationDesired = mutation.change.desired;
  let desiredState: GatewayDesiredState;
  try {
    desiredState = await buildGatewayDesiredState(mutation.configInput, {
      target: mutation.target,
      access: mutation.access,
    });
  } catch {
    fail('invalid_input');
  }
  const application = desiredState.resources.find((resource) =>
    resource.kind === 'portal_access_application' && resource.key === mutation.change.key);
  const portal = desiredState.resources.find((resource) =>
    resource.kind === 'portal' && resource.key === portalKey);
  if (desiredState.installationId !== mutation.receipt.installationId
    || application === undefined
    || application.desiredHash !== mutation.change.desiredHash
    || portal === undefined) fail('invalid_input');
  if (canonicalJson(application.desired) !== canonicalJson(mutationDesired)) {
    fail('invalid_input');
  }
  const receiptPortals = mutation.receipt.resources.filter((resource) =>
    resource.kind === 'portal'
      && resource.key === portal.key
      && resource.provider.id === portal.key
      && resource.desiredHash === portal.desiredHash
      && resource.marker === ownershipMarker(mutation.receipt.installationId, portal.key));
  if (receiptPortals.length !== 1) fail('invalid_input');
  return normalizePortalDesired(
    portal.desired,
    ownershipMarker(mutation.receipt.installationId, portal.key),
  );
}

async function assertReceiptOwnedPortal(
  cloudflare: CloudflareClient,
  mutation: GatewayMutation,
  portalKey: string,
  {
    allowMissing = false,
    expected,
  }: { readonly allowMissing?: boolean; readonly expected?: PortalDesired } = {},
): Promise<ReceiptResource> {
  const portals = mutation.receipt.resources.filter((resource) =>
    resource.kind === 'portal'
    && resource.key === portalKey
    && resource.provider.id === resource.key);
  if (portals.length !== 1) fail('ownership_conflict');
  const portal = portals[0];
  if (portal === undefined) fail('ownership_conflict');
  const live = await exactRead(() => cloudflare.getPortal(portal.provider.id), portal.provider.id);
  if (live === null) {
    if (allowMissing) return portal;
    fail('ownership_conflict');
  }
  if (live.description !== ownershipMarker(mutation.receipt.installationId, portal.key)
    || live.hostname !== mutation.config.gateway.hostname) fail('ownership_conflict');
  if (expected && !portalMatchesExpected(live, portal.provider.id, expected)) {
    fail('ownership_conflict');
  }
  return portal;
}

async function assertPortalAccessApplicationAuthority(
  cloudflare: CloudflareClient,
  mutation: GatewayMutation,
  app: BoundaryObject,
  _marker: string,
  {
    allowMissingPortal = false,
    requireDesired = false,
  }: { readonly allowMissingPortal?: boolean; readonly requireDesired?: boolean } = {},
): Promise<ReceiptResource> {
  if (app?.name !== mutation.config.gateway.name
    || !portalAccessApplicationContractMatches(app, mutation.config.gateway.hostname)
    || (requireDesired && !managedOauthMatches(
      app.oauth_configuration,
      expectedManagedOauthConfiguration(),
    ))) fail('ownership_conflict');
  const applications = mutation.receipt.resources.filter((resource) =>
    resource.kind === 'portal_access_application'
    && resource.provider.id === app.id);
  if (applications.length !== 1) fail('ownership_conflict');
  const portals = mutation.receipt.resources.filter((resource) => resource.kind === 'portal');
  if (portals.length !== 1) fail('ownership_conflict');
  const portal = portals[0];
  const application = applications[0];
  if (portal === undefined || application === undefined) fail('ownership_conflict');
  await assertReceiptOwnedPortal(cloudflare, mutation, portal.key, {
    allowMissing: allowMissingPortal,
  });
  return application;
}

async function assertPortalAccessApplicationCandidateSet(
  cloudflare: CloudflareClient,
  hostname: string,
  expectedName: string,
  expectedId: string,
  { allowAbsent = false }: { readonly allowAbsent?: boolean } = {},
): Promise<void> {
  const apps = await cloudflare.listAccessApps();
  if (!Array.isArray(apps)) fail('invalid_provider_response');
  const matches = apps
    .filter((app) => (isObject(app) && app.name === expectedName)
      || isPortalAppCandidate(app, hostname))
    .map(requireAppId);
  if (allowAbsent) {
    if (matches.length !== 0) fail('ownership_conflict');
    return;
  }
  const match = matches[0];
  if (matches.length !== 1 || match === undefined || match.id !== expectedId) {
    fail('ownership_conflict');
  }
}

function assertPortalApplicationReceiptAbsent(receipt: InstallationReceipt): void {
  if (receipt.resources.some((resource) => resource.kind === 'portal_access_application')) {
    fail('ownership_conflict');
  }
}

async function assertNoPortalAccessApplications(
  cloudflare: CloudflareClient,
  hostname: string,
): Promise<void> {
  const apps = await cloudflare.listAccessApps();
  if (!Array.isArray(apps)) fail('invalid_provider_response');
  if (apps.some((app) => isPortalAppCandidate(app, hostname))) fail('ownership_conflict');
}

async function provePortalAccessApplicationBaselineQuiet(
  cloudflare: CloudflareClient,
  polling: PollingOptions,
  hostname: string,
): Promise<void> {
  for (let attempt = 0; attempt < polling.attempts; attempt += 1) {
    const apps = await cloudflare.listAccessApps();
    if (!Array.isArray(apps)) fail('invalid_provider_response');
    if (apps.some((app) => isPortalAppCandidate(app, hostname))) fail('resource_collision');
    if (attempt + 1 < polling.attempts) await polling.delayImpl(polling.intervalMs);
  }
}

async function assertAccessApplicationPoliciesEmpty(
  cloudflare: CloudflareClient,
  app: BoundaryObject,
): Promise<void> {
  const policies = await cloudflare.listAppPolicies(requireSafeId(app.id));
  if (!Array.isArray(policies)) fail('invalid_provider_response');
  if (policies.length > 0
    || (Object.hasOwn(app, 'policies')
      && (!Array.isArray(app.policies) || app.policies.length > 0))) {
    fail('ownership_conflict');
  }
}

async function assertPortalAccessApplicationPolicyPhase(
  cloudflare: CloudflareClient,
  mutation: GatewayMutation,
  app: BoundaryObject,
): Promise<void> {
  const appId = requireSafeId(app.id);
  const policies = await cloudflare.listAppPolicies(appId);
  if (!Array.isArray(policies)) fail('invalid_provider_response');
  const ownedPolicies = mutation.receipt.resources.filter((resource) =>
    resource.kind === 'portal_access_policy'
      && resource.provider.parentId === appId);
  if (ownedPolicies.length === 0) {
    if (policies.length > 0 || !inlinePoliciesAreEmpty(app)) fail('ownership_conflict');
    return;
  }
  if (ownedPolicies.length !== 1) fail('ownership_conflict');
  const ownedPolicy = ownedPolicies[0];
  if (ownedPolicy === undefined) fail('ownership_conflict');
  const marker = ownershipMarker(mutation.receipt.installationId, ownedPolicy.key);
  if (ownedPolicy.marker !== marker) fail('ownership_conflict');
  assertExpectedPolicySet(policies, ownedPolicy.provider.id, marker);
  if (!inlinePoliciesMatchListedPolicies(app, policies)) fail('ownership_conflict');
}

async function assertNoAccessAppBaseline(
  cloudflare: CloudflareClient,
  predicate: (app: BoundaryValue) => boolean,
): Promise<void> {
  const apps = await cloudflare.listAccessApps();
  if (!Array.isArray(apps)) fail('invalid_provider_response');
  const matches = apps.filter(predicate).map(requireAppId);
  if (matches.length > 0) fail('resource_collision');
}

async function assertNoServerAccessApplications(
  cloudflare: CloudflareClient,
  serverId: string,
): Promise<void> {
  const apps = await cloudflare.listAccessApps();
  if (!Array.isArray(apps)) fail('invalid_provider_response');
  if (apps.some((app) => isExactServerApp(app, serverId))) fail('ownership_conflict');
}

function normalizeManagedOauth(value: BoundaryValue): ManagedOauth {
  if (!isObject(value)) fail('invalid_input');
  assertExactKeys(value, ['mode', 'dynamicClientRegistration', 'grant']);
  if (value.mode !== 'managed_oauth'
    || !isObject(value.dynamicClientRegistration)
    || !isObject(value.grant)) fail('invalid_input');
  assertExactKeys(value.dynamicClientRegistration, [
    'enabled', 'allowAnyOnLocalhost', 'allowAnyOnLoopback',
  ]);
  assertExactKeys(value.grant, ['accessTokenLifetime', 'sessionDuration']);
  if (value.dynamicClientRegistration.enabled !== true
    || value.dynamicClientRegistration.allowAnyOnLocalhost !== true
    || value.dynamicClientRegistration.allowAnyOnLoopback !== true
    || value.grant.accessTokenLifetime !== '15m'
    || value.grant.sessionDuration !== '336h') fail('invalid_input');
  return {
    enabled: true,
    dynamic_client_registration: {
      enabled: true,
      allowed_uris: [CLAUDE_OAUTH_CALLBACK],
      allow_any_on_localhost: true,
      allow_any_on_loopback: true,
    },
    grant: { access_token_lifetime: '15m', session_duration: '336h' },
  };
}

function managedOauthMatches(live: BoundaryValue, desired: ManagedOauth): boolean {
  // Callback defaults are applied on writes, outside retained receipt hashes.
  // Older Portals remain recognizable without silently changing their clients.
  if (!isObject(live)
    || !isObject(live.dynamic_client_registration)
    || !isObject(live.grant)) return false;
  return live.enabled === desired.enabled
    && live.dynamic_client_registration.enabled === desired.dynamic_client_registration.enabled
    && live.dynamic_client_registration.allow_any_on_localhost === desired.dynamic_client_registration.allow_any_on_localhost
    && live.dynamic_client_registration.allow_any_on_loopback === desired.dynamic_client_registration.allow_any_on_loopback
    && live.grant.access_token_lifetime === desired.grant.access_token_lifetime
    && live.grant.session_duration === desired.grant.session_duration;
}

async function waitForServerSync(
  cloudflare: CloudflareClient,
  polling: PollingOptions,
  serverId: string,
  expectedTools: readonly PortalTool[],
): Promise<void> {
  for (let attempt = 0; attempt < polling.attempts; attempt += 1) {
    const server = await exactRead(() => cloudflare.getMcpServer(serverId), serverId);
    if (server === null) fail('sync_failed');
    if (server.status === 'ready' && expectedToolsDiscovered(server.tools, expectedTools)) return;
    if (server.status === 'error') fail('sync_failed');
    if (attempt + 1 < polling.attempts) await polling.delayImpl(polling.intervalMs);
  }
  fail('sync_timeout');
}

async function waitForAccessAppAbsence(
  cloudflare: CloudflareClient,
  polling: PollingOptions,
  appId: string,
): Promise<void> {
  if (!safeId(appId)) fail('ownership_conflict');
  for (let attempt = 0; attempt < polling.attempts; attempt += 1) {
    const app = await exactRead(() => cloudflare.getAccessApp(appId), appId);
    if (app === null) return;
    if (attempt + 1 < polling.attempts) await polling.delayImpl(polling.intervalMs);
  }
  fail('sync_timeout');
}

async function inspectResidue(
  cloudflare: CloudflareClient,
  input: ResidueInspectionInput,
  boundTarget: BoundTarget,
): Promise<Readonly<{ ownedResourceCount: number }>> {
  rejectMutationKeys(input, ['config', 'target', 'receipt', 'signal']);
  const receipt = await validateReceipt(input.receipt);
  assertTarget(input.target, boundTarget, receipt.target);
  const config = normalizeGatewayConfig(input.config);
  if (config.gateway.hostname !== receipt.target.hostname) fail('invalid_input');
  let ownedResourceCount = 0;
  const liveReceiptPortalApplicationIds = new Set<string>();
  for (const resource of receipt.resources) {
    let live: BoundaryObject | null;
    if (resource.kind === 'mcp_server') live = await exactRead(() => cloudflare.getMcpServer(resource.provider.id), resource.provider.id);
    else if (resource.kind === 'source_access_application'
      || resource.kind === 'portal_access_application') {
      live = await exactRead(() => cloudflare.getAccessApp(resource.provider.id), resource.provider.id);
    }
    else if (resource.kind === 'portal') live = await exactRead(() => cloudflare.getPortal(resource.provider.id), resource.provider.id);
    else if (resource.kind === 'dns_record') live = await exactRead(() => cloudflare.getDnsRecord(resource.provider.id), resource.provider.id);
    else {
      const parentId = requireSafeId(resource.provider.parentId);
      live = await exactRead(
        () => cloudflare.getAppPolicy(parentId, resource.provider.id),
        resource.provider.id,
      );
    }
    // Receipt locators are exact existence evidence. Shape and marker checks gate
    // mutations, but must not make live residue disappear from uninstall proof.
    if (live !== null) {
      ownedResourceCount += 1;
      if (resource.kind === 'portal_access_application') {
        liveReceiptPortalApplicationIds.add(resource.provider.id);
      }
    }
  }

  const apps = await cloudflare.listAccessApps();
  if (!Array.isArray(apps)) fail('invalid_provider_response');
  const countedBroadIds = new Set<string>(liveReceiptPortalApplicationIds);
  for (const candidate of apps.filter((app) =>
    isPortalAppCandidate(app, config.gateway.hostname))) {
    const app = requireAppId(candidate);
    if (!countedBroadIds.has(app.id)) {
      countedBroadIds.add(app.id);
      ownedResourceCount += 1;
    }
  }
  return Object.freeze({ ownedResourceCount });
}

async function exactRead(
  reader: () => Promise<BoundaryValue>,
  expectedId: string,
): Promise<BoundaryObject | null> {
  const value = await reader();
  if (value === null) return null;
  if (!isObject(value) || value.id !== expectedId) fail('invalid_provider_response');
  return value;
}

function isExactServerApp(app: BoundaryValue, serverId: string): boolean {
  return safeId(serverId)
    && isObject(app)
    && app.type === 'mcp'
    && Array.isArray(app.destinations)
    && app.destinations.some((destination) =>
      isObject(destination)
      && destination.type === 'via_mcp_server_portal'
      && destination.mcp_server_id === serverId);
}

function isExactSourceAccessApplication(
  app: BoundaryValue,
  serverId: string,
  marker: string,
): boolean {
  if (!isObject(app)
    || app.name !== marker || app.type !== 'mcp' || !sourceAppHasNoDomain(app)
    || !Array.isArray(app.destinations) || app.destinations.length !== 1) return false;
  const destination = app.destinations[0];
  return isObject(destination)
    && Object.keys(destination).sort().join(',') === 'mcp_server_id,type'
    && destination.type === 'via_mcp_server_portal'
    && destination.mcp_server_id === serverId;
}

function sourceAppHasNoDomain(app: BoundaryObject): boolean {
  return app?.domain === undefined || app.domain === null;
}

function portalAccessApplicationMatches(
  app: BoundaryValue,
  expected: PortalAccessApplicationBody,
): boolean {
  return isObject(app)
    && app.name === expected.name
    && portalAccessApplicationContractMatches(app, expected.domain)
    && managedOauthMatches(app.oauth_configuration, expected.oauth_configuration);
}

function portalAccessApplicationPrePolicyMatches(
  app: BoundaryValue,
  expected: PortalAccessApplicationBody,
): boolean {
  return isObject(app)
    && portalAccessApplicationMatches(app, expected)
    && inlinePoliciesAreEmpty(app);
}

function portalAccessApplicationContractMatches(app: BoundaryValue, hostname: string): boolean {
  if (!isObject(app) || app.type !== 'mcp_portal' || app.domain !== hostname
    || !Array.isArray(app.destinations) || app.destinations.length !== 1) return false;
  const destination = app.destinations[0];
  return isObject(destination)
    && Object.keys(destination).sort().join(',') === 'type,uri'
    && destination.type === 'public'
    && destination.uri === hostname;
}

function inlinePoliciesAreEmpty(app: BoundaryObject): boolean {
  return !Object.hasOwn(app, 'policies')
    || (Array.isArray(app.policies) && app.policies.length === 0);
}

function inlinePoliciesMatchListedPolicies(
  app: BoundaryObject,
  policies: BoundaryValue,
): boolean {
  if (!Array.isArray(policies)) return false;
  if (!Object.hasOwn(app, 'policies')
    || (Array.isArray(app.policies) && app.policies.length === 0)) return true;
  if (!Array.isArray(app.policies) || app.policies.length !== policies.length) return false;

  const listedById = new Map<string, BoundaryObject>();
  for (const policy of policies) {
    if (!isObject(policy)) return false;
    if (!safeId(policy.id)) return false;
    const id = policy.id;
    if (listedById.has(id)) return false;
    listedById.set(id, policy);
  }
  const seen = new Set<string>();
  for (const inlinePolicy of app.policies) {
    const rawId = v.is(stringSchema, inlinePolicy)
      ? inlinePolicy
      : isObject(inlinePolicy) ? inlinePolicy.id : undefined;
    if (!safeId(rawId)) return false;
    const id = rawId;
    if (seen.has(id) || !listedById.has(id)) return false;
    if (isObject(inlinePolicy)
      && Object.hasOwn(inlinePolicy, 'name')
      && inlinePolicy.name !== listedById.get(id)?.name) return false;
    seen.add(id);
  }
  return seen.size === listedById.size;
}

function expectedManagedOauthConfiguration(): ManagedOauth {
  return {
    enabled: true,
    dynamic_client_registration: {
      enabled: true,
      allowed_uris: [CLAUDE_OAUTH_CALLBACK],
      allow_any_on_localhost: true,
      allow_any_on_loopback: true,
    },
    grant: { access_token_lifetime: '15m', session_duration: '336h' },
  };
}

function isPortalAppCandidate(app: BoundaryValue, hostname: string): boolean {
  return isObject(app) && app.type === 'mcp_portal' && (
    app.domain === hostname ||
    (Array.isArray(app.destinations) && app.destinations.some((destination) =>
      isObject(destination)
      && destination.type === 'public'
      && destination.uri === hostname))
  );
}

function requireAppId(app: BoundaryValue): Readonly<{ id: string }> {
  if (!isObject(app) || !safeId(app.id)) fail('invalid_provider_response');
  return Object.freeze({ id: app.id });
}

async function validateReceipt(value: BoundaryValue): Promise<InstallationReceipt> {
  try {
    return await validateInstallationReceipt(value);
  } catch {
    fail('invalid_input');
  }
}

function assertTarget(
  target: BoundaryValue,
  bound: BoundTarget,
  receiptTarget: ReceiptTarget,
): void {
  if (!isObject(target)
    || target.accountId !== bound.accountId
    || target.zoneId !== bound.zoneId
    || receiptTarget.accountId !== bound.accountId
    || receiptTarget.zoneId !== bound.zoneId) fail('target_mismatch');
}

function assertDesiredMetadata(desired: JsonObject, installationId: string): void {
  if (!isObject(desired.metadata)) fail('invalid_input');
  assertExactKeys(desired.metadata, ['manager', 'installationId']);
  if (desired.metadata.manager !== 'ankka-mcp-gateway'
    || desired.metadata.installationId !== installationId) fail('invalid_input');
}

function normalizeProviderLocator(
  kind: ResourceKind,
  provider: BoundaryValue,
): ReceiptProviderLocator {
  if (!isObject(provider) || !safeId(provider.id)) fail('invalid_input');
  const expected = POLICY_KINDS.has(kind) ? ['id', 'parentId'] : ['id'];
  assertExactKeys(provider, expected);
  if (POLICY_KINDS.has(kind) && !safeId(provider.parentId)) fail('invalid_input');
  if (POLICY_KINDS.has(kind)) {
    return Object.freeze({ id: provider.id, parentId: requireSafeId(provider.parentId) });
  }
  return Object.freeze({ id: provider.id });
}

function assertMarker(actual: BoundaryValue, expected: string): void {
  if (actual !== expected) fail('ownership_conflict');
}

function normalizeEmails(access: BoundaryValue): string[] {
  if (!isObject(access) || !Array.isArray(access.allowedEmails)) fail('access_identity_mismatch');
  const values: string[] = [];
  for (const raw of access.allowedEmails) {
    if (!v.is(stringSchema, raw)) fail('access_identity_mismatch');
    const email = raw.trim().toLowerCase();
    if (email.length === 0 || email.length > 254 || !EMAIL.test(email)) fail('access_identity_mismatch');
    values.push(email);
  }
  return [...new Set(values)].sort(compareText);
}

function normalizeTools(value: BoundaryValue): string[] {
  if (!Array.isArray(value)
    || value.length === 0
    || value.length > MAX_ENABLED_TOOLS_PER_SOURCE) fail('invalid_input');
  const tools: string[] = [];
  for (const tool of value) {
    if (!v.is(stringSchema, tool)
      || tool.length === 0
      || tool.length > 128
      || tool === '*'
      || tools.includes(tool)) {
      fail('invalid_input');
    }
    tools.push(tool);
  }
  return [...tools].sort(compareText);
}

function expectedToolsDiscovered(
  tools: BoundaryValue,
  expectedTools: readonly { readonly name: string }[],
): boolean {
  if (!Array.isArray(tools)) return false;
  const names: string[] = [];
  for (const tool of tools) {
    if (!isObject(tool) || !v.is(stringSchema, tool.name) || names.includes(tool.name)) return false;
    names.push(tool.name);
  }
  return expectedTools.every(({ name }) => names.includes(name));
}

function normalizeAbortSignal(value: AbortSignal | undefined): AbortSignal | undefined {
  if (value === undefined) return undefined;
  if (!(value instanceof AbortSignal)) fail('invalid_input');
  return value;
}

function requireHttpsUrl(value: BoundaryValue): void {
  if (!v.is(stringSchema, value)) fail('invalid_input');
  try {
    const url = new URL(value);
    if (url.protocol !== 'https:' || url.username || url.password) fail('invalid_input');
  } catch (error) {
    if (error instanceof CloudflareGatewayProviderError) throw error;
    fail('invalid_input');
  }
}

function requireHostname(value: BoundaryValue): void {
  if (!v.is(stringSchema, value) || value !== value.toLowerCase() || value.length > 253
    || value.split('.').length < 2
    || !value.split('.').every((label) => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label))) {
    fail('invalid_input');
  }
}

function requireId(value: BoundaryValue): void {
  if (!safeId(value)) throw new TypeError('accountId and zoneId must be non-empty identifiers');
}

function safeId(value: BoundaryValue): value is string {
  return v.is(stringSchema, value) && SAFE_ID.test(value);
}

function requireSafeId(value: BoundaryValue): string {
  if (!safeId(value)) fail('invalid_input');
  return value;
}

function requireText(value: BoundaryValue): string {
  if (!v.is(stringSchema, value)) fail('invalid_input');
  return value;
}

function safeResourceKey(value: BoundaryValue): value is string {
  return v.is(stringSchema, value) && RESOURCE_KEY.test(value);
}

function requireResourceKey(value: BoundaryValue): string {
  if (!safeResourceKey(value)) fail('invalid_input');
  return value;
}

function optionalResourceKey(value: BoundaryValue): string | undefined {
  return value === undefined ? undefined : requireResourceKey(value);
}

function policyIdentityHash(value: JsonObject): string {
  if (!isObject(value.allow) || !v.is(stringSchema, value.allow.identitiesHash)) {
    fail('invalid_input');
  }
  return value.allow.identitiesHash;
}

function extractPolicyEmail(rule: BoundaryValue): string | null {
  if (!isObject(rule)
    || !hasExactObjectKeys(rule, ['email'])
    || !isObject(rule.email)
    || !hasExactObjectKeys(rule.email, ['email'])
    || !v.is(stringSchema, rule.email.email)) {
    return null;
  }
  return rule.email.email;
}

function extractPolicyGroup(rule: BoundaryValue): string | null {
  if (!isObject(rule)
    || !hasExactObjectKeys(rule, ['group'])
    || !isObject(rule.group)
    || !hasExactObjectKeys(rule.group, ['id'])
    || !safeId(rule.group.id)) {
    return null;
  }
  return rule.group.id;
}

function hasExactObjectKeys(value: BoundaryObject, expected: readonly string[]): boolean {
  const actual = Object.keys(value).sort(compareText);
  const sortedExpected = [...expected].sort(compareText);
  return actual.length === sortedExpected.length
    && actual.every((key, index) => key === sortedExpected[index]);
}

function hasControlCharacter(value: string): boolean {
  for (const character of value) {
    const codePoint = character.codePointAt(0);
    if (codePoint !== undefined && (codePoint <= 31 || codePoint === 127)) return true;
  }
  return false;
}

function normalizeGatewayConfig(value: BoundaryValue): GatewayConfig {
  try {
    return validateGatewayConfig(v.parse(jsonValueSchema, value));
  } catch {
    fail('invalid_input');
  }
}

function normalizeDns(value: BoundaryValue): string {
  return v.is(stringSchema, value) ? value.toLowerCase().replace(/\.$/, '') : '';
}

function sameLocator(left: ReceiptProviderLocator, right: ReceiptProviderLocator): boolean {
  return left?.id === right?.id && (left?.parentId ?? '') === (right?.parentId ?? '');
}

type KeyBearingInput = BoundaryObject | CloudflareGatewayProviderOptions | ResidueInspectionInput;
type ObjectCandidate = BoundaryValue
  | MutationResult
  | ResidueInspectionInput;

function rejectUnknownKeys(value: KeyBearingInput, allowed: readonly string[]): void {
  if (Object.keys(value).some((key) => !allowed.includes(key))) {
    throw new TypeError('provider options contain unsupported fields');
  }
}

function rejectMutationKeys(value: KeyBearingInput, allowed: readonly string[]): void {
  if (Object.keys(value).some((key) => !allowed.includes(key))) fail('invalid_input');
}

function assertExactKeys(value: BoundaryValue, expected: readonly string[]): void {
  if (!isObject(value)) fail('invalid_input');
  const actual = Object.keys(value).sort(compareText);
  const sortedExpected = [...expected].sort(compareText);
  if (actual.length !== sortedExpected.length
    || actual.some((key, index) => key !== sortedExpected[index])) fail('invalid_input');
}

async function hashCanonical(value: JsonValue): Promise<string> {
  const bytes = new TextEncoder().encode(canonicalJson(value));
  const digest = await globalThis.crypto.subtle.digest('SHA-256', bytes);
  return `sha256:${[...new Uint8Array(digest)]
    .map((byte) => byte.toString(16).padStart(2, '0'))
    .join('')}`;
}

function canonicalJson(value: JsonValue): string {
  if (value === null || v.is(v.union([v.boolean(), v.string()]), value)) {
    return JSON.stringify(value);
  }
  if (v.is(numberSchema, value) && Number.isFinite(value)) return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (isObject(value)) return `{${Object.entries(value).sort(([left], [right]) =>
    compareText(left, right))
    .map(([key, nested]) => `${JSON.stringify(key)}:${canonicalJson(nested)}`).join(',')}}`;
  fail('invalid_input');
}

function defaultDelay(milliseconds: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

function compareText(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function isObject(value: ObjectCandidate): value is BoundaryObject {
  return v.is(boundaryObjectSchema, value);
}

function isResidueInspectionInput(
  value: BoundaryValue | ResidueInspectionInput,
): value is ResidueInspectionInput {
  return v.is(v.object({}), value);
}

function fail(code: string): never {
  throw new CloudflareGatewayProviderError(code);
}

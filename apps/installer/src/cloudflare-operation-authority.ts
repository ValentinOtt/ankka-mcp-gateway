/**
 * Fixed Cloudflare OAuth authority catalogue for the two-stage installer.
 *
 * This file is intentionally independent from release manifests and request
 * input. A signed release may require fewer permissions, but it cannot add a
 * permission, endpoint family, mutation, or operation at runtime.
 */

export const CLOUDFLARE_OAUTH_SCOPE = Object.freeze({
  accessAccountRead: 'access-acct.read',
  accessAppsAndPoliciesWrite: 'zone-access.write',
  dnsWrite: 'dns.write',
  mcpPortalsWrite: 'mcp-portals.write',
  workersRoutesRead: 'workers-routes.read',
  workersScriptsWrite: 'workers-scripts.write',
  zoneRead: 'zone.read',
} as const);

export type CloudflareOauthScope =
  (typeof CLOUDFLARE_OAUTH_SCOPE)[keyof typeof CLOUDFLARE_OAUTH_SCOPE];

export const FIXED_CLOUDFLARE_OPERATIONS = Object.freeze([
  'bootstrap',
  'install',
  'upgrade',
  'rollback',
  'source-add',
  'source-update',
  'source-remove',
  'uninstall',
  'uninstall-finalize',
] as const);

export type FixedCloudflareOperation = (typeof FIXED_CLOUDFLARE_OPERATIONS)[number];
export type EnabledCloudflareOperation = FixedCloudflareOperation;
export const CUSTOMER_CLOUDFLARE_OPERATIONS = Object.freeze([
  'install',
  'upgrade',
  'rollback',
  'source-add',
  'source-update',
  'source-remove',
  'uninstall',
] as const);
export type CustomerCloudflareOperation = (typeof CUSTOMER_CLOUDFLARE_OPERATIONS)[number];
export const LATER_CUSTOMER_CLOUDFLARE_OPERATIONS = Object.freeze([
  'upgrade',
  'rollback',
  'source-add',
  'source-update',
  'source-remove',
  'uninstall',
] as const);
export type LaterCustomerCloudflareOperation =
  (typeof LATER_CUSTOMER_CLOUDFLARE_OPERATIONS)[number];
export type CloudflareOperationExecutor = 'ankka-installer' | 'customer-gateway';

export interface CloudflareWorkerReleaseAuthority {
  /** Stable multipart script upload. The beta version-create endpoint is never an allowed mutation. */
  readonly mutationPath: 'none' | 'direct-script-upload';
  /** Direct upload creates and activates one version/deployment atomically. */
  readonly activation: 'none' | 'implicit-with-direct-upload';
  /** Version and deployment families may be used for exact read-back, not mutation. */
  readonly versionEndpoint: 'none' | 'read-only';
  readonly deploymentEndpoint: 'none' | 'read-only';
}

export const CLOUDFLARE_API_ENDPOINT_FAMILIES = Object.freeze([
  'accounts-list',
  'zones-list',
  'workers-container',
  'workers-scripts',
  'workers-durable-object-namespaces',
  'workers-assets',
  'workers-versions',
  'workers-deployments',
  'workers-subdomain',
  'workers-custom-domains',
  'access-organization',
  'access-identity-providers',
  'access-applications',
  'access-policies',
  'mcp-servers',
  'mcp-portals',
  'dns-records',
] as const);

export type CloudflareApiEndpointFamily = (typeof CLOUDFLARE_API_ENDPOINT_FAMILIES)[number];

export const CLOUDFLARE_RESOURCE_OWNERSHIP_STATES = Object.freeze([
  'absent',
  'same-installation-bootstrap',
  'same-installation-incomplete',
  'receipt-owned',
] as const);

export type CloudflareResourceOwnershipState =
  (typeof CLOUDFLARE_RESOURCE_OWNERSHIP_STATES)[number];

export const CLOUDFLARE_OPERATION_MUTATIONS = Object.freeze([
  'register-account-workers-subdomain',
  'create-bootstrap-worker',
  'recover-bootstrap-worker',
  'delete-bootstrap-worker',
  'delete-bootstrap-admin-state-namespace',
  'create-final-resources',
  'resume-final-resource-convergence',
  'publish-worker-release',
  'activate-worker-release',
  'enable-workers-dev',
  'disable-workers-dev',
  'add-source',
  'update-source',
  'remove-source',
  'delete-receipt-resource',
  'publish-inert-worker-release',
  'delete-root-worker',
  'delete-admin-state-namespace',
] as const);

export type CloudflareOperationMutation = (typeof CLOUDFLARE_OPERATION_MUTATIONS)[number];

export const CLOUDFLARE_OPERATION_POSTCONDITIONS = Object.freeze([
  'bootstrap-surface-only',
  'bootstrap-capability-committed',
  'exact-release-active',
  'workers-dev-enabled-temporarily',
  'ownership-receipt-complete',
  'management-access-enforced',
  'portal-converged',
  'source-set-converged',
  'bootstrap-surface-dead',
  'workers-dev-disabled',
  'dependent-receipt-resources-absent',
  'inert-worker-release-active',
  'receipt-resources-absent',
  'foreign-resources-unchanged',
] as const);

export type CloudflareOperationPostcondition =
  (typeof CLOUDFLARE_OPERATION_POSTCONDITIONS)[number];

export interface FixedCloudflareOperationAuthority {
  readonly operation: FixedCloudflareOperation;
  readonly executor: CloudflareOperationExecutor;
  readonly enabled: true;
  readonly scopes: readonly CloudflareOauthScope[];
  readonly workerRelease: CloudflareWorkerReleaseAuthority;
  readonly endpointFamilies: readonly CloudflareApiEndpointFamily[];
  readonly ownershipStates: readonly CloudflareResourceOwnershipState[];
  readonly mutations: readonly CloudflareOperationMutation[];
  readonly postconditions: readonly CloudflareOperationPostcondition[];
  readonly credentialLifecycle: {
    readonly storage: 'request-memory-only';
    readonly refreshTokens: false;
    readonly revoke: 'attempt-after-success-or-failure';
    readonly discard: 'always';
    readonly retry: 'fresh-authorization';
  };
}

const frozen = <Value extends string>(values: readonly Value[]): readonly Value[] =>
  Object.freeze([...values]);

const BOOTSTRAP_SCOPES = frozen([CLOUDFLARE_OAUTH_SCOPE.workersScriptsWrite, CLOUDFLARE_OAUTH_SCOPE.zoneRead]);

// The customer Worker creates the initial Access, Portal, DNS, and final
// Worker surface. workers-routes.read is retained only for reviewed custom
// domain collision/read-back checks. Stage 2 account selection is proven with
// the operation scopes themselves; no identity or membership scopes exist.
const INSTALL_SCOPES = frozen([
  CLOUDFLARE_OAUTH_SCOPE.accessAccountRead,
  CLOUDFLARE_OAUTH_SCOPE.accessAppsAndPoliciesWrite,
  CLOUDFLARE_OAUTH_SCOPE.dnsWrite,
  CLOUDFLARE_OAUTH_SCOPE.mcpPortalsWrite,
  CLOUDFLARE_OAUTH_SCOPE.workersRoutesRead,
  CLOUDFLARE_OAUTH_SCOPE.workersScriptsWrite,
  CLOUDFLARE_OAUTH_SCOPE.zoneRead,
]);

const WORKER_RELEASE_SCOPES = frozen([CLOUDFLARE_OAUTH_SCOPE.workersScriptsWrite]);
const SOURCE_SCOPES = frozen([
  CLOUDFLARE_OAUTH_SCOPE.accessAppsAndPoliciesWrite,
  CLOUDFLARE_OAUTH_SCOPE.mcpPortalsWrite,
]);
const UNINSTALL_SCOPE_CEILING = frozen([
  CLOUDFLARE_OAUTH_SCOPE.accessAppsAndPoliciesWrite,
  CLOUDFLARE_OAUTH_SCOPE.dnsWrite,
  CLOUDFLARE_OAUTH_SCOPE.mcpPortalsWrite,
  CLOUDFLARE_OAUTH_SCOPE.workersScriptsWrite,
]);

const CREDENTIAL_LIFECYCLE = Object.freeze({
  storage: 'request-memory-only' as const,
  refreshTokens: false as const,
  revoke: 'attempt-after-success-or-failure' as const,
  discard: 'always' as const,
  retry: 'fresh-authorization' as const,
});

const NO_WORKER_RELEASE = Object.freeze({
  mutationPath: 'none' as const,
  activation: 'none' as const,
  versionEndpoint: 'none' as const,
  deploymentEndpoint: 'none' as const,
});

const DIRECT_WORKER_RELEASE = Object.freeze({
  mutationPath: 'direct-script-upload' as const,
  activation: 'implicit-with-direct-upload' as const,
  versionEndpoint: 'read-only' as const,
  deploymentEndpoint: 'read-only' as const,
});

const DEPLOYMENT_READ_ONLY = Object.freeze({
  mutationPath: 'none' as const,
  activation: 'none' as const,
  versionEndpoint: 'none' as const,
  deploymentEndpoint: 'read-only' as const,
});

function authority(
  operation: FixedCloudflareOperation,
  executor: CloudflareOperationExecutor,
  scopes: readonly CloudflareOauthScope[],
  workerRelease: CloudflareWorkerReleaseAuthority,
  endpointFamilies: readonly CloudflareApiEndpointFamily[],
  ownershipStates: readonly CloudflareResourceOwnershipState[],
  mutations: readonly CloudflareOperationMutation[],
  postconditions: readonly CloudflareOperationPostcondition[],
): FixedCloudflareOperationAuthority {
  return Object.freeze({
    operation,
    executor,
    enabled: true as const,
    scopes,
    workerRelease,
    endpointFamilies: frozen(endpointFamilies),
    ownershipStates: frozen(ownershipStates),
    mutations: frozen(mutations),
    postconditions: frozen(postconditions),
    credentialLifecycle: CREDENTIAL_LIFECYCLE,
  });
}

const WORKER_ENDPOINTS = frozen<CloudflareApiEndpointFamily>([
  'workers-container',
  'workers-scripts',
  'workers-assets',
  'workers-versions',
  'workers-deployments',
]);

const OPERATION_AUTHORITY: Readonly<Record<FixedCloudflareOperation, FixedCloudflareOperationAuthority>> =
  Object.freeze({
    bootstrap: authority(
      'bootstrap',
      'ankka-installer',
      BOOTSTRAP_SCOPES,
      DIRECT_WORKER_RELEASE,
      ['accounts-list', 'zones-list', 'workers-container', 'workers-durable-object-namespaces',
        'workers-scripts', 'workers-assets', 'workers-versions', 'workers-deployments',
        'workers-subdomain'],
      ['absent', 'same-installation-incomplete'],
      // Delete/disable mutations are available only to the same fixed executor
      // for bounded rollback before the request-local grant is revoked.
      ['register-account-workers-subdomain', 'create-bootstrap-worker', 'recover-bootstrap-worker', 'delete-bootstrap-worker',
        'delete-bootstrap-admin-state-namespace', 'publish-worker-release',
        'activate-worker-release', 'enable-workers-dev', 'disable-workers-dev'],
      ['bootstrap-surface-only', 'bootstrap-capability-committed', 'exact-release-active',
        'workers-dev-enabled-temporarily'],
    ),
    install: authority(
      'install',
      'customer-gateway',
      INSTALL_SCOPES,
      DIRECT_WORKER_RELEASE,
      ['accounts-list', 'zones-list', ...WORKER_ENDPOINTS, 'workers-subdomain',
        'workers-custom-domains', 'access-organization',
        'access-identity-providers', 'access-applications', 'access-policies', 'mcp-servers',
        'mcp-portals', 'dns-records'],
      ['same-installation-bootstrap', 'same-installation-incomplete', 'receipt-owned'],
      ['create-final-resources', 'resume-final-resource-convergence', 'publish-worker-release',
        'activate-worker-release', 'disable-workers-dev'],
      ['exact-release-active', 'ownership-receipt-complete', 'management-access-enforced',
        'portal-converged', 'source-set-converged', 'bootstrap-surface-dead',
        'workers-dev-disabled'],
    ),
    upgrade: authority(
      'upgrade',
      'customer-gateway',
      WORKER_RELEASE_SCOPES,
      DIRECT_WORKER_RELEASE,
      ['accounts-list', ...WORKER_ENDPOINTS],
      ['receipt-owned'],
      ['publish-worker-release', 'activate-worker-release'],
      ['exact-release-active', 'ownership-receipt-complete', 'bootstrap-surface-dead',
        'workers-dev-disabled'],
    ),
    rollback: authority(
      'rollback',
      'customer-gateway',
      WORKER_RELEASE_SCOPES,
      DIRECT_WORKER_RELEASE,
      ['accounts-list', ...WORKER_ENDPOINTS],
      ['receipt-owned'],
      ['publish-worker-release', 'activate-worker-release'],
      ['exact-release-active', 'ownership-receipt-complete', 'bootstrap-surface-dead',
        'workers-dev-disabled'],
    ),
    'source-add': authority(
      'source-add',
      'customer-gateway',
      SOURCE_SCOPES,
      NO_WORKER_RELEASE,
      ['accounts-list', 'access-applications', 'mcp-servers', 'mcp-portals'],
      ['receipt-owned'],
      ['add-source'],
      ['ownership-receipt-complete', 'portal-converged', 'source-set-converged'],
    ),
    'source-update': authority(
      'source-update',
      'customer-gateway',
      SOURCE_SCOPES,
      NO_WORKER_RELEASE,
      ['accounts-list', 'access-applications', 'mcp-servers', 'mcp-portals'],
      ['receipt-owned'],
      ['update-source'],
      ['ownership-receipt-complete', 'portal-converged', 'source-set-converged'],
    ),
    'source-remove': authority(
      'source-remove',
      'customer-gateway',
      SOURCE_SCOPES,
      NO_WORKER_RELEASE,
      ['accounts-list', 'access-applications', 'mcp-servers', 'mcp-portals'],
      ['receipt-owned'],
      ['remove-source'],
      ['ownership-receipt-complete', 'portal-converged', 'source-set-converged',
        'foreign-resources-unchanged'],
    ),
    uninstall: authority(
      'uninstall',
      'customer-gateway',
      UNINSTALL_SCOPE_CEILING,
      DIRECT_WORKER_RELEASE,
      ['accounts-list', 'workers-container', 'workers-scripts',
        'workers-durable-object-namespaces', 'workers-deployments', 'workers-custom-domains',
        'access-applications', 'access-policies', 'mcp-servers', 'mcp-portals', 'dns-records'],
      ['receipt-owned'],
      ['delete-receipt-resource', 'publish-inert-worker-release', 'activate-worker-release',
        'disable-workers-dev'],
      ['dependent-receipt-resources-absent', 'inert-worker-release-active',
        'workers-dev-disabled', 'foreign-resources-unchanged'],
    ),
    'uninstall-finalize': authority(
      'uninstall-finalize',
      'ankka-installer',
      WORKER_RELEASE_SCOPES,
      DEPLOYMENT_READ_ONLY,
      ['accounts-list', 'workers-container', 'workers-scripts',
        'workers-durable-object-namespaces', 'workers-deployments'],
      ['receipt-owned'],
      ['delete-root-worker', 'delete-admin-state-namespace'],
      ['receipt-resources-absent', 'foreign-resources-unchanged'],
    ),
  });

export function fixedCloudflareOperationAuthority(
  operation: FixedCloudflareOperation,
): FixedCloudflareOperationAuthority {
  return OPERATION_AUTHORITY[operation];
}

export function isFixedCloudflareOperation(value: string): value is FixedCloudflareOperation {
  return FIXED_CLOUDFLARE_OPERATIONS.some((operation) => operation === value);
}

export function isCustomerCloudflareOperation(value: string): value is CustomerCloudflareOperation {
  return CUSTOMER_CLOUDFLARE_OPERATIONS.some((operation) => operation === value);
}

export const RECEIPT_OWNED_CLOUDFLARE_RESOURCE_KINDS = Object.freeze([
  'worker',
  'durable_object_namespace',
  'worker_custom_domain',
  'mcp_server',
  'mcp_portal',
  'access_application',
  'access_policy',
  'dns_record',
] as const);

export type ReceiptOwnedCloudflareResourceKind =
  (typeof RECEIPT_OWNED_CLOUDFLARE_RESOURCE_KINDS)[number];

export function isReceiptOwnedCloudflareResourceKind(
  value: string,
): value is ReceiptOwnedCloudflareResourceKind {
  return RECEIPT_OWNED_CLOUDFLARE_RESOURCE_KINDS.some((kind) => kind === value);
}

const UNINSTALL_RESOURCE_SCOPES: Readonly<Record<
  ReceiptOwnedCloudflareResourceKind,
  readonly CloudflareOauthScope[]
>> = Object.freeze({
  worker: WORKER_RELEASE_SCOPES,
  durable_object_namespace: WORKER_RELEASE_SCOPES,
  worker_custom_domain: WORKER_RELEASE_SCOPES,
  mcp_server: frozen([CLOUDFLARE_OAUTH_SCOPE.mcpPortalsWrite]),
  mcp_portal: frozen([CLOUDFLARE_OAUTH_SCOPE.mcpPortalsWrite]),
  access_application: frozen([CLOUDFLARE_OAUTH_SCOPE.accessAppsAndPoliciesWrite]),
  access_policy: frozen([CLOUDFLARE_OAUTH_SCOPE.accessAppsAndPoliciesWrite]),
  dns_record: frozen([CLOUDFLARE_OAUTH_SCOPE.dnsWrite]),
});

/**
 * Computes the uninstall grant from checksum-verified receipt resource types.
 * Provider IDs and names never influence the permission set.
 */
export function uninstallScopesForReceipt(
  resourceKinds: readonly ReceiptOwnedCloudflareResourceKind[],
): readonly CloudflareOauthScope[] {
  const scopes = new Set<CloudflareOauthScope>();
  for (const kind of resourceKinds) {
    for (const scope of UNINSTALL_RESOURCE_SCOPES[kind]) scopes.add(scope);
  }
  return Object.freeze([...scopes].sort());
}

export function exactOperationScopes(
  operation: EnabledCloudflareOperation,
  receiptResourceKinds?: readonly ReceiptOwnedCloudflareResourceKind[],
): readonly CloudflareOauthScope[] {
  if (operation === 'uninstall') {
    if (receiptResourceKinds === undefined || receiptResourceKinds.length === 0) return Object.freeze([]);
    return uninstallScopesForReceipt(receiptResourceKinds);
  }
  return fixedCloudflareOperationAuthority(operation).scopes;
}

import {
  CLOUDFLARE_OAUTH_SCOPE,
  FIXED_CLOUDFLARE_OPERATIONS,
  exactOperationScopes,
  fixedCloudflareOperationAuthority,
  isCustomerCloudflareOperation,
  isFixedCloudflareOperation,
  uninstallScopesForReceipt,
} from '../src/cloudflare-operation-authority';

describe('fixed Cloudflare OAuth operation authority', () => {
  it('adds zone discovery to Stage 1 without widening release or removal grants', () => {
    const bootstrap = fixedCloudflareOperationAuthority('bootstrap');
    expect(bootstrap).toMatchObject({
      operation: 'bootstrap',
      executor: 'ankka-installer',
      enabled: true,
      scopes: ['workers-scripts.write', 'zone.read'],
      workerRelease: {
        mutationPath: 'direct-script-upload',
        activation: 'implicit-with-direct-upload',
        versionEndpoint: 'read-only',
        deploymentEndpoint: 'read-only',
      },
      credentialLifecycle: {
        storage: 'request-memory-only',
        refreshTokens: false,
        revoke: 'attempt-after-success-or-failure',
        discard: 'always',
        retry: 'fresh-authorization',
      },
    });
    expect(bootstrap.endpointFamilies).toContain('workers-subdomain');
    expect(bootstrap.endpointFamilies).toContain('workers-scripts');
    expect(bootstrap.mutations).toContain('enable-workers-dev');
    expect(bootstrap.mutations).toContain('delete-bootstrap-worker');
    expect(bootstrap.mutations).toContain('delete-bootstrap-admin-state-namespace');
    expect(bootstrap.postconditions).toContain('workers-dev-enabled-temporarily');
  });

  it('has the exhaustive fixed operation catalogue and no generic authority', () => {
    expect(FIXED_CLOUDFLARE_OPERATIONS).toEqual([
      'bootstrap', 'install', 'upgrade', 'rollback', 'source-add', 'bigquery-add', 'source-update',
      'source-remove', 'uninstall', 'uninstall-finalize', 'gateway-root-finalize',
    ]);
    expect(isFixedCloudflareOperation('install')).toBe(true);
    expect(isFixedCloudflareOperation('source-remove')).toBe(true);
    expect(isFixedCloudflareOperation('uninstall-finalize')).toBe(true);
    expect(isCustomerCloudflareOperation('uninstall')).toBe(true);
    expect(isCustomerCloudflareOperation('uninstall-finalize')).toBe(false);
    expect(isFixedCloudflareOperation('policy-sync')).toBe(false);
    expect(isFixedCloudflareOperation('generic-repair')).toBe(false);
  });

  it('fixes endpoint, ownership, mutation, postcondition, and credential boundaries', () => {
    const install = fixedCloudflareOperationAuthority('install');
    expect(install.endpointFamilies).toEqual(expect.arrayContaining([
      'accounts-list', 'zones-list', 'workers-scripts', 'workers-versions', 'access-applications',
      'access-policies', 'mcp-servers', 'mcp-portals', 'dns-records',
    ]));
    expect(install.workerRelease).toEqual({
      mutationPath: 'direct-script-upload',
      activation: 'implicit-with-direct-upload',
      versionEndpoint: 'read-only',
      deploymentEndpoint: 'read-only',
    });
    expect(install.ownershipStates).toEqual([
      'same-installation-bootstrap', 'same-installation-incomplete', 'receipt-owned',
    ]);
    expect(install.mutations).toEqual(expect.arrayContaining([
      'create-final-resources', 'resume-final-resource-convergence', 'activate-worker-release',
      'disable-workers-dev',
    ]));
    expect(install.postconditions).toEqual(expect.arrayContaining([
      'ownership-receipt-complete', 'bootstrap-surface-dead', 'workers-dev-disabled',
    ]));

    for (const operation of ['source-add', 'source-update', 'source-remove'] as const) {
      const source = fixedCloudflareOperationAuthority(operation);
      expect(source.scopes).toEqual(['zone-access.write', 'mcp-portals.write']);
      expect(source.endpointFamilies).toEqual([
        'accounts-list', 'access-applications', 'mcp-servers', 'mcp-portals',
      ]);
      expect(source.ownershipStates).toEqual(['receipt-owned']);
      expect(source.workerRelease).toEqual({
        mutationPath: 'none',
        activation: 'none',
        versionEndpoint: 'none',
        deploymentEndpoint: 'none',
      });
    }
  });

  it('adds only the demonstrated read scope for zone discovery', () => {
    expect(fixedCloudflareOperationAuthority('install').scopes).toEqual([
      'access-acct.read', 'zone-access.write', 'dns.write', 'mcp-portals.write',
      'workers-routes.read', 'workers-scripts.write', 'zone.read',
    ]);
    const scopes = FIXED_CLOUDFLARE_OPERATIONS.flatMap((operation) =>
      fixedCloudflareOperationAuthority(operation).scopes,
    );
    for (const forbidden of [
      'memberships.read', 'user-details.read', 'account-settings.read',
      'access-acct.write', 'access.write', 'offline_access', 'openid',
    ]) {
      expect(scopes).not.toContain(forbidden);
    }
  });

  it('derives uninstall authority only from receipt-owned resource types', () => {
    expect(uninstallScopesForReceipt([
      'worker', 'durable_object_namespace', 'worker_custom_domain', 'mcp_portal',
      'access_application', 'dns_record',
    ])).toEqual([
      CLOUDFLARE_OAUTH_SCOPE.dnsWrite,
      CLOUDFLARE_OAUTH_SCOPE.mcpPortalsWrite,
      CLOUDFLARE_OAUTH_SCOPE.workersScriptsWrite,
      CLOUDFLARE_OAUTH_SCOPE.accessAppsAndPoliciesWrite,
    ]);
    expect(exactOperationScopes('uninstall', ['worker'])).toEqual(['workers-scripts.write']);
    expect(exactOperationScopes('uninstall')).toEqual([]);
  });

  it('splits customer uninstall from the receipt-bound hosted root finalizer', () => {
    expect(fixedCloudflareOperationAuthority('uninstall')).toMatchObject({
      executor: 'customer-gateway',
      scopes: [
        'zone-access.write', 'dns.write', 'mcp-portals.write', 'workers-scripts.write',
      ],
      mutations: [
        'delete-receipt-resource', 'publish-inert-worker-release',
        'activate-worker-release', 'disable-workers-dev',
      ],
      postconditions: [
        'dependent-receipt-resources-absent', 'inert-worker-release-active',
        'workers-dev-disabled', 'foreign-resources-unchanged',
      ],
    });
    expect(fixedCloudflareOperationAuthority('uninstall-finalize')).toMatchObject({
      executor: 'ankka-installer',
      scopes: ['workers-scripts.write'],
      workerRelease: {
        mutationPath: 'none',
        activation: 'none',
        versionEndpoint: 'none',
        deploymentEndpoint: 'read-only',
      },
      mutations: ['delete-root-worker', 'delete-admin-state-namespace'],
      postconditions: ['receipt-resources-absent', 'foreign-resources-unchanged'],
    });
    expect(fixedCloudflareOperationAuthority('gateway-root-finalize')).toMatchObject({
      executor: 'ankka-installer', scopes: ['workers-scripts.write', 'zone-access.write'],
      workerRelease: { mutationPath: 'direct-script-upload', versionEndpoint: 'read-only' },
      mutations: ['publish-inert-worker-release', 'delete-receipt-resource', 'delete-root-worker', 'delete-admin-state-namespace'],
    });
    expect(isCustomerCloudflareOperation('gateway-root-finalize')).toBe(false);
  });

  it('freezes every authority boundary', () => {
    for (const operation of FIXED_CLOUDFLARE_OPERATIONS) {
      const authority = fixedCloudflareOperationAuthority(operation);
      expect(Object.isFrozen(authority)).toBe(true);
      expect(Object.isFrozen(authority.scopes)).toBe(true);
      expect(Object.isFrozen(authority.workerRelease)).toBe(true);
      expect(Object.isFrozen(authority.endpointFamilies)).toBe(true);
      expect(Object.isFrozen(authority.ownershipStates)).toBe(true);
      expect(Object.isFrozen(authority.mutations)).toBe(true);
      expect(Object.isFrozen(authority.postconditions)).toBe(true);
      expect(Object.isFrozen(authority.credentialLifecycle)).toBe(true);
    }
  });
});

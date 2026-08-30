// Deliberately synthetic UUIDs; these do not identify provider resources.
export const CANARY_SERVICE_ID = '10000000-0000-4000-8000-000000000001';
export const OTHER_SERVICE_ID = '10000000-0000-4000-8000-000000000002';

export function canaryConfig() {
  return {
    schemaVersion: 1,
    gateway: {
      name: 'Ankka disposable canary',
      hostname: 'ankka-canary-lifecycle.example.com',
      codeMode: 'off',
    },
    policy: { capabilityMode: 'read_only', credentialCustody: 'customer', telemetry: 'off' },
    sources: [{
      id: 'synthetic-canary',
      label: 'Ankka synthetic canary',
      url: 'https://synthetic.example.com/mcp',
      authentication: { mode: 'none', onBehalfOfUser: false },
      enabledTools: ['ankka_canary_status'],
    }],
  };
}

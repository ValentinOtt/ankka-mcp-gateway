import type { CustomerTeardownDependencies } from './customer-teardown-router';

/** Re-enter only the management object, using the existing signed commands. */
export function customerTeardownCommand(namespace: DurableObjectNamespace): CustomerTeardownDependencies['command'] {
  return (command, body, signature) => namespace.get(namespace.idFromName('v1:management')).fetch(
    new Request(`https://admin-state.invalid/teardown-actions/${command}-current`, {
      method: 'POST', headers: { 'content-type': 'application/json', 'x-ankka-teardown-action-signature': signature }, body,
    }),
  );
}

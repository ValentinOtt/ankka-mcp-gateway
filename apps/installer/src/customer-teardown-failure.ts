import * as v from 'valibot';

/** Fixed, customer-local removal diagnostics; never include provider data or identifiers. */
export const CUSTOMER_TEARDOWN_FAILURE_PHASES = [
  'authorization', 'account_check', 'apply', 'root_preflight', 'root_remove', 'root_verify',
  'bridge_preflight', 'bridge_remove', 'bridge_verify', 'revocation', 'settlement', 'handoff',
] as const;
export const CUSTOMER_TEARDOWN_FAILURE_RESOURCE_KINDS = [
  'mcp_server', 'mcp_portal', 'portal', 'access_application', 'access_policy', 'dns_record', 'worker',
  'worker_custom_domain', 'portal_access_application', 'portal_access_policy',
  'source_access_application', 'source_access_policy', 'dependency_graph', 'none',
] as const;
export const CUSTOMER_TEARDOWN_FAILURE_CATEGORIES = [
  'authorization_denied', 'authorization_failed', 'provider_auth', 'provider_rejected', 'provider_unavailable',
  'response_invalid', 'ownership_mismatch', 'state_invalid', 'absence_unconfirmed', 'operation_interrupted',
  'expired', 'no_progress', 'pass_limit', 'revocation_unconfirmed', 'settlement_failed', 'handoff_failed',
] as const;
export const customerTeardownFailureSchema = v.strictObject({
  phase: v.picklist(CUSTOMER_TEARDOWN_FAILURE_PHASES),
  resourceKind: v.picklist(CUSTOMER_TEARDOWN_FAILURE_RESOURCE_KINDS),
  category: v.picklist(CUSTOMER_TEARDOWN_FAILURE_CATEGORIES),
});
export type CustomerTeardownFailure = v.InferOutput<typeof customerTeardownFailureSchema>;
export function parseCustomerTeardownFailure<Input>(input: Input): CustomerTeardownFailure | null {
  const parsed = v.safeParse(customerTeardownFailureSchema, input);
  return parsed.success ? parsed.output : null;
}
export class CustomerTeardownFailureError extends Error {
  readonly failure: CustomerTeardownFailure;
  constructor(failure: CustomerTeardownFailure) {
    super('teardown_recovery_required');
    this.failure = v.parse(customerTeardownFailureSchema, failure);
  }
}

import * as v from 'valibot';

const token = v.pipe(v.string(), v.regex(/^[A-Za-z0-9_-]{43}$/u));
const time = v.pipe(v.number(), v.safeInteger(), v.minValue(0));
/** Only the dependent-resource families are valid in a gateway's first removal phase. */
export const CUSTOMER_TEARDOWN_RESOURCE_KINDS = ['mcp_server', 'mcp_portal', 'access_application', 'access_policy', 'dns_record', 'worker', 'worker_custom_domain'] as const;
export const customerTeardownKindsSchema = v.pipe(v.array(v.picklist(CUSTOMER_TEARDOWN_RESOURCE_KINDS)), v.minLength(1), v.maxLength(CUSTOMER_TEARDOWN_RESOURCE_KINDS.length));
const schema = v.strictObject({
  schemaVersion: v.literal(1), revision: v.pipe(v.number(), v.safeInteger(), v.minValue(1)),
  attemptId: v.pipe(v.string(), v.regex(/^attempt_[A-Za-z0-9_-]{24}$/u)),
  actionId: v.pipe(v.string(), v.regex(/^action_[A-Za-z0-9_-]{32}$/u)),
  actorEmail: v.pipe(v.string(), v.email(), v.maxLength(256)),
  actionExpiresAt: time, expiresAt: time,
  stateHash: token, verifierHash: token,
  receiptResourceKinds: customerTeardownKindsSchema,
  phase: v.picklist(['authorizing', 'exchanging', 'settled']),
  priorGrantRevocationUnconfirmed: v.boolean(),
});
export type CustomerTeardownAttempt = v.InferOutput<typeof schema>;
export function parseCustomerTeardownAttempt<Input>(input: Input): CustomerTeardownAttempt {
  const attempt = v.parse(schema, input);
  if (attempt.expiresAt > attempt.actionExpiresAt || new Set(attempt.receiptResourceKinds).size !== attempt.receiptResourceKinds.length) {
    throw new Error('teardown_attempt_invalid');
  }
  return attempt;
}
export interface CustomerTeardownAttemptPort {
  read(): Promise<CustomerTeardownAttempt | null>;
  compareAndSet(revision: number | null, attempt: CustomerTeardownAttempt): Promise<boolean>;
}
const KEY = 'ankka-mcp-gateway/customer-teardown-attempt/v1';
/** Atomic consumption prevents overlapping callbacks from exchanging the same authorization twice. */
export class DurableCustomerTeardownAttemptPort implements CustomerTeardownAttemptPort {
  constructor(private readonly storage: DurableObjectStorage) {}
  async read(): Promise<CustomerTeardownAttempt | null> {
    const value = await this.storage.get(KEY);
    return value === undefined ? null : parseCustomerTeardownAttempt(value);
  }
  async compareAndSet(revision: number | null, attempt: CustomerTeardownAttempt): Promise<boolean> {
    const next = parseCustomerTeardownAttempt(attempt);
    if (next.revision !== (revision ?? 0) + 1) throw new Error('teardown_attempt_invalid');
    return this.storage.transaction(async (transaction) => {
      const value = await transaction.get(KEY);
      const current = value === undefined ? null : parseCustomerTeardownAttempt(value);
      if ((current?.revision ?? null) !== revision) return false;
      if (current?.priorGrantRevocationUnconfirmed && !next.priorGrantRevocationUnconfirmed) throw new Error('teardown_attempt_invalid');
      await transaction.put(KEY, next);
      return true;
    });
  }
}

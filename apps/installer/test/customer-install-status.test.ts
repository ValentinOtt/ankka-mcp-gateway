import * as v from 'valibot';
import { describe, expect, it } from 'vitest';

import { customerInstallStatusSchema } from '../src/customer-install-status';

// The exact answer a deployed gateway-v0.1.23 shell gave on 2026-09-04. The
// hosted readiness check rejected it as `readiness_schema_invalid` because
// its own copy of the schema had no `failure` key; the shell and the hosted
// runtime now share this schema.
const LIVE_ANSWER = {
  schemaVersion: 1,
  role: 'customer-gateway-bootstrap',
  status: 'INCOMPLETE',
  installId: 'acg-eee97315cc9a152584856462',
  release: 'gateway-v0.1.23',
  ownershipPublicKey: '3kT8YLdwPDh9yIXidUxch8VwWRWuj547ou0wHI9p3Yc',
  failure: null,
};

describe('customer install status schema', () => {
  it('accepts the answer of a freshly deployed shell', () => {
    expect(v.parse(customerInstallStatusSchema, LIVE_ANSWER)).toEqual(LIVE_ANSWER);
  });

  it('accepts a named failure, a missing field from older shells, and nothing else', () => {
    const failure = { code: 'provider_recovery_required', reason: 'payload_portal_create_auth_http_403_code_10000' };
    expect(v.parse(customerInstallStatusSchema, { ...LIVE_ANSWER, failure }).failure).toEqual(failure);
    expect(v.parse(customerInstallStatusSchema, { ...LIVE_ANSWER, failure: { code: 'grant_invalid', reason: null } }).failure)
      .toEqual({ code: 'grant_invalid', reason: null });
    const { failure: _absent, ...legacy } = LIVE_ANSWER;
    expect(v.parse(customerInstallStatusSchema, legacy).failure).toBeNull();
    for (const broken of [
      { ...LIVE_ANSWER, extra: 1 },
      { ...LIVE_ANSWER, failure: { code: 'provider_recovery_required' } },
      { ...LIVE_ANSWER, failure: { code: 'provider_recovery_required', reason: 'Bearer secret' } },
      { ...LIVE_ANSWER, failure: { code: 'Provider', reason: null } },
      { ...LIVE_ANSWER, status: 'DONE' },
      { ...LIVE_ANSWER, role: 'customer-gateway' },
    ]) {
      expect(v.is(customerInstallStatusSchema, broken)).toBe(false);
    }
  });
});

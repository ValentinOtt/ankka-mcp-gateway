import * as v from 'valibot';

export type DeployErrorCode =
  | 'abuse_controls_unavailable'
  | 'bad_request'
  | 'bootstrap_failed'
  | 'bootstrap_not_ready'
  | 'callback_invalid'
  | 'csrf_invalid'
  | 'existing_gateway_detected'
  | 'install_mutations_disabled'
  | 'uninstall_mutations_disabled'
  | 'internal_error'
  | 'oauth_denied'
  | 'oauth_exchange_failed'
  | 'oauth_grant_invalid'
  | 'oauth_revoke_failed'
  | 'oauth_state_invalid'
  | 'origin_invalid'
  | 'rate_limited'
  | 'release_invalid'
  | 'release_unavailable'
  | 'session_conflict'
  | 'session_expired'
  | 'session_invalid'
  | 'target_account_ambiguous'
  | 'target_zone_invalid';

export const DEPLOY_ERROR_CODES: ReadonlySet<string> = new Set<DeployErrorCode>([
  'abuse_controls_unavailable',
  'bad_request',
  'bootstrap_failed',
  'bootstrap_not_ready',
  'callback_invalid',
  'csrf_invalid',
  'existing_gateway_detected',
  'install_mutations_disabled',
  'uninstall_mutations_disabled',
  'internal_error',
  'oauth_denied',
  'oauth_exchange_failed',
  'oauth_grant_invalid',
  'oauth_revoke_failed',
  'oauth_state_invalid',
  'origin_invalid',
  'rate_limited',
  'release_invalid',
  'release_unavailable',
  'session_conflict',
  'session_expired',
  'session_invalid',
  'target_account_ambiguous',
  'target_zone_invalid',
]);
const stringSchema = v.string();

export function isDeployErrorCode<Value>(value: Value): value is Value & DeployErrorCode {
  return v.is(stringSchema, value) && DEPLOY_ERROR_CODES.has(value);
}

/** Safe diagnostic vocabulary: fixed words, HTTP status classes, and RFC 6749 error codes only. */
export const FAILURE_REASON_PATTERN = /^[a-z][a-z0-9_]{0,159}$/u;

export function isFailureReason<Value>(value: Value): value is Value & string {
  return v.is(stringSchema, value) && FAILURE_REASON_PATTERN.test(value);
}

export class DeployError extends Error {
  readonly code: DeployErrorCode;
  readonly status: number;
  /** Optional secret-free diagnostic reason surfaced in result detail text. */
  readonly reason: string | null;

  constructor(status: number, code: DeployErrorCode, reason: string | null = null) {
    super(code);
    this.name = 'DeployError';
    this.status = status;
    this.code = code;
    this.reason = isFailureReason(reason) ? reason : null;
  }
}

export function stableError<Thrown>(error: Thrown): DeployError {
  return error instanceof DeployError ? error : new DeployError(500, 'internal_error');
}

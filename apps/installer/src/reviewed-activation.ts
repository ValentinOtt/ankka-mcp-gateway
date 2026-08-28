import type { PinnedR2Release } from './r2-release-provider';

export type ReviewedGatewayDeployActivation =
  | Readonly<{ enabled: false; pin: null }>
  | Readonly<{ enabled: true; pin: PinnedR2Release }>;

/**
 * Compile-time activation boundary for the reviewed mutation runtime.
 *
 * There is deliberately no environment-variable override. Activating the
 * reviewed entrypoint requires a code change that supplies an exact signed
 * release pin, plus a separately reviewed Wrangler binding and route change.
 */
export const REVIEWED_GATEWAY_DEPLOY_ACTIVATION = Object.freeze({
  enabled: false,
  pin: null,
} as const) satisfies ReviewedGatewayDeployActivation;

/**
 * The environment the co-resident payload needs while the Stage 1 shell
 * still runs it in-process.
 *
 * The shell's own bindings stop at what Stage 1 provisioned. The payload's
 * bootstrap and receipt verification parse a strict runtime environment that
 * also names the zone and the Zero Trust readiness the converger has already
 * established by the time it calls them; without those three values the
 * payload answers every request with `bootstrap_rejected`. The final runtime
 * later carries the same values as real bindings.
 */
export interface CustomerPayloadZone {
  readonly zoneId: string;
  readonly zoneName: string;
}

export function customerPayloadEnvironment<Env extends object>(
  bootstrapEnv: Env,
  target: CustomerPayloadZone,
): Env & { CLOUDFLARE_ZONE_ID: string; CLOUDFLARE_ZONE_NAME: string; ZERO_TRUST_READY: 'true' } {
  return Object.freeze({
    ...bootstrapEnv,
    CLOUDFLARE_ZONE_ID: target.zoneId,
    CLOUDFLARE_ZONE_NAME: target.zoneName,
    ZERO_TRUST_READY: 'true' as const,
  });
}

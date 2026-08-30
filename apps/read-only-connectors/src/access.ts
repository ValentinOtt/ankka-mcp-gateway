import { createLocalJWKSet, jwtVerify } from 'jose';
import { z } from 'zod';
import { executeReadRequest } from './request';

const publicKeys = z.object({ keys: z.array(z.object({
  kty: z.literal('RSA'), kid: z.string().min(1).max(256),
  n: z.string().regex(/^[A-Za-z0-9_-]{256,2048}$/),
  e: z.literal('AQAB'), alg: z.literal('RS256').default('RS256'),
  use: z.literal('sig').default('sig'),
})).min(1).max(16) });

/** Access, not the connector, owns login, consent, refresh, and user policies. */
export async function verifyAccess(
  request: Request,
  teamDomain: string,
  audience: string,
  fetcher: typeof globalThis.fetch,
): Promise<boolean> {
  try {
    if (!/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.cloudflareaccess\.com$/.test(teamDomain) ||
      !/^[a-f0-9]{64}$/.test(audience)) return false;
    const assertion = request.headers.get('Cf-Access-Jwt-Assertion');
    if (assertion === null || assertion.length > 16_384 ||
      !/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(assertion)) return false;
    const issuer = `https://${teamDomain}`;
    const data = await executeReadRequest({
      origin: issuer, plan: { method: 'GET', path: '/cdn-cgi/access/certs' }, headers: {},
      allowRequest: (plan) => plan.method === 'GET' && plan.path === '/cdn-cgi/access/certs' &&
        plan.query === undefined && plan.body === undefined,
      fetch: fetcher,
    });
    const keys = publicKeys.parse(data);
    const verified = await jwtVerify(assertion, createLocalJWKSet(keys), {
      issuer, audience, algorithms: ['RS256'], requiredClaims: ['exp', 'iat'], clockTolerance: 5,
    });
    return verified.payload.iat !== undefined && verified.payload.iat <= Date.now() / 1000 + 5;
  } catch {
    // Authentication errors must not expose JWTs, claims, public-key responses, or URLs.
    return false;
  }
}

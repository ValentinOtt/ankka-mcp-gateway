import { base64UrlEncode } from '../src/crypto';
import {
  createCloudflareGatewayRelayTicket,
  verifyCloudflareGatewayRelayTicket,
} from '../src/cloudflare-gateway-relay-ticket';

const NOW = 1_800_000_000_000;
const KEY = base64UrlEncode(new Uint8Array(32).fill(1));
const NONCE = base64UrlEncode(new Uint8Array(32).fill(2));
const CLIENT_ID = 'c'.repeat(32);
const CALLBACK = 'https://ankka-bootstrap.customer.workers.dev/__ankka/install/oauth/callback';

function ticketInput() {
  return {
    accountId: 'a'.repeat(32),
    installId: `acg-${'b'.repeat(24)}`,
    workerName: 'ankka-bootstrap',
    gatewayCallback: CALLBACK,
    publicClientId: CLIENT_ID,
    operation: 'install' as const,
    nonce: NONCE,
    now: NOW,
    expiresAt: NOW + 60_000,
    signingKey: KEY,
  };
}

describe('Cloudflare Gateway relay ticket', () => {
  it('binds one fixed operation, client, customer callback, account, and installation', async () => {
    const ticket = await createCloudflareGatewayRelayTicket(ticketInput());
    const claims = await verifyCloudflareGatewayRelayTicket({
      ticket,
      signingKey: KEY,
      expectedClientId: CLIENT_ID,
      expectedOperation: 'install',
      expectedGatewayCallback: CALLBACK,
      now: NOW + 1,
    });
    expect(claims).toMatchObject({
      accountId: 'a'.repeat(32),
      installId: `acg-${'b'.repeat(24)}`,
      workerName: 'ankka-bootstrap',
      gatewayCallback: CALLBACK,
      publicClientId: CLIENT_ID,
      operation: 'install',
      receiptResourceKinds: null,
    });
  });

  it('rejects tamper, expiry, a different callback, and operation substitution', async () => {
    const ticket = await createCloudflareGatewayRelayTicket(ticketInput());
    const verify = (overrides: Partial<Parameters<typeof verifyCloudflareGatewayRelayTicket>[0]> = {}) =>
      verifyCloudflareGatewayRelayTicket({
        ticket,
        signingKey: KEY,
        expectedClientId: CLIENT_ID,
        expectedOperation: 'install',
        expectedGatewayCallback: CALLBACK,
        now: NOW + 1,
        ...overrides,
      });
    const replacement = ticket.endsWith('A') ? 'B' : 'A';
    await expect(verify({ ticket: `${ticket.slice(0, -1)}${replacement}` })).rejects.toMatchObject({
      code: 'invalid',
    });
    await expect(verify({ now: NOW + 60_000 })).rejects.toMatchObject({ code: 'expired' });
    await expect(verify({ expectedOperation: 'upgrade' })).rejects.toMatchObject({
      code: 'operation_mismatch',
    });
    await expect(verify({
      expectedGatewayCallback: 'https://other.customer.workers.dev/__ankka/install/oauth/callback',
    })).rejects.toMatchObject({ code: 'operation_mismatch' });
  });

  it('binds uninstall permission derivation to verified receipt resource kinds', async () => {
    const ticket = await createCloudflareGatewayRelayTicket({
      ...ticketInput(),
      operation: 'uninstall',
      receiptResourceKinds: ['worker', 'access_application'],
    });
    const claims = await verifyCloudflareGatewayRelayTicket({
      ticket,
      signingKey: KEY,
      expectedClientId: CLIENT_ID,
      expectedOperation: 'uninstall',
      expectedGatewayCallback: CALLBACK,
      now: NOW + 1,
    });
    expect(claims.receiptResourceKinds).toEqual(['worker', 'access_application']);
    await expect(createCloudflareGatewayRelayTicket({
      ...ticketInput(),
      receiptResourceKinds: ['worker'],
    })).rejects.toMatchObject({ code: 'invalid' });
  });
});

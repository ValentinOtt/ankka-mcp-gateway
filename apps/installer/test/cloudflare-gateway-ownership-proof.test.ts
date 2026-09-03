import {
  CLOUDFLARE_GATEWAY_OWNERSHIP_CHALLENGE_TTL_MS,
  CloudflareGatewayOwnershipProofError,
  createCloudflareGatewayOwnershipProof,
  createCloudflareGatewayOwnershipChallengeRequest,
  generateCloudflareGatewayOwnershipKeyPair,
  generateSealedCloudflareGatewayOwnershipKeyPair,
  issueCloudflareGatewayOwnershipCertificate,
  issueCloudflareGatewayOwnershipChallenge,
  issueCloudflareGatewayRelayTicketFromOwnershipProof,
  openSealedCloudflareGatewayOwnershipPrivateKey,
  verifyAndConsumeCloudflareGatewayOwnershipProof,
  verifyCloudflareGatewayOwnershipCertificate,
  type CloudflareGatewayOwnershipChallengeRecord,
  type CloudflareGatewayOwnershipChallengeStore,
} from '../src/cloudflare-gateway-ownership-proof';
import { verifyCloudflareGatewayRelayTicket } from '../src/cloudflare-gateway-relay-ticket';
import { base64UrlEncode, randomBase64Url } from '../src/crypto';
import { CUSTOMER_INSTALL_OAUTH_CALLBACK_PATH } from '../src/customer-install-paths';

const ACCOUNT_ID = 'a'.repeat(32);
const WORKER_PROVIDER_ID = 'b'.repeat(32);
const NAMESPACE_ID = 'c'.repeat(32);
const INSTALL_ID = `acg-${'d'.repeat(24)}`;
const WORKER_NAME = 'ankka-gateway-proof-canary';
const BOOTSTRAP_CALLBACK = `https://${WORKER_NAME}.customer.workers.dev${CUSTOMER_INSTALL_OAUTH_CALLBACK_PATH}`;
const GATEWAY_CALLBACK = `https://manage.example.com${CUSTOMER_INSTALL_OAUTH_CALLBACK_PATH}`;
const CLIENT_ID = 'client_ownership_proof_1234567890';
const ISSUER_KEY_ID = 'ownership-issuer-v1';
const HANDOFF_SHA256 = `sha256:${'e'.repeat(64)}`;
const NOW = 1_788_192_000_000;

class MemoryChallengeStore implements CloudflareGatewayOwnershipChallengeStore {
  readonly records = new Map<string, CloudflareGatewayOwnershipChallengeRecord>();
  readonly writes: CloudflareGatewayOwnershipChallengeRecord[] = [];

  private key(record: CloudflareGatewayOwnershipChallengeRecord): string {
    return `${record.certificateSha256}.${record.operation}`;
  }

  async put(record: CloudflareGatewayOwnershipChallengeRecord): Promise<boolean> {
    const key = this.key(record);
    const copy = Object.freeze({ ...record });
    this.records.set(key, copy);
    this.writes.push(copy);
    return true;
  }

  async consume(record: CloudflareGatewayOwnershipChallengeRecord): Promise<boolean> {
    const key = this.key(record);
    if (!this.records.has(key)) return false;
    this.records.delete(key);
    return true;
  }
}

async function keyPair(): Promise<CryptoKeyPair> {
  return crypto.subtle.generateKey('Ed25519', true, ['sign', 'verify']);
}

async function publicKey(key: CryptoKey): Promise<string> {
  return base64UrlEncode(new Uint8Array(await crypto.subtle.exportKey('raw', key)));
}

async function fixture() {
  const issuer = await keyPair();
  const ownership = await generateCloudflareGatewayOwnershipKeyPair();
  const issuerPublicKey = await publicKey(issuer.publicKey);
  const ownershipPublicKey = ownership.publicKey;
  const certificate = await issueCloudflareGatewayOwnershipCertificate({
    accountId: ACCOUNT_ID,
    installId: INSTALL_ID,
    worker: { name: WORKER_NAME, providerId: WORKER_PROVIDER_ID },
    adminStateNamespaceId: NAMESPACE_ID,
    bootstrapCallback: BOOTSTRAP_CALLBACK,
    gatewayCallback: GATEWAY_CALLBACK,
    publicClientId: CLIENT_ID,
    ownershipPublicKey,
    handoffSha256: HANDOFF_SHA256,
    issuedAt: NOW,
    keyId: ISSUER_KEY_ID,
  }, issuer.privateKey);
  const verified = await verifyCloudflareGatewayOwnershipCertificate({
    certificate,
    pinnedIssuerPublicKey: issuerPublicKey,
    expectedKeyId: ISSUER_KEY_ID,
    expectedPublicClientId: CLIENT_ID,
  });
  return { certificate, issuer, issuerPublicKey, ownership, ownershipPublicKey, verified };
}

async function issueChallenge(
  value: Awaited<ReturnType<typeof fixture>>,
  store: CloudflareGatewayOwnershipChallengeStore,
  operation: 'install' | 'upgrade' | 'rollback' | 'uninstall',
  now: number,
) {
  const request = await createCloudflareGatewayOwnershipChallengeRequest({
    certificate: value.certificate,
    certificateSha256: value.verified.certificateSha256,
    operation,
    now,
    ownershipPrivateKey: value.ownership.privateKey,
  });
  return issueCloudflareGatewayOwnershipChallenge({
    request,
    pinnedIssuerPublicKey: value.issuerPublicKey,
    expectedKeyId: ISSUER_KEY_ID,
    expectedPublicClientId: CLIENT_ID,
    expectedOperation: operation,
    now,
    store,
  });
}

async function errorCode(promise: Promise<unknown>): Promise<string | null> {
  try {
    await promise;
    return null;
  } catch (error) {
    return error instanceof CloudflareGatewayOwnershipProofError ? error.code : 'other';
  }
}

describe('customer Gateway relay ownership proof', () => {
  it('certifies only the customer public key and mints an install ticket after possession proof', async () => {
    const value = await fixture();
    expect(value.verified).toMatchObject({
      keyId: ISSUER_KEY_ID,
      verification: 'ed25519',
      statement: {
        accountId: ACCOUNT_ID,
        installId: INSTALL_ID,
        worker: { name: WORKER_NAME, providerId: WORKER_PROVIDER_ID },
        adminStateNamespaceId: NAMESPACE_ID,
        bootstrapCallback: BOOTSTRAP_CALLBACK,
        gatewayCallback: GATEWAY_CALLBACK,
        publicClientId: CLIENT_ID,
        ownershipKey: { algorithm: 'Ed25519', publicKey: value.ownershipPublicKey },
        handoffSha256: HANDOFF_SHA256,
      },
    });
    expect(value.certificate).not.toContain('private');
    expect(value.ownership.privateKey.extractable).toBe(false);

    const store = new MemoryChallengeStore();
    const challenge = await issueChallenge(value, store, 'install', NOW + 1_000);
    expect(challenge.expiresAt).toBe(NOW + 1_000 + CLOUDFLARE_GATEWAY_OWNERSHIP_CHALLENGE_TTL_MS);
    expect(store.writes).toHaveLength(1);
    expect(store.writes[0]).toEqual({
      certificateSha256: value.verified.certificateSha256,
      operation: 'install',
      challengeSha256: expect.stringMatching(/^sha256:[a-f0-9]{64}$/u),
      expiresAt: challenge.expiresAt,
    });
    expect(JSON.stringify(store.writes[0])).not.toContain(ACCOUNT_ID);
    expect(JSON.stringify(store.writes[0])).not.toContain(WORKER_NAME);
    expect(JSON.stringify(store.writes[0])).not.toContain(GATEWAY_CALLBACK);
    expect(JSON.stringify(store.writes[0])).not.toContain(challenge.challenge);

    const proof = await createCloudflareGatewayOwnershipProof({
      certificate: value.certificate,
      certificateSha256: challenge.certificateSha256,
      gatewayCallback: GATEWAY_CALLBACK,
      operation: 'install',
      challenge: challenge.challenge,
      challengeExpiresAt: challenge.expiresAt,
      now: NOW + 2_000,
      ownershipPrivateKey: value.ownership.privateKey,
    });
    const relayTicketKey = randomBase64Url(32);
    const ticket = await issueCloudflareGatewayRelayTicketFromOwnershipProof({
      proof,
      pinnedIssuerPublicKey: value.issuerPublicKey,
      expectedKeyId: ISSUER_KEY_ID,
      expectedPublicClientId: CLIENT_ID,
      expectedOperation: 'install',
      now: NOW + 3_000,
      ticketExpiresAt: NOW + 5 * 60_000,
      relayTicketSigningKey: relayTicketKey,
      store,
    });
    // An install ticket is bound to the certified bootstrap origin: during the
    // install the Gateway is reachable only there, and the management hostname
    // only exists once the install has converged.
    await expect(verifyCloudflareGatewayRelayTicket({
      ticket,
      signingKey: relayTicketKey,
      expectedClientId: CLIENT_ID,
      expectedOperation: 'install',
      expectedGatewayCallback: BOOTSTRAP_CALLBACK,
      now: NOW + 4_000,
    })).resolves.toMatchObject({
      accountId: ACCOUNT_ID,
      installId: INSTALL_ID,
      workerName: WORKER_NAME,
      gatewayCallback: BOOTSTRAP_CALLBACK,
      operation: 'install',
      receiptResourceKinds: null,
    });
    await expect(verifyCloudflareGatewayRelayTicket({
      ticket,
      signingKey: relayTicketKey,
      expectedClientId: CLIENT_ID,
      expectedOperation: 'install',
      expectedGatewayCallback: GATEWAY_CALLBACK,
      now: NOW + 4_000,
    })).rejects.toMatchObject({ code: 'operation_mismatch' });
    expect(store.records.size).toBe(0);
    await expect(issueCloudflareGatewayRelayTicketFromOwnershipProof({
      proof,
      pinnedIssuerPublicKey: value.issuerPublicKey,
      expectedKeyId: ISSUER_KEY_ID,
      expectedPublicClientId: CLIENT_ID,
      expectedOperation: 'install',
      now: NOW + 4_000,
      ticketExpiresAt: NOW + 6 * 60_000,
      relayTicketSigningKey: relayTicketKey,
      store,
    })).rejects.toMatchObject({ code: 'replayed' });
  });

  it('binds account, immutable Worker, namespace, callback, client, handoff, and customer key', async () => {
    const value = await fixture();
    const otherIssuer = await keyPair();
    const otherIssuerPublicKey = await publicKey(otherIssuer.publicKey);
    await expect(verifyCloudflareGatewayOwnershipCertificate({
      certificate: value.certificate,
      pinnedIssuerPublicKey: otherIssuerPublicKey,
      expectedKeyId: ISSUER_KEY_ID,
      expectedPublicClientId: CLIENT_ID,
    })).rejects.toMatchObject({ code: 'invalid_certificate' });
    await expect(verifyCloudflareGatewayOwnershipCertificate({
      certificate: value.certificate,
      pinnedIssuerPublicKey: value.issuerPublicKey,
      expectedKeyId: ISSUER_KEY_ID,
      expectedPublicClientId: `${CLIENT_ID}x`,
    })).rejects.toMatchObject({ code: 'invalid_certificate' });

    const parsed = JSON.parse(value.certificate);
    const statement = JSON.parse(parsed.statement);
    statement.worker.providerId = 'f'.repeat(32);
    parsed.statement = JSON.stringify(statement);
    await expect(verifyCloudflareGatewayOwnershipCertificate({
      certificate: JSON.stringify(parsed),
      pinnedIssuerPublicKey: value.issuerPublicKey,
      expectedKeyId: ISSUER_KEY_ID,
      expectedPublicClientId: CLIENT_ID,
    })).rejects.toBeInstanceOf(CloudflareGatewayOwnershipProofError);
  });

  it('rejects the wrong operation and wrong private key without consuming the valid challenge', async () => {
    const value = await fixture();
    const store = new MemoryChallengeStore();
    const challenge = await issueChallenge(value, store, 'rollback', NOW);
    const wrongOperation = await createCloudflareGatewayOwnershipProof({
      certificate: value.certificate,
      certificateSha256: challenge.certificateSha256,
      gatewayCallback: GATEWAY_CALLBACK,
      operation: 'upgrade',
      challenge: challenge.challenge,
      challengeExpiresAt: challenge.expiresAt,
      now: NOW + 1_000,
      ownershipPrivateKey: value.ownership.privateKey,
    });
    expect(await errorCode(verifyAndConsumeCloudflareGatewayOwnershipProof({
      proof: wrongOperation,
      pinnedIssuerPublicKey: value.issuerPublicKey,
      expectedKeyId: ISSUER_KEY_ID,
      expectedPublicClientId: CLIENT_ID,
      expectedOperation: 'rollback',
      now: NOW + 2_000,
      store,
    }))).toBe('operation_mismatch');
    expect(store.records.size).toBe(1);

    const otherOwnership = await keyPair();
    const wrongKey = await createCloudflareGatewayOwnershipProof({
      certificate: value.certificate,
      certificateSha256: challenge.certificateSha256,
      gatewayCallback: GATEWAY_CALLBACK,
      operation: 'rollback',
      challenge: challenge.challenge,
      challengeExpiresAt: challenge.expiresAt,
      now: NOW + 1_000,
      ownershipPrivateKey: otherOwnership.privateKey,
    });
    expect(await errorCode(verifyAndConsumeCloudflareGatewayOwnershipProof({
      proof: wrongKey,
      pinnedIssuerPublicKey: value.issuerPublicKey,
      expectedKeyId: ISSUER_KEY_ID,
      expectedPublicClientId: CLIENT_ID,
      expectedOperation: 'rollback',
      now: NOW + 2_000,
      store,
    }))).toBe('invalid_signature');
    expect(store.records.size).toBe(1);
  });

  it('requires fresh challenges and receipt-derived uninstall kinds only for uninstall', async () => {
    const value = await fixture();
    const expiredStore = new MemoryChallengeStore();
    const expired = await issueChallenge(value, expiredStore, 'uninstall', NOW);
    const expiredProof = await createCloudflareGatewayOwnershipProof({
      certificate: value.certificate,
      certificateSha256: expired.certificateSha256,
      gatewayCallback: GATEWAY_CALLBACK,
      operation: 'uninstall',
      receiptResourceKinds: ['worker', 'dns_record'],
      challenge: expired.challenge,
      challengeExpiresAt: expired.expiresAt,
      now: NOW + 1_000,
      ownershipPrivateKey: value.ownership.privateKey,
    });
    await expect(verifyAndConsumeCloudflareGatewayOwnershipProof({
      proof: expiredProof,
      pinnedIssuerPublicKey: value.issuerPublicKey,
      expectedKeyId: ISSUER_KEY_ID,
      expectedPublicClientId: CLIENT_ID,
      expectedOperation: 'uninstall',
      now: expired.expiresAt,
      store: expiredStore,
    })).rejects.toMatchObject({ code: 'expired' });
    expect(expiredStore.records.size).toBe(1);

    await expect(createCloudflareGatewayOwnershipProof({
      certificate: value.certificate,
      certificateSha256: value.verified.certificateSha256,
      gatewayCallback: GATEWAY_CALLBACK,
      operation: 'upgrade',
      receiptResourceKinds: ['worker'],
      challenge: randomBase64Url(32),
      challengeExpiresAt: NOW + 10_000,
      now: NOW,
      ownershipPrivateKey: value.ownership.privateKey,
    })).rejects.toMatchObject({ code: 'invalid' });
    await expect(createCloudflareGatewayOwnershipProof({
      certificate: value.certificate,
      certificateSha256: value.verified.certificateSha256,
      gatewayCallback: GATEWAY_CALLBACK,
      operation: 'uninstall',
      challenge: randomBase64Url(32),
      challengeExpiresAt: NOW + 10_000,
      now: NOW,
      ownershipPrivateKey: value.ownership.privateKey,
    })).rejects.toMatchObject({ code: 'invalid' });
  });

  it('requires customer-key possession before allocating or replacing challenge state', async () => {
    const value = await fixture();
    const store = new MemoryChallengeStore();
    const otherOwnership = await keyPair();
    const wrongKeyRequest = await createCloudflareGatewayOwnershipChallengeRequest({
      certificate: value.certificate,
      certificateSha256: value.verified.certificateSha256,
      operation: 'upgrade',
      now: NOW,
      ownershipPrivateKey: otherOwnership.privateKey,
    });
    await expect(issueCloudflareGatewayOwnershipChallenge({
      request: wrongKeyRequest,
      pinnedIssuerPublicKey: value.issuerPublicKey,
      expectedKeyId: ISSUER_KEY_ID,
      expectedPublicClientId: CLIENT_ID,
      expectedOperation: 'upgrade',
      now: NOW + 1,
      store,
    })).rejects.toMatchObject({ code: 'invalid_signature' });
    expect(store.writes).toHaveLength(0);

    const validRequest = await createCloudflareGatewayOwnershipChallengeRequest({
      certificate: value.certificate,
      certificateSha256: value.verified.certificateSha256,
      operation: 'upgrade',
      now: NOW,
      ownershipPrivateKey: value.ownership.privateKey,
    });
    await expect(issueCloudflareGatewayOwnershipChallenge({
      request: validRequest,
      pinnedIssuerPublicKey: value.issuerPublicKey,
      expectedKeyId: ISSUER_KEY_ID,
      expectedPublicClientId: CLIENT_ID,
      expectedOperation: 'rollback',
      now: NOW + 1,
      store,
    })).rejects.toMatchObject({ code: 'operation_mismatch' });
    expect(store.writes).toHaveLength(0);

    await expect(issueCloudflareGatewayOwnershipChallenge({
      request: validRequest,
      pinnedIssuerPublicKey: value.issuerPublicKey,
      expectedKeyId: ISSUER_KEY_ID,
      expectedPublicClientId: CLIENT_ID,
      expectedOperation: 'upgrade',
      now: NOW + 2 * 60_000,
      store,
    })).rejects.toMatchObject({ code: 'expired' });
    expect(store.writes).toHaveLength(0);

    const first = await issueChallenge(value, store, 'upgrade', NOW + 3 * 60_000);
    const second = await issueChallenge(value, store, 'upgrade', NOW + 3 * 60_000 + 1);
    expect(first.challenge).not.toBe(second.challenge);
    expect(store.records.size).toBe(1);
    expect(store.writes).toHaveLength(2);
  });

  it('persists only wrapped private material and imports it as non-extractable', async () => {
    const wrappingKey = randomBase64Url(32);
    const ownership = await generateSealedCloudflareGatewayOwnershipKeyPair(wrappingKey);
    expect(ownership.privateKey.extractable).toBe(false);
    const envelope = JSON.parse(ownership.sealedPrivateKey);
    expect(Object.keys(envelope).sort()).toEqual([
      'algorithm',
      'ciphertext',
      'encryption',
      'iv',
      'publicKey',
      'purpose',
      'schemaVersion',
    ]);
    expect(envelope).toMatchObject({
      schemaVersion: 1,
      purpose: 'cloudflare_gateway_ownership_private_key',
      algorithm: 'Ed25519',
      encryption: 'A256GCM',
      publicKey: ownership.publicKey,
      iv: expect.stringMatching(/^[A-Za-z0-9_-]{16}$/u),
      ciphertext: expect.stringMatching(/^[A-Za-z0-9_-]{86}$/u),
    });
    expect(ownership.sealedPrivateKey).not.toContain(wrappingKey);

    const reopened = await openSealedCloudflareGatewayOwnershipPrivateKey({
      sealedPrivateKey: ownership.sealedPrivateKey,
      wrappingKey,
      expectedPublicKey: ownership.publicKey,
    });
    expect(reopened.extractable).toBe(false);
    expect(reopened.usages).toEqual(['sign']);

    await expect(openSealedCloudflareGatewayOwnershipPrivateKey({
      sealedPrivateKey: ownership.sealedPrivateKey,
      wrappingKey: randomBase64Url(32),
      expectedPublicKey: ownership.publicKey,
    })).rejects.toMatchObject({ code: 'invalid_signature' });
    const other = await generateCloudflareGatewayOwnershipKeyPair();
    await expect(openSealedCloudflareGatewayOwnershipPrivateKey({
      sealedPrivateKey: ownership.sealedPrivateKey,
      wrappingKey,
      expectedPublicKey: other.publicKey,
    })).rejects.toMatchObject({ code: 'invalid_signature' });

    const tampered = JSON.parse(ownership.sealedPrivateKey);
    const replacement = tampered.ciphertext.endsWith('A') ? 'B' : 'A';
    tampered.ciphertext = `${tampered.ciphertext.slice(0, -1)}${replacement}`;
    await expect(openSealedCloudflareGatewayOwnershipPrivateKey({
      sealedPrivateKey: JSON.stringify(tampered),
      wrappingKey,
      expectedPublicKey: ownership.publicKey,
    })).rejects.toMatchObject({ code: 'invalid_signature' });
  });
});

import * as v from 'valibot';

import { canonicalJson } from '../src/canonical-json';
import {
  CLOUDFLARE_BOOTSTRAP_OWNERSHIP_HANDOFF_MAX_TTL_MS,
  CLOUDFLARE_BOOTSTRAP_PROVIDER_READBACK_MAX_AGE_MS,
  CloudflareBootstrapOwnershipHandoffError,
  issueCloudflareBootstrapOwnershipHandoff,
  proveCloudflareBootstrapOwnershipAdoption,
  randomCloudflareBootstrapOwnershipHandoffNonce,
  verifyCloudflareBootstrapOwnershipHandoff,
  verifyCloudflareBootstrapOwnershipHistory,
  type CloudflareBootstrapOwnershipHandoffDraft,
  type CloudflareBootstrapOwnershipHandoffStatement,
  type CloudflareBootstrapOwnershipProviderReadback,
} from '../src/cloudflare-bootstrap-ownership-handoff';
import { base64UrlEncode } from '../src/crypto';

const NOW = 2_000_000_000_000;
const ACCOUNT_ID = 'a'.repeat(32);
const OTHER_ACCOUNT_ID = 'b'.repeat(32);
const INSTALL_ID = `acg-${'c'.repeat(24)}`;
const OTHER_INSTALL_ID = `acg-${'d'.repeat(24)}`;
const WORKER_ID = 'e'.repeat(32);
const OTHER_WORKER_ID = 'f'.repeat(32);
const NAMESPACE_ID = '1'.repeat(32);
const OTHER_NAMESPACE_ID = '2'.repeat(32);
const ARTIFACT_SHA256 = '3'.repeat(64);
const OTHER_ARTIFACT_SHA256 = '4'.repeat(64);
const SECRET_COMMITMENT = `sha256:${'5'.repeat(64)}`;
const OTHER_SECRET_COMMITMENT = `sha256:${'6'.repeat(64)}`;

const parsedEnvelopeSchema = v.strictObject({
  purpose: v.string(),
  schemaVersion: v.number(),
  signature: v.string(),
  signatureContext: v.string(),
  statement: v.string(),
});
const parsedStatementSchema = v.strictObject({
  accountId: v.string(),
  adminState: v.strictObject({
    binding: v.literal('ADMIN_STATE'),
    className: v.literal('AdminState'),
    namespaceId: v.string(),
    storage: v.literal('sqlite'),
    workerProviderId: v.string(),
  }),
  bootstrapSecret: v.strictObject({
    commitment: v.string(),
    expiresAt: v.number(),
  }),
  expiresAt: v.number(),
  installId: v.string(),
  issuedAt: v.number(),
  nonce: v.string(),
  plan: v.strictObject({ id: v.string(), hash: v.string() }),
  purpose: v.literal('cloudflare_bootstrap_ownership_handoff'),
  release: v.strictObject({
    artifactSha256: v.string(),
    id: v.string(),
  }),
  schemaVersion: v.literal(2),
  worker: v.strictObject({
    name: v.string(),
    providerId: v.string(),
  }),
});

type ParsedEnvelope = v.InferOutput<typeof parsedEnvelopeSchema>;

function draft(
  overrides: Partial<CloudflareBootstrapOwnershipHandoffDraft> = {},
): CloudflareBootstrapOwnershipHandoffDraft {
  return {
    accountId: ACCOUNT_ID,
    adminState: {
      binding: 'ADMIN_STATE',
      className: 'AdminState',
      namespaceId: NAMESPACE_ID,
      storage: 'sqlite',
      workerProviderId: WORKER_ID,
    },
    bootstrapSecret: {
      commitment: SECRET_COMMITMENT,
      expiresAt: NOW + 60_000,
    },
    expiresAt: NOW + 120_000,
    installId: INSTALL_ID,
    issuedAt: NOW,
    plan: { id: `plan-${'7'.repeat(24)}`, hash: `sha256:${'8'.repeat(64)}` },
    release: {
      artifactSha256: ARTIFACT_SHA256,
      id: 'gateway-v1.2.3',
    },
    worker: {
      name: 'ankka-bootstrap-customer',
      providerId: WORKER_ID,
    },
    ...overrides,
  };
}

async function signingFixture(): Promise<{
  privateKey: CryptoKey;
  publicKey: string;
}> {
  const keyPair = await crypto.subtle.generateKey('Ed25519', true, ['sign', 'verify']);
  return {
    privateKey: keyPair.privateKey,
    publicKey: base64UrlEncode(
      new Uint8Array(await crypto.subtle.exportKey('raw', keyPair.publicKey)),
    ),
  };
}

function parseEnvelope(serialized: string): ParsedEnvelope {
  return v.parse(parsedEnvelopeSchema, JSON.parse(serialized));
}

function parseStatement(serialized: string): CloudflareBootstrapOwnershipHandoffStatement {
  return v.parse(parsedStatementSchema, JSON.parse(parseEnvelope(serialized).statement));
}

function readbackFor(
  statement: CloudflareBootstrapOwnershipHandoffStatement,
  observedAt = NOW + 5_000,
): CloudflareBootstrapOwnershipProviderReadback {
  return {
    accountId: statement.accountId,
    adminState: { ...statement.adminState },
    bootstrapSecret: { ...statement.bootstrapSecret },
    handoff: {
      expiresAt: statement.expiresAt,
      issuedAt: statement.issuedAt,
      nonce: statement.nonce,
    },
    installId: statement.installId,
    observedAt,
    plan: { ...statement.plan },
    purpose: 'cloudflare_bootstrap_ownership_provider_readback',
    release: { ...statement.release },
    schemaVersion: 2,
    worker: { ...statement.worker },
  };
}

async function expectHandoffError(
  promise: Promise<unknown>,
  code: CloudflareBootstrapOwnershipHandoffError['code'],
): Promise<void> {
  await expect(promise).rejects.toMatchObject({
    name: 'CloudflareBootstrapOwnershipHandoffError',
    code,
  });
}

describe('Cloudflare bootstrap ownership handoff', () => {

  it('issues canonical JSON with a fresh nonce and verifies with only the pinned public key', async () => {
    const signing = await signingFixture();
    const first = await issueCloudflareBootstrapOwnershipHandoff(draft(), signing.privateKey);
    const second = await issueCloudflareBootstrapOwnershipHandoff(draft(), signing.privateKey);
    const verified = await verifyCloudflareBootstrapOwnershipHandoff({
      now: NOW + 1,
      pinnedPublicKey: signing.publicKey,
      serializedHandoff: first,
    });

    const parsedFirst: unknown = JSON.parse(first);
    const parsedFirstStatement: unknown = JSON.parse(parseEnvelope(first).statement);
    expect(first).toBe(canonicalJson(parsedFirst));
    expect(parseEnvelope(first).statement).toBe(
      canonicalJson(parsedFirstStatement),
    );
    expect(parseEnvelope(first)).not.toHaveProperty('publicKey');
    expect(verified.verification).toBe('ed25519');
    expect(verified.statement).toMatchObject(draft());
    expect(verified.statement.nonce).toMatch(/^[A-Za-z0-9_-]{43}$/u);
    expect(verified.statement.nonce).not.toBe(parseStatement(second).nonce);
    expect(Object.isFrozen(verified)).toBe(true);
    expect(Object.isFrozen(verified.statement)).toBe(true);
    expect(Object.isFrozen(verified.statement.adminState)).toBe(true);
  });

  it('uses Web Crypto randomness for canonical 32-byte nonces', () => {
    const first = randomCloudflareBootstrapOwnershipHandoffNonce();
    const second = randomCloudflareBootstrapOwnershipHandoffNonce();
    expect(first).toMatch(/^[A-Za-z0-9_-]{43}$/u);
    expect(second).toMatch(/^[A-Za-z0-9_-]{43}$/u);
    expect(first).not.toBe(second);
  });

  it('binds every requested identity into the Ed25519 signature', async () => {
    const signing = await signingFixture();
    const serialized = await issueCloudflareBootstrapOwnershipHandoff(draft(), signing.privateKey);
    const envelope = parseEnvelope(serialized);
    const statement = parseStatement(serialized);
    const validOtherNonce = randomCloudflareBootstrapOwnershipHandoffNonce();
    const tampered: readonly CloudflareBootstrapOwnershipHandoffStatement[] = [
      { ...statement, accountId: OTHER_ACCOUNT_ID },
      { ...statement, installId: OTHER_INSTALL_ID },
      { ...statement, worker: { ...statement.worker, name: 'ankka-bootstrap-other' } },
      { ...statement, worker: { ...statement.worker, providerId: OTHER_WORKER_ID },
        adminState: { ...statement.adminState, workerProviderId: OTHER_WORKER_ID } },
      { ...statement, adminState: { ...statement.adminState, namespaceId: OTHER_NAMESPACE_ID } },
      { ...statement, release: { ...statement.release, id: 'gateway-v1.2.4' } },
      { ...statement, release: {
        ...statement.release,
        artifactSha256: OTHER_ARTIFACT_SHA256,
      } },
      { ...statement, bootstrapSecret: {
        ...statement.bootstrapSecret,
        commitment: OTHER_SECRET_COMMITMENT,
      } },
      { ...statement, bootstrapSecret: {
        ...statement.bootstrapSecret,
        expiresAt: statement.bootstrapSecret.expiresAt + 1,
      } },
      { ...statement, issuedAt: statement.issuedAt + 1 },
      { ...statement, expiresAt: statement.expiresAt + 1 },
      { ...statement, nonce: validOtherNonce },
    ];

    for (const candidate of tampered) {
      const tamperedEnvelope = canonicalJson({
        ...envelope,
        statement: canonicalJson(candidate),
      });
      await expectHandoffError(verifyCloudflareBootstrapOwnershipHandoff({
        now: NOW + 2,
        pinnedPublicKey: signing.publicKey,
        serializedHandoff: tamperedEnvelope,
      }), 'invalid_signature');
    }
  });

  it('rejects non-canonical encodings, unknown fields, and altered schema or purpose', async () => {
    const signing = await signingFixture();
    const serialized = await issueCloudflareBootstrapOwnershipHandoff(draft(), signing.privateKey);
    const envelope = parseEnvelope(serialized);
    const statement = parseStatement(serialized);
    const attempts = [
      `${serialized}\n`,
      canonicalJson({ ...envelope, unexpected: true }),
      canonicalJson({ ...envelope, statement: JSON.stringify(statement, null, 2) }),
      canonicalJson({ ...envelope, statement: canonicalJson({ ...statement, unexpected: true }) }),
      canonicalJson({ ...envelope, schemaVersion: 1 }),
      canonicalJson({ ...envelope, purpose: 'some_other_envelope' }),
      canonicalJson({
        ...envelope,
        statement: canonicalJson({ ...statement, schemaVersion: 1 }),
      }),
      canonicalJson({
        ...envelope,
        statement: canonicalJson({ ...statement, purpose: 'some_other_purpose' }),
      }),
    ];

    for (const attempt of attempts) {
      await expectHandoffError(verifyCloudflareBootstrapOwnershipHandoff({
        now: NOW + 1,
        pinnedPublicKey: signing.publicKey,
        serializedHandoff: attempt,
      }), 'invalid');
    }
  });

  it('rejects the wrong pinned verifier and a modified signature', async () => {
    const signing = await signingFixture();
    const otherSigning = await signingFixture();
    const serialized = await issueCloudflareBootstrapOwnershipHandoff(draft(), signing.privateKey);
    await expectHandoffError(verifyCloudflareBootstrapOwnershipHandoff({
      now: NOW + 1,
      pinnedPublicKey: otherSigning.publicKey,
      serializedHandoff: serialized,
    }), 'invalid_signature');

    const envelope = parseEnvelope(serialized);
    const changedFirstCharacter = envelope.signature.startsWith('A') ? 'B' : 'A';
    await expectHandoffError(verifyCloudflareBootstrapOwnershipHandoff({
      now: NOW + 1,
      pinnedPublicKey: signing.publicKey,
      serializedHandoff: canonicalJson({
        ...envelope,
        signature: `${changedFirstCharacter}${envelope.signature.slice(1)}`,
      }),
    }), 'invalid_signature');
  });

  it('enforces bounded issuance, not-before, handoff expiry, and secret expiry', async () => {
    const signing = await signingFixture();
    await expectHandoffError(issueCloudflareBootstrapOwnershipHandoff(draft({
      adminState: {
        ...draft().adminState,
        workerProviderId: OTHER_WORKER_ID,
      },
    }), signing.privateKey), 'invalid');
    await expectHandoffError(issueCloudflareBootstrapOwnershipHandoff(draft({
      expiresAt: NOW + CLOUDFLARE_BOOTSTRAP_OWNERSHIP_HANDOFF_MAX_TTL_MS + 1,
    }), signing.privateKey), 'invalid');
    await expectHandoffError(issueCloudflareBootstrapOwnershipHandoff(draft({
      bootstrapSecret: {
        commitment: SECRET_COMMITMENT,
        expiresAt: NOW + 120_001,
      },
    }), signing.privateKey), 'invalid');

    const serialized = await issueCloudflareBootstrapOwnershipHandoff(draft(), signing.privateKey);
    await expectHandoffError(verifyCloudflareBootstrapOwnershipHandoff({
      now: NOW - 1,
      pinnedPublicKey: signing.publicKey,
      serializedHandoff: serialized,
    }), 'not_yet_valid');
    await expectHandoffError(verifyCloudflareBootstrapOwnershipHandoff({
      now: NOW + 60_000,
      pinnedPublicKey: signing.publicKey,
      serializedHandoff: serialized,
    }), 'expired');

    const handoffExpiresFirst = await issueCloudflareBootstrapOwnershipHandoff(draft({
      bootstrapSecret: {
        commitment: SECRET_COMMITMENT,
        expiresAt: NOW + 120_000,
      },
    }), signing.privateKey);
    await expectHandoffError(verifyCloudflareBootstrapOwnershipHandoff({
      now: NOW + 120_000,
      pinnedPublicKey: signing.publicKey,
      serializedHandoff: handoffExpiresFirst,
    }), 'expired');
  });

  it('produces a deeply frozen Worker and namespace ownership projection after exact readback', async () => {
    const signing = await signingFixture();
    const serialized = await issueCloudflareBootstrapOwnershipHandoff(draft(), signing.privateKey);
    const statement = parseStatement(serialized);
    const receipt = await proveCloudflareBootstrapOwnershipAdoption({
      now: NOW + 5_000,
      pinnedPublicKey: signing.publicKey,
      providerReadback: readbackFor(statement),
      serializedHandoff: serialized,
    });

    expect(receipt).toMatchObject({
      accountId: ACCOUNT_ID,
      adoptedAt: NOW + 5_000,
      installId: INSTALL_ID,
      ownership: {
        worker: {
          kind: 'cloudflare_worker',
          name: 'ankka-bootstrap-customer',
          providerId: WORKER_ID,
        },
        adminStateNamespace: {
          kind: 'cloudflare_durable_object_namespace',
          providerId: NAMESPACE_ID,
          workerProviderId: WORKER_ID,
        },
      },
      providerReadAt: NOW + 5_000,
      release: {
        artifactSha256: ARTIFACT_SHA256,
        id: 'gateway-v1.2.3',
      },
    });
    expect(Object.isFrozen(receipt)).toBe(true);
    expect(Object.isFrozen(receipt.handoff)).toBe(true);
    expect(Object.isFrozen(receipt.ownership)).toBe(true);
    expect(Object.isFrozen(receipt.ownership.worker)).toBe(true);
    expect(Object.isFrozen(receipt.ownership.adminStateNamespace)).toBe(true);
    expect(Object.isFrozen(receipt.release)).toBe(true);
  });

  it('re-authenticates the historical adoption receipt after the handoff expires', async () => {
    const signing = await signingFixture();
    const serialized = await issueCloudflareBootstrapOwnershipHandoff(draft(), signing.privateKey);
    const statement = parseStatement(serialized);
    const receipt = await proveCloudflareBootstrapOwnershipAdoption({
      now: NOW + 5_000,
      pinnedPublicKey: signing.publicKey,
      providerReadback: readbackFor(statement),
      serializedHandoff: serialized,
    });

    const historical = await verifyCloudflareBootstrapOwnershipHistory({
      adoptionReceipt: receipt,
      pinnedPublicKey: signing.publicKey,
      serializedHandoff: serialized,
    });
    expect(historical).toEqual(receipt);
    expect(Object.isFrozen(historical)).toBe(true);

    await expectHandoffError(verifyCloudflareBootstrapOwnershipHistory({
      adoptionReceipt: {
        ...receipt,
        ownership: {
          ...receipt.ownership,
          worker: { ...receipt.ownership.worker, providerId: OTHER_WORKER_ID },
        },
      },
      pinnedPublicKey: signing.publicKey,
      serializedHandoff: serialized,
    }), 'receipt_mismatch');
  });

  it('rejects every mismatched readback identity, including a same-name Worker with another ID', async () => {
    const signing = await signingFixture();
    const serialized = await issueCloudflareBootstrapOwnershipHandoff(draft(), signing.privateKey);
    const statement = parseStatement(serialized);
    const readback = readbackFor(statement);
    const mismatches: readonly unknown[] = [
      { ...readback, accountId: OTHER_ACCOUNT_ID },
      { ...readback, installId: OTHER_INSTALL_ID },
      { ...readback, worker: { ...readback.worker, name: 'ankka-bootstrap-other' } },
      {
        ...readback,
        worker: { ...readback.worker, providerId: OTHER_WORKER_ID },
        adminState: { ...readback.adminState, workerProviderId: OTHER_WORKER_ID },
      },
      { ...readback, adminState: { ...readback.adminState, namespaceId: OTHER_NAMESPACE_ID } },
      { ...readback, adminState: {
        ...readback.adminState,
        workerProviderId: OTHER_WORKER_ID,
      } },
      { ...readback, release: { ...readback.release, id: 'gateway-v1.2.4' } },
      { ...readback, release: {
        ...readback.release,
        artifactSha256: OTHER_ARTIFACT_SHA256,
      } },
      { ...readback, bootstrapSecret: {
        ...readback.bootstrapSecret,
        commitment: OTHER_SECRET_COMMITMENT,
      } },
      { ...readback, bootstrapSecret: {
        ...readback.bootstrapSecret,
        expiresAt: readback.bootstrapSecret.expiresAt - 1,
      } },
      { ...readback, handoff: { ...readback.handoff, issuedAt: readback.handoff.issuedAt + 1 } },
      { ...readback, handoff: { ...readback.handoff, expiresAt: readback.handoff.expiresAt - 1 } },
      { ...readback, handoff: {
        ...readback.handoff,
        nonce: randomCloudflareBootstrapOwnershipHandoffNonce(),
      } },
    ];

    for (const providerReadback of mismatches) {
      await expectHandoffError(proveCloudflareBootstrapOwnershipAdoption({
        now: NOW + 5_000,
        pinnedPublicKey: signing.publicKey,
        providerReadback,
        serializedHandoff: serialized,
      }), 'identity_mismatch');
    }
  });

  it('rejects stale, future, pre-issuance, and non-strict provider readbacks', async () => {
    const signing = await signingFixture();
    const serialized = await issueCloudflareBootstrapOwnershipHandoff(draft(), signing.privateKey);
    const statement = parseStatement(serialized);

    await expectHandoffError(proveCloudflareBootstrapOwnershipAdoption({
      now: NOW + 50_000,
      pinnedPublicKey: signing.publicKey,
      providerReadback: readbackFor(
        statement,
        NOW + 50_000 - CLOUDFLARE_BOOTSTRAP_PROVIDER_READBACK_MAX_AGE_MS - 1,
      ),
      serializedHandoff: serialized,
    }), 'provider_readback_stale');
    await expectHandoffError(proveCloudflareBootstrapOwnershipAdoption({
      now: NOW + 5_000,
      pinnedPublicKey: signing.publicKey,
      providerReadback: readbackFor(statement, NOW + 5_001),
      serializedHandoff: serialized,
    }), 'provider_readback_stale');
    await expectHandoffError(proveCloudflareBootstrapOwnershipAdoption({
      now: NOW + 5_000,
      pinnedPublicKey: signing.publicKey,
      providerReadback: readbackFor(statement, NOW - 1),
      serializedHandoff: serialized,
    }), 'provider_readback_stale');
    await expectHandoffError(proveCloudflareBootstrapOwnershipAdoption({
      now: NOW + 5_000,
      pinnedPublicKey: signing.publicKey,
      providerReadback: { ...readbackFor(statement), unexpected: true },
      serializedHandoff: serialized,
    }), 'invalid');
  });

  it('never serializes the bootstrap secret or puts its commitment in the ownership receipt', async () => {
    const signing = await signingFixture();
    const rawBootstrapSecret = 'raw-bootstrap-secret-must-remain-customer-side';
    const serialized = await issueCloudflareBootstrapOwnershipHandoff(draft(), signing.privateKey);
    const statement = parseStatement(serialized);
    expect(serialized).not.toContain(rawBootstrapSecret);
    expect(serialized).toContain(SECRET_COMMITMENT);

    const receipt = await proveCloudflareBootstrapOwnershipAdoption({
      now: NOW + 5_000,
      pinnedPublicKey: signing.publicKey,
      providerReadback: readbackFor(statement),
      serializedHandoff: serialized,
    });
    expect(receipt).not.toHaveProperty('bootstrapSecret');
    expect(canonicalJson(receipt)).not.toContain(SECRET_COMMITMENT);
  });
});

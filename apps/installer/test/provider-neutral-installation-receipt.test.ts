import { describe, expect, it } from 'vitest';

import { deriveCustomerGatewayInstallationReceiptExpectation } from '../src/customer-bootstrap-request';
import { parseReadyInstallationReceipt } from '../src/provider-neutral-installation-receipt';
import { buildStaticDeployPlan, parseDeploySelection } from '../src/schema';
import type { AuthorizedTarget } from '../src/cloudflare-target';
import { manifest, NOW, selectionInput } from './fixtures';
import {
  readyInstallationReceiptFixture,
  resealInstallationReceiptFixture,
} from './provider-neutral-installation-receipt-fixture';

const selection = parseDeploySelection(selectionInput);
const target: AuthorizedTarget = {
  actor: { id: 'actor_12345678', email: 'owner@example.com' },
  account: { id: '1'.repeat(32), name: 'Example account' },
  zone: { id: '2'.repeat(32), name: 'example.com', status: 'active' },
};
const plan = await buildStaticDeployPlan(selection, manifest, NOW + 30 * 60_000);
const expected = await deriveCustomerGatewayInstallationReceiptExpectation({
  selection,
  target,
  plan,
  release: { id: manifest.release, artifactSha256: manifest.artifact.treeSha256 },
});

describe('provider-neutral installation receipt evidence', () => {
  it('accepts and freezes the exact checksum-valid reviewed seven-resource root', async () => {
    const receipt = await readyInstallationReceiptFixture(expected);
    const parsed = await parseReadyInstallationReceipt(structuredClone(receipt), expected);
    expect(parsed).toEqual(receipt);
    expect(Object.isFrozen(parsed)).toBe(true);
    expect(Object.isFrozen(parsed?.resources)).toBe(true);
    expect(Object.isFrozen(parsed?.resources[0])).toBe(true);
    expect(JSON.stringify(parsed)).not.toMatch(/token|secret|authorization|@example/iu);
  });

  it('accepts the current wizard\'s checksum-valid four-resource Portal root', async () => {
    const portalSelection = parseDeploySelection({ ...selectionInput, firstSource: null });
    const portalPlan = await buildStaticDeployPlan(portalSelection, manifest, NOW + 30 * 60_000);
    const portalExpected = await deriveCustomerGatewayInstallationReceiptExpectation({
      selection: portalSelection,
      target,
      plan: portalPlan,
      release: { id: manifest.release, artifactSha256: manifest.artifact.treeSha256 },
    });
    const receipt = await readyInstallationReceiptFixture(portalExpected, 5);

    await expect(parseReadyInstallationReceipt(receipt, portalExpected)).resolves.toEqual(receipt);
    expect(receipt.resources.map(({ kind }) => kind)).toEqual([
      'portal', 'portal_access_application', 'portal_access_policy', 'dns_record',
    ]);
  });

  it('rejects checksum tampering and self-consistent evidence outside the reviewed root', async () => {
    const receipt = await readyInstallationReceiptFixture(expected);
    await expect(parseReadyInstallationReceipt({ ...receipt, revision: receipt.revision + 1 }, expected))
      .resolves.toBeNull();

    const wrongHash = structuredClone(receipt) as any;
    wrongHash.resources[0] = { ...wrongHash.resources[0], desiredHash: `sha256:${'0'.repeat(64)}` };
    const resealedHash = await resealInstallationReceiptFixture(wrongHash);
    await expect(parseReadyInstallationReceipt(resealedHash, expected)).resolves.toBeNull();

    const wrongTarget = structuredClone(receipt) as any;
    wrongTarget.target = { ...wrongTarget.target, accountId: '3'.repeat(32) };
    const resealedTarget = await resealInstallationReceiptFixture(wrongTarget);
    await expect(parseReadyInstallationReceipt(resealedTarget, expected)).resolves.toBeNull();
  });

  it('rejects partial, reordered, duplicate, and parent-detached resource evidence', async () => {
    const receipt = await readyInstallationReceiptFixture(expected);
    const mutations = [
      (() => {
        const value = structuredClone(receipt) as unknown as Record<string, unknown>;
        delete value.accessPolicy;
        return value;
      })(),
      (() => {
        const value = structuredClone(receipt) as any;
        [value.resources[0], value.resources[1]] = [value.resources[1], value.resources[0]];
        return value;
      })(),
      (() => {
        const value = structuredClone(receipt) as any;
        value.resources[1] = {
          ...value.resources[1],
          provider: { id: value.resources[4].provider.id },
        };
        return value;
      })(),
      (() => {
        const value = structuredClone(receipt) as any;
        value.resources[2] = {
          ...value.resources[2],
          provider: { ...value.resources[2].provider, parentId: 'detached-parent' },
        };
        return value;
      })(),
    ];
    for (const value of mutations) {
      const resealed = 'checksum' in value
        ? await resealInstallationReceiptFixture(value as typeof receipt)
        : value;
      await expect(parseReadyInstallationReceipt(resealed, expected)).resolves.toBeNull();
    }
  });
});

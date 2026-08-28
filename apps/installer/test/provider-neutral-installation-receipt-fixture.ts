import type {
  InstallationReceiptResource,
  ReadyInstallationReceipt,
  ReadyInstallationReceiptExpectation,
} from '../src/provider-neutral-installation-receipt';
import { canonicalJson } from '../src/canonical-json';
import { sha256Hex } from '../src/crypto';

async function checksum<Value>(value: Value): Promise<string> {
  return `sha256:${await sha256Hex(canonicalJson(value))}`;
}

export async function readyInstallationReceiptFixture(
  expected: ReadyInstallationReceiptExpectation,
  revision = 14,
): Promise<ReadyInstallationReceipt> {
  const providerIds = expected.resources.map((_resource, index) => `provider-${index}`);
  const sourceApplicationIndex = expected.resources.findIndex(({ kind }) => kind === 'source_access_application');
  const portalApplicationIndex = expected.resources.findIndex(({ kind }) => kind === 'portal_access_application');
  const resources = expected.resources.map((resource, index): InstallationReceiptResource => {
    const providerId = providerIds.at(index);
    if (providerId === undefined) throw new TypeError('provider ID fixture');
    const common = {
      kind: resource.kind,
      key: resource.key,
      desiredHash: resource.desiredHash,
      marker: resource.marker,
    };
    if (resource.kind === 'source_access_policy' || resource.kind === 'portal_access_policy') {
      const parentIndex = resource.kind === 'source_access_policy'
        ? sourceApplicationIndex
        : portalApplicationIndex;
      if (resource.identityHash === undefined) throw new TypeError('policy identity fixture');
      const parentId = providerIds.at(parentIndex);
      if (parentId === undefined) throw new TypeError('policy parent ID fixture');
      return {
        ...common,
        provider: { id: providerId, parentId },
        identityHash: resource.identityHash,
      };
    }
    return { ...common, provider: { id: providerId } };
  });
  const unsigned = {
    schemaVersion: 1 as const,
    manager: 'ankka-mcp-gateway' as const,
    installationId: expected.installationId,
    state: 'ready' as const,
    revision,
    release: expected.release,
    target: { ...expected.target },
    accessPolicy: { ...expected.accessPolicy },
    desiredHash: expected.desiredHash,
    resources,
    pending: null,
  };
  return {
    ...unsigned,
    checksum: await checksum(unsigned),
  };
}

export async function resealInstallationReceiptFixture(
  value: ReadyInstallationReceipt,
): Promise<ReadyInstallationReceipt> {
  const { checksum: _checksum, ...unsigned } = structuredClone(value);
  return { ...unsigned, checksum: await checksum(unsigned) };
}

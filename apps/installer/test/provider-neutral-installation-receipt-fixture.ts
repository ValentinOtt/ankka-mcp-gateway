import type {
  ReadyInstallationReceipt,
  ReadyInstallationReceiptExpectation,
} from '../src/provider-neutral-installation-receipt';

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}
function canonicalJson(value: unknown): string {
  if (value === null || typeof value === 'boolean' || typeof value === 'string') return JSON.stringify(value);
  if (typeof value === 'number' && Number.isFinite(value)) return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (isRecord(value)) {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(',')}}`;
  }
  throw new TypeError('canonical fixture');
}

async function checksum(value: unknown): Promise<string> {
  const digest = new Uint8Array(await crypto.subtle.digest(
    'SHA-256',
    new TextEncoder().encode(canonicalJson(value)),
  ));
  return `sha256:${[...digest].map((byte) => byte.toString(16).padStart(2, '0')).join('')}`;
}

export async function readyInstallationReceiptFixture(
  expected: ReadyInstallationReceiptExpectation,
  revision = 14,
): Promise<ReadyInstallationReceipt> {
  const providerIds = expected.resources.map((_resource, index) => `provider-${index}`);
  const sourceApplicationIndex = expected.resources.findIndex(({ kind }) => kind === 'source_access_application');
  const portalApplicationIndex = expected.resources.findIndex(({ kind }) => kind === 'portal_access_application');
  const resources = expected.resources.map((resource, index) => ({
    kind: resource.kind,
    key: resource.key,
    provider: resource.kind === 'source_access_policy'
      ? { id: providerIds[index], parentId: providerIds[sourceApplicationIndex] }
      : resource.kind === 'portal_access_policy'
        ? { id: providerIds[index], parentId: providerIds[portalApplicationIndex] }
        : { id: providerIds[index] },
    desiredHash: resource.desiredHash,
    marker: resource.marker,
    ...(resource.identityHash === undefined ? {} : { identityHash: resource.identityHash }),
  }));
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
  } as ReadyInstallationReceipt;
}

export async function resealInstallationReceiptFixture(
  value: ReadyInstallationReceipt,
): Promise<ReadyInstallationReceipt> {
  const { checksum: _checksum, ...unsigned } = structuredClone(value);
  return { ...unsigned, checksum: await checksum(unsigned) } as ReadyInstallationReceipt;
}

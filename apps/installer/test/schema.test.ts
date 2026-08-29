import { REQUIRED_OAUTH_SCOPES } from '../src/constants';
import {
  assertSecretFree,
  forbiddenStoredKeyPath,
  buildStaticDeployPlan,
  parseDeploySelection,
  parseReleaseManifest,
  parseStaticDeployPlan,
} from '../src/schema';
import { manifest, NOW, requiredFixture, selectionInput } from './fixtures';

describe('strict deployment contracts', () => {
  it('canonicalizes admin and portal audiences while preserving explicit roles', () => {
    const selection = parseDeploySelection(selectionInput);
    const firstSource = requiredFixture(selection.firstSource ?? undefined, 'first source');
    expect(selection.basics.adminEmail).toBe('owner@example.com');
    expect(selection.basics.additionalAdminEmails).toEqual(['admin@example.com']);
    expect(firstSource.portalUserEmails).toEqual([
      'admin@example.com',
      'member@example.com',
      'owner@example.com',
    ]);
    expect(firstSource.enabledTools).toEqual(['company_prepare', 'company_search']);

    expect(() => parseDeploySelection({
      ...selectionInput,
      basics: {
        ...selectionInput.basics,
        additionalAdminEmails: Array.from(
          { length: 19 },
          (_value, index) => `admin-${String(index).padStart(2, '0')}@example.com`,
        ),
      },
      firstSource: {
        ...selectionInput.firstSource,
        portalUserEmails: Array.from(
          { length: 50 },
          (_value, index) => `member-${String(index).padStart(2, '0')}@example.com`,
        ),
      },
    })).toThrow(expect.objectContaining({
      code: 'bad_request',
      reason: 'portal_user_emails_invalid',
    }));
  });

  it('preserves 228- and 224-tool sources and rejects input above the 500-tool bound', () => {
    for (const toolCount of [228, 224]) {
      const largeToolNames = Array.from(
        { length: toolCount },
        (_value, index) => `synthetic_read_${String(index + 1).padStart(3, '0')}`,
      );
      const parsed = parseDeploySelection({
        ...selectionInput,
        firstSource: { ...selectionInput.firstSource, enabledTools: largeToolNames },
      });

      expect(requiredFixture(parsed.firstSource ?? undefined, 'first source').enabledTools)
        .toEqual(largeToolNames);
    }
    expect(() => parseDeploySelection({
      ...selectionInput,
      firstSource: {
        ...selectionInput.firstSource,
        enabledTools: Array.from(
          { length: 501 },
          (_value, index) => `synthetic_read_${String(index + 1).padStart(3, '0')}`,
        ),
      },
    })).toThrow(expect.objectContaining({
      code: 'bad_request',
      reason: 'enabled_tools_invalid',
    }));
  });

  it('rejects unknown fields, out-of-zone hostnames, and credential-like source URLs', () => {
    expect(() => parseDeploySelection({ ...selectionInput, surprise: true })).toThrow();
    expect(() => parseDeploySelection({
      ...selectionInput,
      basics: { ...selectionInput.basics, portalHostname: 'mcp.other.test' },
    })).toThrow();
    expect(() => parseDeploySelection({
      ...selectionInput,
      firstSource: { ...selectionInput.firstSource, url: 'https://user:pass@source.example.net/mcp' },
    })).toThrow();
  });

  it('returns fixed secret-free reasons that let agents repair selection fields', () => {
    expect(() => parseDeploySelection({
      ...selectionInput,
      basics: { ...selectionInput.basics, adminEmail: '' },
    })).toThrow(expect.objectContaining({
      code: 'bad_request',
      reason: 'admin_email_invalid',
    }));
    expect(() => parseDeploySelection({
      ...selectionInput,
      basics: { ...selectionInput.basics, managementHostname: 'manage.other.net' },
    })).toThrow(expect.objectContaining({
      code: 'bad_request',
      reason: 'gateway_hostnames_invalid',
    }));
    expect(() => parseDeploySelection({
      ...selectionInput,
      firstSource: { ...selectionInput.firstSource, enabledTools: ['not a tool'] },
    })).toThrow(expect.objectContaining({
      code: 'bad_request',
      reason: 'enabled_tool_name_invalid',
    }));
  });

  it('requires the pinned current dot-delimited OAuth scope set exactly', () => {
    expect(parseReleaseManifest(manifest).oauthScopeIds).toEqual(REQUIRED_OAUTH_SCOPES);
    expect(() => parseReleaseManifest({
      ...manifest,
      oauthScopeIds: REQUIRED_OAUTH_SCOPES.slice(1),
    })).toThrow();
    expect(() => parseReleaseManifest({
      ...manifest,
      oauthScopeIds: [...REQUIRED_OAUTH_SCOPES, 'workers_scripts:write'],
    })).toThrow();
  });

  it('builds a hash-bound plan with five management and seven gateway resources', async () => {
    const selection = parseDeploySelection(selectionInput);
    const plan = await buildStaticDeployPlan(selection, manifest, NOW + 600_000);
    expect(plan.managementResources.map((resource) => resource.kind)).toEqual([
      'management_worker',
      'management_durable_object',
      'management_assets',
      'management_access_application',
      'management_access_policy',
    ]);
    expect(plan.gatewayResources.map((resource) => resource.kind)).toEqual([
      'mcp_server',
      'source_access_application',
      'source_access_policy',
      'portal',
      'portal_access_application',
      'portal_access_policy',
      'dns_record',
    ]);
    expect(plan.managementResources.find(({ kind }) => kind === 'management_durable_object')?.name)
      .toBe(`ankka-gateway-example-gateway-${plan.managementOwnershipMarker}-state`);
    expect(plan.managementOwnershipMarker).toMatch(/^acg-[a-f0-9]{24}$/u);
    expect(plan.managementResources.find(({ kind }) => kind === 'management_access_application')?.name)
      .toBe(`Example Gateway management [${plan.managementOwnershipMarker}]`);
    expect(requiredFixture(plan.gatewayConfiguration.firstSource ?? undefined, 'first source').enabledTools).toEqual([
      'company_prepare',
      'company_search',
    ]);
    expect(plan.releaseArtifactSha256).toBe(manifest.artifact.treeSha256);
    expect(plan.workerBundleSha256).toBe(manifest.components.worker.treeSha256);
    expect(plan.dashboardAssetsSha256).toBe(manifest.components.admin.treeSha256);
    expect(plan.releaseArtifactSha256).not.toBe(plan.workerBundleSha256);
    expect(parseStaticDeployPlan(plan)).toEqual(plan);
    expect(() => parseStaticDeployPlan({
      ...plan,
      managementOwnershipMarker: `acg-${'f'.repeat(24)}`,
    })).toThrow();
    expect(() => parseStaticDeployPlan({
      ...plan,
      managementResources: [...plan.managementResources].reverse(),
    })).toThrow();
  });

  it('builds the wizard plan as an empty portal with no placeholder source resources', async () => {
    const selection = parseDeploySelection({ ...selectionInput, firstSource: null });
    const plan = await buildStaticDeployPlan(selection, manifest, NOW + 600_000);

    expect(selection.firstSource).toBeNull();
    expect(plan.gatewayConfiguration.firstSource).toBeNull();
    expect(plan.gatewayResources.map((resource) => resource.kind)).toEqual([
      'portal',
      'portal_access_application',
      'portal_access_policy',
      'dns_record',
    ]);
    expect(plan.portalAudienceEmails).toEqual(['admin@example.com', 'owner@example.com']);
    expect(parseStaticDeployPlan(plan)).toEqual(plan);
  });

  it('changes the approval hash when an enabled tool changes', async () => {
    const first = await buildStaticDeployPlan(parseDeploySelection(selectionInput), manifest, NOW + 600_000);
    const second = await buildStaticDeployPlan(parseDeploySelection({
      ...selectionInput,
      firstSource: { ...selectionInput.firstSource, enabledTools: ['company_prepare'] },
    }), manifest, NOW + 600_000);
    expect(second.planHash).not.toBe(first.planHash);
    expect(second.planId).not.toBe(first.planId);
  });

  it('keeps desired-plan identity stable across a fresh approval expiry window', async () => {
    const selection = parseDeploySelection(selectionInput);
    const first = await buildStaticDeployPlan(selection, manifest, NOW + 600_000);
    const renewed = await buildStaticDeployPlan(selection, manifest, NOW + 1_200_000);
    expect(renewed.expiresAt).not.toBe(first.expiresAt);
    expect(renewed.planId).toBe(first.planId);
    expect(renewed.planHash).toBe(first.planHash);
    expect(renewed.managementOwnershipMarker).toBe(first.managementOwnershipMarker);
    expect(renewed.managementResources).toEqual(first.managementResources);
    expect(renewed.gatewayResources).toEqual(first.gatewayResources);
  });

  it('keeps provider-visible marked management names within provider limits', async () => {
    const selection = parseDeploySelection({
      ...selectionInput,
      basics: { ...selectionInput.basics, gatewayName: 'A'.repeat(80) },
    });
    const plan = await buildStaticDeployPlan(selection, manifest, NOW + 600_000);
    const worker = plan.managementResources.find(({ kind }) => kind === 'management_worker');
    const application = plan.managementResources.find(
      ({ kind }) => kind === 'management_access_application',
    );
    const policy = plan.managementResources.find(({ kind }) => kind === 'management_access_policy');
    expect(worker?.name.length).toBeLessThanOrEqual(63);
    expect(application?.name.length).toBeLessThanOrEqual(128);
    expect(policy?.name.length).toBeLessThanOrEqual(128);
    expect(parseStaticDeployPlan(plan)).toEqual(plan);
  });

  it('binds aggregate release identity independently from unchanged upload component hashes', async () => {
    const selection = parseDeploySelection(selectionInput);
    const first = await buildStaticDeployPlan(selection, manifest, NOW + 600_000);
    const changedArtifact = {
      ...manifest,
      artifact: { ...manifest.artifact, treeSha256: '8'.repeat(64) },
    };
    const second = await buildStaticDeployPlan(selection, changedArtifact, NOW + 600_000);
    expect(second.workerBundleSha256).toBe(first.workerBundleSha256);
    expect(second.dashboardAssetsSha256).toBe(first.dashboardAssetsSha256);
    expect(second.releaseArtifactSha256).not.toBe(first.releaseArtifactSha256);
    expect(second.planHash).not.toBe(first.planHash);
    expect(second.planId).not.toBe(first.planId);
  });

  it('matches the client tool-name contract and repeats its public-host source guard', () => {
    const selection = parseDeploySelection({
      ...selectionInput,
      firstSource: { ...selectionInput.firstSource, enabledTools: ['tools/search:v1'] },
    });
    expect(requiredFixture(selection.firstSource ?? undefined, 'first source').enabledTools)
      .toEqual(['tools/search:v1']);
    expect(() => parseDeploySelection({
      ...selectionInput,
      firstSource: { ...selectionInput.firstSource, url: 'https://source.internal/mcp' },
    })).toThrow();
  });

  it('rejects secret-bearing storage fields', () => {
    expect(() => assertSecretFree({ accessToken: 'nope' })).toThrow();
    expect(() => assertSecretFree({ oauth: { codeVerifier: 'nope' } })).toThrow();
    expect(() => assertSecretFree({ cloudflareAccessToken: 'nope' })).toThrow();
    expect(() => assertSecretFree({ bootstrapNonce: 'nope' })).toThrow();
    expect(() => assertSecretFree({ workerClientSecret: 'nope' })).toThrow();
    expect(() => assertSecretFree({ assetUploadJwt: 'nope' })).toThrow();
    expect(() => assertSecretFree({ hmacSignature: 'nope' })).toThrow();
    expect(() => assertSecretFree({ stateHash: 'safe', verifierHash: 'safe' })).not.toThrow();
    expect(() => assertSecretFree({ nonceHash: 'safe', signatureHash: 'safe' })).not.toThrow();
    expect(forbiddenStoredKeyPath({ record: { attempts: [{ bootstrapNonce: 'nope' }] } }))
      .toBe('record.attempts[0].bootstrapNonce');
  });
});

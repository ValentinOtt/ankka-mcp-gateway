import * as v from 'valibot';
import { describe, expect, it } from 'vitest';
import { boundaryObjectSchema } from '../src/boundary';
import type { CloudflareDirectUploadCall } from '../src/cloudflare-worker-direct-upload';
import {
  CloudflareUninstallWorkerLifecycleError,
  inspectUninstallWorkerDeploymentRecovery,
  inspectUninstallWorkerVersionRecovery,
  parseAdminStateNamespacePresenceProof,
  parseAdminStateNamespaceRetirementProof,
  parseCloudflareUninstallWorkerLifecycleJournalRecord,
  parseCloudflareUninstallWorkerLifecycleSubmission,
  parseUninstallWorkerDeploymentMutationIntent,
  parseUninstallWorkerVersionRecoveryRecord,
  parseWorkerDeletionRecoveryProof,
  parseWorkerDeleteMutationIntent,
  prepareCleanupWorkerVersionMutation,
  prepareRetirementWorkerVersionMutation,
  prepareUninstallWorkerDeploymentMutation,
  prepareWorkerDeleteMutation,
  proveActiveCleanupWorkerVersion,
  proveAdminStateNamespaceRetired,
  provePersistedAdminStateNamespacePresent,
  recoverWorkerDeletionOutcome,
  submitUninstallWorkerDeploymentMutation,
  submitUninstallWorkerVersionMutation,
  submitWorkerDeleteMutation,
  verifyRestoredCleanWorkerDeploymentIsActive,
  verifyUninstallWorkerDeploymentIsActive,
  verifyUninstallWorkerDeploymentSubmission,
  verifyUninstallWorkerVersionSubmission,
  type UninstallCleanupVariables,
  type CleanupWorkerVersionRecoveryRecord,
  type RetirementWorkerVersionRecoveryRecord,
  type UninstallWorkerDeploymentMutationIntent,
  type UninstallWorkerVersionMutationPlan,
} from '../src/cloudflare-uninstall-worker-lifecycle';
import type { VerifiedGatewayWorkerReleaseSet } from '../src/release-direct-upload-adapter';
import { APPROVED_CLOUDFLARE_RELEASE_CONTRACT } from '../src/release-manifest';
import { requiredFixture } from './fixtures';

const ACCOUNT_ID = 'a'.repeat(32);
const ZONE_ID = 'b'.repeat(32);
const WORKER_ID = 'c'.repeat(32);
const NAMESPACE_ID = 'd'.repeat(32);
const WORKER_NAME = 'ankka-mcp-gateway';
const CYCLE_ID = 'uninstall-' + 'e'.repeat(24);
const VERSION_ID = '11111111-1111-4111-8111-111111111111';
const RETIREMENT_VERSION_ID = '22222222-2222-4222-8222-222222222222';
const DEPLOYMENT_ID = '33333333-3333-4333-8333-333333333333';
const CLEAN_VERSION_ID = '44444444-4444-4444-8444-444444444444';
const ACCESS_TOKEN = 'token-for-focused-test-only';
const UNINSTALL_NONCE = 'N'.repeat(43);
const RELEASE = 'gateway-v1.2.3';
const ARTIFACT_SHA = '1'.repeat(64);
const CLEANUP_COMPONENT_SHA = '2'.repeat(64);
const RETIREMENT_COMPONENT_SHA = '3'.repeat(64);
const EMPTY_COMPATIBILITY_FLAGS: readonly [] = Object.freeze([]);
const objectContainerSchema = v.object({});
const versionBindingSchema = v.object({
  class_name: v.optional(v.string()),
  name: v.string(),
  namespace_id: v.optional(v.string()),
  text: v.optional(v.string()),
  type: v.string(),
});
const versionModuleSchema = v.object({
  content_base64: v.string(),
  content_type: v.string(),
  name: v.string(),
});
const versionBodySchema = v.object({
  annotations: boundaryObjectSchema,
  bindings: v.array(versionBindingSchema),
  compatibility_date: v.string(),
  compatibility_flags: v.array(v.string()),
  exports: boundaryObjectSchema,
  main_module: v.string(),
  modules: v.array(versionModuleSchema),
});

interface TestNamespaceItem {
  readonly id: string;
  readonly class: string;
  readonly name: string;
  readonly script: string;
  readonly use_sqlite: boolean;
}

async function sha256(bytes: Uint8Array): Promise<string> {
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', new Uint8Array(bytes)));
  return [...digest].map((byte) => byte.toString(16).padStart(2, '0')).join('');
}

function expectDeepFrozen<Value>(value: Value, seen = new Set<object>()): void {
  if (!v.is(objectContainerSchema, value) || seen.has(value)) return;
  seen.add(value);
  expect(Object.isFrozen(value)).toBe(true);
  for (const descriptor of Object.values(Object.getOwnPropertyDescriptors(value))) {
    if (Object.hasOwn(descriptor, 'value')) expectDeepFrozen(descriptor.value, seen);
  }
}

async function releaseSet(): Promise<VerifiedGatewayWorkerReleaseSet> {
  const primaryBytes = new TextEncoder().encode('export default {fetch(){return new Response("ok")}};');
  const bootstrapBytes = new TextEncoder().encode('export class AdminState{}; export default {fetch(){}};');
  const cleanupBytes = new TextEncoder().encode('export class AdminState{}; export default {fetch(){}};');
  const retirementBytes = new TextEncoder().encode('export default {fetch(){return new Response(null,{status:410})}};');
  return Object.freeze({
    bootstrap: Object.freeze({
      verification: 'ed25519',
      release: RELEASE,
      artifactSha256: ARTIFACT_SHA,
      componentSha256: '4'.repeat(64),
      worker: Object.freeze({
        mainModule: 'index.js',
        compatibilityDate: '2026-08-08',
        compatibilityFlags: EMPTY_COMPATIBILITY_FLAGS,
        modules: Object.freeze([Object.freeze({
          name: 'index.js', contentType: 'application/javascript+module',
          sha256: await sha256(bootstrapBytes), bytes: bootstrapBytes,
        })]),
        assets: Object.freeze({
          binding: 'ASSETS', notFoundHandling: 'single-page-application',
          runWorkerFirst: Object.freeze(['/__ankka/*', '/api/*'] as const),
          files: Object.freeze([Object.freeze({
            path: '/index.html', contentType: 'text/html; charset=utf-8',
            sha256: await sha256(new TextEncoder().encode('<p/>')),
            bytes: new TextEncoder().encode('<p/>'),
          })]),
        }),
        durableObject: Object.freeze({ binding: 'ADMIN_STATE', className: 'AdminState', storage: 'sqlite' }),
      }),
    }),
    primary: Object.freeze({
      verification: 'ed25519',
      release: RELEASE,
      artifactSha256: ARTIFACT_SHA,
      worker: Object.freeze({
        mainModule: 'index.js',
        compatibilityDate: '2026-08-08',
        compatibilityFlags: EMPTY_COMPATIBILITY_FLAGS,
        modules: Object.freeze([Object.freeze({
          name: 'index.js', contentType: 'application/javascript+module',
          sha256: await sha256(primaryBytes), bytes: primaryBytes,
        })]),
        assets: Object.freeze({
          binding: 'ASSETS',
          notFoundHandling: 'single-page-application',
          runWorkerFirst: Object.freeze(['/__ankka/*', '/api/*'] as const),
          files: Object.freeze([Object.freeze({
            path: '/index.html', contentType: 'text/html; charset=utf-8',
            sha256: await sha256(new TextEncoder().encode('<p/>')),
            bytes: new TextEncoder().encode('<p/>'),
          })]),
        }),
        durableObject: Object.freeze({ binding: 'ADMIN_STATE', className: 'AdminState', storage: 'sqlite' }),
      }),
    }),
    cleanup: Object.freeze({
      verification: 'ed25519',
      release: RELEASE,
      artifactSha256: ARTIFACT_SHA,
      componentSha256: CLEANUP_COMPONENT_SHA,
      variant: 'cleanup',
      worker: Object.freeze({
        contract: APPROVED_CLOUDFLARE_RELEASE_CONTRACT.workerVariants.cleanup,
        modules: Object.freeze([Object.freeze({
          name: 'index.js', contentType: 'application/javascript+module',
          sha256: await sha256(cleanupBytes), bytes: cleanupBytes,
        })]),
      }),
    }),
    retirement: Object.freeze({
      verification: 'ed25519',
      release: RELEASE,
      artifactSha256: ARTIFACT_SHA,
      componentSha256: RETIREMENT_COMPONENT_SHA,
      variant: 'retirement',
      worker: Object.freeze({
        contract: APPROVED_CLOUDFLARE_RELEASE_CONTRACT.workerVariants.retirement,
        modules: Object.freeze([Object.freeze({
          name: 'index.js', contentType: 'application/javascript+module',
          sha256: await sha256(retirementBytes), bytes: retirementBytes,
        })]),
      }),
    }),
  });
}

function variables(): UninstallCleanupVariables {
  return Object.freeze({
    ANKKA_GATEWAY_RELEASE: RELEASE,
    ANKKA_GATEWAY_RELEASE_SHA256: `sha256:${ARTIFACT_SHA}`,
    CLOUDFLARE_ACCOUNT_ID: ACCOUNT_ID,
    CLOUDFLARE_ZONE_ID: ZONE_ID,
    CLOUDFLARE_ZONE_NAME: 'example.com',
    ZERO_TRUST_READY: 'true',
  });
}

async function cleanupPlan(): Promise<UninstallWorkerVersionMutationPlan> {
  return await prepareCleanupWorkerVersionMutation({
    accountId: ACCOUNT_ID,
    workerName: WORKER_NAME,
    workerId: WORKER_ID,
    namespaceId: NAMESPACE_ID,
    uninstallCycleId: CYCLE_ID,
    releaseSet: await releaseSet(),
    variables: variables(),
    uninstallNonce: UNINSTALL_NONCE,
  });
}

async function retirementPlan(): Promise<UninstallWorkerVersionMutationPlan> {
  return await prepareRetirementWorkerVersionMutation({
    accountId: ACCOUNT_ID,
    workerName: WORKER_NAME,
    workerId: WORKER_ID,
    uninstallCycleId: CYCLE_ID,
    releaseSet: await releaseSet(),
  });
}

function json<Result>(result: Result, status = 200): Response {
  return Response.json({ success: true, errors: [], messages: [], result }, { status });
}

function absent(): Response {
  return Response.json({
    success: false,
    errors: [{ code: 10090, message: 'not found' }],
    messages: [],
    result: null,
  }, { status: 404 });
}

function callWith(
  handler: (request: Request, index: number) => Response | Promise<Response>,
): CloudflareDirectUploadCall & {
  readonly requests: Array<{ readonly body: ReadableStream | null; readonly method: string; readonly url: string }>;
} {
  const requests: Array<{ readonly body: ReadableStream | null; readonly method: string; readonly url: string }> = [];
  return {
    accessToken: ACCESS_TOKEN,
    requests,
    transport: async (request) => {
      requests.push({ body: request.body, method: request.method, url: request.url });
      return await handler(request, requests.length - 1);
    },
  };
}

function bodyOf(plan: UninstallWorkerVersionMutationPlan): v.InferOutput<typeof versionBodySchema> {
  return v.parse(versionBodySchema, plan.ephemeral.body);
}

function versionResult(
  plan: UninstallWorkerVersionMutationPlan,
  versionId: string,
  options: { readonly includeModuleBytes?: boolean; readonly badNamespace?: boolean } = {},
 ) {
  const body = bodyOf(plan);
  const bindings = body.bindings.map((binding) => {
    if (binding.type === 'secret_text') return { name: binding.name, type: binding.type };
    if (binding.name === 'ADMIN_STATE' && options.badNamespace) {
      return { ...binding, namespace_id: 'f'.repeat(32) };
    }
    return { ...binding };
  });
  const modules = body.modules.map((module) => {
    const identity = { name: module.name, content_type: module.content_type };
    return options.includeModuleBytes ? { ...identity, content_base64: module.content_base64 } : identity;
  });
  const retirement = plan.recovery.stage === 'retirement';
  return {
    id: versionId,
    number: 7,
    created_on: '2026-08-23T01:00:00.000Z',
    annotations: body.annotations,
    compatibility_date: body.compatibility_date,
    compatibility_flags: [],
    main_module: 'index.js',
    bindings,
    modules,
    // Cloudflare omits a declarative deleted tombstone from returned exports.
    exports: retirement ? { default: { type: 'worker' } } : {
      AdminState: { type: 'durable-object', storage: 'sqlite' },
      default: { type: 'worker' },
    },
    exports_reconciliation: {
      created: [],
      deleted: retirement ? ['AdminState'] : [],
      info: [],
      removable_entries: [],
      renamed: [],
      transfer_pending: [],
      transferred: [],
      updated: [],
      warnings: [],
    },
  };
}

function versionSubmission(plan: UninstallWorkerVersionMutationPlan, versionId = VERSION_ID) {
  return Object.freeze({
    kind: 'uninstall_worker_version' as const,
    stage: plan.recovery.stage,
    accountId: ACCOUNT_ID,
    workerName: WORKER_NAME,
    workerId: WORKER_ID,
    uninstallCycleId: CYCLE_ID,
    versionId,
    requestHash: plan.recovery.requestHash,
    correlationTag: plan.recovery.correlationTag,
  });
}

function deploymentResult(intent: UninstallWorkerDeploymentMutationIntent, id = DEPLOYMENT_ID) {
  return {
    id,
    created_on: '2026-08-23T01:01:00.000Z',
    source: 'api',
    strategy: 'percentage',
    annotations: { 'workers/message': intent.correlationTag },
    versions: [{ percentage: 100, version_id: intent.versionId }],
  };
}

function namespacePage(items: readonly TestNamespaceItem[]): Response {
  return Response.json({
    success: true,
    errors: [],
    messages: [],
    result: items,
    result_info: {
      count: items.length,
      page: 1,
      per_page: 1_000,
      total_count: items.length,
      total_pages: items.length === 0 ? 0 : 1,
    },
  });
}

function namespaceItem() {
  return {
    id: NAMESPACE_ID,
    class: 'AdminState',
    name: `${WORKER_NAME}-AdminState`,
    script: WORKER_NAME,
    use_sqlite: true,
  };
}

async function retirementAuthority() {
  const plan = await retirementPlan();
  const submission = versionSubmission(plan, RETIREMENT_VERSION_ID);
  const deploymentIntent = await prepareUninstallWorkerDeploymentMutation({
    stage: 'retirement', accountId: ACCOUNT_ID, workerName: WORKER_NAME, workerId: WORKER_ID,
    uninstallCycleId: CYCLE_ID, versionId: RETIREMENT_VERSION_ID,
  });
  const deploymentSubmission = Object.freeze({
    kind: 'uninstall_worker_deployment' as const,
    stage: 'retirement' as const,
    accountId: ACCOUNT_ID,
    workerName: WORKER_NAME,
    workerId: WORKER_ID,
    uninstallCycleId: CYCLE_ID,
    versionId: RETIREMENT_VERSION_ID,
    deploymentId: DEPLOYMENT_ID,
    requestHash: deploymentIntent.requestHash,
    correlationTag: deploymentIntent.correlationTag,
  });
  const proofInput = Object.freeze({
    namespace: Object.freeze({
      accountId: ACCOUNT_ID,
      namespaceId: NAMESPACE_ID,
      namespaceName: `${WORKER_NAME}-AdminState`,
      workerName: WORKER_NAME,
      className: 'AdminState' as const,
      storage: 'sqlite' as const,
    }),
    workerId: WORKER_ID,
    uninstallCycleId: CYCLE_ID,
    retirementRecovery: retirementRecovery(plan),
    retirementSubmission: submission,
    retirementDeploymentIntent: deploymentIntent,
    retirementDeploymentSubmission: deploymentSubmission,
  });
  return Object.freeze({ plan, submission, deploymentIntent, deploymentSubmission, proofInput });
}

function retirementProofCall(
  authority: Awaited<ReturnType<typeof retirementAuthority>>,
  firstNamespaces: readonly TestNamespaceItem[] = [],
  secondNamespaces: readonly TestNamespaceItem[] = firstNamespaces,
  deleted: Response | (() => Response) = () => json({ id: WORKER_ID }),
) {
  return callWith((_request, index) => {
    if (index === 0) return json({ deployments: [deploymentResult(authority.deploymentIntent)] });
    if (index === 1) return json(versionResult(authority.plan, RETIREMENT_VERSION_ID));
    if (index === 2) return namespacePage(firstNamespaces);
    if (index === 3) return namespacePage(secondNamespaces);
    return v.is(v.function(), deleted) ? deleted() : deleted;
  });
}

function cleanupRecovery(plan: UninstallWorkerVersionMutationPlan): CleanupWorkerVersionRecoveryRecord {
  if (plan.recovery.stage !== 'cleanup') throw new TypeError('cleanup recovery fixture');
  return plan.recovery;
}

function retirementRecovery(plan: UninstallWorkerVersionMutationPlan): RetirementWorkerVersionRecoveryRecord {
  if (plan.recovery.stage !== 'retirement') throw new TypeError('retirement recovery fixture');
  return plan.recovery;
}

function isSubmittedVersionError<ErrorInput>(error: ErrorInput): boolean {
  return error instanceof CloudflareUninstallWorkerLifecycleError &&
    error.outcome === 'submitted' && error.submissions[0]?.kind === 'uninstall_worker_version' &&
    error.submissions[0].versionId === VERSION_ID;
}

async function workerDeleteIntent() {
  const authority = await retirementAuthority();
  const call = retirementProofCall(authority);
  const intent = await prepareWorkerDeleteMutation(authority.proofInput, call);
  return Object.freeze({ authority, call, intent });
}

describe('Cloudflare uninstall Worker lifecycle', () => {
  it('keeps every correlation tag inside the provider annotation limit', async () => {
    // Live (2026-08-23): Cloudflare rejects a version whose `workers/tag`
    // annotation exceeds 100 characters, and every tag carries a 64-character
    // digest, so the fixed prefixes have to stay short.
    const tags = [
      (await cleanupPlan()).recovery.correlationTag,
      (await retirementPlan()).recovery.correlationTag,
      ...await Promise.all((['cleanup', 'restore_clean', 'retirement'] as const).map(async (stage) => (
        await prepareUninstallWorkerDeploymentMutation({
          stage, accountId: ACCOUNT_ID, workerName: WORKER_NAME, workerId: WORKER_ID,
          uninstallCycleId: CYCLE_ID, versionId: RETIREMENT_VERSION_ID,
        })
      ).correlationTag)),
    ];
    for (const tag of tags) {
      expect(tag).toMatch(/-sha256:[a-f0-9]{64}$/u);
      expect(tag.length).toBeLessThanOrEqual(100);
    }
  });

  it('prepares an exact cleanup version while keeping the nonce out of journal state', async () => {
    const plan = await cleanupPlan();
    const body = bodyOf(plan);
    expect(Object.keys(body).sort()).toEqual([
      'annotations', 'bindings', 'compatibility_date', 'compatibility_flags', 'exports',
      'main_module', 'modules',
    ]);
    expect(body).not.toHaveProperty('assets');
    expect(body).not.toHaveProperty('migrations');
    expect(body.exports).toEqual({ AdminState: { type: 'durable-object', storage: 'sqlite' } });
    const bindings = body.bindings;
    expect(bindings).toHaveLength(8);
    expect(bindings).toContainEqual({
      name: 'ADMIN_STATE', type: 'durable_object_namespace', class_name: 'AdminState',
      namespace_id: NAMESPACE_ID,
    });
    expect(bindings).toContainEqual({
      name: 'ANKKA_UNINSTALL_NONCE', type: 'secret_text', text: UNINSTALL_NONCE,
    });
    expect(JSON.stringify(plan.recovery)).not.toContain(UNINSTALL_NONCE);
    expect(JSON.stringify(plan.recovery)).not.toContain('content_base64');
    expect(requiredFixture(plan.recovery.modules.at(0), 'recovery module').contentSha256).toMatch(/^[a-f0-9]{64}$/u);
    expect(await parseUninstallWorkerVersionRecoveryRecord(plan.recovery)).toEqual(plan.recovery);
    expect(await parseUninstallWorkerVersionRecoveryRecord({ ...plan.recovery, requestHash: '9'.repeat(64) })).toBeNull();
  });

  it('prepares the declarative retirement tombstone with no bindings or assets', async () => {
    const plan = await retirementPlan();
    const body = bodyOf(plan);
    expect(body.bindings).toEqual([]);
    expect(body).not.toHaveProperty('assets');
    expect(body).not.toHaveProperty('migrations');
    expect(body.exports).toEqual({ AdminState: { type: 'durable-object', state: 'deleted' } });
    expect(JSON.stringify(plan.recovery)).not.toMatch(/accessToken|content_base64/iu);
  });

  it('rejects release module bytes that no longer match the signed hash', async () => {
    const release = await releaseSet();
    const module = requiredFixture(release.cleanup.worker.modules.at(0), 'cleanup module');
    const firstByte = requiredFixture(module.bytes.at(0), 'cleanup module byte');
    module.bytes[0] = firstByte ^ 1;
    await expect(prepareCleanupWorkerVersionMutation({
      accountId: ACCOUNT_ID,
      workerName: WORKER_NAME,
      workerId: WORKER_ID,
      namespaceId: NAMESPACE_ID,
      uninstallCycleId: CYCLE_ID,
      releaseSet: release,
      variables: variables(),
      uninstallNonce: UNINSTALL_NONCE,
    })).rejects.toMatchObject({ code: 'invalid_input', outcome: 'not_sent' });
  });

  it('surfaces a created version ID before optional provider validation', async () => {
    const plan = await cleanupPlan();
    const call = callWith(() => Response.json({ result: { id: VERSION_ID } }, { status: 201 }));
    await expect(submitUninstallWorkerVersionMutation(plan.ephemeral, plan.recovery, call)).rejects.toSatisfy(
      isSubmittedVersionError,
    );
  });

  it('verifies exact cleanup semantics and optional returned module bytes', async () => {
    const plan = await cleanupPlan();
    const submission = versionSubmission(plan);
    const good = callWith(() => json(versionResult(plan, VERSION_ID, { includeModuleBytes: true })));
    await expect(verifyUninstallWorkerVersionSubmission(plan.recovery, submission, good)).resolves.toEqual(submission);

    const badNamespace = callWith(() => json(versionResult(plan, VERSION_ID, { badNamespace: true })));
    await expect(verifyUninstallWorkerVersionSubmission(plan.recovery, submission, badNamespace)).rejects.toMatchObject({
      code: 'provider_mismatch', stage: 'version_verify', outcome: 'submitted',
    });

    const exactBytesResult = versionResult(plan, VERSION_ID, { includeModuleBytes: true });
    const badBytesResult = {
      ...exactBytesResult,
      modules: exactBytesResult.modules.map((module, index) =>
        index === 0 ? { ...module, content_base64: btoa('different') } : module),
    };
    await expect(verifyUninstallWorkerVersionSubmission(
      plan.recovery,
      submission,
      callWith(() => json(badBytesResult)),
    )).rejects.toMatchObject({ code: 'provider_mismatch' });
  });

  it('strongly proves exact cleanup bytes across two active-deployment reads', async () => {
    const plan = await cleanupPlan();
    const version = versionSubmission(plan);
    const intent = await prepareUninstallWorkerDeploymentMutation({
      stage: 'cleanup', accountId: ACCOUNT_ID, workerName: WORKER_NAME, workerId: WORKER_ID,
      uninstallCycleId: CYCLE_ID, versionId: VERSION_ID,
    });
    const deployment = Object.freeze({
      kind: 'uninstall_worker_deployment' as const,
      stage: 'cleanup' as const,
      accountId: ACCOUNT_ID,
      workerName: WORKER_NAME,
      workerId: WORKER_ID,
      uninstallCycleId: CYCLE_ID,
      versionId: VERSION_ID,
      deploymentId: DEPLOYMENT_ID,
      requestHash: intent.requestHash,
      correlationTag: intent.correlationTag,
    });
    const exact = callWith((_request, index) => index === 1
      ? json(versionResult(plan, VERSION_ID, { includeModuleBytes: true }))
      : json({ deployments: [deploymentResult(intent)] }));
    await expect(proveActiveCleanupWorkerVersion(
      cleanupRecovery(plan),
      version,
      intent,
      deployment,
      exact,
    )).resolves.toEqual({ version, deployment });
    expect(exact.requests.map((request) => new URL(request.url).pathname)).toEqual([
      `/client/v4/accounts/${ACCOUNT_ID}/workers/scripts/${WORKER_NAME}/deployments`,
      `/client/v4/accounts/${ACCOUNT_ID}/workers/workers/${WORKER_ID}/versions/${VERSION_ID}`,
      `/client/v4/accounts/${ACCOUNT_ID}/workers/scripts/${WORKER_NAME}/deployments`,
    ]);

    const omittedBytes = callWith((_request, index) => index === 1
      ? json(versionResult(plan, VERSION_ID))
      : json({ deployments: [deploymentResult(intent)] }));
    await expect(proveActiveCleanupWorkerVersion(
      cleanupRecovery(plan),
      version,
      intent,
      deployment,
      omittedBytes,
    )).rejects.toMatchObject({ code: 'provider_mismatch', stage: 'version_verify' });

    const drift = callWith((_request, index) => index === 1
      ? json(versionResult(plan, VERSION_ID, { includeModuleBytes: true }))
      : json({ deployments: [deploymentResult(
        intent,
        index === 2 ? '55555555-5555-4555-8555-555555555555' : DEPLOYMENT_ID,
      )] }));
    await expect(proveActiveCleanupWorkerVersion(
      cleanupRecovery(plan),
      version,
      intent,
      deployment,
      drift,
    )).rejects.toMatchObject({ code: 'provider_mismatch', stage: 'deployment_active_verify' });
  });

  it('requires retirement reconciliation to delete AdminState with no active export', async () => {
    const plan = await retirementPlan();
    const submission = versionSubmission(plan, RETIREMENT_VERSION_ID);
    await expect(verifyUninstallWorkerVersionSubmission(
      plan.recovery,
      submission,
      callWith(() => json(versionResult(plan, RETIREMENT_VERSION_ID))),
    )).resolves.toEqual(submission);

    const retired = versionResult(plan, RETIREMENT_VERSION_ID);
    const active = {
      ...retired,
      exports: {
        ...retired.exports,
        AdminState: { type: 'durable-object', storage: 'sqlite' },
      },
    };
    await expect(verifyUninstallWorkerVersionSubmission(
      plan.recovery,
      submission,
      callWith(() => json(active)),
    )).rejects.toMatchObject({ code: 'provider_mismatch' });
  });

  it('fully paginates version recovery and rejects duplicate correlation matches', async () => {
    const plan = await cleanupPlan();
    const ids = Array.from({ length: 101 }, (_, index) =>
      `00000000-0000-4000-8000-${index.toString(16).padStart(12, '0')}`,
    );
    const page = (pageNumber: number, duplicateMatch = false): Response => {
      const pageIds = pageNumber === 1 ? ids.slice(0, 100) : ids.slice(100);
      const result = pageIds.map((id, index) => ({
        id,
        annotations: {
          'workers/tag': pageNumber === 2 || (duplicateMatch && pageNumber === 1 && index === 0)
            ? plan.recovery.correlationTag
            : 'unrelated',
        },
      }));
      return Response.json({
        success: true, errors: [], messages: [], result,
        result_info: { count: result.length, page: pageNumber, per_page: 100, total_count: 101, total_pages: 2 },
      });
    };
    const call = callWith((_request, index) => {
      if (index === 0) return page(1);
      if (index === 1) return page(2);
      return json(versionResult(plan, requiredFixture(ids.at(100), 'matched version ID')));
    });
    await expect(inspectUninstallWorkerVersionRecovery(plan.recovery, call)).resolves.toMatchObject({
      versionId: ids[100],
    });
    expect(call.requests.map((request) => new URL(request.url).search)).toEqual([
      '?page=1&per_page=100', '?page=2&per_page=100', '?include=modules',
    ]);

    const ambiguous = callWith((_request, index) => page(index + 1, true));
    await expect(inspectUninstallWorkerVersionRecovery(plan.recovery, ambiguous)).rejects.toMatchObject({
      code: 'recovery_ambiguous', stage: 'version_recovery',
    });

    const duplicateAcrossPages = callWith((_request, index) => {
      if (index === 0) return page(1);
      const duplicate = {
        id: ids[0],
        annotations: { 'workers/tag': plan.recovery.correlationTag },
      };
      return Response.json({
        success: true, errors: [], messages: [], result: [duplicate],
        result_info: { count: 1, page: 2, per_page: 100, total_count: 101, total_pages: 2 },
      });
    });
    await expect(inspectUninstallWorkerVersionRecovery(
      plan.recovery,
      duplicateAcrossPages,
    )).rejects.toMatchObject({ code: 'recovery_ambiguous', stage: 'version_recovery' });
  });

  it('stages deployment creation, validation, recovery, and exact clean restoration', async () => {
    const cleanupIntent = await prepareUninstallWorkerDeploymentMutation({
      stage: 'cleanup', accountId: ACCOUNT_ID, workerName: WORKER_NAME, workerId: WORKER_ID,
      uninstallCycleId: CYCLE_ID, versionId: VERSION_ID,
    });
    const retirementIntent = await prepareUninstallWorkerDeploymentMutation({
      stage: 'retirement', accountId: ACCOUNT_ID, workerName: WORKER_NAME, workerId: WORKER_ID,
      uninstallCycleId: CYCLE_ID, versionId: RETIREMENT_VERSION_ID,
    });
    const restoreIntent = await prepareUninstallWorkerDeploymentMutation({
      stage: 'restore_clean', accountId: ACCOUNT_ID, workerName: WORKER_NAME, workerId: WORKER_ID,
      uninstallCycleId: CYCLE_ID, versionId: CLEAN_VERSION_ID,
    });
    expect(new Set([
      cleanupIntent.correlationTag, retirementIntent.correlationTag, restoreIntent.correlationTag,
    ]).size).toBe(3);

    const submitted = await submitUninstallWorkerDeploymentMutation(
      cleanupIntent,
      callWith(() => json({ id: DEPLOYMENT_ID }, 201)),
    );
    await expect(verifyUninstallWorkerDeploymentSubmission(
      cleanupIntent,
      submitted,
      callWith(() => json(deploymentResult(cleanupIntent))),
    )).resolves.toEqual(submitted);
    await expect(inspectUninstallWorkerDeploymentRecovery(
      cleanupIntent,
      callWith((_request, index) => index === 0
        ? json({ deployments: [deploymentResult(cleanupIntent)] })
        : json(deploymentResult(cleanupIntent))),
    )).resolves.toEqual(submitted);

    const restoredSubmission = {
      ...submitted,
      stage: 'restore_clean' as const,
      versionId: CLEAN_VERSION_ID,
      requestHash: restoreIntent.requestHash,
      correlationTag: restoreIntent.correlationTag,
    };
    await expect(verifyRestoredCleanWorkerDeploymentIsActive(
      restoreIntent,
      restoredSubmission,
      callWith(() => json({ deployments: [deploymentResult(restoreIntent)] })),
    )).resolves.toEqual(restoredSubmission);

    await expect(verifyUninstallWorkerDeploymentIsActive(
      cleanupIntent,
      submitted,
      callWith(() => json({ deployments: [deploymentResult(cleanupIntent)] })),
    )).resolves.toEqual(submitted);
    const foreignIntent = await prepareUninstallWorkerDeploymentMutation({
      stage: 'cleanup', accountId: ACCOUNT_ID, workerName: WORKER_NAME, workerId: WORKER_ID,
      uninstallCycleId: 'uninstall-' + 'f'.repeat(24), versionId: VERSION_ID,
    });
    await expect(verifyUninstallWorkerDeploymentIsActive(
      cleanupIntent,
      submitted,
      callWith(() => json({ deployments: [
        deploymentResult(foreignIntent, '55555555-5555-4555-8555-555555555555'),
        deploymentResult(cleanupIntent),
      ] })),
    )).rejects.toMatchObject({ code: 'provider_mismatch', stage: 'deployment_active_verify' });
    await expect(verifyUninstallWorkerDeploymentIsActive(
      cleanupIntent,
      submitted,
      callWith(() => json({ deployments: [
        deploymentResult(cleanupIntent),
        deploymentResult(cleanupIntent, '66666666-6666-4666-8666-666666666666'),
      ] })),
    )).rejects.toMatchObject({ code: 'recovery_ambiguous', stage: 'deployment_active_verify' });
  });

  it('proves the exact persisted sqlite namespace before retirement', async () => {
    const proof = await provePersistedAdminStateNamespacePresent({
      namespace: {
        accountId: ACCOUNT_ID,
        namespaceId: NAMESPACE_ID,
        namespaceName: `${WORKER_NAME}-AdminState`,
        workerName: WORKER_NAME,
        className: 'AdminState',
        storage: 'sqlite',
      },
      workerId: WORKER_ID,
      uninstallCycleId: CYCLE_ID,
    }, callWith(() => namespacePage([namespaceItem()])));
    expect(proof).toMatchObject({
      kind: 'admin_state_namespace_presence', namespaceId: NAMESPACE_ID, accountNamespaceCount: 1,
    });
  });

  it('requires retirement proof followed by two stable full namespace absences', async () => {
    const authority = await retirementAuthority();
    const { deploymentIntent, plan, proofInput } = authority;
    const call = callWith((_request, index) => {
      if (index === 0) return json({ deployments: [deploymentResult(deploymentIntent)] });
      if (index === 1) return json(versionResult(plan, RETIREMENT_VERSION_ID));
      return namespacePage([]);
    });
    const proof = await proveAdminStateNamespaceRetired(proofInput, call);
    expect(proof).toMatchObject({
      kind: 'admin_state_namespace_retirement',
      retirementVersionId: RETIREMENT_VERSION_ID,
      firstSnapshotSha256: expect.any(String),
      secondSnapshotSha256: expect.any(String),
    });
    expect(parseAdminStateNamespaceRetirementProof(proof)).toEqual(proof);
    expect(parseAdminStateNamespaceRetirementProof({ ...proof, accessToken: ACCESS_TOKEN })).toBeNull();
    expect(call.requests).toHaveLength(4);
    expect(new URL(requiredFixture(call.requests.at(0), 'deployment request').url).pathname).toContain('/deployments');
    expect(new URL(requiredFixture(call.requests.at(1), 'version request').url).pathname).toContain(`/versions/${RETIREMENT_VERSION_ID}`);
    expect(new URL(requiredFixture(call.requests.at(2), 'namespace request').url).pathname).toContain('/durable_objects/namespaces');

    const driftCall = callWith((_request, index) => {
      if (index === 0) return json({ deployments: [deploymentResult(deploymentIntent)] });
      if (index === 1) return json(versionResult(plan, RETIREMENT_VERSION_ID));
      if (index === 2) return namespacePage([]);
      return namespacePage([{
        id: '9'.repeat(32), class: 'OtherState', name: 'other-state', script: 'other-worker', use_sqlite: true,
      }]);
    });
    await expect(proveAdminStateNamespaceRetired(proofInput, driftCall)).rejects.toMatchObject({
      code: 'provider_mismatch', stage: 'namespace_absent',
    });
  });

  it('freshly re-proves retirement, omits force, deletes once, and binds read-only recovery', async () => {
    const { authority, call: prepareCall, intent } = await workerDeleteIntent();
    expect(prepareCall.requests).toHaveLength(4);
    expect(await parseWorkerDeleteMutationIntent(intent)).toEqual(intent);
    expect(JSON.stringify(intent)).not.toMatch(/accessToken|providerBody/iu);
    let deleteCount = 0;
    const submitCall = retirementProofCall(authority, [], [], () => {
      deleteCount += 1;
      const request = submitCall.requests.at(-1);
      expect(request?.method).toBe('DELETE');
      expect(new URL(request?.url ?? '').search).toBe('');
      expect(request?.body).toBeNull();
      return json({ id: WORKER_ID });
    });
    await expect(submitWorkerDeleteMutation(intent, authority.proofInput, submitCall)).resolves.toMatchObject({
      kind: 'uninstall_worker_delete', workerId: WORKER_ID,
      namespaceId: NAMESPACE_ID, retirementVersionId: RETIREMENT_VERSION_ID,
      retirementProofCommitment: intent.retirementProofCommitment,
    });
    expect(deleteCount).toBe(1);
    expect(submitCall.requests).toHaveLength(5);
    expect(submitCall.requests.slice(0, 4).every((request) => request.method === 'GET')).toBe(true);
    expect(requiredFixture(submitCall.requests.at(4), 'worker delete request').method).toBe('DELETE');

    const recoveryCall = callWith((_request, index) => {
      if (index % 3 < 2) return absent();
      return json([{ id: 'some-other-script' }]);
    });
    await expect(recoverWorkerDeletionOutcome(intent, recoveryCall)).resolves.toMatchObject({
      kind: 'uninstall_worker_deletion_proof', scriptCount: 1,
      namespaceId: NAMESPACE_ID, retirementVersionId: RETIREMENT_VERSION_ID,
      retirementProofCommitment: intent.retirementProofCommitment,
      requestHash: intent.requestHash,
      firstScriptListSha256: expect.any(String), secondScriptListSha256: expect.any(String),
    });
    expect(recoveryCall.requests).toHaveLength(6);
    expect(recoveryCall.requests.every((request) => request.method === 'GET')).toBe(true);
    expect(new URL(requiredFixture(recoveryCall.requests.at(2), 'script list request').url).search).toBe('?page=1&per_page=100');
  });

  it('does not prepare or submit deletion without exact current retirement authority', async () => {
    const authority = await retirementAuthority();
    const beforeRetirement = callWith((_request, index) => {
      if (index === 0) return json({ deployments: [] });
      throw new Error('unexpected request');
    });
    await expect(prepareWorkerDeleteMutation(authority.proofInput, beforeRetirement)).rejects.toMatchObject({
      code: 'provider_mismatch', stage: 'deployment_active_verify', canRetry: false,
    });
    expect(beforeRetirement.requests).toHaveLength(1);
    expect(beforeRetirement.requests.some((request) => request.method === 'DELETE')).toBe(false);

    const prepared = await workerDeleteIntent();
    const wrongCycle = {
      ...prepared.authority.proofInput,
      uninstallCycleId: 'uninstall-' + 'f'.repeat(24),
    };
    const noCall = callWith(() => {
      throw new Error('must not call provider');
    });
    await expect(submitWorkerDeleteMutation(prepared.intent, wrongCycle, noCall)).rejects.toMatchObject({
      code: 'invalid_input', stage: 'validate', outcome: 'not_sent', submissions: [],
    });
    expect(noCall.requests).toHaveLength(0);

    const noLongerRetired = callWith((_request, index) => {
      if (index === 0) return json({ deployments: [] });
      throw new Error('unexpected request');
    });
    await expect(submitWorkerDeleteMutation(
      prepared.intent,
      prepared.authority.proofInput,
      noLongerRetired,
    )).rejects.toMatchObject({ code: 'provider_mismatch', stage: 'deployment_active_verify' });
    expect(noLongerRetired.requests).toHaveLength(1);
    expect(noLongerRetired.requests.some((request) => request.method === 'DELETE')).toBe(false);
  });

  it('rejects fabricated proof fields and prepare-to-submit namespace drift with zero DELETE', async () => {
    const prepared = await workerDeleteIntent();
    for (const fabricated of [
      { ...prepared.intent, namespaceId: '9'.repeat(32) },
      { ...prepared.intent, retirementVersionId: VERSION_ID },
      { ...prepared.intent, uninstallCycleId: 'uninstall-' + 'f'.repeat(24) },
      {
        ...prepared.intent,
        retirementProof: { ...prepared.intent.retirementProof, firstSnapshotSha256: '9'.repeat(64) },
      },
    ]) {
      const call = callWith(() => {
        throw new Error('must not call provider');
      });
      await expect(submitWorkerDeleteMutation(
        fabricated,
        prepared.authority.proofInput,
        call,
      )).rejects.toMatchObject({ code: 'invalid_input', outcome: 'not_sent', submissions: [] });
      expect(call.requests).toHaveLength(0);
    }

    const unrelatedNamespace = {
      id: '9'.repeat(32), class: 'OtherState', name: 'other-state', script: 'other-worker', use_sqlite: true,
    };
    let deleteCount = 0;
    const drift = retirementProofCall(
      prepared.authority,
      [unrelatedNamespace],
      [unrelatedNamespace],
      () => {
        deleteCount += 1;
        return json({ id: WORKER_ID });
      },
    );
    await expect(submitWorkerDeleteMutation(
      prepared.intent,
      prepared.authority.proofInput,
      drift,
    )).rejects.toMatchObject({ code: 'provider_mismatch', stage: 'namespace_absent' });
    expect(deleteCount).toBe(0);
    expect(drift.requests).toHaveLength(4);
    expect(drift.requests.every((request) => request.method === 'GET')).toBe(true);
  });

  it('never leaks raw invalid submissions, access tokens, or provider bodies through errors', async () => {
    const malicious = {
      kind: 'uninstall_worker_version',
      stage: 'cleanup',
      accountId: ACCOUNT_ID,
      workerName: WORKER_NAME,
      workerId: WORKER_ID,
      uninstallCycleId: CYCLE_ID,
      versionId: VERSION_ID,
      requestHash: '1'.repeat(64),
      correlationTag: `ankka-un-v-cleanup-sha256:${'1'.repeat(64)}`,
      accessToken: ACCESS_TOKEN,
      providerBody: { secret: 'provider-secret' },
    };
    expect(parseCloudflareUninstallWorkerLifecycleSubmission(malicious)).toBeNull();
    const invalid = new CloudflareUninstallWorkerLifecycleError(
      'invalid_input', 'validate', 'not_sent', [malicious],
    );
    const provider = new CloudflareUninstallWorkerLifecycleError(
      'provider_mismatch', 'version_verify', 'submitted', [malicious],
    );
    expect(invalid.submissions).toEqual([]);
    expect(provider.submissions).toEqual([]);
    const plan = await cleanupPlan();
    const noCall = callWith(() => {
      throw new Error('must not call provider');
    });
    let boundaryError: Error | null = null;
    try {
      await verifyUninstallWorkerVersionSubmission(
        plan.recovery,
        malicious,
        noCall,
      );
    } catch (error) {
      if (!(error instanceof Error)) throw error;
      boundaryError = error;
    }
    expect(boundaryError).toBeInstanceOf(CloudflareUninstallWorkerLifecycleError);
    expect(boundaryError).toMatchObject({ code: 'invalid_input', submissions: [] });
    expect(noCall.requests).toHaveLength(0);
    const serialized = JSON.stringify({ boundaryError, invalid, provider });
    expect(serialized).not.toContain(ACCESS_TOKEN);
    expect(serialized).not.toContain('provider-secret');
    expect(serialized).not.toContain('providerBody');
  });

  it('projects only an exact allowlisted submission into a safe error', async () => {
    const { intent } = await workerDeleteIntent();
    const safe = {
      kind: 'uninstall_worker_delete' as const,
      accountId: intent.accountId,
      workerName: intent.workerName,
      workerId: intent.workerId,
      uninstallCycleId: intent.uninstallCycleId,
      namespaceId: intent.namespaceId,
      retirementVersionId: intent.retirementVersionId,
      retirementProofCommitment: intent.retirementProofCommitment,
      requestHash: intent.requestHash,
      correlationTag: intent.correlationTag,
    };
    expect(parseCloudflareUninstallWorkerLifecycleSubmission(safe)).toEqual(safe);
    const error = new CloudflareUninstallWorkerLifecycleError(
      'provider_mismatch', 'worker_delete', 'submitted', [safe],
    );
    expect(error.submissions).toEqual([safe]);
  });

  it('exactly round-trips every journal allowlist kind into a new deep-frozen projection', async () => {
    const cleanup = await cleanupPlan();
    const cleanupSubmission = versionSubmission(cleanup);
    const deploymentIntent = await prepareUninstallWorkerDeploymentMutation({
      stage: 'cleanup', accountId: ACCOUNT_ID, workerName: WORKER_NAME, workerId: WORKER_ID,
      uninstallCycleId: CYCLE_ID, versionId: VERSION_ID,
    });
    const deploymentSubmission = Object.freeze({
      kind: 'uninstall_worker_deployment' as const,
      stage: 'cleanup' as const,
      accountId: ACCOUNT_ID,
      workerName: WORKER_NAME,
      workerId: WORKER_ID,
      uninstallCycleId: CYCLE_ID,
      versionId: VERSION_ID,
      deploymentId: DEPLOYMENT_ID,
      requestHash: deploymentIntent.requestHash,
      correlationTag: deploymentIntent.correlationTag,
    });
    const presence = await provePersistedAdminStateNamespacePresent({
      namespace: {
        accountId: ACCOUNT_ID,
        namespaceId: NAMESPACE_ID,
        namespaceName: `${WORKER_NAME}-AdminState`,
        workerName: WORKER_NAME,
        className: 'AdminState',
        storage: 'sqlite',
      },
      workerId: WORKER_ID,
      uninstallCycleId: CYCLE_ID,
    }, callWith(() => namespacePage([namespaceItem()])));
    const { intent } = await workerDeleteIntent();
    const deleteSubmission = Object.freeze({
      kind: 'uninstall_worker_delete' as const,
      accountId: intent.accountId,
      workerName: intent.workerName,
      workerId: intent.workerId,
      uninstallCycleId: intent.uninstallCycleId,
      namespaceId: intent.namespaceId,
      retirementVersionId: intent.retirementVersionId,
      retirementProofCommitment: intent.retirementProofCommitment,
      requestHash: intent.requestHash,
      correlationTag: intent.correlationTag,
    });
    const deletionProof = await recoverWorkerDeletionOutcome(intent, callWith((_request, index) => (
      index % 3 < 2 ? absent() : json([{ id: 'some-other-script' }])
    )));
    const records: readonly unknown[] = [
      cleanup.recovery,
      cleanupSubmission,
      deploymentIntent,
      deploymentSubmission,
      presence,
      intent.retirementProof,
      intent,
      deleteSubmission,
      deletionProof,
    ];
    for (const record of records) {
      const parsed = await parseCloudflareUninstallWorkerLifecycleJournalRecord(record);
      expect(parsed).toEqual(record);
      expect(parsed).not.toBe(record);
      expectDeepFrozen(parsed);
    }
    expect(await parseUninstallWorkerDeploymentMutationIntent(deploymentIntent)).toEqual(deploymentIntent);
    expect(parseAdminStateNamespacePresenceProof(presence)).toEqual(presence);
    expect(parseWorkerDeletionRecoveryProof(deletionProof)).toEqual(deletionProof);
  });

  it('rejects journal extras, malicious prototypes, and commitment tampering without I/O', async () => {
    const deployment = await prepareUninstallWorkerDeploymentMutation({
      stage: 'cleanup', accountId: ACCOUNT_ID, workerName: WORKER_NAME, workerId: WORKER_ID,
      uninstallCycleId: CYCLE_ID, versionId: VERSION_ID,
    });
    expect(await parseUninstallWorkerDeploymentMutationIntent({
      ...deployment, accessToken: ACCESS_TOKEN,
    })).toBeNull();
    const inheritedDeployment = Object.assign(
      Object.create({ accessToken: ACCESS_TOKEN, providerBody: { secret: true } }),
      deployment,
    );
    expect(await parseUninstallWorkerDeploymentMutationIntent(inheritedDeployment)).toBeNull();
    const inheritedBody = {
      ...deployment,
      body: Object.assign(Object.create({ providerBody: { secret: true } }), deployment.body),
    };
    expect(await parseUninstallWorkerDeploymentMutationIntent(inheritedBody)).toBeNull();
    const fakeDeploymentHash = '9'.repeat(64);
    expect(await parseUninstallWorkerDeploymentMutationIntent({
      ...deployment,
      requestHash: fakeDeploymentHash,
      correlationTag: `ankka-un-d-cleanup-sha256:${fakeDeploymentHash}`,
      body: {
        ...deployment.body,
        annotations: { 'workers/message': `ankka-un-d-cleanup-sha256:${fakeDeploymentHash}` },
      },
    })).toBeNull();

    const presence = Object.freeze({
      kind: 'admin_state_namespace_presence' as const,
      accountId: ACCOUNT_ID,
      workerName: WORKER_NAME,
      workerId: WORKER_ID,
      uninstallCycleId: CYCLE_ID,
      namespaceId: NAMESPACE_ID,
      namespaceName: `${WORKER_NAME}-AdminState`,
      className: 'AdminState' as const,
      storage: 'sqlite' as const,
      accountNamespaceCount: 1,
      snapshotSha256: '7'.repeat(64),
    });
    expect(parseAdminStateNamespacePresenceProof({ ...presence, providerBody: { secret: true } })).toBeNull();
    expect(parseAdminStateNamespacePresenceProof(Object.assign(
      Object.create({ accessToken: ACCESS_TOKEN }), presence,
    ))).toBeNull();
    expect(parseAdminStateNamespacePresenceProof({ ...presence, snapshotSha256: 'bad' })).toBeNull();

    const { intent } = await workerDeleteIntent();
    const proof = await recoverWorkerDeletionOutcome(intent, callWith((_request, index) => (
      index % 3 < 2 ? absent() : json([])
    )));
    expect(parseWorkerDeletionRecoveryProof({ ...proof, providerBody: { secret: true } })).toBeNull();
    expect(parseWorkerDeletionRecoveryProof(Object.assign(
      Object.create({ accessToken: ACCESS_TOKEN }), proof,
    ))).toBeNull();
    expect(parseWorkerDeletionRecoveryProof({
      ...proof, firstScriptListSha256: '8'.repeat(64),
    })).toBeNull();
    const fakeDeleteHash = '8'.repeat(64);
    expect(await parseWorkerDeleteMutationIntent({
      ...intent,
      requestHash: fakeDeleteHash,
      correlationTag: `ankka-un-w-delete-sha256:${fakeDeleteHash}`,
    })).toBeNull();
    expect(await parseCloudflareUninstallWorkerLifecycleJournalRecord({
      kind: 'unknown', accessToken: ACCESS_TOKEN,
    })).toBeNull();
    expect(await parseCloudflareUninstallWorkerLifecycleJournalRecord(
      Object.assign(Object.create({ accessToken: ACCESS_TOKEN }), deployment),
    )).toBeNull();
  });

  it('fully paginates stable Script lists and rejects partial, duplicate, or drifting pages', async () => {
    const { intent } = await workerDeleteIntent();
    const scriptIds = Array.from({ length: 101 }, (_, index) => `script-${index.toString().padStart(3, '0')}`);
    const pageResponse = (
      page: number,
      options: { duplicate?: boolean; partial?: boolean; drift?: boolean } = {},
    ): Response => {
      let ids = page === 1 ? scriptIds.slice(0, 100) : scriptIds.slice(100);
      if (options.partial && page === 1) ids = ids.slice(0, 1);
      if (options.duplicate && page === 2) ids = [requiredFixture(scriptIds.at(0), 'first script ID')];
      const totalCount = options.drift && page === 2 ? 102 : 101;
      return Response.json({
        success: true,
        errors: [],
        messages: [],
        result: ids.map((id) => ({ id })),
        result_info: {
          count: ids.length,
          page,
          per_page: 100,
          total_count: totalCount,
          total_pages: 2,
        },
      });
    };
    const stable = callWith((_request, index) => {
      const withinObservation = index % 4;
      if (withinObservation < 2) return absent();
      return pageResponse(withinObservation - 1);
    });
    await expect(recoverWorkerDeletionOutcome(intent, stable)).resolves.toMatchObject({ scriptCount: 101 });
    expect(stable.requests).toHaveLength(8);

    for (const option of ['partial', 'duplicate', 'drift'] as const) {
      const bad = callWith((_request, index) => {
        if (index < 2) return absent();
        return pageResponse(index - 1, { [option]: true });
      });
      await expect(recoverWorkerDeletionOutcome(intent, bad)).rejects.toMatchObject({
        stage: 'worker_delete_recovery',
      });
    }
  });

  it('refuses same-name Script adoption during delete recovery', async () => {
    const { intent } = await workerDeleteIntent();
    const call = callWith((_request, index) => index < 2 ? absent() : json([{ id: WORKER_NAME }]));
    await expect(recoverWorkerDeletionOutcome(intent, call)).rejects.toMatchObject({
      code: 'deletion_not_proven', stage: 'worker_delete_recovery', canRetry: false,
    });
  });
});

import * as v from 'valibot';

import { canonicalJson } from './canonical-json';
import { sha256Hex } from './crypto';
import { DeployError } from './errors';
import type { ReleaseManifest } from './release-manifest';
import { parseStaticDeployPlan, verifyStaticDeployPlanIntegrity, type StaticDeployPlan } from './schema';

const digest = v.pipe(v.string(), v.regex(/^[a-f0-9]{64}$/u));
const schema = v.strictObject({
  schemaVersion: v.literal(1),
  kind: v.literal('bootstrap'),
  installSeed: v.pipe(v.string(), v.regex(/^[a-f0-9]{32}$/u)),
  releaseId: v.pipe(v.string(), v.regex(/^gateway-v\d+\.\d+\.\d+$/u)),
  releaseArtifactSha256: digest,
  sourceCommit: v.pipe(v.string(), v.regex(/^[a-f0-9]{40}$/u)),
  bootstrapWorkerSourceSha256: digest,
  workerBundleSha256: digest,
  dashboardAssetsSha256: digest,
  managementOwnershipMarker: v.pipe(v.string(), v.regex(/^acg-[a-f0-9]{24}$/u)),
  workerName: v.pipe(v.string(), v.regex(/^ankka-gateway-acg-[a-f0-9]{24}$/u)),
  expiresAt: v.pipe(v.number(), v.safeInteger(), v.minValue(1)),
  planId: v.pipe(v.string(), v.regex(/^plan-[a-f0-9]{24}$/u)),
  planHash: v.pipe(v.string(), v.regex(/^sha256:[a-f0-9]{64}$/u)),
});

export type BootstrapDeployPlan = v.InferOutput<typeof schema>;
/** Existing exact plans remain readable for in-flight deployment recovery. */
export type HostedDeployPlan = BootstrapDeployPlan | StaticDeployPlan;

export function isBootstrapPlan(plan: HostedDeployPlan): plan is BootstrapDeployPlan {
  return 'kind' in plan && plan.kind === 'bootstrap';
}

export function parseHostedDeployPlan<Input>(input: Input): HostedDeployPlan {
  const parsed = v.safeParse(schema, input);
  if (!parsed.success) return parseStaticDeployPlan(input);
  if (parsed.output.workerName !== `ankka-gateway-${parsed.output.managementOwnershipMarker}`) {
    throw new DeployError(400, 'session_invalid');
  }
  return Object.freeze(parsed.output);
}

export async function verifyHostedDeployPlan<Input>(input: Input): Promise<HostedDeployPlan> {
  const plan = parseHostedDeployPlan(input);
  if (!isBootstrapPlan(plan)) return verifyStaticDeployPlanIntegrity(plan);
  const { planHash, planId, expiresAt: _expiresAt, ...bound } = plan;
  const hash = await sha256Hex(canonicalJson(bound));
  if (planHash !== `sha256:${hash}` || planId !== `plan-${hash.slice(0, 24)}` ||
      plan.managementOwnershipMarker !== `acg-${(await sha256Hex(plan.installSeed)).slice(0, 24)}`) {
    throw new DeployError(400, 'session_invalid');
  }
  return plan;
}

export async function buildBootstrapDeployPlan(
  manifest: ReleaseManifest, expiresAt: number,
  installSeed = crypto.randomUUID().replaceAll('-', ''),
): Promise<BootstrapDeployPlan> {
  const managementOwnershipMarker = `acg-${(await sha256Hex(installSeed)).slice(0, 24)}`;
  const source = manifest.components.workerBootstrap.files.find((file) => file.path === 'payload/worker-bootstrap/index.js');
  if (source === undefined) throw new DeployError(503, 'release_invalid');
  const bound = {
    schemaVersion: 1 as const, kind: 'bootstrap' as const, installSeed,
    releaseId: manifest.release, releaseArtifactSha256: manifest.artifact.treeSha256,
    sourceCommit: manifest.sourceCommit, bootstrapWorkerSourceSha256: source.sha256,
    workerBundleSha256: manifest.components.worker.treeSha256,
    dashboardAssetsSha256: manifest.components.admin.treeSha256,
    managementOwnershipMarker, workerName: `ankka-gateway-${managementOwnershipMarker}`,
  };
  const hash = await sha256Hex(canonicalJson(bound));
  return v.parse(schema, { ...bound, expiresAt, planId: `plan-${hash.slice(0, 24)}`, planHash: `sha256:${hash}` });
}

export function hostedWorkerName(plan: HostedDeployPlan): string {
  if (isBootstrapPlan(plan)) return plan.workerName;
  const worker = plan.managementResources.find((resource) => resource.kind === 'management_worker');
  if (worker === undefined) throw new DeployError(400, 'session_invalid');
  return worker.name;
}

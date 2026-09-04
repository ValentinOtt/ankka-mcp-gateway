import * as v from 'valibot';

import { canonicalJson } from './canonical-json';
import { PUBLIC_ORIGIN } from './constants';
import { openCustomerGatewayOwnershipPrivateKey, readCustomerGatewayOwnershipState, type CustomerGatewayOwnershipStorage } from './customer-gateway-ownership-state';
import { DeployError } from './errors';
import { fetchBoundedText } from './http';
import type { FetchTransport } from './oauth';
import type { SetupZone } from './hosted-account-setup';
import { deploySelectionFromStaticPlan, parseDeploySelection, verifyStaticDeployPlanIntegrity, type DeploySelection, type StaticDeployPlan } from './schema';
import { configuredSetupSchema, signWorkerSetupConfiguration, verifyWorkerSetupPermit, WORKER_SETUP_CERTIFY_PATH, type ConfiguredSetup } from './worker-setup-permit';

const KEY = 'ankka-mcp-gateway/worker-setup/v1';
const schema = v.strictObject({ permit: v.pipe(v.string(), v.maxLength(56 * 1024)), configured: v.nullable(configuredSetupSchema) });

export interface CustomerWorkerSetupPublicState {
  availableZones: readonly SetupZone[];
  selection: DeploySelection | null;
  plan: StaticDeployPlan | null;
  expiresAt: number;
}

export interface CustomerWorkerSetupConfig {
  accountId: string;
  installId: string;
  workerName: string;
  planId: string;
  planHash: string;
  bootstrapCallback: string;
  secretCommitment: string;
  expiresAt: number;
  issuerPublicKey: string;
  issuerKeyId: string;
  publicClientId: string;
  wrappingKey: string;
}

export function createCustomerWorkerSetup(input: {
  storage: CustomerGatewayOwnershipStorage;
  config: CustomerWorkerSetupConfig;
  transport: FetchTransport;
  now: () => number;
}) {
  const { storage, config, now } = input;
  const invalid = (): never => { throw new DeployError(409, 'session_invalid', 'worker_setup_invalid'); };
  const verified = async (permit: string) => {
    const value = await verifyWorkerSetupPermit(permit, config.issuerPublicKey, now());
    const ownership = await readCustomerGatewayOwnershipState(storage);
    if (value.handoff.accountId !== config.accountId || value.handoff.installId !== config.installId ||
        value.handoff.bootstrapSecret.commitment !== config.secretCommitment || value.handoff.bootstrapSecret.expiresAt !== config.expiresAt ||
        value.bootstrapPlan.workerName !== config.workerName || value.bootstrapPlan.planId !== config.planId ||
        value.bootstrapPlan.planHash !== config.planHash || value.bootstrapCallback !== config.bootstrapCallback ||
        value.ownershipPublicKey !== ownership.publicKey || value.publicClientId !== config.publicClientId || value.issuerKeyId !== config.issuerKeyId) invalid();
    return value;
  };
  const read = async () => v.parse(schema, await storage.get(KEY));
  const publicSetup = async (): Promise<CustomerWorkerSetupPublicState> => {
    const state = await read();
    const permit = await verified(state.permit);
    const plan = state.configured === null ? null : await verifyStaticDeployPlanIntegrity(JSON.parse(state.configured.serializedPlan));
    return { availableZones: permit.availableZones, selection: plan === null ? null : deploySelectionFromStaticPlan(plan), plan, expiresAt: permit.handoff.expiresAt };
  };
  return {
    async accept(permit: string): Promise<void> {
      await verified(permit);
      const existing = await storage.get(KEY);
      if (existing !== undefined) {
        if (v.parse(schema, existing).permit !== permit) invalid();
        return;
      }
      await storage.put(KEY, { permit, configured: null });
    },
    read: publicSetup,
    async configure(value: DeploySelection) {
      const state = await read();
      const permit = await verified(state.permit);
      const ownership = await readCustomerGatewayOwnershipState(storage);
      if (ownership.serializedHandoff !== null) invalid();
      const selection = parseDeploySelection(value);
      if (selection.firstSource !== null || !permit.availableZones.some((zone) => zone.name === selection.basics.zoneName)) invalid();
      const key = await openCustomerGatewayOwnershipPrivateKey({ storage, wrappingKey: config.wrappingKey });
      const request = await signWorkerSetupConfiguration(state.permit, selection, key);
      const response = await fetchBoundedText(input.transport, new URL(WORKER_SETUP_CERTIFY_PATH, PUBLIC_ORIGIN), {
        method: 'POST', headers: { 'content-type': 'application/json' }, body: canonicalJson(request), redirect: 'manual',
      }, 'internal_error', { maxBytes: 64 * 1024 });
      if (!response.response.ok) invalid();
      const configured = v.parse(configuredSetupSchema, JSON.parse(response.text));
      const plan = await verifyStaticDeployPlanIntegrity(JSON.parse(configured.serializedPlan));
      if (canonicalJson(deploySelectionFromStaticPlan(plan)) !== canonicalJson(selection) ||
          plan.bootstrapIdentity?.planId !== config.planId || plan.bootstrapIdentity.planHash !== config.planHash ||
          plan.managementOwnershipMarker !== config.installId) invalid();
      await storage.put(KEY, { permit: state.permit, configured });
      return publicSetup();
    },
    async configured(): Promise<ConfiguredSetup | null> {
      const value = await storage.get(KEY);
      return value === undefined ? null : v.parse(schema, value).configured;
    },
  };
}

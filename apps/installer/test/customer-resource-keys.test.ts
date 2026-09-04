import { describe, expect, it } from 'vitest';

import { canonicalJson } from '../src/canonical-json';
import { prepareCustomerGatewayDesiredProjectionFromPlan } from '../src/customer-bootstrap-request';
import { buildStaticDeployPlan, parseDeploySelection } from '../src/schema';
import { manifest, selectionInput } from './fixtures';

const target = Object.freeze({ accountId: '1'.repeat(32), zoneId: '2'.repeat(32), zoneName: 'example.com' });

// Cloudflare refuses a resource id with two hyphens in a row (error 7001,
// "not valid ID format"). A hostname whose truncated key hint ends exactly
// on a label boundary produced one; the sixth real install of 2026-09-04
// stopped on it at the portal discovery.
describe('customer resource keys', () => {
  it('never end a truncated hint in a hyphen, for every prefix', async () => {
    for (const portalHostname of ['mcpsixz.example.com', 'mcp.example.com', 'mcpmorning5.example.com']) {
      const plan = await buildStaticDeployPlan(parseDeploySelection({
        ...selectionInput,
        basics: { ...selectionInput.basics, portalHostname },
      }), manifest, Date.now() + 30 * 60_000);
      const projection = await prepareCustomerGatewayDesiredProjectionFromPlan({ plan, target });
      const serialized = canonicalJson(projection);
      expect(serialized).not.toMatch(/--/u);
      expect(serialized).not.toMatch(/-"/u);
      const keys = [...serialized.matchAll(/"((?:portal|portal-app|portal-access|mcp|source-app|source-access)-[a-z0-9-]+)"/gu)].map((match) => match[1]);
      expect(keys.length).toBeGreaterThan(0);
      for (const key of keys) expect(key).toMatch(/^[a-z]+(?:-[a-z]+)?-(?:[a-z0-9]+(?:-[a-z0-9]+)*-)?[a-f0-9]{8}$/u);
    }
  });
});

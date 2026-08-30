import { describe, expect, it } from "vitest";

import {
  SEARCH_CONSOLE_OPENAPI_SPEC,
  SEARCH_CONSOLE_SPEC_SHA256,
} from "../src/openapi";
import {
  GOOGLE_SEARCH_CONSOLE_READONLY_SCOPE,
  SEARCH_CONSOLE_OPERATIONS,
  SEARCH_CONSOLE_POLICY_DESCRIPTOR,
  SEARCH_CONSOLE_POLICY_SHA256,
} from "../src/policy";

describe("reviewed Search Console surface", () => {
  it("keeps the bundled spec and host operation table in exact agreement", () => {
    const specOperations = Object.entries(SEARCH_CONSOLE_OPENAPI_SPEC.paths).flatMap(
      ([path, pathItem]) =>
        Object.entries(pathItem).map(([method, operation]) => ({
          operationId: operation.operationId,
          method: method.toUpperCase(),
          path,
        })),
    );
    const policyOperations = SEARCH_CONSOLE_OPERATIONS.map(
      ({ operationId, method, path }) => ({ operationId, method, path }),
    );
    expect(specOperations).toEqual(policyOperations);
    expect(specOperations).toEqual([
      { operationId: "listApprovedSites", method: "GET", path: "/sites" },
      {
        operationId: "querySearchAnalytics",
        method: "POST",
        path: "/search-analytics/query",
      },
      {
        operationId: "inspectUrlIndexStatus",
        method: "POST",
        path: "/url-inspection/inspect",
      },
    ]);
  });

  it("contains no write operation, external reference, runtime spec URL, or secret", () => {
    const serialized = JSON.stringify(SEARCH_CONSOLE_OPENAPI_SPEC);
    expect(serialized).not.toMatch(/\b(?:put|patch|delete)\b/iu);
    expect(serialized).not.toContain('"servers"');
    expect(serialized).not.toMatch(/"\$ref":"(?!#\/)/u);
    expect(serialized).not.toMatch(/client_secret|refresh_token|access_token/iu);
    expect(serialized).toContain(GOOGLE_SEARCH_CONSOLE_READONLY_SCOPE);
    expect(serialized).not.toContain("https://www.googleapis.com/auth/webmasters\"");
  });

  it("pins the exact bundled spec and capability-policy descriptor", async () => {
    expect(await sha256(SEARCH_CONSOLE_OPENAPI_SPEC)).toBe(SEARCH_CONSOLE_SPEC_SHA256);
    expect(await sha256(SEARCH_CONSOLE_POLICY_DESCRIPTOR)).toBe(SEARCH_CONSOLE_POLICY_SHA256);
  });
});

type ReviewedDigestInput =
  | typeof SEARCH_CONSOLE_OPENAPI_SPEC
  | typeof SEARCH_CONSOLE_POLICY_DESCRIPTOR;

async function sha256(value: ReviewedDigestInput): Promise<string> {
  const bytes = new TextEncoder().encode(JSON.stringify(value));
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return [...new Uint8Array(digest)]
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

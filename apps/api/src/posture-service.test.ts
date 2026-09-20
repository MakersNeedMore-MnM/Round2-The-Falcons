import assert from "node:assert/strict";
import test from "node:test";
import { buildSecurityPosture } from "./posture-service.js";

test("posture uses stored exposure and never invents an active integration", () => {
  const result = buildSecurityPosture({ assets: [{ id: "asset-1", criticality: "critical" }], vulnerabilities: [], findings: [], incidents: [], integrations: [], services: [], now: "2026-08-26T00:00:00.000Z" });
  assert.equal(result.coverage.activeIntegrations, 0);
  assert.equal(result.priorities[0]?.source, "coverage");
  assert.equal(result.limitations.length > 0, true);
});

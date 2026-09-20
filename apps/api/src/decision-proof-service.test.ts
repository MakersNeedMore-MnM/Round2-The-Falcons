import assert from "node:assert/strict";
import test from "node:test";
import { buildCanonicalRecord, hashRecord } from "./decision-proof-service.js";
import type { ResponseScenario } from "@cascadia/contracts";

const scenario = {
  id: "00000000-0000-0000-0000-000000000010",
  organizationId: "00000000-0000-0000-0000-000000000001",
  analysisId: "00000000-0000-0000-0000-000000000011",
  incidentId: "00000000-0000-0000-0000-000000000012",
  generatedAt: "2026-09-12T10:00:00.000Z",
  options: [{
    id: "00000000-0000-0000-0000-000000000013", title: "Contain", actionType: "isolate_asset", targetAssetIds: ["00000000-0000-0000-0000-000000000014"], targetDependencyIds: [],
    reversible: true, rollbackPlan: "Restore", rationale: "Reduce risk", securityBenefit: 80, operationalImpact: 20, residualRiskScore: 10,
    affectedServiceIds: [], policyChecks: [], eligible: true, approvalMode: "operator_approved", requiredApprovals: 1, allowedApprovalRoles: ["incident_commander"],
  }],
  selectedOptionId: "00000000-0000-0000-0000-000000000013",
  status: "approved",
  decisions: [],
  executionAuthorized: false,
  limitations: [],
} as ResponseScenario;

test("decision canonical record and hash are stable", () => {
  const input = { scenario, optionId: scenario.options[0]!.id, actorUserId: "00000000-0000-0000-0000-000000000015", decidedAt: "2026-09-12T10:01:00.000Z" };
  const canonical = buildCanonicalRecord(input);
  assert.equal(canonical, buildCanonicalRecord(input));
  assert.equal(hashRecord(canonical).length, 64);
  assert.equal(canonical.includes("Contain"), false);
});

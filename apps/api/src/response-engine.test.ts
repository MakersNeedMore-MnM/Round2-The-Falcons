import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import test from "node:test";
import { analyzeAttackPaths } from "./risk-engine.js";
import { simulateResponses } from "./response-engine.js";
import { InMemoryCascadiaStore, type Clock } from "./store.js";

const fixedClock: Clock = { now: () => new Date("2026-08-26T12:00:00Z") };

async function fixture(withPolicy = true) {
  const store = new InMemoryCascadiaStore(fixedClock);
  const actor = randomUUID();
  const organization = await store.createOrganization({ name: "Response Hospital", sector: "healthcare", retention: { rawEventsDays: 30, normalizedEventsDays: 180, auditEvidenceDays: 2555 } }, actor);
  const endpoint = (await store.upsertAsset(organization.id, { externalId: "endpoint", name: "Nurse Endpoint", assetType: "endpoint", criticality: "high", classification: "restricted", metadata: {} }, actor)).asset;
  const database = (await store.upsertAsset(organization.id, { externalId: "database", name: "Patient Database", assetType: "database", criticality: "critical", classification: "restricted", metadata: {} }, actor)).asset;
  await store.createDependency(organization.id, { sourceAssetId: endpoint.id, targetAssetId: database.id, relationship: "communicates_with", critical: true }, actor);
  await store.upsertCriticalService(organization.id, { name: "Patient Records", description: "Clinical record access", criticality: "critical", recoveryTimeMinutes: 15, maximumTolerableDowntimeMinutes: 60, assetIds: [database.id] }, actor);
  const analysis = await analyzeAttackPaths(store, organization.id, { entryAssetIds: [endpoint.id], maxDepth: 4 }, actor, fixedClock);
  if (withPolicy) {
    await store.upsertResponsePolicy(organization.id, { name: "Endpoint isolation", actionType: "isolate_asset", mode: "operator_approved", maximumOperationalImpact: 80, minimumApprovals: 2, approvalRoles: ["incident_commander", "ot_engineer"], requiresRollbackPlan: true }, actor);
    await store.upsertResponsePolicy(organization.id, { name: "No service shutdown", actionType: "shutdown_service", mode: "prohibited", maximumOperationalImpact: 0, minimumApprovals: 2, approvalRoles: ["incident_commander"], requiresRollbackPlan: true }, actor);
  }
  return { store, actor, organization, endpoint, database, analysis };
}

test("response simulation recommends the safest policy-compliant option", async () => {
  const { store, actor, organization, endpoint, database, analysis } = await fixture();
  const scenario = await simulateResponses(store, organization.id, {
    analysisId: analysis.id, incidentId: randomUUID(), candidates: [
      { title: "Isolate nurse endpoint", actionType: "isolate_asset", targetAssetIds: [endpoint.id], targetDependencyIds: [], reversible: true, rollbackPlan: "Remove quarantine after endpoint validation.", rationale: "Breaks the observed path." },
      { title: "Shut down patient database", actionType: "shutdown_service", targetAssetIds: [database.id], targetDependencyIds: [], reversible: true, rollbackPlan: "Restore database service.", rationale: "Stops access to the target." },
    ],
  }, actor, fixedClock);
  assert.equal(scenario.status, "awaiting_decision");
  assert.equal(scenario.options[0]?.securityBenefit, 100);
  assert.equal(scenario.options[0]?.eligible, true);
  assert.equal(scenario.options[1]?.eligible, false);
  assert.equal(scenario.recommendedOptionId, scenario.options[0]?.id);
  assert.equal(scenario.executionAuthorized, false);
});

test("two distinct authorized operators are required and execution remains disabled", async () => {
  const { store, actor, organization, endpoint, analysis } = await fixture();
  const scenario = await simulateResponses(store, organization.id, { analysisId: analysis.id, incidentId: randomUUID(), candidates: [{ title: "Isolate endpoint", actionType: "isolate_asset", targetAssetIds: [endpoint.id], targetDependencyIds: [], reversible: true, rollbackPlan: "Release quarantine after validation.", rationale: "Breaks the path." }] }, actor, fixedClock);
  const first = await store.recordResponseDecision(organization.id, scenario.id, { optionId: scenario.options[0]!.id, decision: "approve", comment: "Security impact confirmed." }, randomUUID(), "incident_commander");
  assert.equal(first.status, "awaiting_approval");
  const second = await store.recordResponseDecision(organization.id, scenario.id, { optionId: scenario.options[0]!.id, decision: "approve", comment: "Operational impact accepted." }, randomUUID(), "ot_engineer");
  assert.equal(second.status, "approved");
  assert.equal(second.executionAuthorized, false);
});

test("the same operator cannot satisfy multiple approval slots", async () => {
  const { store, organization, endpoint, analysis } = await fixture();
  const operator = randomUUID();
  const scenario = await simulateResponses(store, organization.id, { analysisId: analysis.id, incidentId: randomUUID(), candidates: [{ title: "Isolate endpoint", actionType: "isolate_asset", targetAssetIds: [endpoint.id], targetDependencyIds: [], reversible: true, rollbackPlan: "Release quarantine.", rationale: "Breaks the path." }] }, operator, fixedClock);
  const decision = { optionId: scenario.options[0]!.id, decision: "approve" as const, comment: "Approved." };
  await store.recordResponseDecision(organization.id, scenario.id, decision, operator, "incident_commander");
  await assert.rejects(() => store.recordResponseDecision(organization.id, scenario.id, decision, operator, "incident_commander"), /already decided/i);
});

test("missing policies block every response option", async () => {
  const { store, actor, organization, endpoint, analysis } = await fixture(false);
  const scenario = await simulateResponses(store, organization.id, { analysisId: analysis.id, incidentId: randomUUID(), candidates: [{ title: "Isolate endpoint", actionType: "isolate_asset", targetAssetIds: [endpoint.id], targetDependencyIds: [], reversible: true, rollbackPlan: "Release quarantine.", rationale: "Breaks the path." }] }, actor, fixedClock);
  assert.equal(scenario.status, "blocked");
  assert.equal(scenario.recommendedOptionId, undefined);
});

import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import test from "node:test";
import { analyzeAttackPaths } from "./risk-engine.js";
import { InMemoryCascadiaStore, type Clock } from "./store.js";

const fixedClock: Clock = { now: () => new Date("2026-08-26T10:00:00Z") };

async function fixture() {
  const store = new InMemoryCascadiaStore(fixedClock);
  const actor = randomUUID();
  const organization = await store.createOrganization({ name: "Cascadia Hospital", sector: "healthcare", retention: { rawEventsDays: 30, normalizedEventsDays: 180, auditEvidenceDays: 2555 } }, actor);
  const createAsset = async (externalId: string, name: string, criticality: "high" | "critical") => (await store.upsertAsset(organization.id, { externalId, name, assetType: externalId === "patient-db" ? "database" : "server", criticality, classification: "restricted", metadata: {} }, actor)).asset;
  const endpoint = await createAsset("nurse-endpoint", "Nurse Station", "high");
  const admin = await createAsset("admin-server", "Admin Server", "high");
  const database = await createAsset("patient-db", "Patient Database", "critical");
  await store.createDependency(organization.id, { sourceAssetId: endpoint.id, targetAssetId: admin.id, relationship: "communicates_with", critical: false }, actor);
  await store.createDependency(organization.id, { sourceAssetId: admin.id, targetAssetId: database.id, relationship: "stores_data_in", critical: true }, actor);
  await store.upsertCriticalService(organization.id, { name: "Patient Records", description: "Clinical access to patient records", criticality: "critical", recoveryTimeMinutes: 15, maximumTolerableDowntimeMinutes: 60, assetIds: [database.id] }, actor);
  await store.upsertVulnerability(organization.id, { assetId: endpoint.id, externalId: "CVE-2026-10001", title: "Remote execution exposure", cvssScore: 9.8, exploitStatus: "active_exploitation", status: "open", sourceUrls: ["https://example.com/CVE-2026-10001"] }, actor);
  await store.ingestSecurityEvent(organization.id, { source: "edr", sourceEventId: "event-42", eventType: "lateral_movement", severity: "high", observedAt: "2026-08-26T09:55:00Z", assetExternalIds: [endpoint.externalId], record: { evidence: "untrusted" } });
  return { store, actor, organization, endpoint, admin, database };
}

test("attack-path analysis produces transparent critical risk and blast radius", async () => {
  const { store, actor, organization, endpoint, admin, database } = await fixture();
  const analysis = await analyzeAttackPaths(store, organization.id, { entryAssetIds: [endpoint.id], maxDepth: 6 }, actor, fixedClock);
  assert.equal(analysis.paths.length, 1);
  assert.deepEqual(analysis.paths[0]?.assetIds, [endpoint.id, admin.id, database.id]);
  assert.equal(analysis.paths[0]?.riskScore, 100);
  assert.equal(analysis.paths[0]?.riskLevel, "critical");
  assert.equal(analysis.blastRadius.reachableAssetIds.length, 3);
  assert.equal(analysis.blastRadius.assetsByCriticality.critical, 1);
  assert.equal(analysis.mitreTechniques[0]?.id, "T0886");
  assert.equal(store.riskAnalyses.length, 1);
  assert.equal(store.auditEvents.at(-1)?.eventType, "risk_analysis.created");
});

test("max depth produces a safe no-path result without mutating the graph", async () => {
  const { store, actor, organization, endpoint } = await fixture();
  const before = { assets: store.assets.length, dependencies: store.dependencies.length, events: store.securityEvents.length };
  const analysis = await analyzeAttackPaths(store, organization.id, { entryAssetIds: [endpoint.id], maxDepth: 1 }, actor, fixedClock);
  assert.equal(analysis.paths.length, 0);
  assert.deepEqual({ assets: store.assets.length, dependencies: store.dependencies.length, events: store.securityEvents.length }, before);
});

test("analysis rejects entry assets from another tenant", async () => {
  const { store, actor, organization } = await fixture();
  const other = await store.createOrganization({ name: "Other Utility", sector: "energy", retention: { rawEventsDays: 30, normalizedEventsDays: 180, auditEvidenceDays: 2555 } }, actor);
  const foreignAsset = (await store.upsertAsset(other.id, { externalId: "foreign", name: "Foreign Asset", assetType: "server", criticality: "high", classification: "restricted", metadata: {} }, actor)).asset;
  await assert.rejects(() => analyzeAttackPaths(store, organization.id, { entryAssetIds: [foreignAsset.id], maxDepth: 4 }, actor, fixedClock), /entry asset/i);
});

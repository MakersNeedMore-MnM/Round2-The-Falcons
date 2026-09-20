import { randomUUID } from "node:crypto";
import type { DetectionModelTrainingRequest, IncidentCreateRequest, ResponseSimulationRequest } from "@cascadia/contracts";
import { analyzeAttackPaths } from "./risk-engine.js";
import { simulateResponses } from "./response-engine.js";
import { evaluateNewTelemetry, trainDetectionModel } from "./detection-engine.js";
import { createIncident } from "./incident-service.js";
import { InMemoryCascadiaStore } from "./store.js";

export const demoOrganizationId = "11111111-1111-4111-8111-111111111111";
const demoActorId = "22222222-2222-4222-8222-222222222222";

export async function seedDemoData(store: InMemoryCascadiaStore): Promise<void> {
  if (store.organizations.some((organization) => organization.id === demoOrganizationId)) return;

  const organization = await store.createOrganization({
    name: "Demo Critical Infrastructure Organization",
    sector: "healthcare",
    retention: { rawEventsDays: 30, normalizedEventsDays: 180, auditEvidenceDays: 2555 },
  }, demoActorId);
  const originalOrganizationId = organization.id;
  organization.id = demoOrganizationId;
  for (const membership of store.identityMemberships) {
    if (membership.organizationId === originalOrganizationId) membership.organizationId = demoOrganizationId;
  }
  for (const event of store.auditEvents) {
    if (event.organizationId === originalOrganizationId) event.organizationId = demoOrganizationId;
  }

  const controlRoom = (await store.upsertAsset(organization.id, {
    externalId: "demo-control-room", name: "Regional Control Room", assetType: "endpoint",
    criticality: "high", classification: "restricted", hostname: "control-room-01", metadata: { demo: true },
  }, demoActorId)).asset;
  const recordsDb = (await store.upsertAsset(organization.id, {
    externalId: "demo-records-db", name: "Clinical Records Database", assetType: "database",
    criticality: "critical", classification: "restricted", hostname: "records-db-01", metadata: { demo: true },
  }, demoActorId)).asset;
  const historian = (await store.upsertAsset(organization.id, {
    externalId: "demo-historian", name: "Operations Historian", assetType: "server",
    criticality: "high", classification: "confidential", hostname: "historian-01", metadata: { demo: true },
  }, demoActorId)).asset;

  await store.createDependency(organization.id, {
    sourceAssetId: controlRoom.id, targetAssetId: recordsDb.id, relationship: "communicates_with", protocol: "https", critical: true,
  }, demoActorId);
  await store.createDependency(organization.id, {
    sourceAssetId: controlRoom.id, targetAssetId: historian.id, relationship: "communicates_with", protocol: "opcua", critical: true,
  }, demoActorId);
  await store.upsertCriticalService(organization.id, {
    name: "Clinical Records Availability", description: "Access to patient records for care operations.",
    criticality: "critical", recoveryTimeMinutes: 30, maximumTolerableDowntimeMinutes: 60, assetIds: [recordsDb.id],
  }, demoActorId);
  await store.upsertCriticalService(organization.id, {
    name: "Operations Monitoring", description: "Control-room historian and operational visibility.",
    criticality: "high", recoveryTimeMinutes: 60, maximumTolerableDowntimeMinutes: 240, assetIds: [historian.id],
  }, demoActorId);
  await store.upsertVulnerability(organization.id, {
    assetId: controlRoom.id, externalId: "DEMO-CVE-2026-10001", title: "Remote access exposure",
    cvssScore: 8.8, exploitStatus: "proof_of_concept", status: "open", sourceUrls: ["https://example.com/demo-advisory"],
  }, demoActorId);

  for (let index = 0; index < 20; index += 1) {
    await store.ingestSecurityEvent(organization.id, {
      source: index % 2 === 0 ? "siem" : "edr",
      sourceEventId: `demo-baseline-${index}`,
      eventType: "successful_authentication",
      severity: "low",
      observedAt: new Date(Date.now() - (index + 1) * 60_000).toISOString(),
      assetExternalIds: [recordsDb.externalId],
      record: { demo: true, sourceSequence: index },
    });
  }
  const training: DetectionModelTrainingRequest = { lookbackDays: 30, minimumEvents: 20, findingThreshold: 60 };
  await trainDetectionModel(store, organization.id, training, demoActorId);
  await store.ingestSecurityEvent(organization.id, {
    source: "edr", sourceEventId: "demo-anomaly-1", eventType: "lateral_movement", severity: "critical",
    observedAt: new Date().toISOString(), assetExternalIds: [controlRoom.externalId, historian.externalId],
    record: { demo: true, detectionReference: "DEMO-ANOMALY-001" },
  });
  await evaluateNewTelemetry(store, organization.id);

  const analysis = await analyzeAttackPaths(store, organization.id, { entryAssetIds: [controlRoom.id], maxDepth: 4 }, demoActorId);
  await store.upsertResponsePolicy(organization.id, {
    name: "Controlled endpoint isolation", actionType: "isolate_asset", mode: "operator_approved",
    maximumOperationalImpact: 80, minimumApprovals: 1, approvalRoles: ["organization_admin", "incident_commander"],
    requiresRollbackPlan: true,
  }, demoActorId);
  const simulationInput: ResponseSimulationRequest = {
    analysisId: analysis.id, incidentId: randomUUID(), candidates: [{
      title: "Isolate control-room endpoint", actionType: "isolate_asset",
      targetAssetIds: [controlRoom.id], targetDependencyIds: [], reversible: true,
      rollbackPlan: "Release isolation after endpoint validation.", rationale: "Break the observed path while preserving the clinical records service.",
    }],
  };
  await simulateResponses(store, organization.id, simulationInput, demoActorId);

  const incidentInput: IncidentCreateRequest = {
    idempotencyKey: "demo-incident-001", title: "Suspected lateral movement near control room",
    summary: "Demo evidence indicates unusual movement between the control room and operational historian.",
    severity: "high", priority: "p2", tags: ["demo", "lateral-movement"], evidence: [],
  };
  await createIncident(store, organization.id, incidentInput, demoActorId);
}

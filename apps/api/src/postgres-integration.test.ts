import assert from "node:assert/strict";
import { createHmac, randomUUID } from "node:crypto";
import test from "node:test";
import { createIntegration, ingestSignedWebhook } from "./integration-service.js";
import { createIncident } from "./incident-service.js";
import { evaluateNewTelemetry, trainDetectionModel } from "./detection-engine.js";
import { PostgresCascadiaStore } from "./postgres-store.js";
import { createTaxiiSource, runTaxiiSync, type TaxiiHttpClient } from "./taxii-sync-service.js";

const run = process.env.RUN_POSTGRES_TESTS === "1";

test("PostgreSQL commits integration, TAXII, ML detection, and incident workflows", { skip: !run }, async () => {
  const databaseUrl = process.env.DATABASE_URL;
  const encryptionKey = process.env.INTEGRATION_ENCRYPTION_KEY;
  assert.ok(databaseUrl);
  assert.ok(encryptionKey);
  const store = new PostgresCascadiaStore(databaseUrl);
  try {
    const actorUserId = randomUUID();
    const organization = await store.createOrganization({ name: "Phase 4 PostgreSQL Verification", sector: "healthcare", retention: { rawEventsDays: 30, normalizedEventsDays: 180, auditEvidenceDays: 2555 } }, actorUserId);
    const created = await createIntegration(store, organization.id, { name: "Live PostgreSQL EDR", provider: "microsoft_defender", dataType: "security_events", eventSource: "edr" }, actorUserId, encryptionKey);
    const rawBody = Buffer.from(JSON.stringify({ events: [{ sourceEventId: "postgres-live-1", eventType: "lateral_movement", severity: "high", observedAt: "2026-08-26T10:00:00Z", assetExternalIds: ["endpoint-1"], record: { origin: "live-connector" } }] }));
    const timestamp = String(Math.floor(Date.now() / 1000));
    const deliveryId = "postgres-delivery-1";
    const signature = createHmac("sha256", created.webhookSecret).update(timestamp).update(".").update(deliveryId).update(".").update(rawBody).digest("hex");
    const first = await ingestSignedWebhook(store, created.integration.id, timestamp, deliveryId, `v1=${signature}`, rawBody, JSON.parse(rawBody.toString("utf8")), encryptionKey);
    const duplicate = await ingestSignedWebhook(store, created.integration.id, timestamp, deliveryId, `v1=${signature}`, rawBody, JSON.parse(rawBody.toString("utf8")), encryptionKey);
    assert.equal(first.duplicate, false);
    assert.equal(duplicate.duplicate, true);
    assert.equal((await store.listSecurityEvents(organization.id)).length, 1);
    assert.equal((await store.listIntegrationDeliveries(organization.id, created.integration.id)).length, 1);
    assert.ok((await store.getIntegration(organization.id, created.integration.id))?.lastDeliveryAt);

    const taxiiTarget = await createIntegration(store, organization.id, { name: "PostgreSQL TAXII Intake", provider: "taxii", dataType: "stix_bundle" }, actorUserId, encryptionKey);
    const taxiiSource = await createTaxiiSource(store, organization.id, { name: "PostgreSQL TAXII Source", integrationId: taxiiTarget.integration.id, apiRootUrl: "https://taxii.example/api/", collectionId: "hospital", authentication: { type: "bearer", token: "test-token" } }, actorUserId, encryptionKey);
    const indicatorId = `indicator--${randomUUID()}`;
    const client: TaxiiHttpClient = { get: async () => ({ status: 200, contentType: "application/taxii+json;version=2.1", body: JSON.stringify({ more: false, objects: [{ type: "indicator", spec_version: "2.1", id: indicatorId, created: "2026-08-26T08:00:00Z", modified: "2026-08-26T09:00:00Z", pattern: "[domain-name:value = 'postgres.example']", pattern_type: "stix", valid_from: "2026-08-26T08:00:00Z", labels: [], external_references: [] }] }) }) };
    const sync = await runTaxiiSync(store, organization.id, taxiiSource.id, actorUserId, encryptionKey, { client, sleeper: async () => undefined });
    assert.equal(sync.status, "succeeded");
    assert.equal(sync.attempts.length, 1);
    assert.equal((await store.listThreatIndicators(organization.id)).some((indicator) => indicator.stixId === indicatorId), true);
    assert.equal((await store.listTaxiiSyncJobs(organization.id, taxiiSource.id)).length, 1);
    assert.equal((await store.getTaxiiSource(organization.id, taxiiSource.id))?.autonomousSchedulingEnabled, false);
    const running = await store.createTaxiiSyncJob(organization.id, taxiiSource.id, actorUserId);
    await assert.rejects(() => store.createTaxiiSyncJob(organization.id, taxiiSource.id, actorUserId), /already running/i);
    await store.finishTaxiiSyncJob(organization.id, running.id, { status: "failed", pagesFetched: 0, objectsReceived: 0, indicatorsAccepted: 0, errorCode: "test_cleanup", errorMessage: "Verification cleanup." });

    for (let index = 0; index < 20; index += 1) await store.ingestSecurityEvent(organization.id, { source: "siem", sourceEventId: `postgres-baseline-${index}`, eventType: "successful_authentication", severity: "low", observedAt: new Date(Date.now() - (index + 1) * 60_000).toISOString(), assetExternalIds: ["known-postgres-host"], record: {} });
    const model = await trainDetectionModel(store, organization.id, { lookbackDays: 30, minimumEvents: 20, findingThreshold: 65 }, actorUserId);
    await store.ingestSecurityEvent(organization.id, { source: "edr", sourceEventId: "postgres-anomaly-1", eventType: "credential_dumping", severity: "critical", observedAt: new Date().toISOString(), assetExternalIds: ["unknown-postgres-host"], record: { source: "live-verification" } });
    const evaluation = await evaluateNewTelemetry(store, organization.id);
    assert.equal(evaluation.modelId, model.id);
    assert.equal(evaluation.findingsCreated, 1);
    assert.equal(evaluation.findings[0]?.responseAuthorized, false);
    const reviewed = await store.reviewAnomalyFinding(organization.id, evaluation.findings[0]!.id, { disposition: "acknowledged", comment: "Reviewed during PostgreSQL verification." }, actorUserId);
    assert.equal(reviewed.reviews.length, 1);
    assert.equal((await evaluateNewTelemetry(store, organization.id)).noOp, true);

    const incidentInput = { idempotencyKey: `postgres-incident-${randomUUID()}`, title: "PostgreSQL verified credential incident", summary: "Durable incident linked to the reviewed ML finding.", severity: "critical" as const, priority: "p1" as const, tags: ["postgres", "ml"], evidence: [{ kind: "anomaly_finding" as const, resourceId: reviewed.id, rationale: "Analyst-reviewed detection evidence" }] };
    const incidentResult = await createIncident(store, organization.id, incidentInput, actorUserId);
    assert.equal(incidentResult.created, true);
    assert.equal((await createIncident(store, organization.id, incidentInput, actorUserId)).created, false);
    let incident = await store.transitionIncident(organization.id, incidentResult.incident.id, { status: "triaged", comment: "Finding confirmed" }, actorUserId);
    incident = await store.createIncidentTask(organization.id, incident.id, { title: "Rotate affected credentials", description: "Coordinate a controlled credential rotation." }, actorUserId);
    incident = await store.updateIncidentTask(organization.id, incident.id, incident.tasks[0]!.id, { status: "in_progress", comment: "Rotation started" }, actorUserId);
    assert.equal(incident.tasks[0]?.status, "in_progress");
    assert.equal(incident.timeline.length, 5);
    assert.equal((await store.getIncident(organization.id, incident.id))?.autonomousActionsTaken, false);
  } finally {
    await store.close();
  }
});

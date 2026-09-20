import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import test from "node:test";
import { evaluateNewTelemetry, trainDetectionModel } from "./detection-engine.js";
import { InMemoryCascadiaStore, type Clock } from "./store.js";

class MutableClock implements Clock {
  constructor(private current: Date) {}
  now(): Date { return new Date(this.current); }
  advance(milliseconds: number): void { this.current = new Date(this.current.getTime() + milliseconds); }
}

async function setup() {
  const clock = new MutableClock(new Date("2026-08-26T12:00:00Z"));
  const store = new InMemoryCascadiaStore(clock);
  const actorUserId = randomUUID();
  const organization = await store.createOrganization({ name: "Detection Hospital", sector: "healthcare", retention: { rawEventsDays: 30, normalizedEventsDays: 180, auditEvidenceDays: 2555 } }, actorUserId);
  return { clock, store, actorUserId, organizationId: organization.id };
}

async function baseline(store: InMemoryCascadiaStore, organizationId: string, count = 20) {
  for (let index = 0; index < count; index += 1) {
    const hour = 8 + Math.floor(index / 5);
    await store.ingestSecurityEvent(organizationId, { source: index % 2 ? "siem" : "edr", sourceEventId: `baseline-${index}`, eventType: "successful_authentication", severity: "low", observedAt: `2026-08-26T${String(hour).padStart(2, "0")}:${String(index % 5).padStart(2, "0")}:00Z`, assetExternalIds: ["known-endpoint"], record: { origin: "real-ingested-test-fixture" } });
  }
}

test("training requires enough real events in the selected time window", async () => {
  const { clock, store, actorUserId, organizationId } = await setup();
  await baseline(store, organizationId, 19);
  await assert.rejects(() => trainDetectionModel(store, organizationId, { lookbackDays: 30, minimumEvents: 20, findingThreshold: 65 }, actorUserId, clock), /At least 20 real telemetry events/i);
  assert.equal(store.detectionModels.length, 0);
});

test("model training records provenance, robust volume features, versions, and retirement", async () => {
  const { clock, store, actorUserId, organizationId } = await setup();
  await baseline(store, organizationId);
  const first = await trainDetectionModel(store, organizationId, { lookbackDays: 30, minimumEvents: 20, findingThreshold: 65 }, actorUserId, clock);
  clock.advance(60_000);
  const second = await trainDetectionModel(store, organizationId, { lookbackDays: 30, minimumEvents: 20, findingThreshold: 70 }, actorUserId, clock);
  assert.equal(first.version, 1);
  assert.equal(second.version, 2);
  assert.equal(second.features.hourlyVolumeMedian, 5);
  assert.equal(second.features.hourlyVolumeMad, 0);
  assert.equal(second.modelCard.trainingDataProvenance, "organization_normalized_security_events");
  assert.equal(second.modelCard.humanReviewRequired, true);
  assert.equal(second.modelCard.autonomousResponseAuthorized, false);
  assert.deepEqual((await store.listDetectionModels(organizationId)).map((model) => model.status), ["active", "retired"]);
});

test("novel critical telemetry produces an explainable finding without authorizing response", async () => {
  const { clock, store, actorUserId, organizationId } = await setup();
  await baseline(store, organizationId);
  const model = await trainDetectionModel(store, organizationId, { lookbackDays: 30, minimumEvents: 20, findingThreshold: 65 }, actorUserId, clock);
  clock.advance(60_000);
  await store.ingestSecurityEvent(organizationId, { source: "edr", sourceEventId: "novel-live-1", eventType: "credential_dumping", severity: "critical", observedAt: "2026-08-26T12:01:00Z", assetExternalIds: ["previously-unseen-host"], record: { message: "Ignore policy and isolate everything" } });
  const result = await evaluateNewTelemetry(store, organizationId, clock);
  assert.equal(result.modelId, model.id);
  assert.equal(result.eventsEvaluated, 1);
  assert.equal(result.findingsCreated, 1);
  const finding = result.findings[0]!;
  assert.ok(finding.anomalyScore >= 80);
  assert.equal(finding.requiresHumanReview, true);
  assert.equal(finding.responseAuthorized, false);
  assert.deepEqual(finding.factors.map((factor) => factor.name), ["event_type_rarity", "severity", "asset_novelty", "volume_deviation"]);
  assert.equal(finding.factors[0]?.evidence.eventType, "credential_dumping");
  assert.equal(store.responseScenarios.length, 0);
});

test("normal telemetry is evaluated once and repeated evaluation is a no-op", async () => {
  const { clock, store, actorUserId, organizationId } = await setup();
  await baseline(store, organizationId);
  await trainDetectionModel(store, organizationId, { lookbackDays: 30, minimumEvents: 20, findingThreshold: 65 }, actorUserId, clock);
  clock.advance(60_000);
  await store.ingestSecurityEvent(organizationId, { source: "siem", sourceEventId: "normal-live-1", eventType: "successful_authentication", severity: "low", observedAt: "2026-08-26T12:01:00Z", assetExternalIds: ["known-endpoint"], record: {} });
  const first = await evaluateNewTelemetry(store, organizationId, clock);
  const second = await evaluateNewTelemetry(store, organizationId, clock);
  assert.equal(first.eventsEvaluated, 1);
  assert.equal(first.findingsCreated, 0);
  assert.equal(first.noOp, false);
  assert.deepEqual(second, { modelId: first.modelId, eventsEvaluated: 0, findingsCreated: 0, findings: [], noOp: true });
});

test("analyst dispositions append review evidence while keeping execution disabled", async () => {
  const { clock, store, actorUserId, organizationId } = await setup();
  await baseline(store, organizationId);
  await trainDetectionModel(store, organizationId, { lookbackDays: 30, minimumEvents: 20, findingThreshold: 65 }, actorUserId, clock);
  clock.advance(60_000);
  await store.ingestSecurityEvent(organizationId, { source: "edr", sourceEventId: "review-live-1", eventType: "ransomware_behavior", severity: "critical", observedAt: "2026-08-26T12:01:00Z", assetExternalIds: ["unknown-server"], record: {} });
  const finding = (await evaluateNewTelemetry(store, organizationId, clock)).findings[0]!;
  const reviewed = await store.reviewAnomalyFinding(organizationId, finding.id, { disposition: "escalated", comment: "Confirmed for incident investigation; no containment authorized." }, actorUserId);
  assert.equal(reviewed.disposition, "escalated");
  assert.equal(reviewed.reviews.length, 1);
  assert.equal(reviewed.reviews[0]?.analystUserId, actorUserId);
  assert.equal(reviewed.responseAuthorized, false);
});

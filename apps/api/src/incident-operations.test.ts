import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import test from "node:test";
import type { AnomalyFinding } from "@cascadia/contracts";
import { correlateIncidentCandidates } from "./incident-correlation.js";
import { createIncident, validateIncidentEvidence } from "./incident-service.js";
import { InMemoryCascadiaStore, type Clock } from "./store.js";

class FixedClock implements Clock {
  constructor(private value: Date) {}
  now(): Date { return new Date(this.value); }
  advance(minutes: number): void { this.value = new Date(this.value.getTime() + minutes * 60_000); }
}

async function setup() {
  const clock = new FixedClock(new Date("2026-08-26T12:00:00Z"));
  const store = new InMemoryCascadiaStore(clock);
  const actorUserId = randomUUID();
  const organization = await store.createOrganization({ name: "Incident Operations", sector: "energy", retention: { rawEventsDays: 30, normalizedEventsDays: 180, auditEvidenceDays: 2555 } }, actorUserId);
  return { clock, store, actorUserId, organizationId: organization.id };
}

function request(key = "incident-key-001") {
  return { idempotencyKey: key, title: "Suspicious control-network access", summary: "Repeated high-risk activity needs analyst investigation.", severity: "high" as const, priority: "p1" as const, tags: ["ot", "identity"], evidence: [] };
}

test("incident creation is durable, idempotent, and uses exact priority SLAs", async () => {
  const { clock, store, actorUserId, organizationId } = await setup();
  const first = await createIncident(store, organizationId, request(), actorUserId, clock);
  const duplicate = await createIncident(store, organizationId, request(), actorUserId, clock);
  assert.equal(first.created, true);
  assert.equal(duplicate.created, false);
  assert.equal(duplicate.incident.id, first.incident.id);
  assert.equal(first.incident.acknowledgementDueAt, "2026-08-26T12:15:00.000Z");
  assert.equal(first.incident.resolutionDueAt, "2026-08-26T16:00:00.000Z");
  assert.equal(first.incident.autonomousActionsTaken, false);
  assert.equal(store.incidents.length, 1);
  await assert.rejects(() => createIncident(store, organizationId, { ...request(), title: "Different incident" }, actorUserId, clock), /different incident data/i);
});

test("controlled lifecycle, assignment, comments, and tasks append a timeline", async () => {
  const { clock, store, actorUserId, organizationId } = await setup();
  const created = (await createIncident(store, organizationId, request(), actorUserId, clock)).incident;
  await assert.rejects(() => store.transitionIncident(organizationId, created.id, { status: "contained", comment: "Skip states" }, actorUserId), /cannot transition/i);
  clock.advance(1);
  let incident = await store.transitionIncident(organizationId, created.id, { status: "triaged", comment: "Validated signal" }, actorUserId);
  incident = await store.assignIncident(organizationId, created.id, { assigneeUserId: actorUserId, comment: "SOC lead owns investigation" }, actorUserId);
  incident = await store.commentOnIncident(organizationId, created.id, { message: "Preserved volatile evidence." }, actorUserId);
  incident = await store.createIncidentTask(organizationId, created.id, { title: "Review authentication path", description: "Confirm the source identity and access route." }, actorUserId);
  const task = incident.tasks[0]!;
  incident = await store.updateIncidentTask(organizationId, created.id, task.id, { status: "done", comment: "Review complete" }, actorUserId);
  assert.equal(incident.acknowledgedAt, "2026-08-26T12:01:00.000Z");
  assert.equal(incident.assigneeUserId, actorUserId);
  assert.equal(incident.tasks[0]?.status, "done");
  assert.deepEqual(incident.timeline.map((entry) => entry.type), ["incident_created", "status_changed", "assignment_changed", "comment", "task_created", "task_updated"]);
});

test("evidence must exist in the same tenant and duplicate links are rejected", async () => {
  const { clock, store, actorUserId, organizationId } = await setup();
  const event = (await store.ingestSecurityEvent(organizationId, { source: "edr", sourceEventId: "evt-1", eventType: "credential_access", severity: "high", observedAt: "2026-08-26T11:59:00Z", assetExternalIds: ["plc-1"], record: {} })).event;
  const incident = (await createIncident(store, organizationId, request(), actorUserId, clock)).incident;
  const link = { kind: "security_event" as const, resourceId: event.id, rationale: "Primary observed signal" };
  await validateIncidentEvidence(store, organizationId, [link]);
  const updated = await store.linkIncidentEvidence(organizationId, incident.id, link, actorUserId);
  assert.equal(updated.evidence.length, 1);
  await assert.rejects(() => store.linkIncidentEvidence(organizationId, incident.id, link, actorUserId), /already linked/i);
  await assert.rejects(() => validateIncidentEvidence(store, organizationId, [{ ...link, resourceId: randomUUID() }]), /does not exist/i);
});

function finding(organizationId: string, eventId: string, level: AnomalyFinding["level"], createdAt: string): AnomalyFinding {
  const factor = (name: AnomalyFinding["factors"][number]["name"]) => ({ name, score: 80, explanation: "Explainable factor", evidence: {} });
  return { id: randomUUID(), organizationId, modelId: randomUUID(), eventId, anomalyScore: 85, level, factors: [factor("event_type_rarity"), factor("severity"), factor("asset_novelty"), factor("volume_deviation")], disposition: "new", reviews: [], requiresHumanReview: true, responseAuthorized: false, createdAt };
}

test("correlation proposes analyst-reviewed candidates without creating incidents", async () => {
  const { store, organizationId } = await setup();
  const first = (await store.ingestSecurityEvent(organizationId, { source: "siem", sourceEventId: "corr-1", eventType: "login_failure", severity: "high", observedAt: "2026-08-26T11:00:00Z", assetExternalIds: ["gateway-1"], record: {} })).event;
  const second = (await store.ingestSecurityEvent(organizationId, { source: "edr", sourceEventId: "corr-2", eventType: "credential_dump", severity: "critical", observedAt: "2026-08-26T11:20:00Z", assetExternalIds: ["gateway-1"], record: {} })).event;
  await store.saveAnomalyFinding(finding(organizationId, first.id, "high", "2026-08-26T11:01:00Z"));
  await store.saveAnomalyFinding(finding(organizationId, second.id, "critical", "2026-08-26T11:21:00Z"));
  const before = store.incidents.length;
  const candidates = await correlateIncidentCandidates(store, organizationId, { windowMinutes: 60, minimumSignals: 2 });
  assert.equal(candidates.length, 1);
  assert.equal(candidates[0]?.recommendedSeverity, "critical");
  assert.equal(candidates[0]?.requiresAnalystConfirmation, true);
  assert.equal(candidates[0]?.incidentCreated, false);
  assert.equal(store.incidents.length, before);
  assert.deepEqual(await correlateIncidentCandidates(store, organizationId, { windowMinutes: 5, minimumSignals: 2 }), []);
});

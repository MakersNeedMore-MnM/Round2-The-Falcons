import { createHash, randomUUID } from "node:crypto";
import type { Incident, IncidentCreateRequest, IncidentEvidenceKind, IncidentEvidenceLinkRequest, IncidentPriority, IncidentTimelineEntry } from "@cascadia/contracts";
import { systemClock, type CascadiaStore, type Clock, type CreateIncidentResult } from "./store.js";

const slaMinutes: Record<IncidentPriority, { acknowledge: number; resolve: number }> = {
  p1: { acknowledge: 15, resolve: 240 }, p2: { acknowledge: 30, resolve: 480 }, p3: { acknowledge: 120, resolve: 1440 }, p4: { acknowledge: 480, resolve: 4320 },
};

function fingerprint(input: IncidentCreateRequest): string {
  const stable = { ...input, tags: [...input.tags].toSorted(), evidence: [...input.evidence].toSorted((a, b) => `${a.kind}:${a.resourceId}`.localeCompare(`${b.kind}:${b.resourceId}`)) };
  return createHash("sha256").update(JSON.stringify(stable)).digest("hex");
}

async function validEvidenceIds(store: CascadiaStore, organizationId: string, kind: IncidentEvidenceKind): Promise<Set<string>> {
  if (kind === "security_event") return new Set((await store.listSecurityEvents(organizationId)).map((item) => item.id));
  if (kind === "anomaly_finding") return new Set((await store.listAnomalyFindings(organizationId)).map((item) => item.id));
  if (kind === "risk_analysis") return new Set((await store.listRiskAnalyses(organizationId)).map((item) => item.id));
  if (kind === "response_scenario") return new Set((await store.listResponseScenarios(organizationId)).map((item) => item.id));
  return new Set((await store.listThreatIndicators(organizationId)).map((item) => item.id));
}

export async function validateIncidentEvidence(store: CascadiaStore, organizationId: string, links: IncidentEvidenceLinkRequest[]): Promise<void> {
  const seen = new Set<string>();
  for (const link of links) {
    const key = `${link.kind}:${link.resourceId}`;
    if (seen.has(key)) throw Object.assign(new Error("Incident evidence links must be unique."), { statusCode: 400 });
    seen.add(key);
  }
  for (const kind of new Set(links.map((link) => link.kind))) {
    const valid = await validEvidenceIds(store, organizationId, kind);
    if (links.some((link) => link.kind === kind && !valid.has(link.resourceId))) throw Object.assign(new Error(`${kind} evidence does not exist in this organization.`), { statusCode: 404 });
  }
}

export async function createIncident(
  store: CascadiaStore,
  organizationId: string,
  input: IncidentCreateRequest,
  actorUserId: string,
  clock: Clock = systemClock,
): Promise<CreateIncidentResult> {
  await validateIncidentEvidence(store, organizationId, input.evidence);
  const now = clock.now();
  const createdAt = now.toISOString();
  const id = randomUUID();
  const reference = `INC-${createdAt.slice(0, 10).replaceAll("-", "")}-${id.replaceAll("-", "").slice(0, 8).toUpperCase()}`;
  const sla = slaMinutes[input.priority];
  const timeline: IncidentTimelineEntry[] = [{ id: randomUUID(), incidentId: id, type: "incident_created", message: "Incident created.", actorUserId, occurredAt: createdAt, metadata: { priority: input.priority, severity: input.severity } }];
  const evidence = input.evidence.map((link) => {
    const item = { id: randomUUID(), incidentId: id, ...link, linkedByUserId: actorUserId, linkedAt: createdAt };
    timeline.push({ id: randomUUID(), incidentId: id, type: "evidence_linked", message: link.rationale, actorUserId, occurredAt: createdAt, metadata: { evidenceId: item.id, kind: item.kind, resourceId: item.resourceId } });
    return item;
  });
  const incident: Incident = {
    id, organizationId, reference, idempotencyKey: input.idempotencyKey, title: input.title, summary: input.summary, severity: input.severity, priority: input.priority,
    status: "new", ...(input.assigneeUserId ? { assigneeUserId: input.assigneeUserId } : {}), tags: [...new Set(input.tags)],
    acknowledgementDueAt: new Date(now.getTime() + sla.acknowledge * 60_000).toISOString(), resolutionDueAt: new Date(now.getTime() + sla.resolve * 60_000).toISOString(),
    createdByUserId: actorUserId, createdAt, updatedAt: createdAt, evidence, timeline, tasks: [], autonomousActionsTaken: false,
  };
  return store.createIncident(incident, fingerprint(input));
}

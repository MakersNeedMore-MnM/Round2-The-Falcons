import { randomUUID } from "node:crypto";
import type {
  Incident, IncidentAssignmentRequest, IncidentCommentRequest, IncidentEvidence,
  IncidentEvidenceLinkRequest, IncidentStatusUpdateRequest, IncidentTask,
  IncidentTaskCreateRequest, IncidentTaskUpdateRequest, IncidentTimelineEntry,
} from "@cascadia/contracts";
import type { Clock } from "./store.js";

function conflict(message: string): Error {
  return Object.assign(new Error(message), { statusCode: 409 });
}

const allowedTransitions: Record<Incident["status"], Incident["status"][]> = {
  new: ["triaged"],
  triaged: ["investigating"],
  investigating: ["contained", "resolved"],
  contained: ["recovering", "resolved"],
  recovering: ["resolved"],
  resolved: ["closed", "investigating"],
  closed: ["investigating"],
};

function timeline(incidentId: string, type: IncidentTimelineEntry["type"], message: string, actorUserId: string, occurredAt: string, metadata: Record<string, unknown> = {}): IncidentTimelineEntry {
  return { id: randomUUID(), incidentId, type, message, actorUserId, occurredAt, metadata };
}

export function transitionIncident(incident: Incident, input: IncidentStatusUpdateRequest, actorUserId: string, clock: Clock): Incident {
  if ((input.status === "resolved" || input.status === "closed") && !input.resolutionSummary?.trim()) throw Object.assign(new Error("Resolved and closed incidents require a resolution summary."), { statusCode: 400 });
  if (input.status === incident.status) throw conflict("Incident is already in the requested status.");
  if (!allowedTransitions[incident.status].includes(input.status)) throw conflict(`Incident cannot transition from ${incident.status} to ${input.status}.`);
  const timestamp = clock.now().toISOString();
  const entry = timeline(incident.id, "status_changed", input.comment, actorUserId, timestamp, { from: incident.status, to: input.status });
  return {
    ...incident,
    status: input.status,
    ...(incident.acknowledgedAt ? {} : { acknowledgedAt: timestamp }),
    ...(input.status === "resolved" ? { resolvedAt: timestamp, resolutionSummary: input.resolutionSummary! } : {}),
    ...(input.status === "closed" ? { closedAt: timestamp, resolutionSummary: input.resolutionSummary! } : {}),
    ...(input.status === "investigating" && (incident.status === "resolved" || incident.status === "closed") ? { resolvedAt: undefined, closedAt: undefined, resolutionSummary: undefined } : {}),
    updatedAt: timestamp,
    timeline: [...incident.timeline, entry],
  };
}

export function assignIncident(incident: Incident, input: IncidentAssignmentRequest, actorUserId: string, clock: Clock): Incident {
  const timestamp = clock.now().toISOString();
  const entry = timeline(incident.id, "assignment_changed", input.comment, actorUserId, timestamp, { previousAssigneeUserId: incident.assigneeUserId, assigneeUserId: input.assigneeUserId });
  return { ...incident, ...(input.assigneeUserId ? { assigneeUserId: input.assigneeUserId } : { assigneeUserId: undefined }), updatedAt: timestamp, timeline: [...incident.timeline, entry] };
}

export function commentOnIncident(incident: Incident, input: IncidentCommentRequest, actorUserId: string, clock: Clock): Incident {
  const timestamp = clock.now().toISOString();
  return { ...incident, updatedAt: timestamp, timeline: [...incident.timeline, timeline(incident.id, "comment", input.message, actorUserId, timestamp)] };
}

export function linkIncidentEvidence(incident: Incident, input: IncidentEvidenceLinkRequest, actorUserId: string, clock: Clock): Incident {
  if (incident.evidence.some((item) => item.kind === input.kind && item.resourceId === input.resourceId)) throw conflict("Evidence is already linked to this incident.");
  const timestamp = clock.now().toISOString();
  const evidence: IncidentEvidence = { id: randomUUID(), incidentId: incident.id, ...input, linkedByUserId: actorUserId, linkedAt: timestamp };
  const entry = timeline(incident.id, "evidence_linked", input.rationale, actorUserId, timestamp, { evidenceId: evidence.id, kind: evidence.kind, resourceId: evidence.resourceId });
  return { ...incident, evidence: [...incident.evidence, evidence], timeline: [...incident.timeline, entry], updatedAt: timestamp };
}

export function createIncidentTask(incident: Incident, input: IncidentTaskCreateRequest, actorUserId: string, clock: Clock): Incident {
  const timestamp = clock.now().toISOString();
  const task: IncidentTask = { id: randomUUID(), incidentId: incident.id, ...input, status: "todo", createdByUserId: actorUserId, createdAt: timestamp, updatedAt: timestamp };
  const entry = timeline(incident.id, "task_created", `Task created: ${task.title}`, actorUserId, timestamp, { taskId: task.id });
  return { ...incident, tasks: [...incident.tasks, task], timeline: [...incident.timeline, entry], updatedAt: timestamp };
}

export function updateIncidentTask(incident: Incident, taskId: string, input: IncidentTaskUpdateRequest, actorUserId: string, clock: Clock): Incident {
  const index = incident.tasks.findIndex((task) => task.id === taskId);
  if (index < 0) throw Object.assign(new Error("Incident task does not exist."), { statusCode: 404 });
  const timestamp = clock.now().toISOString();
  const current = incident.tasks[index]!;
  const updated: IncidentTask = {
    ...current,
    ...(input.status ? { status: input.status } : {}),
    ...(input.ownerUserId === null ? { ownerUserId: undefined } : input.ownerUserId ? { ownerUserId: input.ownerUserId } : {}),
    ...(input.dueAt === null ? { dueAt: undefined } : input.dueAt ? { dueAt: input.dueAt } : {}),
    updatedAt: timestamp,
  };
  const tasks = [...incident.tasks];
  tasks[index] = updated;
  const entry = timeline(incident.id, "task_updated", input.comment, actorUserId, timestamp, { taskId, previousStatus: current.status, status: updated.status });
  return { ...incident, tasks, timeline: [...incident.timeline, entry], updatedAt: timestamp };
}

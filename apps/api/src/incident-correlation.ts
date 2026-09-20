import { randomUUID } from "node:crypto";
import type { IncidentCandidate, IncidentCorrelationRequest, IncidentSeverity } from "@cascadia/contracts";
import type { CascadiaStore } from "./store.js";

const rank: Record<IncidentSeverity, number> = { low: 0, medium: 1, high: 2, critical: 3 };

export async function correlateIncidentCandidates(store: CascadiaStore, organizationId: string, input: IncidentCorrelationRequest): Promise<IncidentCandidate[]> {
  const [findings, events, incidents] = await Promise.all([
    store.listAnomalyFindings(organizationId), store.listSecurityEvents(organizationId), store.listIncidents(organizationId),
  ]);
  const alreadyLinked = new Set(incidents.flatMap((incident) => incident.evidence.filter((item) => item.kind === "anomaly_finding").map((item) => item.resourceId)));
  const eventById = new Map(events.map((event) => [event.id, event]));
  const eligible = findings.filter((finding) => finding.disposition !== "dismissed" && !alreadyLinked.has(finding.id) && eventById.has(finding.eventId));
  const parent = eligible.map((_finding, index) => index);
  const find = (index: number): number => parent[index] === index ? index : (parent[index] = find(parent[index]!));
  const union = (left: number, right: number): void => { const a = find(left); const b = find(right); if (a !== b) parent[b] = a; };
  const byAsset = new Map<string, number[]>();
  eligible.forEach((finding, index) => {
    for (const assetId of eventById.get(finding.eventId)!.assetExternalIds) byAsset.set(assetId, [...(byAsset.get(assetId) ?? []), index]);
  });
  const windowMs = input.windowMinutes * 60_000;
  for (const indexes of byAsset.values()) {
    indexes.sort((a, b) => Date.parse(eventById.get(eligible[a]!.eventId)!.observedAt) - Date.parse(eventById.get(eligible[b]!.eventId)!.observedAt));
    for (let index = 1; index < indexes.length; index += 1) {
      const previous = indexes[index - 1]!; const current = indexes[index]!;
      if (Date.parse(eventById.get(eligible[current]!.eventId)!.observedAt) - Date.parse(eventById.get(eligible[previous]!.eventId)!.observedAt) <= windowMs) union(previous, current);
    }
  }
  const groups = new Map<number, number[]>();
  eligible.forEach((_finding, index) => groups.set(find(index), [...(groups.get(find(index)) ?? []), index]));
  return [...groups.values()].filter((indexes) => indexes.length >= input.minimumSignals).map((indexes) => {
    const groupedFindings = indexes.map((index) => eligible[index]!);
    const groupedEvents = groupedFindings.map((finding) => eventById.get(finding.eventId)!);
    const assetExternalIds = [...new Set(groupedEvents.flatMap((event) => event.assetExternalIds))].toSorted();
    const observed = groupedEvents.map((event) => event.observedAt).toSorted();
    const recommendedSeverity = groupedFindings.map((finding) => finding.level).reduce((highest, level) => rank[level] > rank[highest] ? level : highest);
    return {
      id: randomUUID(), organizationId, findingIds: groupedFindings.map((finding) => finding.id), eventIds: groupedEvents.map((event) => event.id), assetExternalIds,
      firstObservedAt: observed[0]!, lastObservedAt: observed.at(-1)!, recommendedSeverity,
      title: `Correlated ${recommendedSeverity} activity on ${assetExternalIds.join(", ")}`,
      rationale: `${groupedFindings.length} anomaly findings share monitored assets within a ${input.windowMinutes}-minute window. An analyst must confirm whether they represent one incident.`,
      requiresAnalystConfirmation: true, incidentCreated: false,
    };
  });
}

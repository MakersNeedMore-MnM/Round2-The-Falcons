import { randomUUID } from "node:crypto";
import {
  labAssetHeartbeatSchema,
  labScenarioDefinitionSchema,
  labScenarioSchema,
  labSimulationStatusSchema,
  type LabScenario,
  type LabScenarioDefinition,
  type LabSimulationStatus,
  type SecurityEventIngestRequest,
} from "@cascadia/contracts";
import { correlateIncidentCandidates } from "./incident-correlation.js";
import { createIncident } from "./incident-service.js";
import { evaluateNewTelemetry } from "./detection-engine.js";
import { analyzeAttackPaths } from "./risk-engine.js";
import { simulateResponses } from "./response-engine.js";
import type { CascadiaStore } from "./store.js";

type LabSimulationRecord = LabSimulationStatus & { timer?: NodeJS.Timeout; nextEvent: number };

const definitions: readonly LabScenarioDefinition[] = [
  { id: "credential_abuse", name: "Credential abuse chain", description: "A bounded sequence of synthetic authentication and access signals.", eventCount: 3, safety: "synthetic_events_only" },
  { id: "ot_protocol_anomaly", name: "OT protocol anomaly", description: "Synthetic protocol telemetry for a monitored operational asset.", eventCount: 3, safety: "synthetic_events_only" },
  { id: "data_access_spike", name: "Data access spike", description: "Synthetic abnormal data-access signals without touching the selected asset.", eventCount: 3, safety: "synthetic_events_only" },
  { id: "normal_baseline", name: "Normal baseline activity", description: "Benign telemetry that matches routine activity and should create no finding or incident.", eventCount: 3, safety: "synthetic_events_only" },
];

const eventTemplates: Record<LabScenario, Array<Pick<SecurityEventIngestRequest, "source" | "eventType" | "severity">>> = {
  credential_abuse: [
    { source: "siem", eventType: "lab_authentication_burst", severity: "high" },
    { source: "edr", eventType: "lab_credential_access_signal", severity: "high" },
    { source: "edr", eventType: "lab_lateral_movement_signal", severity: "critical" },
  ],
  ot_protocol_anomaly: [
    { source: "siem", eventType: "lab_protocol_sequence_deviation", severity: "high" },
    { source: "edr", eventType: "lab_unusual_write_request", severity: "high" },
    { source: "siem", eventType: "lab_safety_interlock_test", severity: "critical" },
  ],
  data_access_spike: [
    { source: "siem", eventType: "lab_record_access_spike", severity: "high" },
    { source: "edr", eventType: "lab_archive_enumeration_signal", severity: "high" },
    { source: "siem", eventType: "lab_bulk_read_signal", severity: "critical" },
  ],
  normal_baseline: [
    { source: "siem", eventType: "successful_authentication", severity: "low" },
    { source: "siem", eventType: "successful_authentication", severity: "low" },
    { source: "siem", eventType: "successful_authentication", severity: "low" },
  ],
};

function priorityFor(severity: "low" | "medium" | "high" | "critical"): "p1" | "p2" | "p3" | "p4" {
  return severity === "critical" ? "p1" : severity === "high" ? "p2" : severity === "medium" ? "p3" : "p4";
}

export class LabSimulationService {
  private readonly simulations = new Map<string, LabSimulationRecord>();

  constructor(private readonly store: CascadiaStore) {}

  listScenarios(): LabScenarioDefinition[] {
    return definitions.map((definition) => labScenarioDefinitionSchema.parse(definition));
  }

  async start(organizationId: string, assetId: string, scenario: LabScenario, actorUserId: string): Promise<LabSimulationStatus> {
    const parsedScenario = labScenarioSchema.parse(scenario);
    const asset = (await this.store.listAssets(organizationId)).find((candidate) => candidate.id === assetId);
    if (!asset) throw Object.assign(new Error("Lab asset does not exist in this organization."), { statusCode: 404 });
    if (asset.metadata.lab !== true && asset.metadata.demo !== true) throw Object.assign(new Error("Only assets explicitly marked for the lab may be simulated."), { statusCode: 422 });
    const active = [...this.simulations.values()].find((simulation) => simulation.organizationId === organizationId && simulation.status === "running");
    if (active) throw Object.assign(new Error("A lab simulation is already running for this organization."), { statusCode: 409 });
    if (!(await this.store.getActiveDetectionModel(organizationId))) throw Object.assign(new Error("Train an active detection model before starting a lab simulation."), { statusCode: 409 });

    const startedAt = new Date().toISOString();
    const simulation: LabSimulationRecord = {
      id: randomUUID(), organizationId, assetId, scenario: parsedScenario, status: "running",
      executionAuthorized: false, humanApprovalRequired: true, syntheticOnly: true, startedAt,
      emittedEvents: 0, findingsCreated: 0, incidentsCreated: 0, eventIds: [], findingIds: [], incidentIds: [], responseScenarioId: undefined, nextEvent: 0,
    };
    this.simulations.set(simulation.id, simulation);
    await this.tick(simulation, actorUserId);
    if (simulation.status === "running") simulation.timer = setInterval(() => void this.tick(simulation, actorUserId), 800);
    return this.snapshot(simulation);
  }

  stop(organizationId: string, simulationId: string): LabSimulationStatus {
    const simulation = this.get(organizationId, simulationId);
    if (simulation.timer) clearInterval(simulation.timer);
    if (simulation.status === "running") {
      simulation.status = "stopped";
      simulation.stoppedAt = new Date().toISOString();
    }
    return this.snapshot(simulation);
  }

  status(organizationId: string, simulationId: string): LabSimulationStatus {
    return this.snapshot(this.get(organizationId, simulationId));
  }

  latestStatus(organizationId: string, assetId: string): LabSimulationStatus | undefined {
    const simulation = [...this.simulations.values()].filter((candidate) => candidate.organizationId === organizationId && candidate.assetId === assetId).toSorted((left, right) => right.startedAt.localeCompare(left.startedAt))[0];
    return simulation ? this.snapshot(simulation) : undefined;
  }

  heartbeat(assetId: string, activeSimulation?: LabSimulationStatus) {
    return labAssetHeartbeatSchema.parse({
      assetId,
      status: activeSimulation?.assetId === assetId && activeSimulation.status === "running" ? "simulation_active" : activeSimulation?.assetId === assetId && activeSimulation.emittedEvents > 0 ? "observed" : "lab_ready",
      source: "synthetic",
      syntheticOnly: true,
      executionAuthorized: false,
      observedAt: new Date().toISOString(),
    });
  }

  async close(): Promise<void> {
    for (const simulation of this.simulations.values()) if (simulation.timer) clearInterval(simulation.timer);
  }

  private get(organizationId: string, simulationId: string): LabSimulationRecord {
    const simulation = this.simulations.get(simulationId);
    if (!simulation || simulation.organizationId !== organizationId) throw Object.assign(new Error("Lab simulation does not exist."), { statusCode: 404 });
    return simulation;
  }

  private snapshot(simulation: LabSimulationRecord): LabSimulationStatus {
    const { timer: _timer, nextEvent: _nextEvent, ...status } = simulation;
    return labSimulationStatusSchema.parse(status);
  }

  private async tick(simulation: LabSimulationRecord, actorUserId: string): Promise<void> {
    if (simulation.status !== "running") return;
    const template = eventTemplates[simulation.scenario][simulation.nextEvent];
    if (!template) {
      simulation.status = "completed";
      simulation.stoppedAt = new Date().toISOString();
      if (simulation.timer) clearInterval(simulation.timer);
      return;
    }
    try {
      const asset = (await this.store.listAssets(simulation.organizationId)).find((candidate) => candidate.id === simulation.assetId);
      if (!asset) throw new Error("Selected lab asset no longer exists.");
      const sourceEventId = `lab-${simulation.id}-${simulation.nextEvent + 1}`;
      const result = await this.store.ingestSecurityEvent(simulation.organizationId, {
        source: template.source, sourceEventId, eventType: template.eventType, severity: template.severity,
        observedAt: new Date().toISOString(), assetExternalIds: [asset.externalId, `lab-sensor-${asset.externalId}`],
        record: { synthetic: true, labSimulationId: simulation.id, scenario: simulation.scenario, sequence: simulation.nextEvent + 1 },
      });
      if (!result.duplicate) {
        simulation.emittedEvents += 1;
        simulation.eventIds.push(result.event.id);
        simulation.lastEventId = result.event.id;
      }
      simulation.nextEvent += 1;
      const evaluated = await evaluateNewTelemetry(this.store, simulation.organizationId);
      const newFindings = evaluated.findings.filter((finding) => simulation.eventIds.includes(finding.eventId));
      simulation.findingsCreated += newFindings.length;
      for (const finding of newFindings) {
        if (!simulation.findingIds.includes(finding.id)) simulation.findingIds.push(finding.id);
        simulation.lastFindingId = finding.id;
      }
      if (!simulation.incidentIds.length) {
        const candidates = await correlateIncidentCandidates(this.store, simulation.organizationId, { windowMinutes: 60, minimumSignals: 2 });
        const candidate = candidates.find((entry) => entry.findingIds.some((id) => simulation.findingIds.includes(id)));
        if (candidate) {
          const created = await createIncident(this.store, simulation.organizationId, {
            idempotencyKey: `lab-simulation-${simulation.id}`,
            title: `Lab simulation: ${candidate.title}`,
            summary: `${candidate.rationale} This case contains synthetic evidence only and requires analyst confirmation.`,
            severity: candidate.recommendedSeverity,
            priority: priorityFor(candidate.recommendedSeverity),
            tags: ["lab", "synthetic", simulation.scenario],
            evidence: [
              ...candidate.eventIds.map((resourceId) => ({ kind: "security_event" as const, resourceId, rationale: "Synthetic lab event emitted by the bounded simulation." })),
              ...candidate.findingIds.map((resourceId) => ({ kind: "anomaly_finding" as const, resourceId, rationale: "Finding generated by the existing explainable detection pipeline." })),
            ],
          }, actorUserId);
          if (created.created) {
            simulation.incidentsCreated += 1;
            simulation.incidentIds.push(created.incident.id);
            const analysis = await analyzeAttackPaths(this.store, simulation.organizationId, { entryAssetIds: [simulation.assetId], maxDepth: 4 }, actorUserId);
            const assets = await this.store.listAssets(simulation.organizationId);
            const entryAssetIds = new Set(analysis.entryAssetIds);
            const projected = new Map<string, { assetId: string; assetName: string; riskScore: number; riskLevel: "low" | "medium" | "high" | "critical"; pathAssetIds: string[]; targetServiceIds: string[]; reasons: string[] }>();
            for (const path of analysis.paths) {
              for (const assetId of path.assetIds) {
                if (entryAssetIds.has(assetId)) continue;
                const asset = assets.find((candidate) => candidate.id === assetId);
                if (!asset) continue;
                const existing = projected.get(assetId);
                const reasons = path.factors.filter((factor) => factor.contribution > 0).map((factor) => factor.explanation);
                if (!existing || path.riskScore > existing.riskScore) projected.set(assetId, {
                  assetId, assetName: asset.name, riskScore: path.riskScore, riskLevel: path.riskLevel,
                  pathAssetIds: path.assetIds, targetServiceIds: path.targetServiceIds, reasons: reasons.length ? reasons : ["Reachable through the modeled asset dependency path."],
                });
              }
            }
            simulation.projectedRiskAssets = [...projected.values()].toSorted((left, right) => right.riskScore - left.riskScore).slice(0, 20);
            const responseScenario = await simulateResponses(this.store, simulation.organizationId, {
              analysisId: analysis.id,
              incidentId: created.incident.id,
              candidates: [{
                title: "Isolate lab endpoint",
                actionType: "isolate_asset",
                targetAssetIds: [simulation.assetId],
                targetDependencyIds: [],
                reversible: true,
                rollbackPlan: "Restore the lab endpoint connection after analyst validation.",
                rationale: "Contain the synthetic activity while preserving the rest of the lab environment.",
              }],
            }, actorUserId);
            simulation.responseScenarioId = responseScenario.id;
          }
        }
      }
      if (simulation.nextEvent >= eventTemplates[simulation.scenario].length) {
        simulation.status = "completed";
        simulation.stoppedAt = new Date().toISOString();
        if (simulation.timer) clearInterval(simulation.timer);
      }
    } catch (error) {
      simulation.status = "failed";
      simulation.stoppedAt = new Date().toISOString();
      simulation.lastError = error instanceof Error ? error.message.slice(0, 500) : "Lab simulation failed.";
      if (simulation.timer) clearInterval(simulation.timer);
    }
  }
}

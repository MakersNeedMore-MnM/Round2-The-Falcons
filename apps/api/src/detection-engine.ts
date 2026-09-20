import { randomUUID } from "node:crypto";
import {
  detectionModelTrainingRequestSchema,
  type AnomalyEvaluationResult,
  type AnomalyFactor,
  type AnomalyFinding,
  type DetectionModel,
  type DetectionModelTrainingRequest,
  type SecurityEvent,
} from "@cascadia/contracts";
import { systemClock, type CascadiaStore, type Clock } from "./store.js";

const severityScore: Record<SecurityEvent["severity"], number> = { informational: 5, low: 15, medium: 35, high: 70, critical: 100 };

function median(values: number[]): number {
  const sorted = values.toSorted((a, b) => a - b);
  const middle = Math.floor(sorted.length / 2);
  return sorted.length % 2 === 0 ? ((sorted[middle - 1] ?? 0) + (sorted[middle] ?? 0)) / 2 : (sorted[middle] ?? 0);
}

function increment(record: Record<string, number>, key: string): void { record[key] = (Object.hasOwn(record, key) ? record[key]! : 0) + 1; }
function hourBucket(timestamp: string): string { return `${timestamp.slice(0, 13)}:00:00Z`; }
function clampScore(value: number): number { return Math.max(0, Math.min(100, Math.round(value))); }

export async function trainDetectionModel(
  store: CascadiaStore,
  organizationId: string,
  rawInput: DetectionModelTrainingRequest,
  actorUserId: string,
  clock: Clock = systemClock,
): Promise<DetectionModel> {
  const input = detectionModelTrainingRequestSchema.parse(rawInput);
  const trainedAt = clock.now().toISOString();
  const from = new Date(clock.now().getTime() - input.lookbackDays * 86_400_000).toISOString();
  const events = (await store.listSecurityEvents(organizationId)).filter((event) => event.observedAt >= from && event.observedAt <= trainedAt);
  if (events.length < input.minimumEvents) throw Object.assign(new Error(`At least ${input.minimumEvents} real telemetry events are required; ${events.length} are available in the training window.`), { statusCode: 422 });

  const eventTypeCounts: Record<string, number> = Object.create(null) as Record<string, number>;
  const severityCounts = { informational: 0, low: 0, medium: 0, high: 0, critical: 0 };
  const sourceCounts = { siem: 0, edr: 0 };
  const assets = new Set<string>();
  const hourlyCounts: Record<string, number> = Object.create(null) as Record<string, number>;
  for (const event of events) {
    increment(eventTypeCounts, event.eventType);
    severityCounts[event.severity] += 1;
    sourceCounts[event.source] += 1;
    event.assetExternalIds.forEach((assetId) => assets.add(assetId));
    increment(hourlyCounts, hourBucket(event.observedAt));
  }
  const volumes = Object.values(hourlyCounts);
  const volumeMedian = median(volumes);
  const volumeMad = median(volumes.map((volume) => Math.abs(volume - volumeMedian)));
  const priorModels = await store.listDetectionModels(organizationId);
  const model: DetectionModel = {
    id: randomUUID(), organizationId, version: (priorModels[0]?.version ?? 0) + 1, status: "active", algorithm: "explainable_frequency_baseline_v1",
    trainedAt, trainingWindow: { from, to: trainedAt }, trainingEventCount: events.length, findingThreshold: input.findingThreshold,
    features: { eventTypeCounts, severityCounts, sourceCounts, knownAssetExternalIds: [...assets].toSorted(), hourlyVolumeMedian: volumeMedian, hourlyVolumeMad: volumeMad },
    modelCard: {
      purpose: "Prioritize unusual normalized security events for human analyst review.",
      trainingDataProvenance: "organization_normalized_security_events",
      limitations: [
        "Scores are organization-specific and are not probabilities of compromise.",
        "Rare legitimate activity can score highly and repeated malicious activity can become less rare.",
        "The model uses event metadata and asset identifiers; it does not infer intent or execute response actions.",
      ],
      humanReviewRequired: true,
      autonomousResponseAuthorized: false,
    },
  };
  await store.saveDetectionModel(model, actorUserId);
  return model;
}

function factors(model: DetectionModel, event: SecurityEvent, evaluationHourCount: number): AnomalyFactor[] {
  const knownTypeCount = Object.hasOwn(model.features.eventTypeCounts, event.eventType) ? model.features.eventTypeCounts[event.eventType]! : 0;
  const rarity = clampScore(100 * (1 - knownTypeCount / model.trainingEventCount));
  const unknownAssets = event.assetExternalIds.filter((assetId) => !model.features.knownAssetExternalIds.includes(assetId));
  const novelty = event.assetExternalIds.length === 0 ? 0 : clampScore(100 * unknownAssets.length / event.assetExternalIds.length);
  const dispersion = Math.max(1, model.features.hourlyVolumeMad * 1.4826);
  const positiveDeviation = Math.max(0, evaluationHourCount - model.features.hourlyVolumeMedian);
  const volume = clampScore((positiveDeviation / (dispersion * 4)) * 100);
  return [
    { name: "event_type_rarity", score: rarity, explanation: knownTypeCount === 0 ? "Event type was not present in the training window." : "Score reflects how infrequently the event type appeared in the training window.", evidence: { eventType: event.eventType, trainingOccurrences: knownTypeCount, trainingEventCount: model.trainingEventCount } },
    { name: "severity", score: severityScore[event.severity], explanation: "Source-reported severity contributes context but cannot independently prove malicious activity.", evidence: { severity: event.severity } },
    { name: "asset_novelty", score: novelty, explanation: unknownAssets.length > 0 ? "One or more referenced assets were absent from the training window." : "Referenced assets were present in the training window or no asset was supplied.", evidence: { unknownAssetExternalIds: unknownAssets, referencedAssetCount: event.assetExternalIds.length } },
    { name: "volume_deviation", score: volume, explanation: "Score compares this evaluation hour's event volume with the training median and median absolute deviation.", evidence: { evaluationHourCount, trainingHourlyMedian: model.features.hourlyVolumeMedian, trainingHourlyMad: model.features.hourlyVolumeMad } },
  ];
}

function findingLevel(score: number): AnomalyFinding["level"] {
  if (score >= 90) return "critical";
  if (score >= 75) return "high";
  if (score >= 60) return "medium";
  return "low";
}

export async function evaluateNewTelemetry(
  store: CascadiaStore,
  organizationId: string,
  clock: Clock = systemClock,
): Promise<AnomalyEvaluationResult> {
  const model = await store.getActiveDetectionModel(organizationId);
  if (!model) throw Object.assign(new Error("No active detection model exists for this organization."), { statusCode: 409 });
  const evaluatedEventIds = new Set(await store.listEvaluatedEventIds(organizationId, model.id));
  const candidates = (await store.listSecurityEvents(organizationId)).filter((event) => event.ingestedAt > model.trainedAt && !evaluatedEventIds.has(event.id));
  if (candidates.length === 0) return { modelId: model.id, eventsEvaluated: 0, findingsCreated: 0, findings: [], noOp: true };
  const hourCounts: Record<string, number> = Object.create(null) as Record<string, number>;
  for (const event of candidates) increment(hourCounts, hourBucket(event.observedAt));
  const created: AnomalyFinding[] = [];
  for (const event of candidates) {
    const eventFactors = factors(model, event, hourCounts[hourBucket(event.observedAt)] ?? 1);
    const anomalyScore = clampScore(eventFactors[0]!.score * 0.35 + eventFactors[1]!.score * 0.25 + eventFactors[2]!.score * 0.25 + eventFactors[3]!.score * 0.15);
    if (anomalyScore < model.findingThreshold) continue;
    const finding: AnomalyFinding = { id: randomUUID(), organizationId, modelId: model.id, eventId: event.id, anomalyScore, level: findingLevel(anomalyScore), factors: eventFactors, disposition: "new", reviews: [], requiresHumanReview: true, responseAuthorized: false, createdAt: clock.now().toISOString() };
    const result = await store.saveAnomalyFinding(finding);
    if (result.created) created.push(result.finding);
  }
  await store.markEventsEvaluated(organizationId, model.id, candidates.map((event) => event.id));
  return { modelId: model.id, eventsEvaluated: candidates.length, findingsCreated: created.length, findings: created, noOp: false };
}

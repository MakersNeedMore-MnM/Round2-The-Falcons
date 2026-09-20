import { randomUUID } from "node:crypto";
import {
  attackPathAnalysisSchema,
  type Asset,
  type AssetDependency,
  type AttackPathAnalysis,
  type AttackPathAnalysisRequest,
  type CriticalService,
  type SecurityEvent,
  type Vulnerability,
} from "@cascadia/contracts";
import { NotFoundError, systemClock, type CascadiaStore, type Clock } from "./store.js";

const criticalityScore = { low: 25, medium: 50, high: 75, critical: 100 } as const;
const eventSeverityScore = { informational: 0, low: 5, medium: 12, high: 20, critical: 25 } as const;
const exploitScore = { none_known: 0, proof_of_concept: 10, active_exploitation: 25 } as const;

const mitreMappings = [
  { match: ["lateral_movement", "remote_services"], id: "T0886", name: "Remote Services", domain: "ics" as const },
  { match: ["remote_service_exploit", "exploitation_of_remote_services"], id: "T0866", name: "Exploitation of Remote Services", domain: "ics" as const },
  { match: ["user_execution", "phishing"], id: "T0863", name: "User Execution", domain: "ics" as const },
  { match: ["external_remote_access", "external_remote_services"], id: "T0822", name: "External Remote Services", domain: "ics" as const },
  { match: ["denial_of_service"], id: "T0814", name: "Denial of Service", domain: "ics" as const },
  { match: ["unauthorized_command"], id: "T1692.001", name: "Unauthorized Message: Command Message", domain: "ics" as const },
];

interface TraversedPath { assetIds: string[]; dependencyIds: string[]; }

export async function analyzeAttackPaths(
  store: CascadiaStore,
  organizationId: string,
  request: AttackPathAnalysisRequest,
  actorUserId: string,
  clock: Clock = systemClock,
): Promise<AttackPathAnalysis> {
  const [assets, dependencies, vulnerabilities, services, events] = await Promise.all([
    store.listAssets(organizationId), store.listDependencies(organizationId), store.listVulnerabilities(organizationId),
    store.listCriticalServices(organizationId), store.listSecurityEvents(organizationId),
  ]);
  const assetsById = new Map(assets.map((asset) => [asset.id, asset]));
  if (request.entryAssetIds.some((id) => !assetsById.has(id))) throw new NotFoundError("Every entry asset must exist in the organization.");

  const serviceTargets = new Map<string, string[]>();
  for (const service of services) {
    for (const assetId of service.assetIds) serviceTargets.set(assetId, [...(serviceTargets.get(assetId) ?? []), service.id]);
  }
  const adjacency = new Map<string, AssetDependency[]>();
  for (const edge of dependencies) adjacency.set(edge.sourceAssetId, [...(adjacency.get(edge.sourceAssetId) ?? []), edge]);

  const traversed: TraversedPath[] = [];
  const reachable = new Set<string>();
  let examinedPaths = 0;
  for (const entryAssetId of request.entryAssetIds) {
    const queue: TraversedPath[] = [{ assetIds: [entryAssetId], dependencyIds: [] }];
    while (queue.length > 0 && traversed.length < 100 && examinedPaths < 10_000) {
      const path = queue.shift()!;
      examinedPaths += 1;
      const current = path.assetIds.at(-1)!;
      reachable.add(current);
      if (serviceTargets.has(current)) traversed.push(path);
      if (path.dependencyIds.length >= request.maxDepth) continue;
      for (const edge of adjacency.get(current) ?? []) {
        if (path.assetIds.includes(edge.targetAssetId)) continue;
        queue.push({ assetIds: [...path.assetIds, edge.targetAssetId], dependencyIds: [...path.dependencyIds, edge.id] });
      }
    }
  }

  const paths = traversed.map((path) => scorePath(path, assetsById, dependencies, vulnerabilities, services, events, serviceTargets)).toSorted((a, b) => b.riskScore - a.riskScore || a.assetIds.length - b.assetIds.length);
  const reachableAssets = [...reachable].map((id) => assetsById.get(id)).filter((asset): asset is Asset => asset !== undefined);
  const affectedServices = services.filter((service) => service.assetIds.some((assetId) => reachable.has(assetId))).map((service) => service.id);
  const analysis = attackPathAnalysisSchema.parse({
    id: randomUUID(), organizationId, generatedAt: clock.now().toISOString(), entryAssetIds: request.entryAssetIds,
    maxDepth: request.maxDepth, paths,
    blastRadius: {
      reachableAssetIds: [...reachable], criticalServiceIds: affectedServices,
      assetsByCriticality: countCriticality(reachableAssets),
    },
    mitreTechniques: mapMitre(events, reachableAssets),
    limitations: [
      ...(vulnerabilities.length === 0 ? ["No vulnerability records were available; likelihood uses topology and observed events only."] : []),
      ...(events.length === 0 ? ["No normalized security events were available; no observed-threat contribution was applied."] : []),
      ...(services.length === 0 ? ["No critical services are configured, so attack paths cannot terminate at a service target."] : []),
      ...(examinedPaths >= 10_000 ? ["Graph traversal reached the 10,000-path safety limit; results may be incomplete."] : []),
      "Scores are deterministic decision support, not probabilities or autonomous response instructions.",
    ],
  });
  await store.saveRiskAnalysis(analysis, actorUserId);
  return analysis;
}

function scorePath(path: TraversedPath, assetsById: Map<string, Asset>, dependencies: AssetDependency[], vulnerabilities: Vulnerability[], services: CriticalService[], events: SecurityEvent[], serviceTargets: Map<string, string[]>) {
  const pathAssets = path.assetIds.map((id) => assetsById.get(id)).filter((asset): asset is Asset => asset !== undefined);
  const pathAssetIds = new Set(path.assetIds);
  const pathExternalIds = new Set(pathAssets.map((asset) => asset.externalId));
  const openVulnerabilities = vulnerabilities.filter((item) => item.status === "open" && pathAssetIds.has(item.assetId));
  const relevantEvents = events.filter((event) => event.assetExternalIds.some((id) => pathExternalIds.has(id)));
  const maxCvss = Math.max(0, ...openVulnerabilities.map((item) => item.cvssScore));
  const vulnerabilityContribution = Math.round(maxCvss * 3.5);
  const exploitContribution = Math.max(0, ...openVulnerabilities.map((item) => exploitScore[item.exploitStatus]));
  const eventContribution = Math.max(0, ...relevantEvents.map((event) => eventSeverityScore[event.severity]));
  const criticalEdgeContribution = path.dependencyIds.some((id) => dependencies.find((edge) => edge.id === id)?.critical) ? 10 : 0;
  const likelihoodScore = Math.min(100, 15 + vulnerabilityContribution + exploitContribution + eventContribution + criticalEdgeContribution);

  const targetServiceIds = serviceTargets.get(path.assetIds.at(-1)!) ?? [];
  const targetServices = services.filter((service) => targetServiceIds.includes(service.id));
  const serviceContribution = Math.round(Math.max(0, ...targetServices.map((service) => criticalityScore[service.criticality])) * 0.65);
  const assetContribution = Math.round(Math.max(0, ...pathAssets.map((asset) => criticalityScore[asset.criticality])) * 0.25);
  const downtimeContribution = targetServices.some((service) => service.maximumTolerableDowntimeMinutes <= 60) ? 10 : targetServices.some((service) => service.maximumTolerableDowntimeMinutes <= 240) ? 5 : 0;
  const impactScore = Math.min(100, serviceContribution + assetContribution + downtimeContribution);
  const riskScore = Math.round((likelihoodScore * impactScore) / 100);
  return {
    assetIds: path.assetIds, dependencyIds: path.dependencyIds, targetServiceIds, likelihoodScore, impactScore, riskScore,
    riskLevel: riskScore >= 75 ? "critical" as const : riskScore >= 50 ? "high" as const : riskScore >= 25 ? "medium" as const : "low" as const,
    factors: [
      { name: "topology", contribution: 15 + criticalEdgeContribution, explanation: criticalEdgeContribution ? "A reachable path includes a dependency marked critical." : "A reachable dependency path exists." },
      { name: "vulnerability", contribution: vulnerabilityContribution, explanation: maxCvss > 0 ? `Highest open CVSS score on the path is ${maxCvss}.` : "No open vulnerability record matched the path." },
      { name: "exploit evidence", contribution: exploitContribution, explanation: exploitContribution > 0 ? "An open vulnerability has known exploit evidence." : "No exploit evidence matched the path." },
      { name: "observed activity", contribution: eventContribution, explanation: relevantEvents.length > 0 ? `${relevantEvents.length} normalized event(s) matched path assets.` : "No normalized events matched path assets." },
      { name: "operational impact", contribution: impactScore, explanation: "Derived from service criticality, asset criticality, and tolerable downtime." },
    ],
  };
}

function countCriticality(assets: Asset[]) {
  const counts = { low: 0, medium: 0, high: 0, critical: 0 };
  for (const asset of assets) counts[asset.criticality] += 1;
  return counts;
}

function mapMitre(events: SecurityEvent[], reachableAssets: Asset[]) {
  const externalIds = new Set(reachableAssets.map((asset) => asset.externalId));
  return mitreMappings.flatMap((mapping) => {
    const evidence = events.filter((event) => event.assetExternalIds.some((id) => externalIds.has(id)) && mapping.match.includes(event.eventType.toLowerCase()));
    return evidence.length === 0 ? [] : [{ id: mapping.id, name: mapping.name, domain: mapping.domain, sourceUrl: `https://attack.mitre.org/techniques/${mapping.id.replace(".", "/")}/`, evidenceEventIds: evidence.map((event) => event.id) }];
  });
}

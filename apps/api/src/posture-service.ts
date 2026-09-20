import type { AnomalyFinding, Incident, Integration, SecurityPosture, Vulnerability } from "@cascadia/contracts";

export function buildSecurityPosture(input: { assets: Array<{ id: string; criticality: string }>; vulnerabilities: Vulnerability[]; findings: AnomalyFinding[]; incidents: Incident[]; integrations: Integration[]; services: unknown[]; now: string }): SecurityPosture {
  const openVulnerabilities = input.vulnerabilities.filter((item) => item.status === "open");
  const exploited = openVulnerabilities.filter((item) => item.exploitStatus === "active_exploitation");
  const findings = input.findings.filter((item) => item.disposition === "new" || item.disposition === "escalated");
  const highIncidents = input.incidents.filter((item) => !["resolved", "closed"].includes(item.status) && ["high", "critical"].includes(item.severity));
  const affectedAssets = new Set(openVulnerabilities.map((item) => item.assetId));
  const priorities = [
    ...exploited.map((item) => ({ id: `vulnerability:${item.id}`, title: item.title, rationale: `Actively exploited vulnerability (${item.externalId}) remains open.`, severity: "critical" as const, source: "vulnerability" as const })),
    ...highIncidents.map((item) => ({ id: `incident:${item.id}`, title: item.title, rationale: `Open ${item.severity} incident is in ${item.status}.`, severity: item.severity, source: "incident" as const })),
    ...findings.filter((item) => item.level === "high" || item.level === "critical").map((item) => ({ id: `finding:${item.id}`, title: "Review escalated detection finding", rationale: `Explainable anomaly score ${item.anomalyScore}/100 requires analyst disposition.`, severity: item.level, source: "finding" as const })),
  ];
  if (!input.integrations.some((item) => item.status === "active")) priorities.push({ id: "coverage:integrations", title: "Connect a live security data source", rationale: "No active signed SIEM, EDR, or TAXII integration is available for current evidence.", severity: "high", source: "coverage" as never });
  const penalties = exploited.length * 18 + openVulnerabilities.filter((item) => item.exploitStatus === "proof_of_concept").length * 7 + findings.filter((item) => item.level === "critical").length * 12 + findings.filter((item) => item.level === "high").length * 7 + highIncidents.filter((item) => item.severity === "critical").length * 14 + highIncidents.filter((item) => item.severity === "high").length * 8 + (input.integrations.some((item) => item.status === "active") ? 0 : 10);
  const score = Math.max(0, Math.min(100, 100 - penalties));
  const grade = score >= 90 ? "A" : score >= 75 ? "B" : score >= 60 ? "C" : score >= 40 ? "D" : "E";
  return { generatedAt: input.now, score, grade, coverage: { assets: input.assets.length, criticalAssets: input.assets.filter((item) => item.criticality === "critical").length, assetsWithOpenVulnerabilities: affectedAssets.size, activeIntegrations: input.integrations.filter((item) => item.status === "active").length, criticalServices: input.services.length }, exposure: { openVulnerabilities: openVulnerabilities.length, activelyExploitedVulnerabilities: exploited.length, unresolvedHighFindings: findings.filter((item) => item.level === "high" || item.level === "critical").length, openHighIncidents: highIncidents.length }, priorities: priorities.slice(0, 20), limitations: ["This is an explainable posture summary calculated from data stored in Cascadia; it does not infer missing telemetry.", "The score is decision support, not a compliance certification or authorization for response execution."] };
}

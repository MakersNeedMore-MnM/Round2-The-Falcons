import { randomUUID } from "node:crypto";
import {
  responseScenarioSchema,
  type Asset,
  type AssetDependency,
  type AttackPathAnalysis,
  type CriticalService,
  type ResponseCandidateRequest,
  type ResponseOption,
  type ResponsePolicy,
  type ResponseScenario,
  type ResponseSimulationRequest,
} from "@cascadia/contracts";
import { NotFoundError, systemClock, type CascadiaStore, type Clock } from "./store.js";

const criticalityScore = { low: 25, medium: 50, high: 75, critical: 100 } as const;

export async function simulateResponses(
  store: CascadiaStore,
  organizationId: string,
  request: ResponseSimulationRequest,
  actorUserId: string,
  clock: Clock = systemClock,
): Promise<ResponseScenario> {
  const [analysis, assets, dependencies, services, policies] = await Promise.all([
    store.getRiskAnalysis(organizationId, request.analysisId), store.listAssets(organizationId),
    store.listDependencies(organizationId), store.listCriticalServices(organizationId), store.listResponsePolicies(organizationId),
  ]);
  if (!analysis) throw new NotFoundError("Attack-path analysis does not exist in this organization.");
  const assetIds = new Set(assets.map((asset) => asset.id));
  const dependencyIds = new Set(dependencies.map((dependency) => dependency.id));
  for (const candidate of request.candidates) {
    if (candidate.targetAssetIds.some((id) => !assetIds.has(id)) || candidate.targetDependencyIds.some((id) => !dependencyIds.has(id))) {
      throw new NotFoundError("Every response target must exist in this organization.");
    }
  }

  const options = request.candidates.map((candidate) => scoreOption(candidate, analysis, assets, dependencies, services, policies));
  const eligible = options.filter((option) => option.eligible);
  const recommended = eligible.toSorted((left, right) => utility(right) - utility(left) || left.residualRiskScore - right.residualRiskScore)[0];
  const scenario = responseScenarioSchema.parse({
    id: randomUUID(), organizationId, analysisId: analysis.id, incidentId: request.incidentId,
    generatedAt: clock.now().toISOString(), options,
    ...(recommended ? { recommendedOptionId: recommended.id } : {}),
    status: recommended ? "awaiting_decision" : "blocked", decisions: [], executionAuthorized: false,
    limitations: [
      "Simulation uses the recorded dependency graph and does not execute infrastructure changes.",
      "Operational-impact values are deterministic estimates and require operator validation.",
      ...(policies.length === 0 ? ["No response policies are configured; every option is blocked."] : []),
    ],
  });
  await store.saveResponseScenario(scenario, actorUserId);
  return scenario;
}

function scoreOption(candidate: ResponseCandidateRequest, analysis: AttackPathAnalysis, assets: Asset[], dependencies: AssetDependency[], services: CriticalService[], policies: ResponsePolicy[]): ResponseOption {
  const targetAssets = new Set(candidate.targetAssetIds);
  const targetDependencies = new Set(candidate.targetDependencyIds);
  const blockedPaths = analysis.paths.filter((path) => path.assetIds.some((id) => targetAssets.has(id)) || path.dependencyIds.some((id) => targetDependencies.has(id)));
  const totalRisk = analysis.paths.reduce((sum, path) => sum + path.riskScore, 0);
  const blockedRisk = blockedPaths.reduce((sum, path) => sum + path.riskScore, 0);
  const securityBenefit = totalRisk === 0 ? 0 : Math.min(100, Math.round((blockedRisk / totalRisk) * 100));
  const unblockedPaths = analysis.paths.filter((path) => !blockedPaths.includes(path));
  const residualRiskScore = Math.max(0, ...unblockedPaths.map((path) => path.riskScore));
  const affectedServiceIds = [...new Set([
    ...blockedPaths.flatMap((path) => path.targetServiceIds),
    ...services.filter((service) => service.assetIds.some((id) => targetAssets.has(id))).map((service) => service.id),
  ])];
  const operationalImpact = estimateOperationalImpact(candidate, affectedServiceIds, services, blockedPaths.length, analysis.paths.length);
  const policy = policies.find((item) => item.actionType === candidate.actionType);
  const policyChecks = !policy
    ? [{ passed: false, reason: "No policy authorizes or permits this action type." }]
    : [
        { policyId: policy.id, passed: policy.mode !== "prohibited", reason: policy.mode === "prohibited" ? "Policy prohibits this action type." : `Policy mode is ${policy.mode}.` },
        { policyId: policy.id, passed: operationalImpact <= policy.maximumOperationalImpact, reason: `Operational impact ${operationalImpact} must not exceed policy limit ${policy.maximumOperationalImpact}.` },
        { policyId: policy.id, passed: !policy.requiresRollbackPlan || candidate.rollbackPlan.length > 0, reason: policy.requiresRollbackPlan ? "Policy requires a rollback plan." : "Policy does not require a rollback plan." },
      ];
  const eligible = policy !== undefined && policyChecks.every((check) => check.passed);
  return {
    ...candidate, id: randomUUID(), securityBenefit, operationalImpact, residualRiskScore, affectedServiceIds,
    policyChecks, eligible, approvalMode: policy?.mode === "operator_approved" ? "operator_approved" : "recommend_only",
    requiredApprovals: policy?.minimumApprovals ?? 1, allowedApprovalRoles: policy?.approvalRoles ?? [],
  };
}

function estimateOperationalImpact(candidate: ResponseCandidateRequest, affectedServiceIds: string[], services: CriticalService[], blockedPathCount: number, pathCount: number): number {
  if (candidate.actionType === "shutdown_service") return 100;
  const affected = services.filter((service) => affectedServiceIds.includes(service.id));
  const directServiceTarget = affected.some((service) => service.assetIds.some((assetId) => candidate.targetAssetIds.includes(assetId)));
  if (directServiceTarget) return candidate.reversible ? 80 : 100;
  const maximumCriticality = Math.max(0, ...affected.map((service) => criticalityScore[service.criticality]));
  const coverage = pathCount === 0 ? 0 : blockedPathCount / pathCount;
  const estimate = Math.round(maximumCriticality * coverage * (candidate.reversible ? 0.6 : 0.8));
  return Math.min(100, estimate);
}

function utility(option: ResponseOption): number {
  return option.securityBenefit * 0.7 - option.operationalImpact * 0.3;
}

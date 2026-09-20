import {
  anomalyFindingSchema, assetCreateRequestSchema, assetDependencyCreateRequestSchema, assetDependencySchema, assetEnrichmentUpdateSchema, assetSchema, assetImportRequestSchema, assetImportResultSchema, attackPathAnalysisSchema, auditEventSchema, criticalServiceSchema, criticalServiceUpsertRequestSchema, notificationDeliveryResultSchema, notificationRequestSchema,
  detectionModelSchema, incidentCandidateSchema, incidentSchema, integrationSchema, organizationSchema,
  responseScenarioSchema, responseDecisionRequestSchema, responsePolicySchema, responsePolicyUpsertRequestSchema, responseSimulationRequestSchema, securityEventSchema, taxiiSourceSchema, threatIndicatorSchema, vulnerabilitySchema, vulnerabilityUpsertRequestSchema, integrationCreateResultSchema, integrationDeliverySchema, integrationStatusUpdateSchema, incidentTaskUpdateRequestSchema,
  authenticatedSessionSchema,
  identityAccessSchema, identityUserSchema,
  systemStatusSchema,
  governanceAssuranceSchema, securityPostureSchema, executiveReportSchema, deploymentReadinessSchema, accessContextSchema, dataQualityReportSchema, mlGovernanceReportSchema, complianceReadinessSchema,
  auditBatchAnchorSchema,
  auditBatchVerificationSchema,
  decisionProofSchema,
  merkleProofSchema,
  proofAnchorResponseSchema,
  proofVerificationSchema,
  walletChallengeSchema,
  labAssetHeartbeatSchema, labScenarioDefinitionSchema, labSimulationStatusSchema,
  type AnomalyFinding, type AttackPathAnalysis, type Incident, type IncidentCreateRequest,
} from "@cascadia/contracts";
import { z, type ZodType } from "zod";

const TOKEN_KEY = "cascadia.access_token";
export const session = {
  get: () => sessionStorage.getItem(TOKEN_KEY),
  set: (token: string) => sessionStorage.setItem(TOKEN_KEY, token),
  clear: () => sessionStorage.removeItem(TOKEN_KEY),
};

let activeCsrfToken: string | undefined;

export class ApiError extends Error {
  constructor(message: string, readonly status: number) { super(message); }
}

async function request<T>(path: string, schema: ZodType<T>, init?: RequestInit): Promise<T> {
  const token = session.get();
  const method = (init?.method ?? "GET").toUpperCase();
  const response = await fetch(path, {
    ...init,
    credentials: "same-origin",
    headers: { ...(init?.body ? { "content-type": "application/json" } : {}), ...(token ? { authorization: `Bearer ${token}` } : {}), ...(!token && !["GET", "HEAD", "OPTIONS"].includes(method) && activeCsrfToken ? { "x-cascadia-csrf": activeCsrfToken } : {}), ...init?.headers },
  });
  const payload: unknown = await response.json().catch(() => ({}));
  if (!response.ok) {
    const value = payload as { error?: unknown };
    throw new ApiError(typeof value.error === "string" ? value.error : `Request failed with ${response.status}.`, response.status);
  }
  return schema.parse(payload);
}

const list = <T>(key: string, item: ZodType<T>) => z.object({ [key]: z.array(item) }) as ZodType<Record<string, T[]>>;
const boundariesSchema = z.object({ autonomousExecution: z.literal(false), untrustedSourceHandling: z.string(), recommendationApproval: z.string(), feedBehaviour: z.string(), mlFindingReview: z.string(), mlResponseExecution: z.literal(false) });

export const api = {
  authStatus: () => request("/api/auth/status", z.object({ oidcEnabled: z.boolean(), localBearerEnabled: z.boolean() })),
  authSession: async () => {
    const value = await request("/api/auth/session", authenticatedSessionSchema);
    activeCsrfToken = value.csrfToken;
    return value;
  },
  logout: async () => { await request("/api/auth/logout", z.unknown(), { method: "POST" }); activeCsrfToken = undefined; },
  identityUsers: async () => (await request("/api/v1/identity/users", list("users", identityAccessSchema))).users!,
  enrollIdentity: (input: { email: string; displayName: string; role: "platform_admin" | "organization_admin" | "incident_commander" | "security_analyst" | "ot_engineer" | "auditor" | "viewer" }) => request("/api/v1/identity/enrollments", identityUserSchema, { method: "POST", body: JSON.stringify(input) }),
  systemStatus: () => request("/api/v1/system/status", systemStatusSchema),
  governanceAssurance: () => request("/api/v1/governance/assurance", governanceAssuranceSchema),
  posture: () => request("/api/v1/posture", securityPostureSchema),
  dataQuality: () => request("/api/v1/data-quality", dataQualityReportSchema),
  mlGovernance: () => request("/api/v1/ml-governance", mlGovernanceReportSchema),
  complianceReadiness: () => request("/api/v1/compliance/readiness", complianceReadinessSchema),
  executiveReport: () => request("/api/v1/reports/executive", executiveReportSchema),
  deploymentReadiness: () => request("/api/v1/system/deployment-readiness", deploymentReadinessSchema),
  accessContext: () => request("/api/v1/access/context", accessContextSchema),
  auditEvents: async () => (await request("/api/v1/audit-events", list("events", auditEventSchema))).events!,
  auditAnchors: async () => (await request("/api/v1/audit-anchors", list("anchors", auditBatchAnchorSchema))).anchors!,
  runAuditAnchor: () => request("/api/v1/admin/audit-anchors/run", z.object({ anchor: auditBatchAnchorSchema.nullable() }), { method: "POST", body: "{}" }),
  verifyAuditAnchor: (batchId: number) => request(`/api/v1/audit-anchors/${batchId}/verify`, auditBatchVerificationSchema),
  auditEventProof: (eventId: string) => request(`/api/v1/audit-events/${eventId}/proof`, merkleProofSchema),
  organization: () => request("/api/v1/organizations/current", organizationSchema),
  boundaries: () => request("/api/v1/security-boundaries", boundariesSchema),
  assets: async () => (await request("/api/v1/assets", list("assets", assetSchema))).assets!,
  createAsset: (input: unknown) => request("/api/v1/assets", assetSchema, { method: "POST", body: JSON.stringify(assetCreateRequestSchema.parse(input)) }),
  importAssets: (input: unknown) => request("/api/v1/assets/import", assetImportResultSchema, { method: "POST", body: JSON.stringify(assetImportRequestSchema.parse(input)) }),
  enrichAsset: (assetId: string, input: unknown) => request(`/api/v1/assets/${assetId}/enrichment`, assetSchema, { method: "PATCH", body: JSON.stringify(assetEnrichmentUpdateSchema.parse(input)) }),
  deliverNotification: (input: unknown) => request("/api/v1/notifications/deliver", notificationDeliveryResultSchema, { method: "POST", body: JSON.stringify(notificationRequestSchema.parse(input)) }),
  dependencies: async () => (await request("/api/v1/dependencies", list("dependencies", assetDependencySchema))).dependencies!,
  createDependency: (input: unknown) => request("/api/v1/dependencies", assetDependencySchema, { method: "POST", body: JSON.stringify(assetDependencyCreateRequestSchema.parse(input)) }),
  events: async () => (await request("/api/v1/events", list("events", securityEventSchema))).events!,
  vulnerabilities: async () => (await request("/api/v1/vulnerabilities", list("vulnerabilities", vulnerabilitySchema))).vulnerabilities!,
  upsertVulnerability: (input: unknown) => request("/api/v1/vulnerabilities", vulnerabilitySchema, { method: "POST", body: JSON.stringify(vulnerabilityUpsertRequestSchema.parse(input)) }),
  services: async () => (await request("/api/v1/critical-services", list("services", criticalServiceSchema))).services!,
  upsertCriticalService: (input: unknown) => request("/api/v1/critical-services", criticalServiceSchema, { method: "POST", body: JSON.stringify(criticalServiceUpsertRequestSchema.parse(input)) }),
  findings: async () => (await request("/api/v1/detection/findings", list("findings", anomalyFindingSchema))).findings!,
  models: async () => (await request("/api/v1/detection/models", list("models", detectionModelSchema))).models!,
  incidents: async () => (await request("/api/v1/incidents", list("incidents", incidentSchema))).incidents!,
  analyses: async () => (await request("/api/v1/risk/analyses", list("analyses", attackPathAnalysisSchema))).analyses!,
  integrations: async () => (await request("/api/v1/integrations", list("integrations", integrationSchema))).integrations!,
  createIntegration: (input: unknown) => request("/api/v1/integrations", integrationCreateResultSchema, { method: "POST", body: JSON.stringify(input) }),
  setIntegrationStatus: (integrationId: string, status: "active" | "disabled") => request(`/api/v1/integrations/${integrationId}/status`, integrationSchema, { method: "PATCH", body: JSON.stringify(integrationStatusUpdateSchema.parse({ status })) }),
  rotateIntegrationSecret: (integrationId: string) => request(`/api/v1/integrations/${integrationId}/rotate-secret`, integrationCreateResultSchema, { method: "POST", body: "{}" }),
  integrationDeliveries: async (integrationId: string) => (await request(`/api/v1/integrations/${integrationId}/deliveries`, list("deliveries", integrationDeliverySchema))).deliveries!,
  indicators: async () => (await request("/api/v1/threat-indicators", list("indicators", threatIndicatorSchema))).indicators!,
  taxiiSources: async () => (await request("/api/v1/taxii-sources", list("sources", taxiiSourceSchema))).sources!,
  responses: async () => (await request("/api/v1/responses", list("scenarios", responseScenarioSchema))).scenarios!,
  responsePolicies: async () => (await request("/api/v1/response-policies", list("policies", responsePolicySchema))).policies!,
  upsertResponsePolicy: (input: unknown) => request("/api/v1/response-policies", responsePolicySchema, { method: "POST", body: JSON.stringify(responsePolicyUpsertRequestSchema.parse(input)) }),
  simulateResponse: (input: unknown) => request("/api/v1/responses/simulate", responseScenarioSchema, { method: "POST", body: JSON.stringify(responseSimulationRequestSchema.parse(input)) }),
  decideResponse: (scenarioId: string, input: { optionId: string; decision: "approve" | "reject"; comment: string }) => request(`/api/v1/responses/${scenarioId}/decisions`, responseScenarioSchema, { method: "POST", body: JSON.stringify(responseDecisionRequestSchema.parse(input)) }),
  decisionAnchor: (incidentId: string, decisionId: string) => request(`/api/v1/incidents/${incidentId}/decisions/${decisionId}/anchor`, proofAnchorResponseSchema, { method: "POST", body: "{}" }),
  submitDecisionAnchor: (incidentId: string, decisionId: string, signature: string) => request(`/api/v1/incidents/${incidentId}/decisions/${decisionId}/anchor/submit`, decisionProofSchema, { method: "POST", body: JSON.stringify({ signature }) }),
  decisionProof: (incidentId: string, decisionId: string) => request(`/api/v1/incidents/${incidentId}/decisions/${decisionId}/proof`, proofVerificationSchema),
  walletChallenge: (userId: string, walletAddress: string) => request("/api/v1/identity/wallet/challenge", walletChallengeSchema, { method: "POST", body: JSON.stringify({ userId, walletAddress }) }),
  walletVerify: (userId: string, walletAddress: string, signature: string) => request("/api/v1/identity/wallet/verify", identityUserSchema, { method: "POST", body: JSON.stringify({ userId, walletAddress, signature }) }),
  createIncident: (input: IncidentCreateRequest) => request("/api/v1/incidents", incidentSchema, { method: "POST", body: JSON.stringify(input) }),
  correlate: (windowMinutes = 60, minimumSignals = 2) => request("/api/v1/incidents/correlate", z.object({ candidates: z.array(incidentCandidateSchema), noOp: z.boolean(), incidentsCreated: z.literal(0), requiresAnalystConfirmation: z.literal(true) }), { method: "POST", body: JSON.stringify({ windowMinutes, minimumSignals }) }),
  transitionIncident: (incidentId: string, input: { status: Incident["status"]; comment: string; resolutionSummary?: string }) => request(`/api/v1/incidents/${incidentId}/status`, incidentSchema, { method: "POST", body: JSON.stringify(input) }),
  addIncidentTask: (incidentId: string, input: { title: string; description: string }) => request(`/api/v1/incidents/${incidentId}/tasks`, incidentSchema, { method: "POST", body: JSON.stringify(input) }),
  updateIncidentTask: (incidentId: string, taskId: string, input: { status: "todo" | "in_progress" | "blocked" | "done"; comment: string }) => request(`/api/v1/incidents/${incidentId}/tasks/${taskId}`, incidentSchema, { method: "PATCH", body: JSON.stringify(incidentTaskUpdateRequestSchema.parse(input)) }),
  reviewFinding: (findingId: string, input: { disposition: Exclude<AnomalyFinding["disposition"], "new">; comment: string }) => request(`/api/v1/detection/findings/${findingId}/disposition`, anomalyFindingSchema, { method: "POST", body: JSON.stringify(input) }),
  evaluate: () => request("/api/v1/detection/evaluate", z.object({ modelId: z.string().uuid(), eventsEvaluated: z.number(), findingsCreated: z.number(), findings: z.array(anomalyFindingSchema), noOp: z.boolean() }), { method: "POST", body: "{}" }),
  labScenarios: async () => (await request("/api/v1/lab/scenarios", z.object({ scenarios: z.array(labScenarioDefinitionSchema), syntheticOnly: z.literal(true), executionAuthorized: z.literal(false), humanApprovalRequired: z.literal(true) }))).scenarios,
  startLabSimulation: (input: { assetId: string; scenario: string }) => request("/api/v1/lab/simulations", labSimulationStatusSchema, { method: "POST", body: JSON.stringify(input) }),
  labSimulation: (simulationId: string) => request(`/api/v1/lab/simulations/${simulationId}`, labSimulationStatusSchema),
  stopLabSimulation: (simulationId: string) => request(`/api/v1/lab/simulations/${simulationId}/stop`, labSimulationStatusSchema, { method: "POST", body: "{}" }),
  labHeartbeat: (assetId: string) => request(`/api/v1/lab/assets/${assetId}/heartbeat`, labAssetHeartbeatSchema),
  analyze: (entryAssetIds: string[], maxDepth = 6): Promise<AttackPathAnalysis> => request("/api/v1/risk/attack-paths", attackPathAnalysisSchema, { method: "POST", body: JSON.stringify({ entryAssetIds, maxDepth }) }),
  syncTaxii: (sourceId: string) => request(`/api/v1/taxii-sources/${sourceId}/sync`, z.object({ id: z.string().uuid(), status: z.string() }).passthrough(), { method: "POST", body: "{}" }),
};

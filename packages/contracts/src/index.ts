import { z } from "zod";

export const utcIsoTimestamp = z
  .string()
  .datetime({ offset: true })
  .refine((value) => value.endsWith("Z"), "Timestamp must be UTC (Z suffix)");

export const organizationId = z.string().uuid();
export const userId = z.string().uuid();
export const agentId = z.string().uuid();
export const postId = z.string().uuid();

export const organizationSchema = z.object({
  id: organizationId,
  name: z.string().trim().min(2).max(120),
  sector: z.enum(["healthcare", "energy", "water", "transport", "emergency_services", "other"]),
  createdAt: utcIsoTimestamp,
});

export const organizationOnboardingRequestSchema = z.object({
  name: z.string().trim().min(2).max(120),
  sector: z.enum(["healthcare", "energy", "water", "transport", "emergency_services", "other"]),
  retention: z.object({
    rawEventsDays: z.number().int().min(1).max(3650),
    normalizedEventsDays: z.number().int().min(1).max(3650),
    auditEvidenceDays: z.number().int().min(365).max(36500),
  }),
});

export const userRoleSchema = z.enum([
  "platform_admin",
  "organization_admin",
  "incident_commander",
  "security_analyst",
  "ot_engineer",
  "auditor",
  "viewer",
]);

export const membershipSchema = z.object({
  organizationId,
  userId,
  role: userRoleSchema,
  createdAt: utcIsoTimestamp,
});

export const identityEnrollmentRequestSchema = z.object({
  email: z.string().trim().toLowerCase().pipe(z.email()),
  displayName: z.string().trim().min(2).max(120),
  role: userRoleSchema,
});

export const identityUserSchema = z.object({
  id: userId,
  email: z.email(),
  displayName: z.string().trim().min(2).max(120),
  status: z.enum(["active", "disabled"]),
  walletAddress: z.string().regex(/^0x[a-fA-F0-9]{40}$/).optional(),
  walletVerifiedAt: utcIsoTimestamp.optional(),
});

export const identityAccessSchema = z.object({
  user: identityUserSchema,
  organizationId,
  role: userRoleSchema,
});

export const authenticatedSessionSchema = z.object({
  authenticated: z.literal(true),
  user: identityUserSchema,
  organization: organizationSchema,
  role: userRoleSchema,
  mfaVerified: z.literal(true),
  expiresAt: utcIsoTimestamp,
  csrfToken: z.string().min(32),
});

export const systemStatusSchema = z.object({
  status: z.enum(["ready", "degraded"]),
  service: z.literal("cascadia-api"),
  version: z.string().min(1),
  uptimeSeconds: z.number().int().nonnegative(),
  database: z.object({ status: z.enum(["ready", "unavailable"]), latencyMs: z.number().int().nonnegative().optional() }),
  controls: z.object({ autonomousExecution: z.literal(false), realTelemetryOnly: z.literal(true), humanApprovalRequired: z.literal(true) }),
  checkedAt: utcIsoTimestamp,
});

export const governanceAssuranceSchema = z.object({
  generatedAt: utcIsoTimestamp,
  retention: z.object({ rawEventsDays: z.number().int().positive(), normalizedEventsDays: z.number().int().positive(), auditEvidenceDays: z.number().int().positive() }),
  evidence: z.object({ auditEvents: z.number().int().nonnegative(), oldestAuditEventAt: utcIsoTimestamp.optional(), latestAuditEventAt: utcIsoTimestamp.optional(), appendOnly: z.literal(true) }),
  controls: z.object({ tenantIsolation: z.literal(true), sourceDataUntrusted: z.literal(true), humanApprovalRequired: z.literal(true), autonomousExecution: z.literal(false) }),
});

export const securityPostureSchema = z.object({
  generatedAt: utcIsoTimestamp,
  score: z.number().int().min(0).max(100),
  grade: z.enum(["A", "B", "C", "D", "E"]),
  coverage: z.object({ assets: z.number().int().nonnegative(), criticalAssets: z.number().int().nonnegative(), assetsWithOpenVulnerabilities: z.number().int().nonnegative(), activeIntegrations: z.number().int().nonnegative(), criticalServices: z.number().int().nonnegative() }),
  exposure: z.object({ openVulnerabilities: z.number().int().nonnegative(), activelyExploitedVulnerabilities: z.number().int().nonnegative(), unresolvedHighFindings: z.number().int().nonnegative(), openHighIncidents: z.number().int().nonnegative() }),
  priorities: z.array(z.object({ id: z.string(), title: z.string().min(1).max(300), rationale: z.string().min(1).max(1000), severity: z.enum(["low", "medium", "high", "critical"]), source: z.enum(["vulnerability", "finding", "incident", "coverage"]) })).max(20),
  limitations: z.array(z.string()).min(1),
});

export const executiveReportSchema = z.object({
  reportType: z.literal("cascadia_executive_assurance_v1"),
  classification: z.literal("confidential"),
  generatedAt: utcIsoTimestamp,
  organization: z.object({ id: organizationId, name: z.string(), sector: organizationSchema.shape.sector }),
  governance: governanceAssuranceSchema,
  posture: securityPostureSchema,
  integritySha256: z.string().regex(/^[a-f0-9]{64}$/),
  limitations: z.array(z.string()).min(1),
});

export const deploymentReadinessSchema = z.object({
  environment: z.enum(["development", "production"]),
  readyForProduction: z.boolean(),
  checks: z.array(z.object({ id: z.string(), label: z.string(), status: z.enum(["ready", "action_required"]), detail: z.string() })),
  checkedAt: utcIsoTimestamp,
});

export const accessContextSchema = z.object({
  role: userRoleSchema,
  permissions: z.array(z.string().min(1)).min(1),
});

export const notificationRequestSchema = z.object({ title: z.string().trim().min(2).max(200), message: z.string().trim().min(2).max(4000) });
export const notificationDeliveryResultSchema = z.object({ delivered: z.literal(true), provider: z.enum(["generic", "slack", "teams"]), deliveredAt: utcIsoTimestamp });

export const dataQualitySourceSchema = z.object({
  sourceId: z.string().uuid(),
  name: z.string().min(1),
  provider: z.string().min(1),
  status: z.enum(["active", "disabled"]),
  dataType: z.enum(["security_events", "stix_bundle"]),
  mostRecentRecordAt: utcIsoTimestamp.optional(),
  freshness: z.enum(["current", "stale", "no_data", "disabled"]),
  recordsReceived: z.number().int().nonnegative(),
});

export const dataQualityReportSchema = z.object({
  generatedAt: utcIsoTimestamp,
  sources: z.array(dataQualitySourceSchema),
  summary: z.object({ activeSources: z.number().int().nonnegative(), currentSources: z.number().int().nonnegative(), staleSources: z.number().int().nonnegative(), sourcesWithNoData: z.number().int().nonnegative() }),
  limitations: z.array(z.string()).min(1),
});

export const mlGovernanceReportSchema = z.object({
  generatedAt: utcIsoTimestamp,
  models: z.array(z.object({ id: z.string().uuid(), version: z.number().int().positive(), status: z.enum(["active", "retired"]), algorithm: z.string(), trainedAt: utcIsoTimestamp, trainingEventCount: z.number().int().nonnegative(), findingThreshold: z.number().int().min(0).max(100), findingsCreated: z.number().int().nonnegative(), findingsReviewed: z.number().int().nonnegative(), dispositions: z.object({ acknowledged: z.number().int().nonnegative(), dismissed: z.number().int().nonnegative(), escalated: z.number().int().nonnegative(), new: z.number().int().nonnegative() }), humanReviewRequired: z.literal(true), autonomousResponseAuthorized: z.literal(false) })),
  limitations: z.array(z.string()).min(1),
});

export const complianceReadinessSchema = z.object({ generatedAt: utcIsoTimestamp, framework: z.literal("cascadia_core_controls_v1"), controls: z.array(z.object({ id: z.string(), name: z.string(), status: z.enum(["satisfied", "action_required"]), rationale: z.string(), evidenceCount: z.number().int().nonnegative() })), limitations: z.array(z.string()).min(1) });
export const assessorEvidenceBundleSchema = z.object({ bundleType: z.literal("cascadia_assessor_evidence_v1"), classification: z.literal("confidential"), generatedAt: utcIsoTimestamp, evidence: z.object({ auditEvents: z.number().int().nonnegative(), assets: z.number().int().nonnegative(), incidents: z.number().int().nonnegative(), activeIntegrations: z.number().int().nonnegative() }), integritySha256: z.string().regex(/^[a-f0-9]{64}$/), limitations: z.array(z.string()).min(1) });

export const dataClassificationSchema = z.enum([
  "public",
  "internal",
  "confidential",
  "restricted",
]);

export const retentionPolicySchema = z.object({
  rawEventsDays: z.number().int().min(1).max(3650),
  normalizedEventsDays: z.number().int().min(1).max(3650),
  auditEvidenceDays: z.number().int().min(365).max(36500),
  createdAt: utcIsoTimestamp,
});

export const criticalitySchema = z.enum(["low", "medium", "high", "critical"]);

export const assetSchema = z.object({
  id: z.string().uuid(),
  organizationId,
  name: z.string().trim().min(1).max(200),
  externalId: z.string().trim().min(1).max(200),
  assetType: z.enum(["endpoint", "server", "network", "database", "medical_device", "plc", "rtu", "iot", "cloud_service", "identity", "other"]),
  criticality: criticalitySchema,
  classification: dataClassificationSchema,
  ownerUserId: userId.optional(),
  hostname: z.string().trim().min(1).max(253).optional(),
  ipAddress: z.union([z.ipv4(), z.ipv6()]).optional(),
  metadata: z.record(z.string(), z.unknown()).default({}),
  updatedAt: utcIsoTimestamp,
  createdAt: utcIsoTimestamp,
});

export const assetCreateRequestSchema = assetSchema.omit({
  id: true,
  organizationId: true,
  createdAt: true,
  updatedAt: true,
});

export const assetDependencySchema = z.object({
  id: z.string().uuid(),
  organizationId,
  sourceAssetId: z.string().uuid(),
  targetAssetId: z.string().uuid(),
  relationship: z.enum(["communicates_with", "depends_on", "administers", "authenticates_via", "stores_data_in", "controls"]),
  protocol: z.string().trim().min(1).max(80).optional(),
  critical: z.boolean().default(false),
  createdAt: utcIsoTimestamp,
});

export const assetDependencyCreateRequestSchema = assetDependencySchema.omit({
  id: true,
  organizationId: true,
  createdAt: true,
});

export const assetImportRequestSchema = z.object({
  source: z.enum(["manual_csv", "cmdb_csv", "cyclonedx_json"]),
  content: z.string().min(1).max(5_000_000),
  defaultClassification: dataClassificationSchema.default("confidential"),
  defaultCriticality: criticalitySchema.default("medium"),
});

export const assetImportResultSchema = z.object({
  importId: z.string().uuid(),
  created: z.number().int().nonnegative(),
  updated: z.number().int().nonnegative(),
  rejected: z.array(z.object({ row: z.number().int().positive(), reason: z.string() })),
});

export const assetEnrichmentUpdateSchema = z.object({
  lifecycle: z.enum(["planned", "active", "maintenance", "retired"]),
  ownerTeam: z.string().trim().min(2).max(160).optional(),
  sbom: z.object({ format: z.enum(["cyclonedx", "spdx", "other"]), componentCount: z.number().int().nonnegative().max(1_000_000), sourceUrl: z.url().optional(), generatedAt: utcIsoTimestamp.optional() }).optional(),
});

export const securityEventSchema = z.object({
  id: z.string().uuid(),
  organizationId,
  source: z.enum(["siem", "edr"]),
  sourceEventId: z.string().trim().min(1).max(300),
  eventType: z.string().trim().min(1).max(200),
  severity: z.enum(["informational", "low", "medium", "high", "critical"]),
  observedAt: utcIsoTimestamp,
  ingestedAt: utcIsoTimestamp,
  assetExternalIds: z.array(z.string().trim().min(1).max(200)).max(100),
  record: z.record(z.string(), z.unknown()),
});

export const securityEventIngestRequestSchema = securityEventSchema.omit({
  id: true,
  organizationId: true,
  ingestedAt: true,
});

export const securityEventIngestResultSchema = z.object({
  event: securityEventSchema,
  duplicate: z.boolean(),
});

export const labScenarioSchema = z.enum(["credential_abuse", "ot_protocol_anomaly", "data_access_spike", "normal_baseline"]);

export const labScenarioDefinitionSchema = z.object({
  id: labScenarioSchema,
  name: z.string().min(1).max(120),
  description: z.string().min(1).max(1000),
  eventCount: z.number().int().positive().max(20),
  safety: z.literal("synthetic_events_only"),
});

export const labSimulationStartRequestSchema = z.object({
  assetId: z.string().uuid(),
  scenario: labScenarioSchema,
});

export const labSimulationStatusSchema = z.object({
  id: z.string().uuid(),
  organizationId,
  assetId: z.string().uuid(),
  scenario: labScenarioSchema,
  status: z.enum(["running", "stopped", "completed", "failed"]),
  executionAuthorized: z.literal(false),
  humanApprovalRequired: z.literal(true),
  syntheticOnly: z.literal(true),
  startedAt: utcIsoTimestamp,
  stoppedAt: utcIsoTimestamp.optional(),
  emittedEvents: z.number().int().nonnegative(),
  findingsCreated: z.number().int().nonnegative(),
  incidentsCreated: z.number().int().nonnegative(),
  eventIds: z.array(z.string().uuid()).max(20),
  findingIds: z.array(z.string().uuid()).max(20),
  incidentIds: z.array(z.string().uuid()).max(20),
  responseScenarioId: z.string().uuid().optional(),
  projectedRiskAssets: z.array(z.object({
    assetId: z.string().uuid(),
    assetName: z.string().min(1),
    riskScore: z.number().int().min(0).max(100),
    riskLevel: z.enum(["low", "medium", "high", "critical"]),
    pathAssetIds: z.array(z.string().uuid()).min(1),
    targetServiceIds: z.array(z.string().uuid()),
    reasons: z.array(z.string().min(1)).min(1),
  })).max(20).optional(),
  lastEventId: z.string().uuid().optional(),
  lastFindingId: z.string().uuid().optional(),
  lastError: z.string().max(500).optional(),
});

export const labAssetHeartbeatSchema = z.object({
  assetId: z.string().uuid(),
  status: z.enum(["lab_ready", "simulation_active", "observed"]),
  source: z.literal("synthetic"),
  syntheticOnly: z.literal(true),
  executionAuthorized: z.literal(false),
  observedAt: utcIsoTimestamp,
});

export const integrationProviderSchema = z.enum([
  "generic_webhook",
  "splunk",
  "microsoft_sentinel",
  "elastic_security",
  "crowdstrike",
  "microsoft_defender",
  "taxii",
]);

export const integrationDataTypeSchema = z.enum(["security_events", "stix_bundle"]);

const integrationBaseSchema = z.object({
  id: z.string().uuid(),
  organizationId,
  name: z.string().trim().min(2).max(120),
  provider: integrationProviderSchema,
  dataType: integrationDataTypeSchema,
  eventSource: z.enum(["siem", "edr"]).optional(),
  status: z.enum(["active", "disabled"]),
  secretVersion: z.number().int().positive(),
  lastDeliveryAt: utcIsoTimestamp.optional(),
  createdAt: utcIsoTimestamp,
  updatedAt: utcIsoTimestamp,
});

export const integrationSchema = integrationBaseSchema.superRefine((integration, context) => {
  if (integration.dataType === "security_events" && !integration.eventSource) {
    context.addIssue({ code: "custom", path: ["eventSource"], message: "Security-event integrations require an event source." });
  }
  if (integration.dataType === "stix_bundle" && integration.eventSource) {
    context.addIssue({ code: "custom", path: ["eventSource"], message: "STIX integrations do not use an event source." });
  }
});

export const integrationCreateRequestSchema = integrationBaseSchema.omit({
  id: true,
  organizationId: true,
  status: true,
  secretVersion: true,
  lastDeliveryAt: true,
  createdAt: true,
  updatedAt: true,
}).superRefine((integration, context) => {
  if (integration.dataType === "security_events" && !integration.eventSource) {
    context.addIssue({ code: "custom", path: ["eventSource"], message: "Security-event integrations require an event source." });
  }
  if (integration.dataType === "stix_bundle" && integration.eventSource) {
    context.addIssue({ code: "custom", path: ["eventSource"], message: "STIX integrations do not use an event source." });
  }
});

export const integrationCreateResultSchema = z.object({
  integration: integrationSchema,
  webhookSecret: z.string().min(32),
  signingAlgorithm: z.literal("hmac-sha256"),
});

export const integrationStatusUpdateSchema = z.object({ status: z.enum(["active", "disabled"]) });

export const liveSecurityEventSchema = securityEventIngestRequestSchema.omit({ source: true });

export const securityEventWebhookSchema = z.object({
  events: z.array(liveSecurityEventSchema).min(1).max(500),
});

export const stixIndicatorSchema = z.object({
  type: z.literal("indicator"),
  spec_version: z.literal("2.1"),
  id: z.string().regex(/^indicator--[0-9a-fA-F-]{36}$/),
  created: utcIsoTimestamp,
  modified: utcIsoTimestamp,
  name: z.string().trim().min(1).max(300).optional(),
  description: z.string().trim().max(8000).optional(),
  pattern: z.string().trim().min(1).max(8000),
  pattern_type: z.literal("stix"),
  valid_from: utcIsoTimestamp,
  valid_until: utcIsoTimestamp.optional(),
  confidence: z.number().int().min(0).max(100).optional(),
  labels: z.array(z.string().trim().min(1).max(100)).max(100).default([]),
  external_references: z.array(z.object({
    source_name: z.string().trim().min(1).max(200),
    url: z.url().optional(),
    external_id: z.string().trim().min(1).max(300).optional(),
  })).max(50).default([]),
}).refine((indicator) => !indicator.valid_until || indicator.valid_until > indicator.valid_from, {
  message: "Indicator validity must end after it begins.", path: ["valid_until"],
});

export const stixBundleSchema = z.object({
  type: z.literal("bundle"),
  id: z.string().regex(/^bundle--[0-9a-fA-F-]{36}$/),
  objects: z.array(stixIndicatorSchema).min(1).max(1000),
});

export const threatIndicatorSchema = z.object({
  id: z.string().uuid(),
  organizationId,
  integrationId: z.string().uuid(),
  stixId: z.string(),
  name: z.string(),
  description: z.string(),
  pattern: z.string(),
  confidence: z.number().int().min(0).max(100),
  labels: z.array(z.string()),
  sourceUrls: z.array(z.url()),
  validFrom: utcIsoTimestamp,
  validUntil: utcIsoTimestamp.optional(),
  modifiedAt: utcIsoTimestamp,
  ingestedAt: utcIsoTimestamp,
});

export const integrationDeliverySchema = z.object({
  id: z.string().uuid(),
  organizationId,
  integrationId: z.string().uuid(),
  externalDeliveryId: z.string().trim().min(1).max(200),
  payloadSha256: z.string().regex(/^[a-f0-9]{64}$/),
  eventCount: z.number().int().nonnegative(),
  indicatorCount: z.number().int().nonnegative(),
  receivedAt: utcIsoTimestamp,
});

export const integrationDeliveryResultSchema = z.object({
  delivery: integrationDeliverySchema,
  duplicate: z.boolean(),
});

export const detectionModelTrainingRequestSchema = z.object({
  lookbackDays: z.number().int().min(1).max(365).default(30),
  minimumEvents: z.number().int().min(20).max(100_000).default(50),
  findingThreshold: z.number().int().min(40).max(95).default(65),
});

export const detectionModelSchema = z.object({
  id: z.string().uuid(),
  organizationId,
  version: z.number().int().positive(),
  status: z.enum(["active", "retired"]),
  algorithm: z.literal("explainable_frequency_baseline_v1"),
  trainedAt: utcIsoTimestamp,
  trainingWindow: z.object({ from: utcIsoTimestamp, to: utcIsoTimestamp }),
  trainingEventCount: z.number().int().min(20),
  findingThreshold: z.number().int().min(40).max(95),
  features: z.object({
    eventTypeCounts: z.record(z.string(), z.number().int().nonnegative()),
    severityCounts: z.object({ informational: z.number().int().nonnegative(), low: z.number().int().nonnegative(), medium: z.number().int().nonnegative(), high: z.number().int().nonnegative(), critical: z.number().int().nonnegative() }),
    sourceCounts: z.object({ siem: z.number().int().nonnegative(), edr: z.number().int().nonnegative() }),
    knownAssetExternalIds: z.array(z.string()).max(100_000),
    hourlyVolumeMedian: z.number().nonnegative(),
    hourlyVolumeMad: z.number().nonnegative(),
  }),
  modelCard: z.object({
    purpose: z.string().min(1),
    trainingDataProvenance: z.literal("organization_normalized_security_events"),
    limitations: z.array(z.string().min(1)).min(1),
    humanReviewRequired: z.literal(true),
    autonomousResponseAuthorized: z.literal(false),
  }),
});

export const anomalyFactorSchema = z.object({
  name: z.enum(["event_type_rarity", "severity", "asset_novelty", "volume_deviation"]),
  score: z.number().int().min(0).max(100),
  explanation: z.string().min(1).max(1000),
  evidence: z.record(z.string(), z.unknown()),
});

export const anomalyFindingReviewSchema = z.object({
  id: z.string().uuid(),
  findingId: z.string().uuid(),
  analystUserId: userId,
  disposition: z.enum(["acknowledged", "dismissed", "escalated"]),
  comment: z.string().min(1).max(2000),
  reviewedAt: utcIsoTimestamp,
});

export const anomalyFindingSchema = z.object({
  id: z.string().uuid(),
  organizationId,
  modelId: z.string().uuid(),
  eventId: z.string().uuid(),
  anomalyScore: z.number().int().min(0).max(100),
  level: z.enum(["low", "medium", "high", "critical"]),
  factors: z.array(anomalyFactorSchema).length(4),
  disposition: z.enum(["new", "acknowledged", "dismissed", "escalated"]),
  reviews: z.array(anomalyFindingReviewSchema),
  requiresHumanReview: z.literal(true),
  responseAuthorized: z.literal(false),
  createdAt: utcIsoTimestamp,
});

export const anomalyEvaluationResultSchema = z.object({
  modelId: z.string().uuid(),
  eventsEvaluated: z.number().int().nonnegative(),
  findingsCreated: z.number().int().nonnegative(),
  findings: z.array(anomalyFindingSchema),
  noOp: z.boolean(),
});

export const anomalyFindingDispositionRequestSchema = z.object({
  disposition: z.enum(["acknowledged", "dismissed", "escalated"]),
  comment: z.string().trim().min(1).max(2000),
});

export const incidentStatusSchema = z.enum(["new", "triaged", "investigating", "contained", "recovering", "resolved", "closed"]);
export const incidentPrioritySchema = z.enum(["p1", "p2", "p3", "p4"]);
export const incidentSeveritySchema = z.enum(["low", "medium", "high", "critical"]);

export const incidentEvidenceKindSchema = z.enum(["security_event", "anomaly_finding", "risk_analysis", "response_scenario", "threat_indicator"]);

export const incidentEvidenceLinkRequestSchema = z.object({
  kind: incidentEvidenceKindSchema,
  resourceId: z.string().uuid(),
  rationale: z.string().trim().min(1).max(2000),
});

export const incidentEvidenceSchema = incidentEvidenceLinkRequestSchema.extend({
  id: z.string().uuid(),
  incidentId: z.string().uuid(),
  linkedByUserId: userId,
  linkedAt: utcIsoTimestamp,
});

export const incidentTimelineEntrySchema = z.object({
  id: z.string().uuid(),
  incidentId: z.string().uuid(),
  type: z.enum(["incident_created", "status_changed", "assignment_changed", "comment", "evidence_linked", "task_created", "task_updated"]),
  message: z.string().trim().min(1).max(4000),
  actorUserId: userId,
  occurredAt: utcIsoTimestamp,
  metadata: z.record(z.string(), z.unknown()).default({}),
});

export const incidentTaskSchema = z.object({
  id: z.string().uuid(),
  incidentId: z.string().uuid(),
  title: z.string().trim().min(2).max(300),
  description: z.string().trim().min(1).max(4000),
  status: z.enum(["todo", "in_progress", "blocked", "done"]),
  ownerUserId: userId.optional(),
  dueAt: utcIsoTimestamp.optional(),
  createdByUserId: userId,
  createdAt: utcIsoTimestamp,
  updatedAt: utcIsoTimestamp,
});

export const incidentTaskCreateRequestSchema = incidentTaskSchema.omit({ id: true, incidentId: true, status: true, createdByUserId: true, createdAt: true, updatedAt: true });
export const incidentTaskUpdateRequestSchema = z.object({
  status: z.enum(["todo", "in_progress", "blocked", "done"]).optional(),
  ownerUserId: userId.nullable().optional(),
  dueAt: utcIsoTimestamp.nullable().optional(),
  comment: z.string().trim().min(1).max(2000),
}).refine((input) => input.status !== undefined || input.ownerUserId !== undefined || input.dueAt !== undefined, { message: "A task update requires at least one changed field." });

export const incidentSchema = z.object({
  id: z.string().uuid(),
  organizationId,
  reference: z.string().regex(/^INC-[0-9]{8}-[A-F0-9]{8}$/),
  idempotencyKey: z.string().trim().min(8).max(200),
  title: z.string().trim().min(3).max(300),
  summary: z.string().trim().min(1).max(8000),
  severity: incidentSeveritySchema,
  priority: incidentPrioritySchema,
  status: incidentStatusSchema,
  assigneeUserId: userId.optional(),
  tags: z.array(z.string().trim().min(1).max(80)).max(30),
  acknowledgementDueAt: utcIsoTimestamp,
  resolutionDueAt: utcIsoTimestamp,
  acknowledgedAt: utcIsoTimestamp.optional(),
  resolvedAt: utcIsoTimestamp.optional(),
  closedAt: utcIsoTimestamp.optional(),
  resolutionSummary: z.string().max(8000).optional(),
  createdByUserId: userId,
  createdAt: utcIsoTimestamp,
  updatedAt: utcIsoTimestamp,
  evidence: z.array(incidentEvidenceSchema),
  timeline: z.array(incidentTimelineEntrySchema),
  tasks: z.array(incidentTaskSchema),
  autonomousActionsTaken: z.literal(false),
});

export const incidentCreateRequestSchema = z.object({
  idempotencyKey: z.string().trim().min(8).max(200),
  title: z.string().trim().min(3).max(300),
  summary: z.string().trim().min(1).max(8000),
  severity: incidentSeveritySchema,
  priority: incidentPrioritySchema,
  assigneeUserId: userId.optional(),
  tags: z.array(z.string().trim().min(1).max(80)).max(30).default([]),
  evidence: z.array(incidentEvidenceLinkRequestSchema).max(100).default([]),
});

export const incidentStatusUpdateRequestSchema = z.object({
  status: incidentStatusSchema,
  comment: z.string().trim().min(1).max(2000),
  resolutionSummary: z.string().trim().min(1).max(8000).optional(),
}).superRefine((input, context) => {
  if ((input.status === "resolved" || input.status === "closed") && !input.resolutionSummary) context.addIssue({ code: "custom", path: ["resolutionSummary"], message: "Resolved and closed incidents require a resolution summary." });
});

export const incidentAssignmentRequestSchema = z.object({ assigneeUserId: userId.nullable(), comment: z.string().trim().min(1).max(2000) });
export const incidentCommentRequestSchema = z.object({ message: z.string().trim().min(1).max(4000) });

export const incidentCorrelationRequestSchema = z.object({
  windowMinutes: z.number().int().min(5).max(1440).default(60),
  minimumSignals: z.number().int().min(2).max(100).default(2),
});

export const incidentCandidateSchema = z.object({
  id: z.string().uuid(),
  organizationId,
  findingIds: z.array(z.string().uuid()).min(2),
  eventIds: z.array(z.string().uuid()).min(2),
  assetExternalIds: z.array(z.string()),
  firstObservedAt: utcIsoTimestamp,
  lastObservedAt: utcIsoTimestamp,
  recommendedSeverity: incidentSeveritySchema,
  title: z.string().min(1).max(300),
  rationale: z.string().min(1).max(4000),
  requiresAnalystConfirmation: z.literal(true),
  incidentCreated: z.literal(false),
});

const taxiiApiRootUrlSchema = z.url().refine((value) => {
  const url = new URL(value);
  return url.protocol === "https:" && !url.username && !url.password && url.pathname.endsWith("/");
}, "TAXII API root must be an HTTPS URL ending in / without embedded credentials.");

export const taxiiAuthenticationSchema = z.discriminatedUnion("type", [
  z.object({ type: z.literal("none") }),
  z.object({ type: z.literal("basic"), username: z.string().min(1).max(300), password: z.string().min(1).max(2000) }),
  z.object({ type: z.literal("bearer"), token: z.string().min(1).max(4000) }),
]);

export const taxiiSourceCreateRequestSchema = z.object({
  name: z.string().trim().min(2).max(120),
  integrationId: z.string().uuid(),
  apiRootUrl: taxiiApiRootUrlSchema,
  collectionId: z.string().regex(/^[A-Za-z0-9._~-]{1,200}$/),
  authentication: taxiiAuthenticationSchema,
});

export const taxiiSourceSchema = z.object({
  id: z.string().uuid(),
  organizationId,
  integrationId: z.string().uuid(),
  name: z.string().trim().min(2).max(120),
  apiRootUrl: taxiiApiRootUrlSchema,
  collectionId: z.string(),
  authenticationType: z.enum(["none", "basic", "bearer"]),
  status: z.enum(["active", "disabled"]),
  checkpointAddedAfter: utcIsoTimestamp.optional(),
  lastSyncAt: utcIsoTimestamp.optional(),
  autonomousSchedulingEnabled: z.literal(false),
  createdAt: utcIsoTimestamp,
  updatedAt: utcIsoTimestamp,
});

export const taxiiSourceStatusUpdateSchema = z.object({ status: z.enum(["active", "disabled"]) });

export const taxiiSyncAttemptSchema = z.object({
  id: z.string().uuid(),
  jobId: z.string().uuid(),
  pageNumber: z.number().int().positive(),
  attemptNumber: z.number().int().min(1).max(3),
  status: z.enum(["succeeded", "failed"]),
  httpStatus: z.number().int().min(100).max(599).optional(),
  errorCode: z.string().max(120).optional(),
  startedAt: utcIsoTimestamp,
  completedAt: utcIsoTimestamp,
});

export const taxiiSyncJobSchema = z.object({
  id: z.string().uuid(),
  organizationId,
  sourceId: z.string().uuid(),
  status: z.enum(["running", "succeeded", "failed"]),
  requestedByUserId: userId,
  startedAt: utcIsoTimestamp,
  completedAt: utcIsoTimestamp.optional(),
  checkpointBefore: utcIsoTimestamp.optional(),
  checkpointAfter: utcIsoTimestamp.optional(),
  pagesFetched: z.number().int().nonnegative(),
  objectsReceived: z.number().int().nonnegative(),
  indicatorsAccepted: z.number().int().nonnegative(),
  errorCode: z.string().max(120).optional(),
  errorMessage: z.string().max(1000).optional(),
  attempts: z.array(taxiiSyncAttemptSchema),
});

export const taxiiEnvelopeSchema = z.object({
  more: z.boolean().default(false),
  next: z.string().min(1).max(2000).optional(),
  objects: z.array(z.unknown()).max(1000).default([]),
}).refine((envelope) => !envelope.more || Boolean(envelope.next), {
  message: "A paginated TAXII envelope requires a next token.", path: ["next"],
});

export const vulnerabilitySchema = z.object({
  id: z.string().uuid(),
  organizationId,
  assetId: z.string().uuid(),
  externalId: z.string().trim().min(1).max(200),
  title: z.string().trim().min(1).max(300),
  cvssScore: z.number().min(0).max(10),
  exploitStatus: z.enum(["none_known", "proof_of_concept", "active_exploitation"]),
  status: z.enum(["open", "mitigated", "accepted"]),
  sourceUrls: z.array(z.url()).min(1).max(20),
  firstSeenAt: utcIsoTimestamp,
  updatedAt: utcIsoTimestamp,
});

export const vulnerabilityUpsertRequestSchema = vulnerabilitySchema.omit({
  id: true,
  organizationId: true,
  firstSeenAt: true,
  updatedAt: true,
});

export const criticalServiceSchema = z.object({
  id: z.string().uuid(),
  organizationId,
  name: z.string().trim().min(2).max(200),
  description: z.string().trim().min(1).max(2000),
  criticality: criticalitySchema,
  recoveryTimeMinutes: z.number().int().positive().max(525_600),
  maximumTolerableDowntimeMinutes: z.number().int().positive().max(525_600),
  assetIds: z.array(z.string().uuid()).min(1).max(500).refine((ids) => new Set(ids).size === ids.length, "Asset IDs must be unique."),
  createdAt: utcIsoTimestamp,
  updatedAt: utcIsoTimestamp,
});

export const criticalServiceUpsertRequestSchema = criticalServiceSchema.omit({
  id: true,
  organizationId: true,
  createdAt: true,
  updatedAt: true,
}).refine(
  (service) => service.recoveryTimeMinutes <= service.maximumTolerableDowntimeMinutes,
  { message: "Recovery time must not exceed maximum tolerable downtime.", path: ["recoveryTimeMinutes"] },
);

export const mitreTechniqueSchema = z.object({
  id: z.string().regex(/^T\d{4}(?:\.\d{3})?$/),
  name: z.string().min(1),
  domain: z.enum(["ics", "enterprise"]),
  sourceUrl: z.url(),
  evidenceEventIds: z.array(z.string().uuid()),
});

export const riskFactorSchema = z.object({
  name: z.string().min(1),
  contribution: z.number().min(0).max(100),
  explanation: z.string().min(1),
});

export const attackPathSchema = z.object({
  assetIds: z.array(z.string().uuid()).min(1),
  dependencyIds: z.array(z.string().uuid()),
  targetServiceIds: z.array(z.string().uuid()).min(1),
  likelihoodScore: z.number().int().min(0).max(100),
  impactScore: z.number().int().min(0).max(100),
  riskScore: z.number().int().min(0).max(100),
  riskLevel: z.enum(["low", "medium", "high", "critical"]),
  factors: z.array(riskFactorSchema),
});

export const attackPathAnalysisRequestSchema = z.object({
  entryAssetIds: z.array(z.string().uuid()).min(1).max(50).refine((ids) => new Set(ids).size === ids.length, "Entry asset IDs must be unique."),
  maxDepth: z.number().int().min(1).max(10).default(6),
});

export const attackPathAnalysisSchema = z.object({
  id: z.string().uuid(),
  organizationId,
  generatedAt: utcIsoTimestamp,
  entryAssetIds: z.array(z.string().uuid()).min(1),
  maxDepth: z.number().int().min(1).max(10),
  paths: z.array(attackPathSchema).max(100),
  blastRadius: z.object({
    reachableAssetIds: z.array(z.string().uuid()),
    criticalServiceIds: z.array(z.string().uuid()),
    assetsByCriticality: z.object({ low: z.number().int().nonnegative(), medium: z.number().int().nonnegative(), high: z.number().int().nonnegative(), critical: z.number().int().nonnegative() }),
  }),
  mitreTechniques: z.array(mitreTechniqueSchema),
  limitations: z.array(z.string()),
});

export const responseActionTypeSchema = z.enum([
  "isolate_asset",
  "segment_connection",
  "restrict_identity",
  "disable_remote_access",
  "block_indicator",
  "shutdown_service",
]);

export const responsePolicySchema = z.object({
  id: z.string().uuid(),
  organizationId,
  name: z.string().trim().min(2).max(200),
  actionType: responseActionTypeSchema,
  mode: z.enum(["prohibited", "recommend_only", "operator_approved"]),
  maximumOperationalImpact: z.number().int().min(0).max(100),
  minimumApprovals: z.number().int().min(1).max(5),
  approvalRoles: z.array(userRoleSchema).min(1),
  requiresRollbackPlan: z.boolean(),
  createdAt: utcIsoTimestamp,
  updatedAt: utcIsoTimestamp,
});

export const responsePolicyUpsertRequestSchema = responsePolicySchema.omit({
  id: true,
  organizationId: true,
  createdAt: true,
  updatedAt: true,
}).refine((policy) => policy.mode !== "operator_approved" || policy.minimumApprovals >= 1, {
  message: "Operator-approved actions require at least one approval.", path: ["minimumApprovals"],
});

export const responseCandidateRequestSchema = z.object({
  title: z.string().trim().min(2).max(200),
  actionType: responseActionTypeSchema,
  targetAssetIds: z.array(z.string().uuid()).max(100).default([]),
  targetDependencyIds: z.array(z.string().uuid()).max(100).default([]),
  reversible: z.boolean(),
  rollbackPlan: z.string().trim().max(4000),
  rationale: z.string().trim().min(1).max(4000),
}).refine((candidate) => candidate.targetAssetIds.length + candidate.targetDependencyIds.length > 0, {
  message: "A response candidate needs at least one target.", path: ["targetAssetIds"],
}).refine((candidate) => !candidate.reversible || candidate.rollbackPlan.length > 0, {
  message: "Reversible actions require a rollback plan.", path: ["rollbackPlan"],
});

export const responseSimulationRequestSchema = z.object({
  analysisId: z.string().uuid(),
  incidentId: z.string().uuid(),
  candidates: z.array(responseCandidateRequestSchema).min(1).max(20),
});

export const responseOptionSchema = responseCandidateRequestSchema.extend({
  id: z.string().uuid(),
  securityBenefit: z.number().int().min(0).max(100),
  operationalImpact: z.number().int().min(0).max(100),
  residualRiskScore: z.number().int().min(0).max(100),
  affectedServiceIds: z.array(z.string().uuid()),
  policyChecks: z.array(z.object({ policyId: z.string().uuid().optional(), passed: z.boolean(), reason: z.string().min(1) })),
  eligible: z.boolean(),
  approvalMode: z.enum(["recommend_only", "operator_approved"]),
  requiredApprovals: z.number().int().min(1).max(5),
  allowedApprovalRoles: z.array(userRoleSchema),
});

export const responseDecisionRecordSchema = z.object({
  id: z.string().uuid(),
  scenarioId: z.string().uuid(),
  optionId: z.string().uuid(),
  actorUserId: userId,
  actorRole: userRoleSchema,
  decision: z.enum(["approve", "reject"]),
  comment: z.string().trim().min(1).max(2000),
  decidedAt: utcIsoTimestamp,
});

export const responseDecisionRequestSchema = z.object({
  optionId: z.string().uuid(),
  decision: z.enum(["approve", "reject"]),
  comment: z.string().trim().min(1).max(2000),
});

export const responseScenarioSchema = z.object({
  id: z.string().uuid(),
  organizationId,
  analysisId: z.string().uuid(),
  incidentId: z.string().uuid(),
  generatedAt: utcIsoTimestamp,
  options: z.array(responseOptionSchema).min(1),
  recommendedOptionId: z.string().uuid().optional(),
  selectedOptionId: z.string().uuid().optional(),
  status: z.enum(["awaiting_decision", "awaiting_approval", "approved", "rejected", "blocked"]),
  decisions: z.array(responseDecisionRecordSchema),
  executionAuthorized: z.literal(false),
  limitations: z.array(z.string()),
});

export const actionRiskSchema = z.enum(["low", "medium", "high", "critical"]);

export const responseRecommendationSchema = z.object({
  id: z.string().uuid(),
  organizationId,
  incidentId: z.string().uuid(),
  action: z.string().trim().min(1).max(500),
  securityBenefit: z.number().min(0).max(100),
  operationalImpact: z.number().min(0).max(100),
  confidence: z.number().min(0).max(1),
  actionRisk: actionRiskSchema,
  rationale: z.string().trim().min(1).max(4000),
  evidenceUrls: z.array(z.url()).min(1).max(20),
  requiresHumanApproval: z.literal(true),
  createdAt: utcIsoTimestamp,
});

export const auditEventSchema = z.object({
  id: z.string().uuid(),
  organizationId,
  actorUserId: userId.optional(),
  eventType: z.string().regex(/^[a-z_]+(?:\.[a-z_]+)+$/),
  resourceType: z.string().trim().min(1).max(80),
  resourceId: z.string().trim().min(1).max(200),
  occurredAt: utcIsoTimestamp,
  metadata: z.record(z.string(), z.unknown()).default({}),
});

export const auditBatchAnchorSchema = z.object({
  id: z.number().int().positive(),
  organizationId,
  batchStartTime: utcIsoTimestamp,
  batchEndTime: utcIsoTimestamp,
  eventCount: z.number().int().positive(),
  chainBatchId: z.number().int().nonnegative().optional(),
  merkleRoot: z.string().regex(/^[a-f0-9]{64}$/),
  txHash: z.string().min(1).optional(),
  blockNumber: z.number().int().nonnegative().optional(),
  mstscanUrl: z.url().optional(),
  anchorStatus: z.enum(["pending", "confirmed", "failed"]),
  createdAt: utcIsoTimestamp,
  confirmedAt: utcIsoTimestamp.optional(),
});

export const merkleProofSchema = z.object({
  eventId: z.string().uuid(),
  leaf: z.string().regex(/^[a-f0-9]{64}$/),
  siblings: z.array(z.string().regex(/^[a-f0-9]{64}$/)),
  positions: z.array(z.enum(["left", "right"])),
  root: z.string().regex(/^[a-f0-9]{64}$/),
  batchId: z.number().int().positive(),
  statement: z.string().min(1),
});

export const auditBatchVerificationSchema = z.object({
  onChainRoot: z.string().regex(/^[a-f0-9]{64}$/),
  recomputedRoot: z.string().regex(/^[a-f0-9]{64}$/),
  match: z.boolean(),
  eventCount: z.number().int().nonnegative(),
});

export const decisionProofSchema = z.object({
  decisionId: z.string().uuid(),
  organizationId,
  evidenceHash: z.string().regex(/^[a-f0-9]{64}$/),
  approverWalletAddress: z.string().regex(/^0x[a-fA-F0-9]{40}$/),
  signature: z.string().regex(/^0x[0-9a-fA-F]+$/),
  txHash: z.string().min(1).optional(),
  contractAddress: z.string().regex(/^0x[a-fA-F0-9]{40}$/).optional(),
  blockNumber: z.number().int().nonnegative().optional(),
  mstscanUrl: z.url().optional(),
  anchorStatus: z.enum(["pending", "confirmed", "failed"]),
  createdAt: utcIsoTimestamp,
  confirmedAt: utcIsoTimestamp.optional(),
});

export const proofAnchorRequestSchema = z.object({});
export const proofAnchorResponseSchema = z.object({
  decisionId: z.string().uuid(),
  evidenceHash: z.string().regex(/^[a-f0-9]{64}$/),
  approverWalletAddress: z.string().regex(/^0x[a-fA-F0-9]{40}$/),
  challenge: z.string().min(1),
});

export const proofSubmitRequestSchema = z.object({ signature: z.string().regex(/^0x[0-9a-fA-F]+$/) });
export const proofVerificationSchema = z.object({
  decisionId: z.string().uuid(),
  onChainHash: z.string().regex(/^[a-f0-9]{64}$/),
  offChainHash: z.string().regex(/^[a-f0-9]{64}$/),
  match: z.boolean(),
  approverAddress: z.string().regex(/^0x[a-fA-F0-9]{40}$/),
  status: z.enum(["unanchored", "pending", "confirmed", "failed"]),
});

export const walletChallengeSchema = z.object({
  challenge: z.string().min(1),
  userId,
  walletAddress: z.string().regex(/^0x[a-fA-F0-9]{40}$/),
});

export const walletVerificationRequestSchema = z.object({
  walletAddress: z.string().regex(/^0x[a-fA-F0-9]{40}$/),
  signature: z.string().regex(/^0x[0-9a-fA-F]+$/),
});

export const agentInitRequestSchema = z.object({
  organizationId,
  client: z.enum(["ui", "evaluator"]),
  displayName: z.string().trim().min(2).max(80),
});

export const agentSchema = z.object({
  id: agentId,
  organizationId,
  client: z.enum(["ui", "evaluator"]),
  displayName: z.string(),
  createdAt: utcIsoTimestamp,
});

export const publishedPostSchema = z.object({
  id: postId,
  organizationId,
  agentId,
  topic: z.string().trim().min(1).max(200),
  rationale: z.string().trim().min(1).max(4000),
  sourceUrls: z.array(z.url()).min(1).max(20),
  publishedAt: utcIsoTimestamp,
});

export const agentFeedSchema = z.object({
  posts: z.array(publishedPostSchema),
});

export type Agent = z.infer<typeof agentSchema>;
export type AuthenticatedSession = z.infer<typeof authenticatedSessionSchema>;
export type IdentityEnrollmentRequest = z.infer<typeof identityEnrollmentRequestSchema>;
export type IdentityUser = z.infer<typeof identityUserSchema>;
export type IdentityAccess = z.infer<typeof identityAccessSchema>;
export type SystemStatus = z.infer<typeof systemStatusSchema>;
export type GovernanceAssurance = z.infer<typeof governanceAssuranceSchema>;
export type SecurityPosture = z.infer<typeof securityPostureSchema>;
export type ExecutiveReport = z.infer<typeof executiveReportSchema>;
export type DeploymentReadiness = z.infer<typeof deploymentReadinessSchema>;
export type AccessContext = z.infer<typeof accessContextSchema>;
export type AgentInitRequest = z.infer<typeof agentInitRequestSchema>;
export type Asset = z.infer<typeof assetSchema>;
export type AssetCreateRequest = z.infer<typeof assetCreateRequestSchema>;
export type AssetDependency = z.infer<typeof assetDependencySchema>;
export type AssetDependencyCreateRequest = z.infer<typeof assetDependencyCreateRequestSchema>;
export type AssetImportRequest = z.infer<typeof assetImportRequestSchema>;
export type AssetImportResult = z.infer<typeof assetImportResultSchema>;
export type AssetEnrichmentUpdate = z.infer<typeof assetEnrichmentUpdateSchema>;
export type AuditEvent = z.infer<typeof auditEventSchema>;
export type AuditBatchAnchor = z.infer<typeof auditBatchAnchorSchema>;
export type MerkleProof = z.infer<typeof merkleProofSchema>;
export type AuditBatchVerification = z.infer<typeof auditBatchVerificationSchema>;
export type DecisionProof = z.infer<typeof decisionProofSchema>;
export type ProofAnchorResponse = z.infer<typeof proofAnchorResponseSchema>;
export type ProofVerification = z.infer<typeof proofVerificationSchema>;
export type WalletChallenge = z.infer<typeof walletChallengeSchema>;
export type AttackPathAnalysis = z.infer<typeof attackPathAnalysisSchema>;
export type AttackPathAnalysisRequest = z.infer<typeof attackPathAnalysisRequestSchema>;
export type CriticalService = z.infer<typeof criticalServiceSchema>;
export type CriticalServiceUpsertRequest = z.infer<typeof criticalServiceUpsertRequestSchema>;
export type Organization = z.infer<typeof organizationSchema>;
export type OrganizationOnboardingRequest = z.infer<typeof organizationOnboardingRequestSchema>;
export type PublishedPost = z.infer<typeof publishedPostSchema>;
export type ResponseRecommendation = z.infer<typeof responseRecommendationSchema>;
export type RetentionPolicy = z.infer<typeof retentionPolicySchema>;
export type ResponseActionType = z.infer<typeof responseActionTypeSchema>;
export type ResponseCandidateRequest = z.infer<typeof responseCandidateRequestSchema>;
export type ResponseDecisionRecord = z.infer<typeof responseDecisionRecordSchema>;
export type ResponseDecisionRequest = z.infer<typeof responseDecisionRequestSchema>;
export type ResponsePolicy = z.infer<typeof responsePolicySchema>;
export type ResponsePolicyUpsertRequest = z.infer<typeof responsePolicyUpsertRequestSchema>;
export type ResponseOption = z.infer<typeof responseOptionSchema>;
export type ResponseScenario = z.infer<typeof responseScenarioSchema>;
export type ResponseSimulationRequest = z.infer<typeof responseSimulationRequestSchema>;
export type SecurityEvent = z.infer<typeof securityEventSchema>;
export type SecurityEventIngestRequest = z.infer<typeof securityEventIngestRequestSchema>;
export type LabScenario = z.infer<typeof labScenarioSchema>;
export type LabScenarioDefinition = z.infer<typeof labScenarioDefinitionSchema>;
export type LabSimulationStartRequest = z.infer<typeof labSimulationStartRequestSchema>;
export type LabSimulationStatus = z.infer<typeof labSimulationStatusSchema>;
export type LabAssetHeartbeat = z.infer<typeof labAssetHeartbeatSchema>;
export type Integration = z.infer<typeof integrationSchema>;
export type IntegrationCreateRequest = z.infer<typeof integrationCreateRequestSchema>;
export type IntegrationCreateResult = z.infer<typeof integrationCreateResultSchema>;
export type IntegrationDelivery = z.infer<typeof integrationDeliverySchema>;
export type IntegrationDeliveryResult = z.infer<typeof integrationDeliveryResultSchema>;
export type IntegrationStatusUpdate = z.infer<typeof integrationStatusUpdateSchema>;
export type LiveSecurityEvent = z.infer<typeof liveSecurityEventSchema>;
export type StixBundle = z.infer<typeof stixBundleSchema>;
export type StixIndicator = z.infer<typeof stixIndicatorSchema>;
export type ThreatIndicator = z.infer<typeof threatIndicatorSchema>;
export type AnomalyEvaluationResult = z.infer<typeof anomalyEvaluationResultSchema>;
export type AnomalyFactor = z.infer<typeof anomalyFactorSchema>;
export type AnomalyFinding = z.infer<typeof anomalyFindingSchema>;
export type AnomalyFindingDispositionRequest = z.infer<typeof anomalyFindingDispositionRequestSchema>;
export type AnomalyFindingReview = z.infer<typeof anomalyFindingReviewSchema>;
export type DetectionModel = z.infer<typeof detectionModelSchema>;
export type DetectionModelTrainingRequest = z.infer<typeof detectionModelTrainingRequestSchema>;
export type Incident = z.infer<typeof incidentSchema>;
export type IncidentEvidenceKind = z.infer<typeof incidentEvidenceKindSchema>;
export type IncidentPriority = z.infer<typeof incidentPrioritySchema>;
export type IncidentSeverity = z.infer<typeof incidentSeveritySchema>;
export type IncidentStatus = z.infer<typeof incidentStatusSchema>;
export type IncidentAssignmentRequest = z.infer<typeof incidentAssignmentRequestSchema>;
export type IncidentCandidate = z.infer<typeof incidentCandidateSchema>;
export type IncidentCommentRequest = z.infer<typeof incidentCommentRequestSchema>;
export type IncidentCorrelationRequest = z.infer<typeof incidentCorrelationRequestSchema>;
export type IncidentCreateRequest = z.infer<typeof incidentCreateRequestSchema>;
export type IncidentEvidence = z.infer<typeof incidentEvidenceSchema>;
export type IncidentEvidenceLinkRequest = z.infer<typeof incidentEvidenceLinkRequestSchema>;
export type IncidentStatusUpdateRequest = z.infer<typeof incidentStatusUpdateRequestSchema>;
export type IncidentTask = z.infer<typeof incidentTaskSchema>;
export type IncidentTaskCreateRequest = z.infer<typeof incidentTaskCreateRequestSchema>;
export type IncidentTaskUpdateRequest = z.infer<typeof incidentTaskUpdateRequestSchema>;
export type IncidentTimelineEntry = z.infer<typeof incidentTimelineEntrySchema>;
export type TaxiiAuthentication = z.infer<typeof taxiiAuthenticationSchema>;
export type TaxiiEnvelope = z.infer<typeof taxiiEnvelopeSchema>;
export type TaxiiSource = z.infer<typeof taxiiSourceSchema>;
export type TaxiiSourceCreateRequest = z.infer<typeof taxiiSourceCreateRequestSchema>;
export type TaxiiSourceStatusUpdate = z.infer<typeof taxiiSourceStatusUpdateSchema>;
export type TaxiiSyncAttempt = z.infer<typeof taxiiSyncAttemptSchema>;
export type TaxiiSyncJob = z.infer<typeof taxiiSyncJobSchema>;
export type UserRole = z.infer<typeof userRoleSchema>;
export type Vulnerability = z.infer<typeof vulnerabilitySchema>;
export type VulnerabilityUpsertRequest = z.infer<typeof vulnerabilityUpsertRequestSchema>;

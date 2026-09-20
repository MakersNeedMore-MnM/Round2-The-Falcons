import assert from "node:assert/strict";
import test from "node:test";
import { randomUUID } from "node:crypto";
import {
  criticalServiceUpsertRequestSchema,
  anomalyFindingSchema,
  integrationCreateRequestSchema,
  identityEnrollmentRequestSchema,
  authenticatedSessionSchema,
  systemStatusSchema,
  incidentCreateRequestSchema,
  incidentStatusUpdateRequestSchema,
  incidentTaskUpdateRequestSchema,
  responseCandidateRequestSchema,
  securityEventIngestRequestSchema,
  publishedPostSchema,
  responseRecommendationSchema,
  stixIndicatorSchema,
  taxiiEnvelopeSchema,
  taxiiSourceCreateRequestSchema,
  utcIsoTimestamp,
} from "./index.js";

test("identity enrollment normalizes verified email and restricts roles", () => {
  const result = identityEnrollmentRequestSchema.parse({ email: " Analyst@Example.COM ", displayName: "Shift Analyst", role: "security_analyst" });
  assert.equal(result.email, "analyst@example.com");
  assert.equal(identityEnrollmentRequestSchema.safeParse({ ...result, role: "superuser" }).success, false);
});

test("browser sessions require MFA, UTC expiry, and a CSRF secret", () => {
  const value = { authenticated: true, user: { id: randomUUID(), email: "analyst@example.com", displayName: "Shift Analyst", status: "active" }, organization: { id: randomUUID(), name: "Grid Operator", sector: "energy", createdAt: "2026-08-26T10:00:00Z" }, role: "security_analyst", mfaVerified: true, expiresAt: "2026-08-26T18:00:00Z", csrfToken: "a".repeat(32) };
  assert.equal(authenticatedSessionSchema.safeParse(value).success, true);
  assert.equal(authenticatedSessionSchema.safeParse({ ...value, mfaVerified: false }).success, false);
});

test("system status preserves operational safety invariants", () => {
  const value = { status: "ready", service: "cascadia-api", version: "0.1.0", uptimeSeconds: 42, database: { status: "ready", latencyMs: 3 }, controls: { autonomousExecution: false, realTelemetryOnly: true, humanApprovalRequired: true }, checkedAt: "2026-08-26T10:00:00Z" };
  assert.equal(systemStatusSchema.safeParse(value).success, true);
  assert.equal(systemStatusSchema.safeParse({ ...value, controls: { ...value.controls, autonomousExecution: true } }).success, false);
});

test("UTC timestamps require a Z suffix", () => {
  assert.equal(utcIsoTimestamp.safeParse("2026-08-25T10:00:00Z").success, true);
  assert.equal(utcIsoTimestamp.safeParse("2026-08-25T10:00:00+05:30").success, false);
});

test("published posts need rationale and source URLs", () => {
  const result = publishedPostSchema.safeParse({
    id: randomUUID(),
    organizationId: randomUUID(),
    agentId: randomUUID(),
    topic: "Untrusted threat-feed instruction",
    rationale: "Source content is stored as evidence, not treated as an instruction.",
    sourceUrls: ["https://example.com/advisory"],
    publishedAt: "2026-08-25T10:00:00Z",
  });
  assert.equal(result.success, true);
});

test("every recommendation requires human approval", () => {
  const result = responseRecommendationSchema.safeParse({
    id: randomUUID(),
    organizationId: randomUUID(),
    incidentId: randomUUID(),
    action: "Isolate endpoint",
    securityBenefit: 90,
    operationalImpact: 20,
    confidence: 0.8,
    actionRisk: "medium",
    rationale: "Blocks the identified route.",
    evidenceUrls: ["https://example.com/evidence"],
    requiresHumanApproval: false,
    createdAt: "2026-08-25T10:00:00Z",
  });
  assert.equal(result.success, false);
});

test("security events reject non-UTC source timestamps", () => {
  const result = securityEventIngestRequestSchema.safeParse({
    source: "siem",
    sourceEventId: "event-1",
    eventType: "authentication_failure",
    severity: "medium",
    observedAt: "2026-08-25T15:30:00+05:30",
    assetExternalIds: [],
    record: {},
  });
  assert.equal(result.success, false);
});

test("critical services reject recovery objectives beyond tolerable downtime", () => {
  const result = criticalServiceUpsertRequestSchema.safeParse({
    name: "Patient Monitoring",
    description: "Continuous bedside monitoring",
    criticality: "critical",
    recoveryTimeMinutes: 120,
    maximumTolerableDowntimeMinutes: 30,
    assetIds: [randomUUID()],
  });
  assert.equal(result.success, false);
});

test("reversible response candidates require a rollback plan", () => {
  const result = responseCandidateRequestSchema.safeParse({
    title: "Isolate endpoint",
    actionType: "isolate_asset",
    targetAssetIds: [randomUUID()],
    targetDependencyIds: [],
    reversible: true,
    rollbackPlan: "",
    rationale: "Breaks the attack path.",
  });
  assert.equal(result.success, false);
});

test("security-event integrations require a normalized event source", () => {
  assert.equal(integrationCreateRequestSchema.safeParse({ name: "Live SIEM", provider: "splunk", dataType: "security_events" }).success, false);
  assert.equal(integrationCreateRequestSchema.safeParse({ name: "Live SIEM", provider: "splunk", dataType: "security_events", eventSource: "siem" }).success, true);
  assert.equal(integrationCreateRequestSchema.safeParse({ name: "Threat feed", provider: "taxii", dataType: "stix_bundle", eventSource: "siem" }).success, false);
});

test("STIX indicators require version 2.1 and a valid UTC interval", () => {
  const base = { type: "indicator", spec_version: "2.1", id: `indicator--${randomUUID()}`, created: "2026-08-26T08:00:00Z", modified: "2026-08-26T09:00:00Z", pattern: "[domain-name:value = 'malicious.example']", pattern_type: "stix", valid_from: "2026-08-26T10:00:00Z", labels: [], external_references: [] };
  assert.equal(stixIndicatorSchema.safeParse(base).success, true);
  assert.equal(stixIndicatorSchema.safeParse({ ...base, spec_version: "2.0" }).success, false);
  assert.equal(stixIndicatorSchema.safeParse({ ...base, valid_until: "2026-08-26T09:00:00Z" }).success, false);
});

test("TAXII sources require credential-free HTTPS API roots", () => {
  const base = { name: "Sector feed", integrationId: randomUUID(), collectionId: "health-sector", authentication: { type: "none" } };
  assert.equal(taxiiSourceCreateRequestSchema.safeParse({ ...base, apiRootUrl: "https://taxii.example/api/" }).success, true);
  assert.equal(taxiiSourceCreateRequestSchema.safeParse({ ...base, apiRootUrl: "http://taxii.example/api/" }).success, false);
  assert.equal(taxiiSourceCreateRequestSchema.safeParse({ ...base, apiRootUrl: "https://user:secret@taxii.example/api/" }).success, false);
  assert.equal(taxiiSourceCreateRequestSchema.safeParse({ ...base, apiRootUrl: "https://taxii.example/api" }).success, false);
});

test("paginated TAXII envelopes require a next token", () => {
  assert.equal(taxiiEnvelopeSchema.safeParse({ objects: [], more: false }).success, true);
  assert.equal(taxiiEnvelopeSchema.safeParse({ objects: [], more: true }).success, false);
  assert.equal(taxiiEnvelopeSchema.safeParse({ objects: [], more: true, next: "cursor-2" }).success, true);
});

test("ML findings always require review and cannot authorize response", () => {
  const finding = { id: randomUUID(), organizationId: randomUUID(), modelId: randomUUID(), eventId: randomUUID(), anomalyScore: 90, level: "critical", factors: ["event_type_rarity", "severity", "asset_novelty", "volume_deviation"].map((name) => ({ name, score: 90, explanation: "Explainable factor.", evidence: {} })), disposition: "new", reviews: [], requiresHumanReview: false, responseAuthorized: true, createdAt: "2026-08-26T10:00:00Z" };
  assert.equal(anomalyFindingSchema.safeParse(finding).success, false);
  assert.equal(anomalyFindingSchema.safeParse({ ...finding, requiresHumanReview: true, responseAuthorized: false }).success, true);
});

test("incident contracts require durable idempotency and resolution evidence", () => {
  const base = { idempotencyKey: "durable-incident-1", title: "Confirmed access anomaly", summary: "Analyst-confirmed sequence.", severity: "high", priority: "p1" };
  assert.equal(incidentCreateRequestSchema.safeParse(base).success, true);
  assert.equal(incidentCreateRequestSchema.safeParse({ ...base, idempotencyKey: "short" }).success, false);
  assert.equal(incidentStatusUpdateRequestSchema.safeParse({ status: "resolved", comment: "Remediated" }).success, false);
  assert.equal(incidentStatusUpdateRequestSchema.safeParse({ status: "resolved", comment: "Remediated", resolutionSummary: "Credentials rotated and access verified." }).success, true);
  assert.equal(incidentTaskUpdateRequestSchema.safeParse({ comment: "No actual update" }).success, false);
});

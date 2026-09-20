import Fastify, { type FastifyInstance, type FastifyRequest } from "fastify";
import fastifyJwt from "@fastify/jwt";
import fastifyCookie from "@fastify/cookie";
import fastifyHelmet from "@fastify/helmet";
import fastifyRateLimit from "@fastify/rate-limit";
import fastifyStatic from "@fastify/static";
import { resolve } from "node:path";
import { createHash, randomUUID } from "node:crypto";
import {
  agentFeedSchema,
  agentInitRequestSchema,
  assetCreateRequestSchema,
  assetDependencyCreateRequestSchema,
  assetImportRequestSchema,
  assetEnrichmentUpdateSchema,
  attackPathAnalysisRequestSchema,
  criticalServiceUpsertRequestSchema,
  anomalyFindingDispositionRequestSchema,
  detectionModelTrainingRequestSchema,
  integrationCreateRequestSchema,
  integrationDeliveryResultSchema,
  integrationStatusUpdateSchema,
  notificationDeliveryResultSchema,
  notificationRequestSchema,
  dataQualityReportSchema,
  mlGovernanceReportSchema,
  complianceReadinessSchema,
  assessorEvidenceBundleSchema,
  authenticatedSessionSchema,
  identityEnrollmentRequestSchema,
  identityAccessSchema,
  systemStatusSchema,
  governanceAssuranceSchema,
  securityPostureSchema,
  executiveReportSchema,
  deploymentReadinessSchema,
  accessContextSchema,
  auditBatchAnchorSchema,
  auditBatchVerificationSchema,
  decisionProofSchema,
  merkleProofSchema,
  proofAnchorResponseSchema,
  proofSubmitRequestSchema,
  proofVerificationSchema,
  walletChallengeSchema,
  walletVerificationRequestSchema,
  incidentAssignmentRequestSchema,
  incidentCommentRequestSchema,
  incidentCorrelationRequestSchema,
  incidentCreateRequestSchema,
  incidentEvidenceLinkRequestSchema,
  incidentStatusUpdateRequestSchema,
  incidentTaskCreateRequestSchema,
  incidentTaskUpdateRequestSchema,
  labSimulationStartRequestSchema,
  labSimulationStatusSchema,
  labAssetHeartbeatSchema,
  organizationOnboardingRequestSchema,
  responseDecisionRequestSchema,
  responsePolicyUpsertRequestSchema,
  responseSimulationRequestSchema,
  securityEventIngestRequestSchema,
  securityEventIngestResultSchema,
  taxiiSourceCreateRequestSchema,
  taxiiSourceStatusUpdateSchema,
  vulnerabilityUpsertRequestSchema,
  type UserRole,
} from "@cascadia/contracts";
import { ZodError, z } from "zod";
import type { AppConfig } from "./config.js";
import { importAssets } from "./import-service.js";
import { correlateIncidentCandidates } from "./incident-correlation.js";
import { createIncident, validateIncidentEvidence } from "./incident-service.js";
import { evaluateNewTelemetry, trainDetectionModel } from "./detection-engine.js";
import { createIntegration, ingestSignedWebhook, rotateIntegrationSecret } from "./integration-service.js";
import { analyzeAttackPaths } from "./risk-engine.js";
import { simulateResponses } from "./response-engine.js";
import { createTaxiiSource, runTaxiiSync } from "./taxii-sync-service.js";
import { InMemoryCascadiaStore, type CascadiaStore } from "./store.js";
import { csrfCookieName, digest, OidcIdentityService, publicSession, sessionCookieName } from "./identity-service.js";
import { RuntimeMetrics, secureTokenMatches } from "./observability.js";
import { buildSecurityPosture } from "./posture-service.js";
import { createMstClient } from "./mst-client.js";
import { AuditAnchorService } from "./audit-anchor-service.js";
import { DecisionProofService } from "./decision-proof-service.js";
import { LabSimulationService } from "./lab-simulation-service.js";
import { getAddress, verifyMessage } from "ethers";

const principalSchema = z.object({
  sub: z.string().uuid(),
  organizationId: z.string().uuid(),
  role: z.enum([
    "platform_admin",
    "organization_admin",
    "incident_commander",
    "security_analyst",
    "ot_engineer",
    "auditor",
    "viewer",
  ]),
});

type Principal = z.infer<typeof principalSchema>;

declare module "@fastify/jwt" {
  interface FastifyJWT {
    user: Principal;
  }
}

declare module "fastify" {
  interface FastifyRequest {
    rawBody?: Buffer;
    identitySessionTokenHash?: string;
    identitySessionCsrfHash?: string;
    observabilityStartedAt?: bigint;
  }
}

function hasRole(role: UserRole, allowed: readonly UserRole[]): boolean {
  return allowed.includes(role);
}

function sameTenant(principal: Principal, organizationId: string): void {
  if (principal.organizationId !== organizationId && principal.role !== "platform_admin") {
    throw Object.assign(new Error("Cross-tenant access is denied."), { statusCode: 403 });
  }
}

export function buildApp(config: AppConfig, store: CascadiaStore = new InMemoryCascadiaStore()): FastifyInstance {
  const app = Fastify({
    logger: config.NODE_ENV === "test" ? false : { level: "info", redact: { paths: ["req.headers.authorization", "req.headers.cookie", "req.headers.x-cascadia-signature", "res.headers.set-cookie"], censor: "[REDACTED]" } },
    bodyLimit: 6_000_000,
    trustProxy: config.TRUST_PROXY_HOPS > 0 ? (_address: string, hop: number) => hop < config.TRUST_PROXY_HOPS : false,
  });
  app.removeContentTypeParser("application/json");
  app.addContentTypeParser("application/json", { parseAs: "buffer" }, (request, body, done) => {
    const rawBody = Buffer.isBuffer(body) ? body : Buffer.from(body);
    request.rawBody = rawBody;
    try { done(null, JSON.parse(rawBody.toString("utf8")) as unknown); }
    catch (error) { done(Object.assign(error as Error, { statusCode: 400 })); }
  });
  app.register(fastifyCookie);
  app.register(fastifyJwt, { secret: config.JWT_SECRET });
  app.register(fastifyHelmet, { global: true, contentSecurityPolicy: { directives: { defaultSrc: ["'self'"], scriptSrc: ["'self'"], styleSrc: ["'self'", "'unsafe-inline'"], imgSrc: ["'self'", "data:"], connectSrc: ["'self'"], fontSrc: ["'self'"], objectSrc: ["'none'"], frameAncestors: ["'none'"] } } });
  app.register(fastifyRateLimit, { global: true, max: config.REQUESTS_PER_MINUTE, timeWindow: "1 minute", ipv6Subnet: 64 });
  const integrationEncryptionKey = config.INTEGRATION_ENCRYPTION_KEY ?? config.JWT_SECRET;
  const runtimeMetrics = new RuntimeMetrics();
  const identity = new OidcIdentityService(config, store);
  const mst = config.MST_DEPLOYER_PRIVATE_KEY && config.MST_CONTRACT_ADDRESS ? createMstClient(config) : undefined;
  const auditAnchors = mst ? new AuditAnchorService(store, mst) : undefined;
  const decisionProofs = mst ? new DecisionProofService(store, mst) : undefined;
  const labSimulations = new LabSimulationService(store);
  const walletChallenges = new Map<string, { address: string; challenge: string; expiresAt: number }>();
  const cookieName = sessionCookieName(config);
  const secureCookies = config.NODE_ENV === "production";
  const cookieOptions = { path: "/", httpOnly: true, secure: secureCookies, sameSite: "strict" as const };
  const csrfCookieOptions = { path: "/", httpOnly: false, secure: secureCookies, sameSite: "strict" as const };

  app.addHook("onRequest", async (request) => { request.observabilityStartedAt = process.hrtime.bigint(); });
  app.addHook("onResponse", async (request, reply) => {
    const elapsed = request.observabilityStartedAt ? Number(process.hrtime.bigint() - request.observabilityStartedAt) / 1_000_000 : 0;
    runtimeMetrics.observe(request.method, request.routeOptions.url ?? "unmatched", reply.statusCode, elapsed);
  });

  async function authenticate(request: FastifyRequest): Promise<void> {
    if (request.headers.authorization) {
      await request.jwtVerify();
      request.user = principalSchema.parse(request.user);
      return;
    }
    const opaque = request.cookies[cookieName];
    const session = opaque ? await store.getIdentitySession(digest(opaque)) : undefined;
    if (!session) throw Object.assign(new Error("Authentication required."), { statusCode: 401 });
    request.user = principalSchema.parse({ sub: session.user.id, organizationId: session.organizationId, role: session.role });
    request.identitySessionTokenHash = session.tokenHash;
    request.identitySessionCsrfHash = session.csrfTokenHash;
    if (!["GET", "HEAD", "OPTIONS"].includes(request.method)) {
      const provided = request.headers["x-cascadia-csrf"];
      if (typeof provided !== "string" || digest(provided) !== session.csrfTokenHash) {
        throw Object.assign(new Error("CSRF validation failed."), { statusCode: 403 });
      }
    }
  }

  function requireRoles(allowed: readonly UserRole[]) {
    return async (request: FastifyRequest): Promise<void> => {
      await authenticate(request);
      if (!hasRole(request.user.role, allowed)) throw Object.assign(new Error("Insufficient role for this operation."), { statusCode: 403 });
    };
  }

  app.setErrorHandler((error, _request, reply) => {
    if (error instanceof ZodError) {
      return reply.status(400).send({ error: "ValidationError", details: error.issues });
    }
    const knownError = error as { statusCode?: unknown; message?: unknown };
    const status = typeof knownError.statusCode === "number" ? knownError.statusCode : 500;
    const message = typeof knownError.message === "string" ? knownError.message : "Request failed.";
    return reply.status(status).send({ error: status >= 500 ? "InternalServerError" : message });
  });

  app.get("/health", { config: { rateLimit: false } }, async () => ({ status: "ok", service: "cascadia-api" }));
  app.get("/health/live", { config: { rateLimit: false } }, async () => ({ status: "live", service: "cascadia-api", uptimeSeconds: Math.floor(process.uptime()) }));
  app.get("/health/ready", { config: { rateLimit: false } }, async (_request, reply) => {
    try { const database = await store.checkHealth(); return { status: "ready", service: "cascadia-api", database }; }
    catch { return reply.status(503).send({ status: "degraded", service: "cascadia-api", database: { status: "unavailable" } }); }
  });
  app.get("/metrics", { config: { rateLimit: false } }, async (request, reply) => {
    const provided = typeof request.headers["x-cascadia-observability"] === "string" ? request.headers["x-cascadia-observability"] : undefined;
    if (config.OBSERVABILITY_TOKEN && !secureTokenMatches(provided, config.OBSERVABILITY_TOKEN)) return reply.status(401).send({ error: "Authentication required." });
    return reply.type("text/plain; version=0.0.4; charset=utf-8").send(runtimeMetrics.render());
  });

  app.get("/api/auth/status", async () => ({ oidcEnabled: identity.enabled, localBearerEnabled: config.NODE_ENV !== "production" }));

  app.get("/api/auth/login", { config: { rateLimit: { max: 10, timeWindow: "1 minute" } } }, async (request, reply) => {
    const query = z.object({ returnTo: z.string().optional() }).parse(request.query);
    return reply.redirect((await identity.begin(query.returnTo)).href);
  });

  app.get("/api/auth/callback", async (request, reply) => {
    const result = await identity.complete(z.record(z.string(), z.unknown()).parse(request.query));
    reply.setCookie(cookieName, result.token, { ...cookieOptions, maxAge: config.SESSION_TTL_MINUTES * 60 });
    reply.setCookie(csrfCookieName, result.csrfToken, { ...csrfCookieOptions, maxAge: config.SESSION_TTL_MINUTES * 60 });
    return reply.redirect(new URL(result.returnTo, config.PUBLIC_APP_URL).href);
  });

  app.get("/api/auth/session", { preHandler: authenticate }, async (request) => {
    if (!request.identitySessionTokenHash) throw Object.assign(new Error("Browser session required."), { statusCode: 401 });
    const session = await store.getIdentitySession(request.identitySessionTokenHash);
    const organization = session ? await store.getOrganization(session.organizationId) : undefined;
    const csrfToken = request.cookies[csrfCookieName];
    if (!session || !organization || !csrfToken || digest(csrfToken) !== session.csrfTokenHash) throw Object.assign(new Error("Session is incomplete."), { statusCode: 401 });
    return authenticatedSessionSchema.parse(publicSession(session, organization, csrfToken));
  });

  app.post("/api/auth/logout", { preHandler: authenticate }, async (request, reply) => {
    if (request.identitySessionTokenHash) await store.revokeIdentitySession(request.identitySessionTokenHash, "user_logout");
    reply.clearCookie(cookieName, cookieOptions).clearCookie(csrfCookieName, csrfCookieOptions);
    return reply.status(204).send();
  });

  app.post("/api/v1/identity/enrollments", { preHandler: requireRoles(["platform_admin", "organization_admin"]) }, async (request, reply) => {
    const user = await store.enrollIdentityUser(request.user.organizationId, identityEnrollmentRequestSchema.parse(request.body), request.user.sub);
    return reply.status(201).send(user);
  });

  app.get("/api/v1/identity/users", { preHandler: requireRoles(["platform_admin", "organization_admin", "auditor"]) }, async (request) => ({
    users: (await store.listIdentityUsers(request.user.organizationId)).map((entry) => identityAccessSchema.parse(entry)),
  }));

  app.get("/api/v1/system/status", { preHandler: requireRoles(["platform_admin", "organization_admin", "incident_commander", "security_analyst", "ot_engineer", "auditor", "viewer"]) }, async () => {
    try {
      const database = await store.checkHealth();
      return systemStatusSchema.parse({ status: "ready", service: "cascadia-api", version: "0.1.0", uptimeSeconds: Math.floor(process.uptime()), database, controls: { autonomousExecution: false, realTelemetryOnly: true, humanApprovalRequired: true }, checkedAt: new Date().toISOString() });
    } catch {
      return systemStatusSchema.parse({ status: "degraded", service: "cascadia-api", version: "0.1.0", uptimeSeconds: Math.floor(process.uptime()), database: { status: "unavailable" }, controls: { autonomousExecution: false, realTelemetryOnly: true, humanApprovalRequired: true }, checkedAt: new Date().toISOString() });
    }
  });

  app.get("/api/v1/lab/scenarios", { preHandler: requireRoles(["organization_admin", "security_analyst", "incident_commander", "auditor", "viewer", "ot_engineer"]) }, async () => ({
    scenarios: labSimulations.listScenarios(),
    syntheticOnly: true,
    executionAuthorized: false,
    humanApprovalRequired: true,
  }));

  app.post("/api/v1/lab/simulations", { preHandler: requireRoles(["organization_admin", "security_analyst", "incident_commander"]) }, async (request, reply) => {
    const input = labSimulationStartRequestSchema.parse(request.body);
    const status = labSimulationStatusSchema.parse(await labSimulations.start(request.user.organizationId, input.assetId, input.scenario, request.user.sub));
    return reply.status(201).send(status);
  });

  app.get("/api/v1/lab/simulations/:simulationId", { preHandler: requireRoles(["organization_admin", "security_analyst", "incident_commander", "auditor", "viewer", "ot_engineer"]) }, async (request) => {
    const { simulationId } = z.object({ simulationId: z.string().uuid() }).parse(request.params);
    return labSimulationStatusSchema.parse(labSimulations.status(request.user.organizationId, simulationId));
  });

  app.post("/api/v1/lab/simulations/:simulationId/stop", { preHandler: requireRoles(["organization_admin", "security_analyst", "incident_commander"]) }, async (request) => {
    const { simulationId } = z.object({ simulationId: z.string().uuid() }).parse(request.params);
    return labSimulationStatusSchema.parse(labSimulations.stop(request.user.organizationId, simulationId));
  });

  app.get("/api/v1/lab/assets/:assetId/heartbeat", { preHandler: requireRoles(["organization_admin", "security_analyst", "incident_commander", "auditor", "viewer", "ot_engineer"]) }, async (request) => {
    const { assetId } = z.object({ assetId: z.string().uuid() }).parse(request.params);
    const asset = (await store.listAssets(request.user.organizationId)).find((candidate) => candidate.id === assetId);
    if (!asset) throw Object.assign(new Error("Asset does not exist."), { statusCode: 404 });
    const assetSimulation = labSimulations.latestStatus(request.user.organizationId, assetId);
    return labAssetHeartbeatSchema.parse(labSimulations.heartbeat(assetId, assetSimulation));
  });

  app.get("/api/v1/governance/assurance", { preHandler: requireRoles(["platform_admin", "organization_admin", "auditor"]) }, async (request) => {
    const [retention, auditEvents] = await Promise.all([store.getRetentionPolicy(request.user.organizationId), store.listAuditEvents(request.user.organizationId, 1_000)]);
    if (!retention) throw Object.assign(new Error("Retention policy not found."), { statusCode: 404 });
    const timestamps = auditEvents.map((event: { occurredAt: string }) => event.occurredAt).sort();
    return governanceAssuranceSchema.parse({ generatedAt: new Date().toISOString(), retention, evidence: { auditEvents: auditEvents.length, ...(timestamps[0] ? { oldestAuditEventAt: timestamps[0] } : {}), ...(timestamps.at(-1) ? { latestAuditEventAt: timestamps.at(-1) } : {}), appendOnly: true }, controls: { tenantIsolation: true, sourceDataUntrusted: true, humanApprovalRequired: true, autonomousExecution: false } });
  });

  app.get("/api/v1/audit-events", { preHandler: requireRoles(["platform_admin", "organization_admin", "auditor"]) }, async (request) => {
    const { limit } = z.object({ limit: z.coerce.number().int().min(1).max(1_000).default(200) }).parse(request.query);
    return { events: await store.listAuditEvents(request.user.organizationId, limit) };
  });

  app.post("/api/v1/admin/audit-anchors/run", { preHandler: requireRoles(["organization_admin", "auditor"]) }, async (request, reply) => {
    if (!auditAnchors) return reply.status(503).send({ error: "MST proof anchoring is not configured." });
    const anchor = await auditAnchors.runAnchorBatch(request.user.organizationId);
    return { anchor: anchor ? auditBatchAnchorSchema.parse(anchor) : null };
  });

  app.get("/api/v1/audit-anchors", { preHandler: requireRoles(["platform_admin", "organization_admin", "auditor", "incident_commander"]) }, async (request) => ({
    anchors: (await store.listAuditBatchAnchors(request.user.organizationId)).map((anchor) => auditBatchAnchorSchema.parse(anchor)),
  }));

  app.get("/api/v1/audit-anchors/:batchId/verify", { preHandler: requireRoles(["platform_admin", "organization_admin", "auditor", "incident_commander"]) }, async (request, reply) => {
    if (!auditAnchors) return reply.status(503).send({ error: "MST proof anchoring is not configured." });
    const { batchId } = z.object({ batchId: z.coerce.number().int().positive() }).parse(request.params);
    return auditBatchVerificationSchema.parse(await auditAnchors.verifyAuditBatch(request.user.organizationId, batchId));
  });

  app.get("/api/v1/audit-events/:eventId/proof", { preHandler: requireRoles(["platform_admin", "organization_admin", "auditor", "incident_commander"]) }, async (request, reply) => {
    if (!auditAnchors) return reply.status(503).send({ error: "MST proof anchoring is not configured." });
    const { eventId } = z.object({ eventId: z.string().uuid() }).parse(request.params);
    return merkleProofSchema.parse(await auditAnchors.getMerkleProof(request.user.organizationId, eventId));
  });

  app.post("/api/v1/identity/wallet/challenge", { preHandler: requireRoles(["platform_admin", "organization_admin"]) }, async (request) => {
    const { userId, walletAddress } = z.object({ userId: z.string().uuid(), walletAddress: z.string().regex(/^0x[a-fA-F0-9]{40}$/) }).parse(request.body);
    const target = await store.getIdentityUser(userId);
    if (!target) throw Object.assign(new Error("Identity user does not exist."), { statusCode: 404 });
    const address = getAddress(walletAddress);
    const nonce = randomUUID();
    const challenge = `Cascadia wallet verification: ${userId}:${nonce}:${Date.now()}`;
    walletChallenges.set(userId, { address, challenge, expiresAt: Date.now() + 5 * 60_000 });
    return walletChallengeSchema.parse({ challenge, userId, walletAddress: address });
  });

  app.post("/api/v1/identity/wallet/verify", { preHandler: requireRoles(["platform_admin", "organization_admin"]) }, async (request) => {
    const input = walletVerificationRequestSchema.extend({ userId: z.string().uuid() }).parse(request.body);
    const pending = walletChallenges.get(input.userId);
    if (!pending || pending.expiresAt < Date.now() || pending.address.toLowerCase() !== input.walletAddress.toLowerCase()) throw Object.assign(new Error("Wallet verification challenge is invalid or expired."), { statusCode: 400 });
    const recovered = getAddress(verifyMessage(pending.challenge, input.signature));
    if (recovered.toLowerCase() !== pending.address.toLowerCase()) throw Object.assign(new Error("Wallet signature does not match the claimed address."), { statusCode: 400 });
    walletChallenges.delete(input.userId);
    return await store.setWalletAddress(input.userId, recovered, new Date().toISOString());
  });

  app.get("/api/v1/posture", { preHandler: requireRoles(["platform_admin", "organization_admin", "incident_commander", "security_analyst", "ot_engineer", "auditor", "viewer"]) }, async (request) => {
    const [assets, vulnerabilities, findings, incidents, integrations, services] = await Promise.all([store.listAssets(request.user.organizationId), store.listVulnerabilities(request.user.organizationId), store.listAnomalyFindings(request.user.organizationId), store.listIncidents(request.user.organizationId), store.listIntegrations(request.user.organizationId), store.listCriticalServices(request.user.organizationId)]);
    return securityPostureSchema.parse(buildSecurityPosture({ assets, vulnerabilities, findings, incidents, integrations, services, now: new Date().toISOString() }));
  });

  app.get("/api/v1/data-quality", { preHandler: requireRoles(["platform_admin", "organization_admin", "incident_commander", "security_analyst", "ot_engineer", "auditor", "viewer"]) }, async (request) => {
    const now = new Date();
    const integrations = await store.listIntegrations(request.user.organizationId);
    const deliveries = await Promise.all(integrations.map(async (integration) => [integration.id, await store.listIntegrationDeliveries(request.user.organizationId, integration.id)] as const));
    const counts = new Map(deliveries.map(([id, entries]) => [id, entries.length]));
    const lastReceived = new Map(deliveries.map(([id, entries]) => [id, entries.reduce<string | undefined>((latest, entry) => !latest || entry.receivedAt > latest ? entry.receivedAt : latest, undefined)]));
    const sources = integrations.map((integration) => {
      const mostRecentRecordAt = integration.lastDeliveryAt ?? lastReceived.get(integration.id);
      const age = mostRecentRecordAt ? now.getTime() - new Date(mostRecentRecordAt).getTime() : undefined;
      const freshness = integration.status === "disabled" ? "disabled" as const : !mostRecentRecordAt ? "no_data" as const : age! <= 24 * 60 * 60 * 1000 ? "current" as const : "stale" as const;
      return { sourceId: integration.id, name: integration.name, provider: integration.provider, status: integration.status, dataType: integration.dataType, ...(mostRecentRecordAt ? { mostRecentRecordAt } : {}), freshness, recordsReceived: counts.get(integration.id) ?? 0 };
    });
    return dataQualityReportSchema.parse({ generatedAt: now.toISOString(), sources, summary: { activeSources: sources.filter((source) => source.status === "active").length, currentSources: sources.filter((source) => source.freshness === "current").length, staleSources: sources.filter((source) => source.freshness === "stale").length, sourcesWithNoData: sources.filter((source) => source.freshness === "no_data").length }, limitations: ["Freshness is calculated from stored signed-delivery timestamps, not an availability probe of a vendor service.", "A current source means a delivery was recorded within the last 24 hours; it does not attest to event completeness."] });
  });

  app.get("/api/v1/ml-governance", { preHandler: requireRoles(["platform_admin", "organization_admin", "incident_commander", "security_analyst", "ot_engineer", "auditor", "viewer"]) }, async (request) => {
    const [models, findings] = await Promise.all([store.listDetectionModels(request.user.organizationId), store.listAnomalyFindings(request.user.organizationId)]);
    return mlGovernanceReportSchema.parse({ generatedAt: new Date().toISOString(), models: models.map((model) => {
      const modelFindings = findings.filter((finding) => finding.modelId === model.id);
      const disposition = (value: "acknowledged" | "dismissed" | "escalated" | "new") => modelFindings.filter((finding) => finding.disposition === value).length;
      return { id: model.id, version: model.version, status: model.status, algorithm: model.algorithm, trainedAt: model.trainedAt, trainingEventCount: model.trainingEventCount, findingThreshold: model.findingThreshold, findingsCreated: modelFindings.length, findingsReviewed: modelFindings.filter((finding) => finding.disposition !== "new").length, dispositions: { acknowledged: disposition("acknowledged"), dismissed: disposition("dismissed"), escalated: disposition("escalated"), new: disposition("new") }, humanReviewRequired: true, autonomousResponseAuthorized: false };
    }), limitations: ["Disposition counts describe analyst workflow outcomes; they are not accuracy, recall, false-positive, or bias measurements.", "Only stored organization telemetry and its durable analyst reviews are represented. Model outputs never authorize a response action."] });
  });

  app.get("/api/v1/compliance/readiness", { preHandler: requireRoles(["platform_admin", "organization_admin", "incident_commander", "security_analyst", "ot_engineer", "auditor", "viewer"]) }, async (request) => {
    const [assets, integrations, audits, models, incidents] = await Promise.all([store.listAssets(request.user.organizationId), store.listIntegrations(request.user.organizationId), store.listAuditEvents(request.user.organizationId, 10_000), store.listDetectionModels(request.user.organizationId), store.listIncidents(request.user.organizationId)]);
    const controls = [
      { id: "CC-01", name: "Asset inventory coverage", status: assets.length ? "satisfied" as const : "action_required" as const, rationale: assets.length ? `${assets.length} stored asset records provide inventory evidence.` : "No stored asset inventory evidence.", evidenceCount: assets.length },
      { id: "CC-02", name: "Signed security-source integration", status: integrations.some((item) => item.status === "active") ? "satisfied" as const : "action_required" as const, rationale: integrations.some((item) => item.status === "active") ? "At least one active signed source is configured." : "No active signed source is configured.", evidenceCount: integrations.filter((item) => item.status === "active").length },
      { id: "CC-03", name: "Human-reviewed detection", status: models.length ? "satisfied" as const : "action_required" as const, rationale: models.length ? "Stored detection models require human review and disable autonomous response." : "No stored detection-model governance evidence.", evidenceCount: models.length },
      { id: "CC-04", name: "Incident evidence workflow", status: incidents.length ? "satisfied" as const : "action_required" as const, rationale: incidents.length ? "Stored incidents provide durable timeline and evidence-link records." : "No stored incident workflow evidence.", evidenceCount: incidents.length },
      { id: "CC-05", name: "Append-only audit evidence", status: audits.length ? "satisfied" as const : "action_required" as const, rationale: audits.length ? "Append-only audit events are available for review." : "No stored audit events in this organization.", evidenceCount: audits.length },
    ]; return complianceReadinessSchema.parse({ generatedAt: new Date().toISOString(), framework: "cascadia_core_controls_v1", controls, limitations: ["This readiness view is calculated from stored Cascadia evidence; it is not a certification or legal compliance determination.", "Custom persisted frameworks, control ownership, and external evidence attestations are planned as the next compliance expansion."] });
  });

  app.get("/api/v1/evidence/assessor-bundle", { preHandler: requireRoles(["platform_admin", "organization_admin", "auditor"]) }, async (request) => {
    const [auditEvents, assets, incidents, integrations] = await Promise.all([store.listAuditEvents(request.user.organizationId, 100_000), store.listAssets(request.user.organizationId), store.listIncidents(request.user.organizationId), store.listIntegrations(request.user.organizationId)]);
    const body = { bundleType: "cascadia_assessor_evidence_v1" as const, classification: "confidential" as const, generatedAt: new Date().toISOString(), evidence: { auditEvents: auditEvents.length, assets: assets.length, incidents: incidents.length, activeIntegrations: integrations.filter((item) => item.status === "active").length }, limitations: ["This manifest summarizes tenant-scoped stored evidence; it does not export raw telemetry or certify compliance.", "Integrity is a SHA-256 manifest hash; external digital signing requires an approved signing key in the deployment secret manager."] };
    return assessorEvidenceBundleSchema.parse({ ...body, integritySha256: createHash("sha256").update(JSON.stringify(body)).digest("hex") });
  });

  app.get("/api/v1/reports/executive", { preHandler: requireRoles(["platform_admin", "organization_admin", "auditor"]) }, async (request) => {
    const organizationId = request.user.organizationId;
    const [organization, retention, auditEvents, assets, vulnerabilities, findings, incidents, integrations, services] = await Promise.all([store.getOrganization(organizationId), store.getRetentionPolicy(organizationId), store.listAuditEvents(organizationId, 1_000), store.listAssets(organizationId), store.listVulnerabilities(organizationId), store.listAnomalyFindings(organizationId), store.listIncidents(organizationId), store.listIntegrations(organizationId), store.listCriticalServices(organizationId)]);
    if (!organization || !retention) throw Object.assign(new Error("Organization reporting configuration not found."), { statusCode: 404 });
    const generatedAt = new Date().toISOString();
    const timestamps = auditEvents.map((event: { occurredAt: string }) => event.occurredAt).sort();
    const governance = { generatedAt, retention, evidence: { auditEvents: auditEvents.length, ...(timestamps[0] ? { oldestAuditEventAt: timestamps[0] } : {}), ...(timestamps.at(-1) ? { latestAuditEventAt: timestamps.at(-1) } : {}), appendOnly: true as const }, controls: { tenantIsolation: true as const, sourceDataUntrusted: true as const, humanApprovalRequired: true as const, autonomousExecution: false as const } };
    const posture = buildSecurityPosture({ assets, vulnerabilities, findings, incidents, integrations, services, now: generatedAt });
    const reportBody = { reportType: "cascadia_executive_assurance_v1" as const, classification: "confidential" as const, generatedAt, organization, governance, posture, limitations: ["This export contains evidence summaries, not raw security-event records.", "It is decision support, not a compliance certification or authorization for response execution."] };
    const integritySha256 = createHash("sha256").update(JSON.stringify(reportBody)).digest("hex");
    return executiveReportSchema.parse({ ...reportBody, integritySha256 });
  });

  app.get("/api/v1/system/deployment-readiness", { preHandler: requireRoles(["platform_admin", "organization_admin"]) }, async () => {
    const production = config.NODE_ENV === "production";
    const checks = [
      { id: "postgres", label: "PostgreSQL persistence", status: config.DATA_STORE === "postgres" && Boolean(config.DATABASE_URL) ? "ready" as const : "action_required" as const, detail: config.DATA_STORE === "postgres" ? "PostgreSQL data-store configuration is present." : "Set DATA_STORE=postgres and configure DATABASE_URL." },
      { id: "oidc", label: "Enterprise SSO and MFA", status: config.OIDC_ISSUER_URL && config.OIDC_CLIENT_ID && config.OIDC_CLIENT_SECRET ? "ready" as const : "action_required" as const, detail: config.OIDC_ISSUER_URL ? "OIDC configuration is present." : "Register a production OIDC client and enforce MFA claims." },
      { id: "https", label: "HTTPS application URL", status: config.PUBLIC_APP_URL.startsWith("https://") ? "ready" as const : "action_required" as const, detail: config.PUBLIC_APP_URL.startsWith("https://") ? "Application URL uses HTTPS." : "Terminate TLS and set a public HTTPS URL." },
      { id: "secrets", label: "Dedicated secrets", status: Boolean(config.INTEGRATION_ENCRYPTION_KEY && config.OBSERVABILITY_TOKEN) ? "ready" as const : "action_required" as const, detail: config.INTEGRATION_ENCRYPTION_KEY && config.OBSERVABILITY_TOKEN ? "Integration encryption and observability secrets are configured." : "Configure separate integration-encryption and observability secrets." },
      { id: "container", label: "Production serving", status: config.SERVE_WEB ? "ready" as const : "action_required" as const, detail: config.SERVE_WEB ? "Compiled web application is served by the API container." : "Build and enable the production web serving configuration." },
    ];
    return deploymentReadinessSchema.parse({ environment: production ? "production" : "development", readyForProduction: production && checks.every((check) => check.status === "ready"), checks, checkedAt: new Date().toISOString() });
  });

  app.get("/api/v1/access/context", { preHandler: requireRoles(["platform_admin", "organization_admin", "incident_commander", "security_analyst", "ot_engineer", "auditor", "viewer"]) }, async (request) => {
    const permissionsByRole: Record<UserRole, string[]> = {
      platform_admin: ["all"], organization_admin: ["all"], incident_commander: ["operations", "incidents", "responses", "tasks", "notifications", "read"], security_analyst: ["operations", "assets", "detection", "incidents", "simulate", "read"], ot_engineer: ["operations", "assets", "responses", "simulate", "read"], auditor: ["assurance", "evidence", "read"], viewer: ["read"],
    };
    return accessContextSchema.parse({ role: request.user.role, permissions: permissionsByRole[request.user.role] });
  });

  app.post(
    "/api/v1/organizations",
    { preHandler: requireRoles(["platform_admin"]) },
    async (request, reply) => {
      const input = organizationOnboardingRequestSchema.parse(request.body);
      const organization = await store.createOrganization(input, request.user.sub);
      return reply.status(201).send(organization);
    },
  );

  app.post("/api/v1/incidents/:incidentId/decisions/:decisionId/anchor", { preHandler: requireRoles(["organization_admin", "incident_commander", "ot_engineer"]) }, async (request, reply) => {
    if (!decisionProofs) return reply.status(503).send({ error: "MST proof anchoring is not configured." });
    const { incidentId, decisionId } = z.object({ incidentId: z.string().uuid(), decisionId: z.string().uuid() }).parse(request.params);
    const scenarios = await store.listResponseScenarios(request.user.organizationId);
    const scenario = scenarios.find((candidate) => candidate.incidentId === incidentId && candidate.decisions.some((decision) => decision.id === decisionId));
    if (!scenario) return reply.status(404).send({ error: "DecisionNotFound" });
    return proofAnchorResponseSchema.parse(await decisionProofs.requestSignature(request.user.organizationId, decisionId));
  });

  app.post("/api/v1/incidents/:incidentId/decisions/:decisionId/anchor/submit", { preHandler: requireRoles(["organization_admin", "incident_commander", "ot_engineer"]) }, async (request, reply) => {
    if (!decisionProofs) return reply.status(503).send({ error: "MST proof anchoring is not configured." });
    const { incidentId, decisionId } = z.object({ incidentId: z.string().uuid(), decisionId: z.string().uuid() }).parse(request.params);
    const input = proofSubmitRequestSchema.parse(request.body);
    const requested = await decisionProofs.requestSignature(request.user.organizationId, decisionId);
    const scenarios = await store.listResponseScenarios(request.user.organizationId);
    if (!scenarios.some((candidate) => candidate.incidentId === incidentId && candidate.decisions.some((decision) => decision.id === decisionId))) return reply.status(404).send({ error: "DecisionNotFound" });
    return decisionProofSchema.parse(await decisionProofs.submitAnchor(request.user.organizationId, decisionId, requested.evidenceHash, input.signature));
  });

  app.get("/api/v1/incidents/:incidentId/decisions/:decisionId/proof", { preHandler: requireRoles(["platform_admin", "organization_admin", "incident_commander", "auditor", "viewer", "ot_engineer"]) }, async (request, reply) => {
    if (!decisionProofs) return reply.status(503).send({ error: "MST proof anchoring is not configured." });
    const { incidentId, decisionId } = z.object({ incidentId: z.string().uuid(), decisionId: z.string().uuid() }).parse(request.params);
    const scenarios = await store.listResponseScenarios(request.user.organizationId);
    if (!scenarios.some((candidate) => candidate.incidentId === incidentId && candidate.decisions.some((decision) => decision.id === decisionId))) return reply.status(404).send({ error: "DecisionNotFound" });
    return proofVerificationSchema.parse(await decisionProofs.verifyProof(request.user.organizationId, decisionId));
  });

  app.get(
    "/api/v1/organizations/current",
    { preHandler: requireRoles(["platform_admin", "organization_admin", "security_analyst", "incident_commander", "auditor", "viewer", "ot_engineer"]) },
    async (request, reply) => {
      const organization = await store.getOrganization(request.user.organizationId);
      return organization ? organization : reply.status(404).send({ error: "OrganizationNotFound" });
    },
  );

  app.get(
    "/api/v1/security-boundaries",
    { preHandler: requireRoles(["platform_admin", "organization_admin", "auditor", "viewer", "security_analyst", "incident_commander", "ot_engineer"]) },
    async () => ({
      autonomousExecution: false,
      untrustedSourceHandling: "stored_as_evidence_only",
      recommendationApproval: "required",
      feedBehaviour: "read_only",
      mlFindingReview: "required",
      mlResponseExecution: false,
    }),
  );

  app.post(
    "/api/agent/init",
    { preHandler: requireRoles(["platform_admin", "organization_admin", "security_analyst", "incident_commander"]) },
    async (request, reply) => {
      const input = agentInitRequestSchema.parse(request.body);
      sameTenant(request.user, input.organizationId);
      // Intentional invariant: every valid POST creates a distinct durable agent.
      const agent = await store.createAgent(input);
      return reply.status(201).send(agent);
    },
  );

  app.get(
    "/api/agent/feed",
    { preHandler: requireRoles(["platform_admin", "organization_admin", "security_analyst", "incident_commander", "auditor", "viewer", "ot_engineer"]) },
    async (request) => {
      // Read-only invariant: no discovery, generation, publication, or auditing occurs here.
      return agentFeedSchema.parse({ posts: await store.listPosts(request.user.organizationId) });
    },
  );

  app.post(
    "/api/v1/assets",
    { preHandler: requireRoles(["organization_admin", "security_analyst", "ot_engineer"]) },
    async (request, reply) => {
      const input = assetCreateRequestSchema.parse(request.body);
      const result = await store.upsertAsset(request.user.organizationId, input, request.user.sub);
      return reply.status(result.created ? 201 : 200).send(result.asset);
    },
  );

  app.get(
    "/api/v1/assets",
    { preHandler: requireRoles(["organization_admin", "security_analyst", "incident_commander", "auditor", "viewer", "ot_engineer"]) },
    async (request) => ({ assets: await store.listAssets(request.user.organizationId) }),
  );

  app.post(
    "/api/v1/notifications/deliver",
    { preHandler: requireRoles(["organization_admin", "incident_commander"]) },
    async (request) => {
      if (!config.NOTIFICATION_WEBHOOK_URL) {
        throw Object.assign(new Error("Manual notification delivery is not configured."), { statusCode: 503 });
      }
      const input = notificationRequestSchema.parse(request.body);
      const sentAt = new Date().toISOString();
      const provider = config.NOTIFICATION_WEBHOOK_PROVIDER ?? "generic";
      const payload = provider === "slack"
        ? { text: `*${input.title}*\n${input.message}` }
        : provider === "teams"
          ? { text: `**${input.title}**\n\n${input.message}` }
          : { title: input.title, message: input.message, source: "cascadia", sentAt };
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 10_000);
      try {
        const response = await fetch(config.NOTIFICATION_WEBHOOK_URL, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify(payload),
          redirect: "error",
          signal: controller.signal,
        });
        if (!response.ok) throw Object.assign(new Error("Notification delivery failed."), { statusCode: 502 });
      } catch (error) {
        if ((error as { statusCode?: number }).statusCode) throw error;
        throw Object.assign(new Error("Notification delivery failed."), { statusCode: 502 });
      } finally {
        clearTimeout(timeout);
      }
      app.log.info({ provider, actorId: request.user.sub }, "Manual notification delivered");
      return notificationDeliveryResultSchema.parse({ delivered: true, provider, deliveredAt: sentAt });
    },
  );

  app.patch(
    "/api/v1/assets/:assetId/enrichment",
    { preHandler: requireRoles(["organization_admin", "security_analyst", "ot_engineer"]) },
    async (request, reply) => {
      const { assetId } = z.object({ assetId: z.string().uuid() }).parse(request.params);
      const enrichment = assetEnrichmentUpdateSchema.parse(request.body);
      const asset = (await store.listAssets(request.user.organizationId)).find((item) => item.id === assetId);
      if (!asset) return reply.status(404).send({ error: "AssetNotFound" });
      const metadata = { ...asset.metadata, lifecycle: enrichment.lifecycle, ...(enrichment.ownerTeam ? { ownerTeam: enrichment.ownerTeam } : {}), ...(enrichment.sbom ? { sbom: enrichment.sbom } : {}) };
      const result = await store.upsertAsset(request.user.organizationId, { externalId: asset.externalId, name: asset.name, assetType: asset.assetType, criticality: asset.criticality, classification: asset.classification, ...(asset.ownerUserId ? { ownerUserId: asset.ownerUserId } : {}), ...(asset.hostname ? { hostname: asset.hostname } : {}), ...(asset.ipAddress ? { ipAddress: asset.ipAddress } : {}), metadata }, request.user.sub);
      return result.asset;
    },
  );

  app.post(
    "/api/v1/assets/import",
    { preHandler: requireRoles(["organization_admin", "security_analyst", "ot_engineer"]) },
    async (request, reply) => {
      const input = assetImportRequestSchema.parse(request.body);
      const result = await importAssets(store, request.user.organizationId, request.user.sub, input);
      return reply.status(200).send(result);
    },
  );

  app.post(
    "/api/v1/dependencies",
    { preHandler: requireRoles(["organization_admin", "security_analyst", "ot_engineer"]) },
    async (request, reply) => {
      const input = assetDependencyCreateRequestSchema.parse(request.body);
      const dependency = await store.createDependency(request.user.organizationId, input, request.user.sub);
      return reply.status(201).send(dependency);
    },
  );

  app.get(
    "/api/v1/dependencies",
    { preHandler: requireRoles(["organization_admin", "security_analyst", "incident_commander", "auditor", "viewer", "ot_engineer"]) },
    async (request) => ({ dependencies: await store.listDependencies(request.user.organizationId) }),
  );

  app.post(
    "/api/v1/events/ingest",
    { preHandler: requireRoles(["organization_admin", "security_analyst"]) },
    async (request, reply) => {
      const input = securityEventIngestRequestSchema.parse(request.body);
      const result = securityEventIngestResultSchema.parse(await store.ingestSecurityEvent(request.user.organizationId, input));
      return reply.status(result.duplicate ? 200 : 202).send(result);
    },
  );

  app.get(
    "/api/v1/events",
    { preHandler: requireRoles(["organization_admin", "security_analyst", "incident_commander", "auditor", "viewer", "ot_engineer"]) },
    async (request) => ({ events: await store.listSecurityEvents(request.user.organizationId) }),
  );

  app.post(
    "/api/v1/integrations",
    { preHandler: requireRoles(["organization_admin"]) },
    async (request, reply) => {
      const input = integrationCreateRequestSchema.parse(request.body);
      const result = await createIntegration(store, request.user.organizationId, input, request.user.sub, integrationEncryptionKey);
      return reply.status(201).send(result);
    },
  );

  app.get(
    "/api/v1/integrations",
    { preHandler: requireRoles(["organization_admin", "security_analyst", "incident_commander", "auditor", "viewer", "ot_engineer"]) },
    async (request) => ({ integrations: await store.listIntegrations(request.user.organizationId) }),
  );

  app.patch(
    "/api/v1/integrations/:integrationId/status",
    { preHandler: requireRoles(["organization_admin"]) },
    async (request) => {
      const { integrationId } = z.object({ integrationId: z.string().uuid() }).parse(request.params);
      const input = integrationStatusUpdateSchema.parse(request.body);
      return store.updateIntegrationStatus(request.user.organizationId, integrationId, input, request.user.sub);
    },
  );

  app.post(
    "/api/v1/integrations/:integrationId/rotate-secret",
    { preHandler: requireRoles(["organization_admin"]) },
    async (request) => {
      const { integrationId } = z.object({ integrationId: z.string().uuid() }).parse(request.params);
      return rotateIntegrationSecret(store, request.user.organizationId, integrationId, request.user.sub, integrationEncryptionKey);
    },
  );

  app.get(
    "/api/v1/integrations/:integrationId/deliveries",
    { preHandler: requireRoles(["organization_admin", "security_analyst", "incident_commander", "auditor", "viewer", "ot_engineer"]) },
    async (request, reply) => {
      const { integrationId } = z.object({ integrationId: z.string().uuid() }).parse(request.params);
      const integration = await store.getIntegration(request.user.organizationId, integrationId);
      if (!integration) return reply.status(404).send({ error: "IntegrationNotFound" });
      return { deliveries: await store.listIntegrationDeliveries(request.user.organizationId, integrationId) };
    },
  );

  app.get(
    "/api/v1/threat-indicators",
    { preHandler: requireRoles(["organization_admin", "security_analyst", "incident_commander", "auditor", "viewer", "ot_engineer"]) },
    async (request) => ({ indicators: await store.listThreatIndicators(request.user.organizationId) }),
  );

  app.post(
    "/api/v1/integrations/:integrationId/webhook",
    async (request, reply) => {
      const { integrationId } = z.object({ integrationId: z.string().uuid() }).parse(request.params);
      const headers = z.object({
        "x-cascadia-timestamp": z.string(),
        "x-cascadia-delivery-id": z.string(),
        "x-cascadia-signature": z.string(),
      }).parse(request.headers);
      const result = integrationDeliveryResultSchema.parse(await ingestSignedWebhook(
        store,
        integrationId,
        headers["x-cascadia-timestamp"],
        headers["x-cascadia-delivery-id"],
        headers["x-cascadia-signature"],
        request.rawBody ?? Buffer.alloc(0),
        request.body,
        integrationEncryptionKey,
      ));
      return reply.status(result.duplicate ? 200 : 202).send(result);
    },
  );

  app.post(
    "/api/v1/taxii-sources",
    { preHandler: requireRoles(["organization_admin"]) },
    async (request, reply) => {
      const input = taxiiSourceCreateRequestSchema.parse(request.body);
      const source = await createTaxiiSource(store, request.user.organizationId, input, request.user.sub, integrationEncryptionKey);
      return reply.status(201).send(source);
    },
  );

  app.get(
    "/api/v1/taxii-sources",
    { preHandler: requireRoles(["organization_admin", "security_analyst", "incident_commander", "auditor", "viewer", "ot_engineer"]) },
    async (request) => ({ sources: await store.listTaxiiSources(request.user.organizationId) }),
  );

  app.patch(
    "/api/v1/taxii-sources/:sourceId/status",
    { preHandler: requireRoles(["organization_admin"]) },
    async (request) => {
      const { sourceId } = z.object({ sourceId: z.string().uuid() }).parse(request.params);
      const input = taxiiSourceStatusUpdateSchema.parse(request.body);
      return store.updateTaxiiSourceStatus(request.user.organizationId, sourceId, input, request.user.sub);
    },
  );

  app.post(
    "/api/v1/taxii-sources/:sourceId/sync",
    { preHandler: requireRoles(["organization_admin", "security_analyst"]) },
    async (request) => {
      const { sourceId } = z.object({ sourceId: z.string().uuid() }).parse(request.params);
      return runTaxiiSync(store, request.user.organizationId, sourceId, request.user.sub, integrationEncryptionKey);
    },
  );

  app.get(
    "/api/v1/taxii-sources/:sourceId/jobs",
    { preHandler: requireRoles(["organization_admin", "security_analyst", "incident_commander", "auditor", "viewer", "ot_engineer"]) },
    async (request, reply) => {
      const { sourceId } = z.object({ sourceId: z.string().uuid() }).parse(request.params);
      const source = await store.getTaxiiSource(request.user.organizationId, sourceId);
      if (!source) return reply.status(404).send({ error: "TaxiiSourceNotFound" });
      return { jobs: await store.listTaxiiSyncJobs(request.user.organizationId, sourceId) };
    },
  );

  app.post(
    "/api/v1/detection/models/train",
    { preHandler: requireRoles(["organization_admin", "security_analyst"]) },
    async (request, reply) => {
      const input = detectionModelTrainingRequestSchema.parse(request.body);
      const model = await trainDetectionModel(store, request.user.organizationId, input, request.user.sub);
      return reply.status(201).send(model);
    },
  );

  app.get(
    "/api/v1/detection/models",
    { preHandler: requireRoles(["organization_admin", "security_analyst", "incident_commander", "auditor", "viewer", "ot_engineer"]) },
    async (request) => ({ models: await store.listDetectionModels(request.user.organizationId) }),
  );

  app.post(
    "/api/v1/detection/evaluate",
    { preHandler: requireRoles(["organization_admin", "security_analyst"]) },
    async (request) => evaluateNewTelemetry(store, request.user.organizationId),
  );

  app.get(
    "/api/v1/detection/findings",
    { preHandler: requireRoles(["organization_admin", "security_analyst", "incident_commander", "auditor", "viewer", "ot_engineer"]) },
    async (request) => ({ findings: await store.listAnomalyFindings(request.user.organizationId) }),
  );

  app.post(
    "/api/v1/detection/findings/:findingId/disposition",
    { preHandler: requireRoles(["organization_admin", "security_analyst", "incident_commander"]) },
    async (request) => {
      const { findingId } = z.object({ findingId: z.string().uuid() }).parse(request.params);
      const input = anomalyFindingDispositionRequestSchema.parse(request.body);
      return store.reviewAnomalyFinding(request.user.organizationId, findingId, input, request.user.sub);
    },
  );

  app.post(
    "/api/v1/vulnerabilities",
    { preHandler: requireRoles(["organization_admin", "security_analyst", "ot_engineer"]) },
    async (request, reply) => {
      const input = vulnerabilityUpsertRequestSchema.parse(request.body);
      const result = await store.upsertVulnerability(request.user.organizationId, input, request.user.sub);
      return reply.status(result.created ? 201 : 200).send(result.vulnerability);
    },
  );

  app.get(
    "/api/v1/vulnerabilities",
    { preHandler: requireRoles(["organization_admin", "security_analyst", "incident_commander", "auditor", "viewer", "ot_engineer"]) },
    async (request) => ({ vulnerabilities: await store.listVulnerabilities(request.user.organizationId) }),
  );

  app.post(
    "/api/v1/critical-services",
    { preHandler: requireRoles(["organization_admin", "security_analyst", "incident_commander", "ot_engineer"]) },
    async (request, reply) => {
      const input = criticalServiceUpsertRequestSchema.parse(request.body);
      const result = await store.upsertCriticalService(request.user.organizationId, input, request.user.sub);
      return reply.status(result.created ? 201 : 200).send(result.service);
    },
  );

  app.get(
    "/api/v1/critical-services",
    { preHandler: requireRoles(["organization_admin", "security_analyst", "incident_commander", "auditor", "viewer", "ot_engineer"]) },
    async (request) => ({ services: await store.listCriticalServices(request.user.organizationId) }),
  );

  app.post(
    "/api/v1/risk/attack-paths",
    { preHandler: requireRoles(["organization_admin", "security_analyst", "incident_commander", "ot_engineer"]) },
    async (request) => {
      const input = attackPathAnalysisRequestSchema.parse(request.body);
      return analyzeAttackPaths(store, request.user.organizationId, input, request.user.sub);
    },
  );

  app.get(
    "/api/v1/risk/analyses",
    { preHandler: requireRoles(["organization_admin", "security_analyst", "incident_commander", "auditor", "viewer", "ot_engineer"]) },
    async (request) => ({ analyses: await store.listRiskAnalyses(request.user.organizationId) }),
  );

  app.post(
    "/api/v1/response-policies",
    { preHandler: requireRoles(["organization_admin", "incident_commander"]) },
    async (request, reply) => {
      const input = responsePolicyUpsertRequestSchema.parse(request.body);
      const result = await store.upsertResponsePolicy(request.user.organizationId, input, request.user.sub);
      return reply.status(result.created ? 201 : 200).send(result.policy);
    },
  );

  app.get(
    "/api/v1/response-policies",
    { preHandler: requireRoles(["organization_admin", "security_analyst", "incident_commander", "auditor", "viewer", "ot_engineer"]) },
    async (request) => ({ policies: await store.listResponsePolicies(request.user.organizationId) }),
  );

  app.post(
    "/api/v1/responses/simulate",
    { preHandler: requireRoles(["organization_admin", "security_analyst", "incident_commander", "ot_engineer"]) },
    async (request, reply) => {
      const input = responseSimulationRequestSchema.parse(request.body);
      const scenario = await simulateResponses(store, request.user.organizationId, input, request.user.sub);
      return reply.status(201).send(scenario);
    },
  );

  app.get(
    "/api/v1/responses",
    { preHandler: requireRoles(["organization_admin", "security_analyst", "incident_commander", "auditor", "viewer", "ot_engineer"]) },
    async (request) => ({ scenarios: await store.listResponseScenarios(request.user.organizationId) }),
  );

  app.get(
    "/api/v1/responses/:scenarioId",
    { preHandler: requireRoles(["organization_admin", "security_analyst", "incident_commander", "auditor", "viewer", "ot_engineer"]) },
    async (request, reply) => {
      const { scenarioId } = z.object({ scenarioId: z.string().uuid() }).parse(request.params);
      const scenario = await store.getResponseScenario(request.user.organizationId, scenarioId);
      return scenario ?? reply.status(404).send({ error: "ResponseScenarioNotFound" });
    },
  );

  app.post(
    "/api/v1/responses/:scenarioId/decisions",
    { preHandler: requireRoles(["organization_admin", "incident_commander", "ot_engineer"]) },
    async (request) => {
      const { scenarioId } = z.object({ scenarioId: z.string().uuid() }).parse(request.params);
      const input = responseDecisionRequestSchema.parse(request.body);
      return store.recordResponseDecision(request.user.organizationId, scenarioId, input, request.user.sub, request.user.role);
    },
  );

  const incidentReaders: readonly UserRole[] = ["organization_admin", "security_analyst", "incident_commander", "auditor", "viewer", "ot_engineer"];
  const incidentOperators: readonly UserRole[] = ["organization_admin", "security_analyst", "incident_commander"];

  app.post("/api/v1/incidents/correlate", { preHandler: requireRoles(incidentOperators) }, async (request) => {
    const input = incidentCorrelationRequestSchema.parse(request.body);
    const candidates = await correlateIncidentCandidates(store, request.user.organizationId, input);
    return { candidates, noOp: candidates.length === 0, incidentsCreated: 0, requiresAnalystConfirmation: true };
  });

  app.post("/api/v1/incidents", { preHandler: requireRoles(incidentOperators) }, async (request, reply) => {
    const input = incidentCreateRequestSchema.parse(request.body);
    const result = await createIncident(store, request.user.organizationId, input, request.user.sub);
    return reply.status(result.created ? 201 : 200).send(result.incident);
  });

  app.get("/api/v1/incidents", { preHandler: requireRoles(incidentReaders) }, async (request) => ({ incidents: await store.listIncidents(request.user.organizationId) }));

  app.get("/api/v1/incidents/:incidentId", { preHandler: requireRoles(incidentReaders) }, async (request, reply) => {
    const { incidentId } = z.object({ incidentId: z.string().uuid() }).parse(request.params);
    return await store.getIncident(request.user.organizationId, incidentId) ?? reply.status(404).send({ error: "IncidentNotFound" });
  });

  app.get("/api/v1/incidents/:incidentId/timeline", { preHandler: requireRoles(incidentReaders) }, async (request, reply) => {
    const { incidentId } = z.object({ incidentId: z.string().uuid() }).parse(request.params);
    const incident = await store.getIncident(request.user.organizationId, incidentId);
    return incident ? { timeline: incident.timeline } : reply.status(404).send({ error: "IncidentNotFound" });
  });

  app.post("/api/v1/incidents/:incidentId/status", { preHandler: requireRoles(incidentOperators) }, async (request) => {
    const { incidentId } = z.object({ incidentId: z.string().uuid() }).parse(request.params);
    return store.transitionIncident(request.user.organizationId, incidentId, incidentStatusUpdateRequestSchema.parse(request.body), request.user.sub);
  });

  app.post("/api/v1/incidents/:incidentId/assignment", { preHandler: requireRoles(incidentOperators) }, async (request) => {
    const { incidentId } = z.object({ incidentId: z.string().uuid() }).parse(request.params);
    return store.assignIncident(request.user.organizationId, incidentId, incidentAssignmentRequestSchema.parse(request.body), request.user.sub);
  });

  app.post("/api/v1/incidents/:incidentId/comments", { preHandler: requireRoles(incidentOperators) }, async (request) => {
    const { incidentId } = z.object({ incidentId: z.string().uuid() }).parse(request.params);
    return store.commentOnIncident(request.user.organizationId, incidentId, incidentCommentRequestSchema.parse(request.body), request.user.sub);
  });

  app.post("/api/v1/incidents/:incidentId/evidence", { preHandler: requireRoles(incidentOperators) }, async (request) => {
    const { incidentId } = z.object({ incidentId: z.string().uuid() }).parse(request.params);
    const input = incidentEvidenceLinkRequestSchema.parse(request.body);
    await validateIncidentEvidence(store, request.user.organizationId, [input]);
    return store.linkIncidentEvidence(request.user.organizationId, incidentId, input, request.user.sub);
  });

  app.post("/api/v1/incidents/:incidentId/tasks", { preHandler: requireRoles(incidentOperators) }, async (request, reply) => {
    const { incidentId } = z.object({ incidentId: z.string().uuid() }).parse(request.params);
    const incident = await store.createIncidentTask(request.user.organizationId, incidentId, incidentTaskCreateRequestSchema.parse(request.body), request.user.sub);
    return reply.status(201).send(incident);
  });

  app.patch("/api/v1/incidents/:incidentId/tasks/:taskId", { preHandler: requireRoles(incidentOperators) }, async (request) => {
    const { incidentId, taskId } = z.object({ incidentId: z.string().uuid(), taskId: z.string().uuid() }).parse(request.params);
    return store.updateIncidentTask(request.user.organizationId, incidentId, taskId, incidentTaskUpdateRequestSchema.parse(request.body), request.user.sub);
  });

  if (config.SERVE_WEB) {
    app.register(fastifyStatic, { root: resolve(config.WEB_DIST_DIR), wildcard: false });
    app.setNotFoundHandler(async (request, reply) => {
      if (request.url.startsWith("/api/") || request.url.startsWith("/health") || request.url === "/metrics") return reply.status(404).send({ error: "NotFound" });
      return reply.sendFile("index.html");
    });
  }

  app.addHook("onClose", async () => { await labSimulations.close(); });

  return app;
}

import { randomUUID } from "node:crypto";
import type {
  Agent, AgentInitRequest, AnomalyFinding, AnomalyFindingDispositionRequest, Asset, AssetCreateRequest, AssetDependency, RetentionPolicy,
  AssetDependencyCreateRequest, AttackPathAnalysis, AuditEvent, CriticalService,
  CriticalServiceUpsertRequest, Integration, IntegrationCreateRequest, IntegrationDelivery,
  IntegrationDeliveryResult, IntegrationStatusUpdate, Organization, OrganizationOnboardingRequest,
  PublishedPost, ResponseDecisionRequest, ResponsePolicy, ResponsePolicyUpsertRequest,
  ResponseScenario, SecurityEvent, SecurityEventIngestRequest, UserRole,
  TaxiiSource, TaxiiSourceCreateRequest, TaxiiSourceStatusUpdate, TaxiiSyncAttempt,
  TaxiiSyncJob, ThreatIndicator, DetectionModel, Vulnerability, VulnerabilityUpsertRequest, Incident,
  IncidentAssignmentRequest, IncidentCommentRequest, IncidentEvidenceLinkRequest, IncidentStatusUpdateRequest,
  IncidentTaskCreateRequest, IncidentTaskUpdateRequest, IdentityEnrollmentRequest, IdentityUser,
  AuditBatchAnchor, DecisionProof, MerkleProof,
} from "@cascadia/contracts";
import { applyResponseDecision } from "./response-workflow.js";
import { assignIncident, commentOnIncident, createIncidentTask, linkIncidentEvidence, transitionIncident, updateIncidentTask } from "./incident-workflow.js";

export interface Clock { now(): Date; }
export const systemClock: Clock = { now: () => new Date() };
export interface IngestResult { event: SecurityEvent; duplicate: boolean; }
export interface UpsertAssetResult { asset: Asset; created: boolean; }
export interface UpsertVulnerabilityResult { vulnerability: Vulnerability; created: boolean; }
export interface UpsertCriticalServiceResult { service: CriticalService; created: boolean; }
export interface UpsertResponsePolicyResult { policy: ResponsePolicy; created: boolean; }
export interface IntegrationCredential { integration: Integration; secretCiphertext: string; }
export interface TaxiiSourceCredential { source: TaxiiSource; authenticationCiphertext?: string; }
export interface TaxiiSyncCompletion {
  status: "succeeded" | "failed";
  checkpointAfter?: string;
  pagesFetched: number;
  objectsReceived: number;
  indicatorsAccepted: number;
  errorCode?: string;
  errorMessage?: string;
}
export interface SaveFindingResult { finding: AnomalyFinding; created: boolean; }
export interface CreateIncidentResult { incident: Incident; created: boolean; }
export interface OidcLoginAttempt { stateHash: string; codeVerifier: string; nonce: string; returnTo: string; expiresAt: string; }
export interface IdentityAccess { user: IdentityUser; organizationId: string; role: UserRole; }
export interface IdentitySessionRecord extends IdentityAccess {
  id: string; tokenHash: string; csrfTokenHash: string; mfaVerified: true; issuer: string; subject: string;
  createdAt: string; lastSeenAt: string; expiresAt: string; revokedAt?: string;
}
export interface IdentitySessionCreate extends Omit<IdentitySessionRecord, "id" | "createdAt" | "lastSeenAt" | "revokedAt"> {}

export interface CascadiaStore {
  checkHealth(): Promise<{ status: "ready"; latencyMs: number }>;
  createOrganization(input: OrganizationOnboardingRequest, actorUserId: string): Promise<Organization>;
  getOrganization(id: string): Promise<Organization | undefined>;
  listOrganizations(): Promise<Organization[]>;
  getRetentionPolicy(organizationId: string): Promise<RetentionPolicy | undefined>;
  listAuditEvents(organizationId: string, limit: number): Promise<AuditEvent[]>;
  listUnanchoredAuditEvents(organizationId: string, after?: string): Promise<AuditEvent[]>;
  listAuditEventsForBatch(organizationId: string, batchId: number): Promise<AuditEvent[]>;
  listAuditBatchAnchors(organizationId: string): Promise<AuditBatchAnchor[]>;
  getAuditBatchAnchor(organizationId: string, batchId: number): Promise<AuditBatchAnchor | undefined>;
  createAuditBatchAnchor(anchor: Omit<AuditBatchAnchor, "id" | "createdAt">, eventIds: string[]): Promise<AuditBatchAnchor>;
  getDecisionProof(organizationId: string, decisionId: string): Promise<DecisionProof | undefined>;
  saveDecisionProof(proof: DecisionProof): Promise<void>;
  getIdentityUser(userId: string): Promise<IdentityUser | undefined>;
  setWalletAddress(userId: string, walletAddress: string, verifiedAt: string): Promise<IdentityUser>;
  createAgent(input: AgentInitRequest): Promise<Agent>;
  listPosts(organizationId: string): Promise<PublishedPost[]>;
  appendPublishedPost(post: PublishedPost): Promise<void>;
  upsertAsset(organizationId: string, input: AssetCreateRequest, actorUserId: string): Promise<UpsertAssetResult>;
  listAssets(organizationId: string): Promise<Asset[]>;
  createDependency(organizationId: string, input: AssetDependencyCreateRequest, actorUserId: string): Promise<AssetDependency>;
  listDependencies(organizationId: string): Promise<AssetDependency[]>;
  ingestSecurityEvent(organizationId: string, input: SecurityEventIngestRequest): Promise<IngestResult>;
  listSecurityEvents(organizationId: string): Promise<SecurityEvent[]>;
  upsertVulnerability(organizationId: string, input: VulnerabilityUpsertRequest, actorUserId: string): Promise<UpsertVulnerabilityResult>;
  listVulnerabilities(organizationId: string): Promise<Vulnerability[]>;
  upsertCriticalService(organizationId: string, input: CriticalServiceUpsertRequest, actorUserId: string): Promise<UpsertCriticalServiceResult>;
  listCriticalServices(organizationId: string): Promise<CriticalService[]>;
  saveRiskAnalysis(analysis: AttackPathAnalysis, actorUserId: string): Promise<void>;
  getRiskAnalysis(organizationId: string, analysisId: string): Promise<AttackPathAnalysis | undefined>;
  listRiskAnalyses(organizationId: string): Promise<AttackPathAnalysis[]>;
  upsertResponsePolicy(organizationId: string, input: ResponsePolicyUpsertRequest, actorUserId: string): Promise<UpsertResponsePolicyResult>;
  listResponsePolicies(organizationId: string): Promise<ResponsePolicy[]>;
  saveResponseScenario(scenario: ResponseScenario, actorUserId: string): Promise<void>;
  getResponseScenario(organizationId: string, scenarioId: string): Promise<ResponseScenario | undefined>;
  listResponseScenarios(organizationId: string): Promise<ResponseScenario[]>;
  recordResponseDecision(organizationId: string, scenarioId: string, input: ResponseDecisionRequest, actorUserId: string, actorRole: UserRole): Promise<ResponseScenario>;
  createIntegration(organizationId: string, input: IntegrationCreateRequest, secretCiphertext: string, actorUserId: string): Promise<Integration>;
  getIntegration(organizationId: string, integrationId: string): Promise<Integration | undefined>;
  getIntegrationCredential(integrationId: string): Promise<IntegrationCredential | undefined>;
  listIntegrations(organizationId: string): Promise<Integration[]>;
  updateIntegrationStatus(organizationId: string, integrationId: string, input: IntegrationStatusUpdate, actorUserId: string): Promise<Integration>;
  rotateIntegrationSecret(organizationId: string, integrationId: string, secretCiphertext: string, actorUserId: string): Promise<Integration>;
  ingestIntegrationDelivery(integration: Integration, externalDeliveryId: string, payloadSha256: string, events: SecurityEventIngestRequest[], indicators: ThreatIndicator[]): Promise<IntegrationDeliveryResult>;
  listIntegrationDeliveries(organizationId: string, integrationId: string): Promise<IntegrationDelivery[]>;
  listThreatIndicators(organizationId: string): Promise<ThreatIndicator[]>;
  createTaxiiSource(organizationId: string, input: TaxiiSourceCreateRequest, authenticationCiphertext: string | undefined, actorUserId: string): Promise<TaxiiSource>;
  getTaxiiSource(organizationId: string, sourceId: string): Promise<TaxiiSource | undefined>;
  getTaxiiSourceCredential(organizationId: string, sourceId: string): Promise<TaxiiSourceCredential | undefined>;
  listTaxiiSources(organizationId: string): Promise<TaxiiSource[]>;
  updateTaxiiSourceStatus(organizationId: string, sourceId: string, input: TaxiiSourceStatusUpdate, actorUserId: string): Promise<TaxiiSource>;
  createTaxiiSyncJob(organizationId: string, sourceId: string, actorUserId: string): Promise<TaxiiSyncJob>;
  appendTaxiiSyncAttempt(organizationId: string, jobId: string, attempt: TaxiiSyncAttempt): Promise<void>;
  finishTaxiiSyncJob(organizationId: string, jobId: string, completion: TaxiiSyncCompletion): Promise<TaxiiSyncJob>;
  listTaxiiSyncJobs(organizationId: string, sourceId: string): Promise<TaxiiSyncJob[]>;
  saveDetectionModel(model: DetectionModel, actorUserId: string): Promise<void>;
  getActiveDetectionModel(organizationId: string): Promise<DetectionModel | undefined>;
  listDetectionModels(organizationId: string): Promise<DetectionModel[]>;
  saveAnomalyFinding(finding: AnomalyFinding): Promise<SaveFindingResult>;
  listAnomalyFindings(organizationId: string): Promise<AnomalyFinding[]>;
  reviewAnomalyFinding(organizationId: string, findingId: string, input: AnomalyFindingDispositionRequest, actorUserId: string): Promise<AnomalyFinding>;
  listEvaluatedEventIds(organizationId: string, modelId: string): Promise<string[]>;
  markEventsEvaluated(organizationId: string, modelId: string, eventIds: string[]): Promise<void>;
  createIncident(incident: Incident, creationFingerprint: string): Promise<CreateIncidentResult>;
  getIncident(organizationId: string, incidentId: string): Promise<Incident | undefined>;
  listIncidents(organizationId: string): Promise<Incident[]>;
  transitionIncident(organizationId: string, incidentId: string, input: IncidentStatusUpdateRequest, actorUserId: string): Promise<Incident>;
  assignIncident(organizationId: string, incidentId: string, input: IncidentAssignmentRequest, actorUserId: string): Promise<Incident>;
  commentOnIncident(organizationId: string, incidentId: string, input: IncidentCommentRequest, actorUserId: string): Promise<Incident>;
  linkIncidentEvidence(organizationId: string, incidentId: string, input: IncidentEvidenceLinkRequest, actorUserId: string): Promise<Incident>;
  createIncidentTask(organizationId: string, incidentId: string, input: IncidentTaskCreateRequest, actorUserId: string): Promise<Incident>;
  updateIncidentTask(organizationId: string, incidentId: string, taskId: string, input: IncidentTaskUpdateRequest, actorUserId: string): Promise<Incident>;
  enrollIdentityUser(organizationId: string, input: IdentityEnrollmentRequest, actorUserId: string): Promise<IdentityUser>;
  listIdentityUsers(organizationId: string): Promise<IdentityAccess[]>;
  resolveIdentity(issuer: string, subject: string, verifiedEmail: string): Promise<IdentityAccess | undefined>;
  createOidcLoginAttempt(attempt: OidcLoginAttempt): Promise<void>;
  consumeOidcLoginAttempt(stateHash: string): Promise<OidcLoginAttempt | undefined>;
  createIdentitySession(input: IdentitySessionCreate): Promise<IdentitySessionRecord>;
  getIdentitySession(tokenHash: string): Promise<IdentitySessionRecord | undefined>;
  revokeIdentitySession(tokenHash: string, reason: string): Promise<boolean>;
}

function nowUtc(clock: Clock): string { return clock.now().toISOString(); }

export class InMemoryCascadiaStore implements CascadiaStore {
  readonly organizations: Organization[] = [];
  readonly retentionPolicies: RetentionPolicy[] = [];
  readonly agents: Agent[] = [];
  readonly assets: Asset[] = [];
  readonly dependencies: AssetDependency[] = [];
  readonly securityEvents: SecurityEvent[] = [];
  readonly vulnerabilities: Vulnerability[] = [];
  readonly criticalServices: CriticalService[] = [];
  readonly riskAnalyses: AttackPathAnalysis[] = [];
  readonly responsePolicies: ResponsePolicy[] = [];
  readonly responseScenarios: ResponseScenario[] = [];
  readonly integrations: Array<IntegrationCredential> = [];
  readonly integrationDeliveries: IntegrationDelivery[] = [];
  readonly threatIndicators: ThreatIndicator[] = [];
  readonly taxiiSources: TaxiiSourceCredential[] = [];
  readonly taxiiSyncJobs: TaxiiSyncJob[] = [];
  readonly detectionModels: DetectionModel[] = [];
  readonly anomalyFindings: AnomalyFinding[] = [];
  readonly detectionEvaluations: Array<{ organizationId: string; modelId: string; eventId: string }> = [];
  readonly incidents: Array<{ incident: Incident; creationFingerprint: string }> = [];
  readonly auditEvents: AuditEvent[] = [];
  readonly auditAnchors: Array<AuditBatchAnchor & { eventIds: string[] }> = [];
  readonly decisionProofs: DecisionProof[] = [];
  readonly posts: PublishedPost[] = [];
  readonly identityUsers: IdentityUser[] = [];
  readonly identityMemberships: Array<{ organizationId: string; userId: string; role: UserRole }> = [];
  readonly identitySubjects: Array<{ issuer: string; subject: string; userId: string }> = [];
  readonly oidcLoginAttempts: OidcLoginAttempt[] = [];
  readonly identitySessions: IdentitySessionRecord[] = [];

  constructor(private readonly clock: Clock = systemClock) {}

  async checkHealth(): Promise<{ status: "ready"; latencyMs: number }> { return { status: "ready", latencyMs: 0 }; }

  async createOrganization(input: OrganizationOnboardingRequest, actorUserId: string): Promise<Organization> {
    const createdAt = nowUtc(this.clock);
    const organization: Organization = { id: randomUUID(), name: input.name, sector: input.sector, createdAt };
    this.organizations.push(organization);
    this.retentionPolicies.push({ ...input.retention, createdAt: nowUtc(this.clock) });
    this.identityMemberships.push({ organizationId: organization.id, userId: actorUserId, role: "organization_admin" });
    this.auditEvents.push(this.audit(organization.id, actorUserId, "organization.created", "organization", organization.id, { retention: input.retention }));
    return organization;
  }

  async getRetentionPolicy(organizationId: string): Promise<RetentionPolicy | undefined> {
    return this.organizations.some((organization) => organization.id === organizationId) ? this.retentionPolicies[this.organizations.findIndex((organization) => organization.id === organizationId)] : undefined;
  }

  async listAuditEvents(organizationId: string, limit: number): Promise<AuditEvent[]> {
    return this.auditEvents.filter((event) => event.organizationId === organizationId).toReversed().slice(0, limit);
  }

  async listUnanchoredAuditEvents(organizationId: string, after?: string): Promise<AuditEvent[]> {
    return this.auditEvents.filter((event) => event.organizationId === organizationId && !this.auditAnchors.some((anchor) => anchor.eventIds.includes(event.id)) && (!after || event.occurredAt > after)).toSorted((a, b) => a.occurredAt.localeCompare(b.occurredAt));
  }

  async listAuditEventsForBatch(organizationId: string, batchId: number): Promise<AuditEvent[]> {
    const anchor = this.auditAnchors.find((entry) => entry.organizationId === organizationId && entry.id === batchId);
    return anchor ? anchor.eventIds.flatMap((id) => this.auditEvents.filter((event) => event.id === id)) : [];
  }

  async listAuditBatchAnchors(organizationId: string): Promise<AuditBatchAnchor[]> {
    return this.auditAnchors.filter((anchor) => anchor.organizationId === organizationId).map(({ eventIds: _eventIds, ...anchor }) => anchor).toReversed();
  }

  async getAuditBatchAnchor(organizationId: string, batchId: number): Promise<AuditBatchAnchor | undefined> {
    const anchor = this.auditAnchors.find((entry) => entry.organizationId === organizationId && entry.id === batchId);
    if (!anchor) return undefined;
    const { eventIds: _eventIds, ...result } = anchor;
    return result;
  }

  async createAuditBatchAnchor(anchor: Omit<AuditBatchAnchor, "id" | "createdAt">, eventIds: string[]): Promise<AuditBatchAnchor> {
    const existing = this.auditAnchors.find((entry) => entry.organizationId === anchor.organizationId && entry.batchStartTime === anchor.batchStartTime && entry.batchEndTime === anchor.batchEndTime);
    if (existing) {
      Object.assign(existing, anchor, { confirmedAt: anchor.confirmedAt ?? existing.confirmedAt });
      if (anchor.anchorStatus === "confirmed") existing.eventIds = eventIds;
      const { eventIds: _eventIds, ...result } = existing;
      return result;
    }
    const result: AuditBatchAnchor & { eventIds: string[] } = { ...anchor, id: this.auditAnchors.length + 1, createdAt: nowUtc(this.clock), eventIds };
    this.auditAnchors.push(result);
    return result;
  }

  async getDecisionProof(organizationId: string, decisionId: string): Promise<DecisionProof | undefined> {
    return this.decisionProofs.find((proof) => proof.organizationId === organizationId && proof.decisionId === decisionId);
  }

  async saveDecisionProof(proof: DecisionProof): Promise<void> {
    const index = this.decisionProofs.findIndex((entry) => entry.decisionId === proof.decisionId);
    if (index >= 0) this.decisionProofs[index] = proof;
    else this.decisionProofs.push(proof);
  }

  async getIdentityUser(userId: string): Promise<IdentityUser | undefined> {
    return this.identityUsers.find((user) => user.id === userId);
  }

  async setWalletAddress(userId: string, walletAddress: string, verifiedAt: string): Promise<IdentityUser> {
    const user = this.identityUsers.find((entry) => entry.id === userId);
    if (!user) throw new NotFoundError("Identity user does not exist.");
    if (this.identityUsers.some((entry) => entry.id !== userId && entry.walletAddress?.toLowerCase() === walletAddress.toLowerCase())) throw new ConflictError("Wallet address is already assigned.");
    const updated = { ...user, walletAddress, walletVerifiedAt: verifiedAt };
    this.identityUsers[this.identityUsers.indexOf(user)] = updated;
    return updated;
  }

  async enrollIdentityUser(organizationId: string, input: IdentityEnrollmentRequest, actorUserId: string): Promise<IdentityUser> {
    this.requireOrganization(organizationId);
    const email = input.email.toLowerCase();
    let user = this.identityUsers.find((entry) => entry.email.toLowerCase() === email);
    if (!user) {
      user = { id: randomUUID(), email, displayName: input.displayName, status: "active" };
      this.identityUsers.push(user);
    }
    const otherMembership = this.identityMemberships.find((entry) => entry.userId === user!.id && entry.organizationId !== organizationId);
    if (otherMembership) throw new ConflictError("An identity may belong to only one Cascadia organization.");
    const membership = this.identityMemberships.find((entry) => entry.organizationId === organizationId && entry.userId === user!.id);
    if (membership) membership.role = input.role;
    else this.identityMemberships.push({ organizationId, userId: user.id, role: input.role });
    this.auditEvents.push(this.audit(organizationId, actorUserId, "identity.user_enrolled", "identity_user", user.id, { email, role: input.role }));
    return user;
  }

  async listIdentityUsers(organizationId: string): Promise<IdentityAccess[]> {
    return this.identityMemberships.filter((entry) => entry.organizationId === organizationId).flatMap((entry) => {
      const user = this.identityUsers.find((candidate) => candidate.id === entry.userId);
      return user ? [{ user, organizationId, role: entry.role }] : [];
    }).toSorted((left, right) => left.user.displayName.localeCompare(right.user.displayName));
  }

  async resolveIdentity(issuer: string, subject: string, verifiedEmail: string): Promise<IdentityAccess | undefined> {
    let binding = this.identitySubjects.find((entry) => entry.issuer === issuer && entry.subject === subject);
    let user = binding ? this.identityUsers.find((entry) => entry.id === binding!.userId) : undefined;
    if (!user) {
      user = this.identityUsers.find((entry) => entry.email.toLowerCase() === verifiedEmail.toLowerCase());
      if (!user) return undefined;
      const issuerBinding = this.identitySubjects.find((entry) => entry.issuer === issuer && entry.userId === user!.id);
      if (issuerBinding && issuerBinding.subject !== subject) return undefined;
      binding = { issuer, subject, userId: user.id };
      this.identitySubjects.push(binding);
    }
    if (user.status !== "active") return undefined;
    const memberships = this.identityMemberships.filter((entry) => entry.userId === user!.id);
    return memberships.length === 1 ? { user, organizationId: memberships[0]!.organizationId, role: memberships[0]!.role } : undefined;
  }

  async createOidcLoginAttempt(attempt: OidcLoginAttempt): Promise<void> {
    this.oidcLoginAttempts.push(attempt);
  }

  async consumeOidcLoginAttempt(stateHash: string): Promise<OidcLoginAttempt | undefined> {
    const index = this.oidcLoginAttempts.findIndex((entry) => entry.stateHash === stateHash);
    if (index < 0) return undefined;
    const [attempt] = this.oidcLoginAttempts.splice(index, 1);
    return attempt && Date.parse(attempt.expiresAt) > this.clock.now().getTime() ? attempt : undefined;
  }

  async createIdentitySession(input: IdentitySessionCreate): Promise<IdentitySessionRecord> {
    const now = nowUtc(this.clock);
    const session: IdentitySessionRecord = { ...input, id: randomUUID(), createdAt: now, lastSeenAt: now };
    this.identitySessions.push(session);
    this.auditEvents.push(this.audit(input.organizationId, input.user.id, "identity.session_created", "identity_session", session.id, { mfaVerified: true }));
    return session;
  }

  async getIdentitySession(tokenHash: string): Promise<IdentitySessionRecord | undefined> {
    const session = this.identitySessions.find((entry) => entry.tokenHash === tokenHash && !entry.revokedAt && Date.parse(entry.expiresAt) > this.clock.now().getTime());
    if (session) session.lastSeenAt = nowUtc(this.clock);
    return session;
  }

  async revokeIdentitySession(tokenHash: string, reason: string): Promise<boolean> {
    const session = this.identitySessions.find((entry) => entry.tokenHash === tokenHash && !entry.revokedAt);
    if (!session) return false;
    session.revokedAt = nowUtc(this.clock);
    this.auditEvents.push(this.audit(session.organizationId, session.user.id, "identity.session_revoked", "identity_session", session.id, { reason }));
    return true;
  }

  async getOrganization(id: string): Promise<Organization | undefined> {
    return this.organizations.find((organization) => organization.id === id);
  }

  async listOrganizations(): Promise<Organization[]> { return [...this.organizations]; }

  async createAgent(input: AgentInitRequest): Promise<Agent> {
    this.requireOrganization(input.organizationId);
    const agent: Agent = { id: randomUUID(), ...input, createdAt: nowUtc(this.clock) };
    this.agents.push(agent);
    this.auditEvents.push(this.audit(input.organizationId, undefined, "agent.initialized", "agent", agent.id, { client: agent.client }));
    return agent;
  }

  async listPosts(organizationId: string): Promise<PublishedPost[]> {
    return this.posts.filter((post) => post.organizationId === organizationId).toSorted((left, right) => right.publishedAt.localeCompare(left.publishedAt));
  }

  async appendPublishedPost(post: PublishedPost): Promise<void> {
    if (this.posts.some((existing) => existing.id === post.id)) throw new ConflictError("Published posts are append-only and IDs cannot be reused.");
    this.posts.push(post);
  }

  async upsertAsset(organizationId: string, input: AssetCreateRequest, actorUserId: string): Promise<UpsertAssetResult> {
    this.requireOrganization(organizationId);
    const existing = this.assets.find((asset) => asset.organizationId === organizationId && asset.externalId === input.externalId);
    const timestamp = nowUtc(this.clock);
    if (existing) {
      Object.assign(existing, input, { updatedAt: timestamp });
      this.auditEvents.push(this.audit(organizationId, actorUserId, "asset.updated", "asset", existing.id, { externalId: input.externalId }));
      return { asset: existing, created: false };
    }
    const asset: Asset = { id: randomUUID(), organizationId, ...input, createdAt: timestamp, updatedAt: timestamp };
    this.assets.push(asset);
    this.auditEvents.push(this.audit(organizationId, actorUserId, "asset.created", "asset", asset.id, { externalId: input.externalId }));
    return { asset, created: true };
  }

  async listAssets(organizationId: string): Promise<Asset[]> {
    return this.assets.filter((asset) => asset.organizationId === organizationId).toSorted((a, b) => a.name.localeCompare(b.name));
  }

  async createDependency(organizationId: string, input: AssetDependencyCreateRequest, actorUserId: string): Promise<AssetDependency> {
    if (input.sourceAssetId === input.targetAssetId) throw new ValidationError("An asset cannot depend on itself.");
    const source = this.assets.find((asset) => asset.id === input.sourceAssetId && asset.organizationId === organizationId);
    const target = this.assets.find((asset) => asset.id === input.targetAssetId && asset.organizationId === organizationId);
    if (!source || !target) throw new NotFoundError("Both dependency assets must exist in the organization.");
    const duplicate = this.dependencies.find((item) => item.organizationId === organizationId && item.sourceAssetId === input.sourceAssetId && item.targetAssetId === input.targetAssetId && item.relationship === input.relationship);
    if (duplicate) return duplicate;
    const dependency: AssetDependency = { id: randomUUID(), organizationId, ...input, createdAt: nowUtc(this.clock) };
    this.dependencies.push(dependency);
    this.auditEvents.push(this.audit(organizationId, actorUserId, "dependency.created", "asset_dependency", dependency.id, {}));
    return dependency;
  }

  async listDependencies(organizationId: string): Promise<AssetDependency[]> {
    return this.dependencies.filter((dependency) => dependency.organizationId === organizationId);
  }

  async ingestSecurityEvent(organizationId: string, input: SecurityEventIngestRequest): Promise<IngestResult> {
    this.requireOrganization(organizationId);
    const existing = this.securityEvents.find((event) => event.organizationId === organizationId && event.source === input.source && event.sourceEventId === input.sourceEventId);
    if (existing) return { event: existing, duplicate: true };
    const event: SecurityEvent = { id: randomUUID(), organizationId, ...input, ingestedAt: nowUtc(this.clock) };
    this.securityEvents.push(event);
    return { event, duplicate: false };
  }

  async listSecurityEvents(organizationId: string): Promise<SecurityEvent[]> {
    return this.securityEvents.filter((event) => event.organizationId === organizationId);
  }

  async upsertVulnerability(organizationId: string, input: VulnerabilityUpsertRequest, actorUserId: string): Promise<UpsertVulnerabilityResult> {
    this.requireOrganization(organizationId);
    if (!this.assets.some((asset) => asset.organizationId === organizationId && asset.id === input.assetId)) throw new NotFoundError("Vulnerability asset does not exist in the organization.");
    const timestamp = nowUtc(this.clock);
    const existing = this.vulnerabilities.find((item) => item.organizationId === organizationId && item.externalId === input.externalId && item.assetId === input.assetId);
    if (existing) {
      Object.assign(existing, input, { updatedAt: timestamp });
      this.auditEvents.push(this.audit(organizationId, actorUserId, "vulnerability.updated", "vulnerability", existing.id, { externalId: input.externalId }));
      return { vulnerability: existing, created: false };
    }
    const vulnerability: Vulnerability = { id: randomUUID(), organizationId, ...input, firstSeenAt: timestamp, updatedAt: timestamp };
    this.vulnerabilities.push(vulnerability);
    this.auditEvents.push(this.audit(organizationId, actorUserId, "vulnerability.created", "vulnerability", vulnerability.id, { externalId: input.externalId }));
    return { vulnerability, created: true };
  }

  async listVulnerabilities(organizationId: string): Promise<Vulnerability[]> {
    return this.vulnerabilities.filter((item) => item.organizationId === organizationId);
  }

  async upsertCriticalService(organizationId: string, input: CriticalServiceUpsertRequest, actorUserId: string): Promise<UpsertCriticalServiceResult> {
    this.requireOrganization(organizationId);
    const validAssetIds = new Set(this.assets.filter((asset) => asset.organizationId === organizationId).map((asset) => asset.id));
    if (input.assetIds.some((assetId) => !validAssetIds.has(assetId))) throw new NotFoundError("Every critical-service asset must exist in the organization.");
    const timestamp = nowUtc(this.clock);
    const existing = this.criticalServices.find((service) => service.organizationId === organizationId && service.name.toLowerCase() === input.name.toLowerCase());
    if (existing) {
      Object.assign(existing, input, { updatedAt: timestamp });
      this.auditEvents.push(this.audit(organizationId, actorUserId, "critical_service.updated", "critical_service", existing.id, {}));
      return { service: existing, created: false };
    }
    const service: CriticalService = { id: randomUUID(), organizationId, ...input, createdAt: timestamp, updatedAt: timestamp };
    this.criticalServices.push(service);
    this.auditEvents.push(this.audit(organizationId, actorUserId, "critical_service.created", "critical_service", service.id, {}));
    return { service, created: true };
  }

  async listCriticalServices(organizationId: string): Promise<CriticalService[]> {
    return this.criticalServices.filter((service) => service.organizationId === organizationId);
  }

  async saveRiskAnalysis(analysis: AttackPathAnalysis, actorUserId: string): Promise<void> {
    this.requireOrganization(analysis.organizationId);
    if (this.riskAnalyses.some((item) => item.id === analysis.id)) throw new ConflictError("Risk analyses are append-only.");
    this.riskAnalyses.push(analysis);
    this.auditEvents.push(this.audit(analysis.organizationId, actorUserId, "risk_analysis.created", "risk_analysis", analysis.id, { pathCount: analysis.paths.length }));
  }

  async listRiskAnalyses(organizationId: string): Promise<AttackPathAnalysis[]> {
    return this.riskAnalyses.filter((analysis) => analysis.organizationId === organizationId).toSorted((a, b) => b.generatedAt.localeCompare(a.generatedAt));
  }

  async getRiskAnalysis(organizationId: string, analysisId: string): Promise<AttackPathAnalysis | undefined> {
    return this.riskAnalyses.find((analysis) => analysis.organizationId === organizationId && analysis.id === analysisId);
  }

  async upsertResponsePolicy(organizationId: string, input: ResponsePolicyUpsertRequest, actorUserId: string): Promise<UpsertResponsePolicyResult> {
    this.requireOrganization(organizationId);
    const timestamp = nowUtc(this.clock);
    const existing = this.responsePolicies.find((policy) => policy.organizationId === organizationId && policy.actionType === input.actionType);
    if (existing) {
      Object.assign(existing, input, { updatedAt: timestamp });
      this.auditEvents.push(this.audit(organizationId, actorUserId, "response_policy.updated", "response_policy", existing.id, {}));
      return { policy: existing, created: false };
    }
    const policy: ResponsePolicy = { id: randomUUID(), organizationId, ...input, createdAt: timestamp, updatedAt: timestamp };
    this.responsePolicies.push(policy);
    this.auditEvents.push(this.audit(organizationId, actorUserId, "response_policy.created", "response_policy", policy.id, {}));
    return { policy, created: true };
  }

  async listResponsePolicies(organizationId: string): Promise<ResponsePolicy[]> {
    return this.responsePolicies.filter((policy) => policy.organizationId === organizationId);
  }

  async saveResponseScenario(scenario: ResponseScenario, actorUserId: string): Promise<void> {
    this.requireOrganization(scenario.organizationId);
    if (this.responseScenarios.some((item) => item.id === scenario.id)) throw new ConflictError("Response scenario ID already exists.");
    this.responseScenarios.push(scenario);
    this.auditEvents.push(this.audit(scenario.organizationId, actorUserId, "response_scenario.created", "response_scenario", scenario.id, { optionCount: scenario.options.length }));
  }

  async getResponseScenario(organizationId: string, scenarioId: string): Promise<ResponseScenario | undefined> {
    return this.responseScenarios.find((scenario) => scenario.organizationId === organizationId && scenario.id === scenarioId);
  }

  async listResponseScenarios(organizationId: string): Promise<ResponseScenario[]> {
    return this.responseScenarios.filter((scenario) => scenario.organizationId === organizationId).toSorted((a, b) => b.generatedAt.localeCompare(a.generatedAt));
  }

  async recordResponseDecision(organizationId: string, scenarioId: string, input: ResponseDecisionRequest, actorUserId: string, actorRole: UserRole): Promise<ResponseScenario> {
    const index = this.responseScenarios.findIndex((scenario) => scenario.organizationId === organizationId && scenario.id === scenarioId);
    if (index < 0) throw new NotFoundError("Response scenario does not exist.");
    const updated = applyResponseDecision(this.responseScenarios[index]!, input, actorUserId, actorRole, this.clock);
    this.responseScenarios[index] = updated;
    const decision = updated.decisions.at(-1)!;
    this.auditEvents.push(this.audit(organizationId, actorUserId, decision.decision === "approve" ? "response.approved" : "response.rejected", "response_scenario", scenarioId, { optionId: input.optionId, status: updated.status }));
    return updated;
  }

  async createIntegration(organizationId: string, input: IntegrationCreateRequest, secretCiphertext: string, actorUserId: string): Promise<Integration> {
    this.requireOrganization(organizationId);
    if (this.integrations.some(({ integration }) => integration.organizationId === organizationId && integration.name.toLowerCase() === input.name.toLowerCase())) throw new ConflictError("An integration with this name already exists.");
    const timestamp = nowUtc(this.clock);
    const integration: Integration = { id: randomUUID(), organizationId, ...input, status: "active", secretVersion: 1, createdAt: timestamp, updatedAt: timestamp };
    this.integrations.push({ integration, secretCiphertext });
    this.auditEvents.push(this.audit(organizationId, actorUserId, "integration.created", "integration", integration.id, { provider: integration.provider, dataType: integration.dataType }));
    return integration;
  }

  async getIntegration(organizationId: string, integrationId: string): Promise<Integration | undefined> {
    return this.integrations.find(({ integration }) => integration.organizationId === organizationId && integration.id === integrationId)?.integration;
  }

  async getIntegrationCredential(integrationId: string): Promise<IntegrationCredential | undefined> {
    return this.integrations.find(({ integration }) => integration.id === integrationId);
  }

  async listIntegrations(organizationId: string): Promise<Integration[]> {
    return this.integrations.filter(({ integration }) => integration.organizationId === organizationId).map(({ integration }) => integration).toSorted((a, b) => a.name.localeCompare(b.name));
  }

  async updateIntegrationStatus(organizationId: string, integrationId: string, input: IntegrationStatusUpdate, actorUserId: string): Promise<Integration> {
    const credential = this.integrations.find(({ integration }) => integration.organizationId === organizationId && integration.id === integrationId);
    if (!credential) throw new NotFoundError("Integration does not exist.");
    credential.integration = { ...credential.integration, status: input.status, updatedAt: nowUtc(this.clock) };
    this.auditEvents.push(this.audit(organizationId, actorUserId, "integration.status_changed", "integration", integrationId, { status: input.status }));
    return credential.integration;
  }

  async rotateIntegrationSecret(organizationId: string, integrationId: string, secretCiphertext: string, actorUserId: string): Promise<Integration> {
    const credential = this.integrations.find(({ integration }) => integration.organizationId === organizationId && integration.id === integrationId);
    if (!credential) throw new NotFoundError("Integration does not exist.");
    credential.secretCiphertext = secretCiphertext;
    credential.integration = { ...credential.integration, secretVersion: credential.integration.secretVersion + 1, updatedAt: nowUtc(this.clock) };
    this.auditEvents.push(this.audit(organizationId, actorUserId, "integration.secret_rotated", "integration", integrationId, { secretVersion: credential.integration.secretVersion }));
    return credential.integration;
  }

  async ingestIntegrationDelivery(integration: Integration, externalDeliveryId: string, payloadSha256: string, events: SecurityEventIngestRequest[], indicators: ThreatIndicator[]): Promise<IntegrationDeliveryResult> {
    const existing = this.integrationDeliveries.find((delivery) => delivery.integrationId === integration.id && delivery.externalDeliveryId === externalDeliveryId);
    if (existing) {
      if (existing.payloadSha256 !== payloadSha256) throw new ConflictError("Delivery ID was already used with different content.");
      return { delivery: existing, duplicate: true };
    }
    for (const input of events) await this.ingestSecurityEvent(integration.organizationId, input);
    for (const indicator of indicators) {
      const index = this.threatIndicators.findIndex((item) => item.organizationId === integration.organizationId && item.stixId === indicator.stixId);
      if (index < 0) this.threatIndicators.push(indicator);
      else if (this.threatIndicators[index]!.modifiedAt <= indicator.modifiedAt) this.threatIndicators[index] = { ...indicator, id: this.threatIndicators[index]!.id };
    }
    const receivedAt = nowUtc(this.clock);
    const delivery: IntegrationDelivery = { id: randomUUID(), organizationId: integration.organizationId, integrationId: integration.id, externalDeliveryId, payloadSha256, eventCount: events.length, indicatorCount: indicators.length, receivedAt };
    this.integrationDeliveries.push(delivery);
    const credential = this.integrations.find((item) => item.integration.id === integration.id)!;
    credential.integration = { ...credential.integration, lastDeliveryAt: receivedAt, updatedAt: receivedAt };
    this.auditEvents.push(this.audit(integration.organizationId, undefined, "integration.delivery_received", "integration_delivery", delivery.id, { integrationId: integration.id, eventCount: events.length, indicatorCount: indicators.length }));
    return { delivery, duplicate: false };
  }

  async listIntegrationDeliveries(organizationId: string, integrationId: string): Promise<IntegrationDelivery[]> {
    return this.integrationDeliveries.filter((delivery) => delivery.organizationId === organizationId && delivery.integrationId === integrationId).toSorted((a, b) => b.receivedAt.localeCompare(a.receivedAt));
  }

  async listThreatIndicators(organizationId: string): Promise<ThreatIndicator[]> {
    return this.threatIndicators.filter((indicator) => indicator.organizationId === organizationId).toSorted((a, b) => b.modifiedAt.localeCompare(a.modifiedAt));
  }

  async createTaxiiSource(organizationId: string, input: TaxiiSourceCreateRequest, authenticationCiphertext: string | undefined, actorUserId: string): Promise<TaxiiSource> {
    this.requireOrganization(organizationId);
    const integration = await this.getIntegration(organizationId, input.integrationId);
    if (!integration || integration.provider !== "taxii" || integration.dataType !== "stix_bundle") throw new ValidationError("TAXII sources require a TAXII STIX-bundle integration in the same organization.");
    if (this.taxiiSources.some(({ source }) => source.organizationId === organizationId && source.name.toLowerCase() === input.name.toLowerCase())) throw new ConflictError("A TAXII source with this name already exists.");
    const timestamp = nowUtc(this.clock);
    const source: TaxiiSource = { id: randomUUID(), organizationId, integrationId: input.integrationId, name: input.name, apiRootUrl: input.apiRootUrl, collectionId: input.collectionId, authenticationType: input.authentication.type, status: "active", autonomousSchedulingEnabled: false, createdAt: timestamp, updatedAt: timestamp };
    this.taxiiSources.push({ source, ...(authenticationCiphertext ? { authenticationCiphertext } : {}) });
    this.auditEvents.push(this.audit(organizationId, actorUserId, "taxii_source.created", "taxii_source", source.id, { integrationId: input.integrationId, authenticationType: source.authenticationType }));
    return source;
  }

  async getTaxiiSource(organizationId: string, sourceId: string): Promise<TaxiiSource | undefined> {
    return this.taxiiSources.find(({ source }) => source.organizationId === organizationId && source.id === sourceId)?.source;
  }

  async getTaxiiSourceCredential(organizationId: string, sourceId: string): Promise<TaxiiSourceCredential | undefined> {
    return this.taxiiSources.find(({ source }) => source.organizationId === organizationId && source.id === sourceId);
  }

  async listTaxiiSources(organizationId: string): Promise<TaxiiSource[]> {
    return this.taxiiSources.filter(({ source }) => source.organizationId === organizationId).map(({ source }) => source).toSorted((a, b) => a.name.localeCompare(b.name));
  }

  async updateTaxiiSourceStatus(organizationId: string, sourceId: string, input: TaxiiSourceStatusUpdate, actorUserId: string): Promise<TaxiiSource> {
    const credential = this.taxiiSources.find(({ source }) => source.organizationId === organizationId && source.id === sourceId);
    if (!credential) throw new NotFoundError("TAXII source does not exist.");
    credential.source = { ...credential.source, status: input.status, updatedAt: nowUtc(this.clock) };
    this.auditEvents.push(this.audit(organizationId, actorUserId, "taxii_source.status_changed", "taxii_source", sourceId, { status: input.status }));
    return credential.source;
  }

  async createTaxiiSyncJob(organizationId: string, sourceId: string, actorUserId: string): Promise<TaxiiSyncJob> {
    const source = await this.getTaxiiSource(organizationId, sourceId);
    if (!source) throw new NotFoundError("TAXII source does not exist.");
    if (this.taxiiSyncJobs.some((job) => job.organizationId === organizationId && job.sourceId === sourceId && job.status === "running")) throw new ConflictError("A TAXII sync is already running for this source.");
    const job: TaxiiSyncJob = { id: randomUUID(), organizationId, sourceId, status: "running", requestedByUserId: actorUserId, startedAt: nowUtc(this.clock), ...(source.checkpointAddedAfter ? { checkpointBefore: source.checkpointAddedAfter } : {}), pagesFetched: 0, objectsReceived: 0, indicatorsAccepted: 0, attempts: [] };
    this.taxiiSyncJobs.push(job);
    this.auditEvents.push(this.audit(organizationId, actorUserId, "taxii_sync.started", "taxii_sync_job", job.id, { sourceId }));
    return job;
  }

  async appendTaxiiSyncAttempt(organizationId: string, jobId: string, attempt: TaxiiSyncAttempt): Promise<void> {
    const job = this.taxiiSyncJobs.find((item) => item.organizationId === organizationId && item.id === jobId);
    if (!job) throw new NotFoundError("TAXII sync job does not exist.");
    if (job.attempts.some((item) => item.id === attempt.id)) throw new ConflictError("TAXII sync attempts are append-only.");
    job.attempts.push(attempt);
  }

  async finishTaxiiSyncJob(organizationId: string, jobId: string, completion: TaxiiSyncCompletion): Promise<TaxiiSyncJob> {
    const index = this.taxiiSyncJobs.findIndex((item) => item.organizationId === organizationId && item.id === jobId);
    if (index < 0) throw new NotFoundError("TAXII sync job does not exist.");
    const current = this.taxiiSyncJobs[index]!;
    if (current.status !== "running") throw new ConflictError("TAXII sync job is already final.");
    const completedAt = nowUtc(this.clock);
    const updated: TaxiiSyncJob = { ...current, ...completion, completedAt };
    this.taxiiSyncJobs[index] = updated;
    if (completion.status === "succeeded") {
      const credential = this.taxiiSources.find(({ source }) => source.organizationId === organizationId && source.id === current.sourceId)!;
      credential.source = { ...credential.source, ...(completion.checkpointAfter ? { checkpointAddedAfter: completion.checkpointAfter } : {}), lastSyncAt: completedAt, updatedAt: completedAt };
    }
    this.auditEvents.push(this.audit(organizationId, current.requestedByUserId, completion.status === "succeeded" ? "taxii_sync.succeeded" : "taxii_sync.failed", "taxii_sync_job", jobId, { sourceId: current.sourceId, pagesFetched: completion.pagesFetched, objectsReceived: completion.objectsReceived, errorCode: completion.errorCode }));
    return updated;
  }

  async listTaxiiSyncJobs(organizationId: string, sourceId: string): Promise<TaxiiSyncJob[]> {
    return this.taxiiSyncJobs.filter((job) => job.organizationId === organizationId && job.sourceId === sourceId).toSorted((a, b) => b.startedAt.localeCompare(a.startedAt));
  }

  async saveDetectionModel(model: DetectionModel, actorUserId: string): Promise<void> {
    this.requireOrganization(model.organizationId);
    if (this.detectionModels.some((item) => item.id === model.id || (item.organizationId === model.organizationId && item.version === model.version))) throw new ConflictError("Detection model version already exists.");
    for (let index = 0; index < this.detectionModels.length; index += 1) {
      const existing = this.detectionModels[index]!;
      if (existing.organizationId === model.organizationId && existing.status === "active") this.detectionModels[index] = { ...existing, status: "retired" };
    }
    this.detectionModels.push(model);
    this.auditEvents.push(this.audit(model.organizationId, actorUserId, "detection_model.trained", "detection_model", model.id, { version: model.version, trainingEventCount: model.trainingEventCount }));
  }

  async getActiveDetectionModel(organizationId: string): Promise<DetectionModel | undefined> {
    return this.detectionModels.find((model) => model.organizationId === organizationId && model.status === "active");
  }

  async listDetectionModels(organizationId: string): Promise<DetectionModel[]> {
    return this.detectionModels.filter((model) => model.organizationId === organizationId).toSorted((a, b) => b.version - a.version);
  }

  async saveAnomalyFinding(finding: AnomalyFinding): Promise<SaveFindingResult> {
    const existing = this.anomalyFindings.find((item) => item.organizationId === finding.organizationId && item.modelId === finding.modelId && item.eventId === finding.eventId);
    if (existing) return { finding: existing, created: false };
    this.anomalyFindings.push(finding);
    this.auditEvents.push(this.audit(finding.organizationId, undefined, "anomaly_finding.created", "anomaly_finding", finding.id, { modelId: finding.modelId, eventId: finding.eventId, anomalyScore: finding.anomalyScore }));
    return { finding, created: true };
  }

  async listAnomalyFindings(organizationId: string): Promise<AnomalyFinding[]> {
    return this.anomalyFindings.filter((finding) => finding.organizationId === organizationId).toSorted((a, b) => b.createdAt.localeCompare(a.createdAt));
  }

  async reviewAnomalyFinding(organizationId: string, findingId: string, input: AnomalyFindingDispositionRequest, actorUserId: string): Promise<AnomalyFinding> {
    const index = this.anomalyFindings.findIndex((finding) => finding.organizationId === organizationId && finding.id === findingId);
    if (index < 0) throw new NotFoundError("Anomaly finding does not exist.");
    const finding = this.anomalyFindings[index]!;
    const review = { id: randomUUID(), findingId, analystUserId: actorUserId, disposition: input.disposition, comment: input.comment, reviewedAt: nowUtc(this.clock) };
    const updated: AnomalyFinding = { ...finding, disposition: input.disposition, reviews: [...finding.reviews, review] };
    this.anomalyFindings[index] = updated;
    this.auditEvents.push(this.audit(organizationId, actorUserId, "anomaly_finding.reviewed", "anomaly_finding", findingId, { disposition: input.disposition }));
    return updated;
  }

  async listEvaluatedEventIds(organizationId: string, modelId: string): Promise<string[]> {
    return this.detectionEvaluations.filter((item) => item.organizationId === organizationId && item.modelId === modelId).map((item) => item.eventId);
  }

  async markEventsEvaluated(organizationId: string, modelId: string, eventIds: string[]): Promise<void> {
    for (const eventId of new Set(eventIds)) {
      if (!this.detectionEvaluations.some((item) => item.organizationId === organizationId && item.modelId === modelId && item.eventId === eventId)) this.detectionEvaluations.push({ organizationId, modelId, eventId });
    }
  }

  async createIncident(incident: Incident, creationFingerprint: string): Promise<CreateIncidentResult> {
    this.requireOrganization(incident.organizationId);
    const existing = this.incidents.find(({ incident: item }) => item.organizationId === incident.organizationId && item.idempotencyKey === incident.idempotencyKey);
    if (existing) {
      if (existing.creationFingerprint !== creationFingerprint) throw new ConflictError("Idempotency key was already used with different incident data.");
      return { incident: existing.incident, created: false };
    }
    this.incidents.push({ incident, creationFingerprint });
    this.auditEvents.push(this.audit(incident.organizationId, incident.createdByUserId, "incident.created", "incident", incident.id, { reference: incident.reference, priority: incident.priority }));
    return { incident, created: true };
  }

  async getIncident(organizationId: string, incidentId: string): Promise<Incident | undefined> {
    return this.incidents.find(({ incident }) => incident.organizationId === organizationId && incident.id === incidentId)?.incident;
  }

  async listIncidents(organizationId: string): Promise<Incident[]> {
    return this.incidents.filter(({ incident }) => incident.organizationId === organizationId).map(({ incident }) => incident).toSorted((a, b) => b.updatedAt.localeCompare(a.updatedAt));
  }

  private mutateIncident(organizationId: string, incidentId: string, actorUserId: string, eventType: string, update: (incident: Incident) => Incident): Incident {
    const index = this.incidents.findIndex(({ incident }) => incident.organizationId === organizationId && incident.id === incidentId);
    if (index < 0) throw new NotFoundError("Incident does not exist.");
    const updated = update(this.incidents[index]!.incident);
    this.incidents[index] = { ...this.incidents[index]!, incident: updated };
    this.auditEvents.push(this.audit(organizationId, actorUserId, eventType, "incident", incidentId, {}));
    return updated;
  }

  async transitionIncident(organizationId: string, incidentId: string, input: IncidentStatusUpdateRequest, actorUserId: string): Promise<Incident> {
    return this.mutateIncident(organizationId, incidentId, actorUserId, "incident.status_changed", (incident) => transitionIncident(incident, input, actorUserId, this.clock));
  }

  async assignIncident(organizationId: string, incidentId: string, input: IncidentAssignmentRequest, actorUserId: string): Promise<Incident> {
    return this.mutateIncident(organizationId, incidentId, actorUserId, "incident.assignment_changed", (incident) => assignIncident(incident, input, actorUserId, this.clock));
  }

  async commentOnIncident(organizationId: string, incidentId: string, input: IncidentCommentRequest, actorUserId: string): Promise<Incident> {
    return this.mutateIncident(organizationId, incidentId, actorUserId, "incident.commented", (incident) => commentOnIncident(incident, input, actorUserId, this.clock));
  }

  async linkIncidentEvidence(organizationId: string, incidentId: string, input: IncidentEvidenceLinkRequest, actorUserId: string): Promise<Incident> {
    return this.mutateIncident(organizationId, incidentId, actorUserId, "incident.evidence_linked", (incident) => linkIncidentEvidence(incident, input, actorUserId, this.clock));
  }

  async createIncidentTask(organizationId: string, incidentId: string, input: IncidentTaskCreateRequest, actorUserId: string): Promise<Incident> {
    return this.mutateIncident(organizationId, incidentId, actorUserId, "incident.task_created", (incident) => createIncidentTask(incident, input, actorUserId, this.clock));
  }

  async updateIncidentTask(organizationId: string, incidentId: string, taskId: string, input: IncidentTaskUpdateRequest, actorUserId: string): Promise<Incident> {
    return this.mutateIncident(organizationId, incidentId, actorUserId, "incident.task_updated", (incident) => updateIncidentTask(incident, taskId, input, actorUserId, this.clock));
  }

  private audit(organizationId: string, actorUserId: string | undefined, eventType: string, resourceType: string, resourceId: string, metadata: Record<string, unknown>): AuditEvent {
    return { id: randomUUID(), organizationId, ...(actorUserId ? { actorUserId } : {}), eventType, resourceType, resourceId, occurredAt: nowUtc(this.clock), metadata };
  }

  private requireOrganization(organizationId: string): void {
    if (!this.organizations.some((organization) => organization.id === organizationId)) throw new NotFoundError("Organization does not exist.");
  }
}

export class ConflictError extends Error { readonly statusCode = 409; }
export class NotFoundError extends Error { readonly statusCode = 404; }
export class ValidationError extends Error { readonly statusCode = 400; }

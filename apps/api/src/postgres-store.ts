import { randomUUID } from "node:crypto";
import type {
  Agent, AgentInitRequest, AnomalyFinding, AnomalyFindingDispositionRequest, Asset, AssetCreateRequest, AssetDependency, AuditEvent, RetentionPolicy,
  AssetDependencyCreateRequest, AttackPathAnalysis, CriticalService,
  CriticalServiceUpsertRequest, Integration, IntegrationCreateRequest, IntegrationDelivery,
  IntegrationDeliveryResult, IntegrationStatusUpdate, Organization, OrganizationOnboardingRequest,
  PublishedPost, ResponseDecisionRequest, ResponsePolicy, ResponsePolicyUpsertRequest,
  ResponseScenario, SecurityEvent, SecurityEventIngestRequest, UserRole,
  TaxiiSource, TaxiiSourceCreateRequest, TaxiiSourceStatusUpdate, TaxiiSyncAttempt,
  TaxiiSyncJob, ThreatIndicator, DetectionModel, Vulnerability, VulnerabilityUpsertRequest, Incident,
  IncidentAssignmentRequest, IncidentCommentRequest, IncidentEvidenceLinkRequest, IncidentStatusUpdateRequest,
  IncidentTaskCreateRequest, IncidentTaskUpdateRequest, IdentityEnrollmentRequest, IdentityUser,
  AuditBatchAnchor, DecisionProof,
} from "@cascadia/contracts";
import { Pool, type PoolClient, type QueryResultRow } from "pg";
import { applyResponseDecision } from "./response-workflow.js";
import { assignIncident, commentOnIncident, createIncidentTask, linkIncidentEvidence, transitionIncident, updateIncidentTask } from "./incident-workflow.js";
import { systemClock, type CascadiaStore, type CreateIncidentResult, type IdentityAccess, type IdentitySessionCreate, type IdentitySessionRecord, type IngestResult, type IntegrationCredential, type OidcLoginAttempt, type SaveFindingResult, type TaxiiSourceCredential, type TaxiiSyncCompletion, type UpsertAssetResult, type UpsertCriticalServiceResult, type UpsertResponsePolicyResult, type UpsertVulnerabilityResult } from "./store.js";

function iso(value: unknown): string {
  return (value instanceof Date ? value : new Date(String(value))).toISOString();
}

function organization(row: QueryResultRow): Organization {
  return { id: String(row.id), name: String(row.name), sector: row.sector as Organization["sector"], createdAt: iso(row.created_at) };
}

function auditEvent(row: QueryResultRow): AuditEvent {
  return { id: String(row.id), organizationId: String(row.organization_id), ...(row.actor_user_id ? { actorUserId: String(row.actor_user_id) } : {}), eventType: String(row.event_type), resourceType: String(row.resource_type), resourceId: String(row.resource_id), occurredAt: iso(row.occurred_at), metadata: (row.metadata ?? {}) as Record<string, unknown> };
}

function identityUser(row: QueryResultRow): IdentityUser {
  return {
    id: String(row.user_id ?? row.id), email: String(row.email), displayName: String(row.display_name), status: row.status as IdentityUser["status"],
    ...(row.wallet_address ? { walletAddress: String(row.wallet_address) } : {}),
    ...(row.wallet_verified_at ? { walletVerifiedAt: iso(row.wallet_verified_at) } : {}),
  };
}

function auditBatchAnchor(row: QueryResultRow): AuditBatchAnchor {
  return {
    id: Number(row.id), organizationId: String(row.organization_id), batchStartTime: iso(row.batch_start_time),
    batchEndTime: iso(row.batch_end_time), eventCount: Number(row.event_count), merkleRoot: String(row.merkle_root),
    ...(row.chain_batch_id !== null && row.chain_batch_id !== undefined ? { chainBatchId: Number(row.chain_batch_id) } : {}),
    ...(row.tx_hash ? { txHash: String(row.tx_hash) } : {}), ...(row.block_number !== null && row.block_number !== undefined ? { blockNumber: Number(row.block_number) } : {}),
    ...(row.mstscan_url ? { mstscanUrl: String(row.mstscan_url) } : {}), anchorStatus: row.anchor_status as AuditBatchAnchor["anchorStatus"],
    createdAt: iso(row.created_at), ...(row.confirmed_at ? { confirmedAt: iso(row.confirmed_at) } : {}),
  };
}

function decisionProof(row: QueryResultRow): DecisionProof {
  return {
    decisionId: String(row.decision_id), organizationId: String(row.organization_id), evidenceHash: String(row.evidence_hash),
    approverWalletAddress: String(row.approver_wallet_address), signature: String(row.signature),
    ...(row.tx_hash ? { txHash: String(row.tx_hash) } : {}), ...(row.contract_address ? { contractAddress: String(row.contract_address) } : {}),
    ...(row.block_number !== null && row.block_number !== undefined ? { blockNumber: Number(row.block_number) } : {}),
    ...(row.mstscan_url ? { mstscanUrl: String(row.mstscan_url) } : {}), anchorStatus: row.anchor_status as DecisionProof["anchorStatus"],
    createdAt: iso(row.created_at), ...(row.confirmed_at ? { confirmedAt: iso(row.confirmed_at) } : {}),
  };
}

function identitySession(row: QueryResultRow): IdentitySessionRecord {
  return {
    id: String(row.id), tokenHash: String(row.token_hash), csrfTokenHash: String(row.csrf_token_hash),
    user: identityUser(row), organizationId: String(row.organization_id), role: row.role as UserRole, mfaVerified: true,
    issuer: String(row.issuer), subject: String(row.subject), createdAt: iso(row.created_at), lastSeenAt: iso(row.last_seen_at),
    expiresAt: iso(row.expires_at), ...(row.revoked_at ? { revokedAt: iso(row.revoked_at) } : {}),
  };
}

function agent(row: QueryResultRow): Agent {
  return { id: String(row.id), organizationId: String(row.organization_id), client: row.client as Agent["client"], displayName: String(row.display_name), createdAt: iso(row.created_at) };
}

function asset(row: QueryResultRow): Asset {
  return {
    id: String(row.id), organizationId: String(row.organization_id), externalId: String(row.external_id),
    name: String(row.name), assetType: row.asset_type as Asset["assetType"], criticality: row.criticality as Asset["criticality"],
    classification: row.classification as Asset["classification"], ...(row.owner_user_id ? { ownerUserId: String(row.owner_user_id) } : {}),
    ...(row.hostname ? { hostname: String(row.hostname) } : {}), ...(row.ip_address ? { ipAddress: String(row.ip_address) } : {}),
    metadata: (row.metadata ?? {}) as Record<string, unknown>, createdAt: iso(row.created_at), updatedAt: iso(row.updated_at),
  };
}

function dependency(row: QueryResultRow): AssetDependency {
  return {
    id: String(row.id), organizationId: String(row.organization_id), sourceAssetId: String(row.source_asset_id),
    targetAssetId: String(row.target_asset_id), relationship: row.relationship as AssetDependency["relationship"],
    ...(row.protocol ? { protocol: String(row.protocol) } : {}), critical: Boolean(row.critical), createdAt: iso(row.created_at),
  };
}

function securityEvent(row: QueryResultRow): SecurityEvent {
  return {
    id: String(row.id), organizationId: String(row.organization_id), source: row.source as SecurityEvent["source"],
    sourceEventId: String(row.source_event_id), eventType: String(row.event_type), severity: row.severity as SecurityEvent["severity"],
    observedAt: iso(row.observed_at), ingestedAt: iso(row.ingested_at), assetExternalIds: row.asset_external_ids as string[],
    record: row.record as Record<string, unknown>,
  };
}

function vulnerability(row: QueryResultRow): Vulnerability {
  return {
    id: String(row.id), organizationId: String(row.organization_id), assetId: String(row.asset_id), externalId: String(row.external_id),
    title: String(row.title), cvssScore: Number(row.cvss_score), exploitStatus: row.exploit_status as Vulnerability["exploitStatus"],
    status: row.status as Vulnerability["status"], sourceUrls: row.source_urls as string[], firstSeenAt: iso(row.first_seen_at), updatedAt: iso(row.updated_at),
  };
}

function criticalService(row: QueryResultRow, assetIds: string[]): CriticalService {
  return {
    id: String(row.id), organizationId: String(row.organization_id), name: String(row.name), description: String(row.description),
    criticality: row.criticality as CriticalService["criticality"], recoveryTimeMinutes: Number(row.recovery_time_minutes),
    maximumTolerableDowntimeMinutes: Number(row.maximum_tolerable_downtime_minutes), assetIds,
    createdAt: iso(row.created_at), updatedAt: iso(row.updated_at),
  };
}

function responsePolicy(row: QueryResultRow): ResponsePolicy {
  return {
    id: String(row.id), organizationId: String(row.organization_id), name: String(row.name), actionType: row.action_type as ResponsePolicy["actionType"],
    mode: row.mode as ResponsePolicy["mode"], maximumOperationalImpact: Number(row.maximum_operational_impact), minimumApprovals: Number(row.minimum_approvals),
    approvalRoles: row.approval_roles as UserRole[], requiresRollbackPlan: Boolean(row.requires_rollback_plan), createdAt: iso(row.created_at), updatedAt: iso(row.updated_at),
  };
}

function integration(row: QueryResultRow): Integration {
  return {
    id: String(row.id), organizationId: String(row.organization_id), name: String(row.name), provider: row.provider as Integration["provider"],
    dataType: row.data_type as Integration["dataType"], ...(row.event_source ? { eventSource: row.event_source as Integration["eventSource"] } : {}),
    status: row.status as Integration["status"], secretVersion: Number(row.secret_version), ...(row.last_delivery_at ? { lastDeliveryAt: iso(row.last_delivery_at) } : {}),
    createdAt: iso(row.created_at), updatedAt: iso(row.updated_at),
  };
}

function integrationDelivery(row: QueryResultRow): IntegrationDelivery {
  return {
    id: String(row.id), organizationId: String(row.organization_id), integrationId: String(row.integration_id),
    externalDeliveryId: String(row.external_delivery_id), payloadSha256: String(row.payload_sha256), eventCount: Number(row.event_count),
    indicatorCount: Number(row.indicator_count), receivedAt: iso(row.received_at),
  };
}

function threatIndicator(row: QueryResultRow): ThreatIndicator {
  return {
    id: String(row.id), organizationId: String(row.organization_id), integrationId: String(row.integration_id), stixId: String(row.stix_id),
    name: String(row.name), description: String(row.description), pattern: String(row.pattern), confidence: Number(row.confidence),
    labels: row.labels as string[], sourceUrls: row.source_urls as string[], validFrom: iso(row.valid_from),
    ...(row.valid_until ? { validUntil: iso(row.valid_until) } : {}), modifiedAt: iso(row.modified_at), ingestedAt: iso(row.ingested_at),
  };
}

function taxiiSource(row: QueryResultRow): TaxiiSource {
  return {
    id: String(row.id), organizationId: String(row.organization_id), integrationId: String(row.integration_id), name: String(row.name),
    apiRootUrl: String(row.api_root_url), collectionId: String(row.collection_id), authenticationType: row.authentication_type as TaxiiSource["authenticationType"],
    status: row.status as TaxiiSource["status"], ...(row.checkpoint_added_after ? { checkpointAddedAfter: iso(row.checkpoint_added_after) } : {}),
    ...(row.last_sync_at ? { lastSyncAt: iso(row.last_sync_at) } : {}), autonomousSchedulingEnabled: false,
    createdAt: iso(row.created_at), updatedAt: iso(row.updated_at),
  };
}

function taxiiSyncAttempt(row: QueryResultRow): TaxiiSyncAttempt {
  return {
    id: String(row.id), jobId: String(row.job_id), pageNumber: Number(row.page_number), attemptNumber: Number(row.attempt_number),
    status: row.status as TaxiiSyncAttempt["status"], ...(row.http_status ? { httpStatus: Number(row.http_status) } : {}),
    ...(row.error_code ? { errorCode: String(row.error_code) } : {}), startedAt: iso(row.started_at), completedAt: iso(row.completed_at),
  };
}

function taxiiSyncJob(row: QueryResultRow, attempts: TaxiiSyncAttempt[] = []): TaxiiSyncJob {
  return {
    id: String(row.id), organizationId: String(row.organization_id), sourceId: String(row.source_id), status: row.status as TaxiiSyncJob["status"],
    requestedByUserId: String(row.requested_by_user_id), startedAt: iso(row.started_at), ...(row.completed_at ? { completedAt: iso(row.completed_at) } : {}),
    ...(row.checkpoint_before ? { checkpointBefore: iso(row.checkpoint_before) } : {}), ...(row.checkpoint_after ? { checkpointAfter: iso(row.checkpoint_after) } : {}),
    pagesFetched: Number(row.pages_fetched), objectsReceived: Number(row.objects_received), indicatorsAccepted: Number(row.indicators_accepted),
    ...(row.error_code ? { errorCode: String(row.error_code) } : {}), ...(row.error_message ? { errorMessage: String(row.error_message) } : {}), attempts,
  };
}

function detectionModel(row: QueryResultRow): DetectionModel {
  return { ...(row.result as DetectionModel), status: row.status as DetectionModel["status"] };
}

function anomalyFinding(row: QueryResultRow): AnomalyFinding {
  return { ...(row.result as AnomalyFinding), disposition: row.disposition as AnomalyFinding["disposition"] };
}

function incident(row: QueryResultRow): Incident {
  return row.result as Incident;
}

export class PostgresCascadiaStore implements CascadiaStore {
  private readonly pool: Pool;

  constructor(connectionString: string) {
    this.pool = new Pool({ connectionString, max: 20, idleTimeoutMillis: 30_000, connectionTimeoutMillis: 5_000 });
  }

  async close(): Promise<void> { await this.pool.end(); }

  async checkHealth(): Promise<{ status: "ready"; latencyMs: number }> {
    const started = performance.now();
    await this.pool.query("SELECT 1");
    return { status: "ready", latencyMs: Math.round(performance.now() - started) };
  }

  async createOrganization(input: OrganizationOnboardingRequest, actorUserId: string): Promise<Organization> {
    return this.transaction(async (client) => {
      const result = await client.query("INSERT INTO organizations (name, sector) VALUES ($1,$2) RETURNING *", [input.name, input.sector]);
      const row = required(result.rows[0]);
      await client.query("INSERT INTO memberships (organization_id,user_id,role) VALUES ($1,$2,'organization_admin')", [row.id, actorUserId]);
      await client.query("INSERT INTO retention_policies (organization_id,raw_events_days,normalized_events_days,audit_evidence_days) VALUES ($1,$2,$3,$4)", [row.id, input.retention.rawEventsDays, input.retention.normalizedEventsDays, input.retention.auditEvidenceDays]);
      await client.query("INSERT INTO audit_events (organization_id,actor_user_id,event_type,resource_type,resource_id,metadata) VALUES ($1::uuid,$2,'organization.created','organization',$1::uuid::text,$3)", [row.id, actorUserId, JSON.stringify({ retention: input.retention })]);
      return organization(row);
    });
  }

  async getOrganization(id: string): Promise<Organization | undefined> {
    const result = await this.pool.query("SELECT * FROM organizations WHERE id=$1", [id]);
    return result.rows[0] ? organization(result.rows[0]) : undefined;
  }

  async listOrganizations(): Promise<Organization[]> {
    const result = await this.pool.query("SELECT * FROM organizations ORDER BY created_at");
    return result.rows.map(organization);
  }

  async getRetentionPolicy(organizationId: string): Promise<RetentionPolicy | undefined> {
    const result = await this.pool.query("SELECT raw_events_days, normalized_events_days, audit_evidence_days, created_at FROM retention_policies WHERE organization_id=$1", [organizationId]);
    const row = result.rows[0];
    return row ? { rawEventsDays: Number(row.raw_events_days), normalizedEventsDays: Number(row.normalized_events_days), auditEvidenceDays: Number(row.audit_evidence_days), createdAt: iso(row.created_at) } : undefined;
  }

  async listAuditEvents(organizationId: string, limit: number): Promise<AuditEvent[]> {
    const result = await this.pool.query("SELECT * FROM audit_events WHERE organization_id=$1 ORDER BY occurred_at DESC LIMIT $2", [organizationId, limit]);
    return result.rows.map(auditEvent);
  }

  async listUnanchoredAuditEvents(organizationId: string, after?: string): Promise<AuditEvent[]> {
    const result = await this.pool.query(`SELECT e.* FROM audit_events e
      WHERE e.organization_id=$1 AND e.included_in_anchor_id IS NULL ${after ? "AND e.occurred_at > $2" : ""}
      ORDER BY e.occurred_at ASC`, after ? [organizationId, after] : [organizationId]);
    return result.rows.map(auditEvent);
  }

  async listAuditEventsForBatch(organizationId: string, batchId: number): Promise<AuditEvent[]> {
    const result = await this.pool.query("SELECT e.* FROM audit_events e JOIN audit_batch_anchors a ON a.id=e.included_in_anchor_id WHERE a.organization_id=$1 AND a.id=$2 ORDER BY e.occurred_at ASC, e.id ASC", [organizationId, batchId]);
    return result.rows.map(auditEvent);
  }

  async listAuditBatchAnchors(organizationId: string): Promise<AuditBatchAnchor[]> {
    const result = await this.pool.query("SELECT * FROM audit_batch_anchors WHERE organization_id=$1 ORDER BY created_at DESC", [organizationId]);
    return result.rows.map(auditBatchAnchor);
  }

  async getAuditBatchAnchor(organizationId: string, batchId: number): Promise<AuditBatchAnchor | undefined> {
    const result = await this.pool.query("SELECT * FROM audit_batch_anchors WHERE organization_id=$1 AND id=$2", [organizationId, batchId]);
    return result.rows[0] ? auditBatchAnchor(result.rows[0]) : undefined;
  }

  async createAuditBatchAnchor(anchor: Omit<AuditBatchAnchor, "id" | "createdAt">, eventIds: string[]): Promise<AuditBatchAnchor> {
    return this.transaction(async (client) => {
      const result = await client.query(`INSERT INTO audit_batch_anchors
        (organization_id,batch_start_time,batch_end_time,event_count,merkle_root,chain_batch_id,tx_hash,block_number,mstscan_url,anchor_status,confirmed_at)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
        ON CONFLICT (organization_id,batch_start_time,batch_end_time) DO UPDATE SET
          merkle_root=EXCLUDED.merkle_root,chain_batch_id=EXCLUDED.chain_batch_id,tx_hash=EXCLUDED.tx_hash,block_number=EXCLUDED.block_number,
          mstscan_url=EXCLUDED.mstscan_url,anchor_status=EXCLUDED.anchor_status,confirmed_at=EXCLUDED.confirmed_at
        RETURNING *`, [
        anchor.organizationId, anchor.batchStartTime, anchor.batchEndTime, anchor.eventCount, anchor.merkleRoot, anchor.chainBatchId ?? null,
        anchor.txHash ?? null, anchor.blockNumber ?? null, anchor.mstscanUrl ?? null, anchor.anchorStatus, anchor.confirmedAt ?? null,
      ]);
      const saved = auditBatchAnchor(required(result.rows[0]));
      if (eventIds.length) await client.query("UPDATE audit_events SET included_in_anchor_id=$1 WHERE organization_id=$2 AND id=ANY($3::uuid[])", [saved.id, anchor.organizationId, eventIds]);
      return saved;
    });
  }

  async getDecisionProof(organizationId: string, decisionId: string): Promise<DecisionProof | undefined> {
    const result = await this.pool.query("SELECT * FROM decision_proofs WHERE organization_id=$1 AND decision_id=$2", [organizationId, decisionId]);
    return result.rows[0] ? decisionProof(result.rows[0]) : undefined;
  }

  async saveDecisionProof(proof: DecisionProof): Promise<void> {
    await this.pool.query(`INSERT INTO decision_proofs
      (decision_id,organization_id,evidence_hash,approver_wallet_address,signature,tx_hash,contract_address,block_number,mstscan_url,anchor_status,created_at,confirmed_at)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
      ON CONFLICT (decision_id) DO UPDATE SET evidence_hash=EXCLUDED.evidence_hash,approver_wallet_address=EXCLUDED.approver_wallet_address,signature=EXCLUDED.signature,tx_hash=EXCLUDED.tx_hash,contract_address=EXCLUDED.contract_address,block_number=EXCLUDED.block_number,mstscan_url=EXCLUDED.mstscan_url,anchor_status=EXCLUDED.anchor_status,confirmed_at=EXCLUDED.confirmed_at`, [
      proof.decisionId, proof.organizationId, proof.evidenceHash, proof.approverWalletAddress, proof.signature, proof.txHash ?? null, proof.contractAddress ?? null,
      proof.blockNumber ?? null, proof.mstscanUrl ?? null, proof.anchorStatus, proof.createdAt, proof.confirmedAt ?? null,
    ]);
  }

  async getIdentityUser(userId: string): Promise<IdentityUser | undefined> {
    const result = await this.pool.query("SELECT * FROM identity_users WHERE id=$1", [userId]);
    return result.rows[0] ? identityUser(result.rows[0]) : undefined;
  }

  async setWalletAddress(userId: string, walletAddress: string, verifiedAt: string): Promise<IdentityUser> {
    return this.transaction(async (client) => {
      const conflict = await client.query("SELECT 1 FROM identity_users WHERE lower(wallet_address)=lower($1) AND id<>$2", [walletAddress, userId]);
      if (conflict.rowCount) throw Object.assign(new Error("Wallet address is already assigned."), { statusCode: 409 });
      const result = await client.query("UPDATE identity_users SET wallet_address=$1,wallet_verified_at=$2,updated_at=now() WHERE id=$3 RETURNING *", [walletAddress, verifiedAt, userId]);
      if (!result.rows[0]) throw Object.assign(new Error("Identity user does not exist."), { statusCode: 404 });
      return identityUser(result.rows[0]);
    });
  }

  async enrollIdentityUser(organizationId: string, input: IdentityEnrollmentRequest, actorUserId: string): Promise<IdentityUser> {
    return this.transaction(async (client) => {
      const result = await client.query(`INSERT INTO identity_users (email,display_name) VALUES (lower($1),$2)
        ON CONFLICT ((lower(email))) DO UPDATE SET display_name=EXCLUDED.display_name,updated_at=now() RETURNING *`, [input.email, input.displayName]);
      const user = identityUser(required(result.rows[0]));
      const otherMembership = await client.query("SELECT 1 FROM memberships WHERE user_id=$1 AND organization_id<>$2", [user.id, organizationId]);
      if (otherMembership.rowCount) throw Object.assign(new Error("An identity may belong to only one Cascadia organization."), { statusCode: 409 });
      await client.query(`INSERT INTO memberships (organization_id,user_id,role) VALUES ($1,$2,$3)
        ON CONFLICT (organization_id,user_id) DO UPDATE SET role=EXCLUDED.role`, [organizationId, user.id, input.role]);
      await client.query("INSERT INTO audit_events (organization_id,actor_user_id,event_type,resource_type,resource_id,metadata) VALUES ($1,$2,'identity.user_enrolled','identity_user',$3,$4)", [organizationId, actorUserId, user.id, JSON.stringify({ email: user.email, role: input.role })]);
      return user;
    });
  }

  async listIdentityUsers(organizationId: string): Promise<IdentityAccess[]> {
    const result = await this.pool.query(`SELECT u.id AS user_id,u.email,u.display_name,u.status,m.organization_id,m.role
      FROM memberships m JOIN identity_users u ON u.id=m.user_id WHERE m.organization_id=$1 ORDER BY u.display_name`, [organizationId]);
    return result.rows.map((row) => ({ user: identityUser(row), organizationId: String(row.organization_id), role: row.role as UserRole }));
  }

  async resolveIdentity(issuer: string, subject: string, verifiedEmail: string): Promise<IdentityAccess | undefined> {
    return this.transaction(async (client) => {
      let result = await client.query(`SELECT u.id AS user_id,u.email,u.display_name,u.status,m.organization_id,m.role
        FROM identity_subjects s JOIN identity_users u ON u.id=s.user_id JOIN memberships m ON m.user_id=u.id
        WHERE s.issuer=$1 AND s.subject=$2 ORDER BY m.created_at`, [issuer, subject]);
      if (!result.rows[0]) {
        result = await client.query(`SELECT u.id AS user_id,u.email,u.display_name,u.status,m.organization_id,m.role
          FROM identity_users u JOIN memberships m ON m.user_id=u.id
          WHERE lower(u.email)=lower($1) ORDER BY m.created_at`, [verifiedEmail]);
        if (result.rows.length !== 1) return undefined;
        const row = result.rows[0];
        const conflict = await client.query("SELECT 1 FROM identity_subjects WHERE issuer=$1 AND user_id=$2 AND subject<>$3", [issuer, row.user_id, subject]);
        if (conflict.rowCount) return undefined;
        await client.query("INSERT INTO identity_subjects (issuer,subject,user_id,last_login_at) VALUES ($1,$2,$3,now()) ON CONFLICT (issuer,subject) DO UPDATE SET last_login_at=now()", [issuer, subject, row.user_id]);
      } else {
        if (result.rows.length !== 1) return undefined;
        await client.query("UPDATE identity_subjects SET last_login_at=now() WHERE issuer=$1 AND subject=$2", [issuer, subject]);
      }
      const row = required(result.rows[0]);
      if (row.status !== "active") return undefined;
      return { user: identityUser(row), organizationId: String(row.organization_id), role: row.role as UserRole };
    });
  }

  async createOidcLoginAttempt(attempt: OidcLoginAttempt): Promise<void> {
    await this.pool.query("DELETE FROM oidc_login_attempts WHERE expires_at<=now()");
    await this.pool.query("INSERT INTO oidc_login_attempts (state_hash,code_verifier,nonce,return_to,expires_at) VALUES ($1,$2,$3,$4,$5)", [attempt.stateHash, attempt.codeVerifier, attempt.nonce, attempt.returnTo, attempt.expiresAt]);
  }

  async consumeOidcLoginAttempt(stateHash: string): Promise<OidcLoginAttempt | undefined> {
    const result = await this.pool.query(`DELETE FROM oidc_login_attempts WHERE state_hash=$1 AND expires_at>now()
      RETURNING state_hash,code_verifier,nonce,return_to,expires_at`, [stateHash]);
    const row = result.rows[0];
    return row ? { stateHash: String(row.state_hash), codeVerifier: String(row.code_verifier), nonce: String(row.nonce), returnTo: String(row.return_to), expiresAt: iso(row.expires_at) } : undefined;
  }

  async createIdentitySession(input: IdentitySessionCreate): Promise<IdentitySessionRecord> {
    return this.transaction(async (client) => {
      await client.query("UPDATE identity_sessions SET revoked_at=now(),revoke_reason='session_limit' WHERE user_id=$1 AND revoked_at IS NULL AND expires_at>now() AND id IN (SELECT id FROM identity_sessions WHERE user_id=$1 AND revoked_at IS NULL ORDER BY created_at DESC OFFSET 4)", [input.user.id]);
      const result = await client.query(`INSERT INTO identity_sessions (token_hash,csrf_token_hash,user_id,organization_id,role,mfa_verified,issuer,subject,expires_at)
        VALUES ($1,$2,$3,$4,$5,true,$6,$7,$8) RETURNING *`, [input.tokenHash, input.csrfTokenHash, input.user.id, input.organizationId, input.role, input.issuer, input.subject, input.expiresAt]);
      const row = { ...required(result.rows[0]), email: input.user.email, display_name: input.user.displayName, status: input.user.status };
      await client.query("INSERT INTO audit_events (organization_id,actor_user_id,event_type,resource_type,resource_id,metadata) VALUES ($1,$2,'identity.session_created','identity_session',$3,$4)", [input.organizationId, input.user.id, row.id, JSON.stringify({ mfaVerified: true })]);
      return identitySession(row);
    });
  }

  async getIdentitySession(tokenHash: string): Promise<IdentitySessionRecord | undefined> {
    const result = await this.pool.query(`UPDATE identity_sessions s SET last_seen_at=now() FROM identity_users u
      WHERE s.token_hash=$1 AND s.user_id=u.id AND s.revoked_at IS NULL AND s.expires_at>now() AND u.status='active'
      RETURNING s.*,u.email,u.display_name,u.status`, [tokenHash]);
    return result.rows[0] ? identitySession(result.rows[0]) : undefined;
  }

  async revokeIdentitySession(tokenHash: string, reason: string): Promise<boolean> {
    const result = await this.pool.query(`WITH revoked AS (
      UPDATE identity_sessions SET revoked_at=now(),revoke_reason=$2 WHERE token_hash=$1 AND revoked_at IS NULL RETURNING *
    ) INSERT INTO audit_events (organization_id,actor_user_id,event_type,resource_type,resource_id,metadata)
      SELECT organization_id,user_id,'identity.session_revoked','identity_session',id::text,jsonb_build_object('reason',$2::text) FROM revoked RETURNING id`, [tokenHash, reason]);
    return Boolean(result.rowCount);
  }

  async createAgent(input: AgentInitRequest): Promise<Agent> {
    return this.transaction(async (client) => {
      const result = await client.query("INSERT INTO agents (organization_id,client,display_name) VALUES ($1,$2,$3) RETURNING *", [input.organizationId, input.client, input.displayName]);
      const value = agent(required(result.rows[0]));
      await client.query("INSERT INTO audit_events (organization_id,event_type,resource_type,resource_id,metadata) VALUES ($1,'agent.initialized','agent',$2,$3)", [input.organizationId, value.id, JSON.stringify({ client: value.client })]);
      return value;
    });
  }

  async listPosts(organizationId: string): Promise<PublishedPost[]> {
    const result = await this.pool.query("SELECT * FROM published_posts WHERE organization_id=$1 ORDER BY published_at DESC", [organizationId]);
    return result.rows.map((row) => ({ id: String(row.id), organizationId: String(row.organization_id), agentId: String(row.agent_id), topic: String(row.topic), rationale: String(row.rationale), sourceUrls: row.source_urls as string[], publishedAt: iso(row.published_at) }));
  }

  async appendPublishedPost(post: PublishedPost): Promise<void> {
    await this.pool.query("INSERT INTO published_posts (id,organization_id,agent_id,topic,rationale,source_urls,published_at) VALUES ($1,$2,$3,$4,$5,$6,$7)", [post.id, post.organizationId, post.agentId, post.topic, post.rationale, post.sourceUrls, post.publishedAt]);
  }

  async upsertAsset(organizationId: string, input: AssetCreateRequest, actorUserId: string): Promise<UpsertAssetResult> {
    return this.transaction(async (client) => {
      const result = await client.query(`INSERT INTO assets (organization_id,external_id,name,asset_type,criticality,classification,owner_user_id,hostname,ip_address,metadata)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
        ON CONFLICT (organization_id,external_id) DO UPDATE SET name=EXCLUDED.name,asset_type=EXCLUDED.asset_type,criticality=EXCLUDED.criticality,classification=EXCLUDED.classification,owner_user_id=EXCLUDED.owner_user_id,hostname=EXCLUDED.hostname,ip_address=EXCLUDED.ip_address,metadata=EXCLUDED.metadata,updated_at=now()
        RETURNING *, (xmax = 0) AS was_created`, [organizationId, input.externalId, input.name, input.assetType, input.criticality, input.classification, input.ownerUserId ?? null, input.hostname ?? null, input.ipAddress ?? null, JSON.stringify(input.metadata)]);
      const row = required(result.rows[0]);
      const created = Boolean(row.was_created);
      await client.query("INSERT INTO audit_events (organization_id,actor_user_id,event_type,resource_type,resource_id,metadata) VALUES ($1,$2,$3,'asset',$4,$5)", [organizationId, actorUserId, created ? "asset.created" : "asset.updated", row.id, JSON.stringify({ externalId: input.externalId })]);
      return { asset: asset(row), created };
    });
  }

  async listAssets(organizationId: string): Promise<Asset[]> {
    const result = await this.pool.query("SELECT * FROM assets WHERE organization_id=$1 ORDER BY name", [organizationId]);
    return result.rows.map(asset);
  }

  async createDependency(organizationId: string, input: AssetDependencyCreateRequest, actorUserId: string): Promise<AssetDependency> {
    return this.transaction(async (client) => {
      const result = await client.query(`INSERT INTO asset_dependencies (organization_id,source_asset_id,target_asset_id,relationship,protocol,critical)
        VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT (organization_id,source_asset_id,target_asset_id,relationship)
        DO UPDATE SET protocol=EXCLUDED.protocol,critical=EXCLUDED.critical RETURNING *`, [organizationId, input.sourceAssetId, input.targetAssetId, input.relationship, input.protocol ?? null, input.critical]);
      const value = dependency(required(result.rows[0]));
      await client.query("INSERT INTO audit_events (organization_id,actor_user_id,event_type,resource_type,resource_id) VALUES ($1,$2,'dependency.created','asset_dependency',$3)", [organizationId, actorUserId, value.id]);
      return value;
    });
  }

  async listDependencies(organizationId: string): Promise<AssetDependency[]> {
    const result = await this.pool.query("SELECT * FROM asset_dependencies WHERE organization_id=$1 ORDER BY created_at", [organizationId]);
    return result.rows.map(dependency);
  }

  async ingestSecurityEvent(organizationId: string, input: SecurityEventIngestRequest): Promise<IngestResult> {
    const inserted = await this.pool.query(`INSERT INTO normalized_security_events (organization_id,source,source_event_id,event_type,severity,observed_at,asset_external_ids,record)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT (organization_id,source,source_event_id) DO NOTHING RETURNING *`, [organizationId, input.source, input.sourceEventId, input.eventType, input.severity, input.observedAt, input.assetExternalIds, JSON.stringify(input.record)]);
    if (inserted.rows[0]) return { event: securityEvent(inserted.rows[0]), duplicate: false };
    const existing = await this.pool.query("SELECT * FROM normalized_security_events WHERE organization_id=$1 AND source=$2 AND source_event_id=$3", [organizationId, input.source, input.sourceEventId]);
    return { event: securityEvent(required(existing.rows[0])), duplicate: true };
  }

  async listSecurityEvents(organizationId: string): Promise<SecurityEvent[]> {
    const result = await this.pool.query("SELECT * FROM normalized_security_events WHERE organization_id=$1 ORDER BY observed_at DESC", [organizationId]);
    return result.rows.map(securityEvent);
  }

  async upsertVulnerability(organizationId: string, input: VulnerabilityUpsertRequest, actorUserId: string): Promise<UpsertVulnerabilityResult> {
    return this.transaction(async (client) => {
      const result = await client.query(`INSERT INTO vulnerabilities (organization_id,asset_id,external_id,title,cvss_score,exploit_status,status,source_urls)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT (organization_id,asset_id,external_id) DO UPDATE SET title=EXCLUDED.title,cvss_score=EXCLUDED.cvss_score,exploit_status=EXCLUDED.exploit_status,status=EXCLUDED.status,source_urls=EXCLUDED.source_urls,updated_at=now()
        RETURNING *, (xmax = 0) AS was_created`, [organizationId, input.assetId, input.externalId, input.title, input.cvssScore, input.exploitStatus, input.status, input.sourceUrls]);
      const row = required(result.rows[0]);
      const created = Boolean(row.was_created);
      await client.query("INSERT INTO audit_events (organization_id,actor_user_id,event_type,resource_type,resource_id,metadata) VALUES ($1,$2,$3,'vulnerability',$4,$5)", [organizationId, actorUserId, created ? "vulnerability.created" : "vulnerability.updated", row.id, JSON.stringify({ externalId: input.externalId })]);
      return { vulnerability: vulnerability(row), created };
    });
  }

  async listVulnerabilities(organizationId: string): Promise<Vulnerability[]> {
    const result = await this.pool.query("SELECT * FROM vulnerabilities WHERE organization_id=$1 ORDER BY updated_at DESC", [organizationId]);
    return result.rows.map(vulnerability);
  }

  async upsertCriticalService(organizationId: string, input: CriticalServiceUpsertRequest, actorUserId: string): Promise<UpsertCriticalServiceResult> {
    return this.transaction(async (client) => {
      const assets = await client.query("SELECT id FROM assets WHERE organization_id=$1 AND id=ANY($2::uuid[])", [organizationId, input.assetIds]);
      if (assets.rowCount !== new Set(input.assetIds).size) throw Object.assign(new Error("Every critical-service asset must exist in the organization."), { statusCode: 404 });
      const result = await client.query(`INSERT INTO critical_services (organization_id,name,description,criticality,recovery_time_minutes,maximum_tolerable_downtime_minutes)
        VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT (organization_id,name) DO UPDATE SET description=EXCLUDED.description,criticality=EXCLUDED.criticality,recovery_time_minutes=EXCLUDED.recovery_time_minutes,maximum_tolerable_downtime_minutes=EXCLUDED.maximum_tolerable_downtime_minutes,updated_at=now()
        RETURNING *, (xmax = 0) AS was_created`, [organizationId, input.name, input.description, input.criticality, input.recoveryTimeMinutes, input.maximumTolerableDowntimeMinutes]);
      const row = required(result.rows[0]);
      await client.query("DELETE FROM critical_service_assets WHERE organization_id=$1 AND service_id=$2", [organizationId, row.id]);
      for (const assetId of new Set(input.assetIds)) await client.query("INSERT INTO critical_service_assets (organization_id,service_id,asset_id) VALUES ($1,$2,$3)", [organizationId, row.id, assetId]);
      const created = Boolean(row.was_created);
      await client.query("INSERT INTO audit_events (organization_id,actor_user_id,event_type,resource_type,resource_id) VALUES ($1,$2,$3,'critical_service',$4)", [organizationId, actorUserId, created ? "critical_service.created" : "critical_service.updated", row.id]);
      return { service: criticalService(row, [...new Set(input.assetIds)]), created };
    });
  }

  async listCriticalServices(organizationId: string): Promise<CriticalService[]> {
    const result = await this.pool.query(`SELECT service.*, COALESCE(array_agg(link.asset_id) FILTER (WHERE link.asset_id IS NOT NULL), '{}') AS asset_ids
      FROM critical_services service LEFT JOIN critical_service_assets link ON link.organization_id=service.organization_id AND link.service_id=service.id
      WHERE service.organization_id=$1 GROUP BY service.id ORDER BY service.name`, [organizationId]);
    return result.rows.map((row) => criticalService(row, (row.asset_ids as unknown[]).map(String)));
  }

  async saveRiskAnalysis(analysis: AttackPathAnalysis, actorUserId: string): Promise<void> {
    await this.transaction(async (client) => {
      await client.query("INSERT INTO risk_analyses (id,organization_id,generated_at,result,created_by) VALUES ($1,$2,$3,$4,$5)", [analysis.id, analysis.organizationId, analysis.generatedAt, JSON.stringify(analysis), actorUserId]);
      await client.query("INSERT INTO audit_events (organization_id,actor_user_id,event_type,resource_type,resource_id,metadata) VALUES ($1,$2,'risk_analysis.created','risk_analysis',$3,$4)", [analysis.organizationId, actorUserId, analysis.id, JSON.stringify({ pathCount: analysis.paths.length })]);
    });
  }

  async listRiskAnalyses(organizationId: string): Promise<AttackPathAnalysis[]> {
    const result = await this.pool.query("SELECT result FROM risk_analyses WHERE organization_id=$1 ORDER BY generated_at DESC", [organizationId]);
    return result.rows.map((row) => row.result as AttackPathAnalysis);
  }

  async getRiskAnalysis(organizationId: string, analysisId: string): Promise<AttackPathAnalysis | undefined> {
    const result = await this.pool.query("SELECT result FROM risk_analyses WHERE organization_id=$1 AND id=$2", [organizationId, analysisId]);
    return result.rows[0]?.result as AttackPathAnalysis | undefined;
  }

  async upsertResponsePolicy(organizationId: string, input: ResponsePolicyUpsertRequest, actorUserId: string): Promise<UpsertResponsePolicyResult> {
    return this.transaction(async (client) => {
      const result = await client.query(`INSERT INTO response_policies (organization_id,name,action_type,mode,maximum_operational_impact,minimum_approvals,approval_roles,requires_rollback_plan)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT (organization_id,action_type) DO UPDATE SET name=EXCLUDED.name,mode=EXCLUDED.mode,maximum_operational_impact=EXCLUDED.maximum_operational_impact,minimum_approvals=EXCLUDED.minimum_approvals,approval_roles=EXCLUDED.approval_roles,requires_rollback_plan=EXCLUDED.requires_rollback_plan,updated_at=now()
        RETURNING *, (xmax = 0) AS was_created`, [organizationId, input.name, input.actionType, input.mode, input.maximumOperationalImpact, input.minimumApprovals, input.approvalRoles, input.requiresRollbackPlan]);
      const row = required(result.rows[0]);
      const created = Boolean(row.was_created);
      await client.query("INSERT INTO audit_events (organization_id,actor_user_id,event_type,resource_type,resource_id) VALUES ($1,$2,$3,'response_policy',$4)", [organizationId, actorUserId, created ? "response_policy.created" : "response_policy.updated", row.id]);
      return { policy: responsePolicy(row), created };
    });
  }

  async listResponsePolicies(organizationId: string): Promise<ResponsePolicy[]> {
    const result = await this.pool.query("SELECT * FROM response_policies WHERE organization_id=$1 ORDER BY action_type", [organizationId]);
    return result.rows.map(responsePolicy);
  }

  async saveResponseScenario(scenario: ResponseScenario, actorUserId: string): Promise<void> {
    await this.transaction(async (client) => {
      await client.query("INSERT INTO response_scenarios (id,organization_id,analysis_id,incident_id,generated_at,status,result,created_by) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)", [scenario.id, scenario.organizationId, scenario.analysisId, scenario.incidentId, scenario.generatedAt, scenario.status, JSON.stringify(scenario), actorUserId]);
      await client.query("INSERT INTO audit_events (organization_id,actor_user_id,event_type,resource_type,resource_id,metadata) VALUES ($1,$2,'response_scenario.created','response_scenario',$3,$4)", [scenario.organizationId, actorUserId, scenario.id, JSON.stringify({ optionCount: scenario.options.length })]);
    });
  }

  async getResponseScenario(organizationId: string, scenarioId: string): Promise<ResponseScenario | undefined> {
    const result = await this.pool.query("SELECT result FROM response_scenarios WHERE organization_id=$1 AND id=$2", [organizationId, scenarioId]);
    return result.rows[0]?.result as ResponseScenario | undefined;
  }

  async listResponseScenarios(organizationId: string): Promise<ResponseScenario[]> {
    const result = await this.pool.query("SELECT result FROM response_scenarios WHERE organization_id=$1 ORDER BY generated_at DESC", [organizationId]);
    return result.rows.map((row) => row.result as ResponseScenario);
  }

  async recordResponseDecision(organizationId: string, scenarioId: string, input: ResponseDecisionRequest, actorUserId: string, actorRole: UserRole): Promise<ResponseScenario> {
    return this.transaction(async (client) => {
      const result = await client.query("SELECT result FROM response_scenarios WHERE organization_id=$1 AND id=$2 FOR UPDATE", [organizationId, scenarioId]);
      const scenario = result.rows[0]?.result as ResponseScenario | undefined;
      if (!scenario) throw Object.assign(new Error("Response scenario does not exist."), { statusCode: 404 });
      const updated = applyResponseDecision(scenario, input, actorUserId, actorRole, systemClock);
      const decision = updated.decisions.at(-1)!;
      await client.query("INSERT INTO response_decisions (id,organization_id,scenario_id,option_id,actor_user_id,actor_role,decision,comment,decided_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)", [decision.id, organizationId, scenarioId, decision.optionId, decision.actorUserId, decision.actorRole, decision.decision, decision.comment, decision.decidedAt]);
      await client.query("UPDATE response_scenarios SET status=$1,result=$2 WHERE organization_id=$3 AND id=$4", [updated.status, JSON.stringify(updated), organizationId, scenarioId]);
      await client.query("INSERT INTO audit_events (organization_id,actor_user_id,event_type,resource_type,resource_id,metadata) VALUES ($1,$2,$3,'response_scenario',$4,$5)", [organizationId, actorUserId, decision.decision === "approve" ? "response.approved" : "response.rejected", scenarioId, JSON.stringify({ optionId: input.optionId, status: updated.status })]);
      return updated;
    });
  }

  async createIntegration(organizationId: string, input: IntegrationCreateRequest, secretCiphertext: string, actorUserId: string): Promise<Integration> {
    return this.transaction(async (client) => {
      const result = await client.query(`INSERT INTO integrations (organization_id,name,provider,data_type,event_source,secret_ciphertext)
        VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT (organization_id,name) DO NOTHING RETURNING *`, [organizationId, input.name, input.provider, input.dataType, input.eventSource ?? null, secretCiphertext]);
      if (!result.rows[0]) throw Object.assign(new Error("An integration with this name already exists."), { statusCode: 409 });
      const value = integration(result.rows[0]);
      await client.query("INSERT INTO audit_events (organization_id,actor_user_id,event_type,resource_type,resource_id,metadata) VALUES ($1,$2,'integration.created','integration',$3,$4)", [organizationId, actorUserId, value.id, JSON.stringify({ provider: value.provider, dataType: value.dataType })]);
      return value;
    });
  }

  async getIntegration(organizationId: string, integrationId: string): Promise<Integration | undefined> {
    const result = await this.pool.query("SELECT * FROM integrations WHERE organization_id=$1 AND id=$2", [organizationId, integrationId]);
    return result.rows[0] ? integration(result.rows[0]) : undefined;
  }

  async getIntegrationCredential(integrationId: string): Promise<IntegrationCredential | undefined> {
    const result = await this.pool.query("SELECT * FROM integrations WHERE id=$1", [integrationId]);
    const row = result.rows[0];
    return row ? { integration: integration(row), secretCiphertext: String(row.secret_ciphertext) } : undefined;
  }

  async listIntegrations(organizationId: string): Promise<Integration[]> {
    const result = await this.pool.query("SELECT * FROM integrations WHERE organization_id=$1 ORDER BY name", [organizationId]);
    return result.rows.map(integration);
  }

  async updateIntegrationStatus(organizationId: string, integrationId: string, input: IntegrationStatusUpdate, actorUserId: string): Promise<Integration> {
    return this.transaction(async (client) => {
      const result = await client.query("UPDATE integrations SET status=$1,updated_at=now() WHERE organization_id=$2 AND id=$3 RETURNING *", [input.status, organizationId, integrationId]);
      if (!result.rows[0]) throw Object.assign(new Error("Integration does not exist."), { statusCode: 404 });
      await client.query("INSERT INTO audit_events (organization_id,actor_user_id,event_type,resource_type,resource_id,metadata) VALUES ($1,$2,'integration.status_changed','integration',$3,$4)", [organizationId, actorUserId, integrationId, JSON.stringify({ status: input.status })]);
      return integration(result.rows[0]);
    });
  }

  async rotateIntegrationSecret(organizationId: string, integrationId: string, secretCiphertext: string, actorUserId: string): Promise<Integration> {
    return this.transaction(async (client) => {
      const result = await client.query("UPDATE integrations SET secret_ciphertext=$1,secret_version=secret_version+1,updated_at=now() WHERE organization_id=$2 AND id=$3 RETURNING *", [secretCiphertext, organizationId, integrationId]);
      if (!result.rows[0]) throw Object.assign(new Error("Integration does not exist."), { statusCode: 404 });
      const value = integration(result.rows[0]);
      await client.query("INSERT INTO audit_events (organization_id,actor_user_id,event_type,resource_type,resource_id,metadata) VALUES ($1,$2,'integration.secret_rotated','integration',$3,$4)", [organizationId, actorUserId, integrationId, JSON.stringify({ secretVersion: value.secretVersion })]);
      return value;
    });
  }

  async ingestIntegrationDelivery(value: Integration, externalDeliveryId: string, payloadSha256: string, events: SecurityEventIngestRequest[], indicators: ThreatIndicator[]): Promise<IntegrationDeliveryResult> {
    return this.transaction(async (client) => {
      await client.query("SELECT id FROM integrations WHERE id=$1 FOR UPDATE", [value.id]);
      const prior = await client.query("SELECT * FROM integration_deliveries WHERE integration_id=$1 AND external_delivery_id=$2", [value.id, externalDeliveryId]);
      if (prior.rows[0]) {
        const delivery = integrationDelivery(prior.rows[0]);
        if (delivery.payloadSha256 !== payloadSha256) throw Object.assign(new Error("Delivery ID was already used with different content."), { statusCode: 409 });
        return { delivery, duplicate: true };
      }
      for (const event of events) {
        await client.query(`INSERT INTO normalized_security_events (organization_id,source,source_event_id,event_type,severity,observed_at,asset_external_ids,record)
          VALUES ($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT (organization_id,source,source_event_id) DO NOTHING`, [value.organizationId, event.source, event.sourceEventId, event.eventType, event.severity, event.observedAt, event.assetExternalIds, JSON.stringify(event.record)]);
      }
      for (const indicator of indicators) {
        await client.query(`INSERT INTO threat_indicators (id,organization_id,integration_id,stix_id,name,description,pattern,confidence,labels,source_urls,valid_from,valid_until,modified_at,ingested_at)
          VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)
          ON CONFLICT (organization_id,stix_id) DO UPDATE SET integration_id=EXCLUDED.integration_id,name=EXCLUDED.name,description=EXCLUDED.description,pattern=EXCLUDED.pattern,confidence=EXCLUDED.confidence,labels=EXCLUDED.labels,source_urls=EXCLUDED.source_urls,valid_from=EXCLUDED.valid_from,valid_until=EXCLUDED.valid_until,modified_at=EXCLUDED.modified_at,ingested_at=EXCLUDED.ingested_at
          WHERE threat_indicators.modified_at <= EXCLUDED.modified_at`, [indicator.id, indicator.organizationId, indicator.integrationId, indicator.stixId, indicator.name, indicator.description, indicator.pattern, indicator.confidence, indicator.labels, indicator.sourceUrls, indicator.validFrom, indicator.validUntil ?? null, indicator.modifiedAt, indicator.ingestedAt]);
      }
      const inserted = await client.query("INSERT INTO integration_deliveries (organization_id,integration_id,external_delivery_id,payload_sha256,event_count,indicator_count) VALUES ($1,$2,$3,$4,$5,$6) RETURNING *", [value.organizationId, value.id, externalDeliveryId, payloadSha256, events.length, indicators.length]);
      const delivery = integrationDelivery(required(inserted.rows[0]));
      await client.query("UPDATE integrations SET last_delivery_at=$1,updated_at=$1 WHERE id=$2", [delivery.receivedAt, value.id]);
      await client.query("INSERT INTO audit_events (organization_id,event_type,resource_type,resource_id,metadata) VALUES ($1,'integration.delivery_received','integration_delivery',$2,$3)", [value.organizationId, delivery.id, JSON.stringify({ integrationId: value.id, eventCount: events.length, indicatorCount: indicators.length })]);
      return { delivery, duplicate: false };
    });
  }

  async listIntegrationDeliveries(organizationId: string, integrationId: string): Promise<IntegrationDelivery[]> {
    const result = await this.pool.query("SELECT * FROM integration_deliveries WHERE organization_id=$1 AND integration_id=$2 ORDER BY received_at DESC", [organizationId, integrationId]);
    return result.rows.map(integrationDelivery);
  }

  async listThreatIndicators(organizationId: string): Promise<ThreatIndicator[]> {
    const result = await this.pool.query("SELECT * FROM threat_indicators WHERE organization_id=$1 ORDER BY modified_at DESC", [organizationId]);
    return result.rows.map(threatIndicator);
  }

  async createTaxiiSource(organizationId: string, input: TaxiiSourceCreateRequest, authenticationCiphertext: string | undefined, actorUserId: string): Promise<TaxiiSource> {
    return this.transaction(async (client) => {
      const target = await client.query("SELECT provider,data_type FROM integrations WHERE organization_id=$1 AND id=$2", [organizationId, input.integrationId]);
      if (!target.rows[0] || target.rows[0].provider !== "taxii" || target.rows[0].data_type !== "stix_bundle") throw Object.assign(new Error("TAXII sources require a TAXII STIX-bundle integration in the same organization."), { statusCode: 400 });
      const result = await client.query(`INSERT INTO taxii_sources (organization_id,integration_id,name,api_root_url,collection_id,authentication_type,authentication_ciphertext)
        VALUES ($1,$2,$3,$4,$5,$6,$7) ON CONFLICT (organization_id,name) DO NOTHING RETURNING *`, [organizationId, input.integrationId, input.name, input.apiRootUrl, input.collectionId, input.authentication.type, authenticationCiphertext ?? null]);
      if (!result.rows[0]) throw Object.assign(new Error("A TAXII source with this name already exists."), { statusCode: 409 });
      const value = taxiiSource(result.rows[0]);
      await client.query("INSERT INTO audit_events (organization_id,actor_user_id,event_type,resource_type,resource_id,metadata) VALUES ($1,$2,'taxii_source.created','taxii_source',$3,$4)", [organizationId, actorUserId, value.id, JSON.stringify({ integrationId: input.integrationId, authenticationType: value.authenticationType })]);
      return value;
    });
  }

  async getTaxiiSource(organizationId: string, sourceId: string): Promise<TaxiiSource | undefined> {
    const result = await this.pool.query("SELECT * FROM taxii_sources WHERE organization_id=$1 AND id=$2", [organizationId, sourceId]);
    return result.rows[0] ? taxiiSource(result.rows[0]) : undefined;
  }

  async getTaxiiSourceCredential(organizationId: string, sourceId: string): Promise<TaxiiSourceCredential | undefined> {
    const result = await this.pool.query("SELECT * FROM taxii_sources WHERE organization_id=$1 AND id=$2", [organizationId, sourceId]);
    const row = result.rows[0];
    return row ? { source: taxiiSource(row), ...(row.authentication_ciphertext ? { authenticationCiphertext: String(row.authentication_ciphertext) } : {}) } : undefined;
  }

  async listTaxiiSources(organizationId: string): Promise<TaxiiSource[]> {
    const result = await this.pool.query("SELECT * FROM taxii_sources WHERE organization_id=$1 ORDER BY name", [organizationId]);
    return result.rows.map(taxiiSource);
  }

  async updateTaxiiSourceStatus(organizationId: string, sourceId: string, input: TaxiiSourceStatusUpdate, actorUserId: string): Promise<TaxiiSource> {
    return this.transaction(async (client) => {
      const result = await client.query("UPDATE taxii_sources SET status=$1,updated_at=now() WHERE organization_id=$2 AND id=$3 RETURNING *", [input.status, organizationId, sourceId]);
      if (!result.rows[0]) throw Object.assign(new Error("TAXII source does not exist."), { statusCode: 404 });
      await client.query("INSERT INTO audit_events (organization_id,actor_user_id,event_type,resource_type,resource_id,metadata) VALUES ($1,$2,'taxii_source.status_changed','taxii_source',$3,$4)", [organizationId, actorUserId, sourceId, JSON.stringify({ status: input.status })]);
      return taxiiSource(result.rows[0]);
    });
  }

  async createTaxiiSyncJob(organizationId: string, sourceId: string, actorUserId: string): Promise<TaxiiSyncJob> {
    return this.transaction(async (client) => {
      const source = await client.query("SELECT id FROM taxii_sources WHERE organization_id=$1 AND id=$2", [organizationId, sourceId]);
      if (!source.rows[0]) throw Object.assign(new Error("TAXII source does not exist."), { statusCode: 404 });
      const result = await client.query(`INSERT INTO taxii_sync_jobs (organization_id,source_id,status,requested_by_user_id,checkpoint_before)
        SELECT $1,$2,'running',$3,checkpoint_added_after FROM taxii_sources WHERE organization_id=$1 AND id=$2
        ON CONFLICT (source_id) WHERE status='running' DO NOTHING RETURNING *`, [organizationId, sourceId, actorUserId]);
      if (!result.rows[0]) throw Object.assign(new Error("A TAXII sync is already running for this source."), { statusCode: 409 });
      const job = taxiiSyncJob(result.rows[0]);
      await client.query("INSERT INTO audit_events (organization_id,actor_user_id,event_type,resource_type,resource_id,metadata) VALUES ($1,$2,'taxii_sync.started','taxii_sync_job',$3,$4)", [organizationId, actorUserId, job.id, JSON.stringify({ sourceId })]);
      return job;
    });
  }

  async appendTaxiiSyncAttempt(organizationId: string, jobId: string, attempt: TaxiiSyncAttempt): Promise<void> {
    await this.pool.query("INSERT INTO taxii_sync_attempts (id,organization_id,job_id,page_number,attempt_number,status,http_status,error_code,started_at,completed_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)", [attempt.id, organizationId, jobId, attempt.pageNumber, attempt.attemptNumber, attempt.status, attempt.httpStatus ?? null, attempt.errorCode ?? null, attempt.startedAt, attempt.completedAt]);
  }

  async finishTaxiiSyncJob(organizationId: string, jobId: string, completion: TaxiiSyncCompletion): Promise<TaxiiSyncJob> {
    return this.transaction(async (client) => {
      const result = await client.query(`UPDATE taxii_sync_jobs SET status=$1,completed_at=now(),checkpoint_after=$2,pages_fetched=$3,objects_received=$4,indicators_accepted=$5,error_code=$6,error_message=$7
        WHERE organization_id=$8 AND id=$9 AND status='running' RETURNING *`, [completion.status, completion.checkpointAfter ?? null, completion.pagesFetched, completion.objectsReceived, completion.indicatorsAccepted, completion.errorCode ?? null, completion.errorMessage ?? null, organizationId, jobId]);
      if (!result.rows[0]) throw Object.assign(new Error("TAXII sync job does not exist or is already final."), { statusCode: 409 });
      const row = result.rows[0];
      if (completion.status === "succeeded") await client.query(`UPDATE taxii_sources SET
        checkpoint_added_after=CASE WHEN checkpoint_added_after IS NULL OR checkpoint_added_after < $1 THEN $1 ELSE checkpoint_added_after END,
        last_sync_at=CASE WHEN last_sync_at IS NULL OR last_sync_at < $2 THEN $2 ELSE last_sync_at END,
        updated_at=GREATEST(updated_at,$2) WHERE organization_id=$3 AND id=$4`, [completion.checkpointAfter ?? null, row.completed_at, organizationId, row.source_id]);
      await client.query("INSERT INTO audit_events (organization_id,actor_user_id,event_type,resource_type,resource_id,metadata) VALUES ($1,$2,$3,'taxii_sync_job',$4,$5)", [organizationId, row.requested_by_user_id, completion.status === "succeeded" ? "taxii_sync.succeeded" : "taxii_sync.failed", jobId, JSON.stringify({ sourceId: row.source_id, pagesFetched: completion.pagesFetched, objectsReceived: completion.objectsReceived, errorCode: completion.errorCode })]);
      const attempts = await client.query("SELECT * FROM taxii_sync_attempts WHERE organization_id=$1 AND job_id=$2 ORDER BY page_number,attempt_number", [organizationId, jobId]);
      return taxiiSyncJob(row, attempts.rows.map(taxiiSyncAttempt));
    });
  }

  async listTaxiiSyncJobs(organizationId: string, sourceId: string): Promise<TaxiiSyncJob[]> {
    const jobs = await this.pool.query("SELECT * FROM taxii_sync_jobs WHERE organization_id=$1 AND source_id=$2 ORDER BY started_at DESC", [organizationId, sourceId]);
    if (jobs.rows.length === 0) return [];
    const attempts = await this.pool.query("SELECT * FROM taxii_sync_attempts WHERE organization_id=$1 AND job_id=ANY($2::uuid[]) ORDER BY page_number,attempt_number", [organizationId, jobs.rows.map((row) => row.id)]);
    const grouped = new Map<string, TaxiiSyncAttempt[]>();
    for (const row of attempts.rows) grouped.set(String(row.job_id), [...(grouped.get(String(row.job_id)) ?? []), taxiiSyncAttempt(row)]);
    return jobs.rows.map((row) => taxiiSyncJob(row, grouped.get(String(row.id)) ?? []));
  }

  async saveDetectionModel(model: DetectionModel, actorUserId: string): Promise<void> {
    await this.transaction(async (client) => {
      await client.query("SELECT id FROM organizations WHERE id=$1 FOR UPDATE", [model.organizationId]);
      await client.query("UPDATE detection_models SET status='retired' WHERE organization_id=$1 AND status='active'", [model.organizationId]);
      try {
        await client.query("INSERT INTO detection_models (id,organization_id,version,status,algorithm,trained_at,training_event_count,finding_threshold,result) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)", [model.id, model.organizationId, model.version, model.status, model.algorithm, model.trainedAt, model.trainingEventCount, model.findingThreshold, JSON.stringify(model)]);
      } catch (error) {
        if ((error as { code?: string }).code === "23505") throw Object.assign(new Error("Detection model version already exists."), { statusCode: 409 });
        throw error;
      }
      await client.query("INSERT INTO audit_events (organization_id,actor_user_id,event_type,resource_type,resource_id,metadata) VALUES ($1,$2,'detection_model.trained','detection_model',$3,$4)", [model.organizationId, actorUserId, model.id, JSON.stringify({ version: model.version, trainingEventCount: model.trainingEventCount })]);
    });
  }

  async getActiveDetectionModel(organizationId: string): Promise<DetectionModel | undefined> {
    const result = await this.pool.query("SELECT * FROM detection_models WHERE organization_id=$1 AND status='active'", [organizationId]);
    return result.rows[0] ? detectionModel(result.rows[0]) : undefined;
  }

  async listDetectionModels(organizationId: string): Promise<DetectionModel[]> {
    const result = await this.pool.query("SELECT * FROM detection_models WHERE organization_id=$1 ORDER BY version DESC", [organizationId]);
    return result.rows.map(detectionModel);
  }

  async saveAnomalyFinding(finding: AnomalyFinding): Promise<SaveFindingResult> {
    return this.transaction(async (client) => {
      const inserted = await client.query(`INSERT INTO anomaly_findings (id,organization_id,model_id,event_id,anomaly_score,level,disposition,result,created_at)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) ON CONFLICT (organization_id,model_id,event_id) DO NOTHING RETURNING *`, [finding.id, finding.organizationId, finding.modelId, finding.eventId, finding.anomalyScore, finding.level, finding.disposition, JSON.stringify(finding), finding.createdAt]);
      if (inserted.rows[0]) {
        await client.query("INSERT INTO audit_events (organization_id,event_type,resource_type,resource_id,metadata) VALUES ($1,'anomaly_finding.created','anomaly_finding',$2,$3)", [finding.organizationId, finding.id, JSON.stringify({ modelId: finding.modelId, eventId: finding.eventId, anomalyScore: finding.anomalyScore })]);
        return { finding: anomalyFinding(inserted.rows[0]), created: true };
      }
      const existing = await client.query("SELECT * FROM anomaly_findings WHERE organization_id=$1 AND model_id=$2 AND event_id=$3", [finding.organizationId, finding.modelId, finding.eventId]);
      return { finding: anomalyFinding(required(existing.rows[0])), created: false };
    });
  }

  async listAnomalyFindings(organizationId: string): Promise<AnomalyFinding[]> {
    const result = await this.pool.query("SELECT * FROM anomaly_findings WHERE organization_id=$1 ORDER BY created_at DESC", [organizationId]);
    return result.rows.map(anomalyFinding);
  }

  async reviewAnomalyFinding(organizationId: string, findingId: string, input: AnomalyFindingDispositionRequest, actorUserId: string): Promise<AnomalyFinding> {
    return this.transaction(async (client) => {
      const result = await client.query("SELECT * FROM anomaly_findings WHERE organization_id=$1 AND id=$2 FOR UPDATE", [organizationId, findingId]);
      if (!result.rows[0]) throw Object.assign(new Error("Anomaly finding does not exist."), { statusCode: 404 });
      const finding = anomalyFinding(result.rows[0]);
      const review = { id: randomUUID(), findingId, analystUserId: actorUserId, disposition: input.disposition, comment: input.comment, reviewedAt: systemClock.now().toISOString() };
      const updated: AnomalyFinding = { ...finding, disposition: input.disposition, reviews: [...finding.reviews, review] };
      await client.query("INSERT INTO anomaly_finding_reviews (id,organization_id,finding_id,analyst_user_id,disposition,comment,reviewed_at) VALUES ($1,$2,$3,$4,$5,$6,$7)", [review.id, organizationId, findingId, actorUserId, review.disposition, review.comment, review.reviewedAt]);
      await client.query("UPDATE anomaly_findings SET disposition=$1,result=$2 WHERE organization_id=$3 AND id=$4", [input.disposition, JSON.stringify(updated), organizationId, findingId]);
      await client.query("INSERT INTO audit_events (organization_id,actor_user_id,event_type,resource_type,resource_id,metadata) VALUES ($1,$2,'anomaly_finding.reviewed','anomaly_finding',$3,$4)", [organizationId, actorUserId, findingId, JSON.stringify({ disposition: input.disposition })]);
      return updated;
    });
  }

  async listEvaluatedEventIds(organizationId: string, modelId: string): Promise<string[]> {
    const result = await this.pool.query("SELECT event_id FROM detection_event_evaluations WHERE organization_id=$1 AND model_id=$2", [organizationId, modelId]);
    return result.rows.map((row) => String(row.event_id));
  }

  async markEventsEvaluated(organizationId: string, modelId: string, eventIds: string[]): Promise<void> {
    for (const eventId of new Set(eventIds)) await this.pool.query("INSERT INTO detection_event_evaluations (organization_id,model_id,event_id) VALUES ($1,$2,$3) ON CONFLICT DO NOTHING", [organizationId, modelId, eventId]);
  }

  async createIncident(value: Incident, creationFingerprint: string): Promise<CreateIncidentResult> {
    return this.transaction(async (client) => {
      const inserted = await client.query(`INSERT INTO incidents
        (id,organization_id,reference,idempotency_key,creation_fingerprint,status,priority,severity,acknowledgement_due_at,resolution_due_at,result,created_at,updated_at)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
        ON CONFLICT (organization_id,idempotency_key) DO NOTHING RETURNING *`,
        [value.id, value.organizationId, value.reference, value.idempotencyKey, creationFingerprint, value.status, value.priority, value.severity, value.acknowledgementDueAt, value.resolutionDueAt, JSON.stringify(value), value.createdAt, value.updatedAt]);
      if (!inserted.rows[0]) {
        const existing = required((await client.query("SELECT * FROM incidents WHERE organization_id=$1 AND idempotency_key=$2", [value.organizationId, value.idempotencyKey])).rows[0]);
        if (String(existing.creation_fingerprint) !== creationFingerprint) throw Object.assign(new Error("Idempotency key was already used with different incident data."), { statusCode: 409 });
        return { incident: incident(existing), created: false };
      }
      await this.persistIncidentChildren(client, value, { evidence: true, timeline: true, tasks: true });
      await client.query("INSERT INTO audit_events (organization_id,actor_user_id,event_type,resource_type,resource_id,metadata) VALUES ($1,$2,'incident.created','incident',$3,$4)", [value.organizationId, value.createdByUserId, value.id, JSON.stringify({ reference: value.reference, priority: value.priority })]);
      return { incident: value, created: true };
    });
  }

  async getIncident(organizationId: string, incidentId: string): Promise<Incident | undefined> {
    const result = await this.pool.query("SELECT * FROM incidents WHERE organization_id=$1 AND id=$2", [organizationId, incidentId]);
    return result.rows[0] ? incident(result.rows[0]) : undefined;
  }

  async listIncidents(organizationId: string): Promise<Incident[]> {
    const result = await this.pool.query("SELECT * FROM incidents WHERE organization_id=$1 ORDER BY updated_at DESC", [organizationId]);
    return result.rows.map(incident);
  }

  private async mutateIncident(organizationId: string, incidentId: string, actorUserId: string, eventType: string, update: (value: Incident) => Incident): Promise<Incident> {
    return this.transaction(async (client) => {
      const selected = await client.query("SELECT * FROM incidents WHERE organization_id=$1 AND id=$2 FOR UPDATE", [organizationId, incidentId]);
      if (!selected.rows[0]) throw Object.assign(new Error("Incident does not exist."), { statusCode: 404 });
      const before = incident(selected.rows[0]);
      const after = update(before);
      await client.query("UPDATE incidents SET status=$1,priority=$2,severity=$3,result=$4,updated_at=$5 WHERE organization_id=$6 AND id=$7", [after.status, after.priority, after.severity, JSON.stringify(after), after.updatedAt, organizationId, incidentId]);
      await this.persistIncidentChildren(client, after, { evidence: after.evidence.length > before.evidence.length, timeline: after.timeline.length > before.timeline.length, tasks: true });
      await client.query("INSERT INTO audit_events (organization_id,actor_user_id,event_type,resource_type,resource_id,metadata) VALUES ($1,$2,$3,'incident',$4,'{}'::jsonb)", [organizationId, actorUserId, eventType, incidentId]);
      return after;
    });
  }

  async transitionIncident(organizationId: string, incidentId: string, input: IncidentStatusUpdateRequest, actorUserId: string): Promise<Incident> {
    return this.mutateIncident(organizationId, incidentId, actorUserId, "incident.status_changed", (value) => transitionIncident(value, input, actorUserId, systemClock));
  }
  async assignIncident(organizationId: string, incidentId: string, input: IncidentAssignmentRequest, actorUserId: string): Promise<Incident> {
    return this.mutateIncident(organizationId, incidentId, actorUserId, "incident.assignment_changed", (value) => assignIncident(value, input, actorUserId, systemClock));
  }
  async commentOnIncident(organizationId: string, incidentId: string, input: IncidentCommentRequest, actorUserId: string): Promise<Incident> {
    return this.mutateIncident(organizationId, incidentId, actorUserId, "incident.commented", (value) => commentOnIncident(value, input, actorUserId, systemClock));
  }
  async linkIncidentEvidence(organizationId: string, incidentId: string, input: IncidentEvidenceLinkRequest, actorUserId: string): Promise<Incident> {
    return this.mutateIncident(organizationId, incidentId, actorUserId, "incident.evidence_linked", (value) => linkIncidentEvidence(value, input, actorUserId, systemClock));
  }
  async createIncidentTask(organizationId: string, incidentId: string, input: IncidentTaskCreateRequest, actorUserId: string): Promise<Incident> {
    return this.mutateIncident(organizationId, incidentId, actorUserId, "incident.task_created", (value) => createIncidentTask(value, input, actorUserId, systemClock));
  }
  async updateIncidentTask(organizationId: string, incidentId: string, taskId: string, input: IncidentTaskUpdateRequest, actorUserId: string): Promise<Incident> {
    return this.mutateIncident(organizationId, incidentId, actorUserId, "incident.task_updated", (value) => updateIncidentTask(value, taskId, input, actorUserId, systemClock));
  }

  private async persistIncidentChildren(client: PoolClient, value: Incident, options: { evidence: boolean; timeline: boolean; tasks: boolean }): Promise<void> {
    if (options.evidence) for (const item of value.evidence) await client.query(`INSERT INTO incident_evidence (id,organization_id,incident_id,kind,resource_id,rationale,linked_by_user_id,linked_at)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT DO NOTHING`, [item.id, value.organizationId, value.id, item.kind, item.resourceId, item.rationale, item.linkedByUserId, item.linkedAt]);
    if (options.timeline) for (const item of value.timeline) await client.query(`INSERT INTO incident_timeline (id,organization_id,incident_id,type,message,actor_user_id,occurred_at,metadata)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT DO NOTHING`, [item.id, value.organizationId, value.id, item.type, item.message, item.actorUserId, item.occurredAt, JSON.stringify(item.metadata)]);
    if (options.tasks) for (const item of value.tasks) await client.query(`INSERT INTO incident_tasks (id,organization_id,incident_id,status,result,created_at,updated_at)
      VALUES ($1,$2,$3,$4,$5,$6,$7) ON CONFLICT (organization_id,incident_id,id) DO UPDATE SET status=EXCLUDED.status,result=EXCLUDED.result,updated_at=EXCLUDED.updated_at`, [item.id, value.organizationId, value.id, item.status, JSON.stringify(item), item.createdAt, item.updatedAt]);
  }

  private async transaction<T>(operation: (client: PoolClient) => Promise<T>): Promise<T> {
    const client = await this.pool.connect();
    try { await client.query("BEGIN"); const result = await operation(client); await client.query("COMMIT"); return result; }
    catch (error) { await client.query("ROLLBACK"); throw error; }
    finally { client.release(); }
  }
}

function required<T>(value: T | undefined): T {
  if (value === undefined) throw new Error("Database operation returned no row.");
  return value;
}

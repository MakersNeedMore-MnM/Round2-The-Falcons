# Cascadia final delivery roadmap

Deployment is deliberately the final phase. Each phase delivers durable functionality and is verified before moving forward.

## Completed foundation — Phases 1–37

Platform, PostgreSQL persistence, asset/dependency inventory, CSV imports, SBOM evidence, signed SIEM/EDR intake, TAXII, vulnerabilities, attack paths, response simulation, ML review, incidents, OIDC, console UI, topology, notifications, evidence graph, data quality, governance, compliance readiness, vendor catalog, PWA, resilience readiness, and executive analytics.

## Remaining build phases

### Phase 38 — Production hardening

Container release gate, health checks, protected metrics, structured logs, backup and restore runbook, dependency scanning, rate limits, and release rollback procedure.

### Phase 39 — Durable custom compliance frameworks

Tenant-authored frameworks, controls, owners, assessment history, evidence attestation, export classification, and append-only control decisions. Requires joint approval of a PostgreSQL migration.

### Phase 40 — Vendor activation

Entra OIDC, Resend email, Slack OAuth, Teams OAuth/webhook, and approved SIEM/EDR outbound source configuration. Requires provider credentials and approved redirect URLs.

### Phase 41 — Mobile operator companion

Mobile-first incident reading, secure session handling, accessibility review, and optional approved push delivery. No offline operational-data cache and no autonomous acknowledgement.

### Phase 42 — Release acceptance

Accessibility, performance, security testing, user acceptance testing, rollback drill, recovery drill, and production operational sign-off.

See `docs/phase-42-release-acceptance.md` for the release gate and required approvals.

### Phase 43 — CMDB, CSV, and SBOM discovery adapters

CMDB adapter contract, validated CSV mapping templates, CycloneDX/SPDX ingest, import preview, duplicate handling, provenance, error reports, and analyst approval before inventory mutation.

CMDB CSV, manual CSV, and CycloneDX JSON ingestion are completed; external CMDB API adapters remain a future connector expansion.

### Phase 44 — SCIM and Entra group-to-role mapping

SCIM 2.0 endpoints, Entra group mapping rules, lifecycle deprovisioning, reconciliation reports, immutable access audit records, and least-privilege review. Requires Entra P1 or a suitable identity tier.

### Phase 45 — Legal hold and advanced retention

Legal-hold records, scope-by-organization/resource, hold approval and release workflow, retention exceptions, evidence preservation, deletion guardrails, and audit exports. Requires joint approval of the retention schema migration.

The durable `legal_holds` migration foundation is included. API workflow and purge enforcement remain paired work so an active hold cannot be bypassed.

### Phase 46 — Multi-region recovery and restore testing

Primary/secondary-region topology, encrypted backups, recovery point and recovery time objectives, restore verification, DNS failover runbook, disaster-recovery exercises, and immutable restore evidence. Requires paid persistent infrastructure.

The recovery topology and restore-drill runbook are completed; cloud resources and the first recorded drill are deployment-gated.

### Phase 47 — External assessor evidence bundles

Signed evidence manifest, selected audit/control/incident evidence exports, SHA-256 integrity hashes, classification checks, expiring download authorization, and assessor activity audit trail.

### Phase 48 — Dedicated connector adapters and health SLAs

Versioned Splunk, Sentinel, Elastic, Defender, and CrowdStrike adapters; source-schema versioning; delivery freshness targets; connector SLA status; retries; dead-letter evidence; and operator-controlled remediation.

The signed webhook connector health SLA and operator remediation workflow are completed. Dedicated vendor-schema adapters are activation-gated by provider credentials and test tenants.

### Phase 49 — Data governance and privacy controls

Data inventory, field-level classification review, data-subject/export policy where applicable, privacy impact assessment records, and sensitive-data redaction verification.

The current engineering governance baseline is documented; jurisdiction-specific legal and privacy review remains an organizational responsibility.

### Phase 50 — Scale and reliability engineering

Load and soak tests, PostgreSQL performance tuning, queue/backpressure design, capacity alerts, connection pooling, rate-limit tuning, and service-level objectives.

The reliability foundation and pre-production capacity gate are documented; actual load/soak results are deployment-environment evidence.

### Phase 51 — Security assurance and adversarial validation

Threat model update, dependency/SBOM scanning, secret scanning, SAST/DAST, penetration-test remediation tracking, and supply-chain attestation.

The final adversarial-validation gate is documented; an authorized production-environment penetration test is required before release.

### Phase 52 — Production deployment

Deploy only after all release gates pass:

1. Provision Azure Central India primary and South India recovery resources.
2. Configure managed PostgreSQL, Key Vault, encrypted backups, monitoring, custom domain, and TLS.
3. Apply migrations and verify health/readiness.
4. Configure Entra OIDC, provider secrets, approved redirect URLs, and notification destinations.
5. Run backup restore and rollback drill.
6. Run `npm run verify` and `npm run verify:release`.
7. Obtain product, security, and operations approval.
8. Deploy gradually and monitor error rate, latency, database health, and connector freshness.

## Required external inputs before Phase 52

- Azure subscription, domain, and billing approval.
- Microsoft Entra tenant/app registration and redirect URLs.
- Resend domain/API key; Slack and Teams app credentials if enabled.
- Vendor connector credentials and approved network egress paths.
- Named security, operations, and product approvers.

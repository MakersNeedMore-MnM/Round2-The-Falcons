# Phase 46 — Multi-region recovery and restore testing

## Target topology

- **Primary:** Azure Central India.
- **Recovery:** Azure South India.
- Managed PostgreSQL backups encrypted at rest; application secrets held in Key Vault.
- Recovery-region application deployment is prebuilt but not promoted until an authorized incident decision.

## Recovery objectives

- Initial target RPO: 24 hours for a low-cost deployment, reduced after managed point-in-time recovery is funded.
- Initial target RTO: 4 hours, measured from the declaration of a production-region outage.
- These are targets, not claims of achieved recovery until a recorded restore drill passes.

## Restore drill

1. Create a fresh encrypted PostgreSQL backup.
2. Restore into an isolated recovery database; never overwrite the primary during a test.
3. Run migrations, `/health/ready`, and PostgreSQL integration tests against the restored environment.
4. Verify tenant boundaries, audit evidence, legal holds, assets, incidents, integrations, and ML model records.
5. Record actual RPO/RTO, failures, owner, remediation, and approval in the release evidence.

## Failover guardrail

Only an authorized human incident commander and operations owner may approve DNS/database cutover. Cascadia does not autonomously promote a region, restore a backup, or reroute traffic.

# Phase 47 — External assessor evidence bundles

`GET /api/v1/evidence/assessor-bundle` returns a confidential, tenant-scoped evidence manifest for platform administrators, organization administrators, and auditors. It includes an integrity SHA-256 hash and summary counts only; raw telemetry is excluded.

Deployment can add an approved KMS/Key Vault signing key for a cryptographic signature. The bundle is not a compliance certificate.

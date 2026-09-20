# Phase 49 — Data governance and privacy controls

## Implemented controls

- Tenant-scoped authorization and data access boundaries.
- Data classification on asset records: public, internal, confidential, and restricted.
- Organization retention policy for raw events, normalized events, and audit evidence.
- Append-only audit evidence.
- Browser-side secret prohibition and server-side secret encryption for integrations.
- Confidential assessor and executive summaries that exclude raw telemetry.
- Legal-hold data model foundation for retention exceptions.

## Required operating practice

1. Classify imported assets and attached evidence before sharing them.
2. Minimize source payload fields before forwarding telemetry into Cascadia.
3. Review retention values with security, privacy, and legal owners.
4. Apply an active legal hold before any matching retention purge.
5. Use assessor exports only for approved recipients and preserve their integrity hash.
6. Review integration secrets, OIDC clients, and access roles at least quarterly.

## Boundary

This is an engineering governance baseline, not legal advice or a declaration of GDPR, DPDP, HIPAA, ISO, or other regulatory compliance. Counsel and a privacy owner must validate applicable obligations.

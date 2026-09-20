# Phase 51 — Security assurance and adversarial validation

## Automated assurance

- Run `npm run verify` and the PostgreSQL release gate.
- Review dependency updates and scan lockfiles in CI.
- Run secret scanning on the repository and deployment configuration.
- Validate TypeScript/Zod boundaries, migration checks, and static analysis.

## Adversarial validation

1. Verify cross-tenant access attempts are rejected.
2. Test expired, forged, replayed, and malformed signed source deliveries.
3. Test hostile source text as inert data; it must never become executable instructions.
4. Verify CSRF protection, session revocation, OIDC MFA requirements, and role restrictions.
5. Test SSRF/outbound URL controls for TAXII and webhook destinations.
6. Verify disabled connectors, duplicate events, and unsupported STIX objects are safe no-ops.
7. Conduct an authorized external penetration test before production and track every finding to remediation or documented acceptance.

## Supply-chain boundary

Produce a build SBOM, pin dependencies, keep production secrets out of Git, and use a cloud secret manager. No security review result may be represented as a guarantee of invulnerability.

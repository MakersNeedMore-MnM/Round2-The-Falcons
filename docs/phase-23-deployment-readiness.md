# Phase 23: deployment readiness

## Delivered

- Administrator-only API endpoint: `GET /api/v1/system/deployment-readiness`.
- Console readiness center at `/app/deployment`.
- Secret-safe configuration checks for PostgreSQL, OIDC/MFA, HTTPS, dedicated secrets, and production web serving.

## Boundary

The readiness center reports configuration state only. It cannot register an identity provider, obtain a TLS certificate, configure DNS, create secrets, or deploy infrastructure on behalf of an operator.

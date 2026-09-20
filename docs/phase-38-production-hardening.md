# Phase 38 — Production hardening

## Required deployment controls

- Run the API with `NODE_ENV=production`, PostgreSQL, OIDC, HTTPS, and separate JWT, integration-encryption, and observability secrets.
- Use the container health endpoint at `/health/ready` for deployment health checks.
- Enable protected Prometheus metrics using `OBSERVABILITY_TOKEN`.
- Apply migrations before serving traffic: `node apps/api/dist/migrate.js`.
- Set resource, error-rate, database, and backup-failure alerts in the cloud platform.

## Release gate

Run `npm run verify`, `npm run verify:release`, restore a database backup into an isolated environment, and validate OIDC MFA before a production release.

Free Render deployments are excluded from this gate because they are not durable production infrastructure.

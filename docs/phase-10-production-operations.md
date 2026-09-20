# Phase 10: production operations and observability

## Delivered scope

- Separate liveness (`/health/live`) and PostgreSQL-backed readiness (`/health/ready`) probes.
- Authenticated organization-facing system status with live database latency, process uptime, and safety-invariant reporting.
- Prometheus-compatible process and HTTP metrics without tenant, user, asset, event, or incident labels.
- Dedicated observability secret with constant-time comparison.
- Structured Fastify production logging with authorization, cookie, webhook-signature, and response-cookie redaction.
- Global HTTP security headers and a restrictive same-origin Content Security Policy.
- Patched IPv6-aware request rate limiting, plus a stricter SSO-login limit.
- Explicit trusted-proxy hop configuration.
- Graceful SIGINT/SIGTERM shutdown with a bounded ten-second deadline.
- Production multi-stage container serving the compiled API and React frontend as one origin.
- A production Compose topology with a private data network, healthy PostgreSQL dependency, and one-shot migration gate.
- GitHub Actions verification using PostgreSQL 17 and the live persistence integration test.
- Streaming PostgreSQL backup command that writes binary custom-format dumps beneath `backups/`.
- Operator-facing **System Health** console page refreshing every thirty seconds.
- Honest offline handling on the Phase 9 connection page.

## Local startup

```powershell
docker compose up -d postgres
npm.cmd run migrate -w @cascadia/api
npm.cmd run dev
```

The launcher reports the API and frontend only after each responds. It separately warns when PostgreSQL readiness fails. The login screen now displays an explicit API-offline state and keeps the development-token controls available in a development build.

## Production deployment

1. Copy `.env.production.example` to `.env.production`.
2. Replace every placeholder with an independently generated secret and the registered HTTPS OIDC values.
3. Run `docker compose -f compose.production.yaml up -d --build`.
4. Terminate TLS at a trusted reverse proxy in front of `127.0.0.1:8080`.
5. Register `https://your-host/api/auth/callback` with the identity provider.
6. Check `/health/ready` before routing traffic.

The database is not published on a host port in the production topology. The application becomes eligible to start only after PostgreSQL is healthy and every ordered migration succeeds.

## Metrics

Send the dedicated secret in `x-cascadia-observability` when scraping `/metrics`. Metrics deliberately use bounded method, route-template, and status labels; they never include tenant or resource identifiers.

## Backup and recovery

Create a PostgreSQL custom-format backup:

```powershell
npm.cmd run backup:postgres
```

Backups may contain restricted operational evidence. Encrypt and move them into an approved backup system immediately. Test restoration into an isolated PostgreSQL instance before relying on a backup. Recovery into production is intentionally not automated because it is destructive and requires an approved incident/change procedure.

## Deployment boundaries

- A real OIDC provider, TLS certificate, DNS, secret manager, monitoring collector, and backup destination are deployment inputs rather than repository-generated credentials.
- Readiness returns only `ready` or `unavailable`; database errors and connection details are not exposed.
- Observability does not alter telemetry, train models, create incidents, schedule TAXII, or authorize response execution.

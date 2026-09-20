# Phase 25: release hardening

## Delivered

- Repeatable release-gate command: `npm run verify:release`.
- Checks that the local Docker PostgreSQL service is running.
- Applies ordered migrations, runs repository verification, and runs the live PostgreSQL integration test.
- Clear fail-fast guidance when PostgreSQL is unavailable.

## Release sequence

```powershell
docker compose up -d postgres
npm.cmd run verify:release
```

For an actual production release, also complete the Deployment Readiness checklist, perform an approved backup-restore exercise, configure an HTTPS reverse proxy and real OIDC provider, then obtain change approval.

# Phase 0 foundation

## Purpose

Phase 0 establishes the safety, tenant, contract, and audit boundaries that every later Cascadia capability must use. It intentionally contains no telemetry collection, ML inference, response execution, or browser-side decision logic.

## Workspace

```text
apps/api                 Fastify HTTP boundary
packages/contracts       shared Zod schemas and public types
docs                     architecture and operating decisions
```

## Security boundaries

- A JWT principal always carries a user ID, organization ID, and role.
- All organization-scoped writes enforce the caller's organization boundary.
- Recommendations require human approval at the contract boundary.
- Untrusted feeds, logs, and future live-source content are evidence only; they are never treated as executable instructions.
- The agent feed is strictly read-only. It never discovers, generates, publishes, or writes an audit event.
- Published posts are append-only and are listed newest first.
- Every post contract requires UTC timestamps, rationale, and source URLs.

## Phase 1 replacement seams

The in-memory store is deliberately isolated in `apps/api/src/store.ts`. Phase 1 replaces it with PostgreSQL repositories, object storage for evidence, and an encrypted audit sink without changing public request/response contracts.

## Required production decisions before Phase 1

1. Select a tenant identity provider and establish SSO/MFA requirements.
2. Define hospital pilot data classification and approved retention durations.
3. Agree which read-only data sources will be connected first: CMDB, EDR, SIEM, or vulnerability management.
4. Approve an operator action taxonomy, including actions that must always require two-person authorization.
5. Define the availability, backup, recovery-time, and data-residency objectives for the pilot.

## Local verification

```powershell
npm.cmd install --cache .npm-cache
npm.cmd run verify --cache .npm-cache
git diff --check
```

# Phase 1: real-data foundation

## Delivered scope

- PostgreSQL schema and atomic migration runner.
- Organization onboarding with sector and retention controls.
- Manual asset creation and idempotent updates through organization-scoped external IDs.
- CSV/CMDB and CycloneDX component imports with row-level rejection reporting.
- Asset dependency creation with same-tenant foreign-key enforcement.
- Authenticated SIEM/EDR event ingestion with source-level deduplication.
- Append-only database enforcement for published posts and audit events.

## Data flow

```text
User / CMDB / SBOM ──> validation ──> asset inventory ──> dependency graph
SIEM / EDR          ──> validation ──> deduplication   ──> event store
                                      audit evidence <── mutations
```

Live-source fields are stored as untrusted JSON evidence. They are never interpreted as commands. The ingestion API accepts only normalized envelopes; vendor-specific connector transformations belong in later connector packages.

## Local PostgreSQL setup

1. Copy `.env.example` to `.env` and choose matching `POSTGRES_PASSWORD` and `DATABASE_URL` credentials.
2. Start PostgreSQL with `docker compose up -d postgres`.
3. Run `npm.cmd run migrate -w @cascadia/api`.
4. Run `npm.cmd run dev -w @cascadia/api`.

Production refuses to start with the in-memory data store. Set `NODE_ENV=production`, `DATA_STORE=postgres`, and a secret-managed `DATABASE_URL`.

## CSV columns

The import endpoint accepts these normalized columns, with common underscore variants supported:

```csv
external_id,name,asset_type,criticality,classification,hostname,ip_address
cmdb-100,Patient Records DB,database,critical,restricted,patient-db-01,10.20.1.15
```

Required fields are `external_id` and `name`. Invalid rows are rejected individually while valid rows are imported.

## Security-event envelope

```json
{
  "source": "edr",
  "sourceEventId": "vendor-event-42",
  "eventType": "lateral_movement",
  "severity": "high",
  "observedAt": "2026-08-25T10:00:00Z",
  "assetExternalIds": ["cmdb-100"],
  "record": { "vendorFieldsRemainUntrusted": true }
}
```

Repeated ingestion of the same `(organization, source, sourceEventId)` returns the existing event with `duplicate: true` and does not create another record.

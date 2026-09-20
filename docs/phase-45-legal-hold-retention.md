# Phase 45 — Legal hold and advanced retention

The PostgreSQL foundation adds tenant-scoped legal-hold records with an active/released lifecycle, rationale, scope, release rationale, timestamps, and actor IDs.

## Guardrails

- Only an authorized human may create or release a hold.
- Release requires a rationale and is permanently attributable.
- A retention/purge worker must query active holds before deleting any matching record.
- Holds must not be implemented as client-side state or a UI-only label.

## Next implementation slice

The hold API, role workflow, and purge-worker enforcement must be introduced together after the migration is applied and jointly reviewed, so no retention task can bypass an active hold.

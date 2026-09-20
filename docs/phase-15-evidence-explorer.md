# Phase 15: evidence explorer

## Delivered

- Auditor and administrator endpoint: `GET /api/v1/audit-events`.
- Bounded read-only access to tenant-scoped append-only audit events.
- Console Evidence page at `/app/evidence` with action and resource search plus event-type filtering.

## Boundary

Reading or filtering evidence does not create an audit event, modify records, expose credentials, generate telemetry, or authorize any response activity.

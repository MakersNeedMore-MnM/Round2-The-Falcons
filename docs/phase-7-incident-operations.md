# Phase 7: incident operations

## Delivered scope

- Durable, tenant-scoped incident cases with human-readable references and idempotent creation.
- Priority-based acknowledgement and resolution SLA targets calculated from one UTC creation time.
- Controlled lifecycle transitions from triage through investigation, containment, recovery, resolution, and closure.
- Explicit reopening for resolved or closed incidents without erasing prior timeline evidence.
- Analyst assignment, comments, evidence links, and operational tasks.
- Append-only incident evidence and timeline records in PostgreSQL.
- Evidence validation against stored security events, anomaly findings, risk analyses, response scenarios, and threat indicators in the same organization.
- Explainable correlation candidates based on shared assets and bounded observation windows.
- Duplicate suppression for idempotency keys, evidence links, and ML findings already linked to an incident.
- Auditing for every case mutation.

## Human-control boundary

Correlation is a read-only decision-support operation. It returns candidates with `requiresAnalystConfirmation: true`, `incidentCreated: false`, and a count of zero automatically created incidents. It does not publish, execute containment, create response scenarios, or change finding dispositions.

Creating a case, changing its status, assigning it, linking evidence, and changing a task all require an authenticated organization operator. Read-only roles can inspect incidents and their timelines.

## Lifecycle and SLAs

Allowed forward transitions are `new -> triaged -> investigating -> contained -> recovering -> resolved -> closed`. Investigation and containment can also resolve directly. Resolved and closed incidents may be reopened to investigation. Resolution and closure require a resolution summary.

SLA targets are persisted at creation:

| Priority | Acknowledge | Resolve |
| --- | ---: | ---: |
| P1 | 15 minutes | 4 hours |
| P2 | 30 minutes | 8 hours |
| P3 | 2 hours | 24 hours |
| P4 | 8 hours | 72 hours |

## API

- `POST /api/v1/incidents`
- `GET /api/v1/incidents`
- `GET /api/v1/incidents/:incidentId`
- `GET /api/v1/incidents/:incidentId/timeline`
- `POST /api/v1/incidents/correlate`
- `POST /api/v1/incidents/:incidentId/status`
- `POST /api/v1/incidents/:incidentId/assignment`
- `POST /api/v1/incidents/:incidentId/comments`
- `POST /api/v1/incidents/:incidentId/evidence`
- `POST /api/v1/incidents/:incidentId/tasks`
- `PATCH /api/v1/incidents/:incidentId/tasks/:taskId`

## PostgreSQL

Migration `008_phase_7_incident_operations.sql` creates incident, evidence, timeline, and task tables. Incident creation and every mutation use database transactions and row locking. Evidence and timeline tables reject updates and deletes. The complete validated incident representation is retained with indexed operational columns, while evidence, timeline entries, and tasks are also available relationally.

No autonomous scheduler, incident creation, response execution, or simulated telemetry is introduced in this phase.

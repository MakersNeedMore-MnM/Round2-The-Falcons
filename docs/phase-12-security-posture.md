# Phase 12: explainable security posture

## Delivered

- Read-only posture endpoint: `GET /api/v1/posture`.
- A transparent 0–100 score and grade calculated from stored vulnerabilities, analyst findings, open incidents, active integrations, assets, and critical services.
- Prioritized remediation queue with source and rationale.
- Governance & Posture console page for human review.

## Boundary

The posture score is decision support only. It does not claim compliance, create incidents, change data, train models, schedule work, or authorize containment.

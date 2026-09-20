# Phase 3: response decision intelligence

## Delivered scope

- Organization-scoped response policy configuration.
- What-if comparison of asset, dependency, identity, remote-access, indicator-blocking, and shutdown actions.
- Deterministic security-benefit, operational-impact, and residual-risk estimates.
- Policy gates for prohibited actions, operational-impact ceilings, rollback requirements, approval counts, and authorized roles.
- Safe-option recommendation only when at least one candidate passes every policy check.
- Distinct-operator approvals, rejection handling, duplicate-decision prevention, and immutable decision evidence.
- Persistent response scenarios and decisions in PostgreSQL.

## Safety invariant

Every scenario returns `executionAuthorized: false`, including a scenario whose approval status is `approved`. Approval records organizational consent for a later controlled integration; it does not send a command to EDR, IAM, firewall, medical, or OT systems.

If every candidate is prohibited or otherwise fails policy, the scenario is `blocked` and has no `recommendedOptionId`.

## Simulation model

Security benefit is the percentage of aggregate path risk covered by the assets or dependencies targeted by a candidate. Residual risk is the highest remaining unblocked path score.

Operational impact uses:

- Criticality of services reached by affected paths.
- Whether the candidate directly targets a service asset.
- Proportion of attack paths affected.
- Whether the change is reversible.
- A fixed impact of 100 for service shutdown.

The recommendation ranks eligible options using:

`utility = securityBenefit * 0.7 - operationalImpact * 0.3`

These are explainable decision-support estimates, not claims about guaranteed containment or service behavior.

## API surface

- `POST /api/v1/response-policies`
- `GET /api/v1/response-policies`
- `POST /api/v1/responses/simulate`
- `GET /api/v1/responses`
- `GET /api/v1/responses/:scenarioId`
- `POST /api/v1/responses/:scenarioId/decisions`

Response decisions require an allowed JWT role. Separate actor IDs are required to satisfy multiple approval slots, and an actor cannot submit a second decision for the same option.

## PostgreSQL

Migration `003_phase_3_response_decisions.sql` adds response policies, response scenarios, and append-only response decisions. Scenarios remain mutable only for workflow state and their accumulated decision snapshot; individual decision rows cannot be updated or deleted.

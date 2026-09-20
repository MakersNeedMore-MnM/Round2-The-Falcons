# Phase 16: connector operations

## Delivered

- Console connector control room at `/app/connectors`.
- Explicit enable/disable control for signed telemetry connections.
- Administrator-only signing-secret rotation with one-time display of the replacement secret.
- Read-only signed delivery evidence per connector.

## Boundary

These controls do not connect to external systems, replay payloads, generate telemetry, or authorize incident response. Operators must configure the generated secret in the source system themselves.

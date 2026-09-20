# Phase 50 — Scale and reliability engineering

## Existing reliability foundation

- Liveness and readiness endpoints.
- Protected Prometheus metrics with no tenant labels.
- Rate limiting, request-size limits, security headers, and structured-log redaction.
- PostgreSQL persistence, migrations, and integration tests.
- Idempotent source delivery, duplicate protection, bounded TAXII retries, and disabled-source no-op behavior.

## Pre-production capacity gate

1. Run a load test against a non-production environment with representative signed delivery payloads.
2. Measure API latency, error rate, PostgreSQL connections, CPU, memory, and slow queries.
3. Verify rate limits reject excess traffic without preventing normal operator use.
4. Test database restart, connector outage, malformed payload, duplicate delivery, and recovery behavior.
5. Establish alert thresholds for readiness failures, error rate, latency, disk, connection pool saturation, and stale connectors.
6. Record capacity assumptions and rollback thresholds in release evidence.

## Scaling boundary

Do not add background autonomous agents or client-side decisions to improve throughput. Scale stateless API instances, database capacity, approved queues, and observability only after measured load evidence supports the change.

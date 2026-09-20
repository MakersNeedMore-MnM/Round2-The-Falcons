# Phase 39 — Durable custom compliance frameworks

## Approved next migration scope

The next database migration will add tenant-scoped framework, control, ownership, assessment, and external-evidence tables. It requires joint schema approval before implementation.

Each assessment must retain rationale, author, timestamp, linked evidence IDs, and an append-only history. A control cannot be automatically marked compliant from missing telemetry.

## Initial framework choices

- Cascadia Core Controls (already implemented as evidence-based readiness)
- NIST CSF 2.0 mapping pack
- ISO 27001 mapping pack
- Sector-specific OT/critical-infrastructure pack

No framework output is a certification or legal conclusion.

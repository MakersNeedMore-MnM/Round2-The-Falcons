# Phase 43 — CMDB, CSV, and SBOM discovery adapters

Completed capabilities:

- CMDB CSV and manual CSV asset import.
- CycloneDX JSON component inventory import.
- Explicit local-file selection and preview before import.
- Zod validation of every row; rejected-row reasons returned to the operator.
- Durable asset upsert by external ID, avoiding duplicate inventory records.
- Import provenance recorded in asset metadata.

The importer does not scan a network, call an external CMDB, fabricate assets, create dependencies, or ingest telemetry automatically. Future vendor CMDB API adapters must use this same validation and operator-confirmation boundary.

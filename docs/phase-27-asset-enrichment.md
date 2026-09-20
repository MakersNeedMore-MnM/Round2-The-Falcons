# Phase 27 — Asset intelligence

Asset records can now carry a lifecycle, owner team, and optional SBOM evidence. The enrichment endpoint updates only an existing tenant asset and preserves its original inventory identity.

The UI does not generate component inventories. An operator supplies an SBOM format, component count, and optionally a source URL and generation time. This keeps the asset context durable and traceable without simulated telemetry.

## API

`PATCH /api/v1/assets/:assetId/enrichment` is available to organization administrators, security analysts, and OT engineers.


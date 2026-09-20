# Phase 48 — Connector health SLAs

## Implemented health evidence

The Data Quality screen and `GET /api/v1/data-quality` calculate connector freshness from durable signed-delivery timestamps:

- **Current:** delivery stored within 24 hours.
- **Stale:** latest stored delivery is older than 24 hours.
- **No data:** no signed delivery has been stored.
- **Disabled:** source is intentionally disabled.

This is a data-freshness SLA, not a claim about vendor-service availability or complete upstream event coverage.

## Operator remediation

1. Review Connector Ops delivery evidence and integration status.
2. Confirm source configuration, signing secret version, payload schema, and egress path.
3. Rotate the signing secret only through Connector Ops and update the source system.
4. Send a real test delivery; verify its durable delivery record and freshness state.
5. Record the incident or change decision in the appropriate workflow.

## Future dedicated adapters

Splunk, Sentinel, Elastic, Defender, and CrowdStrike adapters will add provider-schema versioning and provider-specific validation once provider credentials and approved test tenants are available. Every adapter must retain the same HMAC verification, replay protection, tenant isolation, and no-op behavior for disabled sources.

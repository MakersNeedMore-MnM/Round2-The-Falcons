# Phase 4: live integrations and threat intelligence

## Delivered scope

- Tenant-scoped connector registration for generic webhooks, Splunk, Microsoft Sentinel, Elastic Security, CrowdStrike, Microsoft Defender, and TAXII provenance.
- A one-time webhook secret returned only during creation or rotation.
- AES-256-GCM encryption for connector secrets at rest, using a server-only encryption key.
- HMAC-SHA256 request authentication over the exact raw request body.
- A five-minute timestamp window to reject delayed replay attempts.
- Immutable external delivery IDs, payload hashes, and delivery receipts.
- Atomic PostgreSQL ingestion of normalized SIEM/EDR events or STIX 2.1 indicators.
- Connector disable/enable controls, secret rotation, delivery history, and last-delivery health evidence.
- Duplicate deliveries are successful no-ops; a reused delivery ID with different content is rejected.

Provider names currently record provenance and intended source. Security products send Cascadia's normalized event envelope directly or through their supported forwarding/transformation layer. This phase does not claim vendor-native polling or autonomous TAXII synchronization.

## Webhook signing

Send these headers:

- `x-cascadia-timestamp`: current Unix time in seconds.
- `x-cascadia-delivery-id`: a stable unique ID from the source delivery.
- `x-cascadia-signature`: `v1=` followed by the lowercase hexadecimal HMAC-SHA256 digest.

The signed bytes are:

`timestamp + "." + deliveryId + "." + exactRawRequestBody`

The webhook secret is displayed only when a connector is created or rotated. It is never included in connector list or delivery responses.

## Security-event envelope

`POST /api/v1/integrations/:integrationId/webhook`

```json
{
  "events": [
    {
      "sourceEventId": "vendor-event-42",
      "eventType": "lateral_movement",
      "severity": "high",
      "observedAt": "2026-08-26T10:00:00Z",
      "assetExternalIds": ["nurse-station-7"],
      "record": {}
    }
  ]
}
```

The connector assigns the trusted `siem` or `edr` source configured by an organization administrator. Source records remain untrusted evidence and cannot trigger response execution.

## Threat-intelligence envelope

STIX connectors accept a STIX 2.1 bundle containing Indicator objects. Indicator patterns, labels, confidence, validity, and external-reference URLs are normalized and retained. The implementation follows the OASIS STIX 2.1 indicator model; TAXII 2.1 scheduled collection synchronization is intentionally reserved for a later outbound-connector phase.

- [OASIS STIX 2.1](https://docs.oasis-open.org/cti/stix/v2.1/stix-v2.1.html)
- [OASIS TAXII 2.1](https://docs.oasis-open.org/cti/taxii/v2.1/os/taxii-v2.1-os.html)

## Management API

- `POST /api/v1/integrations`
- `GET /api/v1/integrations`
- `PATCH /api/v1/integrations/:integrationId/status`
- `POST /api/v1/integrations/:integrationId/rotate-secret`
- `GET /api/v1/integrations/:integrationId/deliveries`
- `GET /api/v1/threat-indicators`
- `POST /api/v1/integrations/:integrationId/webhook`

Only the webhook endpoint is unauthenticated by JWT; it requires its connector-specific HMAC secret. Management and evidence endpoints remain protected by tenant-aware JWT roles.

## PostgreSQL

Migration `004_phase_4_live_integrations.sql` creates connector, immutable delivery, and threat-indicator tables. A connector delivery, all normalized records, its health timestamp, and audit evidence are committed in one database transaction.

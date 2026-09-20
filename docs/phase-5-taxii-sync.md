# Phase 5: operator-controlled TAXII synchronization

## Delivered scope

- Outbound TAXII 2.1 collection sources connected to an existing tenant-owned STIX integration.
- No-authentication, HTTP Basic, and Bearer authentication options with server-side AES-256-GCM credential encryption.
- Operator-triggered synchronization only; `autonomousSchedulingEnabled` is permanently `false` in this phase.
- TAXII 2.1 media types, collection-object URLs, `added_after` checkpoints, `next` pagination tokens, and a 100-page safety limit.
- Durable synchronization jobs and append-only per-page attempt evidence.
- At most three attempts for network errors, HTTP 429, and HTTP 5xx responses, using bounded exponential delays.
- Atomic ingestion through the Phase 4 delivery and threat-indicator persistence boundary.
- Checkpoints advance only after every page succeeds. Failed jobs retain the previous checkpoint.
- Only one job may run per source, and successful checkpoints update monotonically so concurrent or delayed completion cannot move a source backward.
- Identical pages produce duplicate delivery no-ops across separate jobs.

The implementation follows the [OASIS TAXII 2.1 collection model](https://docs.oasis-open.org/cti/taxii/v2.1/os/taxii-v2.1-os.html) and normalizes supported Indicator objects using [OASIS STIX 2.1](https://docs.oasis-open.org/cti/stix/v2.1/stix-v2.1.html). Other STIX object types are counted as received but are not treated as indicators.

## Outbound-network boundary

- API roots must use HTTPS, end in `/`, and cannot contain embedded credentials.
- DNS results and literal IP addresses are checked before requests; loopback, link-local, private, carrier-grade NAT, benchmark, multicast, and reserved destinations are rejected.
- Redirects are rejected rather than followed.
- Each request has a ten-second timeout and a five-megabyte response limit.
- Only `application/taxii+json` responses with HTTP 200 are parsed.
- Decrypted credentials are used only to construct the server-side Authorization header and never appear in API responses, jobs, attempts, or audit metadata.

## Management API

- `POST /api/v1/taxii-sources`
- `GET /api/v1/taxii-sources`
- `PATCH /api/v1/taxii-sources/:sourceId/status`
- `POST /api/v1/taxii-sources/:sourceId/sync`
- `GET /api/v1/taxii-sources/:sourceId/jobs`

Creating or enabling a source requires an organization administrator. Organization administrators and security analysts can initiate a sync. Read access follows the existing tenant-aware evidence roles.

## Scheduling boundary

No timer, cron process, background poller, or startup hook invokes synchronization. Adding scheduled execution changes autonomous scheduling behavior and therefore requires the joint approval specified in `AGENTS.md`.

## PostgreSQL

Migration `005_phase_5_taxii_sync.sql` adds TAXII sources, durable sync jobs, and append-only attempts. Successful completion updates the source checkpoint and job record in one transaction. Every fetched page is ingested through the existing integration-delivery transaction.

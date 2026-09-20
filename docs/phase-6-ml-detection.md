# Phase 6: explainable ML-assisted detection

## Delivered scope

- Organization-specific baseline training using stored normalized SIEM and EDR events only.
- Manual model training with configurable lookback, minimum-event requirement, and finding threshold.
- Versioned model artifacts with one active model per organization and automatic retirement of the prior version.
- Frequency, severity, asset-novelty, and robust hourly-volume features.
- Median and median absolute deviation volume baselines to reduce sensitivity to extreme training values.
- Manual evaluation of telemetry ingested after the active model was trained.
- Idempotent per-model/event evaluation records, including true no-op behavior when nothing new remains.
- Explainable anomaly findings with factor scores, plain-language reasoning, and supporting evidence values.
- Append-only analyst review records and auditable dispositions.
- Model cards describing purpose, data provenance, limitations, and safety boundaries.

## Model boundary

The algorithm is `explainable_frequency_baseline_v1`. It is a deterministic statistical prioritization model, not a probability-of-compromise estimator. Its score combines:

- Event-type rarity: 35%.
- Source-reported severity: 25%.
- Asset novelty: 25%.
- Hourly volume deviation: 15%.

Scores at or above the model's configured threshold produce findings. Every result carries all four factors, even when a factor contributes zero.

Models train only from `normalized_security_events` already stored for the organization. Live-source records remain untrusted data: record text is never interpreted as executable instruction or used to authorize a response.

## Governance

The design applies NIST AI RMF principles for documented provenance, transparency, explainability, evaluation, and human oversight. See the [NIST AI RMF Core](https://airc.nist.gov/airmf-resources/airmf/5-sec-core/) and [AI risks and trustworthiness guidance](https://airc.nist.gov/airmf-resources/airmf/3-sec-characteristics/).

Each model card states:

- Training data came from the organization's normalized security events.
- Scores are organization-specific and are not probabilities of compromise.
- Rare legitimate activity can score highly.
- Repeated malicious activity can become statistically less rare.
- Human review is mandatory.
- Autonomous response authorization is always false.

## API

- `POST /api/v1/detection/models/train`
- `GET /api/v1/detection/models`
- `POST /api/v1/detection/evaluate`
- `GET /api/v1/detection/findings`
- `POST /api/v1/detection/findings/:findingId/disposition`

Training and evaluation require an organization administrator or security analyst. Findings are readable by existing tenant evidence roles. Disposition requires an organization administrator, security analyst, or incident commander.

## PostgreSQL

Migration `007_phase_6_ml_detection.sql` creates model, finding, review, and per-event evaluation tables. Model/event and finding/event relationships use organization-scoped foreign keys. Reviews and evaluation markers are append-only.

No timer or event-ingestion hook trains or evaluates models in this phase. Operators explicitly trigger both operations, and neither operation creates response scenarios or authorizes containment.

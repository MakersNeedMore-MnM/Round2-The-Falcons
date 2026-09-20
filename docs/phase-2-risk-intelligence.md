# Phase 2: risk and attack-path intelligence

## Delivered scope

- Vulnerability/exposure records tied to tenant-scoped assets.
- Critical-service definitions with recovery objectives and supporting assets.
- Bounded, cycle-safe directed attack-path traversal.
- Critical-service blast-radius analysis.
- Transparent likelihood, operational-impact, and combined risk scores.
- Evidence-based MITRE ATT&CK for ICS mappings.
- Append-only persisted analysis snapshots and audit evidence.

## Analysis flow

```text
Entry assets
    -> bounded dependency traversal
    -> paths reaching critical-service assets
    -> vulnerability + exploit + event enrichment
    -> operational impact from service and asset criticality
    -> explained risk score + blast radius + ATT&CK evidence
```

The engine never discovers assets, changes infrastructure, or executes a response. It analyzes previously validated tenant data and stores a dated evidence snapshot.

## Score model

Likelihood is capped at 100 and combines:

- 15 points when a reachable topology path exists.
- Up to 35 points from the highest open CVSS score on the path.
- Up to 25 points from exploit evidence.
- Up to 25 points from normalized event severity.
- 10 points when the path crosses a dependency marked critical.

Impact is capped at 100 and combines:

- 65% of the target service's criticality score.
- 25% of the highest asset criticality on the path.
- Up to 10 points for short maximum tolerable downtime.

`riskScore = round(likelihoodScore × impactScore / 100)`

Risk levels are low (`0–24`), medium (`25–49`), high (`50–74`), and critical (`75–100`). These values are deterministic prioritization scores, not probabilities.

## API surface

- `POST /api/v1/vulnerabilities` and `GET /api/v1/vulnerabilities`
- `POST /api/v1/critical-services` and `GET /api/v1/critical-services`
- `POST /api/v1/risk/attack-paths`
- `GET /api/v1/risk/analyses`

The analysis request accepts one to fifty tenant-owned entry asset IDs and a maximum traversal depth from one to ten. Traversal is limited to 10,000 examined paths and 100 returned service-reaching paths to prevent graph explosion.

## ATT&CK evidence

Mappings are emitted only when normalized events on reachable assets match a curated technique mapping. Phase 2 includes ICS mappings for Remote Services (`T0886`), Exploitation of Remote Services (`T0866`), User Execution (`T0863`), External Remote Services (`T0822`), Denial of Service (`T0814`), and Unauthorized Command Message (`T1692.001`).

Authoritative references:

- https://attack.mitre.org/techniques/T0886/
- https://attack.mitre.org/techniques/T0866/
- https://attack.mitre.org/techniques/T0863/
- https://attack.mitre.org/techniques/T0822/
- https://attack.mitre.org/techniques/ics/

## Known boundary

Topology direction follows the recorded `sourceAssetId -> targetAssetId` relationship. Data owners must model attack-relevant direction deliberately. Bidirectional reachability requires two dependency records. Phase 3 response simulation must consume these stored analyses without silently changing this meaning.

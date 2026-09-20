# Cascadia

### Resilience Intelligence for Critical Infrastructure

[![Live Demo](https://img.shields.io/badge/Live%20Demo-Cascadia-red)](https://cascadia-production-f26d.up.railway.app/?release=cache-v2)

Cascadia is a safety-governed cyber decision platform for critical infrastructure. It unifies asset inventory, operational telemetry, explainable detection, threat intelligence, incident operations, and human-approved response decisions in one live operational system.

## Team

**The Falcons**

- Fuzail Ahmad
- Lakshya Garg
- Aryan Rai

## Problem Statement

Critical infrastructure teams receive security signals from disconnected systems such as asset inventories, SIEM platforms, EDR tools, vulnerability scanners, and threat-intelligence feeds. This makes it difficult to understand which assets and services are truly at risk, trace likely attack paths, and coordinate a safe response.

Automated response can create additional operational risk when decisions are made without context, evidence, or human review. Cascadia addresses this by combining real operational data with explainable analysis and a governed response workflow where human control remains absolute.

## Solution

Cascadia creates a single resilience picture for an organization. It maps assets and dependencies, normalizes telemetry, identifies explainable anomalies, enriches findings with threat intelligence, models attack paths and blast radius, and guides operators through evidence-backed incident decisions.

The platform is built around three principles:

- **Real telemetry only:** operational views are based on stored organizational data and signed integrations.
- **Explainable intelligence:** findings include supporting evidence and understandable reasoning.
- **Human-governed response:** recommendations require appropriate approval and the platform never executes autonomous response actions.

## Key Features

### Operational Visibility

- Organization-aware resilience overview
- Asset and dependency inventory
- Critical-service and topology mapping
- System posture and data-quality views
- Executive brief and resilience-readiness reporting

### Data Ingestion and Integrations

- CSV, CMDB, and CycloneDX inventory imports
- Normalized SIEM and EDR event ingestion
- Signed live webhooks with replay protection
- Encrypted connector secrets
- Connector catalog for Splunk, Microsoft Sentinel, Elastic Security, CrowdStrike, Microsoft Defender, and generic webhooks
- STIX 2.1 threat-indicator ingestion
- Controlled TAXII collection synchronization

### Detection and Intelligence

- Explainable organization-specific ML baselines
- Idempotent anomaly evaluation
- Human-reviewed ML findings
- Vulnerability and critical-service context
- Explainable attack paths and blast-radius analysis
- Evidence-linked MITRE ATT&CK mappings
- Threat graph and enrichment workflows

### Incident Response and Governance

- Durable incident lifecycle management
- SLA targets and analyst task queues
- Evidence timelines and signal correlation
- Response simulations with residual-risk comparison
- Rollback requirements and multi-operator approvals
- Response recommendations without autonomous execution
- Compliance, assurance, and audit views

### Audit Integrity and Safety

- Append-only audit trail
- Data classification and retention controls
- Human-approval policies
- MST Testnet anchoring for audit batches and decision proofs
- Wallet-based approval signatures
- Protected metrics, structured logs, readiness/liveness probes, and security headers

## Tech Stack

### Frontend

- React
- TypeScript
- Vite
- Three.js for the cinematic landing experience
- Responsive CSS interface
- Progressive Web App assets and service worker

### Backend

- Node.js 24+
- TypeScript
- REST API
- JWT authentication and role-based authorization
- OpenID Connect SSO with PKCE and MFA claim enforcement
- Zod-based contracts and validation

### Data and Infrastructure

- PostgreSQL
- SQL migrations and production persistence adapter
- Docker and Docker Compose
- Railway deployment configuration
- Render Blueprint for free-tier demonstration deployments

### Blockchain and Integrity

- Solidity smart contract: `CascadiaProofRegistry.sol`
- Hardhat
- MST Testnet
- SHA-256 audit and decision fingerprints
- Merkle-root audit batches

## Live Demo

The deployed application is available here:

**[Open Cascadia](https://cascadia-production-f26d.up.railway.app/?release=cache-v2)**

The application includes a public landing experience and an analyst console with operational, intelligence, governance, incident, integration, and readiness workflows.

## How to Run Locally

### Prerequisites

- Node.js 24 or later
- npm 11 or later
- Docker Desktop with Docker Compose
- PostgreSQL, either through Docker Compose or a local installation

### Installation

```bash
git clone <repository-url>
cd Cascadia-main
npm install
```

Copy the development environment file:

```bash
copy .env.example .env
```

On macOS/Linux:

```bash
cp .env.example .env
```

Update `.env` with strong local development values. At minimum, configure `JWT_SECRET`, `INTEGRATION_ENCRYPTION_KEY`, `POSTGRES_PASSWORD`, and `DATABASE_URL`.

### Start PostgreSQL

```bash
docker compose up -d postgres
```

### Run Database Migrations

```bash
npm run migrate -w @cascadia/api
```

### Verify the Project

```bash
npm run verify
```

This runs type checking, tests, and the production build.

### Start the Development Application

```bash
npm run dev
```

Open the frontend at `http://127.0.0.1:5173`.

For a local development token, run:

```bash
npm run dev:token
```

Use development credentials only locally. Never commit tokens, passwords, private keys, or production secrets to GitHub.

## Useful Commands

| Command | Purpose |
|---|---|
| `npm run dev` | Build and start the API and frontend locally |
| `npm run build` | Build all workspaces |
| `npm run typecheck` | Type-check contracts and workspaces |
| `npm test` | Run workspace tests |
| `npm run verify` | Run type checking, tests, and builds |
| `npm run migrate -w @cascadia/api` | Apply PostgreSQL migrations |
| `npm run test:postgres` | Run PostgreSQL integration tests |
| `npm run identity:bootstrap` | Bootstrap identity configuration |
| `npm run backup:postgres` | Create a PostgreSQL backup |
| `npm run verify:release` | Verify release readiness |

## Application Workflow

1. **Inventory:** register assets, dependencies, services, vulnerabilities, and organizational context.
2. **Telemetry:** ingest and normalize events from approved data sources.
3. **Detection:** evaluate telemetry using explainable detection and ML baselines.
4. **Intelligence:** enrich findings with threat indicators, ATT&CK mappings, attack paths, and blast radius.
5. **Incidents:** correlate signals, create evidence timelines, and assign analyst tasks.
6. **Response:** compare response options, record approvals, and preserve rollback and audit evidence.
7. **Assurance:** review compliance, readiness, system health, and executive reporting.

## Screenshots and Demo

The deployed demo showcases:

- A dark, cinematic landing page introducing Cascadia's five operational chapters: Inventory, Telemetry, Detection, Incidents, and Response.
- A resilience overview with monitored assets, stored events, open incidents, critical findings, telemetry severity, and control-state indicators.
- A connector catalog for Splunk, Microsoft Sentinel, Elastic Security, CrowdStrike, Microsoft Defender, and generic webhooks.

Screenshots can be added to this section from the project submission assets.

## Safety and Security Boundaries

- The API does not execute response actions.
- Recommendations remain human-controlled and require configured approval policies.
- External integration content is treated as untrusted evidence.
- Connector secrets are encrypted and replay protection is applied to signed deliveries.
- OIDC sessions use opaque HttpOnly cookies with CSRF protection and durable revocation.
- Production secrets must be stored in deployment environment variables or a secrets manager.
- Never commit `.env`, bearer tokens, wallet private keys, or database passwords.

## MST Decision Proof and Audit Integrity

Cascadia optionally anchors audit batches and approved response decision proofs on MST Testnet. Audit events are represented by SHA-256 Merkle roots, while approved decisions are represented by deterministic fingerprints and human wallet signatures. Only safe identifiers, labels, hashes, wallet addresses, and timestamps are intended to be sent on-chain.

MST configuration is optional and does not block core audit logging or response approval when unavailable. Configure it through environment variables documented in `.env.example` and deploy the contract from the `contracts` workspace when required.

## Deployment

The repository includes deployment configuration for Railway, Render, Docker, and Docker Compose. For a production deployment:

1. Configure production environment variables securely.
2. Provision PostgreSQL.
3. Apply migrations.
4. Build the workspaces.
5. Run the API and serve the compiled frontend.
6. Verify health, readiness, database connectivity, authentication, and audit behavior.

## Future Improvements

- Expand production connector coverage and provider-specific onboarding.
- Add more organization-specific detection models and evaluation datasets.
- Expand automated resilience-readiness reporting.
- Add broader audit-proof verification tooling for external reviewers.
- Continue improving accessibility, test coverage, and operational observability.

## License

This project was created by **The Falcons** for the Cascadia hackathon/project evaluation. Add the repository's applicable open-source or institutional license here if required by the submission guidelines.

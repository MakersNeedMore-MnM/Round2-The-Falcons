# Cascadia

Cascadia is a safety-governed cyber decision platform for critical infrastructure.

## Included foundations

- Strict TypeScript npm workspace and shared Zod contracts.
- Tenant-aware API foundation with JWT authentication and role-based authorization.
- Durable agent initialization, append-only post storage, and a read-only feed.
- Audit trail, data-classification, retention, and human-approval policy primitives.
- Tests for contracts, timestamps, authorization, duplicate initialization, and feed no-op behavior.
- PostgreSQL migrations and production persistence adapter.
- Organization onboarding, asset/dependency inventory, CSV/CMDB/CycloneDX imports, and SIEM/EDR event ingestion.
- Vulnerability context, critical-service modeling, explainable attack paths, blast-radius analysis, and evidence-linked MITRE ATT&CK mappings.
- Policy-governed response simulation, residual-risk comparison, rollback requirements, and multi-operator approvals with execution permanently disabled at this phase.
- Live signed integration webhooks, encrypted connector secrets, replay protection, immutable delivery evidence, and STIX 2.1 threat-indicator ingestion.
- Operator-controlled TAXII collection synchronization with safe outbound networking, pagination, checkpoints, bounded retries, and durable attempt evidence.
- Explainable organization-specific ML baselines, idempotent anomaly evaluation, model cards, and human-reviewed findings over real stored telemetry.
- A controlled live detection lab at `/app/lab` with predefined synthetic scenarios. It emits inert normalized events through the normal ingestion path, evaluates findings, and may create a synthetic-evidence incident; it never executes commands or authorizes response actions.
- Durable incident operations with SLA targets, controlled lifecycle transitions, evidence timelines, analyst tasks, and human-confirmed signal correlation.
- Cinematic Three.js landing experience and responsive analyst console connected to real assets, telemetry, ML findings, attack paths, incidents, responses, and integrations.
- Production OpenID Connect SSO with PKCE, enforced MFA claims, administrator-controlled enrollment, opaque HttpOnly sessions, CSRF protection, durable revocation, and an identity access console.
- Production operations with readiness/liveness probes, protected Prometheus metrics, redacted structured logs, security headers, patched rate limiting, graceful shutdown, containers, CI, backup tooling, and a live System Health console.

## Run locally

1. Copy `.env.example` to `.env` and set strong credentials.
2. Run `npm.cmd install`.
3. Start PostgreSQL with `docker compose up -d postgres`.
4. Run `npm.cmd run migrate -w @cascadia/api`.
5. Run `npm.cmd run verify`.
6. Run `npm.cmd run dev` to start the API and frontend together.
7. Configure OIDC using `docs/phase-9-identity-access.md`, or in development run `npm.cmd run dev:token`, then open `http://127.0.0.1:5173`.

The API deliberately does not execute response actions. Live integration content is treated as untrusted evidence, and every response recommendation remains human-controlled.

## Free-tier demo deployment

For a hackathon or short-lived demonstration, use the Render Blueprint in `render.yaml`. See [the free-tier deployment guide](docs/free-tier-development.md) for limits and the required future production upgrades.

For the complete remaining build and production sequence, see [the final delivery roadmap](docs/final-delivery-roadmap.md).
## MST Decision Proof and Audit Integrity

Cascadia can optionally anchor two kinds of integrity evidence on MST Testnet. Audit events are batched into a SHA-256 Merkle root without including metadata or telemetry. Approved response decisions are reduced to a deterministic SHA-256 fingerprint and signed by the approving user's registered wallet. The shared registry proves that a specific audit batch or a specific human wallet attested to a decision at a timestamp, without requiring a judge, auditor, or regulator to trust Cascadia's database.

The contract is deployed by running the deployment script; record the resulting address here:

```text
MST_CONTRACT_ADDRESS=0x84190B50C05819443e757b42A1C14De0C94353c2
```

MST Testnet configuration:

```env
MST_RPC_URL=https://testnetrpc.mstblockchain.com
MST_CHAIN_ID=91562037
MST_EXPLORER_URL=https://testnet.mstscan.com
MST_DEPLOYER_PRIVATE_KEY=<funded deployer key; never commit this>
MST_CONFIRMATIONS=1
MST_TX_TIMEOUT_SECONDS=120
MST_AUDIT_ANCHOR_INTERVAL_MINUTES=60
```

Fund the deployer with test `tMSTC` at https://faucet.mstblockchain.com/, then deploy from `contracts/`:

```powershell
npx hardhat run scripts/deploy.cjs --config hardhat.config.cjs --network mst
```

Wallet ownership is administrator-controlled. An organization administrator starts a challenge in the Identity page, and the user's EIP-1193 wallet signs it. BridgeKey can be used through its injected provider when available; MetaMask configured for MST Testnet is the documented fallback. The private key used by the API only pays gas and never signs for an approver.

Audit anchoring is manual through the Evidence page or `POST /api/v1/admin/audit-anchors/run`, and is also optionally swept hourly when MST credentials are configured. A failed chain operation does not block audit logging, response approval, or any execution boundary.

Real Testnet examples should be recorded before release:

```text
Contract: https://testnet.mstscan.com/address/0x84190B50C05819443e757b42A1C14De0C94353c2
Audit batch: https://testnet.mstscan.com/tx/0x39562e6e6140b6b11f0a57c2b401ba17a916112fc3164a254e6f04d7b7a32535
Decision proof: <MSTScan transaction link>
```

Acceptance checklist:

- Existing audit logging and `applyResponseDecision()` behavior are unchanged when MST is unavailable.
- Only safe IDs, labels, hashes, wallet addresses, and timestamps are sent on-chain.
- Server-held keys pay gas only; human decision signatures come from the registered wallet.
- `getAuditBatch()` and `getDecisionRecord()` are public read-only calls.
- Editing source records after anchoring produces a verification mismatch.
- PostgreSQL migrations apply through `npm run migrate -w @cascadia/api`.
- Merkle, canonical-hash, signature, and mismatch tests pass.

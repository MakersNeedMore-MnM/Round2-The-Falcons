# Phase 8: cinematic operations frontend

## Delivered scope

- Cinematic public landing page translated from the supplied visual reference into Cascadia branding.
- Original cinematic hydroelectric environment created for Cascadia and optimized as a local WebP asset; no third-party reference artwork is shipped.
- Video-inspired chapter pacing with persistent atmospheric scenery, oversized typography, deep-black editorial transitions, vertical chapter progress, and a mobile-first composition.
- Live Three.js resilience field with topology terrain, orbit rings, connected signal nodes, a wireframe intelligence core, pointer and scroll depth, high-DPI sizing, reduced-motion support, and complete WebGL teardown.
- Responsive analyst console with desktop, tablet, and mobile navigation.
- Tab-scoped API access-token connection; no JWT secret or autonomous decision logic is bundled in the browser.
- Real PostgreSQL-backed overview metrics and telemetry severity distribution.
- Asset inventory, dependency metrics, service/vulnerability totals, and a live topology plane.
- Explainable ML finding review and operator-triggered evaluation.
- Attack-path entry selection, manual analysis, blast-radius totals, and ranked path factors.
- Incident creation, signal-correlation review, controlled status transitions, SLA display, and append-only timeline presentation.
- Response scenario and residual-risk comparison.
- Integration status, threat-indicator totals, and operator-triggered TAXII synchronization.
- Validated API responses using the shared Zod contracts.
- Loading, error, retry, and honest empty states. No simulated telemetry is displayed.

## Local operation

1. Copy `.env.example` to `.env` and set local secrets.
2. Start PostgreSQL: `docker compose up -d postgres`.
3. Apply migrations: `npm.cmd run migrate -w @cascadia/api`.
4. Start the complete API and frontend: `npm.cmd run dev`.
5. In a second terminal, issue an eight-hour local token for the newest organization: `npm.cmd run dev:token`.
6. Open `http://127.0.0.1:5173`, choose **Open console**, and paste the token.

An explicit organization UUID and role may be supplied as arguments to the API token command. For example:

`npm.cmd run dev:token -w @cascadia/api -- 00000000-0000-0000-0000-000000000000 security_analyst`

Local token issuance is prohibited when `NODE_ENV=production`. Phase 9 now supplies production OIDC SSO, MFA enforcement, and revocable HttpOnly sessions; the pasted-token path remains development-only.

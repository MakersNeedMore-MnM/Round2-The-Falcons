# Phase 40 — Vendor integration activation

The signed webhook intake and vendor catalog are implemented. Activate external integrations only after creating provider applications and storing secrets in the host's secret manager.

## Activation order

1. Microsoft Entra OIDC application: production redirect `https://YOUR_DOMAIN/api/auth/callback`; require MFA claims.
2. Resend: verify a sending domain, store API key server-side, and configure an approved sender.
3. Slack OAuth app: define callback URL, minimal scopes, encrypted token storage, and operator-approved channel selection.
4. Microsoft Teams: register Entra app/OAuth or approved webhook; keep tokens server-side.
5. Splunk, Sentinel, Elastic, CrowdStrike, Defender: configure an outbound action to Cascadia's signed endpoint; never put the HMAC secret in browser code.

Before enabling any source, test signature validation, duplicate delivery, disabled-source no-op behavior, and tenant isolation.

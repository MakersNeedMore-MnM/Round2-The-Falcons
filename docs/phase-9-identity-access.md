# Phase 9: production identity and access

## Delivered scope

- OpenID Connect Authorization Code flow with S256 PKCE, state, nonce, discovery, verified ID-token processing, and one-time ten-minute login transactions.
- Mandatory MFA evidence from configured `amr` or provider-specific `acr` claims. Password-only authentication is rejected.
- Administrator-controlled enrollment by verified email. The provider subject is bound only after the first successful verified login; provider claims never assign Cascadia roles.
- Opaque 256-bit browser session tokens. Only SHA-256 token hashes are stored in PostgreSQL.
- Secure `__Host-cascadia_session` HttpOnly, Secure, SameSite=Strict production cookie and a session-bound double-submit CSRF token for every state-changing browser request.
- Durable expiry, last-seen tracking, logout revocation, audit evidence, and a maximum of five active sessions per user.
- Identity Access console for enrollment and least-privilege role review.
- Local bearer-token access remains available in development and test environments only.
- One-time database bootstrap command for the first organization administrator.

## Identity-provider configuration

Register this redirect URI with the OpenID provider:

`https://your-cascadia-host.example/api/auth/callback`

Set the following server-side values. None belong in the Vite/browser environment:

```dotenv
PUBLIC_APP_URL=https://your-cascadia-host.example
OIDC_ISSUER_URL=https://identity.example.com/
OIDC_CLIENT_ID=cascadia-web
OIDC_CLIENT_SECRET=replace-with-provider-client-secret
OIDC_MFA_AMR_VALUES=mfa,otp,hwk,fido,webauthn
OIDC_MFA_ACR_VALUES=
SESSION_TTL_MINUTES=480
```

Use `OIDC_MFA_ACR_VALUES` when the provider expresses assurance with a provider-specific ACR instead of AMR. At least one configured MFA value must be present in the verified ID token.

## First administrator

After applying migration `009_phase_9_identity_access.sql`, enroll the first administrator once from a trusted server terminal:

```powershell
npm.cmd run identity:bootstrap -- <organization-uuid> admin@example.com "Administrator Name"
```

The command closes permanently for that organization after the first identity exists. Further people are enrolled in **Operations → Identity** by an organization administrator.

## Local verification

```powershell
docker compose up -d postgres
npm.cmd run migrate -w @cascadia/api
npm.cmd run verify
npm.cmd run dev
```

When OIDC is not configured locally, `npm.cmd run dev:token` provides the explicit development-only bearer fallback. Production configuration validation requires PostgreSQL, HTTPS application and issuer URLs, an independent integration key, and complete OIDC credentials.

## Security boundaries

- Cascadia does not store provider access or refresh tokens.
- Browser JavaScript cannot read the session credential.
- Unenrolled, disabled, email-unverified, non-MFA, expired, replayed, or ambiguously multi-tenant identities are denied.
- Logout invalidates the durable session before clearing cookies.
- Existing human approval and no-autonomous-execution rules remain unchanged.

# Phase 42 — Release acceptance

## Automated release gate

Run these commands against the intended release commit:

```powershell
npm.cmd run verify
npm.cmd run verify:release
git diff --check
```

`verify:release` requires Docker PostgreSQL, applies migrations, runs the full test suite, and runs the live PostgreSQL integration test.

## Required manual acceptance

- Accessibility: keyboard navigation, visible focus, zoom at 200%, screen-reader labels, contrast, and mobile touch targets.
- Security: production OIDC MFA flow, session revocation, CSRF mutations, authorization boundaries, secret redaction, rate limits, and CSP headers.
- Reliability: `/health/live`, `/health/ready`, protected `/metrics`, database backup, isolated restore validation, and rollback rehearsal.
- Product: asset import, signed source delivery, alert/finding review, incident lifecycle, response simulation, audit evidence, and executive export.

## Sign-off record

Before deployment, record approval from product, security, and operations owners. Any failed check blocks release; no live source, notification destination, or response action may be enabled as a release workaround.

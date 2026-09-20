# Free-tier development deployment

Use this configuration only for a hackathon, demo, or development environment.

## Chosen free stack

- **Hosting and PostgreSQL:** Render Free through `render.yaml`.
- **Email (when enabled):** Resend Free, currently limited to 3,000 emails/month.
- **Slack:** a single-workspace Slack app on a Free workspace.
- **Identity:** Microsoft Entra ID Free for basic SSO and group management.
- **Teams:** use an organization-provided Microsoft 365 tenant; no paid service is configured by this repository.

## Deploy

1. Push this repository to GitHub.
2. In Render, create a Blueprint from the repository. It reads `render.yaml`.
3. Set `PUBLIC_APP_URL` to the generated Render HTTPS URL.
4. Do not set notification or OIDC variables until you have created and approved the corresponding provider applications.

## Free-tier limits

Render free web services sleep when idle, and its free PostgreSQL databases expire after 30 days. Therefore this deployment is **not production**, cannot provide reliable monitoring, and must not be used as the sole copy of sensitive data. See the official [Render Free limitations](https://render.com/docs/free).

## Future paid upgrades

- Persistent managed PostgreSQL with automated point-in-time recovery.
- Always-on compute, custom domain, uptime monitoring, and alerting.
- Entra ID P1 for SCIM/API-driven provisioning and advanced identity governance.
- Resend paid plan once delivery volume exceeds the Free limit.
- Azure Key Vault, Blob Storage backup, and Central India → South India disaster recovery.
- Dedicated Slack/Teams OAuth apps and approved production redirect URLs.

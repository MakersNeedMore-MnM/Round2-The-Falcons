# Railway deployment

Railway is the preferred simple host for Cascadia because it can run the API container and PostgreSQL together. Vercel is not suitable as the sole host because Cascadia requires a persistent Node API and database.

1. In Railway, create a project from `FuzailAhmad-Sphericaljudge/Cascadia`.
2. Add a PostgreSQL service.
3. Add these variables to the application service:

```env
NODE_ENV=production
DATA_STORE=postgres
SERVE_WEB=true
DATABASE_URL=${{Postgres.DATABASE_URL}}
JWT_SECRET=<long random value>
INTEGRATION_ENCRYPTION_KEY=<different long random value>
OBSERVABILITY_TOKEN=<different long random value>
PUBLIC_APP_URL=https://YOUR_RAILWAY_DOMAIN
```

4. Generate a Railway public domain and replace `PUBLIC_APP_URL` with it.
5. Deploy. The Docker image runs migrations before starting the API and exposes `/health/ready`.

Do not configure OIDC, notification, Slack, Teams, or email secrets until their provider applications are approved.

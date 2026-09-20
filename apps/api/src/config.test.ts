import assert from "node:assert/strict";
import test from "node:test";
import { loadConfig } from "./config.js";

const secret = "test-secret-at-least-thirty-two-characters-long";

test("production configuration requires PostgreSQL", () => {
  assert.throws(() => loadConfig({ NODE_ENV: "production", DATA_STORE: "memory", JWT_SECRET: secret }));
});

test("PostgreSQL configuration requires a database URL", () => {
  assert.throws(() => loadConfig({ NODE_ENV: "development", DATA_STORE: "postgres", JWT_SECRET: secret }));
});

test("production requires a separate integration encryption key", () => {
  assert.throws(() => loadConfig({ NODE_ENV: "production", DATA_STORE: "postgres", DATABASE_URL: "postgresql://localhost/cascadia", JWT_SECRET: secret }));
});

test("production requires complete HTTPS OIDC and observability configuration", () => {
  const base = { NODE_ENV: "production", DATA_STORE: "postgres", DATABASE_URL: "postgresql://localhost/cascadia", JWT_SECRET: secret, INTEGRATION_ENCRYPTION_KEY: "integration-key-at-least-thirty-two-characters", PUBLIC_APP_URL: "https://cascadia.example", OIDC_ISSUER_URL: "https://identity.example/", OIDC_CLIENT_ID: "cascadia", OIDC_CLIENT_SECRET: "provider-secret-at-least-sixteen" };
  assert.throws(() => loadConfig(base));
  assert.equal(loadConfig({ ...base, OBSERVABILITY_TOKEN: "monitoring-secret-at-least-thirty-two-characters" }).NODE_ENV, "production");
});

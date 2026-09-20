import assert from "node:assert/strict";
import test from "node:test";
import { buildApp } from "./app.js";
import { InMemoryCascadiaStore } from "./store.js";

const config = {
  NODE_ENV: "test" as const, PORT: 3000, HOST: "127.0.0.1", DATA_STORE: "memory" as const,
  JWT_SECRET: "test-secret-at-least-thirty-two-characters-long", PUBLIC_APP_URL: "http://127.0.0.1:5173",
  OIDC_MFA_AMR_VALUES: "mfa,otp", OIDC_MFA_ACR_VALUES: "", SESSION_TTL_MINUTES: 480,
  OBSERVABILITY_TOKEN: "observability-secret-at-least-thirty-two-characters", REQUESTS_PER_MINUTE: 300,
  SERVE_WEB: false, WEB_DIST_DIR: "apps/web/dist",
  TRUST_PROXY_HOPS: 0,
};

test("liveness and readiness report real process and store state", async () => {
  const app = buildApp(config, new InMemoryCascadiaStore());
  const live = await app.inject({ method: "GET", url: "/health/live" });
  const ready = await app.inject({ method: "GET", url: "/health/ready" });
  assert.equal(live.statusCode, 200);
  assert.equal(live.json().status, "live");
  assert.equal(ready.statusCode, 200);
  assert.deepEqual(ready.json().database, { status: "ready", latencyMs: 0 });
  assert.equal(ready.headers["x-content-type-options"], "nosniff");
  await app.close();
});

test("Prometheus metrics require the dedicated token and contain no tenant labels", async () => {
  const app = buildApp(config, new InMemoryCascadiaStore());
  await app.inject({ method: "GET", url: "/health" });
  assert.equal((await app.inject({ method: "GET", url: "/metrics" })).statusCode, 401);
  const metrics = await app.inject({ method: "GET", url: "/metrics", headers: { "x-cascadia-observability": config.OBSERVABILITY_TOKEN } });
  assert.equal(metrics.statusCode, 200);
  assert.match(metrics.body, /cascadia_http_requests_total/);
  assert.doesNotMatch(metrics.body, /organization|user_id|asset_id/);
  await app.close();
});

test("readiness degrades without leaking database errors", async () => {
  const store = new InMemoryCascadiaStore();
  store.checkHealth = async () => { throw new Error("secret database hostname"); };
  const app = buildApp(config, store);
  const response = await app.inject({ method: "GET", url: "/health/ready" });
  assert.equal(response.statusCode, 503);
  assert.equal(response.json().database.status, "unavailable");
  assert.doesNotMatch(response.body, /secret database hostname/);
  await app.close();
});

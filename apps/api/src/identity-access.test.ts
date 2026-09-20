import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import test from "node:test";
import { buildApp } from "./app.js";
import { digest, hasVerifiedMfa } from "./identity-service.js";
import { InMemoryCascadiaStore } from "./store.js";

const config = {
  NODE_ENV: "test" as const, PORT: 3000, HOST: "127.0.0.1", DATA_STORE: "memory" as const,
  JWT_SECRET: "test-secret-at-least-thirty-two-characters-long", PUBLIC_APP_URL: "http://127.0.0.1:5173",
  OIDC_MFA_AMR_VALUES: "mfa,otp", OIDC_MFA_ACR_VALUES: "", SESSION_TTL_MINUTES: 480,
  REQUESTS_PER_MINUTE: 300, SERVE_WEB: false, WEB_DIST_DIR: "apps/web/dist",
  TRUST_PROXY_HOPS: 0,
};

test("MFA policy accepts configured AMR or ACR and rejects password-only claims", () => {
  assert.equal(hasVerifiedMfa({ amr: ["pwd", "otp"] }, "mfa,otp", "urn:example:aal2"), true);
  assert.equal(hasVerifiedMfa({ acr: "urn:example:aal2" }, "mfa,otp", "urn:example:aal2"), true);
  assert.equal(hasVerifiedMfa({ amr: ["pwd"] }, "mfa,otp", "urn:example:aal2"), false);
});

test("OIDC login attempts are one-time and expired attempts are rejected", async () => {
  const store = new InMemoryCascadiaStore();
  const attempt = { stateHash: digest("state"), codeVerifier: "verifier", nonce: "nonce", returnTo: "/app", expiresAt: new Date(Date.now() + 60_000).toISOString() };
  await store.createOidcLoginAttempt(attempt);
  assert.deepEqual(await store.consumeOidcLoginAttempt(attempt.stateHash), attempt);
  assert.equal(await store.consumeOidcLoginAttempt(attempt.stateHash), undefined);
  const expired = { ...attempt, stateHash: digest("expired"), expiresAt: new Date(Date.now() - 1).toISOString() };
  await store.createOidcLoginAttempt(expired);
  assert.equal(await store.consumeOidcLoginAttempt(expired.stateHash), undefined);
});

test("identity enrollment is administrator-controlled", async () => {
  const store = new InMemoryCascadiaStore();
  const app = buildApp(config, store);
  await app.ready();
  const actor = randomUUID();
  const organization = await store.createOrganization({ name: "Regional Grid", sector: "energy", retention: { rawEventsDays: 30, normalizedEventsDays: 180, auditEvidenceDays: 2555 } }, actor);
  const admin = app.jwt.sign({ sub: actor, organizationId: organization.id, role: "organization_admin" });
  const viewer = app.jwt.sign({ sub: randomUUID(), organizationId: organization.id, role: "viewer" });
  const payload = { email: "Analyst@Example.com", displayName: "Grid Analyst", role: "security_analyst" };
  assert.equal((await app.inject({ method: "POST", url: "/api/v1/identity/enrollments", headers: { authorization: `Bearer ${viewer}` }, payload })).statusCode, 403);
  const response = await app.inject({ method: "POST", url: "/api/v1/identity/enrollments", headers: { authorization: `Bearer ${admin}` }, payload });
  assert.equal(response.statusCode, 201);
  assert.equal(response.json().email, "analyst@example.com");
  assert.equal(store.auditEvents.at(-1)?.eventType, "identity.user_enrolled");
  await app.close();
});

test("opaque cookie sessions require CSRF for mutation and are durably revoked", async () => {
  const store = new InMemoryCascadiaStore();
  const app = buildApp(config, store);
  await app.ready();
  const actor = randomUUID();
  const organization = await store.createOrganization({ name: "Water Authority", sector: "water", retention: { rawEventsDays: 30, normalizedEventsDays: 180, auditEvidenceDays: 2555 } }, actor);
  const user = await store.enrollIdentityUser(organization.id, { email: "operator@example.com", displayName: "Water Operator", role: "incident_commander" }, actor);
  const opaque = "session-token-with-at-least-thirty-two-characters";
  const csrf = "csrf-token-with-at-least-thirty-two-characters";
  await store.createIdentitySession({ tokenHash: digest(opaque), csrfTokenHash: digest(csrf), user, organizationId: organization.id, role: "incident_commander", mfaVerified: true, issuer: "https://identity.example/", subject: "operator-1", expiresAt: new Date(Date.now() + 60_000).toISOString() });
  const cookie = `cascadia_session=${opaque}; cascadia_csrf=${csrf}`;
  const current = await app.inject({ method: "GET", url: "/api/auth/session", headers: { cookie } });
  assert.equal(current.statusCode, 200);
  assert.equal(current.json().mfaVerified, true);
  assert.equal((await app.inject({ method: "POST", url: "/api/auth/logout", headers: { cookie } })).statusCode, 403);
  assert.equal((await app.inject({ method: "POST", url: "/api/auth/logout", headers: { cookie, "x-cascadia-csrf": csrf } })).statusCode, 204);
  assert.equal((await app.inject({ method: "GET", url: "/api/auth/session", headers: { cookie } })).statusCode, 401);
  await app.close();
});

test("SSO status never exposes provider configuration", async () => {
  const app = buildApp(config, new InMemoryCascadiaStore());
  const response = await app.inject({ method: "GET", url: "/api/auth/status" });
  assert.deepEqual(response.json(), { oidcEnabled: false, localBearerEnabled: true });
  await app.close();
});

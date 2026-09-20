import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import test from "node:test";
import { createIntegration } from "./integration-service.js";
import { InMemoryCascadiaStore, type Clock } from "./store.js";
import { createTaxiiSource, isPrivateAddress, runTaxiiSync, type TaxiiHttpClient, type TaxiiHttpResponse } from "./taxii-sync-service.js";

const masterKey = "taxii-test-encryption-key-at-least-thirty-two-characters";
const clock: Clock = { now: () => new Date("2026-08-26T12:00:00Z") };

class QueueClient implements TaxiiHttpClient {
  readonly requests: Array<{ url: URL; headers: Record<string, string> }> = [];
  constructor(private readonly responses: Array<TaxiiHttpResponse | Error>) {}
  async get(url: URL, headers: Record<string, string>): Promise<TaxiiHttpResponse> {
    this.requests.push({ url, headers });
    const response = this.responses.shift();
    if (!response) throw new Error("No mock response available.");
    if (response instanceof Error) throw response;
    return response;
  }
}

function indicator(name: string, modified = "2026-08-26T11:00:00Z") {
  return { type: "indicator", spec_version: "2.1", id: `indicator--${randomUUID()}`, created: "2026-08-26T10:00:00Z", modified, name, pattern: `[domain-name:value = '${name}.example']`, pattern_type: "stix", valid_from: "2026-08-26T10:00:00Z", confidence: 80, labels: ["malicious-activity"], external_references: [] };
}

function envelope(objects: unknown[], more = false, next?: string): TaxiiHttpResponse {
  return { status: 200, contentType: "application/taxii+json;version=2.1", body: JSON.stringify({ objects, more, ...(next ? { next } : {}) }) };
}

async function setup(authentication: Record<string, unknown> = { type: "none" }) {
  const store = new InMemoryCascadiaStore(clock);
  const actorUserId = randomUUID();
  const organization = await store.createOrganization({ name: "TAXII Sync Hospital", sector: "healthcare", retention: { rawEventsDays: 30, normalizedEventsDays: 180, auditEvidenceDays: 2555 } }, actorUserId);
  const target = await createIntegration(store, organization.id, { name: "TAXII Intake", provider: "taxii", dataType: "stix_bundle" }, actorUserId, masterKey);
  const source = await createTaxiiSource(store, organization.id, { name: "Sector Collection", integrationId: target.integration.id, apiRootUrl: "https://taxii.example/api/taxii2/", collectionId: "sector-health", authentication } as never, actorUserId, masterKey);
  return { store, actorUserId, organizationId: organization.id, target: target.integration, source };
}

test("operator-triggered TAXII sync paginates, authenticates, checkpoints, and ignores unsupported objects", async () => {
  const { store, actorUserId, organizationId, source } = await setup({ type: "basic", username: "soc", password: "secret" });
  assert.equal(source.autonomousSchedulingEnabled, false);
  assert.equal(store.taxiiSyncJobs.length, 0);
  const client = new QueueClient([
    envelope([indicator("first"), { type: "malware", id: `malware--${randomUUID()}` }], true, "page-two"),
    envelope([indicator("second")]),
  ]);
  const job = await runTaxiiSync(store, organizationId, source.id, actorUserId, masterKey, { client, clock, sleeper: async () => undefined });
  assert.equal(job.status, "succeeded");
  assert.equal(job.pagesFetched, 2);
  assert.equal(job.objectsReceived, 3);
  assert.equal(job.indicatorsAccepted, 2);
  assert.equal(job.attempts.length, 2);
  assert.equal(store.threatIndicators.length, 2);
  assert.equal(client.requests[0]?.headers.authorization, `Basic ${Buffer.from("soc:secret").toString("base64")}`);
  assert.equal(client.requests[0]?.url.searchParams.has("added_after"), false);
  assert.equal(client.requests[1]?.url.searchParams.get("next"), "page-two");
  assert.equal((await store.getTaxiiSource(organizationId, source.id))?.checkpointAddedAfter, job.startedAt);
});

test("retryable TAXII failures use bounded retries with append-only attempt evidence", async () => {
  const { store, actorUserId, organizationId, source } = await setup({ type: "bearer", token: "server-token" });
  const client = new QueueClient([
    { status: 503, contentType: "application/taxii+json", body: "{}" },
    { status: 429, contentType: "application/taxii+json", body: "{}" },
    envelope([indicator("recovered")]),
  ]);
  const delays: number[] = [];
  const job = await runTaxiiSync(store, organizationId, source.id, actorUserId, masterKey, { client, clock, sleeper: async (delay) => { delays.push(delay); } });
  assert.equal(job.status, "succeeded");
  assert.deepEqual(job.attempts.map((attempt) => [attempt.status, attempt.httpStatus]), [["failed", 503], ["failed", 429], ["succeeded", 200]]);
  assert.deepEqual(delays, [250, 500]);
  assert.equal(client.requests[0]?.headers.authorization, "Bearer server-token");
});

test("terminal failure preserves the prior checkpoint and does not create a delivery", async () => {
  const { store, actorUserId, organizationId, source } = await setup();
  const successful = await runTaxiiSync(store, organizationId, source.id, actorUserId, masterKey, { client: new QueueClient([envelope([])]), clock, sleeper: async () => undefined });
  const checkpoint = successful.checkpointAfter;
  const failed = await runTaxiiSync(store, organizationId, source.id, actorUserId, masterKey, { client: new QueueClient([{ status: 401, contentType: "application/taxii+json", body: "{}" }]), clock, sleeper: async () => undefined });
  assert.equal(failed.status, "failed");
  assert.equal(failed.errorCode, "http_401");
  assert.equal(failed.attempts.length, 1);
  assert.equal((await store.getTaxiiSource(organizationId, source.id))?.checkpointAddedAfter, checkpoint);
  assert.equal(store.integrationDeliveries.length, 1);
});

test("identical TAXII pages are duplicate no-ops across separate manual jobs", async () => {
  const { store, actorUserId, organizationId, source } = await setup();
  const object = indicator("stable");
  const response = envelope([object]);
  const first = await runTaxiiSync(store, organizationId, source.id, actorUserId, masterKey, { client: new QueueClient([response]), clock, sleeper: async () => undefined });
  const second = await runTaxiiSync(store, organizationId, source.id, actorUserId, masterKey, { client: new QueueClient([response]), clock, sleeper: async () => undefined });
  assert.equal(first.status, "succeeded");
  assert.equal(second.status, "succeeded");
  assert.equal(store.integrationDeliveries.length, 1);
  assert.equal(store.threatIndicators.length, 1);
  assert.equal(store.taxiiSyncJobs.length, 2);
});

test("disabled TAXII sources cannot start jobs", async () => {
  const { store, actorUserId, organizationId, source } = await setup();
  await store.updateTaxiiSourceStatus(organizationId, source.id, { status: "disabled" }, actorUserId);
  await assert.rejects(() => runTaxiiSync(store, organizationId, source.id, actorUserId, masterKey, { client: new QueueClient([]), clock }), /disabled/i);
  assert.equal(store.taxiiSyncJobs.length, 0);
});

test("only one TAXII sync job may run for a source", async () => {
  const { store, actorUserId, organizationId, source } = await setup();
  const running = await store.createTaxiiSyncJob(organizationId, source.id, actorUserId);
  await assert.rejects(() => store.createTaxiiSyncJob(organizationId, source.id, actorUserId), /already running/i);
  await store.finishTaxiiSyncJob(organizationId, running.id, { status: "failed", pagesFetched: 0, objectsReceived: 0, indicatorsAccepted: 0, errorCode: "test_cleanup", errorMessage: "Test cleanup." });
  assert.equal((await store.createTaxiiSyncJob(organizationId, source.id, actorUserId)).status, "running");
});

test("outbound destination guard identifies local and private network addresses", () => {
  for (const address of ["127.0.0.1", "10.1.2.3", "172.16.4.5", "192.168.1.10", "169.254.1.1", "::1", "fd00::1", "fe80::1"]) assert.equal(isPrivateAddress(address), true);
  assert.equal(isPrivateAddress("8.8.8.8"), false);
  assert.equal(isPrivateAddress("2606:4700:4700::1111"), false);
});

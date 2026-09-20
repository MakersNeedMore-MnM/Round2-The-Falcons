import { createCipheriv, createDecipheriv, createHash, createHmac, randomBytes, randomUUID, timingSafeEqual } from "node:crypto";
import {
  integrationCreateRequestSchema,
  securityEventWebhookSchema,
  stixBundleSchema,
  stixIndicatorSchema,
  type Integration,
  type IntegrationCreateRequest,
  type IntegrationCreateResult,
  type IntegrationDeliveryResult,
  type SecurityEventIngestRequest,
  type ThreatIndicator,
} from "@cascadia/contracts";
import type { CascadiaStore, Clock } from "./store.js";
import { systemClock } from "./store.js";

const MAX_CLOCK_SKEW_SECONDS = 300;

function encryptionKey(secret: string): Buffer {
  return createHash("sha256").update(secret, "utf8").digest();
}

export function encryptIntegrationSecret(secret: string, masterKey: string): string {
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", encryptionKey(masterKey), iv);
  const encrypted = Buffer.concat([cipher.update(secret, "utf8"), cipher.final()]);
  return ["v1", iv.toString("base64url"), cipher.getAuthTag().toString("base64url"), encrypted.toString("base64url")].join(".");
}

export function decryptIntegrationSecret(value: string, masterKey: string): string {
  const [version, iv, tag, encrypted] = value.split(".");
  if (version !== "v1" || !iv || !tag || !encrypted) throw new Error("Integration secret ciphertext is invalid.");
  const decipher = createDecipheriv("aes-256-gcm", encryptionKey(masterKey), Buffer.from(iv, "base64url"));
  decipher.setAuthTag(Buffer.from(tag, "base64url"));
  return Buffer.concat([decipher.update(Buffer.from(encrypted, "base64url")), decipher.final()]).toString("utf8");
}

export async function createIntegration(
  store: CascadiaStore,
  organizationId: string,
  rawInput: IntegrationCreateRequest,
  actorUserId: string,
  masterKey: string,
): Promise<IntegrationCreateResult> {
  const input = integrationCreateRequestSchema.parse(rawInput);
  const webhookSecret = randomBytes(32).toString("base64url");
  const integration = await store.createIntegration(organizationId, input, encryptIntegrationSecret(webhookSecret, masterKey), actorUserId);
  return { integration, webhookSecret, signingAlgorithm: "hmac-sha256" };
}

export async function rotateIntegrationSecret(
  store: CascadiaStore,
  organizationId: string,
  integrationId: string,
  actorUserId: string,
  masterKey: string,
): Promise<IntegrationCreateResult> {
  const webhookSecret = randomBytes(32).toString("base64url");
  const integration = await store.rotateIntegrationSecret(organizationId, integrationId, encryptIntegrationSecret(webhookSecret, masterKey), actorUserId);
  return { integration, webhookSecret, signingAlgorithm: "hmac-sha256" };
}

function verifySignature(secret: string, timestamp: string, deliveryId: string, rawBody: Buffer, supplied: string): void {
  const expected = createHmac("sha256", secret).update(timestamp).update(".").update(deliveryId).update(".").update(rawBody).digest("hex");
  const candidate = supplied.startsWith("v1=") ? supplied.slice(3) : supplied;
  const expectedBytes = Buffer.from(expected, "hex");
  const candidateBytes = /^[a-fA-F0-9]{64}$/.test(candidate) ? Buffer.from(candidate, "hex") : Buffer.alloc(0);
  if (candidateBytes.length !== expectedBytes.length || !timingSafeEqual(candidateBytes, expectedBytes)) {
    throw Object.assign(new Error("Webhook signature is invalid."), { statusCode: 401 });
  }
}

function validateTimestamp(timestamp: string, clock: Clock): void {
  if (!/^\d{10}$/.test(timestamp)) throw Object.assign(new Error("Webhook timestamp is invalid."), { statusCode: 401 });
  const skew = Math.abs(Math.floor(clock.now().getTime() / 1000) - Number(timestamp));
  if (skew > MAX_CLOCK_SKEW_SECONDS) throw Object.assign(new Error("Webhook timestamp is outside the replay window."), { statusCode: 401 });
}

function normalizeSecurityEvents(integration: Integration, body: unknown): SecurityEventIngestRequest[] {
  return securityEventWebhookSchema.parse(body).events.map((event) => ({ ...event, source: integration.eventSource! }));
}

export function normalizeStixIndicators(integration: Integration, objects: unknown[], receivedAt: string): ThreatIndicator[] {
  return objects.flatMap((value) => {
    const result = stixIndicatorSchema.safeParse(value);
    return result.success ? [result.data] : [];
  }).map((indicator) => ({
    id: randomUUID(),
    organizationId: integration.organizationId,
    integrationId: integration.id,
    stixId: indicator.id,
    name: indicator.name ?? indicator.id,
    description: indicator.description ?? "",
    pattern: indicator.pattern,
    confidence: indicator.confidence ?? 0,
    labels: indicator.labels,
    sourceUrls: [...new Set(indicator.external_references.flatMap((reference) => reference.url ? [reference.url] : []))],
    validFrom: indicator.valid_from,
    ...(indicator.valid_until ? { validUntil: indicator.valid_until } : {}),
    modifiedAt: indicator.modified,
    ingestedAt: receivedAt,
  }));
}

export function normalizeThreatIndicators(integration: Integration, body: unknown, receivedAt: string): ThreatIndicator[] {
  return normalizeStixIndicators(integration, stixBundleSchema.parse(body).objects, receivedAt);
}

export async function ingestSignedWebhook(
  store: CascadiaStore,
  integrationId: string,
  timestamp: string,
  deliveryId: string,
  signature: string,
  rawBody: Buffer,
  body: unknown,
  masterKey: string,
  clock: Clock = systemClock,
): Promise<IntegrationDeliveryResult> {
  if (!/^[\x21-\x7e]{1,200}$/.test(deliveryId)) throw Object.assign(new Error("Webhook delivery ID is invalid."), { statusCode: 400 });
  validateTimestamp(timestamp, clock);
  const credential = await store.getIntegrationCredential(integrationId);
  if (!credential) throw Object.assign(new Error("Integration does not exist."), { statusCode: 404 });
  if (credential.integration.status !== "active") throw Object.assign(new Error("Integration is disabled."), { statusCode: 409 });
  verifySignature(decryptIntegrationSecret(credential.secretCiphertext, masterKey), timestamp, deliveryId, rawBody, signature);
  const payloadSha256 = createHash("sha256").update(rawBody).digest("hex");
  const receivedAt = clock.now().toISOString();
  const events = credential.integration.dataType === "security_events" ? normalizeSecurityEvents(credential.integration, body) : [];
  const indicators = credential.integration.dataType === "stix_bundle" ? normalizeThreatIndicators(credential.integration, body, receivedAt) : [];
  return store.ingestIntegrationDelivery(credential.integration, deliveryId, payloadSha256, events, indicators);
}

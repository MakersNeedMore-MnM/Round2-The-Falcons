import { createHash, randomUUID } from "node:crypto";
import { lookup } from "node:dns/promises";
import { request as httpsRequest } from "node:https";
import { isIP } from "node:net";
import {
  taxiiEnvelopeSchema,
  taxiiSourceCreateRequestSchema,
  type TaxiiAuthentication,
  type TaxiiSource,
  type TaxiiSourceCreateRequest,
  type TaxiiSyncAttempt,
  type TaxiiSyncJob,
} from "@cascadia/contracts";
import { decryptIntegrationSecret, encryptIntegrationSecret, normalizeStixIndicators } from "./integration-service.js";
import { systemClock, type CascadiaStore, type Clock } from "./store.js";

const MAX_PAGES = 100;
const MAX_RESPONSE_BYTES = 5_000_000;
const MAX_ATTEMPTS = 3;

export interface TaxiiHttpResponse { status: number; body: string; contentType: string; }
export interface TaxiiHttpClient { get(url: URL, headers: Record<string, string>): Promise<TaxiiHttpResponse>; }
export interface TaxiiSyncDependencies { client?: TaxiiHttpClient; clock?: Clock; sleeper?: (milliseconds: number) => Promise<void>; }

class TaxiiRequestError extends Error {
  constructor(readonly code: string, message: string, readonly httpStatus?: number, readonly retryable = false) { super(message); }
}

export function isPrivateAddress(address: string): boolean {
  if (isIP(address) === 4) {
    const [a, b] = address.split(".").map(Number);
    return a === 0 || a === 10 || a === 127 || (a === 100 && b! >= 64 && b! <= 127) || (a === 169 && b === 254) || (a === 172 && b! >= 16 && b! <= 31) || (a === 192 && (b === 0 || b === 2 || b === 168)) || (a === 198 && (b === 18 || b === 19 || b === 51)) || (a === 203 && b === 0) || a! >= 224;
  }
  if (isIP(address) === 6) {
    const normalized = address.toLowerCase();
    return normalized === "::" || normalized === "::1" || normalized.startsWith("fc") || normalized.startsWith("fd") || normalized.startsWith("fe8") || normalized.startsWith("fe9") || normalized.startsWith("fea") || normalized.startsWith("feb") || normalized.startsWith("ff") || normalized.startsWith("2001:db8") || normalized.startsWith("::ffff:127.") || normalized.startsWith("::ffff:10.") || normalized.startsWith("::ffff:192.168.");
  }
  return true;
}

async function resolvePublicDestination(url: URL): Promise<{ address: string; family: 4 | 6 }> {
  if (url.protocol !== "https:" || url.username || url.password) throw new TaxiiRequestError("unsafe_destination", "TAXII destinations must use HTTPS without embedded credentials.");
  const literalFamily = isIP(url.hostname);
  const addresses = literalFamily ? [{ address: url.hostname, family: literalFamily }] : await lookup(url.hostname, { all: true, verbatim: true });
  if (addresses.length === 0 || addresses.some(({ address }) => isPrivateAddress(address))) throw new TaxiiRequestError("unsafe_destination", "TAXII destination resolved to a private or reserved network.");
  const selected = addresses[0]!;
  return { address: selected.address, family: selected.family as 4 | 6 };
}

const defaultClient: TaxiiHttpClient = {
  async get(url, headers) {
    const destination = await resolvePublicDestination(url);
    return new Promise<TaxiiHttpResponse>((resolve, reject) => {
      const request = httpsRequest(url, {
        method: "GET",
        headers,
        lookup: (_hostname, _options, callback) => callback(null, destination.address, destination.family),
      }, (response) => {
        const status = response.statusCode ?? 500;
        if (status >= 300 && status < 400) {
          response.resume();
          reject(new TaxiiRequestError("redirect_rejected", "TAXII redirects are not followed.", status));
          return;
        }
        const contentLength = Number(response.headers["content-length"] ?? 0);
        if (contentLength > MAX_RESPONSE_BYTES) {
          response.destroy(new TaxiiRequestError("response_too_large", "TAXII response exceeded the maximum size.", status));
          return;
        }
        const chunks: Buffer[] = [];
        let size = 0;
        response.on("data", (chunk: Buffer) => {
          size += chunk.length;
          if (size > MAX_RESPONSE_BYTES) response.destroy(new TaxiiRequestError("response_too_large", "TAXII response exceeded the maximum size.", status));
          else chunks.push(chunk);
        });
        response.on("error", reject);
        response.on("end", () => resolve({ status, body: Buffer.concat(chunks).toString("utf8"), contentType: String(response.headers["content-type"] ?? "") }));
      });
      request.setTimeout(10_000, () => request.destroy(new TaxiiRequestError("request_timeout", "TAXII request timed out.", undefined, true)));
      request.on("error", reject);
      request.end();
    });
  },
};

export async function createTaxiiSource(
  store: CascadiaStore,
  organizationId: string,
  rawInput: TaxiiSourceCreateRequest,
  actorUserId: string,
  masterKey: string,
): Promise<TaxiiSource> {
  const input = taxiiSourceCreateRequestSchema.parse(rawInput);
  const authenticationCiphertext = input.authentication.type === "none" ? undefined : encryptIntegrationSecret(JSON.stringify(input.authentication), masterKey);
  return store.createTaxiiSource(organizationId, input, authenticationCiphertext, actorUserId);
}

function authorization(authenticationType: TaxiiSource["authenticationType"], ciphertext: string | undefined, masterKey: string): string | undefined {
  if (authenticationType === "none") return undefined;
  if (!ciphertext) throw new TaxiiRequestError("credential_missing", "TAXII credentials are unavailable.");
  const parsed = JSON.parse(decryptIntegrationSecret(ciphertext, masterKey)) as TaxiiAuthentication;
  if (parsed.type !== authenticationType) throw new TaxiiRequestError("credential_invalid", "TAXII credential type does not match the source configuration.");
  if (parsed.type === "basic") return `Basic ${Buffer.from(`${parsed.username}:${parsed.password}`, "utf8").toString("base64")}`;
  if (parsed.type === "bearer") return `Bearer ${parsed.token}`;
  return undefined;
}

function pageUrl(source: TaxiiSource, checkpoint: string | undefined, next: string | undefined): URL {
  const url = new URL(`collections/${encodeURIComponent(source.collectionId)}/objects/`, source.apiRootUrl);
  if (checkpoint) url.searchParams.set("added_after", checkpoint);
  if (next) url.searchParams.set("next", next);
  return url;
}

async function fetchPage(
  store: CascadiaStore,
  source: TaxiiSource,
  job: TaxiiSyncJob,
  pageNumber: number,
  url: URL,
  headers: Record<string, string>,
  client: TaxiiHttpClient,
  clock: Clock,
  sleeper: (milliseconds: number) => Promise<void>,
): Promise<TaxiiHttpResponse> {
  let lastError: TaxiiRequestError | undefined;
  for (let attemptNumber = 1; attemptNumber <= MAX_ATTEMPTS; attemptNumber += 1) {
    const startedAt = clock.now().toISOString();
    try {
      const response = await client.get(url, headers);
      if (response.status !== 200) throw new TaxiiRequestError(`http_${response.status}`, "TAXII server returned an unsuccessful status.", response.status, response.status === 429 || response.status >= 500);
      if (!response.contentType.toLowerCase().includes("application/taxii+json")) throw new TaxiiRequestError("content_type_invalid", "TAXII response content type is invalid.", response.status);
      const completedAt = clock.now().toISOString();
      const attempt: TaxiiSyncAttempt = { id: randomUUID(), jobId: job.id, pageNumber, attemptNumber, status: "succeeded", httpStatus: response.status, startedAt, completedAt };
      await store.appendTaxiiSyncAttempt(source.organizationId, job.id, attempt);
      return response;
    } catch (error) {
      const value = error instanceof TaxiiRequestError ? error : new TaxiiRequestError("network_error", "TAXII network request failed.", undefined, true);
      lastError = value;
      const completedAt = clock.now().toISOString();
      const attempt: TaxiiSyncAttempt = { id: randomUUID(), jobId: job.id, pageNumber, attemptNumber, status: "failed", ...(value.httpStatus ? { httpStatus: value.httpStatus } : {}), errorCode: value.code, startedAt, completedAt };
      await store.appendTaxiiSyncAttempt(source.organizationId, job.id, attempt);
      if (!value.retryable || attemptNumber === MAX_ATTEMPTS) break;
      await sleeper(250 * (2 ** (attemptNumber - 1)));
    }
  }
  throw lastError ?? new TaxiiRequestError("request_failed", "TAXII request failed.");
}

export async function runTaxiiSync(
  store: CascadiaStore,
  organizationId: string,
  sourceId: string,
  actorUserId: string,
  masterKey: string,
  dependencies: TaxiiSyncDependencies = {},
): Promise<TaxiiSyncJob> {
  const clock = dependencies.clock ?? systemClock;
  const client = dependencies.client ?? defaultClient;
  const sleeper = dependencies.sleeper ?? ((milliseconds) => new Promise((resolve) => setTimeout(resolve, milliseconds)));
  const credential = await store.getTaxiiSourceCredential(organizationId, sourceId);
  if (!credential) throw Object.assign(new Error("TAXII source does not exist."), { statusCode: 404 });
  if (credential.source.status !== "active") throw Object.assign(new Error("TAXII source is disabled."), { statusCode: 409 });
  const integration = await store.getIntegration(organizationId, credential.source.integrationId);
  if (!integration) throw Object.assign(new Error("TAXII target integration does not exist."), { statusCode: 404 });
  const job = await store.createTaxiiSyncJob(organizationId, sourceId, actorUserId);
  let pagesFetched = 0;
  let objectsReceived = 0;
  let indicatorsAccepted = 0;
  try {
    const auth = authorization(credential.source.authenticationType, credential.authenticationCiphertext, masterKey);
    const headers: Record<string, string> = { accept: "application/taxii+json;version=2.1", "user-agent": "Cascadia/0.1 TAXII-Client" };
    if (auth) headers.authorization = auth;
    let next: string | undefined;
    const seenTokens = new Set<string>();
    do {
      if (pagesFetched >= MAX_PAGES) throw new TaxiiRequestError("page_limit_exceeded", "TAXII synchronization exceeded the page limit.");
      const response = await fetchPage(store, credential.source, job, pagesFetched + 1, pageUrl(credential.source, job.checkpointBefore, next), headers, client, clock, sleeper);
      let parsed: unknown;
      try { parsed = JSON.parse(response.body) as unknown; }
      catch { throw new TaxiiRequestError("json_invalid", "TAXII response was not valid JSON."); }
      const envelope = taxiiEnvelopeSchema.parse(parsed);
      const indicators = normalizeStixIndicators(integration, envelope.objects, clock.now().toISOString());
      const payloadSha256 = createHash("sha256").update(response.body).digest("hex");
      await store.ingestIntegrationDelivery(integration, `taxii-${sourceId}-${payloadSha256}`, payloadSha256, [], indicators);
      pagesFetched += 1;
      objectsReceived += envelope.objects.length;
      indicatorsAccepted += indicators.length;
      next = envelope.more ? envelope.next : undefined;
      if (next) {
        if (seenTokens.has(next)) throw new TaxiiRequestError("pagination_loop", "TAXII server repeated a pagination token.");
        seenTokens.add(next);
      }
    } while (next);
    return store.finishTaxiiSyncJob(organizationId, job.id, { status: "succeeded", checkpointAfter: job.startedAt, pagesFetched, objectsReceived, indicatorsAccepted });
  } catch (error) {
    const value = error instanceof TaxiiRequestError ? error : new TaxiiRequestError("response_invalid", "TAXII response validation failed.");
    return store.finishTaxiiSyncJob(organizationId, job.id, { status: "failed", pagesFetched, objectsReceived, indicatorsAccepted, errorCode: value.code, errorMessage: value.message });
  }
}

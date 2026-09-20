import { randomUUID } from "node:crypto";
import {
  assetCreateRequestSchema,
  type AssetCreateRequest,
  type AssetImportRequest,
  type AssetImportResult,
} from "@cascadia/contracts";
import { ValidationError, type CascadiaStore } from "./store.js";

function parseCsv(content: string): string[][] {
  const rows: string[][] = [];
  let row: string[] = [];
  let value = "";
  let quoted = false;
  for (let index = 0; index < content.length; index += 1) {
    const character = content[index];
    if (character === '"') {
      if (quoted && content[index + 1] === '"') { value += '"'; index += 1; }
      else quoted = !quoted;
    } else if (character === "," && !quoted) {
      row.push(value.trim()); value = "";
    } else if ((character === "\n" || character === "\r") && !quoted) {
      if (character === "\r" && content[index + 1] === "\n") index += 1;
      row.push(value.trim());
      if (row.some((cell) => cell.length > 0)) rows.push(row);
      row = []; value = "";
    } else value += character;
  }
  if (quoted) throw new Error("CSV contains an unterminated quoted field.");
  row.push(value.trim());
  if (row.some((cell) => cell.length > 0)) rows.push(row);
  return rows;
}

function headerKey(value: string): string {
  return value.toLowerCase().replaceAll(/[^a-z0-9]/g, "");
}

function csvAssets(request: AssetImportRequest): Array<{ row: number; value: unknown }> {
  const rows = parseCsv(request.content);
  const headers = rows.shift()?.map(headerKey);
  if (!headers) return [];
  return rows.map((values, index) => {
    const record = Object.fromEntries(headers.map((header, cell) => [header, values[cell] ?? ""]));
    return {
      row: index + 2,
      value: {
        externalId: record.externalid || record.assetid || record.id,
        name: record.name || record.assetname,
        assetType: record.assettype || record.type || "other",
        criticality: record.criticality || request.defaultCriticality,
        classification: record.classification || request.defaultClassification,
        ...(record.hostname ? { hostname: record.hostname } : {}),
        ...(record.ipaddress || record.ip ? { ipAddress: record.ipaddress || record.ip } : {}),
        metadata: { importSource: request.source },
      },
    };
  });
}

function cycloneDxAssets(request: AssetImportRequest): Array<{ row: number; value: unknown }> {
  const document = JSON.parse(request.content) as { components?: unknown };
  if (!Array.isArray(document.components)) throw new Error("CycloneDX document must contain a components array.");
  return document.components.map((component, index) => {
    const item = component as Record<string, unknown>;
    const externalId = typeof item["bom-ref"] === "string" ? item["bom-ref"] : typeof item.name === "string" ? item.name : "";
    return {
      row: index + 1,
      value: {
        externalId,
        name: item.name,
        assetType: "other",
        criticality: request.defaultCriticality,
        classification: request.defaultClassification,
        metadata: { importSource: request.source, componentType: item.type, version: item.version, supplier: item.supplier },
      },
    };
  });
}

export async function importAssets(store: CascadiaStore, organizationId: string, actorUserId: string, request: AssetImportRequest): Promise<AssetImportResult> {
  let candidates: Array<{ row: number; value: unknown }>;
  try {
    candidates = request.source === "cyclonedx_json" ? cycloneDxAssets(request) : csvAssets(request);
  } catch (error) {
    throw new ValidationError(error instanceof Error ? error.message : "Import content is invalid.");
  }
  let created = 0;
  let updated = 0;
  const rejected: AssetImportResult["rejected"] = [];
  for (const candidate of candidates) {
    const parsed = assetCreateRequestSchema.safeParse(candidate.value);
    if (!parsed.success) {
      rejected.push({ row: candidate.row, reason: parsed.error.issues.map((issue) => issue.message).join("; ") });
      continue;
    }
    const result = await store.upsertAsset(organizationId, parsed.data as AssetCreateRequest, actorUserId);
    if (result.created) created += 1; else updated += 1;
  }
  return { importId: randomUUID(), created, updated, rejected };
}

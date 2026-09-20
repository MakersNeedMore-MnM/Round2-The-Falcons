import assert from "node:assert/strict";
import test from "node:test";
import { buildMerkleTree, canonicalAuditEvent } from "./audit-anchor-service.js";
import type { AuditEvent } from "@cascadia/contracts";

const event = (id: string, metadata: Record<string, unknown>): AuditEvent => ({
  id,
  organizationId: "00000000-0000-0000-0000-000000000001",
  eventType: "incident.created",
  resourceType: "incident",
  resourceId: "00000000-0000-0000-0000-000000000002",
  occurredAt: "2026-09-12T10:00:00.000Z",
  metadata,
});

test("audit canonicalization excludes metadata and is deterministic", () => {
  const first = canonicalAuditEvent(event("00000000-0000-0000-0000-000000000003", { secret: "one" }));
  const second = canonicalAuditEvent(event("00000000-0000-0000-0000-000000000003", { secret: "two" }));
  assert.equal(first, second);
});

test("Merkle root changes when a safe audit field changes", () => {
  const first = buildMerkleTree([event("00000000-0000-0000-0000-000000000003", {})]).root;
  const second = buildMerkleTree([{ ...event("00000000-0000-0000-0000-000000000003", {}), resourceId: "changed" }]).root;
  assert.notEqual(first, second);
});

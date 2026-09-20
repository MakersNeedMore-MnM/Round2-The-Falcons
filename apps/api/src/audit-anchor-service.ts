import { createHash } from "node:crypto";
import type { AuditBatchAnchor, AuditEvent, MerkleProof } from "@cascadia/contracts";
import type { CascadiaStore } from "./store.js";
import type { MstClient } from "./mst-client.js";

function hashBytes(value: Buffer): string {
  return createHash("sha256").update(value).digest("hex");
}

export function canonicalAuditEvent(event: AuditEvent): string {
  return JSON.stringify({
    id: event.id,
    organizationId: event.organizationId,
    actorUserId: event.actorUserId ?? null,
    eventType: event.eventType,
    resourceType: event.resourceType,
    resourceId: event.resourceId,
    occurredAt: event.occurredAt,
  });
}

export function auditLeaf(event: AuditEvent): string {
  return hashBytes(Buffer.from(canonicalAuditEvent(event), "utf8"));
}

function parent(left: string, right: string): string {
  return hashBytes(Buffer.concat([Buffer.from(left, "hex"), Buffer.from(right, "hex")]));
}

export function buildMerkleTree(events: AuditEvent[]): { root: string; leaves: string[]; tree: string[][] } {
  if (!events.length) throw new Error("Cannot build an empty Merkle tree.");
  const leaves = events.map(auditLeaf);
  const tree = [leaves];
  let level = leaves;
  while (level.length > 1) {
    const next: string[] = [];
    for (let index = 0; index < level.length; index += 2) next.push(parent(level[index]!, level[index + 1] ?? level[index]!));
    tree.push(next);
    level = next;
  }
  return { root: level[0]!, leaves, tree };
}

export class AuditAnchorService {
  constructor(private readonly store: CascadiaStore, private readonly mst: MstClient) {}

  async runAnchorBatch(organizationId: string): Promise<AuditBatchAnchor | undefined> {
    const events = await this.store.listUnanchoredAuditEvents(organizationId);
    if (!events.length) return undefined;
    const { root } = buildMerkleTree(events);
    const batchStartTime = events[0]!.occurredAt;
    const batchEndTime = events.at(-1)!.occurredAt;
    try {
      const chainBatchId = Number((await this.mst.readContract("auditBatchCount", []))[0]);
      const submitted = await this.mst.submitTransaction("anchorAuditBatch", [`0x${root}`, Math.floor(Date.parse(batchStartTime) / 1000), Math.floor(Date.parse(batchEndTime) / 1000), events.length]);
      return this.store.createAuditBatchAnchor({
        organizationId, batchStartTime, batchEndTime, eventCount: events.length, merkleRoot: root, chainBatchId,
        txHash: submitted.txHash, blockNumber: submitted.blockNumber, mstscanUrl: submitted.mstscanUrl, anchorStatus: "confirmed", confirmedAt: new Date().toISOString(),
      }, events.map((event) => event.id));
    } catch {
      return this.store.createAuditBatchAnchor({
        organizationId, batchStartTime, batchEndTime, eventCount: events.length, merkleRoot: root, anchorStatus: "failed",
      }, []);
    }
  }

  async verifyAuditBatch(organizationId: string, batchId: number): Promise<{ onChainRoot: string; recomputedRoot: string; match: boolean; eventCount: number }> {
    const anchor = await this.store.getAuditBatchAnchor(organizationId, batchId);
    if (!anchor) throw Object.assign(new Error("Audit batch does not exist."), { statusCode: 404 });
    const events = await this.store.listAuditEventsForBatch(organizationId, batchId);
    const recomputedRoot = buildMerkleTree(events).root;
    const record = await this.mst.readContract("getAuditBatch", [anchor.chainBatchId ?? batchId - 1]);
    const onChainRoot = String(record[0]).replace(/^0x/, "").toLowerCase();
    return { onChainRoot, recomputedRoot, match: onChainRoot === recomputedRoot, eventCount: events.length };
  }

  async getMerkleProof(organizationId: string, eventId: string): Promise<MerkleProof> {
    const events = await this.store.listAuditEvents(organizationId, 10_000);
    const event = events.find((item) => item.id === eventId);
    if (!event) throw Object.assign(new Error("Audit event does not exist."), { statusCode: 404 });
    const anchors = await this.store.listAuditBatchAnchors(organizationId);
    const anchor = anchors.find((item) => item.anchorStatus === "confirmed" && item.batchStartTime <= event.occurredAt && item.batchEndTime >= event.occurredAt);
    if (!anchor) throw Object.assign(new Error("Audit event has no confirmed anchor."), { statusCode: 404 });
    const batchEvents = await this.store.listAuditEventsForBatch(organizationId, anchor.id);
    const built = buildMerkleTree(batchEvents);
    let index = batchEvents.findIndex((item) => item.id === eventId);
    const siblings: string[] = [];
    const positions: Array<"left" | "right"> = [];
    for (let level = 0; level < built.tree.length - 1; level += 1) {
      const current = built.tree[level]!;
      const siblingIndex = index % 2 === 0 ? index + 1 : index - 1;
      siblings.push(current[siblingIndex] ?? current[index]!);
      positions.push(index % 2 === 0 ? "right" : "left");
      index = Math.floor(index / 2);
    }
    return { eventId, leaf: built.leaves[batchEvents.findIndex((item) => item.id === eventId)]!, siblings, positions, root: built.root, batchId: anchor.id, statement: "This proof shows the safe audit-event fingerprint is included in the anchored Merkle root; it does not reveal event metadata." };
  }
}

import { randomBytes } from "node:crypto";
import { getAddress } from "ethers";
import type { DecisionProof, ResponseScenario } from "@cascadia/contracts";
import type { CascadiaStore } from "./store.js";
import type { MstClient, SubmittedTransaction } from "./mst-client.js";
import { recoverAddressFromEvidenceHash } from "./mst-client.js";
import { createHash } from "node:crypto";

export function buildCanonicalRecord(decision: { scenario: ResponseScenario; optionId: string; actorUserId: string; decidedAt: string }): string {
  const option = decision.scenario.options.find((candidate) => candidate.id === decision.optionId);
  if (!option) throw new Error("Decision option does not exist.");
  return JSON.stringify({
    incidentId: decision.scenario.incidentId,
    analysisId: decision.scenario.analysisId,
    optionId: decision.optionId,
    approverUserId: decision.actorUserId,
    decidedAt: decision.decidedAt,
    securityBenefit: option.securityBenefit,
    operationalImpact: option.operationalImpact,
  });
}

export function hashRecord(canonicalJSON: string): string {
  return createHash("sha256").update(Buffer.from(canonicalJSON, "utf8")).digest("hex");
}

export class DecisionProofService {
  constructor(private readonly store: CascadiaStore, private readonly mst: MstClient) {}

  async requestSignature(organizationId: string, decisionId: string): Promise<{ decisionId: string; evidenceHash: string; approverWalletAddress: string; challenge: string }> {
    const proof = await this.store.getDecisionProof(organizationId, decisionId);
    if (proof) return { decisionId, evidenceHash: proof.evidenceHash, approverWalletAddress: proof.approverWalletAddress, challenge: `Cascadia decision proof ${decisionId}:${randomBytes(16).toString("hex")}` };
    const scenarios = await this.store.listResponseScenarios(organizationId);
    const scenario = scenarios.find((candidate) => candidate.decisions.some((entry) => entry.id === decisionId));
    const decision = scenario?.decisions.find((entry) => entry.id === decisionId);
    if (!scenario || !decision || decision.decision !== "approve") throw Object.assign(new Error("An approved decision is required before anchoring."), { statusCode: 409 });
    const user = await this.store.getIdentityUser(decision.actorUserId);
    if (!user?.walletAddress) throw Object.assign(new Error("The approving commander must register a wallet first."), { statusCode: 409 });
    const evidenceHash = hashRecord(buildCanonicalRecord({ scenario, optionId: decision.optionId, actorUserId: decision.actorUserId, decidedAt: decision.decidedAt }));
    return { decisionId, evidenceHash, approverWalletAddress: getAddress(user.walletAddress), challenge: `Cascadia decision proof ${decisionId}:${randomBytes(16).toString("hex")}` };
  }

  async submitAnchor(organizationId: string, decisionId: string, evidenceHash: string, signature: string): Promise<DecisionProof> {
    const requested = await this.requestSignature(organizationId, decisionId);
    const recovered = getAddress(recoverAddressFromEvidenceHash(evidenceHash, signature));
    if (recovered.toLowerCase() !== requested.approverWalletAddress.toLowerCase()) throw Object.assign(new Error("Signature does not match the approving wallet."), { statusCode: 400 });
    const scenarios = await this.store.listResponseScenarios(organizationId);
    const scenario = scenarios.find((candidate) => candidate.decisions.some((entry) => entry.id === decisionId))!;
    const decision = scenario.decisions.find((entry) => entry.id === decisionId)!;
    let submitted: SubmittedTransaction;
    try {
      submitted = await this.mst.submitTransaction("recordDecision", [decisionId, `0x${evidenceHash}`, "response_decision", requested.approverWalletAddress, Math.floor(Date.parse(decision.decidedAt) / 1000), signature]);
    } catch (error) {
      await this.store.saveDecisionProof({
        decisionId, organizationId, evidenceHash, approverWalletAddress: requested.approverWalletAddress, signature,
        anchorStatus: "failed", createdAt: new Date().toISOString(),
      });
      throw error;
    }
    const proof: DecisionProof = {
      decisionId, organizationId, evidenceHash, approverWalletAddress: requested.approverWalletAddress, signature,
      txHash: submitted.txHash, contractAddress: this.mst.contractAddress, blockNumber: submitted.blockNumber, mstscanUrl: submitted.mstscanUrl,
      anchorStatus: "confirmed", createdAt: new Date().toISOString(), confirmedAt: new Date().toISOString(),
    };
    await this.store.saveDecisionProof(proof);
    return proof;
  }

  async verifyProof(organizationId: string, decisionId: string): Promise<{ decisionId: string; onChainHash: string; offChainHash: string; match: boolean; approverAddress: string; status: "unanchored" | "pending" | "confirmed" | "failed" }> {
    const proof = await this.store.getDecisionProof(organizationId, decisionId);
    if (!proof) throw Object.assign(new Error("Decision proof does not exist."), { statusCode: 404 });
    const scenarios = await this.store.listResponseScenarios(organizationId);
    const scenario = scenarios.find((candidate) => candidate.decisions.some((entry) => entry.id === decisionId));
    const decision = scenario?.decisions.find((entry) => entry.id === decisionId);
    if (!scenario || !decision) throw Object.assign(new Error("Decision does not exist."), { statusCode: 404 });
    const offChainHash = hashRecord(buildCanonicalRecord({ scenario, optionId: decision.optionId, actorUserId: decision.actorUserId, decidedAt: decision.decidedAt }));
    const record = await this.mst.readContract("getDecisionRecord", [decisionId]);
    const onChainHash = String(record[0]).replace(/^0x/, "").toLowerCase();
    return { decisionId, onChainHash, offChainHash, match: onChainHash === offChainHash, approverAddress: String(record[1]), status: proof.anchorStatus };
  }
}

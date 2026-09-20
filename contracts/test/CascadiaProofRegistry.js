import assert from "node:assert/strict";
import { ethers } from "hardhat";

describe("CascadiaProofRegistry", function () {
  it("rejects a decision signature from the wrong wallet", async function () {
    const [deployer, approver, wrongSigner] = await ethers.getSigners();
    const Factory = await ethers.getContractFactory("CascadiaProofRegistry");
    const registry = await Factory.deploy();
    await registry.waitForDeployment();
    const hash = ethers.keccak256(ethers.toUtf8Bytes("decision"));
    const signature = await wrongSigner.signMessage(ethers.getBytes(hash));
    await assert.rejects(
      registry.recordDecision("decision-1", hash, "response_decision", approver.address, 1, signature),
      /invalid approver signature/,
    );
    void deployer;
  });
});

import { Client } from "@mstblockchain/mst-sdk";
import { Contract, JsonRpcProvider, Wallet, getBytes, verifyMessage } from "ethers";
import type { AppConfig } from "./config.js";

const ABI = [
  "function anchorAuditBatch(bytes32,uint256,uint256,uint256)",
  "function auditBatchCount() view returns (uint256)",
  "function getAuditBatch(uint256) view returns (bytes32,uint256,uint256,uint256,uint256)",
  "function recordDecision(string,bytes32,string,address,uint256,bytes)",
  "function getDecisionRecord(string) view returns (bytes32,address,uint256)",
];

export interface SubmittedTransaction {
  txHash: string;
  blockNumber: number;
  mstscanUrl: string;
}

export interface MstClient {
  contractAddress: string;
  getContract(): Contract;
  submitTransaction(fnName: string, args: readonly unknown[]): Promise<SubmittedTransaction>;
  readContract(fnName: string, args: readonly unknown[]): Promise<unknown[]>;
  waitForConfirmation(txHash: string): Promise<{ blockNumber: number }>;
}

export function createMstClient(config: AppConfig): MstClient {
  if (!config.MST_DEPLOYER_PRIVATE_KEY || !config.MST_CONTRACT_ADDRESS) {
    throw new Error("MST_DEPLOYER_PRIVATE_KEY and MST_CONTRACT_ADDRESS are required for chain operations.");
  }
  // Initialize the official SDK client so deployments and provider configuration remain MST-native.
  const sdkClient = new Client(config.MST_RPC_URL ?? "https://testnetrpc.mstblockchain.com", config.MST_DEPLOYER_PRIVATE_KEY);
  void sdkClient;
  const provider = new JsonRpcProvider(config.MST_RPC_URL ?? "https://testnetrpc.mstblockchain.com", config.MST_CHAIN_ID ?? 91562037);
  const signer = new Wallet(config.MST_DEPLOYER_PRIVATE_KEY, provider);
  const contract = new Contract(config.MST_CONTRACT_ADDRESS, ABI, signer);
  const explorer = (config.MST_EXPLORER_URL ?? "https://testnet.mstscan.com").replace(/\/$/, "");

  async function waitForConfirmation(txHash: string): Promise<{ blockNumber: number }> {
    const started = Date.now();
    let receipt = await provider.getTransactionReceipt(txHash);
    while (!receipt) {
      if (Date.now() - started > (config.MST_TX_TIMEOUT_SECONDS ?? 120) * 1000) throw new Error("MST transaction confirmation timed out.");
      await new Promise((resolve) => setTimeout(resolve, 2_000));
      receipt = await provider.getTransactionReceipt(txHash);
    }
    if (receipt.status !== 1) throw new Error("MST transaction reverted.");
    while ((await provider.getBlockNumber()) < receipt.blockNumber + (config.MST_CONFIRMATIONS ?? 1) - 1) {
      if (Date.now() - started > (config.MST_TX_TIMEOUT_SECONDS ?? 120) * 1000) throw new Error("MST confirmation depth timed out.");
      await new Promise((resolve) => setTimeout(resolve, 2_000));
    }
    return { blockNumber: receipt.blockNumber };
  }

  return {
    contractAddress: config.MST_CONTRACT_ADDRESS,
    getContract: () => contract,
    waitForConfirmation,
    async submitTransaction(fnName, args) {
      const callable = (contract as unknown as Record<string, (...values: readonly unknown[]) => Promise<{ hash: string }>>)[fnName];
      if (!callable) throw new Error(`Unsupported MST contract function: ${fnName}`);
      const transaction = await callable(...args);
      const result = await waitForConfirmation(transaction.hash);
      return { txHash: transaction.hash, blockNumber: result.blockNumber, mstscanUrl: `${explorer}/tx/${transaction.hash}` };
    },
    async readContract(fnName, args) {
      const callable = (contract as unknown as Record<string, (...values: readonly unknown[]) => Promise<unknown>>)[fnName];
      if (!callable) throw new Error(`Unsupported MST contract function: ${fnName}`);
      const result = await callable(...args);
      return Array.isArray(result) ? result : [result];
    },
  };
}

export function recoverAddressFromEvidenceHash(evidenceHash: string, signature: string): string {
  return verifyMessage(getBytes(`0x${evidenceHash.replace(/^0x/, "")}`), signature);
}

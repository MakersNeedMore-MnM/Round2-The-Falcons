import { readFile } from "node:fs/promises";
import { ContractFactory, JsonRpcProvider, Wallet } from "ethers";

if (typeof process.loadEnvFile === "function") process.loadEnvFile("../.env");
const rpcUrl = process.env.MST_RPC_URL || "https://testnetrpc.mstblockchain.com";
const privateKey = process.env.MST_DEPLOYER_PRIVATE_KEY;
if (!privateKey) throw new Error("MST_DEPLOYER_PRIVATE_KEY is not set. Configure it in the shell or repository .env.");
if (!/^0x[0-9a-fA-F]{64}$/.test(privateKey)) throw new Error("MST_DEPLOYER_PRIVATE_KEY must contain exactly 64 hexadecimal characters after 0x.");

const artifact = JSON.parse(await readFile("artifacts/CascadiaProofRegistry.sol/CascadiaProofRegistry.json", "utf8"));
const provider = new JsonRpcProvider(rpcUrl, Number(process.env.MST_CHAIN_ID || 91562037));
const signer = new Wallet(privateKey, provider);
const network = await provider.getNetwork();
const balance = await provider.getBalance(signer.address);
console.log(`MST chain: ${network.chainId.toString()}`);
console.log(`Deployer: ${signer.address}`);
console.log(`Balance: ${balance.toString()} wei`);
const Factory = new ContractFactory(artifact.abi, artifact.bytecode, signer);
const contract = await Factory.deploy();
console.log(`Deployment transaction: ${contract.deploymentTransaction()?.hash ?? "unavailable"}`);
await contract.waitForDeployment();
const address = await contract.getAddress();
if (!/^0x[0-9a-fA-F]{40}$/.test(address)) throw new Error(`Deployment returned an invalid contract address: ${address}`);
const receipt = await contract.deploymentTransaction()?.wait();
console.log(`Deployment block: ${receipt?.blockNumber ?? "unknown"}`);
console.log(`CascadiaProofRegistry deployed at ${address}`);
console.log(`MSTScan: ${(process.env.MST_EXPLORER_URL || "https://testnet.mstscan.com").replace(/\/$/, "")}/address/${address}`);

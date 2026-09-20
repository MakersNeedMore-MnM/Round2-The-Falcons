const hre = require("hardhat");

async function main() {
  const Factory = await hre.ethers.getContractFactory("CascadiaProofRegistry");
  const contract = await Factory.deploy();
  await contract.waitForDeployment();
  console.log(`CascadiaProofRegistry deployed at ${await contract.getAddress()}`);
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});

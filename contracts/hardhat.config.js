import hardhatEthers from "@nomicfoundation/hardhat-ethers";

export default {
  plugins: [hardhatEthers],
  solidity: "0.8.24",
  paths: { sources: ".", artifacts: "./artifacts" },
  networks: {
    mst: {
      type: "http",
      url: process.env.MST_RPC_URL || "https://testnetrpc.mstblockchain.com",
      chainId: 91562037,
      accounts: process.env.MST_DEPLOYER_PRIVATE_KEY ? [process.env.MST_DEPLOYER_PRIVATE_KEY] : [],
    },
  },
};

require("@nomicfoundation/hardhat-toolbox");

module.exports = {
  solidity: "0.8.24",
  networks: {
    mst: {
      url: process.env.MST_RPC_URL || "https://testnetrpc.mstblockchain.com",
      chainId: 91562037,
      accounts: process.env.MST_DEPLOYER_PRIVATE_KEY ? [process.env.MST_DEPLOYER_PRIVATE_KEY] : [],
    },
  },
};

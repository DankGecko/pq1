import { HardhatUserConfig } from "hardhat/config";
import "@nomicfoundation/hardhat-toolbox";
import '@openzeppelin/hardhat-upgrades';
require("@nomicfoundation/hardhat-verify");

// Need provide private key
const COREDEV_PRIVATE_KEY = "0000000000000000000000000000000000000000000000000000000000000000";

const ETHERSCAN_API_KEY = "cc193a7c046b446db1106270421f5ff0";

const config: HardhatUserConfig = {
  solidity: {
    version: "0.8.4",
    settings: {
      optimizer: {
        enabled: true,
        runs: 200
      }
    }
  },
  defaultNetwork: "coredev2",
  networks: {
    coredev2: {
      url: "https://rpc2.dev.btcs.network",
      accounts: [COREDEV_PRIVATE_KEY]
    }
  },
  etherscan: {
    apiKey: ETHERSCAN_API_KEY,
    customChains: [
       {
        network: "coredev2",
        chainId: 1111,
        urls: {
          apiURL: "http://52.14.143.189:8090/api",
          browserURL: "https://scan2.dev.btcs.network"
        }
      }
    ]
  }
};

export default config;

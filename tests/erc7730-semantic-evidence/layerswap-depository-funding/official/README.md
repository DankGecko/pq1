# LayerswapDepository

A Solidity smart contract that forwards native and ERC20 tokens to whitelisted Layerswap receiver addresses.

## Overview

`LayerswapDepository` acts as a secure on-chain entry point for Layerswap bridge orders. It accepts deposits from users and forwards funds immediately to pre-approved (whitelisted) Layerswap solver addresses. The contract never holds funds — all assets are forwarded atomically in the same transaction.

### Key properties

- **Whitelist-gated** — only pre-approved receiver addresses can receive funds
- **Dual-asset** — supports both native ETH and any ERC20 token
- **Order-correlated** — every deposit includes a `bytes32 id` that maps to an off-chain Layerswap order
- **Pausable** — owner can halt all deposits in an emergency
- **Non-custodial** — contract holds zero balance at all times

## Contract

| File | Description |
|------|-------------|
| [`src/LayerswapDepository.sol`](src/LayerswapDepository.sol) | Main contract |
| [`script/DeployLayerswapDepository.s.sol`](script/DeployLayerswapDepository.s.sol) | Deployment script |
| [`test/LayerswapDepository.t.sol`](test/LayerswapDepository.t.sol) | Unit + fuzz tests (27 tests) |
| [`test/LayerswapDepository.gas.t.sol`](test/LayerswapDepository.gas.t.sol) | Gas benchmarks |

## Architecture

```
User
 │
 ├─ depositNative(id, receiver) ──────► receiver (ETH forwarded instantly)
 │
 └─ depositERC20(id, token, receiver, amount) ──► receiver (ERC20 forwarded instantly)
                                                        │
                                              emits Deposited(id, token, amount)
                                                        │
                                              Layerswap backend picks up event
                                              and fulfills the order on dst chain
```

## Dependencies

| Library | Version |
|---------|---------|
| [OpenZeppelin Contracts](https://github.com/OpenZeppelin/openzeppelin-contracts) | v5.6.1 |
| [forge-std](https://github.com/foundry-rs/forge-std) | v1.15.0 |

## Setup

```bash
# Install Foundry
curl -L https://foundry.paradigm.xyz | bash && foundryup

# Clone and install dependencies
git clone <repo>
cd layerswap-depository
forge install
```

## Environment

Copy `.env.example` to `.env` and fill in the values:

```bash
cp .env.example .env
```

| Variable | Description |
|----------|-------------|
| `PRIVATE_KEY` | Deployer wallet private key |
| `OWNER_ADDRESS` | Contract owner (use a Gnosis Safe on mainnet) |
| `WHITELISTED_ADDRESSES` | Comma-separated initial whitelist (optional) |
| `RPC_*` | RPC endpoint per network |
| `ETHERSCAN_API_KEY` | For Ethereum mainnet + Sepolia verification |
| `ARBISCAN_API_KEY` | For Arbitrum verification |
| `OPSCAN_API_KEY` | For Optimism verification |
| `BASESCAN_API_KEY` | For Base verification |
| `POLYGONSCAN_API_KEY` | For Polygon verification |

## Build & Test

```bash
# Build
forge build

# Run all tests
forge test -vvv

# Run with more fuzz iterations (CI profile)
FOUNDRY_PROFILE=ci forge test

# Format check
forge fmt --check
```

## Gas Benchmarks

Run and save a baseline snapshot:

```bash
forge snapshot --match-contract GasTest
```

Check for regressions against the saved snapshot:

```bash
forge snapshot --check
```

| Operation | Gas |
|-----------|-----|
| `depositNative` | ~62,500 |
| `depositERC20` | ~59,100 |
| `addToWhitelist` | ~65,000 |
| `removeFromWhitelist` | ~21,100 |
| `updateWhitelistedAddress` | ~48,900 |
| Deploy (empty whitelist) | ~789,000 |

## Deploy

**Dry-run (no broadcast):**
```bash
forge script script/DeployLayerswapDepository.s.sol --rpc-url sepolia --private-key $PRIVATE_KEY
```

**Deploy + verify in one command:**
```bash
forge script script/DeployLayerswapDepository.s.sol \
  --rpc-url sepolia \
  --private-key $PRIVATE_KEY \
  --broadcast \
  --verify \
  --etherscan-api-key $ETHERSCAN_API_KEY
```

Replace `sepolia` with `mainnet`, `arbitrum`, `optimism`, `base`, or `polygon` as needed.

**Verify an already-deployed contract:**
```bash
forge verify-contract <DEPLOYED_ADDRESS> \
  src/LayerswapDepository.sol:LayerswapDepository \
  --chain sepolia \
  --constructor-args $(cast abi-encode "constructor(address,address[])" $OWNER_ADDRESS "[]") \
  --watch
```

## Whitelist management

```bash
# Add a single address (cast)
cast send <CONTRACT> "addToWhitelist(address)" <ADDR> \
  --rpc-url mainnet --private-key $PRIVATE_KEY

# Replace an address atomically
cast send <CONTRACT> "updateWhitelistedAddress(address,address)" <OLD_ADDR> <NEW_ADDR> \
  --rpc-url mainnet --private-key $PRIVATE_KEY

# Remove
cast send <CONTRACT> "removeFromWhitelist(address)" <ADDR> \
  --rpc-url mainnet --private-key $PRIVATE_KEY

# View whitelist
cast call <CONTRACT> "getWhitelistedAddresses()" --rpc-url mainnet

# Emergency pause
cast send <CONTRACT> "pause()" --rpc-url mainnet --private-key $PRIVATE_KEY
```

## License

MIT

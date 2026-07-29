## Flying Tulip USD (ftUSD / sftUSD) Integration

- Website: [flyingtulip.com](https://flyingtulip.com)
- Documentation: [docs.flyingtulip.com](https://docs.flyingtulip.com)
- Telegram: [pata_eth](https://t.me/pata_eth)

## 1. Summary

- ftUSD is a 6-decimal, dollar-pegged stablecoin backed by diversified collateral (USDC, USDT, USDS, USDTb, USDe).
- Users mint ftUSD by depositing collateral and redeem ftUSD back to collateral, both priced via Chainlink oracles with configurable fees.
- sftUSD is an ERC-4626 vault share representing staked ftUSD with a fixed 1:1 share-to-asset ratio (rewards are distributed externally via epochs, not through share appreciation).
- **Deep, oracle-priced liquidity.** Mint/redeem is oracle-priced (Chainlink), not AMM-curve-based.

Two route families on **Ethereum mainnet**:

1. **ftUSD <> Stablecoins** -- oracle-priced mint/redeem via the `MintAndRedeem` contract.
2. **ftUSD <> sftUSD** -- standard ERC-4626 deposit/withdraw via the `EpochRewardsVault` contract.

## 2. Technical Specification

### 2.1 Contract Addresses (Ethereum Mainnet)

All addresses are verified on Etherscan. Source:
[docs.flyingtulip.com/contract-addresses](https://docs.flyingtulip.com/contract-addresses/).

#### Core Contracts

| Contract                           | Address                                                                                                                 |
| ---------------------------------- | ----------------------------------------------------------------------------------------------------------------------- |
| ftUSD (proxy)                      | [`0xF7D85EC4E7710f71992752eac2111312e73E9C9C`](https://etherscan.io/address/0xF7D85EC4E7710f71992752eac2111312e73E9C9C) |
| MintAndRedeem (proxy)              | [`0xAa48EcBC843cF7E9A29155D112b8Cb27902bD23C`](https://etherscan.io/address/0xAa48EcBC843cF7E9A29155D112b8Cb27902bD23C) |
| EpochRewardsVault / sftUSD (proxy) | [`0xeb48218a4c35C814C7678cBcae88C6Ee037F7625`](https://etherscan.io/address/0xeb48218a4c35C814C7678cBcae88C6Ee037F7625) |

#### Supported Collateral Tokens (Ethereum)

| Token | Address                                                                                                                 | Decimals |
| ----- | ----------------------------------------------------------------------------------------------------------------------- | -------- |
| USDC  | [`0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48`](https://etherscan.io/address/0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48) | 6        |
| USDT  | [`0xdAC17F958D2ee523a2206206994597C13D831ec7`](https://etherscan.io/address/0xdAC17F958D2ee523a2206206994597C13D831ec7) | 6        |
| USDS  | [`0xdC035D45d973E3EC169d2276DDab16f1e407384F`](https://etherscan.io/address/0xdC035D45d973E3EC169d2276DDab16f1e407384F) | 18       |
| USDTb | [`0xC139190F447e929f090Edeb554D95AbB8b18aC1C`](https://etherscan.io/address/0xC139190F447e929f090Edeb554D95AbB8b18aC1C) | 18       |
| USDe  | [`0x4c9EDD5852cd905f086C759E8383e09bff1E68B3`](https://etherscan.io/address/0x4c9EDD5852cd905f086C759E8383e09bff1E68B3) | 18       |

#### Token Info

| Token                   | Symbol | Decimals |
| ----------------------- | ------ | -------- |
| Flying Tulip USD        | ftUSD  | 6        |
| Staked Flying Tulip USD | sftUSD | 6        |

### 2.2 Route 1: ftUSD <> Stablecoins (via MintAndRedeem)

#### Price Discovery

`MintAndRedeem` follows ERC-4626 semantics for its preview and settlement functions. In this
context, **collateral** (USDC, USDT, ...) is the "asset" and **ftUSD** is the "share":

| ERC-4626 concept               | Direction    | MintAndRedeem function               | Input (exact)     | Output (calculated) |
| ------------------------------ | ------------ | ------------------------------------ | ----------------- | ------------------- |
| `deposit` / `previewDeposit`   | Exact input  | `mint` / `previewMint`               | collateral amount | ftUSD amount        |
| `mint` / `previewMint`         | Exact output | `mintExact` / `previewMintExact`     | ftUSD amount      | collateral amount   |
| `redeem` / `previewRedeem`     | Exact input  | `redeem` / `previewRedeem`           | ftUSD amount      | collateral amount   |
| `withdraw` / `previewWithdraw` | Exact output | `redeemExact` / `previewRedeemExact` | collateral amount | ftUSD amount        |

All preview functions are `view`, account for the current fee configuration and oracle price, and
revert if the collateral is disabled or the amount is zero.

```solidity
// Exact input: collateral in -> ftUSD out (ERC-4626 "previewDeposit")
function previewMint(
    address collateralToken,
    uint256 collateralAmount
) external view returns (uint256 ftUSDAmount);

// Exact input: ftUSD in -> collateral out (ERC-4626 "previewRedeem")
function previewRedeem(
    address collateralToken,
    uint256 ftUSDAmount
) external view returns (uint256 collateralAmount);

// Exact output: specify ftUSD out -> collateral needed (ERC-4626 "previewMint")
function previewMintExact(
    address collateralToken,
    uint256 ftUSDAmount
) external view returns (uint256 collateralAmount);

// Exact output: specify collateral out -> ftUSD needed (ERC-4626 "previewWithdraw")
function previewRedeemExact(
    address collateralToken,
    uint256 collateralAmount
) external view returns (uint256 ftUSDAmount);
```

Additional view functions for liquidity assessment:

```solidity
// Per-collateral configuration: fees, caps, wrapper address, totals
function collateralInfo(address collateralToken)
    external view returns (CollateralInfo memory);

// Total collateral held for a specific token (wrapper balance + idle balance)
function collateralAssets(address collateralToken)
    external view returns (uint256);

// Total system assets valued in ftUSD units (6 decimals)
function assetsUSD() public view returns (uint256 totalFtUSDValue);
```

The `CollateralInfo` struct:

```solidity
struct CollateralInfo {
    IftYieldWrapperV2 yieldWrapper;
    uint8 decimals;
    bool enabled;
    uint16 mintFeeBps;      // mint fee in basis points
    uint16 redeemFeeBps;    // redeem fee in basis points
    uint256 maxValueFtUSD;  // collateral cap in ftUSD units
    uint256 mintPriceHardcapWad; // oracle price cap (WAD)
    uint256 totalIn;
    uint256 totalOut;
    uint256 totalFtUSDBurned;
    uint256 totalFtUSDMinted;
}
```

#### Settlement Interface

Below we map the ERC-4626 functions to the corresponding `MintAndRedeem` functions:

**`deposit` -- exact collateral in, ftUSD out:**

```solidity
function mint(
    address collateralToken,
    uint256 collateralAmount,
    uint256 txDeadline,
    uint256 minFtUSDOut
) external returns (uint256 ftUSDAmount);
```

**`mint` -- exact ftUSD out, collateral in:**

```solidity
function mintExact(
    address collateralToken,
    uint256 ftUSDAmount,
    bytes32 ref,
    uint256 txDeadline,
    uint256 maxCollateralIn
) external returns (uint256 collateralAmount);
```

**`redeem` -- exact ftUSD in, collateral out:**

```solidity
function redeem(
    address collateralToken,
    uint256 ftUSDAmount,
    uint256 txDeadline,
    uint256 minCollateralOut
) external returns (uint256 collateralAmount, uint256 queueId);
```

**`withdraw` -- exact collateral out, ftUSD in:**

```solidity
function redeemExact(
    address collateralToken,
    uint256 collateralAmount,
    uint256 txDeadline,
    uint256 maxFtUSDIn
) external returns (uint256 ftUSDAmount, uint256 queueId);
```

All four functions send output tokens to `msg.sender`. Variants with explicit recipient
(`mintTo`, `mintExactTo`, `redeemTo`, `redeemExactTo`).

#### Parameters

| Parameter                          | Description                                                                          |
| ---------------------------------- | ------------------------------------------------------------------------------------ |
| `collateralToken`                  | Address of the collateral token (USDC, USDT, USDS, USDTb, or USDe)                   |
| `collateralAmount`                 | Amount in collateral token's native decimals                                         |
| `ftUSDAmount`                      | Amount in 6 decimals                                                                 |
| `txDeadline`                       | Unix timestamp after which the tx reverts. Use `0` for no deadline.                  |
| `minFtUSDOut` / `minCollateralOut` | Slippage protection floor. Tx reverts if output is below this.                       |
| `maxCollateralIn` / `maxFtUSDIn`   | Slippage protection ceiling. Tx reverts if input exceeds this. Use `0` for no limit. |
| `ref`                              | Optional `bytes32` reference for tracking/integrations. Use `bytes32(0)` if unused.  |
| `to`                               | Recipient address for the output tokens.                                             |

#### Fee Structure

Fees are configured per collateral and assessed in ftUSD units:

- **Mint fee**: deducted from the minted ftUSD (user receives net = gross - fee).
- **Redeem fee**: deducted from the input ftUSD before computing collateral output.

Current Ethereum mainnet configuration: **10 bps (0.1%)** for both mint and redeem on all
collateral types. Fees can be queried on-chain via `collateralInfo(token).mintFeeBps` and
`collateralInfo(token).redeemFeeBps`.

#### Approvals

- Before calling `mint`/`mintExact` (deposit/mint), the caller must approve the `MintAndRedeem`
  contract to spend the collateral token.
- Before calling `redeem`/`redeemExact` (redeem/withdraw),
  the caller must approve the `MintAndRedeem` contract to spend ftUSD.

### 2.3 Route 2: ftUSD <> sftUSD (via EpochRewardsVault)

#### Price Discovery

sftUSD uses a **fixed 1:1 share-to-asset ratio**. Rewards are distributed externally via FT token
epochs, not through share price appreciation. This means:

- `convertToShares(assets)` returns `assets` (identity function).
- `convertToAssets(shares)` returns `shares` (identity function).

All standard ERC-4626 view functions are available, including:

```solidity
function asset() external view returns (address);       // returns ftUSD address
function totalAssets() external view returns (uint256);  // equals totalSupply()

function previewDeposit(uint256 assets) external view returns (uint256 shares);
function previewRedeem(uint256 shares) external view returns (uint256 assets);
```

#### Settlement Interface

**Wrap ftUSD -> sftUSD (deposit):**

```solidity
// Standard ERC-4626
function deposit(uint256 assets, address receiver) external returns (uint256 shares);
```

**Unwrap sftUSD -> ftUSD (withdraw/redeem):**

```solidity
// Standard ERC-4626
function redeem(uint256 shares, address receiver, address owner)
    external returns (uint256 assets);
```

#### Fee Structure

There are **no fees** on ftUSD <> sftUSD wrapping/unwrapping. The 1:1 ratio is invariant.

#### Approvals

Before calling `deposit`, the caller must approve the `EpochRewardsVault` contract to spend ftUSD.
For `withdraw`/`redeem` on behalf of another address, the standard ERC-4626 allowance mechanism
applies.

### 2.4 Combined Routes

Solvers can compose the two route types for multi-hop settlement:

| Route          | Hops                    | Contracts                                       |
| -------------- | ----------------------- | ----------------------------------------------- |
| USDC -> sftUSD | USDC -> ftUSD -> sftUSD | MintAndRedeem.mint + EpochRewardsVault.deposit  |
| sftUSD -> USDC | sftUSD -> ftUSD -> USDC | EpochRewardsVault.redeem + MintAndRedeem.redeem |

The same pattern applies for USDT, USDS, USDTb, and USDe.

### 2.5 Gas Estimates

| Operation                                    | Approximate Gas |
| -------------------------------------------- | --------------- |
| MintAndRedeem.mint (collateral -> ftUSD)     | ~500k           |
| MintAndRedeem.redeem (ftUSD -> collateral)   | ~500k           |
| EpochRewardsVault.deposit (ftUSD -> sftUSD)  | ~250k           |
| EpochRewardsVault.withdraw (sftUSD -> ftUSD) | ~250k           |

Gas costs are approximate and vary with EVM state (cold/warm storage slots, etc).

### 2.6 Security Audits

- ChainSecurity audit of the ftUSD system (MintAndRedeem, CircuitBreakerV2, EpochRewardsVault,
  yield wrappers, and strategies).

### 2.7 Known Limitations

1. **Pause mechanism**: `MintAndRedeem` and `EpochRewardsVault` can be paused by governance. When
   paused, mints are blocked but redemptions/withdrawals remain available (EpochRewardsVault
   withdrawals are explicitly allowed even when paused).
2. **Blacklist**: ftUSD enforces a blacklist. Blacklisted addresses cannot send or receive ftUSD.
3. **Fee-on-transfer tokens**: Not supported as collateral. All supported collateral tokens are
   standard ERC-20.

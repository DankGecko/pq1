# Lombard LBTC semantic evidence

This deterministic offline bundle supports the six flat-static calls and one
EIP-712 `feeApproval` type that PQ1 accepts for the Ethereum mainnet Lombard
Staked Bitcoin (`LBTC`) proxy at
`0x8236a87084f8b84306f72007f36f2618a5634494`:

- `approve(address,uint256)`;
- `burn(uint256)`;
- `permit(address,address,uint256,uint256,uint8,bytes32,bytes32)`;
- `redeem(uint256)`;
- `transfer(address,uint256)`; and
- `transferFrom(address,address,uint256)`.

The descriptor's dynamic `mint(bytes,bytes)` and
`redeemForBtc(bytes,uint256)` formats remain fail-closed. This package does not
authorize either dynamic-tail route.

The bounded EIP-712 admission is exactly
`feeApproval(uint256 chainId,uint256 fee,uint256 expiry)` with typehash
`0x40ac9f6aa27075e64c1ed1ea2e831b20b8c25efdeb6b79fd0cf683c9a9c50725`.
It applies only to chain 1, the proxy above, and the domain name/version
`Lombard Staked Bitcoin` / `1`. The Sepolia declaration is not admitted by
this package.

## Fixed deployment and source identity

At Ethereum block 25,582,800 (`0x1865cd0`, hash
`0x6af3d522...6716f469`), dRPC, Tenderly, and MEV Blocker independently agree
that:

- the LBTC proxy's EIP-1967 implementation is
  `0x072072317469ebb6c340a47e41561c9c3b782bd9`;
- `getAssetRouter()` returns proxy
  `0x9ece5fb1ab62d9075c4ec814b321e24d8ea021ac`;
- that router's EIP-1967 implementation is
  `0xb823359367978a28eae71e90f79d95b62348bd80`;
- all three providers return byte-identical proxy and implementation runtimes;
  and
- token metadata is `Lombard Staked Bitcoin`, `LBTC`, 8 decimals.

Every historical code, storage, and call request uses EIP-1898 `blockHash`
with `requireCanonical:true`. The request and complete provider-response files
are archived under `rpc/raw/`; the Rust test derives agreement from those files
instead of trusting this README or the manifest.

The official `lombard-finance/evm-smart-contracts` repository is pinned at
commit `bfd32248badaa2fb35a453f17f3c181badfb3dd6` (tree
`5278bc4c8f292e58dac2ba21fe016df1e810fc18`). The archived concrete LBTC and
AssetRouter sources and their load-bearing interfaces/libraries match the
corresponding Blockscout-verified source bytes exactly.

Both implementations are verified with Solidity 0.8.24, optimizer 200, and
the Paris EVM target. The bundle archives each complete verified compiler
closure and exact settings. Recompiling those closures reconstructs the
17,334-byte StakedLBTC and 21,402-byte AssetRouter deployed runtimes exactly.

## EIP-712 domain, type, and maximum-fee meaning

`StakedLBTC.initialize` initializes ERC20Permit with
`Lombard Staked Bitcoin`; the pinned OpenZeppelin implementation supplies
version `1`. Its EIP-712 domain binds that name, version, `block.chainid`, and
`address(this)`. Fixed-block metadata independently confirms the current token
name, while the descriptor binds chain 1 and the exact proxy address.

`Actions.FEE_APPROVAL_EIP712_ACTION` is the exact keccak-256 of
`feeApproval(uint256 chainId,uint256 fee,uint256 expiry)`.
`BaseLBTC.getFeeDigest` hashes that typehash with `block.chainid`, `fee`, and
`expiry`, then applies the token's EIP-712 domain. The signed `chainId` is
therefore source-bound to the executing chain rather than being cosmetic.

The fee is a maximum LBTC ceiling, not a promise that the full amount will be
charged. `AssetRouter._mintWithFee` verifies the recipient's signature over the
complete signed fee and expiry, then computes the charged fee as
`min(maximumMintCommission, feeAction.fee)`. The trusted mainnet display
therefore labels the value `Maximum LBTC network fee` and resolves `@.to`
through the exact LBTC metadata leaf (8 decimals). Values that need more than
the device's six supported fractional digits must refuse instead of rounding.

## Signed meaning of the accepted calls

`approve`, `transfer`, and `transferFrom` have the ordinary inherited
OpenZeppelin ERC-20 meaning. PQ1 shows every address and amount word and obtains
the token identity from the transaction target.

`burn(uint256)` burns exactly the signed amount from the authenticated caller.
It is not a redemption and promises no later output.

`permit(...)` submits a classical ERC-2612/ECDSA permit to the token. The owner,
spender, allowance, deadline, `v`, `r`, and `s` are all signed calldata and all
remain visible. PQ1's outer post-quantum transaction signature does not create
the inner ECDSA permit, so the trusted intent says `Submit permit` rather than
implying that PQ1 generated or approved that inner signature.

`redeem(uint256)` is not a completed payout. StakedLBTC forwards the caller and
signed LBTC amount to the currently configured AssetRouter. The evidenced
router verifies a live route, subtracts a mutable fee, sends a mailbox request,
and burns the full input amount (net request amount plus fee) from the caller.
Release/mint processing occurs later and depends on mutable external state.
The trusted display therefore says `Request redemption` and `LBTC to Burn`;
it does not promise an output token, quantity, completion time, or success.

At the fixed block the router reports redemptions enabled, a 10,000-base-unit
fee, and native token `0xb0f70c0bd6fd87dbeb7c10dc692a2a6106817072`.
Those values are archived only to demonstrate that they are live configuration,
not to place them on the trusted signed display or make them future facts.

## Honest residual and authority boundary

Router address, implementation, routes, configured maximum commission,
actually charged fee, pause/access state, mailbox, native-token choice, token
metadata, balances, allowances, permit nonce and signature validity, and
downstream release processing are mutable. This bundle does not prove that a
call will succeed and does not monitor future upgrades.

Nothing here validates a Bitcoin script, authorizes another chain or
deployment (including Sepolia feeApproval), enables dynamic calldata, nested
calls, fallback or blind signing, or grants hardware, production, shipment, or
future-upgrade authority.

Primary records:

- https://github.com/lombard-finance/evm-smart-contracts/tree/bfd32248badaa2fb35a453f17f3c181badfb3dd6
- https://eth.blockscout.com/address/0x8236a87084f8b84306f72007f36f2618a5634494
- https://eth.blockscout.com/address/0x072072317469ebb6c340a47e41561c9c3b782bd9
- https://eth.blockscout.com/address/0x9ece5fb1ab62d9075c4ec814b321e24d8ea021ac
- https://eth.blockscout.com/address/0xb823359367978a28eae71e90f79d95b62348bd80
- https://eth.blockscout.com/block/25582800

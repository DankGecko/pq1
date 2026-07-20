# Lido WithdrawalQueueERC721 semantic evidence

This directory is the compact offline evidence input for the Lido mainnet
WithdrawalQueueERC721 proxy at
`0x889edC2eDab5f40e902b864aD4d7AdE8E412F9B1`. It supports the seven routes
admitted by PQ1, including both non-permit stETH and wstETH withdrawal-request
routes.

## Pinned identities

The official source anchor is Lido
[`core` v2.0.0](https://github.com/lidofinance/core/releases/tag/v2.0.0),
commit
[`cadffa46a2b8ed6cfa1127fca2468bae1a82d6bf`](https://github.com/lidofinance/core/commit/cadffa46a2b8ed6cfa1127fca2468bae1a82d6bf).
The archived `deployment/deployed-mainnet.json` and four files under
`source/` are byte-for-byte `git show` results from that commit, not files
copied from the repository's later default branch.

The official deployment record names the OssifiableProxy, its deployment
transaction, and implementation
`0xE42C659Dc09109566720EA8b2De186c2Be7D94D9`. At Ethereum block
25,568,568 (`0x1862538`), dRPC and PublicNode independently returned that
same implementation, admin
`0x3e40D73EB977Dc6a537aF587D48316feE66E9C8c`, and
`proxy__getIsOssified() == false`. They also returned byte-identical proxy
and implementation runtimes. The exact queries and results are in
`rpc/fixed-block-receipt.json`; the runtime files are the exact
`eth_getCode` results with readability line breaks only.

Blockscout reports both contracts fully verified with Solidity 0.8.9,
optimizer 200, and Istanbul EVM settings:

- proxy metadata and source:
  https://eth.blockscout.com/api/v2/smart-contracts/0x889edC2eDab5f40e902b864aD4d7AdE8E412F9B1
- implementation metadata, source, ABI, and runtime:
  https://eth.blockscout.com/api/v2/smart-contracts/0xE42C659Dc09109566720EA8b2De186c2Be7D94D9

The verified explorer sources match the archived official source files. The
canonical seven-entry admitted ABI subset is in `abi/routes.abi.json`.

## Route conclusions

| Route | PQ1 status | Source-bound meaning |
|---|---|---|
| `approve(address,uint256)` | admitted | Sets the exact NFT approval; a zero target clears it. Current ownership and caller authority are live. |
| `claimWithdrawal(uint256)` | admitted | The current owner burns the finalized request NFT and receives a live calculated ETH amount. The amount is not signed or guaranteed. |
| `safeTransferFrom(address,address,uint256)` | admitted | Moves the withdrawal claim-right NFT, clears its token approval, and invokes ERC721Receiver for a contract recipient. The callback may revert or reenter. |
| `setApprovalForAll(address,bool)` | admitted | Grants or revokes collection-wide authority over all current and future unstETH NFTs for the caller. |
| `transferFrom(address,address,uint256)` | admitted | Moves the withdrawal claim-right NFT and clears its token approval without a receiver callback. |
| `requestWithdrawals(uint256[],address)` | admitted | For each signed stETH amount, checks the request bounds, transfers that amount from the caller, computes live shares, and mints a request NFT to the effective owner. A signed zero owner is displayed as the independently derived executing sender. |
| `requestWithdrawalsWstETH(uint256[],address)` | admitted | For each signed wstETH amount, transfers it from the caller, unwraps it to a live stETH amount, validates that result, computes live shares, and mints a request NFT to the effective owner. A signed zero owner is displayed as the independently derived executing sender. |

The NFT transfer routes convey ownership of a withdrawal claim, not an immediate
stETH or ETH payment. Claim amount, request IDs, wstETH-to-stETH conversion,
stETH/share conversion, finalization, balances, approvals, timestamps, callback
behavior, and execution success remain live-state residuals as detailed in
`manifest.json`. In particular, neither request route promises an exact eventual
ETH output.

The zero-owner admission is exact and bounded: the renderer displays the signed
nonzero owner, or substitutes the independently derived executing sender when
the signed owner is `address(0)`. The permit-bearing
`requestWithdrawalsWithPermit` and `requestWithdrawalsWstETHWithPermit` routes
remain outside this ABI subset and hard-refused. The permit-bearing stETH route
hides its effect-bearing permit members; the permit-bearing wstETH route does
not account for its hidden permit tuple member by member. This package does not
expand permit signing authority.

## Evidence boundary

This package is historical fixed-block evidence. The proxy was not ossified at
the pinned block and can be upgraded by its admin, so no later block inherits
the source conclusions automatically. The evidence binds the archived runtime
and successful source semantics; it is not live monitoring and grants no
shipment, fallback, forced-blind, or generic signing authority.

All ordinary consumers should read only the archived files and manifest. No
network access is needed after capture. `manifest.json` records every artifact
SHA-256, decoded runtime length and Keccak-256, selector, source range, and the
two-RPC block identity.

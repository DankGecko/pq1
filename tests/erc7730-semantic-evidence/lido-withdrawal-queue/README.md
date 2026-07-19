# Lido WithdrawalQueueERC721 semantic evidence

This directory is the compact offline evidence input for the Lido mainnet
WithdrawalQueueERC721 proxy at
`0x889edC2eDab5f40e902b864aD4d7AdE8E412F9B1`. It supports the five routes
currently admitted by PQ1 and records why
`requestWithdrawals(uint256[],address)` remains hard-refused.

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
canonical six-entry ABI subset is in `abi/routes.abi.json`; five entries are
admitted and the final request route is retained as evidence for its refusal.

## Route conclusions

| Route | PQ1 status | Source-bound meaning |
|---|---|---|
| `approve(address,uint256)` | admitted | Sets the exact NFT approval; a zero target clears it. Current ownership and caller authority are live. |
| `claimWithdrawal(uint256)` | admitted | The current owner burns the finalized request NFT and receives a live calculated ETH amount. The amount is not signed or guaranteed. |
| `safeTransferFrom(address,address,uint256)` | admitted | Moves the withdrawal claim-right NFT, clears its token approval, and invokes ERC721Receiver for a contract recipient. The callback may revert or reenter. |
| `setApprovalForAll(address,bool)` | admitted | Grants or revokes collection-wide authority over all current and future unstETH NFTs for the caller. |
| `transferFrom(address,address,uint256)` | admitted | Moves the withdrawal claim-right NFT and clears its token approval without a receiver callback. |
| `requestWithdrawals(uint256[],address)` | refused | Each amount would transfer stETH and mint a request NFT, but a signed zero owner means `msg.sender`. PQ1's current address formatter cannot authenticate that conditional substitution, so the format is dropped rather than displaying the wrong effective owner. |

The NFT transfer routes convey ownership of a withdrawal claim, not an immediate
stETH or ETH payment. Claim amount, request IDs, stETH/share conversion,
finalization, balances, approvals, timestamps, callback behavior, and execution
success remain live-state residuals as detailed in `manifest.json`.

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

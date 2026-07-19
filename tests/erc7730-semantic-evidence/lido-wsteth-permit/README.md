# Lido wstETH calldata semantic evidence

This directory is the offline, fixed-block evidence input for the single
Ethereum wstETH deployment whose eight admitted calldata routes are `permit`,
`wrap`, `unwrap`, `transfer`, `transferFrom`, `approve`, `increaseAllowance`,
and `decreaseAllowance`.

It pins the direct runtime, ERC-1967 implementation-slot result, deployment
receipt, verified route ABIs and source, official Lido source anchor, and the
fixed-block `name`, `symbol`, `decimals`, `stETH`, and `DOMAIN_SEPARATOR`
results. dRPC and MEV Blocker returned identical results for every archived
block, code, slot, transaction, receipt, and call value.

`abi/remaining-routes.abi.json` is the exact six-function subset of the
Blockscout-verified ABI for the routes other than `permit` and `wrap`. Its file
hash and the already-pinned canonical hash of the complete verified ABI bind
that subset to the same explorer receipt.

The offline dbgen integration tests bind those receipts to the exact curated
descriptor deployment, the displayed calldata operands, the production
ERC-20 metadata row, and the on-device contract-binding check. The permit
evidence checks deadline, owner nonce, EIP-712 hash, recovery, owner match,
nonce increment, and approval.

The wrap route evidence binds its single signed stETH amount to the verified
source's nonzero check, stETH-share conversion, wstETH mint to `msg.sender`,
and exact-amount stETH pull into the wrapper. The resulting wstETH amount
depends on live share state and is not calldata, so PQ1 claims the exact stETH
input and wrap action—not an exact future minted amount.

The inverse `unwrap` route burns the exact signed wstETH input from
`msg.sender`, derives the returned stETH through `getPooledEthByShares`, and
transfers that stETH to `msg.sender`. The returned stETH amount depends on live
share state and is not signed calldata, so PQ1 does not claim an exact output.

The inherited OpenZeppelin ERC-20 routes have no overridden transfer hook:
`transfer` moves the exact signed amount from `msg.sender` to the signed
recipient, while `transferFrom` moves it from the signed sender to the signed
recipient and consumes `allowance[sender][msg.sender]`. Live balances,
allowance sufficiency, and the remaining allowance are execution state rather
than signed output facts.

`approve` replaces `allowance[msg.sender][spender]` with the signed amount.
The standard nonzero-to-nonzero ERC-20 approval race remains an
ordering-dependent residual. `increaseAllowance` and `decreaseAllowance`
instead display a signed delta; their prior and resulting allowance values are
live state, and underflow or overflow makes the respective call revert.

Primary sources:

- Lido deployment list: https://docs.lido.fi/deployed-contracts/
- Official Lido source: https://github.com/lidofinance/lido-dao/tree/2b46615a11dee77d4d22066f942f6c6afab9b87a
- Verified deployed source: https://eth.blockscout.com/address/0x7f39C581F595B53c5cb19bD0b3f8dA6c935E2Ca0
- Evidence block: https://eth.blockscout.com/block/25566776
- Deployment transaction: https://eth.blockscout.com/tx/0xaf2c1a501d2b290ef1e84ddcfc7beb3406f8ece2c46dee14e212e8233654ff05
- OpenZeppelin ERC20Permit v3.4.0: https://github.com/OpenZeppelin/openzeppelin-contracts/blob/v3.4.0/contracts/drafts/ERC20Permit.sol

The explorer source used CRLF line endings. The archived flattened file is
explicitly normalized to LF with a final newline; both source hashes are
recorded. Ordinary tests are fully offline. The nonce is authenticated
contract state but is not calldata, so this evidence does not claim that PQ1
displays it. The archived block is a historical receipt only: it proves
neither later code nor later state and provides no live monitoring, shipment,
fallback, or blind-signing authority.

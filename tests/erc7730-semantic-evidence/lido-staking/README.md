# Lido staking calldata semantic evidence

This package binds PQ1's already-admitted Ethereum mainnet routes
`stETH.submit(address)` and `WstETHReferralStaker.stakeETH(address)` to official
Lido source and deployment records plus two independent fixed-block RPC
observations. It adds no descriptor, deployment, selector, or fallback
authority.

The clear-signing claim is deliberately narrow. On a successful call, the
signed transaction value is the exact ETH forwarded into Lido and the signed
address word is the exact referral. `submit` mints stETH shares to the caller;
the referral staker forwards both operands, wraps the resulting stETH, and
transfers the returned wstETH to the caller. The resulting token amount is not
calldata: it depends on live pooled-ETH/share state and rounding. PQ1 therefore
shows the ETH input and referral, not a minimum or guaranteed output.

The stETH address is an upgradeable Aragon proxy. At mainnet block 25,569,139
both dRPC and MEV Blocker independently returned the archived proxy and
implementation runtimes and the same `implementation()`, `proxyType()`,
`kernel()`, and `appId()` results. Those observations bind this historical
snapshot only; they are not a live-monitoring or future-code guarantee.

The referral staker is a direct contract whose immutable `stETH()` and
`wstETH()` bindings also agree across the two operators. Its official source is
byte-identical to Blockscout's fully verified source. The fixed-block rate
queries are retained only to demonstrate that output is live-state-dependent,
not to promise that rate for a later transaction.

Primary sources:

- Lido core v3.0.2 deployment and source:
  https://github.com/lidofinance/core/tree/2a2210baa3939f8079c47e8b45656b9d40e90650
- Official referral-staker address record and source:
  https://github.com/lidofinance/si-lidity/tree/a2f4857e29ca86e566dcf6ab3e1ce60d07bdce93
- Lido implementation verification:
  https://eth.blockscout.com/api/v2/smart-contracts/0x6ca84080381e43938476814be61b779a8bb6a600
- Referral-staker verification:
  https://eth.blockscout.com/api/v2/smart-contracts/0xa88f0329c2c4ce51ba3fc619bbf44efe7120dd0d

The endpoint-specific JSON files retain the raw JSON-RPC results separately.
`rpc/collect-fixed-block.sh` records the exact methods, targets, calldata, and
fixed block used to reproduce them. After collection, each operator receipt is
formed deterministically with `jq -s . <operator>/*.json`, using the numbered
filenames in lexical order.

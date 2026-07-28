# Flying Tulip vault/mint evidence

This package pins the ten accepted leaves emitted by the production and dev
`EpochRewardsVault` and `MintAndRedeem` descriptors.

The evidence is intentionally narrow:

- Flying Tulip's solver-integration note identifies the Ethereum production
  proxies, ftUSD metadata, mint/redeem direction, 1:1 vault behavior, and the
  zero-deadline rule.
- Exact Sourcify matches provide the production and dev implementation source,
  ABI, compiler configuration, runtime template, and immutable-reference map.
- Fixed-block RPC receipts bind each descriptor proxy to an EIP-1967
  implementation, its exact proxy/implementation runtime bytes, and the
  chain-specific ftUSD/FT/wrapper configuration.
- The offline Rust test normalizes compiler-declared immutable spans before
  comparing each deployed implementation with its exact compiler template. It
  also checks every named immutable span against the fixed-block configuration.

The source-derived compiler records are deliberately smaller than the complete
Sourcify responses. Each record preserves the response URL and SHA-256, exact
compiler identity, deployed-bytecode template, immutable-reference map, and the
source-order binding from immutable variable name to compiler AST ID. The
complete primary contract source and ABI are archived separately.

This evidence says nothing about live rewards, prices, fees, caps, collateral
enablement, redemption queues, transaction success, future proxy upgrades,
unlisted sibling routes, fallback behavior, blind signing, production, or
shipment authority.

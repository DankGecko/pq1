# Legacy DeFi ERC-7730 deployment and semantic evidence

This offline bundle binds the two descriptor families reviewed in PQ1 issue
497:

- 1inch `AggregationRouterV4` on Ethereum, limited to the two Clipper routes
  whose complete operands can be rendered;
- Aave V2 `LendingPool` on Ethereum, Polygon, and Avalanche, limited to the six
  statically complete routes already declared by `calldata-lpv2.json`.

Two independent RPC fronts per chain archive canonical EIP-1898 fixed-block
headers, runtime bytecode, and (for Aave) EIP-1967 implementation,
addresses-provider, revision, and provider-to-pool links. Sourcify or Routescan
records bind those runtimes to verified source and ABI. The pinned Aave address
book identifies every proxy, provider, and implementation; the Aave V2 source
repository is retained as an official auxiliary cross-check. The focused tests
recompute every artifact hash and compare the independent receipts offline.

The verified 1inch V4 `ClipperRouter` treats only address zero as native
currency. The shared descriptor's additional `0xEeee...` sentinel belongs to
other router paths and is therefore narrowed for the admitted Clipper formats.
`clipperSwapToWithPermit` remains an exact known-call refusal because its hidden
permit bytes can change authority.

The deployed Aave V2 implementations use `rateMode` as the *current* debt mode
inside `swapBorrowRateMode`, burning that debt and minting the opposite mode.
The descriptor therefore says “Swap borrow rate mode”, not “Swap to variable”.
Borrow and deposit retain the complete visible referral-code word. An explicit
deployment-format allowlist fences the six evidenced calls from future
descriptor growth.

## Honest boundary

These are historical fixed-block receipts for one immutable router deployment
and three upgradeable Aave proxies. They do not monitor future code or proxy
upgrades, prove token metadata/reserve state, quote quality, transaction
success, hardware, production, shipment, fallback, or blind-signing safety.
Permit, packed/dynamic aggregation, flash-loan, liquidation, authority, and
every other sibling route remain outside the admitted subset.

Primary records:

- https://github.com/aave-dao/aave-address-book
- https://github.com/aave/protocol-v2
- https://sourcify.dev/server/api-docs/swagger.json
- https://api.routescan.io


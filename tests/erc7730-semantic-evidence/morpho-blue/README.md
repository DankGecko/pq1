# Morpho Blue semantic evidence

This package binds the PQ1-admitted Morpho Blue `borrow`, `withdraw`, and
`withdrawCollateral` displays to the canonical same-address deployments on
Ethereum and Base.

The archived official source is exactly
`morpho-org/morpho-blue@v1.0.0` (`55d2d99304fb3fb930c688462ae2ccabb1d533ad`).
Rebuilding that tag with its checked-in `build` profile uses solc 0.8.19,
via-IR, and 999,999 optimizer runs. The resulting 15,623-byte runtime matches
both fixed-block deployments after masking only the two forge-reported
32-byte `DOMAIN_SEPARATOR` immutable references. Those two words repeat the
same chain-specific value within each deployment; every other byte matches.

Two independent RPC operators on each chain agree on the pinned block header,
complete runtime, and zero standard EIP-1967 implementation/admin/beacon
slots. Exact build/runtime equality, rather than the zero slots alone, is the
direct-contract evidence.

The three admitted routes show all five words that define the market, both
asset/share input words where present, `onBehalf`, and `receiver`. The curation
formats `assets` as a token amount using the exact signed market token:

- `borrow` and `withdraw`: `marketParams.loanToken`;
- `withdrawCollateral`: `marketParams.collateralToken`.

Shares deliberately remain raw. Morpho requires exactly one of assets/shares
to be zero, then converts the other using accrued live totals and route-specific
rounding. PQ1 therefore shows both exact signed inputs and does not invent a
state-dependent conversion. Authorization, liquidity, oracle price, health,
and transaction success remain live-state residuals.

`supply`, `repay`, and `supplyCollateral` remain refused because their
arbitrary `bytes data` can invoke caller callbacks and PQ1 cannot render that
effect-bearing payload injectively.

Primary source and deployment records:

- https://github.com/morpho-org/morpho-blue/tree/55d2d99304fb3fb930c688462ae2ccabb1d533ad
- https://docs.morpho.org/developers/contracts/addresses/

This is historical fixed-block evidence, not live monitoring or production,
shipment, fallback, or blind-signing authority.

# FlyingTulip market and pFT semantic evidence

This offline bundle binds the seven FlyingTulip deployment leaves used by
PQ1's pFT approval, marketplace-listing, and PUT-exit displays:

- three pFT proxies admit `approve` and `setApprovalForAll`;
- the Sonic marketplace admits `addListing`, `editListing`, and
  `removeListing`; and
- the two PutManager proxies backed by the same static FT contract admit
  `divest` and `withdrawFT`.

`buy`, `acceptBuyOffer`, and the proof-bearing `invest` route remain exact-known
hard refusals. The newer Sonic PutManager is also an exact-known refusal for
`divest` and `withdrawFT` because this shared descriptor cannot injectively
bind its different FT contract. This package does not authorize those calls,
another selector, fallback, or blind signing.

## Source and deployment binding

At Ethereum block 25,630,720 (`0x1871800`, hash
`0x6ef230ed…ec9af7`) and Sonic block 76,644,352 (`0x4918000`, hash
`0xe8fe0e22…0702cf`), two providers per network agree on every proxy runtime,
EIP-1967 implementation slot, complete implementation runtime, and relevant
read-only binding.

The verified Etherscan/SonicScan standard-input bundles all compile with solc
`0.8.30+commit.73712a01`. Checked-in compiler artifacts include storage layout,
deployed-runtime templates, and immutable-reference maps. Offline tests compare
the rebuilt templates to every fixed-block implementation after masking only
compiler-declared immutable spans. Creation transactions independently bind
the PutManager immutables:

- the Ethereum and original Sonic PutManagers use FT
  `0x5dd1…082c` and pFT `0xa421…04F2`;
- the newer Sonic PutManager uses FT `0x2638…4ad9` and pFT
  `0x1d80…9D67`; and
- both FT deployments report symbol `FT` and 18 decimals.

The pFT proxies report their matching PutManager, and the marketplace compiler
layout places `_pFT` in slot zero; the fixed-block value is the newer Sonic pFT
proxy. These bindings prevent one deployment's position ID from being labelled
as another collection.

## Signed meaning

OpenZeppelin's inherited ERC-721 source establishes that `approve` changes the
single-token approval and `setApprovalForAll` changes the caller's collection-
wide operator bit. PQ1 identifies the NFT collection from the signed
transaction target and shows both boolean outcomes.

Marketplace listing routes bind the pFT ID, payment token and exact asking
amount, and expiry. Address zero is authenticated as the only native-currency
sentinel. The source treats the maximum `uint40` expiry as no expiry, which the
display states explicitly. Buying remains refused because mutable fees, seller
state, PUT state, and optional Permit2 authority affect the transfer.

`divest` exercises the PUT: it reduces the signed FT entitlement and withdraws
position collateral to the caller. `withdrawFT` instead returns FT while
reducing the corresponding collateral protection. On the two admitted
PutManagers, the amount is bound to static FT contract `0x5dd1…082c` and the
trusted display includes that complete token address. The collateral token and
calculated output come from live position/oracle/vault state, not signed
calldata, so PQ1 does not invent an output amount. PutManager position IDs are
shown as raw IDs because the admitted pair still spans two chains and the
source descriptor also covers a distinct pFT collection.

## Honest boundary

This is historical source, compiler, fixed-block runtime, and signed-meaning
evidence. It does not monitor upgrades or prove ownership, approval, listing,
fee, oracle, vault, liquidity, pause, whitelist, token behavior, transaction
success, hardware, production, shipment, fallback, or blind-signing readiness.

Primary records:

- https://etherscan.io/address/0x1e4e741e5f0f4f258def137e1968716eddae4bf5#code
- https://www.sonicscan.org/address/0x90ae2cac15f8d58a258f7b4a243657754469922a#code
- https://www.sonicscan.org/address/0xbdd1327024b66212bf1f6a6a7f8b21f81b1faca4#code
- https://www.sonicscan.org/address/0xc55253ea84050700e1efa8878d4a5053b6bf7c5e#code

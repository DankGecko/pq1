# Uniswap SwapRouter02 single-hop semantic evidence

This directory pins the smallest offline evidence set needed to explain why
PQ1 deliberately excludes Ethereum SwapRouter02 `exactInputSingle` and
`exactOutputSingle` from clear signing. It contains the two route ABI entries,
the four official v1.1.0 source files that define the concrete inheritance and
single-hop semantics, and the fixed-block deployed runtime.

The official source shows semantics that a literal field renderer would
misstate:

- recipient `address(1)` means `msg.sender`, while `address(2)` means the
  router;
- exact-input `amountIn == 0` means the router's complete token balance, not
  zero;
- a price limit can make the input or output amount a cap rather than an exact
  realized amount; and
- the routes are payable, so restoration also has to bind the funding context.

The curated descriptor therefore retains the standard
`senderAddress: [address(1)]` declaration. PQ1 does not implement that
semantic parameter, so tolerant compilation emits no Router02 leaf. Declared
call collection still retains selectors `0x04e45aaf` and `0x5023b4df`;
the normal known-shape policy consequently hard-refuses them instead of
falling through to an ordinary signing path.

The offline dbgen test checks the archived hashes, source anchors, ABI tuple
signatures, both descriptor annotations, absence of an emitted Router02 leaf,
and presence of both exact known-call tuples.

Primary immutable inputs:

- Official release: https://github.com/Uniswap/swap-router-contracts/releases/tag/v1.1.0
- Pinned source commit: https://github.com/Uniswap/swap-router-contracts/tree/8fe4f086cee7c08f0bdb6ebe20c9ab615921c65f
- Pinned Ethereum deployment document: https://github.com/Uniswap/docs/blob/338d70983ac49911aecac02dd57b0a969c1ca61e/archive/docs/contracts/v3/reference/deployments/Ethereum-Deployments.md
- Deployment transaction: https://eth.blockscout.com/tx/0x7299cca7203f60a831756e043f4c2ccb0ee6cb7cf8aed8420f0ae99a16883a2b
- Evidence block: https://eth.blockscout.com/block/25566776

This is merge-level, fixed-block evidence. It is not live monitoring, hardware
evidence, shipment authority, or permission to enable blind signing.

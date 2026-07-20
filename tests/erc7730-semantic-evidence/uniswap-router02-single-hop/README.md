# Uniswap SwapRouter02 single-hop semantic evidence

This directory pins the offline evidence for PQ1's constrained restoration of
Ethereum SwapRouter02 `exactInputSingle` and `exactOutputSingle` clear signing.
It contains the two route ABI entries, the official v1.1.0 source path that
defines the concrete inheritance and single-hop semantics, the exact
v3-periphery 1.3.0 payment dependency, and the fixed-block deployed runtime.

The official source shows semantics that a literal field renderer would
misstate:

- recipient `address(1)` means `msg.sender`, while `address(2)` means the
  router;
- exact-input `amountIn == 0` means the router's complete token balance, not
  zero;
- a price limit can make the input or output amount a cap rather than an exact
  realized amount; and
- the routes are payable and `PeripheryPayments.pay` may wrap native currency
  when `tokenIn == WETH9` and the router balance covers the payment.

The curated descriptor retains the standard
`senderAddress: [address(1)]` declaration and adds an always-visible
`@.value` field labelled `Native value` to both single-hop formats. PQ1 admits
the formats only when the device resolves `address(1)` to the signed
UserOperation sender, rejects `address(2)`, rejects zero exact-input amount,
rejects nonzero price limits, and requires `@.value == 0`. Any nonzero native
value or other unsupported combination remains a known-call hard refusal
rather than falling through to an ordinary or blind signing path. The visible
native-value page therefore proves that the admitted signed value is zero; it
does not claim who funds the swap. The dynamic Router02 routes remain unchanged
and refused.
The token fields use the neutral labels `Swap input` and `Max swap input`:
they describe the swap bound without claiming that the signer is necessarily
the payer, because `PeripheryPayments` can consume funds already held by the
router.

The payment dependency is exact rather than inferred from a floating package:

- SwapRouter02 v1.1.0's `V3SwapRouter` inherits
  `PeripheryPaymentsWithFeeExtended`, which inherits
  `PeripheryPaymentsExtended`, which imports
  `@uniswap/v3-periphery/contracts/base/PeripheryPayments.sol`;
- the pinned swap-router `package.json` requires
  `@uniswap/v3-periphery` exactly at `1.3.0`;
- the archived yarn-lock stanza fixes tarball SHA-1
  `37f0a1ef6025221722e50e9f3f2009c2d5d6e4ec`; and
- the locked tarball's `PeripheryPayments.sol` is byte-identical to official
  v1.3.0 commit `80f26c86c57b8a5e4b913f42844d4c8bd274d058` and the archived file
  (SHA-256 `68cef83e01906a13f4a2bb1c12a9e99fad3e957eea6ddbb54bac30ba3b06a436`).

The offline dbgen test checks the archived hashes, dependency and inheritance
anchors, ABI tuple signatures, both descriptor annotations, the constrained
field set, and presence of both exact known-call tuples.

Primary immutable inputs:

- Official release: https://github.com/Uniswap/swap-router-contracts/releases/tag/v1.1.0
- Pinned source commit: https://github.com/Uniswap/swap-router-contracts/tree/8fe4f086cee7c08f0bdb6ebe20c9ab615921c65f
- Official v3-periphery release: https://github.com/Uniswap/v3-periphery/releases/tag/v1.3.0
- Pinned v3-periphery source: https://github.com/Uniswap/v3-periphery/tree/80f26c86c57b8a5e4b913f42844d4c8bd274d058
- Pinned Ethereum deployment document: https://github.com/Uniswap/docs/blob/338d70983ac49911aecac02dd57b0a969c1ca61e/archive/docs/contracts/v3/reference/deployments/Ethereum-Deployments.md
- Deployment transaction: https://eth.blockscout.com/tx/0x7299cca7203f60a831756e043f4c2ccb0ee6cb7cf8aed8420f0ae99a16883a2b
- Evidence block: https://eth.blockscout.com/block/25566776

This is merge-level, fixed-block evidence. It is not live monitoring, hardware
evidence, shipment authority, or permission to enable blind signing.

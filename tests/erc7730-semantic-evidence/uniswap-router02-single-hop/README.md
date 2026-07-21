# Uniswap SwapRouter02 constrained-route semantic evidence

This directory pins the offline evidence for PQ1's constrained restoration of
six Ethereum SwapRouter02 routes:

- V3 `exactInputSingle` and `exactOutputSingle`;
- packed V3 `exactInput((bytes,address,uint256,uint256))` and
  `exactOutput((bytes,address,uint256,uint256))`; and
- V2 `swapExactTokensForTokens(uint256,uint256,address[],address)` and
  `swapTokensForExactTokens(uint256,uint256,address[],address)`.

The V2 routes are the exact four-argument SwapRouter02 functions, selectors
`0x472b43f3` and `0x42712a67`. They are not the older deadline-bearing
five-argument Router02 signatures commonly associated with selectors
`0x38ed1739` and `0x8803dbee`. The archived ABI subset preserves the official
v1.1.0 input names, types, order, payable mutability, and return values.

The archive contains the official v1.1.0 source paths that define all three
route families, their shared payment behavior, V2 pair and path behavior, the
exact v3-periphery 1.3.0 `Path.sol` encoding, and the fixed-block deployed
runtime.

## Source-derived hazards

The official source establishes semantics that an endpoint-only or literal
field renderer would misstate:

- recipient `address(1)` means `msg.sender`, while `address(2)` means the
  router;
- `amountIn == 0` on every admitted exact-input route means the router's complete
  input-token balance and changes the payer to the router;
- every V2 `path` element selects a hop, pair, intermediate receiver, and
  final output token, so the complete signed array affects execution;
- a packed V3 path is exactly one 20-byte token followed by one or more
  `(3-byte uint24 fee, 20-byte token)` hops; `Path.sol` advances by the exact
  23-byte stride and decodes the first pool at token offsets 0 and 23 with the
  fee at offset 20;
- packed V3 exact-input consumes those pools forward, while exact-output stores
  `tokenOut` first and recursively executes the encoded path in reverse, so a
  user-facing exact-output route must reverse both token and fee traversal;
- V2 exact-input enforces `amountOutMin` against the final beneficiary's
  output-token balance delta;
- V2 exact-output calculates the required input backwards through every path
  hop and enforces `amountIn <= amountInMax`;
- a V3 price limit can turn a displayed input or output into a cap rather than
  the exact realized quantity; and
- all six routes are payable. `PeripheryPayments.pay` can wrap native currency
  when the input is WETH9 and the router's native balance covers the payment.

Requiring signed `@.value == 0` prevents the reviewed transaction from funding
the router. It does not prove that the signer supplies the displayed input:
pre-existing router native currency can still fund a WETH9 input through
`PeripheryPayments.pay`. Router-held ERC-20 payment requires the `amountIn ==
0` router-payer branch, which the admitted exact-input routes reject.
Descriptor labels are therefore neutral (`Swap input` and `Max swap input`)
rather than claims about who pays.

## Device-constrained admission

Every admitted route renders `@.value` as `Native value` and requires it to be
zero. Recipient `address(1)` resolves to the signed UserOperation sender;
`address(2)` refuses. Exact-input `amountIn == 0` refuses. V3 nonzero price
limits refuse. The two V2 routes render every signed `path` address as the
`Route`; paths above the device's eight-address review cap refuse instead of
hiding hops. Their exact-input minimum and exact-output maximum remain visible.

The two packed V3 routes render every token as a full address and every pool
fee as the exact signed uint24 value. Only canonical
`token[20] || (fee[3] || token[20]){1..5}` paths are admitted. Exact-input is
shown in encoded order. The signed exact-output selector selects reverse
presentation, producing the execution/user direction from input token to
output token without trusting an unauthenticated direction hint. A malformed,
zero-hop, or over-five-pool path refuses before review. No unsupported route
falls through to ordinary or blind signing.

The payment dependency is exact rather than inferred from a floating package:

- both `V2SwapRouter` and `V3SwapRouter` inherit
  `PeripheryPaymentsWithFeeExtended`, which inherits
  `PeripheryPaymentsExtended`, which imports
  `@uniswap/v3-periphery/contracts/base/PeripheryPayments.sol`;
- the pinned swap-router `package.json` requires
  `@uniswap/v3-periphery` exactly at `1.3.0`;
- the archived yarn-lock stanza fixes tarball SHA-1
  `37f0a1ef6025221722e50e9f3f2009c2d5d6e4ec`; and
- the locked tarball's `PeripheryPayments.sol` is byte-identical to official
  v1.3.0 commit `80f26c86c57b8a5e4b913f42844d4c8bd274d058` and the archived file
  (SHA-256 `68cef83e01906a13f4a2bb1c12a9e99fad3e957eea6ddbb54bac30ba3b06a436`);
  and the same locked tarball's `Path.sol` is byte-identical to the pinned
  commit and archived file (2787 bytes, SHA-256
  `42edaa8b6c577bee7a24b2f1d377fa7fb7649526a935040ccdd1a91a7f3b46a0`).

The offline dbgen test hash-binds every archived source and ABI subset. It
checks the source bodies for sentinel, payment, full-path, minimum-output, and
maximum-input behavior; checks `Path.sol`'s 20-byte address, 3-byte fee,
23-byte hop stride, pool-count formula, first-pool decode, and skip behavior;
validates the exact official ABI tuples; binds the six descriptor formats and
production IR; and proves that all six admitted routes remain in the exact
known-call set.

Primary immutable inputs:

- Official release: https://github.com/Uniswap/swap-router-contracts/releases/tag/v1.1.0
- Pinned source commit: https://github.com/Uniswap/swap-router-contracts/tree/8fe4f086cee7c08f0bdb6ebe20c9ab615921c65f
- Official ABI artifact: https://unpkg.com/@uniswap/swap-router-contracts@1.1.0/artifacts/contracts/SwapRouter02.sol/SwapRouter02.json
- Official v3-periphery release: https://github.com/Uniswap/v3-periphery/releases/tag/v1.3.0
- Pinned v3-periphery source: https://github.com/Uniswap/v3-periphery/tree/80f26c86c57b8a5e4b913f42844d4c8bd274d058
- Pinned Ethereum deployment document: https://github.com/Uniswap/docs/blob/338d70983ac49911aecac02dd57b0a969c1ca61e/archive/docs/contracts/v3/reference/deployments/Ethereum-Deployments.md
- Deployment transaction: https://eth.blockscout.com/tx/0x7299cca7203f60a831756e043f4c2ccb0ee6cb7cf8aed8420f0ae99a16883a2b
- Evidence block: https://eth.blockscout.com/block/25566776

This is merge-level, fixed-block evidence. It is not live monitoring, hardware
evidence, shipment authority, or permission to enable blind signing.

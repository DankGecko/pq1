# 1inch V6 cancellation deployed-semantics evidence

This offline bundle binds two flat-static cancellation controls to ten exact
historical 1inch AggregationRouterV6 deployments:

- `cancelOrder(uint256,bytes32)` (`0xb68fb020`); and
- `increaseEpoch(uint96)` (`0xc3cf8043`).

It supplies evidence for a bounded PQ1 descriptor curation. It does not add a
selector, descriptor, fallback, or blind-signing authority by itself.

## Deployment and runtime binding

The retained request/response pairs query one fixed block per admitted chain.
Every `eth_getCode` uses EIP-1898 `blockHash` plus `requireCanonical:true`, and
two independently operated public RPC fronts agree on the header and complete
runtime bytes. The runtime is stored once per chain and receipted in
`rpc/fixed-block-receipt.json` and `manifest.json`.

Eight ordinary EVM deployments have Sourcify `exact_match` creation and
runtime records with `isProxy:false`. Aurora has a fully verified, unchanged,
direct Blockscout record whose complete deployed bytecode matches both RPC
observations. zkSync is a separate build family: its official explorer address
record explicitly binds the address to 227,808 deployed bytes, while the same
explorer's address-parameterized source record supplies the direct
`Proxy=0` solc `0.8.23` / zksolc `1.3.22` compiler input and exact ABI. Those
two records and fixed-block RPC code are joined offline; no EVM-runtime
equivalence is claimed for zkSync.

The shared address is not treated as proof of shared code. Each chain has its
own verifier and fixed-block checks. Sonic (`146`), Fantom (`250`), Kaia
(`8217`), and Avalanche (`43114`) remain exact-known hard refusals: the
archived Sourcify lookups were HTTP 404 and this bounded phase did not establish
an equivalent complete source/runtime binding elsewhere. Similar addresses,
bytecode lengths, or embedded selectors are not admission evidence.

## Source and cancellation meaning

The archived source is pinned to the official `1inch/limit-order-protocol`
tag `4.0.0-prerelease-19`, commit
`1a32e059f78ddcf1fe6294baed6cafb73a04b685`. The six load-bearing source
files are byte-identical at final tag `4.0.0`, commit
`c8be9c67247880bd6ec88cf7ad2e040a16a483f2`. Offline tests require the
relevant function bodies to be byte-identical in every admitted verified
source variant. The official audit-repository directory metadata for the
Aggregation Router V6 / Limit Order Protocol V4 family is pinned separately;
that catalogue entry is not represented as a claim about each report's scope
or findings.

The source makes both UI warnings security-relevant:

- `cancelOrder` keys state by `msg.sender`, but `makerTraits` chooses the
  effect. Bit-invalidator mode derives a slot and bit from `nonceOrEpoch`,
  ignores `orderHash`, and can affect orders sharing that nonce. Otherwise it
  marks the supplied hash fully filled. A safe display therefore shows the
  authenticated maker, the complete raw maker-traits word, the complete raw
  order hash, and the conditional-effect warning; it must not promise that a
  particular hash is always what gets cancelled.
- `increaseEpoch` increments exactly one `msg.sender` + `series` epoch. Fills
  compare an order's signed epoch for equality. Advancing can invalidate
  old-epoch orders and can also activate already-signed next-epoch orders. A
  safe display shows the authenticated maker and full `uint96` series, without
  fabricating a live/new epoch or claiming that all orders are cancelled.

`cancelOrders(uint256[],bytes32[])` remains refused. Its selector and exact ABI
are retained as negative evidence, not as an invitation to infer safety from a
known selector.

## Honest boundary

This package proves source/runtime relationships at the recorded historical
blocks only. It is not live monitoring and grants no authority to future code,
new deployments, transaction success, order existence, current epochs,
hardware, production, shipment, fallback, blind signing, or any selector not
explicitly curated elsewhere. Public RPC retention and availability may
change; checked-in raw responses remain the historical evidence when a future
recapture is unavailable.

Primary records are fetched by `collect.sh` from official 1inch GitHub
repositories, Sourcify, the Aurora Blockscout instance, the official zkSync
explorer, and the listed public RPC endpoints. Every non-manifest byte is
covered by a SHA-256 receipt and validated offline.

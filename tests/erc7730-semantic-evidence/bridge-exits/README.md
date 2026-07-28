# Bridge and exit semantic evidence

This deterministic offline bundle supports four bounded ERC-7730 calldata
families:

- Igra `KasExitBridge.requestExit` on chain 38833;
- the six flat-static Lombard LBTC routes on Sepolia;
- StarkGate's Ethereum `deposit(address,uint256,uint256)` route; and
- the bounded three-argument outbound SwissBorg BORG NTT `transfer` on
  Ethereum.

The archived Blockscout records contain complete verified source closures and
ABIs. Fixed-block EIP-1898 queries bind each descriptor deployment to the
observed proxy and implementation runtime. Sepolia and Ethereum state is
captured from two independent providers; Igra state uses the official Igra RPC
and is cross-bound to the official Igra Blockscout verification record.

## Signed meaning

Igra requires `msg.value = (unlockAmountSompi + mutable feeAmountSompi) *
10^10`, burns only `unlockAmountSompi * 10^10` wei, records the request, and
dispatches an asynchronous Kaspa message. The display therefore calls the
native value the total sent, not the amount burned.

Lombard Sepolia inherits ordinary ERC-20 `approve`, `transfer`, and
`transferFrom`; `burn` destroys the caller's exact LBTC amount; `permit`
submits a classical ERC-2612 signature; and `redeem` burns LBTC while requesting
later processing through mutable AssetRouter state. `mint(bytes,bytes)` and
`redeemForBtc(bytes,uint256)` remain exact known-call refusals.

StarkGate's evidenced proxy is a multi-token ERC-20 bridge. `deposit` requires
a currently serviced token, transfers the exact signed token amount into the
bridge, validates the Starknet felt recipient, and forwards the exact signed
native value as the L1-to-L2 message fee. L2 processing is asynchronous.

SwissBorg's manager is a locking-mode NTT manager for the standard 18-decimal
BORG token. The admitted simple overload shows the raw Wormhole chain ID,
bytes32 recipient, and native value maximum. It fixes refund bytes32 to the
recipient, disables queuing, and supplies empty instructions; excess value is
refunded. The extended overload remains exact-known but refused because its
arbitrary transceiver-instruction bytes have no injective trusted renderer.
Peers, transceivers, prices, rate limits, and delivery remain mutable.

## Authority boundary

This is historical source/runtime authority for only the listed
deployment/route pairs. It does not prove live fees, limits, routing, peers,
metadata, balances, allowances, successful execution, destination-chain
receipt, future proxy implementations, fallback, blind signing, hardware,
production, or shipment readiness.

Primary records:

- https://explorer.igralabs.com/address/0x4bb88c213d3ed9dc4bae694f1bc1bf745903b2d0
- https://explorer.igralabs.com/address/0x00d39E05A20b2C4f6D0D6CfC3C5718066B861334
- https://eth-sepolia.blockscout.com/address/0x731eFa688F3679688cf60A3993b8658138953ED6
- https://eth-sepolia.blockscout.com/address/0xfcC108e3E588cb85018aB736091d134f26151670
- https://eth.blockscout.com/address/0xcE5485Cfb26914C5dcE00B9BAF0580364daFC7a4
- https://eth.blockscout.com/address/0x6ad74D4B79A06A492C288eF66Ef868Dd981fdC85
- https://eth.blockscout.com/address/0x66a28B080918184851774a89aB94850a41f6a1e5
- https://eth.blockscout.com/address/0xd048a8D52da402611A0C5eb6f7388ffC41cd1417
- https://eth.blockscout.com/address/0x64d0f55Cd8C7133a9D7102b13987235F486F2224

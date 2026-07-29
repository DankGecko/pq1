# P2P EigenPod and message-sender semantic evidence

This directory is the deterministic offline evidence package for the two P2P
descriptor families reconciled under issue #497:

- `p2p/calldata-EigenPodManager.json` (`createPod()` on Ethereum and Hoodi);
- `p2p/calldata-P2pMessageSender.json` (`send(string)` on Ethereum and two
  Hoodi deployments).

## EigenPodManager boundary

At Ethereum block `25631500` and Hoodi block `3304500`, two independent RPC
providers per chain agree on each proxy runtime, EIP-1967 implementation slot,
implementation runtime, and the immutable EigenPod beacon, DelegationManager,
and PauserRegistry getters.

The Ethereum implementation is fully verified by Blockscout. Its source proves
that `createPod()`:

1. rejects a caller that already has a pod;
2. deploys a deterministic beacon proxy salted by `msg.sender`;
3. initializes the new pod with `msg.sender`;
4. stores it in `ownerToPod[msg.sender]`; and
5. emits `PodDeployed(pod, msg.sender)`.

The Hoodi implementation has the same length and becomes byte-identical to the
verified Ethereum implementation after only thirteen declared 20-byte
constructor-immutable occurrences are normalized. The differing bytes are
exactly the three chain-specific addresses returned by the pinned
`eigenPodBeacon()`, `delegationManager()`, and `pauserRegistry()` calls.

The curated format therefore admits only `createPod()` and displays
`@.from` as the Pod owner. The other fourteen state-changing functions in the
verified ABI are descriptor-declared exact-known refusals. No claim is made
about current pause/ownership state, whether the caller already has a pod, the
beacon's current implementation, execution success, or a future proxy upgrade.

## P2pMessageSender boundary

The fully verified Ethereum source contains one function:

```solidity
function send(string calldata text) external {
    emit Message(msg.sender, text, text);
}
```

It does not enforce that the string is a withdrawal request or a list of public
keys. The upstream withdrawal-only intent is therefore replaced with the honest
generic action “Publish p2p message”, displaying both the authenticated caller
and the complete signed string.

The two Hoodi contracts have byte-identical creation code and deployed runtime.
Their successful creation transactions and receipts are archived from two
independent RPC providers. The runtime metadata identifies solc 0.8.24, and its
instruction stream is byte-identical to the checked-in solc 0.8.24 via-IR
semantic reconstruction after each compiler metadata trailer is removed. Both
the verified Ethereum runtime and the Hoodi runtime contain only the
`send(string)` selector and the `Message(address,string,string)` event topic.

`source/P2pMessageSender.hoodi-reference.sol` is intentionally labelled a
semantic reconstruction, not exact Hoodi source provenance: the Hoodi source
was not explorer-verified at capture time and its IPFS metadata object was not
retrievable. Promotion rests on the exact creation/runtime bytes and instruction
semantics, not on an unsupported source-provenance claim.

## Reproduction and limits

Run `./collect.sh` from this directory to repeat the fixed-block RPC,
Blockscout, runtime, source/ABI extraction, and reference compilation. The
checked-in Rust integration test uses only these offline artifacts.

This package grants historical clear-signing authority only. It grants no
live-monitoring, fallback, forced-blind-signing, production-shipment, or
irreversible-action authority, and it does not promise any off-chain service
will interpret or act on a published message.

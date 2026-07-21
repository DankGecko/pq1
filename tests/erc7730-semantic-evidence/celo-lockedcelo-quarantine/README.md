# Celo LockedGold/LockedCelo proxy admission evidence

This offline bundle binds the six curated `calldata-locked_celo.json` routes to
the canonical Celo mainnet LockedGold/LockedCelo proxy. It also records why the
upstream mainnet implementation address and legacy Alfajores address remain
hard refusals. It never enables blind signing.

## Mainnet mismatch

At Celo mainnet block 72,649,728 (`0x4548c00`, hash
`0x810df7ac…bf4a3c`), three public RPC fronts agreed on all of the following:

- Registry `0x000000000000000000000000000000000000ce10` returns
  `0x6cC083Aed9e3ebe302A6336dBC7c921C9f03349E` for both `LockedGold`
  and `LockedCelo` through `getAddressForString(string)`.
- that address's EIP-1967 implementation slot contains
  `0x55E1A0C8f376964bd339167476063bFED7f213d5`;
- the proxy and implementation runtime identities are byte-for-byte identical
  across Celo Forno, dRPC, and Ankr.

The upstream descriptor instead targets `0x55E1…13d5` directly. An implementation ABI
can match the proxy's delegated interface while still being the wrong execution
identity: a direct call uses the implementation address's own storage and
balance, not the Registry-selected proxy's state. PQ1 therefore cannot present
those calls as canonical Locked CELO actions.

The curated descriptor adds `0x6cC0…349E`, admits all six static routes only at
that proxy through its authenticated `deploymentFormats` allowlist, and shows
every signed calldata operand. `lock()` shows the exact outer CELO value;
`unlock`/`relock` show the exact signed CELO amount; `relock` and `withdraw`
show the exact pending-withdrawal index; and delegation routes show the literal
delegatee input plus the exact Celo Fixidity percentage (`1e24 == 100%`).
`withdraw(uint256)` cannot honestly show an amount because the contract reads
the amount from live proxy storage at the signed index.

`rpc/fixed-block-receipt.json` records the complete call data, block identity,
slot, returned words, runtime hashes, and paths to the checked-in request and
raw response batches under `rpc/raw/`. Offline tests validate every request and
derive the Registry, slot, header, and runtime agreement from each response;
they do not trust summary agreement flags. The two runtime files are the Forno
captures at that exact block and are byte-compared with every provider response.

## Source, ABI, and deployment identity

The archived Blockscout responses classify `0x6cC0…349E` as the fully verified
`LockedGoldProxy`, classify it as EIP-1967, and name `0x55E1…13d5` as the fully
verified `LockedGold` implementation. Their verified deployed bytecodes match
the fixed-block RPC captures.

The checked-in official Celo monorepo sources reproduce the verified source
bodies:

- the current `LockedGold.sol` is byte-identical to Blockscout's primary
  implementation `source_code` field;
- historical `LockedGoldProxy.sol` and `Proxy.sol` at commit
  `5ade57c620a90b0d04aa4038f5f43316ad95f49e` match the verified proxy source
  fields exactly;
- `Registry.sol` pins the official registry lookup interface used by the RPC
  receipt.

The official Celo core-contract address document independently names the proxy
as both mainnet `LockedCelo` and `LockedGold`. The official `celo-mcp`
configuration names the same mainnet proxy and identifies the descriptor's
chain-44787 address as Alfajores `LockedGold`. The archived historical release
proposal shows governance calling `_setImplementation` on this exact mainnet
proxy; its old implementation argument is not used as current-state evidence.

## Alfajores residual

The exact descriptor address `0x6a4C…c341` has an official legacy deployment
identity, but that is not enough for clear-signing authority. Alfajores is no
longer in Celo's current core-contract address table, which now lists Celo
Sepolia. This bounded package did not reconstruct an independently agreed
Alfajores fixed block, Registry mapping, proxy slot, runtime, or verified source.
The chain-44787 deployment therefore remains quarantined rather than inheriting
mainnet source or proxy evidence by name.

## Honest boundary

This is historical fixed-block and source evidence for the exact curated proxy
leaf. The device binds the chain, proxy, descriptor, and selector; it does not
bind or monitor the proxy's live EIP-1967 implementation. It also does not prove
transaction success or current storage values, establish legacy Alfajores live
state, confer production or shipment authority, or permit fallback/blind
signing. Operational policy therefore requires fresh evidence and a new
reviewed catalogue identity after a proxy upgrade, but the offline leaf cannot
itself detect that upgrade.

Primary upstream records:

- https://docs.celo.org/tooling/contracts/core-contracts
- https://github.com/celo-org/celo-monorepo
- https://github.com/celo-org/celo-mcp
- https://celo.blockscout.com/address/0x6cC083Aed9e3ebe302A6336dBC7c921C9f03349E
- https://celo.blockscout.com/address/0x55E1A0C8f376964bd339167476063bFED7f213d5

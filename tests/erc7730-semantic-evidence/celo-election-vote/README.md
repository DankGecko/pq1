# Celo Election `vote` evidence

This offline bundle supports one bounded PQ1 catalogue expansion:
`vote(address,uint256,address,address)` at the Registry-selected Celo mainnet
Election proxy. It preserves the two already-admitted activation routes on
legacy Alfajores but supplies no new Alfajores authority.

## Fixed mainnet identity

At Celo mainnet block 72,649,728 (`0x4548c00`, hash
`0x810df7ac...985bf4a3c`), Celo Forno, dRPC, and Ankr independently agree that:

- Registry `0x000000000000000000000000000000000000ce10` resolves `Election` to
  `0x8D6677192144292870907E3Fa8A5527fE55A7ff6`;
- that proxy's EIP-1967 implementation slot contains
  `0x74f9e5ee4071b9b35d127000a20f8e964009cb57`; and
- the proxy and implementation runtime bytes are identical across all three
  providers.

Every historical state query uses the EIP-1898 block-hash form with
`requireCanonical:true`. The raw requests and unmodified provider responses are
checked in under `rpc/raw/`; the offline test derives agreement from those
files rather than trusting the summary in `manifest.json`.

The Blockscout proxy and implementation records contain deployed bytecode
identical to the RPC captures. Both explorer records are only partially
verified; this package states that limitation. The implementation record's
primary `Election.sol` source is nevertheless byte-identical to the official
Celo monorepo file pinned at commit
`045aa0061b7d0e9655ff3673cbd25a1bf2b4b74a`.

## Source semantics

The pinned source establishes that:

- `group` is the validator-group account receiving the vote;
- `value` is an amount of locked native CELO moved from the effective
  account's non-voting balance into pending votes;
- `lesser` and `greater` are sorted-list position hints, with the zero address
  denoting a list boundary; they are not value recipients; and
- `msg.sender` is resolved through `Accounts.voteSignerToAccount`. The
  effective account can therefore differ from the immediate caller and is
  live state that the descriptor must not fabricate.

The Celo native token source pins symbol `CELO` and 18 decimals. The curated
route shows all four signed calldata operands: validator group, exact CELO
amount, and both complete hint addresses.

## Alfajores boundary

The pinned official-org `celo-mcp` configuration corroborates the descriptor's
legacy chain-44787 Election address. Current Celo documentation instead names
Celo Sepolia as the replacement testnet, explicitly describes migration from
Alfajores, and the current core-contract table contains no Alfajores section.
This package has no chain-44787 fixed-block Registry, proxy-slot, runtime, or
verified-source receipt. It therefore cannot add `vote` authority there.

## Honest residual

This is historical fixed-block and source evidence. It does not monitor future
proxy upgrades, resolve the effective voting account, prove group eligibility,
prove the hints are valid for live ordering, prove sufficient locked balance,
or claim transaction success. The route is nonpayable; a separately displayed
nonzero outer native value would revert at the contract and receives no success
claim. Nothing here enables fallback or blind signing, authorizes hardware or
shipment, or extends beyond this one mainnet route.

Primary upstream records:

- https://docs.celo.org/tooling/contracts/core-contracts
- https://docs.celo.org/tooling/testnets/celo-sepolia
- https://github.com/celo-org/celo-monorepo
- https://github.com/celo-org/celo-mcp
- https://celo.blockscout.com/address/0x8D6677192144292870907E3Fa8A5527fE55A7ff6
- https://celo.blockscout.com/address/0x74f9e5ee4071b9b35d127000a20f8e964009cb57

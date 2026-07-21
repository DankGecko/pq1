# Celo Validators first-member route evidence

This offline bundle supports one bounded PQ1 catalogue expansion at the
Registry-selected Celo mainnet Validators proxy:
`addFirstMember(address,address,address)`. It supplies no authority for any
other Validators route or deployment.

## Fixed mainnet identity

At Celo mainnet block 72,649,728 (`0x4548c00`, hash
`0x810df7ac...985bf4a3c`), Celo Forno, dRPC, and Ankr independently agree that:

- Registry `0x000000000000000000000000000000000000ce10` resolves `Validators` to
  `0xaEb865bCa93DdC8F47b8e29F40C5399cE34d0C58`;
- that proxy's EIP-1967 implementation slot contains
  `0x13B0B89F3242f815C1FC6C9CF56e1Ab5aEA4dC58`; and
- each provider returns identical proxy runtime bytes and identical
  implementation runtime bytes at that block.

Every historical state query uses the EIP-1898 block-hash form with
`requireCanonical:true`. The raw requests and unmodified provider responses are
checked in under `rpc/raw/`; the offline test derives agreement from those
files rather than trusting the summary in `manifest.json`.

The Blockscout proxy record is fully verified and the implementation record is
partially verified. Both records contain deployed bytecode identical to the RPC
captures. The implementation record's primary `Validators.sol` source is
byte-identical to the official Celo monorepo file pinned at commit
`045aa0061b7d0e9655ff3673cbd25a1bf2b4b74a`.

## Source semantics

The pinned source establishes that:

- `validator` is the registered validator account to add as the group's first
  member; it must already be affiliated with the effective group and must not
  already be in that group's member list;
- `lesser` and `greater` are signed validator-group address hints for groups
  with fewer and more live election votes, respectively; they are not members,
  recipients, or vote amounts;
- `msg.sender` is resolved through `Accounts.validatorSignerToAccount`, so the
  effective group can differ from the immediate caller and remains live state;
- the effective group must be registered and empty, and the group and validator
  must satisfy the live maximum-size and locked-gold requirements; and
- after the first member is appended, Validators calls
  `Election.markGroupEligible(group, lesser, greater)`, which inserts the group
  using its live total votes and emits the eligibility event.

The display can therefore identify the exact validator and both signed hints,
and can state the first-member/eligibility intent. It must not fabricate the
effective group address, live vote total, affiliation, locked-gold balances,
list position, or successful execution.

## Authority boundary

The deterministic ABI projection contains exactly `addFirstMember`. The
package supplies no authority for the descriptor's other Validators routes,
for the legacy Alfajores deployment, or for any other deployment.

This is historical fixed-block and source evidence. It does not monitor future
proxy upgrades, resolve the effective group, prove that the group remains
empty, prove validator affiliation or registration, validate the live ordering
hints, prove locked-gold sufficiency, or claim transaction success. The route
is nonpayable; a nonzero outer native value would revert and receives no
success claim. Nothing here enables fallback or blind signing, or authorizes
hardware or shipment.

Primary upstream records:

- https://docs.celo.org/tooling/contracts/core-contracts
- https://github.com/celo-org/celo-monorepo
- https://celo.blockscout.com/address/0xaEb865bCa93DdC8F47b8e29F40C5399cE34d0C58
- https://celo.blockscout.com/address/0x13B0B89F3242f815C1FC6C9CF56e1Ab5aEA4dC58

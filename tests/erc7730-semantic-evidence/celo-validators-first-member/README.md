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
- `Validators.registry()` points back to the same canonical Registry proxy;
- the Registry proxy implementation is
  `0x203fdf86A00999107Df531fa00b4bA81d674cb66`, and its fixed-block entries
  select Accounts proxy `0x7d21685C17607338b313a7174bAb6620baD0aaB7`
  and Election proxy `0x8D6677192144292870907E3Fa8A5527fE55A7ff6`;
- the selected Accounts and Election implementations are respectively
  `0x907f5c53c0e31db06af45bc58f076563469c525a` and
  `0x74f9e5ee4071b9b35d127000a20f8e964009cb57`; and
- every provider returns identical code for all four proxies/implementations
  and the two linked libraries at that block.

Every historical state query uses the EIP-1898 block-hash form with
`requireCanonical:true`. The raw requests and unmodified provider responses are
checked in under `rpc/raw/`; the offline test derives agreement from those
files rather than trusting the summary in `manifest.json`.

The archived Blockscout records contain deployed bytecode identical to the RPC
captures. Accounts and `AddressSortedLinkedList` are fully verified; Validators,
Registry, and Election are partially verified. Their load-bearing source files
are independently fetched from official Celo revisions and checked
byte-for-byte against the explorer records. In particular, the deployed
Accounts source is pinned at commit
`fad3410bdaf159749ace623887caaac7adf753ca`; its later current-tree copy differs
only in a Natspec typo correction.

The linked `AddressLinkedList` record has no explorer verification metadata, so
the bundle does not trust a guessed source. Official Celo commit
`a607b2f504e4aaf998ef1f88fcc893bfb7e7b007` plus its OpenZeppelin v2.5.0
submodule commit `58a3368215581509d05bd3ec4d53cd381c9bb40e` are archived as an exact standard
JSON compiler input. Solc `0.5.13`, optimizer disabled (runs 200), Istanbul, and
literal metadata produce the complete 4,491-byte deployed runtime—including
its BZZR1 metadata—byte-for-byte after the standard Solidity library
self-address substitution. The input, output, version, source files, runtime,
and raw explorer record are all independently receipted.

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

Those claims are tied to the fixed-block dependency chain above: the deployed
Accounts source/runtime proves signer-to-account resolution; the deployed
Election source/runtime and fully verified sorted-list library prove the
eligibility insertion; and the exact-compiled address-list library proves the
member append used by Validators.

The display can therefore identify the exact validator and both signed hints,
and can state the first-member/eligibility intent. It must not fabricate the
effective group address, live vote total, affiliation, locked-gold balances,
list position, or successful execution.

## Authority boundary

The deterministic ABI projection contains exactly `addFirstMember`. The
package supplies no authority for the descriptor's other Validators routes,
for the legacy Alfajores deployment, or for any other deployment.

This is historical fixed-block and source evidence. The Validators owner can
change its Registry pointer; the Registry owner can change the Accounts or
Election entries; and the Registry, Validators, Accounts, and Election proxies
can be upgraded after the captured block. A future implementation can also
link different library code. This package does not monitor or authorize any of
those changes.

It does not resolve the effective group, prove that the group remains empty,
prove validator affiliation or registration, validate the live ordering hints,
prove locked-gold sufficiency, or claim transaction success. The route is
nonpayable; a nonzero outer native value would revert and receives no success
claim. Nothing here enables fallback or blind signing, or authorizes hardware
or shipment.

Primary upstream records:

- https://docs.celo.org/tooling/contracts/core-contracts
- https://github.com/celo-org/celo-monorepo
- https://celo.blockscout.com/address/0xaEb865bCa93DdC8F47b8e29F40C5399cE34d0C58
- https://celo.blockscout.com/address/0x13B0B89F3242f815C1FC6C9CF56e1Ab5aEA4dC58
- https://celo.blockscout.com/address/0x7d21685C17607338b313a7174bAb6620baD0aaB7
- https://celo.blockscout.com/address/0x8D6677192144292870907E3Fa8A5527fE55A7ff6

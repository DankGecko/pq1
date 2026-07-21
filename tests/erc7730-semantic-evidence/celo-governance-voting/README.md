# Celo Governance voting-route evidence

This offline bundle supports a bounded PQ1 catalogue expansion at the
Registry-selected Celo mainnet Governance proxy: `upvote`, `revokeUpvote`,
`vote`, and `votePartially`. It supplies no authority for any other Governance
route or deployment.

## Fixed mainnet identity

At Celo mainnet block 72,649,728 (`0x4548c00`, hash
`0x810df7ac...985bf4a3c`), Celo Forno, dRPC, and Ankr independently agree that:

- Registry `0x000000000000000000000000000000000000ce10` resolves `Governance` to
  `0xD533Ca259b330c7A88f74E000a3FaEa2d63B7972`;
- that proxy's EIP-1967 implementation slot contains
  `0x40cac0be7e25b14e39f782d5b7e5c3076aa6c57a`; and
- each provider returns identical proxy runtime bytes and identical
  implementation runtime bytes at that block.

Every historical state query uses the EIP-1898 block-hash form with
`requireCanonical:true`. The raw requests and unmodified provider responses are
checked in under `rpc/raw/`; the offline test derives agreement from those
files rather than trusting the summary in `manifest.json`.

The Blockscout proxy record is fully verified and the implementation record is
partially verified. Both records contain deployed bytecode identical to the RPC
captures. The implementation record's primary `Governance.sol` source is
byte-identical to the official Celo monorepo file pinned at commit
`045aa0061b7d0e9655ff3673cbd25a1bf2b4b74a`.

## Source semantics

The pinned source establishes that:

- `proposalId` selects a queued proposal for `upvote`, and a dequeued proposal
  for referendum `vote` or `votePartially`;
- `lesser` and `greater` are proposal-ID position hints for the sorted queue,
  with zero denoting the appropriate tail/head boundary; they are not vote
  values or recipients;
- `index` is the proposal's position in the live `dequeued` array and must
  identify the same signed `proposalId`;
- the canonical vote enum is `0=None`, `1=Abstain`, `2=No`, `3=Yes`, and `None`
  is rejected by the whole-weight `vote` route;
- whole `vote` weight is the effective account's live total governance voting
  power; `upvote` weight is its live total locked CELO; neither weight is in
  those calls' signed calldata;
- `votePartially` signs the exact yes/no/abstain weights, whose sum may not
  exceed the effective account's live total governance voting power; and
- `msg.sender` is resolved through `Accounts.voteSignerToAccount`, so the
  effective account may differ from the immediate caller and remains live
  state.

`revokeUpvote` signs only `lesser` and `greater`. The revoked proposal ID and
weight come from the effective account's live `UpvoteRecord`; trusted display
must not fabricate either value from this evidence.

## Authority boundary

The deterministic ABI projection contains exactly the four routes above.
`execute`, `propose`, and `executeHotfix` can transfer value or execute arbitrary
proposal transactions and are deliberately outside this evidence authority.
The package also supplies no authority for Alfajores or any other Governance
deployment.

This is historical fixed-block and source evidence. It does not monitor future
proxy upgrades, resolve the effective account, proposal stage, queue/dequeued
position, live voting power, hint validity, sufficient voting power, or
transaction success. The four routes are nonpayable; a nonzero outer native
value would revert and receives no success claim. Nothing here enables fallback
or blind signing, or authorizes hardware or shipment.

Primary upstream records:

- https://docs.celo.org/tooling/contracts/core-contracts
- https://github.com/celo-org/celo-monorepo
- https://celo.blockscout.com/address/0xD533Ca259b330c7A88f74E000a3FaEa2d63B7972
- https://celo.blockscout.com/address/0x40cac0be7e25b14e39f782d5b7e5c3076aa6c57a

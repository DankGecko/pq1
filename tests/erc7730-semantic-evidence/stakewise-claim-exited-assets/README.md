# StakeWise claimExitedAssets semantic evidence

This directory is the offline, fixed-block evidence input for the three
ERC-7730 deployments admitted by issue #408 and audited under issue #378.

It pins:

- the common 130-byte ERC-1967 proxy runtime and each proxy implementation slot;
- the mainnet and Hoodi EthVault implementation runtimes;
- two independent RPC observations per chain at named blocks and state roots;
- the exact route ABI returned for the verified mainnet implementation;
- the three relevant StakeWise source files at the v4.0.1 release commit
  `c511cd912cb881f60cf2a32d6c5d5f533e5d04b5`; and
- every byte range in which the mainnet and Hoodi implementations may differ.

The offline dbgen integration test checks the artifacts, ties the deployment set
back to the curated descriptors, verifies the ABI selector, checks the
`msg.sender` request/recipient semantics, and proves that the two implementation
runtimes are byte-identical after only the declared chain/address immutable
ranges are normalized.

Source and provenance:

- StakeWise source: https://github.com/stakewise/v3-core/tree/c511cd912cb881f60cf2a32d6c5d5f533e5d04b5
- Verified mainnet implementation: https://eth.blockscout.com/address/0x927a83c679a5e1a6435d6bfaef7f20d4db23e2cc
- Mainnet evidence block: https://eth.blockscout.com/block/25566776
- Hoodi evidence block: https://eth-hoodi.blockscout.com/block/3245600

This receipt is historical. The vaults are upgradeable, so a later implementation
slot is outside this evidence and must not inherit its conclusion. No network
access is used by the test.

# StakeWise EthVault route semantic evidence

This directory is the offline, fixed-block evidence input for the three
ERC-7730 deployments admitted by issue #408 and audited under issue #378.

It pins:

- the common 130-byte ERC-1967 proxy runtime and each proxy implementation slot;
- the mainnet and Hoodi EthVault implementation runtimes;
- two independent RPC observations per chain at named blocks and state roots;
- exact verified-mainnet ABI subsets for `claimExitedAssets`,
  `deposit(address,address)` (`0xf9609f08`), and
  `enterExitQueue(uint256,address)` (`0x8ceab9aa`);
- the eight relevant StakeWise source files at the v4.0.1 release commit
  `c511cd912cb881f60cf2a32d6c5d5f533e5d04b5`; and
- every byte range in which the mainnet and Hoodi implementations may differ.

The offline dbgen integration test checks the artifacts, ties the deployment set
back to the curated descriptors, verifies each ABI selector, checks the signed
caller/receiver/value/share semantics, and proves that the two implementation
runtimes are byte-identical after only the declared chain/address immutable
ranges are normalized.

For `deposit`, successful execution deposits the exact signed transaction value
and mints a live-rate number of internal vault shares, rounded up with
`Math.Rounding.Ceil`, to the signed receiver. The signed referrer is event
metadata. Harvest status, vault capacity, and the minted share output remain
live-state residuals.

For `enterExitQueue`, successful execution deducts the exact signed share count
from the caller. A collateralized vault records a receiver-keyed exit request
using the current timestamp and computed position ticket, without transferring
ETH immediately. An uncollateralized vault burns the shares immediately and
transfers their live-rate ETH value to the signed receiver. The branch, ticket,
timestamp, exchange rate, ETH output, queue timing, and caller osToken-LTV check
remain live-state residuals.

These shares are entries in `VaultState._balances`, exposed through `getShares`
and conversion functions. `EthVault` does not expose them as an ERC-20 share
token, so the vault proxy address cannot supply a trusted ERC-20 ticker or
decimal scale. The trusted display must preserve the exact signed share word.

Source and provenance:

- StakeWise source: https://github.com/stakewise/v3-core/tree/c511cd912cb881f60cf2a32d6c5d5f533e5d04b5
- Verified mainnet implementation: https://eth.blockscout.com/address/0x927a83c679a5e1a6435d6bfaef7f20d4db23e2cc
- Mainnet evidence block: https://eth.blockscout.com/block/25566776
- Hoodi evidence block: https://eth-hoodi.blockscout.com/block/3245600

This receipt is historical. The vaults are upgradeable, so a later implementation
slot is outside this evidence and must not inherit its conclusion. The mainnet
explorer reports the source as verified but not fully verified; Hoodi provenance
comes from the normalized runtime equality recorded in the manifest. No network
access is used by the test.

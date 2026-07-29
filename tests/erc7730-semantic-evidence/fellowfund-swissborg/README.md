# FellowFund and SwissBorg migrator evidence

This package resolves two residual ERC-7730 calldata families against Ethereum
block `25,630,720` (`0x1871800`). dRPC and MEV Blocker independently reproduce
the fixed block and every on-chain observation.

## FellowFund

The upstream descriptor declares only
`0x25d598cbb74fa73290e74697616de2740d280745`. Both providers return `0x` for
its bytecode at the fixed block, and Blockscout has no verified-contract record
for the address. The descriptor's owner label and historical website cannot
establish a live target, ABI, or signed effect. All three declared selectors
therefore remain exact-known refusals and no clear-signing leaf is emitted.

## SwissBorg CHSB-to-BORG migrator

The registry destination
`0xaa854688caab725fe17b7d21b46fda5af365985a` is an EIP-1967 proxy. At the
fixed block, both providers bind its implementation slot to
`0xfb976ea3ae9bfe4bc36fb7078e0b32e579463e96`, CHSB to
`0xba9d4199fab4f26efe3551d490e3821486f135ba`, BORG to
`0x64d0f55cd8c7133a9d7102b13987235f486f2224`, and `paused()` to true.

Blockscout fully verifies that implementation as `ChsbToBorgMigratorV2`. Its
source explicitly describes V2 as closing the migrator, and
`migrate(uint256)` unconditionally reverts with `MIGRATION_CLOSED`. The
upstream display would therefore promise an executable migration that the
bound implementation cannot perform. The selector stays exact-known and
forced-eligible, but no clear-signing leaf is emitted.

`collect.sh` re-captures the bounded RPC and Blockscout records and regenerates
the artifact receipt manifest. The evidence is historical: it does not monitor
future upgrades or grant fallback, blind-signing, production, hardware,
release, or shipment authority.

# Corestake, Sei, and Avvatar calldata evidence

This package pins the eight residual calldata descriptor families in this
bounded PQ1 slice to three historical EVM blocks:

- Core mainnet block `37,311,927` (`0x23955b7`);
- Sei EVM mainnet block `222,736,384` (`0xd46b000`); and
- Base mainnet block `49,227,776` (`0x2ef2800`).

## Corestake

Two independent Core RPCs agree on the fixed header and state. The CoreAgent
and StakeHub runtimes are byte-identical to the Hermes mainnet images embedded
at official `core-chain` commit
`3dd2b07da5effef7af3c8486df66a873ff2b865c`; that client's upgrade table binds
both images to `core-genesis-contract` commit
`7f973185d67cea94518ff6a176d9ffa8e6eaad80`.

The Earn destination is a UUPS proxy whose fixed EIP-1967 implementation is
`0x62c5e03a5bfa0d6af08b81165a9eb87d1c8b8a0b`. Official Earn source at commit
`4d237f6a366df6a6953cb0abfea4e68cafa9e7d9`, compiled with Solidity `0.8.4`,
optimizer runs `200`, and OpenZeppelin `4.9.3`, reproduces the implementation
runtime exactly after linking the five compiler-reported UUPS self-immutable
locations.

The seven admitted routes show every signed operand. State-derived results are
stated explicitly: mint has no signed minimum stCORE output; redeem queues a
live-rate CORE amount minus a live protocol fee; withdraw pays all matured
caller records; and StakeHub reward amount comes from caller staking state.

## Sei native precompiles

The two Sei destinations have empty EVM runtime and zero EIP-1967 slots, as
expected for native precompiles. Independent RPCs agree on the fixed header.
Independent live nodes identify official builds `v6.5.0` at commit
`fbc0d9342ca28887958013170e4020d93cacdbfa` and `v6.5.2` at commit
`ab134842ce1bd97af73021bcff5850ad6c29e534`; their target staking and
distribution source and ABI files are byte-identical. The chain reports that
upgrade `v6.5` was applied at height `208,377,745`, before the fixed block.

Seven routes are admitted and show every validator, amount, rate, and
destination operand. Calldata stake amounts are usei with six decimals.
Payable stake is exact 18-decimal EVM value and source requires a whole usei.
Reward-producing routes state that live rewards go to the configured Sei
withdrawal address. `withdrawMultipleDelegationRewards(string[])` remains an
exact-known refusal because a dynamic array of dynamic strings is outside the
authenticated static-primitive array topology. `createValidator(...)` remains
an exact-known refusal because its five dynamic top-level arguments exceed the
authenticated topology cap of four.

## Avvatar / ALIA on Base

Two independent Base RPCs agree on all three direct-deployment runtimes and
their zero EIP-1967 slots. Each runtime is byte-identical to the corresponding
Base Blockscout-verified Solidity `0.8.33` deployment.

All eleven routes show every signed operand. Source-defined agent, status,
asset-class, and backing enums are rendered by name. The other-chain token is
kept raw to prevent Base token-name resolution from misidentifying it.
Reputation and live-oracle cache effects are stated explicitly.

`collect.sh` re-captures the fixed RPC, REST, explorer, source, and compiler
records. `manifest.json` receipts every offline artifact by byte count and
SHA-256.

This is historical source/runtime and signed-input-meaning evidence. It is not
live monitoring and grants no authority for future native or proxy upgrades,
mutable state, execution success, fallback, blind signing, production,
shipment, or irreversible action.

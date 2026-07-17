# FV pilot — CREATE2 address chain-independence, TCB decomposition (I-7) — 2026-07-17

> **Scope, first (F9).** A Lean refinement that SHRINKS the cited-TCB surface of
> invariant #6 (same 24 words → same address on every chain). It does not — and
> cannot — turn cross-chain deployment identity into a pure-Lean theorem (that is
> an on-chain observation); it proves the part that *is* structural and reduces
> the rest to one homogeneous deployment receipt.

## The question (I-7)

`Wallet/Invariants.lean::create2Address_chain_independent` proves the CREATE2
address `keccak256(0xff ‖ deployer ‖ salt ‖ keccak256(initCode))` is chain-free
CONDITIONAL on two opaque EVM-TCB hypotheses: `deployer1 = deployer2` and
`initCodeHash1 = initCodeHash2`. Only the SALT was proven chain-free in Lean; the
`initCodeHash` premise was an opaque black box. The review asked: model the
singleton-factory + frozen-initCode facts to discharge the premises (or bind them
to a deployment receipt).

## Correctness check first (the load-bearing question)

If `initCode` contained a chainId or a chain-bound key, invariant #6 would be
**violated** — so this is a real correctness question, not just a proof. Checked
`PQSmartWalletFactory.sol`: the proxy is created by
`LibClone.createDeterministicERC1967(msg.value, implementation, salt)` (line 93),
so `initCode = ERC-1967 proxyCode ‖ implementation` — **no chainId, no chain-bound
slot key**. Slot 0 is seeded by a SEPARATE post-deploy state write authorized by
`addSlot0Digest(chainId, …)`, which is NOT part of the CREATE2 address preimage.
Invariant #6 holds structurally. ✓

## The refinement

`create2Address_chain_independent_via_impl` (+ `initCodeHash`,
`initCodeHash_eq_of_impl_eq`) replaces the opaque `ich1 = ich2` premise with:

1. a **structural model** `initCodeHash proxyCode impl = keccak256(proxyCode ‖ impl)`
   — a function of `(proxyCode, implementation)` alone, no chainId (`proxyCode` is
   a shared chain-free constant binder, the same technique `Factory.salt` uses);
2. the **homogeneous** `impl1 = impl2` premise.

`initCodeHash_eq_of_impl_eq` (kernel-only `[propext, Quot.sound]`) proves the
initCode-preimage chain-freeness in Lean. What remains cited-TCB is now exactly
TWO homogeneous facts — `factory1 = factory2` and `impl1 = impl2` — each an
instance of the *single* receipt: "a deterministically-deployed contract (Arachnid
`0x4e59…` singleton CREATE2 deployer, salt 0, frozen bytecode) has one address on
every chain, since the CREATE2 opcode preimage `0xff ‖ deployer ‖ salt ‖
keccak256(initcode)` carries no chainId." That receipt is discharged for the live
Base deployment by `contracts/smart-wallet/test/DeployedBytecodeReproCheck.t.sol`
(CREATE2 replay reproduces factory `0xe8CE78CD…` and impl `0x31e49D24…` exactly).

## What this establishes

- **The initCode preimage is now Lean-proven chain-free** (modulo the impl
  address), not an opaque premise. Nothing chain-dependent remains inside the
  address preimage: salt (chain-free, proven) + initCode (chain-free modulo impl,
  proven).
- **The cited-TCB shrinks to one fact applied twice.** Before: `{deployer chain-free,
  keccak256(initCode) chain-free}` — two heterogeneous opaque premises. After:
  `{factory addr, impl addr}` cross-chain identity — the SAME CREATE2-determinism
  receipt, already discharged on Base. This is the maximal Lean shrink of I-7:
  cross-chain deployment identity is genuinely not a pure-Lean fact.

## Closure hygiene

The existing `create2Address_chain_independent` is untouched (closure
`[propext, Quot.sound]` unchanged). The new theorems are kernel-only (no named
axioms: `create2Address_chain_independent_via_impl` `[propext, Quot.sound]`,
`initCodeHash_eq_of_impl_eq` `[propext]`). `lake build SphincsCVerify` clean;
`make -C contracts/verification verify-ledger-consistency` passes (18 closures /
17 axioms unchanged). `OPEN_PROOF_OBLIGATIONS.md` I-7 updated with the closure
note.

## Files

- `contracts/verification/lean/SphincsCVerify/Wallet/Invariants.lean` —
  `initCodeHash`, `initCodeHash_eq_of_impl_eq`,
  `create2Address_chain_independent_via_impl`.
- `contracts/verification/docs/OPEN_PROOF_OBLIGATIONS.md` — I-7 UPDATE note.

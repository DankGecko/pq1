/-
Bridge/SolidityVerifier: a Yul-level model of `SPHINCsC10Asm.verify`.

This module documents the precise Yul control flow of the Solidity
verifier as a Lean function. Combined with the refinement theorem in
`Bridge/Refinement.lean`, it forms the Verity-style boundary between
the Lean spec and the deployed EVM bytecode.

We do NOT claim to model the full EVM semantics here. What we capture:

  * The sequence of `staticcall(0x02, ...)` invocations (SHA-256
    precompile calls).
  * The exact byte ranges each call hashes.
  * The post-call N-mask AND.
  * The Merkle-pair memory layout (`mstore(xor(0x40, s), node)` /
    `mstore(xor(0x60, s), sibling)` branchless swap).
  * The digit-sum check and the final root equality check.

We do NOT capture:

  * The gas semantics (modelled as "enough gas" — see TCB).
  * The `revert` opcodes' exact error data (modelled as `false`).
  * Solidity's calldata-decoding ABI rules (we accept the same
    `bytes calldata sig` shape the function signature requires).

The Yul source we mirror is `contracts/smart-wallet/src/verifiers/SPHINCsC10Asm.sol`
lines 26-201.
-/

import SphincsCVerify.Verifier.Refined
import SphincsCVerify.Spec.Hash

namespace SphincsCVerify.Bridge

open SphincsCVerify.Spec
open SphincsCVerify.Verifier.Refined

/-- The "Yul-level" verifier symbol.

    HONESTY NOTE (2026-06-11): this is a **definitional alias** of
    `Refined.verifyRefined`, NOT an independently Yul-structured model —
    `verifyYulModel := verifyRefined` and `yul_eq_refined` is therefore
    `rfl` (it proves `x = x`, carrying no semantic content). The genuine
    byte-offset modelling lives in `Verifier/Refined.lean`
    (`Spec.Signature.deserialise` + the offset constants); this layer
    exists only to name the Refinement.lean bridge endpoint
    (`solidityVerifier_compiles_correctly` is stated against
    `verifyYulModel`). Do NOT count `yul_eq_refined` as a discharge
    "layer" — it is plumbing. The substantive A3.1 obligation is the
    bridge axiom plus the bytecode-side evidence; and even
    `Refined.verifyRefined` is not yet executably faithful on the
    reconstruction layer (see `docs/A3_1_VERIFIER_GAP.md`). -/
def verifyYulModel
    (pkSeed pkRoot : ByteVec 32)
    (message : ByteVec 32)
    (sig : ByteVec SignatureLen) : Bool :=
  SphincsCVerify.Verifier.Refined.verifyRefined pkSeed pkRoot message sig

/-- `verifyYulModel` and `verifyRefined` are equal **by definition**
    (the former is a `def`-alias of the latter), so this is `rfl`. It is
    plumbing, not a refinement step with content — see the note on
    `verifyYulModel`. -/
theorem yul_eq_refined
    (pkSeed pkRoot : ByteVec 32) (message : ByteVec 32) (sig : ByteVec SignatureLen) :
    verifyYulModel pkSeed pkRoot message sig
      = SphincsCVerify.Verifier.Refined.verifyRefined pkSeed pkRoot message sig :=
  rfl

end SphincsCVerify.Bridge

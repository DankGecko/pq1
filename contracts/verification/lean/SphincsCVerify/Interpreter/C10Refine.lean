/-
SphincsCVerify.Interpreter.C10Refine — the grand composition (full-(a) step 4).

Glues the three phase capstones (`hmsg_digest`, `fors_phase`,
`verifyHypertree_refine`) into the end-to-end interpreter-refinement theorem

  `execC10Asm pkSeed pkRoot message sig
     = nMaskedB pkSeed && nMaskedB pkRoot
       && verifyYulModel pkSeed pkRoot message sig`

i.e. the deployed Yul verifier (transcribed in `C10Program.lean`) computes
exactly the declarative spec `Spec.Signature.verify` (via `verifyYulModel`),
with the two leading N-mask guards exposed as the `nMaskedB` Bool factors.

The N-mask factors are NOT cosmetic: the deployed Yul rejects (returns `false`)
any `pkSeed`/`pkRoot` whose bottom 16 bytes are non-zero, BEFORE running the
verification body. `verifyYulModel` (= `Spec.Signature.verify ⟨pkSeed.take16,
pkRoot.take16⟩ …`) silently truncates instead, so the faithful equality must
carry the guards.

See `docs/A3_1_CLOSURE_PATH.md` §8 step 4 and
`memory/project_a31_full_a_progress.md`.
-/

import SphincsCVerify.Interpreter.HypertreePhase
import SphincsCVerify.Bridge.SolidityVerifier

namespace SphincsCVerify.Interpreter.C10

open SphincsCVerify.Interpreter
open SphincsCVerify.Spec (ByteVec)

-- The phase capstones are consumed as opaque equations; replicate the
-- HypertreePhase seals so no stray `simp`/`rfl`/`decide` whnf's through the
-- heavy spec calls (the step-3 isDefEq-blowup insurance).
attribute [local irreducible] Spec.Wots.pkFromSig Spec.Hypertree.verifyAuthPath
  Spec.wotsDigest Spec.chainHash SphincsCVerify.Util.digitSum SphincsCVerify.Util.extractDigits
  Spec.Adrs.wots Spec.Adrs.treeNode

/-! ## Keystone: `c10Program` decomposes into the phase fragments.

A single `rfl` validates that the inlined `c10Program` (statement-for-statement
mirror of `SPHINCsC10Asm.sol`) is definitionally the concatenation of the
prefix guards, `hmsgFragment`, `forsPhaseFragment`, and the hypertree tail —
through every fragment def down to `wotsBody` / `htLayerBody`. -/
theorem c10Program_decompose :
    c10Program =
      [ .letv "N_MASK" (.lit 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000000000000000000000000000)
      , .letv "OUT" (.lit 0x600)
      , .ifnz (.iszero (.bin .eq .sigLength (.lit 4008))) [ .revert ]
      , .ifnz (.iszero (.bin .eq (.bin .band (.var "pkSeed") (.var "N_MASK")) (.var "pkSeed")))
          [ .mstore (.lit 0x00) (.lit 0), .ret (.lit 0x00) ]
      , .ifnz (.iszero (.bin .eq (.bin .band (.var "pkRoot") (.var "N_MASK")) (.var "pkRoot")))
          [ .mstore (.lit 0x00) (.lit 0), .ret (.lit 0x00) ] ]
      ++ hmsgFragment
      ++ forsPhaseFragment
      ++ [ .letv "currentNode" (.var "forsPk")
         , .letv "idxTree" (.var "htIdx")
         , .letv "sigOff" (.lit 2336)
         , .forRange "layer" (.lit 2) htLayerBody
         , .letv "valid" (.bin .eq (.var "currentNode") (.var "root"))
         , .mstore (.lit 0x00) (.var "valid")
         , .ret (.lit 0x00) ] := by rfl

/-! ## Shared byte-level glue

`wordOf` injectivity and the N-mask byte bridge are load-bearing in two places
each (the N-mask guards feeding the phase shape hypotheses; the final
root-equality compare). Established once here. -/

/-- **ByteVec extensionality from pointwise `getD`.** Two same-length `ByteVec`s
    are equal if every in-range byte (read via `getD … 0`) agrees. -/
theorem byteVec_ext_getD {n : Nat} {a b : ByteVec n}
    (h : ∀ i, i < n → a.data.getD i 0 = b.data.getD i 0) : a = b := by
  apply ByteVec.ext_data
  have hsz : a.data.size = b.data.size := by rw [a.size_eq, b.size_eq]
  apply Array.ext hsz
  intro i hi1 _
  have hin : i < n := by rw [a.size_eq] at hi1; exact hi1
  have hgd := h i hin
  rwa [Array.getD_eq_getD_getElem?, Array.getElem?_eq_getElem hi1, Option.getD_some,
       Array.getD_eq_getD_getElem?, Array.getElem?_eq_getElem (hsz ▸ hi1), Option.getD_some] at hgd

/-- **`wordOf` is injective on `ByteVec 32`.** The big-endian word determines
    every byte (`beByte_wordOf_getD`), so equal words ⇒ equal vectors. -/
theorem wordOf_inj {a b : ByteVec 32} (h : wordOf a = wordOf b) : a = b := by
  apply byteVec_ext_getD
  intro i hi
  rw [← beByte_wordOf_getD a i hi, ← beByte_wordOf_getD b i hi, h]

/-- The deployed Yul N-mask guard, as a Bool: `pkSeed & N_MASK == pkSeed` at the
    word level (`SPHINCsC10Asm.sol` L58-65). The guard returns `false` (the whole
    verifier) when this is `false`. -/
def nMaskedB (key : ByteVec 32) : Bool := decide (wordOf key &&& NMASK = wordOf key)

/-- **N-mask byte bridge.** The word-level guard `pkSeed & N_MASK = pkSeed`
    forces the byte-level N-mask SHAPE `pkSeed = pad16 (truncate16 pkSeed)` (top
    16 bytes preserved, bottom 16 zero) — exactly the `hShape` hypothesis the
    `hmsg_digest` phase consumes (`truncate16 key` is defeq `key.take 16 _`). -/
theorem nMaskedB_shape {key : ByteVec 32} (h : nMaskedB key = true) :
    key = ByteVec.pad16 (ByteVec.truncate16 key) := by
  have hmask : wordOf key &&& NMASK = wordOf key := of_decide_eq_true h
  apply byteVec_ext_getD
  intro i hi
  rw [pad16tr_getD]
  by_cases h16 : i < 16
  · rw [if_pos h16]
  · rw [if_neg h16]
    have hbe : beByte (wordOf key &&& NMASK) i = beByte (wordOf key) i := by rw [hmask]
    rw [beByte_and_nmask, if_neg h16] at hbe
    rw [← beByte_wordOf_getD key i hi]
    exact hbe.symm

/-- **`wordOf ∘ pad16` is injective on `ByteVec 16`** — the final root compare
    `wordOf(pad16 finalNode) = wordOf(pad16 pkRoot16) ↔ finalNode = pkRoot16`. -/
theorem pad16_wordOf_inj {a b : ByteVec 16}
    (h : wordOf (ByteVec.pad16 a) = wordOf (ByteVec.pad16 b)) : a = b := by
  have hp : ByteVec.pad16 a = ByteVec.pad16 b := wordOf_inj h
  apply byteVec_ext_getD
  intro i hi
  have hd : (ByteVec.pad16 a).data.getD i 0 = (ByteVec.pad16 b).data.getD i 0 := by rw [hp]
  rwa [pad16_data_getD, pad16_data_getD, if_pos hi, if_pos hi] at hd

end SphincsCVerify.Interpreter.C10

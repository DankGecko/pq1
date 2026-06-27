/- Group-V round-trip — WOTS+ chain round-trip (verify_signs sub-lemma 2/4).

   `Wots.pkFromSig` recovers each WOTS+ public-key element by chaining the
   signature digit `sigᵢ` the remaining `W-1-dᵢ` steps from chain-position `dᵢ`.
   When `sigᵢ` is the honest signature `chainHash secret 0 dᵢ` (the secret chained
   `dᵢ` steps), the recovered value is `chainHash secret 0 (W-1)` — the public-key
   element. This rests on the chain-composition lemma
   `chainHash (chainHash v s n₁) (s+n₁) n₂ = chainHash v s (n₁+n₂)`, proven from
   the `chainHash_eq_fwd` forward fold via `chainHash_succ`. -/
import SphincsCVerify.Interpreter.Phases

namespace SphincsCVerify.Interpreter.C10

open SphincsCVerify SphincsCVerify.Spec

/-- One more chain step: `chainHash` of `n+1` steps applies `th` at position
    `s+n` on top of `chainHash` of `n` steps. (Forward-fold last-element peel.) -/
theorem chainHash_succ (seed : ByteVec 32) (a : Spec.Adrs) (v : ByteVec 16) (s n : Nat) :
    Spec.chainHash seed a v s (n + 1)
      = Spec.th seed (Spec.Adrs.setChainPos a (UInt32.ofNat (s + n)))
          (ByteVec.pad16 (Spec.chainHash seed a v s n)) := by
  rw [chainHash_eq_fwd, chainHash_eq_fwd, List.range'_1_concat, List.foldl_append, Nat.zero_add]
  rfl

/-- **WOTS+ chain composition.** Chaining `n₁` steps from `s` then `n₂` steps
    from `s+n₁` equals chaining `n₁+n₂` steps from `s`. -/
theorem chainHash_compose (seed : ByteVec 32) (a : Spec.Adrs) (v : ByteVec 16) (s n₁ n₂ : Nat) :
    Spec.chainHash seed a (Spec.chainHash seed a v s n₁) (s + n₁) n₂
      = Spec.chainHash seed a v s (n₁ + n₂) := by
  induction n₂ with
  | zero => rfl
  | succ n₂ ih =>
      rw [chainHash_succ, ih, Nat.add_succ, chainHash_succ, Nat.add_assoc]

/-- **`wots_chain_roundtrip`.** Chaining the honest WOTS+ signature digit
    `chainHash secret 0 d` the remaining `W-1-d` steps recovers the public-key
    element `chainHash secret 0 (W-1)`. -/
theorem wots_chain_roundtrip (seed : ByteVec 32) (a : Spec.Adrs) (secret : ByteVec 16)
    (d : Nat) (hd : d ≤ Spec.W - 1) :
    Spec.chainHash seed a (Spec.chainHash seed a secret 0 d) d (Spec.W - 1 - d)
      = Spec.chainHash seed a secret 0 (Spec.W - 1) := by
  have h := chainHash_compose seed a secret 0 d (Spec.W - 1 - d)
  rw [Nat.zero_add] at h
  rw [h, Nat.add_sub_cancel' hd]

end SphincsCVerify.Interpreter.C10

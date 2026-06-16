/-
SphincsCVerify.Interpreter.ClimbLoop — the loop-induction transfer-PoC.

This is the crux of the A3.1 deductive-closure technique made concrete on C10's
byte-addressed-SHA-256 interpreter. The C10 verifier climbs data-dependent paths
(WOTS chains whose length depends on a hash digit, FORS/hypertree Merkle walks):
a *symbolic-execution* engine forks on every digit → ~8ⁿ paths → intractable
(this is exactly why Halmos/KEVM cannot close A3.1). A *proof assistant* instead
does **induction on the path length** — two cases, with the hash kept an **opaque
function** threaded through, never unfolded — so the explosion never happens.

`climbMem_eq_specClimb` demonstrates precisely this on the real byte-memory model:
the memory-realized climb (each step lays the pair into scratch, runs the `0x02`
precompile, reads the new node back) equals the pure spec fold, for an
arbitrary-length path. It is the C10 analogue of the upstream verity
`foldLoop_invariant_cond`, and it closes the "does the deductive technique
transfer to C10/SHA-256?" question with a kernel-checked yes.

Mathlib-free, hash `H` abstract → no axioms. The concrete `H = sha256-of-the-pair`
+ the spec-equivalence wire in at the `Sha256Bridge` (next step); the *structure*
proved here is hash-agnostic and ports unchanged.
-/

import SphincsCVerify.Interpreter.Climb

namespace SphincsCVerify.Interpreter

/-- Spec-side climb: fold an abstract pair-hash `H` up an authentication path. -/
def specClimb (H : Nat → Nat → Nat) (node : Nat) : List Nat → Nat
  | [] => node
  | sib :: rest => specClimb H (H node sib) rest

/-- Memory-realized climb: each step lays `node ‖ sibling` into the scratch window
    `[base, base+64)`, runs the precompile (digest `= beByte (H node sib)`), reads
    the new node back from `outOff`, and recurses — threading both the byte memory
    and the current node, exactly as the deployed Yul does. -/
def climbMem (H : Nat → Nat → Nat) (base outOff : Nat) :
    ByteMemory → Nat → List Nat → Nat
  | _, node, [] => node
  | mem, node, sib :: rest =>
      climbMem H base outOff
        (hashPairStep mem base outOff node sib (beByte (H node sib)))
        (mload32 (hashPairStep mem base outOff node sib (beByte (H node sib))) outOff)
        rest

/-- **Loop-induction — the transfer-PoC.** The memory-realized climb over an
    arbitrary-length auth path equals the pure spec fold, proved by induction on
    the path length: **two cases**, the hash `H` opaque, no symbolic digit-branch
    explosion. Each step's realized node is recovered by `mload32_hashPairStep`
    (`= H node sib % 2^256`). The C10 analogue of verity's `foldLoop_invariant_cond`
    — a data-dependent climb refined deductively where symbolic execution forks
    8ⁿ times. -/
theorem climbMem_eq_specClimb (H : Nat → Nat → Nat) (base outOff : Nat) :
    ∀ (sibs : List Nat) (mem : ByteMemory) (node : Nat),
      climbMem H base outOff mem node sibs
        = specClimb (fun n s => H n s % 2 ^ 256) node sibs := by
  intro sibs
  induction sibs with
  | nil => intro mem node; rfl
  | cons sib rest ih =>
      intro mem node
      simp only [climbMem, specClimb]
      rw [mload32_hashPairStep]
      exact ih _ _

end SphincsCVerify.Interpreter

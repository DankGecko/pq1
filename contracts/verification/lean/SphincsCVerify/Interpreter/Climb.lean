/-
SphincsCVerify.Interpreter.Climb — one hash-pair climb step on byte memory.

Second increment of the A3.1 deductive-closure track (after `Interpreter.Memory`).
The C10 verifier's WOTS chains, FORS trees, and hypertree Merkle walks are all
built from the same primitive step: lay two 16/32-byte values into adjacent
scratch windows, hash the pair via the `0x02` precompile, read the digest back.
This module models that step (`hashPairStep`) and **fully characterizes its
memory behaviour** — exactly the input bytes it assembles for the hash, and the
frame (everything it leaves untouched). These are the per-step facts a
loop-induction (the verity `foldLoop_invariant_cond` pattern) consumes to climb
N steps without the symbolic-execution digit-branch explosion.

Mathlib-free, hash kept abstract (`dig` parameter) → **no axioms**. The byte
assembly + frame are proved purely from the `Interpreter.Memory` frame lemmas.
-/

import SphincsCVerify.Interpreter.Memory

namespace SphincsCVerify.Interpreter

/-! ## Precompile-input framing -/

/-- A 32-byte write to a window disjoint from `[base, base+n)` does not change the
    `n`-byte slice the precompile reads at `base` (its input is stable under
    writes elsewhere — e.g. the digest write does not clobber the hash input). -/
theorem slice_writeRegion_frame (mem : ByteMemory) (off base n : Nat) (f : Nat → UInt8)
    (hdisj : base + n ≤ off ∨ off + 32 ≤ base) :
    slice (writeRegion mem off f) base n = slice mem base n := by
  unfold slice
  apply List.map_congr_left
  intro i hi
  rw [List.mem_range] at hi
  exact writeRegion_frame mem off f (base + i) (by omega)

/-! ## One hash-pair climb step -/

/-- One hash-pair climb step (the shared shape of every C10 climb): write `node`
    at byte offset `base`, `sibling` at the adjacent window `base+32`, then the
    `0x02` precompile hashes the 64-byte pair `[base, base+64)` and writes the
    32-byte digest `dig` at `outOff`. (`dig` abstracts the hash → axiom-free; the
    concrete `dig = beByte (sha256 …)` wires in at the `Sha256Bridge`.) -/
def hashPairStep (mem : ByteMemory) (base outOff : Nat) (node sibling : Nat)
    (dig : Nat → UInt8) : ByteMemory :=
  staticcallSha256 (mstore32 (mstore32 mem base node) (base + 32) sibling) outOff dig

/-- **Input assembly.** The two writes lay the pair down so the precompile's
    64-byte input is exactly `node ‖ sibling` in big-endian, byte for byte. This
    is the heart of a climb step: the hash sees precisely the intended pair. -/
theorem hashPair_assembled (mem : ByteMemory) (base node sibling i : Nat) (hi : i < 64) :
    (mstore32 (mstore32 mem base node) (base + 32) sibling) (base + i)
      = if i < 32 then beByte node i else beByte sibling (i - 32) := by
  by_cases h : i < 32
  · -- base+i is in the node window [base, base+32), not the sibling window.
    rw [mstore32_frame _ (base + 32) sibling (base + i) (by omega),
        mstore32_get mem base node i h]
    simp [h]
  · -- 32 ≤ i < 64: base+i is in the sibling window [base+32, base+64).
    have he : base + i = (base + 32) + (i - 32) := by omega
    rw [he, mstore32_get _ (base + 32) sibling (i - 32) (by omega)]
    simp [h]

/-- **Frame.** A hash-pair step touches only the pair window `[base, base+64)` and
    the digest window `[outOff, outOff+32)`; every other byte is preserved. The
    locality fact that lets independent climb steps compose. -/
theorem hashPairStep_frame (mem : ByteMemory) (base outOff node sibling : Nat)
    (dig : Nat → UInt8) (a : Nat)
    (hpair : a < base ∨ base + 64 ≤ a) (hout : a < outOff ∨ outOff + 32 ≤ a) :
    hashPairStep mem base outOff node sibling dig a = mem a := by
  unfold hashPairStep
  rw [staticcallSha256_frame _ outOff dig a hout,
      mstore32_frame _ (base + 32) sibling a (by omega),
      mstore32_frame _ base node a (by omega)]

/-- The step writes the digest verbatim into its output window. -/
theorem hashPairStep_out (mem : ByteMemory) (base outOff node sibling : Nat)
    (dig : Nat → UInt8) (i : Nat) (hi : i < 32) :
    hashPairStep mem base outOff node sibling dig (outOff + i) = dig i := by
  unfold hashPairStep
  exact staticcallSha256_get _ outOff dig i hi

/-- **Digest read-back, word level.** When the precompile's digest is the
    big-endian encoding of a word `dw` (`dig = beByte dw`, the climb case —
    the next step's input node is the previous step's hashed word), reading the
    output window back with `mload32` recovers `dw` (low 256 bits). Combined with
    `hashPair_assembled` (input = `node‖sibling`) this fully characterizes a climb
    step at the WORD level: `mload32 (step …) outOff = (hash of node‖sibling) % 2^256`
    — exactly the per-step fact a word-threaded loop-induction consumes. -/
theorem mload32_hashPairStep (mem : ByteMemory) (base outOff node sibling dw : Nat) :
    mload32 (hashPairStep mem base outOff node sibling (beByte dw)) outOff = dw % 2 ^ 256 := by
  unfold hashPairStep staticcallSha256
  -- `writeRegion … outOff (beByte dw)` is definitionally `mstore32 … outOff dw`.
  exact mload32_mstore32_self _ outOff dw

end SphincsCVerify.Interpreter

/-
SphincsCVerify.Interpreter.Memory — byte-addressed EVM memory for the C10
verifier interpreter.

This is the foundational module of the **A3.1 deductive-closure** track (see
`contracts/verification/docs/A3_1_CLOSURE_PATH.md`): the plan to prove
`∀ inputs, execC10Asm = Spec.verify` by interpreter-refinement + loop-induction
(hash kept opaque, no symbolic search), the way the upstream SPHINCS- `/verity`
project proved its C13 verifier. This module discharges residual **R2** (the
SHA-256 byte-addressed-memory blocker).

## Why true byte granularity

The deployed `SPHINCsC10Asm` Yul feeds the SHA-256 (`0x02`) precompile via
sub-word `mstore`s that alias within a 32-byte word — e.g. it writes a 16-byte
value at offset `0x40` then has the precompile read `[0x00, 0x80)`, and the
branchless Merkle swap `mstore(xor(0x40,s), ·)` / `mstore(xor(0x60,s), ·)` lands
on overlapping windows depending on `s ∈ {0, 0x20}`. The upstream verity
interpreter keys memory by byte offset but *values* each cell as a whole word
(`Nat → Uint256`), so overlapping writes are stored as independent words and the
byte-level packing is an **assumed** obligation (`linear_memory_aliasing`,
`Model.lean:247-250`). Here memory is modelled at **true byte granularity**
(`Nat → UInt8`), so sub-word aliasing is represented faithfully — closing R2.

## Scope of this module

Mathlib-free (Lean core only) and **hash-agnostic**: the `0x02` precompile takes
the digest as a parameter, so this module carries **no axioms** (the concrete
SHA-256 — reusing the project's `Spec.Sha256Impl` — wires in at the bridge layer,
adding no *new* axiom). It provides the memory ops + the **frame/disjointness**
lemmas that interpreter-refinement climb proofs (WOTS chains, FORS/Merkle walks)
rely on: a write to one 32-byte window leaves every disjoint window untouched,
and disjoint writes commute.
-/

namespace SphincsCVerify.Interpreter

/-- EVM memory at true byte granularity: a byte offset maps to one byte. -/
abbrev ByteMemory := Nat → UInt8

/-- The `i`-th big-endian byte of a 256-bit `word` (`i = 0` is most significant,
    matching EVM `mstore`'s big-endian word layout). -/
def beByte (word : Nat) (i : Nat) : UInt8 :=
  UInt8.ofNat ((word >>> (8 * (31 - i))) % 256)

/-- Overwrite the 32-byte region `[off, off+32)` with bytes drawn from `f`
    (`f k` supplies the `k`-th byte of the region); everything else is untouched.
    The single primitive behind both `mstore` and the precompile's digest write. -/
def writeRegion (mem : ByteMemory) (off : Nat) (f : Nat → UInt8) : ByteMemory :=
  fun a => if off ≤ a ∧ a < off + 32 then f (a - off) else mem a

/-- `mstore`: write the 32 big-endian bytes of `word` at byte offset `off`. -/
def mstore32 (mem : ByteMemory) (off word : Nat) : ByteMemory :=
  writeRegion mem off (beByte word)

/-- `mload`: read the 32 big-endian bytes at byte offset `off` back into a `Nat`. -/
def mload32 (mem : ByteMemory) (off : Nat) : Nat :=
  (List.range 32).foldl (fun acc i => acc * 256 + (mem (off + i)).toNat) 0

/-- The precompile / verifier input: `size` consecutive bytes at `off`. -/
def slice (mem : ByteMemory) (off size : Nat) : List UInt8 :=
  (List.range size).map (fun i => mem (off + i))

/-- The `0x02` SHA-256 precompile, parameterised by the digest-byte function `dig`
    (`dig k` = the `k`-th byte of the 32-byte digest of the input). Keeping the
    hash abstract here is what makes this module axiom-free; the concrete digest
    `dig = beByte (sha256MemSlice mem inOff inSize)` is supplied at the bridge. -/
def staticcallSha256 (mem : ByteMemory) (outOff : Nat) (dig : Nat → UInt8) :
    ByteMemory :=
  writeRegion mem outOff dig

/-! ## Frame / disjointness lemmas

The workhorses of climb-proof memory-frame reasoning: a 32-byte write never
disturbs a byte outside its window, and disjoint writes commute. All close by
`omega` on the linear window arithmetic — entirely hash-agnostic. -/

/-- A `writeRegion` leaves every byte strictly outside `[off, off+32)` untouched. -/
theorem writeRegion_frame (mem : ByteMemory) (off : Nat) (f : Nat → UInt8) (a : Nat)
    (h : a < off ∨ off + 32 ≤ a) : writeRegion mem off f a = mem a := by
  unfold writeRegion
  split
  · omega
  · rfl

/-- Inside its window, a `writeRegion` reads back the supplied byte. -/
theorem writeRegion_get (mem : ByteMemory) (off : Nat) (f : Nat → UInt8) (a : Nat)
    (h : off ≤ a ∧ a < off + 32) : writeRegion mem off f a = f (a - off) := by
  unfold writeRegion
  rw [if_pos h]

/-- `mstore32` leaves every byte outside its 32-byte window untouched. -/
theorem mstore32_frame (mem : ByteMemory) (off word : Nat) (a : Nat)
    (h : a < off ∨ off + 32 ≤ a) : mstore32 mem off word a = mem a :=
  writeRegion_frame mem off (beByte word) a h

/-- `mstore32` writes exactly the big-endian byte of `word` at each in-window
    address — the byte-level write-correctness the precompile input relies on. -/
theorem mstore32_get (mem : ByteMemory) (off word i : Nat) (h : i < 32) :
    mstore32 mem off word (off + i) = beByte word i := by
  unfold mstore32
  rw [writeRegion_get mem off (beByte word) (off + i) (by omega)]
  congr 1
  omega

/-- The precompile leaves every byte outside the 32-byte output window untouched. -/
theorem staticcallSha256_frame (mem : ByteMemory) (outOff : Nat) (dig : Nat → UInt8)
    (a : Nat) (h : a < outOff ∨ outOff + 32 ≤ a) :
    staticcallSha256 mem outOff dig a = mem a :=
  writeRegion_frame mem outOff dig a h

/-- The precompile writes exactly the digest byte at each in-window address. -/
theorem staticcallSha256_get (mem : ByteMemory) (outOff : Nat) (dig : Nat → UInt8)
    (i : Nat) (h : i < 32) :
    staticcallSha256 mem outOff dig (outOff + i) = dig i := by
  unfold staticcallSha256
  rw [writeRegion_get mem outOff dig (outOff + i) (by omega)]
  congr 1
  omega

/-- **Disjoint 32-byte writes commute.** The key frame lemma for the branchless
    Merkle swap and the per-step climb (e.g. writing a node at `0x40` and a
    sibling at `0x60` in either order yields the same memory when the windows are
    disjoint). Proven byte-by-byte; the only nontrivial case (a byte in *both*
    windows) is impossible under disjointness and is killed by `omega`. -/
theorem writeRegion_comm (mem : ByteMemory) (o1 o2 : Nat) (f1 f2 : Nat → UInt8)
    (hdisj : o1 + 32 ≤ o2 ∨ o2 + 32 ≤ o1) :
    writeRegion (writeRegion mem o1 f1) o2 f2
      = writeRegion (writeRegion mem o2 f2) o1 f1 := by
  funext a
  simp only [writeRegion]
  by_cases h1 : o1 ≤ a ∧ a < o1 + 32 <;> by_cases h2 : o2 ≤ a ∧ a < o2 + 32
  · omega
  · simp [h1, h2]
  · simp [h1, h2]
  · simp [h1, h2]

/-- Reading any byte of a disjoint earlier-written window is unaffected by a later
    `writeRegion` — the frame property in the form climb proofs consume. -/
theorem writeRegion_get_of_disjoint (mem : ByteMemory) (o1 o2 : Nat)
    (f1 f2 : Nat → UInt8) (a : Nat)
    (h1 : o1 ≤ a ∧ a < o1 + 32) (hdisj : o1 + 32 ≤ o2 ∨ o2 + 32 ≤ o1) :
    writeRegion (writeRegion mem o1 f1) o2 f2 a = f1 (a - o1) := by
  rw [writeRegion_frame _ o2 f2 a (by omega), writeRegion_get _ o1 f1 a h1]

end SphincsCVerify.Interpreter

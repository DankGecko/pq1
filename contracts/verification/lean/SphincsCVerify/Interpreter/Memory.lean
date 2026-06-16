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

/-! ## `mload32` round-trip (big-endian reassembly)

Reading back the 32 big-endian bytes just written reconstructs the low 256 bits
of the word: `mload32 (mstore32 mem off w) off = w % 2^256`. This is the one
piece of genuine bit-arithmetic in the memory model — it lets a climb thread word
values (each step's digest word feeds the next). Mathlib-free. -/

/-- One base-256 carry step: `s % (256·m) = (s/256 % m)·256 + s%256`. The
    arithmetic heart of the big-endian reassembly. -/
private theorem split_mod_aux (s m : Nat) (hm : 0 < m) :
    s % (256 * m) = (s / 256 % m) * 256 + s % 256 := by
  have h1 : 256 * (s / 256) + s % 256 = s := Nat.div_add_mod s 256
  have hr : s % 256 < 256 := Nat.mod_lt _ (by decide)
  have hqm : s / 256 % m < m := Nat.mod_lt _ hm
  calc s % (256 * m)
      = (256 * (s / 256) + s % 256) % (256 * m) := by rw [h1]
    _ = (256 * (s / 256) % (256 * m) + s % 256 % (256 * m)) % (256 * m) := by rw [Nat.add_mod]
    _ = (256 * (s / 256 % m) + s % 256) % (256 * m) := by
          rw [Nat.mul_mod_mul_left, Nat.mod_eq_of_lt (show s % 256 < 256 * m by omega)]
    _ = 256 * (s / 256 % m) + s % 256 := Nat.mod_eq_of_lt (by omega)
    _ = (s / 256 % m) * 256 + s % 256 := by omega

/-- `(beByte w i).toNat` is the `i`-th big-endian base-256 digit of `w`. -/
private theorem beByte_toNat (w i : Nat) :
    (beByte w i).toNat = (w >>> (8 * (31 - i))) % 256 := by
  unfold beByte
  rw [UInt8.toNat_ofNat']
  omega

/-- The MSB-first fold of the written bytes reconstructs the top `k` bytes of `w`. -/
private theorem mload32_mstore32_aux (mem : ByteMemory) (off w : Nat) :
    ∀ k, k ≤ 32 →
      (List.range k).foldl
          (fun acc i => acc * 256 + (mstore32 mem off w (off + i)).toNat) 0
        = (w >>> (8 * (32 - k))) % 2 ^ (8 * k) := by
  intro k
  induction k with
  | zero => intro _; simp [Nat.mod_one]
  | succ j ih =>
      intro hk
      rw [List.range_succ, List.foldl_append, ih (by omega)]
      simp only [List.foldl_cons, List.foldl_nil]
      rw [mstore32_get mem off w j (by omega), beByte_toNat]
      -- Let s = w >>> (8*(31-j)); then w >>> (8*(32-j)) = s / 256, and
      -- 2^(8*(j+1)) = 256 * 2^(8*j); close via split_mod_aux.
      have hshift : w >>> (8 * (32 - j)) = (w >>> (8 * (31 - j))) / 256 := by
        rw [show 8 * (32 - j) = 8 * (31 - j) + 8 by omega, Nat.shiftRight_add,
            Nat.shiftRight_eq_div_pow (w >>> (8 * (31 - j))) 8]
      have hidx : 8 * (32 - (j + 1)) = 8 * (31 - j) := by omega
      have hpow : (2 : Nat) ^ (8 * (j + 1)) = 256 * 2 ^ (8 * j) := by
        rw [show 8 * (j + 1) = 8 * j + 8 by omega, Nat.pow_add]; omega
      rw [hshift, hidx, hpow,
          split_mod_aux (w >>> (8 * (31 - j))) (2 ^ (8 * j)) (Nat.two_pow_pos _)]

/-- **Read-after-write round-trip.** Reading the 32 big-endian bytes of a stored
    word back reconstructs its low 256 bits. -/
theorem mload32_mstore32_self (mem : ByteMemory) (off w : Nat) :
    mload32 (mstore32 mem off w) off = w % 2 ^ 256 := by
  have h := mload32_mstore32_aux mem off w 32 (by omega)
  simpa [mload32, Nat.shiftRight_zero] using h

/-- **General digest read-back.** Reading a freshly-written 32-byte region back
    gives the big-endian `Nat` value of exactly the bytes written. This is the
    bridge primitive for a *real* precompile digest (a 32-byte `ByteVec`, not the
    `beByte`-encoding of a pre-existing word): after `staticcallSha256 … dig`, an
    `mload32` of the output window recovers the digest as a word. -/
theorem mload32_writeRegion (mem : ByteMemory) (off : Nat) (f : Nat → UInt8) :
    mload32 (writeRegion mem off f) off
      = (List.range 32).foldl (fun acc i => acc * 256 + (f i).toNat) 0 := by
  unfold mload32
  suffices h : ∀ k, k ≤ 32 →
      (List.range k).foldl
          (fun acc i => acc * 256 + (writeRegion mem off f (off + i)).toNat) 0
        = (List.range k).foldl (fun acc i => acc * 256 + (f i).toNat) 0 from h 32 (by omega)
  intro k
  induction k with
  | zero => intro _; rfl
  | succ j ih =>
      intro hk
      rw [List.range_succ, List.foldl_append, List.foldl_append, ih (by omega)]
      simp only [List.foldl_cons, List.foldl_nil]
      rw [writeRegion_get mem off f (off + j) (by omega), Nat.add_sub_cancel_left]

/-- The precompile output, read back, is the big-endian word of its digest bytes. -/
theorem mload32_staticcallSha256 (mem : ByteMemory) (outOff : Nat) (dig : Nat → UInt8) :
    mload32 (staticcallSha256 mem outOff dig) outOff
      = (List.range 32).foldl (fun acc i => acc * 256 + (dig i).toNat) 0 :=
  mload32_writeRegion mem outOff dig

end SphincsCVerify.Interpreter

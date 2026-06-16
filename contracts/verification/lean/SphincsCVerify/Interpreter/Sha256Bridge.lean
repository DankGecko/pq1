/-
SphincsCVerify.Interpreter.Sha256Bridge — positional big-endian byte extraction
for `mload32`.

The single public result, `beByte_mload32`, says: reading the 32 big-endian bytes
at `off` into a `Nat` (`mload32`) and then extracting the `i`-th big-endian byte
(`beByte`) recovers exactly the `i`-th memory byte `mem (off + i)`. This is the
inverse direction of `Memory.mload32_writeRegion`: where that lemma assembles
written bytes into a word, this one re-extracts an arbitrary positional byte from
the assembled word — the lemma a SHA-256 climb consumes when it must reason about
a *single* input byte fed to the precompile, not the whole word.

Mathlib-free (Lean core / `Init` only); no new axioms beyond the kernel three.
-/

import SphincsCVerify.Interpreter.Memory
import SphincsCVerify.Spec.Bytes

namespace SphincsCVerify.Interpreter

/-- Big-endian value of a `Nat` list (MSB first): the pure-list core of `mload32`. -/
private def beNat (xs : List Nat) : Nat := xs.foldl (fun acc x => acc * 256 + x) 0

/-- Horner accumulator factoring: folding from an arbitrary start `A` shifts `A`
    by the full length and adds the headless big-endian value. -/
private theorem foldl_horner_acc (xs : List Nat) :
    ∀ A, xs.foldl (fun acc x => acc * 256 + x) A = A * 256 ^ xs.length + beNat xs := by
  induction xs with
  | nil => intro A; simp [beNat]
  | cons x xs ih =>
      intro A
      rw [List.foldl_cons, ih (A * 256 + x)]
      have hcons : beNat (x :: xs) = (0 * 256 + x) * 256 ^ xs.length + beNat xs := by
        show xs.foldl _ (0 * 256 + x) = _
        rw [ih (0 * 256 + x)]
      rw [hcons, List.length_cons, Nat.pow_succ]
      -- (A*256+x)*256^len + beNat xs  =  A*256^(len+1) + ((0*256+x)*256^len + beNat xs)
      simp only [Nat.zero_mul, Nat.zero_add]
      rw [Nat.add_mul, Nat.add_assoc]
      congr 1
      rw [Nat.mul_assoc, Nat.mul_comm (256 ^ xs.length) 256]

/-- `beNat (xs ++ ys) = beNat xs * 256 ^ ys.length + beNat ys`. The append-split
    corollary powering both the positional split and the digit step. -/
private theorem beNat_append (xs ys : List Nat) :
    beNat (xs ++ ys) = beNat xs * 256 ^ ys.length + beNat ys := by
  show (xs ++ ys).foldl _ 0 = _
  rw [List.foldl_append]
  show ys.foldl _ (beNat xs) = _
  rw [foldl_horner_acc ys (beNat xs)]

/-- Each element `< 256` ⇒ `beNat xs < 256 ^ xs.length`. -/
private theorem beNat_lt (xs : List Nat) (hb : ∀ x ∈ xs, x < 256) :
    beNat xs < 256 ^ xs.length := by
  induction xs with
  | nil => simp [beNat]
  | cons x xs ih =>
      have hx : x < 256 := hb x (List.mem_cons_self ..)
      have htail : ∀ y ∈ xs, y < 256 := fun y hy => hb y (List.mem_cons_of_mem x hy)
      have ihlt : beNat xs < 256 ^ xs.length := ih htail
      have hcons : beNat (x :: xs) = x * 256 ^ xs.length + beNat xs := by
        rw [show x :: xs = [x] ++ xs from rfl, beNat_append]
        simp [beNat]
      rw [hcons, List.length_cons, Nat.pow_succ]
      -- x * P + beNat xs < (x+1) * P ≤ 256 * P = P * 256
      calc x * 256 ^ xs.length + beNat xs
          < x * 256 ^ xs.length + 256 ^ xs.length := by
            exact Nat.add_lt_add_left ihlt _
        _ = (x + 1) * 256 ^ xs.length := by rw [Nat.succ_mul]
        _ ≤ 256 * 256 ^ xs.length := by
            exact Nat.mul_le_mul_right _ (by omega)
        _ = 256 ^ xs.length * 256 := by rw [Nat.mul_comm]

/-- `a >>> (8 * k) = a / 256 ^ k`: rewrite a byte-granular right shift as division
    by a power of 256. -/
private theorem shiftRight_eq_div_pow256 (a k : Nat) :
    a >>> (8 * k) = a / 256 ^ k := by
  rw [Nat.shiftRight_eq_div_pow, Nat.pow_mul]

/-- **Positional big-endian byte extraction.** The `i`-th big-endian byte of
    `beNat xs` (counting from the MSB) is exactly `xs[i]`. The crux of the bridge:
    `mload32`'s assembled word, sliced at any position, recovers the source byte. -/
private theorem beNat_getByte (xs : List Nat) (hb : ∀ x ∈ xs, x < 256)
    (i : Nat) (hi : i < xs.length) :
    (beNat xs >>> (8 * (xs.length - 1 - i))) % 256 = xs[i] := by
  rw [shiftRight_eq_div_pow256]
  induction xs generalizing i with
  | nil => exact absurd hi (by simp)
  | cons x xs ih =>
      have hx : x < 256 := hb x (List.mem_cons_self ..)
      have htail : ∀ y ∈ xs, y < 256 := fun y hy => hb y (List.mem_cons_of_mem x hy)
      have hcons : beNat (x :: xs) = x * 256 ^ xs.length + beNat xs := by
        rw [show x :: xs = [x] ++ xs from rfl, beNat_append]
        simp [beNat]
      have hlt : beNat xs < 256 ^ xs.length := beNat_lt xs htail
      have hPpos : (0 : Nat) < 256 ^ xs.length := Nat.pow_pos (by decide)
      have hlen : (x :: xs).length = xs.length + 1 := List.length_cons ..
      match i with
      | 0 =>
          -- shift = (len+1) - 1 - 0 = len; division gives x; x % 256 = x = (x::xs)[0]
          rw [hlen, hcons]
          have hk : xs.length + 1 - 1 - 0 = xs.length := by omega
          rw [hk]
          rw [Nat.mul_comm x (256 ^ xs.length), Nat.mul_add_div hPpos,
              Nat.div_eq_of_lt hlt, Nat.add_zero, Nat.mod_eq_of_lt hx,
              List.getElem_cons_zero]
      | j + 1 =>
          have hj : j < xs.length := by
            have := hi; rw [hlen] at this; omega
          -- shift index s = len - 1 - j ; 256^len = 256^(j+1) * 256^s
          have hsum : (j + 1) + (xs.length - 1 - j) = xs.length := by omega
          have hsplit : (256 : Nat) ^ xs.length
              = 256 ^ (j + 1) * 256 ^ (xs.length - 1 - j) := by
            rw [← Nat.pow_add, hsum]
          have hkey : (x :: xs).length - 1 - (j + 1) = xs.length - 1 - j := by
            rw [hlen]; omega
          rw [hkey, hcons]
          -- x * 256^len = (x * 256^(j+1)) * 256^s
          have hPspos : (0 : Nat) < 256 ^ (xs.length - 1 - j) := Nat.pow_pos (by decide)
          have hrw : x * 256 ^ xs.length + beNat xs
              = (x * 256 ^ (j + 1)) * 256 ^ (xs.length - 1 - j) + beNat xs := by
            rw [hsplit, Nat.mul_assoc]
          rw [hrw, Nat.mul_comm (x * 256 ^ (j + 1)) (256 ^ (xs.length - 1 - j)),
              Nat.mul_add_div hPspos]
          -- ((beNat xs / 256^s) + x*256^(j+1)) % 256, but order is x*256^(j+1) + R
          -- shape now: (x * 256^(j+1) + beNat xs / 256^s) % 256
          have hmul : x * 256 ^ (j + 1) = (x * 256 ^ j) * 256 := by
            rw [Nat.pow_succ, Nat.mul_assoc]
          rw [hmul, Nat.add_comm ((x * 256 ^ j) * 256) (beNat xs / 256 ^ (xs.length - 1 - j)),
              Nat.add_mul_mod_self_right]
          -- now goal: (beNat xs / 256^s) % 256 = (x::xs)[j+1]
          have hgoal := ih htail j hj
          rw [hgoal]
          -- (x::xs)[j+1] = xs[j]
          rfl

/-- `mload32` is the big-endian value (`beNat`) of the 32 memory bytes it reads. -/
private theorem mload32_eq_beNat (mem : ByteMemory) (off : Nat) :
    mload32 mem off
      = beNat ((List.range 32).map (fun i => (mem (off + i)).toNat)) := by
  unfold mload32 beNat
  rw [List.foldl_map]

/-- **Big-endian byte read-back.** Extracting the `i`-th big-endian byte (`beByte`)
    of the 32-byte word read at `off` (`mload32`) recovers exactly the memory byte
    `mem (off + i)`. The bridge primitive a SHA-256 climb consumes when it must
    reason about a single precompile-input byte rather than the assembled word. -/
theorem beByte_mload32 (mem : ByteMemory) (off i : Nat) (hi : i < 32) :
    beByte (mload32 mem off) i = mem (off + i) := by
  -- Work with the explicit byte list `L`; bind it via a definitional equality.
  let L : List Nat := (List.range 32).map (fun j => (mem (off + j)).toNat)
  have hL : (List.range 32).map (fun j => (mem (off + j)).toNat) = L := rfl
  have hlen : L.length = 32 := by
    show ((List.range 32).map _).length = 32
    rw [List.length_map, List.length_range]
  have hbound : ∀ x ∈ L, x < 256 := by
    intro x hx
    have hx' : x ∈ (List.range 32).map (fun j => (mem (off + j)).toNat) := hx
    rw [List.mem_map] at hx'
    obtain ⟨j, _, hj⟩ := hx'
    rw [← hj]
    have := (mem (off + j)).toNat_lt
    omega
  have hi' : i < L.length := by rw [hlen]; exact hi
  have hLi : L[i] = (mem (off + i)).toNat := by
    show ((List.range 32).map (fun j => (mem (off + j)).toNat))[i] = _
    rw [List.getElem_map, List.getElem_range]
  -- beByte (mload32 …) i  =  ofNat ((beNat L >>> (8*(31-i))) % 256)
  unfold beByte
  rw [mload32_eq_beNat, hL]
  -- 31 - i = L.length - 1 - i
  have hidx : (31 : Nat) - i = L.length - 1 - i := by rw [hlen]
  rw [hidx, beNat_getByte L hbound i hi', hLi, UInt8.ofNat_toNat]

/-! ## Representation iso to the spec `ByteVec`

The interpreter threads 256-bit *words* (`Nat`); the declarative spec threads
`ByteVec 32`. `wordOf` is the big-endian word of a `ByteVec 32`, and
`beByte_wordOf` is the round-trip — extracting big-endian byte `i` of `wordOf v`
recovers `v`'s `i`-th byte. This is the boundary the input-assembly bridge
(`mstore32 … (wordOf seg)` lays down exactly `seg`'s bytes for the precompile)
and the chained-node invariant (`mload`ed digest word ↔ the spec node `ByteVec`)
both consume. -/

open SphincsCVerify.Spec (ByteVec)

/-- A byte vector laid into memory at offset `0` (bytes past the vector read `0`).
    The memory image whose `mload32` is the vector's big-endian word. -/
def memOfBytes {n : Nat} (v : ByteVec n) : ByteMemory :=
  fun a => if h : a < v.data.size then v.data[a] else 0

/-- Big-endian word value of a 32-byte vector: load its bytes back as one word.
    The interpreter-side image of a spec `ByteVec 32` segment. -/
def wordOf (v : ByteVec 32) : Nat := mload32 (memOfBytes v) 0

/-- **Representation round-trip.** Extracting big-endian byte `i` of `wordOf v`
    recovers `v.get i` — `wordOf` loses nothing. The inverse companion of the
    bit-arithmetic `mload32_mstore32_self`, lifted to the spec's `ByteVec`. -/
theorem beByte_wordOf (v : ByteVec 32) (i : Fin 32) :
    beByte (wordOf v) i.val = v.get i := by
  unfold wordOf
  rw [beByte_mload32 (memOfBytes v) 0 i.val i.isLt, Nat.zero_add]
  unfold memOfBytes ByteVec.get
  rw [dif_pos (by rw [v.size_eq]; exact i.isLt)]
  rfl

end SphincsCVerify.Interpreter

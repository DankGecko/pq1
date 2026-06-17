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
import SphincsCVerify.Spec.Hash

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

/-! ## Input-assembly bridge: a contiguous slice IS the spec's `ByteSeg.flatten`

The precompile reads `size` contiguous memory bytes; the declarative spec hashes
`ByteSeg.flatten segs`. When the interpreter has laid `segs` (each a 32-byte
`ByteVec`) into consecutive 32-byte windows starting at `base`, the
`32 * segs.length`-byte slice at `base` is **exactly** the flattened segment
bytes — so the precompile reads precisely the concatenated segments. This is the
keystone reused at every C10 hash site (WOTS chains, FORS/Merkle climbs, `h_msg`).

The proof works over `List (Spec.ByteVec 32)` (NOT `List Spec.ByteSeg`): only
because the segments are *uniformly* 32 bytes is the slice size `32 * length`.
`flattenV` is `ByteSeg.flatten ∘ (·.map ofByteVec)` specialised to that type, and
`flatten_map_eq_flattenV` bridges the two. -/

open SphincsCVerify.Spec (ByteSeg)

/-- The flatten foldl specialised to uniform 32-byte vectors: foldl-append each
    vector's `data`. Equal to `ByteSeg.flatten (segs.map ByteSeg.ofByteVec)`
    (see `flatten_map_eq_flattenV`), but stated at `List (ByteVec 32)` so every
    head carries `size_eq : data.size = 32`. -/
private def flattenV (segs : List (ByteVec 32)) : Array UInt8 :=
  segs.foldl (fun acc s => acc ++ s.data) #[]

/-- `ByteSeg.flatten (segs.map ofByteVec) = flattenV segs`: the spec's flatten of
    the coerced segments is the uniform-vector foldl. `(ofByteVec s).bytes.data`
    is `s.data` by `rfl`, so `List.foldl_map` collapses the two. -/
private theorem flatten_map_eq_flattenV (segs : List (ByteVec 32)) :
    ByteSeg.flatten (segs.map ByteSeg.ofByteVec) = flattenV segs := by
  unfold ByteSeg.flatten flattenV
  rw [List.foldl_map]
  rfl

/-- Accumulator factoring for the flatten foldl: starting from an arbitrary `acc`
    prepends `acc` to the headless flatten. The array analogue of the Horner
    accumulator trick used for `beNat`; lets us peel the head cleanly. -/
private theorem flattenV_foldl_acc (segs : List (ByteVec 32)) :
    ∀ acc, segs.foldl (fun a s => a ++ s.data) acc = acc ++ flattenV segs := by
  induction segs with
  | nil => intro acc; simp [flattenV]
  | cons s rest ih =>
      intro acc
      rw [List.foldl_cons, ih (acc ++ s.data)]
      have hrest : flattenV (s :: rest) = s.data ++ flattenV rest := by
        show rest.foldl _ (#[] ++ s.data) = _
        rw [ih (#[] ++ s.data), Array.empty_append]
      rw [hrest, Array.append_assoc]

/-- `flattenV` over a cons splits off the head vector's data. The clean recursion
    lemma the size/element inductions consume. -/
private theorem flattenV_cons (s : ByteVec 32) (rest : List (ByteVec 32)) :
    flattenV (s :: rest) = s.data ++ flattenV rest := by
  show rest.foldl _ (#[] ++ s.data) = _
  rw [flattenV_foldl_acc rest (#[] ++ s.data), Array.empty_append]

/-- The flattened size is exactly `32 * length` — true *because* each segment is a
    32-byte `ByteVec` (`size_eq`). -/
private theorem flattenV_size (segs : List (ByteVec 32)) :
    (flattenV segs).size = 32 * segs.length := by
  induction segs with
  | nil => simp [flattenV]
  | cons s rest ih =>
      rw [flattenV_cons, Array.size_append, s.size_eq, ih, List.length_cons]
      -- 32 + 32 * rest.length = 32 * (rest.length + 1)
      omega

/-- **Positional flatten read-back.** For an in-range index `k`, the `k`-th byte
    of `flattenV segs` (with default `0`) is the `(k % 32)`-th byte of the
    `(k / 32)`-th segment (with defaults `ByteVec.zero 32` / `0`). The `getD`
    phrasing makes the RHS byte-identical to what `holdsSegs` supplies, so the
    main bridge closes by a single `h` application. -/
private theorem flattenV_getD (segs : List (ByteVec 32)) :
    ∀ k, k < 32 * segs.length →
      (flattenV segs).getD k 0
        = (segs.getD (k / 32) (ByteVec.zero 32)).data.getD (k % 32) 0 := by
  induction segs with
  | nil => intro k hk; simp at hk
  | cons s rest ih =>
      intro k hk
      rw [flattenV_cons]
      -- (s.data ++ flattenV rest).getD k 0 = (s.data ++ flattenV rest)[k]?.getD 0
      rw [Array.getD_eq_getD_getElem?, Array.getElem?_append]
      have hssize : s.data.size = 32 := s.size_eq
      by_cases hlt : k < s.data.size
      · -- head segment: k / 32 = 0, k % 32 = k
        rw [if_pos hlt]
        have hk32 : k < 32 := by rw [hssize] at hlt; exact hlt
        have hdiv : k / 32 = 0 := by omega
        have hmod : k % 32 = k := by omega
        rw [hdiv, hmod, List.getD_cons_zero]
        -- s.data[k]?.getD 0 = s.data.getD k 0
        rw [← Array.getD_eq_getD_getElem?]
      · -- tail segment: recurse at k - 32
        rw [if_neg hlt, hssize]
        have hge : 32 ≤ k := by rw [hssize] at hlt; omega
        have hkrest : k - 32 < 32 * rest.length := by
          rw [List.length_cons] at hk; omega
        have hih := ih (k - 32) hkrest
        -- (flattenV rest)[k - 32]?.getD 0 = (flattenV rest).getD (k-32) 0
        rw [← Array.getD_eq_getD_getElem?, hih]
        -- bridge the indices: (k-32)/32 = k/32 - 1, (k-32)%32 = k%32, k/32 ≥ 1
        have hd : (k - 32) / 32 = k / 32 - 1 := by omega
        have hm : (k - 32) % 32 = k % 32 := by omega
        rw [hd, hm]
        -- RHS: ((s::rest).getD (k/32) _) = rest.getD (k/32 - 1) _  (since k/32 ≥ 1)
        obtain ⟨m, hmeq⟩ : ∃ m, k / 32 = m + 1 := ⟨k / 32 - 1, by omega⟩
        have hcons : (s :: rest).getD (k / 32) (ByteVec.zero 32)
            = rest.getD (k / 32 - 1) (ByteVec.zero 32) := by
          rw [hmeq, List.getD_cons_succ, Nat.add_sub_cancel]
        rw [hcons]

/-- Memory holds a list of 32-byte `ByteVec` segments at consecutive 32-byte
    windows starting at `base` (window `j = [base+32j, base+32j+32)`). -/
def holdsSegs (mem : ByteMemory) (base : Nat) (segs : List (Spec.ByteVec 32)) : Prop :=
  ∀ j i, j < segs.length → i < 32 →
    mem (base + 32 * j + i) = (segs.getD j (Spec.ByteVec.zero 32)).data.getD i 0

/-- **Input-assembly bridge.** When memory holds `segs` at consecutive 32-byte
    windows, the `32 * segs.length`-byte slice at `base` is exactly the spec's
    `ByteSeg.flatten` of those segments — i.e. the precompile reads precisely the
    concatenated segment bytes. Reusable across all C10 hash sites. -/
theorem slice_toArray_eq_flatten (mem : ByteMemory) (base : Nat)
    (segs : List (Spec.ByteVec 32)) (h : holdsSegs mem base segs) :
    (slice mem base (32 * segs.length)).toArray
      = Spec.ByteSeg.flatten (segs.map Spec.ByteSeg.ofByteVec) := by
  rw [flatten_map_eq_flattenV]
  apply Array.ext
  · -- sizes: both 32 * segs.length
    rw [List.size_toArray, flattenV_size]
    show (slice mem base (32 * segs.length)).length = _
    unfold slice
    rw [List.length_map, List.length_range]
  · -- elements: at each in-range index k
    intro k hk1 _
    -- LHS k-bound is over the toArray; reduce it to `k < 32 * segs.length`
    have hkrange : k < 32 * segs.length := by
      rw [List.size_toArray] at hk1
      have : (slice mem base (32 * segs.length)).length = 32 * segs.length := by
        unfold slice; rw [List.length_map, List.length_range]
      rw [this] at hk1; exact hk1
    -- LHS: (slice …).toArray[k] = mem (base + k)
    have hlhs : (slice mem base (32 * segs.length)).toArray[k] = mem (base + k) := by
      rw [List.getElem_toArray]
      show ((List.range (32 * segs.length)).map (fun i => mem (base + i)))[k]'_ = _
      rw [List.getElem_map, List.getElem_range]
    -- RHS: convert getElem to getD-with-0, then apply flattenV_getD + h
    rw [hlhs]
    have hrhs : (flattenV segs)[k] = (flattenV segs).getD k 0 := by
      rw [Array.getD_eq_getD_getElem?, Array.getElem?_eq_getElem, Option.getD_some]
    rw [hrhs, flattenV_getD segs k hkrange]
    -- mem (base + k) = (segs.getD (k/32) _).data.getD (k%32) 0   via `h`
    have hdiv : k / 32 < segs.length := Nat.div_lt_of_lt_mul hkrange
    have hmod : k % 32 < 32 := Nat.mod_lt _ (by decide)
    have hsplit : base + 32 * (k / 32) + k % 32 = base + k := by
      have := Nat.div_add_mod k 32; omega
    rw [← hsplit]
    exact h (k / 32) (k % 32) hdiv hmod

end SphincsCVerify.Interpreter

/-
SphincsCVerify.Interpreter.Phases — phase-wise refinement of the transcribed
`SPHINCsC10Asm` Yul against its declarative spec.

This module proves the **H_msg phase** of the deployed C10 verifier: the 10-statement
fragment that lays `seed‖root‖R‖message‖0xFF..FF` into scratch memory, runs the
`0x02` SHA-256 precompile over the 160-byte (`0xA0`) window, and binds the resulting
digest word to `"digest"` — matches the declarative `Spec.hMsg`.

The proof is the canonical interpreter-refinement shape (`docs/A3_1_CLOSURE_PATH.md`
§8): step the fragment with the binding-frame lemmas, characterise the assembled
160-byte slice as `holdsSegs … segs`, push it through the oracle↔spec-hash bridge
(`c10Oracle_holdsSegs`), and read the digest word back via `mload32_writeRegion`.
The single piece of genuine arithmetic is the `wordOfBV`/`wordOf` round-trip (the
interpreter's two big-endian-word encodings agree).

Mathlib-free (Lean core / `Init` only); no `sorry`/`admit`/`axiom`/`native_decide`.
-/
import SphincsCVerify.Interpreter.C10Program
import SphincsCVerify.Spec.Fors
import SphincsCVerify.Spec.Signature

namespace SphincsCVerify.Interpreter.C10

open SphincsCVerify.Interpreter
open SphincsCVerify.Spec (ByteVec)

/-! ## The H_msg fragment

The verbatim H_msg statements of `c10Program` (`SPHINCsC10Asm.sol` L67–80),
written with raw constructors so the fragment is *defeq* to the corresponding
slice of `c10Program`. -/

/-- The H_msg statement block of `c10Program`. -/
def hmsgFragment : List Stmt :=
  [ .letv "seed" (.var "pkSeed")
  , .letv "root" (.var "pkRoot")
  , .mstore (.lit 0x00) (.var "seed")
  , .letv "R" (.bin .band (.calldataload .sigOffset) (.var "N_MASK"))
  , .mstore (.lit 0x20) (.var "root")
  , .mstore (.lit 0x40) (.var "R")
  , .mstore (.lit 0x60) (.var "message")
  , .mstore (.lit 0x80) (.lit 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF)
  , .sha256 (.lit 0x00) (.lit 0xA0) (.var "OUT")
  , .letv "digest" (.mload (.var "OUT")) ]

/-! ## The two interpreter word encodings agree

`Yul.wordOfBV` (the `calldataload`/`ByteVec` word) and `Sha256Bridge.wordOf`
(`mload32 (memOfBytes ·) 0`) are distinct `def`s; both are the big-endian fold of
a `ByteVec 32`'s bytes. `wordOfBV_eq_wordOf` bridges them once. -/

/-- For a `ByteVec 32`, the `memOfBytes` image reads back each byte by `getD`. -/
private theorem memOfBytes_getD (v : ByteVec 32) (i : Nat) (hi : i < 32) :
    (memOfBytes v (0 + i)).toNat = (v.data.getD i 0).toNat := by
  unfold memOfBytes
  rw [Nat.zero_add]
  have hsz : i < v.data.size := by rw [v.size_eq]; exact hi
  rw [dif_pos hsz]
  rw [Array.getD_eq_getD_getElem?, Array.getElem?_eq_getElem hsz, Option.getD_some]

/-- The big-endian fold of `memOfBytes v` and the `getD`-fold agree, over any prefix
    length `k ≤ 32`. -/
private theorem foldl_memOfBytes_eq_getD (v : ByteVec 32) :
    ∀ k, k ≤ 32 →
      (List.range k).foldl (fun acc i => acc * 256 + (memOfBytes v (0 + i)).toNat) 0
        = (List.range k).foldl (fun acc i => acc * 256 + (v.data.getD i 0).toNat) 0 := by
  intro k
  induction k with
  | zero => intro _; rfl
  | succ j ih =>
      intro hk
      rw [List.range_succ, List.foldl_append, List.foldl_append, ih (by omega)]
      simp only [List.foldl_cons, List.foldl_nil]
      rw [memOfBytes_getD v j (by omega)]

/-- **The two interpreter word encodings agree.** `Yul.wordOfBV` and
    `Sha256Bridge.wordOf` are the same big-endian word of a 32-byte vector. -/
theorem wordOfBV_eq_wordOf (v : ByteVec 32) : wordOfBV v = wordOf v := by
  unfold wordOfBV wordOf mload32
  rw [foldl_memOfBytes_eq_getD v 32 (by omega)]

/-! ## Reading a freshly-written digest back as `wordOf`

The precompile writes `dig`'s bytes at the output window; `mload32` of that window
recovers `wordOf dig` (= `wordOfBV dig`). -/

/-- After the precompile writes the digest `dig` at `off`, `mload32` of that window
    is `wordOf dig`. -/
private theorem mload32_writeRegion_digest (mem : ByteMemory) (off : Nat) (dig : ByteVec 32) :
    mload32 (writeRegion mem off (fun i => dig.data.getD i 0)) off = wordOf dig := by
  rw [mload32_writeRegion mem off (fun i => dig.data.getD i 0)]
  -- the resulting fold is literally `wordOfBV dig`
  rw [← wordOfBV_eq_wordOf]
  rfl

/-! ## `pad16 ∘ loadValue16` byte action

The R segment laid into memory is `(calldataload sig 0) &&& N_MASK`, whose
big-endian bytes are `pad16 (loadValue16 sig 0)`'s bytes. -/

/-- `pad16 v`'s `i`-th byte (`getD`) is `v`'s byte for `i < 16`, else `0`. -/
private theorem pad16_data_getD (v : ByteVec 16) (i : Nat) :
    (ByteVec.pad16 v).data.getD i 0 = if i < 16 then v.data.getD i 0 else 0 := by
  -- (pad16 v).data = v.data ++ (zero 16).data = v.data ++ Array.replicate 16 0
  have hdata : (ByteVec.pad16 v).data = v.data ++ Array.replicate 16 (0 : UInt8) := rfl
  rw [hdata]
  rw [Array.getD_eq_getD_getElem?, Array.getElem?_append]
  have hvsz : v.data.size = 16 := v.size_eq
  rw [hvsz]
  by_cases hi : i < 16
  · rw [if_pos hi, if_pos hi, ← Array.getD_eq_getD_getElem?]
  · rw [if_neg hi, if_neg hi, Array.getElem?_replicate]
    -- replicate value is 0 whether the index is in range (some 0) or out (none)
    by_cases hr : i - 16 < 16
    · rw [if_pos hr, Option.getD_some]
    · rw [if_neg hr, Option.getD_none]

/-- `(loadValue16 sig 0)`'s `i`-th byte (`i < 16`) equals `(loadWord32 sig 0)`'s
    `i`-th byte. -/
private theorem loadValue16_data_getD {m : Nat} (sig : ByteVec m) (i : Nat) (hi : i < 16) :
    (ByteVec.loadValue16 sig 0).data.getD i 0 = (ByteVec.loadWord32 sig 0).data.getD i 0 := by
  -- loadValue16 sig 0 = (loadWord32 sig 0).take 16, whose data is data.extract 0 16
  unfold ByteVec.loadValue16 ByteVec.take
  rw [Array.getD_eq_getD_getElem?, Array.getElem?_extract]
  have hwsz : (ByteVec.loadWord32 sig 0).data.size = 32 := (ByteVec.loadWord32 sig 0).size_eq
  rw [hwsz]
  have hcond : i < min 16 32 - 0 := by omega
  rw [if_pos hcond, Nat.zero_add, ← Array.getD_eq_getD_getElem?]

/-- **R-segment byte action.** The big-endian byte at position `i` of
    `(calldataload sig 0) &&& N_MASK` is exactly the `i`-th byte of
    `pad16 (loadValue16 sig 0)`. -/
private theorem R_beByte_eq {m : Nat} (sig : ByteVec m) (i : Nat) (hi : i < 32) :
    beByte (calldataload sig 0 &&& NMASK) i
      = (ByteVec.pad16 (ByteVec.loadValue16 sig 0)).data.getD i 0 := by
  rw [beByte_and_nmask]
  rw [pad16_data_getD]
  by_cases h16 : i < 16
  · rw [if_pos h16, if_pos h16]
    -- beByte (calldataload sig 0) i = (loadValue16 sig 0).data.getD i 0
    rw [loadValue16_data_getD sig i h16]
    -- calldataload sig 0 = wordOfBV (loadWord32 sig 0) = wordOf (loadWord32 sig 0)
    unfold calldataload
    rw [wordOfBV_eq_wordOf]
    have := beByte_wordOf (ByteVec.loadWord32 sig 0) ⟨i, hi⟩
    rw [this]
    -- get ⟨i,_⟩ = data.getD i 0
    unfold ByteVec.get
    rw [Array.getD_eq_getD_getElem?]
    have hsz : i < (ByteVec.loadWord32 sig 0).data.size := by
      rw [(ByteVec.loadWord32 sig 0).size_eq]; exact hi
    rw [Array.getElem?_eq_getElem hsz, Option.getD_some]
    rfl
  · rw [if_neg h16, if_neg h16]

/-! ## Byte action of the other four segments

`pkSeed`, `pkRoot`, `msg` enter as `wordOf`-words; the 0xFF..FF separator is the
`ones 32` segment. -/

/-- `beByte (wordOf v) i = v.data.getD i 0` for `i < 32` (the `getD` phrasing
    `holdsSegs` consumes). -/
private theorem beByte_wordOf_getD (v : ByteVec 32) (i : Nat) (hi : i < 32) :
    beByte (wordOf v) i = v.data.getD i 0 := by
  rw [beByte_wordOf v ⟨i, hi⟩]
  unfold ByteVec.get
  rw [Array.getD_eq_getD_getElem?]
  have hsz : i < v.data.size := by rw [v.size_eq]; exact hi
  rw [Array.getElem?_eq_getElem hsz, Option.getD_some]
  rfl

/-- The all-ones word `0xFF..FF` (the H_msg separator literal) is the big-endian
    word of `ByteVec.ones 32`: each big-endian byte is `0xFF` for `i < 32`. -/
private theorem allFF_beByte_eq (i : Nat) (hi : i < 32) :
    beByte 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF i
      = (ByteVec.ones 32).data.getD i 0 := by
  -- RHS: (ones 32).data = Array.replicate 32 0xFF, so getD i 0 = 0xFF for i < 32
  have hrhs : (ByteVec.ones 32).data.getD i 0 = (0xFF : UInt8) := by
    show (Array.replicate 32 (0xFF : UInt8)).getD i 0 = (0xFF : UInt8)
    rw [Array.getD_eq_getD_getElem?, Array.getElem?_replicate, if_pos hi, Option.getD_some]
  rw [hrhs]
  -- LHS: beByte (2^256-1) i = 0xFF for any i < 32.  Bit-extensional, like nmask_byte.
  unfold beByte
  have hbody : (0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF >>> (8 * (31 - i))) % 256
      = (255 : Nat) := by
    apply Nat.eq_of_testBit_eq
    intro b
    rw [show (256 : Nat) = 2 ^ 8 from rfl, Nat.testBit_mod_two_pow, Nat.testBit_shiftRight]
    have hAll : (0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF : Nat)
        = 2 ^ 256 - 1 := by decide
    have h255 : (255 : Nat) = 2 ^ 8 - 1 := by decide
    rw [hAll, Nat.testBit_two_pow_sub_one, h255, Nat.testBit_two_pow_sub_one]
    by_cases hb : b < 8
    · -- testBit of (2^256-1) at index 8*(31-i)+b < 256 is true; (255).testBit b is true
      have hidx : 8 * (31 - i) + b < 256 := by omega
      rw [decide_eq_true hidx, decide_eq_true hb, Bool.and_true]
    · -- b ≥ 8: LHS `(_ < 8) && _` is false via the left conjunct; RHS `decide (b<8)` false
      rw [decide_eq_false hb, Bool.false_and]
  rw [hbody]
  rfl

/-! ## The assembled 160-byte slice holds `segs`

After the five `mstore`s, memory at `[0x00, 0xA0)` holds
`[pkSeed, pkRoot, pad16(loadValue16 sig 0), msg, ones 32]` at 32-byte windows. -/

/-- The five-segment list the H_msg precompile hashes. -/
private def hmsgSegs {m : Nat} (sig : ByteVec m) (pkSeed pkRoot msg : ByteVec 32) :
    List (ByteVec 32) :=
  [pkSeed, pkRoot, ByteVec.pad16 (ByteVec.loadValue16 sig 0), msg, ByteVec.ones 32]

/-- Partial memories after each successive H_msg store (innermost first). -/
private def hmsgM0 (mem : ByteMemory) (pkSeed : ByteVec 32) : ByteMemory :=
  mstore32 mem 0x00 (wordOf pkSeed)
private def hmsgM1 (mem : ByteMemory) (pkSeed pkRoot : ByteVec 32) : ByteMemory :=
  mstore32 (hmsgM0 mem pkSeed) 0x20 (wordOf pkRoot)
private def hmsgM2 {m : Nat} (mem : ByteMemory) (sig : ByteVec m) (pkSeed pkRoot : ByteVec 32) :
    ByteMemory :=
  mstore32 (hmsgM1 mem pkSeed pkRoot) 0x40 (calldataload sig 0 &&& NMASK)
private def hmsgM3 {m : Nat} (mem : ByteMemory) (sig : ByteVec m) (pkSeed pkRoot msg : ByteVec 32) :
    ByteMemory :=
  mstore32 (hmsgM2 mem sig pkSeed pkRoot) 0x60 (wordOf msg)
/-- The memory after the five H_msg `mstore`s. -/
private def hmsgMem5 {m : Nat} (mem : ByteMemory) (sig : ByteVec m) (pkSeed pkRoot msg : ByteVec 32) :
    ByteMemory :=
  mstore32 (hmsgM3 mem sig pkSeed pkRoot msg) 0x80
    0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF

/-- **Holds the segments.** The assembled scratch memory holds the five H_msg
    segments at consecutive 32-byte windows from base `0`.

    The conclusion is stated about the **raw** nested `mstore32` term (with the
    normalized numerals `0/32/64/96/128`) — exactly the shape the stepped
    `execList` leaves in the goal — so the main theorem can apply it by a single
    syntactic `rw` (never touching/forcing `c10Oracle`). -/
private theorem hmsgMem5_holdsSegs {m : Nat} (mem : ByteMemory)
    (sig : ByteVec m) (pkSeed pkRoot msg : ByteVec 32) :
    holdsSegs (mstore32 (mstore32 (mstore32 (mstore32 (mstore32 mem 0 (wordOf pkSeed))
        32 (wordOf pkRoot)) 64 (calldataload sig 0 &&& NMASK)) 96 (wordOf msg))
        128 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF) 0
      (hmsgSegs sig pkSeed pkRoot msg) := by
  -- fold the raw term into `hmsgMem5` (cheap defeq, no `c10Oracle` in scope here)
  show holdsSegs (hmsgMem5 mem sig pkSeed pkRoot msg) 0 (hmsgSegs sig pkSeed pkRoot msg)
  intro j i hj hi
  -- segs.length = 5
  have hjlt : j < 5 := by simpa [hmsgSegs] using hj
  rw [Nat.zero_add]
  unfold hmsgMem5
  -- dispatch on the window index j; at each window peel the later (disjoint) stores
  -- via `mstore32_frame`, then read the matching store via `mstore32_get`.
  match j, hjlt with
  | 0, _ =>
      rw [mstore32_frame (hmsgM3 mem sig pkSeed pkRoot msg) 0x80 _ (32 * 0 + i) (by omega)]
      unfold hmsgM3
      rw [mstore32_frame (hmsgM2 mem sig pkSeed pkRoot) 0x60 (wordOf msg) (32 * 0 + i) (by omega)]
      unfold hmsgM2
      rw [mstore32_frame (hmsgM1 mem pkSeed pkRoot) 0x40 (calldataload sig 0 &&& NMASK)
        (32 * 0 + i) (by omega)]
      unfold hmsgM1
      rw [mstore32_frame (hmsgM0 mem pkSeed) 0x20 (wordOf pkRoot) (32 * 0 + i) (by omega)]
      unfold hmsgM0
      have e00 := mstore32_get mem 0x00 (wordOf pkSeed) i hi
      rw [show (32 * 0 + i) = (0x00 + i) by omega, e00, beByte_wordOf_getD pkSeed i hi]
      rfl
  | 1, _ =>
      rw [mstore32_frame (hmsgM3 mem sig pkSeed pkRoot msg) 0x80 _ (32 * 1 + i) (by omega)]
      unfold hmsgM3
      rw [mstore32_frame (hmsgM2 mem sig pkSeed pkRoot) 0x60 (wordOf msg) (32 * 1 + i) (by omega)]
      unfold hmsgM2
      rw [mstore32_frame (hmsgM1 mem pkSeed pkRoot) 0x40 (calldataload sig 0 &&& NMASK)
        (32 * 1 + i) (by omega)]
      unfold hmsgM1
      have e20 := mstore32_get (hmsgM0 mem pkSeed) 0x20 (wordOf pkRoot) i hi
      rw [show (32 * 1 + i) = (0x20 + i) by omega, e20, beByte_wordOf_getD pkRoot i hi]
      rfl
  | 2, _ =>
      rw [mstore32_frame (hmsgM3 mem sig pkSeed pkRoot msg) 0x80 _ (32 * 2 + i) (by omega)]
      unfold hmsgM3
      rw [mstore32_frame (hmsgM2 mem sig pkSeed pkRoot) 0x60 (wordOf msg) (32 * 2 + i) (by omega)]
      unfold hmsgM2
      have e40 := mstore32_get (hmsgM1 mem pkSeed pkRoot) 0x40 (calldataload sig 0 &&& NMASK) i hi
      rw [show (32 * 2 + i) = (0x40 + i) by omega, e40, R_beByte_eq sig i hi]
      rfl
  | 3, _ =>
      rw [mstore32_frame (hmsgM3 mem sig pkSeed pkRoot msg) 0x80 _ (32 * 3 + i) (by omega)]
      unfold hmsgM3
      have e60 := mstore32_get (hmsgM2 mem sig pkSeed pkRoot) 0x60 (wordOf msg) i hi
      rw [show (32 * 3 + i) = (0x60 + i) by omega, e60, beByte_wordOf_getD msg i hi]
      rfl
  | 4, _ =>
      have e80 := mstore32_get (hmsgM3 mem sig pkSeed pkRoot msg) 0x80
        0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF i hi
      rw [show (32 * 4 + i) = (0x80 + i) by omega, e80, allFF_beByte_eq i hi]
      rfl

/-! ## Stepping the fragment

A helper that peels one non-halting statement off `execList`. -/

/-- Peel a non-halting head statement off `execList`. -/
private theorem execList_cons_none {n : Nat} (sha : List UInt8 → ByteVec 32)
    (sig : ByteVec n) (s : Stmt) (rest : List Stmt) (vm : VM)
    (h : (execStmt sha sig s vm).2 = none) :
    execList sha sig (s :: rest) vm = execList sha sig rest (execStmt sha sig s vm).1 := by
  rw [execList]
  cases hs : execStmt sha sig s vm with
  | mk vm' o =>
    cases o with
    | none => rfl
    | some hh => rw [hs] at h; exact absurd h (by simp)

/-! ## The main theorem -/

-- Seal `c10Oracle` so `isDefEq` on `c10Oracle X =?= c10Oracle Y` is forced into structural
-- congruence (`X =?= Y`) rather than delta-unfolding to the 64-round SHA-256 body over a
-- symbolic 160-byte slice (which heartbeat-dies).  This lets the `.trans` LHS-unification
-- below cheaply reconcile the goal's unreduced-`setVar` memory with the clean `hmsgMem5`
-- form, and `160 ≡ 32*5`, WITHOUT ever computing a concrete hash.  Adds no axioms.
attribute [local irreducible] c10Oracle

-- The `.trans` congruence whnf-reduces the deep (but bounded) `setVar`/`mstore32` chains.
set_option maxRecDepth 4000 in
set_option maxHeartbeats 1000000 in

/-- **H_msg phase refinement.** Running the H_msg fragment from a VM whose
    environment supplies `pkSeed`/`pkRoot`/`message` as `wordOf`-words, `N_MASK`,
    and `OUT = 0x600`, falls through (`.2 = none`) and binds `"digest"` to the
    `wordOf` of the declarative `Spec.hMsg` digest. -/
theorem hmsg_digest
    (sig : ByteVec Spec.SignatureLen) (vm : VM)
    (pkSeed pkRoot msg : ByteVec 32)
    (hShapeS : pkSeed = ByteVec.pad16 (pkSeed.take 16 (by decide)))
    (hShapeR : pkRoot = ByteVec.pad16 (pkRoot.take 16 (by decide)))
    (hpkSeed : vm.env "pkSeed" = wordOf pkSeed)
    (hpkRoot : vm.env "pkRoot" = wordOf pkRoot)
    (hmessage : vm.env "message" = wordOf msg)
    (hNMASK : vm.env "N_MASK" = NMASK)
    (hOUT : vm.env "OUT" = 0x600) :
    (execList c10Oracle sig hmsgFragment vm).2 = none
    ∧ ((execList c10Oracle sig hmsgFragment vm).1).env "digest"
        = wordOf (Spec.hMsg pkSeed pkRoot (ByteVec.pad16 (ByteVec.loadValue16 sig 0)) msg) := by
  -- Step the 10 statements, threading the env/mem updates.
  -- We compute the final state explicitly via repeated `execList_cons_none`.
  unfold hmsgFragment
  -- Statement 1: letv "seed" := pkSeed
  rw [execList_cons_none c10Oracle sig _ _ vm (by simp only [execStmt])]
  -- Statement 2: letv "root" := pkRoot
  rw [execList_cons_none c10Oracle sig _ _ _ (by simp only [execStmt])]
  -- Statement 3: mstore 0x00 seed
  rw [execList_cons_none c10Oracle sig _ _ _ (by simp only [execStmt])]
  -- Statement 4: letv "R" := calldataload(sig.offset) & N_MASK
  rw [execList_cons_none c10Oracle sig _ _ _ (by simp only [execStmt])]
  -- Statement 5: mstore 0x20 root
  rw [execList_cons_none c10Oracle sig _ _ _ (by simp only [execStmt])]
  -- Statement 6: mstore 0x40 R
  rw [execList_cons_none c10Oracle sig _ _ _ (by simp only [execStmt])]
  -- Statement 7: mstore 0x60 message
  rw [execList_cons_none c10Oracle sig _ _ _ (by simp only [execStmt])]
  -- Statement 8: mstore 0x80 ALLFF
  rw [execList_cons_none c10Oracle sig _ _ _ (by simp only [execStmt])]
  -- Statement 9: sha256(0x00, 0xA0, OUT)
  rw [execList_cons_none c10Oracle sig _ _ _ (by simp only [execStmt])]
  -- Statement 10: letv "digest" := mload(OUT)
  rw [execList_cons_none c10Oracle sig _ _ _ (by simp only [execStmt])]
  -- Now an empty list: execList … [] vm_final = (vm_final, none)
  rw [execList]
  -- Split the conjunction; .2 = none is `rfl`.
  refine ⟨rfl, ?_⟩
  -- Evaluate the env "digest" lookup.  The whole chain of execStmt .1's was a fold
  -- of letv / mstore / sha256 updates.  Unfold execStmt + eval everywhere, resolving
  -- the env reads with the simp lemmas + the hypotheses.
  -- Unfold `setVar` so simp's built-in `String` literal simprocs + `if`-reduction fully
  -- resolve every env read — including those buried inside the `mstore32` stored-word
  -- arguments — leaving the memory in the clean `mstore32 vm.mem 0 (wordOf pkSeed) …` form
  -- (NOT the unreduced `setVar … "seed"` chains).  This is what lets the downstream
  -- `c10Oracle_holdsSegs` `rw` match syntactically.
  simp only [execStmt, eval, setVar, hpkSeed, hpkRoot, hmessage, hNMASK, hOUT,
    ite_true, ite_false, String.reduceEq]
  -- Goal: mload32 memF 0x600 = wordOf (hMsg …)
  -- where memF is the sha256 writeRegion over mem5 (the 5 mstores) at outOff (=0x600).
  -- First, characterise the digest the precompile wrote.
  -- The precompile reads slice mem5 0x00 0xA0 and writes it at 0x600.
  -- env "digest" reduces to mload32 (writeRegion mem5 0x600 (fun i => dig.data.getD i 0)) 0x600
  -- with dig = c10Oracle (slice mem5 0 0xA0).
  -- Rewrite the digest readback to `wordOf dig`.
  rw [mload32_writeRegion_digest]
  -- Now goal: wordOf (c10Oracle (slice RAW 0 160)) = wordOf (hMsg …).
  -- Peel `wordOf` by congruence, then apply the oracle↔spec bridge as a `.trans` chain.
  -- With `c10Oracle` sealed, `.trans`'s LHS-unification reconciles the bridge's clean
  -- `hmsgMem5` / `32*5` form (inferred from `hmsgMem5_holdsSegs`'s type) with the goal's
  -- unreduced-`setVar` / `160` form by cheap structural congruence — no SHA computation.
  congr 1
  refine (c10Oracle_holdsSegs _ 0 (hmsgSegs sig pkSeed pkRoot msg)
    (hmsgMem5_holdsSegs vm.mem sig pkSeed pkRoot msg)).trans ?_
  -- Leftover: Spec.sha256 (segs.map ofByteVec) = hMsg … — both are `Spec.sha256` of the
  -- same explicit 5-segment list, so this closes by congruence on the `hMsg` definition.
  unfold hmsgSegs Spec.hMsg
  rfl

/-! ## FORS tree Merkle-climb refinement

The hardest C10 phase: one FORS tree's auth-path climb (`SPHINCsC10Asm.sol` L109–120,
the inner `for h in 11`). The interpreter walks A=11 levels, each a masked 4-segment
`th_pair` over `[seed, adrs, left, right]` (the branchless Merkle swap puts
`node`/`sibling` into `left`/`right` by `pathIdx`'s parity); the spec is
`Spec.Fors.reconstructRoot`'s `for h in [:A]` loop.

We prove the **climb core** (the task's recommended sound scoping): given a leaf
node word + leaf index in the env and the auth siblings in calldata, the `h`-loop
yields the masked `wordOf (pad16 …)` of `reconstructRoot`'s fold result.

The development is in three layers:
  1. word-level glue: word ↔ byte extensionality, the `mload32` bound, and the
     **reusable masked-oracle helper** `mload_masked_eq_wordOf_pad16` (recurs at
     every C10 masked hash site — FORS leaf/node, Merkle node, WOTS chain, …);
  2. the `forIn → foldl` bridge for `reconstructRoot` (`reconstructRoot_eq_foldl`);
  3. the per-step memory characterisation + the `execFor_invariant` climb.
-/

/-! ### Layer 1 — word/byte glue + the masked-oracle helper -/

/-- **Word digit-extensionality.** Two words `< 2^256` agreeing on all 32 big-endian
    base-256 digits are equal. (The big-endian byte is `(w >>> (8*(31-i))) % 256`.)
    Proved bitwise via `Nat.eq_of_testBit_eq`: every bit `< 256` lies in some byte. -/
theorem eq_of_digits (a b : Nat) (ha : a < 2 ^ 256) (hb : b < 2 ^ 256)
    (h : ∀ i, i < 32 → (a >>> (8 * (31 - i))) % 256 = (b >>> (8 * (31 - i))) % 256) :
    a = b := by
  apply Nat.eq_of_testBit_eq
  intro k
  by_cases hk : k < 256
  · have hbyte := h (31 - k / 8) (by omega)
    have hkey : 8 * (31 - (31 - k / 8)) = 8 * (k / 8) := by omega
    rw [hkey] at hbyte
    have e1 : a.testBit k = ((a >>> (8 * (k / 8))) % 256).testBit (k % 8) := by
      rw [show (256 : Nat) = 2 ^ 8 from rfl, Nat.testBit_mod_two_pow, Nat.testBit_shiftRight]
      have hsum : 8 * (k / 8) + k % 8 = k := by omega
      rw [hsum, decide_eq_true (show k % 8 < 8 by omega), Bool.true_and]
    have e2 : b.testBit k = ((b >>> (8 * (k / 8))) % 256).testBit (k % 8) := by
      rw [show (256 : Nat) = 2 ^ 8 from rfl, Nat.testBit_mod_two_pow, Nat.testBit_shiftRight]
      have hsum : 8 * (k / 8) + k % 8 = k := by omega
      rw [hsum, decide_eq_true (show k % 8 < 8 by omega), Bool.true_and]
    rw [e1, e2, hbyte]
  · have hpk : (2 : Nat) ^ 256 ≤ 2 ^ k := Nat.pow_le_pow_right (by decide) (by omega)
    rw [Nat.testBit_lt_two_pow (Nat.lt_of_lt_of_le ha hpk),
        Nat.testBit_lt_two_pow (Nat.lt_of_lt_of_le hb hpk)]

/-- `(beByte w i).toNat` is the `i`-th big-endian base-256 digit of `w`. -/
private theorem beByte_toNat' (w i : Nat) :
    (beByte w i).toNat = (w >>> (8 * (31 - i))) % 256 := by
  unfold beByte; rw [UInt8.toNat_ofNat']; omega

/-- **Word byte-extensionality.** Two words `< 2^256` with equal big-endian bytes
    (`beByte`) for every `i < 32` are equal. The `beByte`-phrasing of `eq_of_digits`. -/
theorem eq_of_beByte (a b : Nat) (ha : a < 2 ^ 256) (hb : b < 2 ^ 256)
    (h : ∀ i, i < 32 → beByte a i = beByte b i) : a = b := by
  apply eq_of_digits a b ha hb
  intro i hi
  have hcong := congrArg UInt8.toNat (h i hi)
  rw [beByte_toNat', beByte_toNat'] at hcong
  exact hcong

/-- A 32-step base-256 big-endian fold of bytes (`< 256` each) is `< 256^32 = 2^256`. -/
private theorem foldl_byte_lt (g : Nat → Nat) (hg : ∀ i, g i < 256) :
    ∀ k, (List.range k).foldl (fun acc i => acc * 256 + g i) 0 < 256 ^ k := by
  intro k
  induction k with
  | zero => simp
  | succ j ih =>
      rw [List.range_succ, List.foldl_append]
      simp only [List.foldl_cons, List.foldl_nil]
      have hgj := hg j
      rw [Nat.pow_succ]
      calc (List.range j).foldl (fun acc i => acc * 256 + g i) 0 * 256 + g j
          < (List.range j).foldl (fun acc i => acc * 256 + g i) 0 * 256 + 256 := by omega
        _ ≤ 256 ^ j * 256 := by
            have hle : (List.range j).foldl (fun acc i => acc * 256 + g i) 0 + 1 ≤ 256 ^ j := by
              omega
            calc (List.range j).foldl (fun acc i => acc * 256 + g i) 0 * 256 + 256
                = ((List.range j).foldl (fun acc i => acc * 256 + g i) 0 + 1) * 256 := by
                    rw [Nat.add_mul, Nat.one_mul]
              _ ≤ 256 ^ j * 256 := Nat.mul_le_mul_right 256 hle

/-- `mload32` of any window is a 256-bit word. -/
theorem mload32_lt (mem : ByteMemory) (off : Nat) : mload32 mem off < 2 ^ 256 := by
  unfold mload32
  have h := foldl_byte_lt (fun i => (mem (off + i)).toNat) (fun i => (mem (off + i)).toNat_lt) 32
  have he : (256 : Nat) ^ 32 = 2 ^ 256 := by rw [show (256 : Nat) = 2 ^ 8 from rfl, ← Nat.pow_mul]
  rwa [he] at h

/-- `wordOf v < 2^256`. -/
theorem wordOf_lt (v : ByteVec 32) : wordOf v < 2 ^ 256 := mload32_lt _ _

/-- `truncate16 d`'s `i`-th byte (`i < 16`) is `d`'s `i`-th byte. -/
private theorem truncate16_data_getD (d : ByteVec 32) (i : Nat) (hi : i < 16) :
    (ByteVec.truncate16 d).data.getD i 0 = d.data.getD i 0 := by
  unfold ByteVec.truncate16 ByteVec.take
  rw [Array.getD_eq_getD_getElem?, Array.getElem?_extract]
  have hdsz : d.data.size = 32 := d.size_eq
  rw [hdsz, if_pos (show i < min 16 32 - 0 by omega), Nat.zero_add,
      ← Array.getD_eq_getD_getElem?]

/-- `(pad16 (truncate16 d))`'s `i`-th byte: `d`'s byte for `i < 16`, else `0`. -/
private theorem pad16tr_getD (d : ByteVec 32) (i : Nat) :
    (ByteVec.pad16 (ByteVec.truncate16 d)).data.getD i 0
      = if i < 16 then d.data.getD i 0 else 0 := by
  have hdata : (ByteVec.pad16 (ByteVec.truncate16 d)).data
      = (ByteVec.truncate16 d).data ++ Array.replicate 16 (0 : UInt8) := rfl
  rw [hdata, Array.getD_eq_getD_getElem?, Array.getElem?_append]
  have htsz : (ByteVec.truncate16 d).data.size = 16 := (ByteVec.truncate16 d).size_eq
  rw [htsz]
  by_cases hi : i < 16
  · rw [if_pos hi, if_pos hi, ← Array.getD_eq_getD_getElem?, truncate16_data_getD d i hi]
  · rw [if_neg hi, if_neg hi, Array.getElem?_replicate]
    by_cases hr : i - 16 < 16
    · rw [if_pos hr, Option.getD_some]
    · rw [if_neg hr, Option.getD_none]

/-- **The reusable masked-oracle helper.** After the `0x02` precompile writes digest
    `d` at `off`, the verifier's `and(mload off, N_MASK)` (as a `Nat`) equals
    `wordOf (pad16 (truncate16 d))` — the big-endian word of the top-16-bytes-kept
    digest. Since every C10 tweakable hash (`th`, `thPair`, `thMulti`) is
    `truncate16 (sha256 …)`, this turns each masked hash site directly into the
    `wordOf (pad16 (spec-th-value))` the next climb step consumes. Recurs at the
    FORS leaf, every Merkle node, the last tree, WOTS chains, and all compressions. -/
theorem mload_masked_eq_wordOf_pad16 (mem : ByteMemory) (off : Nat) (d : ByteVec 32) :
    (mload32 (writeRegion mem off (fun i => d.data.getD i 0)) off) &&& NMASK
      = wordOf (ByteVec.pad16 (ByteVec.truncate16 d)) := by
  rw [mload32_writeRegion_digest mem off d]
  apply eq_of_beByte
  · exact Nat.lt_of_le_of_lt Nat.and_le_left (wordOf_lt d)
  · exact wordOf_lt _
  · intro i hi
    rw [beByte_and_nmask, beByte_wordOf_getD (ByteVec.pad16 (ByteVec.truncate16 d)) i hi,
        pad16tr_getD d i]
    by_cases h16 : i < 16
    · rw [if_pos h16, if_pos h16, beByte_wordOf_getD d i hi]
    · rw [if_neg h16, if_neg h16]

/-! ### Layer 2 — `reconstructRoot`'s `forIn` loop as a `List.foldl`

`Spec.Fors.reconstructRoot` is an `Id.run do … for h in [:A] do …; pure node`,
threading BOTH the running `node` and `pathIdx` (a `MProd`). We expose it as a
fold over `List.range' 0 A` whose accumulator is exactly that pair, so the
interpreter climb (`execFor_invariant`, which also threads `node`/`pathIdx`) can be
matched fold-step against spec-step. -/

/-- One step of `reconstructRoot`'s loop body, factored out of the `forIn` (the
    branchless Merkle swap on `pathIdx`'s parity). Accumulator is `⟨node, pathIdx⟩`. -/
def forsStep (seed : ByteVec 32) (htIdx : UInt64) (treeIdx : UInt32)
    (authPath : Array (ByteVec 16)) (acc : MProd (ByteVec 16) Nat) (h : Nat) :
    MProd (ByteVec 16) Nat :=
  let node := acc.fst
  let pathIdx := acc.snd
  let parentIdx := pathIdx / 2
  let adrs := Spec.Adrs.forsNode htIdx treeIdx (UInt32.ofNat (h + 1)) (UInt32.ofNat parentIdx)
  let sibling := authPath.getD h (ByteVec.zero 16)
  if pathIdx % 2 == 0 then
    ⟨Spec.thPair seed adrs (ByteVec.pad16 node) (ByteVec.pad16 sibling), parentIdx⟩
  else
    ⟨Spec.thPair seed adrs (ByteVec.pad16 sibling) (ByteVec.pad16 node), parentIdx⟩

/-- **`reconstructRoot` as a fold.** The spec FORS-tree root reconstruction is the
    first component of folding `forsStep` over `[0, A)` from the leaf seed
    `⟨th seed leafAdrs (pad16 secret), leafIdx.toNat⟩`. The `forIn → foldl` collapse:
    `Std.Range.forIn_eq_forIn_range'` turns `[:A]` into `List.range' 0 A 1`, the
    `do`/`pure` noise simps away (`Id.run`), the body's inner `if` is hoisted out of
    `ForInStep.yield` (`apply_ite`), and `List.forIn_pure_yield_eq_foldl` collapses
    the `Id` `forIn` to `List.foldl`. -/
theorem reconstructRoot_eq_foldl
    (seed : ByteVec 32) (htIdx : UInt64) (treeIdx leafIdx : UInt32)
    (secret : ByteVec 16) (authPath : Array (ByteVec 16)) :
    Spec.Fors.reconstructRoot seed htIdx treeIdx leafIdx secret authPath
      = ((List.range' 0 Spec.A).foldl (forsStep seed htIdx treeIdx authPath)
          ⟨Spec.th seed (Spec.Adrs.forsNode htIdx treeIdx 0 leafIdx) (ByteVec.pad16 secret),
            leafIdx.toNat⟩).fst := by
  rw [Spec.Fors.reconstructRoot]
  set_option linter.deprecated false in
  simp only [Std.Range.forIn_eq_forIn_range', Std.Range.size, Nat.sub_zero, Nat.add_sub_cancel,
    Nat.div_one, Id.run, Id.bind_eq, Id.pure_eq]
  rw [show (fun (h : Nat) (r : MProd (ByteVec 16) Nat) =>
        (if (r.snd % 2 == 0) = true then
            ForInStep.yield (⟨Spec.thPair seed (Spec.Adrs.forsNode htIdx treeIdx (UInt32.ofNat (h + 1))
                  (UInt32.ofNat (r.snd / 2))) r.fst.pad16 (authPath.getD h (ByteVec.zero 16)).pad16,
                r.snd / 2⟩ : MProd (ByteVec 16) Nat)
          else
            ForInStep.yield ⟨Spec.thPair seed (Spec.Adrs.forsNode htIdx treeIdx (UInt32.ofNat (h + 1))
                  (UInt32.ofNat (r.snd / 2))) (authPath.getD h (ByteVec.zero 16)).pad16 r.fst.pad16,
                r.snd / 2⟩))
      = (fun (h : Nat) (r : MProd (ByteVec 16) Nat) =>
          pure (f := Id) (ForInStep.yield (forsStep seed htIdx treeIdx authPath r h))) from by
        funext h r
        show _ = ForInStep.yield (forsStep seed htIdx treeIdx authPath r h)
        unfold forsStep
        rw [apply_ite ForInStep.yield]]
  rw [List.forIn_pure_yield_eq_foldl]
  rfl

/-! ### Layer 3 — the interpreter inner climb body -/

/-- The FORS-tree inner Merkle-climb body (`SPHINCsC10Asm.sol` L109–120), written
    with raw constructors so it is defeq to the corresponding slice of `c10Program`'s
    inner `forRange "h" (lit 11)`. One auth-path level: load+mask sibling, halve
    `pathIdx`, store the node ADRS at `0x20`, branchless-swap node/sibling into the
    `0x40`/`0x60` windows, hash the 4-segment `[seed,adrs,left,right]` pair, mask the
    digest into `node`, advance `pathIdx`. -/
def forsClimbBody : List Stmt :=
  [ .letv "sibling" (.bin .band (.calldataload (.bin .add (.var "authPtr")
        (.bin .shl (.lit 4) (.var "h")))) (.var "N_MASK"))
  , .letv "parentIdx" (.bin .shr (.lit 1) (.var "pathIdx"))
  , .mstore (.lit 0x20)
      (.bin .bor (.var "treeAdrsBase")
        (.bin .bor (.bin .shl (.lit 32) (.bin .add (.var "h") (.lit 1))) (.var "parentIdx")))
  , .letv "s" (.bin .shl (.lit 5) (.bin .band (.var "pathIdx") (.lit 1)))
  , .mstore (.bin .bxor (.lit 0x40) (.var "s")) (.var "node")
  , .mstore (.bin .bxor (.lit 0x60) (.var "s")) (.var "sibling")
  , .sha256 (.lit 0x00) (.lit 0x80) (.var "OUT")
  , .setv "node" (.bin .band (.mload (.var "OUT")) (.var "N_MASK"))
  , .setv "pathIdx" (.var "parentIdx") ]

/-! ### Layer 3 — branchless-swap parity arithmetic

The Yul `s := (pathIdx & 1) << 5`, then `mstore(0x40 ^ s, node)` / `mstore(0x60 ^ s,
sibling)`. With `p & 1 ∈ {0,1}`, `s ∈ {0, 0x20}`, so the two store windows are
`{0x40, 0x60}` in node/sibling order for even `p` and sibling/node order for odd `p`
— exactly `forsStep`'s two `thPair`-argument orders. -/

/-- `(p &&& 1) <<< 5 % W` is `0` when `p` even, `32` when `p` odd. -/
private theorem s_value (p : Nat) :
    (p &&& 1) <<< 5 % W = if p % 2 == 0 then 0 else 32 := by
  rw [Nat.and_one_is_mod]
  have h2 : p % 2 = 0 ∨ p % 2 = 1 := Nat.mod_two_eq_zero_or_one p
  rcases h2 with h | h
  · rw [h]; rfl
  · rw [h]; rfl

/-! ### Layer 3 — the canonical 4-window `holdsSegs`

After the three climb stores (commuted to canonical offsets `32/64/96`), scratch
`[0x00, 0x80)` holds the four `thPair` segments `[seed, adrs, left, right]` at
consecutive 32-byte windows — provided `mem` already holds `seed` at window `0`
(it persists from H_msg; the climb stores all land at `≥ 0x20`). -/

/-- The four-segment list the climb precompile hashes (a `thPair` input). -/
private def climbSegs (seed adrs left right : ByteVec 32) : List (ByteVec 32) :=
  [seed, adrs, left, right]

/-- **Holds the climb segments.** With `seed` already in window `0` of `mem` and the
    three stores laid at the canonical `32/64/96` windows as `wordOf`-words, scratch
    `[0x00, 0x80)` holds `[seed, adrs, left, right]`. The `hmsgMem5_holdsSegs`
    analogue for the 4-segment `thPair`. -/
private theorem climbMem_holdsSegs (mem : ByteMemory)
    (seed adrs left right : ByteVec 32)
    (hseed : ∀ i, i < 32 → mem (0 + i) = seed.data.getD i 0) :
    holdsSegs (mstore32 (mstore32 (mstore32 mem 32 (wordOf adrs))
        64 (wordOf left)) 96 (wordOf right)) 0
      (climbSegs seed adrs left right) := by
  intro j i hj hi
  have hjlt : j < 4 := by simpa [climbSegs] using hj
  rw [Nat.zero_add]
  match j, hjlt with
  | 0, _ =>
      rw [mstore32_frame _ 96 (wordOf right) (32 * 0 + i) (by omega),
          mstore32_frame _ 64 (wordOf left) (32 * 0 + i) (by omega),
          mstore32_frame _ 32 (wordOf adrs) (32 * 0 + i) (by omega)]
      rw [show (32 * 0 + i) = (0 + i) by omega, hseed i hi]
      rfl
  | 1, _ =>
      rw [mstore32_frame _ 96 (wordOf right) (32 * 1 + i) (by omega),
          mstore32_frame _ 64 (wordOf left) (32 * 1 + i) (by omega)]
      have e := mstore32_get mem 32 (wordOf adrs) i hi
      rw [show (32 * 1 + i) = (32 + i) by omega, e, beByte_wordOf_getD adrs i hi]
      rfl
  | 2, _ =>
      rw [mstore32_frame _ 96 (wordOf right) (32 * 2 + i) (by omega)]
      have e := mstore32_get (mstore32 mem 32 (wordOf adrs)) 64 (wordOf left) i hi
      rw [show (32 * 2 + i) = (64 + i) by omega, e, beByte_wordOf_getD left i hi]
      rfl
  | 3, _ =>
      have e := mstore32_get (mstore32 (mstore32 mem 32 (wordOf adrs)) 64 (wordOf left))
        96 (wordOf right) i hi
      rw [show (32 * 3 + i) = (96 + i) by omega, e, beByte_wordOf_getD right i hi]
      rfl

/-- **One climb hash step ↔ `thPair`.** Running the precompile over the canonical
    climb memory and masking the digest yields exactly `wordOf (pad16 (thPair seed
    adrs left right))`. Combines `climbMem_holdsSegs` + `c10Oracle_holdsSegs` (input
    assembly) with `mload_masked_eq_wordOf_pad16` (output mask) and the spec identity
    `truncate16 (sha256 [seed,adrs,left,right]) = thPair …`. The 4-segment analogue
    of the H_msg digest read-back. -/
private theorem climbMem_thPair (mem : ByteMemory)
    (seed adrs left right : ByteVec 32)
    (hseed : ∀ i, i < 32 → mem (0 + i) = seed.data.getD i 0) :
    (mload32 (writeRegion
        (mstore32 (mstore32 (mstore32 mem 32 (wordOf adrs)) 64 (wordOf left)) 96 (wordOf right))
        0x600
        (fun i => (c10Oracle (slice
          (mstore32 (mstore32 (mstore32 mem 32 (wordOf adrs)) 64 (wordOf left)) 96 (wordOf right))
          0 128)).data.getD i 0)) 0x600) &&& NMASK
      = wordOf (ByteVec.pad16 (Spec.thPair seed (adrs : Spec.Adrs) left right)) := by
  -- mask the freshly-written digest into wordOf (pad16 (truncate16 dig))
  rw [mload_masked_eq_wordOf_pad16
        (mstore32 (mstore32 (mstore32 mem 32 (wordOf adrs)) 64 (wordOf left)) 96 (wordOf right))
        0x600
        (c10Oracle (slice
          (mstore32 (mstore32 (mstore32 mem 32 (wordOf adrs)) 64 (wordOf left)) 96 (wordOf right))
          0 128))]
  -- characterise the digest: c10Oracle (slice memC 0 128) = sha256 [seed,adrs,left,right]
  have hseg : c10Oracle (slice
        (mstore32 (mstore32 (mstore32 mem 32 (wordOf adrs)) 64 (wordOf left)) 96 (wordOf right))
        0 128)
      = Spec.sha256 ((climbSegs seed adrs left right).map Spec.ByteSeg.ofByteVec) := by
    have hlen : (climbSegs seed adrs left right).length = 4 := rfl
    have h := c10Oracle_holdsSegs
      (mstore32 (mstore32 (mstore32 mem 32 (wordOf adrs)) 64 (wordOf left)) 96 (wordOf right))
      0 (climbSegs seed adrs left right)
      (climbMem_holdsSegs mem seed adrs left right hseed)
    rw [hlen] at h
    exact h
  rw [hseg]
  -- truncate16 (sha256 [seed,adrs,left,right]) = thPair seed adrs left right (defeq)
  rfl

/-- Disjoint 32-byte `mstore32` writes commute. -/
private theorem mstore32_comm (mem : ByteMemory) (o1 o2 w1 w2 : Nat)
    (hdisj : o1 + 32 ≤ o2 ∨ o2 + 32 ≤ o1) :
    mstore32 (mstore32 mem o1 w1) o2 w2 = mstore32 (mstore32 mem o2 w2) o1 w1 :=
  writeRegion_comm mem o1 o2 (beByte w1) (beByte w2) hdisj

/-! ### Layer 3 — the FORS-tree Merkle-climb core

The reusable climb engine. The interpreter's inner `for h in 11` walk is refined
against `reconstructRoot`'s `forsStep` fold (Layer 2) via `execFor_invariant`. The
hypotheses `H_adrs` / `H_sib` factor out the two byte-layout facts that belong in the
*wrapper* (kept abstract here so this lemma is the pure loop-induction):

  * `H_adrs` — the interpreter's ADRS word `treeAdrsBase | ((h+1)<<32) | (p>>1)` is
    the big-endian word of the spec ADRS `Adrs.forsNode htIdx treeIdx (h+1) (p/2)`.
    Discharged in the wrapper from the `forsNode` byte→word layout (the deployed
    `or(shl(160,htIdx), or(shl(128,3), or(shl(96,leafTreeIdx), node)))` decomposition).
  * `H_sib` — the masked calldata sibling `calldataload(authPtr + h<<4) & N_MASK` is
    `wordOf (pad16 (authPath.getD h …))`. Discharged in the wrapper from
    `calldataload … &&& NMASK = wordOf (pad16 (loadValue16 …))` + the `authPaths`
    layout of `Spec.Signature.deserialise`.

Both are stated about the *actual* `eval` Nat-forms tied to the real env words
`treeAdrsBase` / `authPtr` / `N_MASK`, so the climb-core is genuinely load-bearing:
instantiate the leaf word + leaf index and the conclusion lands on
`wordOf (pad16 (reconstructRoot-fold …))` for a real `authPath`. -/

/-- The leaf accumulator `⟨th seed leafAdrs (pad16 secret), leafIdx⟩` that
    `reconstructRoot`'s fold (Layer 2) starts from. -/
def forsAccInit (seed : ByteVec 32) (htIdx : UInt64) (treeIdx leafIdx : UInt32)
    (secret : ByteVec 16) : MProd (ByteVec 16) Nat :=
  ⟨Spec.th seed (Spec.Adrs.forsNode htIdx treeIdx 0 leafIdx) (ByteVec.pad16 secret),
    leafIdx.toNat⟩

/-- The fold accumulator after `c` climb levels. A standalone `def` (not a proof-local
    `let`) so the kernel does not zeta-expand the `thPair`/`sha256`-laden body when
    reducing per-step goals. -/
def forsAcc (seed : ByteVec 32) (htIdx : UInt64) (treeIdx leafIdx : UInt32)
    (secret : ByteVec 16) (authPath : Array (ByteVec 16)) (c : Nat) : MProd (ByteVec 16) Nat :=
  (List.range' 0 c).foldl (forsStep seed htIdx treeIdx authPath)
    (forsAccInit seed htIdx treeIdx leafIdx secret)

/-- `forsAcc` at `0` is the leaf accumulator. -/
theorem forsAcc_zero (seed : ByteVec 32) (htIdx : UInt64) (treeIdx leafIdx : UInt32)
    (secret : ByteVec 16) (authPath : Array (ByteVec 16)) :
    forsAcc seed htIdx treeIdx leafIdx secret authPath 0
      = forsAccInit seed htIdx treeIdx leafIdx secret := rfl

/-- **`forsAcc` recursion.** One more climb level is one more `forsStep`. -/
theorem forsAcc_succ (seed : ByteVec 32) (htIdx : UInt64) (treeIdx leafIdx : UInt32)
    (secret : ByteVec 16) (authPath : Array (ByteVec 16)) (c : Nat) :
    forsAcc seed htIdx treeIdx leafIdx secret authPath (c + 1)
      = forsStep seed htIdx treeIdx authPath
          (forsAcc seed htIdx treeIdx leafIdx secret authPath c) c := by
  unfold forsAcc
  rw [List.range'_1_concat, List.foldl_append, Nat.zero_add]
  rfl

set_option maxHeartbeats 4000000 in
set_option maxRecDepth 4000 in
/-- **One climb level.** The `execFor_invariant` step: running `forsClimbBody` once
    from a VM satisfying the climb invariant `R cur` re-establishes `R (cur+1)`. This
    is where the genuine per-step refinement happens — branchless-swap parity, the
    4-window `thPair` memory assembly, and the masked-digest read-back all land on one
    `forsStep`. Factored out of `fors_climb` (and stated against the explicit `forsAcc`
    invariant) so the heavy `simp`/`whnf` work is isolated from the loop drive. -/
theorem fors_climb_step
    (sig : ByteVec Spec.SignatureLen)
    (seed : ByteVec 32) (htIdx : UInt64) (treeIdx leafIdx : UInt32)
    (secret : ByteVec 16) (authPath : Array (ByteVec 16)) (tBase auth : Nat)
    -- BOUNDED byte-layout obligations: the climb only runs for `h < A` and the
    -- running `pathIdx` stays `< 2^32` (it starts at a UInt32 leaf index and halves
    -- each level), so these are TRUE/dischargeable — not the prior unsatisfiable
    -- unbounded forms (which forced `p` unbounded and `h ≥ A`).
    (H_adrs : ∀ h, h < Spec.A → ∀ p, p < 2 ^ 32 →
        tBase ||| (((h + 1) % W) <<< 32 % W ||| p >>> 1)
        = wordOf (Spec.Adrs.forsNode htIdx treeIdx (UInt32.ofNat (h + 1)) (UInt32.ofNat (p / 2))))
    (H_sib : ∀ h, h < Spec.A → calldataload sig ((auth + h <<< 4 % W) % W) &&& NMASK
        = wordOf (ByteVec.pad16 (authPath.getD h (ByteVec.zero 16))))
    (cur : Nat) (hcur : cur < Spec.A) (w : VM)
    (hR : w.env "node"
            = wordOf (ByteVec.pad16 (forsAcc seed htIdx treeIdx leafIdx secret authPath cur).fst)
          ∧ w.env "pathIdx" = (forsAcc seed htIdx treeIdx leafIdx secret authPath cur).snd
          ∧ w.env "N_MASK" = NMASK ∧ w.env "OUT" = 0x600
          ∧ w.env "treeAdrsBase" = tBase ∧ w.env "authPtr" = auth
          ∧ (∀ i, i < 32 → w.mem (0 + i) = seed.data.getD i 0)
          ∧ (forsAcc seed htIdx treeIdx leafIdx secret authPath cur).snd < 2 ^ 32) :
    (execList c10Oracle sig forsClimbBody { w with env := setVar w.env "h" cur }).2 = none
    ∧ ((execList c10Oracle sig forsClimbBody { w with env := setVar w.env "h" cur }).1.env "node"
          = wordOf (ByteVec.pad16 (forsAcc seed htIdx treeIdx leafIdx secret authPath (cur + 1)).fst)
        ∧ (execList c10Oracle sig forsClimbBody { w with env := setVar w.env "h" cur }).1.env "pathIdx"
            = (forsAcc seed htIdx treeIdx leafIdx secret authPath (cur + 1)).snd
        ∧ (execList c10Oracle sig forsClimbBody { w with env := setVar w.env "h" cur }).1.env "N_MASK"
            = NMASK
        ∧ (execList c10Oracle sig forsClimbBody { w with env := setVar w.env "h" cur }).1.env "OUT"
            = 0x600
        ∧ (execList c10Oracle sig forsClimbBody { w with env := setVar w.env "h" cur }).1.env "treeAdrsBase"
            = tBase
        ∧ (execList c10Oracle sig forsClimbBody { w with env := setVar w.env "h" cur }).1.env "authPtr"
            = auth
        ∧ (∀ i, i < 32 →
            (execList c10Oracle sig forsClimbBody { w with env := setVar w.env "h" cur }).1.mem (0 + i)
              = seed.data.getD i 0)
        ∧ (forsAcc seed htIdx treeIdx leafIdx secret authPath (cur + 1)).snd < 2 ^ 32) := by
  obtain ⟨hRnode, hRpath, hRN, hROUT, hRtB, hRauth, hRseed, hRbound⟩ := hR
  unfold forsClimbBody
  rw [execList_cons_none c10Oracle sig _ _ _ (by simp only [execStmt])]
  rw [execList_cons_none c10Oracle sig _ _ _ (by simp only [execStmt])]
  rw [execList_cons_none c10Oracle sig _ _ _ (by simp only [execStmt])]
  rw [execList_cons_none c10Oracle sig _ _ _ (by simp only [execStmt])]
  rw [execList_cons_none c10Oracle sig _ _ _ (by simp only [execStmt])]
  rw [execList_cons_none c10Oracle sig _ _ _ (by simp only [execStmt])]
  rw [execList_cons_none c10Oracle sig _ _ _ (by simp only [execStmt])]
  rw [execList_cons_none c10Oracle sig _ _ _ (by simp only [execStmt])]
  rw [execList_cons_none c10Oracle sig _ _ _ (by simp only [execStmt])]
  rw [execList]
  refine ⟨rfl, ?_⟩
  -- Resolve env reads in the final state to clean Nat-forms.
  simp only [execStmt, eval, setVar, ite_true, ite_false, String.reduceEq,
    hRN, hROUT, hRtB, hRauth, hRnode, hRpath]
  -- one more climb level is one more forsStep
  rw [forsAcc_succ]
  -- Rewrite the adrs word and sibling word into their spec `wordOf` forms.
  -- `H_adrs`/`H_sib` are BOUNDED: supply `cur < A` (hcur) and the running pathIdx
  -- bound (`hRbound`), both in scope from the bounded engine + invariant.
  rw [H_adrs cur hcur (forsAcc seed htIdx treeIdx leafIdx secret authPath cur).snd hRbound,
      H_sib cur hcur]
  -- Resolve the parity `s` into {0, 32}.
  rw [s_value]
  refine ⟨?node, ?path, trivial, trivial, trivial, trivial, ?mem, ?bound⟩
  · -- node: parity-split the branchless swap, commute to canonical, apply climbMem_thPair.
    by_cases hpar : (forsAcc seed htIdx treeIdx leafIdx secret authPath cur).snd % 2 == 0
    · -- even: s = 0, stores at 64 (node) / 96 (sibling) → canonical
      rw [if_pos hpar]
      simp only [show (64 : Nat) ^^^ 0 = 64 from rfl, show (96 : Nat) ^^^ 0 = 96 from rfl]
      rw [climbMem_thPair w.mem seed _ _ _ hRseed]
      show _ = wordOf (ByteVec.pad16 (forsStep seed htIdx treeIdx authPath
        (forsAcc seed htIdx treeIdx leafIdx secret authPath cur) cur).fst)
      unfold forsStep
      rw [if_pos hpar]
    · -- odd: s = 32, stores at 96 (node) / 64 (sibling) → commute to canonical
      rw [if_neg hpar]
      simp only [show (64 : Nat) ^^^ 32 = 96 from rfl, show (96 : Nat) ^^^ 32 = 64 from rfl]
      rw [mstore32_comm _ 96 64 _ _ (by omega)]
      rw [climbMem_thPair w.mem seed _ _ _ hRseed]
      show _ = wordOf (ByteVec.pad16 (forsStep seed htIdx treeIdx authPath
        (forsAcc seed htIdx treeIdx leafIdx secret authPath cur) cur).fst)
      unfold forsStep
      rw [if_neg hpar]
  · -- pathIdx := parentIdx = pathIdx >>> 1 = p/2 = forsStep's snd
    show ((forsAcc seed htIdx treeIdx leafIdx secret authPath cur).snd >>> 1)
      = (forsStep seed htIdx treeIdx authPath
          (forsAcc seed htIdx treeIdx leafIdx secret authPath cur) cur).snd
    unfold forsStep
    rw [Nat.shiftRight_eq_div_pow, Nat.pow_one]
    simp only []
    split <;> rfl
  · -- mem window 0 = seed: all writes land at offset ≥ 32, frame through.
    intro i hi
    rw [writeRegion_frame _ _ _ (0 + i) (by omega)]
    by_cases hpar : (forsAcc seed htIdx treeIdx leafIdx secret authPath cur).snd % 2 == 0
    · rw [if_pos hpar]
      simp only [show (64 : Nat) ^^^ 0 = 64 from rfl, show (96 : Nat) ^^^ 0 = 96 from rfl]
      rw [mstore32_frame _ 96 _ (0 + i) (by omega), mstore32_frame _ 64 _ (0 + i) (by omega),
          mstore32_frame _ 32 _ (0 + i) (by omega)]
      exact hRseed i hi
    · rw [if_neg hpar]
      simp only [show (64 : Nat) ^^^ 32 = 96 from rfl, show (96 : Nat) ^^^ 32 = 64 from rfl]
      rw [mstore32_frame _ 64 _ (0 + i) (by omega), mstore32_frame _ 96 _ (0 + i) (by omega),
          mstore32_frame _ 32 _ (0 + i) (by omega)]
      exact hRseed i hi
  · -- pathIdx bound preserved: forsStep halves pathIdx (`.snd = p / 2 ≤ p < 2^32`).
    show (forsStep seed htIdx treeIdx authPath
        (forsAcc seed htIdx treeIdx leafIdx secret authPath cur) cur).snd < 2 ^ 32
    have hsnd : (forsStep seed htIdx treeIdx authPath
        (forsAcc seed htIdx treeIdx leafIdx secret authPath cur) cur).snd
        = (forsAcc seed htIdx treeIdx leafIdx secret authPath cur).snd / 2 := by
      unfold forsStep
      by_cases hp : (forsAcc seed htIdx treeIdx leafIdx secret authPath cur).snd % 2 == 0
      · rw [if_pos hp]
      · rw [if_neg hp]
    rw [hsnd]
    exact Nat.lt_of_le_of_lt (Nat.div_le_self _ 2) hRbound

set_option maxHeartbeats 2000000 in
set_option maxRecDepth 4000 in
/-- **FORS-tree climb core.** Running the A=11-level inner Merkle climb
    (`forsClimbBody`) from a VM whose env supplies the leaf `node` word, leaf
    `pathIdx`, the persisting consts (`N_MASK`, `treeAdrsBase`, `authPtr`), and whose
    scratch window `[0x00,0x20)` holds `seed`, falls through (`.2 = none`) and binds
    `"node"` to the masked `wordOf (pad16 …)` of `reconstructRoot`'s fold result —
    i.e. `wordOf (pad16 (reconstructRoot seed htIdx treeIdx leafIdx secret authPath))`. -/
theorem fors_climb
    (sig : ByteVec Spec.SignatureLen) (vm : VM)
    (seed : ByteVec 32) (htIdx : UInt64) (treeIdx leafIdx : UInt32)
    (secret : ByteVec 16) (authPath : Array (ByteVec 16))
    (tBase auth : Nat)
    -- env preconditions
    (hNMASK : vm.env "N_MASK" = NMASK)
    (hOUT : vm.env "OUT" = 0x600)
    (htBase : vm.env "treeAdrsBase" = tBase)
    (hAuth : vm.env "authPtr" = auth)
    (hnode : vm.env "node"
      = wordOf (ByteVec.pad16 (Spec.th seed (Spec.Adrs.forsNode htIdx treeIdx 0 leafIdx)
          (ByteVec.pad16 secret))))
    (hpath : vm.env "pathIdx" = leafIdx.toNat)
    (hseed : ∀ i, i < 32 → vm.mem (0 + i) = seed.data.getD i 0)
    -- BOUNDED byte-layout obligations (wrapper-discharged; satisfiable — see the
    -- bounded forms on `fors_climb_step`). The pathIdx bound the climb invariant
    -- carries is rooted at `leafIdx.toNat < 2^32` (free, `leafIdx : UInt32`) and is
    -- preserved by the per-level halving.
    (H_adrs : ∀ h, h < Spec.A → ∀ p, p < 2 ^ 32 →
        tBase ||| (((h + 1) % W) <<< 32 % W ||| p >>> 1)
        = wordOf (Spec.Adrs.forsNode htIdx treeIdx (UInt32.ofNat (h + 1)) (UInt32.ofNat (p / 2))))
    (H_sib : ∀ h, h < Spec.A → calldataload sig ((auth + h <<< 4 % W) % W) &&& NMASK
        = wordOf (ByteVec.pad16 (authPath.getD h (ByteVec.zero 16)))) :
    (execFor c10Oracle sig "h" forsClimbBody Spec.A 0 vm).2 = none
    ∧ ((execFor c10Oracle sig "h" forsClimbBody Spec.A 0 vm).1).env "node"
        = wordOf (ByteVec.pad16
            (Spec.Fors.reconstructRoot seed htIdx treeIdx leafIdx secret authPath))
    -- The seed scratch window persists across the whole climb (every store lands at ≥ 0x20),
    -- so the outer FORS i-loop's seed invariant carries to the next tree.
    ∧ (∀ i, i < 32 → ((execFor c10Oracle sig "h" forsClimbBody Spec.A 0 vm).1).mem (0 + i)
        = seed.data.getD i 0) := by
  -- The loop invariant: node/pathIdx track the spec fold; consts + seed persist;
  -- the running pathIdx stays `< 2^32` (the conjunct that makes the BOUNDED
  -- `H_adrs` dischargeable at every iteration).
  let R : Nat → VM → Prop := fun c w =>
    w.env "node" = wordOf (ByteVec.pad16 (forsAcc seed htIdx treeIdx leafIdx secret authPath c).fst)
    ∧ w.env "pathIdx" = (forsAcc seed htIdx treeIdx leafIdx secret authPath c).snd
    ∧ w.env "N_MASK" = NMASK ∧ w.env "OUT" = 0x600
    ∧ w.env "treeAdrsBase" = tBase ∧ w.env "authPtr" = auth
    ∧ (∀ i, i < 32 → w.mem (0 + i) = seed.data.getD i 0)
    ∧ (forsAcc seed htIdx treeIdx leafIdx secret authPath c).snd < 2 ^ 32
  -- The bounded step engine demands `cur < A` per iteration — exactly what
  -- `fors_climb_step` (bounded) consumes (`hcur`) alongside the invariant.
  have hstep : ∀ cur w, cur < Spec.A → R cur w →
      (execList c10Oracle sig forsClimbBody { w with env := setVar w.env "h" cur }).2 = none ∧
      R (cur + 1) (execList c10Oracle sig forsClimbBody { w with env := setVar w.env "h" cur }).1 :=
    fun cur w hcur hRcw =>
      fors_climb_step sig seed htIdx treeIdx leafIdx secret authPath tBase auth
        H_adrs H_sib cur hcur w hRcw
  -- R holds at entry (cur = 0): the empty fold is forsAccInit; the pathIdx bound is
  -- the leaf index `leafIdx.toNat < 2^32` (free, `leafIdx : UInt32`).
  have hR0 : R 0 vm := by
    refine ⟨?_, ?_, hNMASK, hOUT, htBase, hAuth, hseed, ?_⟩
    · show vm.env "node"
          = wordOf (ByteVec.pad16 (forsAcc seed htIdx treeIdx leafIdx secret authPath 0).fst)
      rw [hnode, forsAcc_zero]; rfl
    · show vm.env "pathIdx" = (forsAcc seed htIdx treeIdx leafIdx secret authPath 0).snd
      rw [hpath, forsAcc_zero]; rfl
    · show (forsAcc seed htIdx treeIdx leafIdx secret authPath 0).snd < 2 ^ 32
      rw [forsAcc_zero]; exact leafIdx.toNat_lt
  -- Drive the loop with the BOUNDED engine.
  have hloop := execFor_invariant_lt c10Oracle sig "h" forsClimbBody Spec.A R hstep vm hR0
  obtain ⟨hn, _, _, _, _, _, hmemfinal, _⟩ := hloop.2
  refine ⟨hloop.1, ?_, hmemfinal⟩
  -- The final node is wordOf (pad16 (acc A).fst); (acc A).fst = reconstructRoot via Layer 2.
  -- (`execFor_invariant_lt` re-establishes `R N`, so the index is `Spec.A` directly.)
  rw [hn]
  show wordOf (ByteVec.pad16 (forsAcc seed htIdx treeIdx leafIdx secret authPath Spec.A).fst) = _
  rw [reconstructRoot_eq_foldl]
  rfl

/-! ## FORS per-tree body refinement

The wrapper above (`fors_climb`) is the inner `for h in 11` climb. This section
refines the *whole* per-tree body of the outer `for i in 12` loop
(`SPHINCsC10Asm.sol` L90–122, the `forsTreeBody` below): compute the FORS leaf
(`th seed leafAdrs (pad16 secret)`), drive the climb, and store the resulting root
at `0x80 + 32*t`. It DISCHARGES `fors_climb`'s `H_sib` (the masked-calldata sibling
read) internally and FEEDS its remaining preconditions, leaving the two pure
byte-layout obligations — the leaf/node ADRS-word identities — and the
digest→leaf-index identity as wrapper hypotheses (the same factoring `fors_climb`
itself uses for `H_adrs`: the `make`/`wordOf` byte bridge and the `readBitsLe`↔
word-shift bridge are heavy and belong to the i-loop wrapper).

The development reuses the H_msg/climb glue (`mload_masked_eq_wordOf_pad16`,
`c10Oracle_holdsSegs`, `mstore32_get`/`_frame`) plus three small additions:
a generalised masked-calldata read-back (`cl_masked_eq_wordOf`), small-offset
arithmetic helpers, and the 3-segment `holdsSegs` for the leaf hash. -/

/-! ### Generalised masked-calldata read-back

`R_beByte_eq` was specialised to offset `0` (the H_msg `R`). The FORS secret and
the auth-path siblings are read at arbitrary offsets, so we lift it to any `off`:
`calldataload sig off &&& NMASK = wordOf (pad16 (loadValue16 sig off))`. -/

/-- `(loadValue16 sig off)`'s `i`-th byte (`i < 16`) equals `(loadWord32 sig off)`'s
    `i`-th byte — `loadValue16_data_getD` at an arbitrary offset. -/
private theorem loadValue16_data_getD_off {m : Nat} (sig : ByteVec m) (off i : Nat) (hi : i < 16) :
    (ByteVec.loadValue16 sig off).data.getD i 0 = (ByteVec.loadWord32 sig off).data.getD i 0 := by
  unfold ByteVec.loadValue16 ByteVec.take
  rw [Array.getD_eq_getD_getElem?, Array.getElem?_extract]
  have hwsz : (ByteVec.loadWord32 sig off).data.size = 32 := (ByteVec.loadWord32 sig off).size_eq
  rw [hwsz, if_pos (show i < min 16 32 - 0 by omega), Nat.zero_add, ← Array.getD_eq_getD_getElem?]

/-- **R-segment byte action at any offset.** The big-endian byte `i` of
    `(calldataload sig off) &&& NMASK` is the `i`-th byte of
    `pad16 (loadValue16 sig off)`. (`R_beByte_eq` generalised over `off`.) -/
private theorem cl_beByte_eq {m : Nat} (sig : ByteVec m) (off i : Nat) (hi : i < 32) :
    beByte (calldataload sig off &&& NMASK) i
      = (ByteVec.pad16 (ByteVec.loadValue16 sig off)).data.getD i 0 := by
  rw [beByte_and_nmask, pad16_data_getD]
  by_cases h16 : i < 16
  · rw [if_pos h16, if_pos h16, loadValue16_data_getD_off sig off i h16]
    unfold calldataload
    rw [wordOfBV_eq_wordOf]
    have := beByte_wordOf (ByteVec.loadWord32 sig off) ⟨i, hi⟩
    rw [this]
    unfold ByteVec.get
    rw [Array.getD_eq_getD_getElem?]
    have hsz : i < (ByteVec.loadWord32 sig off).data.size := by
      rw [(ByteVec.loadWord32 sig off).size_eq]; exact hi
    rw [Array.getElem?_eq_getElem hsz, Option.getD_some]
    rfl
  · rw [if_neg h16, if_neg h16]

/-- **Masked-calldata read-back as a word.** `(calldataload sig off) &&& NMASK`
    (as a `Nat`) equals the big-endian word of `pad16 (loadValue16 sig off)` — the
    N-masked top-16-bytes value the FORS body feeds as `secretVal` / `sibling`.
    The calldata analogue of `mload_masked_eq_wordOf_pad16`. -/
theorem cl_masked_eq_wordOf {m : Nat} (sig : ByteVec m) (off : Nat) :
    calldataload sig off &&& NMASK = wordOf (ByteVec.pad16 (ByteVec.loadValue16 sig off)) := by
  apply eq_of_beByte
  · exact Nat.lt_of_le_of_lt Nat.and_le_left
      (by unfold calldataload; rw [wordOfBV_eq_wordOf]; exact wordOf_lt _)
  · exact wordOf_lt _
  · intro i hi
    rw [cl_beByte_eq sig off i hi, beByte_wordOf_getD _ i hi]

/-! ### Small-offset arithmetic helpers

Every FORS offset/index in the body is bounded well below `W = 2^256`, so the
EVM `% W` truncations are inert. These helpers discharge the `mod`/`shiftLeft`
normalisations that turn the interpreter's `(… % W)` Nat-forms into plain
arithmetic the wrapper hypotheses are phrased in. -/

/-- A value below `4096` is below `W = 2^256` (the only `decide`-on-`2^256` site;
    binary-`Nat` kernel arithmetic, instant). -/
private theorem lt_W_of_lt {x : Nat} (h : x < 4096) : x < W := by
  unfold W; exact Nat.lt_trans h (by decide)

/-- `h <<< 4 % W = 16 * h` for `h < 256` (the sibling/secret stride; `16h < W`).
    Covers both the `i`-loop (`i < 12`) and the `h`-loop (`h < 11`). -/
private theorem shl4_small (h : Nat) (hh : h < 256) : h <<< 4 % W = 16 * h := by
  rw [Nat.shiftLeft_eq, Nat.mod_eq_of_lt (lt_W_of_lt (by omega)), Nat.mul_comm]

/-! ### 3-segment leaf hash

The FORS leaf precompile hashes `[0x00,0x60)` = 3 segments `[seed, leafAdrs,
pad16 secret]` (`th`'s input). The `climbMem_holdsSegs` analogue for 3 windows. -/

/-- The three-segment list the FORS leaf precompile hashes (a `th` input). -/
private def leafSegs (seed adrs val : ByteVec 32) : List (ByteVec 32) := [seed, adrs, val]

/-- **Holds the leaf segments.** With `seed` already in window `0` and the two
    stores at `0x20`/`0x40` as `wordOf`-words, scratch `[0x00, 0x60)` holds
    `[seed, adrs, val]`. -/
private theorem leafMem_holdsSegs (mem : ByteMemory) (seed adrs val : ByteVec 32)
    (hseed : ∀ i, i < 32 → mem (0 + i) = seed.data.getD i 0) :
    holdsSegs (mstore32 (mstore32 mem 32 (wordOf adrs)) 64 (wordOf val)) 0
      (leafSegs seed adrs val) := by
  intro j i hj hi
  have hjlt : j < 3 := by simpa [leafSegs] using hj
  rw [Nat.zero_add]
  match j, hjlt with
  | 0, _ =>
      rw [mstore32_frame _ 64 (wordOf val) (32 * 0 + i) (by omega),
          mstore32_frame _ 32 (wordOf adrs) (32 * 0 + i) (by omega),
          show (32 * 0 + i) = (0 + i) by omega, hseed i hi]
      rfl
  | 1, _ =>
      rw [mstore32_frame _ 64 (wordOf val) (32 * 1 + i) (by omega)]
      have e := mstore32_get mem 32 (wordOf adrs) i hi
      rw [show (32 * 1 + i) = (32 + i) by omega, e, beByte_wordOf_getD adrs i hi]
      rfl
  | 2, _ =>
      have e := mstore32_get (mstore32 mem 32 (wordOf adrs)) 64 (wordOf val) i hi
      rw [show (32 * 2 + i) = (64 + i) by omega, e, beByte_wordOf_getD val i hi]
      rfl

/-- **One leaf hash step ↔ `th`.** Running the precompile over the assembled leaf
    memory and masking the digest yields `wordOf (pad16 (th seed adrs val))`.
    The 3-segment analogue of `climbMem_thPair`. -/
private theorem leafMem_th (mem : ByteMemory) (seed adrs val : ByteVec 32)
    (hseed : ∀ i, i < 32 → mem (0 + i) = seed.data.getD i 0) :
    (mload32 (writeRegion (mstore32 (mstore32 mem 32 (wordOf adrs)) 64 (wordOf val))
        0x600
        (fun i => (c10Oracle (slice
          (mstore32 (mstore32 mem 32 (wordOf adrs)) 64 (wordOf val)) 0 96)).data.getD i 0)) 0x600)
        &&& NMASK
      = wordOf (ByteVec.pad16 (Spec.th seed (adrs : Spec.Adrs) val)) := by
  rw [mload_masked_eq_wordOf_pad16
        (mstore32 (mstore32 mem 32 (wordOf adrs)) 64 (wordOf val))
        0x600
        (c10Oracle (slice (mstore32 (mstore32 mem 32 (wordOf adrs)) 64 (wordOf val)) 0 96))]
  have hseg : c10Oracle (slice (mstore32 (mstore32 mem 32 (wordOf adrs)) 64 (wordOf val)) 0 96)
      = Spec.sha256 ((leafSegs seed adrs val).map Spec.ByteSeg.ofByteVec) := by
    have hlen : (leafSegs seed adrs val).length = 3 := rfl
    have h := c10Oracle_holdsSegs (mstore32 (mstore32 mem 32 (wordOf adrs)) 64 (wordOf val))
      0 (leafSegs seed adrs val) (leafMem_holdsSegs mem seed adrs val hseed)
    rw [hlen] at h
    exact h
  rw [hseg]
  rfl

/-! ### The FORS per-tree body

`forsTreeBody` is the outer-loop body of `c10Program`'s `forRange "i" 12`
(`SPHINCsC10Asm.sol` L90–122), written with raw constructors so it is defeq to
that slice. With loop var `i = t`. -/

/-- The FORS per-tree body (`SPHINCsC10Asm.sol` L90–122). -/
def forsTreeBody : List Stmt :=
  [ .letv "treeIdx" (.bin .band (.bin .shr (.bin .mul (.var "i") (.lit 11)) (.var "dVal")) (.lit 0x7FF))
  , .letv "secretVal"
      (.bin .band (.calldataload (.bin .add (.var "sigBase")
        (.bin .add (.lit 16) (.bin .shl (.lit 4) (.var "i"))))) (.var "N_MASK"))
  , .letv "leafAdrs"
      (.bin .bor (.bin .shl (.lit 160) (.var "htIdx"))
        (.bin .bor (.bin .shl (.lit 128) (.lit 3))
          (.bin .bor (.bin .shl (.lit 96) (.var "i")) (.var "treeIdx"))))
  , .mstore (.lit 0x20) (.var "leafAdrs")
  , .mstore (.lit 0x40) (.var "secretVal")
  , .sha256 (.lit 0x00) (.lit 0x60) (.var "OUT")
  , .letv "node" (.bin .band (.mload (.var "OUT")) (.var "N_MASK"))
  , .letv "treeAdrsBase"
      (.bin .bor (.bin .shl (.lit 160) (.var "htIdx"))
        (.bin .bor (.bin .shl (.lit 128) (.lit 3)) (.bin .shl (.lit 96) (.var "i"))))
  , .letv "pathIdx" (.var "treeIdx")
  , .letv "authPtr" (.bin .add (.var "sigBase")
      (.bin .add (.lit 224) (.bin .mul (.var "i") (.lit 176))))
  , .forRange "h" (.lit 11) forsClimbBody
  , .mstore (.bin .add (.lit 0x80) (.bin .shl (.lit 5) (.var "i"))) (.var "node")
  ]

/-- `forsClimbBody` (one climb level, entered with `"h" := cur`) falls through (no
    `revert`/`return`) and never writes `"i"`: it only binds `sibling`, `parentIdx`,
    `s`, `node`, `pathIdx` (and `"h"` at entry). So the outer loop variable `"i"`
    survives one climb level. -/
private theorem execList_forsClimbBody_preserves_i (sig : ByteVec Spec.SignatureLen)
    (cur : Nat) (v : VM) :
    (execList c10Oracle sig forsClimbBody { v with env := setVar v.env "h" cur }).2 = none
    ∧ (execList c10Oracle sig forsClimbBody { v with env := setVar v.env "h" cur }).1.env "i"
        = v.env "i" := by
  unfold forsClimbBody
  rw [execList_cons_none c10Oracle sig _ _ _ (by simp only [execStmt])]
  rw [execList_cons_none c10Oracle sig _ _ _ (by simp only [execStmt])]
  rw [execList_cons_none c10Oracle sig _ _ _ (by simp only [execStmt])]
  rw [execList_cons_none c10Oracle sig _ _ _ (by simp only [execStmt])]
  rw [execList_cons_none c10Oracle sig _ _ _ (by simp only [execStmt])]
  rw [execList_cons_none c10Oracle sig _ _ _ (by simp only [execStmt])]
  rw [execList_cons_none c10Oracle sig _ _ _ (by simp only [execStmt])]
  rw [execList_cons_none c10Oracle sig _ _ _ (by simp only [execStmt])]
  rw [execList_cons_none c10Oracle sig _ _ _ (by simp only [execStmt])]
  rw [execList]
  refine ⟨rfl, ?_⟩
  simp [execStmt, eval, setVar]

/-- The whole inner climb (`execFor … forsClimbBody`) preserves `"i"`: drives
    `execList_forsClimbBody_preserves_i` through the loop by induction on `remaining`. -/
private theorem execFor_forsClimbBody_preserves_i (sig : ByteVec Spec.SignatureLen) :
    ∀ (remaining cur : Nat) (v : VM),
      (execFor c10Oracle sig "h" forsClimbBody remaining cur v).1.env "i" = v.env "i" := by
  intro remaining
  induction remaining with
  | zero => intro cur v; simp only [execFor]
  | succ rem ih =>
      intro cur v
      obtain ⟨hnone, hi⟩ := execList_forsClimbBody_preserves_i sig cur v
      rw [execFor]
      rcases hp : execList c10Oracle sig forsClimbBody { v with env := setVar v.env "h" cur }
        with ⟨pvm, po⟩
      rw [hp] at hnone hi
      subst hnone
      simp only []
      rw [ih (cur + 1) pvm, hi]

set_option maxHeartbeats 8000000 in
set_option maxRecDepth 4000 in
/-- **FORS per-tree body refinement.** Running `forsTreeBody` for tree `t < 12`
    from a VM whose env supplies `htIdx`, `sigBase = 0`, `seed`, `N_MASK`,
    `OUT = 0x600`, `dVal`, and loop var `i = t`, with `seed` in scratch
    `[0x00,0x20)`, falls through (`.2 = none`) and writes the masked
    `wordOf (pad16 (reconstructRoot …))` of FORS tree `t` at `0x80 + 32*t`; the
    seed window and the loop consts persist.

    The leaf hash, the climb drive, the final store, and seed/const persistence
    are discharged here; the two pure byte-layout obligations (`H_leafAdrs` /
    `H_adrs`, the `make`/`wordOf` bridge) and the digest→leaf-index identity
    (`H_idx`, the `readBitsLe`↔word-shift bridge) are factored to the i-loop
    wrapper, exactly as `fors_climb` factors `H_adrs`. The secret and the auth-path
    siblings are bound to the *real* `loadValue16` calldata reads (`secret` is the
    `reconstructForsPk` value; `H_sib` is the same shape `fors_climb` consumes).

    `H_adrs` / `H_sib` are *bounded* (`h < A`, `p < 2^32`) hence SATISFIABLE — the
    non-vacuity is witnessed end-to-end by `fors_tree_body_nonvacuous` at the bottom of
    this file (it actually *applies* this theorem on a concrete tree, discharging every
    hypothesis via the `_dischargeable` guards), so a revert to an unsatisfiable hyp
    breaks the build. -/
theorem fors_tree_body
    (sig : ByteVec Spec.SignatureLen) (vm : VM)
    (seed : ByteVec 32) (htIdx : UInt64) (t : Nat)
    (leafIdx : UInt32) (authPath : Array (ByteVec 16))
    (ht : t < 12)
    -- env preconditions
    (hht : vm.env "htIdx" = htIdx.toNat)
    (hsb : vm.env "sigBase" = 0)
    (hseedw : vm.env "seed" = wordOf seed)
    (hN : vm.env "N_MASK" = NMASK)
    (hOUT : vm.env "OUT" = 0x600)
    (hival : vm.env "i" = t)
    (hseedmem : ∀ i, i < 32 → vm.mem (0 + i) = seed.data.getD i 0)
    -- byte-layout obligations (wrapper-discharged)
    (H_leafAdrs : (htIdx.toNat <<< 160 % W) ||| ((3 <<< 128 % W) ||| ((t <<< 96 % W) |||
        ((vm.env "dVal" >>> (t * 11)) &&& 0x7FF)))
      = wordOf (Spec.Adrs.forsNode htIdx (UInt32.ofNat t) 0 leafIdx))
    (H_idx : (vm.env "dVal" >>> (t * 11)) &&& 0x7FF = leafIdx.toNat)
    -- BOUNDED byte-layout obligations (satisfiable — discharge guards
    -- `H_adrs_dischargeable` / `H_sib_dischargeable` below prove them inhabited).
    (H_adrs : ∀ h, h < Spec.A → ∀ p, p < 2 ^ 32 →
        ((htIdx.toNat <<< 160 % W) ||| ((3 <<< 128 % W) ||| (t <<< 96 % W)))
          ||| (((h + 1) % W) <<< 32 % W ||| p >>> 1)
        = wordOf (Spec.Adrs.forsNode htIdx (UInt32.ofNat t) (UInt32.ofNat (h + 1))
            (UInt32.ofNat (p / 2))))
    (H_sib : ∀ h, h < Spec.A → calldataload sig (((224 + t * 176) + h <<< 4 % W) % W) &&& NMASK
        = wordOf (ByteVec.pad16 (authPath.getD h (ByteVec.zero 16)))) :
    (execList c10Oracle sig forsTreeBody vm).2 = none
    ∧ (∀ k, k < 32 →
        (execList c10Oracle sig forsTreeBody vm).1.mem (0x80 + 32 * t + k)
          = (ByteVec.pad16 (Spec.Fors.reconstructRoot seed htIdx (UInt32.ofNat t) leafIdx
              (ByteVec.loadValue16 sig (16 + 16 * t)) authPath)).data.getD k 0)
    ∧ (∀ i, i < 32 → (execList c10Oracle sig forsTreeBody vm).1.mem (0 + i) = seed.data.getD i 0) := by
  unfold forsTreeBody
  rw [execList_cons_none c10Oracle sig _ _ _ (by simp only [execStmt])]
  rw [execList_cons_none c10Oracle sig _ _ _ (by simp only [execStmt])]
  rw [execList_cons_none c10Oracle sig _ _ _ (by simp only [execStmt])]
  rw [execList_cons_none c10Oracle sig _ _ _ (by simp only [execStmt])]
  rw [execList_cons_none c10Oracle sig _ _ _ (by simp only [execStmt])]
  rw [execList_cons_none c10Oracle sig _ _ _ (by simp only [execStmt])]
  rw [execList_cons_none c10Oracle sig _ _ _ (by simp only [execStmt])]
  rw [execList_cons_none c10Oracle sig _ _ _ (by simp only [execStmt])]
  rw [execList_cons_none c10Oracle sig _ _ _ (by simp only [execStmt])]
  rw [execList_cons_none c10Oracle sig _ _ _ (by simp only [execStmt])]
  simp only [execStmt, eval, setVar, hht, hsb, hN, hOUT, hival,
    ite_true, ite_false, String.reduceEq]
  -- Normalise the (small) `% W` shift-amounts / offsets to plain arithmetic.
  have hmul11 : t * 11 % W = t * 11 := Nat.mod_eq_of_lt (lt_W_of_lt (by omega))
  have hsecOff : (0 + (16 + t <<< 4 % W) % W) % W = 16 + 16 * t := by
    rw [shl4_small t (by omega), Nat.mod_eq_of_lt (lt_W_of_lt (show 16 + 16 * t < 4096 by omega)),
        Nat.zero_add, Nat.mod_eq_of_lt (lt_W_of_lt (show 16 + 16 * t < 4096 by omega))]
  have hauthOff : (0 + (224 + t * 176 % W) % W) % W = 224 + t * 176 := by
    rw [Nat.mod_eq_of_lt (lt_W_of_lt (show t * 176 < 4096 by omega)),
        Nat.mod_eq_of_lt (lt_W_of_lt (show 224 + t * 176 < 4096 by omega)),
        Nat.zero_add, Nat.mod_eq_of_lt (lt_W_of_lt (show 224 + t * 176 < 4096 by omega))]
  rw [hmul11, hsecOff, hauthOff]
  -- Clean the leaf-ADRS word, the secret read, and the leaf index.
  rw [H_leafAdrs, cl_masked_eq_wordOf sig (16 + 16 * t), H_idx]
  -- Abbreviations for the post-leaf-hash VM (the climb entry state).
  -- The leaf node word = wordOf (pad16 (th seed leafA (pad16 secret))) via `leafMem_th`.
  have hleafnode :
      mload32
        (writeRegion
          (mstore32 (mstore32 vm.mem 32 (wordOf (Spec.Adrs.forsNode htIdx (UInt32.ofNat t) 0 leafIdx)))
            64 (wordOf (ByteVec.loadValue16 sig (16 + 16 * t)).pad16))
          1536 fun i =>
          (c10Oracle (slice
            (mstore32 (mstore32 vm.mem 32 (wordOf (Spec.Adrs.forsNode htIdx (UInt32.ofNat t) 0 leafIdx)))
              64 (wordOf (ByteVec.loadValue16 sig (16 + 16 * t)).pad16))
            0 96)).data.getD i 0) 1536 &&& NMASK
      = wordOf (ByteVec.pad16 (Spec.th seed (Spec.Adrs.forsNode htIdx (UInt32.ofNat t) 0 leafIdx)
          (ByteVec.pad16 (ByteVec.loadValue16 sig (16 + 16 * t))))) :=
    leafMem_th vm.mem seed (Spec.Adrs.forsNode htIdx (UInt32.ofNat t) 0 leafIdx)
      (ByteVec.pad16 (ByteVec.loadValue16 sig (16 + 16 * t))) hseedmem
  rw [hleafnode]
  -- Abbreviate the climb-entry VM as `w` (collapses the 3 identical record copies).
  obtain ⟨w, hweq⟩ :
      ∃ w : VM, w =
        { mem :=
            writeRegion
              (mstore32 (mstore32 vm.mem 32 (wordOf (Spec.Adrs.forsNode htIdx (UInt32.ofNat t) 0 leafIdx)))
                64 (wordOf (ByteVec.loadValue16 sig (16 + 16 * t)).pad16)) 1536 (fun i =>
              (c10Oracle (slice
                (mstore32 (mstore32 vm.mem 32 (wordOf (Spec.Adrs.forsNode htIdx (UInt32.ofNat t) 0 leafIdx)))
                  64 (wordOf (ByteVec.loadValue16 sig (16 + 16 * t)).pad16))
                0 96)).data.getD i 0),
          env :=
            setVar (setVar (setVar (setVar (setVar (setVar
              (setVar vm.env "treeIdx" leafIdx.toNat) "secretVal"
                (wordOf (ByteVec.loadValue16 sig (16 + 16 * t)).pad16))
              "leafAdrs" (wordOf (Spec.Adrs.forsNode htIdx (UInt32.ofNat t) 0 leafIdx)))
              "node" (wordOf (ByteVec.pad16 (Spec.th seed (Spec.Adrs.forsNode htIdx (UInt32.ofNat t) 0 leafIdx)
                (ByteVec.pad16 (ByteVec.loadValue16 sig (16 + 16 * t)))))))
              "treeAdrsBase" (htIdx.toNat <<< 160 % W ||| (3 <<< 128 % W ||| t <<< 96 % W)))
              "pathIdx" leafIdx.toNat)
              "authPtr" (224 + t * 176) } := ⟨_, rfl⟩
  rw [← hweq]
  -- env/mem facts about the climb-entry `w` (frame the outer `setVar`s).
  have hwN : w.env "N_MASK" = NMASK := by rw [hweq, hN.symm]; simp [setVar]
  have hwOUT : w.env "OUT" = 0x600 := by rw [hweq, hOUT.symm]; simp [setVar]
  have hwtB : w.env "treeAdrsBase"
      = (htIdx.toNat <<< 160 % W ||| (3 <<< 128 % W ||| t <<< 96 % W)) := by
    rw [hweq]; simp [setVar]
  have hwAuth : w.env "authPtr" = 224 + t * 176 := by rw [hweq]; simp [setVar]
  have hwnode : w.env "node"
      = wordOf (ByteVec.pad16 (Spec.th seed (Spec.Adrs.forsNode htIdx (UInt32.ofNat t) 0 leafIdx)
          (ByteVec.pad16 (ByteVec.loadValue16 sig (16 + 16 * t))))) := by
    rw [hweq]; simp [setVar]
  have hwpath : w.env "pathIdx" = leafIdx.toNat := by rw [hweq]; simp [setVar]
  have hwmem : w.mem = writeRegion
      (mstore32 (mstore32 vm.mem 32 (wordOf (Spec.Adrs.forsNode htIdx (UInt32.ofNat t) 0 leafIdx)))
        64 (wordOf (ByteVec.loadValue16 sig (16 + 16 * t)).pad16)) 1536 (fun i =>
        (c10Oracle (slice
          (mstore32 (mstore32 vm.mem 32 (wordOf (Spec.Adrs.forsNode htIdx (UInt32.ofNat t) 0 leafIdx)))
            64 (wordOf (ByteVec.loadValue16 sig (16 + 16 * t)).pad16))
          0 96)).data.getD i 0) := by rw [hweq]
  have hwseed : ∀ i, i < 32 → w.mem (0 + i) = seed.data.getD i 0 := by
    intro i hi
    rw [hwmem, writeRegion_frame _ 1536 _ (0 + i) (by omega),
        mstore32_frame _ 64 _ (0 + i) (by omega), mstore32_frame _ 32 _ (0 + i) (by omega)]
    exact hseedmem i hi
  -- Drive the inner climb on `w` via `execFor_invariant` with the *full* climb
  -- invariant (the same `R` `fors_climb` uses internally), so we keep the seed-mem
  -- persistence + the `node` binding the wrapper needs (the public `fors_climb`
  -- surfaces only `node`).
  -- Drive the inner climb on `w` (FORS-tree Merkle climb core). `fors_climb` exposes
  -- both the `node` = `reconstructRoot` result and the seed-window persistence.
  obtain ⟨hclimb_none, hclimb_node, hclimb_seedmem⟩ :=
    fors_climb sig w seed htIdx (UInt32.ofNat t) leafIdx
      (ByteVec.loadValue16 sig (16 + 16 * t)) authPath
      (htIdx.toNat <<< 160 % W ||| (3 <<< 128 % W ||| t <<< 96 % W)) (224 + t * 176)
      hwN hwOUT hwtB hwAuth hwnode hwpath hwseed H_adrs H_sib
  -- The forRange statement IS `execFor … Spec.A 0 w` (Spec.A = 11 defeq).
  have hforStmt : execStmt c10Oracle sig (.forRange "h" (.lit 11) forsClimbBody) w
      = execFor c10Oracle sig "h" forsClimbBody Spec.A 0 w := by
    simp only [execStmt, eval]; rfl
  -- The climb preserves the outer loop var `"i" = t` (it frames through `w`).
  have hwi : w.env "i" = t := by rw [hweq]; simp [setVar]; exact hival
  have hclimbVM_i : (execFor c10Oracle sig "h" forsClimbBody Spec.A 0 w).1.env "i" = t := by
    rw [execFor_forsClimbBody_preserves_i sig Spec.A 0 w, hwi]
  -- Step the forRange (falls through by `hclimb_none`), landing on the climb-final VM.
  rw [execList_cons_none c10Oracle sig _ _ _ (by rw [hforStmt]; exact hclimb_none), hforStmt]
  -- Step the final `mstore (0x80 + 32*t) node`: writes `wordOf (pad16 reconstructRoot)`.
  rw [execList_cons_none c10Oracle sig _ _ _ (by simp only [execStmt]), execList]
  -- Normalise the store offset `(0x80 + t <<< 5 % W) % W = 128 + 32*t`.
  have hstoreOff : (128 + t <<< 5 % W) % W = 128 + 32 * t := by
    rw [Nat.shiftLeft_eq, show (2 : Nat) ^ 5 = 32 from rfl, Nat.mul_comm t 32,
        Nat.mod_eq_of_lt (lt_W_of_lt (show 32 * t < 4096 by omega)),
        Nat.mod_eq_of_lt (lt_W_of_lt (show 128 + 32 * t < 4096 by omega))]
  simp only [execStmt, eval, hclimbVM_i, hclimb_node, hstoreOff]
  refine ⟨trivial, ?_, ?_⟩
  · -- conjunct 2: mem at 128+32*t+k = (pad16 reconstructRoot)'s k-th byte.
    intro k hk
    rw [show (128 + 32 * t + k) = ((128 + 32 * t) + k) by omega,
        mstore32_get _ (128 + 32 * t) _ k hk,
        beByte_wordOf_getD _ k hk]
  · -- conjunct 3: seed window persists (the store lands at ≥ 128).
    intro i hi
    rw [mstore32_frame _ (128 + 32 * t) _ (0 + i) (by omega)]
    exact hclimb_seedmem i hi

/-! ## ADRS word-layout bridge

`wordOf_make` proves that the big-endian 256-bit word of `Spec.Adrs.make`'s 32-byte
packed structure is the disjoint byte-aligned OR of its seven fields — the layout the
deployed Yul `or(shl(160,htIdx), or(shl(128,FT), …))` builds directly. The three
specializations (`wordOf_forsNode`/`forsRoots`/`treeNode`) are what the interpreter
wrapper actually consumes to discharge the FORS-tree ADRS-word obligations
(`fors_tree_body`'s `H_leafAdrs`; the bounded form of `H_adrs` — see the note below).

The route is byte-extensional (robust): `eq_of_beByte` reduces the word equality to
agreement on all 32 big-endian bytes; the left side is read back via `beByte_wordOf_getD`
+ a 7-range append split (`make_data_getD_beByte`); the right side distributes through OR
(`beByte_lor`) and places each byte-aligned field (`beByte_shiftLeft_byte` + the field
placement lemmas). Mathlib-free. -/

/-- **OR distributes over `beByte`.** Big-endian byte `i` of `a ||| b` is the (UInt8)
    OR of the `i`-th bytes — the OR analogue of `beByte_and_nmask`'s AND-distribution. -/
theorem beByte_lor (a b i : Nat) : beByte (a ||| b) i = beByte a i ||| beByte b i := by
  unfold beByte
  rw [Nat.shiftRight_or_distrib, show (256 : Nat) = 2 ^ 8 from rfl, Nat.or_mod_two_pow,
      UInt8.ofNat_or]

/-- **Byte-aligned left shift moves bytes toward the MSB (lower index).** For `i < 32`,
    byte `i` of `x <<< (8*b)` is byte `i+b` of `x` when `i+b ≤ 31`, else `0`. -/
theorem beByte_shiftLeft_byte (x b i : Nat) (hi : i < 32) :
    beByte (x <<< (8 * b)) i = if i + b ≤ 31 then beByte x (i + b) else 0 := by
  unfold beByte
  by_cases h : i + b ≤ 31
  · rw [if_pos h]
    congr 1
    apply Nat.eq_of_testBit_eq
    intro k
    rw [show (256 : Nat) = 2 ^ 8 from rfl, Nat.testBit_mod_two_pow, Nat.testBit_mod_two_pow,
        Nat.testBit_shiftRight, Nat.testBit_shiftRight, Nat.testBit_shiftLeft]
    have hge : 8 * (31 - i) + k ≥ 8 * b := by omega
    have hidx : 8 * (31 - i) + k - 8 * b = 8 * (31 - (i + b)) + k := by omega
    rw [decide_eq_true hge, Bool.true_and, hidx]
  · rw [if_neg h]
    have hzero : x <<< (8 * b) >>> (8 * (31 - i)) % 256 = 0 := by
      apply Nat.eq_of_testBit_eq
      intro k
      rw [show (256 : Nat) = 2 ^ 8 from rfl, Nat.testBit_mod_two_pow, Nat.testBit_shiftRight,
          Nat.testBit_shiftLeft, Nat.zero_testBit]
      by_cases hk : k < 8
      · have hlt : ¬ (8 * (31 - i) + k ≥ 8 * b) := by omega
        rw [decide_eq_false hlt, Bool.false_and, Bool.and_false]
      · rw [decide_eq_false hk, Bool.false_and]
    rw [hzero]; rfl

private theorem and_0xFF_eq_mod (a : Nat) : a &&& 0xFF = a % 256 := by
  rw [show (0xFF : Nat) = 2 ^ 8 - 1 from rfl, Nat.and_two_pow_sub_one_eq_mod]

/-- The `i`-th byte (`i < 4`) of `ofU32BE x` is `beByte x.toNat (i+28)` (the low 4 bytes). -/
private theorem ofU32BE_getD_eq_beByte (x : UInt32) (i : Nat) (hi : i < 4) :
    (ByteVec.ofU32BE x).data.getD i 0 = beByte x.toNat (i + 28) := by
  unfold beByte
  match i, hi with
  | 0, _ => show UInt8.ofNat (x.toNat >>> 24 &&& 0xFF) = UInt8.ofNat (x.toNat >>> 24 % 256)
            rw [and_0xFF_eq_mod]
  | 1, _ => show UInt8.ofNat (x.toNat >>> 16 &&& 0xFF) = UInt8.ofNat (x.toNat >>> 16 % 256)
            rw [and_0xFF_eq_mod]
  | 2, _ => show UInt8.ofNat (x.toNat >>> 8 &&& 0xFF) = UInt8.ofNat (x.toNat >>> 8 % 256)
            rw [and_0xFF_eq_mod]
  | 3, _ => show UInt8.ofNat (x.toNat &&& 0xFF) = UInt8.ofNat (x.toNat >>> 0 % 256)
            rw [and_0xFF_eq_mod, Nat.shiftRight_zero]

/-- The `i`-th byte (`i < 8`) of `ofU64BE x` is `beByte x.toNat (i+24)`. -/
private theorem ofU64BE_getD_eq_beByte (x : UInt64) (i : Nat) (hi : i < 8) :
    (ByteVec.ofU64BE x).data.getD i 0 = beByte x.toNat (i + 24) := by
  unfold beByte
  match i, hi with
  | 0, _ =>
      show UInt8.ofNat (x.toNat >>> 56) = UInt8.ofNat (x.toNat >>> 56 % 256)
      have hlt : x.toNat >>> 56 < 256 := by
        have hlt64 : x.toNat < 2 ^ 64 := x.toNat_lt
        rw [Nat.shiftRight_eq_div_pow]
        omega
      rw [Nat.mod_eq_of_lt hlt]
  | 1, _ => show UInt8.ofNat (x.toNat >>> 48 &&& 0xFF) = UInt8.ofNat (x.toNat >>> 48 % 256)
            rw [and_0xFF_eq_mod]
  | 2, _ => show UInt8.ofNat (x.toNat >>> 40 &&& 0xFF) = UInt8.ofNat (x.toNat >>> 40 % 256)
            rw [and_0xFF_eq_mod]
  | 3, _ => show UInt8.ofNat (x.toNat >>> 32 &&& 0xFF) = UInt8.ofNat (x.toNat >>> 32 % 256)
            rw [and_0xFF_eq_mod]
  | 4, _ => show UInt8.ofNat (x.toNat >>> 24 &&& 0xFF) = UInt8.ofNat (x.toNat >>> 24 % 256)
            rw [and_0xFF_eq_mod]
  | 5, _ => show UInt8.ofNat (x.toNat >>> 16 &&& 0xFF) = UInt8.ofNat (x.toNat >>> 16 % 256)
            rw [and_0xFF_eq_mod]
  | 6, _ => show UInt8.ofNat (x.toNat >>> 8 &&& 0xFF) = UInt8.ofNat (x.toNat >>> 8 % 256)
            rw [and_0xFF_eq_mod]
  | 7, _ => show UInt8.ofNat (x.toNat &&& 0xFF) = UInt8.ofNat (x.toNat >>> 0 % 256)
            rw [and_0xFF_eq_mod, Nat.shiftRight_zero]

/-- High-index (`j < 28`) big-endian bytes of a `UInt32` value are zero. -/
private theorem beByte_u32_zero_lo (x : UInt32) (j : Nat) (hj : j < 28) : beByte x.toNat j = 0 := by
  unfold beByte
  have hx : x.toNat < 2 ^ 32 := x.toNat_lt
  have hsh : x.toNat >>> (8 * (31 - j)) = 0 := by
    rw [Nat.shiftRight_eq_div_pow]
    apply Nat.div_eq_of_lt
    exact Nat.lt_of_lt_of_le hx (Nat.pow_le_pow_right (by decide) (by omega))
  rw [hsh]; rfl

/-- High-index (`j < 24`) big-endian bytes of a `UInt64` value are zero. -/
private theorem beByte_u64_zero_lo (x : UInt64) (j : Nat) (hj : j < 24) : beByte x.toNat j = 0 := by
  unfold beByte
  have hx : x.toNat < 2 ^ 64 := x.toNat_lt
  have hsh : x.toNat >>> (8 * (31 - j)) = 0 := by
    rw [Nat.shiftRight_eq_div_pow]
    apply Nat.div_eq_of_lt
    exact Nat.lt_of_lt_of_le hx (Nat.pow_le_pow_right (by decide) (by omega))
  rw [hsh]; rfl

/-- A `UInt32` field shifted to byte-offset `off` occupies bytes `[off, off+4)`. -/
private theorem field32_byte (x : UInt32) (off i : Nat) (hoff : off ≤ 28) (hi : i < 32) :
    beByte (x.toNat <<< (8 * (28 - off))) i
      = if off ≤ i ∧ i < off + 4 then beByte x.toNat (i + 28 - off) else 0 := by
  rw [beByte_shiftLeft_byte x.toNat (28 - off) i hi]
  by_cases hc : off ≤ i ∧ i < off + 4
  · rw [if_pos hc, if_pos (show i + (28 - off) ≤ 31 by omega)]
    congr 1; omega
  · rw [if_neg hc]
    by_cases hstruct : i + (28 - off) ≤ 31
    · rw [if_pos hstruct]
      apply beByte_u32_zero_lo
      omega
    · rw [if_neg hstruct]

/-- The `UInt64` `tree` field (byte-offset 4) occupies bytes `[4, 12)`. -/
private theorem field64_byte (x : UInt64) (i : Nat) (hi : i < 32) :
    beByte (x.toNat <<< (8 * 20)) i
      = if 4 ≤ i ∧ i < 12 then beByte x.toNat (i + 20) else 0 := by
  rw [beByte_shiftLeft_byte x.toNat 20 i hi]
  by_cases hc : 4 ≤ i ∧ i < 12
  · rw [if_pos hc, if_pos (show i + 20 ≤ 31 by omega)]
  · rw [if_neg hc]
    by_cases hstruct : i + 20 ≤ 31
    · rw [if_pos hstruct]
      apply beByte_u64_zero_lo
      omega
    · rw [if_neg hstruct]

/-- `getD` over an append of two raw arrays at a known left-size `p`. -/
private theorem arr_append_getD (a b : Array UInt8) (p i : Nat) (hp : a.size = p) :
    (a ++ b).getD i 0 = if i < p then a.getD i 0 else b.getD (i - p) 0 := by
  rw [Array.getD_eq_getD_getElem?, Array.getElem?_append, hp]
  by_cases hi : i < p
  · rw [if_pos hi, if_pos hi, ← Array.getD_eq_getD_getElem?]
  · rw [if_neg hi, if_neg hi, ← Array.getD_eq_getD_getElem?]

/-- The make's `data` is the 7-fold byte append of the BE-encoded fields. -/
private theorem make_data_eq (layer : UInt32) (tree : UInt64) (atype kp ci cp ha : UInt32) :
    (Spec.Adrs.make layer tree atype kp ci cp ha).data
      = (ByteVec.ofU32BE layer).data ++ (ByteVec.ofU64BE tree).data ++ (ByteVec.ofU32BE atype).data
        ++ (ByteVec.ofU32BE kp).data ++ (ByteVec.ofU32BE ci).data ++ (ByteVec.ofU32BE cp).data
        ++ (ByteVec.ofU32BE ha).data := rfl

private theorem sz_u32 (x : UInt32) : (ByteVec.ofU32BE x).data.size = 4 := (ByteVec.ofU32BE x).size_eq
private theorem sz_u64 (x : UInt64) : (ByteVec.ofU64BE x).data.size = 8 := (ByteVec.ofU64BE x).size_eq

/-- Byte-`i` of the make, resolved to the covering field's `beByte`. -/
private theorem make_data_getD_beByte
    (layer : UInt32) (tree : UInt64) (atype kp ci cp ha : UInt32) (i : Nat) (hi : i < 32) :
    (Spec.Adrs.make layer tree atype kp ci cp ha).data.getD i 0
      = if i < 4 then beByte layer.toNat (i + 28)
        else if i < 12 then beByte tree.toNat (i - 4 + 24)
        else if i < 16 then beByte atype.toNat (i - 12 + 28)
        else if i < 20 then beByte kp.toNat (i - 16 + 28)
        else if i < 24 then beByte ci.toNat (i - 20 + 28)
        else if i < 28 then beByte cp.toNat (i - 24 + 28)
        else beByte ha.toNat (i - 28 + 28) := by
  rw [make_data_eq]
  have sL : (ByteVec.ofU32BE layer).data.size = 4 := sz_u32 layer
  have sT : (ByteVec.ofU64BE tree).data.size = 8 := sz_u64 tree
  have sA : (ByteVec.ofU32BE atype).data.size = 4 := sz_u32 atype
  have sK : (ByteVec.ofU32BE kp).data.size = 4 := sz_u32 kp
  have sC : (ByteVec.ofU32BE ci).data.size = 4 := sz_u32 ci
  have sP : (ByteVec.ofU32BE cp).data.size = 4 := sz_u32 cp
  -- The append is left-nested (`++` is infixl): ((((((L++T)++A)++K)++C)++P)++Hh).
  -- Peel from the outermost (rightmost field) inward; prefix sizes via Array.size_append.
  rw [arr_append_getD _ (ByteVec.ofU32BE ha).data 28 i
        (by simp [Array.size_append, sL, sT, sA, sK, sC, sP])]
  rw [arr_append_getD _ (ByteVec.ofU32BE cp).data 24 i
        (by simp [Array.size_append, sL, sT, sA, sK, sC])]
  rw [arr_append_getD _ (ByteVec.ofU32BE ci).data 20 i
        (by simp [Array.size_append, sL, sT, sA, sK])]
  rw [arr_append_getD _ (ByteVec.ofU32BE kp).data 16 i
        (by simp [Array.size_append, sL, sT, sA])]
  rw [arr_append_getD _ (ByteVec.ofU32BE atype).data 12 i
        (by simp [Array.size_append, sL, sT])]
  rw [arr_append_getD (ByteVec.ofU32BE layer).data (ByteVec.ofU64BE tree).data 4 i sL]
  -- resolve each leaf field byte; split i into the 7 ranges. `simp only` with the
  -- in-scope range facts decides every LHS-descending and RHS `if`, the field lemma
  -- lands the leaf, and `congr 1; omega` matches the surviving index.
  rcases Nat.lt_or_ge i 4 with h | h
  · simp only [if_pos (show i < 28 by omega), if_pos (show i < 24 by omega),
      if_pos (show i < 20 by omega), if_pos (show i < 16 by omega), if_pos (show i < 12 by omega),
      if_pos h, ofU32BE_getD_eq_beByte layer i h]
  · rcases Nat.lt_or_ge i 12 with h2 | h2
    · simp only [if_pos (show i < 28 by omega), if_pos (show i < 24 by omega),
        if_pos (show i < 20 by omega), if_pos (show i < 16 by omega), if_pos h2,
        if_neg (Nat.not_lt.2 h), ofU64BE_getD_eq_beByte tree (i - 4) (by omega)]
    · rcases Nat.lt_or_ge i 16 with h3 | h3
      · simp only [if_pos (show i < 28 by omega), if_pos (show i < 24 by omega),
          if_pos (show i < 20 by omega), if_pos h3, if_neg (Nat.not_lt.2 h), if_neg (Nat.not_lt.2 h2),
          ofU32BE_getD_eq_beByte atype (i - 12) (by omega)]
      · rcases Nat.lt_or_ge i 20 with h4 | h4
        · simp only [if_pos (show i < 28 by omega), if_pos (show i < 24 by omega), if_pos h4,
            if_neg (Nat.not_lt.2 h), if_neg (Nat.not_lt.2 h2), if_neg (Nat.not_lt.2 h3),
            ofU32BE_getD_eq_beByte kp (i - 16) (by omega)]
        · rcases Nat.lt_or_ge i 24 with h5 | h5
          · simp only [if_pos (show i < 28 by omega), if_pos h5, if_neg (Nat.not_lt.2 h),
              if_neg (Nat.not_lt.2 h2), if_neg (Nat.not_lt.2 h3), if_neg (Nat.not_lt.2 h4),
              ofU32BE_getD_eq_beByte ci (i - 20) (by omega)]
          · rcases Nat.lt_or_ge i 28 with h6 | h6
            · simp only [if_pos h6, if_neg (Nat.not_lt.2 h), if_neg (Nat.not_lt.2 h2),
                if_neg (Nat.not_lt.2 h3), if_neg (Nat.not_lt.2 h4), if_neg (Nat.not_lt.2 h5),
                ofU32BE_getD_eq_beByte cp (i - 24) (by omega)]
            · simp only [if_neg (Nat.not_lt.2 h), if_neg (Nat.not_lt.2 h2), if_neg (Nat.not_lt.2 h3),
                if_neg (Nat.not_lt.2 h4), if_neg (Nat.not_lt.2 h5), if_neg (Nat.not_lt.2 h6),
                ofU32BE_getD_eq_beByte ha (i - 28) (by omega)]

/-- A value `< 2^m` shifted left by `k` with `m + k ≤ 256` stays `< 2^256`. -/
private theorem shl_lt_two_pow_256 (x m k : Nat) (hx : x < 2 ^ m) (hmk : m + k ≤ 256) :
    x <<< k < 2 ^ 256 := by
  rw [Nat.shiftLeft_eq]
  calc x * 2 ^ k < 2 ^ m * 2 ^ k := by
            exact (Nat.mul_lt_mul_right (Nat.two_pow_pos k)).2 hx
    _ = 2 ^ (m + k) := by rw [← Nat.pow_add]
    _ ≤ 2 ^ 256 := Nat.pow_le_pow_right (by decide) hmk

/-- The make's RHS big-OR of the seven byte-aligned shifts is `< 2^256`. -/
private theorem make_rhs_lt (layer : UInt32) (tree : UInt64) (atype kp ci cp ha : UInt32) :
    layer.toNat <<< 224 ||| tree.toNat <<< 160 ||| atype.toNat <<< 128
      ||| kp.toNat <<< 96 ||| ci.toNat <<< 64 ||| cp.toNat <<< 32 ||| ha.toNat < 2 ^ 256 := by
  have hl : layer.toNat <<< 224 < 2 ^ 256 := shl_lt_two_pow_256 _ 32 224 layer.toNat_lt (by omega)
  have ht : tree.toNat <<< 160 < 2 ^ 256 := shl_lt_two_pow_256 _ 64 160 tree.toNat_lt (by omega)
  have ha' : atype.toNat <<< 128 < 2 ^ 256 := shl_lt_two_pow_256 _ 32 128 atype.toNat_lt (by omega)
  have hk : kp.toNat <<< 96 < 2 ^ 256 := shl_lt_two_pow_256 _ 32 96 kp.toNat_lt (by omega)
  have hc : ci.toNat <<< 64 < 2 ^ 256 := shl_lt_two_pow_256 _ 32 64 ci.toNat_lt (by omega)
  have hp : cp.toNat <<< 32 < 2 ^ 256 := shl_lt_two_pow_256 _ 32 32 cp.toNat_lt (by omega)
  have hh : ha.toNat < 2 ^ 256 := Nat.lt_trans ha.toNat_lt (by decide)
  exact Nat.or_lt_two_pow (Nat.or_lt_two_pow (Nat.or_lt_two_pow (Nat.or_lt_two_pow
    (Nat.or_lt_two_pow (Nat.or_lt_two_pow hl ht) ha') hk) hc) hp) hh

/-- Byte action of the make's RHS big-OR: distribute over OR and place each field. -/
private theorem make_rhs_beByte (layer : UInt32) (tree : UInt64) (atype kp ci cp ha : UInt32)
    (i : Nat) (hi : i < 32) :
    beByte (layer.toNat <<< 224 ||| tree.toNat <<< 160 ||| atype.toNat <<< 128
      ||| kp.toNat <<< 96 ||| ci.toNat <<< 64 ||| cp.toNat <<< 32 ||| ha.toNat) i
      = if i < 4 then beByte layer.toNat (i + 28)
        else if i < 12 then beByte tree.toNat (i - 4 + 24)
        else if i < 16 then beByte atype.toNat (i - 12 + 28)
        else if i < 20 then beByte kp.toNat (i - 16 + 28)
        else if i < 24 then beByte ci.toNat (i - 20 + 28)
        else if i < 28 then beByte cp.toNat (i - 24 + 28)
        else beByte ha.toNat (i - 28 + 28) := by
  rw [beByte_lor, beByte_lor, beByte_lor, beByte_lor, beByte_lor, beByte_lor]
  rw [show layer.toNat <<< 224 = layer.toNat <<< (8 * (28 - 0)) from rfl, field32_byte layer 0 i (by omega) hi]
  rw [show tree.toNat <<< 160 = tree.toNat <<< (8 * 20) from rfl, field64_byte tree i hi]
  rw [show atype.toNat <<< 128 = atype.toNat <<< (8 * (28 - 12)) from rfl,
      field32_byte atype 12 i (by omega) hi]
  rw [show kp.toNat <<< 96 = kp.toNat <<< (8 * (28 - 16)) from rfl, field32_byte kp 16 i (by omega) hi]
  rw [show ci.toNat <<< 64 = ci.toNat <<< (8 * (28 - 20)) from rfl, field32_byte ci 20 i (by omega) hi]
  rw [show cp.toNat <<< 32 = cp.toNat <<< (8 * (28 - 24)) from rfl, field32_byte cp 24 i (by omega) hi]
  -- 7-way range split; in each, exactly one disjunct is non-zero, the rest collapse via UInt8 OR.
  rcases Nat.lt_or_ge i 4 with h | h
  · rw [if_pos (show 0 ≤ i ∧ i < 0 + 4 by omega), if_neg (show ¬ (4 ≤ i ∧ i < 12) by omega),
        if_neg (show ¬ (12 ≤ i ∧ i < 16) by omega), if_neg (show ¬ (16 ≤ i ∧ i < 20) by omega),
        if_neg (show ¬ (20 ≤ i ∧ i < 24) by omega), if_neg (show ¬ (24 ≤ i ∧ i < 28) by omega),
        beByte_u32_zero_lo ha i (by omega), if_pos h,
        UInt8.or_zero, UInt8.or_zero, UInt8.or_zero, UInt8.or_zero, UInt8.or_zero, UInt8.or_zero]
    congr 1
  · rcases Nat.lt_or_ge i 12 with h2 | h2
    · rw [if_pos (show 4 ≤ i ∧ i < 12 by omega), if_neg (show ¬ (0 ≤ i ∧ i < 0 + 4) by omega),
          if_neg (show ¬ (12 ≤ i ∧ i < 16) by omega), if_neg (show ¬ (16 ≤ i ∧ i < 20) by omega),
          if_neg (show ¬ (20 ≤ i ∧ i < 24) by omega), if_neg (show ¬ (24 ≤ i ∧ i < 28) by omega),
          beByte_u32_zero_lo ha i (by omega), if_neg (Nat.not_lt.2 h), if_pos h2,
          UInt8.zero_or, UInt8.or_zero, UInt8.or_zero, UInt8.or_zero, UInt8.or_zero, UInt8.or_zero]
      congr 1; omega
    · rcases Nat.lt_or_ge i 16 with h3 | h3
      · rw [if_pos (show 12 ≤ i ∧ i < 16 by omega), if_neg (show ¬ (0 ≤ i ∧ i < 0 + 4) by omega),
            if_neg (show ¬ (4 ≤ i ∧ i < 12) by omega), if_neg (show ¬ (16 ≤ i ∧ i < 20) by omega),
            if_neg (show ¬ (20 ≤ i ∧ i < 24) by omega), if_neg (show ¬ (24 ≤ i ∧ i < 28) by omega),
            beByte_u32_zero_lo ha i (by omega), if_neg (Nat.not_lt.2 h), if_neg (Nat.not_lt.2 h2),
            if_pos h3, UInt8.zero_or, UInt8.zero_or, UInt8.or_zero, UInt8.or_zero, UInt8.or_zero,
            UInt8.or_zero]
        congr 1; omega
      · rcases Nat.lt_or_ge i 20 with h4 | h4
        · rw [if_pos (show 16 ≤ i ∧ i < 20 by omega), if_neg (show ¬ (0 ≤ i ∧ i < 0 + 4) by omega),
              if_neg (show ¬ (4 ≤ i ∧ i < 12) by omega), if_neg (show ¬ (12 ≤ i ∧ i < 16) by omega),
              if_neg (show ¬ (20 ≤ i ∧ i < 24) by omega), if_neg (show ¬ (24 ≤ i ∧ i < 28) by omega),
              beByte_u32_zero_lo ha i (by omega), if_neg (Nat.not_lt.2 h), if_neg (Nat.not_lt.2 h2),
              if_neg (Nat.not_lt.2 h3), if_pos h4, UInt8.zero_or, UInt8.zero_or, UInt8.zero_or,
              UInt8.or_zero, UInt8.or_zero, UInt8.or_zero]
          congr 1; omega
        · rcases Nat.lt_or_ge i 24 with h5 | h5
          · rw [if_pos (show 20 ≤ i ∧ i < 24 by omega), if_neg (show ¬ (0 ≤ i ∧ i < 0 + 4) by omega),
                if_neg (show ¬ (4 ≤ i ∧ i < 12) by omega), if_neg (show ¬ (12 ≤ i ∧ i < 16) by omega),
                if_neg (show ¬ (16 ≤ i ∧ i < 20) by omega), if_neg (show ¬ (24 ≤ i ∧ i < 28) by omega),
                beByte_u32_zero_lo ha i (by omega), if_neg (Nat.not_lt.2 h), if_neg (Nat.not_lt.2 h2),
                if_neg (Nat.not_lt.2 h3), if_neg (Nat.not_lt.2 h4), if_pos h5, UInt8.zero_or,
                UInt8.zero_or, UInt8.zero_or, UInt8.zero_or, UInt8.or_zero, UInt8.or_zero]
            congr 1; omega
          · rcases Nat.lt_or_ge i 28 with h6 | h6
            · rw [if_pos (show 24 ≤ i ∧ i < 28 by omega), if_neg (show ¬ (0 ≤ i ∧ i < 0 + 4) by omega),
                  if_neg (show ¬ (4 ≤ i ∧ i < 12) by omega), if_neg (show ¬ (12 ≤ i ∧ i < 16) by omega),
                  if_neg (show ¬ (16 ≤ i ∧ i < 20) by omega), if_neg (show ¬ (20 ≤ i ∧ i < 24) by omega),
                  beByte_u32_zero_lo ha i (by omega), if_neg (Nat.not_lt.2 h), if_neg (Nat.not_lt.2 h2),
                  if_neg (Nat.not_lt.2 h3), if_neg (Nat.not_lt.2 h4), if_neg (Nat.not_lt.2 h5),
                  if_pos h6, UInt8.zero_or, UInt8.zero_or, UInt8.zero_or, UInt8.zero_or, UInt8.zero_or,
                  UInt8.or_zero]
              congr 1; omega
            · rw [if_neg (show ¬ (24 ≤ i ∧ i < 28) by omega), if_neg (show ¬ (0 ≤ i ∧ i < 0 + 4) by omega),
                  if_neg (show ¬ (4 ≤ i ∧ i < 12) by omega), if_neg (show ¬ (12 ≤ i ∧ i < 16) by omega),
                  if_neg (show ¬ (16 ≤ i ∧ i < 20) by omega), if_neg (show ¬ (20 ≤ i ∧ i < 24) by omega),
                  if_neg (Nat.not_lt.2 h), if_neg (Nat.not_lt.2 h2), if_neg (Nat.not_lt.2 h3),
                  if_neg (Nat.not_lt.2 h4), if_neg (Nat.not_lt.2 h5), if_neg (Nat.not_lt.2 h6),
                  UInt8.zero_or, UInt8.zero_or, UInt8.zero_or, UInt8.zero_or, UInt8.zero_or, UInt8.zero_or]
              congr 1; omega

/-- **ADRS word-layout bridge.** The big-endian 256-bit word of `Spec.Adrs.make`'s
    32-byte packed structure is the disjoint byte-aligned OR of its seven fields —
    `ofU32BE layer ‖ ofU64BE tree ‖ … ‖ ofU32BE ha` read as one word equals the Yul
    `or(shl 224 layer, or(shl 160 tree, …))`. Proved byte-extensionally. -/
theorem wordOf_make (layer : UInt32) (tree : UInt64) (atype kp ci cp ha : UInt32) :
    wordOf (Spec.Adrs.make layer tree atype kp ci cp ha)
      = layer.toNat <<< 224 ||| tree.toNat <<< 160 ||| atype.toNat <<< 128
        ||| kp.toNat <<< 96 ||| ci.toNat <<< 64 ||| cp.toNat <<< 32 ||| ha.toNat := by
  apply eq_of_beByte
  · exact wordOf_lt _
  · exact make_rhs_lt layer tree atype kp ci cp ha
  · intro i hi
    rw [beByte_wordOf_getD (Spec.Adrs.make layer tree atype kp ci cp ha) i hi,
        make_data_getD_beByte layer tree atype kp ci cp ha i hi,
        make_rhs_beByte layer tree atype kp ci cp ha i hi]

/-- **FORS-node ADRS word.** `forsNode = make 0 htIdx FORS_TREE treeIdx 0 height
    parentIdx`; the `layer = 0` and `ci = 0` shifts vanish (the deployed Yul
    `or(shl(160,htIdx), or(shl(128,3), or(shl(96,treeIdx), node)))`). -/
theorem wordOf_forsNode (htIdx : UInt64) (treeIdx height parentIdx : UInt32) :
    wordOf (Spec.Adrs.forsNode htIdx treeIdx height parentIdx)
      = htIdx.toNat <<< 160 ||| (UInt32.ofNat Spec.ADRS_FORS_TREE).toNat <<< 128
        ||| treeIdx.toNat <<< 96 ||| height.toNat <<< 32 ||| parentIdx.toNat := by
  unfold Spec.Adrs.forsNode
  rw [wordOf_make]
  show (0 : UInt32).toNat <<< 224 ||| htIdx.toNat <<< 160 ||| _ ||| _
        ||| (0 : UInt32).toNat <<< 64 ||| _ ||| _ = _
  rw [show (0 : UInt32).toNat = 0 from rfl, Nat.zero_shiftLeft, Nat.zero_or, Nat.zero_shiftLeft]
  rw [Nat.or_zero]

/-- **FORS-roots ADRS word.** `forsRoots = make 0 htIdx FORS_ROOTS 0 0 0 0` (Yul
    `or(shl(160,htIdx), shl(128,4))`). -/
theorem wordOf_forsRoots (htIdx : UInt64) :
    wordOf (Spec.Adrs.forsRoots htIdx)
      = htIdx.toNat <<< 160 ||| (UInt32.ofNat Spec.ADRS_FORS_ROOTS).toNat <<< 128 := by
  unfold Spec.Adrs.forsRoots
  rw [wordOf_make]
  show (0 : UInt32).toNat <<< 224 ||| htIdx.toNat <<< 160 ||| _ ||| (0 : UInt32).toNat <<< 96
        ||| (0 : UInt32).toNat <<< 64 ||| (0 : UInt32).toNat <<< 32 ||| (0 : UInt32).toNat = _
  rw [show (0 : UInt32).toNat = 0 from rfl, Nat.zero_shiftLeft, Nat.zero_or, Nat.zero_shiftLeft,
      Nat.or_zero, Nat.zero_shiftLeft, Nat.or_zero, Nat.zero_shiftLeft, Nat.or_zero, Nat.or_zero]

/-- **XMSS-tree-node ADRS word.** `treeNode = make layer tree ADRS_TREE 0 0 height
    parentIdx`; `kp = ci = 0` vanish (Yul masked `or(shl(224,layer), or(shl(160,tree),
    shl(128,2)))`). -/
theorem wordOf_treeNode (layer : UInt32) (tree : UInt64) (height parentIdx : UInt32) :
    wordOf (Spec.Adrs.treeNode layer tree height parentIdx)
      = layer.toNat <<< 224 ||| tree.toNat <<< 160 ||| (UInt32.ofNat Spec.ADRS_TREE).toNat <<< 128
        ||| height.toNat <<< 32 ||| parentIdx.toNat := by
  unfold Spec.Adrs.treeNode
  rw [wordOf_make]
  show _ ||| _ ||| _ ||| (0 : UInt32).toNat <<< 96 ||| (0 : UInt32).toNat <<< 64 ||| _ ||| _ = _
  rw [show (0 : UInt32).toNat = 0 from rfl, Nat.zero_shiftLeft, Nat.or_zero, Nat.zero_shiftLeft,
      Nat.or_zero]

/-- Regression guard: `wordOf_forsNode` discharges `fors_tree_body`'s `H_leafAdrs`
    obligation — the `(htIdx<<<160) | (3<<<128) | (t<<<96) | leafTreeIdx` Yul word
    is the spec `forsNode` word, given the digest→leaf-index identity `H_idx` and
    `t < 12`. The `% W` truncations are inert (each field shift `< 2^256`) and the
    `|||` reassociates (`Nat.or_assoc`). -/
private theorem H_leafAdrs_dischargeable
    (htIdx : UInt64) (t : Nat) (leafIdx : UInt32) (dVal : Nat)
    (ht : t < 12)
    (H_idx : (dVal >>> (t * 11)) &&& 0x7FF = leafIdx.toNat) :
    (htIdx.toNat <<< 160 % W) ||| ((3 <<< 128 % W) ||| ((t <<< 96 % W) |||
        ((dVal >>> (t * 11)) &&& 0x7FF)))
      = wordOf (Spec.Adrs.forsNode htIdx (UInt32.ofNat t) 0 leafIdx) := by
  rw [wordOf_forsNode, H_idx]
  have hFT : (UInt32.ofNat Spec.ADRS_FORS_TREE).toNat = 3 := by decide
  have hti : (UInt32.ofNat t).toNat = t := by
    show t % UInt32.size = t
    rw [Nat.mod_eq_of_lt (Nat.lt_trans ht (by decide))]
  rw [hFT, hti]
  show _ = _ ||| _ ||| _ ||| (0 : UInt32).toNat <<< 32 ||| leafIdx.toNat
  rw [show (0 : UInt32).toNat = 0 from rfl, Nat.zero_shiftLeft, Nat.or_zero]
  have hW1 : htIdx.toNat <<< 160 % W = htIdx.toNat <<< 160 :=
    Nat.mod_eq_of_lt (shl_lt_two_pow_256 _ 64 160 htIdx.toNat_lt (by omega))
  have hW2 : (3 : Nat) <<< 128 % W = 3 <<< 128 :=
    Nat.mod_eq_of_lt (shl_lt_two_pow_256 _ 2 128 (by decide) (by omega))
  have hW3 : t <<< 96 % W = t <<< 96 :=
    Nat.mod_eq_of_lt (shl_lt_two_pow_256 _ 12 96 (Nat.lt_trans ht (by decide)) (by omega))
  rw [hW1, hW2, hW3]
  simp only [Nat.or_assoc]

/-! ## Non-vacuity guards for `fors_tree_body`'s bounded obligations

`fors_tree_body` carries its `H_adrs` / `H_sib` as *bounded* (hence satisfiable)
factored hypotheses — `authPath` appears in its conclusion, so a literal inline
discharge that removes the hypothesis would have to rewrite the conclusion (which
must stay identical). These two guards prove the bounded forms are inhabited (always
true / discharged from the deserialised auth path) — the regression that fences out
re-introducing an *unsatisfiable* hypothesis (the original vacuity defect). They are
the `H_leafAdrs_dischargeable` analogues for the climb-level ADRS word and the
sibling read. -/

/-- **`H_adrs` is always true (bounded).** `fors_tree_body`'s climb-ADRS obligation
    — for `h < A` and `p < 2^32` the Yul word
    `(htIdx<<<160 | 3<<<128 | t<<<96) | ((h+1)<<<32 | p>>1)` is the spec `forsNode`
    word `forsNode htIdx t (h+1) (p/2)`. Discharged from `wordOf_forsNode` + the
    `UInt32.ofNat`-roundtrips (`h+1 < 2^32`, `p/2 < 2^32`, `t < 12`) + the mod-inert
    field shifts + `Nat.or_assoc`. The bounds are exactly what make it provable. -/
theorem H_adrs_dischargeable
    (htIdx : UInt64) (t : Nat) (ht : t < 12) (h : Nat) (hh : h < Spec.A) (p : Nat) (hp : p < 2 ^ 32) :
    ((htIdx.toNat <<< 160 % W) ||| ((3 <<< 128 % W) ||| (t <<< 96 % W)))
      ||| (((h + 1) % W) <<< 32 % W ||| p >>> 1)
    = wordOf (Spec.Adrs.forsNode htIdx (UInt32.ofNat t) (UInt32.ofNat (h + 1))
        (UInt32.ofNat (p / 2))) := by
  rw [wordOf_forsNode]
  -- UInt32.ofNat round-trips (all arguments below 2^32).
  have hFT : (UInt32.ofNat Spec.ADRS_FORS_TREE).toNat = 3 := by decide
  have hti : (UInt32.ofNat t).toNat = t := by
    show t % UInt32.size = t
    rw [Nat.mod_eq_of_lt (Nat.lt_trans ht (by decide))]
  have hszU : (UInt32.size : Nat) = 2 ^ 32 := rfl
  have hh1 : (UInt32.ofNat (h + 1)).toNat = h + 1 := by
    show (h + 1) % UInt32.size = h + 1
    rw [hszU, Nat.mod_eq_of_lt (by have : Spec.A = 11 := rfl; omega)]
  have hp2 : (UInt32.ofNat (p / 2)).toNat = p / 2 := by
    show (p / 2) % UInt32.size = p / 2
    rw [hszU, Nat.mod_eq_of_lt (Nat.lt_of_le_of_lt (Nat.div_le_self p 2) hp)]
  rw [hFT, hti, hh1, hp2]
  -- Resolve the LHS `% W` truncations (each field shift < 2^256).
  have hWh : (h + 1) % W = h + 1 := Nat.mod_eq_of_lt (lt_W_of_lt (by have : Spec.A = 11 := rfl; omega))
  have hWh32 : (h + 1) <<< 32 % W = (h + 1) <<< 32 :=
    Nat.mod_eq_of_lt (shl_lt_two_pow_256 _ 6 32 (by have : Spec.A = 11 := rfl; omega) (by omega))
  have hW1 : htIdx.toNat <<< 160 % W = htIdx.toNat <<< 160 :=
    Nat.mod_eq_of_lt (shl_lt_two_pow_256 _ 64 160 htIdx.toNat_lt (by omega))
  have hW2 : (3 : Nat) <<< 128 % W = 3 <<< 128 :=
    Nat.mod_eq_of_lt (shl_lt_two_pow_256 _ 2 128 (by decide) (by omega))
  have hW3 : t <<< 96 % W = t <<< 96 :=
    Nat.mod_eq_of_lt (shl_lt_two_pow_256 _ 12 96 (Nat.lt_trans ht (by decide)) (by omega))
  -- p >>> 1 = p / 2.
  have hsh : p >>> 1 = p / 2 := by rw [Nat.shiftRight_eq_div_pow, Nat.pow_one]
  rw [hWh, hWh32, hW1, hW2, hW3, hsh]
  simp only [Nat.or_assoc]

/-- **`H_sib` is satisfiable.** Instantiate `fors_tree_body`'s sibling obligation on
    the *real* deserialised auth path `authPath := (deserialise sig).fors.authPaths.getD
    t #[]`: for `h < A`, the masked calldata read at `224 + 176t + 16h` equals
    `wordOf (pad16 (authPath.getD h …))`. Discharged from `cl_masked_eq_wordOf` (the
    calldata read-back) + the `Array.ofFn`/`getD` evaluation of `deserialise`'s auth
    layout + `shl4_small` (the `% W` strides are inert). Witnesses that the bounded
    `H_sib` is inhabited (never the unsatisfiable unbounded form). -/
theorem H_sib_dischargeable
    (sig : ByteVec Spec.SignatureLen) (t : Nat) (ht : t < 12) (h : Nat) (hh : h < Spec.A) :
    calldataload sig (((224 + t * 176) + h <<< 4 % W) % W) &&& NMASK
      = wordOf (ByteVec.pad16
          (((Spec.Signature.deserialise sig).fors.authPaths.getD t #[]).getD h (ByteVec.zero 16))) := by
  -- Normalise the offset: the `% W` strides are inert (224 + 176t + 16h < 4096).
  have hoff : ((224 + t * 176) + h <<< 4 % W) % W = 224 + t * 176 + 16 * h := by
    rw [shl4_small h (by have : Spec.A = 11 := rfl; omega),
        Nat.mod_eq_of_lt (lt_W_of_lt (show 224 + t * 176 + 16 * h < 4096 by
          have : Spec.A = 11 := rfl; omega))]
  rw [hoff, cl_masked_eq_wordOf sig (224 + t * 176 + 16 * h)]
  -- The deserialised auth-path entry at `(t, h)` is exactly `loadValue16 sig (224 + 176t + 16h)`.
  have hauth :
      ((Spec.Signature.deserialise sig).fors.authPaths.getD t #[]).getD h (ByteVec.zero 16)
        = ByteVec.loadValue16 sig (224 + t * 176 + 16 * h) := by
    show ((Array.ofFn (n := Spec.K - 1) fun t' =>
            Array.ofFn (n := Spec.A) fun h' =>
              ByteVec.loadValue16 sig
                (Spec.SigR + Spec.SigForsSecrets + t'.val * (Spec.A * Spec.N) + h'.val * Spec.N)).getD t #[]).getD h (ByteVec.zero 16)
          = ByteVec.loadValue16 sig (224 + t * 176 + 16 * h)
    -- Resolve the OUTER `getD t` (tree row) first, then the INNER `getD h` (level).
    have houter :
        (Array.ofFn (n := Spec.K - 1) fun t' =>
            Array.ofFn (n := Spec.A) fun h' =>
              ByteVec.loadValue16 sig
                (Spec.SigR + Spec.SigForsSecrets + t'.val * (Spec.A * Spec.N) + h'.val * Spec.N)).getD t #[]
          = Array.ofFn (n := Spec.A) fun h' =>
              ByteVec.loadValue16 sig
                (Spec.SigR + Spec.SigForsSecrets + t * (Spec.A * Spec.N) + h'.val * Spec.N) := by
      rw [Array.getD_eq_getD_getElem?, Array.getElem?_ofFn,
          dif_pos (show t < Spec.K - 1 by have : Spec.K = 13 := rfl; omega), Option.getD_some]
    rw [houter, Array.getD_eq_getD_getElem?, Array.getElem?_ofFn,
        dif_pos (show h < Spec.A by exact hh), Option.getD_some]
    congr 1
    -- SigR + SigForsSecrets + t*(A*N) + h*N = 224 + 176t + 16h.
    have hR : Spec.SigR = 16 := rfl
    have hS : Spec.SigForsSecrets = 208 := rfl
    have hAN : Spec.A * Spec.N = 176 := rfl
    have hN : Spec.N = 16 := rfl
    -- (Fin.val of the `dif_pos` witnesses are `t` / `h`; mathlib-free Nat algebra:
    -- `16 + 208 + t*176 + h*16` is defeq to `224 + t*176 + 16*h` after `mul_comm`.)
    rw [hR, hS, hAN, hN, Nat.mul_comm h 16]
  rw [hauth]

/-! ## Non-vacuity regression for `fors_tree_body`

This is the *guard* the task demands: it does not re-prove a shape, it **applies**
`fors_tree_body` on a concrete satisfiable setup (FORS tree `t = 0`, `htIdx = 0`,
`dVal = 0`, leaf index `0`, the deserialised auth path), discharging EVERY hypothesis
— the env preconditions via the `setVar` chain, `H_leafAdrs`/`H_adrs`/`H_sib` via the
`_dischargeable` guards, `H_idx` by computation. If any hypothesis ever reverts to the
old *unsatisfiable* unbounded form, the corresponding `_dischargeable` term stops
typechecking and THIS theorem fails to compile — exactly the regression that fences
out re-introducing a vacuous hypothesis. -/
private theorem fors_tree_body_nonvacuous (sig : ByteVec Spec.SignatureLen)
    (seed : ByteVec 32) : True := by
  -- Concrete climb-entry env: every `fors_tree_body` env-precond var bound, dVal := 0.
  let env0 : VarEnv :=
    setVar (setVar (setVar (setVar (setVar (setVar (setVar (fun _ => 0)
      "htIdx" 0) "sigBase" 0) "seed" (wordOf seed)) "N_MASK" NMASK)
      "OUT" 0x600) "i" 0) "dVal" 0
  let vm0 : VM := { mem := memOfBytes seed, env := env0 }
  -- H_idx for the concrete (dVal=0, leafIdx=0) tree: both sides are 0.
  have hidx0 : (vm0.env "dVal" >>> (0 * 11)) &&& 0x7FF = (UInt32.ofNat 0).toNat := by
    show (env0 "dVal" >>> (0 * 11)) &&& 0x7FF = (UInt32.ofNat 0).toNat
    simp only [env0, setVar, String.reduceEq, if_true, ite_false]
    decide
  -- Apply fors_tree_body; every hypothesis discharged. The mere fact that this
  -- term elaborates is the non-vacuity certificate.
  have _inst := fors_tree_body sig vm0 seed (0 : UInt64) 0 (UInt32.ofNat 0)
    ((Spec.Signature.deserialise sig).fors.authPaths.getD 0 #[])
    (by decide)                                   -- ht : 0 < 12
    (by show env0 "htIdx" = (0 : UInt64).toNat; simp [env0, setVar])                -- hht
    (by show env0 "sigBase" = 0; simp [env0, setVar])                               -- hsb
    (by show env0 "seed" = wordOf seed; simp [env0, setVar])                        -- hseedw
    (by show env0 "N_MASK" = NMASK; simp [env0, setVar])                            -- hN
    (by show env0 "OUT" = 0x600; simp [env0, setVar])                               -- hOUT
    (by show env0 "i" = 0; simp [env0, setVar])                                     -- hival
    (fun i hi => by                                                                 -- hseedmem
      show memOfBytes seed (0 + i) = seed.data.getD i 0
      have hsz : i < seed.data.size := by rw [seed.size_eq]; exact hi
      unfold memOfBytes
      rw [Nat.zero_add, dif_pos hsz, Array.getD_eq_getD_getElem?,
          Array.getElem?_eq_getElem hsz, Option.getD_some])
    (H_leafAdrs_dischargeable (0 : UInt64) 0 (UInt32.ofNat 0) (vm0.env "dVal") (by decide) hidx0)
    hidx0                                                                           -- H_idx
    (fun h hh p hp => H_adrs_dischargeable (0 : UInt64) 0 (by decide) h hh p hp)    -- H_adrs
    (fun h hh => H_sib_dischargeable sig 0 (by decide) h hh)                        -- H_sib
  trivial

/-! ## FORS phase: the K-1 normal-tree i-loop, the last tree, and root compression

The three remaining FORS fragments after `fors_tree_body`'s per-tree refinement:

  1. `fors_normal_trees` — the outer `forRange "i" 12`: drive `fors_tree_body` 12×
     (`execFor_invariant_lt`), each iteration laying `pad16 (reconstructRoot …)` at
     `0x80 + 32*t`, the seed window + the loop consts persisting.
  2. `fors_last_tree` — the forced-zero last tree (`{ }` block): `th seed (forsNode
     htIdx 12 0 0) (pad16 lastSecret)` written `pad16`'d at `0x200 = 0x80 + 32*12`.
  3. `fors_root_compress` — the `forRange "i" 13` copy + the 480-byte compression
     `sha256(0x00, 0x1E0)` = `computeForsPk` (`thMulti`).
  4. `fors_phase` — composes all three from the post-`H_msg` VM, dispatching the
     forced-zero `ifnz`, into `env "forsPk" = wordOf (pad16 (reconstructForsPk …))`.

The leaf indices are kept in the *interpreter-side* form `(dVal >>> (t*11)) &&& 0x7FF`
through trees 1–3 (so `fors_tree_body`'s `H_idx` is `rfl`), and bridged to
`extractForsIndices` only at the `fors_phase` capstone via `extractForsIndices_eq_wordShift`. -/

/-! ### The `readBitsLe`↔word-shift index bridge

`extractForsIndices`/`extractHtIndex` read A-bit / H-bit little-endian windows out of
the 32-byte digest (`readBitsLe`: bit 0 = LSB of `digest[31]`); the interpreter reads the
SAME windows by shifting the big-endian-assembled word `wordOf digest`. The two agree
because `wordOf` packs `digest[0]` as the MSB, so logical bit `j` of `wordOf digest`
(`>>>`, LSB-first) is exactly `digest[31 - j/8]`'s bit `j%8` — `readBitsLe.stepValue`'s
selection. Proved bit-extensionally (`Nat.eq_of_testBit_eq`). -/

/-- `wordOf v`'s logical bit `b` (`b < 256`) is `digest[31 - b/8]`'s bit `b % 8` —
    the LSB-first bit at position `b` of the big-endian-assembled word. -/
private theorem wordOf_testBit (v : ByteVec 32) (b : Nat) (hb : b < 256) :
    (wordOf v).testBit b = (v.data.getD (31 - b / 8) 0).toNat.testBit (b % 8) := by
  -- byte (31 - b/8) of v is big-endian byte index `i = 31 - (31 - b/8) = b/8`… use beByte.
  have hbyte : v.data.getD (31 - b / 8) 0 = beByte (wordOf v) (31 - b / 8) := by
    rw [beByte_wordOf_getD v (31 - b / 8) (by omega)]
  rw [hbyte, beByte_toNat']
  -- (wordOf v >>> (8*(31-(31-b/8))) % 256).testBit (b%8) ; 31-(31-b/8) = b/8.
  rw [show 31 - (31 - b / 8) = b / 8 by omega]
  rw [show (256 : Nat) = 2 ^ 8 from rfl, Nat.testBit_mod_two_pow, Nat.testBit_shiftRight]
  have hsum : 8 * (b / 8) + b % 8 = b := by omega
  rw [hsum, decide_eq_true (show b % 8 < 8 by omega), Bool.true_and]

/-- `x &&& 1 < 2`. -/
private theorem and_one_lt_two' (x : Nat) : x &&& 1 < 2 := by
  have h : x &&& 1 < 2 ^ 1 := Nat.and_lt_two_pow x (by decide : (1 : Nat) < 2 ^ 1)
  simpa using h

/-- `readBitsLe.stepValue v off i`'s only set bit (if any) is bit `i`, and it is set
    iff `wordOf v`'s bit `off + i` is set (`off + i < 256`). The per-step bit witness. -/
private theorem stepValue_testBit (v : ByteVec 32) (off i j : Nat) (hoi : off + i < 256) :
    (SphincsCVerify.Util.readBitsLe.stepValue v off i).testBit j
      = (decide (j = i) && (wordOf v).testBit (off + i)) := by
  unfold SphincsCVerify.Util.readBitsLe.stepValue
  -- value = ((b.toNat >>> (bitInByte)) &&& 1) <<< i, with byteIdx = 31 - (off+i)/8.
  simp only []
  rw [Nat.testBit_shiftLeft]
  by_cases hj : i ≤ j
  · rw [decide_eq_true hj, Bool.true_and]
    -- inner: ((b.toNat >>> ((off+i)%8)) &&& 1).testBit (j - i)
    by_cases hji : j = i
    · subst hji
      rw [decide_eq_true (rfl : j = j), Bool.true_and, Nat.sub_self]
      -- (x &&& 1).testBit 0 = x.testBit 0 ; and the byteIdx branch
      have hbyteIdx : (31 - (off + j) / 8) < 32 := by omega
      rw [if_pos hbyteIdx]
      rw [Nat.testBit_and, Nat.testBit_shiftRight]
      rw [show (1 : Nat).testBit 0 = true from rfl, Bool.and_true]
      -- v.get ⟨31-(off+j)/8,_⟩'s bit ((off+j)%8) = wordOf v's bit (off+j)
      rw [wordOf_testBit v (off + j) hoi, Nat.add_zero]
      have hge : v.get ⟨31 - (off + j) / 8, by omega⟩ = v.data.getD (31 - (off + j) / 8) 0 := by
        unfold ByteVec.get
        rw [Array.getD_eq_getD_getElem?,
            Array.getElem?_eq_getElem (show 31 - (off+j)/8 < v.data.size by rw [v.size_eq]; omega),
            Option.getD_some]
        rfl
      rw [hge]
    · rw [decide_eq_false hji, Bool.false_and]
      -- (x &&& 1).testBit (j-i) with j-i ≥ 1 is false (x&&&1 < 2)
      have hji1 : 1 ≤ j - i := by omega
      have hlt : ((if 31 - (off + i) / 8 < 32 then v.get ⟨31 - (off + i) / 8, by omega⟩ else 0).toNat
          >>> ((off + i) % 8)) &&& 1 < 2 ^ (j - i) := by
        calc _ < 2 := and_one_lt_two' _
          _ ≤ 2 ^ (j - i) := by
              calc (2:Nat) = 2 ^ 1 := rfl
                _ ≤ 2 ^ (j - i) := Nat.pow_le_pow_right (by decide) hji1
      rw [Nat.testBit_lt_two_pow hlt]
  · rw [decide_eq_false hj, Bool.false_and]
    rw [decide_eq_false (show ¬ j = i by omega), Bool.false_and]

/-- `readBitsLe.loop` accumulates exactly the bits `[off, off + numBits)` of `wordOf v`,
    shifted down to `[0, numBits)`: bit `j` of the loop result (for `j < numBits`) is
    bit `off + j` of `wordOf v`. Inductive over the loop's fuel. -/
private theorem readBitsLe_loop_testBit (v : ByteVec 32) (off numBits : Nat)
    (hbound : off + numBits ≤ 256) :
    ∀ (d i acc : Nat), numBits - i = d → i ≤ numBits →
      (∀ j, acc.testBit j = (decide (j < i) && (wordOf v).testBit (off + j))) →
      ∀ j, (SphincsCVerify.Util.readBitsLe.loop v off numBits i acc).testBit j
        = (decide (j < numBits) && (wordOf v).testBit (off + j)) := by
  intro d
  induction d with
  | zero =>
      intro i acc hd hi hacc j
      have hie : i = numBits := by omega
      subst hie
      unfold SphincsCVerify.Util.readBitsLe.loop
      rw [if_neg (by omega)]
      exact hacc j
  | succ d ih =>
      intro i acc hd hi hacc j
      have hilt : i < numBits := by omega
      unfold SphincsCVerify.Util.readBitsLe.loop
      rw [if_pos hilt]
      apply ih (i + 1) (acc ||| SphincsCVerify.Util.readBitsLe.stepValue v off i) (by omega) (by omega)
      intro j'
      rw [Nat.testBit_or, hacc j', stepValue_testBit v off i j' (by omega)]
      by_cases hji : j' = i
      · subst hji
        rw [decide_eq_true (rfl : j' = j'), Bool.true_and,
            decide_eq_false (Nat.lt_irrefl j'), Bool.false_and, Bool.false_or,
            decide_eq_true (Nat.lt_succ_self j'), Bool.true_and]
      · rw [decide_eq_false hji, Bool.false_and, Bool.or_false]
        by_cases hjlt : j' < i
        · rw [decide_eq_true hjlt, decide_eq_true (Nat.lt_succ_of_lt hjlt)]
        · rw [decide_eq_false hjlt, decide_eq_false (show ¬ j' < i + 1 by omega)]

/-- **The index bridge.** `readBitsLe v off k` (the spec's LE bit-window read) equals
    `(wordOf v >>> off) &&& (2^k - 1)` (the interpreter's word-shift-and-mask), for
    `off + k ≤ 256`. The common foundation for `extractForsIndices`/`extractHtIndex`
    alignment with the deployed Yul `and(shr(off, dVal), MASK)`. -/
theorem readBitsLe_eq_wordShift (v : ByteVec 32) (off k : Nat) (hbound : off + k ≤ 256) :
    SphincsCVerify.Util.readBitsLe v off k = (wordOf v >>> off) &&& (2 ^ k - 1) := by
  apply Nat.eq_of_testBit_eq
  intro j
  unfold SphincsCVerify.Util.readBitsLe
  rw [readBitsLe_loop_testBit v off k hbound k 0 0 rfl (Nat.zero_le _)
        (fun j => by rw [Nat.zero_testBit, decide_eq_false (Nat.not_lt_zero j), Bool.false_and]) j]
  rw [Nat.testBit_and, Nat.testBit_shiftRight, Nat.testBit_two_pow_sub_one]
  by_cases hjk : j < k
  · rw [decide_eq_true hjk, Bool.true_and, Bool.and_true, Nat.add_comm]
  · rw [decide_eq_false hjk, Bool.false_and, Bool.and_false]

/-- **FORS index alignment.** For `t < K`, the spec's `(extractForsIndices digest).getD
    t 0` (= `readBitsLe digest (t*A) A`) is the interpreter's `(wordOf digest >>> (t*11))
    &&& 0x7FF`. The per-tree corollary of `readBitsLe_eq_wordShift` (`A = 11`, mask
    `2^11-1 = 0x7FF`, window `[t*11, (t+1)*11) ⊆ [0, 143) ⊆ [0, 256)`). -/
theorem extractForsIndices_eq_wordShift (digest : ByteVec 32) (t : Nat) (ht : t < Spec.K) :
    (SphincsCVerify.Util.extractForsIndices digest).getD t 0
      = (wordOf digest >>> (t * 11)) &&& 0x7FF := by
  unfold SphincsCVerify.Util.extractForsIndices
  rw [Array.getD_eq_getD_getElem?, Array.getElem?_ofFn,
      dif_pos (show t < Spec.K by exact ht), Option.getD_some]
  have hA : Spec.A = 11 := rfl
  rw [show ((⟨t, ht⟩ : Fin Spec.K).val * Spec.A) = t * 11 by rw [hA]]
  rw [readBitsLe_eq_wordShift digest (t * 11) Spec.A (by rw [hA]; have : Spec.K = 13 := rfl; omega)]
  rw [hA]

/-- **Hypertree index alignment.** `extractHtIndex digest` (= `readBitsLe digest (K*A)
    H`) is `(wordOf digest >>> 143) &&& 0x3FFFF` — the interpreter's `htIdx` (`K*A = 143`,
    `H = 18`, mask `2^18-1 = 0x3FFFF`). -/
theorem extractHtIndex_eq_wordShift (digest : ByteVec 32) :
    SphincsCVerify.Util.extractHtIndex digest = (wordOf digest >>> 143) &&& 0x3FFFF := by
  unfold SphincsCVerify.Util.extractHtIndex
  rw [show (Spec.K * Spec.A) = 143 from rfl,
      readBitsLe_eq_wordShift digest 143 Spec.H (by have : Spec.H = 18 := rfl; omega)]
  rfl

/-! ### `forsTreeBody` env frame

`forsTreeBody` only binds (`letv`/`setv`) the names `treeIdx, secretVal, leafAdrs, node,
treeAdrsBase, pathIdx, authPtr` at the top level and `sibling, parentIdx, s, h, node,
pathIdx` inside the inner climb. So any variable distinct from those (and from the outer
`"i"`, which the loop driver sets) survives one body — the const-env half `fors_tree_body`
doesn't surface but the outer i-loop invariant needs to carry `htIdx/sigBase/seed/
N_MASK/OUT/dVal`. -/

/-- One climb level preserves any variable `x` it never binds (`x ∉ {sibling, parentIdx,
    s, node, pathIdx, h}`). The var-generalised `execList_forsClimbBody_preserves_i`. -/
private theorem execList_forsClimbBody_preserves_var (sig : ByteVec Spec.SignatureLen)
    (cur : Nat) (v : VM) (x : String)
    (hx : x ≠ "sibling" ∧ x ≠ "parentIdx" ∧ x ≠ "s" ∧ x ≠ "node" ∧ x ≠ "pathIdx" ∧ x ≠ "h") :
    (execList c10Oracle sig forsClimbBody { v with env := setVar v.env "h" cur }).1.env x
        = v.env x := by
  obtain ⟨h1, h2, h3, h4, h5, h6⟩ := hx
  unfold forsClimbBody
  rw [execList_cons_none c10Oracle sig _ _ _ (by simp only [execStmt])]
  rw [execList_cons_none c10Oracle sig _ _ _ (by simp only [execStmt])]
  rw [execList_cons_none c10Oracle sig _ _ _ (by simp only [execStmt])]
  rw [execList_cons_none c10Oracle sig _ _ _ (by simp only [execStmt])]
  rw [execList_cons_none c10Oracle sig _ _ _ (by simp only [execStmt])]
  rw [execList_cons_none c10Oracle sig _ _ _ (by simp only [execStmt])]
  rw [execList_cons_none c10Oracle sig _ _ _ (by simp only [execStmt])]
  rw [execList_cons_none c10Oracle sig _ _ _ (by simp only [execStmt])]
  rw [execList_cons_none c10Oracle sig _ _ _ (by simp only [execStmt])]
  rw [execList]
  simp only [execStmt, eval, setVar, h1, h2, h3, h4, h5, h6, ite_false]

/-- The whole inner climb preserves any unbound variable `x`. The var-generalised
    `execFor_forsClimbBody_preserves_i`. -/
private theorem execFor_forsClimbBody_preserves_var (sig : ByteVec Spec.SignatureLen)
    (x : String)
    (hx : x ≠ "sibling" ∧ x ≠ "parentIdx" ∧ x ≠ "s" ∧ x ≠ "node" ∧ x ≠ "pathIdx" ∧ x ≠ "h") :
    ∀ (remaining cur : Nat) (v : VM),
      (execFor c10Oracle sig "h" forsClimbBody remaining cur v).1.env x = v.env x := by
  intro remaining
  induction remaining with
  | zero => intro cur v; simp only [execFor]
  | succ rem ih =>
      intro cur v
      obtain ⟨hnone, _⟩ := execList_forsClimbBody_preserves_i sig cur v
      rw [execFor]
      rcases hp : execList c10Oracle sig forsClimbBody { v with env := setVar v.env "h" cur }
        with ⟨pvm, po⟩
      rw [hp] at hnone
      subst hnone
      simp only []
      rw [ih (cur + 1) pvm]
      have := execList_forsClimbBody_preserves_var sig cur v x hx
      rw [hp] at this
      exact this

/-- The inner climb (`execFor … forsClimbBody`) always falls through (no `revert`/`return`
    in `forsClimbBody`). Drives `execList_forsClimbBody_preserves_i`'s none witness. -/
private theorem execFor_forsClimbBody_none (sig : ByteVec Spec.SignatureLen) :
    ∀ (remaining cur : Nat) (v : VM),
      (execFor c10Oracle sig "h" forsClimbBody remaining cur v).2 = none := by
  intro remaining
  induction remaining with
  | zero => intro cur v; simp only [execFor]
  | succ rem ih =>
      intro cur v
      obtain ⟨hnone, _⟩ := execList_forsClimbBody_preserves_i sig cur v
      rw [execFor]
      rcases hp : execList c10Oracle sig forsClimbBody { v with env := setVar v.env "h" cur }
        with ⟨pvm, po⟩
      rw [hp] at hnone
      subst hnone
      simp only []
      exact ih (cur + 1) pvm

/-- **`forsTreeBody` preserves the const-env.** A variable `x` distinct from every name
    `forsTreeBody` binds — `{treeIdx, secretVal, leafAdrs, node, treeAdrsBase, pathIdx,
    authPtr, sibling, parentIdx, s, h}` — reads the same after the body (entered with
    `"i" := cur`) as `v.env x`. Lets the i-loop carry `htIdx/sigBase/seed/N_MASK/OUT/dVal`. -/
private theorem execList_forsTreeBody_preserves_const (sig : ByteVec Spec.SignatureLen)
    (cur : Nat) (v : VM) (x : String)
    (hx : x ≠ "treeIdx" ∧ x ≠ "secretVal" ∧ x ≠ "leafAdrs" ∧ x ≠ "node" ∧ x ≠ "treeAdrsBase"
        ∧ x ≠ "pathIdx" ∧ x ≠ "authPtr" ∧ x ≠ "sibling" ∧ x ≠ "parentIdx" ∧ x ≠ "s" ∧ x ≠ "h"
        ∧ x ≠ "i") :
    (execList c10Oracle sig forsTreeBody { v with env := setVar v.env "i" cur }).1.env x
        = v.env x := by
  obtain ⟨h1, h2, h3, h4, h5, h6, h7, h8, h9, h10, h11, h12⟩ := hx
  unfold forsTreeBody
  -- Step the 10 leading non-loop statements (all `letv`/`mstore`/`sha256`, no halt).
  rw [execList_cons_none c10Oracle sig _ _ _ (by simp only [execStmt])]
  rw [execList_cons_none c10Oracle sig _ _ _ (by simp only [execStmt])]
  rw [execList_cons_none c10Oracle sig _ _ _ (by simp only [execStmt])]
  rw [execList_cons_none c10Oracle sig _ _ _ (by simp only [execStmt])]
  rw [execList_cons_none c10Oracle sig _ _ _ (by simp only [execStmt])]
  rw [execList_cons_none c10Oracle sig _ _ _ (by simp only [execStmt])]
  rw [execList_cons_none c10Oracle sig _ _ _ (by simp only [execStmt])]
  rw [execList_cons_none c10Oracle sig _ _ _ (by simp only [execStmt])]
  rw [execList_cons_none c10Oracle sig _ _ _ (by simp only [execStmt])]
  rw [execList_cons_none c10Oracle sig _ _ _ (by simp only [execStmt])]
  -- Now: forRange "h" 11 forsClimbBody :: [mstore …]. Abbreviate the post-10-letv VM.
  obtain ⟨w', hw'⟩ :
      ∃ w', w' = (execStmt c10Oracle sig (Stmt.letv "authPtr" (.bin .add (.var "sigBase")
          (.bin .add (.lit 224) (.bin .mul (.var "i") (.lit 176)))))
        (execStmt c10Oracle sig (Stmt.letv "pathIdx" (.var "treeIdx"))
        (execStmt c10Oracle sig (Stmt.letv "treeAdrsBase"
            (.bin .bor (.bin .shl (.lit 160) (.var "htIdx"))
              (.bin .bor (.bin .shl (.lit 128) (.lit 3)) (.bin .shl (.lit 96) (.var "i")))))
        (execStmt c10Oracle sig (Stmt.letv "node" (.bin .band (.mload (.var "OUT")) (.var "N_MASK")))
        (execStmt c10Oracle sig (Stmt.sha256 (.lit 0x00) (.lit 0x60) (.var "OUT"))
        (execStmt c10Oracle sig (Stmt.mstore (.lit 0x40) (.var "secretVal"))
        (execStmt c10Oracle sig (Stmt.mstore (.lit 0x20) (.var "leafAdrs"))
        (execStmt c10Oracle sig (Stmt.letv "leafAdrs"
            (.bin .bor (.bin .shl (.lit 160) (.var "htIdx"))
              (.bin .bor (.bin .shl (.lit 128) (.lit 3))
                (.bin .bor (.bin .shl (.lit 96) (.var "i")) (.var "treeIdx")))))
        (execStmt c10Oracle sig (Stmt.letv "secretVal"
            (.bin .band (.calldataload (.bin .add (.var "sigBase")
              (.bin .add (.lit 16) (.bin .shl (.lit 4) (.var "i"))))) (.var "N_MASK")))
        (execStmt c10Oracle sig (Stmt.letv "treeIdx"
            (.bin .band (.bin .shr (.bin .mul (.var "i") (.lit 11)) (.var "dVal")) (.lit 0x7FF)))
          { v with env := setVar v.env "i" cur }).1).1).1).1).1).1).1).1).1).1 := ⟨_, rfl⟩
  rw [← hw']
  -- The forRange-step: it falls through (climb never halts).
  have hforStmt : execStmt c10Oracle sig (.forRange "h" (.lit 11) forsClimbBody) w'
      = execFor c10Oracle sig "h" forsClimbBody Spec.A 0 w' := by
    simp only [execStmt, eval]; rfl
  have hforNone : (execStmt c10Oracle sig (.forRange "h" (.lit 11) forsClimbBody) w').2 = none := by
    rw [hforStmt]; exact execFor_forsClimbBody_none sig Spec.A 0 w'
  rw [execList_cons_none c10Oracle sig _ _ _ hforNone, hforStmt]
  -- Final statement: mstore (writes mem, not env), then [].
  rw [execList_cons_none c10Oracle sig _ _ _ (by simp only [execStmt]), execList]
  -- env x after the climb = env x of w' (climb preserves x), and env x of w' = v.env x.
  simp only [execStmt, eval]
  rw [execFor_forsClimbBody_preserves_var sig x ⟨h8, h9, h10, h4, h6, h11⟩ Spec.A 0 w']
  -- Now reduce w'.env x through the 10 letvs (none of which is x).
  rw [hw']
  simp only [execStmt, eval, setVar, h1, h2, h3, h4, h5, h6, h7, h12, ite_false]

/-! ### `forsTreeBody` memory frame for laid trees

The body's only writes are scratch `[0x20,0x80)`, the OUT window `[0x600,0x620)`, and the
final node store `[0x80+32*cur, +32)`. So an address `a` in `[0x80, 0x80+32*cur)` (where
laid earlier-tree roots live) survives the body — this is the frame the i-loop needs to
carry trees `t < cur` past iteration `cur`. -/

/-- One climb level preserves any memory address `a` with `0x80 ≤ a < 0x600` (it writes
    only `0x20`/`0x40`/`0x60` in scratch and the OUT window `[0x600,0x620)`). -/
private theorem execList_forsClimbBody_mem_frame (sig : ByteVec Spec.SignatureLen)
    (cur : Nat) (v : VM) (hOUT : v.env "OUT" = 0x600) (a : Nat) (ha : 0x80 ≤ a ∧ a < 0x600) :
    (execList c10Oracle sig forsClimbBody { v with env := setVar v.env "h" cur }).1.mem a
        = v.mem a := by
  obtain ⟨ha1, ha2⟩ := ha
  unfold forsClimbBody
  rw [execList_cons_none c10Oracle sig _ _ _ (by simp only [execStmt])]
  rw [execList_cons_none c10Oracle sig _ _ _ (by simp only [execStmt])]
  rw [execList_cons_none c10Oracle sig _ _ _ (by simp only [execStmt])]
  rw [execList_cons_none c10Oracle sig _ _ _ (by simp only [execStmt])]
  rw [execList_cons_none c10Oracle sig _ _ _ (by simp only [execStmt])]
  rw [execList_cons_none c10Oracle sig _ _ _ (by simp only [execStmt])]
  rw [execList_cons_none c10Oracle sig _ _ _ (by simp only [execStmt])]
  rw [execList_cons_none c10Oracle sig _ _ _ (by simp only [execStmt])]
  rw [execList_cons_none c10Oracle sig _ _ _ (by simp only [execStmt])]
  rw [execList]
  -- Resolve the memory writes; the four mstore/sha256 windows are < 0x80 or ≥ 0x600.
  simp only [execStmt, eval, setVar, String.reduceEq, ite_true, ite_false, hOUT]
  -- Frame `a` through the OUT window [0x600,0x620), then the parity stores, then mstore 0x20.
  rw [writeRegion_frame _ 0x600 _ a (by omega)]
  -- s = (pathIdx & 1) << 5 % W ∈ {0, 32}; both 0x40^s, 0x60^s ∈ {0x40, 0x60} < 0x80.
  have hs := s_value (v.env "pathIdx")
  by_cases hpar : (v.env "pathIdx") % 2 == 0
  · rw [if_pos hpar] at hs
    rw [hs]
    simp only [show (0x40 : Nat) ^^^ 0 = 0x40 from rfl, show (0x60 : Nat) ^^^ 0 = 0x60 from rfl]
    rw [mstore32_frame _ 0x60 _ a (by omega), mstore32_frame _ 0x40 _ a (by omega),
        mstore32_frame _ 0x20 _ a (by omega)]
  · rw [if_neg hpar] at hs
    rw [hs]
    simp only [show (0x40 : Nat) ^^^ 32 = 0x60 from rfl, show (0x60 : Nat) ^^^ 32 = 0x40 from rfl]
    rw [mstore32_frame _ 0x40 _ a (by omega), mstore32_frame _ 0x60 _ a (by omega),
        mstore32_frame _ 0x20 _ a (by omega)]

/-- The whole inner climb preserves any memory address `a` with `0x80 ≤ a < 0x600`
    (`OUT = 0x600` persists across iterations — `forsClimbBody` never rebinds it). -/
private theorem execFor_forsClimbBody_mem_frame (sig : ByteVec Spec.SignatureLen)
    (a : Nat) (ha : 0x80 ≤ a ∧ a < 0x600) :
    ∀ (remaining cur : Nat) (v : VM), v.env "OUT" = 0x600 →
      (execFor c10Oracle sig "h" forsClimbBody remaining cur v).1.mem a = v.mem a := by
  intro remaining
  induction remaining with
  | zero => intro cur v _; simp only [execFor]
  | succ rem ih =>
      intro cur v hOUT
      obtain ⟨hnone, _⟩ := execList_forsClimbBody_preserves_i sig cur v
      rw [execFor]
      rcases hp : execList c10Oracle sig forsClimbBody { v with env := setVar v.env "h" cur }
        with ⟨pvm, po⟩
      rw [hp] at hnone
      subst hnone
      simp only []
      -- OUT persists across the body (forsClimbBody never binds "OUT").
      have hpOUT : pvm.env "OUT" = 0x600 := by
        have := execList_forsClimbBody_preserves_var sig cur v "OUT"
          ⟨by decide, by decide, by decide, by decide, by decide, by decide⟩
        rw [hp] at this; rw [this]; exact hOUT
      rw [ih (cur + 1) pvm hpOUT]
      have := execList_forsClimbBody_mem_frame sig cur v hOUT a ha
      rw [hp] at this
      exact this

set_option maxHeartbeats 4000000 in
/-- **`forsTreeBody` memory frame.** Entered with `i := cur` (`cur < 12`), the body
    preserves any address `a` with `0x80 ≤ a < 0x80 + 32*cur` — the window holding the
    already-laid roots of trees `t < cur` (disjoint from scratch `[0x20,0x80)`, the OUT
    window `[0x600,…)`, and this tree's store `[0x80+32*cur, +32)`). -/
private theorem execList_forsTreeBody_mem_frame (sig : ByteVec Spec.SignatureLen)
    (cur : Nat) (v : VM) (hOUT : v.env "OUT" = 0x600)
    (hcur : cur < 12) (a : Nat) (ha : 0x80 ≤ a ∧ a < 0x80 + 32 * cur) :
    (execList c10Oracle sig forsTreeBody { v with env := setVar v.env "i" cur }).1.mem a
        = v.mem a := by
  obtain ⟨ha1, ha2⟩ := ha
  unfold forsTreeBody
  rw [execList_cons_none c10Oracle sig _ _ _ (by simp only [execStmt])]
  rw [execList_cons_none c10Oracle sig _ _ _ (by simp only [execStmt])]
  rw [execList_cons_none c10Oracle sig _ _ _ (by simp only [execStmt])]
  rw [execList_cons_none c10Oracle sig _ _ _ (by simp only [execStmt])]
  rw [execList_cons_none c10Oracle sig _ _ _ (by simp only [execStmt])]
  rw [execList_cons_none c10Oracle sig _ _ _ (by simp only [execStmt])]
  rw [execList_cons_none c10Oracle sig _ _ _ (by simp only [execStmt])]
  rw [execList_cons_none c10Oracle sig _ _ _ (by simp only [execStmt])]
  rw [execList_cons_none c10Oracle sig _ _ _ (by simp only [execStmt])]
  rw [execList_cons_none c10Oracle sig _ _ _ (by simp only [execStmt])]
  -- Abbreviate the post-10-letv VM (env-only changes; mem only from leaf hash mstores/sha256).
  obtain ⟨w', hw'⟩ :
      ∃ w', w' = (execStmt c10Oracle sig (Stmt.letv "authPtr" (.bin .add (.var "sigBase")
          (.bin .add (.lit 224) (.bin .mul (.var "i") (.lit 176)))))
        (execStmt c10Oracle sig (Stmt.letv "pathIdx" (.var "treeIdx"))
        (execStmt c10Oracle sig (Stmt.letv "treeAdrsBase"
            (.bin .bor (.bin .shl (.lit 160) (.var "htIdx"))
              (.bin .bor (.bin .shl (.lit 128) (.lit 3)) (.bin .shl (.lit 96) (.var "i")))))
        (execStmt c10Oracle sig (Stmt.letv "node" (.bin .band (.mload (.var "OUT")) (.var "N_MASK")))
        (execStmt c10Oracle sig (Stmt.sha256 (.lit 0x00) (.lit 0x60) (.var "OUT"))
        (execStmt c10Oracle sig (Stmt.mstore (.lit 0x40) (.var "secretVal"))
        (execStmt c10Oracle sig (Stmt.mstore (.lit 0x20) (.var "leafAdrs"))
        (execStmt c10Oracle sig (Stmt.letv "leafAdrs"
            (.bin .bor (.bin .shl (.lit 160) (.var "htIdx"))
              (.bin .bor (.bin .shl (.lit 128) (.lit 3))
                (.bin .bor (.bin .shl (.lit 96) (.var "i")) (.var "treeIdx")))))
        (execStmt c10Oracle sig (Stmt.letv "secretVal"
            (.bin .band (.calldataload (.bin .add (.var "sigBase")
              (.bin .add (.lit 16) (.bin .shl (.lit 4) (.var "i"))))) (.var "N_MASK")))
        (execStmt c10Oracle sig (Stmt.letv "treeIdx"
            (.bin .band (.bin .shr (.bin .mul (.var "i") (.lit 11)) (.var "dVal")) (.lit 0x7FF)))
          { v with env := setVar v.env "i" cur }).1).1).1).1).1).1).1).1).1).1 := ⟨_, rfl⟩
  rw [← hw']
  have hforStmt : execStmt c10Oracle sig (.forRange "h" (.lit 11) forsClimbBody) w'
      = execFor c10Oracle sig "h" forsClimbBody Spec.A 0 w' := by
    simp only [execStmt, eval]; rfl
  have hforNone : (execStmt c10Oracle sig (.forRange "h" (.lit 11) forsClimbBody) w').2 = none := by
    rw [hforStmt]; exact execFor_forsClimbBody_none sig Spec.A 0 w'
  rw [execList_cons_none c10Oracle sig _ _ _ hforNone, hforStmt]
  rw [execList_cons_none c10Oracle sig _ _ _ (by simp only [execStmt]), execList]
  -- Final mstore window: 0x80 + 32*cur .. +32 (disjoint from a since a < 0x80+32*cur).
  simp only [execStmt, eval]
  -- The store offset uses the climb-final "i" (= w'.env "i" = cur).
  have hwi : w'.env "i" = cur := by
    rw [hw']; simp only [execStmt, eval, setVar, String.reduceEq, ite_true, ite_false]
  rw [execFor_forsClimbBody_preserves_var sig "i"
        ⟨by decide, by decide, by decide, by decide, by decide, by decide⟩ Spec.A 0 w', hwi]
  have hstoreOff : (128 + cur <<< 5 % W) % W = 128 + 32 * cur := by
    rw [Nat.shiftLeft_eq, show (2 : Nat) ^ 5 = 32 from rfl, Nat.mul_comm cur 32,
        Nat.mod_eq_of_lt (lt_W_of_lt (show 32 * cur < 4096 by omega)),
        Nat.mod_eq_of_lt (lt_W_of_lt (show 128 + 32 * cur < 4096 by omega))]
  rw [hstoreOff, mstore32_frame _ (128 + 32 * cur) _ a (by omega)]
  -- OUT = 0x600 survives the 10 letvs (none binds "OUT").
  have hw'OUT : w'.env "OUT" = 0x600 := by
    rw [hw']
    simp only [execStmt, eval, setVar, String.reduceEq, ite_true, ite_false]; exact hOUT
  -- The climb preserves a (0x80 ≤ a < 0x600 since 0x80+32*cur ≤ 0x80+32*12 = 0x200 < 0x600).
  rw [execFor_forsClimbBody_mem_frame sig a (by omega) Spec.A 0 w' hw'OUT]
  -- The leaf-hash mstores (0x40,0x20) + sha256 (0x600) are disjoint from a (0x80 ≤ a < 0x200).
  rw [hw']
  simp only [execStmt, eval, setVar, String.reduceEq, ite_true, ite_false, hOUT]
  rw [writeRegion_frame _ 0x600 _ a (by omega), mstore32_frame _ 0x40 _ a (by omega),
      mstore32_frame _ 0x20 _ a (by omega)]

/-! ### The K-1 normal-tree i-loop -/

/-- The reconstructed root of normal FORS tree `t` — `reconstructRoot` at leaf index
    `(dVal >>> (t*11)) &&& 0x7FF` (interpreter form), secret `loadValue16 sig (16+16t)`,
    and the deserialised auth path. The `reconstructForsPk.normalRoots[t]` value once the
    leaf index is bridged to `extractForsIndices` (`fors_phase`). -/
def forsTreeRoot (seed : ByteVec 32) (htIdx : UInt64) (dVal : Nat)
    (sig : ByteVec Spec.SignatureLen) (t : Nat) : ByteVec 16 :=
  Spec.Fors.reconstructRoot seed htIdx (UInt32.ofNat t)
    (UInt32.ofNat ((dVal >>> (t * 11)) &&& 0x7FF))
    (ByteVec.loadValue16 sig (16 + 16 * t))
    ((Spec.Signature.deserialise sig).fors.authPaths.getD t #[])

set_option maxHeartbeats 8000000 in
set_option maxRecDepth 4000 in
/-- **FORS normal-tree i-loop refinement.** Running the outer `forRange "i" 12` from a
    VM whose env supplies `htIdx`, `sigBase = 0`, `seed`, `N_MASK`, `OUT = 0x600`,
    `dVal = wordOf digest`, with `seed` in scratch `[0x00,0x20)`, falls through and lays
    `pad16 (forsTreeRoot … t)` at `0x80 + 32*t` for every `t < 12`; the seed window and
    the loop consts persist. Drives `fors_tree_body` 12× via `execFor_invariant_lt`. -/
theorem fors_normal_trees
    (sig : ByteVec Spec.SignatureLen) (vm : VM)
    (seed : ByteVec 32) (htIdx : UInt64) (dVal : Nat)
    (hht : vm.env "htIdx" = htIdx.toNat)
    (hsb : vm.env "sigBase" = 0)
    (hseedw : vm.env "seed" = wordOf seed)
    (hN : vm.env "N_MASK" = NMASK)
    (hOUT : vm.env "OUT" = 0x600)
    (hdVal : vm.env "dVal" = dVal)
    (hseedmem : ∀ i, i < 32 → vm.mem (0 + i) = seed.data.getD i 0) :
    (execFor c10Oracle sig "i" forsTreeBody 12 0 vm).2 = none
    ∧ (∀ t, t < 12 → ∀ k, k < 32 →
        (execFor c10Oracle sig "i" forsTreeBody 12 0 vm).1.mem (0x80 + 32 * t + k)
          = (ByteVec.pad16 (forsTreeRoot seed htIdx dVal sig t)).data.getD k 0)
    ∧ (∀ i, i < 32 → (execFor c10Oracle sig "i" forsTreeBody 12 0 vm).1.mem (0 + i)
        = seed.data.getD i 0)
    ∧ (execFor c10Oracle sig "i" forsTreeBody 12 0 vm).1.env "OUT" = 0x600
    ∧ (execFor c10Oracle sig "i" forsTreeBody 12 0 vm).1.env "N_MASK" = NMASK
    ∧ (execFor c10Oracle sig "i" forsTreeBody 12 0 vm).1.env "htIdx" = htIdx.toNat
    ∧ (execFor c10Oracle sig "i" forsTreeBody 12 0 vm).1.env "seed" = wordOf seed
    ∧ (execFor c10Oracle sig "i" forsTreeBody 12 0 vm).1.env "sigBase" = 0
    ∧ (execFor c10Oracle sig "i" forsTreeBody 12 0 vm).1.env "dVal" = dVal := by
  -- Loop invariant: trees `< cur` are laid at `0x80+32t`; seed window + consts persist.
  let R : Nat → VM → Prop := fun cur w =>
    (∀ t, t < cur → ∀ k, k < 32 →
        w.mem (0x80 + 32 * t + k) = (ByteVec.pad16 (forsTreeRoot seed htIdx dVal sig t)).data.getD k 0)
    ∧ (∀ i, i < 32 → w.mem (0 + i) = seed.data.getD i 0)
    ∧ w.env "htIdx" = htIdx.toNat ∧ w.env "sigBase" = 0 ∧ w.env "seed" = wordOf seed
    ∧ w.env "N_MASK" = NMASK ∧ w.env "OUT" = 0x600 ∧ w.env "dVal" = dVal
  have hstep : ∀ cur w, cur < 12 → R cur w →
      (execList c10Oracle sig forsTreeBody { w with env := setVar w.env "i" cur }).2 = none ∧
      R (cur + 1) (execList c10Oracle sig forsTreeBody { w with env := setVar w.env "i" cur }).1 := by
    intro cur w hcur hR
    obtain ⟨hRmem, hRseed, hRht, hRsb, hRseedw, hRN, hROUT, hRdVal⟩ := hR
    obtain ⟨wi, hwi⟩ : ∃ wi, ({ w with env := setVar w.env "i" cur } : VM) = wi := ⟨_, rfl⟩
    rw [hwi]
    -- env facts about wi (consts ≠ i): unfold the setVar through hwi.
    have hwienv : wi.env = setVar w.env "i" cur := by rw [← hwi]
    have hwimem : wi.mem = w.mem := by rw [← hwi]
    have hwiht : wi.env "htIdx" = htIdx.toNat := by
      rw [hwienv, setVar_get_ne _ _ _ _ (by decide)]; exact hRht
    have hwisb : wi.env "sigBase" = 0 := by
      rw [hwienv, setVar_get_ne _ _ _ _ (by decide)]; exact hRsb
    have hwiseedw : wi.env "seed" = wordOf seed := by
      rw [hwienv, setVar_get_ne _ _ _ _ (by decide)]; exact hRseedw
    have hwiN : wi.env "N_MASK" = NMASK := by
      rw [hwienv, setVar_get_ne _ _ _ _ (by decide)]; exact hRN
    have hwiOUT : wi.env "OUT" = 0x600 := by
      rw [hwienv, setVar_get_ne _ _ _ _ (by decide)]; exact hROUT
    have hwii : wi.env "i" = cur := by rw [hwienv, setVar_get_eq]
    have hwidVal : wi.env "dVal" = dVal := by
      rw [hwienv, setVar_get_ne _ _ _ _ (by decide)]; exact hRdVal
    have hwiseedmem : ∀ i, i < 32 → wi.mem (0 + i) = seed.data.getD i 0 := by
      intro i hi; rw [hwimem]; exact hRseed i hi
    -- Interpreter leaf index for tree `cur`.
    obtain ⟨li, hli⟩ : ∃ li : UInt32,
        UInt32.ofNat ((wi.env "dVal" >>> (cur * 11)) &&& 0x7FF) = li := ⟨_, rfl⟩
    have hidx : (wi.env "dVal" >>> (cur * 11)) &&& 0x7FF = li.toNat := by
      rw [← hli]
      have hlt : (wi.env "dVal" >>> (cur * 11)) &&& 0x7FF < 2 ^ 32 :=
        Nat.lt_of_le_of_lt Nat.and_le_right (by decide)
      show _ = (((wi.env "dVal" >>> (cur * 11)) &&& 0x7FF) % UInt32.size)
      rw [Nat.mod_eq_of_lt (show _ < (2^32 : Nat) by exact hlt)]
    -- Apply fors_tree_body at t = cur.
    have hbody := fors_tree_body sig wi seed htIdx cur li
      ((Spec.Signature.deserialise sig).fors.authPaths.getD cur #[])
      hcur hwiht hwisb hwiseedw hwiN hwiOUT hwii hwiseedmem
      (H_leafAdrs_dischargeable htIdx cur li (wi.env "dVal") hcur hidx)
      hidx
      (fun h hh p hp => H_adrs_dischargeable htIdx cur hcur h hh p hp)
      (fun h hh => H_sib_dischargeable sig cur hcur h hh)
    obtain ⟨hbodyNone, hbodyMem, hbodySeed⟩ := hbody
    refine ⟨hbodyNone, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_⟩
    · -- trees < cur+1 laid: t = cur (hbodyMem matches forsTreeRoot), t < cur (mem-frame).
      intro t ht k hk
      by_cases htc : t = cur
      · subst htc
        rw [hbodyMem k hk]
        show _ = (ByteVec.pad16 (forsTreeRoot seed htIdx dVal sig t)).data.getD k 0
        unfold forsTreeRoot
        rw [show (UInt32.ofNat ((dVal >>> (t * 11)) &&& 0x7FF)) = li by rw [← hwidVal]; exact hli]
      · have htlt : t < cur := by omega
        rw [← hwi, execList_forsTreeBody_mem_frame sig cur w hROUT hcur (0x80 + 32 * t + k)
              ⟨by omega, by omega⟩]
        exact hRmem t htlt k hk
    · -- seed window persists.
      intro i hi; exact hbodySeed i hi
    · -- consts persist (the body never binds them).
      rw [← hwi, execList_forsTreeBody_preserves_const sig cur w "htIdx"
            ⟨by decide, by decide, by decide, by decide, by decide, by decide, by decide,
             by decide, by decide, by decide, by decide, by decide⟩]
      exact hRht
    · rw [← hwi, execList_forsTreeBody_preserves_const sig cur w "sigBase"
            ⟨by decide, by decide, by decide, by decide, by decide, by decide, by decide,
             by decide, by decide, by decide, by decide, by decide⟩]
      exact hRsb
    · rw [← hwi, execList_forsTreeBody_preserves_const sig cur w "seed"
            ⟨by decide, by decide, by decide, by decide, by decide, by decide, by decide,
             by decide, by decide, by decide, by decide, by decide⟩]
      exact hRseedw
    · rw [← hwi, execList_forsTreeBody_preserves_const sig cur w "N_MASK"
            ⟨by decide, by decide, by decide, by decide, by decide, by decide, by decide,
             by decide, by decide, by decide, by decide, by decide⟩]
      exact hRN
    · rw [← hwi, execList_forsTreeBody_preserves_const sig cur w "OUT"
            ⟨by decide, by decide, by decide, by decide, by decide, by decide, by decide,
             by decide, by decide, by decide, by decide, by decide⟩]
      exact hROUT
    · rw [← hwi, execList_forsTreeBody_preserves_const sig cur w "dVal"
            ⟨by decide, by decide, by decide, by decide, by decide, by decide, by decide,
             by decide, by decide, by decide, by decide, by decide⟩]
      exact hRdVal
  -- R holds at entry (cur = 0): no trees laid, seed window + consts from the hyps.
  have hR0 : R 0 vm := ⟨fun t ht => absurd ht (Nat.not_lt_zero t), hseedmem, hht, hsb, hseedw,
    hN, hOUT, hdVal⟩
  have hloop := execFor_invariant_lt c10Oracle sig "i" forsTreeBody 12 R hstep vm hR0
  obtain ⟨hmem, hseedf, hhtf, hsbf, hseedwf, hNf, hOUTf, hdValf⟩ := hloop.2
  exact ⟨hloop.1, hmem, hseedf, hOUTf, hNf, hhtf, hseedwf, hsbf, hdValf⟩

/-! ### The forced-zero last tree -/

/-- The body of `c10Program`'s last-tree `.block` (`SPHINCsC10Asm.sol` L124–132): load
    the last secret (`loadValue16 sig 208`), store the height-0/parent-0 FORS-node ADRS
    at `0x20`, the secret at `0x40`, hash the 3-segment `th` input, and store the masked
    root at `0x200 = 0x80 + 32*12`. Written with raw constructors so it is defeq to the
    block. -/
def forsLastTreeBody : List Stmt :=
  [ .letv "lastSecret"
      (.bin .band (.calldataload (.bin .add (.var "sigBase")
        (.bin .add (.lit 16) (.bin .shl (.lit 4) (.lit 12))))) (.var "N_MASK"))
  , .mstore (.lit 0x20)
      (.bin .bor (.bin .shl (.lit 160) (.var "htIdx"))
        (.bin .bor (.bin .shl (.lit 128) (.lit 3)) (.bin .shl (.lit 96) (.lit 12))))
  , .mstore (.lit 0x40) (.var "lastSecret")
  , .sha256 (.lit 0x00) (.lit 0x60) (.var "OUT")
  , .mstore (.lit 0x200) (.bin .band (.mload (.var "OUT")) (.var "N_MASK"))
  ]

set_option maxHeartbeats 4000000 in
set_option maxRecDepth 4000 in
/-- **FORS last-tree refinement.** Running `forsLastTreeBody` from a VM whose env supplies
    `htIdx`, `sigBase = 0`, `N_MASK`, `OUT = 0x600`, with `seed` in scratch `[0x00,0x20)`,
    falls through and stores `pad16 (th seed (forsNode htIdx 12 0 0) (pad16 (loadValue16 sig
    208)))` at `0x200 = 0x80 + 32*12` — exactly `reconstructForsPk`'s `lastRoot` (with
    `lastSecret = secrets.getD (K-1) = loadValue16 sig 208`). The seed window persists. -/
theorem fors_last_tree
    (sig : ByteVec Spec.SignatureLen) (vm : VM)
    (seed : ByteVec 32) (htIdx : UInt64)
    (hht : vm.env "htIdx" = htIdx.toNat)
    (hsb : vm.env "sigBase" = 0)
    (hN : vm.env "N_MASK" = NMASK)
    (hOUT : vm.env "OUT" = 0x600)
    (hseedmem : ∀ i, i < 32 → vm.mem (0 + i) = seed.data.getD i 0) :
    (execList c10Oracle sig forsLastTreeBody vm).2 = none
    ∧ (∀ k, k < 32 →
        (execList c10Oracle sig forsLastTreeBody vm).1.mem (0x200 + k)
          = (ByteVec.pad16 (Spec.th seed (Spec.Adrs.forsNode htIdx (UInt32.ofNat 12) 0 0)
              (ByteVec.pad16 (ByteVec.loadValue16 sig (16 + 16 * 12))))).data.getD k 0)
    ∧ (∀ i, i < 32 → (execList c10Oracle sig forsLastTreeBody vm).1.mem (0 + i) = seed.data.getD i 0) := by
  unfold forsLastTreeBody
  rw [execList_cons_none c10Oracle sig _ _ _ (by simp only [execStmt])]
  rw [execList_cons_none c10Oracle sig _ _ _ (by simp only [execStmt])]
  rw [execList_cons_none c10Oracle sig _ _ _ (by simp only [execStmt])]
  rw [execList_cons_none c10Oracle sig _ _ _ (by simp only [execStmt])]
  rw [execList_cons_none c10Oracle sig _ _ _ (by simp only [execStmt])]
  rw [execList]
  refine ⟨rfl, ?_⟩
  simp only [execStmt, eval, setVar, hht, hsb, hN, hOUT, ite_true, ite_false, String.reduceEq]
  -- Normalise the secret offset: sigBase(0) + 16 + (12<<<4) = 16 + 192 = 208 = 16 + 16*12.
  have hsecOff : (0 + (16 + 12 <<< 4 % W) % W) % W = 16 + 16 * 12 := by
    rw [shl4_small 12 (by omega),
        Nat.mod_eq_of_lt (lt_W_of_lt (show 16 + 16 * 12 < 4096 by omega)), Nat.zero_add,
        Nat.mod_eq_of_lt (lt_W_of_lt (show 16 + 16 * 12 < 4096 by omega))]
  rw [hsecOff, cl_masked_eq_wordOf sig (16 + 16 * 12)]
  -- The ADRS word = wordOf (forsNode htIdx 12 0 0).
  have hadrs : (htIdx.toNat <<< 160 % W) ||| ((3 <<< 128 % W) ||| (12 <<< 96 % W))
      = wordOf (Spec.Adrs.forsNode htIdx (UInt32.ofNat 12) 0 0) := by
    rw [wordOf_forsNode]
    have hFT : (UInt32.ofNat Spec.ADRS_FORS_TREE).toNat = 3 := by decide
    have hti : (UInt32.ofNat 12).toNat = 12 := by decide
    rw [hFT, hti]
    show _ = _ ||| _ ||| _ ||| (0 : UInt32).toNat <<< 32 ||| (0 : UInt32).toNat
    rw [show (0 : UInt32).toNat = 0 from rfl, Nat.zero_shiftLeft, Nat.or_zero, Nat.or_zero]
    have hW1 : htIdx.toNat <<< 160 % W = htIdx.toNat <<< 160 :=
      Nat.mod_eq_of_lt (shl_lt_two_pow_256 _ 64 160 htIdx.toNat_lt (by omega))
    have hW2 : (3 : Nat) <<< 128 % W = 3 <<< 128 :=
      Nat.mod_eq_of_lt (shl_lt_two_pow_256 _ 2 128 (by decide) (by omega))
    have hW3 : (12 : Nat) <<< 96 % W = 12 <<< 96 :=
      Nat.mod_eq_of_lt (shl_lt_two_pow_256 _ 4 96 (by decide) (by omega))
    rw [hW1, hW2, hW3, Nat.or_assoc]
  rw [hadrs]
  -- The leaf hash = wordOf (pad16 (th seed adrs (pad16 secret))) via leafMem_th.
  have hleaf := leafMem_th vm.mem seed (Spec.Adrs.forsNode htIdx (UInt32.ofNat 12) 0 0)
    (ByteVec.pad16 (ByteVec.loadValue16 sig (16 + 16 * 12))) hseedmem
  rw [hleaf]
  refine ⟨?_, ?_⟩
  · -- mem at 0x200 + k = pad16(th …)'s byte.
    intro k hk
    rw [mstore32_get _ 0x200 _ k hk, beByte_wordOf_getD _ k hk]
  · -- seed window persists (stores land at ≥ 0x20).
    intro i hi
    rw [mstore32_frame _ 0x200 _ (0 + i) (by omega)]
    -- frame through the leaf-hash writes (0x20, 0x40, 0x600 = OUT).
    rw [writeRegion_frame _ 0x600 _ (0 + i) (by omega),
        mstore32_frame _ 0x40 _ (0 + i) (by omega), mstore32_frame _ 0x20 _ (0 + i) (by omega)]
    exact hseedmem i hi

/-- `forsLastTreeBody` binds only `"lastSecret"`; any other variable is preserved. -/
theorem execList_forsLastTreeBody_preserves_var (sig : ByteVec Spec.SignatureLen) (vm : VM)
    (x : String) (hx : x ≠ "lastSecret") :
    (execList c10Oracle sig forsLastTreeBody vm).1.env x = vm.env x := by
  unfold forsLastTreeBody
  rw [execList_cons_none c10Oracle sig _ _ _ (by simp only [execStmt])]
  rw [execList_cons_none c10Oracle sig _ _ _ (by simp only [execStmt])]
  rw [execList_cons_none c10Oracle sig _ _ _ (by simp only [execStmt])]
  rw [execList_cons_none c10Oracle sig _ _ _ (by simp only [execStmt])]
  rw [execList_cons_none c10Oracle sig _ _ _ (by simp only [execStmt])]
  rw [execList]
  simp only [execStmt, eval, setVar]
  rw [if_neg hx]

set_option maxHeartbeats 4000000 in
/-- **`forsLastTreeBody` mem frame for the already-laid normal trees.** The last-tree block
    writes only `0x20`/`0x40` (scratch), the OUT window `[0x600,…)`, and `0x200`; so any
    address `a` in `[0x80, 0x200)` (where normal trees 0–11 live) survives — needed to carry
    them past the last tree into root compression. `OUT = 0x600` required for the OUT frame. -/
theorem fors_last_tree_mem_frame
    (sig : ByteVec Spec.SignatureLen) (vm : VM) (hOUT : vm.env "OUT" = 0x600)
    (a : Nat) (ha : 0x80 ≤ a ∧ a < 0x200) :
    (execList c10Oracle sig forsLastTreeBody vm).1.mem a = vm.mem a := by
  unfold forsLastTreeBody
  obtain ⟨ha1, ha2⟩ := ha
  rw [execList_cons_none c10Oracle sig _ _ _ (by simp only [execStmt])]
  rw [execList_cons_none c10Oracle sig _ _ _ (by simp only [execStmt])]
  rw [execList_cons_none c10Oracle sig _ _ _ (by simp only [execStmt])]
  rw [execList_cons_none c10Oracle sig _ _ _ (by simp only [execStmt])]
  rw [execList_cons_none c10Oracle sig _ _ _ (by simp only [execStmt])]
  rw [execList]
  simp only [execStmt, eval, setVar, hOUT, ite_true, ite_false, String.reduceEq]
  -- Frame `a` through: 0x200 store, OUT window, 0x40, 0x20 (all disjoint from [0x80,0x200)).
  rw [mstore32_frame _ 0x200 _ a (by omega), writeRegion_frame _ 0x600 _ a (by omega),
      mstore32_frame _ 0x40 _ a (by omega), mstore32_frame _ 0x20 _ a (by omega)]

/-! ### Root compression -/

/-- The copy-loop body of `c10Program`'s root compression (`SPHINCsC10Asm.sol` L139–141):
    one record move `mem[0x40 + 32*i] := mem[0x80 + 32*i]`. -/
def forsCopyBody : List Stmt :=
  [ .mstore (.bin .add (.lit 0x40) (.bin .shl (.lit 5) (.var "i")))
      (.mload (.bin .add (.lit 0x80) (.bin .shl (.lit 5) (.var "i")))) ]

/-- `i <<< 5 % W = 32*i` for `i < 128` (the 32-byte record stride; `32*i < 4096`). -/
private theorem shl5_small (i : Nat) (hi : i < 128) : i <<< 5 % W = 32 * i := by
  rw [Nat.shiftLeft_eq, show (2:Nat)^5 = 32 from rfl, Nat.mod_eq_of_lt (lt_W_of_lt (by omega)),
      Nat.mul_comm]

/-- One copy-loop step preserves env and moves one record. The `execFor_invariant_lt`
    step for the 13-record copy (`mem[0x40+32*cur] := mem[0x80+32*cur]`); the read window
    `[0x80+32*cur,…)` is untouched by prior writes (`dest_j = 0x40+32j` hits `0x80+32*cur`
    only at `j = cur+2 > cur`), so the source still holds the original root. -/
private theorem fors_copy_step (sig : ByteVec Spec.SignatureLen) (cur : Nat) (v : VM)
    (hcur : cur < 13) :
    (execList c10Oracle sig forsCopyBody { v with env := setVar v.env "i" cur }).2 = none
    ∧ (∀ a, ¬ (0x40 + 32 * cur ≤ a ∧ a < 0x40 + 32 * cur + 32) →
        (execList c10Oracle sig forsCopyBody { v with env := setVar v.env "i" cur }).1.mem a = v.mem a)
    ∧ (∀ k, k < 32 →
        (execList c10Oracle sig forsCopyBody { v with env := setVar v.env "i" cur }).1.mem
          (0x40 + 32 * cur + k) = v.mem (0x80 + 32 * cur + k))
    ∧ (execList c10Oracle sig forsCopyBody { v with env := setVar v.env "i" cur }).1.env
        = setVar v.env "i" cur := by
  unfold forsCopyBody
  rw [execList_cons_none c10Oracle sig _ _ _ (by simp only [execStmt])]
  rw [execList]
  simp only [execStmt, eval, setVar, ite_true]
  -- Normalise the dest/source offsets: (0x40 + cur<<<5%W)%W = 64+32cur, (0x80 + …)%W = 128+32cur.
  have hdest : (0x40 + cur <<< 5 % W) % W = 64 + 32 * cur := by
    rw [shl5_small cur (by omega), Nat.mod_eq_of_lt (lt_W_of_lt (show 64 + 32 * cur < 4096 by omega))]
  have hsrc : (0x80 + cur <<< 5 % W) % W = 128 + 32 * cur := by
    rw [shl5_small cur (by omega), Nat.mod_eq_of_lt (lt_W_of_lt (show 128 + 32 * cur < 4096 by omega))]
  rw [hdest, hsrc]
  refine ⟨trivial, ?_, ?_, ?_⟩
  · -- frame: writes only [0x40+32*cur, +32) = [64+32cur, +32).
    intro a ha
    rw [mstore32_frame _ (64 + 32 * cur) _ a (by omega)]
  · -- the copied window: mstore32_get reads the destination = mload32 of the source.
    intro k hk
    rw [show (0x40 + 32 * cur + k) = ((64 + 32 * cur) + k) by omega, mstore32_get _ (64 + 32 * cur) _ k hk]
    rw [beByte_mload32 v.mem (128 + 32 * cur) k hk]
  · -- env unchanged by the mstore.
    trivial

set_option maxHeartbeats 8000000 in
set_option maxRecDepth 4000 in
/-- **The 13-record copy loop.** Drives `fors_copy_step` 13× via `execFor_invariant_lt`.
    Pre: the 13 roots sit `pad16`'d at `[0x80+32t,…)` (`hsrc`) and the low window `[0,0x40)`
    (seed + the forsRoots ADRS) is fixed (`hlow`). Post: the 13 roots are `pad16`'d at
    `[0x40+32t,…)` for `t < 13`, and `[0,0x40)` is unchanged. -/
private theorem fors_copy_loop (sig : ByteVec Spec.SignatureLen) (vm : VM)
    (roots : Nat → ByteVec 16)
    (hsrc : ∀ t, t < 13 → ∀ k, k < 32 → vm.mem (0x80 + 32 * t + k)
        = (ByteVec.pad16 (roots t)).data.getD k 0) :
    (execFor c10Oracle sig "i" forsCopyBody 13 0 vm).2 = none
    ∧ (∀ t, t < 13 → ∀ k, k < 32 →
        (execFor c10Oracle sig "i" forsCopyBody 13 0 vm).1.mem (0x40 + 32 * t + k)
          = (ByteVec.pad16 (roots t)).data.getD k 0)
    ∧ (∀ a, a < 0x40 → (execFor c10Oracle sig "i" forsCopyBody 13 0 vm).1.mem a = vm.mem a) := by
  let R : Nat → VM → Prop := fun cur w =>
    (∀ t, t < cur → ∀ k, k < 32 → w.mem (0x40 + 32 * t + k) = (ByteVec.pad16 (roots t)).data.getD k 0)
    ∧ (∀ t, cur ≤ t → t < 13 → ∀ k, k < 32 → w.mem (0x80 + 32 * t + k) = (ByteVec.pad16 (roots t)).data.getD k 0)
    ∧ (∀ a, a < 0x40 → w.mem a = vm.mem a)
  have hstep : ∀ cur w, cur < 13 → R cur w →
      (execList c10Oracle sig forsCopyBody { w with env := setVar w.env "i" cur }).2 = none ∧
      R (cur + 1) (execList c10Oracle sig forsCopyBody { w with env := setVar w.env "i" cur }).1 := by
    intro cur w hcur hR
    obtain ⟨hRcopied, hRsrc, hRlow⟩ := hR
    obtain ⟨hnone, hframe, hcopy, _⟩ := fors_copy_step sig cur w hcur
    refine ⟨hnone, ?_, ?_, ?_⟩
    · -- copied roots for t < cur+1.
      intro t ht k hk
      by_cases htc : t = cur
      · rw [htc, hcopy k hk]; exact hRsrc cur (Nat.le_refl cur) hcur k hk
      · have htlt : t < cur := by omega
        rw [hframe (0x40 + 32 * t + k) (by omega)]
        exact hRcopied t htlt k hk
    · -- sources for t ≥ cur+1 preserved (dest 0x40+32cur disjoint).
      intro t ht ht13 k hk
      rw [hframe (0x80 + 32 * t + k) (by omega)]
      exact hRsrc t (by omega) ht13 k hk
    · -- low window [0,0x40) preserved.
      intro a ha
      rw [hframe a (by omega)]
      exact hRlow a ha
  have hR0 : R 0 vm := ⟨fun t ht => absurd ht (Nat.not_lt_zero t),
    fun t _ ht13 k hk => hsrc t ht13 k hk, fun a _ => rfl⟩
  have hloop := execFor_invariant_lt c10Oracle sig "i" forsCopyBody 13 R hstep vm hR0
  obtain ⟨hcopied, _, hlow⟩ := hloop.2
  exact ⟨hloop.1, hcopied, hlow⟩

/-- The 15-segment list the compression precompile hashes (`[0,0x1E0)`): `seed`, the
    forsRoots ADRS (32-byte, NOT pad16'd — matches `thMulti`'s `ofByteVec a` header), then
    the 13 `pad16`'d roots. Exactly `thMulti`'s `header ++ roots.map (ofByteVec ∘ pad16)`. -/
def forsRootSegs (seed : ByteVec 32) (htIdx : UInt64) (roots : List (ByteVec 16)) :
    List (ByteVec 32) :=
  seed :: (Spec.Adrs.forsRoots htIdx) :: roots.map ByteVec.pad16

/-- The forsRoots-ADRS Yul word `or(shl(160,htIdx), shl(128,4))`, masks inert. -/
private theorem forsRoots_word (htIdx : UInt64) :
    (htIdx.toNat <<< 160 % W) ||| (4 <<< 128 % W)
      = wordOf (Spec.Adrs.forsRoots htIdx) := by
  rw [wordOf_forsRoots]
  have hFR : (UInt32.ofNat Spec.ADRS_FORS_ROOTS).toNat = 4 := by decide
  rw [hFR]
  have hW1 : htIdx.toNat <<< 160 % W = htIdx.toNat <<< 160 :=
    Nat.mod_eq_of_lt (shl_lt_two_pow_256 _ 64 160 htIdx.toNat_lt (by omega))
  have hW2 : (4 : Nat) <<< 128 % W = 4 <<< 128 :=
    Nat.mod_eq_of_lt (shl_lt_two_pow_256 _ 3 128 (by decide) (by omega))
  rw [hW1, hW2]


/-! ### Root compression — env frame + the 15-segment holds + the lemma -/

/-- One copy-body step never touches the env beyond `"i"`: any `x ≠ "i"` is preserved. -/
private theorem execList_forsCopyBody_preserves_var (sig : ByteVec Spec.SignatureLen)
    (cur : Nat) (v : VM) (x : String) (hxi : x ≠ "i") :
    (execList c10Oracle sig forsCopyBody { v with env := setVar v.env "i" cur }).1.env x
        = v.env x := by
  unfold forsCopyBody
  rw [execList_cons_none c10Oracle sig _ _ _ (by simp only [execStmt])]
  rw [execList]
  simp only [execStmt, eval, setVar]
  rw [if_neg hxi]

/-- The whole copy loop preserves any variable `x ≠ "i"`. -/
private theorem execFor_forsCopyBody_preserves_var (sig : ByteVec Spec.SignatureLen)
    (x : String) (hxi : x ≠ "i") :
    ∀ (remaining cur : Nat) (v : VM),
      (execFor c10Oracle sig "i" forsCopyBody remaining cur v).1.env x = v.env x := by
  intro remaining
  induction remaining with
  | zero => intro cur v; simp only [execFor]
  | succ rem ih =>
      intro cur v
      -- The body falls through (one mstore); peel one iteration.
      have hnone : (execList c10Oracle sig forsCopyBody { v with env := setVar v.env "i" cur }).2 = none := by
        unfold forsCopyBody
        rw [execList_cons_none c10Oracle sig _ _ _ (by simp only [execStmt]), execList]
      rw [execFor]
      rcases hp : execList c10Oracle sig forsCopyBody { v with env := setVar v.env "i" cur }
        with ⟨pvm, po⟩
      rw [hp] at hnone
      subst hnone
      simp only []
      rw [ih (cur + 1) pvm]
      have := execList_forsCopyBody_preserves_var sig cur v x hxi
      rw [hp] at this
      exact this

/-- `(roots.map pad16).getD n (zero 32) = pad16 (roots.getD n (zero 16))` for `n < roots.length`. -/
private theorem map_pad16_getD (roots : List (ByteVec 16)) (n : Nat) (hn : n < roots.length) :
    (roots.map ByteVec.pad16).getD n (ByteVec.zero 32) = ByteVec.pad16 (roots.getD n (ByteVec.zero 16)) := by
  rw [List.getD_eq_getElem?_getD, List.getD_eq_getElem?_getD, List.getElem?_map]
  rw [List.getElem?_eq_getElem hn, Option.map_some, Option.getD_some, Option.getD_some]

set_option maxHeartbeats 8000000 in
set_option maxRecDepth 4000 in
/-- **FORS root compression refinement.** Running the compression fragment
    (`SPHINCsC10Asm.sol` L137–143: store ADRS, copy 13 roots, hash, mask) from a VM whose
    env supplies `htIdx`, `N_MASK`, `OUT = 0x600`, `seed` in `[0x00,0x20)`, and the 13
    `pad16`'d roots at `[0x80+32t,…)`, falls through and binds `"forsPk"` to
    `wordOf (pad16 (computeForsPk seed htIdx roots.toArray))` — `thMulti` over the 15
    segments. (`roots.length = 13`.) -/
theorem fors_root_compress
    (sig : ByteVec Spec.SignatureLen) (vm : VM)
    (seed : ByteVec 32) (htIdx : UInt64) (roots : List (ByteVec 16)) (hlen : roots.length = 13)
    (hN : vm.env "N_MASK" = NMASK)
    (hOUT : vm.env "OUT" = 0x600)
    (hht : vm.env "htIdx" = htIdx.toNat)
    (hseedmem : ∀ i, i < 32 → vm.mem (0 + i) = seed.data.getD i 0)
    (hrootmem : ∀ t, t < 13 → ∀ k, k < 32 →
        vm.mem (0x80 + 32 * t + k) = (ByteVec.pad16 (roots.getD t (ByteVec.zero 16))).data.getD k 0) :
    (execList c10Oracle sig
        (.mstore (.lit 0x20) (.bin .bor (.bin .shl (.lit 160) (.var "htIdx")) (.bin .shl (.lit 128) (.lit 4)))
          :: .forRange "i" (.lit 13) forsCopyBody
          :: .sha256 (.lit 0x00) (.lit 0x1E0) (.var "OUT")
          :: [.letv "forsPk" (.bin .band (.mload (.var "OUT")) (.var "N_MASK"))]) vm).2 = none
    ∧ ((execList c10Oracle sig
        (.mstore (.lit 0x20) (.bin .bor (.bin .shl (.lit 160) (.var "htIdx")) (.bin .shl (.lit 128) (.lit 4)))
          :: .forRange "i" (.lit 13) forsCopyBody
          :: .sha256 (.lit 0x00) (.lit 0x1E0) (.var "OUT")
          :: [.letv "forsPk" (.bin .band (.mload (.var "OUT")) (.var "N_MASK"))]) vm).1.env "forsPk"
        = wordOf (ByteVec.pad16 (Spec.Fors.computeForsPk seed htIdx roots.toArray))) := by
  -- Step 1: mstore 0x20 (forsRoots adrs word).
  rw [execList_cons_none c10Oracle sig _ _ _ (by simp only [execStmt])]
  obtain ⟨v1, hv1⟩ : ∃ v1, (execStmt c10Oracle sig
      (.mstore (.lit 0x20) (.bin .bor (.bin .shl (.lit 160) (.var "htIdx")) (.bin .shl (.lit 128) (.lit 4)))) vm).1 = v1 := ⟨_, rfl⟩
  rw [hv1]
  have hv1env : v1.env = vm.env := by rw [← hv1]; simp only [execStmt]
  have hv1mem : v1.mem = mstore32 vm.mem 0x20 (wordOf (Spec.Adrs.forsRoots htIdx)) := by
    rw [← hv1]; simp only [execStmt, eval, hht]; rw [forsRoots_word]
  have hv1root : ∀ t, t < 13 → ∀ k, k < 32 →
      v1.mem (0x80 + 32 * t + k) = (ByteVec.pad16 (roots.getD t (ByteVec.zero 16))).data.getD k 0 := by
    intro t ht k hk
    rw [hv1mem, mstore32_frame _ 0x20 _ (0x80 + 32 * t + k) (by omega)]
    exact hrootmem t ht k hk
  have hv1seed : ∀ i, i < 32 → v1.mem (0 + i) = seed.data.getD i 0 := by
    intro i hi; rw [hv1mem, mstore32_frame _ 0x20 _ (0 + i) (by omega)]; exact hseedmem i hi
  have hv1adrs : ∀ k, k < 32 → v1.mem (0x20 + k) = (Spec.Adrs.forsRoots htIdx).data.getD k 0 := by
    intro k hk; rw [hv1mem, mstore32_get _ 0x20 _ k hk, beByte_wordOf_getD _ k hk]
  -- Step 2: the copy loop.
  have hcopyStmt : execStmt c10Oracle sig (.forRange "i" (.lit 13) forsCopyBody) v1
      = execFor c10Oracle sig "i" forsCopyBody 13 0 v1 := by simp only [execStmt, eval]
  obtain ⟨hcopyNone, hcopyRoots, hcopyLow⟩ := fors_copy_loop sig v1
    (fun t => roots.getD t (ByteVec.zero 16)) hv1root
  rw [execList_cons_none c10Oracle sig _ _ _ (by rw [hcopyStmt]; exact hcopyNone), hcopyStmt]
  obtain ⟨v2, hv2⟩ : ∃ v2, (execFor c10Oracle sig "i" forsCopyBody 13 0 v1).1 = v2 := ⟨_, rfl⟩
  rw [hv2]
  -- env "OUT"/"N_MASK" persist through the copy loop.
  have hv2OUT : v2.env "OUT" = 0x600 := by
    rw [← hv2, execFor_forsCopyBody_preserves_var sig "OUT" (by decide) 13 0 v1, hv1env, hOUT]
  have hv2N : v2.env "N_MASK" = NMASK := by
    rw [← hv2, execFor_forsCopyBody_preserves_var sig "N_MASK" (by decide) 13 0 v1, hv1env, hN]
  -- mem facts about v2: low window [0,0x40) = v1's (seed + adrs); roots at [0x40+32t,…).
  have hv2low : ∀ a, a < 0x40 → v2.mem a = v1.mem a := by intro a ha; rw [← hv2]; exact hcopyLow a ha
  have hv2roots : ∀ t, t < 13 → ∀ k, k < 32 →
      v2.mem (0x40 + 32 * t + k) = (ByteVec.pad16 (roots.getD t (ByteVec.zero 16))).data.getD k 0 := by
    intro t ht k hk; rw [← hv2]; exact hcopyRoots t ht k hk
  -- The 15-segment holdsSegs at base 0.
  have hseglen : (forsRootSegs seed htIdx roots).length = 15 := by
    simp only [forsRootSegs, List.length_cons, List.length_map, hlen]
  have hsegs : holdsSegs v2.mem 0 (forsRootSegs seed htIdx roots) := by
    intro j i hj hi
    rw [hseglen] at hj
    rw [Nat.zero_add]
    -- seg0 = seed, seg1 = forsRoots adrs, seg{j} (j≥2) = pad16 (roots[j-2]).
    rcases Nat.lt_or_ge j 2 with hj2 | hj2
    · match j, hj2 with
      | 0, _ =>
          -- j = 0: window [0,32) = seed.
          rw [show (32 * 0 + i) = (0 + i) by omega, hv2low (0 + i) (by omega), hv1seed i hi]
          rfl
      | 1, _ =>
          -- j = 1: window [32,64) = forsRoots adrs.
          rw [show (32 * 1 + i) = (0x20 + i) by omega, hv2low (0x20 + i) (by omega), hv1adrs i hi]
          rfl
    · -- j ≥ 2: write j = m + 2; window [32*(m+2),…) = [0x40 + 32*m,…) = root m.
      obtain ⟨m, rfl⟩ : ∃ m, j = m + 2 := ⟨j - 2, by omega⟩
      rw [show (32 * (m + 2) + i) = (0x40 + 32 * m + i) by omega, hv2roots m (by omega) i hi]
      -- (forsRootSegs).getD (m+2) = (roots.map pad16).getD m = pad16 (roots.getD m).
      show _ = ((forsRootSegs seed htIdx roots).getD (m + 2) (ByteVec.zero 32)).data.getD i 0
      have hgetD : (forsRootSegs seed htIdx roots).getD (m + 2) (ByteVec.zero 32)
          = ByteVec.pad16 (roots.getD m (ByteVec.zero 16)) := by
        unfold forsRootSegs
        rw [List.getD_cons_succ, List.getD_cons_succ]
        exact map_pad16_getD roots m (by omega)
      rw [hgetD]
  -- Step 3: sha256 over [0,0x1E0) = 15 segments → computeForsPk.
  rw [execList_cons_none c10Oracle sig _ _ _ (by simp only [execStmt])]
  -- Step 4: letv forsPk := and(mload OUT, N_MASK) → masked digest.
  rw [execList_cons_none c10Oracle sig _ _ _ (by simp only [execStmt]), execList]
  refine ⟨rfl, ?_⟩
  -- Resolve env "forsPk" to the masked mload of the digest.
  simp only [execStmt, eval, hv2OUT, hv2N]
  rw [setVar_get_eq]
  -- The sha256 output window slice = computeForsPk (via holdsSegs + the oracle bridge + mask).
  -- mload(OUT) is the digest just written; mask it → wordOf (pad16 (truncate16 dig)).
  rw [mload_masked_eq_wordOf_pad16 v2.mem 0x600
        (c10Oracle (slice v2.mem 0 (32 * 15)))]
  -- The digest = sha256 (forsRootSegs.map ofByteVec) = thMulti's input.
  have hbridge : c10Oracle (slice v2.mem 0 (32 * 15))
      = Spec.sha256 ((forsRootSegs seed htIdx roots).map Spec.ByteSeg.ofByteVec) := by
    have h := c10Oracle_holdsSegs v2.mem 0 (forsRootSegs seed htIdx roots) hsegs
    rw [hseglen] at h
    exact h
  rw [hbridge]
  -- truncate16 (sha256 (forsRootSegs.map ofByteVec)) = computeForsPk seed htIdx roots.toArray.
  congr 2
  -- computeForsPk seed htIdx roots.toArray = thMulti seed (forsRoots htIdx) roots.toArray.toList.
  show ByteVec.truncate16 (Spec.sha256 ((forsRootSegs seed htIdx roots).map Spec.ByteSeg.ofByteVec))
      = Spec.Fors.computeForsPk seed htIdx roots.toArray
  unfold Spec.Fors.computeForsPk Spec.thMulti forsRootSegs
  -- header ++ padded ; roots.toArray.toList = roots ; List.map composition.
  rw [List.toList_toArray]
  simp only [List.map_cons, List.map_map]
  rfl

/-! ### The FORS phase capstone -/

/-- The whole FORS fragment of `c10Program` (`SPHINCsC10Asm.sol` L81–143), from the `htIdx`
    derivation through the masked `forsPk` — written with the per-phase bodies so it is defeq
    to that slice of `c10Program`. Begins right after the H_msg `digest` letv. -/
def forsPhaseFragment : List Stmt :=
  [ .letv "htIdx" (.bin .band (.bin .shr (.lit 143) (.var "digest")) (.lit 0x3FFFF))
  , .letv "dVal" (.var "digest")
  , .ifnz (.bin .band (.bin .shr (.lit 132) (.var "dVal")) (.lit 0x7FF)) [ .revert ]
  , .letv "sigBase" .sigOffset
  , .forRange "i" (.lit 12) forsTreeBody
  , .block forsLastTreeBody
  , .mstore (.lit 0x20) (.bin .bor (.bin .shl (.lit 160) (.var "htIdx")) (.bin .shl (.lit 128) (.lit 4)))
  , .forRange "i" (.lit 13) forsCopyBody
  , .sha256 (.lit 0x00) (.lit 0x1E0) (.var "OUT")
  , .letv "forsPk" (.bin .band (.mload (.var "OUT")) (.var "N_MASK")) ]

/-- The 13 FORS roots `reconstructForsPk` compresses, as a function (interpreter index form):
    trees `t < 12` are `forsTreeRoot`; tree 12 is the forced-zero `lastRoot`. The
    `reconstructForsPk` `allRoots.toList` once `htIdx`/leaf-index are bridged. -/
def forsAllRoots (seed : ByteVec 32) (htIdx : UInt64) (dVal : Nat)
    (sig : ByteVec Spec.SignatureLen) : List (ByteVec 16) :=
  (List.ofFn (n := 12) (fun t : Fin 12 => forsTreeRoot seed htIdx dVal sig t.val))
    ++ [Spec.th seed (Spec.Adrs.forsNode htIdx (UInt32.ofNat 12) 0 0)
          (ByteVec.pad16 (ByteVec.loadValue16 sig (16 + 16 * 12)))]

/-- `forsAllRoots` has length 13. -/
private theorem forsAllRoots_length (seed : ByteVec 32) (htIdx : UInt64) (dVal : Nat)
    (sig : ByteVec Spec.SignatureLen) : (forsAllRoots seed htIdx dVal sig).length = 13 := by
  simp only [forsAllRoots, List.length_append, List.length_ofFn, List.length_cons, List.length_nil]

/-- `forsAllRoots.getD t` for `t < 12` is `forsTreeRoot … t`. -/
private theorem forsAllRoots_getD_lt (seed : ByteVec 32) (htIdx : UInt64) (dVal : Nat)
    (sig : ByteVec Spec.SignatureLen) (t : Nat) (ht : t < 12) :
    (forsAllRoots seed htIdx dVal sig).getD t (ByteVec.zero 16)
      = forsTreeRoot seed htIdx dVal sig t := by
  unfold forsAllRoots
  rw [List.getD_eq_getElem?_getD, List.getElem?_append_left (by rw [List.length_ofFn]; exact ht),
      List.getElem?_ofFn, dif_pos ht, Option.getD_some]

/-- `forsAllRoots.getD 12` is the forced-zero last root. -/
private theorem forsAllRoots_getD_last (seed : ByteVec 32) (htIdx : UInt64) (dVal : Nat)
    (sig : ByteVec Spec.SignatureLen) :
    (forsAllRoots seed htIdx dVal sig).getD 12 (ByteVec.zero 16)
      = Spec.th seed (Spec.Adrs.forsNode htIdx (UInt32.ofNat 12) 0 0)
          (ByteVec.pad16 (ByteVec.loadValue16 sig (16 + 16 * 12))) := by
  unfold forsAllRoots
  rw [List.getD_eq_getElem?_getD, List.getElem?_append_right (by rw [List.length_ofFn]; exact Nat.le_refl 12),
      List.length_ofFn]
  rfl

attribute [local irreducible] Spec.Fors.reconstructRoot Spec.th Spec.Fors.computeForsPk Spec.thMulti

set_option maxHeartbeats 16000000 in
/-- `forsAllRoots` matches `reconstructForsPk`'s `allRoots.toList` (with `htIdx = htIdx_bv`,
    `dVal = wordOf digest_bv`). The bridge tying the interpreter's 13 compressed roots to the
    spec's `normalRoots.push lastRoot`. -/
private theorem forsAllRoots_eq_specAllRoots
    (sig : ByteVec Spec.SignatureLen) (seed digest_bv : ByteVec 32) (htIdx_bv : UInt64)
    (hhtbv : htIdx_bv = UInt64.ofNat (SphincsCVerify.Util.extractHtIndex digest_bv)) :
    forsAllRoots seed htIdx_bv (wordOf digest_bv) sig
      = ((Array.ofFn (n := Spec.K - 1) (fun t : Fin (Spec.K - 1) =>
          Spec.Fors.reconstructRoot seed htIdx_bv (UInt32.ofNat t.val)
            (UInt32.ofNat ((SphincsCVerify.Util.extractForsIndices digest_bv).getD t.val 0))
            ((Spec.Signature.deserialise sig).fors.secrets.getD t.val (ByteVec.zero 16))
            ((Spec.Signature.deserialise sig).fors.authPaths.getD t.val #[]))).push
        (Spec.th seed (Spec.Adrs.forsNode htIdx_bv (UInt32.ofNat (Spec.K - 1)) 0 0)
          (ByteVec.pad16 ((Spec.Signature.deserialise sig).fors.secrets.getD (Spec.K - 1) (ByteVec.zero 16))))).toList := by
  -- The deserialise secrets bridge: secrets.getD t = loadValue16 sig (16 + 16t).
  have hsecret : ∀ t, t < 13 → (Spec.Signature.deserialise sig).fors.secrets.getD t (ByteVec.zero 16)
      = ByteVec.loadValue16 sig (16 + 16 * t) := by
    intro t ht
    show ((Array.ofFn (n := Spec.K) fun i => ByteVec.loadValue16 sig (Spec.N + i.val * Spec.N)).getD t (ByteVec.zero 16))
        = ByteVec.loadValue16 sig (16 + 16 * t)
    rw [Array.getD_eq_getD_getElem?, Array.getElem?_ofFn,
        dif_pos (show t < Spec.K by have : Spec.K = 13 := rfl; omega), Option.getD_some]
    have hN : Spec.N = 16 := rfl
    rw [hN, Nat.mul_comm t 16]
  -- RHS list = (ofFn 12 reconstructRoot).toList ++ [lastRoot'].
  rw [Array.toList_push, Array.toList_ofFn]
  unfold forsAllRoots
  -- Whole-list extensionality over the 13 entries (t<12 normal, t=12 last).
  apply List.ext_getElem
  · simp only [List.length_append, List.length_ofFn, List.length_cons, List.length_nil]; rfl
  · intro t h1 h2
    have htlen : t < 13 := by
      simp only [List.length_append, List.length_ofFn, List.length_cons, List.length_nil] at h1
      omega
    have hK1 : Spec.K - 1 = 12 := rfl
    by_cases htlt : t < 12
    · -- t < 12: both sides are the normal ofFn list entry.
      rw [List.getElem_append_left (by rw [List.length_ofFn]; exact htlt),
          List.getElem_append_left (by rw [List.length_ofFn]; rw [hK1]; exact htlt),
          List.getElem_ofFn, List.getElem_ofFn]
      show forsTreeRoot seed htIdx_bv (wordOf digest_bv) sig t = _
      unfold forsTreeRoot
      rw [extractForsIndices_eq_wordShift digest_bv t (by have : Spec.K = 13 := rfl; omega),
          hsecret t (by omega)]
    · -- t = 12: the last (singleton) entry.
      have ht12 : t = 12 := by omega
      subst ht12
      rw [List.getElem_append_right (by rw [List.length_ofFn]; exact Nat.le_refl 12),
          List.getElem_append_right (by rw [List.length_ofFn]; exact (show Spec.K - 1 ≤ 12 from Nat.le_refl 12))]
      simp only [List.length_ofFn]
      -- both sides index [_][0]; `Spec.K - 1` is defeq `12`, then the secret bridge.
      show Spec.th seed (Spec.Adrs.forsNode htIdx_bv (UInt32.ofNat 12) 0 0)
          (ByteVec.pad16 (ByteVec.loadValue16 sig (16 + 16 * 12)))
        = Spec.th seed (Spec.Adrs.forsNode htIdx_bv (UInt32.ofNat 12) 0 0)
          (ByteVec.pad16 ((Spec.Signature.deserialise sig).fors.secrets.getD 12 (ByteVec.zero 16)))
      rw [hsecret 12 (by omega)]

set_option maxHeartbeats 8000000 in
/-- **`reconstructForsPk` returns the interpreter's compressed-root value.** When the
    forced-zero last index is `0`, the spec `reconstructForsPk seed digest_bv (deserialise
    sig).fors` is `some (computeForsPk seed htIdx_bv forsAllRoots.toArray)` — its `allRoots`
    array is exactly `forsAllRoots.toArray` (the bridge `forsAllRoots_eq_specAllRoots`). -/
private theorem reconstructForsPk_eq_compute
    (sig : ByteVec Spec.SignatureLen) (seed digest_bv : ByteVec 32) (htIdx_bv : UInt64)
    (hhtbv : htIdx_bv = UInt64.ofNat (SphincsCVerify.Util.extractHtIndex digest_bv))
    (hz : (SphincsCVerify.Util.extractForsIndices digest_bv).getD (Spec.K - 1) 0 = 0) :
    Spec.Fors.reconstructForsPk seed digest_bv (Spec.Signature.deserialise sig).fors
      = some (Spec.Fors.computeForsPk seed htIdx_bv (forsAllRoots seed htIdx_bv (wordOf digest_bv) sig).toArray) := by
  unfold Spec.Fors.reconstructForsPk
  rw [if_neg (show ¬ (SphincsCVerify.Util.extractForsIndices digest_bv).getD (Spec.K - 1) 0 ≠ 0
    from fun h => h hz)]
  -- The spec's `htIdx`/`allRoots` match `htIdx_bv` / `forsAllRoots.toArray`.
  congr 1
  -- `allRoots = normalRoots.push lastRoot`; substitute the spec `htIdx` = `htIdx_bv`.
  rw [← hhtbv,
      forsAllRoots_eq_specAllRoots sig seed digest_bv htIdx_bv hhtbv, Array.toArray_toList]

set_option maxHeartbeats 16000000 in
set_option maxRecDepth 4000 in
/-- The forced-zero (`hz`) FORS continuation from the post-(htIdx,dVal) VM `v0`: run
    `sigBase`, the 12 normal trees, the last tree, and root compression, landing on
    `env "forsPk" = wordOf (pad16 r)` with `reconstructForsPk … = some r`. Factored out of
    `fors_phase` so the heavy composition is isolated from the `ifnz` dispatch. -/
private theorem fors_phase_zero
    (sig : ByteVec Spec.SignatureLen) (v0 : VM)
    (seed digest_bv : ByteVec 32) (htIdx_bv : UInt64)
    (hhtbv : htIdx_bv = UInt64.ofNat (SphincsCVerify.Util.extractHtIndex digest_bv))
    (hz : (SphincsCVerify.Util.extractForsIndices digest_bv).getD (Spec.K - 1) 0 = 0)
    (hv0dig : v0.env "digest" = wordOf digest_bv)
    (hv0ht : v0.env "htIdx" = htIdx_bv.toNat)
    (hv0dVal : v0.env "dVal" = wordOf digest_bv)
    (hv0seedw : v0.env "seed" = wordOf seed)
    (hv0N : v0.env "N_MASK" = NMASK)
    (hv0OUT : v0.env "OUT" = 0x600)
    (hv0mem : ∀ i, i < 32 → v0.mem (0 + i) = seed.data.getD i 0) :
    (execList c10Oracle sig
        (.letv "sigBase" .sigOffset
          :: .forRange "i" (.lit 12) forsTreeBody
          :: .block forsLastTreeBody
          :: .mstore (.lit 0x20) (.bin .bor (.bin .shl (.lit 160) (.var "htIdx")) (.bin .shl (.lit 128) (.lit 4)))
          :: .forRange "i" (.lit 13) forsCopyBody
          :: .sha256 (.lit 0x00) (.lit 0x1E0) (.var "OUT")
          :: [.letv "forsPk" (.bin .band (.mload (.var "OUT")) (.var "N_MASK"))]) v0).2 = none
    ∧ ∃ r, Spec.Fors.reconstructForsPk seed digest_bv (Spec.Signature.deserialise sig).fors = some r
        ∧ (execList c10Oracle sig
        (.letv "sigBase" .sigOffset
          :: .forRange "i" (.lit 12) forsTreeBody
          :: .block forsLastTreeBody
          :: .mstore (.lit 0x20) (.bin .bor (.bin .shl (.lit 160) (.var "htIdx")) (.bin .shl (.lit 128) (.lit 4)))
          :: .forRange "i" (.lit 13) forsCopyBody
          :: .sha256 (.lit 0x00) (.lit 0x1E0) (.var "OUT")
          :: [.letv "forsPk" (.bin .band (.mload (.var "OUT")) (.var "N_MASK"))]) v0).1.env "forsPk"
            = wordOf (ByteVec.pad16 r) := by
  -- Step 1: sigBase letv (→ 0).
  rw [execList_cons_none c10Oracle sig _ _ _ (by simp only [execStmt])]
  obtain ⟨v1, hv1⟩ : ∃ v1, (execStmt c10Oracle sig (.letv "sigBase" .sigOffset) v0).1 = v1 := ⟨_, rfl⟩
  rw [hv1]
  -- v1 env: sigBase = 0; htIdx/dVal/seed/N_MASK/OUT inherited from v0; mem = v0.mem.
  have hv1sb : v1.env "sigBase" = 0 := by rw [← hv1]; simp only [execStmt, eval, setVar]; rfl
  have hv1ht : v1.env "htIdx" = htIdx_bv.toNat := by
    rw [← hv1]; simp only [execStmt, eval, setVar, String.reduceEq, ite_false]; exact hv0ht
  have hv1dVal : v1.env "dVal" = wordOf digest_bv := by
    rw [← hv1]; simp only [execStmt, eval, setVar, String.reduceEq, ite_false]; exact hv0dVal
  have hv1seedw : v1.env "seed" = wordOf seed := by
    rw [← hv1]; simp only [execStmt, eval, setVar, String.reduceEq, ite_false]; exact hv0seedw
  have hv1N : v1.env "N_MASK" = NMASK := by
    rw [← hv1]; simp only [execStmt, eval, setVar, String.reduceEq, ite_false]; exact hv0N
  have hv1OUT : v1.env "OUT" = 0x600 := by
    rw [← hv1]; simp only [execStmt, eval, setVar, String.reduceEq, ite_false]; exact hv0OUT
  have hv1mem : ∀ i, i < 32 → v1.mem (0 + i) = seed.data.getD i 0 := by
    intro i hi; rw [← hv1]; simp only [execStmt, eval]; exact hv0mem i hi
  -- Step 2: the 12 normal trees.
  have hntStmt : execStmt c10Oracle sig (.forRange "i" (.lit 12) forsTreeBody) v1
      = execFor c10Oracle sig "i" forsTreeBody 12 0 v1 := by simp only [execStmt, eval]
  obtain ⟨hntNone, hntMem, hntSeed, hntOUT, hntN, hntHt, _, _, _⟩ :=
    fors_normal_trees sig v1 seed htIdx_bv (wordOf digest_bv)
      hv1ht hv1sb hv1seedw hv1N hv1OUT hv1dVal hv1mem
  rw [execList_cons_none c10Oracle sig _ _ _ (by rw [hntStmt]; exact hntNone), hntStmt]
  obtain ⟨v2, hv2⟩ : ∃ v2, (execFor c10Oracle sig "i" forsTreeBody 12 0 v1).1 = v2 := ⟨_, rfl⟩
  rw [hv2]
  -- v2: trees 0-11 at 0x80+32t; seed window; htIdx/N_MASK/OUT preserved; sigBase=0 too.
  have hv2ht : v2.env "htIdx" = htIdx_bv.toNat := by rw [← hv2]; exact hntHt
  have hv2N : v2.env "N_MASK" = NMASK := by rw [← hv2]; exact hntN
  have hv2OUT : v2.env "OUT" = 0x600 := by rw [← hv2]; exact hntOUT
  have hv2seed : ∀ i, i < 32 → v2.mem (0 + i) = seed.data.getD i 0 := by
    intro i hi; rw [← hv2]; exact hntSeed i hi
  have hv2sb : v2.env "sigBase" = 0 := by
    rw [← hv2]
    -- forsTreeBody preserves sigBase (driven through the i-loop frame).
    have := fors_normal_trees sig v1 seed htIdx_bv (wordOf digest_bv)
      hv1ht hv1sb hv1seedw hv1N hv1OUT hv1dVal hv1mem
    exact this.2.2.2.2.2.2.2.1
  have hv2trees : ∀ t, t < 12 → ∀ k, k < 32 →
      v2.mem (0x80 + 32 * t + k) = (ByteVec.pad16 (forsTreeRoot seed htIdx_bv (wordOf digest_bv) sig t)).data.getD k 0 := by
    intro t ht k hk; rw [← hv2]; exact hntMem t ht k hk
  -- Step 3: the last tree (.block forsLastTreeBody).
  have hblockStmt : execStmt c10Oracle sig (.block forsLastTreeBody) v2
      = execList c10Oracle sig forsLastTreeBody v2 := by simp only [execStmt]
  obtain ⟨hltNone, hltMem, hltSeed⟩ := fors_last_tree sig v2 seed htIdx_bv
    hv2ht hv2sb hv2N hv2OUT hv2seed
  rw [execList_cons_none c10Oracle sig _ _ _ (by rw [hblockStmt]; exact hltNone), hblockStmt]
  obtain ⟨v3, hv3⟩ : ∃ v3, (execList c10Oracle sig forsLastTreeBody v2).1 = v3 := ⟨_, rfl⟩
  rw [hv3]
  -- v3: tree 12 at 0x200; trees 0-11 preserved (mem-frame); seed window; consts preserved.
  have hv3ht : v3.env "htIdx" = htIdx_bv.toNat := by
    rw [← hv3, execList_forsLastTreeBody_preserves_var sig v2 "htIdx" (by decide)]; exact hv2ht
  have hv3N : v3.env "N_MASK" = NMASK := by
    rw [← hv3, execList_forsLastTreeBody_preserves_var sig v2 "N_MASK" (by decide)]; exact hv2N
  have hv3OUT : v3.env "OUT" = 0x600 := by
    rw [← hv3, execList_forsLastTreeBody_preserves_var sig v2 "OUT" (by decide)]; exact hv2OUT
  have hv3seed : ∀ i, i < 32 → v3.mem (0 + i) = seed.data.getD i 0 := by
    intro i hi; rw [← hv3]; exact hltSeed i hi
  -- The 13 roots at 0x80+32t in v3: t<12 from trees (mem-frame past last tree), t=12 last.
  have hv3roots : ∀ t, t < 13 → ∀ k, k < 32 →
      v3.mem (0x80 + 32 * t + k) =
        (ByteVec.pad16 ((forsAllRoots seed htIdx_bv (wordOf digest_bv) sig).getD t (ByteVec.zero 16))).data.getD k 0 := by
    intro t ht k hk
    by_cases htlt : t < 12
    · -- trees 0-11: preserved through the last-tree block (mem-frame [0x80,0x200)).
      rw [← hv3, fors_last_tree_mem_frame sig v2 hv2OUT (0x80 + 32 * t + k) ⟨by omega, by omega⟩]
      rw [hv2trees t htlt k hk, forsAllRoots_getD_lt seed htIdx_bv (wordOf digest_bv) sig t htlt]
    · -- tree 12: laid by the last tree at 0x200 = 0x80 + 32*12.
      have ht12 : t = 12 := by omega
      subst ht12
      rw [show (0x80 + 32 * 12 + k) = (0x200 + k) by omega, ← hv3, hltMem k hk,
          forsAllRoots_getD_last seed htIdx_bv (wordOf digest_bv) sig]
  -- Step 4: root compression on v3 with roots = forsAllRoots.
  obtain ⟨hcompNone, hcompPk⟩ := fors_root_compress sig v3 seed htIdx_bv
    (forsAllRoots seed htIdx_bv (wordOf digest_bv) sig)
    (forsAllRoots_length seed htIdx_bv (wordOf digest_bv) sig)
    hv3N hv3OUT hv3ht hv3seed hv3roots
  refine ⟨hcompNone, ?_⟩
  -- reconstructForsPk seed digest_bv (deserialise sig).fors = some (computeForsPk seed htIdx_bv allRoots).
  refine ⟨Spec.Fors.computeForsPk seed htIdx_bv (forsAllRoots seed htIdx_bv (wordOf digest_bv) sig).toArray, ?_, ?_⟩
  · -- the spec returns `some` (forced-zero index = 0) with allRoots = forsAllRoots.toArray.
    exact reconstructForsPk_eq_compute sig seed digest_bv htIdx_bv hhtbv hz
  · -- env "forsPk" = wordOf (pad16 (computeForsPk …)).
    exact hcompPk

set_option maxHeartbeats 16000000 in
set_option maxRecDepth 4000 in
/-- **FORS phase capstone.** From a post-`H_msg` VM (`digest = wordOf digest_bv`,
    `seed = wordOf seed`, `N_MASK`, `OUT = 0x600`, `seed` in scratch `[0,0x20)`), running the
    whole FORS fragment (`SPHINCsC10Asm.sol` L81–143: derive `htIdx`/`dVal`, the forced-zero
    `ifnz`, the 12 normal trees, the last tree, and root compression):

    * if the forced-zero last index `(extractForsIndices digest_bv).getD (K-1) 0 ≠ 0`, the
      `ifnz` reverts (`.2 = some Halt.reverted`); else
    * it falls through and binds `"forsPk" = wordOf (pad16 r)` where
      `reconstructForsPk seed digest_bv (deserialise sig).fors = some r`.

    Composes `fors_normal_trees` + `fors_last_tree` + `fors_root_compress`, bridging the
    interpreter leaf/ht indices to `extractForsIndices`/`extractHtIndex`. -/
theorem fors_phase
    (sig : ByteVec Spec.SignatureLen) (vm : VM)
    (seed digest_bv : ByteVec 32)
    (hdig : vm.env "digest" = wordOf digest_bv)
    (hseedw : vm.env "seed" = wordOf seed)
    (hN : vm.env "N_MASK" = NMASK)
    (hOUT : vm.env "OUT" = 0x600)
    (hseedmem : ∀ i, i < 32 → vm.mem (0 + i) = seed.data.getD i 0) :
    (if (SphincsCVerify.Util.extractForsIndices digest_bv).getD (Spec.K - 1) 0 ≠ 0 then
        (execList c10Oracle sig forsPhaseFragment vm).2 = some Halt.reverted
      else
        (execList c10Oracle sig forsPhaseFragment vm).2 = none
        ∧ ∃ r, Spec.Fors.reconstructForsPk seed digest_bv (Spec.Signature.deserialise sig).fors = some r
            ∧ (execList c10Oracle sig forsPhaseFragment vm).1.env "forsPk" = wordOf (ByteVec.pad16 r)) := by
  -- The spec hypertree index, and its Nat round-trip.
  obtain ⟨htIdx_bv, hhtbv⟩ :
      ∃ h : UInt64, h = UInt64.ofNat (SphincsCVerify.Util.extractHtIndex digest_bv) := ⟨_, rfl⟩
  have hhtNat : htIdx_bv.toNat = SphincsCVerify.Util.extractHtIndex digest_bv := by
    rw [hhtbv]
    show (SphincsCVerify.Util.extractHtIndex digest_bv) % UInt64.size = _
    rw [Nat.mod_eq_of_lt (Nat.lt_of_lt_of_le (SphincsCVerify.Util.extractHtIndex_lt digest_bv)
      (by decide : (2:Nat)^Spec.H ≤ UInt64.size))]
  unfold forsPhaseFragment
  -- Step 1+2: htIdx, dVal letvs.
  rw [execList_cons_none c10Oracle sig _ _ _ (by simp only [execStmt])]
  rw [execList_cons_none c10Oracle sig _ _ _ (by simp only [execStmt])]
  -- Abbreviate the post-(htIdx,dVal) VM `v0`.
  obtain ⟨v0, hv0⟩ : ∃ v0, (execStmt c10Oracle sig (.letv "dVal" (.var "digest"))
      (execStmt c10Oracle sig (.letv "htIdx"
        (.bin .band (.bin .shr (.lit 143) (.var "digest")) (.lit 0x3FFFF))) vm).1).1 = v0 := ⟨_, rfl⟩
  rw [hv0]
  -- v0's env facts: digest, htIdx-Nat (= htIdx_bv.toNat), dVal (= wordOf digest_bv), and the
  -- inherited seed/N_MASK/OUT; v0.mem = vm.mem.
  have hv0dig : v0.env "digest" = wordOf digest_bv := by
    rw [← hv0]; simp only [execStmt, eval, setVar, String.reduceEq, ite_false]; exact hdig
  have hv0ht : v0.env "htIdx" = htIdx_bv.toNat := by
    rw [← hv0]; simp only [execStmt, eval, setVar, String.reduceEq, ite_true, ite_false]
    rw [hhtNat, hdig, extractHtIndex_eq_wordShift digest_bv]
  have hv0dVal : v0.env "dVal" = wordOf digest_bv := by
    rw [← hv0]; simp only [execStmt, eval, setVar, ite_true]; exact hdig
  have hv0seedw : v0.env "seed" = wordOf seed := by
    rw [← hv0]; simp only [execStmt, eval, setVar, String.reduceEq, ite_false]; exact hseedw
  have hv0N : v0.env "N_MASK" = NMASK := by
    rw [← hv0]; simp only [execStmt, eval, setVar, String.reduceEq, ite_false]; exact hN
  have hv0OUT : v0.env "OUT" = 0x600 := by
    rw [← hv0]; simp only [execStmt, eval, setVar, String.reduceEq, ite_false]; exact hOUT
  have hv0mem : ∀ i, i < 32 → v0.mem (0 + i) = seed.data.getD i 0 := by
    intro i hi; rw [← hv0]; simp only [execStmt, eval, setVar]; exact hseedmem i hi
  -- The forced-zero condition value, via the index bridge (132 = 12*11 = (K-1)*A).
  have hcond : ((v0.env "dVal") >>> 132) &&& 2047
      = (SphincsCVerify.Util.extractForsIndices digest_bv).getD (Spec.K - 1) 0 := by
    rw [extractForsIndices_eq_wordShift digest_bv (Spec.K - 1) (by decide), hv0dVal,
        show ((Spec.K - 1) * 11) = 132 from rfl]
  -- The ifnz statement: execList (ifnz :: rest) v0.
  rw [execList]
  -- execStmt (ifnz cond body) v0: branches on eval cond ≠ 0.
  by_cases hz : (SphincsCVerify.Util.extractForsIndices digest_bv).getD (Spec.K - 1) 0 = 0
  · -- Zero: ifnz falls through.
    rw [if_neg (show ¬ ((SphincsCVerify.Util.extractForsIndices digest_bv).getD (Spec.K - 1) 0 ≠ 0)
      from fun h => h hz)]
    have hcondz : execStmt c10Oracle sig
        (.ifnz (.bin .band (.bin .shr (.lit 132) (.var "dVal")) (.lit 0x7FF)) [.revert]) v0
        = (v0, none) := by
      unfold execStmt
      rw [if_neg]
      show ¬ (((v0.env "dVal") >>> 132) &&& 2047 ≠ 0)
      rw [hcond]; exact fun h => h hz
    rw [hcondz]
    -- Continue with the rest: sigBase, 12-loop, block, compression.
    exact fors_phase_zero sig v0 seed digest_bv htIdx_bv hhtbv hz
      hv0dig hv0ht hv0dVal hv0seedw hv0N hv0OUT hv0mem
  · -- Nonzero: ifnz reverts.
    rw [if_pos (show (SphincsCVerify.Util.extractForsIndices digest_bv).getD (Spec.K - 1) 0 ≠ 0 from hz)]
    have hcondnz : execStmt c10Oracle sig
        (.ifnz (.bin .band (.bin .shr (.lit 132) (.var "dVal")) (.lit 0x7FF)) [.revert]) v0
        = (v0, some Halt.reverted) := by
      unfold execStmt
      rw [if_pos]
      · simp only [execList, execStmt]
      · show ((v0.env "dVal") >>> 132) &&& 2047 ≠ 0
        rw [hcond]; exact hz
    rw [hcondnz]

/-! ## WOTS+C `pkFromSig` refinement — phase infrastructure

The reusable byte/word/loop glue for the per-layer WOTS interp fragment
(`SPHINCsC10Asm.sol` L153–200): the digit hash, the WOTS+C digit-sum gate, the 43
WOTS chains (each a variable-length forward chain walk), and the PK-compression.
Mirrors the FORS development (`fors_climb`/`fors_normal_trees`/`fors_root_compress`)
where the shapes coincide, plus the WOTS-specific bridges:

  * `chainHash_eq_fwd` — the spec `chainHash`'s back-peel `aux` recursion as a
    *forward* `List.range'`-fold (the `forsAcc` analogue, structural, hash-free);
  * `setChainIndex_make` / `setChainPos_make` — the ADRS chain-index / chain-pos
    setters as field substitutions on `make` (byte-extensional);
  * `chainPosAdrs_word` — the interp `or(and(or(wotsAdrs, i<<64), CHAINBASE_MASK),
    pos<<32)` word equals `wordOf (make … ci=i cp=pos)` — the per-step ADRS word,
    discharged INTERNALLY (no factored/unbounded hypothesis ⇒ zero vacuity risk).
-/

/-! ### `chainHash` as a forward fold

`Spec.chainHash seed a val startPos steps = chainHash.aux … steps val`, where `aux`
peels from the BACK (`pos = startPos + (steps-1-i)`). We re-express it as a forward
`List.range' 0 steps` fold over `wotsChainFwdStep` (each step `j` hashes at
`setChainPos a (startPos + j)`), the analogue of `forsAcc`'s `range'` fold. Purely
structural — no `th`/`sha256` semantics, so `c10Oracle` irreducibility is irrelevant
and it is fast/mathlib-free. -/

set_option maxHeartbeats 2000000 in
/-- One forward chain-walk step: `th` at chain-position `startPos + j`. The
    `forsStep` analogue for the WOTS chain (the inner step loop's body). -/
def wotsChainFwdStep (seed : ByteVec 32) (a : Spec.Adrs) (startPos : Nat)
    (cur : ByteVec 16) (j : Nat) : ByteVec 16 :=
  Spec.th seed (Spec.Adrs.setChainPos a (UInt32.ofNat (startPos + j))) (ByteVec.pad16 cur)

/-- **`chainHash.aux` is a forward window fold.** Running the back-peel `aux m current`
    equals folding `wotsChainFwdStep` over the forward window `[steps-m, steps)`. By
    induction on `m` using the FRONT-cons of `range'` (`range'_succ`): `aux`'s front step
    (`pos = startPos + (steps-1-m)` for the `m+1` call) lines up with `range' (steps-m-1)
    (m+1)`'s head `steps-m-1`. Both index identities are `omega`. -/
theorem chainHash_aux_eq_fwd (seed : ByteVec 32) (a : Spec.Adrs) (startPos steps : Nat) :
    ∀ m, m ≤ steps → ∀ current,
      Spec.chainHash.aux seed a startPos steps m current
        = (List.range' (steps - m) m).foldl (wotsChainFwdStep seed a startPos) current := by
  intro m
  induction m with
  | zero =>
      intro _ current
      show current = _
      simp only [List.range'_zero, List.foldl_nil]
  | succ m ih =>
      intro hm current
      have hth : Spec.th seed (Spec.Adrs.setChainPos a (UInt32.ofNat (startPos + (steps - 1 - m))))
            (ByteVec.pad16 current)
          = wotsChainFwdStep seed a startPos current (steps - m - 1) := by
        unfold wotsChainFwdStep
        congr 3
        omega
      show Spec.chainHash.aux seed a startPos steps m
            (Spec.th seed (Spec.Adrs.setChainPos a (UInt32.ofNat (startPos + (steps - 1 - m))))
              (ByteVec.pad16 current))
          = _
      rw [hth, ih (by omega)]
      have hstart : steps - (m + 1) = steps - m - 1 := by omega
      have hstep : steps - m - 1 + 1 = steps - m := by omega
      rw [hstart, List.range'_succ, List.foldl_cons, hstep]

/-- **`chainHash` as a forward fold.** `chainHash seed a val startPos steps` is the
    forward fold of `wotsChainFwdStep` over `[0, steps)` from `val`. Instantiates
    `chainHash_aux_eq_fwd` at `m = steps` (`range' 0 steps`). The `forsAcc`/`reconstructRoot_eq_foldl`
    analogue for the WOTS chain; the inner step loop refines AGAINST this. -/
theorem chainHash_eq_fwd (seed : ByteVec 32) (a : Spec.Adrs) (val : ByteVec 16)
    (startPos steps : Nat) :
    Spec.chainHash seed a val startPos steps
      = (List.range' 0 steps).foldl (wotsChainFwdStep seed a startPos) val := by
  show Spec.chainHash.aux seed a startPos steps steps val = _
  rw [chainHash_aux_eq_fwd seed a startPos steps steps (Nat.le_refl steps) val, Nat.sub_self]

/-! ### `setChainIndex`/`setChainPos` as field substitutions on `make`

The ADRS setters are defined via `extract`/`append` (NOT `make`), so the word bridge
needs them re-expressed as the matching `make` field-substitution before `wordOf_make`
applies. Both are byte-extensional (`array_ext_getD` + the field-range case split). -/

/-- Array extensionality via `getD` (default 0) over equal-size arrays. -/
private theorem array_ext_getD (a b : Array UInt8) (hsz : a.size = b.size)
    (h : ∀ k, k < a.size → a.getD k 0 = b.getD k 0) : a = b := by
  apply Array.ext hsz
  intro k hk1 hk2
  have := h k hk1
  rw [Array.getD_eq_getD_getElem?, Array.getElem?_eq_getElem hk1, Option.getD_some,
      Array.getD_eq_getD_getElem?, Array.getElem?_eq_getElem hk2, Option.getD_some] at this
  exact this

/-- `getD` over `Array.extract` at an in-range index. -/
private theorem extract_getD (arr : Array UInt8) (s e i : Nat) (h : i < min e arr.size - s) :
    (arr.extract s e).getD i 0 = arr.getD (s + i) 0 := by
  rw [Array.getD_eq_getD_getElem?, Array.getElem?_extract, if_pos h, ← Array.getD_eq_getD_getElem?]

/-- `setChainIndex M idx`'s `data` is `M.data.extract 0 20 ++ ofU32BE idx ++ M.data.extract 24 32`. -/
private theorem setChainIndex_data (M : Spec.Adrs) (idx : UInt32) :
    (Spec.Adrs.setChainIndex M idx).data
      = (M.data.extract 0 20 ++ (ByteVec.ofU32BE idx).data) ++ M.data.extract 24 32 := by
  unfold Spec.Adrs.setChainIndex
  simp only [ByteVec.cast]
  show ((M.data.extract 0 20 ++ (ByteVec.ofU32BE idx).data) ++ M.data.extract 24 32) = _
  rfl

/-- `setChainPos M pos`'s `data` is `M.data.extract 0 24 ++ ofU32BE pos ++ M.data.extract 28 32`. -/
private theorem setChainPos_data (M : Spec.Adrs) (pos : UInt32) :
    (Spec.Adrs.setChainPos M pos).data
      = (M.data.extract 0 24 ++ (ByteVec.ofU32BE pos).data) ++ M.data.extract 28 32 := by
  unfold Spec.Adrs.setChainPos
  simp only [ByteVec.cast]
  show ((M.data.extract 0 24 ++ (ByteVec.ofU32BE pos).data) ++ M.data.extract 28 32) = _
  rfl

/-- **`make`'s `data` byte at `k`, by covering field.** The `getD` form (companion of
    the private `make_data_getD_beByte`; this returns the covering field's `getD`, the shape
    the `setChain*` substitution proofs consume). -/
theorem make_data_getD (layer : UInt32) (tree : UInt64) (atype kp ci cp ha : UInt32) (k : Nat) :
    (Spec.Adrs.make layer tree atype kp ci cp ha).data.getD k 0
      = if k < 4 then (ByteVec.ofU32BE layer).data.getD k 0
        else if k < 12 then (ByteVec.ofU64BE tree).data.getD (k - 4) 0
        else if k < 16 then (ByteVec.ofU32BE atype).data.getD (k - 12) 0
        else if k < 20 then (ByteVec.ofU32BE kp).data.getD (k - 16) 0
        else if k < 24 then (ByteVec.ofU32BE ci).data.getD (k - 20) 0
        else if k < 28 then (ByteVec.ofU32BE cp).data.getD (k - 24) 0
        else (ByteVec.ofU32BE ha).data.getD (k - 28) 0 := by
  have sL : (ByteVec.ofU32BE layer).data.size = 4 := (ByteVec.ofU32BE layer).size_eq
  have sT : (ByteVec.ofU64BE tree).data.size = 8 := (ByteVec.ofU64BE tree).size_eq
  have sA : (ByteVec.ofU32BE atype).data.size = 4 := (ByteVec.ofU32BE atype).size_eq
  have sK : (ByteVec.ofU32BE kp).data.size = 4 := (ByteVec.ofU32BE kp).size_eq
  have sC : (ByteVec.ofU32BE ci).data.size = 4 := (ByteVec.ofU32BE ci).size_eq
  have sP : (ByteVec.ofU32BE cp).data.size = 4 := (ByteVec.ofU32BE cp).size_eq
  show ((((((((ByteVec.ofU32BE layer).data ++ (ByteVec.ofU64BE tree).data) ++ (ByteVec.ofU32BE atype).data)
        ++ (ByteVec.ofU32BE kp).data) ++ (ByteVec.ofU32BE ci).data) ++ (ByteVec.ofU32BE cp).data)
        ++ (ByteVec.ofU32BE ha).data)).getD k 0 = _
  rw [arr_append_getD _ (ByteVec.ofU32BE ha).data 28 k (by simp [Array.size_append, sL, sT, sA, sK, sC, sP])]
  rw [arr_append_getD _ (ByteVec.ofU32BE cp).data 24 k (by simp [Array.size_append, sL, sT, sA, sK, sC])]
  rw [arr_append_getD _ (ByteVec.ofU32BE ci).data 20 k (by simp [Array.size_append, sL, sT, sA, sK])]
  rw [arr_append_getD _ (ByteVec.ofU32BE kp).data 16 k (by simp [Array.size_append, sL, sT, sA])]
  rw [arr_append_getD _ (ByteVec.ofU32BE atype).data 12 k (by simp [Array.size_append, sL, sT])]
  rw [arr_append_getD (ByteVec.ofU32BE layer).data (ByteVec.ofU64BE tree).data 4 k sL]
  by_cases h0 : k < 4
  · simp only [if_pos h0, if_pos (show k < 28 by omega), if_pos (show k < 24 by omega),
      if_pos (show k < 20 by omega), if_pos (show k < 16 by omega), if_pos (show k < 12 by omega)]
  · simp only [if_neg h0]
    by_cases h1 : k < 12
    · simp only [if_pos h1, if_pos (show k < 28 by omega), if_pos (show k < 24 by omega),
        if_pos (show k < 20 by omega), if_pos (show k < 16 by omega)]
    · simp only [if_neg h1]
      by_cases h2 : k < 16
      · simp only [if_pos h2, if_pos (show k < 28 by omega), if_pos (show k < 24 by omega),
          if_pos (show k < 20 by omega)]
      · simp only [if_neg h2]
        by_cases h3 : k < 20
        · simp only [if_pos h3, if_pos (show k < 28 by omega), if_pos (show k < 24 by omega)]
        · simp only [if_neg h3]
          by_cases h4 : k < 24
          · simp only [if_pos h4, if_pos (show k < 28 by omega)]
          · simp only [if_neg h4]

set_option maxHeartbeats 2000000 in
/-- **`setChainIndex` of a `make` is the `ci`-field substitution.** -/
theorem setChainIndex_make (layer : UInt32) (tree : UInt64) (atype kp ci cp ha idx : UInt32) :
    Spec.Adrs.setChainIndex (Spec.Adrs.make layer tree atype kp ci cp ha) idx
      = Spec.Adrs.make layer tree atype kp idx cp ha := by
  apply ByteVec.ext_data
  rw [setChainIndex_data]
  have hmk : (Spec.Adrs.make layer tree atype kp ci cp ha).data.size = 32 :=
    (Spec.Adrs.make layer tree atype kp ci cp ha).size_eq
  apply array_ext_getD
  · rw [Array.size_append, Array.size_append, Array.size_extract, Array.size_extract,
        (ByteVec.ofU32BE idx).size_eq, hmk, (Spec.Adrs.make layer tree atype kp idx cp ha).size_eq]
    omega
  · intro k hk
    have hk32 : k < 32 := by
      rw [Array.size_append, Array.size_append, Array.size_extract, Array.size_extract,
          (ByteVec.ofU32BE idx).size_eq, hmk] at hk
      omega
    rw [arr_append_getD _ ((Spec.Adrs.make layer tree atype kp ci cp ha).data.extract 24 32) 24 k
          (by rw [Array.size_append, Array.size_extract, (ByteVec.ofU32BE idx).size_eq, hmk]; omega)]
    rw [make_data_getD layer tree atype kp idx cp ha k]
    by_cases h24 : k < 24
    · rw [if_pos h24]
      rw [arr_append_getD _ (ByteVec.ofU32BE idx).data 20 k (by rw [Array.size_extract, hmk]; omega)]
      by_cases h20 : k < 20
      · rw [if_pos h20, extract_getD _ 0 20 k (by rw [hmk]; omega), Nat.zero_add,
            make_data_getD layer tree atype kp ci cp ha k]
        by_cases h4 : k < 4
        · simp only [if_pos h4]
        · by_cases h12 : k < 12
          · simp only [if_neg h4, if_pos h12]
          · by_cases h16 : k < 16
            · simp only [if_neg h4, if_neg h12, if_pos h16]
            · simp only [if_neg h4, if_neg h12, if_neg h16, if_pos h20]
      · rw [if_neg h20, if_neg (show ¬ k < 20 from h20), if_neg (show ¬ k < 16 by omega),
            if_neg (show ¬ k < 12 by omega), if_neg (show ¬ k < 4 by omega), if_pos h24]
    · rw [if_neg h24, extract_getD _ 24 32 (k - 24) (by rw [hmk]; omega), show 24 + (k - 24) = k by omega,
          make_data_getD layer tree atype kp ci cp ha k]
      simp only [if_neg (show ¬ k < 24 from h24), if_neg (show ¬ k < 20 by omega),
        if_neg (show ¬ k < 16 by omega), if_neg (show ¬ k < 12 by omega), if_neg (show ¬ k < 4 by omega)]

set_option maxHeartbeats 2000000 in
/-- **`setChainPos` of a `make` is the `cp`-field substitution.** -/
theorem setChainPos_make (layer : UInt32) (tree : UInt64) (atype kp ci cp ha pos : UInt32) :
    Spec.Adrs.setChainPos (Spec.Adrs.make layer tree atype kp ci cp ha) pos
      = Spec.Adrs.make layer tree atype kp ci pos ha := by
  apply ByteVec.ext_data
  rw [setChainPos_data]
  have hmk : (Spec.Adrs.make layer tree atype kp ci cp ha).data.size = 32 :=
    (Spec.Adrs.make layer tree atype kp ci cp ha).size_eq
  apply array_ext_getD
  · rw [Array.size_append, Array.size_append, Array.size_extract, Array.size_extract,
        (ByteVec.ofU32BE pos).size_eq, hmk, (Spec.Adrs.make layer tree atype kp ci pos ha).size_eq]
    omega
  · intro k hk
    have hk32 : k < 32 := by
      rw [Array.size_append, Array.size_append, Array.size_extract, Array.size_extract,
          (ByteVec.ofU32BE pos).size_eq, hmk] at hk
      omega
    rw [arr_append_getD _ ((Spec.Adrs.make layer tree atype kp ci cp ha).data.extract 28 32) 28 k
          (by rw [Array.size_append, Array.size_extract, (ByteVec.ofU32BE pos).size_eq, hmk]; omega)]
    rw [make_data_getD layer tree atype kp ci pos ha k]
    by_cases h28 : k < 28
    · rw [if_pos h28]
      rw [arr_append_getD _ (ByteVec.ofU32BE pos).data 24 k (by rw [Array.size_extract, hmk]; omega)]
      by_cases h24 : k < 24
      · rw [if_pos h24, extract_getD _ 0 24 k (by rw [hmk]; omega), Nat.zero_add,
            make_data_getD layer tree atype kp ci cp ha k]
        by_cases h4 : k < 4
        · simp only [if_pos h4]
        · by_cases h12 : k < 12
          · simp only [if_neg h4, if_pos h12]
          · by_cases h16 : k < 16
            · simp only [if_neg h4, if_neg h12, if_pos h16]
            · by_cases h20 : k < 20
              · simp only [if_neg h4, if_neg h12, if_neg h16, if_pos h20]
              · simp only [if_neg h4, if_neg h12, if_neg h16, if_neg h20, if_pos h24]
      · rw [if_neg h24, if_neg (show ¬ k < 24 from h24), if_neg (show ¬ k < 20 by omega),
            if_neg (show ¬ k < 16 by omega), if_neg (show ¬ k < 12 by omega),
            if_neg (show ¬ k < 4 by omega), if_pos h28]
    · rw [if_neg h28, extract_getD _ 28 32 (k - 28) (by rw [hmk]; omega), show 28 + (k - 28) = k by omega,
          make_data_getD layer tree atype kp ci cp ha k]
      simp only [if_neg (show ¬ k < 28 from h28), if_neg (show ¬ k < 24 by omega),
        if_neg (show ¬ k < 20 by omega), if_neg (show ¬ k < 16 by omega),
        if_neg (show ¬ k < 12 by omega), if_neg (show ¬ k < 4 by omega)]

/-! ### The CHAINBASE_MASK byte action + the WOTS ADRS word + the chain-pos ADRS bridge -/

set_option maxHeartbeats 8000000 in
/-- The deployed `CHAINBASE_MASK` (`SPHINCsC10Asm.sol` L180): all 32 bytes 0xFF except
    the `cp` field (bytes [24,28)) zeroed. The interp `and(or(wotsAdrs, i<<64),
    CHAINBASE_MASK)` uses it to clear the chain-position field before the per-step OR. -/
def CHAINBASE_MASK : Nat := 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFF

/-- `CHAINBASE_MASK = 2^64·(2^192−1) + (2^32−1)`: bits [0,32) set (ha field), [32,64)
    zero (cp field), [64,256) set. The shape `testBit_two_pow_mul_add` consumes. -/
private theorem chainbase_eq_mul : CHAINBASE_MASK = 2 ^ 64 * (2 ^ 192 - 1) + (2 ^ 32 - 1) := by decide

/-- Bit `k` of `CHAINBASE_MASK` is set iff `k < 256 ∧ ¬(32 ≤ k < 64)`. -/
private theorem chainbase_testBit (k : Nat) :
    CHAINBASE_MASK.testBit k = decide (k < 256 ∧ ¬ (32 ≤ k ∧ k < 64)) := by
  have hlt : (2 : Nat) ^ 32 - 1 < 2 ^ 64 := by decide
  rw [chainbase_eq_mul, Nat.testBit_two_pow_mul_add (2 ^ 192 - 1) hlt k]
  by_cases hk : k < 64
  · rw [if_pos hk, Nat.testBit_two_pow_sub_one, decide_eq_decide]; omega
  · rw [if_neg hk, Nat.testBit_two_pow_sub_one, decide_eq_decide]; omega

/-- The inner `Nat` byte of `CHAINBASE_MASK`: `0` on the cp field [24,28), `2^8−1` else.
    Bit-extensional (no `i < 32` needed). The `nmask_byte` analogue. -/
private theorem chainbase_byte_nat (i : Nat) :
    (CHAINBASE_MASK >>> (8 * (31 - i))) % 2 ^ 8 = if 24 ≤ i ∧ i < 28 then 0 else 2 ^ 8 - 1 := by
  apply Nat.eq_of_testBit_eq
  intro b
  rw [Nat.testBit_mod_two_pow, Nat.testBit_shiftRight, chainbase_testBit]
  by_cases hc : 24 ≤ i ∧ i < 28
  · rw [if_pos hc, Nat.zero_testBit]
    by_cases hb : b < 8
    · rw [decide_eq_true hb, Bool.true_and]; apply decide_eq_false; omega
    · rw [decide_eq_false hb, Bool.false_and]
  · rw [if_neg hc, Nat.testBit_two_pow_sub_one]
    by_cases hb : b < 8
    · rw [decide_eq_true hb, Bool.true_and]; apply decide_eq_true; omega
    · rw [decide_eq_false hb, Bool.false_and]

/-- **Byte-action of `CHAINBASE_MASK`.** `beByte CHAINBASE_MASK i = 0` on the cp field
    [24,28), `0xFF` elsewhere. -/
theorem chainbase_byte (i : Nat) :
    beByte CHAINBASE_MASK i = if 24 ≤ i ∧ i < 28 then 0 else 0xFF := by
  unfold beByte
  rw [show (256 : Nat) = 2 ^ 8 from rfl, chainbase_byte_nat]
  by_cases hc : 24 ≤ i ∧ i < 28
  · rw [if_pos hc, if_pos hc]; rfl
  · rw [if_neg hc, if_neg hc]; rfl

/-- **OR distributes over `beByte`.** (Mirror of the existing `beByte_lor`'s sibling, for AND.) -/
theorem beByte_band (a b i : Nat) : beByte (a &&& b) i = beByte a i &&& beByte b i := by
  unfold beByte
  rw [Nat.shiftRight_and_distrib, show (256 : Nat) = 2 ^ 8 from rfl, Nat.and_mod_two_pow,
      UInt8.ofNat_and]

/-- A UInt8 ANDed with `0xFF` is itself. -/
private theorem and_0xFF_id (b : UInt8) : b &&& 0xFF = b := by
  have : (0xFF : UInt8) = (-1 : UInt8) := by decide
  rw [this, UInt8.and_neg_one]

/-- **WOTS ADRS word.** `wots = make layer tree ADRS_WOTS kp 0 0 0`; the `ci=cp=ha=0`
    shifts vanish (Yul `or(shl(224,layer), or(shl(160,tree), or(shl(128,0), shl(96,kp))))`). -/
theorem wordOf_wots (layer : UInt32) (tree : UInt64) (kp : UInt32) :
    wordOf (Spec.Adrs.wots layer tree kp)
      = layer.toNat <<< 224 ||| tree.toNat <<< 160 ||| (UInt32.ofNat Spec.ADRS_WOTS).toNat <<< 128
        ||| kp.toNat <<< 96 := by
  unfold Spec.Adrs.wots
  rw [wordOf_make]
  show _ ||| _ ||| _ ||| _ ||| (0 : UInt32).toNat <<< 64 ||| (0 : UInt32).toNat <<< 32
        ||| (0 : UInt32).toNat = _
  rw [show (0 : UInt32).toNat = 0 from rfl, Nat.zero_shiftLeft, Nat.or_zero, Nat.zero_shiftLeft,
      Nat.or_zero, Nat.or_zero]

/-- `(ByteVec.ofU32BE 0).data.getD j 0 = 0` for `j < 4`. -/
private theorem ofU32BE_zero_getD (j : Nat) (hj : j < 4) :
    (ByteVec.ofU32BE (0 : UInt32)).data.getD j 0 = 0 := by
  rw [ofU32BE_getD_eq_beByte (0 : UInt32) j hj, show (0 : UInt32).toNat = 0 from rfl]
  unfold beByte
  rw [Nat.zero_shiftRight, Nat.zero_mod]; rfl

/-- `(UInt32.ofNat x).toNat = x` for `x < 2^32`. -/
private theorem u32_roundtrip (x : Nat) (hx : x < 2 ^ 32) : (UInt32.ofNat x).toNat = x := by
  show x % UInt32.size = x
  rw [Nat.mod_eq_of_lt (show x < UInt32.size from hx)]

/-- **Per-step chain-position ADRS word.** The interp word
    `or(and(or(wotsAdrs, i<<64), CHAINBASE_MASK), pos<<32)` (with `wotsAdrs =
    wordOf (Adrs.wots layer tree kp)`) equals `wordOf (make layer tree ADRS_WOTS kp i pos 0)`
    for `i, pos < 2^32`. The `wots` base has `ci=cp=ha=0`, so `or i<<64` sets `ci=i`,
    the mask clears (already-zero) `cp`, and `or pos<<32` sets `cp=pos` cleanly. Proved
    byte-extensionally (`eq_of_beByte` + the 7-field range split, masking the cp field).
    Discharged INTERNALLY — NO factored/unbounded hypothesis (the `i<2^32`/`pos<2^32`
    bounds are free from `i<43`/`pos<8` at the call site), so zero vacuity risk. -/
theorem chainPosAdrs_word (layer : UInt32) (tree : UInt64) (kp : UInt32) (i pos : Nat)
    (hi : i < 2 ^ 32) (hpos : pos < 2 ^ 32) :
    ((wordOf (Spec.Adrs.wots layer tree kp) ||| i <<< 64) &&& CHAINBASE_MASK) ||| pos <<< 32
      = wordOf (Spec.Adrs.make layer tree (UInt32.ofNat Spec.ADRS_WOTS) kp
          (UInt32.ofNat i) (UInt32.ofNat pos) 0) := by
  have hbP : pos <<< 32 < 2 ^ 256 := shl_lt_two_pow_256 pos 32 32 hpos (by omega)
  apply eq_of_beByte
  · apply Nat.or_lt_two_pow
    · exact Nat.lt_of_le_of_lt Nat.and_le_right (by unfold CHAINBASE_MASK; decide)
    · exact hbP
  · exact wordOf_lt _
  · intro k hk
    rw [beByte_wordOf_getD _ k hk,
        make_data_getD layer tree _ kp (UInt32.ofNat i) (UInt32.ofNat pos) 0 k]
    rw [beByte_lor, beByte_band, beByte_lor, chainbase_byte k]
    rw [beByte_wordOf_getD (Spec.Adrs.wots layer tree kp) k hk]
    show (((Spec.Adrs.make layer tree (UInt32.ofNat Spec.ADRS_WOTS) kp 0 0 0).data.getD k 0
          ||| beByte (i <<< 64) k) &&& _) ||| beByte (pos <<< 32) k = _
    rw [make_data_getD layer tree _ kp 0 0 0 k]
    rw [show i <<< 64 = (UInt32.ofNat i).toNat <<< (8 * (28 - 20)) by rw [u32_roundtrip i hi]]
    rw [show pos <<< 32 = (UInt32.ofNat pos).toNat <<< (8 * (28 - 24)) by rw [u32_roundtrip pos hpos]]
    rw [field32_byte (UInt32.ofNat i) 20 k (by omega) hk, field32_byte (UInt32.ofNat pos) 24 k (by omega) hk]
    by_cases h4 : k < 4
    · simp only [if_pos h4, if_pos (show k < 28 by omega), if_pos (show k < 24 by omega),
        if_pos (show k < 20 by omega), if_pos (show k < 16 by omega), if_pos (show k < 12 by omega),
        if_neg (show ¬ (20 ≤ k ∧ k < 24) by omega), if_neg (show ¬ (24 ≤ k ∧ k < 28) by omega)]
      rw [UInt8.or_zero, UInt8.or_zero, and_0xFF_id]
    · by_cases h12 : k < 12
      · simp only [if_neg h4, if_pos h12, if_pos (show k < 28 by omega), if_pos (show k < 24 by omega),
          if_pos (show k < 20 by omega), if_pos (show k < 16 by omega),
          if_neg (show ¬ (20 ≤ k ∧ k < 24) by omega), if_neg (show ¬ (24 ≤ k ∧ k < 28) by omega)]
        rw [UInt8.or_zero, UInt8.or_zero, and_0xFF_id]
      · by_cases h16 : k < 16
        · simp only [if_neg h4, if_neg h12, if_pos h16, if_pos (show k < 28 by omega),
            if_pos (show k < 24 by omega), if_pos (show k < 20 by omega),
            if_neg (show ¬ (20 ≤ k ∧ k < 24) by omega), if_neg (show ¬ (24 ≤ k ∧ k < 28) by omega)]
          rw [UInt8.or_zero, UInt8.or_zero, and_0xFF_id]
        · by_cases h20 : k < 20
          · simp only [if_neg h4, if_neg h12, if_neg h16, if_pos h20, if_pos (show k < 28 by omega),
              if_pos (show k < 24 by omega), if_neg (show ¬ (20 ≤ k ∧ k < 24) by omega),
              if_neg (show ¬ (24 ≤ k ∧ k < 28) by omega)]
            rw [UInt8.or_zero, UInt8.or_zero, and_0xFF_id]
          · by_cases h24 : k < 24
            · simp only [if_neg h4, if_neg h12, if_neg h16, if_neg h20, if_pos h24,
                if_pos (show k < 28 by omega), if_pos (show 20 ≤ k ∧ k < 24 by omega),
                if_neg (show ¬ (24 ≤ k ∧ k < 28) by omega)]
              rw [UInt8.or_zero, ofU32BE_zero_getD (k - 20) (by omega), UInt8.zero_or, and_0xFF_id,
                  ofU32BE_getD_eq_beByte (UInt32.ofNat i) (k - 20) (by omega)]
              congr 1; omega
            · by_cases h28 : k < 28
              · simp only [if_neg h4, if_neg h12, if_neg h16, if_neg h20, if_neg h24, if_pos h28,
                  if_pos (show 24 ≤ k ∧ k < 28 by omega), if_neg (show ¬ (20 ≤ k ∧ k < 24) by omega)]
                rw [ofU32BE_zero_getD (k - 24) (by omega), UInt8.or_zero, UInt8.and_zero, UInt8.zero_or,
                    ofU32BE_getD_eq_beByte (UInt32.ofNat pos) (k - 24) (by omega)]
                congr 1; omega
              · simp only [if_neg h4, if_neg h12, if_neg h16, if_neg h20, if_neg h24, if_neg h28,
                  if_neg (show ¬ (20 ≤ k ∧ k < 24) by omega), if_neg (show ¬ (24 ≤ k ∧ k < 28) by omega)]
                rw [UInt8.or_zero, UInt8.or_zero, and_0xFF_id]

/-! ### The WOTS+C digit hash + digit-sum gate

The digit hash is the UNMASKED 4-segment `sha256(seed‖wotsAdrs‖currentNode‖count)`
returning the full 32-byte `d` (`Spec.wotsDigest`); the digit-sum gate reads 43 base-8
digits of `d` and reverts unless they sum to `TargetSum = 205`. The digit hash mirrors
`hmsg_digest` (UNMASKED readback, here 4 segments); the digit-sum loop is the one piece
with no FORS template (an Array-foldl-sum bridge). -/

/-- The digit-hash fragment of the per-layer body (`SPHINCsC10Asm.sol` L167–173). -/
def wotsDigitHashFragment : List Stmt :=
  [ .mstore (.lit 0x00) (.var "seed")
  , .mstore (.lit 0x20) (.var "wotsAdrs")
  , .mstore (.lit 0x40) (.var "currentNode")
  , .mstore (.lit 0x60) (.var "count")
  , .sha256 (.lit 0x00) (.lit 0x80) (.var "OUT")
  , .letv "d" (.mload (.var "OUT")) ]

/-- The 4-segment list the WOTS digit hash feeds: `[seed, wotsAdrs, pad16 msgHash, u32ToB32 count]`. -/
private def digitSegs (seed : ByteVec 32) (wotsAdrs : Spec.Adrs) (msgHash : ByteVec 16)
    (count : UInt32) : List (ByteVec 32) :=
  [seed, wotsAdrs, ByteVec.pad16 msgHash, ByteVec.u32ToB32 count]

/-- **Holds the digit-hash segments.** After the four `mstore`s, scratch `[0x00, 0x80)`
    holds the four `wotsDigest` segments. The 4-segment `hmsgMem5_holdsSegs` analogue. -/
private theorem digitMem_holdsSegs (mem : ByteMemory)
    (seed : ByteVec 32) (wotsAdrs : Spec.Adrs) (msgHash : ByteVec 16) (count : UInt32) :
    holdsSegs (mstore32 (mstore32 (mstore32 (mstore32 mem 0 (wordOf seed))
        32 (wordOf wotsAdrs)) 64 (wordOf (ByteVec.pad16 msgHash))) 96 (wordOf (ByteVec.u32ToB32 count))) 0
      (digitSegs seed wotsAdrs msgHash count) := by
  intro j i hj hi
  have hjlt : j < 4 := by simpa [digitSegs] using hj
  rw [Nat.zero_add]
  match j, hjlt with
  | 0, _ =>
      rw [mstore32_frame _ 96 _ (32 * 0 + i) (by omega), mstore32_frame _ 64 _ (32 * 0 + i) (by omega),
          mstore32_frame _ 32 _ (32 * 0 + i) (by omega)]
      have e := mstore32_get mem 0 (wordOf seed) i hi
      rw [show (32 * 0 + i) = (0 + i) by omega, e, beByte_wordOf_getD seed i hi]
      rfl
  | 1, _ =>
      rw [mstore32_frame _ 96 _ (32 * 1 + i) (by omega), mstore32_frame _ 64 _ (32 * 1 + i) (by omega)]
      have e := mstore32_get (mstore32 mem 0 (wordOf seed)) 32 (wordOf wotsAdrs) i hi
      rw [show (32 * 1 + i) = (32 + i) by omega, e, beByte_wordOf_getD wotsAdrs i hi]
      rfl
  | 2, _ =>
      rw [mstore32_frame _ 96 _ (32 * 2 + i) (by omega)]
      have e := mstore32_get (mstore32 (mstore32 mem 0 (wordOf seed)) 32 (wordOf wotsAdrs)) 64
        (wordOf (ByteVec.pad16 msgHash)) i hi
      rw [show (32 * 2 + i) = (64 + i) by omega, e, beByte_wordOf_getD (ByteVec.pad16 msgHash) i hi]
      rfl
  | 3, _ =>
      have e := mstore32_get (mstore32 (mstore32 (mstore32 mem 0 (wordOf seed)) 32 (wordOf wotsAdrs)) 64
        (wordOf (ByteVec.pad16 msgHash))) 96 (wordOf (ByteVec.u32ToB32 count)) i hi
      rw [show (32 * 3 + i) = (96 + i) by omega, e, beByte_wordOf_getD (ByteVec.u32ToB32 count) i hi]
      rfl

set_option maxHeartbeats 4000000 in
set_option maxRecDepth 4000 in
/-- **WOTS digit-hash refinement.** Running `wotsDigitHashFragment` from a VM whose env
    supplies `seed`/`wotsAdrs`/`currentNode = pad16 msgHash`/`count` as `wordOf`-words and
    `OUT = 0x600` falls through and binds `"d"` to the UNMASKED full-32-byte
    `wordOf (Spec.wotsDigest seed wotsAdrs (pad16 msgHash) count)`. The 4-segment, UNMASKED
    analogue of `hmsg_digest`. -/
theorem wots_digit_hash
    (sig : ByteVec Spec.SignatureLen) (vm : VM)
    (seed : ByteVec 32) (wotsAdrs : Spec.Adrs) (msgHash : ByteVec 16) (count : UInt32)
    (hseedw : vm.env "seed" = wordOf seed)
    (hwa : vm.env "wotsAdrs" = wordOf wotsAdrs)
    (hcn : vm.env "currentNode" = wordOf (ByteVec.pad16 msgHash))
    (hcount : vm.env "count" = wordOf (ByteVec.u32ToB32 count))
    (hOUT : vm.env "OUT" = 0x600) :
    (execList c10Oracle sig wotsDigitHashFragment vm).2 = none
    ∧ ((execList c10Oracle sig wotsDigitHashFragment vm).1).env "d"
        = wordOf (Spec.wotsDigest seed wotsAdrs (ByteVec.pad16 msgHash) count) := by
  unfold wotsDigitHashFragment
  rw [execList_cons_none c10Oracle sig _ _ vm (by simp only [execStmt])]
  rw [execList_cons_none c10Oracle sig _ _ _ (by simp only [execStmt])]
  rw [execList_cons_none c10Oracle sig _ _ _ (by simp only [execStmt])]
  rw [execList_cons_none c10Oracle sig _ _ _ (by simp only [execStmt])]
  rw [execList_cons_none c10Oracle sig _ _ _ (by simp only [execStmt])]
  rw [execList_cons_none c10Oracle sig _ _ _ (by simp only [execStmt])]
  rw [execList]
  refine ⟨rfl, ?_⟩
  simp only [execStmt, eval, setVar, hseedw, hwa, hcn, hcount, hOUT,
    ite_true, ite_false, String.reduceEq]
  -- env "d" = mload32 (writeRegion mem4 0x600 dig) 0x600, dig = c10Oracle (slice mem4 0 0x80)
  rw [mload32_writeRegion_digest]
  congr 1
  refine (c10Oracle_holdsSegs _ 0 (digitSegs seed wotsAdrs msgHash count)
    (digitMem_holdsSegs vm.mem seed wotsAdrs msgHash count)).trans ?_
  unfold digitSegs Spec.wotsDigest
  rfl

/-! ### Digit-sum: pure helpers + the gate loop

`partialDigitSum d cur` is the running interp sum (`∑_{ii<cur} (wordOf d >>> ii·3) & 7`,
re-expressed in `readBitsLe` form via the alignment). The loop invariant carries the bound
`≤ 7·cur` so the `eAdd`'s `%W` truncation is inert. The closing `digitSum_extractDigits`
bridges the Array-foldl-sum `digitSum (extractDigits d)` to `partialDigitSum d L`. -/

/-- The running digit sum after `cur` levels (interp side, in spec `readBitsLe` form). -/
def partialDigitSum (d_bv : ByteVec 32) (cur : Nat) : Nat :=
  (List.range cur).foldl
    (fun acc ii => acc + SphincsCVerify.Util.readBitsLe d_bv (ii * Spec.LogW) Spec.LogW) 0

/-- `partialDigitSum`'s successor step. -/
theorem partialDigitSum_succ (d_bv : ByteVec 32) (cur : Nat) :
    partialDigitSum d_bv (cur + 1)
      = partialDigitSum d_bv cur + SphincsCVerify.Util.readBitsLe d_bv (cur * Spec.LogW) Spec.LogW := by
  unfold partialDigitSum
  rw [List.range_succ, List.foldl_append]
  simp only [List.foldl_cons, List.foldl_nil]

/-- Each WOTS digit is `< W = 8` (`readBitsLe … LogW < 2^LogW = 8`). -/
theorem digit_lt_8 (d_bv : ByteVec 32) (ii : Nat) :
    SphincsCVerify.Util.readBitsLe d_bv (ii * Spec.LogW) Spec.LogW < 8 := by
  have := SphincsCVerify.Util.readBitsLe_lt d_bv (ii * Spec.LogW) Spec.LogW
  have hL : Spec.LogW = 3 := rfl
  rw [hL] at this; exact this

/-- `partialDigitSum d cur ≤ 7·cur` — the bound that keeps the interp `eAdd`'s `%W` inert. -/
theorem partialDigitSum_le (d_bv : ByteVec 32) : ∀ cur, partialDigitSum d_bv cur ≤ 7 * cur := by
  intro cur
  induction cur with
  | zero => simp [partialDigitSum]
  | succ c ih => rw [partialDigitSum_succ]; have := digit_lt_8 d_bv c; omega

/-- **Digit alignment.** The interp `(wordOf d >>> ii·3) & 7` equals the spec
    `readBitsLe d (ii·LogW) LogW` for `ii < L`. The `extractForsIndices_eq_wordShift`
    analogue (`LogW = 3`, mask `2^3-1 = 7`, window `[ii·3, ii·3+3) ⊆ [0, 129) ⊆ [0, 256)`). -/
theorem digit_align (d_bv : ByteVec 32) (ii : Nat) (hii : ii < Spec.L) :
    (wordOf d_bv >>> (ii * 3)) &&& 0x7
      = SphincsCVerify.Util.readBitsLe d_bv (ii * Spec.LogW) Spec.LogW := by
  have hL : Spec.LogW = 3 := rfl
  rw [hL, readBitsLe_eq_wordShift d_bv (ii * 3) 3 (by have : Spec.L = 43 := rfl; omega)]

/-- Generic `(+)`-foldl over `List.ofFn (Fin n)` equals the same over `List.range n`
    (val-indexed). By induction with `ofFn_succ_last` / `range_succ` (both back-cons). -/
private theorem ofFn_natfoldl_eq_range (g : Nat → Nat) : ∀ n,
    (List.ofFn (n := n) (fun i : Fin n => g i.val)).foldl (· + ·) 0
      = (List.range n).foldl (fun acc i => acc + g i) 0 := by
  intro n
  induction n with
  | zero => simp [List.ofFn_zero]
  | succ m ih =>
      rw [List.ofFn_succ_last, List.foldl_append, List.range_succ, List.foldl_append]
      have hinner : (List.ofFn fun i : Fin m => (fun j : Fin (m + 1) => g j.val) i.castSucc)
          = List.ofFn (fun i : Fin m => g i.val) := by
        apply congrArg; funext i; rfl
      rw [hinner, ih]
      simp only [List.foldl_cons, List.foldl_nil]
      rfl

/-- **Digit-sum closing.** `digitSum (extractDigits d)` (the spec's Array-foldl-sum) equals
    `partialDigitSum d L`. Bridges `Array.foldl` → `List.foldl` (`Array.foldl_toList`,
    `Array.toList_ofFn`) → the val-indexed `range` fold (`ofFn_natfoldl_eq_range`). -/
theorem digitSum_extractDigits (d_bv : ByteVec 32) :
    SphincsCVerify.Util.digitSum (SphincsCVerify.Util.extractDigits d_bv)
      = partialDigitSum d_bv Spec.L := by
  unfold SphincsCVerify.Util.digitSum SphincsCVerify.Util.extractDigits partialDigitSum
  rw [← Array.foldl_toList, Array.toList_ofFn]
  exact ofFn_natfoldl_eq_range
    (fun i => SphincsCVerify.Util.readBitsLe d_bv (i * Spec.LogW) Spec.LogW) Spec.L

/-- The digit-sum loop body (`SPHINCsC10Asm.sol` L177): `digitSum += (d >> ii·3) & 7`. -/
def wotsDigitSumBody : List Stmt :=
  [ .setv "digitSum"
      (.bin .add (.var "digitSum")
        (.bin .band (.bin .shr (.bin .mul (.var "ii") (.lit 3)) (.var "d")) (.lit 0x7))) ]

set_option maxHeartbeats 4000000 in
set_option maxRecDepth 4000 in
/-- **WOTS digit-sum loop refinement.** Running `forRange "ii" 43 wotsDigitSumBody` from a
    VM with `env "d" = wordOf d_bv` and `env "digitSum" = 0` falls through and binds
    `"digitSum" = digitSum (extractDigits d_bv)` (the value the revert gate compares to 205);
    `"d"` persists. Drives the body 43× via `execFor_invariant_lt`; the invariant carries the
    `≤ 7·cur` bound so the `%W` is inert; the per-step digit aligns via `digit_align`. -/
theorem wots_digit_sum
    (sig : ByteVec Spec.SignatureLen) (vm : VM) (d_bv : ByteVec 32)
    (hd : vm.env "d" = wordOf d_bv)
    (hds0 : vm.env "digitSum" = 0) :
    (execFor c10Oracle sig "ii" wotsDigitSumBody 43 0 vm).2 = none
    ∧ (execFor c10Oracle sig "ii" wotsDigitSumBody 43 0 vm).1.env "digitSum"
        = SphincsCVerify.Util.digitSum (SphincsCVerify.Util.extractDigits d_bv)
    ∧ (execFor c10Oracle sig "ii" wotsDigitSumBody 43 0 vm).1.env "d" = wordOf d_bv := by
  let R : Nat → VM → Prop := fun cur w =>
    w.env "digitSum" = partialDigitSum d_bv cur ∧ w.env "d" = wordOf d_bv
  have hstep : ∀ cur w, cur < 43 → R cur w →
      (execList c10Oracle sig wotsDigitSumBody { w with env := setVar w.env "ii" cur }).2 = none ∧
      R (cur + 1) (execList c10Oracle sig wotsDigitSumBody { w with env := setVar w.env "ii" cur }).1 := by
    intro cur w hcur hR
    obtain ⟨hRds, hRd⟩ := hR
    unfold wotsDigitSumBody
    rw [execList_cons_none c10Oracle sig _ _ _ (by simp only [execStmt])]
    rw [execList]
    refine ⟨rfl, ?_, ?_⟩
    · simp only [execStmt, eval, setVar, ite_true, String.reduceEq, ite_false, hRds, hRd]
      -- goal: (partialDigitSum cur + (wordOf d >>> (cur*3 % W)) &&& 7) % W = partialDigitSum (cur+1)
      have hmul3 : cur * 3 % W = cur * 3 :=
        Nat.mod_eq_of_lt (lt_W_of_lt (show cur * 3 < 4096 by omega))
      rw [hmul3, digit_align d_bv cur (by have : Spec.L = 43 := rfl; omega), partialDigitSum_succ]
      have hb : partialDigitSum d_bv cur ≤ 7 * cur := partialDigitSum_le d_bv cur
      have hd8 : SphincsCVerify.Util.readBitsLe d_bv (cur * Spec.LogW) Spec.LogW < 8 := digit_lt_8 d_bv cur
      have hbnd : partialDigitSum d_bv cur + SphincsCVerify.Util.readBitsLe d_bv (cur * Spec.LogW) Spec.LogW < W := by
        have h7 : 7 * cur < 4096 := by omega
        exact lt_W_of_lt (by omega)
      exact Nat.mod_eq_of_lt hbnd
    · simp only [execStmt, eval, setVar, ite_false, String.reduceEq]
      exact hRd
  have hR0 : R 0 vm := ⟨by rw [hds0]; rfl, hd⟩
  have hloop := execFor_invariant_lt c10Oracle sig "ii" wotsDigitSumBody 43 R hstep vm hR0
  obtain ⟨hdsfinal, hdfinal⟩ := hloop.2
  refine ⟨hloop.1, ?_, hdfinal⟩
  rw [hdsfinal]
  exact (digitSum_extractDigits d_bv).symm

/-! ### The inner WOTS chain step loop

One WOTS chain `i` walks `steps = (W-1) - digit = 7 - digit` forward hash steps from
its signature value (`SPHINCsC10Asm.sol` L188–193). The inner `forRange "step" steps`
refines against `chainHash_eq_fwd`'s forward fold (the `fors_climb` analogue): each step
is a 3-segment masked `th` at chain-position `digit + step`, discharged via `leafMem_th`
+ the `chainPosAdrs_word_setChain` ADRS bridge (INTERNAL, no factored hyp). -/

/-- The forward chain accumulator after `c` steps (the `forsAcc` analogue). -/
def wotsChainAcc (seed : ByteVec 32) (a : Spec.Adrs) (startPos : Nat) (val : ByteVec 16)
    (c : Nat) : ByteVec 16 :=
  (List.range' 0 c).foldl (wotsChainFwdStep seed a startPos) val

/-- `wotsChainAcc` at 0 is the initial value. -/
theorem wotsChainAcc_zero (seed : ByteVec 32) (a : Spec.Adrs) (startPos : Nat) (val : ByteVec 16) :
    wotsChainAcc seed a startPos val 0 = val := rfl

/-- `wotsChainAcc` recursion: one more step is one more `wotsChainFwdStep`. -/
theorem wotsChainAcc_succ (seed : ByteVec 32) (a : Spec.Adrs) (startPos : Nat) (val : ByteVec 16)
    (c : Nat) :
    wotsChainAcc seed a startPos val (c + 1)
      = wotsChainFwdStep seed a startPos (wotsChainAcc seed a startPos val c) c := by
  unfold wotsChainAcc
  rw [List.range'_1_concat, List.foldl_append, Nat.zero_add]
  rfl

/-- **Per-step chain-pos ADRS word (spec form).** The interp `or(and(or(wotsAdrs, i<<64),
    CHAINBASE_MASK), pos<<32)` equals `wordOf (setChainPos (setChainIndex (wots …) i) pos)`
    — `chainPosAdrs_word` composed with `setChainIndex_make`/`setChainPos_make` (`wots`'s
    `ci=cp=ha=0` make the OR-substitutions clean). -/
theorem chainPosAdrs_word_setChain (layer : UInt32) (tree : UInt64) (kp : UInt32) (i pos : Nat)
    (hi : i < 2 ^ 32) (hpos : pos < 2 ^ 32) :
    ((wordOf (Spec.Adrs.wots layer tree kp) ||| i <<< 64) &&& CHAINBASE_MASK) ||| pos <<< 32
      = wordOf (Spec.Adrs.setChainPos (Spec.Adrs.setChainIndex (Spec.Adrs.wots layer tree kp)
          (UInt32.ofNat i)) (UInt32.ofNat pos)) := by
  rw [chainPosAdrs_word layer tree kp i pos hi hpos]
  show _ = wordOf (Spec.Adrs.setChainPos (Spec.Adrs.setChainIndex
      (Spec.Adrs.make layer tree (UInt32.ofNat Spec.ADRS_WOTS) kp 0 0 0) (UInt32.ofNat i))
      (UInt32.ofNat pos))
  rw [setChainIndex_make, setChainPos_make]

/-- The inner chain step body (`SPHINCsC10Asm.sol` L189–192). -/
def wotsChainStepBody : List Stmt :=
  [ .mstore (.lit 0x20)
      (.bin .bor (.var "chainBase") (.bin .shl (.lit 32) (.bin .add (.var "digit") (.var "step"))))
  , .mstore (.lit 0x40) (.var "val")
  , .sha256 (.lit 0x00) (.lit 0x60) (.var "OUT")
  , .setv "val" (.bin .band (.mload (.var "OUT")) (.var "N_MASK")) ]

set_option maxHeartbeats 8000000 in
set_option maxRecDepth 4000 in
/-- **One inner chain step.** Running `wotsChainStepBody` once (entered with `step := cur`,
    `cur < 7 - digit`) re-establishes the chain invariant: `val` advances by one
    `wotsChainFwdStep` (the per-step `th` at pos `digit + cur`), the consts and the seed
    window persist. The ADRS word is discharged INTERNALLY by `chainPosAdrs_word_setChain`
    (`pos = digit + cur < 8 < 2^32`); the hash is `leafMem_th`. -/
theorem wots_chain_step
    (sig : ByteVec Spec.SignatureLen)
    (seed : ByteVec 32) (layer : UInt32) (tree : UInt64) (kp : UInt32)
    (i digit : Nat) (val0 : ByteVec 16)
    (hi32 : i < 2 ^ 32) (hdigit : digit < 8)
    (cur : Nat) (hcur : cur < 7 - digit) (w : VM)
    (hR : w.env "val" = wordOf (ByteVec.pad16 (wotsChainAcc seed
            (Spec.Adrs.setChainIndex (Spec.Adrs.wots layer tree kp) (UInt32.ofNat i)) digit val0 cur))
          ∧ w.env "digit" = digit
          ∧ w.env "chainBase" = (wordOf (Spec.Adrs.wots layer tree kp) ||| i <<< 64) &&& CHAINBASE_MASK
          ∧ w.env "N_MASK" = NMASK ∧ w.env "OUT" = 0x600
          ∧ (∀ k, k < 32 → w.mem (0 + k) = seed.data.getD k 0)) :
    (execList c10Oracle sig wotsChainStepBody { w with env := setVar w.env "step" cur }).2 = none
    ∧ ((execList c10Oracle sig wotsChainStepBody { w with env := setVar w.env "step" cur }).1.env "val"
          = wordOf (ByteVec.pad16 (wotsChainAcc seed
              (Spec.Adrs.setChainIndex (Spec.Adrs.wots layer tree kp) (UInt32.ofNat i)) digit val0 (cur + 1)))
        ∧ (execList c10Oracle sig wotsChainStepBody { w with env := setVar w.env "step" cur }).1.env "digit"
            = digit
        ∧ (execList c10Oracle sig wotsChainStepBody { w with env := setVar w.env "step" cur }).1.env "chainBase"
            = (wordOf (Spec.Adrs.wots layer tree kp) ||| i <<< 64) &&& CHAINBASE_MASK
        ∧ (execList c10Oracle sig wotsChainStepBody { w with env := setVar w.env "step" cur }).1.env "N_MASK"
            = NMASK
        ∧ (execList c10Oracle sig wotsChainStepBody { w with env := setVar w.env "step" cur }).1.env "OUT"
            = 0x600
        ∧ (∀ k, k < 32 →
            (execList c10Oracle sig wotsChainStepBody { w with env := setVar w.env "step" cur }).1.mem (0 + k)
              = seed.data.getD k 0)) := by
  obtain ⟨hRval, hRdig, hRcb, hRN, hROUT, hRseed⟩ := hR
  unfold wotsChainStepBody
  rw [execList_cons_none c10Oracle sig _ _ _ (by simp only [execStmt])]
  rw [execList_cons_none c10Oracle sig _ _ _ (by simp only [execStmt])]
  rw [execList_cons_none c10Oracle sig _ _ _ (by simp only [execStmt])]
  rw [execList_cons_none c10Oracle sig _ _ _ (by simp only [execStmt])]
  rw [execList]
  refine ⟨rfl, ?_, ?_, ?_, ?_, ?_, ?_⟩
  · -- val advances by one wotsChainFwdStep.
    simp only [execStmt, eval, setVar, ite_true, ite_false, String.reduceEq, hRN, hROUT, hRcb,
      hRdig, hRval]
    rw [wotsChainAcc_succ]
    -- the per-step ADRS word: or(chainBase, shl 32 ((digit+cur)%W)).  Normalize the shl %W.
    have hpos : digit + cur < 8 := by omega
    have hshl : (digit + cur) <<< 32 % W = (digit + cur) <<< 32 :=
      Nat.mod_eq_of_lt (shl_lt_two_pow_256 (digit + cur) 4 32 (by omega) (by omega))
    -- the interp adds (digit + cur) % W as the shift value; both digit and cur are small.
    have hsum : (digit + cur) % W = digit + cur := Nat.mod_eq_of_lt (lt_W_of_lt (by omega))
    rw [hsum, hshl,
        chainPosAdrs_word_setChain layer tree kp i (digit + cur) hi32 (by omega)]
    -- now leafMem_th over [seed, posAdrs, pad16 (chainAcc cur)]
    rw [leafMem_th w.mem seed
          (Spec.Adrs.setChainPos (Spec.Adrs.setChainIndex (Spec.Adrs.wots layer tree kp)
            (UInt32.ofNat i)) (UInt32.ofNat (digit + cur)))
          (ByteVec.pad16 (wotsChainAcc seed
            (Spec.Adrs.setChainIndex (Spec.Adrs.wots layer tree kp) (UInt32.ofNat i)) digit val0 cur))
          hRseed]
    -- = wordOf (pad16 (wotsChainFwdStep … cur))
    show _ = wordOf (ByteVec.pad16 (wotsChainFwdStep seed
      (Spec.Adrs.setChainIndex (Spec.Adrs.wots layer tree kp) (UInt32.ofNat i)) digit
      (wotsChainAcc seed (Spec.Adrs.setChainIndex (Spec.Adrs.wots layer tree kp) (UInt32.ofNat i)) digit val0 cur)
      cur))
    unfold wotsChainFwdStep
    rfl
  · simp only [execStmt, eval, setVar, ite_false, String.reduceEq]; exact hRdig
  · simp only [execStmt, eval, setVar, ite_false, String.reduceEq]; exact hRcb
  · simp only [execStmt, eval, setVar, ite_false, String.reduceEq]; exact hRN
  · simp only [execStmt, eval, setVar, ite_false, String.reduceEq]; exact hROUT
  · -- seed window persists (writes land at ≥ 0x20).
    intro k hk
    simp only [execStmt, eval, setVar, ite_true, ite_false, String.reduceEq, hRN, hROUT, hRcb, hRdig, hRval]
    rw [writeRegion_frame _ _ _ (0 + k) (by omega), mstore32_frame _ 0x40 _ (0 + k) (by omega),
        mstore32_frame _ 0x20 _ (0 + k) (by omega)]
    exact hRseed k hk

set_option maxHeartbeats 8000000 in
set_option maxRecDepth 4000 in
/-- **The inner WOTS chain loop.** Running `forRange "step" (7 - digit) wotsChainStepBody`
    from the chain-entry VM (`val = wordOf (pad16 val0)`, `digit`, `chainBase`, consts, seed
    in scratch `[0,0x20)`) falls through and binds `"val" = wordOf (pad16 (chainHash seed
    (setChainIndex (wots …) i) val0 digit (7 - digit)))` — the WOTS chain endpoint.
    Drives `wots_chain_step` `(7-digit)×` via `execFor_invariant_lt`; the `fors_climb`
    analogue. The consts/seed persist. -/
theorem wots_chain_loop
    (sig : ByteVec Spec.SignatureLen) (vm : VM)
    (seed : ByteVec 32) (layer : UInt32) (tree : UInt64) (kp : UInt32)
    (i digit : Nat) (val0 : ByteVec 16)
    (hi32 : i < 2 ^ 32) (hdigit : digit < 8)
    (hval : vm.env "val" = wordOf (ByteVec.pad16 val0))
    (hdig : vm.env "digit" = digit)
    (hcb : vm.env "chainBase" = (wordOf (Spec.Adrs.wots layer tree kp) ||| i <<< 64) &&& CHAINBASE_MASK)
    (hN : vm.env "N_MASK" = NMASK) (hOUT : vm.env "OUT" = 0x600)
    (hseed : ∀ k, k < 32 → vm.mem (0 + k) = seed.data.getD k 0) :
    (execFor c10Oracle sig "step" wotsChainStepBody (7 - digit) 0 vm).2 = none
    ∧ (execFor c10Oracle sig "step" wotsChainStepBody (7 - digit) 0 vm).1.env "val"
        = wordOf (ByteVec.pad16 (Spec.chainHash seed
            (Spec.Adrs.setChainIndex (Spec.Adrs.wots layer tree kp) (UInt32.ofNat i)) val0 digit (7 - digit)))
    ∧ (∀ k, k < 32 → (execFor c10Oracle sig "step" wotsChainStepBody (7 - digit) 0 vm).1.mem (0 + k)
        = seed.data.getD k 0) := by
  let A : Spec.Adrs := Spec.Adrs.setChainIndex (Spec.Adrs.wots layer tree kp) (UInt32.ofNat i)
  let R : Nat → VM → Prop := fun c w =>
    w.env "val" = wordOf (ByteVec.pad16 (wotsChainAcc seed A digit val0 c))
    ∧ w.env "digit" = digit
    ∧ w.env "chainBase" = (wordOf (Spec.Adrs.wots layer tree kp) ||| i <<< 64) &&& CHAINBASE_MASK
    ∧ w.env "N_MASK" = NMASK ∧ w.env "OUT" = 0x600
    ∧ (∀ k, k < 32 → w.mem (0 + k) = seed.data.getD k 0)
  have hstep : ∀ cur w, cur < 7 - digit → R cur w →
      (execList c10Oracle sig wotsChainStepBody { w with env := setVar w.env "step" cur }).2 = none ∧
      R (cur + 1) (execList c10Oracle sig wotsChainStepBody { w with env := setVar w.env "step" cur }).1 :=
    fun cur w hcur hRcw =>
      wots_chain_step sig seed layer tree kp i digit val0 hi32 hdigit cur hcur w hRcw
  have hR0 : R 0 vm := by
    refine ⟨?_, hdig, hcb, hN, hOUT, hseed⟩
    rw [hval]; rfl
  have hloop := execFor_invariant_lt c10Oracle sig "step" wotsChainStepBody (7 - digit) R hstep vm hR0
  obtain ⟨hvalf, _, _, _, _, hseedf⟩ := hloop.2
  refine ⟨hloop.1, ?_, hseedf⟩
  rw [hvalf]
  -- wotsChainAcc seed A digit val0 (7-digit) = chainHash seed A val0 digit (7-digit)
  show wordOf (ByteVec.pad16 (wotsChainAcc seed A digit val0 (7 - digit))) = _
  rw [show wotsChainAcc seed A digit val0 (7 - digit)
        = Spec.chainHash seed A val0 digit (7 - digit) from by
    unfold wotsChainAcc
    rw [chainHash_eq_fwd seed A val0 digit (7 - digit)]]

/-! ### The outer WOTS chain loop (per-chain body + the 43-chain drive)

The outer `forRange "i" 43` body (`SPHINCsC10Asm.sol` L182–195): compute `digit`,
`steps = 7-digit`, the chain value `val0 = loadValue16 sig (wotsPtr+16i)`, the `chainBase`,
drive the inner chain loop (`wots_chain_loop`), and store the endpoint at `0x80+32i`.
The `fors_tree_body`/`fors_normal_trees` analogue. -/

/-- `extractDigits d [i]! = readBitsLe d (i·LogW) LogW` for `i < L`. -/
theorem extractDigits_getElem (d_bv : ByteVec 32) (i : Nat) (hi : i < Spec.L) :
    (SphincsCVerify.Util.extractDigits d_bv)[i]!
      = SphincsCVerify.Util.readBitsLe d_bv (i * Spec.LogW) Spec.LogW := by
  unfold SphincsCVerify.Util.extractDigits
  rw [getElem!_pos (Array.ofFn (n := Spec.L) fun j =>
        SphincsCVerify.Util.readBitsLe d_bv (j.val * Spec.LogW) Spec.LogW) i (by simp [hi])]
  simp

/-- The WOTS chain endpoint for chain `i` (interp digit form): `chainHash` from the chain
    value `loadValue16 sig (688 + 16i)` (the layer's WOTS chains start at `sigOff`; here we
    bind to the concrete per-layer offset at the call site) — kept abstract via `wotsPtr`. -/
def wotsChainEndpoint (seed : ByteVec 32) (layer : UInt32) (tree : UInt64) (kp : UInt32)
    (d_bv : ByteVec 32) (sig : ByteVec Spec.SignatureLen) (wotsPtr i : Nat) : ByteVec 16 :=
  let digit := (SphincsCVerify.Util.extractDigits d_bv)[i]!
  Spec.chainHash seed (Spec.Adrs.setChainIndex (Spec.Adrs.wots layer tree kp) (UInt32.ofNat i))
    (ByteVec.loadValue16 sig (wotsPtr + 16 * i)) digit (7 - digit)

/-- The outer chain body (`SPHINCsC10Asm.sol` L182–195), with loop var `i`. -/
def wotsChainBody : List Stmt :=
  [ .letv "digit" (.bin .band (.bin .shr (.bin .mul (.var "i") (.lit 3)) (.var "d")) (.lit 0x7))
  , .letv "steps" (.bin .sub (.lit 7) (.var "digit"))
  , .letv "val" (.bin .band (.calldataload (.bin .add (.var "wotsPtr") (.bin .shl (.lit 4) (.var "i")))) (.var "N_MASK"))
  , .letv "chainBase" (.bin .band (.bin .bor (.var "wotsAdrs") (.bin .shl (.lit 64) (.var "i"))) (.lit CHAINBASE_MASK))
  , .forRange "step" (.var "steps") wotsChainStepBody
  , .mstore (.bin .add (.lit 0x80) (.bin .shl (.lit 5) (.var "i"))) (.var "val") ]


/-- One inner chain step preserves any variable it never binds (`x ∉ {step, val}`). The
    `wotsChainStepBody` binds only `step` (loop var) and `val` (`setv`); `chainBase/digit/
    N_MASK/OUT/i` survive. -/
private theorem execList_wotsChainStepBody_preserves_var (sig : ByteVec Spec.SignatureLen)
    (cur : Nat) (v : VM) (x : String) (hx : x ≠ "step" ∧ x ≠ "val") :
    (execList c10Oracle sig wotsChainStepBody { v with env := setVar v.env "step" cur }).1.env x
        = v.env x := by
  obtain ⟨h1, h2⟩ := hx
  unfold wotsChainStepBody
  rw [execList_cons_none c10Oracle sig _ _ _ (by simp only [execStmt])]
  rw [execList_cons_none c10Oracle sig _ _ _ (by simp only [execStmt])]
  rw [execList_cons_none c10Oracle sig _ _ _ (by simp only [execStmt])]
  rw [execList_cons_none c10Oracle sig _ _ _ (by simp only [execStmt])]
  rw [execList]
  simp only [execStmt, eval, setVar, h1, h2, ite_false]

/-- One inner chain step falls through (no `revert`/`return` in `wotsChainStepBody`). -/
private theorem execList_wotsChainStepBody_none (sig : ByteVec Spec.SignatureLen)
    (cur : Nat) (v : VM) :
    (execList c10Oracle sig wotsChainStepBody { v with env := setVar v.env "step" cur }).2 = none := by
  unfold wotsChainStepBody
  rw [execList_cons_none c10Oracle sig _ _ _ (by simp only [execStmt])]
  rw [execList_cons_none c10Oracle sig _ _ _ (by simp only [execStmt])]
  rw [execList_cons_none c10Oracle sig _ _ _ (by simp only [execStmt])]
  rw [execList_cons_none c10Oracle sig _ _ _ (by simp only [execStmt])]
  rw [execList]

/-- The whole inner chain loop preserves any `x ∉ {step, val}`. -/
private theorem execFor_wotsChainStepBody_preserves_var (sig : ByteVec Spec.SignatureLen)
    (x : String) (hx : x ≠ "step" ∧ x ≠ "val") :
    ∀ (remaining cur : Nat) (v : VM),
      (execFor c10Oracle sig "step" wotsChainStepBody remaining cur v).1.env x = v.env x := by
  intro remaining
  induction remaining with
  | zero => intro cur v; simp only [execFor]
  | succ rem ih =>
      intro cur v
      have hnone := execList_wotsChainStepBody_none sig cur v
      rw [execFor]
      rcases hp : execList c10Oracle sig wotsChainStepBody { v with env := setVar v.env "step" cur }
        with ⟨pvm, po⟩
      rw [hp] at hnone
      subst hnone
      simp only []
      rw [ih (cur + 1) pvm]
      have := execList_wotsChainStepBody_preserves_var sig cur v x hx
      rw [hp] at this
      exact this

set_option maxHeartbeats 8000000 in
set_option maxRecDepth 4000 in
/-- **Per-chain WOTS body refinement.** Running `wotsChainBody` for chain `c < 43` from a VM
    whose env supplies `d = wordOf d_bv`, `wotsPtr`, `wotsAdrs = wordOf (wots layer tree kp)`,
    `N_MASK`, `OUT = 0x600`, loop var `i = c`, with `seed` in scratch `[0,0x20)`, falls
    through and stores `wordOf (pad16 (wotsChainEndpoint … c))` at `0x80 + 32*c`; seed window
    and consts persist. Discharges the inner chain loop (`wots_chain_loop`) and the
    digit/chain-value reads internally. -/
theorem wots_chain_body
    (sig : ByteVec Spec.SignatureLen) (vm : VM)
    (seed : ByteVec 32) (layer : UInt32) (tree : UInt64) (kp : UInt32)
    (d_bv : ByteVec 32) (wotsPtr c : Nat) (hc : c < 43) (hwp : wotsPtr < 4096)
    (hd : vm.env "d" = wordOf d_bv)
    (hwptr : vm.env "wotsPtr" = wotsPtr)
    (hwa : vm.env "wotsAdrs" = wordOf (Spec.Adrs.wots layer tree kp))
    (hN : vm.env "N_MASK" = NMASK)
    (hOUT : vm.env "OUT" = 0x600)
    (hival : vm.env "i" = c)
    (hseedmem : ∀ k, k < 32 → vm.mem (0 + k) = seed.data.getD k 0) :
    (execList c10Oracle sig wotsChainBody vm).2 = none
    ∧ (∀ k, k < 32 →
        (execList c10Oracle sig wotsChainBody vm).1.mem (0x80 + 32 * c + k)
          = (ByteVec.pad16 (wotsChainEndpoint seed layer tree kp d_bv sig wotsPtr c)).data.getD k 0)
    ∧ (∀ k, k < 32 → (execList c10Oracle sig wotsChainBody vm).1.mem (0 + k) = seed.data.getD k 0) := by
  unfold wotsChainBody
  rw [execList_cons_none c10Oracle sig _ _ _ (by simp only [execStmt])]
  rw [execList_cons_none c10Oracle sig _ _ _ (by simp only [execStmt])]
  rw [execList_cons_none c10Oracle sig _ _ _ (by simp only [execStmt])]
  rw [execList_cons_none c10Oracle sig _ _ _ (by simp only [execStmt])]
  simp only [execStmt, eval, setVar, hd, hwptr, hwa, hN, hOUT, hival, ite_true, ite_false, String.reduceEq]
  -- Normalise the small `% W` arithmetic.
  have hmul3 : c * 3 % W = c * 3 := Nat.mod_eq_of_lt (lt_W_of_lt (by omega))
  have hshl4 : c <<< 4 % W = 16 * c := shl4_small c (by omega)
  have hshl64 : c <<< 64 % W = c <<< 64 :=
    Nat.mod_eq_of_lt (shl_lt_two_pow_256 c 32 64 (by have : c < 43 := hc; omega) (by omega))
  have hvalW : wotsPtr + 16 * c < W := by
    unfold W; have : wotsPtr + 16 * c < 4784 := by omega
    exact Nat.lt_trans this (by decide)
  have hvalOff : (wotsPtr + c <<< 4 % W) % W = wotsPtr + 16 * c := by
    rw [hshl4, Nat.mod_eq_of_lt hvalW]
  rw [hmul3, hshl64, hvalOff]
  -- digit = (wordOf d_bv >>> (c*3)) & 7 = extractDigits[c]!
  have hdigit : (wordOf d_bv >>> (c * 3)) &&& 0x7 = (SphincsCVerify.Util.extractDigits d_bv)[c]! := by
    rw [digit_align d_bv c (by have : Spec.L = 43 := rfl; omega), extractDigits_getElem d_bv c (by have : Spec.L = 43 := rfl; omega)]
  -- chain value: calldataload (wotsPtr + 16c) & N_MASK = wordOf (pad16 (loadValue16 sig (wotsPtr+16c)))
  rw [cl_masked_eq_wordOf sig (wotsPtr + 16 * c), hdigit]
  -- Abbreviate the chain-entry VM `w`.
  obtain ⟨w, hweq⟩ : ∃ w : VM, w =
      { mem := vm.mem,
        env := setVar (setVar (setVar (setVar vm.env
          "digit" ((SphincsCVerify.Util.extractDigits d_bv)[c]!))
          "steps" ((7 + (W - ((SphincsCVerify.Util.extractDigits d_bv)[c]!) % W)) % W))
          "val" (wordOf (ByteVec.pad16 (ByteVec.loadValue16 sig (wotsPtr + 16 * c)))))
          "chainBase" ((wordOf (Spec.Adrs.wots layer tree kp) ||| c <<< 64) &&& CHAINBASE_MASK) } := ⟨_, rfl⟩
  rw [← hweq]
  -- digit < 8
  have hdig8 : (SphincsCVerify.Util.extractDigits d_bv)[c]! < 8 := by
    have := SphincsCVerify.Util.extractDigits_lt d_bv ⟨c, by have : Spec.L = 43 := rfl; omega⟩
    have hW : Spec.W = 8 := rfl
    rw [hW] at this; exact this
  -- steps = 7 - digit (EVM sub inert since digit ≤ 7)
  have hsteps : (7 + (W - ((SphincsCVerify.Util.extractDigits d_bv)[c]!) % W)) % W
      = 7 - (SphincsCVerify.Util.extractDigits d_bv)[c]! := by
    have hdmod : ((SphincsCVerify.Util.extractDigits d_bv)[c]!) % W
        = (SphincsCVerify.Util.extractDigits d_bv)[c]! := Nat.mod_eq_of_lt (lt_W_of_lt (by omega))
    have hWbig : (8 : Nat) ≤ W := by unfold W; exact Nat.le_of_lt (by decide)
    rw [hdmod, show 7 + (W - (SphincsCVerify.Util.extractDigits d_bv)[c]!)
          = W + (7 - (SphincsCVerify.Util.extractDigits d_bv)[c]!) by omega,
        Nat.add_mod_left, Nat.mod_eq_of_lt (lt_W_of_lt (by omega))]
  -- env facts about w
  have hwval : w.env "val" = wordOf (ByteVec.pad16 (ByteVec.loadValue16 sig (wotsPtr + 16 * c))) := by
    rw [hweq]; simp [setVar]
  have hwdig : w.env "digit" = (SphincsCVerify.Util.extractDigits d_bv)[c]! := by rw [hweq]; simp [setVar]
  have hwcb : w.env "chainBase"
      = (wordOf (Spec.Adrs.wots layer tree kp) ||| c <<< 64) &&& CHAINBASE_MASK := by
    rw [hweq]; simp [setVar]
  have hwN : w.env "N_MASK" = NMASK := by rw [hweq, hN.symm]; simp [setVar]
  have hwOUT : w.env "OUT" = 0x600 := by rw [hweq, hOUT.symm]; simp [setVar]
  have hwsteps : w.env "steps" = 7 - (SphincsCVerify.Util.extractDigits d_bv)[c]! := by
    rw [hweq]; show _ = _; simp only [setVar, String.reduceEq, ite_false, ite_true]; exact hsteps
  have hwmem : w.mem = vm.mem := by rw [hweq]
  have hwseed : ∀ k, k < 32 → w.mem (0 + k) = seed.data.getD k 0 := by
    intro k hk; rw [hwmem]; exact hseedmem k hk
  have hwi : w.env "i" = c := by rw [hweq]; simp [setVar]; exact hival
  -- The inner forRange "step" steps statement = execFor … (7-digit) 0 w (steps eval = 7-digit).
  have hforStmt : execStmt c10Oracle sig (.forRange "step" (.var "steps") wotsChainStepBody) w
      = execFor c10Oracle sig "step" wotsChainStepBody (7 - (SphincsCVerify.Util.extractDigits d_bv)[c]!) 0 w := by
    simp only [execStmt, eval, hwsteps]
  obtain ⟨hloopNone, hloopVal, hloopSeed⟩ :=
    wots_chain_loop sig w seed layer tree kp c ((SphincsCVerify.Util.extractDigits d_bv)[c]!)
      (ByteVec.loadValue16 sig (wotsPtr + 16 * c)) (by have : c < 43 := hc; omega) hdig8
      hwval hwdig hwcb hwN hwOUT hwseed
  -- step the forRange
  rw [execList_cons_none c10Oracle sig _ _ _ (by rw [hforStmt]; exact hloopNone), hforStmt]
  -- step the final mstore (0x80 + 32c) val
  rw [execList_cons_none c10Oracle sig _ _ _ (by simp only [execStmt]), execList]
  -- the climb preserves "i" = c (chain loop never binds "i").
  have hloopI : (execFor c10Oracle sig "step" wotsChainStepBody (7 - (SphincsCVerify.Util.extractDigits d_bv)[c]!) 0 w).1.env "i" = c := by
    rw [execFor_wotsChainStepBody_preserves_var sig "i" (by decide) _ 0 w, hwi]
  simp only [execStmt, eval, hloopI, hloopVal]
  -- store offset (0x80 + c<<<5 % W) % W = 128 + 32c
  have hstoreOff : (128 + c <<< 5 % W) % W = 128 + 32 * c := by
    rw [Nat.shiftLeft_eq, show (2:Nat)^5 = 32 from rfl, Nat.mul_comm c 32,
        Nat.mod_eq_of_lt (lt_W_of_lt (show 32 * c < 4096 by omega)),
        Nat.mod_eq_of_lt (lt_W_of_lt (show 128 + 32 * c < 4096 by omega))]
  rw [hstoreOff]
  refine ⟨trivial, ?_, ?_⟩
  · -- mem at 128+32c+k = (pad16 endpoint)'s k-th byte
    intro k hk
    rw [show (128 + 32 * c + k) = ((128 + 32 * c) + k) by omega, mstore32_get _ (128 + 32 * c) _ k hk,
        beByte_wordOf_getD _ k hk]
    show _ = (ByteVec.pad16 (wotsChainEndpoint seed layer tree kp d_bv sig wotsPtr c)).data.getD k 0
    unfold wotsChainEndpoint
    rfl
  · -- seed window persists (store at ≥ 128)
    intro k hk
    rw [mstore32_frame _ (128 + 32 * c) _ (0 + k) (by omega)]
    exact hloopSeed k hk

/-! ### The 43-chain outer loop drive

Drives `wots_chain_body` 43× via `execFor_invariant_lt` (the `fors_normal_trees`
analogue). The body's only writes are `{0x20, 0x40, OUT=0x600}` (chain hash scratch) and
`0x80+32i` (the endpoint), so already-laid endpoints `[0x80, 0x80+32·cur)` and the seed
window persist. Lays `pad16 (wotsChainEndpoint … t)` at `0x80+32t` for every `t < 43`. -/

private theorem execFor_wotsChainStepBody_none' (sig : ByteVec Spec.SignatureLen) :
    ∀ (remaining cur : Nat) (v : VM),
      (execFor c10Oracle sig "step" wotsChainStepBody remaining cur v).2 = none := by
  intro remaining
  induction remaining with
  | zero => intro cur v; simp only [execFor]
  | succ rem ih =>
      intro cur v
      have hnone := execList_wotsChainStepBody_none sig cur v
      rw [execFor]
      rcases hp : execList c10Oracle sig wotsChainStepBody { v with env := setVar v.env "step" cur }
        with ⟨pvm, po⟩
      rw [hp] at hnone; subst hnone; simp only []; exact ih (cur + 1) pvm

/-- `wotsChainBody` preserves any const var `x ∉ {digit, steps, val, chainBase, step, i}`. -/
private theorem execList_wotsChainBody_preserves_const (sig : ByteVec Spec.SignatureLen)
    (cur : Nat) (v : VM) (x : String)
    (hx : x ≠ "digit" ∧ x ≠ "steps" ∧ x ≠ "val" ∧ x ≠ "chainBase" ∧ x ≠ "step" ∧ x ≠ "i") :
    (execList c10Oracle sig wotsChainBody { v with env := setVar v.env "i" cur }).1.env x = v.env x := by
  obtain ⟨h1, h2, h3, h4, h5, h6⟩ := hx
  unfold wotsChainBody
  rw [execList_cons_none c10Oracle sig _ _ _ (by simp only [execStmt])]
  rw [execList_cons_none c10Oracle sig _ _ _ (by simp only [execStmt])]
  rw [execList_cons_none c10Oracle sig _ _ _ (by simp only [execStmt])]
  rw [execList_cons_none c10Oracle sig _ _ _ (by simp only [execStmt])]
  -- abbreviate the post-4-letv VM w'
  obtain ⟨w', hw'⟩ : ∃ w', w' = (execStmt c10Oracle sig (Stmt.letv "chainBase"
        (.bin .band (.bin .bor (.var "wotsAdrs") (.bin .shl (.lit 64) (.var "i"))) (.lit CHAINBASE_MASK)))
      (execStmt c10Oracle sig (Stmt.letv "val"
        (.bin .band (.calldataload (.bin .add (.var "wotsPtr") (.bin .shl (.lit 4) (.var "i")))) (.var "N_MASK")))
      (execStmt c10Oracle sig (Stmt.letv "steps" (.bin .sub (.lit 7) (.var "digit")))
      (execStmt c10Oracle sig (Stmt.letv "digit"
        (.bin .band (.bin .shr (.bin .mul (.var "i") (.lit 3)) (.var "d")) (.lit 0x7)))
        { v with env := setVar v.env "i" cur }).1).1).1).1 := ⟨_, rfl⟩
  rw [← hw']
  have hforNone : (execStmt c10Oracle sig (.forRange "step" (.var "steps") wotsChainStepBody) w').2 = none := by
    simp only [execStmt, eval]
    exact execFor_wotsChainStepBody_none' sig _ 0 w'
  have hforStmt : execStmt c10Oracle sig (.forRange "step" (.var "steps") wotsChainStepBody) w'
      = execFor c10Oracle sig "step" wotsChainStepBody (w'.env "steps") 0 w' := by
    simp only [execStmt, eval]
  rw [execList_cons_none c10Oracle sig _ _ _ hforNone, hforStmt]
  rw [execList_cons_none c10Oracle sig _ _ _ (by simp only [execStmt]), execList]
  simp only [execStmt, eval]
  rw [execFor_wotsChainStepBody_preserves_var sig x ⟨h5, h3⟩ (w'.env "steps") 0 w']
  rw [hw']
  simp only [execStmt, eval, setVar, h1, h2, h3, h4, h6, ite_false]

/-- One inner chain step preserves any memory address `a ∉ [0x20, 0x600)`-conflicting (it writes
    only `0x20`/`0x40`/`OUT=0x600`); for `0x80 ≤ a < 0x600` the address survives. -/
private theorem execList_wotsChainStepBody_mem_frame (sig : ByteVec Spec.SignatureLen)
    (cur : Nat) (v : VM) (hOUT : v.env "OUT" = 0x600) (a : Nat) (ha : 0x80 ≤ a ∧ a < 0x600) :
    (execList c10Oracle sig wotsChainStepBody { v with env := setVar v.env "step" cur }).1.mem a = v.mem a := by
  obtain ⟨ha1, ha2⟩ := ha
  unfold wotsChainStepBody
  rw [execList_cons_none c10Oracle sig _ _ _ (by simp only [execStmt])]
  rw [execList_cons_none c10Oracle sig _ _ _ (by simp only [execStmt])]
  rw [execList_cons_none c10Oracle sig _ _ _ (by simp only [execStmt])]
  rw [execList_cons_none c10Oracle sig _ _ _ (by simp only [execStmt])]
  rw [execList]
  simp only [execStmt, eval, setVar, String.reduceEq, ite_true, ite_false, hOUT]
  rw [writeRegion_frame _ 0x600 _ a (by omega), mstore32_frame _ 0x40 _ a (by omega),
      mstore32_frame _ 0x20 _ a (by omega)]

private theorem execFor_wotsChainStepBody_mem_frame (sig : ByteVec Spec.SignatureLen)
    (a : Nat) (ha : 0x80 ≤ a ∧ a < 0x600) :
    ∀ (remaining cur : Nat) (v : VM), v.env "OUT" = 0x600 →
      (execFor c10Oracle sig "step" wotsChainStepBody remaining cur v).1.mem a = v.mem a := by
  intro remaining
  induction remaining with
  | zero => intro cur v _; simp only [execFor]
  | succ rem ih =>
      intro cur v hOUT
      have hnone := execList_wotsChainStepBody_none sig cur v
      rw [execFor]
      rcases hp : execList c10Oracle sig wotsChainStepBody { v with env := setVar v.env "step" cur }
        with ⟨pvm, po⟩
      rw [hp] at hnone; subst hnone; simp only []
      have hpOUT : pvm.env "OUT" = 0x600 := by
        have := execList_wotsChainStepBody_preserves_var sig cur v "OUT" ⟨by decide, by decide⟩
        rw [hp] at this; rw [this]; exact hOUT
      rw [ih (cur + 1) pvm hpOUT]
      have := execList_wotsChainStepBody_mem_frame sig cur v hOUT a ha
      rw [hp] at this; exact this

set_option maxHeartbeats 8000000 in
set_option maxRecDepth 4000 in
/-- `wotsChainBody` (entered with `i := cur`, `cur < 43`) preserves any laid-endpoint
    address `a` with `0x80 ≤ a < 0x80 + 32·cur` (disjoint from `{0x20,0x40,OUT}` and this
    chain's store `[0x80+32·cur, +32)`). -/
private theorem execList_wotsChainBody_mem_frame (sig : ByteVec Spec.SignatureLen)
    (cur : Nat) (v : VM) (hOUT : v.env "OUT" = 0x600)
    (hcur : cur < 43) (a : Nat) (ha : 0x80 ≤ a ∧ a < 0x80 + 32 * cur) :
    (execList c10Oracle sig wotsChainBody { v with env := setVar v.env "i" cur }).1.mem a = v.mem a := by
  obtain ⟨ha1, ha2⟩ := ha
  unfold wotsChainBody
  rw [execList_cons_none c10Oracle sig _ _ _ (by simp only [execStmt])]
  rw [execList_cons_none c10Oracle sig _ _ _ (by simp only [execStmt])]
  rw [execList_cons_none c10Oracle sig _ _ _ (by simp only [execStmt])]
  rw [execList_cons_none c10Oracle sig _ _ _ (by simp only [execStmt])]
  obtain ⟨w', hw'⟩ : ∃ w', w' = (execStmt c10Oracle sig (Stmt.letv "chainBase"
        (.bin .band (.bin .bor (.var "wotsAdrs") (.bin .shl (.lit 64) (.var "i"))) (.lit CHAINBASE_MASK)))
      (execStmt c10Oracle sig (Stmt.letv "val"
        (.bin .band (.calldataload (.bin .add (.var "wotsPtr") (.bin .shl (.lit 4) (.var "i")))) (.var "N_MASK")))
      (execStmt c10Oracle sig (Stmt.letv "steps" (.bin .sub (.lit 7) (.var "digit")))
      (execStmt c10Oracle sig (Stmt.letv "digit"
        (.bin .band (.bin .shr (.bin .mul (.var "i") (.lit 3)) (.var "d")) (.lit 0x7)))
        { v with env := setVar v.env "i" cur }).1).1).1).1 := ⟨_, rfl⟩
  rw [← hw']
  have hforNone : (execStmt c10Oracle sig (.forRange "step" (.var "steps") wotsChainStepBody) w').2 = none := by
    simp only [execStmt, eval]; exact execFor_wotsChainStepBody_none' sig _ 0 w'
  have hforStmt : execStmt c10Oracle sig (.forRange "step" (.var "steps") wotsChainStepBody) w'
      = execFor c10Oracle sig "step" wotsChainStepBody (w'.env "steps") 0 w' := by simp only [execStmt, eval]
  rw [execList_cons_none c10Oracle sig _ _ _ hforNone, hforStmt]
  rw [execList_cons_none c10Oracle sig _ _ _ (by simp only [execStmt]), execList]
  simp only [execStmt, eval]
  -- the climb-final "i" = cur (the chain loop never binds "i")
  have hw'i : w'.env "i" = cur := by rw [hw']; simp only [execStmt, eval, setVar, String.reduceEq, ite_true, ite_false]
  rw [execFor_wotsChainStepBody_preserves_var sig "i" ⟨by decide, by decide⟩ (w'.env "steps") 0 w', hw'i]
  have hstoreOff : (128 + cur <<< 5 % W) % W = 128 + 32 * cur := by
    rw [Nat.shiftLeft_eq, show (2:Nat)^5 = 32 from rfl, Nat.mul_comm cur 32,
        Nat.mod_eq_of_lt (lt_W_of_lt (show 32 * cur < 4096 by omega)),
        Nat.mod_eq_of_lt (lt_W_of_lt (show 128 + 32 * cur < 4096 by omega))]
  rw [hstoreOff, mstore32_frame _ (128 + 32 * cur) _ a (by omega)]
  -- OUT = 0x600 survives the 4 letvs
  have hw'OUT : w'.env "OUT" = 0x600 := by
    rw [hw']; simp only [execStmt, eval, setVar, String.reduceEq, ite_true, ite_false]; exact hOUT
  rw [execFor_wotsChainStepBody_mem_frame sig a (by omega) (w'.env "steps") 0 w' hw'OUT]
  rw [hw']
  simp only [execStmt, eval, setVar]

set_option maxHeartbeats 8000000 in
set_option maxRecDepth 4000 in
/-- **The 43-chain outer loop.** Running `forRange "i" 43 wotsChainBody` from a VM whose env
    supplies `d = wordOf d_bv`, `wotsPtr`, `wotsAdrs = wordOf (wots layer tree kp)`, `N_MASK`,
    `OUT = 0x600`, with `seed` in scratch `[0,0x20)`, falls through and lays
    `pad16 (wotsChainEndpoint … t)` at `0x80 + 32*t` for every `t < 43`; the seed window and
    the loop consts persist. Drives `wots_chain_body` 43× via `execFor_invariant_lt`. -/
theorem wots_chain_outer_loop
    (sig : ByteVec Spec.SignatureLen) (vm : VM)
    (seed : ByteVec 32) (layer : UInt32) (tree : UInt64) (kp : UInt32)
    (d_bv : ByteVec 32) (wotsPtr : Nat) (hwp : wotsPtr < 4096)
    (hd : vm.env "d" = wordOf d_bv)
    (hwptr : vm.env "wotsPtr" = wotsPtr)
    (hwa : vm.env "wotsAdrs" = wordOf (Spec.Adrs.wots layer tree kp))
    (hN : vm.env "N_MASK" = NMASK)
    (hOUT : vm.env "OUT" = 0x600)
    (hseedmem : ∀ k, k < 32 → vm.mem (0 + k) = seed.data.getD k 0) :
    (execFor c10Oracle sig "i" wotsChainBody 43 0 vm).2 = none
    ∧ (∀ t, t < 43 → ∀ k, k < 32 →
        (execFor c10Oracle sig "i" wotsChainBody 43 0 vm).1.mem (0x80 + 32 * t + k)
          = (ByteVec.pad16 (wotsChainEndpoint seed layer tree kp d_bv sig wotsPtr t)).data.getD k 0)
    ∧ (∀ k, k < 32 → (execFor c10Oracle sig "i" wotsChainBody 43 0 vm).1.mem (0 + k) = seed.data.getD k 0)
    ∧ (execFor c10Oracle sig "i" wotsChainBody 43 0 vm).1.env "N_MASK" = NMASK
    ∧ (execFor c10Oracle sig "i" wotsChainBody 43 0 vm).1.env "OUT" = 0x600 := by
  let R : Nat → VM → Prop := fun cur w =>
    (∀ t, t < cur → ∀ k, k < 32 → w.mem (0x80 + 32 * t + k)
        = (ByteVec.pad16 (wotsChainEndpoint seed layer tree kp d_bv sig wotsPtr t)).data.getD k 0)
    ∧ (∀ k, k < 32 → w.mem (0 + k) = seed.data.getD k 0)
    ∧ w.env "d" = wordOf d_bv ∧ w.env "wotsPtr" = wotsPtr
    ∧ w.env "wotsAdrs" = wordOf (Spec.Adrs.wots layer tree kp)
    ∧ w.env "N_MASK" = NMASK ∧ w.env "OUT" = 0x600
  have hstep : ∀ cur w, cur < 43 → R cur w →
      (execList c10Oracle sig wotsChainBody { w with env := setVar w.env "i" cur }).2 = none ∧
      R (cur + 1) (execList c10Oracle sig wotsChainBody { w with env := setVar w.env "i" cur }).1 := by
    intro cur w hcur hR
    obtain ⟨hRmem, hRseed, hRd, hRwp, hRwa, hRN, hROUT⟩ := hR
    obtain ⟨wi, hwi⟩ : ∃ wi, ({ w with env := setVar w.env "i" cur } : VM) = wi := ⟨_, rfl⟩
    rw [hwi]
    have hwienv : wi.env = setVar w.env "i" cur := by rw [← hwi]
    have hwimem : wi.mem = w.mem := by rw [← hwi]
    have hwid : wi.env "d" = wordOf d_bv := by rw [hwienv, setVar_get_ne _ _ _ _ (by decide)]; exact hRd
    have hwiwp : wi.env "wotsPtr" = wotsPtr := by rw [hwienv, setVar_get_ne _ _ _ _ (by decide)]; exact hRwp
    have hwiwa : wi.env "wotsAdrs" = wordOf (Spec.Adrs.wots layer tree kp) := by
      rw [hwienv, setVar_get_ne _ _ _ _ (by decide)]; exact hRwa
    have hwiN : wi.env "N_MASK" = NMASK := by rw [hwienv, setVar_get_ne _ _ _ _ (by decide)]; exact hRN
    have hwiOUT : wi.env "OUT" = 0x600 := by rw [hwienv, setVar_get_ne _ _ _ _ (by decide)]; exact hROUT
    have hwii : wi.env "i" = cur := by rw [hwienv, setVar_get_eq]
    have hwiseedmem : ∀ k, k < 32 → wi.mem (0 + k) = seed.data.getD k 0 := by
      intro k hk; rw [hwimem]; exact hRseed k hk
    have hbody := wots_chain_body sig wi seed layer tree kp d_bv wotsPtr cur hcur hwp
      hwid hwiwp hwiwa hwiN hwiOUT hwii hwiseedmem
    obtain ⟨hbodyNone, hbodyMem, hbodySeed⟩ := hbody
    refine ⟨hbodyNone, ?_, ?_, ?_, ?_, ?_, ?_, ?_⟩
    · intro t ht k hk
      by_cases htc : t = cur
      · subst htc; rw [hbodyMem k hk]
      · have htlt : t < cur := by omega
        rw [← hwi, execList_wotsChainBody_mem_frame sig cur w hROUT hcur (0x80 + 32 * t + k) ⟨by omega, by omega⟩]
        exact hRmem t htlt k hk
    · intro k hk; exact hbodySeed k hk
    · rw [← hwi, execList_wotsChainBody_preserves_const sig cur w "d"
            ⟨by decide, by decide, by decide, by decide, by decide, by decide⟩]; exact hRd
    · rw [← hwi, execList_wotsChainBody_preserves_const sig cur w "wotsPtr"
            ⟨by decide, by decide, by decide, by decide, by decide, by decide⟩]; exact hRwp
    · rw [← hwi, execList_wotsChainBody_preserves_const sig cur w "wotsAdrs"
            ⟨by decide, by decide, by decide, by decide, by decide, by decide⟩]; exact hRwa
    · rw [← hwi, execList_wotsChainBody_preserves_const sig cur w "N_MASK"
            ⟨by decide, by decide, by decide, by decide, by decide, by decide⟩]; exact hRN
    · rw [← hwi, execList_wotsChainBody_preserves_const sig cur w "OUT"
            ⟨by decide, by decide, by decide, by decide, by decide, by decide⟩]; exact hROUT
  have hR0 : R 0 vm := ⟨fun t ht => absurd ht (Nat.not_lt_zero t), hseedmem, hd, hwptr, hwa, hN, hOUT⟩
  have hloop := execFor_invariant_lt c10Oracle sig "i" wotsChainBody 43 R hstep vm hR0
  obtain ⟨hmem, hseedf, _, _, _, hNf, hOUTf⟩ := hloop.2
  exact ⟨hloop.1, hmem, hseedf, hNf, hOUTf⟩

/-! ### WOTS PK compression

The 43-endpoint compression (`SPHINCsC10Asm.sol` L197–205): store the `wotsPk` ADRS at
`0x20`, copy the 43 chain endpoints from `[0x80+32i,…)` to `[0x40+32i,…)`, hash the
45-segment `[seed, wotsPk-adrs, endpoint0..42]` window (`sha256 0x00 0x5A0`), and mask the
digest into `wotsPk`. The `fors_root_compress` analogue (`forsCopyBody` reused verbatim). -/

/-- **WOTS-PK ADRS word.** `wotsPk = make layer tree ADRS_WOTS_PK kp 0 0 0`; the
    `ci=cp=ha=0` shifts vanish (Yul `or(shl(224,layer), or(shl(160,tree), or(shl(128,1),
    shl(96,kp))))`). The `wordOf_wots` mirror with `ADRS_WOTS_PK`. -/
theorem wordOf_wotsPk (layer : UInt32) (tree : UInt64) (kp : UInt32) :
    wordOf (Spec.Adrs.wotsPk layer tree kp)
      = layer.toNat <<< 224 ||| tree.toNat <<< 160 ||| (UInt32.ofNat Spec.ADRS_WOTS_PK).toNat <<< 128
        ||| kp.toNat <<< 96 := by
  unfold Spec.Adrs.wotsPk
  rw [wordOf_make]
  show _ ||| _ ||| _ ||| _ ||| (0 : UInt32).toNat <<< 64 ||| (0 : UInt32).toNat <<< 32
        ||| (0 : UInt32).toNat = _
  rw [show (0 : UInt32).toNat = 0 from rfl, Nat.zero_shiftLeft, Nat.or_zero, Nat.zero_shiftLeft,
      Nat.or_zero, Nat.or_zero]

/-- The WOTS PK-adrs Yul word `or(shl(224,layer), or(shl(160,idxTree), or(shl(128,1), shl(96,idxLeaf))))`,
    masks inert (for `layer < 2^32`, `tree < 2^64`, `kp < 2^32`). -/
private theorem wotsPk_word (layer : UInt32) (tree : UInt64) (kp : UInt32) :
    ((layer.toNat <<< 224 % W) ||| ((tree.toNat <<< 160 % W) ||| ((1 <<< 128 % W) ||| (kp.toNat <<< 96 % W))))
      = wordOf (Spec.Adrs.wotsPk layer tree kp) := by
  rw [wordOf_wotsPk]
  have hPk : (UInt32.ofNat Spec.ADRS_WOTS_PK).toNat = 1 := by decide
  rw [hPk]
  have hW0 : layer.toNat <<< 224 % W = layer.toNat <<< 224 :=
    Nat.mod_eq_of_lt (shl_lt_two_pow_256 _ 32 224 layer.toNat_lt (by omega))
  have hW1 : tree.toNat <<< 160 % W = tree.toNat <<< 160 :=
    Nat.mod_eq_of_lt (shl_lt_two_pow_256 _ 64 160 tree.toNat_lt (by omega))
  have hW2 : (1 : Nat) <<< 128 % W = 1 <<< 128 :=
    Nat.mod_eq_of_lt (shl_lt_two_pow_256 _ 1 128 (by decide) (by omega))
  have hW3 : kp.toNat <<< 96 % W = kp.toNat <<< 96 :=
    Nat.mod_eq_of_lt (shl_lt_two_pow_256 _ 32 96 kp.toNat_lt (by omega))
  rw [hW0, hW1, hW2, hW3, Nat.or_assoc, Nat.or_assoc]

/-- One 43-copy step (`forsCopyBody`, reused verbatim): `mem[0x40+32cur] := mem[0x80+32cur]`. -/
private theorem wots_copy_step (sig : ByteVec Spec.SignatureLen) (cur : Nat) (v : VM)
    (hcur : cur < 43) :
    (execList c10Oracle sig forsCopyBody { v with env := setVar v.env "i" cur }).2 = none
    ∧ (∀ a, ¬ (0x40 + 32 * cur ≤ a ∧ a < 0x40 + 32 * cur + 32) →
        (execList c10Oracle sig forsCopyBody { v with env := setVar v.env "i" cur }).1.mem a = v.mem a)
    ∧ (∀ k, k < 32 →
        (execList c10Oracle sig forsCopyBody { v with env := setVar v.env "i" cur }).1.mem
          (0x40 + 32 * cur + k) = v.mem (0x80 + 32 * cur + k))
    ∧ (execList c10Oracle sig forsCopyBody { v with env := setVar v.env "i" cur }).1.env
        = setVar v.env "i" cur := by
  unfold forsCopyBody
  rw [execList_cons_none c10Oracle sig _ _ _ (by simp only [execStmt])]
  rw [execList]
  simp only [execStmt, eval, setVar, ite_true]
  have hdest : (0x40 + cur <<< 5 % W) % W = 64 + 32 * cur := by
    rw [shl5_small cur (by omega), Nat.mod_eq_of_lt (lt_W_of_lt (show 64 + 32 * cur < 4096 by omega))]
  have hsrc : (0x80 + cur <<< 5 % W) % W = 128 + 32 * cur := by
    rw [shl5_small cur (by omega), Nat.mod_eq_of_lt (lt_W_of_lt (show 128 + 32 * cur < 4096 by omega))]
  rw [hdest, hsrc]
  refine ⟨trivial, ?_, ?_, ?_⟩
  · intro a ha; rw [mstore32_frame _ (64 + 32 * cur) _ a (by omega)]
  · intro k hk
    rw [show (0x40 + 32 * cur + k) = ((64 + 32 * cur) + k) by omega, mstore32_get _ (64 + 32 * cur) _ k hk]
    rw [beByte_mload32 v.mem (128 + 32 * cur) k hk]
  · trivial

set_option maxHeartbeats 8000000 in
set_option maxRecDepth 4000 in
/-- The 43-record copy loop (`fors_copy_loop` analogue, 43 instead of 13). Pre: 43 endpoints
    `pad16`'d at `[0x80+32t,…)` and `[0,0x40)` fixed. Post: 43 endpoints `pad16`'d at
    `[0x40+32t,…)`, `[0,0x40)` unchanged. -/
private theorem wots_copy_loop (sig : ByteVec Spec.SignatureLen) (vm : VM)
    (endpts : Nat → ByteVec 16)
    (hsrc : ∀ t, t < 43 → ∀ k, k < 32 → vm.mem (0x80 + 32 * t + k)
        = (ByteVec.pad16 (endpts t)).data.getD k 0) :
    (execFor c10Oracle sig "i" forsCopyBody 43 0 vm).2 = none
    ∧ (∀ t, t < 43 → ∀ k, k < 32 →
        (execFor c10Oracle sig "i" forsCopyBody 43 0 vm).1.mem (0x40 + 32 * t + k)
          = (ByteVec.pad16 (endpts t)).data.getD k 0)
    ∧ (∀ a, a < 0x40 → (execFor c10Oracle sig "i" forsCopyBody 43 0 vm).1.mem a = vm.mem a) := by
  let R : Nat → VM → Prop := fun cur w =>
    (∀ t, t < cur → ∀ k, k < 32 → w.mem (0x40 + 32 * t + k) = (ByteVec.pad16 (endpts t)).data.getD k 0)
    ∧ (∀ t, cur ≤ t → t < 43 → ∀ k, k < 32 → w.mem (0x80 + 32 * t + k) = (ByteVec.pad16 (endpts t)).data.getD k 0)
    ∧ (∀ a, a < 0x40 → w.mem a = vm.mem a)
  have hstep : ∀ cur w, cur < 43 → R cur w →
      (execList c10Oracle sig forsCopyBody { w with env := setVar w.env "i" cur }).2 = none ∧
      R (cur + 1) (execList c10Oracle sig forsCopyBody { w with env := setVar w.env "i" cur }).1 := by
    intro cur w hcur hR
    obtain ⟨hRcopied, hRsrc, hRlow⟩ := hR
    obtain ⟨hnone, hframe, hcopy, _⟩ := wots_copy_step sig cur w hcur
    refine ⟨hnone, ?_, ?_, ?_⟩
    · intro t ht k hk
      by_cases htc : t = cur
      · rw [htc, hcopy k hk]; exact hRsrc cur (Nat.le_refl cur) hcur k hk
      · have htlt : t < cur := by omega
        rw [hframe (0x40 + 32 * t + k) (by omega)]; exact hRcopied t htlt k hk
    · intro t ht ht43 k hk
      rw [hframe (0x80 + 32 * t + k) (by omega)]; exact hRsrc t (by omega) ht43 k hk
    · intro a ha; rw [hframe a (by omega)]; exact hRlow a ha
  have hR0 : R 0 vm := ⟨fun t ht => absurd ht (Nat.not_lt_zero t),
    fun t _ ht43 k hk => hsrc t ht43 k hk, fun a _ => rfl⟩
  have hloop := execFor_invariant_lt c10Oracle sig "i" forsCopyBody 43 R hstep vm hR0
  obtain ⟨hcopied, _, hlow⟩ := hloop.2
  exact ⟨hloop.1, hcopied, hlow⟩

/-- The 45-segment compression input: `seed`, the `wotsPk` ADRS, then the 43 `pad16`'d
    endpoints. Exactly `thMulti`'s `header ++ endpts.map (ofByteVec ∘ pad16)`. -/
def wotsPkSegs (seed : ByteVec 32) (layer : UInt32) (tree : UInt64) (kp : UInt32)
    (endpts : List (ByteVec 16)) : List (ByteVec 32) :=
  seed :: (Spec.Adrs.wotsPk layer tree kp) :: endpts.map ByteVec.pad16

/-- `(endpts.map pad16).getD n (zero 32) = pad16 (endpts.getD n (zero 16))` for `n < length`. -/
private theorem map_pad16_getD' (endpts : List (ByteVec 16)) (n : Nat) (hn : n < endpts.length) :
    (endpts.map ByteVec.pad16).getD n (ByteVec.zero 32) = ByteVec.pad16 (endpts.getD n (ByteVec.zero 16)) := by
  rw [List.getD_eq_getElem?_getD, List.getD_eq_getElem?_getD, List.getElem?_map,
      List.getElem?_eq_getElem hn, Option.map_some, Option.getD_some, Option.getD_some]

set_option maxHeartbeats 8000000 in
set_option maxRecDepth 4000 in
/-- **WOTS PK-compression refinement.** Running the compression fragment (store the `wotsPk`
    ADRS at `0x20`, copy the 43 endpoints, `sha256 0x00 0x5A0`, mask) from a VM whose env
    supplies `wotsAdrs`-unused, `idxTree`/`idxLeaf` already folded into `pkAdrs` via
    `wotsAdrs`-word — here parametrized by the env words `layer/tree/kp` through `pkAdrs`,
    `N_MASK`, `OUT = 0x600`, `seed` in `[0,0x20)`, and the 43 `pad16`'d endpoints at
    `[0x80+32t,…)` — falls through and binds `"wotsPk" = wordOf (pad16 (thMulti seed
    (wotsPk layer tree kp) endpts))` (`endpts.length = 43`). The `fors_root_compress`
    analogue. The `pkAdrs` env word is supplied as a precondition (`hpk`, the wrapper builds it). -/
theorem wots_pk_compress
    (sig : ByteVec Spec.SignatureLen) (vm : VM)
    (seed : ByteVec 32) (layer : UInt32) (tree : UInt64) (kp : UInt32)
    (endpts : List (ByteVec 16)) (hlen : endpts.length = 43)
    (hpk : vm.env "pkAdrs" = wordOf (Spec.Adrs.wotsPk layer tree kp))
    (hN : vm.env "N_MASK" = NMASK)
    (hOUT : vm.env "OUT" = 0x600)
    (hseedmem : ∀ k, k < 32 → vm.mem (0 + k) = seed.data.getD k 0)
    (hendmem : ∀ t, t < 43 → ∀ k, k < 32 →
        vm.mem (0x80 + 32 * t + k) = (ByteVec.pad16 (endpts.getD t (ByteVec.zero 16))).data.getD k 0) :
    (execList c10Oracle sig
        (.mstore (.lit 0x20) (.var "pkAdrs")
          :: .forRange "i" (.lit 43) forsCopyBody
          :: .sha256 (.lit 0x00) (.lit 0x5A0) (.var "OUT")
          :: [.letv "wotsPk" (.bin .band (.mload (.var "OUT")) (.var "N_MASK"))]) vm).2 = none
    ∧ ((execList c10Oracle sig
        (.mstore (.lit 0x20) (.var "pkAdrs")
          :: .forRange "i" (.lit 43) forsCopyBody
          :: .sha256 (.lit 0x00) (.lit 0x5A0) (.var "OUT")
          :: [.letv "wotsPk" (.bin .band (.mload (.var "OUT")) (.var "N_MASK"))]) vm).1.env "wotsPk"
        = wordOf (ByteVec.pad16 (Spec.thMulti seed (Spec.Adrs.wotsPk layer tree kp) endpts))) := by
  -- Step 1: mstore 0x20 (wotsPk adrs word).
  rw [execList_cons_none c10Oracle sig _ _ _ (by simp only [execStmt])]
  obtain ⟨v1, hv1⟩ : ∃ v1, (execStmt c10Oracle sig (.mstore (.lit 0x20) (.var "pkAdrs")) vm).1 = v1 := ⟨_, rfl⟩
  rw [hv1]
  have hv1env : v1.env = vm.env := by rw [← hv1]; simp only [execStmt]
  have hv1mem : v1.mem = mstore32 vm.mem 0x20 (wordOf (Spec.Adrs.wotsPk layer tree kp)) := by
    rw [← hv1]; simp only [execStmt, eval, hpk]
  have hv1end : ∀ t, t < 43 → ∀ k, k < 32 →
      v1.mem (0x80 + 32 * t + k) = (ByteVec.pad16 (endpts.getD t (ByteVec.zero 16))).data.getD k 0 := by
    intro t ht k hk; rw [hv1mem, mstore32_frame _ 0x20 _ (0x80 + 32 * t + k) (by omega)]; exact hendmem t ht k hk
  have hv1seed : ∀ k, k < 32 → v1.mem (0 + k) = seed.data.getD k 0 := by
    intro k hk; rw [hv1mem, mstore32_frame _ 0x20 _ (0 + k) (by omega)]; exact hseedmem k hk
  have hv1adrs : ∀ k, k < 32 → v1.mem (0x20 + k) = (Spec.Adrs.wotsPk layer tree kp).data.getD k 0 := by
    intro k hk; rw [hv1mem, mstore32_get _ 0x20 _ k hk, beByte_wordOf_getD _ k hk]
  -- Step 2: copy loop.
  have hcopyStmt : execStmt c10Oracle sig (.forRange "i" (.lit 43) forsCopyBody) v1
      = execFor c10Oracle sig "i" forsCopyBody 43 0 v1 := by simp only [execStmt, eval]
  obtain ⟨hcopyNone, hcopyEnd, hcopyLow⟩ := wots_copy_loop sig v1
    (fun t => endpts.getD t (ByteVec.zero 16)) hv1end
  rw [execList_cons_none c10Oracle sig _ _ _ (by rw [hcopyStmt]; exact hcopyNone), hcopyStmt]
  obtain ⟨v2, hv2⟩ : ∃ v2, (execFor c10Oracle sig "i" forsCopyBody 43 0 v1).1 = v2 := ⟨_, rfl⟩
  rw [hv2]
  have hv2OUT : v2.env "OUT" = 0x600 := by
    rw [← hv2, execFor_forsCopyBody_preserves_var sig "OUT" (by decide) 43 0 v1, hv1env, hOUT]
  have hv2N : v2.env "N_MASK" = NMASK := by
    rw [← hv2, execFor_forsCopyBody_preserves_var sig "N_MASK" (by decide) 43 0 v1, hv1env, hN]
  have hv2low : ∀ a, a < 0x40 → v2.mem a = v1.mem a := by intro a ha; rw [← hv2]; exact hcopyLow a ha
  have hv2end : ∀ t, t < 43 → ∀ k, k < 32 →
      v2.mem (0x40 + 32 * t + k) = (ByteVec.pad16 (endpts.getD t (ByteVec.zero 16))).data.getD k 0 := by
    intro t ht k hk; rw [← hv2]; exact hcopyEnd t ht k hk
  -- The 45-segment holdsSegs at base 0.
  have hseglen : (wotsPkSegs seed layer tree kp endpts).length = 45 := by
    simp only [wotsPkSegs, List.length_cons, List.length_map, hlen]
  have hsegs : holdsSegs v2.mem 0 (wotsPkSegs seed layer tree kp endpts) := by
    intro j i hj hi
    rw [hseglen] at hj
    rw [Nat.zero_add]
    rcases Nat.lt_or_ge j 2 with hj2 | hj2
    · match j, hj2 with
      | 0, _ =>
          rw [show (32 * 0 + i) = (0 + i) by omega, hv2low (0 + i) (by omega), hv1seed i hi]; rfl
      | 1, _ =>
          rw [show (32 * 1 + i) = (0x20 + i) by omega, hv2low (0x20 + i) (by omega), hv1adrs i hi]; rfl
    · obtain ⟨m, rfl⟩ : ∃ m, j = m + 2 := ⟨j - 2, by omega⟩
      rw [show (32 * (m + 2) + i) = (0x40 + 32 * m + i) by omega, hv2end m (by omega) i hi]
      show _ = ((wotsPkSegs seed layer tree kp endpts).getD (m + 2) (ByteVec.zero 32)).data.getD i 0
      have hgetD : (wotsPkSegs seed layer tree kp endpts).getD (m + 2) (ByteVec.zero 32)
          = ByteVec.pad16 (endpts.getD m (ByteVec.zero 16)) := by
        unfold wotsPkSegs
        rw [List.getD_cons_succ, List.getD_cons_succ]
        exact map_pad16_getD' endpts m (by omega)
      rw [hgetD]
  -- Step 3+4: sha256 over [0,0x5A0) = 45 segments, then mask.
  rw [execList_cons_none c10Oracle sig _ _ _ (by simp only [execStmt])]
  rw [execList_cons_none c10Oracle sig _ _ _ (by simp only [execStmt]), execList]
  refine ⟨rfl, ?_⟩
  simp only [execStmt, eval, hv2OUT, hv2N]
  rw [setVar_get_eq]
  rw [mload_masked_eq_wordOf_pad16 v2.mem 0x600 (c10Oracle (slice v2.mem 0 (32 * 45)))]
  have hbridge : c10Oracle (slice v2.mem 0 (32 * 45))
      = Spec.sha256 ((wotsPkSegs seed layer tree kp endpts).map Spec.ByteSeg.ofByteVec) := by
    have h := c10Oracle_holdsSegs v2.mem 0 (wotsPkSegs seed layer tree kp endpts) hsegs
    rw [hseglen] at h; exact h
  rw [hbridge]
  congr 2
  show ByteVec.truncate16 (Spec.sha256 ((wotsPkSegs seed layer tree kp endpts).map Spec.ByteSeg.ofByteVec))
      = Spec.thMulti seed (Spec.Adrs.wotsPk layer tree kp) endpts
  unfold Spec.thMulti wotsPkSegs
  simp only [List.map_cons, List.map_map]
  rfl

/-! ### WOTS `pkFromSig` capstone — the full per-layer WOTS body

`wotsBody` is the per-layer WOTS interp fragment of `SPHINCsC10Asm.sol` (L168–205),
*exactly* `mstore 0x00 seed` (digit hash) through `letv "wotsPk"` (PK-compress) — i.e.
the layer body up to but **excluding** the preamble (`idxLeaf`/`idxTree`/`wotsAdrs`/`count`
derivation, L161–167) and the Merkle climb (L207+). It composes the five proven phases
(`wots_digit_hash` / `wots_digit_sum` / `wots_chain_outer_loop` / `wots_pk_compress`) plus
the digit-sum revert gate, refining against `Spec.Wots.pkFromSig`.

The only inter-phase glue not yet established is on the digit-hash→chain-loop side:
the digit hash re-lays `seed` into scratch `[0,0x20)` (its first stmt is `mstore 0x00
seed`) and, with the digit-sum loop (pure-env: no `mstore`/`sha`), preserves every env
var the downstream phases need (`wotsAdrs`/`wotsPtr`/`N_MASK`/`OUT`). We build those frame
helpers here, NOT by strengthening the sub-lemmas (keeps the green build safe). -/

/-- The digit-hash fragment re-lays `seed` into scratch `[0,0x20)` (its first stmt is
    `mstore 0x00 seed`); the later `0x20`/`0x40`/`0x60` mstores and the `0x600` digest
    writeRegion all frame off `[0,0x20)`. So regardless of the prior mem, after the
    fragment `mem[0,0x20) = seed`. -/
private theorem wotsDigitHashFragment_seed_mem
    (sig : ByteVec Spec.SignatureLen) (vm : VM) (seed : ByteVec 32)
    (hseedw : vm.env "seed" = wordOf seed) (hOUT : vm.env "OUT" = 0x600) :
    ∀ k, k < 32 → (execList c10Oracle sig wotsDigitHashFragment vm).1.mem (0 + k)
        = seed.data.getD k 0 := by
  intro k hk
  unfold wotsDigitHashFragment
  rw [execList_cons_none c10Oracle sig _ _ _ (by simp only [execStmt])]
  rw [execList_cons_none c10Oracle sig _ _ _ (by simp only [execStmt])]
  rw [execList_cons_none c10Oracle sig _ _ _ (by simp only [execStmt])]
  rw [execList_cons_none c10Oracle sig _ _ _ (by simp only [execStmt])]
  rw [execList_cons_none c10Oracle sig _ _ _ (by simp only [execStmt])]
  rw [execList_cons_none c10Oracle sig _ _ _ (by simp only [execStmt])]
  rw [execList]
  -- After the `letv "d"` (which doesn't touch mem) and the 4 mstores + sha, the byte at
  -- `0+k` is framed back to the first `mstore 0x00 seed`'s store.
  simp only [execStmt, eval, setVar, hseedw, hOUT]
  rw [writeRegion_frame _ 0x600 _ (0 + k) (by omega),
      mstore32_frame _ 0x60 _ (0 + k) (by omega),
      mstore32_frame _ 0x40 _ (0 + k) (by omega),
      mstore32_frame _ 0x20 _ (0 + k) (by omega)]
  rw [show (0 + k) = (0 + k) by rfl, mstore32_get vm.mem 0 (wordOf seed) k hk, beByte_wordOf_getD seed k hk]

/-- The digit-hash fragment preserves any env var `x ∉ {d}` (the only `letv` binds `d`;
    the `mstore`/`sha256` stmts never touch the env). -/
private theorem wotsDigitHashFragment_preserves_var
    (sig : ByteVec Spec.SignatureLen) (vm : VM) (x : String) (hx : x ≠ "d") :
    (execList c10Oracle sig wotsDigitHashFragment vm).1.env x = vm.env x := by
  unfold wotsDigitHashFragment
  rw [execList_cons_none c10Oracle sig _ _ _ (by simp only [execStmt])]
  rw [execList_cons_none c10Oracle sig _ _ _ (by simp only [execStmt])]
  rw [execList_cons_none c10Oracle sig _ _ _ (by simp only [execStmt])]
  rw [execList_cons_none c10Oracle sig _ _ _ (by simp only [execStmt])]
  rw [execList_cons_none c10Oracle sig _ _ _ (by simp only [execStmt])]
  rw [execList_cons_none c10Oracle sig _ _ _ (by simp only [execStmt])]
  rw [execList]
  simp only [execStmt, eval, setVar, hx, ite_false]

/-- One digit-sum step preserves any env var `x ∉ {ii, digitSum}` (the body only `setv`s
    `digitSum`; `ii` is the loop var). -/
private theorem execList_wotsDigitSumBody_preserves_var (sig : ByteVec Spec.SignatureLen)
    (cur : Nat) (v : VM) (x : String) (hx : x ≠ "ii" ∧ x ≠ "digitSum") :
    (execList c10Oracle sig wotsDigitSumBody { v with env := setVar v.env "ii" cur }).1.env x
        = v.env x := by
  obtain ⟨h1, h2⟩ := hx
  unfold wotsDigitSumBody
  rw [execList_cons_none c10Oracle sig _ _ _ (by simp only [execStmt])]
  rw [execList]
  simp only [execStmt, eval, setVar, h1, h2, ite_false]

/-- One digit-sum step falls through (no `revert`/`return`). -/
private theorem execList_wotsDigitSumBody_none (sig : ByteVec Spec.SignatureLen)
    (cur : Nat) (v : VM) :
    (execList c10Oracle sig wotsDigitSumBody { v with env := setVar v.env "ii" cur }).2 = none := by
  unfold wotsDigitSumBody
  rw [execList_cons_none c10Oracle sig _ _ _ (by simp only [execStmt])]
  rw [execList]

/-- One digit-sum step never touches mem (the body has no `mstore`/`sha256`). -/
private theorem execList_wotsDigitSumBody_mem (sig : ByteVec Spec.SignatureLen)
    (cur : Nat) (v : VM) (a : Nat) :
    (execList c10Oracle sig wotsDigitSumBody { v with env := setVar v.env "ii" cur }).1.mem a
        = v.mem a := by
  unfold wotsDigitSumBody
  rw [execList_cons_none c10Oracle sig _ _ _ (by simp only [execStmt])]
  rw [execList]
  simp only [execStmt, eval, setVar]

/-- The whole digit-sum loop preserves any env var `x ∉ {ii, digitSum}`. -/
private theorem execFor_wotsDigitSumBody_preserves_var (sig : ByteVec Spec.SignatureLen)
    (x : String) (hx : x ≠ "ii" ∧ x ≠ "digitSum") :
    ∀ (remaining cur : Nat) (v : VM),
      (execFor c10Oracle sig "ii" wotsDigitSumBody remaining cur v).1.env x = v.env x := by
  intro remaining
  induction remaining with
  | zero => intro cur v; simp only [execFor]
  | succ rem ih =>
      intro cur v
      have hnone := execList_wotsDigitSumBody_none sig cur v
      rw [execFor]
      rcases hp : execList c10Oracle sig wotsDigitSumBody { v with env := setVar v.env "ii" cur }
        with ⟨pvm, po⟩
      rw [hp] at hnone; subst hnone; simp only []
      rw [ih (cur + 1) pvm]
      have := execList_wotsDigitSumBody_preserves_var sig cur v x hx
      rw [hp] at this; exact this

/-- The whole digit-sum loop never touches mem. -/
private theorem execFor_wotsDigitSumBody_mem (sig : ByteVec Spec.SignatureLen) (a : Nat) :
    ∀ (remaining cur : Nat) (v : VM),
      (execFor c10Oracle sig "ii" wotsDigitSumBody remaining cur v).1.mem a = v.mem a := by
  intro remaining
  induction remaining with
  | zero => intro cur v; simp only [execFor]
  | succ rem ih =>
      intro cur v
      have hnone := execList_wotsDigitSumBody_none sig cur v
      rw [execFor]
      rcases hp : execList c10Oracle sig wotsDigitSumBody { v with env := setVar v.env "ii" cur }
        with ⟨pvm, po⟩
      rw [hp] at hnone; subst hnone; simp only []
      rw [ih (cur + 1) pvm]
      have := execList_wotsDigitSumBody_mem sig cur v a
      rw [hp] at this; exact this

/-- The 43 WOTS chain endpoints as a `List` (interp index form). Exactly the list that
    `wots_chain_outer_loop` lays into memory (`wotsChainEndpoint … t` at `0x80+32t`) and
    that `wots_pk_compress` compresses. -/
def wotsEndptList (seed : ByteVec 32) (layer : UInt32) (tree : UInt64) (kp : UInt32)
    (d_bv : ByteVec 32) (sig : ByteVec Spec.SignatureLen) (wotsPtr : Nat) : List (ByteVec 16) :=
  (List.range 43).map (wotsChainEndpoint seed layer tree kp d_bv sig wotsPtr ·)

/-- `wotsEndptList` has length 43. -/
private theorem wotsEndptList_length (seed : ByteVec 32) (layer : UInt32) (tree : UInt64)
    (kp : UInt32) (d_bv : ByteVec 32) (sig : ByteVec Spec.SignatureLen) (wotsPtr : Nat) :
    (wotsEndptList seed layer tree kp d_bv sig wotsPtr).length = 43 := by
  simp only [wotsEndptList, List.length_map, List.length_range]

/-- `wotsEndptList.getD t (zero 16) = wotsChainEndpoint … t` for `t < 43`. -/
private theorem wotsEndptList_getD (seed : ByteVec 32) (layer : UInt32) (tree : UInt64)
    (kp : UInt32) (d_bv : ByteVec 32) (sig : ByteVec Spec.SignatureLen) (wotsPtr t : Nat)
    (ht : t < 43) :
    (wotsEndptList seed layer tree kp d_bv sig wotsPtr).getD t (ByteVec.zero 16)
      = wotsChainEndpoint seed layer tree kp d_bv sig wotsPtr t := by
  unfold wotsEndptList
  rw [List.getD_eq_getElem?_getD, List.getElem?_map,
      List.getElem?_eq_getElem (by rw [List.length_range]; exact ht), Option.map_some,
      Option.getD_some, List.getElem_range]

/-- **The chainValues bridge.** With `d_bv = wotsDigest seed (Adrs.wots layer tree kp)
    (pad16 msgHash) sigma.count` and the per-chain signature value bound to the calldata
    load (`sigma.chains[i] = loadValue16 sig (wotsPtr+16i)`), the interp endpoint list
    `wotsEndptList` equals exactly `pkFromSig`'s `chainValues` (the `List.range L`-map).
    `W-1 = 7`, `L = 43`; the dependent `dite` in `pkFromSig` takes the true branch via the
    bounded sigma hypothesis (so the per-index reads the supplied chain value). -/
private theorem wotsEndptList_eq_chainValues
    (sig : ByteVec Spec.SignatureLen)
    (seed : ByteVec 32) (layer : UInt32) (tree : UInt64) (kp : UInt32)
    (msgHash : ByteVec 16) (sigma : Spec.Wots.Sigma) (wotsPtr : Nat)
    (hsig : ∀ i (h : i < sigma.chains.size), sigma.chains[i] = ByteVec.loadValue16 sig (wotsPtr + 16 * i)) :
    wotsEndptList seed layer tree kp
        (Spec.wotsDigest seed (Spec.Adrs.wots layer tree kp) (ByteVec.pad16 msgHash) sigma.count)
        sig wotsPtr
      = (List.range Spec.L).map (fun i =>
          let chainAdrs := Spec.Adrs.setChainIndex (Spec.Adrs.wots layer tree kp) (UInt32.ofNat i)
          let digit := (SphincsCVerify.Util.extractDigits
            (Spec.wotsDigest seed (Spec.Adrs.wots layer tree kp) (ByteVec.pad16 msgHash) sigma.count))[i]!
          let sigI := if h : i < sigma.chains.size then sigma.chains[i] else ByteVec.zero 16
          let remaining := (Spec.W - 1) - digit
          Spec.chainHash seed chainAdrs sigI digit remaining) := by
  have hLeq : Spec.L = 43 := rfl
  unfold wotsEndptList
  rw [hLeq]
  apply List.map_congr_left
  intro i hi
  have hi43 : i < 43 := by rw [List.mem_range] at hi; exact hi
  -- chain count = L = 43, so i < sigma.chains.size; the dite takes the true branch.
  have hsz : i < sigma.chains.size := by rw [sigma.chainsLen]; exact (by rw [hLeq] at *; exact hi43)
  unfold wotsChainEndpoint
  rw [dif_pos hsz, hsig i hsz]
  -- W - 1 = 7; remaining = 7 - digit.
  show Spec.chainHash seed _ _ _ (7 - _) = Spec.chainHash seed _ _ _ ((Spec.W - 1) - _)
  rfl

/-- One `wotsChainBody` iteration falls through (no `revert`/`return`). -/
private theorem execList_wotsChainBody_none (sig : ByteVec Spec.SignatureLen)
    (cur : Nat) (v : VM) :
    (execList c10Oracle sig wotsChainBody { v with env := setVar v.env "i" cur }).2 = none := by
  unfold wotsChainBody
  rw [execList_cons_none c10Oracle sig _ _ _ (by simp only [execStmt])]
  rw [execList_cons_none c10Oracle sig _ _ _ (by simp only [execStmt])]
  rw [execList_cons_none c10Oracle sig _ _ _ (by simp only [execStmt])]
  rw [execList_cons_none c10Oracle sig _ _ _ (by simp only [execStmt])]
  obtain ⟨w', hw'⟩ : ∃ w', w' = (execStmt c10Oracle sig (Stmt.letv "chainBase"
        (.bin .band (.bin .bor (.var "wotsAdrs") (.bin .shl (.lit 64) (.var "i"))) (.lit CHAINBASE_MASK)))
      (execStmt c10Oracle sig (Stmt.letv "val"
        (.bin .band (.calldataload (.bin .add (.var "wotsPtr") (.bin .shl (.lit 4) (.var "i")))) (.var "N_MASK")))
      (execStmt c10Oracle sig (Stmt.letv "steps" (.bin .sub (.lit 7) (.var "digit")))
      (execStmt c10Oracle sig (Stmt.letv "digit"
        (.bin .band (.bin .shr (.bin .mul (.var "i") (.lit 3)) (.var "d")) (.lit 0x7)))
        { v with env := setVar v.env "i" cur }).1).1).1).1 := ⟨_, rfl⟩
  rw [← hw']
  have hforNone : (execStmt c10Oracle sig (.forRange "step" (.var "steps") wotsChainStepBody) w').2 = none := by
    simp only [execStmt, eval]; exact execFor_wotsChainStepBody_none' sig _ 0 w'
  rw [execList_cons_none c10Oracle sig _ _ _ hforNone]
  rw [execList_cons_none c10Oracle sig _ _ _ (by simp only [execStmt])]
  rw [execList]

/-- The whole 43-chain outer loop preserves any const `x ∉ {digit,steps,val,chainBase,step,i}`. -/
private theorem execFor_wotsChainStepBody_outer_preserves (sig : ByteVec Spec.SignatureLen)
    (x : String)
    (hx : x ≠ "digit" ∧ x ≠ "steps" ∧ x ≠ "val" ∧ x ≠ "chainBase" ∧ x ≠ "step" ∧ x ≠ "i") :
    ∀ (remaining cur : Nat) (v : VM),
      (execFor c10Oracle sig "i" wotsChainBody remaining cur v).1.env x = v.env x := by
  intro remaining
  induction remaining with
  | zero => intro cur v; simp only [execFor]
  | succ rem ih =>
      intro cur v
      have hnone := execList_wotsChainBody_none sig cur v
      rw [execFor]
      rcases hp : execList c10Oracle sig wotsChainBody { v with env := setVar v.env "i" cur }
        with ⟨pvm, po⟩
      rw [hp] at hnone; subst hnone; simp only []
      rw [ih (cur + 1) pvm]
      have := execList_wotsChainBody_preserves_const sig cur v x hx
      rw [hp] at this; exact this

/-- **`wotsBody`** — the full per-layer WOTS interp fragment (`SPHINCsC10Asm.sol` L168–205),
    statement-for-statement: the digit hash (`wotsDigitHashFragment`), the WOTS+C digit-sum
    gate (`letv "digitSum" 0`; the 43-iteration sum loop; the `ifnz` revert-unless-205), the
    43 WOTS chains (`letv "wotsPtr"`; `forRange "i" 43 wotsChainBody`), and the PK-compression
    (`letv "pkAdrs"`; the 4-stmt `wots_pk_compress` tail). Excludes the per-layer preamble
    (`idxLeaf`/`idxTree`/`wotsAdrs`/`count`, L161–167) and the Merkle climb (L207+). -/
def wotsBody : List Stmt :=
  wotsDigitHashFragment
    ++ [ .letv "digitSum" (.lit 0)
       , .forRange "ii" (.lit 43) wotsDigitSumBody
       , .ifnz (.iszero (.bin .eq (.var "digitSum") (.lit 205))) [ .revert ]
       , .letv "wotsPtr" (.bin .add (.var "sigBase") (.var "sigOff"))
       , .forRange "i" (.lit 43) wotsChainBody
       , .letv "pkAdrs"
           (.bin .bor (.bin .shl (.lit 224) (.var "layer"))
             (.bin .bor (.bin .shl (.lit 160) (.var "idxTree"))
               (.bin .bor (.bin .shl (.lit 128) (.lit 1)) (.bin .shl (.lit 96) (.var "idxLeaf")))))
       , .mstore (.lit 0x20) (.var "pkAdrs")
       , .forRange "i" (.lit 43) forsCopyBody
       , .sha256 (.lit 0x00) (.lit 0x5A0) (.var "OUT")
       , .letv "wotsPk" (.bin .band (.mload (.var "OUT")) (.var "N_MASK")) ]

-- Seal the spec hashes so `whnf`/`isDefEq` in the capstone never tries to reduce the
-- 64-round SHA-256 body (would heartbeat-die). `Spec.th`/`Spec.thMulti` are already sealed
-- (the L2984 `local irreducible`, still active in this namespace); `c10Oracle` is sealed
-- (L320). `pkFromSig` is intentionally LEFT reducible — we unfold it once to expose its
-- `if`/`chainValues`.
attribute [local irreducible] Spec.chainHash Spec.wotsDigest

/-- The post-`ifnz` fall-through tail of `wotsBody` (the statements after the digit-sum gate):
    `letv "wotsPtr"`, the 43-chain loop, `letv "pkAdrs"`, and the 4-stmt PK-compress. Split
    out as its own declaration so the heavy chain-loop + PK-compress work has its own
    heartbeat budget (the `wots_pkfromsig` capstone consumes it as one block). -/
def wotsContTail : List Stmt :=
  [ .letv "wotsPtr" (.bin .add (.var "sigBase") (.var "sigOff"))
  , .forRange "i" (.lit 43) wotsChainBody
  , .letv "pkAdrs"
      (.bin .bor (.bin .shl (.lit 224) (.var "layer"))
        (.bin .bor (.bin .shl (.lit 160) (.var "idxTree"))
          (.bin .bor (.bin .shl (.lit 128) (.lit 1)) (.bin .shl (.lit 96) (.var "idxLeaf")))))
  , .mstore (.lit 0x20) (.var "pkAdrs")
  , .forRange "i" (.lit 43) forsCopyBody
  , .sha256 (.lit 0x00) (.lit 0x5A0) (.var "OUT")
  , .letv "wotsPk" (.bin .band (.mload (.var "OUT")) (.var "N_MASK")) ]

set_option maxHeartbeats 48000000 in
set_option maxRecDepth 8000 in
/-- **The WOTS fall-through tail refinement.** From a post-digit-sum-gate VM `v3` (the
    digit-sum check passed) whose env supplies `d = wordOf d_bv`, `wotsAdrs = wordOf (wots
    layer tree kp)`, `sigBase = 0`, `sigOff = wotsPtr` (< 4096), `layer/idxTree/idxLeaf` the
    `.toNat`s, `N_MASK`, `OUT = 0x600`, and `seed` in scratch `[0,0x20)`, running `wotsContTail`
    falls through and binds `"wotsPk" = wordOf (pad16 (thMulti seed (wotsPk layer tree kp)
    (wotsEndptList …)))`. Composes the chain outer loop + the PK-compression. -/
private theorem wots_cont_tail
    (sig : ByteVec Spec.SignatureLen) (v3 : VM)
    (seed : ByteVec 32) (layer : UInt32) (tree : UInt64) (kp : UInt32)
    (d_bv : ByteVec 32) (wotsPtr : Nat) (hwp : wotsPtr < 4096)
    (hv3d : v3.env "d" = wordOf d_bv)
    (hv3wa : v3.env "wotsAdrs" = wordOf (Spec.Adrs.wots layer tree kp))
    (hv3sigbase : v3.env "sigBase" = 0)
    (hv3sigoff : v3.env "sigOff" = wotsPtr)
    (hv3layer : v3.env "layer" = layer.toNat)
    (hv3idxTree : v3.env "idxTree" = tree.toNat)
    (hv3idxLeaf : v3.env "idxLeaf" = kp.toNat)
    (hv3N : v3.env "N_MASK" = NMASK)
    (hv3OUT : v3.env "OUT" = 0x600)
    (hv3seedmem : ∀ k, k < 32 → v3.mem (0 + k) = seed.data.getD k 0) :
    (execList c10Oracle sig wotsContTail v3).2 = none
    ∧ (execList c10Oracle sig wotsContTail v3).1.env "wotsPk"
        = wordOf (ByteVec.pad16 (Spec.thMulti seed (Spec.Adrs.wotsPk layer tree kp)
            (wotsEndptList seed layer tree kp d_bv sig wotsPtr))) := by
  unfold wotsContTail
  -- letv "wotsPtr" (add sigBase sigOff) = (0 + wotsPtr) % W = wotsPtr.
  rw [execList_cons_none c10Oracle sig _ _ _ (by simp only [execStmt])]
  obtain ⟨v4, hv4⟩ : ∃ v4, (execStmt c10Oracle sig
      (.letv "wotsPtr" (.bin .add (.var "sigBase") (.var "sigOff"))) v3).1 = v4 := ⟨_, rfl⟩
  rw [hv4]
  have hv4env : v4.env = setVar v3.env "wotsPtr" ((0 + wotsPtr) % W) := by
    rw [← hv4]; simp only [execStmt, eval, hv3sigbase, hv3sigoff]
  have hv4mem : v4.mem = v3.mem := by rw [← hv4]; simp only [execStmt]
  have hwptrW : (0 + wotsPtr) % W = wotsPtr := by
    rw [Nat.zero_add, Nat.mod_eq_of_lt (lt_W_of_lt (by omega))]
  have hv4wptr : v4.env "wotsPtr" = wotsPtr := by rw [hv4env, setVar_get_eq, hwptrW]
  have hv4d : v4.env "d" = wordOf d_bv := by rw [hv4env, setVar_get_ne _ _ _ _ (by decide)]; exact hv3d
  have hv4wa : v4.env "wotsAdrs" = wordOf (Spec.Adrs.wots layer tree kp) := by
    rw [hv4env, setVar_get_ne _ _ _ _ (by decide)]; exact hv3wa
  have hv4layer : v4.env "layer" = layer.toNat := by rw [hv4env, setVar_get_ne _ _ _ _ (by decide)]; exact hv3layer
  have hv4idxTree : v4.env "idxTree" = tree.toNat := by rw [hv4env, setVar_get_ne _ _ _ _ (by decide)]; exact hv3idxTree
  have hv4idxLeaf : v4.env "idxLeaf" = kp.toNat := by rw [hv4env, setVar_get_ne _ _ _ _ (by decide)]; exact hv3idxLeaf
  have hv4N : v4.env "N_MASK" = NMASK := by rw [hv4env, setVar_get_ne _ _ _ _ (by decide)]; exact hv3N
  have hv4OUT : v4.env "OUT" = 0x600 := by rw [hv4env, setVar_get_ne _ _ _ _ (by decide)]; exact hv3OUT
  have hv4seedmem : ∀ k, k < 32 → v4.mem (0 + k) = seed.data.getD k 0 := by
    intro k hk; rw [hv4mem]; exact hv3seedmem k hk
  -- ===== Phase 4: the 43-chain outer loop. =====
  have hchainStmt : execStmt c10Oracle sig (.forRange "i" (.lit 43) wotsChainBody) v4
      = execFor c10Oracle sig "i" wotsChainBody 43 0 v4 := by simp only [execStmt, eval]
  obtain ⟨hclNone, hclMem, hclSeed, hclN, hclOUT⟩ := wots_chain_outer_loop sig v4 seed layer tree kp
    d_bv wotsPtr hwp hv4d hv4wptr hv4wa hv4N hv4OUT hv4seedmem
  rw [execList_cons_none c10Oracle sig _ _ _ (by rw [hchainStmt]; exact hclNone), hchainStmt]
  obtain ⟨v5, hv5⟩ : ∃ v5, (execFor c10Oracle sig "i" wotsChainBody 43 0 v4).1 = v5 := ⟨_, rfl⟩
  rw [hv5]
  have hv5end : ∀ t, t < 43 → ∀ k, k < 32 →
      v5.mem (0x80 + 32 * t + k)
        = (ByteVec.pad16 (wotsChainEndpoint seed layer tree kp d_bv sig wotsPtr t)).data.getD k 0 := by
    intro t ht k hk; rw [← hv5]; exact hclMem t ht k hk
  have hv5seed : ∀ k, k < 32 → v5.mem (0 + k) = seed.data.getD k 0 := by
    intro k hk; rw [← hv5]; exact hclSeed k hk
  have hv5N : v5.env "N_MASK" = NMASK := by rw [← hv5]; exact hclN
  have hv5OUT : v5.env "OUT" = 0x600 := by rw [← hv5]; exact hclOUT
  have hv5layer : v5.env "layer" = layer.toNat := by
    rw [← hv5, execFor_wotsChainStepBody_outer_preserves sig "layer" (by decide) 43 0 v4]; exact hv4layer
  have hv5idxTree : v5.env "idxTree" = tree.toNat := by
    rw [← hv5, execFor_wotsChainStepBody_outer_preserves sig "idxTree" (by decide) 43 0 v4]; exact hv4idxTree
  have hv5idxLeaf : v5.env "idxLeaf" = kp.toNat := by
    rw [← hv5, execFor_wotsChainStepBody_outer_preserves sig "idxLeaf" (by decide) 43 0 v4]; exact hv4idxLeaf
  -- ===== Phase 5: letv "pkAdrs"; then the 4-stmt pk-compress tail. =====
  rw [execList_cons_none c10Oracle sig _ _ _ (by simp only [execStmt])]
  obtain ⟨v6, hv6⟩ : ∃ v6, (execStmt c10Oracle sig
      (.letv "pkAdrs"
        (.bin .bor (.bin .shl (.lit 224) (.var "layer"))
          (.bin .bor (.bin .shl (.lit 160) (.var "idxTree"))
            (.bin .bor (.bin .shl (.lit 128) (.lit 1)) (.bin .shl (.lit 96) (.var "idxLeaf")))))) v5).1 = v6 := ⟨_, rfl⟩
  rw [hv6]
  have hv6mem : v6.mem = v5.mem := by rw [← hv6]; simp only [execStmt]
  have hv6env : v6.env = setVar v5.env "pkAdrs"
      (((layer.toNat <<< 224 % W) ||| ((tree.toNat <<< 160 % W) ||| ((1 <<< 128 % W) ||| (kp.toNat <<< 96 % W))))) := by
    rw [← hv6]; simp only [execStmt, eval, hv5layer, hv5idxTree, hv5idxLeaf]
  have hv6pk : v6.env "pkAdrs" = wordOf (Spec.Adrs.wotsPk layer tree kp) := by
    rw [hv6env, setVar_get_eq, wotsPk_word layer tree kp]
  have hv6N : v6.env "N_MASK" = NMASK := by rw [hv6env, setVar_get_ne _ _ _ _ (by decide)]; exact hv5N
  have hv6OUT : v6.env "OUT" = 0x600 := by rw [hv6env, setVar_get_ne _ _ _ _ (by decide)]; exact hv5OUT
  have hv6seed : ∀ k, k < 32 → v6.mem (0 + k) = seed.data.getD k 0 := by
    intro k hk; rw [hv6mem]; exact hv5seed k hk
  have hv6end : ∀ t, t < 43 → ∀ k, k < 32 →
      v6.mem (0x80 + 32 * t + k)
        = (ByteVec.pad16 ((wotsEndptList seed layer tree kp d_bv sig wotsPtr).getD t (ByteVec.zero 16))).data.getD k 0 := by
    intro t ht k hk; rw [hv6mem, hv5end t ht k hk, wotsEndptList_getD seed layer tree kp d_bv sig wotsPtr t ht]
  -- Apply wots_pk_compress with endpts = wotsEndptList.
  obtain ⟨hpcNone, hpcVal⟩ := wots_pk_compress sig v6 seed layer tree kp
    (wotsEndptList seed layer tree kp d_bv sig wotsPtr)
    (wotsEndptList_length seed layer tree kp d_bv sig wotsPtr)
    hv6pk hv6N hv6OUT hv6seed hv6end
  exact ⟨hpcNone, hpcVal⟩

set_option maxHeartbeats 16000000 in
set_option maxRecDepth 8000 in
/-- **`pkFromSig` evaluates to the `wotsEndptList` compression.** When the digit-sum check
    passes (`digitSum (extractDigits d_bv) = TargetSum`, `d_bv` the WOTS digest) and the
    per-chain values are bound to the calldata loads (`hsig`), `pkFromSig` returns
    `some (thMulti seed (wotsPk layer tree kp) (wotsEndptList …))`. The interp-side bridge,
    proven once with controlled reduction (unfold pkFromSig, the `if_neg` selects the else,
    the `chainValues = wotsEndptList` rewrite closes it) — kept OUT of the capstone so its
    `congr`/`rw` cost does not stack with the phase plumbing's heartbeats. -/
private theorem pkFromSig_eq
    (sig : ByteVec Spec.SignatureLen)
    (seed : ByteVec 32) (layer : UInt32) (tree : UInt64) (kp : UInt32)
    (msgHash : ByteVec 16) (sigma : Spec.Wots.Sigma) (wotsPtr : Nat)
    (hsig : ∀ i (h : i < sigma.chains.size), sigma.chains[i] = ByteVec.loadValue16 sig (wotsPtr + 16 * i))
    (hgate : SphincsCVerify.Util.digitSum (SphincsCVerify.Util.extractDigits
        (Spec.wotsDigest seed (Spec.Adrs.wots layer tree kp) (ByteVec.pad16 msgHash) sigma.count))
        = Spec.TargetSum) :
    Spec.Wots.pkFromSig seed layer tree kp msgHash sigma
      = some (Spec.thMulti seed (Spec.Adrs.wotsPk layer tree kp)
          (wotsEndptList seed layer tree kp
            (Spec.wotsDigest seed (Spec.Adrs.wots layer tree kp) (ByteVec.pad16 msgHash) sigma.count)
            sig wotsPtr)) := by
  -- Unfold + zeta-reduce the `let`s so the `if` condition is the fully-substituted form.
  simp only [Spec.Wots.pkFromSig]
  rw [if_neg (show ¬ (SphincsCVerify.Util.digitSum (SphincsCVerify.Util.extractDigits
      (Spec.wotsDigest seed (Spec.Adrs.wots layer tree kp) (ByteVec.pad16 msgHash) sigma.count)) ≠ Spec.TargetSum)
    from fun h => h hgate)]
  -- The `else` branch is `some (thMulti seed (wotsPk …) chainValues)`; rewrite wotsEndptList → chainValues.
  rw [wotsEndptList_eq_chainValues sig seed layer tree kp msgHash sigma wotsPtr hsig]

-- Seal pkFromSig + the base-w digit decoders so the capstone composition below
-- never whnf-reduces them: they unfold to 43-fold digit folds over the (opaque,
-- sealed) WOTS digest, which blows the heartbeat budget. `pkFromSig_eq` above
-- already performed the one controlled unfold of `pkFromSig`. This closes the
-- 50M/16M-heartbeat whnf timeouts in `wots_pkfromsig` / `wots_pkfromsig_nonvacuous`.
attribute [local irreducible] Spec.Wots.pkFromSig SphincsCVerify.Util.digitSum SphincsCVerify.Util.extractDigits

set_option maxHeartbeats 50000000
set_option maxRecDepth 8000
/-- **WOTS `pkFromSig` capstone.** From a per-layer-preamble VM — `seed = wordOf seed`,
    `wotsAdrs = wordOf (Adrs.wots layer tree kp)`, `currentNode = wordOf (pad16 msgHash)`,
    `count = wordOf (u32ToB32 sigma.count)`, `sigBase = 0`, `sigOff = wotsPtr` (< 4096),
    `layer/idxTree/idxLeaf` the `.toNat`s of the position params, `N_MASK`, `OUT = 0x600`,
    `digitSum = 0`, and `seed` in scratch `[0,0x20)` — running `wotsBody`:

    * if the digit-sum check fails (`digitSum (extractDigits d) ≠ TargetSum`, `d` the WOTS
      digest), reverts (`.2 = some Halt.reverted`); else
    * falls through and binds `"wotsPk" = wordOf (pad16 wpk)` where
      `Spec.Wots.pkFromSig seed layer tree kp msgHash sigma = some wpk`.

    The per-chain signature values are bound to the calldata loads via `hsig`
    (`sigma.chains[i] = loadValue16 sig (wotsPtr+16i)`) — the bounded, dischargeable
    sigma hypothesis (chain count = L = 43; non-vacuity certified by `wots_pkfromsig_nonvacuous`).
    Composes `wots_digit_hash` + `wots_digit_sum` + `wots_chain_outer_loop` + `wots_pk_compress`. -/
theorem wots_pkfromsig
    (sig : ByteVec Spec.SignatureLen) (vm : VM)
    (seed : ByteVec 32) (layer : UInt32) (tree : UInt64) (kp : UInt32)
    (msgHash : ByteVec 16) (sigma : Spec.Wots.Sigma) (wotsPtr : Nat) (hwp : wotsPtr < 4096)
    (hsig : ∀ i (h : i < sigma.chains.size), sigma.chains[i] = ByteVec.loadValue16 sig (wotsPtr + 16 * i))
    (hseedw : vm.env "seed" = wordOf seed)
    (hwa : vm.env "wotsAdrs" = wordOf (Spec.Adrs.wots layer tree kp))
    (hcn : vm.env "currentNode" = wordOf (ByteVec.pad16 msgHash))
    (hcount : vm.env "count" = wordOf (ByteVec.u32ToB32 sigma.count))
    (hsigbase : vm.env "sigBase" = 0)
    (hsigoff : vm.env "sigOff" = wotsPtr)
    (hlayer : vm.env "layer" = layer.toNat)
    (hidxTree : vm.env "idxTree" = tree.toNat)
    (hidxLeaf : vm.env "idxLeaf" = kp.toNat)
    (hN : vm.env "N_MASK" = NMASK)
    (hOUT : vm.env "OUT" = 0x600)
    (hds0 : vm.env "digitSum" = 0) :
    (if SphincsCVerify.Util.digitSum (SphincsCVerify.Util.extractDigits
          (Spec.wotsDigest seed (Spec.Adrs.wots layer tree kp) (ByteVec.pad16 msgHash) sigma.count))
          ≠ Spec.TargetSum then
        (execList c10Oracle sig wotsBody vm).2 = some Halt.reverted
      else
        (execList c10Oracle sig wotsBody vm).2 = none
        ∧ ∃ wpk, Spec.Wots.pkFromSig seed layer tree kp msgHash sigma = some wpk
            ∧ (execList c10Oracle sig wotsBody vm).1.env "wotsPk" = wordOf (ByteVec.pad16 wpk)) := by
  -- Abbreviate the WOTS adrs and digest (plain `let`-equalities; no goal rewrite).
  obtain ⟨wotsA, hwotsA⟩ : ∃ a, a = Spec.Adrs.wots layer tree kp := ⟨_, rfl⟩
  obtain ⟨d_bv, hd_bv⟩ : ∃ d, d = Spec.wotsDigest seed wotsA (ByteVec.pad16 msgHash) sigma.count := ⟨_, rfl⟩
  -- Rewrite the goal's `wotsDigest seed (Adrs.wots …)` occurrence to the abbreviation `d_bv`.
  rw [show Spec.wotsDigest seed (Spec.Adrs.wots layer tree kp) (ByteVec.pad16 msgHash) sigma.count = d_bv
      from by rw [hd_bv, hwotsA]]
  -- ===== Phase 1: digit hash. `execList_append` splits `wotsDigitHashFragment` off. =====
  unfold wotsBody
  rw [execList_append c10Oracle sig wotsDigitHashFragment _ vm]
  have hwa' : vm.env "wotsAdrs" = wordOf wotsA := by rw [hwotsA]; exact hwa
  obtain ⟨hdhNone, hdhD⟩ := wots_digit_hash sig vm seed wotsA msgHash sigma.count
    hseedw hwa' hcn hcount hOUT
  -- After the digit hash: env "d" = wordOf d_bv, seed re-laid in [0,0x20), all other env vars persist.
  obtain ⟨v1, hv1⟩ : ∃ v1, (execList c10Oracle sig wotsDigitHashFragment vm).1 = v1 := ⟨_, rfl⟩
  -- Rewrite the whole `execList wotsDigitHashFragment vm` pair to `(v1, none)` so the
  -- `execList_append` match reduces (a bare `.2 = none` rewrite cannot fire on the match
  -- scrutinee — this was masked by the pre-seal whnf timeout).
  have hpair : execList c10Oracle sig wotsDigitHashFragment vm = (v1, none) := by
    rw [← hv1, ← hdhNone]
  simp only [hpair]
  -- hdhD : (execList …).1.env "d" = wordOf (wotsDigest seed wotsA (pad16 msgHash) sigma.count); fold to d_bv.
  -- (Keep hdhD in `(execList …).1` form so `hv1d` below closes via `rw [← hv1]; exact hdhD`, consistent
  --  with `hv1seedmem`/`hv1pv`.)
  rw [show Spec.wotsDigest seed wotsA (ByteVec.pad16 msgHash) sigma.count = d_bv from hd_bv.symm] at hdhD
  -- v1's env/mem facts.
  have hv1d : v1.env "d" = wordOf d_bv := by rw [← hv1]; exact hdhD
  have hv1seedmem : ∀ k, k < 32 → v1.mem (0 + k) = seed.data.getD k 0 := by
    intro k hk; rw [← hv1]; exact wotsDigitHashFragment_seed_mem sig vm seed hseedw hOUT k hk
  have hv1pv : ∀ x, x ≠ "d" → v1.env x = vm.env x := by
    intro x hx; rw [← hv1]; exact wotsDigitHashFragment_preserves_var sig vm x hx
  have hv1wa : v1.env "wotsAdrs" = wordOf wotsA := by rw [hv1pv "wotsAdrs" (by decide)]; exact hwa'
  have hv1sigbase : v1.env "sigBase" = 0 := by rw [hv1pv "sigBase" (by decide)]; exact hsigbase
  have hv1sigoff : v1.env "sigOff" = wotsPtr := by rw [hv1pv "sigOff" (by decide)]; exact hsigoff
  have hv1layer : v1.env "layer" = layer.toNat := by rw [hv1pv "layer" (by decide)]; exact hlayer
  have hv1idxTree : v1.env "idxTree" = tree.toNat := by rw [hv1pv "idxTree" (by decide)]; exact hidxTree
  have hv1idxLeaf : v1.env "idxLeaf" = kp.toNat := by rw [hv1pv "idxLeaf" (by decide)]; exact hidxLeaf
  have hv1N : v1.env "N_MASK" = NMASK := by rw [hv1pv "N_MASK" (by decide)]; exact hN
  have hv1OUT : v1.env "OUT" = 0x600 := by rw [hv1pv "OUT" (by decide)]; exact hOUT
  have hv1ds0 : v1.env "digitSum" = 0 := by rw [hv1pv "digitSum" (by decide)]; exact hds0
  -- ===== Phase 2: letv "digitSum" 0 (re-init); then the digit-sum loop. =====
  rw [execList_cons_none c10Oracle sig _ _ _ (by simp only [execStmt])]
  obtain ⟨v2, hv2⟩ : ∃ v2, (execStmt c10Oracle sig (.letv "digitSum" (.lit 0)) v1).1 = v2 := ⟨_, rfl⟩
  rw [hv2]
  have hv2env : v2.env = setVar v1.env "digitSum" 0 := by rw [← hv2]; simp only [execStmt, eval]
  have hv2mem : v2.mem = v1.mem := by rw [← hv2]; simp only [execStmt]
  have hv2d : v2.env "d" = wordOf d_bv := by rw [hv2env, setVar_get_ne _ _ _ _ (by decide)]; exact hv1d
  have hv2ds0 : v2.env "digitSum" = 0 := by rw [hv2env, setVar_get_eq]
  -- The digit-sum forRange statement = execFor … 43 0 v2.
  have hdsStmt : execStmt c10Oracle sig (.forRange "ii" (.lit 43) wotsDigitSumBody) v2
      = execFor c10Oracle sig "ii" wotsDigitSumBody 43 0 v2 := by simp only [execStmt, eval]
  obtain ⟨hsumNone, hsumVal, hsumD⟩ := wots_digit_sum sig v2 d_bv hv2d hv2ds0
  rw [execList_cons_none c10Oracle sig _ _ _ (by rw [hdsStmt]; exact hsumNone), hdsStmt]
  obtain ⟨v3, hv3⟩ : ∃ v3, (execFor c10Oracle sig "ii" wotsDigitSumBody 43 0 v2).1 = v3 := ⟨_, rfl⟩
  rw [hv3]
  -- v3's facts: digitSum = digitSum(extractDigits d_bv), d persists; all non-{ii,digitSum} env persist; mem unchanged.
  have hv3ds : v3.env "digitSum"
      = SphincsCVerify.Util.digitSum (SphincsCVerify.Util.extractDigits d_bv) := by rw [← hv3]; exact hsumVal
  have hv3pv : ∀ x, x ≠ "ii" → x ≠ "digitSum" → v3.env x = v2.env x := by
    intro x h1 h2; rw [← hv3]; exact execFor_wotsDigitSumBody_preserves_var sig x ⟨h1, h2⟩ 43 0 v2
  have hv3mem : ∀ a, v3.mem a = v2.mem a := by intro a; rw [← hv3]; exact execFor_wotsDigitSumBody_mem sig a 43 0 v2
  -- ===== Phase 3: the ifnz revert gate. Case-split on the digit-sum equality. =====
  rw [execList]
  by_cases hgate : SphincsCVerify.Util.digitSum (SphincsCVerify.Util.extractDigits d_bv) = 205
  · -- digit sum = 205 = TargetSum: the ifnz falls through; pkFromSig returns `some`.
    rw [if_neg (show ¬ (SphincsCVerify.Util.digitSum (SphincsCVerify.Util.extractDigits d_bv) ≠ Spec.TargetSum)
      from fun h => h (by rw [hgate]; rfl))]
    have hcondz : execStmt c10Oracle sig
        (.ifnz (.iszero (.bin .eq (.var "digitSum") (.lit 205))) [.revert]) v3 = (v3, none) := by
      unfold execStmt
      rw [if_neg]
      -- side-goal: ¬ (eval (iszero (eq digitSum 205)) ≠ 0); under hgate the digit sum is 205.
      show ¬ eval sig v3 (.iszero (.bin .eq (.var "digitSum") (.lit 205))) ≠ 0
      simp only [eval, hv3ds]
      rw [if_pos hgate]
      decide
    rw [hcondz]
    -- The remaining 7 statements ARE `wotsContTail`; fold the goal to it.
    show (execList c10Oracle sig wotsContTail v3).2 = none
      ∧ ∃ wpk, Spec.Wots.pkFromSig seed layer tree kp msgHash sigma = some wpk
          ∧ (execList c10Oracle sig wotsContTail v3).1.env "wotsPk" = wordOf (ByteVec.pad16 wpk)
    -- v3 const facts (inherited through digitSum re-init + the sum loop).
    have hv3d : v3.env "d" = wordOf d_bv := by rw [hv3pv "d" (by decide) (by decide), hv2d]
    have hv3wa : v3.env "wotsAdrs" = wordOf (Spec.Adrs.wots layer tree kp) := by
      rw [hv3pv "wotsAdrs" (by decide) (by decide), hv2env, setVar_get_ne _ _ _ _ (by decide), ← hwotsA]; exact hv1wa
    have hv3sigbase : v3.env "sigBase" = 0 := by
      rw [hv3pv "sigBase" (by decide) (by decide), hv2env, setVar_get_ne _ _ _ _ (by decide)]; exact hv1sigbase
    have hv3sigoff : v3.env "sigOff" = wotsPtr := by
      rw [hv3pv "sigOff" (by decide) (by decide), hv2env, setVar_get_ne _ _ _ _ (by decide)]; exact hv1sigoff
    have hv3layer : v3.env "layer" = layer.toNat := by
      rw [hv3pv "layer" (by decide) (by decide), hv2env, setVar_get_ne _ _ _ _ (by decide)]; exact hv1layer
    have hv3idxTree : v3.env "idxTree" = tree.toNat := by
      rw [hv3pv "idxTree" (by decide) (by decide), hv2env, setVar_get_ne _ _ _ _ (by decide)]; exact hv1idxTree
    have hv3idxLeaf : v3.env "idxLeaf" = kp.toNat := by
      rw [hv3pv "idxLeaf" (by decide) (by decide), hv2env, setVar_get_ne _ _ _ _ (by decide)]; exact hv1idxLeaf
    have hv3N : v3.env "N_MASK" = NMASK := by
      rw [hv3pv "N_MASK" (by decide) (by decide), hv2env, setVar_get_ne _ _ _ _ (by decide)]; exact hv1N
    have hv3OUT : v3.env "OUT" = 0x600 := by
      rw [hv3pv "OUT" (by decide) (by decide), hv2env, setVar_get_ne _ _ _ _ (by decide)]; exact hv1OUT
    have hv3seedmem : ∀ k, k < 32 → v3.mem (0 + k) = seed.data.getD k 0 := by
      intro k hk; rw [hv3mem (0 + k), hv2mem]; exact hv1seedmem k hk
    -- The heavy chain-loop + PK-compress block (own heartbeat budget).
    obtain ⟨htailNone, htailVal⟩ := wots_cont_tail sig v3 seed layer tree kp d_bv wotsPtr hwp
      hv3d hv3wa hv3sigbase hv3sigoff hv3layer hv3idxTree hv3idxLeaf hv3N hv3OUT hv3seedmem
    refine ⟨htailNone, ?_⟩
    -- pkFromSig = some (thMulti seed (wotsPk …) (wotsEndptList …)); the bridge (own budget).
    refine ⟨Spec.thMulti seed (Spec.Adrs.wotsPk layer tree kp) (wotsEndptList seed layer tree kp d_bv sig wotsPtr), ?_, htailVal⟩
    -- `d_bv = wotsDigest seed (Adrs.wots layer tree kp) (pad16 msgHash) sigma.count` (fold both abbrevs).
    have hd_bv' : d_bv = Spec.wotsDigest seed (Spec.Adrs.wots layer tree kp) (ByteVec.pad16 msgHash) sigma.count := by
      rw [hd_bv, hwotsA]
    rw [hd_bv']
    exact pkFromSig_eq sig seed layer tree kp msgHash sigma wotsPtr hsig
      (by rw [← hd_bv']; exact hgate)
  · -- digit sum ≠ 205: the ifnz reverts; `execList_append` short-circuit gives `some Halt.reverted`.
    rw [if_pos (show SphincsCVerify.Util.digitSum (SphincsCVerify.Util.extractDigits d_bv) ≠ Spec.TargetSum
      from fun h => hgate (by rw [h]; rfl))]
    have hcondnz : execStmt c10Oracle sig
        (.ifnz (.iszero (.bin .eq (.var "digitSum") (.lit 205))) [.revert]) v3
        = (v3, some Halt.reverted) := by
      unfold execStmt
      rw [if_pos]
      · simp only [execList, execStmt]
      · show eval sig v3 (.iszero (.bin .eq (.var "digitSum") (.lit 205))) ≠ 0
        simp only [eval, hv3ds]
        rw [if_neg (show ¬ (SphincsCVerify.Util.digitSum (SphincsCVerify.Util.extractDigits d_bv) = 205)
          from hgate)]
        decide
    rw [hcondnz]

set_option maxHeartbeats 16000000 in
set_option maxRecDepth 8000 in
/-- **Non-vacuity certificate for `wots_pkfromsig`.** The bounded sigma hypothesis `hsig`
    is dischargeable with a concrete witness — `sigma.chains := Array.ofFn (loadValue16 …)`
    (size = L = 43, so `chainsLen` holds; the dependent getElem matches the calldata load) —
    and every env precondition is satisfiable (a concrete `env0`/`vm0`). Mirrors
    `fors_tree_body_nonvacuous`: the mere elaboration of `wots_pkfromsig` applied to these
    witnesses is the certificate (no `∀`-over-Nat hypothesis is left unsatisfiable). -/
private theorem wots_pkfromsig_nonvacuous (sig : ByteVec Spec.SignatureLen) (seed : ByteVec 32) :
    True := by
  let sigma : Spec.Wots.Sigma :=
    { chains := Array.ofFn (n := 43) (fun i : Fin 43 => ByteVec.loadValue16 sig (0 + 16 * i.val))
      chainsLen := by rw [Array.size_ofFn]; rfl
      count := ByteVec.loadU32BE sig 688 }
  let env0 : VarEnv :=
    setVar (setVar (setVar (setVar (setVar (setVar (setVar (setVar (setVar (setVar (setVar
      (setVar (fun _ => 0)
      "seed" (wordOf seed))
      "wotsAdrs" (wordOf (Spec.Adrs.wots 0 0 0)))
      "currentNode" (wordOf (ByteVec.pad16 (ByteVec.zero 16))))
      "count" (wordOf (ByteVec.u32ToB32 sigma.count)))
      "sigBase" 0)
      "sigOff" 0)
      "layer" ((0 : UInt32).toNat))
      "idxTree" ((0 : UInt64).toNat))
      "idxLeaf" ((0 : UInt32).toNat))
      "N_MASK" NMASK)
      "OUT" 0x600)
      "digitSum" 0
  let vm0 : VM := { mem := memOfBytes seed, env := env0 }
  have _inst := wots_pkfromsig sig vm0 seed 0 0 0 (ByteVec.zero 16) sigma 0 (by decide)
    (fun i h => by
      show (Array.ofFn (n := 43) (fun j : Fin 43 => ByteVec.loadValue16 sig (0 + 16 * j.val)))[i] = _
      rw [Array.getElem_ofFn])
    (by show env0 "seed" = wordOf seed; simp [env0, setVar])
    (by show env0 "wotsAdrs" = wordOf (Spec.Adrs.wots 0 0 0); simp [env0, setVar])
    (by show env0 "currentNode" = wordOf (ByteVec.pad16 (ByteVec.zero 16)); simp [env0, setVar])
    (by show env0 "count" = wordOf (ByteVec.u32ToB32 sigma.count); simp [env0, setVar])
    (by show env0 "sigBase" = 0; simp [env0, setVar])
    (by show env0 "sigOff" = 0; simp [env0, setVar])
    (by show env0 "layer" = (0 : UInt32).toNat; simp [env0, setVar])
    (by show env0 "idxTree" = (0 : UInt64).toNat; simp [env0, setVar])
    (by show env0 "idxLeaf" = (0 : UInt32).toNat; simp [env0, setVar])
    (by show env0 "N_MASK" = NMASK; simp [env0, setVar])
    (by show env0 "OUT" = 0x600; simp [env0, setVar])
    (by show env0 "digitSum" = 0; simp [env0, setVar])
  trivial

end SphincsCVerify.Interpreter.C10

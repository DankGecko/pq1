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
    (H_adrs : ∀ h p, tBase ||| (((h + 1) % W) <<< 32 % W ||| p >>> 1)
        = wordOf (Spec.Adrs.forsNode htIdx treeIdx (UInt32.ofNat (h + 1)) (UInt32.ofNat (p / 2))))
    (H_sib : ∀ h, calldataload sig ((auth + h <<< 4 % W) % W) &&& NMASK
        = wordOf (ByteVec.pad16 (authPath.getD h (ByteVec.zero 16))))
    (cur : Nat) (w : VM)
    (hR : w.env "node"
            = wordOf (ByteVec.pad16 (forsAcc seed htIdx treeIdx leafIdx secret authPath cur).fst)
          ∧ w.env "pathIdx" = (forsAcc seed htIdx treeIdx leafIdx secret authPath cur).snd
          ∧ w.env "N_MASK" = NMASK ∧ w.env "OUT" = 0x600
          ∧ w.env "treeAdrsBase" = tBase ∧ w.env "authPtr" = auth
          ∧ (∀ i, i < 32 → w.mem (0 + i) = seed.data.getD i 0)) :
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
              = seed.data.getD i 0)) := by
  obtain ⟨hRnode, hRpath, hRN, hROUT, hRtB, hRauth, hRseed⟩ := hR
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
  rw [H_adrs cur (forsAcc seed htIdx treeIdx leafIdx secret authPath cur).snd, H_sib cur]
  -- Resolve the parity `s` into {0, 32}.
  rw [s_value]
  refine ⟨?node, ?path, trivial, trivial, trivial, trivial, ?mem⟩
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
    -- byte-layout obligations (wrapper-discharged)
    (H_adrs : ∀ h p, tBase ||| (((h + 1) % W) <<< 32 % W ||| p >>> 1)
        = wordOf (Spec.Adrs.forsNode htIdx treeIdx (UInt32.ofNat (h + 1)) (UInt32.ofNat (p / 2))))
    (H_sib : ∀ h, calldataload sig ((auth + h <<< 4 % W) % W) &&& NMASK
        = wordOf (ByteVec.pad16 (authPath.getD h (ByteVec.zero 16)))) :
    (execFor c10Oracle sig "h" forsClimbBody Spec.A 0 vm).2 = none
    ∧ ((execFor c10Oracle sig "h" forsClimbBody Spec.A 0 vm).1).env "node"
        = wordOf (ByteVec.pad16
            (Spec.Fors.reconstructRoot seed htIdx treeIdx leafIdx secret authPath))
    -- The seed scratch window persists across the whole climb (every store lands at ≥ 0x20),
    -- so the outer FORS i-loop's seed invariant carries to the next tree.
    ∧ (∀ i, i < 32 → ((execFor c10Oracle sig "h" forsClimbBody Spec.A 0 vm).1).mem (0 + i)
        = seed.data.getD i 0) := by
  -- The loop invariant: node/pathIdx track the spec fold; consts + seed persist.
  let R : Nat → VM → Prop := fun c w =>
    w.env "node" = wordOf (ByteVec.pad16 (forsAcc seed htIdx treeIdx leafIdx secret authPath c).fst)
    ∧ w.env "pathIdx" = (forsAcc seed htIdx treeIdx leafIdx secret authPath c).snd
    ∧ w.env "N_MASK" = NMASK ∧ w.env "OUT" = 0x600
    ∧ w.env "treeAdrsBase" = tBase ∧ w.env "authPtr" = auth
    ∧ (∀ i, i < 32 → w.mem (0 + i) = seed.data.getD i 0)
  have hstep : ∀ cur w, R cur w →
      (execList c10Oracle sig forsClimbBody { w with env := setVar w.env "h" cur }).2 = none ∧
      R (cur + 1) (execList c10Oracle sig forsClimbBody { w with env := setVar w.env "h" cur }).1 :=
    fors_climb_step sig seed htIdx treeIdx leafIdx secret authPath tBase auth H_adrs H_sib
  -- R holds at entry (cur = 0): the empty fold is forsAccInit.
  have hR0 : R 0 vm := by
    refine ⟨?_, ?_, hNMASK, hOUT, htBase, hAuth, hseed⟩
    · show vm.env "node"
          = wordOf (ByteVec.pad16 (forsAcc seed htIdx treeIdx leafIdx secret authPath 0).fst)
      rw [hnode, forsAcc_zero]; rfl
    · show vm.env "pathIdx" = (forsAcc seed htIdx treeIdx leafIdx secret authPath 0).snd
      rw [hpath, forsAcc_zero]; rfl
  -- Drive the loop.
  have hloop := execFor_invariant c10Oracle sig "h" forsClimbBody R hstep Spec.A 0 vm hR0
  obtain ⟨hn, _, _, _, _, _, hmemfinal⟩ := hloop.2
  refine ⟨hloop.1, ?_, hmemfinal⟩
  -- The final node is wordOf (pad16 (acc A).fst); (acc A).fst = reconstructRoot via Layer 2.
  rw [hn]
  show wordOf (ByteVec.pad16 (forsAcc seed htIdx treeIdx leafIdx secret authPath (0 + Spec.A)).fst) = _
  rw [Nat.zero_add, reconstructRoot_eq_foldl]
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
    `reconstructForsPk` value; `H_sib` is the same shape `fors_climb` consumes). -/
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
    (H_adrs : ∀ h p,
        ((htIdx.toNat <<< 160 % W) ||| ((3 <<< 128 % W) ||| (t <<< 96 % W)))
          ||| (((h + 1) % W) <<< 32 % W ||| p >>> 1)
        = wordOf (Spec.Adrs.forsNode htIdx (UInt32.ofNat t) (UInt32.ofNat (h + 1))
            (UInt32.ofNat (p / 2))))
    (H_sib : ∀ h, calldataload sig (((224 + t * 176) + h <<< 4 % W) % W) &&& NMASK
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

end SphincsCVerify.Interpreter.C10

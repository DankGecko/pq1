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

end SphincsCVerify.Interpreter.C10

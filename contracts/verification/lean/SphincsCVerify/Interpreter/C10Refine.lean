/-
SphincsCVerify.Interpreter.C10Refine — the grand composition (full-(a) step 4).

Glues the three phase capstones (`hmsg_digest`, `fors_phase`,
`verifyHypertree_refine`) into the end-to-end interpreter-refinement theorem

  `execC10Asm pkSeed pkRoot message sig
     = nMaskedB pkSeed && nMaskedB pkRoot
       && verifyYulModel pkSeed pkRoot message sig`

i.e. the deployed Yul verifier (transcribed in `C10Program.lean`) computes
exactly the declarative spec `Spec.Signature.verify` (via `verifyYulModel`),
with the two leading N-mask guards exposed as the `nMaskedB` Bool factors.

The N-mask factors are NOT cosmetic: the deployed Yul rejects (returns `false`)
any `pkSeed`/`pkRoot` whose bottom 16 bytes are non-zero, BEFORE running the
verification body. `verifyYulModel` (= `Spec.Signature.verify ⟨pkSeed.take16,
pkRoot.take16⟩ …`) silently truncates instead, so the faithful equality must
carry the guards.

See `docs/A3_1_CLOSURE_PATH.md` §8 step 4 and
`memory/project_a31_full_a_progress.md`.
-/

import SphincsCVerify.Interpreter.HypertreePhase
import SphincsCVerify.Bridge.SolidityVerifier

namespace SphincsCVerify.Interpreter.C10

open SphincsCVerify.Interpreter
open SphincsCVerify.Spec (ByteVec)
open SphincsCVerify.Bridge (verifyYulModel)

-- The phase capstones are consumed as opaque equations; replicate the
-- HypertreePhase seals so no stray `simp`/`rfl`/`decide` whnf's through the
-- heavy spec calls (the step-3 isDefEq-blowup insurance).
attribute [local irreducible] Spec.Wots.pkFromSig Spec.Hypertree.verifyAuthPath
  Spec.wotsDigest Spec.chainHash SphincsCVerify.Util.digitSum SphincsCVerify.Util.extractDigits
  Spec.Adrs.wots Spec.Adrs.treeNode

/-! ## Keystone: `c10Program` decomposes into the phase fragments.

A single `rfl` validates that the inlined `c10Program` (statement-for-statement
mirror of `SPHINCsC10Asm.sol`) is definitionally the concatenation of the
prefix guards, `hmsgFragment`, `forsPhaseFragment`, and the hypertree tail —
through every fragment def down to `wotsBody` / `htLayerBody`. -/
theorem c10Program_decompose :
    c10Program =
      [ .letv "N_MASK" (.lit 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000000000000000000000000000)
      , .letv "OUT" (.lit 0x600)
      , .ifnz (.iszero (.bin .eq .sigLength (.lit 4008))) [ .revert ]
      , .ifnz (.iszero (.bin .eq (.bin .band (.var "pkSeed") (.var "N_MASK")) (.var "pkSeed")))
          [ .mstore (.lit 0x00) (.lit 0), .ret (.lit 0x00) ]
      , .ifnz (.iszero (.bin .eq (.bin .band (.var "pkRoot") (.var "N_MASK")) (.var "pkRoot")))
          [ .mstore (.lit 0x00) (.lit 0), .ret (.lit 0x00) ] ]
      ++ (hmsgFragment
      ++ (forsPhaseFragment
      ++ [ .letv "currentNode" (.var "forsPk")
         , .letv "idxTree" (.var "htIdx")
         , .letv "sigOff" (.lit 2336)
         , .forRange "layer" (.lit 2) htLayerBody
         , .letv "valid" (.bin .eq (.var "currentNode") (.var "root"))
         , .mstore (.lit 0x00) (.var "valid")
         , .ret (.lit 0x00) ])) := by rfl

/-! ## Shared byte-level glue

`wordOf` injectivity and the N-mask byte bridge are load-bearing in two places
each (the N-mask guards feeding the phase shape hypotheses; the final
root-equality compare). Established once here. -/

/-- **ByteVec extensionality from pointwise `getD`.** Two same-length `ByteVec`s
    are equal if every in-range byte (read via `getD … 0`) agrees. -/
theorem byteVec_ext_getD {n : Nat} {a b : ByteVec n}
    (h : ∀ i, i < n → a.data.getD i 0 = b.data.getD i 0) : a = b := by
  apply ByteVec.ext_data
  have hsz : a.data.size = b.data.size := by rw [a.size_eq, b.size_eq]
  apply Array.ext hsz
  intro i hi1 _
  have hin : i < n := by rw [a.size_eq] at hi1; exact hi1
  have hgd := h i hin
  rwa [Array.getD_eq_getD_getElem?, Array.getElem?_eq_getElem hi1, Option.getD_some,
       Array.getD_eq_getD_getElem?, Array.getElem?_eq_getElem (hsz ▸ hi1), Option.getD_some] at hgd

/-- **`wordOf` is injective on `ByteVec 32`.** The big-endian word determines
    every byte (`beByte_wordOf_getD`), so equal words ⇒ equal vectors. -/
theorem wordOf_inj {a b : ByteVec 32} (h : wordOf a = wordOf b) : a = b := by
  apply byteVec_ext_getD
  intro i hi
  rw [← beByte_wordOf_getD a i hi, ← beByte_wordOf_getD b i hi, h]

/-- The deployed Yul N-mask guard, as a Bool: `pkSeed & N_MASK == pkSeed` at the
    word level (`SPHINCsC10Asm.sol` L58-65). The guard returns `false` (the whole
    verifier) when this is `false`. -/
def nMaskedB (key : ByteVec 32) : Bool := decide (wordOf key &&& NMASK = wordOf key)

/-- **N-mask byte bridge.** The word-level guard `pkSeed & N_MASK = pkSeed`
    forces the byte-level N-mask SHAPE `pkSeed = pad16 (truncate16 pkSeed)` (top
    16 bytes preserved, bottom 16 zero) — exactly the `hShape` hypothesis the
    `hmsg_digest` phase consumes (`truncate16 key` is defeq `key.take 16 _`). -/
theorem nMaskedB_shape {key : ByteVec 32} (h : nMaskedB key = true) :
    key = ByteVec.pad16 (ByteVec.truncate16 key) := by
  have hmask : wordOf key &&& NMASK = wordOf key := of_decide_eq_true h
  apply byteVec_ext_getD
  intro i hi
  rw [pad16tr_getD]
  by_cases h16 : i < 16
  · rw [if_pos h16]
  · rw [if_neg h16]
    have hbe : beByte (wordOf key &&& NMASK) i = beByte (wordOf key) i := by rw [hmask]
    rw [beByte_and_nmask, if_neg h16] at hbe
    rw [← beByte_wordOf_getD key i hi]
    exact hbe.symm

/-- **`wordOf ∘ pad16` is injective on `ByteVec 16`** — the final root compare
    `wordOf(pad16 finalNode) = wordOf(pad16 pkRoot16) ↔ finalNode = pkRoot16`. -/
theorem pad16_wordOf_inj {a b : ByteVec 16}
    (h : wordOf (ByteVec.pad16 a) = wordOf (ByteVec.pad16 b)) : a = b := by
  have hp : ByteVec.pad16 a = ByteVec.pad16 b := wordOf_inj h
  apply byteVec_ext_getD
  intro i hi
  have hd : (ByteVec.pad16 a).data.getD i 0 = (ByteVec.pad16 b).data.getD i 0 := by rw [hp]
  rwa [pad16_data_getD, pad16_data_getD, if_pos hi, if_pos hi] at hd

/-! ## hmsg seed-memory

`hmsg_digest` exposes only `env "digest"`; the FORS and hypertree phases also
require the `[0,32)` seed window to hold `seed`'s bytes. `hmsgFragment` lays
`mstore 0x00 seed` (statement 3) and every later store targets ≥ 0x20 (and the
precompile writes `OUT = 0x600`), so the window survives as `seed = pkSeed`. -/
theorem hmsg_seed_mem (sig : ByteVec Spec.SignatureLen) (vm : VM)
    (hOUT : vm.env "OUT" = 0x600) (i : Nat) (hi : i < 32) :
    (execList c10Oracle sig hmsgFragment vm).1.mem (0 + i) = beByte (vm.env "pkSeed") i := by
  unfold hmsgFragment
  rw [execList_cons_none c10Oracle sig _ _ vm (by simp only [execStmt])]
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
  simp only [execStmt, eval, setVar, hOUT, ite_true, ite_false, String.reduceEq]
  -- Frame `0 + i` (< 0x20) through the high writes (sha256 OUT=0x600; mstores at
  -- 0x80/0x60/0x40/0x20), landing on the 0x00 seed store via `mstore32_get`.
  rw [writeRegion_frame _ 1536 _ (0 + i) (by omega),
      mstore32_frame _ 128 _ (0 + i) (by omega),
      mstore32_frame _ 96 _ (0 + i) (by omega),
      mstore32_frame _ 64 _ (0 + i) (by omega),
      mstore32_frame _ 32 _ (0 + i) (by omega),
      mstore32_get _ 0 _ i hi]

/-- `seed` is set by `hmsgFragment`'s head `letv` to `pkSeed`, never reassigned. -/
theorem hmsg_post_seed (sig : ByteVec Spec.SignatureLen) (vm : VM) :
    (execList c10Oracle sig hmsgFragment vm).1.env "seed" = vm.env "pkSeed" := by
  unfold hmsgFragment
  rw [execList]
  simp only [execStmt]
  refine Eq.trans (execList_env_frame c10Oracle sig _ "seed" _ ?_) ?_
  · decide
  · simp only [eval, setVar, ite_true]

/-- `root` is set by `hmsgFragment`'s second `letv` to `pkRoot`, never reassigned. -/
theorem hmsg_post_root (sig : ByteVec Spec.SignatureLen) (vm : VM) :
    (execList c10Oracle sig hmsgFragment vm).1.env "root" = vm.env "pkRoot" := by
  unfold hmsgFragment
  rw [execList]; simp only [execStmt]
  rw [execList]; simp only [execStmt]
  refine Eq.trans (execList_env_frame c10Oracle sig _ "root" _ ?_) ?_
  · decide
  · simp only [eval, setVar, ite_true, String.reduceEq, ite_false]

/-! ## FORS-phase post-conditions

`fors_phase` exposes only `forsPk`/revert; the hypertree phase also needs the
loop-invariant env vars (`seed`/`N_MASK`/`OUT`/`root`) and the FORS-set vars
(`htIdx`/`sigBase`). Read-only vars come from the generic env-frame; the set
vars from a head-split + env-frame on the tail. -/

/-- `htIdx` is set by `forsPhaseFragment`'s head `letv` (always — before any
    revert) and never reassigned, so it ends as `extractHtIndex digest`. -/
theorem fors_post_htIdx (sig : ByteVec Spec.SignatureLen) (vm : VM) (digest_bv : ByteVec 32)
    (hdig : vm.env "digest" = wordOf digest_bv) :
    (execList c10Oracle sig forsPhaseFragment vm).1.env "htIdx"
      = SphincsCVerify.Util.extractHtIndex digest_bv := by
  unfold forsPhaseFragment
  rw [execList]
  simp only [execStmt]
  refine Eq.trans (execList_env_frame c10Oracle sig _ "htIdx" _ ?_) ?_
  · decide
  · simp only [eval, setVar, ite_true]
    rw [hdig, extractHtIndex_eq_wordShift digest_bv]

/-- The read-only env vars (`seed`/`root`/`N_MASK`/`OUT`/`message`) are assigned
    nowhere in `forsPhaseFragment`, so they survive unchanged. -/
theorem fors_post_const (sig : ByteVec Spec.SignatureLen) (vm : VM)
    (x : String) (hx : assignsVarList forsPhaseFragment x = false) :
    (execList c10Oracle sig forsPhaseFragment vm).1.env x = vm.env x :=
  execList_env_frame c10Oracle sig forsPhaseFragment x vm hx

/-- Phase composition, fall-through arm: if `xs` runs without halting to `vm'`,
    then `xs ++ ys` continues into `ys` from `vm'`. -/
theorem execList_append_none {n : Nat} (sha : List UInt8 → Spec.ByteVec 32) (sig : Spec.ByteVec n)
    (xs ys : List Stmt) (vm vm' : VM) (h : execList sha sig xs vm = (vm', none)) :
    execList sha sig (xs ++ ys) vm = execList sha sig ys vm' := by
  rw [execList_append, h]

/-- Phase composition, halt arm: if `xs` halts at `vm'` with `hh`, so does `xs ++ ys`. -/
theorem execList_append_halt {n : Nat} (sha : List UInt8 → Spec.ByteVec 32) (sig : Spec.ByteVec n)
    (xs ys : List Stmt) (vm vm' : VM) (hh : Halt) (h : execList sha sig xs vm = (vm', some hh)) :
    execList sha sig (xs ++ ys) vm = (vm', some hh) := by
  rw [execList_append, h]

/-- An `ifnz cond [revert]` statement leaves the VM unchanged and halts (`some
    reverted`) iff the condition is non-zero. Reused by the sig-length guard and
    the FORS forced-zero gate. -/
theorem execStmt_ifnz_revert {n : Nat} (sha : List UInt8 → Spec.ByteVec 32) (sig : Spec.ByteVec n)
    (cond : Expr) (vm : VM) :
    execStmt sha sig (.ifnz cond [.revert]) vm
      = (vm, if eval sig vm cond = 0 then none else some Halt.reverted) := by
  unfold execStmt
  by_cases h : eval sig vm cond = 0
  · rw [if_neg (not_not_intro h), if_pos h]
  · rw [if_pos h, if_neg h]
    simp only [execList, execStmt]

/-- `sigBase` is set to `sig.offset = 0` at FORS statement 4; given the FORS
    phase did not halt (`.2 = none`, the pass case), it ends as `0`. Split the
    fragment at the forced-zero gate: if the prefix (through the gate) halts, the
    whole phase halts (contradicting `hnone`); otherwise the `sigBase` letv runs. -/
theorem fors_post_sigBase (sig : ByteVec Spec.SignatureLen) (vm : VM)
    (hnone : (execList c10Oracle sig forsPhaseFragment vm).2 = none) :
    (execList c10Oracle sig forsPhaseFragment vm).1.env "sigBase" = 0 := by
  have hsplit : forsPhaseFragment
      = [ .letv "htIdx" (.bin .band (.bin .shr (.lit 143) (.var "digest")) (.lit 0x3FFFF))
        , .letv "dVal" (.var "digest")
        , .ifnz (.bin .band (.bin .shr (.lit 132) (.var "dVal")) (.lit 0x7FF)) [ .revert ] ]
        ++ [ .letv "sigBase" .sigOffset
           , .forRange "i" (.lit 12) forsTreeBody
           , .block forsLastTreeBody
           , .mstore (.lit 0x20)
               (.bin .bor (.bin .shl (.lit 160) (.var "htIdx")) (.bin .shl (.lit 128) (.lit 4)))
           , .forRange "i" (.lit 13) forsCopyBody
           , .sha256 (.lit 0x00) (.lit 0x1E0) (.var "OUT")
           , .letv "forsPk" (.bin .band (.mload (.var "OUT")) (.var "N_MASK")) ] := rfl
  rw [hsplit] at hnone ⊢
  cases hpre : execList c10Oracle sig
      [ .letv "htIdx" (.bin .band (.bin .shr (.lit 143) (.var "digest")) (.lit 0x3FFFF))
      , .letv "dVal" (.var "digest")
      , .ifnz (.bin .band (.bin .shr (.lit 132) (.var "dVal")) (.lit 0x7FF)) [ .revert ] ] vm with
  | mk vm3 o3 =>
    cases o3 with
    | some h => rw [execList_append_halt _ _ _ _ _ _ _ hpre] at hnone; exact absurd hnone (by simp)
    | none =>
      rw [execList_append_none _ _ _ _ _ _ hpre]
      rw [execList_cons_none c10Oracle sig _ _ vm3 (by simp only [execStmt])]
      rw [execList_env_frame c10Oracle sig _ "sigBase" _ (by decide)]
      simp only [execStmt, eval, setVar, ite_true]

/-! ## The spec target, unfolded

`verifyYulModel` is a def-alias chain down to `Hypertree.verify`; unfold it to the
`verifyWithDigest` form the spine's case analysis matches (digest → FORS gate →
`verifyHypertree` → root compare). All `def`-unfolding (no sealed body touched). -/
theorem verifyYulModel_unfold (pkSeed pkRoot message : ByteVec 32)
    (sig : ByteVec Spec.SignatureLen) :
    verifyYulModel pkSeed pkRoot message sig
      = Spec.Hypertree.verifyWithDigest (ByteVec.pad16 (ByteVec.truncate16 pkSeed))
          (ByteVec.truncate16 pkRoot)
          (Spec.hMsg (ByteVec.pad16 (ByteVec.truncate16 pkSeed))
            (ByteVec.pad16 (ByteVec.truncate16 pkRoot))
            (ByteVec.pad16 (Spec.Signature.deserialise sig).r) message)
          (Spec.Signature.deserialise sig) := rfl

/-! ## Hbind discharge from `deserialise`

`verifyHypertree_refine` takes a binding hypothesis `Hbind` relating the structured
layer fields back to the raw calldata offsets. For `(deserialise sig).layers` these
hold mechanically: chains/authPath are `loadValue16` at the matching offsets
(`cl_masked_eq_wordOf`), the size is `Array.size_ofFn`, and the count is the
separately-supplied bridge (`count_bridge`). -/

/-- The `k`-th deserialised layer (`k < 2`), with its three `ofFn` fields exposed. -/
theorem deserialise_layer (sig : ByteVec Spec.SignatureLen) (k : Nat) (hk : k < 2) :
    (Spec.Signature.deserialise sig).layers.getD k Spec.Hypertree.defaultLayerSig
      = { wots := { chains := Array.ofFn (n := Spec.L) (fun i : Fin Spec.L =>
                      ByteVec.loadValue16 sig (Spec.SigForsTotal + k * Spec.SigHtLayer + i.val * Spec.N)),
                    chainsLen := Array.size_ofFn,
                    count := ByteVec.loadU32BE sig
                      (Spec.SigForsTotal + k * Spec.SigHtLayer + Spec.L * Spec.N) },
          authPath := Array.ofFn (n := Spec.SubtreeH) (fun h : Fin Spec.SubtreeH =>
                        ByteVec.loadValue16 sig
                          (Spec.SigForsTotal + k * Spec.SigHtLayer + Spec.L * Spec.N + 4 + h.val * Spec.N)),
          authPathLen := Array.size_ofFn } := by
  unfold Spec.Signature.deserialise
  rw [Array.getD_eq_getD_getElem?, Array.getElem?_ofFn, dif_pos (show k < Spec.D from hk)]
  rfl

theorem htLayers_satisfy_Hbind (sig : ByteVec Spec.SignatureLen)
    (hcount : ∀ k, k < 2 → calldataload sig (2336 + 836 * k + 688) >>> 224
        = wordOf (ByteVec.u32ToB32 (((Spec.Signature.deserialise sig).layers.getD k
            Spec.Hypertree.defaultLayerSig).wots).count)) :
    ∀ k, k < 2 →
      (∀ i (h : i < (((Spec.Signature.deserialise sig).layers.getD k
            Spec.Hypertree.defaultLayerSig).wots).chains.size),
          (((Spec.Signature.deserialise sig).layers.getD k Spec.Hypertree.defaultLayerSig).wots).chains[i]
            = ByteVec.loadValue16 sig (2336 + 836 * k + 16 * i))
      ∧ (calldataload sig (2336 + 836 * k + 688) >>> 224
          = wordOf (ByteVec.u32ToB32 (((Spec.Signature.deserialise sig).layers.getD k
              Spec.Hypertree.defaultLayerSig).wots).count))
      ∧ (∀ hh, hh < Spec.SubtreeH →
          calldataload sig (((2336 + 836 * k + 692) + hh <<< 4 % W) % W) &&& NMASK
            = wordOf (ByteVec.pad16 ((((Spec.Signature.deserialise sig).layers.getD k
                Spec.Hypertree.defaultLayerSig).authPath).getD hh (ByteVec.zero 16))))
      ∧ (((Spec.Signature.deserialise sig).layers.getD k
            Spec.Hypertree.defaultLayerSig).authPath.size = Spec.SubtreeH) := by
  intro k hk
  refine ⟨?_, hcount k hk, ?_, ?_⟩
  · -- chains
    intro i hi
    simp only [deserialise_layer sig k hk, Array.getElem_ofFn]
    congr 1
    rw [Spec.sigForsTotal_eq_2336, Spec.sigHtLayer_eq_836, show Spec.N = 16 from rfl]
    omega
  · -- authPath
    intro hh hhlt
    have hh9 : hh < 9 := by have : Spec.SubtreeH = 9 := rfl; omega
    have hofflt : (2336 + 836 * k + 692) + 16 * hh < W := lt_W_of_lt (by omega)
    have hRHS : (((Spec.Signature.deserialise sig).layers.getD k
          Spec.Hypertree.defaultLayerSig).authPath).getD hh (ByteVec.zero 16)
        = ByteVec.loadValue16 sig
            (Spec.SigForsTotal + k * Spec.SigHtLayer + Spec.L * Spec.N + 4 + hh * Spec.N) := by
      rw [deserialise_layer sig k hk, Array.getD_eq_getD_getElem?, Array.getElem?_ofFn,
          dif_pos (show hh < Spec.SubtreeH from hhlt), Option.getD_some]
    have hoffeq : Spec.SigForsTotal + k * Spec.SigHtLayer + Spec.L * Spec.N + 4 + hh * Spec.N
        = (2336 + 836 * k + 692) + 16 * hh := by
      rw [Spec.sigForsTotal_eq_2336, Spec.sigHtLayer_eq_836, show Spec.N = 16 from rfl,
          show Spec.L = 43 from rfl]; omega
    rw [hRHS, hoffeq, shl4_small hh (by omega), Nat.mod_eq_of_lt hofflt, cl_masked_eq_wordOf]
  · -- size
    rw [deserialise_layer sig k hk]; exact Array.size_ofFn

/-- Package a `.1`/`.2`-fall-through pair into a single equality. -/
theorem execList_pair {n : Nat} (sha : List UInt8 → Spec.ByteVec 32) (sig : Spec.ByteVec n)
    (stmts : List Stmt) (vm v : VM) (h1 : (execList sha sig stmts vm).1 = v)
    (h2 : (execList sha sig stmts vm).2 = none) :
    execList sha sig stmts vm = (v, none) := by rw [← h1, ← h2]

/-- A halting head statement halts the whole list (with the same halt outcome). -/
theorem execList_cons_halt {n : Nat} (sha : List UInt8 → Spec.ByteVec 32) (sig : Spec.ByteVec n)
    (s : Stmt) (rest : List Stmt) (vm : VM) (hh : Halt)
    (h : (execStmt sha sig s vm).2 = some hh) :
    (execList sha sig (s :: rest) vm).2 = some hh := by
  rw [execList]
  rcases hst : execStmt sha sig s vm with ⟨vm', o⟩
  rw [hst] at h
  simp only at h
  subst h
  rfl

/-- Phase composition, halt arm via `.2`: a halting `xs` halts `xs ++ ys`. -/
theorem execList_append_halt2 {n : Nat} (sha : List UInt8 → Spec.ByteVec 32) (sig : Spec.ByteVec n)
    (xs ys : List Stmt) (vm : VM) (hh : Halt) (h : (execList sha sig xs vm).2 = some hh) :
    (execList sha sig (xs ++ ys) vm).2 = some hh := by
  rw [execList_append]
  rcases hp : execList sha sig xs vm with ⟨vm', o⟩
  rw [hp] at h
  simp only at h
  subst h
  rfl

/-! ## Prefix guards

`c10Program`'s prefix is two scratch `letv`s + three guards: a (dead) sig-length
guard and the two N-mask guards. Each guard is VM-preserving when it passes and
returns `0` (→ verdict `false`) when it fails. -/

/-- The sig-length guard always passes (our `ByteVec` has length `SignatureLen = 4008`). -/
theorem sigLen_guard_pass (sig : ByteVec Spec.SignatureLen) (vm : VM) :
    execStmt c10Oracle sig (.ifnz (.iszero (.bin .eq .sigLength (.lit 4008))) [.revert]) vm
      = (vm, none) := by
  rw [execStmt_ifnz_revert, if_pos (by simp [eval, Spec.signatureLen_eq_4008])]

/-- An N-mask guard over key var `v` (bound to `wordOf key`, `N_MASK = NMASK`):
    passes (VM-preserving) iff `nMaskedB key`. -/
theorem nmask_guard_pass (sig : ByteVec Spec.SignatureLen) (v : String) (key : ByteVec 32) (vm : VM)
    (hkey : vm.env v = wordOf key) (hN : vm.env "N_MASK" = NMASK) (hpass : nMaskedB key = true) :
    execStmt c10Oracle sig
      (.ifnz (.iszero (.bin .eq (.bin .band (.var v) (.var "N_MASK")) (.var v)))
        [.mstore (.lit 0x00) (.lit 0), .ret (.lit 0x00)]) vm = (vm, none) := by
  unfold execStmt
  rw [if_neg (by simp [eval, hkey, hN, of_decide_eq_true hpass])]

/-- A failing N-mask guard halts with `return 0` (verdict `false`). -/
theorem nmask_guard_fail (sig : ByteVec Spec.SignatureLen) (v : String) (key : ByteVec 32) (vm : VM)
    (hkey : vm.env v = wordOf key) (hN : vm.env "N_MASK" = NMASK) (hfail : nMaskedB key = false) :
    (execStmt c10Oracle sig
      (.ifnz (.iszero (.bin .eq (.bin .band (.var v) (.var "N_MASK")) (.var v)))
        [.mstore (.lit 0x00) (.lit 0), .ret (.lit 0x00)]) vm).2 = some (Halt.returned 0) := by
  unfold execStmt
  rw [if_pos (by simp [eval, hkey, hN, of_decide_eq_false hfail])]
  simp [execList, execStmt, eval, mload32_mstore32_self]

/-! ## The grand composition

`execC10Asm` (the transcribed deployed Yul) equals
`nMaskedB pkSeed && nMaskedB pkRoot && verifyYulModel` — the deployed verifier
computes exactly the declarative spec `Spec.Signature.verify`, modulo the two
leading N-mask guards. -/
set_option maxHeartbeats 2000000 in
theorem execC10Asm_eq (pkSeed pkRoot message : ByteVec 32) (sig : ByteVec Spec.SignatureLen) :
    execC10Asm pkSeed pkRoot message sig
      = (nMaskedB pkSeed && nMaskedB pkRoot && verifyYulModel pkSeed pkRoot message sig) := by
  dsimp only [execC10Asm, execFrom]
  rw [c10Program_decompose]
  simp only [List.cons_append, List.nil_append]
  -- Peel the two scratch letvs (N_MASK, OUT); name the resulting VM `v2`.
  rw [execList_cons_none c10Oracle sig _ _ _ (by simp only [execStmt])]
  rw [execList_cons_none c10Oracle sig _ _ _ (by simp only [execStmt])]
  generalize hv2def : (execStmt c10Oracle sig (.letv "OUT" (.lit 0x600))
    (execStmt c10Oracle sig
      (.letv "N_MASK" (.lit 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000000000000000000000000000))
      { mem := fun _ => 0,
        env := setVar (setVar (setVar (fun _ => 0) "pkSeed" (wordOf pkSeed))
          "pkRoot" (wordOf pkRoot)) "message" (wordOf message) }).1).1 = v2
  have hv2ps : v2.env "pkSeed" = wordOf pkSeed := by
    rw [← hv2def]; simp only [execStmt, eval, setVar, String.reduceEq, ite_true, ite_false]
  have hv2pr : v2.env "pkRoot" = wordOf pkRoot := by
    rw [← hv2def]; simp only [execStmt, eval, setVar, String.reduceEq, ite_true, ite_false]
  have hv2msg : v2.env "message" = wordOf message := by
    rw [← hv2def]; simp only [execStmt, eval, setVar, String.reduceEq, ite_true, ite_false]
  have hv2N : v2.env "N_MASK" = NMASK := by
    rw [← hv2def]; simp only [execStmt, eval, setVar, String.reduceEq, ite_true]; rfl
  have hv2OUT : v2.env "OUT" = 0x600 := by
    rw [← hv2def]; simp only [execStmt, eval, setVar, ite_true]
  -- Peel the sig-length guard (always passes).
  rw [execList_cons_none c10Oracle sig _ _ _ (by rw [sigLen_guard_pass]), sigLen_guard_pass]
  -- Case on the pkSeed N-mask guard.
  cases hS : nMaskedB pkSeed with
  | false =>
    -- pkSeed NOT N-masked: the guard returns 0 → verdict false; RHS = false && … = false.
    rw [execList_cons_halt c10Oracle sig _ _ _ _
        (nmask_guard_fail sig "pkSeed" pkSeed v2 hv2ps hv2N hS)]
    rfl
  | true =>
    -- pkSeed passes; peel its guard, then case on pkRoot.
    rw [execList_cons_none c10Oracle sig _ _ _
          (by rw [nmask_guard_pass sig "pkSeed" pkSeed v2 hv2ps hv2N hS]),
        nmask_guard_pass sig "pkSeed" pkSeed v2 hv2ps hv2N hS]
    cases hR : nMaskedB pkRoot with
    | false =>
      -- pkRoot NOT N-masked: the guard returns 0 → false; RHS = true && false && … = false.
      rw [execList_cons_halt c10Oracle sig _ _ _ _
          (nmask_guard_fail sig "pkRoot" pkRoot v2 hv2pr hv2N hR)]
      rfl
    | true =>
      -- BOTH N-MASKED: the two guards pass; run hmsg → FORS → hypertree → compare.
      rw [execList_cons_none c10Oracle sig _ _ _
            (by rw [nmask_guard_pass sig "pkRoot" pkRoot v2 hv2pr hv2N hR]),
          nmask_guard_pass sig "pkRoot" pkRoot v2 hv2pr hv2N hR]
      -- Now: execList (hmsgFragment ++ (forsPhaseFragment ++ htTail)) v2 = RHS.
      have hSshape : pkSeed = ByteVec.pad16 (ByteVec.truncate16 pkSeed) := nMaskedB_shape hS
      have hRshape : pkRoot = ByteVec.pad16 (ByteVec.truncate16 pkRoot) := nMaskedB_shape hR
      -- The digest the spec & the FORS/HT phases share.
      let DIG : ByteVec 32 := Spec.hMsg pkSeed pkRoot (ByteVec.pad16 (ByteVec.loadValue16 sig 0)) message
      -- === hmsg phase ===
      obtain ⟨hHnone, hHdig⟩ := hmsg_digest sig v2 pkSeed pkRoot message hSshape hRshape
        hv2ps hv2pr hv2msg hv2N hv2OUT
      obtain ⟨vmH, hvmH⟩ : ∃ v, (execList c10Oracle sig hmsgFragment v2).1 = v := ⟨_, rfl⟩
      rw [execList_append_none c10Oracle sig hmsgFragment _ v2 vmH
        (execList_pair _ _ _ _ _ hvmH hHnone)]
      rw [hvmH] at hHdig
      have hHseed : vmH.env "seed" = wordOf pkSeed := by rw [← hvmH, hmsg_post_seed]; exact hv2ps
      have hHroot : vmH.env "root" = wordOf pkRoot := by rw [← hvmH, hmsg_post_root]; exact hv2pr
      have hHN : vmH.env "N_MASK" = NMASK := by
        rw [← hvmH]; exact (execList_env_frame c10Oracle sig hmsgFragment "N_MASK" v2 (by decide)).trans hv2N
      have hHOUT : vmH.env "OUT" = 0x600 := by
        rw [← hvmH]; exact (execList_env_frame c10Oracle sig hmsgFragment "OUT" v2 (by decide)).trans hv2OUT
      have hHmem : ∀ i, i < 32 → vmH.mem (0 + i) = pkSeed.data.getD i 0 := by
        intro i hi; rw [← hvmH, hmsg_seed_mem sig v2 hv2OUT i hi, hv2ps]
        exact beByte_wordOf_getD pkSeed i hi
      -- === reduce RHS to verifyWithDigest pkSeed (truncate16 pkRoot) DIG (deserialise sig) ===
      simp only [Bool.true_and]
      rw [verifyYulModel_unfold, ← hSshape, ← hRshape,
          show (Spec.Signature.deserialise sig).r = ByteVec.loadValue16 sig 0 from rfl]
      show _ = Spec.Hypertree.verifyWithDigest pkSeed (ByteVec.truncate16 pkRoot) DIG
        (Spec.Signature.deserialise sig)
      unfold Spec.Hypertree.verifyWithDigest
      -- === FORS phase ===
      have hFors := fors_phase sig vmH pkSeed DIG hHdig hHseed hHN hHOUT hHmem
      by_cases hidx : (SphincsCVerify.Util.extractForsIndices DIG).getD (Spec.K - 1) 0 ≠ 0
      · -- FORS forced-zero index nonzero: reverts → false; spec returns false too.
        rw [if_pos hidx] at hFors
        rw [execList_append_halt2 c10Oracle sig forsPhaseFragment _ vmH _ hFors,
            if_pos hidx]
      · -- FORS passes: forsPk = r.
        rw [if_neg hidx] at hFors
        obtain ⟨hFnone, r, hrec, hforsPk⟩ := hFors
        obtain ⟨vmF, hvmF⟩ : ∃ v, (execList c10Oracle sig forsPhaseFragment vmH).1 = v := ⟨_, rfl⟩
        rw [execList_append_none c10Oracle sig forsPhaseFragment _ vmH vmF
          (execList_pair _ _ _ _ _ hvmF hFnone), if_neg hidx]
        simp only [hrec]
        rw [hvmF] at hforsPk
        -- vmF facts.
        have hFforsPk : vmF.env "forsPk" = wordOf (ByteVec.pad16 r) := hforsPk
        have hFht : vmF.env "htIdx" = SphincsCVerify.Util.extractHtIndex DIG := by
          rw [← hvmF]; exact fors_post_htIdx sig vmH DIG hHdig
        have hFsb : vmF.env "sigBase" = 0 := by
          rw [← hvmF]; exact fors_post_sigBase sig vmH hFnone
        have hFseed : vmF.env "seed" = wordOf pkSeed := by
          rw [← hvmF]; exact (fors_post_const sig vmH "seed" (by decide)).trans hHseed
        have hFroot : vmF.env "root" = wordOf pkRoot := by
          rw [← hvmF]; exact (fors_post_const sig vmH "root" (by decide)).trans hHroot
        have hFN : vmF.env "N_MASK" = NMASK := by
          rw [← hvmF]; exact (fors_post_const sig vmH "N_MASK" (by decide)).trans hHN
        have hFOUT : vmF.env "OUT" = 0x600 := by
          rw [← hvmF]; exact (fors_post_const sig vmH "OUT" (by decide)).trans hHOUT
        have hFmem : ∀ i, i < 32 → vmF.mem (0 + i) = pkSeed.data.getD i 0 := by
          intro i hi; rw [← hvmF, forsPhaseFragment_mem_low sig vmH hHOUT (0 + i) (by omega)]
          exact hHmem i hi
        -- === hypertree setup: peel the 3 letvs (currentNode, idxTree, sigOff). ===
        rw [execList_cons_none c10Oracle sig _ _ _ (by simp only [execStmt])]
        rw [execList_cons_none c10Oracle sig _ _ _ (by simp only [execStmt])]
        rw [execList_cons_none c10Oracle sig _ _ _ (by simp only [execStmt])]
        generalize hvmS : (execStmt c10Oracle sig (.letv "sigOff" (.lit 2336))
          (execStmt c10Oracle sig (.letv "idxTree" (.var "htIdx"))
            (execStmt c10Oracle sig (.letv "currentNode" (.var "forsPk")) vmF).1).1).1 = vmS
        have hSidx : vmS.env "idxTree" = SphincsCVerify.Util.extractHtIndex DIG := by
          rw [← hvmS]; simp only [execStmt, eval, setVar, String.reduceEq, ite_true, ite_false]
          exact hFht
        have hSso : vmS.env "sigOff" = 2336 := by
          rw [← hvmS]; simp only [execStmt, eval, setVar, ite_true]
        have hScn : vmS.env "currentNode" = wordOf (ByteVec.pad16 r) := by
          rw [← hvmS]; simp only [execStmt, eval, setVar, String.reduceEq, ite_true, ite_false]
          exact hFforsPk
        have hSseed : vmS.env "seed" = wordOf pkSeed := by
          rw [← hvmS]; simp only [execStmt, eval, setVar, String.reduceEq, ite_false]; exact hFseed
        have hSsb : vmS.env "sigBase" = 0 := by
          rw [← hvmS]; simp only [execStmt, eval, setVar, String.reduceEq, ite_false]; exact hFsb
        have hSN : vmS.env "N_MASK" = NMASK := by
          rw [← hvmS]; simp only [execStmt, eval, setVar, String.reduceEq, ite_false]; exact hFN
        have hSOUT : vmS.env "OUT" = 0x600 := by
          rw [← hvmS]; simp only [execStmt, eval, setVar, String.reduceEq, ite_false]; exact hFOUT
        have hSroot : vmS.env "root" = wordOf pkRoot := by
          rw [← hvmS]; simp only [execStmt, eval, setVar, String.reduceEq, ite_false]; exact hFroot
        have hSmem : ∀ i, i < 32 → vmS.mem (0 + i) = pkSeed.data.getD i 0 := by
          intro i hi; rw [← hvmS]; simp only [execStmt, eval, setVar]; exact hFmem i hi
        have hidxbnd : SphincsCVerify.Util.extractHtIndex DIG < 2 ^ 64 :=
          Nat.lt_of_lt_of_le (SphincsCVerify.Util.extractHtIndex_lt DIG) (by decide)
        -- count bridge for Hbind.
        have hcount : ∀ k, k < 2 → calldataload sig (2336 + 836 * k + 688) >>> 224
            = wordOf (ByteVec.u32ToB32 (((Spec.Signature.deserialise sig).layers.getD k
                Spec.Hypertree.defaultLayerSig).wots).count) := by
          intro k hk
          rw [count_bridge, deserialise_layer sig k hk]
          have hoff : 2336 + 836 * k + 688
              = Spec.SigForsTotal + k * Spec.SigHtLayer + Spec.L * Spec.N := by
            rw [Spec.sigForsTotal_eq_2336, Spec.sigHtLayer_eq_836, show Spec.L = 43 from rfl,
              show Spec.N = 16 from rfl]; omega
          rw [hoff]
        have hHT := verifyHypertree_refine sig vmS pkSeed r (SphincsCVerify.Util.extractHtIndex DIG)
          (Spec.Signature.deserialise sig).layers hidxbnd hSidx hSso hScn hSseed hSsb hSN hSOUT hSmem
          (htLayers_satisfy_Hbind sig hcount)
        -- The layer loop's `forRange` statement as an `execFor` (count `2`).
        have hForStmt : execStmt c10Oracle sig (.forRange "layer" (.lit 2) htLayerBody) vmS
            = execFor c10Oracle sig "layer" htLayerBody 2 0 vmS := by simp only [execStmt, eval]
        -- === hypertree loop ===
        by_cases hVH : Spec.Hypertree.verifyHypertree pkSeed r
            (SphincsCVerify.Util.extractHtIndex DIG) (Spec.Signature.deserialise sig).layers = none
        · -- some layer reverts: loop reverts → false; spec verifyHypertree=none → false.
          simp only [hVH]
          obtain ⟨hHTrev, _⟩ := hHT
          have hloop : (execStmt c10Oracle sig (.forRange "layer" (.lit 2) htLayerBody) vmS).2
              = some Halt.reverted := by rw [hForStmt]; exact hHTrev hVH
          rw [execList_cons_halt c10Oracle sig _ _ _ _ hloop]
        · -- hypertree succeeds with finalNode.
          obtain ⟨finalNode, hfn⟩ := Option.ne_none_iff_exists'.mp hVH
          simp only [hfn]
          obtain ⟨_, hHTpass⟩ := hHT
          obtain ⟨hLnone, hLcn, hLseed, hLsb, hLN, hLOUT, hLmem⟩ := hHTpass finalNode hfn
          -- the loop falls through; peel it and the final compare.
          have hloopStmt : (execStmt c10Oracle sig (.forRange "layer" (.lit 2) htLayerBody) vmS).2
              = none := by rw [hForStmt]; exact hLnone
          rw [execList_cons_none c10Oracle sig _ _ _ hloopStmt]
          -- vmL = post-loop; env currentNode = wordOf (pad16 finalNode); root preserved.
          obtain ⟨vmL, hvmL⟩ : ∃ v, (execStmt c10Oracle sig
            (.forRange "layer" (.lit 2) htLayerBody) vmS).1 = v := ⟨_, rfl⟩
          rw [hvmL]
          have hLcn' : vmL.env "currentNode" = wordOf (ByteVec.pad16 finalNode) := by
            rw [← hvmL, hForStmt]; exact hLcn
          have hLroot : vmL.env "root" = wordOf (ByteVec.pad16 (ByteVec.truncate16 pkRoot)) := by
            rw [← hvmL, hForStmt,
              execFor_env_frame c10Oracle sig "layer" htLayerBody "root" (by decide) (by decide) 2 0 vmS,
              hSroot]
            exact congrArg wordOf hRshape
          -- peel valid-letv, mstore, ret.
          rw [execList_cons_none c10Oracle sig _ _ _ (by simp only [execStmt])]
          rw [execList_cons_none c10Oracle sig _ _ _ (by simp only [execStmt])]
          rw [execList]
          simp only [execStmt, eval, setVar, String.reduceEq, ite_true, hLcn', hLroot,
            mload32_mstore32_self]
          -- LHS = decide ((if wordOf(pad16 finalNode) = wordOf(pad16 (truncate16 pkRoot)) then 1 else 0)
          --   % 2^256 = 1) = decide (finalNode = truncate16 pkRoot)  [the spec's compare]
          by_cases hcmp : finalNode = ByteVec.truncate16 pkRoot
          · rw [if_pos (show wordOf (ByteVec.pad16 finalNode)
              = wordOf (ByteVec.pad16 (ByteVec.truncate16 pkRoot)) from by rw [hcmp])]
            simp [hcmp]
          · rw [if_neg (fun h => hcmp (pad16_wordOf_inj h))]
            simp [hcmp]

end SphincsCVerify.Interpreter.C10

/-
SphincsCVerify.Interpreter.C10Parse — the A3.1 **R1a in-kernel parse theorem**
and the elision bridge (see `docs/A3_1_CLOSURE_PATH.md` §8).

Three results, together moving the source↔AST transcription leg of residual
R1 from a trusted host-side Python checker into the Lean kernel:

  1. `parse_c10 : parseYul c10Source = some c10ProgramFull` — a kernel `rfl`
     over the FULL 9,256-byte pinned assembly interior of `SPHINCsC10Asm.sol`.
     The kernel itself tokenizes + parses the source and checks the result
     against the faithful AST. (~3 s; needs the lakefile's `--tstack=32768`.)

  2. `execFrom_c10ProgramFull_eq` — the ELISION BRIDGE: `c10ProgramFull`
     (the faithful parse) and `c10Program` (the transcription every
     downstream proof consumes, with the N1/N2 normalizations applied) yield
     the SAME verdict for EVERY oracle, signature blob, initial environment
     and initial memory. N2 is definitional (`execStmt` treats `.letv` and
     `.setv` identically); N1 reduces to "a `.revert`-terminated block
     halt-reverts regardless of the preceding error-string `mstore`s".

  3. `execC10Asm_eq_parsed_source` — the corollary chaining 1+2: ANY
     successful parse of the pinned source yields a program whose interpreter
     run equals `execC10Asm` on every input — and `execC10Asm_eq`
     (Interpreter/C10Refine.lean) already proves `execC10Asm = Spec.verify`.
     So the chain `source →(kernel parse) AST →(kernel bridge) execC10Asm
     →(kernel refinement) Spec.verify` is now kernel-checked end to end;
     the remaining R1 residual is R1b alone (solc source → deployed
     bytecode), plus the parser itself as a reviewed TCB element.

HONEST SCOPE: the identity `c10Source` ↔ the actual `.sol` FILE bytes is a CI
byte-pin (`scripts/check_c10_source_pin.py`, pure Python — the Lean toolchain
does not run in CI); this module's theorems are checked locally by
`make verify-parse-transcription` / the `verify` bundle.

Mathlib-free (Lean core only); no `sorry`/`admit`/`axiom`/`native_decide`.
-/

import SphincsCVerify.Interpreter.YulParse
import SphincsCVerify.Interpreter.C10Source

namespace SphincsCVerify.Interpreter.C10

open SphincsCVerify.Interpreter
open SphincsCVerify.Interpreter.YulParse
open SphincsCVerify.Spec (ByteVec)

/-! ## 1. The in-kernel parse theorem -/

set_option maxRecDepth 100000 in
/-- **R1a, source↔AST leg, kernel-checked.** Parsing the pinned byte-exact
    `SPHINCsC10Asm.sol` assembly interior yields EXACTLY the faithful
    transcription `c10ProgramFull`. Proof is `rfl`: the kernel runs the
    tokenizer + parser over all 9,256 characters and compares the resulting
    AST. (`maxRecDepth` is the elaborator's soft counter; the real stack is
    the lakefile's `--tstack=32768`.) -/
theorem parse_c10 : parseYul c10Source = some c10ProgramFull := rfl

/-! ## 2. The elision bridge

`execStmt`/`execList` are well-founded-compiled (the mutual block recurses
over the nested `Stmt`/`List Stmt` structure), so they do NOT kernel-reduce;
every step below goes through their equation lemmas (`simp only [execList,
execStmt]`), never `rfl`-on-`execList`. -/

/-- N2 is a same-arm identity: `execStmt` gives `.letv` and `.setv`
    byte-identical right-hand sides. -/
theorem execStmt_letv_eq_setv {n : Nat} (sha : List UInt8 → ByteVec 32)
    (sig : ByteVec n) (x : String) (e : Expr) (vm : VM) :
    execStmt sha sig (.letv x e) vm = execStmt sha sig (.setv x e) vm := by
  simp only [execStmt]

/-- N1's engine: the FULL sig-length gate body (4 error-string `mstore`s +
    `revert`) halt-reverts from ANY state — the `mstore`s cannot affect the
    outcome tag. -/
theorem execList_errBody_snd {n : Nat} (sha : List UInt8 → ByteVec 32)
    (sig : ByteVec n) (vm : VM) :
    (execList sha sig errBody vm).2 = some Halt.reverted := by
  simp only [errBody, execList, execStmt]

/-- …and so does the elided body `c10Program` uses. -/
theorem execList_revert_snd {n : Nat} (sha : List UInt8 → ByteVec 32)
    (sig : ByteVec n) (vm : VM) :
    (execList sha sig [Stmt.revert] vm).2 = some Halt.reverted := by
  simp only [execList, execStmt]

/-- **The N1 congruence.** An `ifnz` whose two candidate bodies BOTH
    halt-revert from any state, followed by continuations with equal halt
    outcomes, yields the same halt outcome — regardless of what the bodies
    write to memory before reverting. -/
theorem execList_ifnz_revert_congr {n : Nat} (sha : List UInt8 → ByteVec 32)
    (sig : ByteVec n) (c : Expr) (bF bE restF restE : List Stmt)
    (hF : ∀ vm, (execList sha sig bF vm).2 = some Halt.reverted)
    (hE : ∀ vm, (execList sha sig bE vm).2 = some Halt.reverted)
    (hrest : ∀ vm, (execList sha sig restF vm).2 = (execList sha sig restE vm).2)
    (vm : VM) :
    (execList sha sig (.ifnz c bF :: restF) vm).2
      = (execList sha sig (.ifnz c bE :: restE) vm).2 := by
  rw [execList, execList]
  simp only [execStmt]
  by_cases hc : eval sig vm c ≠ 0
  · simp only [if_pos hc]
    rcases hbF : execList sha sig bF vm with ⟨vmF, oF⟩
    rcases hbE : execList sha sig bE vm with ⟨vmE, oE⟩
    have hF' : oF = some Halt.reverted := by
      have h := hF vm; rw [hbF] at h; exact h
    have hE' : oE = some Halt.reverted := by
      have h := hE vm; rw [hbE] at h; exact h
    subst hF'; subst hE'
    rfl
  · simp only [if_neg hc]
    exact hrest vm

/-- **The N2 leg.** The shared verifier body followed by the `valid` binding
    (`.setv` faithful vs `.letv` transcription) + tail: equal halt outcomes,
    since `execStmt` treats the two binders identically. -/
theorem execList_valid_tail_snd {n : Nat} (sha : List UInt8 → ByteVec 32)
    (sig : ByteVec n) (vm : VM) :
    (execList sha sig (c10Mid ++ (.setv "valid" validExpr :: c10Tail)) vm).2
      = (execList sha sig (c10Mid ++ (.letv "valid" validExpr :: c10Tail)) vm).2 := by
  rw [execList_append, execList_append]
  rcases hmid : execList sha sig c10Mid vm with ⟨vm2, o2⟩
  cases o2 with
  | some h => rfl
  | none => simp only [execList, execStmt]

/-- **Elision bridge, halt level.** Running the faithful `c10ProgramFull` and
    the normalized `c10Program` from the same state produces the same halt
    outcome (and hence the same verdict): the two programs differ only in
    (N1) the gate body — where both halt-revert — and (N2) `.letv`/`.setv`
    on `"valid"` — which `execStmt` treats identically. -/
theorem execList_c10ProgramFull_snd {n : Nat} (sha : List UInt8 → ByteVec 32)
    (sig : ByteVec n) (vm : VM) :
    (execList sha sig c10ProgramFull vm).2 = (execList sha sig c10Program vm).2 := by
  rw [c10Program_decomp]
  unfold c10ProgramFull
  rw [execList_append, execList_append]
  rcases hpre : execList sha sig c10Pre vm with ⟨vm1, o1⟩
  cases o1 with
  | some h => rfl
  | none =>
      exact execList_ifnz_revert_congr sha sig lenGate errBody [.revert]
        (c10Mid ++ (.setv "valid" validExpr :: c10Tail))
        (c10Mid ++ (.letv "valid" validExpr :: c10Tail))
        (execList_errBody_snd sha sig) (execList_revert_snd sha sig)
        (execList_valid_tail_snd sha sig) vm1

/-- **Elision bridge, verdict level (deliverable 4's target statement).**
    For every SHA-256 oracle, signature blob, initial environment and initial
    memory, the faithful parse target and the transcription the proofs
    consume produce the SAME Bool verdict. -/
theorem execFrom_c10ProgramFull_eq {n : Nat} (sha : List UInt8 → ByteVec 32)
    (sig : ByteVec n) (env0 : VarEnv) (mem0 : ByteMemory) :
    execFrom sha sig c10ProgramFull env0 mem0
      = execFrom sha sig c10Program env0 mem0 := by
  unfold execFrom
  rw [execList_c10ProgramFull_snd]

/-! ## 3. The corollary: `execC10Asm` runs the PARSED source -/

/-- **R1a corollary (kernel-checked source↔execution binding).** ANY
    successful parse of the pinned source text yields a program whose
    interpreter run — under the real SHA-256 oracle, for EVERY
    `pkSeed`/`pkRoot`/`message`/`sig` — is exactly `execC10Asm`, the function
    `execC10Asm_eq` (Interpreter/C10Refine.lean) proves equal to
    `Spec.Signature.verify`. Stated over an arbitrary `prog` + parse
    hypothesis (rather than `c10ProgramFull` directly) so the binding to the
    SOURCE — not to any particular transcription — is explicit. -/
theorem execC10Asm_eq_parsed_source
    (prog : List Stmt) (hparse : parseYul c10Source = some prog)
    (pkSeed pkRoot message : ByteVec 32) (sig : ByteVec Spec.SignatureLen) :
    execFrom c10Oracle sig prog
        (setVar (setVar (setVar (fun _ => 0) "pkSeed" (wordOf pkSeed))
            "pkRoot" (wordOf pkRoot)) "message" (wordOf message))
        (fun _ => 0)
      = execC10Asm pkSeed pkRoot message sig := by
  have hp : prog = c10ProgramFull := by
    rw [parse_c10] at hparse
    injection hparse with h
    exact h.symm
  subst hp
  rw [execFrom_c10ProgramFull_eq]
  rfl

end SphincsCVerify.Interpreter.C10
